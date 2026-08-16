package observability

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"unicode/utf8"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Every database-derived label set is rejected before it can create an
	// unbounded Prometheus vector. The platform's controlled books, assets,
	// regions, rails and topics must fit this deployment-wide ceiling.
	maxMetricSeries = 4096
	maxLabelBytes   = 128
)

// FinancialMetrics contains only bounded-cardinality labels. Account, payment,
// transaction and idempotency identifiers must never be metric labels.
type FinancialMetrics struct {
	LedgerBalanceResidual       *prometheus.GaugeVec
	JournalReplayDelta          *prometheus.GaugeVec
	DuplicateEffectConflict     prometheus.Counter
	EscrowConservationDelta     *prometheus.GaugeVec
	SequenceGap                 *prometheus.GaugeVec
	OutboxLag                   *prometheus.GaugeVec
	ReconciliationLag           *prometheus.GaugeVec
	InTransitValue              *prometheus.GaugeVec
	UnknownExternalEffects      *prometheus.GaugeVec
	RefundOvercaptureAttempt    prometheus.Counter
	CashbackRuleViolation       prometheus.Counter
	FinancialInvariantViolation *prometheus.CounterVec
}

func NewFinancialMetrics(reg prometheus.Registerer) *FinancialMetrics {
	m := &FinancialMetrics{
		LedgerBalanceResidual: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "ledger_balance_residual_atoms",
			Help: "Total absolute debit/credit residual at a verified committed watermark.",
		}, []string{"book", "asset"}),
		JournalReplayDelta: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "journal_replay_delta_atoms",
			Help: "Total absolute materialized-balance versus journal-replay delta at one verified watermark.",
		}, []string{"region", "asset"}),
		DuplicateEffectConflict: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Name: "duplicate_effect_conflict_total",
			Help: "Idempotency keys reused with a different canonical request hash.",
		}),
		EscrowConservationDelta: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "escrow_conservation_delta_atoms",
			Help: "Total absolute authority conservation delta at one verified watermark.",
		}, []string{"asset"}),
		SequenceGap: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "sequence_gap",
			Help: "Number of missing journal sequence values below the verified watermark.",
		}, []string{"book"}),
		OutboxLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "outbox_lag_seconds",
			Help: "Age in seconds of the oldest unpublished outbox event.",
		}, []string{"region", "topic"}),
		ReconciliationLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "reconciliation_lag_seconds",
			Help: "Age of the oldest unreconciled effect.",
		}, []string{"region", "counterparty"}),
		InTransitValue: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "in_transit_value_atoms",
			Help: "Value held by unconsumed transfer certificates.",
		}, []string{"source_region", "destination_region", "asset"}),
		UnknownExternalEffects: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "unknown_external_effects",
			Help: "External effects whose outcome must be queried or reconciled before retry.",
		}, []string{"rail", "region"}),
		RefundOvercaptureAttempt: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Name: "refund_overcapture_attempt_total",
			Help: "Refund attempts rejected because cumulative principal exceeded captured principal.",
		}),
		CashbackRuleViolation: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Name: "cashback_rule_violation_total",
			Help: "Committed or proposed cashback amounts that exceed the pinned rule result.",
		}),
		FinancialInvariantViolation: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Name: "financial_invariant_violation_total",
			Help: "Financial safety violations. Every increment is severity=P0.",
		}, []string{"invariant", "severity"}),
	}
	reg.MustRegister(
		m.LedgerBalanceResidual,
		m.JournalReplayDelta,
		m.DuplicateEffectConflict,
		m.EscrowConservationDelta,
		m.SequenceGap,
		m.OutboxLag,
		m.ReconciliationLag,
		m.InTransitValue,
		m.UnknownExternalEffects,
		m.RefundOvercaptureAttempt,
		m.CashbackRuleViolation,
		m.FinancialInvariantViolation,
	)
	return m
}

func (m *FinancialMetrics) invariantViolation(name string) {
	m.FinancialInvariantViolation.WithLabelValues(name, "P0").Inc()
}

// ObserveReport exports financial gauges only from a reconciliation report
// that was committed with the SERIALIZABLE snapshot it describes. Absolute
// aggregation is intentional: opposite account/transaction defects must
// never cancel and make a broken invariant appear healthy.
func (m *FinancialMetrics) ObserveReport(region string, report reconciliation.Report) error {
	if m == nil {
		return nil
	}
	if err := validateMetricLabel("region", region); err != nil {
		return err
	}

	ledgerResiduals := make(map[[2]string]*big.Int)
	replayDeltas := make(map[string]*big.Int)
	escrowDeltas := make(map[string]*big.Int)
	sequenceGaps := make(map[string]*big.Int)
	for _, finding := range report.Findings {
		if finding.Severity == reconciliation.SeverityP0 {
			if err := validateMetricLabel("invariant", string(finding.Category)); err != nil {
				return err
			}
		}
		switch finding.Category {
		case reconciliation.UnbalancedTransaction:
			if err := validateMetricLabels(map[string]string{"book": finding.BookID, "asset": finding.AssetID}); err != nil {
				return err
			}
			addAbsolute(ledgerResiduals, [2]string{finding.BookID, finding.AssetID}, finding.Amount)
		case reconciliation.JournalReplayMismatch:
			if err := validateMetricLabel("asset", finding.AssetID); err != nil {
				return err
			}
			addAbsolute(replayDeltas, finding.AssetID, finding.Amount)
		case reconciliation.EscrowNotConserved:
			if err := validateMetricLabel("asset", finding.AssetID); err != nil {
				return err
			}
			addAbsolute(escrowDeltas, finding.AssetID, finding.Amount)
		case reconciliation.JournalSequenceGap:
			if err := validateMetricLabel("book", finding.BookID); err != nil {
				return err
			}
			gap, err := sequenceGap(finding)
			if err != nil {
				return err
			}
			addBigInt(sequenceGaps, finding.BookID, gap)
		}
	}
	if len(ledgerResiduals) > maxMetricSeries || len(replayDeltas) > maxMetricSeries ||
		len(escrowDeltas) > maxMetricSeries || len(sequenceGaps) > maxMetricSeries {
		return fmt.Errorf("observability: reconciliation report exceeds %d series per metric", maxMetricSeries)
	}

	// Reset first so a finding resolved by this newer durable report cannot
	// leave a stale non-zero series behind.
	m.LedgerBalanceResidual.Reset()
	m.JournalReplayDelta.Reset()
	m.EscrowConservationDelta.Reset()
	m.SequenceGap.Reset()
	for labels, value := range ledgerResiduals {
		m.LedgerBalanceResidual.WithLabelValues(labels[0], labels[1]).Set(bigIntFloat(value))
	}
	for asset, value := range replayDeltas {
		m.JournalReplayDelta.WithLabelValues(region, asset).Set(bigIntFloat(value))
	}
	for asset, value := range escrowDeltas {
		m.EscrowConservationDelta.WithLabelValues(asset).Set(bigIntFloat(value))
	}
	for book, value := range sequenceGaps {
		m.SequenceGap.WithLabelValues(book).Set(bigIntFloat(value))
	}
	for _, finding := range report.Findings {
		if finding.Severity == reconciliation.SeverityP0 {
			m.invariantViolation(string(finding.Category))
		}
		if finding.Category == reconciliation.CashbackRuleExceeded {
			m.CashbackRuleViolation.Inc()
		}
	}
	return nil
}

// ObservePaymentError maps only bounded, typed financial command failures to
// counters. It deliberately receives neither identifiers nor caller data.
func (m *FinancialMetrics) ObservePaymentError(_ string, err error) {
	if m == nil || err == nil {
		return
	}
	if errors.Is(err, idempotency.ErrKeyConflict) || errors.Is(err, ledger.ErrEffectConflict) {
		m.DuplicateEffectConflict.Inc()
	}
	if errors.Is(err, payment.ErrOverRefund) {
		m.RefundOvercaptureAttempt.Inc()
	}
	if errors.Is(err, payment.ErrCashbackRule) {
		m.CashbackRuleViolation.Inc()
	}
}

func addAbsolute[K comparable](values map[K]*big.Int, key K, amount ledger.Amount) {
	integer, ok := new(big.Int).SetString(amount.String(), 10)
	if !ok {
		panic("ledger.Amount produced a non-integer string")
	}
	integer.Abs(integer)
	addBigInt(values, key, integer)
}

func addBigInt[K comparable](values map[K]*big.Int, key K, amount *big.Int) {
	if existing, found := values[key]; found {
		existing.Add(existing, amount)
		return
	}
	values[key] = new(big.Int).Set(amount)
}

func bigIntFloat(value *big.Int) float64 {
	result, _ := new(big.Float).SetInt(value).Float64()
	return result
}

func sequenceGap(finding reconciliation.Finding) (*big.Int, error) {
	expected, ok := new(big.Int).SetString(finding.Details["expected"], 10)
	if !ok || expected.Sign() < 0 {
		return nil, errors.New("observability: invalid expected sequence in durable report")
	}
	count, ok := new(big.Int).SetString(finding.Details["count"], 10)
	if !ok || count.Sign() < 0 {
		return nil, errors.New("observability: invalid sequence count in durable report")
	}
	gap := new(big.Int).Sub(expected, count)
	gap.Abs(gap)
	if gap.Sign() == 0 && finding.Details["maximum"] != expected.String() {
		// A non-contiguous set can have the expected cardinality but a wrong
		// maximum. Such corruption must remain visibly non-zero.
		gap.SetInt64(1)
	}
	return gap, nil
}

func validateMetricLabels(labels map[string]string) error {
	for name, value := range labels {
		if err := validateMetricLabel(name, value); err != nil {
			return err
		}
	}
	return nil
}

func validateMetricLabel(name, value string) error {
	if value == "" || len(value) > maxLabelBytes || !utf8.ValidString(value) {
		return fmt.Errorf("observability: invalid %s metric label length/encoding", name)
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return fmt.Errorf("observability: invalid control character in %s metric label", name)
		}
	}
	return nil
}

func parseNonNegativeFloat(name, raw string) (float64, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("observability: invalid %s value %q", name, raw)
	}
	return value, nil
}
