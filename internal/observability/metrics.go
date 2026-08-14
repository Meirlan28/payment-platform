package observability

import "github.com/prometheus/client_golang/prometheus"

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
			Help: "Non-zero debit/credit residual at a verified committed watermark.",
		}, []string{"book", "asset"}),
		JournalReplayDelta: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "journal_replay_delta_atoms",
			Help: "Difference between a materialized balance and journal replay at the same watermark.",
		}, []string{"region", "asset"}),
		DuplicateEffectConflict: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Name: "duplicate_effect_conflict_total",
			Help: "Idempotency keys reused with a different canonical request hash.",
		}),
		EscrowConservationDelta: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Name: "escrow_conservation_delta_atoms",
			Help: "Difference between issued authority and all spendable/in-transit rights.",
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

func (m *FinancialMetrics) InvariantViolation(name string) {
	m.FinancialInvariantViolation.WithLabelValues(name, "P0").Inc()
}
