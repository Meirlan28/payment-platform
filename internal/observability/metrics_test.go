package observability

import (
	"fmt"
	"testing"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestFinancialMetricsAreDerivedFromDurableReportWithoutCancellation(t *testing.T) {
	metrics := NewFinancialMetrics(prometheus.NewRegistry())
	report := reconciliation.Report{RunID: "run-1", Status: "FAILED", Findings: []reconciliation.Finding{
		{Category: reconciliation.UnbalancedTransaction, Severity: reconciliation.SeverityP0,
			BookID: "book-a", AssetID: "KZT", Amount: ledger.NewAmountInt64(7)},
		{Category: reconciliation.UnbalancedTransaction, Severity: reconciliation.SeverityP0,
			BookID: "book-a", AssetID: "KZT", Amount: ledger.NewAmountInt64(-2)},
		{Category: reconciliation.JournalReplayMismatch, Severity: reconciliation.SeverityP0,
			AssetID: "KZT", Amount: ledger.NewAmountInt64(-4)},
		{Category: reconciliation.JournalReplayMismatch, Severity: reconciliation.SeverityP0,
			AssetID: "KZT", Amount: ledger.NewAmountInt64(3)},
		{Category: reconciliation.EscrowNotConserved, Severity: reconciliation.SeverityP0,
			AssetID: "KZT", Amount: ledger.NewAmountInt64(-5)},
		{Category: reconciliation.JournalSequenceGap, Severity: reconciliation.SeverityP0,
			BookID: "book-a", Amount: ledger.NewAmountInt64(0),
			Details: map[string]string{"expected": "11", "count": "8", "maximum": "11"}},
	}}
	if err := metrics.ObserveReport("region-a", report); err != nil {
		t.Fatal(err)
	}
	assertGauge(t, metrics.LedgerBalanceResidual.WithLabelValues("book-a", "KZT"), 9)
	assertGauge(t, metrics.JournalReplayDelta.WithLabelValues("region-a", "KZT"), 7)
	assertGauge(t, metrics.EscrowConservationDelta.WithLabelValues("KZT"), 5)
	assertGauge(t, metrics.SequenceGap.WithLabelValues("book-a"), 3)
	assertCounter(t, metrics.FinancialInvariantViolation.WithLabelValues(
		string(reconciliation.UnbalancedTransaction), "P0"), 2)

	// A later safe durable report deletes the old vector children. Calling
	// WithLabelValues again creates a fresh zero-valued child.
	if err := metrics.ObserveReport("region-a", reconciliation.Report{RunID: "run-2", Status: "PASSED"}); err != nil {
		t.Fatal(err)
	}
	assertGauge(t, metrics.LedgerBalanceResidual.WithLabelValues("book-a", "KZT"), 0)
	assertGauge(t, metrics.JournalReplayDelta.WithLabelValues("region-a", "KZT"), 0)
}

func TestInvalidReportCannotEraseLastKnownMetricSnapshot(t *testing.T) {
	metrics := NewFinancialMetrics(prometheus.NewRegistry())
	valid := reconciliation.Report{Status: "FAILED", Findings: []reconciliation.Finding{{
		Category: reconciliation.UnbalancedTransaction, Severity: reconciliation.SeverityP0,
		BookID: "book-a", AssetID: "USD", Amount: ledger.NewAmountInt64(7),
	}}}
	if err := metrics.ObserveReport("region-a", valid); err != nil {
		t.Fatal(err)
	}
	invalid := reconciliation.Report{Status: "FAILED", Findings: []reconciliation.Finding{{
		Category: reconciliation.UnbalancedTransaction, Severity: reconciliation.SeverityP0,
		BookID: "", AssetID: "USD", Amount: ledger.NewAmountInt64(11),
	}}}
	if err := metrics.ObserveReport("region-a", invalid); err == nil {
		t.Fatal("invalid high-cardinality label input was accepted")
	}
	assertGauge(t, metrics.LedgerBalanceResidual.WithLabelValues("book-a", "USD"), 7)
}

func TestTypedPaymentFailuresIncrementOnlyBoundedCounters(t *testing.T) {
	metrics := NewFinancialMetrics(prometheus.NewRegistry())
	metrics.ObservePaymentError("capture", fmt.Errorf("wrapped: %w", idempotency.ErrKeyConflict))
	metrics.ObservePaymentError("refund", payment.ErrOverRefund)
	metrics.ObservePaymentError("capture", payment.ErrCashbackRule)
	metrics.ObservePaymentError("capture", ledger.ErrInsufficientFunds)
	assertCounter(t, metrics.DuplicateEffectConflict, 1)
	assertCounter(t, metrics.RefundOvercaptureAttempt, 1)
	assertCounter(t, metrics.CashbackRuleViolation, 1)
}

func assertGauge(t *testing.T, metric prometheus.Metric, expected float64) {
	t.Helper()
	if actual := gaugeValue(t, metric); actual != expected {
		t.Fatalf("gauge=%v, want %v", actual, expected)
	}
}

func assertCounter(t *testing.T, metric prometheus.Metric, expected float64) {
	t.Helper()
	result := &dto.Metric{}
	if err := metric.Write(result); err != nil {
		t.Fatal(err)
	}
	if actual := result.GetCounter().GetValue(); actual != expected {
		t.Fatalf("counter=%v, want %v", actual, expected)
	}
}
