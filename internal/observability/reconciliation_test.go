package observability

import (
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestReconciliationMetricsComeFromDurableReport(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewReconciliationMetrics(registry)
	if err := metrics.Observe(reconciliation.Report{
		Status: "FAILED", Watermarks: map[string]int64{"book-a": 41},
		Findings: []reconciliation.Finding{{
			Category: reconciliation.EscrowNotConserved,
			Severity: reconciliation.SeverityP0,
			Amount:   ledger.NewAmountInt64(7),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if value := gaugeValue(t, metrics.LatestSafe); value != 0 {
		t.Fatalf("unsafe report exported as safe: %v", value)
	}
	if value := gaugeValue(t, metrics.CurrentFindings.WithLabelValues("P0", "ESCROW_NOT_CONSERVED")); value != 1 {
		t.Fatalf("wrong current finding count: %v", value)
	}
	if value := gaugeValue(t, metrics.VerifiedWatermark.WithLabelValues("book-a")); value != 41 {
		t.Fatalf("wrong verified watermark: %v", value)
	}
}

func TestFinancialAndReconciliationCollectorsHaveNoDuplicateMetricNames(t *testing.T) {
	registry := prometheus.NewRegistry()
	NewFinancialMetrics(registry)
	NewReconciliationMetrics(registry)
	if _, err := registry.Gather(); err != nil {
		t.Fatal(err)
	}
}

func gaugeValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	result := &dto.Metric{}
	if err := metric.Write(result); err != nil {
		t.Fatal(err)
	}
	return result.GetGauge().GetValue()
}
