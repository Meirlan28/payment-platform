package observability

import (
	"math"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestOperationalSnapshotSetsAndClearsEveryGaugeFamily(t *testing.T) {
	metrics := NewFinancialMetrics(prometheus.NewRegistry())
	first := OperationalSnapshot{
		Region:    "region-a",
		OutboxLag: []OutboxLagSample{{Topic: "payment-events", AgeSeconds: 17}},
		InTransit: []InTransitSample{{
			SourceRegion: "region-a", DestinationRegion: "region-b", Asset: "USD", AmountAtoms: 23,
		}},
		UnknownExternal: []UnknownExternalSample{{Rail: "card", Count: 2}},
		Reconciliation:  []ReconciliationLagSample{{Counterparty: "rail/card", AgeSeconds: 31}},
	}
	if err := metrics.ObserveOperational(first); err != nil {
		t.Fatal(err)
	}
	assertGauge(t, metrics.OutboxLag.WithLabelValues("region-a", "payment-events"), 17)
	assertGauge(t, metrics.InTransitValue.WithLabelValues("region-a", "region-b", "USD"), 23)
	assertGauge(t, metrics.UnknownExternalEffects.WithLabelValues("card", "region-a"), 2)
	assertGauge(t, metrics.ReconciliationLag.WithLabelValues("region-a", "rail/card"), 31)

	if err := metrics.ObserveOperational(OperationalSnapshot{Region: "region-a"}); err != nil {
		t.Fatal(err)
	}
	assertGauge(t, metrics.OutboxLag.WithLabelValues("region-a", "payment-events"), 0)
	assertGauge(t, metrics.InTransitValue.WithLabelValues("region-a", "region-b", "USD"), 0)
	assertGauge(t, metrics.UnknownExternalEffects.WithLabelValues("card", "region-a"), 0)
	assertGauge(t, metrics.ReconciliationLag.WithLabelValues("region-a", "rail/card"), 0)
}

func TestInvalidOperationalSnapshotDoesNotReplacePreviousValues(t *testing.T) {
	metrics := NewFinancialMetrics(prometheus.NewRegistry())
	if err := metrics.ObserveOperational(OperationalSnapshot{
		Region: "region-a", OutboxLag: []OutboxLagSample{{Topic: "events", AgeSeconds: 5}},
	}); err != nil {
		t.Fatal(err)
	}
	err := metrics.ObserveOperational(OperationalSnapshot{
		Region: "region-a", OutboxLag: []OutboxLagSample{{Topic: "events", AgeSeconds: math.NaN()}},
	})
	if err == nil {
		t.Fatal("NaN gauge was accepted")
	}
	assertGauge(t, metrics.OutboxLag.WithLabelValues("region-a", "events"), 5)
}
