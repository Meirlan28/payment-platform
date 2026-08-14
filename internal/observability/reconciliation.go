package observability

import (
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/prometheus/client_golang/prometheus"
)

// ReconciliationMetrics is fed only by a completed, persisted reconciliation
// report. It never presents a live read from one replica as proof that a
// financial invariant holds.
type ReconciliationMetrics struct {
	Runs              *prometheus.CounterVec
	CycleErrors       prometheus.Counter
	LatestSafe        prometheus.Gauge
	CurrentFindings   *prometheus.GaugeVec
	VerifiedWatermark *prometheus.GaugeVec
	InvariantFailures *prometheus.CounterVec
}

func NewReconciliationMetrics(registerer prometheus.Registerer) *ReconciliationMetrics {
	m := &ReconciliationMetrics{
		Runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "runs_total",
			Help: "Durably completed reconciliation runs by terminal result.",
		}, []string{"result"}),
		CycleErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "cycle_errors_total",
			Help: "Reconciliation cycles that could not persist a complete report.",
		}),
		LatestSafe: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "latest_safe",
			Help: "One only when the latest durable report contains no P0 finding.",
		}),
		CurrentFindings: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "current_findings",
			Help: "Findings in the latest durable report, with bounded category labels.",
		}, []string{"severity", "category"}),
		VerifiedWatermark: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "verified_watermark",
			Help: "Highest book sequence included in the latest consistent reconciliation snapshot.",
		}, []string{"book"}),
		InvariantFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Name: "financial_invariant_violation_total",
			Help: "P0 financial invariant findings emitted by durable reconciliation.",
		}, []string{"invariant", "severity"}),
	}
	registerer.MustRegister(m.Runs, m.CycleErrors, m.LatestSafe, m.CurrentFindings,
		m.VerifiedWatermark, m.InvariantFailures)
	for _, result := range []string{"PASSED", "FAILED"} {
		m.Runs.WithLabelValues(result)
	}
	return m
}

func (m *ReconciliationMetrics) Observe(report reconciliation.Report) {
	if m == nil {
		return
	}
	m.CurrentFindings.Reset()
	m.VerifiedWatermark.Reset()
	counts := make(map[[2]string]float64)
	for _, finding := range report.Findings {
		key := [2]string{string(finding.Severity), string(finding.Category)}
		counts[key]++
		if finding.Severity == reconciliation.SeverityP0 {
			m.InvariantFailures.WithLabelValues(string(finding.Category), "P0").Inc()
		}
	}
	for key, count := range counts {
		m.CurrentFindings.WithLabelValues(key[0], key[1]).Set(count)
	}
	for book, watermark := range report.Watermarks {
		m.VerifiedWatermark.WithLabelValues(book).Set(float64(watermark))
	}
	if report.Safe() {
		m.LatestSafe.Set(1)
	} else {
		m.LatestSafe.Set(0)
	}
	m.Runs.WithLabelValues(report.Status).Inc()
}
