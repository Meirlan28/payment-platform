package observability

import (
	"fmt"

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
}

func NewReconciliationMetrics(registerer prometheus.Registerer) *ReconciliationMetrics {
	m := &ReconciliationMetrics{
		Runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "runs_total",
			Help: "Durably completed reconciliation runs by terminal result.",
		}, []string{"result"}),
		CycleErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "reconciliation", Name: "cycle_errors_total",
			Help: "Reconciliation cycles that could not persist and export a complete report/snapshot.",
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
	}
	registerer.MustRegister(m.Runs, m.CycleErrors, m.LatestSafe, m.CurrentFindings,
		m.VerifiedWatermark)
	for _, result := range []string{"PASSED", "FAILED"} {
		m.Runs.WithLabelValues(result)
	}
	return m
}

func (m *ReconciliationMetrics) Observe(report reconciliation.Report) error {
	if m == nil {
		return nil
	}
	if report.Status != "PASSED" && report.Status != "FAILED" {
		return fmt.Errorf("observability: reconciliation report has non-terminal status %q", report.Status)
	}
	if (report.Status == "PASSED") != report.Safe() {
		return fmt.Errorf("observability: reconciliation status %q disagrees with P0 findings", report.Status)
	}
	counts := make(map[[2]string]float64)
	for _, finding := range report.Findings {
		if err := validateMetricLabels(map[string]string{
			"severity": string(finding.Severity), "category": string(finding.Category),
		}); err != nil {
			return err
		}
		key := [2]string{string(finding.Severity), string(finding.Category)}
		counts[key]++
	}
	if len(counts) > maxMetricSeries || len(report.Watermarks) > maxMetricSeries {
		return fmt.Errorf("observability: reconciliation report exceeds %d metric series", maxMetricSeries)
	}
	for book, watermark := range report.Watermarks {
		if err := validateMetricLabel("book", book); err != nil {
			return err
		}
		if watermark < 0 {
			return fmt.Errorf("observability: negative verified watermark for book %q", book)
		}
	}

	// Reset after validation so an invalid/corrupt report cannot partially
	// replace the last known-good metric snapshot.
	m.CurrentFindings.Reset()
	m.VerifiedWatermark.Reset()
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
	return nil
}
