package auditexport

import (
	"context"

	"github.com/example/payment-platform/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	CheckpointLagEntries *prometheus.GaugeVec
	ExportLagEntries     *prometheus.GaugeVec
	SinkReady            *prometheus.GaugeVec
	WorkerReady          prometheus.Gauge
	SignatureFailures    prometheus.Counter
	ExportFailures       *prometheus.CounterVec
	WORMConflicts        *prometheus.CounterVec
	Cycles               *prometheus.CounterVec
}

func NewMetrics(registerer prometheus.Registerer) *Metrics {
	metrics := &Metrics{
		CheckpointLagEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "audit", Name: "checkpoint_lag_entries",
			Help: "Closed ledger entries not yet covered by a signed checkpoint.",
		}, []string{"book"}),
		ExportLagEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "audit", Name: "export_lag_entries",
			Help: "Checkpointed ledger entries not yet receipted by a WORM sink.",
		}, []string{"sink", "book"}),
		SinkReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "audit", Name: "worm_sink_ready",
			Help: "Whether workload identity, versioning, and COMPLIANCE retention checks passed.",
		}, []string{"sink"}),
		WorkerReady: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "payments", Subsystem: "audit", Name: "worker_ready",
			Help: "Whether DB, HSM, both WORM sinks, and lag gates are healthy.",
		}),
		SignatureFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "audit", Name: "signature_failures_total",
			Help: "Vault Transit sign or verify failures.",
		}),
		ExportFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "audit", Name: "worm_export_failures_total",
			Help: "WORM export/probe failures excluding immutable conflicts.",
		}, []string{"sink"}),
		WORMConflicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "audit", Name: "worm_conflicts_total",
			Help: "P0 immutable-object conflicts at deterministic audit keys.",
		}, []string{"sink"}),
		Cycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "audit", Name: "cycles_total",
			Help: "Completed scheduler cycles by result.",
		}, []string{"result"}),
	}
	if registerer != nil {
		registerer.MustRegister(
			metrics.CheckpointLagEntries, metrics.ExportLagEntries,
			metrics.SinkReady, metrics.WorkerReady, metrics.SignatureFailures,
			metrics.ExportFailures, metrics.WORMConflicts, metrics.Cycles,
		)
	}
	return metrics
}

func (m *Metrics) ExportFailure(sinkID string) {
	if m != nil {
		m.ExportFailures.WithLabelValues(sinkID).Inc()
	}
}

func (m *Metrics) WORMConflict(sinkID string) {
	if m != nil {
		m.WORMConflicts.WithLabelValues(sinkID).Inc()
	}
}

type ObservedSigner struct {
	Inner interface {
		audit.CheckpointSigner
		Health(context.Context) error
	}
	Metrics *Metrics
}

func (s ObservedSigner) Sign(ctx context.Context, key string, payload []byte) ([]byte, error) {
	signature, err := s.Inner.Sign(ctx, key, payload)
	if err != nil && s.Metrics != nil {
		s.Metrics.SignatureFailures.Inc()
	}
	return signature, err
}

func (s ObservedSigner) Verify(ctx context.Context, key string, payload, signature []byte) error {
	err := s.Inner.Verify(ctx, key, payload, signature)
	if err != nil && s.Metrics != nil {
		s.Metrics.SignatureFailures.Inc()
	}
	return err
}

func (s ObservedSigner) Health(ctx context.Context) error {
	err := s.Inner.Health(ctx)
	if err != nil && s.Metrics != nil {
		s.Metrics.SignatureFailures.Inc()
	}
	return err
}
