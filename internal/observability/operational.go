package observability

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OperationalSnapshot is a single read-only SERIALIZABLE database snapshot.
// Ages are calculated by CockroachDB, never by an application host clock.
// Unlike financial invariant gauges, these values describe work in progress
// and are therefore allowed to be eventually consistent between regions.
type OperationalSnapshot struct {
	Region          string
	OutboxLag       []OutboxLagSample
	InTransit       []InTransitSample
	UnknownExternal []UnknownExternalSample
	Reconciliation  []ReconciliationLagSample
}

type OutboxLagSample struct {
	Topic      string
	AgeSeconds float64
}

type InTransitSample struct {
	SourceRegion      string
	DestinationRegion string
	Asset             string
	AmountAtoms       float64
}

type UnknownExternalSample struct {
	Rail  string
	Count float64
}

type ReconciliationLagSample struct {
	Counterparty string
	AgeSeconds   float64
}

// OperationalCollector reads only protocol state granted to the
// reconciliation_runtime role. It cannot post or repair a financial fact.
type OperationalCollector struct {
	pool    *pgxpool.Pool
	metrics *FinancialMetrics
}

func NewOperationalCollector(pool *pgxpool.Pool, metrics *FinancialMetrics) (*OperationalCollector, error) {
	if pool == nil || metrics == nil {
		return nil, errors.New("observability: database pool and financial metrics are required")
	}
	return &OperationalCollector{pool: pool, metrics: metrics}, nil
}

func (c *OperationalCollector) Collect(ctx context.Context, region string) error {
	if c == nil || c.pool == nil || c.metrics == nil {
		return errors.New("observability: operational collector is not configured")
	}
	if err := validateMetricLabel("region", region); err != nil {
		return err
	}
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("observability: begin operational snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	snapshot := OperationalSnapshot{Region: region}
	if snapshot.OutboxLag, err = readOutboxLag(ctx, tx); err != nil {
		return err
	}
	if snapshot.InTransit, err = readInTransit(ctx, tx); err != nil {
		return err
	}
	if snapshot.UnknownExternal, err = readUnknownExternal(ctx, tx); err != nil {
		return err
	}
	if snapshot.Reconciliation, err = readReconciliationLag(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("observability: commit operational snapshot: %w", err)
	}
	return c.metrics.ObserveOperational(snapshot)
}

func (m *FinancialMetrics) ObserveOperational(snapshot OperationalSnapshot) error {
	if m == nil {
		return nil
	}
	if err := validateMetricLabel("region", snapshot.Region); err != nil {
		return err
	}
	if len(snapshot.OutboxLag) > maxMetricSeries || len(snapshot.InTransit) > maxMetricSeries ||
		len(snapshot.UnknownExternal) > maxMetricSeries || len(snapshot.Reconciliation) > maxMetricSeries {
		return fmt.Errorf("observability: operational snapshot exceeds %d series per metric", maxMetricSeries)
	}
	for _, sample := range snapshot.OutboxLag {
		if err := validateMetricLabel("topic", sample.Topic); err != nil {
			return err
		}
		if err := validateGaugeValue("outbox lag", sample.AgeSeconds); err != nil {
			return err
		}
	}
	for _, sample := range snapshot.InTransit {
		if err := validateMetricLabels(map[string]string{
			"source_region": sample.SourceRegion, "destination_region": sample.DestinationRegion,
			"asset": sample.Asset,
		}); err != nil {
			return err
		}
		if err := validateGaugeValue("in-transit value", sample.AmountAtoms); err != nil {
			return err
		}
	}
	for _, sample := range snapshot.UnknownExternal {
		if err := validateMetricLabel("rail", sample.Rail); err != nil {
			return err
		}
		if err := validateGaugeValue("unknown external count", sample.Count); err != nil {
			return err
		}
	}
	for _, sample := range snapshot.Reconciliation {
		if err := validateMetricLabel("counterparty", sample.Counterparty); err != nil {
			return err
		}
		if err := validateGaugeValue("reconciliation lag", sample.AgeSeconds); err != nil {
			return err
		}
	}

	// Deleting every old vector child before publishing the new snapshot is
	// essential: resolved work must not remain as a false alarm forever.
	m.OutboxLag.Reset()
	m.InTransitValue.Reset()
	m.UnknownExternalEffects.Reset()
	m.ReconciliationLag.Reset()
	for _, sample := range snapshot.OutboxLag {
		m.OutboxLag.WithLabelValues(snapshot.Region, sample.Topic).Set(sample.AgeSeconds)
	}
	for _, sample := range snapshot.InTransit {
		m.InTransitValue.WithLabelValues(sample.SourceRegion, sample.DestinationRegion, sample.Asset).Set(sample.AmountAtoms)
	}
	for _, sample := range snapshot.UnknownExternal {
		m.UnknownExternalEffects.WithLabelValues(sample.Rail, snapshot.Region).Set(sample.Count)
	}
	for _, sample := range snapshot.Reconciliation {
		m.ReconciliationLag.WithLabelValues(snapshot.Region, sample.Counterparty).Set(sample.AgeSeconds)
	}
	return nil
}

func readOutboxLag(ctx context.Context, tx pgx.Tx) ([]OutboxLagSample, error) {
	rows, err := tx.Query(ctx, `
SELECT topic,
       greatest(0, extract(epoch FROM transaction_timestamp()-min(created_at)))::FLOAT8
  FROM outbox_messages
 WHERE status <> 'PUBLISHED'
 GROUP BY topic
 ORDER BY topic
 LIMIT $1`, maxMetricSeries+1)
	if err != nil {
		return nil, fmt.Errorf("observability: query outbox lag: %w", err)
	}
	defer rows.Close()
	result := make([]OutboxLagSample, 0)
	for rows.Next() {
		var sample OutboxLagSample
		if err := rows.Scan(&sample.Topic, &sample.AgeSeconds); err != nil {
			return nil, fmt.Errorf("observability: scan outbox lag: %w", err)
		}
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: read outbox lag: %w", err)
	}
	return checkedSeries("outbox lag", result)
}

func readInTransit(ctx context.Context, tx pgx.Tx) ([]InTransitSample, error) {
	rows, err := tx.Query(ctx, `
SELECT source_region, destination_region, asset_id, sum(amount)::STRING
  FROM escrow_transfers
 WHERE status='IN_TRANSIT'
 GROUP BY source_region, destination_region, asset_id
 ORDER BY source_region, destination_region, asset_id
 LIMIT $1`, maxMetricSeries+1)
	if err != nil {
		return nil, fmt.Errorf("observability: query in-transit authority: %w", err)
	}
	defer rows.Close()
	result := make([]InTransitSample, 0)
	for rows.Next() {
		var sample InTransitSample
		var amount string
		if err := rows.Scan(&sample.SourceRegion, &sample.DestinationRegion, &sample.Asset, &amount); err != nil {
			return nil, fmt.Errorf("observability: scan in-transit authority: %w", err)
		}
		value, err := parseNonNegativeFloat("in-transit authority", amount)
		if err != nil {
			return nil, err
		}
		sample.AmountAtoms = value
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: read in-transit authority: %w", err)
	}
	return checkedSeries("in-transit authority", result)
}

func readUnknownExternal(ctx context.Context, tx pgx.Tx) ([]UnknownExternalSample, error) {
	rows, err := tx.Query(ctx, `
SELECT rail, count(*)::FLOAT8
  FROM external_attempts
 WHERE status IN ('IN_FLIGHT','UNKNOWN')
 GROUP BY rail
 ORDER BY rail
 LIMIT $1`, maxMetricSeries+1)
	if err != nil {
		return nil, fmt.Errorf("observability: query unknown external effects: %w", err)
	}
	defer rows.Close()
	result := make([]UnknownExternalSample, 0)
	for rows.Next() {
		var sample UnknownExternalSample
		if err := rows.Scan(&sample.Rail, &sample.Count); err != nil {
			return nil, fmt.Errorf("observability: scan unknown external effects: %w", err)
		}
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: read unknown external effects: %w", err)
	}
	return checkedSeries("unknown external effects", result)
}

func readReconciliationLag(ctx context.Context, tx pgx.Tx) ([]ReconciliationLagSample, error) {
	rows, err := tx.Query(ctx, `
SELECT counterparty, max(age_seconds)::FLOAT8
  FROM (
        SELECT 'region/' || destination_region AS counterparty,
               greatest(0, extract(epoch FROM transaction_timestamp()-created_at)) AS age_seconds
          FROM escrow_transfers
         WHERE status='IN_TRANSIT'
		UNION ALL
		SELECT 'rail/' || rail AS counterparty,
		       greatest(0, extract(epoch FROM transaction_timestamp()-created_at)) AS age_seconds
          FROM external_attempts
         WHERE status IN ('IN_FLIGHT','UNKNOWN')
            OR (status='SUCCEEDED' AND NOT EXISTS (
                  SELECT 1 FROM ledger_transactions AS journal
                   WHERE journal.operation_id=external_attempts.operation_id
                     AND journal.status='POSTED'))
       ) AS pending
 GROUP BY counterparty
 ORDER BY counterparty
 LIMIT $1`, maxMetricSeries+1)
	if err != nil {
		return nil, fmt.Errorf("observability: query reconciliation lag: %w", err)
	}
	defer rows.Close()
	result := make([]ReconciliationLagSample, 0)
	for rows.Next() {
		var sample ReconciliationLagSample
		if err := rows.Scan(&sample.Counterparty, &sample.AgeSeconds); err != nil {
			return nil, fmt.Errorf("observability: scan reconciliation lag: %w", err)
		}
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: read reconciliation lag: %w", err)
	}
	return checkedSeries("reconciliation lag", result)
}

func checkedSeries[T any](name string, values []T) ([]T, error) {
	if len(values) > maxMetricSeries {
		return nil, fmt.Errorf("observability: %s exceeds %d series", name, maxMetricSeries)
	}
	return values, nil
}

func validateGaugeValue(name string, value float64) error {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("observability: invalid %s gauge value", name)
	}
	return nil
}
