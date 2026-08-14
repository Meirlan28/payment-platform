package schemamigration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
)

// Verify performs an exact bidirectional set comparison and records two
// independently streamed SHA-256 digests at the closed per-book watermarks.
// Digests are audit artifacts; correctness does not rely on collision
// probability because the SQL anti-joins must also report zero mismatches.
func (w *Workflow) Verify(ctx context.Context, generation, expectedStateVersion int64) (Verification, Status, error) {
	var verification Verification
	var result Status
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		current, err := loadStatus(ctx, tx, true)
		if err != nil {
			return err
		}
		if current.ActiveGeneration != generation {
			return ErrWrongGeneration
		}
		if phaseAtLeast(current.Phase, PhaseVerified) {
			verification, err = loadVerification(ctx, tx, generation)
			result = current
			return err
		}
		if current.Phase != PhaseShadowing {
			return ErrWrongPhase
		}
		if current.StateVersion != expectedStateVersion {
			return ErrStaleState
		}

		verification, err = verifySnapshot(ctx, tx, generation)
		if err != nil {
			return err
		}
		runTag, err := tx.Exec(ctx, `
UPDATE reference_migration_runs
SET phase='VERIFIED', source_rows=$1, projected_rows=$2,
    source_digest=$3, projected_digest=$4,
    verified_at=transaction_timestamp()
WHERE migration_name=$5 AND generation=$6 AND phase='SHADOWING'`,
			verification.SourceRows, verification.ProjectedRows,
			verification.SourceDigest[:], verification.ProjectedDigest[:],
			ReferenceMigration, generation)
		if err != nil {
			return err
		}
		if runTag.RowsAffected() != 1 {
			return ErrStaleState
		}
		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_control
SET phase='VERIFIED', state_version=state_version+1,
    updated_at=transaction_timestamp()
WHERE migration_name=$1 AND active_generation=$2
  AND phase='SHADOWING' AND state_version=$3`,
			ReferenceMigration, generation, expectedStateVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStaleState
		}
		result, err = loadStatus(ctx, tx, false)
		return err
	})
	return verification, result, err
}

func verifySnapshot(ctx context.Context, tx pgx.Tx, generation int64) (Verification, error) {
	result := Verification{Generation: generation}
	var pending int64
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM reference_migration_book_watermarks
WHERE migration_name=$1 AND generation=$2 AND completed=false`,
		ReferenceMigration, generation).Scan(&pending); err != nil {
		return result, err
	}
	if pending != 0 {
		return result, fmt.Errorf("%w: %d books are not backfilled", ErrWrongPhase, pending)
	}
	if err := verifyWatermarkHeads(ctx, tx, generation); err != nil {
		return result, err
	}

	sourceRows, err := tx.Query(ctx, `
SELECT t.book_id, t.sequence_no, t.transaction_id,
       'LEDGER_TRANSACTION', t.reference_transaction_id, t.schema_version
FROM ledger_transactions AS t
JOIN reference_migration_book_watermarks AS w
  ON w.migration_name=$1 AND w.generation=$2 AND w.book_id=t.book_id
WHERE t.status='POSTED' AND t.sequence_no <= w.watermark_sequence_no
  AND t.reference_transaction_id IS NOT NULL
ORDER BY t.book_id, t.sequence_no, t.transaction_id`, ReferenceMigration, generation)
	if err != nil {
		return result, err
	}
	result.SourceRows, result.SourceDigest, err = streamDigest(sourceRows)
	if err != nil {
		return result, err
	}

	targetRows, err := tx.Query(ctx, `
SELECT t.book_id, t.sequence_no, t.transaction_id,
       p.reference_type, p.reference_id, p.source_schema_version
FROM ledger_transaction_references_shadow AS p
JOIN ledger_transactions AS t ON t.transaction_id=p.transaction_id
JOIN reference_migration_book_watermarks AS w
  ON w.migration_name=$1 AND w.generation=$2 AND w.book_id=t.book_id
WHERE t.status='POSTED' AND t.sequence_no <= w.watermark_sequence_no
ORDER BY t.book_id, t.sequence_no, t.transaction_id`, ReferenceMigration, generation)
	if err != nil {
		return result, err
	}
	result.ProjectedRows, result.ProjectedDigest, err = streamDigest(targetRows)
	if err != nil {
		return result, err
	}

	var mismatches int64
	if err := tx.QueryRow(ctx, `
WITH source_rows AS (
    SELECT t.transaction_id, t.reference_transaction_id, t.schema_version
    FROM ledger_transactions AS t
    JOIN reference_migration_book_watermarks AS w
      ON w.migration_name=$1 AND w.generation=$2 AND w.book_id=t.book_id
    WHERE t.status='POSTED' AND t.sequence_no <= w.watermark_sequence_no
      AND t.reference_transaction_id IS NOT NULL
), target_rows AS (
    SELECT p.transaction_id, p.reference_type, p.reference_id, p.source_schema_version
    FROM ledger_transaction_references_shadow AS p
    JOIN ledger_transactions AS t ON t.transaction_id=p.transaction_id
    JOIN reference_migration_book_watermarks AS w
      ON w.migration_name=$1 AND w.generation=$2 AND w.book_id=t.book_id
    WHERE t.status='POSTED' AND t.sequence_no <= w.watermark_sequence_no
)
SELECT count(*) FROM (
    SELECT s.transaction_id
    FROM source_rows AS s
    LEFT JOIN target_rows AS p ON p.transaction_id=s.transaction_id
    WHERE p.transaction_id IS NULL OR p.reference_type <> 'LEDGER_TRANSACTION'
       OR p.reference_id IS DISTINCT FROM s.reference_transaction_id
       OR p.source_schema_version IS DISTINCT FROM s.schema_version
    UNION ALL
    SELECT p.transaction_id
    FROM target_rows AS p
    LEFT JOIN source_rows AS s ON s.transaction_id=p.transaction_id
    WHERE s.transaction_id IS NULL
) AS differences`, ReferenceMigration, generation).Scan(&mismatches); err != nil {
		return result, err
	}
	if mismatches != 0 || result.SourceRows != result.ProjectedRows ||
		!bytes.Equal(result.SourceDigest[:], result.ProjectedDigest[:]) {
		return result, fmt.Errorf("%w: mismatches=%d source_rows=%d projected_rows=%d",
			ErrProjectionMismatch, mismatches, result.SourceRows, result.ProjectedRows)
	}
	return result, nil
}

func verifyWatermarkHeads(ctx context.Context, tx pgx.Tx, generation int64) error {
	rows, err := tx.Query(ctx, `
SELECT book_id, watermark_sequence_no, watermark_entry_hash
FROM reference_migration_book_watermarks
WHERE migration_name=$1 AND generation=$2
ORDER BY book_id`, ReferenceMigration, generation)
	if err != nil {
		return err
	}
	type watermark struct {
		bookID   string
		sequence int64
		hash     []byte
	}
	var watermarks []watermark
	for rows.Next() {
		var mark watermark
		if err := rows.Scan(&mark.bookID, &mark.sequence, &mark.hash); err != nil {
			rows.Close()
			return err
		}
		mark.hash = bytes.Clone(mark.hash)
		watermarks = append(watermarks, mark)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, mark := range watermarks {
		var actual []byte
		if mark.sequence == 0 {
			genesis := ledger.GenesisHash(mark.bookID)
			actual = genesis[:]
		} else {
			err := tx.QueryRow(ctx, `
SELECT entry_hash FROM ledger_transactions
WHERE book_id=$1 AND sequence_no=$2 AND status='POSTED'`,
				mark.bookID, mark.sequence).Scan(&actual)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: missing book=%s sequence=%d",
					ErrWatermarkCorrupt, mark.bookID, mark.sequence)
			}
			if err != nil {
				return err
			}
		}
		if len(mark.hash) != sha256.Size || !bytes.Equal(actual, mark.hash) {
			return fmt.Errorf("%w: book=%s sequence=%d",
				ErrWatermarkCorrupt, mark.bookID, mark.sequence)
		}
	}
	return nil
}

func loadVerification(ctx context.Context, tx pgx.Tx, generation int64) (Verification, error) {
	result := Verification{Generation: generation}
	var sourceDigest, projectedDigest []byte
	err := tx.QueryRow(ctx, `
SELECT source_rows, projected_rows, source_digest, projected_digest
FROM reference_migration_runs
WHERE migration_name=$1 AND generation=$2
  AND phase IN ('VERIFIED','CUTOVER','CONTRACTED')`,
		ReferenceMigration, generation).Scan(&result.SourceRows, &result.ProjectedRows,
		&sourceDigest, &projectedDigest)
	if err != nil {
		return result, err
	}
	if len(sourceDigest) != sha256.Size || len(projectedDigest) != sha256.Size {
		return result, ErrProjectionMismatch
	}
	copy(result.SourceDigest[:], sourceDigest)
	copy(result.ProjectedDigest[:], projectedDigest)
	return result, nil
}

// Cutover re-verifies the closed snapshot in the same transaction as the
// compare-and-swap that publishes read_generation. Readers switch only on this
// durable generation; no DNS, clock, or process-local flag is authoritative.
func (w *Workflow) Cutover(ctx context.Context, generation, expectedStateVersion int64) (Status, error) {
	var result Status
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		current, err := loadStatus(ctx, tx, true)
		if err != nil {
			return err
		}
		if current.ActiveGeneration != generation {
			return ErrWrongGeneration
		}
		if current.ReadGeneration == generation && phaseAtLeast(current.Phase, PhaseCutover) {
			result = current
			return nil
		}
		if current.Phase != PhaseVerified {
			return ErrWrongPhase
		}
		if current.StateVersion != expectedStateVersion {
			return ErrStaleState
		}
		stored, err := loadVerification(ctx, tx, generation)
		if err != nil {
			return err
		}
		currentVerification, err := verifySnapshot(ctx, tx, generation)
		if err != nil {
			return err
		}
		if stored.SourceRows != currentVerification.SourceRows ||
			stored.ProjectedRows != currentVerification.ProjectedRows ||
			stored.SourceDigest != currentVerification.SourceDigest ||
			stored.ProjectedDigest != currentVerification.ProjectedDigest {
			return ErrProjectionMismatch
		}
		var requiredConsumers int64
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM reference_migration_consumers
WHERE migration_name=$1 AND required`, ReferenceMigration).Scan(&requiredConsumers); err != nil {
			return err
		}
		if requiredConsumers == 0 {
			return fmt.Errorf("%w: register the complete required reader set before cutover", ErrContractBlocked)
		}
		runTag, err := tx.Exec(ctx, `
UPDATE reference_migration_runs
SET phase='CUTOVER', cutover_at=transaction_timestamp()
WHERE migration_name=$1 AND generation=$2 AND phase='VERIFIED'`,
			ReferenceMigration, generation)
		if err != nil {
			return err
		}
		if runTag.RowsAffected() != 1 {
			return ErrStaleState
		}
		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_control
SET read_generation=$1, phase='CUTOVER', state_version=state_version+1,
    updated_at=transaction_timestamp()
WHERE migration_name=$2 AND active_generation=$1 AND read_generation < $1
  AND phase='VERIFIED' AND state_version=$3`,
			generation, ReferenceMigration, expectedStateVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStaleState
		}
		result, err = loadStatus(ctx, tx, false)
		return err
	})
	return result, err
}

func (w *Workflow) RegisterConsumer(ctx context.Context, consumerID string, required bool) error {
	if consumerID == "" {
		return errors.New("schema migration: consumer id is required")
	}
	return w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		status, err := loadStatus(ctx, tx, false)
		if err != nil {
			return err
		}
		if phaseAtLeast(status.Phase, PhaseCutover) {
			return errors.New("schema migration: consumer set is frozen at cutover")
		}
		tag, err := tx.Exec(ctx, `
INSERT INTO reference_migration_consumers (migration_name, consumer_id, required)
VALUES ($1,$2,$3)
ON CONFLICT (migration_name, consumer_id) DO NOTHING`,
			ReferenceMigration, consumerID, required)
		if err != nil || tag.RowsAffected() == 1 {
			return err
		}
		var stored bool
		if err := tx.QueryRow(ctx, `
SELECT required FROM reference_migration_consumers
WHERE migration_name=$1 AND consumer_id=$2`, ReferenceMigration, consumerID).Scan(&stored); err != nil {
			return err
		}
		if stored != required {
			return errors.New("schema migration: consumer registration is immutable")
		}
		return nil
	})
}

func (w *Workflow) AcknowledgeConsumer(ctx context.Context, consumerID string, generation int64) error {
	if consumerID == "" || generation <= 0 {
		return errors.New("schema migration: consumer id and positive generation are required")
	}
	return w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		status, err := loadStatus(ctx, tx, false)
		if err != nil {
			return err
		}
		if generation > status.ActiveGeneration {
			return ErrWrongGeneration
		}
		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_consumers
SET acknowledged_generation=$1, acknowledged_at=transaction_timestamp()
WHERE migration_name=$2 AND consumer_id=$3
  AND acknowledged_generation < $1`, generation, ReferenceMigration, consumerID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var acknowledged int64
		err = tx.QueryRow(ctx, `
SELECT acknowledged_generation FROM reference_migration_consumers
WHERE migration_name=$1 AND consumer_id=$2`, ReferenceMigration, consumerID).Scan(&acknowledged)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("schema migration: consumer is not registered")
		}
		if err != nil {
			return err
		}
		if acknowledged < generation {
			return ErrStaleState
		}
		return nil
	})
}

// Contract retires the old read contract only after every required deployment
// consumer has acknowledged read_generation. The hash-covered legacy source
// column remains physically present for ten-year audit verification.
func (w *Workflow) Contract(ctx context.Context, generation, expectedStateVersion int64) (Status, error) {
	var result Status
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		current, err := loadStatus(ctx, tx, true)
		if err != nil {
			return err
		}
		if current.ActiveGeneration != generation || current.ReadGeneration != generation {
			return ErrWrongGeneration
		}
		if current.Phase == PhaseContracted {
			result = current
			return nil
		}
		if current.Phase != PhaseCutover {
			return ErrWrongPhase
		}
		if current.StateVersion != expectedStateVersion {
			return ErrStaleState
		}
		var required, unacknowledged int64
		if err := tx.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE required),
       count(*) FILTER (WHERE required AND acknowledged_generation < $2)
FROM reference_migration_consumers
WHERE migration_name=$1`, ReferenceMigration, generation).Scan(&required, &unacknowledged); err != nil {
			return err
		}
		if required == 0 || unacknowledged != 0 {
			return fmt.Errorf("%w: required=%d unacknowledged=%d",
				ErrContractBlocked, required, unacknowledged)
		}
		runTag, err := tx.Exec(ctx, `
UPDATE reference_migration_runs
SET phase='CONTRACTED', contracted_at=transaction_timestamp()
WHERE migration_name=$1 AND generation=$2 AND phase='CUTOVER'`,
			ReferenceMigration, generation)
		if err != nil {
			return err
		}
		if runTag.RowsAffected() != 1 {
			return ErrStaleState
		}
		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_control
SET phase='CONTRACTED', state_version=state_version+1,
    updated_at=transaction_timestamp()
WHERE migration_name=$1 AND active_generation=$2 AND read_generation=$2
  AND phase='CUTOVER' AND state_version=$3`,
			ReferenceMigration, generation, expectedStateVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStaleState
		}
		result, err = loadStatus(ctx, tx, false)
		return err
	})
	return result, err
}
