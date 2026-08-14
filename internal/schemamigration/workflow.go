package schemamigration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

const (
	defaultBatchSize = 1000
	maxBatchSize     = 10000
	digestDomain     = "payment-platform/reference-projection/v1\x00"
)

type Workflow struct {
	transactions *store.Runner
	batchSize    int
}

func NewWorkflow(transactions *store.Runner, batchSize int) (*Workflow, error) {
	if transactions == nil || transactions.DB == nil {
		return nil, errors.New("schema migration: transaction runner is required")
	}
	if batchSize == 0 {
		batchSize = defaultBatchSize
	}
	if batchSize < 1 || batchSize > maxBatchSize {
		return nil, fmt.Errorf("schema migration: batch size must be between 1 and %d", maxBatchSize)
	}
	return &Workflow{transactions: transactions, batchSize: batchSize}, nil
}

// Start captures a per-book sequence/hash watermark in the same SERIALIZABLE
// transaction that advances the durable generation to SHADOWING. A retry after
// an ambiguous result returns the already active generation.
func (w *Workflow) Start(ctx context.Context, expectedStateVersion int64) (Status, error) {
	var result Status
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		current, err := loadStatus(ctx, tx, true)
		if err != nil {
			return err
		}
		if current.Phase != PhaseExpanded {
			// There is only one ledger-reference-v2 rollout. Returning its active
			// state makes a start retry safe after an unknown COMMIT outcome.
			result = current
			return nil
		}
		if current.StateVersion != expectedStateVersion {
			return ErrStaleState
		}

		generation := current.ActiveGeneration + 1
		if _, err := tx.Exec(ctx, `
INSERT INTO reference_migration_runs
    (migration_name, generation, phase, started_from_version)
VALUES ($1,$2,'SHADOWING',$3)`, ReferenceMigration, generation, expectedStateVersion); err != nil {
			return err
		}

		rows, err := tx.Query(ctx, `
SELECT book_id, next_sequence_no - 1, last_entry_hash
FROM books
ORDER BY book_id`)
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
			var next watermark
			if err := rows.Scan(&next.bookID, &next.sequence, &next.hash); err != nil {
				rows.Close()
				return err
			}
			if len(next.hash) != sha256.Size {
				rows.Close()
				return ErrWatermarkCorrupt
			}
			next.hash = bytes.Clone(next.hash)
			watermarks = append(watermarks, next)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, mark := range watermarks {
			completed := mark.sequence == 0
			if _, err := tx.Exec(ctx, `
INSERT INTO reference_migration_book_watermarks (
    migration_name, generation, book_id, watermark_sequence_no,
    watermark_entry_hash, next_sequence_no, completed
) VALUES ($1,$2,$3,$4,$5,1,$6)`, ReferenceMigration, generation,
				mark.bookID, mark.sequence, mark.hash, completed); err != nil {
				return err
			}
		}

		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_control
SET active_generation=$1, phase='SHADOWING', state_version=state_version+1,
    updated_at=transaction_timestamp()
WHERE migration_name=$2 AND phase='EXPANDED' AND state_version=$3`,
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

// BackfillOnce claims one book cursor and projects at most batchSize immutable
// POSTED headers. Progress and projection inserts commit atomically. Repeating
// a batch can only validate an identical row; it never overwrites a mismatch.
func (w *Workflow) BackfillOnce(ctx context.Context, generation int64) (BackfillReport, error) {
	result := BackfillReport{Generation: generation, Batches: 1}
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		current, err := loadStatus(ctx, tx, false)
		if err != nil {
			return err
		}
		if current.ActiveGeneration != generation {
			return ErrWrongGeneration
		}
		if phaseAtLeast(current.Phase, PhaseVerified) {
			result.Complete = true
			result.Batches = 0
			return nil
		}
		if current.Phase != PhaseShadowing {
			return ErrWrongPhase
		}

		var bookID string
		var watermark, cursor int64
		err = tx.QueryRow(ctx, `
SELECT book_id, watermark_sequence_no, next_sequence_no
FROM reference_migration_book_watermarks
WHERE migration_name=$1 AND generation=$2 AND completed=false
ORDER BY book_id
LIMIT 1
FOR UPDATE SKIP LOCKED`, ReferenceMigration, generation).Scan(&bookID, &watermark, &cursor)
		if errors.Is(err, pgx.ErrNoRows) {
			// With concurrent workers, SKIP LOCKED can yield no row while a
			// different worker still owns unfinished work. Distinguish that
			// state from a genuinely complete generation.
			var pending int64
			if err := tx.QueryRow(ctx, `
SELECT count(*) FROM reference_migration_book_watermarks
WHERE migration_name=$1 AND generation=$2 AND completed=false`,
				ReferenceMigration, generation).Scan(&pending); err != nil {
				return err
			}
			result.Complete = pending == 0
			result.Batches = 0
			return nil
		}
		if err != nil {
			return err
		}
		result.BookID = bookID

		rows, err := tx.Query(ctx, `
SELECT sequence_no, transaction_id, reference_transaction_id, schema_version
FROM ledger_transactions
WHERE book_id=$1 AND status='POSTED'
  AND sequence_no >= $2 AND sequence_no <= $3
ORDER BY sequence_no
LIMIT $4`, bookID, cursor, watermark, w.batchSize)
		if err != nil {
			return err
		}
		type sourceRow struct {
			sequence      int64
			transactionID string
			reference     sql.NullString
			schemaVersion int64
		}
		var source []sourceRow
		for rows.Next() {
			var next sourceRow
			if err := rows.Scan(&next.sequence, &next.transactionID, &next.reference, &next.schemaVersion); err != nil {
				rows.Close()
				return err
			}
			source = append(source, next)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(source) == 0 {
			return fmt.Errorf("%w: missing posted sequence %d in book %s", ErrWatermarkCorrupt, cursor, bookID)
		}
		for index, item := range source {
			expectedSequence := cursor + int64(index)
			if item.sequence != expectedSequence {
				return fmt.Errorf("%w: book %s expected sequence %d, found %d",
					ErrWatermarkCorrupt, bookID, expectedSequence, item.sequence)
			}
			if !item.reference.Valid {
				continue
			}
			if err := insertOrValidateProjection(ctx, tx, item.transactionID,
				item.reference.String, item.schemaVersion); err != nil {
				return err
			}
			result.ReferencesSeen++
		}

		result.RowsScanned = int64(len(source))
		lastSequence := source[len(source)-1].sequence
		if len(source) < w.batchSize && lastSequence != watermark {
			return fmt.Errorf("%w: book %s stopped at %d before watermark %d",
				ErrWatermarkCorrupt, bookID, lastSequence, watermark)
		}
		nextCursor := lastSequence + 1
		bookComplete := nextCursor == watermark+1
		tag, err := tx.Exec(ctx, `
UPDATE reference_migration_book_watermarks
SET next_sequence_no=$1,
    referenced_rows_scanned=referenced_rows_scanned+$2,
    completed=$3, updated_at=transaction_timestamp()
WHERE migration_name=$4 AND generation=$5 AND book_id=$6
  AND next_sequence_no=$7 AND completed=false`, nextCursor, result.ReferencesSeen,
			bookComplete, ReferenceMigration, generation, bookID, cursor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStaleState
		}
		var pending int64
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM reference_migration_book_watermarks
WHERE migration_name=$1 AND generation=$2 AND completed=false`,
			ReferenceMigration, generation).Scan(&pending); err != nil {
			return err
		}
		result.Complete = pending == 0
		return nil
	})
	return result, err
}

// Backfill repeatedly executes bounded transactions. maxBatches=0 means run
// until the captured watermark is complete; a job may use a positive limit to
// yield predictably and let another worker continue.
func (w *Workflow) Backfill(ctx context.Context, generation, maxBatches int64) (BackfillReport, error) {
	total := BackfillReport{Generation: generation}
	for maxBatches == 0 || total.Batches < maxBatches {
		next, err := w.BackfillOnce(ctx, generation)
		if err != nil {
			return total, err
		}
		total.Batches += next.Batches
		total.RowsScanned += next.RowsScanned
		total.ReferencesSeen += next.ReferencesSeen
		total.BookID = next.BookID
		total.Complete = next.Complete
		if next.Complete {
			return total, nil
		}
		if next.Batches == 0 {
			// Another worker holds the remaining cursor. Yield to the job
			// controller instead of spinning inside this process.
			return total, nil
		}
	}
	return total, nil
}

func insertOrValidateProjection(ctx context.Context, tx pgx.Tx, transactionID, referenceID string, schemaVersion int64) error {
	tag, err := tx.Exec(ctx, `
INSERT INTO ledger_transaction_references_shadow
    (transaction_id, reference_type, reference_id, source_schema_version)
VALUES ($1,$2,$3,$4)
ON CONFLICT (transaction_id) DO NOTHING`, transactionID, ReferenceType, referenceID, schemaVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var storedType, storedID string
	var storedVersion int64
	if err := tx.QueryRow(ctx, `
SELECT reference_type, reference_id, source_schema_version
FROM ledger_transaction_references_shadow
WHERE transaction_id=$1`, transactionID).Scan(&storedType, &storedID, &storedVersion); err != nil {
		return err
	}
	if storedType != ReferenceType || storedID != referenceID || storedVersion != schemaVersion {
		return fmt.Errorf("%w: transaction %s", ErrProjectionMismatch, transactionID)
	}
	return nil
}

func (w *Workflow) Status(ctx context.Context) (Status, error) {
	var result Status
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var err error
		result, err = loadStatus(ctx, tx, false)
		return err
	})
	return result, err
}

// ReadReference is the reference read contract used during rollout. Before
// cutover it reads the immutable legacy header. After the durable generation
// CAS it reads only the verified projection. This makes the control row, not a
// process-local feature flag or wall clock, authoritative.
func (w *Workflow) ReadReference(ctx context.Context, transactionID string) (Reference, error) {
	if transactionID == "" {
		return Reference{}, errors.New("schema migration: transaction id is required")
	}
	var result Reference
	err := w.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		status, err := loadStatus(ctx, tx, false)
		if err != nil {
			return err
		}
		result.TransactionID = transactionID
		result.ReadGeneration = status.ReadGeneration
		var referenceType, referenceID sql.NullString
		if status.ReadGeneration == 0 {
			err = tx.QueryRow(ctx, `
SELECT schema_version, 'LEDGER_TRANSACTION', reference_transaction_id
FROM ledger_transactions
WHERE transaction_id=$1 AND status='POSTED'`, transactionID).Scan(
				&result.SourceSchemaVersion, &referenceType, &referenceID)
		} else {
			err = tx.QueryRow(ctx, `
SELECT t.schema_version, p.reference_type, p.reference_id
FROM ledger_transactions AS t
LEFT JOIN ledger_transaction_references_shadow AS p
  ON p.transaction_id=t.transaction_id
WHERE t.transaction_id=$1 AND t.status='POSTED'`, transactionID).Scan(
				&result.SourceSchemaVersion, &referenceType, &referenceID)
		}
		if err != nil {
			return err
		}
		if referenceID.Valid {
			if !referenceType.Valid {
				return ErrProjectionMismatch
			}
			result.ReferenceType = referenceType.String
			result.ReferenceID = referenceID.String
			result.Found = true
		}
		return nil
	})
	return result, err
}

func loadStatus(ctx context.Context, tx pgx.Tx, forUpdate bool) (Status, error) {
	query := `
SELECT migration_name, active_generation, read_generation, phase,
       state_version, updated_at
FROM reference_migration_control
WHERE migration_name=$1`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var result Status
	var phase string
	err := tx.QueryRow(ctx, query, ReferenceMigration).Scan(
		&result.MigrationName, &result.ActiveGeneration, &result.ReadGeneration,
		&phase, &result.StateVersion, &result.UpdatedAt)
	result.Phase = Phase(phase)
	return result, err
}

type digestRow struct {
	bookID        string
	sequence      int64
	transactionID string
	referenceType string
	referenceID   string
	schemaVersion int64
}

func writeDigestRow(destination hash.Hash, row digestRow) {
	var raw [8]byte
	for _, value := range []string{row.bookID, row.transactionID, row.referenceType, row.referenceID} {
		binary.BigEndian.PutUint64(raw[:], uint64(len(value)))
		_, _ = destination.Write(raw[:])
		_, _ = destination.Write([]byte(value))
	}
	binary.BigEndian.PutUint64(raw[:], uint64(row.sequence))
	_, _ = destination.Write(raw[:])
	binary.BigEndian.PutUint64(raw[:], uint64(row.schemaVersion))
	_, _ = destination.Write(raw[:])
}

func streamDigest(rows pgx.Rows) (int64, [32]byte, error) {
	digest := sha256.New()
	_, _ = digest.Write([]byte(digestDomain))
	var count int64
	for rows.Next() {
		var row digestRow
		if err := rows.Scan(&row.bookID, &row.sequence, &row.transactionID,
			&row.referenceType, &row.referenceID, &row.schemaVersion); err != nil {
			rows.Close()
			return 0, [32]byte{}, err
		}
		writeDigestRow(digest, row)
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, [32]byte{}, err
	}
	rows.Close()
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return count, result, nil
}
