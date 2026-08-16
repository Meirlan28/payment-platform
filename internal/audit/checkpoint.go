package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrCheckpointRace     = errors.New("audit: checkpoint predecessor changed; recompute and resign")
	ErrCheckpointConflict = errors.New("audit: checkpoint key already contains different evidence")
	ErrCheckpointEvidence = errors.New("audit: stored checkpoint does not match verified journal evidence")
)

type Checkpoint struct {
	BookID                 string
	FirstSequence          int64
	LastSequence           int64
	LeafCount              int64
	MerkleRoot             [32]byte
	LastEntryHash          [32]byte
	PreviousCheckpointRoot *[32]byte
	Signature              []byte
	SigningKeyID           string
	CreatedAt              time.Time
}

// CheckpointSigner is implemented in production by an HSM/KMS signing API.
// Private key bytes never need to enter this process.
type CheckpointSigner interface {
	Sign(context.Context, string, []byte) ([]byte, error)
	Verify(context.Context, string, []byte, []byte) error
}

type Checkpointer struct {
	DB     *pgxpool.Pool
	Signer CheckpointSigner
}

func (c Checkpointer) Create(ctx context.Context, bookID string, first, last int64, keyID string) (Checkpoint, error) {
	if c.DB == nil || c.Signer == nil || bookID == "" || keyID == "" || first <= 0 || last < first {
		return Checkpoint{}, errors.New("audit: invalid checkpoint request")
	}
	if existing, err := loadCheckpoint(ctx, c.DB, bookID, last); err == nil {
		if existing.FirstSequence != first || existing.SigningKeyID != keyID {
			return Checkpoint{}, ErrCheckpointConflict
		}
		if err := c.Verify(ctx, existing); err != nil {
			return Checkpoint{}, err
		}
		return existing, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Checkpoint{}, err
	}
	previous, previousLast, previousEntry, err := c.latest(ctx, bookID)
	if err != nil {
		return Checkpoint{}, err
	}
	if previousLast == 0 {
		if first != 1 {
			return Checkpoint{}, ErrSequenceGap
		}
		previousEntry = ledger.GenesisHash(bookID)
	} else if first != previousLast+1 {
		return Checkpoint{}, ErrSequenceGap
	}
	requested := Range{BookID: bookID, First: first, Last: last, ExpectedPrev: previousEntry}
	transactions, err := (SQLReader{DB: c.DB}).LoadRange(ctx, requested)
	if err != nil {
		return Checkpoint{}, err
	}
	verification, err := VerifyRange(requested, transactions)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint := Checkpoint{
		BookID: bookID, FirstSequence: first, LastSequence: last,
		LeafCount: int64(verification.Count), MerkleRoot: verification.Merkle,
		LastEntryHash: verification.LastHash, PreviousCheckpointRoot: previous,
		SigningKeyID: keyID,
	}
	payload, err := checkpoint.Payload()
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint.Signature, err = c.Signer.Sign(ctx, keyID, payload)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: sign checkpoint: %w", err)
	}
	if len(checkpoint.Signature) == 0 {
		return Checkpoint{}, errors.New("audit: signer returned an empty signature")
	}
	// Fail closed before making an immutable row durable. A broken or
	// misconfigured remote signer must not permanently poison the checkpoint
	// chain with evidence that cannot be verified.
	if err := c.Verify(ctx, checkpoint); err != nil {
		return Checkpoint{}, err
	}

	tx, err := c.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Checkpoint{}, err
	}
	defer tx.Rollback(ctx)
	var lockedBook string
	if err := tx.QueryRow(ctx, `SELECT book_id FROM books WHERE book_id=$1 FOR UPDATE`, bookID).Scan(&lockedBook); err != nil {
		return Checkpoint{}, err
	}
	currentPrevious, currentLast, currentEntry, err := latestInTx(ctx, tx, bookID)
	if err != nil {
		return Checkpoint{}, err
	}
	if currentLast != previousLast || !optionalHashEqual(currentPrevious, previous) ||
		currentLast > 0 && currentEntry != previousEntry {
		return Checkpoint{}, ErrCheckpointRace
	}

	var previousBytes any
	if checkpoint.PreviousCheckpointRoot != nil {
		previousBytes = checkpoint.PreviousCheckpointRoot[:]
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO audit.merkle_checkpoints
 (book_id, first_sequence, last_sequence, leaf_count, merkle_root,
  last_entry_hash, previous_checkpoint_root, signature, signing_key_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (book_id,last_sequence) DO NOTHING`, checkpoint.BookID,
		checkpoint.FirstSequence, checkpoint.LastSequence, checkpoint.LeafCount,
		checkpoint.MerkleRoot[:], checkpoint.LastEntryHash[:], previousBytes,
		checkpoint.Signature, checkpoint.SigningKeyID)
	if err != nil {
		return Checkpoint{}, err
	}
	if tag.RowsAffected() == 0 {
		stored, err := loadCheckpoint(ctx, tx, bookID, last)
		if err != nil {
			return Checkpoint{}, err
		}
		if !checkpointEqual(stored, checkpoint) {
			return Checkpoint{}, ErrCheckpointConflict
		}
		checkpoint = stored
	}
	if err := tx.Commit(ctx); err != nil {
		return Checkpoint{}, err
	}
	checkpoint, err = loadCheckpoint(ctx, c.DB, bookID, last)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := c.Verify(ctx, checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func (c Checkpointer) Verify(ctx context.Context, checkpoint Checkpoint) error {
	if c.Signer == nil {
		return errors.New("audit: checkpoint verifier is required")
	}
	payload, err := checkpoint.Payload()
	if err != nil {
		return err
	}
	if err := c.Signer.Verify(ctx, checkpoint.SigningKeyID, payload, checkpoint.Signature); err != nil {
		return fmt.Errorf("audit: invalid checkpoint signature: %w", err)
	}
	return nil
}

// VerifyStored replays the exact persisted closed range, including canonical
// metadata bytes and the ledger hash chain, before a checkpoint is exported.
// This is intentionally repeated after a crash: a durable checkpoint receipt
// alone never causes unverified bytes to be copied to WORM.
func (c Checkpointer) VerifyStored(ctx context.Context, checkpoint Checkpoint) error {
	if c.DB == nil {
		return errors.New("audit: checkpoint database is required")
	}
	if err := c.Verify(ctx, checkpoint); err != nil {
		return err
	}
	var expectedPrevious [32]byte
	if checkpoint.FirstSequence == 1 {
		if checkpoint.PreviousCheckpointRoot != nil {
			return ErrCheckpointEvidence
		}
		expectedPrevious = ledger.GenesisHash(checkpoint.BookID)
	} else {
		previous, err := loadCheckpoint(ctx, c.DB, checkpoint.BookID, checkpoint.FirstSequence-1)
		if err != nil {
			return fmt.Errorf("%w: predecessor: %v", ErrCheckpointEvidence, err)
		}
		if checkpoint.PreviousCheckpointRoot == nil ||
			*checkpoint.PreviousCheckpointRoot != previous.MerkleRoot {
			return ErrCheckpointEvidence
		}
		expectedPrevious = previous.LastEntryHash
	}
	requested := Range{
		BookID: checkpoint.BookID, First: checkpoint.FirstSequence,
		Last: checkpoint.LastSequence, ExpectedPrev: expectedPrevious,
	}
	transactions, err := (SQLReader{DB: c.DB}).LoadRange(ctx, requested)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCheckpointEvidence, err)
	}
	verified, err := VerifyRange(requested, transactions)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCheckpointEvidence, err)
	}
	if int64(verified.Count) != checkpoint.LeafCount ||
		verified.Merkle != checkpoint.MerkleRoot ||
		verified.LastHash != checkpoint.LastEntryHash {
		return ErrCheckpointEvidence
	}
	return nil
}

func (c Checkpoint) Payload() ([]byte, error) {
	if c.BookID == "" || c.FirstSequence <= 0 || c.LastSequence < c.FirstSequence ||
		c.LeafCount != c.LastSequence-c.FirstSequence+1 || c.SigningKeyID == "" {
		return nil, errors.New("audit: invalid checkpoint")
	}
	var buffer bytes.Buffer
	buffer.WriteString("payment-platform/audit-checkpoint/v1\x00")
	writeCheckpointString(&buffer, c.BookID)
	_ = binary.Write(&buffer, binary.BigEndian, c.FirstSequence)
	_ = binary.Write(&buffer, binary.BigEndian, c.LastSequence)
	_ = binary.Write(&buffer, binary.BigEndian, c.LeafCount)
	buffer.Write(c.MerkleRoot[:])
	buffer.Write(c.LastEntryHash[:])
	if c.PreviousCheckpointRoot == nil {
		buffer.WriteByte(0)
	} else {
		buffer.WriteByte(1)
		buffer.Write(c.PreviousCheckpointRoot[:])
	}
	writeCheckpointString(&buffer, c.SigningKeyID)
	return buffer.Bytes(), nil
}

func writeCheckpointString(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	buffer.WriteString(value)
}

func (c Checkpointer) latest(ctx context.Context, bookID string) (*[32]byte, int64, [32]byte, error) {
	return latestQuery(ctx, c.DB, bookID)
}

func latestInTx(ctx context.Context, tx pgx.Tx, bookID string) (*[32]byte, int64, [32]byte, error) {
	return latestQuery(ctx, tx, bookID)
}

type checkpointQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func latestQuery(ctx context.Context, query checkpointQuerier, bookID string) (*[32]byte, int64, [32]byte, error) {
	var last int64
	var root, entry []byte
	err := query.QueryRow(ctx, `
SELECT last_sequence, merkle_root, last_entry_hash
FROM audit.merkle_checkpoints
WHERE book_id=$1 ORDER BY last_sequence DESC LIMIT 1`, bookID).Scan(&last, &root, &entry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, [32]byte{}, nil
	}
	if err != nil {
		return nil, 0, [32]byte{}, err
	}
	if len(root) != sha256.Size || len(entry) != sha256.Size {
		return nil, 0, [32]byte{}, errors.New("audit: corrupt checkpoint digest")
	}
	var rootHash, entryHash [32]byte
	copy(rootHash[:], root)
	copy(entryHash[:], entry)
	return &rootHash, last, entryHash, nil
}

func loadCheckpoint(ctx context.Context, query checkpointQuerier, bookID string, last int64) (Checkpoint, error) {
	var result Checkpoint
	var root, entry, previous []byte
	err := query.QueryRow(ctx, `
SELECT book_id, first_sequence, last_sequence, leaf_count, merkle_root,
       last_entry_hash, previous_checkpoint_root, signature, signing_key_id,
       created_at
FROM audit.merkle_checkpoints WHERE book_id=$1 AND last_sequence=$2`, bookID, last).Scan(
		&result.BookID, &result.FirstSequence, &result.LastSequence, &result.LeafCount,
		&root, &entry, &previous, &result.Signature, &result.SigningKeyID,
		&result.CreatedAt)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(root) != sha256.Size || len(entry) != sha256.Size || len(previous) != 0 && len(previous) != sha256.Size {
		return Checkpoint{}, errors.New("audit: corrupt checkpoint digest")
	}
	copy(result.MerkleRoot[:], root)
	copy(result.LastEntryHash[:], entry)
	if len(previous) != 0 {
		var hash [32]byte
		copy(hash[:], previous)
		result.PreviousCheckpointRoot = &hash
	}
	result.Signature = append([]byte(nil), result.Signature...)
	return result, nil
}

func optionalHashEqual(left, right *[32]byte) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func checkpointEqual(left, right Checkpoint) bool {
	return left.BookID == right.BookID && left.FirstSequence == right.FirstSequence &&
		left.LastSequence == right.LastSequence && left.LeafCount == right.LeafCount &&
		left.MerkleRoot == right.MerkleRoot && left.LastEntryHash == right.LastEntryHash &&
		optionalHashEqual(left.PreviousCheckpointRoot, right.PreviousCheckpointRoot) &&
		left.SigningKeyID == right.SigningKeyID
}
