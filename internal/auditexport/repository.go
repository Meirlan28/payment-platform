package auditexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/example/payment-platform/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrManifestConflict = errors.New("audit export: canonical manifest conflict")

type BookHead struct {
	BookID             string
	ClosedLastSequence int64
	CheckpointedLast   int64
}

type Receipt struct {
	SinkID            string
	BookID            string
	LastSequence      int64
	ObjectKey         string
	ContentSHA256     [32]byte
	Bucket            string
	EndpointAuthority string
	ProviderIdentity  string
	VersionID         string
	ETag              string
	RetentionUntil    time.Time
}

type Repository struct {
	DB *pgxpool.Pool
}

func (r Repository) Ping(ctx context.Context) error {
	if r.DB == nil {
		return errors.New("audit export: database is required")
	}
	return r.DB.Ping(ctx)
}

func (r Repository) ListBooks(ctx context.Context) ([]BookHead, error) {
	if r.DB == nil {
		return nil, errors.New("audit export: database is required")
	}
	rows, err := r.DB.Query(ctx, `
SELECT book.book_id, book.next_sequence_no-1,
       coalesce(max(checkpoint.last_sequence), 0)
  FROM books AS book
  LEFT JOIN audit.merkle_checkpoints AS checkpoint
    ON checkpoint.book_id=book.book_id
 GROUP BY book.book_id, book.next_sequence_no
 ORDER BY book.book_id`)
	if err != nil {
		return nil, fmt.Errorf("audit export: enumerate books: %w", err)
	}
	defer rows.Close()
	var result []BookHead
	for rows.Next() {
		var head BookHead
		if err := rows.Scan(&head.BookID, &head.ClosedLastSequence, &head.CheckpointedLast); err != nil {
			return nil, fmt.Errorf("audit export: scan book: %w", err)
		}
		if head.ClosedLastSequence < 0 || head.CheckpointedLast < 0 ||
			head.CheckpointedLast > head.ClosedLastSequence {
			return nil, errors.New("audit export: corrupt book/checkpoint watermark")
		}
		result = append(result, head)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit export: enumerate books: %w", err)
	}
	return result, nil
}

func (r Repository) EnsureManifest(ctx context.Context, artifact Artifact) (Artifact, error) {
	if r.DB == nil || artifact.BookID == "" || artifact.LastSequence <= 0 ||
		artifact.Format != ManifestFormat || artifact.ObjectKey == "" ||
		len(artifact.Bytes) == 0 || artifact.RetainUntil.IsZero() ||
		sha256.Sum256(artifact.Bytes) != artifact.SHA256 {
		return Artifact{}, errors.New("audit export: invalid manifest artifact")
	}
	_, err := r.DB.Exec(ctx, `
INSERT INTO audit.checkpoint_manifests
       (book_id, last_sequence, manifest_format, object_key, manifest_bytes,
        content_sha256, retention_until)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (book_id,last_sequence) DO NOTHING`, artifact.BookID,
		artifact.LastSequence, artifact.Format, artifact.ObjectKey,
		artifact.Bytes, artifact.SHA256[:], artifact.RetainUntil)
	if err != nil {
		return Artifact{}, fmt.Errorf("audit export: persist manifest: %w", err)
	}
	stored, err := r.LoadManifest(ctx, artifact.BookID, artifact.LastSequence)
	if err != nil {
		return Artifact{}, err
	}
	if !artifactEqual(stored, artifact) {
		return Artifact{}, ErrManifestConflict
	}
	return stored, nil
}

func (r Repository) LoadManifest(ctx context.Context, bookID string, last int64) (Artifact, error) {
	var artifact Artifact
	var digest []byte
	err := r.DB.QueryRow(ctx, `
SELECT book_id, last_sequence, manifest_format, object_key, manifest_bytes,
       content_sha256, retention_until
  FROM audit.checkpoint_manifests
 WHERE book_id=$1 AND last_sequence=$2`, bookID, last).Scan(
		&artifact.BookID, &artifact.LastSequence, &artifact.Format,
		&artifact.ObjectKey, &artifact.Bytes, &digest, &artifact.RetainUntil)
	if err != nil {
		return Artifact{}, fmt.Errorf("audit export: load manifest: %w", err)
	}
	if len(digest) != sha256.Size {
		return Artifact{}, errors.New("audit export: corrupt manifest digest")
	}
	copy(artifact.SHA256[:], digest)
	artifact.Bytes = append([]byte(nil), artifact.Bytes...)
	if sha256.Sum256(artifact.Bytes) != artifact.SHA256 {
		return Artifact{}, errors.New("audit export: manifest bytes do not match digest")
	}
	return artifact, nil
}

func (r Repository) HasReceipt(ctx context.Context, sinkID, bookID string, last int64) (bool, error) {
	var exists bool
	err := r.DB.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM audit.worm_export_receipts
   WHERE sink_id=$1 AND book_id=$2 AND last_sequence=$3
)`, sinkID, bookID, last).Scan(&exists)
	return exists, err
}

func (r Repository) LoadReceipt(ctx context.Context, sinkID, bookID string, last int64) (Receipt, error) {
	var receipt Receipt
	var digest []byte
	err := r.DB.QueryRow(ctx, `
SELECT sink_id, book_id, last_sequence, object_key, content_sha256,
       bucket, endpoint_authority, provider_identity, object_version_id,
       etag, retention_until
  FROM audit.worm_export_receipts
 WHERE sink_id=$1 AND book_id=$2 AND last_sequence=$3`,
		sinkID, bookID, last).Scan(
		&receipt.SinkID, &receipt.BookID, &receipt.LastSequence,
		&receipt.ObjectKey, &digest, &receipt.Bucket,
		&receipt.EndpointAuthority, &receipt.ProviderIdentity,
		&receipt.VersionID, &receipt.ETag, &receipt.RetentionUntil)
	if err != nil {
		return Receipt{}, err
	}
	if len(digest) != sha256.Size {
		return Receipt{}, errors.New("audit export: corrupt WORM receipt digest")
	}
	copy(receipt.ContentSHA256[:], digest)
	return receipt, nil
}

func (r Repository) RecordReceipt(ctx context.Context, receipt Receipt) error {
	if receipt.SinkID == "" || receipt.BookID == "" || receipt.LastSequence <= 0 ||
		receipt.ObjectKey == "" || receipt.Bucket == "" ||
		receipt.EndpointAuthority == "" || receipt.ProviderIdentity == "" ||
		receipt.VersionID == "" || receipt.ETag == "" || receipt.RetentionUntil.IsZero() {
		return errors.New("audit export: incomplete WORM receipt")
	}
	_, err := r.DB.Exec(ctx, `
INSERT INTO audit.worm_export_receipts
       (sink_id, book_id, last_sequence, object_key, content_sha256,
        checksum_algorithm, bucket, endpoint_authority, provider_identity,
        object_version_id, etag, object_lock_mode, retention_until)
VALUES ($1,$2,$3,$4,$5,'SHA256',$6,$7,$8,$9,$10,'COMPLIANCE',$11)
ON CONFLICT (sink_id,book_id,last_sequence) DO NOTHING`,
		receipt.SinkID, receipt.BookID, receipt.LastSequence, receipt.ObjectKey,
		receipt.ContentSHA256[:], receipt.Bucket, receipt.EndpointAuthority,
		receipt.ProviderIdentity, receipt.VersionID, receipt.ETag,
		receipt.RetentionUntil)
	if err != nil {
		return fmt.Errorf("audit export: persist WORM receipt: %w", err)
	}
	var stored Receipt
	var digest []byte
	err = r.DB.QueryRow(ctx, `
SELECT sink_id, book_id, last_sequence, object_key, content_sha256,
       bucket, endpoint_authority, provider_identity, object_version_id,
       etag, retention_until
  FROM audit.worm_export_receipts
 WHERE sink_id=$1 AND book_id=$2 AND last_sequence=$3`,
		receipt.SinkID, receipt.BookID, receipt.LastSequence).Scan(
		&stored.SinkID, &stored.BookID, &stored.LastSequence, &stored.ObjectKey,
		&digest, &stored.Bucket, &stored.EndpointAuthority,
		&stored.ProviderIdentity, &stored.VersionID, &stored.ETag,
		&stored.RetentionUntil)
	if err != nil {
		return fmt.Errorf("audit export: load WORM receipt: %w", err)
	}
	if len(digest) != sha256.Size {
		return errors.New("audit export: corrupt WORM receipt digest")
	}
	copy(stored.ContentSHA256[:], digest)
	if !receiptEqual(stored, receipt) {
		return ErrManifestConflict
	}
	return nil
}

func (r Repository) RecordConflict(ctx context.Context, conflict *ConflictError) error {
	if conflict == nil {
		return errors.New("audit export: conflict evidence is required")
	}
	incidentID := conflict.IncidentID()
	var observed any
	if conflict.ObservedSHA256 != nil {
		observed = conflict.ObservedSHA256[:]
	}
	_, err := r.DB.Exec(ctx, `
INSERT INTO audit.worm_export_incidents
       (incident_id, incident_kind, sink_id, book_id, last_sequence,
        object_key, expected_sha256, observed_sha256)
VALUES ($1,'OBJECT_CONFLICT',$2,$3,$4,$5,$6,$7)
ON CONFLICT (incident_id) DO NOTHING`, incidentID[:], conflict.SinkID,
		conflict.BookID, conflict.LastSequence, conflict.ObjectKey,
		conflict.ExpectedSHA256[:], observed)
	if err != nil {
		return fmt.Errorf("audit export: persist P0 WORM conflict: %w", err)
	}
	return nil
}

func (r Repository) LatestCheckpoint(ctx context.Context, bookID string) (int64, error) {
	var last int64
	err := r.DB.QueryRow(ctx, `
SELECT coalesce(max(last_sequence),0)
  FROM audit.merkle_checkpoints WHERE book_id=$1`, bookID).Scan(&last)
	return last, err
}

func (r Repository) PendingCheckpoints(ctx context.Context, bookID, firstSink, secondSink string, limit int) ([]audit.Checkpoint, error) {
	if bookID == "" || firstSink == "" || secondSink == "" ||
		firstSink == secondSink || limit <= 0 || limit > 1024 {
		return nil, errors.New("audit export: invalid pending-checkpoint query")
	}
	rows, err := r.DB.Query(ctx, `
SELECT checkpoint.book_id, checkpoint.first_sequence,
       checkpoint.last_sequence, checkpoint.leaf_count,
       checkpoint.merkle_root, checkpoint.last_entry_hash,
       checkpoint.previous_checkpoint_root, checkpoint.signature,
       checkpoint.signing_key_id, checkpoint.created_at
  FROM audit.merkle_checkpoints AS checkpoint
 WHERE checkpoint.book_id=$1
   AND (NOT EXISTS (
          SELECT 1 FROM audit.worm_export_receipts AS receipt
           WHERE receipt.sink_id=$2
             AND receipt.book_id=checkpoint.book_id
             AND receipt.last_sequence=checkpoint.last_sequence)
        OR NOT EXISTS (
          SELECT 1 FROM audit.worm_export_receipts AS receipt
           WHERE receipt.sink_id=$3
             AND receipt.book_id=checkpoint.book_id
             AND receipt.last_sequence=checkpoint.last_sequence))
 ORDER BY checkpoint.last_sequence
 LIMIT $4`, bookID, firstSink, secondSink, limit)
	if err != nil {
		return nil, fmt.Errorf("audit export: query pending checkpoints: %w", err)
	}
	defer rows.Close()
	var result []audit.Checkpoint
	for rows.Next() {
		checkpoint, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, checkpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit export: query pending checkpoints: %w", err)
	}
	return result, nil
}

func (r Repository) ExportedLast(ctx context.Context, sinkID, bookID string) (int64, error) {
	var last int64
	err := r.DB.QueryRow(ctx, `
SELECT coalesce(max(last_sequence),0)
  FROM audit.worm_export_receipts
 WHERE sink_id=$1 AND book_id=$2`, sinkID, bookID).Scan(&last)
	return last, err
}

func (r Repository) LoadCheckpoint(ctx context.Context, bookID string, last int64) (audit.Checkpoint, error) {
	return scanCheckpoint(r.DB.QueryRow(ctx, `
SELECT book_id, first_sequence, last_sequence, leaf_count, merkle_root,
       last_entry_hash, previous_checkpoint_root, signature, signing_key_id,
       created_at
  FROM audit.merkle_checkpoints
 WHERE book_id=$1 AND last_sequence=$2`, bookID, last))
}

func (r Repository) NextHistoricalCheckpoint(ctx context.Context, bookID string, after, before int64) (audit.Checkpoint, bool, error) {
	if bookID == "" || after < 0 || before <= 1 {
		return audit.Checkpoint{}, false, nil
	}
	query := func(minimum int64) (audit.Checkpoint, error) {
		return scanCheckpoint(r.DB.QueryRow(ctx, `
SELECT book_id, first_sequence, last_sequence, leaf_count, merkle_root,
       last_entry_hash, previous_checkpoint_root, signature, signing_key_id,
       created_at
  FROM audit.merkle_checkpoints
 WHERE book_id=$1 AND last_sequence>$2 AND last_sequence<$3
 ORDER BY last_sequence LIMIT 1`, bookID, minimum, before))
	}
	checkpoint, err := query(after)
	if errors.Is(err, pgx.ErrNoRows) && after != 0 {
		checkpoint, err = query(0)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return audit.Checkpoint{}, false, nil
	}
	if err != nil {
		return audit.Checkpoint{}, false, err
	}
	return checkpoint, true, nil
}

type checkpointScanner interface {
	Scan(...any) error
}

func scanCheckpoint(scanner checkpointScanner) (audit.Checkpoint, error) {
	var checkpoint audit.Checkpoint
	var merkle, entry, previous []byte
	if err := scanner.Scan(
		&checkpoint.BookID, &checkpoint.FirstSequence,
		&checkpoint.LastSequence, &checkpoint.LeafCount,
		&merkle, &entry, &previous, &checkpoint.Signature,
		&checkpoint.SigningKeyID, &checkpoint.CreatedAt,
	); err != nil {
		return audit.Checkpoint{}, fmt.Errorf("audit export: scan checkpoint: %w", err)
	}
	if len(merkle) != sha256.Size || len(entry) != sha256.Size ||
		(len(previous) != 0 && len(previous) != sha256.Size) {
		return audit.Checkpoint{}, errors.New("audit export: corrupt checkpoint digest")
	}
	copy(checkpoint.MerkleRoot[:], merkle)
	copy(checkpoint.LastEntryHash[:], entry)
	if len(previous) != 0 {
		var digest [32]byte
		copy(digest[:], previous)
		checkpoint.PreviousCheckpointRoot = &digest
	}
	checkpoint.Signature = append([]byte(nil), checkpoint.Signature...)
	return checkpoint, nil
}

func artifactEqual(left, right Artifact) bool {
	return left.BookID == right.BookID && left.LastSequence == right.LastSequence &&
		left.Format == right.Format && left.ObjectKey == right.ObjectKey &&
		bytes.Equal(left.Bytes, right.Bytes) && left.SHA256 == right.SHA256 &&
		left.RetainUntil.Equal(right.RetainUntil)
}

func receiptEqual(left, right Receipt) bool {
	return left.SinkID == right.SinkID && left.BookID == right.BookID &&
		left.LastSequence == right.LastSequence && left.ObjectKey == right.ObjectKey &&
		left.ContentSHA256 == right.ContentSHA256 && left.Bucket == right.Bucket &&
		left.EndpointAuthority == right.EndpointAuthority &&
		left.ProviderIdentity == right.ProviderIdentity &&
		left.VersionID == right.VersionID && left.ETag == right.ETag &&
		left.RetentionUntil.Equal(right.RetentionUntil)
}
