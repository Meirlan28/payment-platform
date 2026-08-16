//go:build integration

package auditexport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/audit"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAppendOnlyManifestAndPerSinkCursor(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	bookID := "audit-integration-book-" + suffix
	genesis := ledger.GenesisHash(bookID)
	if _, err := db.Exec(ctx, `
INSERT INTO books(book_id,legal_entity_id,jurisdiction,last_entry_hash)
VALUES ($1,'audit-integration','KZ',$2)`, bookID, genesis[:]); err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	checkpoint := audit.Checkpoint{
		BookID: bookID, FirstSequence: 1, LastSequence: 1, LeafCount: 1,
		MerkleRoot: [32]byte{1}, LastEntryHash: [32]byte{2},
		Signature: []byte("vault:v1:test"), SigningKeyID: "audit-checkpoint",
		CreatedAt: created,
	}
	if _, err := db.Exec(ctx, `
INSERT INTO audit.merkle_checkpoints
       (book_id,first_sequence,last_sequence,leaf_count,merkle_root,
        last_entry_hash,signature,signing_key_id,created_at)
VALUES ($1,1,1,1,$2,$3,$4,$5,$6)`, bookID, checkpoint.MerkleRoot[:],
		checkpoint.LastEntryHash[:], checkpoint.Signature,
		checkpoint.SigningKeyID, created); err != nil {
		t.Fatal(err)
	}
	repository := Repository{DB: db}
	artifact, err := BuildManifest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err = repository.EnsureManifest(ctx, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.EnsureManifest(ctx, artifact); err != nil {
		t.Fatalf("same manifest retry failed: %v", err)
	}
	conflicting := artifact
	conflicting.ObjectKey += ".different"
	if _, err := repository.EnsureManifest(ctx, conflicting); !errors.Is(err, ErrManifestConflict) {
		t.Fatalf("expected immutable manifest conflict, got %v", err)
	}
	for _, sink := range []struct{ id, endpoint, bucket, identity string }{
		{"sink-a", "a.example", "bucket-a", "identity-a"},
		{"sink-b", "b.example", "bucket-b", "identity-b"},
	} {
		receipt := Receipt{
			SinkID: sink.id, BookID: bookID, LastSequence: 1,
			ObjectKey: artifact.ObjectKey, ContentSHA256: artifact.SHA256,
			Bucket: sink.bucket, EndpointAuthority: sink.endpoint,
			ProviderIdentity: sink.identity, VersionID: "version-1",
			ETag: "etag-1", RetentionUntil: artifact.RetainUntil.Add(time.Hour),
		}
		if err := repository.RecordReceipt(ctx, receipt); err != nil {
			t.Fatal(err)
		}
		if err := repository.RecordReceipt(ctx, receipt); err != nil {
			t.Fatalf("same receipt retry failed: %v", err)
		}
	}
	if _, err := db.Exec(ctx, `UPDATE audit.worm_export_receipts
SET etag='mutated' WHERE sink_id='sink-a' AND book_id=$1`, bookID); sqlState(err) == "" {
		t.Fatalf("append-only receipt accepted UPDATE: %v", err)
	}
	incident := &ConflictError{
		SinkID: "sink-a", BookID: bookID, LastSequence: 1,
		ObjectKey: artifact.ObjectKey, ExpectedSHA256: artifact.SHA256,
		Reason: "integration conflict",
	}
	if err := repository.RecordConflict(ctx, incident); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordConflict(ctx, incident); err != nil {
		t.Fatalf("same P0 incident retry failed: %v", err)
	}
}

func TestAuditCheckpointerRoleCannotMutateLedger(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	connection, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `SET ROLE audit_checkpointer_runtime`); err != nil {
		t.Fatal(err)
	}
	defer connection.Exec(ctx, `RESET ROLE`)
	if _, err := connection.Exec(ctx, `SELECT book_id FROM books LIMIT 1`); err != nil {
		t.Fatalf("role cannot audit books: %v", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE books SET jurisdiction=jurisdiction WHERE false`); sqlState(err) != "42501" {
		t.Fatalf("role unexpectedly has ledger UPDATE, state=%s err=%v", sqlState(err), err)
	}
	if _, err := connection.Exec(ctx, `SELECT payment_id FROM payment_operations LIMIT 1`); sqlState(err) != "42501" {
		t.Fatalf("role unexpectedly reads payments, state=%s err=%v", sqlState(err), err)
	}
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
