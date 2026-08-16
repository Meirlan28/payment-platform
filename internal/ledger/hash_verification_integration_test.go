//go:build integration

package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type hashVerificationFixture struct {
	journal  *Service
	pool     *pgxpool.Pool
	assetID  string
	bookID   string
	debitID  string
	creditID string
	suffix   string
}

func newHashVerificationFixture(t *testing.T) hashVerificationFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ids := &integrationIDs{prefix: fmt.Sprintf("hash-verify-%d", time.Now().UnixNano())}
	fixture := hashVerificationFixture{journal: NewService(store.NewRunner(pool), ids), pool: pool}
	fixture.suffix, _ = ids.Next(ctx)
	fixture.assetID = "asset-" + fixture.suffix
	fixture.bookID = "book-" + fixture.suffix
	fixture.debitID = "debit-" + fixture.suffix
	fixture.creditID = "credit-" + fixture.suffix
	if err := fixture.journal.RegisterAsset(ctx, Asset{
		AssetID: fixture.assetID, DisplayCode: "HASH-" + fixture.suffix, AtomicScale: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.journal.CreateBook(ctx, Book{
		BookID: fixture.bookID, LegalEntityID: "entity", Jurisdiction: "KZ",
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{AccountID: fixture.debitID, BookID: fixture.bookID, AssetID: fixture.assetID, AccountType: "ASSET", NormalSide: Debit},
		{AccountID: fixture.creditID, BookID: fixture.bookID, AssetID: fixture.assetID, AccountType: "LIABILITY", NormalSide: Credit},
	} {
		if err := fixture.journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (f hashVerificationFixture) posting(id string, metadata json.RawMessage) PostRequest {
	requestHash := sha256.Sum256([]byte("request-" + id))
	return PostRequest{
		TransactionID:      "transaction-" + id + "-" + f.suffix,
		BookID:             f.bookID,
		OperationID:        "operation-" + id + "-" + f.suffix,
		EffectID:           "effect-" + id + "-" + f.suffix,
		Kind:               "HASH_VERIFICATION_TEST",
		PostingRuleVersion: "hash-verification-v1",
		SchemaVersion:      1,
		RequestHash:        requestHash,
		Metadata:           metadata,
		Lines: []Line{
			{AccountID: f.debitID, AssetID: f.assetID, Side: Debit, AmountAtoms: NewAmountInt64(73), Memo: "плательщик 💳"},
			{AccountID: f.creditID, AssetID: f.assetID, Side: Credit, AmountAtoms: NewAmountInt64(73), Memo: "продавец 東京"},
		},
	}
}

func TestDatabaseVerifiesNestedUnicodeLedgerHash(t *testing.T) {
	ctx := context.Background()
	fixture := newHashVerificationFixture(t)
	request := fixture.posting("unicode", json.RawMessage(
		`{"z":[{"emoji":"💳","escaped":"\u0434"}],"a":{"decimal":1.20,"text":"Қазақстан"}}`,
	))
	request.Lines[0].AmountAtoms = MustAmount("99999999999999999999999999999999999999")
	request.Lines[1].AmountAtoms = MustAmount("99999999999999999999999999999999999999")
	canonical, err := CanonicalJSON(request.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := fixture.journal.Post(ctx, request)
	if err != nil {
		t.Fatalf("database rejected Go canonical ledger hash: %v", err)
	}

	var storedCanonical, storedEntry []byte
	if err := fixture.pool.QueryRow(ctx, `
SELECT canonical_metadata, entry_hash
FROM ledger_transactions WHERE transaction_id=$1`, request.TransactionID).Scan(
		&storedCanonical, &storedEntry); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedCanonical, canonical) {
		t.Fatalf("stored canonical bytes differ: got=%q want=%q", storedCanonical, canonical)
	}
	if !bytes.Equal(storedEntry, receipt.EntryHash[:]) {
		t.Fatal("durable entry hash differs from commit receipt")
	}
	loaded, err := fixture.journal.LoadTransaction(ctx, request.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	recomputed, err := CanonicalEntryHash(loaded.PrevHash[:], loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recomputed, storedEntry) {
		t.Fatal("independent Go audit fold differs from database-verified hash")
	}
}

func TestDatabaseRejectsMissingCanonicalBytesAndTamperedEntryHash(t *testing.T) {
	ctx := context.Background()
	fixture := newHashVerificationFixture(t)
	request := fixture.posting("tamper", json.RawMessage(`{"nested":{"value":"ёж"}}`))
	canonical, err := CanonicalJSON(request.Metadata)
	if err != nil {
		t.Fatal(err)
	}

	var sequence int64
	var previous []byte
	if err := fixture.pool.QueryRow(ctx, `
SELECT next_sequence_no, last_entry_hash FROM books WHERE book_id=$1`, fixture.bookID).Scan(
		&sequence, &previous); err != nil {
		t.Fatal(err)
	}
	bogus := sha256.Sum256([]byte("caller-controlled-but-wrong-entry-hash"))

	_, err = fixture.pool.Exec(ctx, `
INSERT INTO ledger_transactions (
 transaction_id, book_id, operation_id, effect_id, transaction_kind,
 posting_rule_version, schema_version, request_hash, metadata,
 sequence_no, prev_hash, entry_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::JSONB,$10,$11,$12)`,
		"missing-canonical-"+fixture.suffix, fixture.bookID,
		"missing-operation-"+fixture.suffix, "missing-effect-"+fixture.suffix,
		request.Kind, request.PostingRuleVersion, request.SchemaVersion,
		request.RequestHash[:], string(canonical), sequence, previous, bogus[:])
	if err == nil || !strings.Contains(err.Error(), "requires canonical metadata") {
		t.Fatalf("new INSERT without canonical bytes was not rejected: %v", err)
	}

	err = store.NewRunner(fixture.pool).RunSerializable(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
INSERT INTO ledger_transactions (
 transaction_id, book_id, operation_id, effect_id, transaction_kind,
 posting_rule_version, schema_version, request_hash, metadata, canonical_metadata,
 sequence_no, prev_hash, entry_hash
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::JSONB,$10,$11,$12,$13)`,
			request.TransactionID, request.BookID, request.OperationID, request.EffectID,
			request.Kind, request.PostingRuleVersion, request.SchemaVersion,
			request.RequestHash[:], string(canonical), canonical, sequence, previous, bogus[:]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
INSERT INTO ledger_lines
 (transaction_id,line_no,account_id,asset_id,side,amount_atoms,memo)
VALUES ($1,1,$2,$4,'DEBIT','73',$5),
       ($1,2,$3,$4,'CREDIT','73',$6)`,
			request.TransactionID, fixture.debitID, fixture.creditID, fixture.assetID,
			request.Lines[0].Memo, request.Lines[1].Memo)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a DRAFT written between the expand migration and writer rollout.
	// Enforcement must fail closed: operators drain these rows before 018 or
	// recover them explicitly; no unverified chain advance is permitted.
	if _, err := fixture.pool.Exec(ctx, `
UPDATE ledger_transactions SET canonical_metadata=NULL
WHERE transaction_id=$1 AND status='DRAFT'`, request.TransactionID); err != nil {
		t.Fatal(err)
	}
	var finalized *string
	err = fixture.pool.QueryRow(ctx, `SELECT public.finalize_ledger_transaction($1)`,
		request.TransactionID).Scan(&finalized)
	if err == nil || !strings.Contains(err.Error(), "finalization requires canonical metadata") {
		t.Fatalf("legacy DRAFT without canonical bytes did not fail closed: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `
UPDATE ledger_transactions SET canonical_metadata=$2
WHERE transaction_id=$1 AND status='DRAFT'`, request.TransactionID, canonical); err != nil {
		t.Fatal(err)
	}

	err = fixture.pool.QueryRow(ctx, `SELECT public.finalize_ledger_transaction($1)`,
		request.TransactionID).Scan(&finalized)
	if err == nil || !strings.Contains(err.Error(), "entry hash verification failed") {
		t.Fatalf("caller-supplied bogus entry hash was not rejected: %v", err)
	}

	var status string
	var nextSequence int64
	var chainHead []byte
	if err := fixture.pool.QueryRow(ctx, `
SELECT txn.status, book.next_sequence_no, book.last_entry_hash
FROM ledger_transactions AS txn
JOIN books AS book ON book.book_id=txn.book_id
WHERE txn.transaction_id=$1`, request.TransactionID).Scan(
		&status, &nextSequence, &chainHead); err != nil {
		t.Fatal(err)
	}
	if status != "DRAFT" || nextSequence != sequence || !bytes.Equal(chainHead, previous) {
		t.Fatalf("failed verification mutated money state: status=%s next=%d", status, nextSequence)
	}
	for _, accountID := range []string{fixture.debitID, fixture.creditID} {
		balance, err := fixture.journal.Balance(ctx, accountID)
		if err != nil {
			t.Fatal(err)
		}
		if !balance.CurrentBalanceAtoms.IsZero() {
			t.Fatalf("failed verification mutated balance %s: %s", accountID, balance.CurrentBalanceAtoms.String())
		}
	}
}
