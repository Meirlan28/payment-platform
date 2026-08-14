//go:build integration

package ledger

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLedgerWriterCanPostOnlyThroughGuardedTriggers(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ids := &integrationIDs{prefix: fmt.Sprintf("role-%d", time.Now().UnixNano())}
	journal := NewService(store.NewRunner(pool), ids)
	suffix, _ := ids.Next(ctx)
	assetID, bookID := "asset-"+suffix, "book-"+suffix
	debitID, creditID := "debit-"+suffix, "credit-"+suffix
	if err := journal.RegisterAsset(ctx, Asset{AssetID: assetID, DisplayCode: "ROLE-" + suffix, AtomicScale: 0}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, Book{BookID: bookID, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{AccountID: debitID, BookID: bookID, AssetID: assetID, AccountType: "ASSET", NormalSide: Debit},
		{AccountID: creditID, BookID: bookID, AssetID: assetID, AccountType: "LIABILITY", NormalSide: Credit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}

	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE ledger_writer`); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("runtime-role-post"))
	receipt, err := journal.PostInTx(ctx, tx, PostRequest{
		TransactionID: "transaction-" + suffix, BookID: bookID,
		OperationID: "operation-" + suffix, EffectID: "effect-" + suffix,
		Kind: "ROLE_TEST", PostingRuleVersion: "role-test-v1", SchemaVersion: 1,
		RequestHash: hash,
		Lines: []Line{
			{AccountID: debitID, AssetID: assetID, Side: Debit, AmountAtoms: NewAmountInt64(7)},
			{AccountID: creditID, AssetID: assetID, Side: Credit, AmountAtoms: NewAmountInt64(7)},
		},
	})
	if err != nil {
		t.Fatalf("ledger_writer guarded post failed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if receipt.SequenceNo != 1 || receipt.EntryHash == ([32]byte{}) {
		t.Fatalf("missing durable receipt: %#v", receipt)
	}
	// During expand/shadow/cutover, a reference-bearing POST must project in
	// the same transaction without granting ledger_writer access to the
	// migration control plane or the shadow table.
	projection, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer projection.Rollback(ctx)
	if _, err := projection.Exec(ctx, `UPDATE reference_migration_control
SET active_generation=1, read_generation=0, phase='SHADOWING', state_version=state_version+1
WHERE migration_name='ledger-reference-v2' AND phase='EXPANDED'`); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Exec(ctx, `SET LOCAL ROLE ledger_writer`); err != nil {
		t.Fatal(err)
	}
	projectedID := "transaction-reference-" + suffix
	referenceTransactionID := "transaction-" + suffix
	if _, err := journal.PostInTx(ctx, projection, PostRequest{
		TransactionID: projectedID, BookID: bookID,
		OperationID: "operation-reference-" + suffix, EffectID: "effect-reference-" + suffix,
		Kind: "ROLE_REFERENCE_TEST", ReferenceTransactionID: &referenceTransactionID,
		PostingRuleVersion: "role-test-v1", SchemaVersion: 1, RequestHash: hash,
		Lines: []Line{
			{AccountID: debitID, AssetID: assetID, Side: Debit, AmountAtoms: NewAmountInt64(3)},
			{AccountID: creditID, AssetID: assetID, Side: Credit, AmountAtoms: NewAmountInt64(3)},
		},
	}); err != nil {
		t.Fatalf("ledger_writer atomic reference projection failed: %v", err)
	}
	if _, err := projection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	var projectedReference string
	if err := projection.QueryRow(ctx, `SELECT reference_id
FROM ledger_transaction_references_shadow WHERE transaction_id=$1`, projectedID).Scan(&projectedReference); err != nil {
		t.Fatal(err)
	}
	if projectedReference != "transaction-"+suffix {
		t.Fatalf("wrong atomically projected reference: %q", projectedReference)
	}
	if err := projection.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"balance update": `UPDATE account_balances SET current_balance_atoms=999 WHERE account_id='` + creditID + `'`,
		"journal update": `UPDATE ledger_transactions SET metadata='{"tampered":true}' WHERE transaction_id='transaction-` + suffix + `'`,
	} {
		restricted, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := restricted.Exec(ctx, `SET LOCAL ROLE ledger_writer`); err != nil {
			_ = restricted.Rollback(ctx)
			t.Fatal(err)
		}
		if _, err := restricted.Exec(ctx, statement); err == nil {
			_ = restricted.Rollback(ctx)
			t.Fatalf("runtime writer unexpectedly permitted %s", name)
		}
		_ = restricted.Rollback(ctx)
	}
}
