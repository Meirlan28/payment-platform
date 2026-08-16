//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type rolloutIDs struct{ next int64 }

func (ids *rolloutIDs) Next(context.Context) (string, error) {
	ids.next++
	return "capture-rollout-id-" + ledger.NewAmountInt64(ids.next).String(), nil
}

// The first backfill in 021 is intentionally not treated as the contract.
// This regression creates another legacy capture after 021 and proves 022
// closes the entire mixed-version window before raw insert is revoked.
func TestPaymentCaptureExpandContractClosesOldWriterWindow(t *testing.T) {
	base := os.Getenv("DATABASE_URL")
	if base == "" {
		t.Skip("DATABASE_URL is required")
	}
	ctx := context.Background()
	databaseName := "capture_rollout_" + randomHex(t, 8)
	admin, err := pgxpool.New(ctx, databaseURLWithName(t, base, "defaultdb"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+databaseName+` CASCADE`)
		admin.Close()
	})

	migrationsDirectory, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", databaseURLWithName(t, base, databaseName))
	t.Setenv("MIGRATIONS_DIR", migrationsDirectory)
	t.Setenv("MIGRATION_TARGET_VERSION", "020_runtime_privilege_contract.sql")
	t.Setenv("MIGRATION_APPLY_ALL_ACK", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, logger); err != nil {
		t.Fatal(err)
	}

	pool, err := pgxpool.New(ctx, databaseURLWithName(t, base, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	runner := store.NewRunner(pool)
	journal := ledger.NewService(runner, &rolloutIDs{})
	asset, book := "asset-rollout", "book-rollout"
	available, held := "available-rollout", "held-rollout"
	merchant, funding := "merchant-rollout", "funding-rollout"
	if err := journal.RegisterAsset(ctx, ledger.Asset{AssetID: asset, DisplayCode: "ROL", AtomicScale: 0}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{BookID: book, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: available, BookID: book, AssetID: asset, AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: held, BookID: book, AssetID: asset, AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: merchant, BookID: book, AssetID: asset, AccountType: "MERCHANT", NormalSide: ledger.Credit},
		{AccountID: funding, BookID: book, AssetID: asset, AccountType: "CASH", NormalSide: ledger.Debit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	post := func(transactionID, effectID, kind string, amount int64, debit, credit string, reference *string) {
		t.Helper()
		hash := sha256.Sum256([]byte(effectID))
		if _, err := journal.Post(ctx, ledger.PostRequest{
			TransactionID: transactionID, BookID: book,
			OperationID: "operation-" + effectID, EffectID: effectID, Kind: kind,
			ReferenceTransactionID: reference, PostingRuleVersion: "rollout-v1",
			SchemaVersion: 1, RequestHash: hash,
			Metadata: []byte(`{"payment_id":"payment-rollout"}`),
			Lines: []ledger.Line{
				{AccountID: debit, AssetID: asset, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(amount)},
				{AccountID: credit, AssetID: asset, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(amount)},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	post("fund-transaction", "fund-effect", "DEPOSIT", 100, funding, available, nil)
	post("hold-transaction", "hold-effect", "HOLD", 100, available, held, nil)
	if _, err := pool.Exec(ctx, `
INSERT INTO payment_operations (
 payment_id,idempotency_scope,idempotency_key,asset_id,
 customer_available_account_id,customer_held_account_id,merchant_account_id,
 state,authorized_atoms)
VALUES ('payment-rollout','legacy/hold','hold-key',$1,$2,$3,$4,'HELD',100)`,
		asset, available, held, merchant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO holds (
 hold_id,payment_id,authorization_transaction_id,authorization_atoms)
VALUES ('hold-rollout','payment-rollout','hold-transaction',100)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO payment_effects (
 payment_effect_id,payment_id,effect_kind,amount_atoms,ledger_transaction_id)
VALUES ('hold-effect','payment-rollout','HOLD',100,'hold-transaction')`); err != nil {
		t.Fatal(err)
	}
	holdReference := "hold-transaction"
	post("capture-a-transaction", "capture-a-effect", "CAPTURE", 40, held, merchant, &holdReference)
	if _, err := pool.Exec(ctx, `UPDATE payment_operations
SET captured_atoms=40,state='PARTIALLY_CAPTURED',version=version+1
WHERE payment_id='payment-rollout'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE holds
SET captured_atoms=40,state='PARTIALLY_CAPTURED',version=version+1
WHERE payment_id='payment-rollout'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO payment_effects (
 payment_effect_id,payment_id,effect_kind,amount_atoms,
 ledger_transaction_id,original_transaction_id)
VALUES ('capture-a-effect','payment-rollout','CAPTURE',40,
        'capture-a-transaction','hold-transaction')`); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MIGRATION_TARGET_VERSION", "021_payment_posting_boundary_expand.sql")
	if err := run(ctx, logger); err != nil {
		t.Fatal(err)
	}
	assertCaptureFinancialCount(t, ctx, pool, 1)

	// A still-running old pod writes after the expand backfill.
	post("capture-b-transaction", "capture-b-effect", "CAPTURE", 60, held, merchant, &holdReference)
	if _, err := pool.Exec(ctx, `UPDATE payment_operations
SET captured_atoms=100,state='CAPTURED',version=version+1
WHERE payment_id='payment-rollout'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE holds
SET captured_atoms=100,state='CAPTURED',version=version+1
WHERE payment_id='payment-rollout'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO payment_effects (
 payment_effect_id,payment_id,effect_kind,amount_atoms,
 ledger_transaction_id,original_transaction_id)
VALUES ('capture-b-effect','payment-rollout','CAPTURE',60,
        'capture-b-transaction','hold-transaction')`); err != nil {
		t.Fatal(err)
	}
	assertCaptureFinancialCount(t, ctx, pool, 1)

	t.Setenv("MIGRATION_TARGET_VERSION", "022_payment_posting_boundary_contract.sql")
	if err := run(ctx, logger); err != nil {
		t.Fatal(err)
	}
	assertCaptureFinancialCount(t, ctx, pool, 2)
	var missing int64
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM payment_effects AS effect
WHERE NOT EXISTS (SELECT 1 FROM payment_effect_request_receipts AS receipt
                  WHERE receipt.payment_effect_id=effect.payment_effect_id)`).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != 0 {
		t.Fatalf("canonical payment effect receipts missing=%d", missing)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE payment_runtime`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO payment_effects
 (payment_effect_id,payment_id,effect_kind,amount_atoms,ledger_transaction_id)
VALUES ('late-raw-effect','payment-rollout','HOLD',1,'hold-transaction')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("contract raw effect error=%v, want permission denied", err)
	}
}

func assertCaptureFinancialCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, expected int64) {
	t.Helper()
	var actual int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM payment_capture_financials
WHERE payment_id='payment-rollout'`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("capture financial count=%d, want %d", actual, expected)
	}
}
