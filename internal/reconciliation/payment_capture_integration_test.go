//go:build integration

package reconciliation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type captureTestIDs struct {
	prefix string
	next   atomic.Int64
}

func (ids *captureTestIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", ids.prefix, ids.next.Add(1)), nil
}

type captureTestEnvironment struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	runner    *store.Runner
	journal   *ledger.Service
	payments  *payment.Service
	ids       *captureTestIDs
	book      string
	asset     string
	available string
	held      string
	merchant  string
	funding   string
	fee       string
	tax       string
	expense   string
}

func TestCaptureReconciliationUsesExactPerCaptureFacts(t *testing.T) {
	env := newCaptureTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(200))

	ordinary, err := env.payments.Hold(env.ctx, payment.HoldRequest{
		Scope: env.book, IdempotencyKey: "ordinary-hold", BookID: env.book,
		AssetID: env.asset, CustomerAvailableAccountID: env.available,
		CustomerHeldAccountID: env.held, MerchantAccountID: env.merchant,
		Amount: ledger.NewAmountInt64(100), CashbackRuleMaximum: ledger.NewAmountInt64(5),
		PostingRuleVersion: "capture-reconciliation-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.payments.Capture(env.ctx, payment.CaptureRequest{
		Scope: env.book, IdempotencyKey: "ordinary-capture", PaymentID: ordinary.PaymentID,
		BookID: env.book, AssetID: env.asset, Amount: ledger.NewAmountInt64(100),
		Fee: ledger.NewAmountInt64(2), Tax: ledger.NewAmountInt64(3),
		Cashback: ledger.NewAmountInt64(5), FeeAccountID: env.fee,
		TaxAccountID: env.tax, CashbackExpenseAccountID: env.expense,
		PostingRuleVersion: "capture-reconciliation-v1",
	}); err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(env.runner)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryReport, err := checker.Run(env.ctx, "ordinary-"+env.ids.prefix)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPaymentFinding(t, ordinaryReport, ordinary.PaymentID)

	misattributed, err := env.payments.Hold(env.ctx, payment.HoldRequest{
		Scope: env.book, IdempotencyKey: "misattributed-hold", BookID: env.book,
		AssetID: env.asset, CustomerAvailableAccountID: env.available,
		CustomerHeldAccountID: env.held, MerchantAccountID: env.merchant,
		Amount: ledger.NewAmountInt64(100), PostingRuleVersion: "capture-reconciliation-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := env.payments.Capture(env.ctx, payment.CaptureRequest{
		Scope: env.book, IdempotencyKey: "capture-a", PaymentID: misattributed.PaymentID,
		BookID: env.book, AssetID: env.asset, Amount: ledger.NewAmountInt64(40),
		PostingRuleVersion: "capture-reconciliation-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.payments.Capture(env.ctx, payment.CaptureRequest{
		Scope: env.book, IdempotencyKey: "capture-b", PaymentID: misattributed.PaymentID,
		BookID: env.book, AssetID: env.asset, Amount: ledger.NewAmountInt64(60),
		PostingRuleVersion: "capture-reconciliation-v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	refundEffect := "misattributed-refund-effect-" + env.ids.prefix
	refundHash := sha256.Sum256([]byte(refundEffect))
	err = env.runner.RunSerializable(env.ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(env.ctx, `
UPDATE payment_capture_financials
   SET refunded_atoms=refunded_atoms+10, version=version+1,
       updated_at=transaction_timestamp()
 WHERE payment_id=$1 AND capture_transaction_id=$2`,
			misattributed.PaymentID, second.Ledger.TransactionID); err != nil {
			return err
		}
		reference := first.Ledger.TransactionID
		refund, err := env.journal.PostInTx(env.ctx, tx, ledger.PostRequest{
			TransactionID: "misattributed-refund-transaction-" + env.ids.prefix,
			BookID:        env.book, OperationID: "misattributed-refund-operation-" + env.ids.prefix,
			EffectID: refundEffect, Kind: "REFUND", ReferenceTransactionID: &reference,
			PostingRuleVersion: "capture-reconciliation-v1", SchemaVersion: 1,
			RequestHash: refundHash,
			Lines: []ledger.Line{
				{AccountID: env.merchant, AssetID: env.asset, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(10)},
				{AccountID: env.available, AssetID: env.asset, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(10)},
			},
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(env.ctx, `
UPDATE payment_operations
   SET refunded_atoms=refunded_atoms+10, state='PARTIALLY_REFUNDED',
       version=version+1, updated_at=transaction_timestamp()
 WHERE payment_id=$1`, misattributed.PaymentID); err != nil {
			return err
		}
		if _, err := tx.Exec(env.ctx, `
INSERT INTO payment_effects
 (payment_effect_id,payment_id,effect_kind,amount_atoms,
  ledger_transaction_id,original_transaction_id)
VALUES ($1,$2,'REFUND',10,$3,$4)`, refundEffect, misattributed.PaymentID,
			refund.TransactionID, first.Ledger.TransactionID); err != nil {
			return err
		}
		_, err = tx.Exec(env.ctx, `
INSERT INTO payment_effect_request_receipts (payment_effect_id,request_hash)
VALUES ($1,$2)`, refundEffect, refundHash[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	brokenReport, err := checker.Run(env.ctx, "misattributed-"+env.ids.prefix)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range brokenReport.Findings {
		if finding.Category == PaymentCaptureMismatch &&
			finding.Details["payment_id"] == misattributed.PaymentID {
			found = true
		}
	}
	if !found {
		t.Fatalf("per-capture counter substitution was not detected: %#v", brokenReport.Findings)
	}
}

func newCaptureTestEnvironment(t *testing.T) *captureTestEnvironment {
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
	ids := &captureTestIDs{prefix: fmt.Sprintf("capture-recon-%d", time.Now().UnixNano())}
	runner := store.NewRunner(pool)
	runner.MaxAttempts = 50
	runner.BaseBackoff = time.Millisecond
	journal := ledger.NewService(runner, ids)
	env := &captureTestEnvironment{
		ctx: ctx, pool: pool, runner: runner, journal: journal, ids: ids,
		book: "book-" + ids.prefix, asset: "asset-" + ids.prefix,
		available: "available-" + ids.prefix, held: "held-" + ids.prefix,
		merchant: "merchant-" + ids.prefix, funding: "funding-" + ids.prefix,
		fee: "fee-" + ids.prefix, tax: "tax-" + ids.prefix,
		expense: "expense-" + ids.prefix,
	}
	env.payments = payment.NewService(runner, journal, idempotency.NewService(ids), ids)
	if err := journal.RegisterAsset(ctx, ledger.Asset{AssetID: env.asset, DisplayCode: "R-" + ids.prefix, AtomicScale: 0}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{BookID: env.book, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: env.available, BookID: env.book, AssetID: env.asset, AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: env.held, BookID: env.book, AssetID: env.asset, AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: env.merchant, BookID: env.book, AssetID: env.asset, AccountType: "MERCHANT", NormalSide: ledger.Credit},
		{AccountID: env.funding, BookID: env.book, AssetID: env.asset, AccountType: "CASH", NormalSide: ledger.Debit},
		{AccountID: env.fee, BookID: env.book, AssetID: env.asset, AccountType: "FEE_REVENUE", NormalSide: ledger.Credit},
		{AccountID: env.tax, BookID: env.book, AssetID: env.asset, AccountType: "TAX_PAYABLE", NormalSide: ledger.Credit},
		{AccountID: env.expense, BookID: env.book, AssetID: env.asset, AccountType: "CASHBACK_EXPENSE", NormalSide: ledger.Debit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

func (env *captureTestEnvironment) fund(t *testing.T, amount ledger.Amount) {
	t.Helper()
	hash := sha256.Sum256([]byte("fund/" + env.ids.prefix))
	if _, err := env.journal.Post(env.ctx, ledger.PostRequest{
		TransactionID: "fund-transaction-" + env.ids.prefix,
		BookID:        env.book, OperationID: "fund-operation-" + env.ids.prefix,
		EffectID: "fund-effect-" + env.ids.prefix, Kind: "DEPOSIT",
		PostingRuleVersion: "capture-reconciliation-v1", SchemaVersion: 1,
		RequestHash: hash,
		Lines: []ledger.Line{
			{AccountID: env.funding, AssetID: env.asset, Side: ledger.Debit, AmountAtoms: amount},
			{AccountID: env.available, AssetID: env.asset, Side: ledger.Credit, AmountAtoms: amount},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func assertNoPaymentFinding(t *testing.T, report Report, paymentID string) {
	t.Helper()
	for _, finding := range report.Findings {
		if (finding.Category == PaymentAggregateMismatch || finding.Category == PaymentCaptureMismatch) &&
			(finding.EffectID == paymentID || finding.Details["payment_id"] == paymentID) {
			t.Fatalf("valid capture produced reconciliation finding: %#v", finding)
		}
	}
}
