//go:build integration

package payment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testIDs struct {
	prefix string
	value  atomic.Int64
}

func (g *testIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.value.Add(1)), nil
}

type testEnvironment struct {
	ctx             context.Context
	pool            *pgxpool.Pool
	journal         *ledger.Service
	payments        *Service
	ids             *testIDs
	bookID          string
	assetID         string
	available       string
	held            string
	merchant        string
	funding         string
	fee             string
	tax             string
	cashbackExpense string
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ids := &testIDs{prefix: fmt.Sprintf("test-%d", time.Now().UnixNano())}
	runner := store.NewRunner(pool)
	runner.MaxAttempts = 50
	runner.BaseBackoff = time.Millisecond
	journal := ledger.NewService(runner, ids)
	payments := NewService(runner, journal, idempotency.NewService(ids), ids)
	generatedSuffix, _ := ids.Next(ctx)
	suffix := t.Name() + "-" + generatedSuffix
	env := &testEnvironment{
		ctx: ctx, pool: pool, journal: journal, payments: payments, ids: ids,
		bookID: "book-" + suffix, assetID: "asset-" + suffix,
		available: "available-" + suffix, held: "held-" + suffix,
		merchant: "merchant-" + suffix, funding: "funding-" + suffix,
		fee: "fee-" + suffix, tax: "tax-" + suffix,
		cashbackExpense: "cashback-expense-" + suffix,
	}
	if err := journal.RegisterAsset(ctx, ledger.Asset{AssetID: env.assetID, DisplayCode: "CODE-" + suffix, AtomicScale: 2}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{BookID: env.bookID, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: env.available, BookID: env.bookID, AssetID: env.assetID, AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: env.held, BookID: env.bookID, AssetID: env.assetID, AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: env.merchant, BookID: env.bookID, AssetID: env.assetID, AccountType: "MERCHANT", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: env.funding, BookID: env.bookID, AssetID: env.assetID, AccountType: "CASH", NormalSide: ledger.Debit},
		{AccountID: env.fee, BookID: env.bookID, AssetID: env.assetID, AccountType: "FEE_REVENUE", NormalSide: ledger.Credit},
		{AccountID: env.tax, BookID: env.bookID, AssetID: env.assetID, AccountType: "TAX_PAYABLE", NormalSide: ledger.Credit},
		{AccountID: env.cashbackExpense, BookID: env.bookID, AssetID: env.assetID, AccountType: "CASHBACK_EXPENSE", NormalSide: ledger.Debit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

func TestCaptureComponentsAndCashbackAreImmutableFacts(t *testing.T) {
	env := newTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(100))
	hold, err := env.payments.Hold(env.ctx, HoldRequest{
		Scope: env.bookID, IdempotencyKey: "hold", BookID: env.bookID, AssetID: env.assetID,
		CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
		MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(100),
		CashbackRuleMaximum: ledger.NewAmountInt64(10), PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := CaptureRequest{
		Scope: env.bookID, IdempotencyKey: "capture", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID, Amount: ledger.NewAmountInt64(100),
		Fee: ledger.NewAmountInt64(2), Tax: ledger.NewAmountInt64(3),
		Cashback: ledger.NewAmountInt64(5), FeeAccountID: env.fee,
		TaxAccountID: env.tax, CashbackExpenseAccountID: env.cashbackExpense,
		PostingRuleVersion: "test-v1",
	}
	receipt, err := env.payments.Capture(env.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := env.payments.Capture(env.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Duplicate || retry.Ledger.TransactionID != receipt.Ledger.TransactionID {
		t.Fatal("capture retry did not return the original durable receipt")
	}

	rows, err := env.pool.Query(env.ctx, `
SELECT effect_kind, ledger_transaction_id
FROM payment_effects WHERE payment_id=$1 ORDER BY effect_kind`, hold.PaymentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	effects := make(map[string]string)
	for rows.Next() {
		var kind, transactionID string
		if err := rows.Scan(&kind, &transactionID); err != nil {
			t.Fatal(err)
		}
		effects[kind] = transactionID
	}
	for _, kind := range []string{"HOLD", "CAPTURE", "FEE", "TAX", "CASHBACK"} {
		if effects[kind] == "" {
			t.Fatalf("missing immutable %s component fact", kind)
		}
	}
	if effects["CAPTURE"] != effects["FEE"] || effects["CAPTURE"] != effects["TAX"] {
		t.Fatal("fee/tax facts do not reference the primary composite capture")
	}
	if effects["CASHBACK"] == effects["CAPTURE"] {
		t.Fatal("cashback must have a separately reversible ledger transaction")
	}
	var cashbackReference string
	if err := env.pool.QueryRow(env.ctx, `
SELECT reference_transaction_id FROM ledger_transactions WHERE transaction_id=$1`,
		effects["CASHBACK"]).Scan(&cashbackReference); err != nil {
		t.Fatal(err)
	}
	if cashbackReference != effects["CAPTURE"] {
		t.Fatal("cashback transaction does not reference its capture")
	}
	var captureEffectID, captured, expected, refunded, chargedBack, reversed string
	if err := env.pool.QueryRow(env.ctx, `
SELECT capture_effect_id, captured_atoms::STRING,
       expected_cashback_atoms::STRING, refunded_atoms::STRING,
       charged_back_atoms::STRING, cashback_reversed_atoms::STRING
FROM payment_capture_financials
WHERE payment_id=$1 AND capture_transaction_id=$2`,
		hold.PaymentID, receipt.Ledger.TransactionID).Scan(&captureEffectID,
		&captured, &expected, &refunded, &chargedBack, &reversed); err != nil {
		t.Fatal(err)
	}
	if captureEffectID == "" || captured != "100" || expected != "5" ||
		refunded != "0" || chargedBack != "0" || reversed != "0" {
		t.Fatalf("unexpected immutable capture financials: effect=%q captured=%s expected=%s refund=%s chargeback=%s reversed=%s",
			captureEffectID, captured, expected, refunded, chargedBack, reversed)
	}
	if _, err := env.pool.Exec(env.ctx, `
UPDATE payment_capture_financials
SET expected_cashback_atoms=6, version=version+1
WHERE capture_transaction_id=$1`, receipt.Ledger.TransactionID); err == nil {
		t.Fatal("calculated cashback result was mutable after capture commit")
	}
}

func TestPaymentMutationIsFencedByAuthenticatedScope(t *testing.T) {
	env := newTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(20))
	hold, err := env.payments.Hold(env.ctx, HoldRequest{
		Scope: env.bookID, IdempotencyKey: "scope-hold", BookID: env.bookID, AssetID: env.assetID,
		CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
		MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(20),
		PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.payments.Capture(env.ctx, CaptureRequest{
		Scope: "different-principal", IdempotencyKey: "cross-scope-capture",
		PaymentID: hold.PaymentID, BookID: env.bookID, AssetID: env.assetID,
		Amount: ledger.NewAmountInt64(20), PostingRuleVersion: "test-v1",
	})
	if !errors.Is(err, ErrPaymentNotFound) {
		t.Fatalf("cross-scope mutation must not reveal or change the payment, got %v", err)
	}

	receipt, err := env.payments.GetForScope(env.ctx, env.bookID, hold.PaymentID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != Held || receipt.Amount.Cmp(ledger.NewAmountInt64(20)) != 0 {
		t.Fatalf("cross-scope attempt changed payment: %#v", receipt)
	}
}

func (e *testEnvironment) fund(t *testing.T, amount ledger.Amount) {
	t.Helper()
	id, _ := e.ids.Next(e.ctx)
	hash := sha256.Sum256([]byte("fund-" + id))
	_, err := e.journal.Post(e.ctx, ledger.PostRequest{
		TransactionID: "fund-tx-" + id, BookID: e.bookID,
		OperationID: "fund-op-" + id, EffectID: "fund-effect-" + id,
		Kind: "DEPOSIT", PostingRuleVersion: "test-v1", SchemaVersion: 1,
		RequestHash: hash,
		Lines: []ledger.Line{
			{AccountID: e.funding, AssetID: e.assetID, Side: ledger.Debit, AmountAtoms: amount},
			{AccountID: e.available, AssetID: e.assetID, Side: ledger.Credit, AmountAtoms: amount},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentWithdrawalsNeverExceedBalance(t *testing.T) {
	env := newTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(100))
	rights := escrow.NewService(env.pool, nil, nil)
	if err := rights.CreateAuthority(env.ctx, env.available, env.assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := rights.Allocate(env.ctx, escrow.EffectRequest{
		EffectID: "allocate-withdrawals-" + env.bookID, AccountID: env.available,
		AssetID: env.assetID, Region: "region-a", Amount: ledger.NewAmountInt64(100),
	}); err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int64
	var unexpected atomic.Int64
	firstUnexpected := make(chan error, 1)
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := env.payments.Hold(env.ctx, HoldRequest{
				Scope: env.bookID, IdempotencyKey: fmt.Sprintf("withdraw-%d", index),
				BookID: env.bookID, AssetID: env.assetID,
				CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
				MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(2),
				PostingRuleVersion: "test-v1", AuthorityRegion: "region-a",
			})
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ledger.ErrInsufficientFunds) && !errors.Is(err, escrow.ErrInsufficientRights) {
				unexpected.Add(1)
				select {
				case firstUnexpected <- err:
				default:
				}
			}
		}(index)
	}
	wait.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("unexpected concurrent errors: %d, first: %v", unexpected.Load(), <-firstUnexpected)
	}
	if successes.Load()*2 > 100 {
		t.Fatalf("confirmed withdrawals exceeded balance: %d atoms", successes.Load()*2)
	}
	if successes.Load() != 50 {
		t.Fatalf("expected exactly 50 bounded successes, got %d", successes.Load())
	}
	balance, err := env.journal.Balance(env.ctx, env.available)
	if err != nil {
		t.Fatal(err)
	}
	if balance.CurrentBalanceAtoms.Sign() < 0 {
		t.Fatalf("available balance became negative: %s", balance.CurrentBalanceAtoms.String())
	}
}

func TestConcurrentRefundAndChargebackFoldNeverExceedsCapture(t *testing.T) {
	env := newTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(100))
	hold, err := env.payments.Hold(env.ctx, HoldRequest{
		Scope: env.bookID, IdempotencyKey: "hold", BookID: env.bookID, AssetID: env.assetID,
		CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
		MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(100), PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := env.payments.Capture(env.ctx, CaptureRequest{
		Scope: env.bookID, IdempotencyKey: "capture", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID, Amount: ledger.NewAmountInt64(100), PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	seed := RefundRequest{
		Scope: env.bookID, IdempotencyKey: "seed-refund", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID,
		OriginalCaptureTransactionID: capture.Ledger.TransactionID,
		MerchantDebitAccountID:       env.merchant, Amount: ledger.NewAmountInt64(2),
		PostingRuleVersion: "test-v1",
	}
	seedReceipt, err := env.payments.Refund(env.ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	seedRetry, err := env.payments.Refund(env.ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !seedRetry.Duplicate || seedRetry.Ledger.TransactionID != seedReceipt.Ledger.TransactionID {
		t.Fatal("refund retry did not return the original durable effect")
	}

	var successes atomic.Int64
	var unexpected atomic.Int64
	firstUnexpected := make(chan error, 1)
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			var err error
			if index%2 == 0 {
				_, err = env.payments.Refund(env.ctx, RefundRequest{
					Scope: env.bookID, IdempotencyKey: fmt.Sprintf("refund-%d", index),
					PaymentID: hold.PaymentID, BookID: env.bookID, AssetID: env.assetID,
					OriginalCaptureTransactionID: capture.Ledger.TransactionID,
					MerchantDebitAccountID:       env.merchant, Amount: ledger.NewAmountInt64(2),
					PostingRuleVersion: "test-v1",
				})
			} else {
				_, err = env.payments.Chargeback(env.ctx, ChargebackRequest{
					Scope: env.bookID, IdempotencyKey: fmt.Sprintf("chargeback-%d", index),
					PaymentID: hold.PaymentID, BookID: env.bookID, AssetID: env.assetID,
					OriginalCaptureTransactionID: capture.Ledger.TransactionID,
					MerchantReserveAccountID:     env.merchant, Amount: ledger.NewAmountInt64(2),
					PostingRuleVersion: "test-v1",
				})
			}
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrOverRefund) && !errors.Is(err, ledger.ErrInsufficientFunds) {
				unexpected.Add(1)
				select {
				case firstUnexpected <- err:
				default:
				}
			}
		}(index)
	}
	wait.Wait()
	if unexpected.Load() != 0 {
		t.Fatalf("unexpected concurrent return errors: %d, first: %v", unexpected.Load(), <-firstUnexpected)
	}
	if successes.Load() != 49 {
		t.Fatalf("expected 49 concurrent successes after the 2-atom seed, got %d", successes.Load())
	}

	var captureRefunded, captureChargedBack, paymentRefunded, paymentChargedBack string
	if err := env.pool.QueryRow(env.ctx, `
SELECT capture.refunded_atoms::STRING, capture.charged_back_atoms::STRING,
       payment.refunded_atoms::STRING, payment.charged_back_atoms::STRING
FROM payment_capture_financials AS capture
JOIN payment_operations AS payment ON payment.payment_id=capture.payment_id
WHERE capture.payment_id=$1 AND capture.capture_transaction_id=$2`, hold.PaymentID,
		capture.Ledger.TransactionID).Scan(&captureRefunded, &captureChargedBack,
		&paymentRefunded, &paymentChargedBack); err != nil {
		t.Fatal(err)
	}
	captureRefundAmount, err := ledger.ParseAmount(captureRefunded)
	if err != nil {
		t.Fatal(err)
	}
	captureChargebackAmount, err := ledger.ParseAmount(captureChargedBack)
	if err != nil {
		t.Fatal(err)
	}
	total, err := captureRefundAmount.Add(captureChargebackAmount)
	if err != nil {
		t.Fatal(err)
	}
	if total.String() != "100" {
		t.Fatalf("capture return authority did not close at exactly 100: refund=%s chargeback=%s",
			captureRefunded, captureChargedBack)
	}
	if paymentRefunded != captureRefunded || paymentChargedBack != captureChargedBack {
		t.Fatalf("aggregate projection diverged from capture fold: capture=(%s,%s) payment=(%s,%s)",
			captureRefunded, captureChargedBack, paymentRefunded, paymentChargedBack)
	}
}

func TestReturnCannotBorrowCapacityFromAnotherCapture(t *testing.T) {
	env := newTestEnvironment(t)
	env.fund(t, ledger.NewAmountInt64(100))
	hold, err := env.payments.Hold(env.ctx, HoldRequest{
		Scope: env.bookID, IdempotencyKey: "hold", BookID: env.bookID, AssetID: env.assetID,
		CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
		MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(100),
		PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := env.payments.Capture(env.ctx, CaptureRequest{
		Scope: env.bookID, IdempotencyKey: "capture-40", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID, Amount: ledger.NewAmountInt64(40),
		PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.payments.Capture(env.ctx, CaptureRequest{
		Scope: env.bookID, IdempotencyKey: "capture-60", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID, Amount: ledger.NewAmountInt64(60),
		PostingRuleVersion: "test-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.payments.Refund(env.ctx, RefundRequest{
		Scope: env.bookID, IdempotencyKey: "refund-first-40", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID,
		OriginalCaptureTransactionID: first.Ledger.TransactionID,
		MerchantDebitAccountID:       env.merchant, Amount: ledger.NewAmountInt64(40),
		PostingRuleVersion: "test-v1",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = env.payments.Refund(env.ctx, RefundRequest{
		Scope: env.bookID, IdempotencyKey: "refund-first-over", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID,
		OriginalCaptureTransactionID: first.Ledger.TransactionID,
		MerchantDebitAccountID:       env.merchant, Amount: ledger.NewAmountInt64(1),
		PostingRuleVersion: "test-v1",
	})
	if !errors.Is(err, ErrOverRefund) {
		t.Fatalf("first capture borrowed unused second-capture capacity: %v", err)
	}
	if _, err := env.payments.Chargeback(env.ctx, ChargebackRequest{
		Scope: env.bookID, IdempotencyKey: "chargeback-second-60", PaymentID: hold.PaymentID,
		BookID: env.bookID, AssetID: env.assetID,
		OriginalCaptureTransactionID: second.Ledger.TransactionID,
		MerchantReserveAccountID:     env.merchant, Amount: ledger.NewAmountInt64(60),
		PostingRuleVersion: "test-v1",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := env.pool.Query(env.ctx, `
SELECT capture_transaction_id, refunded_atoms::STRING, charged_back_atoms::STRING
FROM payment_capture_financials
WHERE payment_id=$1 ORDER BY captured_atoms`, hold.PaymentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string][2]string{
		first.Ledger.TransactionID:  {"40", "0"},
		second.Ledger.TransactionID: {"0", "60"},
	}
	seen := 0
	for rows.Next() {
		var transactionID, refunded, chargedBack string
		if err := rows.Scan(&transactionID, &refunded, &chargedBack); err != nil {
			t.Fatal(err)
		}
		if got, ok := want[transactionID]; !ok || got != [2]string{refunded, chargedBack} {
			t.Fatalf("unexpected capture return fold: tx=%s refund=%s chargeback=%s",
				transactionID, refunded, chargedBack)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("expected two capture authorities, got %d", seen)
	}
}

func TestHoldEscrowAndLedgerRollbackAtomically(t *testing.T) {
	t.Run("insufficient rights do not debit money", func(t *testing.T) {
		env := newTestEnvironment(t)
		env.fund(t, ledger.NewAmountInt64(100))
		rights := escrow.NewService(env.pool, nil, nil)
		if err := rights.CreateAuthority(env.ctx, env.available, env.assetID, ledger.NewAmountInt64(10)); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.Allocate(env.ctx, escrow.EffectRequest{
			EffectID: "allocate-insufficient-rights-" + env.bookID, AccountID: env.available,
			AssetID: env.assetID, Region: "region-a", Amount: ledger.NewAmountInt64(10),
		}); err != nil {
			t.Fatal(err)
		}
		_, err := env.payments.Hold(env.ctx, HoldRequest{
			Scope: env.bookID, IdempotencyKey: "too-large", BookID: env.bookID, AssetID: env.assetID,
			CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
			MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(20),
			PostingRuleVersion: "test-v1", AuthorityRegion: "region-a",
		})
		if !errors.Is(err, escrow.ErrInsufficientRights) {
			t.Fatalf("expected insufficient escrow rights, got %v", err)
		}
		balance, err := env.journal.Balance(env.ctx, env.available)
		if err != nil {
			t.Fatal(err)
		}
		if balance.CurrentBalanceAtoms.Cmp(ledger.NewAmountInt64(100)) != 0 {
			t.Fatalf("money changed after escrow rejection: %s", balance.CurrentBalanceAtoms.String())
		}
	})

	t.Run("ledger rejection restores spent rights", func(t *testing.T) {
		env := newTestEnvironment(t)
		env.fund(t, ledger.NewAmountInt64(10))
		rights := escrow.NewService(env.pool, nil, nil)
		if err := rights.CreateAuthority(env.ctx, env.available, env.assetID, ledger.NewAmountInt64(100)); err != nil {
			t.Fatal(err)
		}
		if _, err := rights.Allocate(env.ctx, escrow.EffectRequest{
			EffectID: "allocate-ledger-rollback-" + env.bookID, AccountID: env.available,
			AssetID: env.assetID, Region: "region-a", Amount: ledger.NewAmountInt64(100),
		}); err != nil {
			t.Fatal(err)
		}
		_, err := env.payments.Hold(env.ctx, HoldRequest{
			Scope: env.bookID, IdempotencyKey: "insufficient-money", BookID: env.bookID, AssetID: env.assetID,
			CustomerAvailableAccountID: env.available, CustomerHeldAccountID: env.held,
			MerchantAccountID: env.merchant, Amount: ledger.NewAmountInt64(20),
			PostingRuleVersion: "test-v1", AuthorityRegion: "region-a",
		})
		if !errors.Is(err, ledger.ErrInsufficientFunds) {
			t.Fatalf("expected insufficient money, got %v", err)
		}
		snapshot, err := rights.Snapshot(env.ctx, env.available, env.assetID)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.RegionalRights["region-a"].Cmp(ledger.NewAmountInt64(100)) != 0 {
			t.Fatalf("escrow debit survived rolled-back ledger post: %s", snapshot.RegionalRights["region-a"].String())
		}
	})
}
