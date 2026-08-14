//go:build integration

package repair

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/audit"
	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/reconciliation"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type repairIDs struct {
	prefix string
	next   atomic.Int64
}

func (g *repairIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.next.Add(1)), nil
}

func TestDuplicateCashbackIncidentIsDetectedAndRepairedIdempotently(t *testing.T) {
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
	ids := &repairIDs{prefix: "repair-" + randomSuffix(t)}
	runner := store.NewRunner(pool)
	runner.MaxAttempts = 50
	runner.BaseBackoff = time.Millisecond
	journal := ledger.NewService(runner, ids)
	payments := payment.NewService(runner, journal, idempotency.NewService(ids), ids)
	suffix, _ := ids.Next(ctx)
	assetID, bookID := "asset-"+suffix, "book-"+suffix
	available, held := "available-"+suffix, "held-"+suffix
	merchant, funding, expense := "merchant-"+suffix, "funding-"+suffix, "cashback-expense-"+suffix
	if err := journal.RegisterAsset(ctx, ledger.Asset{AssetID: assetID, DisplayCode: "CB-" + suffix, AtomicScale: 2}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{BookID: bookID, LegalEntityID: "entity", Jurisdiction: "KZ"}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: available, BookID: bookID, AssetID: assetID, AccountType: "CUSTOMER_AVAILABLE", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: held, BookID: bookID, AssetID: assetID, AccountType: "CUSTOMER_HELD", NormalSide: ledger.Credit, EnforceSpendLimit: true},
		{AccountID: merchant, BookID: bookID, AssetID: assetID, AccountType: "MERCHANT_PAYABLE", NormalSide: ledger.Credit},
		{AccountID: funding, BookID: bookID, AssetID: assetID, AccountType: "CASH", NormalSide: ledger.Debit},
		{AccountID: expense, BookID: bookID, AssetID: assetID, AccountType: "CASHBACK_EXPENSE", NormalSide: ledger.Debit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	fundingHash := sha256.Sum256([]byte("fund/" + suffix))
	if _, err := journal.Post(ctx, ledger.PostRequest{
		TransactionID: "fund-tx-" + suffix, BookID: bookID,
		OperationID: "fund-op-" + suffix, EffectID: "fund-effect-" + suffix,
		Kind: "DEPOSIT", PostingRuleVersion: "deposit-v1", SchemaVersion: 1,
		RequestHash: fundingHash,
		Lines: []ledger.Line{
			{AccountID: funding, AssetID: assetID, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(100)},
			{AccountID: available, AssetID: assetID, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(100)},
		},
	}); err != nil {
		t.Fatal(err)
	}
	rights := escrow.NewService(pool, nil, nil)
	if err := rights.CreateAuthority(ctx, available, assetID, ledger.NewAmountInt64(100)); err != nil {
		t.Fatal(err)
	}
	if _, err := rights.Allocate(ctx, escrow.EffectRequest{
		EffectID: "allocate-" + suffix, AccountID: available, AssetID: assetID,
		Region: "region-a", Amount: ledger.NewAmountInt64(100),
	}); err != nil {
		t.Fatal(err)
	}
	hold, err := payments.Hold(ctx, payment.HoldRequest{
		Scope: bookID, IdempotencyKey: "hold", BookID: bookID, AssetID: assetID,
		CustomerAvailableAccountID: available, CustomerHeldAccountID: held,
		MerchantAccountID: merchant, Amount: ledger.NewAmountInt64(100),
		CashbackRuleMaximum: ledger.NewAmountInt64(50), PostingRuleVersion: "hold-v1",
		AuthorityRegion: "region-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := payments.Capture(ctx, payment.CaptureRequest{
		Scope: bookID, IdempotencyKey: "capture", PaymentID: hold.PaymentID,
		BookID: bookID, AssetID: assetID, Amount: ledger.NewAmountInt64(100),
		Cashback: ledger.NewAmountInt64(10), CashbackExpenseAccountID: expense,
		PostingRuleVersion: "cashback-bug-v42",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reproduce the faulty deployment: it appends a second balanced cashback
	// fact but fails to advance the aggregate counter a second time.
	duplicateHash := sha256.Sum256([]byte("buggy-duplicate/" + hold.PaymentID))
	var duplicate ledger.Receipt
	err = runner.RunSerializable(ctx, func(tx pgx.Tx) error {
		duplicate, err = journal.PostInTx(ctx, tx, ledger.PostRequest{
			TransactionID: "bug-cashback-tx-" + suffix, BookID: bookID,
			OperationID: "bug-cashback-op-" + suffix, EffectID: "bug-cashback-effect-" + suffix,
			Kind: "CASHBACK", ReferenceTransactionID: &capture.Ledger.TransactionID,
			PostingRuleVersion: "cashback-bug-v42", SchemaVersion: 1,
			RequestHash: duplicateHash,
			Lines: []ledger.Line{
				{AccountID: expense, AssetID: assetID, Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(10)},
				{AccountID: available, AssetID: assetID, Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(10)},
			},
		})
		if err != nil {
			return err
		}
		if _, err = escrow.ReturnInTx(ctx, tx, escrow.EffectRequest{
			EffectID: "bug-cashback-effect-" + suffix, AccountID: available,
			AssetID: assetID, Region: "region-a", Amount: ledger.NewAmountInt64(10),
		}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO payment_effects
 (payment_effect_id,payment_id,effect_kind,amount_atoms,ledger_transaction_id,original_transaction_id)
VALUES ($1,$2,'CASHBACK','10',$3,$4)`, "bug-cashback-effect-"+suffix,
			hold.PaymentID, duplicate.TransactionID, capture.Ledger.TransactionID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	job, err := NewCashbackRepair(runner, journal)
	if err != nil {
		t.Fatal(err)
	}
	incident := CashbackIncident{
		IncidentID: "deployment-2026-08-10-v42", BookID: bookID,
		FirstSequence: duplicate.SequenceNo, LastSequence: duplicate.SequenceNo,
		BuggyRuleVersion: "cashback-bug-v42",
	}
	manifests, err := job.Plan(ctx, incident)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 1 || manifests[0].Expected.String() != "10" ||
		manifests[0].Actual.String() != "20" || manifests[0].Excess.String() != "10" {
		t.Fatalf("unexpected repair manifest: %#v", manifests)
	}
	if manifests[0].CaptureTransactionID != capture.Ledger.TransactionID {
		t.Fatalf("repair was not pinned to the affected capture: %#v", manifests[0])
	}

	type executionResult struct {
		receipt ledger.Receipt
		err     error
	}
	const workers = 16
	start := make(chan struct{})
	results := make(chan executionResult, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			receipt, executeErr := job.Execute(ctx, manifests[0].RepairID)
			results <- executionResult{receipt: receipt, err: executeErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var firstReceipt ledger.Receipt
	nonDuplicate := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.receipt.Duplicate {
			firstReceipt = result.receipt
			nonDuplicate++
		} else if firstReceipt.TransactionID != "" &&
			result.receipt.TransactionID != firstReceipt.TransactionID {
			t.Fatalf("concurrent retry returned a different correction: %#v", result.receipt)
		}
	}
	if nonDuplicate != 1 {
		t.Fatalf("expected one correction winner, got %d", nonDuplicate)
	}
	retryReceipt, err := job.Execute(ctx, manifests[0].RepairID)
	if err != nil {
		t.Fatal(err)
	}
	if !retryReceipt.Duplicate || retryReceipt.TransactionID != firstReceipt.TransactionID {
		t.Fatal("repair retry did not return the original durable correction")
	}
	var correctionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ledger_transactions WHERE effect_id=$1`,
		manifests[0].CorrectionEffectID).Scan(&correctionCount); err != nil {
		t.Fatal(err)
	}
	if correctionCount != 1 {
		t.Fatalf("correction effect count = %d", correctionCount)
	}
	var escrowEffectCount int
	var escrowEffectKind string
	if err := pool.QueryRow(ctx, `
SELECT count(*), min(effect_kind)
FROM escrow_effect_receipts WHERE effect_id=$1`, manifests[0].CorrectionEffectID).
		Scan(&escrowEffectCount, &escrowEffectKind); err != nil {
		t.Fatal(err)
	}
	if escrowEffectCount != 1 || escrowEffectKind != string(escrow.EffectSpend) {
		t.Fatalf("correction escrow receipt = count:%d kind:%q", escrowEffectCount, escrowEffectKind)
	}
	var grossCashback, aggregateReversed, captureExpected, captureReversed string
	if err := pool.QueryRow(ctx, `
SELECT payment.cashback_atoms::STRING, payment.cashback_reversed_atoms::STRING,
       capture.expected_cashback_atoms::STRING, capture.cashback_reversed_atoms::STRING
FROM payment_operations AS payment
JOIN payment_capture_financials AS capture ON capture.payment_id=payment.payment_id
WHERE payment.payment_id=$1 AND capture.capture_transaction_id=$2`,
		hold.PaymentID, capture.Ledger.TransactionID).Scan(&grossCashback,
		&aggregateReversed, &captureExpected, &captureReversed); err != nil {
		t.Fatal(err)
	}
	if grossCashback != "10" || aggregateReversed != "10" ||
		captureExpected != "10" || captureReversed != "10" {
		t.Fatalf("cashback gross/reversal evidence diverged: gross=%s aggregate-reversed=%s expected=%s capture-reversed=%s",
			grossCashback, aggregateReversed, captureExpected, captureReversed)
	}
	authority, err := rights.Snapshot(ctx, available, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Total.String() != "10" || authority.RegionalRights["region-a"].String() != "10" {
		t.Fatalf("repair did not atomically consume duplicate cashback rights: total=%s regional=%s",
			authority.Total, authority.RegionalRights["region-a"])
	}
	balance, err := journal.Balance(ctx, available)
	if err != nil {
		t.Fatal(err)
	}
	folded, err := journal.FoldBalance(ctx, available)
	if err != nil {
		t.Fatal(err)
	}
	if balance.CurrentBalanceAtoms.String() != "10" || folded.Cmp(balance.CurrentBalanceAtoms) != 0 {
		t.Fatalf("post-repair available/materialized mismatch: balance=%s fold=%s",
			balance.CurrentBalanceAtoms, folded)
	}

	checker, err := reconciliation.NewChecker(runner)
	if err != nil {
		t.Fatal(err)
	}
	report, err := checker.Run(ctx, "reconciliation-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Safe() || report.Status != "PASSED" {
		t.Fatalf("post-repair reconciliation failed: %#v", report.Findings)
	}
	transactions, err := (audit.SQLReader{DB: pool}).LoadRange(ctx, audit.Range{
		BookID: bookID, First: 1, Last: report.Watermarks[bookID],
		ExpectedPrev: ledger.GenesisHash(bookID),
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := audit.VerifyRange(audit.Range{
		BookID: bookID, First: 1, Last: report.Watermarks[bookID],
		ExpectedPrev: ledger.GenesisHash(bookID),
	}, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if err := (audit.SQLReader{DB: pool}).VerifyBookHead(ctx, verification); err != nil {
		t.Fatal(err)
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
