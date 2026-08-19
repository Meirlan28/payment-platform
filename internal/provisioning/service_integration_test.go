//go:build integration

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/payment"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) (context.Context, *pgxpool.Pool) {
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
	return ctx, pool
}

// newFixture builds a provisioning service with its own durable ID issuer and
// a funding source account inside the book the customer will be opened into.
func newFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix, externalReference string) (*Service, *ledger.Service, *store.Runner, string, string) {
	t.Helper()
	assetID := "asset-" + suffix
	issuer := "issuer-" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO id_issuers (issuer_prefix, incarnation) VALUES ($1,1)`, issuer); err != nil {
		t.Fatal(err)
	}
	generator, err := idgen.New(pool, issuer, 512)
	if err != nil {
		t.Fatal(err)
	}
	runner := store.NewRunner(pool)
	runner.MaxAttempts = 20
	journal := ledger.NewService(runner, generator)
	if err := journal.RegisterAsset(ctx, ledger.Asset{
		AssetID: assetID, DisplayCode: "PRV-" + suffix, AtomicScale: 2,
	}); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Region: "test-a", LegalEntityID: "entity-" + suffix, Jurisdiction: "KZ",
		BookShards: 4, PolicyVersion: "provisioning-v1", GrantedBy: "test-admin",
		FundingAccountID: "funding-" + suffix,
	}
	service, err := New(runner, journal, generator, config)
	if err != nil {
		t.Fatal(err)
	}

	// The funding source must live in the same book as the account it credits,
	// because every ledger line of one transaction belongs to one book.
	bookID := service.BookIDFor(externalReference)
	if err := journal.CreateBook(ctx, ledger.Book{
		BookID: bookID, LegalEntityID: config.LegalEntityID, Jurisdiction: config.Jurisdiction,
	}); err != nil {
		t.Fatal(err)
	}
	// The funding source lives inside the book it funds, which is what the
	// deposit path derives with FundingAccountFor.
	if err := journal.CreateAccount(ctx, ledger.Account{
		AccountID: FundingAccountFor(config.FundingAccountID, bookID),
		BookID:    bookID, AssetID: assetID,
		AccountType: "CASH", NormalSide: ledger.Debit,
	}); err != nil {
		t.Fatal(err)
	}
	return service, journal, runner, assetID, bookID
}

func TestProvisionedAndFundedAccountCanCompleteARealPayment(t *testing.T) {
	ctx, pool := testPool(t)
	suffix := fmt.Sprintf("prov-%d", time.Now().UnixNano())
	reference := "user-" + suffix
	principal := "spiffe://payments.test/wallet/" + suffix
	service, journal, runner, assetID, bookID := newFixture(t, ctx, pool, suffix, reference)

	request := CustomerAccountRequest{
		ExternalReference: reference, AssetID: assetID, PaymentPrincipalID: principal,
	}
	provisioned, err := service.ProvisionCustomerAccount(ctx, request)
	if err != nil {
		t.Fatalf("provision customer account: %v", err)
	}
	if provisioned.Duplicate || provisioned.BookID != bookID || provisioned.Region != "test-a" {
		t.Fatalf("unexpected first provisioning result: %#v", provisioned)
	}

	// A replay of the identical request must return the same wallet rather than
	// opening a second one.
	replayed, err := service.ProvisionCustomerAccount(ctx, request)
	if err != nil {
		t.Fatalf("replay provisioning: %v", err)
	}
	if !replayed.Duplicate ||
		replayed.AvailableAccountID != provisioned.AvailableAccountID ||
		replayed.HeldAccountID != provisioned.HeldAccountID {
		t.Fatalf("replay opened a different wallet: first=%#v replay=%#v", provisioned, replayed)
	}

	// A freshly provisioned wallet has no spending rights at all, so a payment
	// must be impossible before any deposit.
	payments := payment.NewService(runner, journal, idempotency.NewService(mustGenerator(t, service)), mustGenerator(t, service))
	merchantID := "merchant-" + suffix
	if err := service.ProvisionMerchantAccount(ctx, MerchantAccountRequest{
		AccountID: merchantID, AssetID: assetID, BookID: bookID, PaymentPrincipalID: principal,
	}); err != nil {
		t.Fatalf("provision merchant account: %v", err)
	}
	holdRequest := payment.HoldRequest{
		Scope: "principal/" + principal, IdempotencyKey: "hold-before-funding",
		BookID: bookID, AssetID: assetID,
		CustomerAvailableAccountID: provisioned.AvailableAccountID,
		CustomerHeldAccountID:      provisioned.HeldAccountID,
		MerchantAccountID:          merchantID, AuthorityRegion: "test-a",
		Amount: ledger.NewAmountInt64(500), PostingRuleVersion: "payment-v1",
	}
	if _, err := payments.Hold(ctx, holdRequest); err == nil {
		t.Fatal("an unfunded wallet authorized a payment")
	}

	// Funding raises balance and escrow rights together.
	deposit := DepositRequest{
		ExternalReference: "deposit-1-" + suffix, AccountID: provisioned.AvailableAccountID,
		AssetID: assetID, AmountAtoms: ledger.NewAmountInt64(10000),
		FundingSourceReference: "settlement-" + suffix,
	}
	credited, err := service.Deposit(ctx, deposit)
	if err != nil {
		t.Fatalf("deposit: %v", err)
	}
	if credited.Duplicate || credited.LedgerTransactionID == "" {
		t.Fatalf("unexpected deposit result: %#v", credited)
	}
	replayedDeposit, err := service.Deposit(ctx, deposit)
	if err != nil {
		t.Fatalf("replay deposit: %v", err)
	}
	if !replayedDeposit.Duplicate ||
		replayedDeposit.LedgerTransactionID != credited.LedgerTransactionID {
		t.Fatalf("replayed deposit credited twice: %#v", replayedDeposit)
	}

	assertEscrowConserved(t, ctx, pool, provisioned.AvailableAccountID, assetID)

	// The deposit must have produced exactly one durable outbox intent, since
	// the read model learns about funding only through that event.
	var events int
	var topic, eventType string
	if err := pool.QueryRow(ctx, `
SELECT count(*), coalesce(max(topic), ''), coalesce(max(headers->>'event_type'), '')
  FROM outbox_messages WHERE aggregate_id=$1`,
		provisioned.AvailableAccountID).Scan(&events, &topic, &eventType); err != nil {
		t.Fatal(err)
	}
	if events != 1 || topic != FundingEventTopic || eventType != FundingEventType {
		t.Fatalf("funding outbox: count=%d topic=%q type=%q", events, topic, eventType)
	}

	// Now the same payment that failed before funding must succeed end to end.
	held, err := payments.Hold(ctx, payment.HoldRequest{
		Scope: "principal/" + principal, IdempotencyKey: "hold-after-funding",
		BookID: bookID, AssetID: assetID,
		CustomerAvailableAccountID: provisioned.AvailableAccountID,
		CustomerHeldAccountID:      provisioned.HeldAccountID,
		MerchantAccountID:          merchantID, AuthorityRegion: "test-a",
		Amount: ledger.NewAmountInt64(500), PostingRuleVersion: "payment-v1",
	})
	if err != nil {
		t.Fatalf("authorize against a funded wallet: %v", err)
	}
	captured, err := payments.Capture(ctx, payment.CaptureRequest{
		Scope: "principal/" + principal, IdempotencyKey: "capture-after-funding",
		PaymentID: held.PaymentID, BookID: bookID, AssetID: assetID,
		Amount: ledger.NewAmountInt64(500), PostingRuleVersion: "payment-v1",
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if captured.State != payment.Captured {
		t.Fatalf("unexpected captured state %q", captured.State)
	}

	assertEscrowConserved(t, ctx, pool, provisioned.AvailableAccountID, assetID)

	// 10000 credited minus 500 captured leaves 9500 spendable.
	balance, err := journal.Balance(ctx, provisioned.AvailableAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if balance.CurrentBalanceAtoms.Cmp(ledger.NewAmountInt64(9500)) != 0 {
		t.Fatalf("available balance = %s, want 9500", balance.CurrentBalanceAtoms)
	}
}

// Every wallet after the first lands in a book that already has postings. The
// book's last_entry_hash is the head of its hash chain, so re-entering an
// active book must not be mistaken for a book whose definition changed.
func TestProvisioningKeepsWorkingInABookThatAlreadyPosted(t *testing.T) {
	ctx, pool := testPool(t)
	suffix := fmt.Sprintf("shared-%d", time.Now().UnixNano())
	first := "user-first-" + suffix
	service, _, _, assetID, bookID := newFixture(t, ctx, pool, suffix, first)
	principal := "spiffe://payments.test/wallet/" + suffix

	provisioned, err := service.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference: first, AssetID: assetID, PaymentPrincipalID: principal,
	})
	if err != nil {
		t.Fatalf("provision first wallet: %v", err)
	}
	// Post into the book so its chain head moves away from genesis.
	if _, err := service.Deposit(ctx, DepositRequest{
		ExternalReference: "deposit-" + suffix, AccountID: provisioned.AvailableAccountID,
		AssetID: assetID, AmountAtoms: ledger.NewAmountInt64(1000),
		FundingSourceReference: "settlement-" + suffix,
	}); err != nil {
		t.Fatalf("fund first wallet: %v", err)
	}

	// Find a second reference that maps to the same book, then provision it.
	var second string
	for candidate := 0; candidate < 10000; candidate++ {
		reference := fmt.Sprintf("user-second-%d-%s", candidate, suffix)
		if service.BookIDFor(reference) == bookID {
			second = reference
			break
		}
	}
	if second == "" {
		t.Fatal("no second reference mapped to the same book")
	}
	if _, err := service.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference: second, AssetID: assetID, PaymentPrincipalID: principal,
	}); err != nil {
		t.Fatalf("provision a second wallet into an active book: %v", err)
	}
}

func TestProvisioningRejectsAReusedReferenceWithADifferentRequest(t *testing.T) {
	ctx, pool := testPool(t)
	suffix := fmt.Sprintf("conflict-%d", time.Now().UnixNano())
	reference := "user-" + suffix
	service, _, _, assetID, _ := newFixture(t, ctx, pool, suffix, reference)

	if _, err := service.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference: reference, AssetID: assetID,
		PaymentPrincipalID: "spiffe://payments.test/wallet/" + suffix,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := service.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference: reference, AssetID: assetID,
		// A different principal for the same reference is a conflicting request,
		// not a duplicate: silently returning the first wallet would hide an
		// attempt to bind someone else's identity to it.
		PaymentPrincipalID: "spiffe://payments.test/attacker/" + suffix,
	})
	if !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("reused reference with a different principal: err=%v", err)
	}
}

func TestDepositRequiresAProvisionedAccount(t *testing.T) {
	ctx, pool := testPool(t)
	suffix := fmt.Sprintf("unprov-%d", time.Now().UnixNano())
	service, _, _, assetID, _ := newFixture(t, ctx, pool, suffix, "user-"+suffix)

	_, err := service.Deposit(ctx, DepositRequest{
		ExternalReference: "deposit-" + suffix, AccountID: "never-provisioned-" + suffix,
		AssetID: assetID, AmountAtoms: ledger.NewAmountInt64(100),
		FundingSourceReference: "settlement-" + suffix,
	})
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("deposit into an unknown account: err=%v", err)
	}
}

func TestAccountSnapshotReadsTheLedgerAtAPastWatermark(t *testing.T) {
	ctx, pool := testPool(t)
	suffix := fmt.Sprintf("snap-%d", time.Now().UnixNano())
	reference := "user-" + suffix
	service, _, _, assetID, _ := newFixture(t, ctx, pool, suffix, reference)

	provisioned, err := service.ProvisionCustomerAccount(ctx, CustomerAccountRequest{
		ExternalReference: reference, AssetID: assetID,
		PaymentPrincipalID: "spiffe://payments.test/wallet/" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Deposit(ctx, DepositRequest{
		ExternalReference: "deposit-" + suffix, AccountID: provisioned.AvailableAccountID,
		AssetID: assetID, AmountAtoms: ledger.NewAmountInt64(2500),
		FundingSourceReference: "settlement-" + suffix,
	}); err != nil {
		t.Fatal(err)
	}

	// CockroachDB keeps recent history, so a watermark a moment in the past is
	// readable and must observe the committed deposit.
	watermark := time.Now().Add(-1 * time.Second)
	deadline := time.Now().Add(20 * time.Second)
	var snapshot Snapshot
	for {
		snapshot, err = AccountSnapshot(ctx, pool, provisioned.AvailableAccountID,
			assetID, "test-a", watermark)
		if err == nil && snapshot.BalanceAtoms.Cmp(ledger.NewAmountInt64(2500)) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot did not observe the deposit: snapshot=%#v err=%v", snapshot, err)
		}
		time.Sleep(250 * time.Millisecond)
		watermark = time.Now().Add(-1 * time.Second)
	}
	if snapshot.EscrowAvailableAtoms.Cmp(ledger.NewAmountInt64(2500)) != 0 {
		t.Fatalf("escrow rights = %s, want 2500", snapshot.EscrowAvailableAtoms)
	}
	if snapshot.LastSequenceNo <= 0 {
		t.Fatalf("snapshot has no ledger sequence: %#v", snapshot)
	}
}

// assertEscrowConserved checks the platform's own escrow conservation view,
// which is the invariant a funding path could most plausibly break.
func assertEscrowConserved(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accountID, assetID string) {
	t.Helper()
	var conserved bool
	var total, unallocated, regional string
	if err := pool.QueryRow(ctx, `
SELECT conserved, total_authority::STRING, unallocated::STRING, regional::STRING
  FROM escrow_authority_conservation WHERE account_id=$1 AND asset_id=$2`,
		accountID, assetID).Scan(&conserved, &total, &unallocated, &regional); err != nil {
		t.Fatal(err)
	}
	if !conserved {
		t.Fatalf("escrow conservation broken: total=%s unallocated=%s regional=%s",
			total, unallocated, regional)
	}
}

func mustGenerator(t *testing.T, service *Service) ledger.IDGenerator {
	t.Helper()
	if service.ids == nil {
		t.Fatal("fixture service has no ID generator")
	}
	return service.ids
}
