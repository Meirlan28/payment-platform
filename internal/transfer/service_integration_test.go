//go:build integration

package transfer_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/authz"
	"github.com/example/payment-platform/internal/idgen"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/provisioning"
	"github.com/example/payment-platform/internal/store"
	"github.com/example/payment-platform/internal/transfer"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests run against a real CockroachDB. A transfer's whole value is that
// it is atomic across two independently hash-chained books while every
// invariant the ledger enforces stays enforced, and none of that can be
// demonstrated against a fake.

type fixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	service   *transfer.Service
	provision *provisioning.Service
	journal   *ledger.Service
	assetID   string
	principal string
	region    string
}

func newFixture(t *testing.T) *fixture {
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

	suffix := fmt.Sprintf("xfer-%d", time.Now().UnixNano())
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
		AssetID: assetID, DisplayCode: "X" + suffix[len(suffix)-8:], AtomicScale: 2,
	}); err != nil {
		t.Fatal(err)
	}

	principal := "spiffe://payments.test/wallet/" + suffix
	provisionConfig := provisioning.Config{
		Region: "test-a", LegalEntityID: "entity-" + suffix, Jurisdiction: "KZ",
		BookShards: 4, PolicyVersion: "transfer-test-v1", GrantedBy: "test-admin",
		FundingAccountID: "funding-" + suffix,
	}
	provision, err := provisioning.New(runner, journal, generator, provisionConfig)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := authz.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := transfer.New(runner, journal, capabilities, generator,
		transfer.Config{Region: "test-a", PolicyVersion: "transfer-test-v1"})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		ctx: ctx, pool: pool, service: service, provision: provision, journal: journal,
		assetID: assetID, principal: principal, region: "test-a",
	}
}

// wallet opens a funded customer wallet and returns its available account.
func (f *fixture) wallet(t *testing.T, reference string, atoms int64) (accountID, bookID string) {
	t.Helper()
	// Provisioning creates the book, its settlement account and the wallet.
	provisioned, err := f.provision.ProvisionCustomerAccount(f.ctx, provisioning.CustomerAccountRequest{
		ExternalReference: reference, AssetID: f.assetID, PaymentPrincipalID: f.principal,
		// Named explicitly, because provisioning grants transfer authority only
		// when asked. Omitting it opens a wallet that can pay merchants and
		// cannot send to a person, which is the intended default.
		TransferPrincipalID: f.principal,
	})
	if err != nil {
		t.Fatalf("provision %s: %v", reference, err)
	}
	if atoms > 0 {
		f.fund(t, provisioned.BookID, provisioned.AvailableAccountID, atoms)
	}
	return provisioned.AvailableAccountID, provisioned.BookID
}

// fund credits a wallet the way the funding API does: a balanced posting plus
// a matching raise of escrow rights, so the money is genuinely spendable.
func (f *fixture) fund(t *testing.T, bookID, accountID string, atoms int64) {
	t.Helper()
	source := provisioning.FundingAccountFor("funding-source", bookID)
	if err := f.journal.CreateAccount(f.ctx, ledger.Account{
		AccountID: source, BookID: bookID, AssetID: f.assetID,
		AccountType: "CASH", NormalSide: ledger.Debit,
	}); err != nil && !errors.Is(err, ledger.ErrInvalidPosting) {
		// Already created for an earlier wallet in the same book.
		_ = err
	}
	amount, err := ledger.ParseAmount(fmt.Sprint(atoms))
	if err != nil {
		t.Fatal(err)
	}
	transactionID := fmt.Sprintf("fund-%s-%d", accountID, time.Now().UnixNano())
	if _, err := f.journal.Post(f.ctx, ledger.PostRequest{
		TransactionID: transactionID, BookID: bookID,
		OperationID: transactionID, EffectID: transactionID,
		Kind: "DEPOSIT", PostingRuleVersion: "transfer-test-v1", SchemaVersion: 1,
		Lines: []ledger.Line{
			{AccountID: source, AssetID: f.assetID, Side: ledger.Debit, AmountAtoms: amount},
			{AccountID: accountID, AssetID: f.assetID, Side: ledger.Credit, AmountAtoms: amount},
		},
	}); err != nil {
		t.Fatalf("fund posting: %v", err)
	}
	// Escrow rights are raised alongside, exactly as Deposit does.
	if _, err := f.pool.Exec(f.ctx, `
UPDATE escrow_authorities SET total_authority = total_authority + $3::DECIMAL, version = version + 1
 WHERE account_id=$1 AND asset_id=$2`, accountID, f.assetID, atoms); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `
UPDATE escrow_regional_rights SET available = available + $4::DECIMAL, version = version + 1
 WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
		accountID, f.assetID, f.region, atoms); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) balance(t *testing.T, accountID string) int64 {
	t.Helper()
	var text string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT current_balance_atoms::STRING FROM account_balances WHERE account_id=$1`,
		accountID).Scan(&text); err != nil {
		t.Fatalf("balance of %s: %v", accountID, err)
	}
	value, ok := new(big.Int).SetString(text, 10)
	if !ok {
		t.Fatalf("balance %q is not an integer", text)
	}
	return value.Int64()
}

func (f *fixture) escrow(t *testing.T, accountID string) int64 {
	t.Helper()
	var text string
	if err := f.pool.QueryRow(f.ctx, `
SELECT available::STRING FROM escrow_regional_rights
 WHERE account_id=$1 AND asset_id=$2 AND region=$3`,
		accountID, f.assetID, f.region).Scan(&text); err != nil {
		t.Fatalf("escrow of %s: %v", accountID, err)
	}
	value, _ := new(big.Int).SetString(text, 10)
	return value.Int64()
}

// settlementResidual is the invariant that replaces the one a cross-book
// transfer would otherwise break: every atom that left a book through
// settlement arrived in another the same way, so the total is zero.
func (f *fixture) settlementResidual(t *testing.T) int64 {
	t.Helper()
	var text string
	err := f.pool.QueryRow(f.ctx, `
SELECT coalesce(residual_atoms, 0)::STRING FROM interbook_settlement_residual
 WHERE asset_id=$1`, f.assetID).Scan(&text)
	if err != nil {
		// No settlement account has been used for this asset yet.
		return 0
	}
	value, _ := new(big.Int).SetString(text, 10)
	return value.Int64()
}

// differentBooks opens wallets until it has two in different books, which is
// the case cross-book transfers exist for. Book membership is a hash of the
// reference, so it is found by trying rather than by choosing.
func (f *fixture) differentBooks(t *testing.T, prefix string, payerAtoms, payeeAtoms int64) (payer, payee string) {
	t.Helper()
	first, firstBook := f.wallet(t, fmt.Sprintf("%s-a-%d", prefix, time.Now().UnixNano()), payerAtoms)
	for index := 0; index < 40; index++ {
		candidate, book := f.wallet(t,
			fmt.Sprintf("%s-b-%d-%d", prefix, time.Now().UnixNano(), index), payeeAtoms)
		if book != firstBook {
			return first, candidate
		}
	}
	t.Fatal("could not find two customers in different books")
	return "", ""
}

// sameBook is the mirror image, for the degenerate one-transaction case.
func (f *fixture) sameBook(t *testing.T, prefix string, payerAtoms, payeeAtoms int64) (payer, payee string) {
	t.Helper()
	first, firstBook := f.wallet(t, fmt.Sprintf("%s-a-%d", prefix, time.Now().UnixNano()), payerAtoms)
	for index := 0; index < 60; index++ {
		candidate, book := f.wallet(t,
			fmt.Sprintf("%s-b-%d-%d", prefix, time.Now().UnixNano(), index), payeeAtoms)
		if book == firstBook {
			return first, candidate
		}
	}
	t.Skip("no same-book pair appeared in this shard layout")
	return "", ""
}

func (f *fixture) request(transferID, key, payer, payee string, atoms int64) transfer.Request {
	amount, _ := ledger.ParseAmount(fmt.Sprint(atoms))
	return transfer.Request{
		// The scope is per-fixture because idempotency identity is global: two
		// tests reusing "k1" would be one transfer replaying, which is the
		// behaviour under test rather than a fixture detail.
		TransferID: transferID, IdempotencyScope: f.assetID, IdempotencyKey: key,
		PrincipalID: f.principal, AssetID: f.assetID,
		PayerAccountID: payer, PayeeAccountID: payee, AmountAtoms: amount,
		Memo: "integration",
	}
}

// The central case: two customers in different books, one atomic transfer.
func TestTransferAcrossBooksMovesValueAndRightsAtomically(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()

	alice, bob := f.differentBooks(t, "cross", 10000, 0)

	receipt, err := f.service.Execute(f.ctx,
		f.request(fmt.Sprintf("tr-%d", suffix), "k1", alice, bob, 2500))
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if !receipt.CrossBook {
		t.Fatal("a transfer between two books did not report itself as cross-book")
	}
	if receipt.PayerTransactionID == receipt.PayeeTransactionID {
		t.Fatal("a cross-book transfer wrote a single transaction")
	}

	if got := f.balance(t, alice); got != 7500 {
		t.Fatalf("payer balance = %d, want 7500", got)
	}
	if got := f.balance(t, bob); got != 2500 {
		t.Fatalf("payee balance = %d, want 2500", got)
	}
	// The recipient must be able to spend what they received; rights that did
	// not move with the value would leave the money there and unusable.
	if got := f.escrow(t, bob); got != 2500 {
		t.Fatalf("payee escrow rights = %d, want 2500", got)
	}
	if got := f.escrow(t, alice); got != 7500 {
		t.Fatalf("payer escrow rights = %d, want 7500", got)
	}
	if residual := f.settlementResidual(t); residual != 0 {
		t.Fatalf("inter-book settlement residual = %d, want 0", residual)
	}
}

func TestTransferWithinOneBookWritesOneTransaction(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()

	one, two := f.sameBook(t, "same", 5000, 0)

	receipt, err := f.service.Execute(f.ctx,
		f.request(fmt.Sprintf("tr-same-%d", suffix), "k1", one, two, 1000))
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if receipt.CrossBook {
		t.Fatal("a same-book transfer reported itself as cross-book")
	}
	// One transaction moved both sides, so no settlement account was touched
	// and there is nothing for the zero-sum invariant to net out.
	if receipt.PayerTransactionID != receipt.PayeeTransactionID {
		t.Fatal("a same-book transfer wrote two transactions")
	}
	if got := f.balance(t, one); got != 4000 {
		t.Fatalf("payer balance = %d, want 4000", got)
	}
	if got := f.balance(t, two); got != 1000 {
		t.Fatalf("payee balance = %d, want 1000", got)
	}
	if residual := f.settlementResidual(t); residual != 0 {
		t.Fatalf("settlement residual = %d, want 0", residual)
	}
}

// A replay must return the original transfer, not perform a second one.
func TestReplayingATransferIsNotASecondTransfer(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()
	alice, _ := f.wallet(t, fmt.Sprintf("idem-a-%d", suffix), 4000)
	bob, _ := f.wallet(t, fmt.Sprintf("idem-b-%d", suffix), 0)

	request := f.request(fmt.Sprintf("tr-idem-%d", suffix), "same-key", alice, bob, 1500)
	first, err := f.service.Execute(f.ctx, request)
	if err != nil {
		t.Fatalf("first transfer: %v", err)
	}
	if first.Duplicate {
		t.Fatal("the first execution reported itself as a duplicate")
	}
	second, err := f.service.Execute(f.ctx, request)
	if err != nil {
		t.Fatalf("replayed transfer: %v", err)
	}
	if !second.Duplicate {
		t.Fatal("a replay was not recognised as one")
	}
	if second.TransferID != first.TransferID ||
		second.PayerTransactionID != first.PayerTransactionID ||
		second.PayeeTransactionID != first.PayeeTransactionID {
		t.Fatalf("the replay described a different transfer: %#v vs %#v", second, first)
	}
	if got := f.balance(t, alice); got != 2500 {
		t.Fatalf("payer balance = %d after a replay, want 2500 — the money moved twice", got)
	}
	if got := f.balance(t, bob); got != 1500 {
		t.Fatalf("payee balance = %d after a replay, want 1500", got)
	}
}

// The same key with different terms is a caller defect, and answering it with
// either transfer would be wrong.
func TestSameKeyWithDifferentTermsIsRefused(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()
	alice, _ := f.wallet(t, fmt.Sprintf("conf-a-%d", suffix), 4000)
	bob, _ := f.wallet(t, fmt.Sprintf("conf-b-%d", suffix), 0)

	transferID := fmt.Sprintf("tr-conf-%d", suffix)
	if _, err := f.service.Execute(f.ctx, f.request(transferID, "key", alice, bob, 1000)); err != nil {
		t.Fatalf("first transfer: %v", err)
	}
	_, err := f.service.Execute(f.ctx, f.request(transferID+"-b", "key", alice, bob, 2000))
	if !errors.Is(err, transfer.ErrRequestConflict) {
		t.Fatalf("reused key with a different amount produced %v", err)
	}
	if got := f.balance(t, alice); got != 3000 {
		t.Fatalf("payer balance = %d, want 3000 — the conflicting request took effect", got)
	}
}

// Nothing may move when the payer cannot cover the amount, and the failure
// must leave no partial trace in either book.
func TestAnUnaffordableTransferMovesNothing(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()
	alice, _ := f.wallet(t, fmt.Sprintf("poor-a-%d", suffix), 500)
	bob, _ := f.wallet(t, fmt.Sprintf("poor-b-%d", suffix), 0)

	_, err := f.service.Execute(f.ctx,
		f.request(fmt.Sprintf("tr-poor-%d", suffix), "k1", alice, bob, 5000))
	if err == nil {
		t.Fatal("a transfer larger than the balance succeeded")
	}
	if got := f.balance(t, alice); got != 500 {
		t.Fatalf("payer balance = %d, want 500", got)
	}
	if got := f.balance(t, bob); got != 0 {
		t.Fatalf("payee balance = %d, want 0 — a failed transfer credited the payee", got)
	}
	if residual := f.settlementResidual(t); residual != 0 {
		t.Fatalf("settlement residual = %d after a failed transfer, want 0", residual)
	}
}

func TestPayingYourselfIsRefused(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()
	alice, _ := f.wallet(t, fmt.Sprintf("self-%d", suffix), 1000)

	_, err := f.service.Execute(f.ctx,
		f.request(fmt.Sprintf("tr-self-%d", suffix), "k1", alice, alice, 100))
	if !errors.Is(err, transfer.ErrSameAccount) {
		t.Fatalf("self-transfer produced %v", err)
	}
}

// A principal without the transfer capability must not move anybody's money,
// even though it may well be allowed to authorize payments for them.
func TestAPrincipalWithoutTheTransferCapabilityIsDenied(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()
	alice, _ := f.wallet(t, fmt.Sprintf("cap-a-%d", suffix), 3000)
	bob, _ := f.wallet(t, fmt.Sprintf("cap-b-%d", suffix), 0)

	request := f.request(fmt.Sprintf("tr-cap-%d", suffix), "k1", alice, bob, 1000)
	request.PrincipalID = "spiffe://payments.test/wallet/somebody-else"

	if _, err := f.service.Execute(f.ctx, request); !errors.Is(err, transfer.ErrDenied) {
		t.Fatalf("an unauthorized principal produced %v", err)
	}
	if got := f.balance(t, alice); got != 3000 {
		t.Fatalf("payer balance = %d after a denied transfer", got)
	}
}

// Opposing transfers between the same two books must not deadlock on the
// books' chain rows. The legs are written in a globally fixed order for
// exactly this reason.
func TestOpposingCrossBookTransfersDoNotDeadlock(t *testing.T) {
	f := newFixture(t)
	suffix := time.Now().UnixNano()

	alice, bob := f.differentBooks(t, "deadlock", 20000, 20000)

	// Opposing transfers launched together. If the legs were written
	// payer-first rather than in a globally fixed order, A→B and B→A would
	// grab the two books' chain rows in opposite sequences and deadlock.
	//
	// The width is deliberately modest, and not because of any environment
	// limit. Every transfer between this pair of books must advance both
	// books' hash chains, so transfers over one pair serialize by
	// construction — that is what makes a book independently verifiable, and
	// it is why customers are sharded across books in the first place.
	//
	// Measured here: driving one book pair at eight concurrent transfers
	// collapses on serialization retries and takes minutes rather than
	// seconds. That is the expected shape of contention on a single pair and
	// it is worth a real number, but a number belongs in a load test. What
	// this test proves is the part that must never fail at any width — that
	// the ordering is deadlock-free and that concurrent traffic neither loses
	// nor invents value.
	const (
		rounds = 6
		pairs  = 2
	)
	for round := 0; round < rounds; round++ {
		errs := make(chan error, pairs*2)
		for index := 0; index < pairs; index++ {
			go func(index int) {
				_, err := f.service.Execute(f.ctx, f.request(
					fmt.Sprintf("tr-ab-%d-%d-%d", suffix, round, index),
					fmt.Sprintf("ab-%d-%d", round, index), alice, bob, 100))
				errs <- err
			}(index)
			go func(index int) {
				_, err := f.service.Execute(f.ctx, f.request(
					fmt.Sprintf("tr-ba-%d-%d-%d", suffix, round, index),
					fmt.Sprintf("ba-%d-%d", round, index), bob, alice, 100))
				errs <- err
			}(index)
		}
		for index := 0; index < pairs*2; index++ {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: concurrent opposing transfers failed: %v", round, err)
			}
		}
	}
	// Equal traffic in both directions leaves both balances where they started.
	if got := f.balance(t, alice); got != 20000 {
		t.Fatalf("payer balance = %d after symmetric traffic, want 20000", got)
	}
	if got := f.balance(t, bob); got != 20000 {
		t.Fatalf("peer balance = %d after symmetric traffic, want 20000", got)
	}
	if residual := f.settlementResidual(t); residual != 0 {
		t.Fatalf("settlement residual = %d after concurrent transfers, want 0", residual)
	}
}
