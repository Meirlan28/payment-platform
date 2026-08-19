//go:build integration

package offline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationIDs struct {
	prefix string
	value  atomic.Int64
}

type unavailableSigner struct{}

type unavailablePresentationVerifier struct{}

func (unavailablePresentationVerifier) VerifyPresentation(
	context.Context, PresentationKeyBinding, []byte, []byte,
) error {
	return ErrVerifierUnavailable
}

type unavailableClosureVerifier struct{}

type closureVerifierSet map[string]*localEd25519

func (v closureVerifierSet) VerifyClosure(
	ctx context.Context,
	binding ClosureKeyBinding,
	payload, signature []byte,
) error {
	verifier, ok := v[binding.KeyID]
	if !ok {
		return ErrInvalidClosure
	}
	return verifier.VerifyClosure(ctx, binding, payload, signature)
}

func (unavailableClosureVerifier) VerifyClosure(
	context.Context, ClosureKeyBinding, []byte, []byte,
) error {
	return ErrVerifierUnavailable
}

func (unavailableSigner) ActiveKeyID(context.Context) (string, error) {
	return "", errors.New("simulated HSM outage")
}

func (unavailableSigner) Sign(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("simulated HSM outage")
}

func (g *integrationIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.value.Add(1)), nil
}

type integrationFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	runner    *store.Runner
	service   *Service
	journal   *ledger.Service
	accountID string
	assetID   string
	merchant  string
	bookID    string
	region    string
	domain    string
	epoch     uint64
	device    [32]byte
	deviceSE  *localEd25519
	closure   *localEd25519
	ids       *integrationIDs
}

func newIntegrationFixture(t *testing.T, authority int64) *integrationFixture {
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
	suffix := integrationSuffix(t)
	ids := &integrationIDs{prefix: "offline-" + suffix}
	runner := store.NewRunner(pool)
	journal := ledger.NewService(runner, ids)
	assetID, bookID := "offline-asset-"+suffix, "offline-book-"+suffix
	accountID, merchant := "offline-customer-"+suffix, "offline-merchant-"+suffix
	if err := journal.RegisterAsset(ctx, ledger.Asset{
		AssetID: assetID, DisplayCode: "OFF-" + suffix, AtomicScale: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.CreateBook(ctx, ledger.Book{
		BookID: bookID, LegalEntityID: "offline-test-entity", Jurisdiction: "KZ",
	}); err != nil {
		t.Fatal(err)
	}
	for _, account := range []ledger.Account{
		{AccountID: accountID, BookID: bookID, AssetID: assetID, AccountType: "CUSTOMER", NormalSide: ledger.Credit},
		{AccountID: merchant, BookID: bookID, AssetID: assetID, AccountType: "MERCHANT", NormalSide: ledger.Credit},
	} {
		if err := journal.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	escrowService := escrow.NewService(pool, nil, nil)
	if err := escrowService.CreateAuthority(ctx, accountID, assetID, ledger.NewAmountInt64(authority)); err != nil {
		t.Fatal(err)
	}
	region := "origin-kz"
	if _, err := escrowService.Allocate(ctx, escrow.EffectRequest{
		EffectID: "offline-allocation-" + suffix, AccountID: accountID,
		AssetID: assetID, Region: region, Amount: ledger.NewAmountInt64(authority),
	}); err != nil {
		t.Fatal(err)
	}
	issuer := newLocalEd25519(t)
	issuer.keyID = "issuer-" + suffix
	deviceSE := newLocalEd25519(t)
	deviceSE.keyID = "device-" + suffix
	closure := newLocalEd25519(t)
	closure.keyID = "closure-" + suffix
	service := NewService(runner, ids, issuer, issuer, deviceSE, closure)
	domain := "acceptance-" + suffix
	epoch := integrationEpoch(t)
	if err := service.ConfigureAcceptanceDomain(ctx, AcceptanceDomain{
		Name: domain, ClosureKeyID: closure.keyID,
		FirstSettlementEpoch: epoch, LastSettlementEpoch: epoch + 4,
	}); err != nil {
		t.Fatal(err)
	}
	device := deviceSE.identityHash()
	if err := service.EnrollDevice(ctx, Device{
		AccountID: accountID, AssetID: assetID, OriginRegion: region,
		DeviceIdentityHash: device, IssuerEpoch: epoch,
	}); err != nil {
		t.Fatal(err)
	}
	return &integrationFixture{
		ctx: ctx, pool: pool, runner: runner, service: service, journal: journal,
		accountID: accountID, assetID: assetID, merchant: merchant, bookID: bookID,
		region: region, domain: domain, epoch: epoch, device: device, deviceSE: deviceSE,
		closure: closure, ids: ids,
	}
}

func (f *integrationFixture) issue(t *testing.T, amount int64) Allowance {
	t.Helper()
	allowanceID, err := f.service.NewAllowanceID(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	allowance, err := f.service.Issue(f.ctx, IssueRequest{
		AllowanceID: allowanceID, AccountID: f.accountID, AssetID: f.assetID,
		OriginRegion: f.region, DeviceIdentityHash: f.device,
		Amount: ledger.NewAmountInt64(amount),
	})
	if err != nil {
		t.Fatal(err)
	}
	return allowance
}

func (f *integrationFixture) presentation(t *testing.T, allowance Allowance) VerifiedPresentation {
	t.Helper()
	challenge := sha256.Sum256([]byte("merchant-challenge:" + allowance.AllowanceID))
	presentation, err := f.deviceSE.present(allowance, f.merchant, f.domain, challenge)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.service.VerifyPresentation(f.ctx, presentation)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func (f *integrationFixture) closureFor(t *testing.T, allowance Allowance) DomainClosure {
	t.Helper()
	closure, err := f.closure.closure(
		f.domain, allowance, allowance.Counter,
	)
	if err != nil {
		t.Fatal(err)
	}
	return closure
}

func (f *integrationFixture) fenceRequest(
	t *testing.T,
	allowance Allowance,
	closures ...DomainClosure,
) FenceRequest {
	t.Helper()
	payloadHash, err := allowance.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	return FenceRequest{
		AllowanceID: allowance.AllowanceID, ExpectedPayloadHash: payloadHash,
		ExpectedIssuerEpoch:   allowance.IssuerEpoch,
		ExpectedDeviceCounter: allowance.Counter, Kind: Revoked,
		PolicyEvidenceHash: sha256.Sum256([]byte("policy:" + allowance.AllowanceID)),
		DomainClosures:     closures,
	}
}

func TestOfflineIssueAndLedgerRedemptionAreExactlyOnce(t *testing.T) {
	fixture := newIntegrationFixture(t, 100)
	allowanceID, err := fixture.service.NewAllowanceID(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{
		AllowanceID: allowanceID, AccountID: fixture.accountID, AssetID: fixture.assetID,
		OriginRegion: fixture.region, DeviceIdentityHash: fixture.device,
		Amount: ledger.NewAmountInt64(40),
	}
	allowance, err := fixture.service.Issue(fixture.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	// Lost issuance ACK: retrying the same globally unique ID returns the exact
	// certificate and does not reserve another counter or another 40 atoms.
	// Use an unavailable signer to prove the retry reads the durable certificate
	// before touching the HSM control plane.
	outageService := NewService(
		fixture.runner, fixture.ids, unavailableSigner{}, fixture.service.verifier,
		fixture.service.presentationVerifier, fixture.service.closureVerifier,
	)
	retried, err := outageService.Issue(fixture.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Counter != allowance.Counter || !bytesEqual(retried.Signature, allowance.Signature) {
		t.Fatal("issuance retry did not return the original instrument")
	}
	assertConservation(t, fixture, "100", "60", "40")

	verified := fixture.presentation(t, allowance)
	postingHash := sha256.Sum256([]byte("offline-posting-request:" + allowance.AllowanceID))
	effect := RedemptionEffect{
		EffectID:            "redeem-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "redeem-tx-" + allowance.AllowanceID,
		PostingRequestHash:  postingHash,
	}
	post := ledger.PostRequest{
		TransactionID: effect.LedgerTransactionID, BookID: fixture.bookID,
		OperationID: "redeem-op-" + allowance.AllowanceID, EffectID: effect.EffectID,
		Kind: "OFFLINE_REDEMPTION", PostingRuleVersion: "offline/v1", SchemaVersion: 1,
		RequestHash: postingHash,
		Lines: []ledger.Line{
			{AccountID: fixture.accountID, AssetID: fixture.assetID, Side: ledger.Debit, AmountAtoms: allowance.Amount},
			{AccountID: fixture.merchant, AssetID: fixture.assetID, Side: ledger.Credit, AmountAtoms: allowance.Amount},
		},
	}
	// The database itself rejects a phantom consumption if a caller forgets to
	// post the ledger effect first; the whole attempted transaction rolls back.
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		_, inner := fixture.service.RedeemPresentationInTx(fixture.ctx, tx, verified, effect)
		return inner
	})
	if err == nil {
		t.Fatal("redemption without a matching POSTED ledger effect succeeded")
	}
	assertConservation(t, fixture, "100", "60", "40")
	wrongPost := post
	wrongPost.Lines = append([]ledger.Line(nil), post.Lines...)
	wrongPost.Lines[0].AmountAtoms = ledger.NewAmountInt64(39)
	wrongPost.Lines[1].AmountAtoms = ledger.NewAmountInt64(39)
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		if _, inner := fixture.journal.PostInTx(fixture.ctx, tx, wrongPost); inner != nil {
			return inner
		}
		_, inner := fixture.service.RedeemPresentationInTx(fixture.ctx, tx, verified, effect)
		return inner
	})
	if err == nil {
		t.Fatal("redemption whose ledger debit differs from the allowance succeeded")
	}
	assertConservation(t, fixture, "100", "60", "40")
	washPost := post
	washPost.TransactionID += "-wash"
	washPost.EffectID += "-wash"
	washPost.OperationID += "-wash"
	washPost.RequestHash = sha256.Sum256([]byte("offline-wash-post"))
	washPost.Lines = append([]ledger.Line(nil), post.Lines...)
	washPost.Lines = append(washPost.Lines,
		ledger.Line{AccountID: fixture.accountID, AssetID: fixture.assetID,
			Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(1)},
		ledger.Line{AccountID: fixture.merchant, AssetID: fixture.assetID,
			Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(1)},
	)
	washEffect := RedemptionEffect{
		EffectID: washPost.EffectID, LedgerTransactionID: washPost.TransactionID,
		PostingRequestHash: washPost.RequestHash,
	}
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		if _, inner := fixture.journal.PostInTx(fixture.ctx, tx, washPost); inner != nil {
			return inner
		}
		_, inner := fixture.service.RedeemPresentationInTx(
			fixture.ctx, tx, verified, washEffect,
		)
		return inner
	})
	if err == nil {
		t.Fatal("database accepted wash credits/debits around exact offline amount")
	}
	assertConservation(t, fixture, "100", "60", "40")

	var first Redemption
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		_, inner := fixture.journal.PostInTx(fixture.ctx, tx, post)
		if inner != nil {
			return inner
		}
		first, inner = fixture.service.RedeemPresentationInTx(fixture.ctx, tx, verified, effect)
		return inner
	})
	if err != nil || first.Duplicate {
		t.Fatalf("first atomic redemption = %#v, %v", first, err)
	}
	// Lost commit ACK: both the allowance receipt and ledger effect are durable
	// and the exact retry is a no-op in the same transaction.
	var duplicate Redemption
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		_, inner := fixture.journal.PostInTx(fixture.ctx, tx, post)
		if inner != nil {
			return inner
		}
		duplicate, inner = fixture.service.RedeemPresentationInTx(fixture.ctx, tx, verified, effect)
		return inner
	})
	if err != nil || !duplicate.Duplicate {
		t.Fatalf("duplicate atomic redemption = %#v, %v", duplicate, err)
	}
	different := effect
	different.EffectID += "-different"
	different.LedgerTransactionID += "-different"
	differentPost := post
	differentPost.EffectID = different.EffectID
	differentPost.TransactionID = different.LedgerTransactionID
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, verified, fixture.journal, differentPost,
	); !errors.Is(err, ErrRedemptionConflict) {
		t.Fatalf("different second redemption = %v", err)
	}
	assertConservation(t, fixture, "60", "60", "0")
}

func TestBareAllowanceCannotRedeemOrPostLedger(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 20)
	effect := RedemptionEffect{
		EffectID:            "bare-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "bare-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("bare-allowance-attempt")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, VerifiedPresentation{}, fixture.journal,
		fixture.posting(allowance, effect),
	); !errors.Is(err, ErrInvalidPresentation) {
		t.Fatalf("bare allowance redemption = %v", err)
	}
	var transactions int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT count(*) FROM ledger_transactions WHERE transaction_id=$1`,
		effect.LedgerTransactionID).Scan(&transactions); err != nil {
		t.Fatal(err)
	}
	if transactions != 0 {
		t.Fatalf("bare allowance created %d ledger transactions", transactions)
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestValidPresentationForUnconfiguredDomainFailsAtomically(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 20)
	raw, err := fixture.deviceSE.present(
		allowance, fixture.merchant, "unconfigured-domain",
		sha256.Sum256([]byte("unconfigured-domain-challenge")),
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.service.VerifyPresentation(fixture.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	effect := RedemptionEffect{
		EffectID:            "domain-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "domain-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("unconfigured-domain-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, verified, fixture.journal, fixture.posting(allowance, effect),
	); err == nil {
		t.Fatal("validly signed presentation from an unconfigured domain redeemed")
	}
	var transactions int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT count(*) FROM ledger_transactions WHERE transaction_id=$1`,
		effect.LedgerTransactionID).Scan(&transactions); err != nil {
		t.Fatal(err)
	}
	if transactions != 0 {
		t.Fatalf("rejected domain left %d ledger transactions", transactions)
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestOfflineRevocationRequiresDurableFenceAndReturnsOriginRight(t *testing.T) {
	fixture := newIntegrationFixture(t, 75)
	allowance := fixture.issue(t, 30)
	payloadHash, err := allowance.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	evidence := sha256.Sum256([]byte("signed-policy-decision:device-compromised"))
	request := FenceRequest{
		AllowanceID: allowance.AllowanceID, ExpectedPayloadHash: payloadHash,
		ExpectedIssuerEpoch: allowance.IssuerEpoch, ExpectedDeviceCounter: allowance.Counter,
		Kind: Revoked, PolicyEvidenceHash: evidence,
		DomainClosures: []DomainClosure{fixture.closureFor(t, allowance)},
	}
	proof, err := fixture.service.Terminate(fixture.ctx, request)
	if err != nil || proof.Duplicate || proof.FenceVersion == 0 {
		t.Fatalf("first revocation proof = %#v, %v", proof, err)
	}
	duplicate, err := fixture.service.Terminate(fixture.ctx, request)
	if err != nil || !duplicate.Duplicate || duplicate.ProofHash != proof.ProofHash {
		t.Fatalf("duplicate revocation proof = %#v, %v", duplicate, err)
	}
	effect := RedemptionEffect{
		EffectID: "late-effect", LedgerTransactionID: "late-tx",
		PostingRequestHash: sha256.Sum256([]byte("late-redemption")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, fixture.presentation(t, allowance), fixture.journal,
		fixture.posting(allowance, effect),
	); !errors.Is(err, ErrAllowanceTerminal) {
		t.Fatalf("redemption after fenced revocation = %v", err)
	}
	assertConservation(t, fixture, "75", "75", "0")
}

func TestConcurrentDuplicateRedemptionConsumesOnce(t *testing.T) {
	fixture := newIntegrationFixture(t, 50)
	allowance := fixture.issue(t, 50)
	verified := fixture.presentation(t, allowance)
	effect := RedemptionEffect{
		EffectID:            "one-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "one-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("same-economic-effect")),
	}
	post := fixture.posting(allowance, effect)
	const workers = 24
	var successes, duplicates atomic.Int64
	var group sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			redemption, err := fixture.service.RedeemAndPost(
				fixture.ctx, verified, fixture.journal, post,
			)
			if err != nil {
				errorsFound <- err
				return
			}
			if redemption.Allowance.Duplicate {
				duplicates.Add(1)
			} else {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	if successes.Load() != 1 || duplicates.Load() != workers-1 {
		t.Fatalf("successes=%d duplicates=%d", successes.Load(), duplicates.Load())
	}
	assertConservation(t, fixture, "0", "0", "0")
	customerBalance, err := fixture.journal.Balance(fixture.ctx, fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	customerFold, err := fixture.journal.FoldBalance(fixture.ctx, fixture.accountID)
	if err != nil {
		t.Fatal(err)
	}
	merchantFold, err := fixture.journal.FoldBalance(fixture.ctx, fixture.merchant)
	if err != nil {
		t.Fatal(err)
	}
	if customerBalance.CurrentBalanceAtoms.String() != "-50" ||
		customerFold.String() != "-50" || merchantFold.String() != "50" {
		t.Fatalf("ledger was not posted exactly once: balance=%s customer_fold=%s merchant_fold=%s",
			customerBalance.CurrentBalanceAtoms.String(), customerFold.String(), merchantFold.String())
	}
}

func TestCopiedAllowanceCannotChangeMerchantDomainOrChallenge(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 20)
	challenge := sha256.Sum256([]byte("terminal-nonce:" + allowance.AllowanceID))
	presentation, err := fixture.deviceSE.present(
		allowance, fixture.merchant, fixture.domain, challenge,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.VerifyPresentation(fixture.ctx, presentation); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Presentation){
		func(value *Presentation) { value.MerchantAccountID += "-attacker" },
		func(value *Presentation) { value.AcceptanceDomain += "-foreign" },
		func(value *Presentation) { value.MerchantChallenge[0] ^= 1 },
	}
	for index, mutate := range mutations {
		copied := presentation
		copied.Signature = append([]byte(nil), presentation.Signature...)
		mutate(&copied)
		if _, err := fixture.service.VerifyPresentation(fixture.ctx, copied); !errors.Is(err, ErrInvalidPresentation) {
			t.Fatalf("copied presentation mutation %d = %v", index, err)
		}
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestPresentationChallengeDedupIsPermanentAcrossAllowances(t *testing.T) {
	fixture := newIntegrationFixture(t, 60)
	firstAllowance := fixture.issue(t, 20)
	secondAllowance := fixture.issue(t, 20)
	challenge := sha256.Sum256([]byte("domain-unique-merchant-challenge"))
	firstRaw, err := fixture.deviceSE.present(
		firstAllowance, fixture.merchant, fixture.domain, challenge,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := fixture.deviceSE.present(
		secondAllowance, fixture.merchant, fixture.domain, challenge,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.service.VerifyPresentation(fixture.ctx, firstRaw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.service.VerifyPresentation(fixture.ctx, secondRaw)
	if err != nil {
		t.Fatal(err)
	}
	firstEffect := RedemptionEffect{
		EffectID:            "challenge-first-" + firstAllowance.AllowanceID,
		LedgerTransactionID: "challenge-first-tx-" + firstAllowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("challenge-first-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, first, fixture.journal, fixture.posting(firstAllowance, firstEffect),
	); err != nil {
		t.Fatal(err)
	}
	secondEffect := RedemptionEffect{
		EffectID:            "challenge-second-" + secondAllowance.AllowanceID,
		LedgerTransactionID: "challenge-second-tx-" + secondAllowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("challenge-second-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, second, fixture.journal, fixture.posting(secondAllowance, secondEffect),
	); !errors.Is(err, ErrRedemptionConflict) {
		t.Fatalf("reused challenge = %v", err)
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestDelayedValidPresentationCannotBeTerminatedBeforeClosure(t *testing.T) {
	fixture := newIntegrationFixture(t, 50)
	allowance := fixture.issue(t, 20)
	verified := fixture.presentation(t, allowance)
	staleClosure, err := fixture.closure.closure(
		fixture.domain, allowance, allowance.Counter-1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Terminate(
		fixture.ctx, fixture.fenceRequest(t, allowance, staleClosure),
	); !errors.Is(err, ErrIncompleteClosure) {
		t.Fatalf("termination below upload fence = %v", err)
	}
	assertConservation(t, fixture, "50", "30", "20")
	effect := RedemptionEffect{
		EffectID:            "delayed-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "delayed-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("delayed-valid-presentation")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, verified, fixture.journal, fixture.posting(allowance, effect),
	); err != nil {
		t.Fatal(err)
	}
	assertConservation(t, fixture, "30", "30", "0")
}

func TestTerminationRequiresEveryConfiguredAcceptanceDomain(t *testing.T) {
	fixture := newIntegrationFixture(t, 50)
	secondClosure := newLocalEd25519(t)
	secondClosure.keyID = "second-closure-" + integrationSuffix(t)
	secondDomain := "second-domain-" + integrationSuffix(t)
	if err := fixture.service.ConfigureAcceptanceDomain(fixture.ctx, AcceptanceDomain{
		Name: secondDomain, ClosureKeyID: secondClosure.keyID,
		FirstSettlementEpoch: fixture.epoch, LastSettlementEpoch: fixture.epoch + 1,
	}); err != nil {
		t.Fatal(err)
	}
	allowance := fixture.issue(t, 20)
	completeService := NewService(
		fixture.runner, fixture.ids, fixture.service.signer, fixture.service.verifier,
		fixture.service.presentationVerifier,
		closureVerifierSet{
			fixture.closure.keyID: fixture.closure,
			secondClosure.keyID:   secondClosure,
		},
	)
	if _, err := completeService.Terminate(
		fixture.ctx, fixture.fenceRequest(t, allowance, fixture.closureFor(t, allowance)),
	); !errors.Is(err, ErrIncompleteClosure) {
		t.Fatalf("termination with one domain missing = %v", err)
	}
	assertConservation(t, fixture, "50", "30", "20")
	secondEvidence, err := secondClosure.closure(
		secondDomain, allowance, allowance.Counter,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := completeService.Terminate(fixture.ctx, fixture.fenceRequest(
		t, allowance, fixture.closureFor(t, allowance), secondEvidence,
	)); err != nil {
		t.Fatalf("termination with complete independently signed domain set = %v", err)
	}
	assertConservation(t, fixture, "50", "50", "0")
}

func TestClosureForDifferentIssuanceNamespaceCannotReturnAuthority(t *testing.T) {
	fixture := newIntegrationFixture(t, 60)
	first := fixture.issue(t, 20)
	foreignNamespace := first
	foreignNamespace.DeviceIdentityHash = sha256.Sum256([]byte("foreign-device-namespace"))
	if err := fixture.service.EnrollDevice(fixture.ctx, Device{
		AccountID: fixture.accountID, AssetID: fixture.assetID,
		OriginRegion: fixture.region, DeviceIdentityHash: foreignNamespace.DeviceIdentityHash,
		IssuerEpoch: fixture.epoch,
	}); err != nil {
		t.Fatal(err)
	}
	// The high watermark deliberately covers first.Counter. Safety must still
	// bind to the exact device/authority namespace because counters are not global.
	wrongEvidence, err := fixture.closure.closure(
		fixture.domain, foreignNamespace, first.Counter+100,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.fenceRequest(t, first, wrongEvidence)
	if _, err := fixture.service.Terminate(
		fixture.ctx, request,
	); !errors.Is(err, ErrIncompleteClosure) {
		t.Fatalf("closure for another allowance = %v", err)
	}
	// Defense in depth: even a buggy runtime that bypassed the Go namespace
	// comparison cannot manufacture a non-redemption proof directly in SQL.
	closureSet, err := verifyClosureSet(fixture.ctx, fixture.service.closureVerifier, request)
	if err != nil {
		t.Fatal(err)
	}
	value := closureSet.byDomain[fixture.domain]
	forgedProofHash := sha256.Sum256([]byte("forged-proof"))
	proofAttempted := false
	err = fixture.runner.RunSerializable(fixture.ctx, func(tx pgx.Tx) error {
		if _, inner := tx.Exec(fixture.ctx, `
INSERT INTO offline_domain_closure_evidence
 (evidence_hash, acceptance_domain, account_id, asset_id, origin_region,
  device_identity_hash, closed_settlement_epoch, closed_upload_fence,
  key_id, payload_hash, canonical_payload, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			value.evidenceHash[:], fixture.domain, value.closure.AccountID,
			value.closure.AssetID, value.closure.OriginRegion,
			value.closure.DeviceIdentityHash[:], int64(value.closure.ClosedSettlementEpoch),
			int64(value.closure.ClosedUploadFence), value.closure.KeyID,
			value.payloadHash[:], value.payload, value.closure.Signature); inner != nil {
			return inner
		}
		if _, inner := tx.Exec(fixture.ctx, `
INSERT INTO offline_termination_closure_links
 (allowance_id, acceptance_domain, evidence_hash)
VALUES ($1,$2,$3)`, first.AllowanceID, fixture.domain, value.evidenceHash[:]); inner != nil {
			return inner
		}
		proofAttempted = true
		_, inner := tx.Exec(fixture.ctx, `
INSERT INTO offline_non_redemption_proofs
 (allowance_id, terminal_kind, payload_hash, issuer_epoch, device_counter,
  fence_version, policy_evidence_hash, closure_set_hash, proof_hash)
VALUES ($1,'REVOKED',$2,$3,$4,1,$5,$6,$7)`, first.AllowanceID,
			request.ExpectedPayloadHash[:], int64(request.ExpectedIssuerEpoch),
			int64(request.ExpectedDeviceCounter), request.PolicyEvidenceHash[:],
			closureSet.setHash[:], forgedProofHash[:])
		return inner
	})
	if !proofAttempted || err == nil ||
		(!strings.Contains(err.Error(), "offline termination lacks complete signed domain closure") &&
			!strings.Contains(err.Error(), "offline termination proof does not bind terminal allowance")) {
		t.Fatalf("database accepted cross-namespace closure: attempted=%t error=%v", proofAttempted, err)
	}
	assertConservation(t, fixture, "60", "40", "20")
}

func TestDevicePresentationCounterCannotBeReusedAcrossAllowances(t *testing.T) {
	fixture := newIntegrationFixture(t, 60)
	firstAllowance := fixture.issue(t, 20)
	secondAllowance := fixture.issue(t, 20)
	first := fixture.presentation(t, firstAllowance)
	secondRaw, err := fixture.deviceSE.present(
		secondAllowance, fixture.merchant, fixture.domain,
		sha256.Sum256([]byte("second-counter-challenge:"+secondAllowance.AllowanceID)),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw.PresentationCounter = first.presentation.PresentationCounter
	payload, err := secondRaw.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	secondRaw.Signature = ed25519.Sign(fixture.deviceSE.private, payload)
	second, err := fixture.service.VerifyPresentation(fixture.ctx, secondRaw)
	if err != nil {
		t.Fatal(err)
	}
	firstEffect := RedemptionEffect{
		EffectID:            "counter-first-" + firstAllowance.AllowanceID,
		LedgerTransactionID: "counter-first-tx-" + firstAllowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("counter-first-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, first, fixture.journal, fixture.posting(firstAllowance, firstEffect),
	); err != nil {
		t.Fatal(err)
	}
	secondEffect := RedemptionEffect{
		EffectID:            "counter-second-" + secondAllowance.AllowanceID,
		LedgerTransactionID: "counter-second-tx-" + secondAllowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("counter-second-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, second, fixture.journal, fixture.posting(secondAllowance, secondEffect),
	); !errors.Is(err, ErrRedemptionConflict) {
		t.Fatalf("reused hardware presentation counter = %v", err)
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestRedemptionTerminationRaceHasOneEconomicWinner(t *testing.T) {
	fixture := newIntegrationFixture(t, 70)
	allowance := fixture.issue(t, 30)
	verified := fixture.presentation(t, allowance)
	effect := RedemptionEffect{
		EffectID:            "race-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "race-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("termination-race")),
	}
	termination := fixture.fenceRequest(t, allowance, fixture.closureFor(t, allowance))
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := fixture.service.RedeemAndPost(
			fixture.ctx, verified, fixture.journal, fixture.posting(allowance, effect),
		)
		results <- err
	}()
	go func() {
		<-start
		_, err := fixture.service.Terminate(fixture.ctx, termination)
		results <- err
	}()
	close(start)
	first, second := <-results, <-results
	successes := 0
	for _, err := range []error{first, second} {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrAlreadyRedeemed) && !errors.Is(err, ErrAllowanceTerminal) {
			t.Fatalf("unexpected race result: %v (other=%v)", err, second)
		}
	}
	if successes != 1 {
		t.Fatalf("race successes=%d first=%v second=%v", successes, first, second)
	}
	snapshot, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || snapshot.OfflineIssued.Sign() != 0 {
		t.Fatalf("race broke conservation: %#v", snapshot)
	}
}

func TestHardwareVerifierOutageFailsClosed(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 20)
	challenge := sha256.Sum256([]byte("hsm-outage-challenge"))
	presentation, err := fixture.deviceSE.present(
		allowance, fixture.merchant, fixture.domain, challenge,
	)
	if err != nil {
		t.Fatal(err)
	}
	outage := NewService(
		fixture.runner, fixture.ids, fixture.service.signer, fixture.service.verifier,
		unavailablePresentationVerifier{}, unavailableClosureVerifier{},
	)
	if _, err := outage.VerifyPresentation(fixture.ctx, presentation); !errors.Is(err, ErrVerifierUnavailable) {
		t.Fatalf("presentation verifier outage = %v", err)
	}
	if _, err := outage.Terminate(
		fixture.ctx, fixture.fenceRequest(t, allowance, fixture.closureFor(t, allowance)),
	); !errors.Is(err, ErrVerifierUnavailable) {
		t.Fatalf("closure verifier outage = %v", err)
	}
	assertConservation(t, fixture, "40", "20", "20")
}

func TestIssuerEpochFencesDelayedPreparedAllowance(t *testing.T) {
	fixture := newIntegrationFixture(t, 20)
	allowanceID, err := fixture.service.NewAllowanceID(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{
		AllowanceID: allowanceID, AccountID: fixture.accountID, AssetID: fixture.assetID,
		OriginRegion: fixture.region, DeviceIdentityHash: fixture.device,
		Amount: ledger.NewAmountInt64(5),
	}
	keyID, err := fixture.service.signer.ActiveKeyID(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	prepared, state, err := fixture.service.prepare(fixture.ctx, request, keyID)
	if err != nil || state != statePrepared {
		t.Fatalf("prepare = %#v, %s, %v", prepared, state, err)
	}
	if err := fixture.service.AdvanceIssuerEpoch(fixture.ctx, Device{
		AccountID: fixture.accountID, AssetID: fixture.assetID,
		OriginRegion: fixture.region, DeviceIdentityHash: fixture.device, IssuerEpoch: fixture.epoch,
	}, fixture.epoch+1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.signAndActivate(fixture.ctx, prepared); !errors.Is(err, ErrFenceConflict) {
		t.Fatalf("stale prepared allowance activation = %v", err)
	}
	assertConservation(t, fixture, "20", "20", "0")
	fresh := fixture.issue(t, 5)
	if fresh.IssuerEpoch != fixture.epoch+1 || fresh.Counter != 1 {
		t.Fatalf("new fenced namespace = epoch %d counter %d", fresh.IssuerEpoch, fresh.Counter)
	}
	assertConservation(t, fixture, "20", "15", "5")
}

func TestVerifiedPresentationOwnsAuditBytesAfterCallerMutation(t *testing.T) {
	fixture := newIntegrationFixture(t, 30)
	allowance := fixture.issue(t, 20)
	challenge := sha256.Sum256([]byte("owned-audit-bytes:" + allowance.AllowanceID))
	raw, err := fixture.deviceSE.present(
		allowance, fixture.merchant, fixture.domain, challenge,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.service.VerifyPresentation(fixture.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	expectedPayload := append([]byte(nil), verified.payload...)
	expectedPresentationSignature := append([]byte(nil), raw.Signature...)
	expectedAllowanceSignature := append([]byte(nil), raw.Allowance.Signature...)
	raw.Signature[0] ^= 0xff
	raw.Allowance.Signature[0] ^= 0xff

	effect := RedemptionEffect{
		EffectID:            "owned-bytes-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "owned-bytes-tx-" + allowance.AllowanceID,
		PostingRequestHash:  sha256.Sum256([]byte("owned-bytes-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, verified, fixture.journal, fixture.posting(allowance, effect),
	); err != nil {
		t.Fatal(err)
	}
	var storedPayload, storedPresentationSignature, storedAllowanceSignature []byte
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT receipt.presentation_payload, receipt.presentation_signature,
       allowance.signature
FROM offline_redemption_receipts AS receipt
JOIN offline_allowances AS allowance USING (allowance_id)
WHERE receipt.allowance_id=$1`, allowance.AllowanceID).Scan(
		&storedPayload, &storedPresentationSignature, &storedAllowanceSignature); err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(storedPayload, expectedPayload) ||
		!bytesEqual(storedPresentationSignature, expectedPresentationSignature) ||
		!bytesEqual(storedAllowanceSignature, expectedAllowanceSignature) {
		t.Fatal("caller-owned slices changed immutable financial audit bytes")
	}
}

func TestAcceptanceDomainKeyRotationIsAppendOnlyAndEpochBound(t *testing.T) {
	fixture := newIntegrationFixture(t, 90)
	first := fixture.issue(t, 20)
	oldHistorical := closureAtEpoch(
		t, fixture.closure, fixture.domain, first, fixture.epoch, first.Counter,
	)
	newKey := newLocalEd25519(t)
	newKey.keyID = "rotated-closure-" + integrationSuffix(t)
	if err := fixture.service.RotateAcceptanceDomainKey(fixture.ctx, AcceptanceDomainKeyRotation{
		AcceptanceDomain: fixture.domain, ExpectedKeyID: fixture.closure.keyID,
		NewKeyID: newKey.keyID, EffectiveEpoch: fixture.epoch + 1,
		PriorKeyReason: KeyRetired,
	}); err != nil {
		t.Fatal(err)
	}
	completeService := NewService(
		fixture.runner, fixture.ids, fixture.service.signer, fixture.service.verifier,
		fixture.service.presentationVerifier,
		closureVerifierSet{fixture.closure.keyID: fixture.closure, newKey.keyID: newKey},
	)
	// Retirement is prospective: a closure whose signed logical watermark is
	// inside the old window remains independently auditable and valid.
	if _, err := completeService.Terminate(
		fixture.ctx, fixture.fenceRequest(t, first, oldHistorical),
	); err != nil {
		t.Fatalf("historical closure after rotation = %v", err)
	}
	if err := fixture.service.AdvanceIssuerEpoch(fixture.ctx, Device{
		AccountID: fixture.accountID, AssetID: fixture.assetID,
		OriginRegion: fixture.region, DeviceIdentityHash: fixture.device,
		IssuerEpoch: fixture.epoch,
	}, fixture.epoch+1); err != nil {
		t.Fatal(err)
	}
	second := fixture.issue(t, 20)
	compromisedOld := closureAtEpoch(
		t, fixture.closure, fixture.domain, second, fixture.epoch+1, second.Counter,
	)
	if _, err := completeService.Terminate(
		fixture.ctx, fixture.fenceRequest(t, second, compromisedOld),
	); !errors.Is(err, ErrIncompleteClosure) {
		t.Fatalf("retired key at later epoch = %v", err)
	}
	newEvidence := closureAtEpoch(
		t, newKey, fixture.domain, second, fixture.epoch+1, second.Counter,
	)
	if _, err := completeService.Terminate(
		fixture.ctx, fixture.fenceRequest(t, second, newEvidence),
	); err != nil {
		t.Fatalf("rotated key at exact epoch = %v", err)
	}

	var activations, terminations, overlaps int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT
 (SELECT count(*) FROM offline_acceptance_domain_key_activations
   WHERE acceptance_domain=$1),
 (SELECT count(*) FROM offline_acceptance_domain_key_terminations
   WHERE acceptance_domain=$1),
 (SELECT count(*)
    FROM offline_acceptance_domain_key_activations AS left_key
    JOIN offline_acceptance_domain_key_activations AS right_key
      ON right_key.acceptance_domain=left_key.acceptance_domain
     AND right_key.activated_epoch>left_key.activated_epoch
    LEFT JOIN offline_acceptance_domain_key_terminations AS left_end
      ON left_end.acceptance_domain=left_key.acceptance_domain
     AND left_end.key_id=left_key.key_id
   WHERE left_key.acceptance_domain=$1
     AND (left_end.terminated_epoch IS NULL
          OR left_end.terminated_epoch>right_key.activated_epoch))`,
		fixture.domain).Scan(&activations, &terminations, &overlaps); err != nil {
		t.Fatal(err)
	}
	if activations != 2 || terminations != 1 || overlaps != 0 {
		t.Fatalf("key history activations=%d terminations=%d overlaps=%d",
			activations, terminations, overlaps)
	}
}

func TestConcurrentKeyRotationHasOneNonOverlappingWinner(t *testing.T) {
	fixture := newIntegrationFixture(t, 10)
	firstCandidate := "rotation-a-" + integrationSuffix(t)
	secondCandidate := "rotation-b-" + integrationSuffix(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, keyID := range []string{firstCandidate, secondCandidate} {
		keyID := keyID
		go func() {
			<-start
			results <- fixture.service.RotateAcceptanceDomainKey(
				fixture.ctx, AcceptanceDomainKeyRotation{
					AcceptanceDomain: fixture.domain,
					ExpectedKeyID:    fixture.closure.keyID, NewKeyID: keyID,
					EffectiveEpoch: fixture.epoch + 1, PriorKeyReason: KeyRevoked,
				},
			)
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for index := 0; index < 2; index++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrKeyLifecycleConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent rotation result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("rotation successes=%d conflicts=%d", successes, conflicts)
	}
	var activations, terminations int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT
 (SELECT count(*) FROM offline_acceptance_domain_key_activations
   WHERE acceptance_domain=$1),
 (SELECT count(*) FROM offline_acceptance_domain_key_terminations
   WHERE acceptance_domain=$1)`, fixture.domain).Scan(&activations, &terminations); err != nil {
		t.Fatal(err)
	}
	if activations != 2 || terminations != 1 {
		t.Fatalf("concurrent rotation history activations=%d terminations=%d",
			activations, terminations)
	}
}

func TestAcceptanceDomainConfigurationRoleIsExecuteOnly(t *testing.T) {
	fixture := newIntegrationFixture(t, 10)
	tx, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(fixture.ctx)
	if _, err := tx.Exec(fixture.ctx, `SET LOCAL ROLE offline_configuration_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(fixture.ctx, `
INSERT INTO offline_acceptance_domain_key_activations
 (acceptance_domain,key_id,activated_epoch) VALUES ($1,$2,$3)`,
		fixture.domain, "raw-key-"+integrationSuffix(t), int64(fixture.epoch+1)); !isOfflinePermissionDenied(err) {
		t.Fatalf("raw key activation error=%v, want SQLSTATE 42501", err)
	}
	// A permission error aborts the SQL transaction; use a fresh one for the
	// guarded operation.
	_ = tx.Rollback(fixture.ctx)
	tx, err = fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(fixture.ctx)
	if _, err := tx.Exec(fixture.ctx, `SET LOCAL ROLE offline_configuration_runtime`); err != nil {
		t.Fatal(err)
	}
	newKeyID := "control-plane-key-" + integrationSuffix(t)
	var changed bool
	if err := tx.QueryRow(fixture.ctx, `
SELECT public.rotate_offline_acceptance_domain_key($1,$2,$3,$4,'RETIRED')`,
		fixture.domain, fixture.closure.keyID, newKeyID,
		int64(fixture.epoch+1)).Scan(&changed); err != nil || !changed {
		t.Fatalf("guarded key rotation changed=%t err=%v", changed, err)
	}
	if err := tx.Commit(fixture.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineRuntimeCannotRawMintOrBypassCoherentProcedures(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 10)
	before, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"coherent authority mint": `UPDATE escrow_authorities SET total_authority=total_authority+100, unallocated=unallocated+100 WHERE account_id='` + fixture.accountID + `' AND asset_id='` + fixture.assetID + `'`,
		"raw total authority":     `UPDATE escrow_authorities SET total_authority=total_authority+100 WHERE account_id='` + fixture.accountID + `' AND asset_id='` + fixture.assetID + `'`,
		"raw regional authority":  `UPDATE escrow_regional_rights SET available=available+100 WHERE account_id='` + fixture.accountID + `' AND asset_id='` + fixture.assetID + `'`,
		"raw allowance":           `UPDATE offline_allowances SET state='REDEEMED', redeemed_at=transaction_timestamp() WHERE allowance_id='` + allowance.AllowanceID + `'`,
		"raw proof":               `INSERT INTO offline_non_redemption_proofs (allowance_id,terminal_kind,payload_hash,issuer_epoch,device_counter,fence_version,policy_evidence_hash,closure_set_hash,proof_hash) SELECT allowance_id,'REVOKED',payload_hash,issuer_epoch,device_counter,1,payload_hash,payload_hash,payload_hash FROM offline_allowances WHERE allowance_id='` + allowance.AllowanceID + `'`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(fixture.ctx)
			if _, err := tx.Exec(fixture.ctx, `SET LOCAL ROLE offline_runtime`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(fixture.ctx, statement); !isOfflinePermissionDenied(err) {
				t.Fatalf("raw authority error=%v, want SQLSTATE 42501", err)
			}
		})
	}
	// EXECUTE is also not an arbitrary mint primitive: without an immutable
	// prepared allowance it cannot move any financial bucket.
	tx, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(fixture.ctx, `SET LOCAL ROLE offline_runtime`); err != nil {
		_ = tx.Rollback(fixture.ctx)
		t.Fatal(err)
	}
	var changed bool
	err = tx.QueryRow(fixture.ctx, `
SELECT public.activate_offline_allowance($1,$2,$3)`,
		"nonexistent-"+allowance.AllowanceID, make([]byte, 32), []byte("not-an-hsm-proof")).Scan(&changed)
	_ = tx.Rollback(fixture.ctx)
	if err == nil || isOfflinePermissionDenied(err) {
		t.Fatalf("unlinked activation error=%v; expected guarded procedure rejection", err)
	}
	after, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	if before.TotalAuthority.Cmp(after.TotalAuthority) != 0 ||
		before.Regional.Cmp(after.Regional) != 0 ||
		before.OfflineIssued.Cmp(after.OfflineIssued) != 0 || !after.Conserved() {
		t.Fatalf("denied coherent-mint attempts changed authority: before=%#v after=%#v",
			before, after)
	}
}

func TestNarrowProceduresRejectKeyAndAllowanceFenceSubstitution(t *testing.T) {
	fixture := newIntegrationFixture(t, 40)
	allowance := fixture.issue(t, 10)
	before, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	var counterBefore int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT last_counter FROM offline_device_counters
WHERE account_id=$1 AND asset_id=$2 AND origin_region=$3
  AND device_identity_hash=$4`, fixture.accountID, fixture.assetID,
		fixture.region, fixture.device[:]).Scan(&counterBefore); err != nil {
		t.Fatal(err)
	}
	var changed bool
	err = fixture.pool.QueryRow(fixture.ctx, `
SELECT public.prepare_offline_allowance($1,$2,$3,$4,$5,$6,$7)`,
		allowance.AllowanceID, allowance.AccountID, allowance.AssetID,
		allowance.OriginRegion, allowance.DeviceIdentityHash[:],
		allowance.Amount.String(), "substituted-issuer-key").Scan(&changed)
	if err != nil || changed {
		t.Fatalf("existing allowance retry after key rotation changed=%t error=%v", changed, err)
	}
	var storedKey string
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT key_id FROM offline_allowances WHERE allowance_id=$1`,
		allowance.AllowanceID).Scan(&storedKey); err != nil {
		t.Fatal(err)
	}
	if storedKey != allowance.KeyID {
		t.Fatalf("idempotent retry replaced stored issuer key %q with %q",
			allowance.KeyID, storedKey)
	}
	payloadHash, err := allowance.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	policyHash := sha256.Sum256([]byte("substituted-policy"))
	closureSetHash := sha256.Sum256([]byte("substituted-closure-set"))
	var fence int64
	err = fixture.pool.QueryRow(fixture.ctx, `
SELECT public.terminate_offline_allowance($1,$2,$3,$4,$5,$6,$7)`,
		allowance.AllowanceID, string(Revoked), payloadHash[:],
		int64(allowance.IssuerEpoch+1), int64(allowance.Counter),
		policyHash[:], closureSetHash[:]).Scan(&fence)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "allowance mismatch") {
		t.Fatalf("termination issuer-epoch substitution error=%v", err)
	}
	var state string
	var counterAfter int64
	if err := fixture.pool.QueryRow(fixture.ctx, `
SELECT allowance.state, device.last_counter
FROM offline_allowances AS allowance
JOIN offline_device_counters AS device
  ON device.account_id=allowance.account_id
 AND device.asset_id=allowance.asset_id
 AND device.origin_region=allowance.origin_region
 AND device.device_identity_hash=allowance.device_identity_hash
WHERE allowance.allowance_id=$1`, allowance.AllowanceID).Scan(&state, &counterAfter); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	if state != stateIssued || counterAfter != counterBefore || !after.Conserved() ||
		before.TotalAuthority.Cmp(after.TotalAuthority) != 0 ||
		before.Regional.Cmp(after.Regional) != 0 ||
		before.OfflineIssued.Cmp(after.OfflineIssued) != 0 {
		t.Fatalf("substitution changed facts: state=%s counter=%d/%d before=%#v after=%#v",
			state, counterBefore, counterAfter, before, after)
	}
}

func closureAtEpoch(
	t *testing.T,
	signer *localEd25519,
	domain string,
	allowance Allowance,
	epoch, fence uint64,
) DomainClosure {
	t.Helper()
	closure := DomainClosure{
		Version: ClosureVersion, AcceptanceDomain: domain,
		AccountID: allowance.AccountID, AssetID: allowance.AssetID,
		OriginRegion:          allowance.OriginRegion,
		DeviceIdentityHash:    allowance.DeviceIdentityHash,
		ClosedSettlementEpoch: epoch, ClosedUploadFence: fence,
		KeyID: signer.keyID,
	}
	payload, err := closure.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	closure.Signature = ed25519.Sign(signer.private, payload)
	return closure
}

func isOfflinePermissionDenied(err error) bool {
	var databaseError *pgconn.PgError
	return err != nil && errors.As(err, &databaseError) && databaseError.Code == "42501"
}

func (f *integrationFixture) posting(allowance Allowance, effect RedemptionEffect) ledger.PostRequest {
	return ledger.PostRequest{
		TransactionID: effect.LedgerTransactionID, BookID: f.bookID,
		OperationID: "offline-operation-" + allowance.AllowanceID,
		EffectID:    effect.EffectID, Kind: "OFFLINE_REDEMPTION",
		PostingRuleVersion: "offline/v1", SchemaVersion: 1,
		RequestHash: effect.PostingRequestHash,
		Lines: []ledger.Line{
			{AccountID: f.accountID, AssetID: f.assetID, Side: ledger.Debit, AmountAtoms: allowance.Amount},
			{AccountID: f.merchant, AssetID: f.assetID, Side: ledger.Credit, AmountAtoms: allowance.Amount},
		},
	}
}

func assertConservation(t *testing.T, fixture *integrationFixture, total, regional, offline string) {
	t.Helper()
	snapshot, err := fixture.service.Snapshot(fixture.ctx, fixture.accountID, fixture.assetID)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Conserved() || snapshot.TotalAuthority.String() != total ||
		snapshot.Regional.String() != regional || snapshot.OfflineIssued.String() != offline {
		t.Fatalf("authority conservation failed: %#v", snapshot)
	}
}

func integrationSuffix(t *testing.T) string {
	t.Helper()
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}

func integrationEpoch(t *testing.T) uint64 {
	t.Helper()
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	epoch := binary.BigEndian.Uint64(value[:]) & uint64(math.MaxInt64)
	if epoch == 0 {
		epoch = 1
	}
	if epoch == uint64(math.MaxInt64) {
		epoch--
	}
	return epoch
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
