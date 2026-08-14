//go:build integration

package offline

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
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
	if err := service.ConfigureAcceptanceDomain(ctx, AcceptanceDomain{
		Name: domain, ClosureKeyID: closure.keyID, FirstSettlementEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	device := deviceSE.identityHash()
	if err := service.EnrollDevice(ctx, Device{
		AccountID: accountID, AssetID: assetID, OriginRegion: region,
		DeviceIdentityHash: device, IssuerEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return &integrationFixture{
		ctx: ctx, pool: pool, runner: runner, service: service, journal: journal,
		accountID: accountID, assetID: assetID, merchant: merchant, bookID: bookID,
		region: region, domain: domain, device: device, deviceSE: deviceSE,
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
	closure, err := f.closure.closure(f.domain, allowance.IssuerEpoch, allowance.Counter)
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
		ExpectedIssuerEpoch: allowance.IssuerEpoch,
		ExpectedDeviceCounter: allowance.Counter, Kind: Revoked,
		PolicyEvidenceHash: sha256.Sum256([]byte("policy:" + allowance.AllowanceID)),
		DomainClosures: closures,
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
		if _, err := fixture.service.VerifyPresentation(fixture.ctx, copied);
			!errors.Is(err, ErrInvalidPresentation) {
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
		EffectID: "challenge-first-" + firstAllowance.AllowanceID,
		LedgerTransactionID: "challenge-first-tx-" + firstAllowance.AllowanceID,
		PostingRequestHash: sha256.Sum256([]byte("challenge-first-post")),
	}
	if _, err := fixture.service.RedeemAndPost(
		fixture.ctx, first, fixture.journal, fixture.posting(firstAllowance, firstEffect),
	); err != nil {
		t.Fatal(err)
	}
	secondEffect := RedemptionEffect{
		EffectID: "challenge-second-" + secondAllowance.AllowanceID,
		LedgerTransactionID: "challenge-second-tx-" + secondAllowance.AllowanceID,
		PostingRequestHash: sha256.Sum256([]byte("challenge-second-post")),
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
		fixture.domain, allowance.IssuerEpoch, allowance.Counter-1,
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
		EffectID: "delayed-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "delayed-tx-" + allowance.AllowanceID,
		PostingRequestHash: sha256.Sum256([]byte("delayed-valid-presentation")),
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
	if err := fixture.service.ConfigureAcceptanceDomain(fixture.ctx, AcceptanceDomain{
		Name: "second-domain-" + integrationSuffix(t), ClosureKeyID: secondClosure.keyID,
		FirstSettlementEpoch: 1,
	}); err != nil {
		t.Fatal(err)
	}
	allowance := fixture.issue(t, 20)
	if _, err := fixture.service.Terminate(
		fixture.ctx, fixture.fenceRequest(t, allowance, fixture.closureFor(t, allowance)),
	); !errors.Is(err, ErrIncompleteClosure) {
		t.Fatalf("termination with one domain missing = %v", err)
	}
	assertConservation(t, fixture, "50", "30", "20")
}

func TestRedemptionTerminationRaceHasOneEconomicWinner(t *testing.T) {
	fixture := newIntegrationFixture(t, 70)
	allowance := fixture.issue(t, 30)
	verified := fixture.presentation(t, allowance)
	effect := RedemptionEffect{
		EffectID: "race-effect-" + allowance.AllowanceID,
		LedgerTransactionID: "race-tx-" + allowance.AllowanceID,
		PostingRequestHash: sha256.Sum256([]byte("termination-race")),
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
	if _, err := outage.VerifyPresentation(fixture.ctx, presentation);
		!errors.Is(err, ErrVerifierUnavailable) {
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
		OriginRegion: fixture.region, DeviceIdentityHash: fixture.device, IssuerEpoch: 1,
	}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.signAndActivate(fixture.ctx, prepared); !errors.Is(err, ErrFenceConflict) {
		t.Fatalf("stale prepared allowance activation = %v", err)
	}
	assertConservation(t, fixture, "20", "20", "0")
	fresh := fixture.issue(t, 5)
	if fresh.IssuerEpoch != 2 || fresh.Counter != 1 {
		t.Fatalf("new fenced namespace = epoch %d counter %d", fresh.IssuerEpoch, fresh.Counter)
	}
	assertConservation(t, fixture, "20", "15", "5")
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
