package offline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

// localEd25519 is deliberately test-only. Production code exposes only the
// HSM/KMS interfaces and never loads raw private keys into the process.
type localEd25519 struct {
	keyID               string
	private             ed25519.PrivateKey
	public              ed25519.PublicKey
	presentMu           sync.Mutex
	spentAllowances     map[[32]byte]struct{}
	presentationCounter uint64
}

func newLocalEd25519(t *testing.T) *localEd25519 {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &localEd25519{
		keyID: "test-key-version-7", private: private, public: public,
		spentAllowances: make(map[[32]byte]struct{}),
	}
}

func (s *localEd25519) ActiveKeyID(context.Context) (string, error) { return s.keyID, nil }

func (s *localEd25519) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	if keyID != s.keyID {
		return nil, errors.New("unknown key version")
	}
	return ed25519.Sign(s.private, message), nil
}

func (s *localEd25519) Verify(_ context.Context, keyID string, message, signature []byte) error {
	if keyID != s.keyID || !ed25519.Verify(s.public, message, signature) {
		return errors.New("signature mismatch")
	}
	return nil
}

func (s *localEd25519) identityHash() [32]byte { return sha256Sum(s.public) }

func (s *localEd25519) VerifyPresentation(
	_ context.Context,
	binding PresentationKeyBinding,
	message, signature []byte,
) error {
	if binding.DeviceIdentityHash != s.identityHash() || binding.DeviceKeyID != s.keyID ||
		!ed25519.Verify(s.public, message, signature) {
		return errors.New("secure-element attestation/signature mismatch")
	}
	return nil
}

func (s *localEd25519) VerifyClosure(
	_ context.Context,
	binding ClosureKeyBinding,
	message, signature []byte,
) error {
	if binding.KeyID != s.keyID || !ed25519.Verify(s.public, message, signature) {
		return errors.New("closure signature mismatch")
	}
	return nil
}

// present models the security contract of a certified secure element: its
// monotonic counter and per-allowance spent latch are updated before the
// signature is released. There is intentionally no production software
// implementation of this primitive.
func (s *localEd25519) present(
	allowance Allowance,
	merchantAccountID, acceptanceDomain string,
	challenge [32]byte,
) (Presentation, error) {
	allowanceHash, err := allowance.PayloadHash()
	if err != nil {
		return Presentation{}, err
	}
	s.presentMu.Lock()
	defer s.presentMu.Unlock()
	if _, spent := s.spentAllowances[allowanceHash]; spent {
		return Presentation{}, ErrPresentationSpent
	}
	s.presentationCounter++
	presentation := Presentation{
		Version: PresentationVersion, Allowance: allowance,
		AllowancePayloadHash: allowanceHash, MerchantAccountID: merchantAccountID,
		AcceptanceDomain: acceptanceDomain, MerchantChallenge: challenge,
		SettlementEpoch: allowance.IssuerEpoch, UploadFence: allowance.Counter,
		PresentationCounter: s.presentationCounter, DeviceKeyID: s.keyID,
	}
	payload, err := presentation.CanonicalPayload()
	if err != nil {
		return Presentation{}, err
	}
	presentation.Signature = ed25519.Sign(s.private, payload)
	// This state transition precedes returning the signature, matching an SE's
	// fail-closed non-exportable one-use latch even when the caller loses ACK.
	s.spentAllowances[allowanceHash] = struct{}{}
	return presentation, nil
}

func (s *localEd25519) closure(
	domain string,
	allowance Allowance,
	fence uint64,
) (DomainClosure, error) {
	closure := DomainClosure{
		Version: ClosureVersion, AcceptanceDomain: domain,
		AccountID: allowance.AccountID, AssetID: allowance.AssetID,
		OriginRegion: allowance.OriginRegion, DeviceIdentityHash: allowance.DeviceIdentityHash,
		ClosedSettlementEpoch: allowance.IssuerEpoch,
		ClosedUploadFence:     fence, KeyID: s.keyID,
	}
	payload, err := closure.CanonicalPayload()
	if err != nil {
		return DomainClosure{}, err
	}
	closure.Signature = ed25519.Sign(s.private, payload)
	return closure, nil
}

func testAllowance(t *testing.T) (Allowance, *localEd25519) {
	t.Helper()
	signer := newLocalEd25519(t)
	device := sha256Sum([]byte("device-attestation-public-key"))
	allowance := Allowance{
		Version: AllowanceVersion, AllowanceID: "issuer-a:incarnation-4:counter-91",
		AccountID: "account-001", AssetID: "USD:2", OriginRegion: "us-east",
		DeviceIdentityHash: device, Counter: 42,
		Amount:      ledger.MustAmount("99999999999999999999999999999999999999"),
		IssuerEpoch: 8, KeyID: signer.keyID,
	}
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	allowance.Signature, err = signer.Sign(context.Background(), signer.keyID, payload)
	if err != nil {
		t.Fatal(err)
	}
	return allowance, signer
}

func testVerifiedPresentation(t *testing.T) (VerifiedPresentation, Presentation, *localEd25519) {
	t.Helper()
	allowance, issuer := testAllowance(t)
	device := newLocalEd25519(t)
	device.keyID = "test-secure-element-key"
	allowance.DeviceIdentityHash = device.identityHash()
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	allowance.Signature, err = issuer.Sign(context.Background(), issuer.keyID, payload)
	if err != nil {
		t.Fatal(err)
	}
	challenge := sha256Sum([]byte("merchant challenge 1"))
	presentation, err := device.present(allowance, "merchant-123", "terminal-domain-kz", challenge)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyPresentation(context.Background(), issuer, device, presentation)
	if err != nil {
		t.Fatal(err)
	}
	return verified, presentation, device
}

func TestCanonicalPayloadGoldenAndBindsEveryField(t *testing.T) {
	allowance, verifier := testAllowance(t)
	payload, err := allowance.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256Sum(payload)
	got := hex.EncodeToString(payloadHash[:])
	const want = "c63950d5a9f5ca4d47e89ddeebd5154bf09c5b59523ae032d49b17e80a772b9b"
	if got != want {
		t.Fatalf("canonical hash = %s, want %s", got, want)
	}

	mutations := map[string]func(*Allowance){
		"allowance id": func(a *Allowance) { a.AllowanceID += "x" },
		"account":      func(a *Allowance) { a.AccountID += "x" },
		"asset":        func(a *Allowance) { a.AssetID += "x" },
		"region":       func(a *Allowance) { a.OriginRegion += "x" },
		"device":       func(a *Allowance) { a.DeviceIdentityHash[0] ^= 1 },
		"counter":      func(a *Allowance) { a.Counter++ },
		"amount":       func(a *Allowance) { a.Amount = ledger.NewAmountInt64(1) },
		"epoch":        func(a *Allowance) { a.IssuerEpoch++ },
		"key id":       func(a *Allowance) { a.KeyID += "x" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := allowance
			changed.Signature = append([]byte(nil), allowance.Signature...)
			mutate(&changed)
			if _, err := verifyAllowance(context.Background(), verifier, changed); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("mutation verification error = %v", err)
			}
		})
	}
}

func TestCanonicalEncodingHasNoDelimiterAmbiguity(t *testing.T) {
	first, _ := testAllowance(t)
	first.AccountID, first.AssetID = "ab", "c"
	second := first
	second.AccountID, second.AssetID = "a", "bc"
	left, err := first.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	right, err := second.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if string(left) == string(right) {
		t.Fatal("length-prefixed fields collided")
	}
}

func TestVerifiedAllowanceIsRaceSafe(t *testing.T) {
	allowance, verifier := testAllowance(t)
	const workers = 64
	var group sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				verified, err := verifyAllowance(context.Background(), verifier, allowance)
				if err != nil || verified.AllowanceID() != allowance.AllowanceID {
					errorsFound <- fmt.Errorf("verify: %v", err)
					return
				}
				if _, err := allowance.CanonicalPayload(); err != nil {
					errorsFound <- err
					return
				}
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func TestConservationIncludesOfflineBucket(t *testing.T) {
	snapshot := ConservationSnapshot{
		TotalAuthority: ledger.NewAmountInt64(100), Unallocated: ledger.NewAmountInt64(10),
		Regional: ledger.NewAmountInt64(40), InTransit: ledger.NewAmountInt64(20),
		OfflineIssued: ledger.NewAmountInt64(30), FoldedOutstanding: ledger.NewAmountInt64(30),
	}
	if !snapshot.Conserved() {
		t.Fatal("valid five-bucket authority was rejected")
	}
	snapshot.FoldedOutstanding = ledger.NewAmountInt64(29)
	if snapshot.Conserved() {
		t.Fatal("materialized offline bucket diverged from allowance fold")
	}
}

func TestPostingMustDebitExactAllowanceAmount(t *testing.T) {
	verified, _, _ := testVerifiedPresentation(t)
	allowance := verified.presentation.Allowance
	posting := ledger.PostRequest{Lines: []ledger.Line{
		{AccountID: allowance.AccountID, AssetID: allowance.AssetID, Side: ledger.Debit, AmountAtoms: ledger.MustAmount("40000000000000000000000000000000000000")},
		{AccountID: allowance.AccountID, AssetID: allowance.AssetID, Side: ledger.Debit, AmountAtoms: ledger.MustAmount("59999999999999999999999999999999999999")},
		{AccountID: verified.MerchantAccountID(), AssetID: allowance.AssetID, Side: ledger.Credit, AmountAtoms: allowance.Amount},
	}}
	if err := validatePostingForPresentation(verified, posting); err != nil {
		t.Fatalf("split exact debit rejected: %v", err)
	}
	posting.Lines[1].AmountAtoms = ledger.MustAmount("59999999999999999999999999999999999998")
	if err := validatePostingForPresentation(verified, posting); !errors.Is(err, ErrPostingMismatch) {
		t.Fatalf("mismatched debit error = %v", err)
	}
	posting.Lines[1].AmountAtoms = ledger.MustAmount("59999999999999999999999999999999999999")
	posting.Lines[2].AccountID = "copied-token-attacker"
	if err := validatePostingForPresentation(verified, posting); !errors.Is(err, ErrPostingMismatch) {
		t.Fatalf("wrong merchant credit error = %v", err)
	}
	posting.Lines[2].AccountID = verified.MerchantAccountID()
	posting.Lines = append(posting.Lines,
		ledger.Line{AccountID: allowance.AccountID, AssetID: allowance.AssetID,
			Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(1)},
		ledger.Line{AccountID: verified.MerchantAccountID(), AssetID: allowance.AssetID,
			Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(1)},
	)
	if err := validatePostingForPresentation(verified, posting); !errors.Is(err, ErrPostingMismatch) {
		t.Fatalf("wash credit/debit error = %v", err)
	}
}

func TestPresentationBindsMerchantDomainChallengeAndAllowance(t *testing.T) {
	_, presentation, device := testVerifiedPresentation(t)
	// The original allowance verifier is not needed: canonical mutations are
	// rejected by the device signature before a database transaction can open.
	mutations := map[string]func(*Presentation){
		"allowance hash":   func(p *Presentation) { p.AllowancePayloadHash[0] ^= 1 },
		"merchant":         func(p *Presentation) { p.MerchantAccountID += "-copied" },
		"domain":           func(p *Presentation) { p.AcceptanceDomain += "-copied" },
		"challenge":        func(p *Presentation) { p.MerchantChallenge[0] ^= 1 },
		"settlement epoch": func(p *Presentation) { p.SettlementEpoch++ },
		"upload fence":     func(p *Presentation) { p.UploadFence++ },
		"counter":          func(p *Presentation) { p.PresentationCounter++ },
		"device key":       func(p *Presentation) { p.DeviceKeyID += "-copied" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := presentation
			changed.Signature = append([]byte(nil), presentation.Signature...)
			mutate(&changed)
			payload, err := changed.CanonicalPayload()
			if err != nil {
				return
			}
			if err := device.VerifyPresentation(context.Background(), PresentationKeyBinding{
				DeviceIdentityHash: changed.Allowance.DeviceIdentityHash,
				DeviceKeyID:        changed.DeviceKeyID,
			}, payload, changed.Signature); err == nil {
				t.Fatal("tampered presentation signature verified")
			}
		})
	}
}

func TestSecureElementFencesAllowanceAfterFirstChallenge(t *testing.T) {
	_, first, device := testVerifiedPresentation(t)
	secondChallenge := sha256Sum([]byte("merchant challenge 2"))
	if _, err := device.present(
		first.Allowance, "different-merchant", "different-domain", secondChallenge,
	); !errors.Is(err, ErrPresentationSpent) {
		t.Fatalf("second presentation = %v", err)
	}
}

func TestBareAllowanceCannotConstructVerifiedPresentation(t *testing.T) {
	if err := validateVerifiedPresentation(VerifiedPresentation{}); !errors.Is(err, ErrInvalidPresentation) {
		t.Fatalf("zero/bare verified presentation = %v", err)
	}
}

func TestVerifiedValuesOwnSignatureAndEnvelopeBytes(t *testing.T) {
	allowance, issuer := testAllowance(t)
	expectedAllowanceSignature := append([]byte(nil), allowance.Signature...)
	verifiedAllowance, err := verifyAllowance(context.Background(), issuer, allowance)
	if err != nil {
		t.Fatal(err)
	}
	allowance.Signature[0] ^= 0xff
	if err := validateVerifiedAllowance(verifiedAllowance); err != nil {
		t.Fatalf("caller mutation invalidated verified allowance: %v", err)
	}
	if !bytes.Equal(verifiedAllowance.allowance.Signature, expectedAllowanceSignature) {
		t.Fatal("verified allowance retained caller signature alias")
	}

	verified, presentation, _ := testVerifiedPresentation(t)
	expectedPresentationSignature := append([]byte(nil), presentation.Signature...)
	expectedNestedSignature := append([]byte(nil), presentation.Allowance.Signature...)
	presentation.Signature[0] ^= 0xff
	presentation.Allowance.Signature[0] ^= 0xff
	if err := validateVerifiedPresentation(verified); err != nil {
		t.Fatalf("caller mutation invalidated verified presentation: %v", err)
	}
	if !bytes.Equal(verified.presentation.Signature, expectedPresentationSignature) ||
		!bytes.Equal(verified.presentation.Allowance.Signature, expectedNestedSignature) ||
		!bytes.Equal(verified.allowance.allowance.Signature, expectedNestedSignature) {
		t.Fatal("verified presentation retained caller signature alias")
	}

	tampered := verified
	tampered.payload = append([]byte(nil), verified.payload...)
	tampered.payload[0] ^= 0xff
	if err := validateVerifiedPresentation(tampered); !errors.Is(err, ErrInvalidPresentation) {
		t.Fatalf("tampered opaque presentation = %v", err)
	}
}

func TestVerifiedClosureSetOwnsAndRevalidatesEnvelopeBytes(t *testing.T) {
	allowance, _ := testAllowance(t)
	signer := newLocalEd25519(t)
	closure, err := signer.closure("domain-kz", allowance, allowance.Counter)
	if err != nil {
		t.Fatal(err)
	}
	expectedSignature := append([]byte(nil), closure.Signature...)
	request := FenceRequest{
		AllowanceID: allowance.AllowanceID,
		ExpectedPayloadHash: func() [32]byte {
			value, hashErr := allowance.PayloadHash()
			if hashErr != nil {
				t.Fatal(hashErr)
			}
			return value
		}(),
		ExpectedIssuerEpoch: allowance.IssuerEpoch, ExpectedDeviceCounter: allowance.Counter,
		Kind: Revoked, PolicyEvidenceHash: sha256Sum([]byte("policy")),
		DomainClosures: []DomainClosure{closure},
	}
	verified, err := verifyClosureSet(context.Background(), signer, request)
	if err != nil {
		t.Fatal(err)
	}
	closure.Signature[0] ^= 0xff
	request.DomainClosures[0].Signature[1] ^= 0xff
	if err := validateVerifiedClosureSet(verified); err != nil {
		t.Fatalf("caller mutation invalidated verified closure set: %v", err)
	}
	if !bytes.Equal(verified.byDomain["domain-kz"].closure.Signature, expectedSignature) {
		t.Fatal("verified closure retained caller signature alias")
	}
	tampered := verified
	tampered.byDomain = make(map[string]verifiedClosure, len(verified.byDomain))
	for domain, value := range verified.byDomain {
		value.closure.Signature = append([]byte(nil), value.closure.Signature...)
		value.closure.Signature[0] ^= 0xff
		tampered.byDomain[domain] = value
	}
	if err := validateVerifiedClosureSet(tampered); !errors.Is(err, ErrInvalidClosure) {
		t.Fatalf("tampered opaque closure set = %v", err)
	}
}

func TestDomainClosureSignatureBindsIssuanceNamespace(t *testing.T) {
	allowance, _ := testAllowance(t)
	signer := newLocalEd25519(t)
	closure, err := signer.closure("domain-kz", allowance, allowance.Counter)
	if err != nil {
		t.Fatal(err)
	}
	mutated := closure
	mutated.DeviceIdentityHash[0] ^= 1
	payload, err := mutated.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyClosure(context.Background(), ClosureKeyBinding{
		AcceptanceDomain: mutated.AcceptanceDomain,
		KeyID:            mutated.KeyID,
	}, payload, mutated.Signature); err == nil {
		t.Fatal("closure signature remained valid for a different allowance hash")
	}
}
