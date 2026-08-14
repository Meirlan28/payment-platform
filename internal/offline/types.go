// Package offline implements single-use, cryptographically signed offline
// spending allowances backed by pre-allocated escrow authority.
package offline

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/example/payment-platform/internal/ledger"
)

const (
	AllowanceVersion    uint16 = 1
	PresentationVersion uint16 = 1
	ClosureVersion      uint16 = 1
)

var (
	ErrInvalidArgument       = errors.New("offline: invalid argument")
	ErrInvalidSignature      = errors.New("offline: invalid allowance signature")
	ErrInvalidPresentation   = errors.New("offline: invalid secure-element presentation")
	ErrInvalidClosure        = errors.New("offline: invalid acceptance-domain closure")
	ErrVerifierUnavailable   = errors.New("offline: hardware verifier unavailable")
	ErrAllowanceNotFound     = errors.New("offline: allowance not found")
	ErrAllowanceConflict     = errors.New("offline: allowance id reused with different payload")
	ErrInsufficientRights    = errors.New("offline: insufficient origin-region authority")
	ErrNotIssued             = errors.New("offline: allowance has not been issued")
	ErrAlreadyRedeemed       = errors.New("offline: allowance was already redeemed")
	ErrRedemptionConflict    = errors.New("offline: allowance was redeemed by a different effect")
	ErrPostingMismatch       = errors.New("offline: ledger posting does not debit the allowance authority")
	ErrAllowanceTerminal     = errors.New("offline: allowance was revoked or expired")
	ErrFenceConflict         = errors.New("offline: non-redemption fence does not match allowance")
	ErrIncompleteClosure     = errors.New("offline: complete acceptance-domain closure proof is required")
	ErrAcceptanceDomain      = errors.New("offline: acceptance domain is not configured for settlement epoch")
	ErrPresentationSpent     = errors.New("offline: secure element already presented this allowance")
	ErrDeviceConflict        = errors.New("offline: device enrollment or issuer epoch conflict")
	ErrCounterExhausted      = errors.New("offline: device counter exhausted")
	ErrConservationViolation = errors.New("offline: escrow authority conservation violation")
)

// Signer is implemented by a production HSM/KMS adapter. Sign receives a key
// version identifier so a PREPARED issuance remains recoverable across key
// rotation. Implementations must never export private key material.
type Signer interface {
	ActiveKeyID(context.Context) (string, error)
	Sign(context.Context, string, []byte) ([]byte, error)
}

// Verifier is backed by an HSM/KMS verification API or a pinned public-key
// cache whose key versions are durably retained for the allowance lifetime.
type Verifier interface {
	Verify(context.Context, string, []byte, []byte) error
}

// PresentationVerifier is a production trust-boundary interface, not a
// software-signature convenience hook. Its implementation MUST verify a
// hardware-backed secure-element attestation chain, bind keyID to the exact
// DeviceIdentityHash enrolled for the allowance, and enforce that the key's
// policy has an irreversible one-presentation latch plus a monotonic hardware
// counter. A plain public-key verifier is permitted only in tests.
type PresentationVerifier interface {
	VerifyPresentation(context.Context, PresentationKeyBinding, []byte, []byte) error
}

type PresentationKeyBinding struct {
	DeviceIdentityHash [32]byte
	DeviceKeyID        string
}

// ClosureVerifier verifies an acceptance-domain control-plane signature. A
// production adapter MUST resolve the exact configured domain/key binding in
// HSM-backed trust metadata and must fail closed when that service is
// unavailable. It must never fall back to an application-owned software key.
type ClosureVerifier interface {
	VerifyClosure(context.Context, ClosureKeyBinding, []byte, []byte) error
}

type ClosureKeyBinding struct {
	AcceptanceDomain string
	KeyID            string
}

type Device struct {
	AccountID          string
	AssetID            string
	OriginRegion       string
	DeviceIdentityHash [32]byte
	IssuerEpoch        uint64
}

func (d Device) validate() error {
	if !validText(d.AccountID) || !validText(d.AssetID) || !validText(d.OriginRegion) ||
		d.DeviceIdentityHash == ([32]byte{}) || d.IssuerEpoch == 0 || d.IssuerEpoch > math.MaxInt64 {
		return ErrInvalidArgument
	}
	return nil
}

type IssueRequest struct {
	AllowanceID        string
	AccountID          string
	AssetID            string
	OriginRegion       string
	DeviceIdentityHash [32]byte
	Amount             ledger.Amount
}

func (r IssueRequest) validate() error {
	if !validText(r.AllowanceID) || !validText(r.AccountID) || !validText(r.AssetID) ||
		!validText(r.OriginRegion) || r.DeviceIdentityHash == ([32]byte{}) || r.Amount.Sign() <= 0 {
		return ErrInvalidArgument
	}
	return nil
}

type Allowance struct {
	Version            uint16        `json:"version"`
	AllowanceID        string        `json:"allowance_id"`
	AccountID          string        `json:"account_id"`
	AssetID            string        `json:"asset_id"`
	OriginRegion       string        `json:"origin_region"`
	DeviceIdentityHash [32]byte      `json:"device_identity_hash"`
	Counter            uint64        `json:"counter"`
	Amount             ledger.Amount `json:"amount_atoms"`
	IssuerEpoch        uint64        `json:"issuer_epoch"`
	KeyID              string        `json:"key_id"`
	Signature          []byte        `json:"signature"`
}

func (a Allowance) ValidatePayload() error {
	if a.Version != AllowanceVersion || !validText(a.AllowanceID) ||
		!validText(a.AccountID) || !validText(a.AssetID) || !validText(a.OriginRegion) ||
		a.DeviceIdentityHash == ([32]byte{}) || a.Counter == 0 || a.Counter > math.MaxInt64 ||
		a.Amount.Sign() <= 0 || a.IssuerEpoch == 0 || a.IssuerEpoch > math.MaxInt64 ||
		!validText(a.KeyID) {
		return ErrInvalidArgument
	}
	return nil
}

// VerifiedAllowance has no exported fields, so callers cannot bypass the
// verifier before entering a transaction shared with ledger.PostInTx.
type VerifiedAllowance struct {
	allowance   Allowance
	payloadHash [32]byte
}

func (v VerifiedAllowance) AllowanceID() string { return v.allowance.AllowanceID }

// Presentation is produced by the payer device's certified secure element at
// the merchant terminal. The signed payload binds the non-transferable
// allowance to one merchant challenge. SettlementEpoch and UploadFence are
// logical counters copied from the signed allowance (IssuerEpoch and Counter);
// neither is a wall-clock timestamp.
type Presentation struct {
	Version              uint16   `json:"version"`
	Allowance            Allowance `json:"allowance"`
	AllowancePayloadHash [32]byte `json:"allowance_payload_hash"`
	MerchantAccountID    string   `json:"merchant_account_id"`
	AcceptanceDomain     string   `json:"acceptance_domain"`
	MerchantChallenge    [32]byte `json:"merchant_challenge"`
	SettlementEpoch      uint64   `json:"settlement_epoch"`
	UploadFence          uint64   `json:"upload_fence"`
	PresentationCounter  uint64   `json:"presentation_counter"`
	DeviceKeyID          string   `json:"device_key_id"`
	Signature            []byte   `json:"signature"`
}

func (p Presentation) ValidatePayload() error {
	if p.Version != PresentationVersion || p.Allowance.ValidatePayload() != nil ||
		p.AllowancePayloadHash == ([32]byte{}) || !validText(p.MerchantAccountID) ||
		!validText(p.AcceptanceDomain) || p.MerchantChallenge == ([32]byte{}) ||
		p.SettlementEpoch == 0 || p.SettlementEpoch > math.MaxInt64 ||
		p.UploadFence == 0 || p.UploadFence > math.MaxInt64 ||
		p.PresentationCounter == 0 || p.PresentationCounter > math.MaxInt64 ||
		!validText(p.DeviceKeyID) {
		return ErrInvalidArgument
	}
	return nil
}

// VerifiedPresentation is intentionally opaque. Only VerifyPresentation can
// create a non-zero value, so the financial path cannot accidentally accept a
// copied bearer allowance without secure-element verification.
type VerifiedPresentation struct {
	presentation     Presentation
	allowance         VerifiedAllowance
	payload           []byte
	payloadHash       [32]byte
	presentationHash  [32]byte
	challengeHash     [32]byte
}

func (v VerifiedPresentation) AllowanceID() string {
	return v.presentation.Allowance.AllowanceID
}

func (v VerifiedPresentation) MerchantAccountID() string {
	return v.presentation.MerchantAccountID
}

type RedemptionEffect struct {
	EffectID            string
	LedgerTransactionID string
	PostingRequestHash  [32]byte
}

func (e RedemptionEffect) validate() error {
	if !validText(e.EffectID) || !validText(e.LedgerTransactionID) ||
		e.PostingRequestHash == ([32]byte{}) {
		return ErrInvalidArgument
	}
	return nil
}

type Redemption struct {
	AllowanceID string
	EffectHash  [32]byte
	Duplicate   bool
}

type AtomicRedemption struct {
	Allowance Redemption
	Ledger    ledger.Receipt
}

type TerminalKind string

const (
	Revoked TerminalKind = "REVOKED"
	Expired TerminalKind = "EXPIRED"
)

type FenceRequest struct {
	AllowanceID           string
	ExpectedPayloadHash   [32]byte
	ExpectedIssuerEpoch   uint64
	ExpectedDeviceCounter uint64
	Kind                  TerminalKind
	PolicyEvidenceHash    [32]byte
	DomainClosures        []DomainClosure
}

func (r FenceRequest) validate() error {
	if !validText(r.AllowanceID) || r.ExpectedPayloadHash == ([32]byte{}) ||
		r.ExpectedIssuerEpoch == 0 || r.ExpectedIssuerEpoch > math.MaxInt64 ||
		r.ExpectedDeviceCounter == 0 || r.ExpectedDeviceCounter > math.MaxInt64 ||
		(r.Kind != Revoked && r.Kind != Expired) || r.PolicyEvidenceHash == ([32]byte{}) ||
		len(r.DomainClosures) == 0 {
		return ErrInvalidArgument
	}
	return nil
}

// AcceptanceDomain is immutable configuration. Distinct ClosureKeyID values
// are required by the database so one compromised domain key cannot fabricate
// a complete multi-domain closure set.
type AcceptanceDomain struct {
	Name                 string
	ClosureKeyID         string
	FirstSettlementEpoch uint64
	LastSettlementEpoch  uint64 // zero means no configured upper bound
}

func (d AcceptanceDomain) validate() error {
	if !validText(d.Name) || !validText(d.ClosureKeyID) ||
		d.FirstSettlementEpoch == 0 || d.FirstSettlementEpoch > math.MaxInt64 ||
		d.LastSettlementEpoch > math.MaxInt64 ||
		(d.LastSettlementEpoch != 0 && d.LastSettlementEpoch < d.FirstSettlementEpoch) {
		return ErrInvalidArgument
	}
	return nil
}

// DomainClosure is signed independently by an acceptance domain after that
// domain has durably ingested or rejected every presentation at or below the
// logical (settlement epoch, upload fence) watermark. Times are deliberately
// absent from the correctness payload.
type DomainClosure struct {
	Version               uint16   `json:"version"`
	AcceptanceDomain      string   `json:"acceptance_domain"`
	ClosedSettlementEpoch uint64   `json:"closed_settlement_epoch"`
	ClosedUploadFence     uint64   `json:"closed_upload_fence"`
	KeyID                 string   `json:"key_id"`
	Signature             []byte   `json:"signature"`
}

func (c DomainClosure) ValidatePayload() error {
	if c.Version != ClosureVersion || !validText(c.AcceptanceDomain) ||
		c.ClosedSettlementEpoch == 0 || c.ClosedSettlementEpoch > math.MaxInt64 ||
		c.ClosedUploadFence > math.MaxInt64 || !validText(c.KeyID) {
		return ErrInvalidArgument
	}
	return nil
}

type verifiedClosure struct {
	closure     DomainClosure
	payload     []byte
	payloadHash [32]byte
	evidenceHash [32]byte
}

type verifiedClosureSet struct {
	byDomain map[string]verifiedClosure
	setHash  [32]byte
}

type NonRedemptionProof struct {
	AllowanceID        string
	Kind               TerminalKind
	PayloadHash        [32]byte
	IssuerEpoch        uint64
	DeviceCounter      uint64
	FenceVersion       uint64
	PolicyEvidenceHash [32]byte
	ClosureSetHash     [32]byte
	ProofHash          [32]byte
	Duplicate          bool
}

type ConservationSnapshot struct {
	AccountID         string
	AssetID           string
	TotalAuthority    ledger.Amount
	Unallocated       ledger.Amount
	Regional          ledger.Amount
	InTransit         ledger.Amount
	OfflineIssued     ledger.Amount
	FoldedOutstanding ledger.Amount
}

func (s ConservationSnapshot) Conserved() bool {
	if s.TotalAuthority.Sign() < 0 || s.Unallocated.Sign() < 0 ||
		s.Regional.Sign() < 0 || s.InTransit.Sign() < 0 ||
		s.OfflineIssued.Sign() < 0 || s.FoldedOutstanding.Sign() < 0 ||
		s.OfflineIssued.Cmp(s.FoldedOutstanding) != 0 {
		return false
	}
	total, err := s.Unallocated.Add(s.Regional)
	if err != nil {
		return false
	}
	total, err = total.Add(s.InTransit)
	if err != nil {
		return false
	}
	total, err = total.Add(s.OfflineIssued)
	return err == nil && total.Cmp(s.TotalAuthority) == 0
}

func validText(value string) bool {
	return value != "" && len(value) <= 1024
}

func checkedInt64(value uint64) (int64, error) {
	if value == 0 || value > math.MaxInt64 {
		return 0, fmt.Errorf("%w: counter or epoch outside INT8", ErrInvalidArgument)
	}
	return int64(value), nil
}
