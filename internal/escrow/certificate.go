package escrow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
)

const certificateVersion uint16 = 2

// KeyPurpose prevents a valid key from one protocol from being confused with
// a key from another protocol.  Production resolvers are backed by the
// regional key registry; StaticKeyRegistry is only an in-memory adapter for
// deterministic tests.
type KeyPurpose string

const (
	KeyPurposeTransferCertificate KeyPurpose = "ESCROW_TRANSFER_CERTIFICATE_V2"
	KeyPurposeConsumptionReceipt  KeyPurpose = "ESCROW_CONSUMPTION_RECEIPT_V1"
)

// KeyBinding is immutable registry metadata.  KeyID alone is never enough to
// authorize a signature: region, legal entity, epoch, and protocol purpose
// must all agree with the signed object.
type KeyBinding struct {
	KeyID         string
	Region        string
	LegalEntityID string
	Epoch         uint64
	Purpose       KeyPurpose
}

func (b KeyBinding) validFor(purpose KeyPurpose) bool {
	return b.KeyID != "" && b.Region != "" && b.LegalEntityID != "" &&
		b.Epoch > 0 && b.Purpose == purpose
}

type VerificationKey struct {
	Binding   KeyBinding
	PublicKey ed25519.PublicKey
}

type KeyResolver interface {
	ResolveKey(keyID string) (VerificationKey, bool)
}

type StaticKeyRegistry map[string]VerificationKey

func (s StaticKeyRegistry) ResolveKey(keyID string) (VerificationKey, bool) {
	key, ok := s[keyID]
	if !ok || key.Binding.KeyID != keyID {
		return VerificationKey{}, false
	}
	return key, true
}

// Certificate is a single-use, signed bearer instrument. SourceEpoch is a
// durable issuance sequence, and KeyEpoch fences restored/stale signing
// identities without consulting wall clocks.
type Certificate struct {
	Version                  uint16        `json:"version"`
	TransferID               string        `json:"transfer_id"`
	AccountID                string        `json:"account_id"`
	AssetID                  string        `json:"asset_id"`
	SourceRegion             string        `json:"source_region"`
	DestinationRegion        string        `json:"destination_region"`
	SourceLegalEntityID      string        `json:"source_legal_entity_id"`
	DestinationLegalEntityID string        `json:"destination_legal_entity_id"`
	Amount                   ledger.Amount `json:"amount_atoms"`
	SourceEpoch              uint64        `json:"source_epoch"`
	KeyID                    string        `json:"key_id"`
	KeyEpoch                 uint64        `json:"key_epoch"`
	Signature                []byte        `json:"-"`
}

type wireCertificate struct {
	Version                  uint16 `json:"version"`
	TransferID               string `json:"transfer_id"`
	AccountID                string `json:"account_id"`
	AssetID                  string `json:"asset_id"`
	SourceRegion             string `json:"source_region"`
	DestinationRegion        string `json:"destination_region"`
	SourceLegalEntityID      string `json:"source_legal_entity_id"`
	DestinationLegalEntityID string `json:"destination_legal_entity_id"`
	Amount                   string `json:"amount_atoms"`
	SourceEpoch              uint64 `json:"source_epoch"`
	KeyID                    string `json:"key_id"`
	KeyEpoch                 uint64 `json:"key_epoch"`
	Signature                string `json:"signature"`
}

func (c Certificate) Validate() error {
	if c.Version != certificateVersion || c.TransferID == "" || c.AccountID == "" ||
		c.AssetID == "" || c.SourceRegion == "" || c.DestinationRegion == "" ||
		c.SourceRegion == c.DestinationRegion || c.SourceLegalEntityID == "" ||
		c.DestinationLegalEntityID == "" || c.Amount.Sign() <= 0 || c.SourceEpoch == 0 ||
		c.KeyID == "" || c.KeyEpoch == 0 {
		return ErrCertificateInvalid
	}
	return nil
}

// Payload is the only byte representation that may be signed. Every variable
// field is length-prefixed, avoiding delimiter and Unicode boundary ambiguity.
func (c Certificate) Payload() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("payment-platform/escrow-certificate/v2\x00")
	_ = binary.Write(&out, binary.BigEndian, c.Version)
	for _, value := range []string{
		c.TransferID, c.AccountID, c.AssetID, c.SourceRegion,
		c.DestinationRegion, c.SourceLegalEntityID,
		c.DestinationLegalEntityID, c.KeyID,
	} {
		if err := writeCanonicalString(&out, value); err != nil {
			return nil, err
		}
	}
	if err := writeCanonicalString(&out, c.Amount.String()); err != nil {
		return nil, err
	}
	_ = binary.Write(&out, binary.BigEndian, c.SourceEpoch)
	_ = binary.Write(&out, binary.BigEndian, c.KeyEpoch)
	return out.Bytes(), nil
}

func writeCanonicalString(out *bytes.Buffer, value string) error {
	if len(value) > 1<<20 {
		return ErrCertificateInvalid
	}
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	out.WriteString(value)
	return nil
}

func (c Certificate) PayloadHash() ([32]byte, error) {
	payload, err := c.Payload()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func (c Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireCertificate{
		Version: c.Version, TransferID: c.TransferID, AccountID: c.AccountID,
		AssetID: c.AssetID, SourceRegion: c.SourceRegion,
		DestinationRegion:        c.DestinationRegion,
		SourceLegalEntityID:      c.SourceLegalEntityID,
		DestinationLegalEntityID: c.DestinationLegalEntityID,
		Amount:                   c.Amount.String(), SourceEpoch: c.SourceEpoch,
		KeyID: c.KeyID, KeyEpoch: c.KeyEpoch,
		Signature: base64.RawStdEncoding.EncodeToString(c.Signature),
	})
}

func (c *Certificate) UnmarshalJSON(data []byte) error {
	var wire wireCertificate
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(wire.Signature)
	if err != nil {
		return fmt.Errorf("decode certificate signature: %w", err)
	}
	amount, err := ledger.ParseAmount(wire.Amount)
	if err != nil {
		return fmt.Errorf("decode certificate amount: %w", err)
	}
	*c = Certificate{
		Version: wire.Version, TransferID: wire.TransferID, AccountID: wire.AccountID,
		AssetID: wire.AssetID, SourceRegion: wire.SourceRegion,
		DestinationRegion:        wire.DestinationRegion,
		SourceLegalEntityID:      wire.SourceLegalEntityID,
		DestinationLegalEntityID: wire.DestinationLegalEntityID,
		Amount:                   amount, SourceEpoch: wire.SourceEpoch, KeyID: wire.KeyID,
		KeyEpoch: wire.KeyEpoch, Signature: signature,
	}
	return nil
}

type CertificateSigner interface {
	Binding() KeyBinding
	Sign(Certificate) (Certificate, error)
}

// Ed25519Signer is a local adapter for tests and sealed-file deployments.
// Production injects an HSM/KMS adapter with the same bound-key contract.
type Ed25519Signer struct {
	KeyID         string
	PrivateKey    ed25519.PrivateKey
	Region        string
	LegalEntityID string
	Epoch         uint64
}

func (s Ed25519Signer) Binding() KeyBinding {
	return KeyBinding{
		KeyID: s.KeyID, Region: s.Region, LegalEntityID: s.LegalEntityID,
		Epoch: s.Epoch, Purpose: KeyPurposeTransferCertificate,
	}
}

func (s Ed25519Signer) Sign(c Certificate) (Certificate, error) {
	binding := s.Binding()
	if !binding.validFor(KeyPurposeTransferCertificate) || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return Certificate{}, fmt.Errorf("%w: certificate signer", ErrInvalidArgument)
	}
	if (c.KeyID != "" && c.KeyID != binding.KeyID) ||
		(c.KeyEpoch != 0 && c.KeyEpoch != binding.Epoch) ||
		(c.SourceRegion != "" && c.SourceRegion != binding.Region) ||
		(c.SourceLegalEntityID != "" && c.SourceLegalEntityID != binding.LegalEntityID) {
		return Certificate{}, ErrCertificateInvalid
	}
	c.Version = certificateVersion
	c.KeyID, c.KeyEpoch = binding.KeyID, binding.Epoch
	c.SourceRegion, c.SourceLegalEntityID = binding.Region, binding.LegalEntityID
	payload, err := c.Payload()
	if err != nil {
		return Certificate{}, err
	}
	c.Signature = ed25519.Sign(s.PrivateKey, payload)
	return c, nil
}

func VerifyCertificate(c Certificate, resolver KeyResolver) error {
	if resolver == nil {
		return ErrCertificateInvalid
	}
	payload, err := c.Payload()
	if err != nil {
		return err
	}
	key, ok := resolver.ResolveKey(c.KeyID)
	if !ok || !key.Binding.validFor(KeyPurposeTransferCertificate) ||
		key.Binding.Region != c.SourceRegion ||
		key.Binding.LegalEntityID != c.SourceLegalEntityID ||
		key.Binding.Epoch != c.KeyEpoch ||
		len(key.PublicKey) != ed25519.PublicKeySize ||
		len(c.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key.PublicKey, payload, c.Signature) {
		return ErrCertificateInvalid
	}
	return nil
}
