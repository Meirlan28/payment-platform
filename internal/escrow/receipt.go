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

const consumptionReceiptVersion uint16 = 1

// ConsumptionReceipt is destination-signed proof that the destination rights
// mutation passed its SERIALIZABLE commit boundary.  The watermark is a
// destination-local durable counter, not a wall-clock timestamp.
type ConsumptionReceipt struct {
	Version                    uint16
	TransferID                 string
	CertificateHash            [sha256.Size]byte
	AccountID                  string
	AssetID                    string
	Amount                     ledger.Amount
	SourceRegion               string
	SourceLegalEntityID        string
	SourceEpoch                uint64
	SourceKeyEpoch             uint64
	DestinationRegion          string
	DestinationLegalEntityID   string
	DestinationCommitWatermark uint64
	KeyID                      string
	KeyEpoch                   uint64
	Signature                  []byte
}

type wireConsumptionReceipt struct {
	Version                    uint16 `json:"version"`
	TransferID                 string `json:"transfer_id"`
	CertificateHash            string `json:"certificate_hash"`
	AccountID                  string `json:"account_id"`
	AssetID                    string `json:"asset_id"`
	Amount                     string `json:"amount_atoms"`
	SourceRegion               string `json:"source_region"`
	SourceLegalEntityID        string `json:"source_legal_entity_id"`
	SourceEpoch                uint64 `json:"source_epoch"`
	SourceKeyEpoch             uint64 `json:"source_key_epoch"`
	DestinationRegion          string `json:"destination_region"`
	DestinationLegalEntityID   string `json:"destination_legal_entity_id"`
	DestinationCommitWatermark uint64 `json:"destination_commit_watermark"`
	KeyID                      string `json:"key_id"`
	KeyEpoch                   uint64 `json:"key_epoch"`
	Signature                  string `json:"signature"`
}

func (r ConsumptionReceipt) Validate() error {
	if r.Version != consumptionReceiptVersion || r.TransferID == "" ||
		r.CertificateHash == ([sha256.Size]byte{}) || r.AccountID == "" || r.AssetID == "" ||
		r.Amount.Sign() <= 0 || r.SourceRegion == "" || r.SourceLegalEntityID == "" ||
		r.SourceEpoch == 0 || r.SourceKeyEpoch == 0 || r.DestinationRegion == "" ||
		r.DestinationLegalEntityID == "" || r.SourceRegion == r.DestinationRegion ||
		r.DestinationCommitWatermark == 0 || r.KeyID == "" || r.KeyEpoch == 0 {
		return ErrConsumptionReceiptInvalid
	}
	return nil
}

func (r ConsumptionReceipt) Payload() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("payment-platform/escrow-consumption-receipt/v1\x00")
	_ = binary.Write(&out, binary.BigEndian, r.Version)
	for _, value := range []string{
		r.TransferID, r.AccountID, r.AssetID, r.SourceRegion,
		r.SourceLegalEntityID, r.DestinationRegion,
		r.DestinationLegalEntityID, r.KeyID,
	} {
		if err := writeCanonicalString(&out, value); err != nil {
			return nil, ErrConsumptionReceiptInvalid
		}
	}
	if err := writeCanonicalString(&out, r.Amount.String()); err != nil {
		return nil, ErrConsumptionReceiptInvalid
	}
	out.Write(r.CertificateHash[:])
	_ = binary.Write(&out, binary.BigEndian, r.SourceEpoch)
	_ = binary.Write(&out, binary.BigEndian, r.SourceKeyEpoch)
	_ = binary.Write(&out, binary.BigEndian, r.DestinationCommitWatermark)
	_ = binary.Write(&out, binary.BigEndian, r.KeyEpoch)
	return out.Bytes(), nil
}

func (r ConsumptionReceipt) PayloadHash() ([sha256.Size]byte, error) {
	payload, err := r.Payload()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func (r ConsumptionReceipt) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireConsumptionReceipt{
		Version: r.Version, TransferID: r.TransferID,
		CertificateHash: base64.RawStdEncoding.EncodeToString(r.CertificateHash[:]),
		AccountID:       r.AccountID, AssetID: r.AssetID, Amount: r.Amount.String(),
		SourceRegion: r.SourceRegion, SourceLegalEntityID: r.SourceLegalEntityID,
		SourceEpoch: r.SourceEpoch, SourceKeyEpoch: r.SourceKeyEpoch,
		DestinationRegion:          r.DestinationRegion,
		DestinationLegalEntityID:   r.DestinationLegalEntityID,
		DestinationCommitWatermark: r.DestinationCommitWatermark,
		KeyID:                      r.KeyID, KeyEpoch: r.KeyEpoch,
		Signature: base64.RawStdEncoding.EncodeToString(r.Signature),
	})
}

func (r *ConsumptionReceipt) UnmarshalJSON(data []byte) error {
	var wire wireConsumptionReceipt
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	certificateHash, err := base64.RawStdEncoding.DecodeString(wire.CertificateHash)
	if err != nil || len(certificateHash) != sha256.Size {
		return fmt.Errorf("decode receipt certificate hash: %w", ErrConsumptionReceiptInvalid)
	}
	signature, err := base64.RawStdEncoding.DecodeString(wire.Signature)
	if err != nil {
		return fmt.Errorf("decode receipt signature: %w", err)
	}
	amount, err := ledger.ParseAmount(wire.Amount)
	if err != nil {
		return fmt.Errorf("decode receipt amount: %w", err)
	}
	*r = ConsumptionReceipt{
		Version: wire.Version, TransferID: wire.TransferID,
		AccountID: wire.AccountID, AssetID: wire.AssetID, Amount: amount,
		SourceRegion: wire.SourceRegion, SourceLegalEntityID: wire.SourceLegalEntityID,
		SourceEpoch: wire.SourceEpoch, SourceKeyEpoch: wire.SourceKeyEpoch,
		DestinationRegion:          wire.DestinationRegion,
		DestinationLegalEntityID:   wire.DestinationLegalEntityID,
		DestinationCommitWatermark: wire.DestinationCommitWatermark,
		KeyID:                      wire.KeyID, KeyEpoch: wire.KeyEpoch, Signature: signature,
	}
	copy(r.CertificateHash[:], certificateHash)
	return nil
}

type ConsumptionReceiptSigner interface {
	Binding() KeyBinding
	SignReceipt(ConsumptionReceipt) (ConsumptionReceipt, error)
}

// Ed25519ReceiptSigner is the local counterpart of a destination HSM/KMS
// signer.  Production key retention must cover every committed unsigned draft
// so a crash between destination commit and signature persistence is retryable.
type Ed25519ReceiptSigner struct {
	KeyID         string
	PrivateKey    ed25519.PrivateKey
	Region        string
	LegalEntityID string
	Epoch         uint64
}

func (s Ed25519ReceiptSigner) Binding() KeyBinding {
	return KeyBinding{
		KeyID: s.KeyID, Region: s.Region, LegalEntityID: s.LegalEntityID,
		Epoch: s.Epoch, Purpose: KeyPurposeConsumptionReceipt,
	}
}

func (s Ed25519ReceiptSigner) SignReceipt(r ConsumptionReceipt) (ConsumptionReceipt, error) {
	binding := s.Binding()
	if !binding.validFor(KeyPurposeConsumptionReceipt) || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return ConsumptionReceipt{}, fmt.Errorf("%w: receipt signer", ErrInvalidArgument)
	}
	if (r.KeyID != "" && r.KeyID != binding.KeyID) ||
		(r.KeyEpoch != 0 && r.KeyEpoch != binding.Epoch) ||
		(r.DestinationRegion != "" && r.DestinationRegion != binding.Region) ||
		(r.DestinationLegalEntityID != "" && r.DestinationLegalEntityID != binding.LegalEntityID) {
		return ConsumptionReceipt{}, ErrConsumptionReceiptInvalid
	}
	r.Version = consumptionReceiptVersion
	r.KeyID, r.KeyEpoch = binding.KeyID, binding.Epoch
	r.DestinationRegion = binding.Region
	r.DestinationLegalEntityID = binding.LegalEntityID
	payload, err := r.Payload()
	if err != nil {
		return ConsumptionReceipt{}, err
	}
	r.Signature = ed25519.Sign(s.PrivateKey, payload)
	return r, nil
}

func VerifyConsumptionReceipt(receipt ConsumptionReceipt, certificate Certificate, resolver KeyResolver) error {
	if resolver == nil {
		return ErrConsumptionReceiptInvalid
	}
	payload, err := receipt.Payload()
	if err != nil {
		return err
	}
	certificateHash, err := certificate.PayloadHash()
	if err != nil || receipt.CertificateHash != certificateHash ||
		receipt.TransferID != certificate.TransferID ||
		receipt.AccountID != certificate.AccountID || receipt.AssetID != certificate.AssetID ||
		receipt.Amount.Cmp(certificate.Amount) != 0 ||
		receipt.SourceRegion != certificate.SourceRegion ||
		receipt.SourceLegalEntityID != certificate.SourceLegalEntityID ||
		receipt.SourceEpoch != certificate.SourceEpoch ||
		receipt.SourceKeyEpoch != certificate.KeyEpoch ||
		receipt.DestinationRegion != certificate.DestinationRegion ||
		receipt.DestinationLegalEntityID != certificate.DestinationLegalEntityID {
		return ErrConsumptionReceiptInvalid
	}
	key, ok := resolver.ResolveKey(receipt.KeyID)
	if !ok || !key.Binding.validFor(KeyPurposeConsumptionReceipt) ||
		key.Binding.Region != receipt.DestinationRegion ||
		key.Binding.LegalEntityID != receipt.DestinationLegalEntityID ||
		key.Binding.Epoch != receipt.KeyEpoch ||
		len(key.PublicKey) != ed25519.PublicKeySize ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key.PublicKey, payload, receipt.Signature) {
		return ErrConsumptionReceiptInvalid
	}
	return nil
}
