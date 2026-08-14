package escrow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

func TestCertificateExactAmountSignatureAndRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	amount := ledger.MustAmount("99999999999999999999999999999999999999")
	signer := Ed25519Signer{KeyID: "test-key-1", PrivateKey: privateKey,
		Region: "A", LegalEntityID: "entity-a", Epoch: 7}
	certificate, err := signer.Sign(Certificate{
		TransferID: "transfer-1", AccountID: "account-1", AssetID: "USD",
		SourceRegion: "A", DestinationRegion: "B", SourceLegalEntityID: "entity-a",
		DestinationLegalEntityID: "entity-b", Amount: amount, SourceEpoch: 17,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := StaticKeyRegistry{"test-key-1": {
		Binding: signer.Binding(), PublicKey: publicKey,
	}}
	if err := VerifyCertificate(certificate, keys); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	wire, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Certificate
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Amount.Cmp(amount) != 0 {
		t.Fatalf("amount changed: got %s", decoded.Amount.String())
	}
	if err := VerifyCertificate(decoded, keys); err != nil {
		t.Fatalf("round-trip certificate rejected: %v", err)
	}

	tampered := decoded
	tampered.Amount = ledger.MustAmount("99999999999999999999999999999999999998")
	if err := VerifyCertificate(tampered, keys); err == nil {
		t.Fatal("tampered amount passed signature verification")
	}
	wrongDestination := decoded
	wrongDestination.DestinationRegion = "C"
	if err := VerifyCertificate(wrongDestination, keys); err == nil {
		t.Fatal("tampered destination passed signature verification")
	}
}

func TestConsumptionReceiptBindsCommitWatermarkAndBothKeyIdentities(t *testing.T) {
	sourcePublic, sourcePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destinationPublic, destinationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceSigner := Ed25519Signer{
		KeyID: "source-key", PrivateKey: sourcePrivate, Region: "eu-west",
		LegalEntityID: "entity-eu", Epoch: 11,
	}
	destinationSigner := Ed25519ReceiptSigner{
		KeyID: "destination-key", PrivateKey: destinationPrivate, Region: "us-east",
		LegalEntityID: "entity-us", Epoch: 29,
	}
	registry := StaticKeyRegistry{
		sourceSigner.KeyID: {
			Binding: sourceSigner.Binding(), PublicKey: sourcePublic,
		},
		destinationSigner.KeyID: {
			Binding: destinationSigner.Binding(), PublicKey: destinationPublic,
		},
	}
	certificate, err := sourceSigner.Sign(Certificate{
		TransferID: "transfer-receipt", AccountID: "account", AssetID: "USD",
		SourceRegion: "eu-west", DestinationRegion: "us-east",
		SourceLegalEntityID: "entity-eu", DestinationLegalEntityID: "entity-us",
		Amount: ledger.MustAmount("123456789012345678901"), SourceEpoch: 41,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateHash, err := certificate.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := destinationSigner.SignReceipt(ConsumptionReceipt{
		TransferID: certificate.TransferID, CertificateHash: certificateHash,
		AccountID: certificate.AccountID, AssetID: certificate.AssetID,
		Amount: certificate.Amount, SourceRegion: certificate.SourceRegion,
		SourceLegalEntityID: certificate.SourceLegalEntityID,
		SourceEpoch:         certificate.SourceEpoch, SourceKeyEpoch: certificate.KeyEpoch,
		DestinationRegion:          certificate.DestinationRegion,
		DestinationLegalEntityID:   certificate.DestinationLegalEntityID,
		DestinationCommitWatermark: 9081,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsumptionReceipt(receipt, certificate, registry); err != nil {
		t.Fatalf("valid committed receipt rejected: %v", err)
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ConsumptionReceipt
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	payload, _ := receipt.Payload()
	decodedPayload, _ := decoded.Payload()
	if !bytes.Equal(payload, decodedPayload) ||
		!bytes.Equal(receipt.Signature, decoded.Signature) {
		t.Fatal("receipt JSON round trip changed signed bytes")
	}

	tests := map[string]func(ConsumptionReceipt) ConsumptionReceipt{
		"watermark": func(value ConsumptionReceipt) ConsumptionReceipt {
			value.DestinationCommitWatermark++
			return value
		},
		"destination": func(value ConsumptionReceipt) ConsumptionReceipt {
			value.DestinationRegion = "ap-south"
			return value
		},
		"key epoch": func(value ConsumptionReceipt) ConsumptionReceipt {
			value.KeyEpoch++
			return value
		},
		"certificate hash": func(value ConsumptionReceipt) ConsumptionReceipt {
			value.CertificateHash = sha256.Sum256([]byte("different-certificate"))
			return value
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := VerifyConsumptionReceipt(mutate(receipt), certificate, registry); err == nil {
				t.Fatal("tampered receipt passed verification")
			}
		})
	}

	wrongBinding := registry
	wrongBinding[destinationSigner.KeyID] = VerificationKey{
		Binding: KeyBinding{
			KeyID: destinationSigner.KeyID, Region: "us-east",
			LegalEntityID: "different-entity", Epoch: destinationSigner.Epoch,
			Purpose: KeyPurposeConsumptionReceipt,
		},
		PublicKey: destinationPublic,
	}
	if err := VerifyConsumptionReceipt(receipt, certificate, wrongBinding); err == nil {
		t.Fatal("receipt key registered to a different legal entity was accepted")
	}
}

func TestCertificateRegistryRejectsCrossRegionAndCrossPurposeKeyReuse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{
		KeyID: "bound-key", PrivateKey: privateKey,
		Region: "source", LegalEntityID: "source-entity", Epoch: 4,
	}
	certificate, err := signer.Sign(Certificate{
		TransferID: "bound-transfer", AccountID: "account", AssetID: "EUR",
		SourceRegion: "source", DestinationRegion: "destination",
		SourceLegalEntityID:      "source-entity",
		DestinationLegalEntityID: "destination-entity",
		Amount:                   ledger.NewAmountInt64(1), SourceEpoch: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, binding := range map[string]KeyBinding{
		"wrong region": {
			KeyID: signer.KeyID, Region: "other", LegalEntityID: signer.LegalEntityID,
			Epoch: signer.Epoch, Purpose: KeyPurposeTransferCertificate,
		},
		"wrong legal entity": {
			KeyID: signer.KeyID, Region: signer.Region, LegalEntityID: "other",
			Epoch: signer.Epoch, Purpose: KeyPurposeTransferCertificate,
		},
		"wrong epoch": {
			KeyID: signer.KeyID, Region: signer.Region, LegalEntityID: signer.LegalEntityID,
			Epoch: signer.Epoch + 1, Purpose: KeyPurposeTransferCertificate,
		},
		"cross purpose": {
			KeyID: signer.KeyID, Region: signer.Region, LegalEntityID: signer.LegalEntityID,
			Epoch: signer.Epoch, Purpose: KeyPurposeConsumptionReceipt,
		},
	} {
		t.Run(name, func(t *testing.T) {
			registry := StaticKeyRegistry{signer.KeyID: {
				Binding: binding, PublicKey: publicKey,
			}}
			if err := VerifyCertificate(certificate, registry); err == nil {
				t.Fatal("misbound registry key was accepted")
			}
		})
	}
}

func TestAuthorityConservationUsesExactArithmetic(t *testing.T) {
	authority := Authority{
		Total:       ledger.MustAmount("10000000000000000000000000000000000000"),
		Unallocated: ledger.MustAmount("1"),
		InTransit:   ledger.MustAmount("9999999999999999999999999999999999996"),
		RegionalRights: map[string]ledger.Amount{
			"A": ledger.MustAmount("2"),
			"B": ledger.MustAmount("1"),
		},
	}
	if !authority.Conserved() {
		t.Fatal("exact 38-digit authority should be conserved")
	}
	authority.RegionalRights["B"] = ledger.MustAmount("2")
	if authority.Conserved() {
		t.Fatal("created authority was not detected")
	}
}

func TestCertificateRejectsUnknownKeyAndInvalidAmount(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := Ed25519Signer{KeyID: "retired", PrivateKey: privateKey,
		Region: "A", LegalEntityID: "entity-a", Epoch: 2}
	certificate, err := signer.Sign(Certificate{
		TransferID: "t", AccountID: "a", AssetID: "USD", SourceRegion: "A",
		DestinationRegion: "B", SourceLegalEntityID: "entity-a",
		DestinationLegalEntityID: "entity-b", Amount: ledger.NewAmountInt64(1), SourceEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificate(certificate, StaticKeyRegistry{}); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := signer.Sign(Certificate{
		TransferID: "bad", AccountID: "a", AssetID: "USD", SourceRegion: "A",
		DestinationRegion: "B", SourceLegalEntityID: "entity-a",
		DestinationLegalEntityID: "entity-b", Amount: ledger.NewAmountInt64(0), SourceEpoch: 2,
	}); err == nil {
		t.Fatal("zero allowance signed")
	}
}
