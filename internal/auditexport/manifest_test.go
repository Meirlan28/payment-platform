package auditexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/audit"
)

func TestManifestIsDeterministicAndCarriesSignedCheckpoint(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := audit.Checkpoint{
		BookID: "book-κ", FirstSequence: 1, LastSequence: 3, LeafCount: 3,
		MerkleRoot: [32]byte{1, 2, 3}, LastEntryHash: [32]byte{4, 5, 6},
		SigningKeyID: "audit-checkpoint", CreatedAt: time.Date(2026, 8, 16, 12, 1, 2, 345000000, time.FixedZone("offset", 6*3600)),
	}
	payload, err := checkpoint.Payload()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature = ed25519.Sign(private, payload)
	first, err := BuildManifest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildManifest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes, second.Bytes) || first.SHA256 != second.SHA256 || first.ObjectKey != second.ObjectKey {
		t.Fatal("same signed checkpoint produced different canonical artifacts")
	}
	if first.RetainUntil.Sub(checkpoint.CreatedAt) < 10*365*24*time.Hour {
		t.Fatal("retention is shorter than ten calendar years")
	}
	var decoded manifestV1
	if err := json.Unmarshal(first.Bytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Format != ManifestFormat || decoded.BookID != checkpoint.BookID ||
		decoded.LastSequence != "3" || decoded.CheckpointCreatedAt != "2026-08-16T06:01:02.345Z" {
		t.Fatalf("unexpected canonical manifest: %+v", decoded)
	}
	if !ed25519.Verify(public, payload, checkpoint.Signature) {
		t.Fatal("fixture checkpoint signature is not verifiable")
	}
	checkpoint.LastEntryHash[0]++
	changed, err := BuildManifest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if changed.SHA256 == first.SHA256 || changed.ObjectKey == first.ObjectKey {
		t.Fatal("checkpoint mutation did not alter deterministic evidence")
	}
}
