package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

type testCheckpointSigner struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func (s testCheckpointSigner) Sign(_ context.Context, _ string, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.private, payload), nil
}

func (s testCheckpointSigner) Verify(_ context.Context, _ string, payload, signature []byte) error {
	if !ed25519.Verify(s.public, payload, signature) {
		return errors.New("signature mismatch")
	}
	return nil
}

func TestCheckpointSignatureCoversRangeAndRoots(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := testCheckpointSigner{private: private, public: public}
	checkpoint := Checkpoint{
		BookID: "book-1", FirstSequence: 1, LastSequence: 2, LeafCount: 2,
		MerkleRoot: [32]byte{1}, LastEntryHash: [32]byte{2}, SigningKeyID: "hsm-key-7",
	}
	payload, err := checkpoint.Payload()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature, err = signer.Sign(context.Background(), checkpoint.SigningKeyID, payload)
	if err != nil {
		t.Fatal(err)
	}
	checkpointer := Checkpointer{Signer: signer}
	if err := checkpointer.Verify(context.Background(), checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint.LastSequence = 3
	checkpoint.LeafCount = 3
	if err := checkpointer.Verify(context.Background(), checkpoint); err == nil {
		t.Fatal("range tampering must invalidate checkpoint signature")
	}
}
