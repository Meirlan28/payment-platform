package audit

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

func TestVerifierDetectsHistoricalTampering(t *testing.T) {
	bookID := "book-a"
	previous := ledger.GenesisHash(bookID)
	request := ledger.PostRequest{
		TransactionID: "tx-1", BookID: bookID, OperationID: "op-1", EffectID: "effect-1",
		Kind: "DEPOSIT", PostingRuleVersion: "deposit/v1", SchemaVersion: 1,
		RequestHash: sha256.Sum256([]byte("request")),
		Lines: []ledger.Line{
			{AccountID: "cash", AssetID: "USD", Side: ledger.Debit, AmountAtoms: ledger.NewAmountInt64(100)},
			{AccountID: "wallet", AssetID: "USD", Side: ledger.Credit, AmountAtoms: ledger.NewAmountInt64(100)},
		},
	}
	hash, err := ledger.HashEntry(previous, 1, request)
	if err != nil {
		t.Fatal(err)
	}
	transaction := ledger.Transaction{PostRequest: request, SequenceNo: 1, PrevHash: previous, EntryHash: hash, Status: "POSTED"}
	rangeRequest := Range{BookID: bookID, First: 1, Last: 1, ExpectedPrev: previous}
	if _, err := VerifyRange(rangeRequest, []ledger.Transaction{transaction}); err != nil {
		t.Fatalf("untampered journal failed verification: %v", err)
	}

	// This models a privileged/raw-storage mutation that bypassed the normal
	// append-only SQL role. The stored entry hash remains the committed value.
	transaction.Lines[0].AmountAtoms = ledger.NewAmountInt64(101)
	transaction.Lines[1].AmountAtoms = ledger.NewAmountInt64(101)
	if _, err := VerifyRange(rangeRequest, []ledger.Transaction{transaction}); !errors.Is(err, ErrEntryHash) {
		t.Fatalf("expected entry hash mismatch, got %v", err)
	}
}

func TestMerkleRootChangesOnMutation(t *testing.T) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	first := MerkleRoot([][32]byte{a, b})
	b = sha256.Sum256([]byte("changed"))
	second := MerkleRoot([][32]byte{a, b})
	if first == second {
		t.Fatal("Merkle root did not change")
	}
}
