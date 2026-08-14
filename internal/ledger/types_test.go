package ledger

import (
	"encoding/json"
	"errors"
	"testing"
)

func validPosting() PostRequest {
	return PostRequest{
		TransactionID: "txn-1", BookID: "book-1", OperationID: "op-1",
		EffectID: "effect-1", Kind: "TRANSFER", PostingRuleVersion: "v1",
		SchemaVersion: 1, Metadata: json.RawMessage(`{"b":2,"a":1}`),
		Lines: []Line{
			{AccountID: "from", AssetID: "USD", Side: Debit, AmountAtoms: NewAmountInt64(100)},
			{AccountID: "to", AssetID: "USD", Side: Credit, AmountAtoms: NewAmountInt64(100)},
		},
	}
}

func TestPostingBalancesEveryAssetIndependently(t *testing.T) {
	posting := validPosting()
	posting.Lines = []Line{
		{AccountID: "usd-from", AssetID: "USD", Side: Debit, AmountAtoms: NewAmountInt64(100)},
		{AccountID: "eur-to", AssetID: "EUR", Side: Credit, AmountAtoms: NewAmountInt64(100)},
	}
	if err := posting.Validate(); !errors.Is(err, ErrUnbalanced) {
		t.Fatalf("cross-currency netting was accepted: %v", err)
	}

	posting.Lines = append(posting.Lines,
		Line{AccountID: "usd-position", AssetID: "USD", Side: Credit, AmountAtoms: NewAmountInt64(100)},
		Line{AccountID: "eur-position", AssetID: "EUR", Side: Debit, AmountAtoms: NewAmountInt64(100)},
	)
	if err := posting.Validate(); err != nil {
		t.Fatalf("separately balanced FX legs rejected: %v", err)
	}
}

func TestHashEntryCanonicalMetadataAndSensitivity(t *testing.T) {
	posting := validPosting()
	prev := GenesisHash(posting.BookID)
	first, err := HashEntry(prev, 1, posting)
	if err != nil {
		t.Fatal(err)
	}
	posting.Metadata = json.RawMessage(`{ "a" : 1, "b" : 2 }`)
	second, err := HashEntry(prev, 1, posting)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("equivalent JSON metadata changed the audit hash")
	}
	posting.Lines[0].AmountAtoms = NewAmountInt64(101)
	posting.Lines[1].AmountAtoms = NewAmountInt64(101)
	third, err := HashEntry(prev, 1, posting)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("financial line change did not change the audit hash")
	}
}
