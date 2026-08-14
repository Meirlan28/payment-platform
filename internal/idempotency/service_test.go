package idempotency

import (
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

func TestRequestHashCanonicalAndExact(t *testing.T) {
	type request struct {
		Amount ledger.Amount    `json:"amount"`
		Meta   map[string]int64 `json:"meta"`
	}
	first, err := RequestHash(request{
		Amount: ledger.MustAmount("12345678901234567890123456789012345678"),
		Meta:   map[string]int64{"b": 2, "a": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalBytesHash([]byte(`{
        "meta":{"a":1,"b":2},
        "amount":"12345678901234567890123456789012345678"
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("canonical-equivalent requests have different hashes")
	}
}
