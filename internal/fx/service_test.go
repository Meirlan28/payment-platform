package fx

import (
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

func TestConvertRoundingRules(t *testing.T) {
	tests := []struct {
		name                         string
		base, numerator, denominator string
		rule                         RoundingRule
		want                         string
	}{
		{"floor", "5", "1", "2", Floor, "2"},
		{"ceiling", "5", "1", "2", Ceiling, "3"},
		{"half-even-down", "5", "1", "2", HalfEven, "2"},
		{"half-even-up", "7", "1", "2", HalfEven, "4"},
		{"exact-large", "10000000000000000000000000000000000000", "3", "2", HalfEven, "15000000000000000000000000000000000000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Convert(ledger.MustAmount(test.base), ledger.MustAmount(test.numerator), ledger.MustAmount(test.denominator), test.rule)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != test.want {
				t.Fatalf("got %s, want %s", got.String(), test.want)
			}
		})
	}
}
