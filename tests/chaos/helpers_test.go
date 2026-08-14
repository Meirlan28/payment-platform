package chaos_test

import (
	"testing"

	"github.com/example/payment-platform/internal/failuresim"
	"github.com/example/payment-platform/internal/ledger"
)

func atoms(value int64) ledger.Amount { return ledger.NewAmountInt64(value) }

func newWorld(t *testing.T, balance, credit int64, rights map[string]int64) *failuresim.World {
	t.Helper()
	converted := make(map[string]ledger.Amount, len(rights))
	for region, amount := range rights {
		converted[region] = atoms(amount)
	}
	world, err := failuresim.NewWorld(failuresim.Config{
		Asset: "USD", InitialBalance: atoms(balance), CreditLimit: atoms(credit),
		RegionalRights: converted,
	}, 0x5eed)
	if err != nil {
		t.Fatalf("new failure model: %v", err)
	}
	assertInvariants(t, world)
	return world
}

func assertInvariants(t *testing.T, world *failuresim.World) {
	t.Helper()
	if err := world.AssertAllFinancialInvariants(); err != nil {
		t.Fatalf("financial invariant violation: %v\nworld: %s", err, world)
	}
}
