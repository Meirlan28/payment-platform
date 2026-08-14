package payment

import (
	"errors"
	"testing"

	"github.com/example/payment-platform/internal/ledger"
)

func TestStateMachineRejectsInvalidTransitions(t *testing.T) {
	if err := ValidateTransition(Held, Refunded); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("HELD -> REFUNDED accepted: %v", err)
	}
	if err := ValidateTransition(Held, Captured); err != nil {
		t.Fatalf("valid transition rejected: %v", err)
	}
	if err := ValidateTransition(Refunded, Settled); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal refund was mutated: %v", err)
	}
}

func TestCounterDerivedStates(t *testing.T) {
	state, err := captureState(ledger.NewAmountInt64(100), ledger.NewAmountInt64(60), ledger.NewAmountInt64(40))
	if err != nil || state != Captured {
		t.Fatalf("unexpected capture state %s: %v", state, err)
	}
	if _, err := refundState(ledger.NewAmountInt64(100), ledger.NewAmountInt64(80), ledger.NewAmountInt64(30)); !errors.Is(err, ErrOverRefund) {
		t.Fatalf("over-refund accepted: %v", err)
	}
}
