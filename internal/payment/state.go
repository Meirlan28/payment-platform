package payment

import (
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
)

type State string

const (
	Created           State = "CREATED"
	Authorized        State = "AUTHORIZED"
	Held              State = "HELD"
	PartiallyCaptured State = "PARTIALLY_CAPTURED"
	Captured          State = "CAPTURED"
	Settled           State = "SETTLED"
	PartiallyRefunded State = "PARTIALLY_REFUNDED"
	Refunded          State = "REFUNDED"
	Reversed          State = "REVERSED"
	Disputed          State = "DISPUTED"
	ChargedBack       State = "CHARGED_BACK"
	Failed            State = "FAILED"
	Unknown           State = "UNKNOWN"
)

var (
	ErrInvalidTransition = errors.New("payment: invalid state transition")
	ErrInvalidRequest    = errors.New("payment: invalid request")
	ErrPaymentNotFound   = errors.New("payment: payment not found")
	ErrOverCapture       = errors.New("payment: capture plus release exceeds authorization")
	ErrOverRefund        = errors.New("payment: refunds plus chargebacks exceed captured principal")
	ErrCashbackRule      = errors.New("payment: cashback exceeds pinned rule result")
)

var transitions = map[State]map[State]struct{}{
	Created:           set(Authorized, Held, Failed, Unknown),
	Authorized:        set(Held, Captured, Reversed, Failed, Unknown),
	Held:              set(PartiallyCaptured, Captured, Reversed, Unknown),
	PartiallyCaptured: set(Captured, Reversed, Unknown),
	Captured:          set(Settled, PartiallyRefunded, Refunded, Disputed, ChargedBack, Unknown),
	Settled:           set(PartiallyRefunded, Refunded, Disputed, ChargedBack),
	PartiallyRefunded: set(Refunded, Disputed, ChargedBack),
	Disputed:          set(ChargedBack, Settled, PartiallyRefunded, Refunded),
	Unknown:           set(Authorized, Held, Captured, Settled, Failed, Reversed),
}

func set(states ...State) map[State]struct{} {
	result := make(map[State]struct{}, len(states))
	for _, state := range states {
		result[state] = struct{}{}
	}
	return result
}

func CanTransition(from, to State) bool {
	if from == to {
		return true
	}
	_, ok := transitions[from][to]
	return ok
}

func ValidateTransition(from, to State) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}

func captureState(authorized, captured, released ledger.Amount) (State, error) {
	used, err := captured.Add(released)
	if err != nil || used.Cmp(authorized) > 0 {
		return "", ErrOverCapture
	}
	if used.Cmp(authorized) == 0 && captured.Sign() > 0 {
		return Captured, nil
	}
	return PartiallyCaptured, nil
}

func refundState(captured, refunded, chargedBack ledger.Amount) (State, error) {
	returned, err := refunded.Add(chargedBack)
	if err != nil || returned.Cmp(captured) > 0 {
		return "", ErrOverRefund
	}
	if returned.Cmp(captured) == 0 {
		if chargedBack.Sign() > 0 && refunded.IsZero() {
			return ChargedBack, nil
		}
		return Refunded, nil
	}
	return PartiallyRefunded, nil
}
