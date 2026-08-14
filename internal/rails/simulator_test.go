package rails

import (
	"context"
	"errors"
	"testing"
)

func TestSuccessLostResponseResolvesBySameReference(t *testing.T) {
	simulator := NewCardSimulator()
	simulator.Script("payment-1", Behavior{Mode: BehaviorSuccessLostResponse, Code: "00"})
	request := Request{
		OperationID: "payment-1", Rail: Card, ProviderReference: "stable-ref-1",
		Payload: []byte("charge"),
	}
	if _, err := simulator.Submit(context.Background(), request); !errors.Is(err, ErrRailTimeout) {
		t.Fatalf("submit error = %v", err)
	}
	response, err := simulator.Lookup(context.Background(), request.ProviderReference)
	if err != nil || response.Outcome != OutcomeSucceeded {
		t.Fatalf("lookup = %#v, %v", response, err)
	}
	duplicate, err := simulator.Submit(context.Background(), request)
	if err != nil || duplicate.Outcome != OutcomeSucceeded || !duplicate.Duplicate {
		t.Fatalf("same reference was not idempotent: %#v, %v", duplicate, err)
	}
	if got := simulator.SubmitCount(request.ProviderReference); got != 2 {
		t.Fatalf("submit count = %d", got)
	}
}

func TestDelayedResultDuplicateWebhookAndLateFraudVerdict(t *testing.T) {
	blockchain := NewBlockchainSimulator()
	blockchain.Script("withdrawal-1", Behavior{Mode: BehaviorDelayedSuccess, DelayTicks: 3})
	request := Request{OperationID: "withdrawal-1", Rail: Blockchain, ProviderReference: "tx-1", Payload: []byte("raw")}
	if _, err := blockchain.Submit(context.Background(), request); !errors.Is(err, ErrRailTimeout) {
		t.Fatalf("delayed submit = %v", err)
	}
	blockchain.Advance(2)
	if _, err := blockchain.Lookup(context.Background(), "tx-1"); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("premature finality: %v", err)
	}
	blockchain.Advance(1)
	if response, err := blockchain.Lookup(context.Background(), "tx-1"); err != nil || response.Outcome != OutcomeSucceeded {
		t.Fatalf("final lookup = %#v, %v", response, err)
	}

	antifraud := NewAntifraudSimulator()
	antifraud.Script("risk-1", Behavior{
		Mode: BehaviorDuplicateWebhook, DelayTicks: 2,
		LateVerdict: &Webhook{Outcome: OutcomeFailed, Code: "FRAUD"},
	})
	_, err := antifraud.Submit(context.Background(), Request{
		OperationID: "risk-1", Rail: Antifraud, ProviderReference: "risk-ref", Payload: []byte("features"),
	})
	if err != nil {
		t.Fatal(err)
	}
	initial := antifraud.DrainWebhooks()
	if len(initial) != 2 || !initial[1].Duplicate {
		t.Fatalf("duplicate webhook script = %#v", initial)
	}
	antifraud.Advance(2)
	late := antifraud.DrainWebhooks()
	if len(late) != 1 || late[0].Code != "FRAUD" || late[0].Outcome != OutcomeFailed {
		t.Fatalf("late fraud verdict = %#v", late)
	}
}

func TestTimeoutWithoutEffectStaysUnknown(t *testing.T) {
	bank := NewBankSimulator()
	bank.Script("bank-1", Behavior{Mode: BehaviorTimeoutNoEffect})
	request := Request{OperationID: "bank-1", Rail: Bank, ProviderReference: "bank-ref", Payload: []byte("transfer")}
	if _, err := bank.Submit(context.Background(), request); !errors.Is(err, ErrRailTimeout) {
		t.Fatal(err)
	}
	if _, err := bank.Lookup(context.Background(), "bank-ref"); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("missing transfer should remain unknown: %v", err)
	}
}
