package chaos_test

import (
	"errors"
	"testing"

	"github.com/example/payment-platform/internal/simulation"
)

func TestTransferSurvivesSourceCrashAndRetry(t *testing.T) {
	world := newWorld(t, 25, 0, map[string]int64{"A": 25, "B": 0})
	fence, _ := world.Fence("A")
	certificate, _, err := world.InitiateTransfer(fence, "source-crash", "B", atoms(9))
	if err != nil {
		t.Fatal(err)
	}
	if err := world.CrashRegion("A"); err != nil {
		t.Fatal(err)
	}
	failures := world.DispatchOutbox()
	if len(failures) != 1 || !errors.Is(failures[0], simulation.ErrNodeDown) {
		t.Fatalf("dispatch from crashed source: %v", failures)
	}
	transfer, _ := world.Transfer("source-crash")
	if !transfer.InTransit || transfer.Certificate.CommitProof != certificate.CommitProof {
		t.Fatal("source crash lost durable certificate/in-transit ownership")
	}
	assertInvariants(t, world)
	if err := world.RestartRegion("A"); err != nil {
		t.Fatal(err)
	}
	if err := world.PumpUntilSettled(20); err != nil {
		t.Fatal(err)
	}
	if world.Rights("B").Cmp(atoms(9)) != 0 {
		t.Fatal("source restart failed to retransmit committed certificate")
	}
	assertInvariants(t, world)
}

func TestTransferSurvivesDestinationCrashBeforeConsume(t *testing.T) {
	world := newWorld(t, 25, 0, map[string]int64{"A": 25, "B": 0})
	fence, _ := world.Fence("A")
	if _, _, err := world.InitiateTransfer(fence, "destination-crash", "B", atoms(9)); err != nil {
		t.Fatal(err)
	}
	if err := world.CrashRegion("B"); err != nil {
		t.Fatal(err)
	}
	failures := world.DispatchOutbox()
	if len(failures) != 1 || !errors.Is(failures[0], simulation.ErrNodeDown) {
		t.Fatalf("dispatch to crashed destination: %v", failures)
	}
	if world.Rights("B").Sign() != 0 || world.EffectCount("rights-transfer-in:destination-crash") != 0 {
		t.Fatal("destination crash created a partial consume")
	}
	assertInvariants(t, world)
	if err := world.RestartRegion("B"); err != nil {
		t.Fatal(err)
	}
	if err := world.PumpUntilSettled(20); err != nil {
		t.Fatal(err)
	}
	if world.Rights("B").Cmp(atoms(9)) != 0 || world.EffectCount("rights-transfer-in:destination-crash") != 1 {
		t.Fatal("destination recovery failed to consume exactly once")
	}
	assertInvariants(t, world)
}

func TestTamperedTransferCertificateIsRejected(t *testing.T) {
	world := newWorld(t, 25, 0, map[string]int64{"A": 25, "B": 0})
	fence, _ := world.Fence("A")
	certificate, _, err := world.InitiateTransfer(fence, "tamper", "B", atoms(9))
	if err != nil {
		t.Fatal(err)
	}
	certificate.Amount = atoms(10)
	if _, _, err := world.ConsumeTransfer(certificate); err == nil {
		t.Fatal("tampered certificate was accepted")
	}
	if world.Rights("B").Sign() != 0 || world.EffectCount("rights-transfer-in:tamper") != 0 {
		t.Fatal("rejected certificate changed destination state")
	}
	assertInvariants(t, world)
}
