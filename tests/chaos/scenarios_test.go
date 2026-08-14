package chaos_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/failuresim"
	"github.com/example/payment-platform/internal/simulation"
)

func TestDeterministicChaosScenarios(t *testing.T) {
	t.Run("01_server_dies_before_commit", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 10})
		world.CrashBeforeCommit("before")
		if _, err := world.Pay("A", "before", "before-op", atoms(5)); !errors.Is(err, failuresim.ErrCrashBeforeCommit) {
			t.Fatalf("got %v, want crash before commit", err)
		}
		if world.EffectCount("payment:before-op") != 0 || world.Balance(failuresim.UserAccount).Cmp(atoms(10)) != 0 {
			t.Fatal("crash before commit left a partial economic effect")
		}
		assertInvariants(t, world)
	})

	t.Run("02_server_dies_after_commit_before_response", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 10, "B": 0})
		world.CrashAfterCommit("after")
		first, err := world.Pay("A", "after", "after-op", atoms(5))
		if !errors.Is(err, failuresim.ErrCrashAfterCommit) {
			t.Fatalf("got %v, want crash after commit", err)
		}
		if err := world.RestartRegion("A"); err != nil {
			t.Fatal(err)
		}
		second, err := world.Pay("B", "after", "after-op", atoms(5))
		if err != nil || !second.Duplicate || second.TransactionID != first.TransactionID {
			t.Fatalf("retry failed: receipt=%+v err=%v", second, err)
		}
		if world.EffectCount("payment:after-op") != 1 {
			t.Fatal("post-commit crash duplicated or lost the effect")
		}
		assertInvariants(t, world)
	})

	t.Run("03_message_delivered_twice", func(t *testing.T) {
		world := newWorld(t, 20, 0, map[string]int64{"A": 20, "B": 0})
		fence, _ := world.Fence("A")
		if _, _, err := world.InitiateTransfer(fence, "duplicate", "B", atoms(7)); err != nil {
			t.Fatal(err)
		}
		world.Network().DuplicateNext("transfer:duplicate", 1)
		if failures := world.DispatchOutbox(); len(failures) != 0 {
			t.Fatalf("dispatch: %v", failures)
		}
		if failures := world.DeliverMessages(); len(failures) != 0 {
			t.Fatalf("consume duplicates: %v", failures)
		}
		if failures := world.DeliverMessages(); len(failures) != 0 {
			t.Fatalf("deliver ACKs: %v", failures)
		}
		inbox, ok := world.InboxRecord("transfer:duplicate")
		if !ok || inbox.DuplicateDeliveries != 1 {
			t.Fatalf("durable inbox did not observe exactly one duplicate: %+v", inbox)
		}
		if world.EffectCount("rights-transfer-in:duplicate") != 1 || world.Rights("B").Cmp(atoms(7)) != 0 {
			t.Fatal("duplicate transport delivery duplicated destination rights")
		}
		assertInvariants(t, world)
	})

	t.Run("04_messages_reordered", func(t *testing.T) {
		world := newWorld(t, 30, 0, map[string]int64{"A": 30, "B": 0})
		fence, _ := world.Fence("A")
		if _, _, err := world.InitiateTransfer(fence, "order-1", "B", atoms(4)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := world.InitiateTransfer(fence, "order-2", "B", atoms(6)); err != nil {
			t.Fatal(err)
		}
		world.SetReordering(true)
		world.DispatchOutbox()
		if failures := world.DeliverMessages(); len(failures) != 0 {
			t.Fatalf("reordered consumption: %v", failures)
		}
		world.DeliverMessages()
		if world.Rights("B").Cmp(atoms(10)) != 0 {
			t.Fatalf("destination rights = %s, want 10", world.Rights("B").String())
		}
		assertInvariants(t, world)
	})

	t.Run("05_network_partition_and_heal", func(t *testing.T) {
		world := newWorld(t, 20, 0, map[string]int64{"A": 20, "B": 0})
		fence, _ := world.Fence("A")
		if _, _, err := world.InitiateTransfer(fence, "partition-transfer", "B", atoms(8)); err != nil {
			t.Fatal(err)
		}
		world.Partition("A", "B")
		failures := world.DispatchOutbox()
		if len(failures) != 1 || !errors.Is(failures[0], simulation.ErrPartitioned) {
			t.Fatalf("partitioned dispatch: %v", failures)
		}
		transfer, _ := world.Transfer("partition-transfer")
		if !transfer.InTransit || transfer.Consumed || world.Rights("B").Sign() != 0 {
			t.Fatal("partition manufactured destination rights")
		}
		assertInvariants(t, world)
		world.Heal("A", "B")
		if err := world.PumpUntilSettled(10); err != nil {
			t.Fatal(err)
		}
		if world.Rights("B").Cmp(atoms(8)) != 0 {
			t.Fatal("healed transfer did not settle")
		}
		assertInvariants(t, world)
	})

	t.Run("06_partition_plus_concurrent_spending", func(t *testing.T) {
		// The high-contention proof is TestB; this scenario also verifies the
		// partition does not prevent independent use of preallocated rights.
		world := newWorld(t, 10, 0, map[string]int64{"A": 6, "B": 4})
		world.Partition("A", "B")
		for index := 0; index < 6; index++ {
			if _, err := world.Pay("A", key("pa", index), key("pa-op", index), atoms(1)); err != nil {
				t.Fatal(err)
			}
		}
		for index := 0; index < 4; index++ {
			if _, err := world.Pay("B", key("pb", index), key("pb-op", index), atoms(1)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := world.Pay("A", "exhausted", "exhausted-op", atoms(1)); !errors.Is(err, failuresim.ErrInsufficientRights) && !errors.Is(err, failuresim.ErrInsufficientFunds) {
			t.Fatalf("exhausted escrow payment: %v", err)
		}
		assertInvariants(t, world)
	})

	t.Run("07_thirty_percent_packet_loss", func(t *testing.T) {
		world := newWorld(t, 20, 0, map[string]int64{"A": 20, "B": 0})
		fence, _ := world.Fence("A")
		if _, _, err := world.InitiateTransfer(fence, "lossy", "B", atoms(9)); err != nil {
			t.Fatal(err)
		}
		world.SetPacketLoss(30)
		world.SetDuplicateEvery(3)
		if err := world.PumpUntilSettled(200); err != nil {
			t.Fatal(err)
		}
		if world.Rights("B").Cmp(atoms(9)) != 0 || world.EffectCount("rights-transfer-in:lossy") != 1 {
			t.Fatal("at-least-once retries under loss changed economic cardinality")
		}
		assertInvariants(t, world)
	})

	t.Run("08_coordinator_crash", func(t *testing.T) {
		world := newWorld(t, 20, 0, map[string]int64{"A": 20})
		if _, err := world.StartSaga("saga-1", "A", "saga-payment", atoms(7)); err != nil {
			t.Fatal(err)
		}
		world.CrashCoordinatorAfterEffect("saga-1")
		if _, err := world.AdvanceSaga("saga-1"); !errors.Is(err, failuresim.ErrCoordinatorCrash) {
			t.Fatalf("advance: got %v, want coordinator crash", err)
		}
		if world.EffectCount("payment:saga-payment") != 1 {
			t.Fatal("financial effect was not durable at coordinator crash boundary")
		}
		world.RestartCoordinator()
		if _, err := world.AdvanceSaga("saga-1"); err != nil {
			t.Fatal(err)
		}
		saga, err := world.AdvanceSaga("saga-1")
		if err != nil || !saga.Completed {
			t.Fatalf("resumed saga did not finish: %+v err=%v", saga, err)
		}
		if world.EffectCount("payment:saga-payment") != 1 {
			t.Fatal("resumed coordinator duplicated payment")
		}
		assertInvariants(t, world)
	})

	t.Run("09_consumer_crash_after_effect_before_ack", func(t *testing.T) {
		world := newWorld(t, 20, 0, map[string]int64{"A": 20, "B": 0})
		fence, _ := world.Fence("A")
		if _, _, err := world.InitiateTransfer(fence, "consumer-crash", "B", atoms(5)); err != nil {
			t.Fatal(err)
		}
		world.CrashConsumerAfterApply("transfer:consumer-crash")
		world.DispatchOutbox()
		failures := world.DeliverMessages()
		if len(failures) != 1 || !errors.Is(failures[0], failuresim.ErrConsumerCrash) {
			t.Fatalf("consumer failure boundary: %v", failures)
		}
		if world.Rights("B").Cmp(atoms(5)) != 0 {
			t.Fatal("atomic effect was not committed before consumer crash")
		}
		assertInvariants(t, world)
		if err := world.RestartRegion("B"); err != nil {
			t.Fatal(err)
		}
		if err := world.PumpUntilSettled(10); err != nil {
			t.Fatal(err)
		}
		if world.Rights("B").Cmp(atoms(5)) != 0 || world.EffectCount("rights-transfer-in:consumer-crash") != 1 {
			t.Fatal("consumer restart duplicated applied effect")
		}
		assertInvariants(t, world)
	})

	t.Run("10_stale_worker_after_leader_change", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 10})
		stale, _ := world.Fence("A")
		_ = world.CrashRegion("A")
		_ = world.RestartRegion("A")
		if _, err := world.PayWithFence(stale, "stale", "stale-op", atoms(1)); !errors.Is(err, failuresim.ErrStaleEpoch) {
			t.Fatalf("stale worker: %v", err)
		}
		if world.EffectCount("payment:stale-op") != 0 {
			t.Fatal("stale worker committed an effect")
		}
		if _, err := world.Pay("A", "fresh", "fresh-op", atoms(1)); err != nil {
			t.Fatal(err)
		}
		assertInvariants(t, world)
	})

	t.Run("11_clock_jumps_do_not_order_money", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 5, "B": 5})
		base := time.Unix(1_000, 0)
		world.ClockSkew("A", 15*time.Minute)
		world.ClockSkew("B", -15*time.Minute)
		if delta := world.RegionalTime("A", base).Sub(world.RegionalTime("B", base)); delta != 30*time.Minute {
			t.Fatalf("injected skew = %s", delta)
		}
		first, err := world.Pay("B", "clock-b", "clock-b-op", atoms(1))
		if err != nil {
			t.Fatal(err)
		}
		second, err := world.Pay("A", "clock-a", "clock-a-op", atoms(1))
		if err != nil {
			t.Fatal(err)
		}
		if first.CommitSequence >= second.CommitSequence {
			t.Fatal("journal order did not follow consensus sequence")
		}
		assertInvariants(t, world)
	})

	t.Run("12_any_three_DC_failures_preserve_quorum", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 10})
		for _, dc := range []string{"dc01", "dc02", "dc03"} {
			if err := world.CrashDC(dc); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := world.Pay("A", "three-dc", "three-dc-op", atoms(1)); err != nil {
			t.Fatalf("RF7/Q4 rejected write after three replica DC failures: %v", err)
		}
		if err := world.CrashDC("dc04"); err != nil {
			t.Fatal(err)
		}
		if _, err := world.Pay("A", "four-dc", "four-dc-op", atoms(1)); !errors.Is(err, failuresim.ErrNoQuorum) {
			t.Fatalf("write without Q4: %v", err)
		}
		if world.EffectCount("payment:four-dc-op") != 0 {
			t.Fatal("write committed without quorum")
		}
		assertInvariants(t, world)
	})

	t.Run("13_delayed_fraud_verdict_compensates", func(t *testing.T) {
		world := newWorld(t, 10, 0, map[string]int64{"A": 10})
		if _, err := world.Pay("A", "fraud-pay", "fraud-op", atoms(7)); err != nil {
			t.Fatal(err)
		}
		if err := world.ScheduleFraudVerdict("verdict-1", "fraud-op", true, 10); err != nil {
			t.Fatal(err)
		}
		world.AdvanceLogicalTicks(9)
		if world.Balance(failuresim.UserAccount).Cmp(atoms(3)) != 0 {
			t.Fatal("fraud compensation ran before its logical due tick")
		}
		if failures := world.AdvanceLogicalTicks(1); len(failures) != 0 {
			t.Fatalf("late verdict: %v", failures)
		}
		if world.Balance(failuresim.UserAccount).Cmp(atoms(10)) != 0 || world.EffectCount("fraud-reversal:verdict-1") != 1 {
			t.Fatal("late fraud verdict did not create one compensating entry")
		}
		if err := world.ScheduleFraudVerdict("verdict-1", "fraud-op", true, 0); err != nil {
			t.Fatal(err)
		}
		world.AdvanceLogicalTicks(100)
		if world.EffectCount("fraud-reversal:verdict-1") != 1 {
			t.Fatal("duplicate fraud verdict duplicated compensation")
		}
		assertInvariants(t, world)
	})

	t.Run("14_external_success_then_timeout", func(t *testing.T) {
		processor := failuresim.NewExternalProcessor()
		processor.SucceedThenTimeout("rail-op")
		first, err := processor.Charge("rail-op", atoms(11))
		if !errors.Is(err, failuresim.ErrExternalTimeout) || !first.Succeeded {
			t.Fatalf("first rail charge: result=%+v err=%v", first, err)
		}
		second, err := processor.Charge("rail-op", atoms(11))
		if err != nil || !second.Duplicate || second.Proof != first.Proof {
			t.Fatalf("rail inquiry/retry: result=%+v err=%v", second, err)
		}
		if processor.EffectCount("rail-op") != 1 {
			t.Fatal("external timeout caused a second charge")
		}
	})
}

func key(prefix string, value int) string {
	return fmt.Sprintf("%s-%03d", prefix, value)
}
