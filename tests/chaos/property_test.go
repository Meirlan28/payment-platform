package chaos_test

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/failuresim"
	"github.com/example/payment-platform/internal/simulation"
)

type generatedPayment struct {
	key       string
	operation string
	amount    int64
}

func TestPropertyRandomSequencesPreserveInvariants(t *testing.T) {
	const (
		seeds = 24
		steps = 300
	)
	for seed := int64(1); seed <= seeds; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed_%02d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			world := newWorld(t, 100, 20, map[string]int64{"A": 50, "B": 40, "C": 30})
			processor := failuresim.NewExternalProcessor()
			var payments []generatedPayment
			regions := []string{"A", "B", "C"}

			for step := 0; step < steps; step++ {
				action := random.Intn(16)
				region := regions[random.Intn(len(regions))]
				amount := int64(random.Intn(8) + 1)
				suffix := fmt.Sprintf("s%02d-n%04d", seed, step)
				var actionErr error

				switch action {
				case 0: // deposit
					_, actionErr = world.Deposit(region, "deposit-key-"+suffix, "deposit-"+suffix, atoms(amount))
				case 1, 2, 3: // payment, weighted to build contention
					key := "pay-key-" + suffix
					operation := "pay-" + suffix
					if random.Intn(10) == 0 {
						world.LoseResponse(key)
					}
					_, actionErr = world.Pay(region, key, operation, atoms(amount))
					if actionErr == nil || errors.Is(actionErr, failuresim.ErrResponseLost) || errors.Is(actionErr, failuresim.ErrCrashAfterCommit) {
						payments = append(payments, generatedPayment{key: key, operation: operation, amount: amount})
					}
				case 4: // retry a committed request through another region
					if len(payments) > 0 {
						payment := payments[random.Intn(len(payments))]
						_, actionErr = world.Pay(region, payment.key, payment.operation, atoms(payment.amount))
					}
				case 5: // refund or chargeback; races with prior release totals semantically
					if len(payments) > 0 {
						payment := payments[random.Intn(len(payments))]
						if random.Intn(2) == 0 {
							_, actionErr = world.Refund(region, "refund-key-"+suffix, "refund-"+suffix, payment.operation, atoms(amount))
						} else {
							_, actionErr = world.Chargeback(region, "chargeback-key-"+suffix, "chargeback-"+suffix, payment.operation, atoms(amount))
						}
					}
				case 6: // independently partition or heal a continental link
					other := regions[(indexOf(regions, region)+1+random.Intn(2))%len(regions)]
					if random.Intn(2) == 0 {
						world.Partition(region, other)
					} else {
						world.Heal(region, other)
					}
				case 7: // transfer regional spending authority
					other := regions[(indexOf(regions, region)+1+random.Intn(2))%len(regions)]
					if fence, err := world.Fence(region); err == nil {
						_, _, actionErr = world.InitiateTransfer(fence, "transfer-"+suffix, other, atoms(amount))
					} else {
						actionErr = err
					}
				case 8: // at-least-once publisher/consumer under changing faults
					world.SetPacketLoss(uint8([]int{0, 10, 30}[random.Intn(3)]))
					world.SetReordering(random.Intn(2) == 0)
					world.SetDuplicateEvery(uint64(random.Intn(5)))
					_ = world.DispatchOutbox()
					_ = world.DeliverMessages()
					_ = world.DeliverMessages()
				case 9: // process crash/restart; committed maps survive both
					state, _ := world.Region(region)
					if state.Running {
						actionErr = world.CrashRegion(region)
					} else {
						actionErr = world.RestartRegion(region)
					}
				case 10: // cashback is bounded by an immutable per-operation rule
					if len(payments) > 0 {
						payment := payments[random.Intn(len(payments))]
						_, actionErr = world.GrantCashback(region, "cashback-key-"+suffix, "cashback-effect-"+suffix,
							payment.operation, atoms(1), atoms(3))
					}
				case 11: // delayed fraud uses logical ticks, not skewable clocks
					if len(payments) > 0 {
						payment := payments[random.Intn(len(payments))]
						actionErr = world.ScheduleFraudVerdict("fraud-"+suffix, payment.operation, random.Intn(2) == 0, uint64(random.Intn(8)))
					}
				case 12:
					_ = world.AdvanceLogicalTicks(uint64(random.Intn(4)))
				case 13: // external success may be ambiguous, operation ID remains unique
					op := "external-" + suffix
					if random.Intn(2) == 0 {
						processor.SucceedThenTimeout(op)
					}
					_, actionErr = processor.Charge(op, atoms(amount))
					if errors.Is(actionErr, failuresim.ErrExternalTimeout) {
						_, actionErr = processor.Charge(op, atoms(amount))
					}
					if processor.EffectCount(op) != 1 {
						t.Fatalf("seed=%d step=%d external effect cardinality", seed, step)
					}
				case 14: // conflicting reuse must be rejected, never overwritten
					if len(payments) > 0 {
						payment := payments[random.Intn(len(payments))]
						_, actionErr = world.Pay(region, payment.key, payment.operation+"-different", atoms(payment.amount+1))
					}
				case 15: // clock jumps have no effect on commit sequence
					skew := 15 * time.Minute
					if random.Intn(2) == 0 {
						skew = -skew
					}
					world.ClockSkew(region, skew)
				}

				if actionErr != nil && !expectedGeneratedError(actionErr) {
					t.Fatalf("seed=%d step=%d action=%d unexpected error: %v", seed, step, action, actionErr)
				}
				if err := world.AssertAllFinancialInvariants(); err != nil {
					t.Fatalf("seed=%d step=%d action=%d: %v\nworld: %s", seed, step, action, err, world)
				}
			}

			world.HealAll()
			world.SetPacketLoss(0)
			for _, region := range regions {
				state, _ := world.Region(region)
				if !state.Running {
					if err := world.RestartRegion(region); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := world.Reconcile(2_000); err != nil {
				t.Fatalf("seed=%d final reconciliation: %v", seed, err)
			}
			assertInvariants(t, world)
		})
	}
}

func indexOf(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}

func expectedGeneratedError(err error) bool {
	return errors.Is(err, failuresim.ErrInsufficientFunds) ||
		errors.Is(err, failuresim.ErrInsufficientRights) ||
		errors.Is(err, failuresim.ErrRegionDown) ||
		errors.Is(err, failuresim.ErrNoQuorum) ||
		errors.Is(err, failuresim.ErrStaleEpoch) ||
		errors.Is(err, failuresim.ErrRefundExceeded) ||
		errors.Is(err, failuresim.ErrIdempotencyConflict) ||
		errors.Is(err, failuresim.ErrEffectConflict) ||
		errors.Is(err, failuresim.ErrResponseLost) ||
		errors.Is(err, failuresim.ErrCrashBeforeCommit) ||
		errors.Is(err, failuresim.ErrCrashAfterCommit) ||
		errors.Is(err, failuresim.ErrExternalTimeout) ||
		errors.Is(err, failuresim.ErrCashbackExceeded) ||
		errors.Is(err, simulation.ErrPacketLost) ||
		errors.Is(err, simulation.ErrPartitioned) ||
		errors.Is(err, simulation.ErrNodeDown)
}
