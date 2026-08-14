package chaos_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/example/payment-platform/internal/failuresim"
)

func TestAConcurrentWithdrawalsCannotOverspend(t *testing.T) {
	world := newWorld(t, 100, 0, map[string]int64{"A": 100, "B": 0, "C": 0})
	var confirmed atomic.Int64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 100; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := world.Pay("A", fmt.Sprintf("withdraw-key-%03d", index), fmt.Sprintf("withdraw-%03d", index), atoms(2))
			switch {
			case err == nil:
				confirmed.Add(1)
			case errors.Is(err, failuresim.ErrInsufficientFunds), errors.Is(err, failuresim.ErrInsufficientRights):
			default:
				t.Errorf("unexpected withdrawal error: %v", err)
			}
		}()
	}
	close(start)
	workers.Wait()

	if got := confirmed.Load(); got != 50 {
		t.Fatalf("confirmed withdrawals = %d, want exactly 50", got)
	}
	if world.GrossCaptured().Cmp(atoms(100)) != 0 {
		t.Fatalf("gross capture = %s, want 100", world.GrossCaptured().String())
	}
	assertInvariants(t, world)
}

func TestBPartitionedRegionsCannotExceedEscrow(t *testing.T) {
	world := newWorld(t, 100, 0, map[string]int64{"A": 60, "B": 40, "C": 0})
	world.Partition("A", "B")

	var confirmedA, confirmedB atomic.Int64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 200; index++ {
		index := index
		region := "A"
		counter := &confirmedA
		if index%2 == 1 {
			region = "B"
			counter = &confirmedB
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := world.Pay(region, fmt.Sprintf("partition-key-%03d", index), fmt.Sprintf("partition-pay-%03d", index), atoms(1))
			if err == nil {
				counter.Add(1)
				return
			}
			if !errors.Is(err, failuresim.ErrInsufficientRights) && !errors.Is(err, failuresim.ErrInsufficientFunds) {
				t.Errorf("unexpected payment error: %v", err)
			}
		}()
	}
	close(start)
	workers.Wait()

	if confirmedA.Load() != 60 || confirmedB.Load() != 40 {
		t.Fatalf("confirmed A/B = %d/%d, want 60/40", confirmedA.Load(), confirmedB.Load())
	}
	if total := confirmedA.Load() + confirmedB.Load(); total > 100 {
		t.Fatalf("confirmed spend exceeded escrow: %d", total)
	}
	assertInvariants(t, world)
}

func TestCLostResponseRetryInAnotherRegionIsOneEffect(t *testing.T) {
	world := newWorld(t, 100, 0, map[string]int64{"A": 60, "B": 40, "C": 0})
	world.LoseResponse("shared-key")
	first, err := world.Pay("A", "shared-key", "economic-payment", atoms(25))
	if !errors.Is(err, failuresim.ErrResponseLost) {
		t.Fatalf("first payment: got %v, want lost response", err)
	}
	second, err := world.Pay("B", "shared-key", "economic-payment", atoms(25))
	if err != nil {
		t.Fatalf("cross-region retry: %v", err)
	}
	if !second.Duplicate || first.TransactionID != second.TransactionID || first.CommitSequence != second.CommitSequence {
		t.Fatalf("retry did not return original durable receipt: first=%+v second=%+v", first, second)
	}
	if count := world.EffectCount("payment:economic-payment"); count != 1 {
		t.Fatalf("economic effect count = %d, want 1", count)
	}
	if world.Rights("A").Cmp(atoms(35)) != 0 || world.Rights("B").Cmp(atoms(40)) != 0 {
		t.Fatal("retry consumed rights in the second region")
	}
	assertInvariants(t, world)
}

func TestDRightsTransferLostACKAndCertificateRetry(t *testing.T) {
	world := newWorld(t, 100, 0, map[string]int64{"A": 60, "B": 40, "C": 0})
	fence, err := world.Fence("A")
	if err != nil {
		t.Fatal(err)
	}
	certificate, duplicate, err := world.InitiateTransfer(fence, "rights-1", "B", atoms(20))
	if err != nil || duplicate {
		t.Fatalf("initiate transfer: duplicate=%v err=%v", duplicate, err)
	}
	first, duplicate, err := world.ConsumeTransfer(certificate)
	if err != nil || duplicate {
		t.Fatalf("consume certificate: duplicate=%v err=%v", duplicate, err)
	}
	second, duplicate, err := world.ConsumeTransfer(certificate)
	if err != nil || !duplicate {
		t.Fatalf("retry certificate: duplicate=%v err=%v", duplicate, err)
	}
	if first.TransactionID != second.TransactionID || world.EffectCount("rights-transfer-in:rights-1") != 1 {
		t.Fatal("certificate retry created a second destination credit")
	}
	if world.Rights("A").Cmp(atoms(40)) != 0 || world.Rights("B").Cmp(atoms(60)) != 0 {
		t.Fatalf("rights after retry: A=%s B=%s", world.Rights("A").String(), world.Rights("B").String())
	}
	transfer, _ := world.Transfer("rights-1")
	if transfer.SourceAcknowledged {
		t.Fatal("direct consume unexpectedly manufactured a source ACK")
	}
	assertInvariants(t, world)
}

func TestEConcurrentRefundsCannotOverRefund(t *testing.T) {
	world := newWorld(t, 100, 0, map[string]int64{"A": 100, "B": 0, "C": 0})
	if _, err := world.Pay("A", "capture-key", "capture-100", atoms(100)); err != nil {
		t.Fatal(err)
	}
	var confirmed atomic.Int64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < 100; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := world.Refund("A", fmt.Sprintf("refund-key-%03d", index), fmt.Sprintf("refund-%03d", index), "capture-100", atoms(2))
			if err == nil {
				confirmed.Add(1)
				return
			}
			if !errors.Is(err, failuresim.ErrRefundExceeded) {
				t.Errorf("unexpected refund error: %v", err)
			}
		}()
	}
	close(start)
	workers.Wait()

	if got := confirmed.Load(); got != 50 {
		t.Fatalf("confirmed refunds = %d, want 50", got)
	}
	if total := world.RefundTotal("capture-100"); total.Cmp(atoms(100)) != 0 {
		t.Fatalf("refund total = %s, want 100", total.String())
	}
	assertInvariants(t, world)
}

func TestConcurrentDuplicateEconomicEffectAcrossDifferentKeys(t *testing.T) {
	world := newWorld(t, 10, 0, map[string]int64{"A": 10, "B": 0})
	start := make(chan struct{})
	receipts := make(chan failuresim.Receipt, 64)
	errorsSeen := make(chan error, 64)
	var workers sync.WaitGroup
	for index := 0; index < 64; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			receipt, err := world.Pay("A", fmt.Sprintf("independent-key-%02d", index), "same-economic-operation", atoms(10))
			if err != nil {
				errorsSeen <- err
				return
			}
			receipts <- receipt
		}()
	}
	close(start)
	workers.Wait()
	close(receipts)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("duplicate economic request returned error: %v", err)
	}
	var transactionID string
	count := 0
	for receipt := range receipts {
		count++
		if transactionID == "" {
			transactionID = receipt.TransactionID
		}
		if receipt.TransactionID != transactionID {
			t.Fatalf("different durable receipts: %s and %s", transactionID, receipt.TransactionID)
		}
	}
	if count != 64 || world.EffectCount("payment:same-economic-operation") != 1 {
		t.Fatalf("responses=%d effect_count=%d", count, world.EffectCount("payment:same-economic-operation"))
	}
	assertInvariants(t, world)
}

func TestExplicitCreditIsTheOnlyPermittedOverdraft(t *testing.T) {
	world := newWorld(t, 100, 20, map[string]int64{"A": 120})
	if _, err := world.Pay("A", "credit-key", "credit-payment", atoms(120)); err != nil {
		t.Fatalf("payment within explicit credit: %v", err)
	}
	if balance := world.Balance(failuresim.UserAccount); balance.Cmp(atoms(-20)) != 0 {
		t.Fatalf("balance = %s, want -20", balance.String())
	}
	if _, err := world.Pay("A", "over-credit-key", "over-credit-payment", atoms(1)); !errors.Is(err, failuresim.ErrInsufficientFunds) && !errors.Is(err, failuresim.ErrInsufficientRights) {
		t.Fatalf("payment beyond explicit credit: %v", err)
	}
	if world.EffectCount("payment:over-credit-payment") != 0 {
		t.Fatal("payment beyond credit committed")
	}
	assertInvariants(t, world)
}

func TestEveryCombinationOfThreeDCFailuresRetainsRF7Quorum(t *testing.T) {
	dcs := []string{"dc01", "dc02", "dc03", "dc04", "dc05", "dc06", "dc07", "dc08", "dc09", "dc10", "dc11", "dc12"}
	combinations := 0
	for first := 0; first < len(dcs); first++ {
		for second := first + 1; second < len(dcs); second++ {
			for third := second + 1; third < len(dcs); third++ {
				world := newWorld(t, 1, 0, map[string]int64{"A": 1})
				for _, dc := range []string{dcs[first], dcs[second], dcs[third]} {
					if err := world.CrashDC(dc); err != nil {
						t.Fatalf("combination %s/%s/%s: %v", dcs[first], dcs[second], dcs[third], err)
					}
				}
				operation := fmt.Sprintf("three-failures-%02d-%02d-%02d", first, second, third)
				if _, err := world.Pay("A", operation+"-key", operation, atoms(1)); err != nil {
					t.Fatalf("combination %s/%s/%s lost Q4: %v", dcs[first], dcs[second], dcs[third], err)
				}
				assertInvariants(t, world)
				combinations++
			}
		}
	}
	if combinations != 220 {
		t.Fatalf("tested %d combinations, want C(12,3)=220", combinations)
	}
}
