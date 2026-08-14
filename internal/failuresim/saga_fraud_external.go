package failuresim

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/example/payment-platform/internal/ledger"
)

func (w *World) StartSaga(sagaID, region, operationID string, amount ledger.Amount) (SagaSnapshot, error) {
	if sagaID == "" || operationID == "" || amount.Sign() <= 0 {
		return SagaSnapshot{}, ledger.ErrInvalidPosting
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if existing := w.sagas[sagaID]; existing != nil {
		snapshot := existing.snapshot
		if snapshot.Region != region || snapshot.OperationID != operationID || snapshot.Amount.Cmp(amount) != 0 {
			return SagaSnapshot{}, ErrEffectConflict
		}
		return snapshot, nil
	}
	snapshot := SagaSnapshot{SagaID: sagaID, Region: region, OperationID: operationID, Amount: amount}
	w.sagas[sagaID] = &sagaState{snapshot: snapshot}
	return snapshot, nil
}

// AdvanceSaga executes at most one durable state transition. Step zero posts
// the payment through the normal idempotent API. A crash between that commit
// and saving NextStep intentionally leaves step zero to be retried.
func (w *World) AdvanceSaga(sagaID string) (SagaSnapshot, error) {
	w.mu.Lock()
	if !w.coordinatorRunning {
		w.mu.Unlock()
		return SagaSnapshot{}, ErrCoordinatorDown
	}
	saga := w.sagas[sagaID]
	if saga == nil {
		w.mu.Unlock()
		return SagaSnapshot{}, ErrEffectConflict
	}
	snapshot := saga.snapshot
	w.mu.Unlock()

	switch snapshot.NextStep {
	case 0:
		receipt, err := w.Pay(snapshot.Region, "saga:"+sagaID+":payment", snapshot.OperationID, snapshot.Amount)
		if err != nil && !committedDespiteResponseError(err) {
			return snapshot, err
		}
		w.mu.Lock()
		saga = w.sagas[sagaID]
		if consumeCounter(w.coordinatorCrashAfter, sagaID) {
			w.coordinatorRunning = false
			w.mu.Unlock()
			return snapshot, ErrCoordinatorCrash
		}
		saga.snapshot.PaymentReceipt = receipt
		saga.snapshot.NextStep = 1
		snapshot = saga.snapshot
		w.mu.Unlock()
		return snapshot, nil
	case 1:
		// This represents a remote follow-up whose durable parent is the
		// payment outbox. Re-execution only advances the monotonic step.
		w.mu.Lock()
		saga = w.sagas[sagaID]
		saga.snapshot.NextStep = 2
		saga.snapshot.Completed = true
		snapshot = saga.snapshot
		w.mu.Unlock()
		return snapshot, nil
	default:
		return snapshot, nil
	}
}

func (w *World) CrashCoordinatorAfterEffect(sagaID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coordinatorCrashAfter[sagaID]++
}

func (w *World) CrashCoordinator() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coordinatorRunning = false
}

func (w *World) RestartCoordinator() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coordinatorRunning = true
}

func (w *World) Saga(sagaID string) (SagaSnapshot, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	saga, ok := w.sagas[sagaID]
	if !ok {
		return SagaSnapshot{}, false
	}
	return saga.snapshot, true
}

func (w *World) ScheduleFraudVerdict(eventID, paymentID string, fraudulent bool, delayTicks uint64) error {
	if eventID == "" || paymentID == "" {
		return ledger.ErrInvalidPosting
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.payments[paymentID]; !ok {
		return ErrPaymentNotFound
	}
	if existing := w.fraudVerdicts[eventID]; existing != nil {
		if existing.snapshot.PaymentID != paymentID || existing.snapshot.Fraudulent != fraudulent {
			return ErrEffectConflict
		}
		return nil
	}
	w.fraudVerdicts[eventID] = &fraudVerdictState{snapshot: FraudVerdictSnapshot{
		EventID: eventID, PaymentID: paymentID, Fraudulent: fraudulent, DueTick: w.logicalTick + delayTicks,
	}}
	return nil
}

// AdvanceLogicalTicks drives delayed events using a monotonic simulation tick.
// Regional wall-clock offsets never participate in this ordering.
func (w *World) AdvanceLogicalTicks(ticks uint64) []error {
	w.mu.Lock()
	w.logicalTick += ticks
	var due []string
	for eventID, verdict := range w.fraudVerdicts {
		if !verdict.snapshot.Processed && verdict.snapshot.DueTick <= w.logicalTick {
			due = append(due, eventID)
		}
	}
	sortStrings(due)
	var failures []error
	for _, eventID := range due {
		verdict := w.fraudVerdicts[eventID]
		if !verdict.snapshot.Fraudulent {
			verdict.snapshot.Processed = true
			continue
		}
		if !w.hasQuorumLocked() {
			failures = append(failures, ErrNoQuorum)
			continue
		}
		payment := w.payments[verdict.snapshot.PaymentID]
		if payment == nil {
			failures = append(failures, ErrPaymentNotFound)
			continue
		}
		released, _ := amountSum(payment.refunded, payment.reversed, payment.chargedBack)
		remaining, err := payment.captured.Sub(released)
		if err != nil || remaining.Sign() < 0 {
			failures = append(failures, ErrRefundExceeded)
			continue
		}
		if remaining.IsZero() {
			verdict.snapshot.Processed = true
			continue
		}
		region := w.regions[payment.region]
		newRights, err := region.rights.Add(remaining)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		newAuthority, err := w.authorityTotal.Add(remaining)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		fingerprint := requestFingerprint("LATE_FRAUD_REVERSAL", eventID, payment.operationID, remaining.String())
		receipt, err := w.postLocked("fraud-reversal:"+eventID, "LATE_FRAUD_REVERSAL", fingerprint, []JournalLine{
			{Account: MerchantAccount, Asset: w.asset, Side: ledger.Debit, Amount: remaining},
			{Account: UserAccount, Asset: w.asset, Side: ledger.Credit, Amount: remaining},
			{Account: AuthorityConsumedAccount, Asset: w.authorityAsset, Side: ledger.Debit, Amount: remaining},
			{Account: RegionalAuthorityAccount(payment.region), Asset: w.authorityAsset, Side: ledger.Credit, Amount: remaining},
		})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !receipt.Duplicate {
			region.rights = newRights
			w.authorityTotal = newAuthority
			payment.chargedBack, _ = payment.chargedBack.Add(remaining)
			payment.updateState()
			w.addOutboxLocked(receipt, "LATE_FRAUD_REVERSAL", payment.region, payment.region, []byte(eventID))
		}
		verdict.snapshot.Processed = true
	}
	w.mu.Unlock()
	return failures
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func (w *World) FraudVerdict(eventID string) (FraudVerdictSnapshot, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	verdict, ok := w.fraudVerdicts[eventID]
	if !ok {
		return FraudVerdictSnapshot{}, false
	}
	return verdict.snapshot, true
}

// ExternalProcessor models a processor's durable operation-id deduplication.
// SucceedThenTimeout commits at the processor and loses only its response.
type ExternalProcessor struct {
	mu sync.Mutex

	results             map[string]ExternalResult
	timeoutAfterSuccess map[string]int
}

func NewExternalProcessor() *ExternalProcessor {
	return &ExternalProcessor{
		results: make(map[string]ExternalResult), timeoutAfterSuccess: make(map[string]int),
	}
}

func (p *ExternalProcessor) SucceedThenTimeout(operationID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timeoutAfterSuccess[operationID]++
}

func (p *ExternalProcessor) Charge(operationID string, amount ledger.Amount) (ExternalResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if operationID == "" || amount.Sign() <= 0 {
		return ExternalResult{}, ledger.ErrInvalidPosting
	}
	if result, ok := p.results[operationID]; ok {
		if result.Amount.Cmp(amount) != 0 {
			return ExternalResult{}, ErrEffectConflict
		}
		result.Duplicate = true
		return result, nil
	}
	proof := sha256.Sum256([]byte(fmt.Sprintf("external-proof/v1\x00%s\x00%s", operationID, amount.String())))
	result := ExternalResult{OperationID: operationID, Amount: amount, Succeeded: true, Proof: proof}
	p.results[operationID] = result
	if consumeCounter(p.timeoutAfterSuccess, operationID) {
		return result, ErrExternalTimeout
	}
	return result, nil
}

func (p *ExternalProcessor) EffectCount(operationID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.results[operationID]; ok {
		return 1
	}
	return 0
}

func (p *ExternalProcessor) Result(operationID string) (ExternalResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.results[operationID]
	return result, ok
}

func IsCommittedExternalTimeout(err error) bool { return errors.Is(err, ErrExternalTimeout) }
