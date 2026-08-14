package failuresim

import (
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
)

func (w *World) Pay(region, idempotencyKey, operationID string, amount ledger.Amount) (Receipt, error) {
	fence, err := w.Fence(region)
	if err != nil {
		return Receipt{}, err
	}
	return w.PayWithFence(fence, idempotencyKey, operationID, amount)
}

func (w *World) PayWithFence(fence Fence, idempotencyKey, operationID string, amount ledger.Amount) (Receipt, error) {
	fingerprint := requestFingerprint("PAYMENT", operationID, amount.String())
	effectID := "payment:" + operationID

	w.mu.Lock()
	region, err := w.requireWriterLocked(fence)
	if err != nil {
		w.mu.Unlock()
		return Receipt{}, err
	}
	if idempotencyKey == "" || operationID == "" || amount.Sign() <= 0 {
		w.mu.Unlock()
		return Receipt{}, ledger.ErrInvalidPosting
	}
	if record, ok := w.idempotency[idempotencyKey]; ok {
		if record.requestHash != fingerprint {
			w.mu.Unlock()
			return Receipt{}, ErrIdempotencyConflict
		}
		receipt := record.receipt
		receipt.Duplicate = true
		lost := consumeCounter(w.loseResponses, idempotencyKey)
		w.mu.Unlock()
		if lost {
			return receipt, ErrResponseLost
		}
		return receipt, nil
	}
	if receipt, found, replayErr := w.replayEffectLocked(effectID, fingerprint, idempotencyKey); found || replayErr != nil {
		w.mu.Unlock()
		return receipt, replayErr
	}
	if consumeCounter(w.crashBeforeCommit, idempotencyKey) {
		region.running = false
		w.mu.Unlock()
		w.network.Crash(fence.Region)
		return Receipt{}, ErrCrashBeforeCommit
	}

	available, addErr := w.balances[UserAccount].Add(w.creditLimit)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	if available.Cmp(amount) < 0 {
		w.mu.Unlock()
		return Receipt{}, ErrInsufficientFunds
	}
	if region.rights.Cmp(amount) < 0 {
		w.mu.Unlock()
		return Receipt{}, ErrInsufficientRights
	}
	newRights, subErr := region.rights.Sub(amount)
	if subErr != nil {
		w.mu.Unlock()
		return Receipt{}, subErr
	}
	newAuthority, subErr := w.authorityTotal.Sub(amount)
	if subErr != nil || newAuthority.Sign() < 0 {
		w.mu.Unlock()
		return Receipt{}, ErrInsufficientRights
	}

	receipt, postErr := w.postLocked(effectID, "PAYMENT_CAPTURE", fingerprint, []JournalLine{
		{Account: UserAccount, Asset: w.asset, Side: ledger.Debit, Amount: amount},
		{Account: MerchantAccount, Asset: w.asset, Side: ledger.Credit, Amount: amount},
		{Account: RegionalAuthorityAccount(fence.Region), Asset: w.authorityAsset, Side: ledger.Debit, Amount: amount},
		{Account: AuthorityConsumedAccount, Asset: w.authorityAsset, Side: ledger.Credit, Amount: amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return Receipt{}, postErr
	}
	if !receipt.Duplicate {
		region.rights = newRights
		w.authorityTotal = newAuthority
		payment := &paymentState{
			operationID: operationID, region: fence.Region, authorized: amount,
			captured: amount, state: PaymentCaptured, receipt: receipt,
		}
		w.payments[operationID] = payment
		w.addOutboxLocked(receipt, "PAYMENT_CAPTURED", fence.Region, fence.Region, []byte(effectID))
	}
	receipt.IdempotencyKey = idempotencyKey
	w.idempotency[idempotencyKey] = idempotencyRecord{requestHash: fingerprint, receipt: receipt}
	crashAfter := consumeCounter(w.crashAfterCommit, idempotencyKey)
	lost := consumeCounter(w.loseResponses, idempotencyKey)
	if crashAfter {
		region.running = false
	}
	w.mu.Unlock()

	if crashAfter {
		w.network.Crash(fence.Region)
		return receipt, ErrCrashAfterCommit
	}
	if lost {
		return receipt, ErrResponseLost
	}
	return receipt, nil
}

func consumeCounter(values map[string]int, key string) bool {
	if values[key] <= 0 {
		return false
	}
	values[key]--
	return true
}

func (w *World) Deposit(region, idempotencyKey, operationID string, amount ledger.Amount) (Receipt, error) {
	fence, err := w.Fence(region)
	if err != nil {
		return Receipt{}, err
	}
	fingerprint := requestFingerprint("DEPOSIT", operationID, amount.String())
	effectID := "deposit:" + operationID

	w.mu.Lock()
	state, err := w.requireWriterLocked(fence)
	if err != nil {
		w.mu.Unlock()
		return Receipt{}, err
	}
	if idempotencyKey == "" || operationID == "" || amount.Sign() <= 0 {
		w.mu.Unlock()
		return Receipt{}, ledger.ErrInvalidPosting
	}
	if existing, ok := w.idempotency[idempotencyKey]; ok {
		if existing.requestHash != fingerprint {
			w.mu.Unlock()
			return Receipt{}, ErrIdempotencyConflict
		}
		receipt := existing.receipt
		receipt.Duplicate = true
		w.mu.Unlock()
		return receipt, nil
	}
	if receipt, found, replayErr := w.replayEffectLocked(effectID, fingerprint, idempotencyKey); found || replayErr != nil {
		w.mu.Unlock()
		return receipt, replayErr
	}
	newRights, addErr := state.rights.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	newAuthority, addErr := w.authorityTotal.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	receipt, postErr := w.postLocked(effectID, "DEPOSIT", fingerprint, []JournalLine{
		{Account: FundingAccount, Asset: w.asset, Side: ledger.Debit, Amount: amount},
		{Account: UserAccount, Asset: w.asset, Side: ledger.Credit, Amount: amount},
		{Account: AuthorityIssuerAccount, Asset: w.authorityAsset, Side: ledger.Debit, Amount: amount},
		{Account: RegionalAuthorityAccount(region), Asset: w.authorityAsset, Side: ledger.Credit, Amount: amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return Receipt{}, postErr
	}
	if !receipt.Duplicate {
		state.rights = newRights
		w.authorityTotal = newAuthority
		w.addOutboxLocked(receipt, "DEPOSIT_CONFIRMED", region, region, []byte(effectID))
	}
	receipt.IdempotencyKey = idempotencyKey
	w.idempotency[idempotencyKey] = idempotencyRecord{requestHash: fingerprint, receipt: receipt}
	w.mu.Unlock()
	return receipt, nil
}

func (w *World) Refund(region, idempotencyKey, refundID, paymentID string, amount ledger.Amount) (Receipt, error) {
	return w.releaseCapture(region, idempotencyKey, refundID, paymentID, amount, "REFUND")
}

func (w *World) Reverse(region, idempotencyKey, reversalID, paymentID string, amount ledger.Amount) (Receipt, error) {
	return w.releaseCapture(region, idempotencyKey, reversalID, paymentID, amount, "REVERSAL")
}

func (w *World) Chargeback(region, idempotencyKey, chargebackID, paymentID string, amount ledger.Amount) (Receipt, error) {
	return w.releaseCapture(region, idempotencyKey, chargebackID, paymentID, amount, "CHARGEBACK")
}

func (w *World) releaseCapture(region, idempotencyKey, releaseID, paymentID string, amount ledger.Amount, kind string) (Receipt, error) {
	fence, err := w.Fence(region)
	if err != nil {
		return Receipt{}, err
	}
	fingerprint := requestFingerprint(kind, releaseID, paymentID, amount.String())
	effectID := kind + ":" + releaseID

	w.mu.Lock()
	regionState, err := w.requireWriterLocked(fence)
	if err != nil {
		w.mu.Unlock()
		return Receipt{}, err
	}
	if idempotencyKey == "" || releaseID == "" || paymentID == "" || amount.Sign() <= 0 {
		w.mu.Unlock()
		return Receipt{}, ledger.ErrInvalidPosting
	}
	if existing, ok := w.idempotency[idempotencyKey]; ok {
		if existing.requestHash != fingerprint {
			w.mu.Unlock()
			return Receipt{}, ErrIdempotencyConflict
		}
		receipt := existing.receipt
		receipt.Duplicate = true
		w.mu.Unlock()
		return receipt, nil
	}
	if receipt, found, replayErr := w.replayEffectLocked(effectID, fingerprint, idempotencyKey); found || replayErr != nil {
		w.mu.Unlock()
		return receipt, replayErr
	}
	payment := w.payments[paymentID]
	if payment == nil {
		w.mu.Unlock()
		return Receipt{}, ErrPaymentNotFound
	}
	released, addErr := amountSum(payment.refunded, payment.reversed, payment.chargedBack, amount)
	if addErr != nil || released.Cmp(payment.captured) > 0 {
		w.mu.Unlock()
		return Receipt{}, ErrRefundExceeded
	}
	newRights, addErr := regionState.rights.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	newAuthority, addErr := w.authorityTotal.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	receipt, postErr := w.postLocked(effectID, kind, fingerprint, []JournalLine{
		{Account: MerchantAccount, Asset: w.asset, Side: ledger.Debit, Amount: amount},
		{Account: UserAccount, Asset: w.asset, Side: ledger.Credit, Amount: amount},
		{Account: AuthorityConsumedAccount, Asset: w.authorityAsset, Side: ledger.Debit, Amount: amount},
		{Account: RegionalAuthorityAccount(region), Asset: w.authorityAsset, Side: ledger.Credit, Amount: amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return Receipt{}, postErr
	}
	if !receipt.Duplicate {
		regionState.rights = newRights
		w.authorityTotal = newAuthority
		switch kind {
		case "REFUND":
			payment.refunded, _ = payment.refunded.Add(amount)
			w.refunds[releaseID] = amount
		case "REVERSAL":
			payment.reversed, _ = payment.reversed.Add(amount)
		case "CHARGEBACK":
			payment.chargedBack, _ = payment.chargedBack.Add(amount)
		}
		payment.updateState()
		w.addOutboxLocked(receipt, kind+"_CONFIRMED", region, region, []byte(effectID))
	}
	receipt.IdempotencyKey = idempotencyKey
	w.idempotency[idempotencyKey] = idempotencyRecord{requestHash: fingerprint, receipt: receipt}
	w.mu.Unlock()
	return receipt, nil
}

func (p *paymentState) updateState() {
	released, _ := amountSum(p.refunded, p.reversed, p.chargedBack)
	switch {
	case p.chargedBack.Sign() > 0:
		p.state = PaymentDisputed
	case p.reversed.Sign() > 0 && released.Cmp(p.captured) == 0:
		p.state = PaymentReversed
	case p.refunded.Cmp(p.captured) == 0:
		p.state = PaymentRefunded
	case released.Sign() > 0:
		p.state = PaymentPartiallyRefunded
	default:
		p.state = PaymentCaptured
	}
}

func (w *World) GrantCashback(region, idempotencyKey, effectID, operationID string, amount, ruleMaximum ledger.Amount) (Receipt, error) {
	fence, err := w.Fence(region)
	if err != nil {
		return Receipt{}, err
	}
	fingerprint := requestFingerprint("CASHBACK", effectID, operationID, amount.String(), ruleMaximum.String())

	w.mu.Lock()
	state, err := w.requireWriterLocked(fence)
	if err != nil {
		w.mu.Unlock()
		return Receipt{}, err
	}
	if idempotencyKey == "" || effectID == "" || operationID == "" || amount.Sign() <= 0 || ruleMaximum.Sign() < 0 {
		w.mu.Unlock()
		return Receipt{}, ledger.ErrInvalidPosting
	}
	if existing, ok := w.idempotency[idempotencyKey]; ok {
		if existing.requestHash != fingerprint {
			w.mu.Unlock()
			return Receipt{}, ErrIdempotencyConflict
		}
		receipt := existing.receipt
		receipt.Duplicate = true
		w.mu.Unlock()
		return receipt, nil
	}
	if receipt, found, replayErr := w.replayEffectLocked("cashback:"+effectID, fingerprint, idempotencyKey); found || replayErr != nil {
		w.mu.Unlock()
		return receipt, replayErr
	}
	if rule, exists := w.cashbackRules[operationID]; exists && rule.Cmp(ruleMaximum) != 0 {
		w.mu.Unlock()
		return Receipt{}, ErrEffectConflict
	}
	paid, addErr := w.cashbackPaid[operationID].Add(amount)
	if addErr != nil || paid.Cmp(ruleMaximum) > 0 {
		w.mu.Unlock()
		return Receipt{}, ErrCashbackExceeded
	}
	newRights, addErr := state.rights.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	newAuthority, addErr := w.authorityTotal.Add(amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, addErr
	}
	receipt, postErr := w.postLocked("cashback:"+effectID, "CASHBACK", fingerprint, []JournalLine{
		{Account: CashbackExpenseAccount, Asset: w.asset, Side: ledger.Debit, Amount: amount},
		{Account: UserAccount, Asset: w.asset, Side: ledger.Credit, Amount: amount},
		{Account: AuthorityIssuerAccount, Asset: w.authorityAsset, Side: ledger.Debit, Amount: amount},
		{Account: RegionalAuthorityAccount(region), Asset: w.authorityAsset, Side: ledger.Credit, Amount: amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return Receipt{}, postErr
	}
	if !receipt.Duplicate {
		state.rights = newRights
		w.authorityTotal = newAuthority
		w.cashbackRules[operationID] = ruleMaximum
		w.cashbackPaid[operationID] = paid
		w.addOutboxLocked(receipt, "CASHBACK_GRANTED", region, region, []byte(effectID))
	}
	receipt.IdempotencyKey = idempotencyKey
	w.idempotency[idempotencyKey] = idempotencyRecord{requestHash: fingerprint, receipt: receipt}
	w.mu.Unlock()
	return receipt, nil
}

func (w *World) RefundTotal(paymentID string) ledger.Amount {
	w.mu.Lock()
	defer w.mu.Unlock()
	if payment := w.payments[paymentID]; payment != nil {
		return payment.refunded
	}
	return ledger.Amount{}
}

func (w *World) IdempotencyReceipt(key string) (Receipt, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	record, ok := w.idempotency[key]
	return record.receipt, ok
}

func (w *World) addOutboxLocked(receipt Receipt, kind, source, destination string, payload []byte) *OutboxRecord {
	messageID := "event:" + receipt.TransactionID + ":" + kind
	record := &OutboxRecord{
		MessageID: messageID, Kind: kind, SourceRegion: source, DestinationRegion: destination,
		ParentTransactionID: receipt.TransactionID, Payload: append([]byte(nil), payload...),
	}
	w.outbox[messageID] = record
	return record
}

func (w *World) replayEffectLocked(effectID string, fingerprint [32]byte, idempotencyKey string) (Receipt, bool, error) {
	effect, ok := w.effects[effectID]
	if !ok {
		return Receipt{}, false, nil
	}
	if effect.fingerprint != fingerprint {
		return Receipt{}, true, ErrEffectConflict
	}
	receipt := effect.receipt
	receipt.IdempotencyKey = idempotencyKey
	receipt.Duplicate = true
	w.idempotency[idempotencyKey] = idempotencyRecord{requestHash: fingerprint, receipt: receipt}
	return receipt, true, nil
}

func (w *World) OutboxRecords() []OutboxRecord {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]OutboxRecord, 0, len(w.outbox))
	for _, record := range w.outbox {
		copy := *record
		copy.Payload = append([]byte(nil), record.Payload...)
		result = append(result, copy)
	}
	return result
}

func (w *World) InboxRecord(messageID string) (InboxRecord, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	record, ok := w.inbox[messageID]
	if !ok {
		return InboxRecord{}, false
	}
	return *record, true
}

func (w *World) CheckOperationalError(err error) bool { return isExpectedOperationalError(err) }

func committedDespiteResponseError(err error) bool {
	return errors.Is(err, ErrResponseLost) || errors.Is(err, ErrCrashAfterCommit)
}

func (w *World) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return fmt.Sprintf("asset=%s seq=%d balance=%s authority=%s", w.asset, w.sequence,
		w.balances[UserAccount].String(), w.authorityTotal.String())
}
