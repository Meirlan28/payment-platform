package failuresim

import (
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
)

// AssertAllFinancialInvariants independently folds immutable facts and checks
// every derived view. It never repairs state and is safe to call after every
// simulated transition, including while messages are in transit.
func (w *World) AssertAllFinancialInvariants() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	folded := make(map[string]ledger.Amount)
	seenEffects := make(map[string]struct{}, len(w.journal))
	transactions := make(map[string]JournalTransaction, len(w.journal))
	previousHash := [32]byte{}
	for index, transaction := range w.journal {
		wantSequence := uint64(index + 1)
		if transaction.Sequence != wantSequence {
			return fmt.Errorf("sequence gap: got %d want %d", transaction.Sequence, wantSequence)
		}
		if transaction.PreviousHash != previousHash || transaction.Hash != hashTransaction(transaction) {
			return fmt.Errorf("journal hash-chain mismatch at sequence %d", transaction.Sequence)
		}
		if _, duplicate := seenEffects[transaction.EffectID]; duplicate {
			return fmt.Errorf("economic effect %q appears more than once", transaction.EffectID)
		}
		seenEffects[transaction.EffectID] = struct{}{}
		if _, duplicate := transactions[transaction.ID]; duplicate {
			return fmt.Errorf("duplicate transaction id %s", transaction.ID)
		}
		transactions[transaction.ID] = transaction

		type totals struct{ debit, credit ledger.Amount }
		perAsset := make(map[string]totals)
		for _, line := range transaction.Lines {
			if line.Amount.Sign() <= 0 {
				return fmt.Errorf("transaction %s contains non-positive amount", transaction.ID)
			}
			total := perAsset[line.Asset]
			var err error
			switch line.Side {
			case ledger.Debit:
				total.debit, err = total.debit.Add(line.Amount)
				folded[line.Account], err = subtractChecked(folded[line.Account], line.Amount, err)
			case ledger.Credit:
				total.credit, err = total.credit.Add(line.Amount)
				folded[line.Account], err = addChecked(folded[line.Account], line.Amount, err)
			default:
				return fmt.Errorf("transaction %s contains invalid side", transaction.ID)
			}
			if err != nil {
				return fmt.Errorf("fold transaction %s: %w", transaction.ID, err)
			}
			perAsset[line.Asset] = total
		}
		for asset, total := range perAsset {
			if total.debit.Cmp(total.credit) != 0 {
				return fmt.Errorf("transaction %s is unbalanced for %s: debit=%s credit=%s",
					transaction.ID, asset, total.debit.String(), total.credit.String())
			}
		}
		previousHash = transaction.Hash
	}
	if previousHash != w.headHash || uint64(len(w.journal)) != w.sequence {
		return fmt.Errorf("journal head is inconsistent")
	}
	for account, expected := range folded {
		if actual := w.balances[account]; actual.Cmp(expected) != 0 {
			return fmt.Errorf("journal replay delta for %s: stored=%s folded=%s", account, actual.String(), expected.String())
		}
	}
	for account, actual := range w.balances {
		if actual.Cmp(folded[account]) != 0 {
			return fmt.Errorf("unexplained materialized balance for %s", account)
		}
	}

	for effectID, effect := range w.effects {
		if _, ok := seenEffects[effectID]; !ok {
			return fmt.Errorf("effect receipt %s has no journal transaction", effectID)
		}
		transaction, ok := transactions[effect.receipt.TransactionID]
		if !ok {
			return fmt.Errorf("effect receipt %s references missing transaction", effectID)
		}
		if transaction.EffectID != effectID || transaction.Sequence != effect.receipt.CommitSequence ||
			effect.receipt.EffectID != effectID || transaction.RequestHash != effect.fingerprint {
			return fmt.Errorf("effect receipt %s does not prove its journal commit", effectID)
		}
	}
	for key, idempotency := range w.idempotency {
		effect, ok := w.effects[idempotency.receipt.EffectID]
		if !ok || idempotency.requestHash != effect.fingerprint ||
			effect.receipt.TransactionID != idempotency.receipt.TransactionID ||
			effect.receipt.CommitSequence != idempotency.receipt.CommitSequence {
			return fmt.Errorf("committed success %s lacks durable effect receipt", key)
		}
	}

	available, err := w.balances[UserAccount].Add(w.creditLimit)
	if err != nil {
		return err
	}
	if available.Sign() < 0 {
		return fmt.Errorf("available balance %s is below explicit credit", available.String())
	}
	if available.Cmp(w.authorityTotal) != 0 {
		return fmt.Errorf("balance/authority residual: available=%s authority=%s", available.String(), w.authorityTotal.String())
	}

	escrowTotal := w.unallocated
	for name, region := range w.regions {
		if region.rights.Sign() < 0 {
			return fmt.Errorf("negative rights in region %s", name)
		}
		escrowTotal, err = escrowTotal.Add(region.rights)
		if err != nil {
			return err
		}
		if journalRights := w.balances[RegionalAuthorityAccount(name)]; journalRights.Cmp(region.rights) != 0 {
			return fmt.Errorf("rights journal mismatch in %s: state=%s journal=%s", name, region.rights.String(), journalRights.String())
		}
	}
	inTransit := ledger.Amount{}
	for transferID, transfer := range w.transfers {
		if !w.verifyCertificateLocked(transfer.certificate) {
			return fmt.Errorf("transfer %s has invalid commit proof", transferID)
		}
		if transfer.inTransit == transfer.consumed {
			return fmt.Errorf("transfer %s must be exclusively in-transit or consumed", transferID)
		}
		if transfer.inTransit {
			inTransit, err = inTransit.Add(transfer.certificate.Amount)
			if err != nil {
				return err
			}
		}
		if transfer.sourceAcknowledged && !transfer.consumed {
			return fmt.Errorf("transfer %s acknowledged before consumption", transferID)
		}
		if transfer.consumed {
			messageID := "transfer:" + transferID
			if _, ok := w.inbox[messageID]; !ok {
				return fmt.Errorf("consumed transfer %s lacks durable inbox proof", transferID)
			}
			if w.EffectCountLocked("rights-transfer-in:"+transferID) != 1 {
				return fmt.Errorf("transfer %s destination effect count is not one", transferID)
			}
		}
	}
	escrowTotal, err = escrowTotal.Add(inTransit)
	if err != nil {
		return err
	}
	if escrowTotal.Cmp(w.authorityTotal) != 0 {
		return fmt.Errorf("escrow conservation residual: unallocated+rights+transit=%s authority=%s",
			escrowTotal.String(), w.authorityTotal.String())
	}
	if journalTransit := w.balances[AuthorityTransitAccount]; journalTransit.Cmp(inTransit) != 0 {
		return fmt.Errorf("in-transit journal mismatch: state=%s journal=%s", inTransit.String(), journalTransit.String())
	}
	if journalUnallocated := w.balances[AuthorityUnallocatedAccount]; journalUnallocated.Cmp(w.unallocated) != 0 {
		return fmt.Errorf("unallocated authority journal mismatch")
	}

	for _, payment := range w.payments {
		if payment.captured.Cmp(payment.authorized) > 0 {
			return fmt.Errorf("payment %s captured above authorization", payment.operationID)
		}
		released, sumErr := amountSum(payment.refunded, payment.reversed, payment.chargedBack)
		if sumErr != nil || released.Cmp(payment.captured) > 0 {
			return fmt.Errorf("payment %s released above capture", payment.operationID)
		}
		if payment.receipt.TransactionID == "" {
			return fmt.Errorf("payment %s lacks durable receipt", payment.operationID)
		}
	}

	for operationID, paid := range w.cashbackPaid {
		maximum, ok := w.cashbackRules[operationID]
		if !ok || paid.Cmp(maximum) > 0 {
			return fmt.Errorf("cashback rule violation for %s: paid=%s maximum=%s", operationID, paid.String(), maximum.String())
		}
	}
	for messageID, outbox := range w.outbox {
		if outbox.MessageID != messageID {
			return fmt.Errorf("outbox key mismatch for %s", messageID)
		}
		if _, ok := transactions[outbox.ParentTransactionID]; !ok {
			return fmt.Errorf("outbox %s lacks parent transaction", messageID)
		}
	}
	for messageID, inbox := range w.inbox {
		if inbox.MessageID != messageID || inbox.EffectID == "" {
			return fmt.Errorf("invalid inbox receipt %s", messageID)
		}
		if _, ok := w.effects[inbox.EffectID]; !ok {
			return fmt.Errorf("inbox %s references missing economic effect", messageID)
		}
	}
	for sagaID, saga := range w.sagas {
		if saga.snapshot.NextStep < 0 || saga.snapshot.NextStep > 2 ||
			(saga.snapshot.Completed && saga.snapshot.NextStep != 2) {
			return fmt.Errorf("saga %s has invalid durable progress", sagaID)
		}
		if saga.snapshot.NextStep > 0 {
			if _, ok := w.effects["payment:"+saga.snapshot.OperationID]; !ok {
				return fmt.Errorf("saga %s advanced without payment effect", sagaID)
			}
		}
	}
	return nil
}

func addChecked(current, amount ledger.Amount, prior error) (ledger.Amount, error) {
	if prior != nil {
		return ledger.Amount{}, prior
	}
	return current.Add(amount)
}

func subtractChecked(current, amount ledger.Amount, prior error) (ledger.Amount, error) {
	if prior != nil {
		return ledger.Amount{}, prior
	}
	return current.Sub(amount)
}

func (w *World) EffectCountLocked(effectID string) int {
	count := 0
	for _, transaction := range w.journal {
		if transaction.EffectID == effectID {
			count++
		}
	}
	return count
}

// AssertAllFinancialInvariants is also available as a free function for
// scenario runners that keep models behind an interface.
func AssertAllFinancialInvariants(world *World) error {
	if world == nil {
		return ErrInvalidConfiguration
	}
	return world.AssertAllFinancialInvariants()
}
