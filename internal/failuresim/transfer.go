package failuresim

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/simulation"
)

const transferMessageKind = "RIGHTS_TRANSFER"

type pendingEnvelope struct {
	messageID, source, destination string
	payload                        []byte
}

func (w *World) InitiateTransfer(fence Fence, transferID, destination string, amount ledger.Amount) (TransferCertificate, bool, error) {
	fingerprint := requestFingerprint("RIGHTS_TRANSFER_OUT", transferID, fence.Region, destination, amount.String())

	w.mu.Lock()
	source, err := w.requireWriterLocked(fence)
	if err != nil {
		w.mu.Unlock()
		return TransferCertificate{}, false, err
	}
	if transferID == "" || destination == "" || fence.Region == destination || amount.Sign() <= 0 {
		w.mu.Unlock()
		return TransferCertificate{}, false, ErrTransferInvalid
	}
	if _, ok := w.regions[destination]; !ok {
		w.mu.Unlock()
		return TransferCertificate{}, false, ErrTransferInvalid
	}
	if existing := w.transfers[transferID]; existing != nil {
		candidate := existing.certificate
		if candidate.SourceRegion != fence.Region || candidate.DestinationRegion != destination || candidate.Amount.Cmp(amount) != 0 {
			w.mu.Unlock()
			return TransferCertificate{}, false, ErrTransferConflict
		}
		w.mu.Unlock()
		return candidate, true, nil
	}
	if source.rights.Cmp(amount) < 0 {
		w.mu.Unlock()
		return TransferCertificate{}, false, ErrInsufficientRights
	}
	newRights, subErr := source.rights.Sub(amount)
	if subErr != nil {
		w.mu.Unlock()
		return TransferCertificate{}, false, subErr
	}
	receipt, postErr := w.postLocked("rights-transfer-out:"+transferID, "RIGHTS_TRANSFER_OUT", fingerprint, []JournalLine{
		{Account: RegionalAuthorityAccount(fence.Region), Asset: w.authorityAsset, Side: ledger.Debit, Amount: amount},
		{Account: AuthorityTransitAccount, Asset: w.authorityAsset, Side: ledger.Credit, Amount: amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return TransferCertificate{}, false, postErr
	}
	certificate := TransferCertificate{
		TransferID: transferID, Asset: w.asset, SourceRegion: fence.Region,
		DestinationRegion: destination, Amount: amount, SourceEpoch: fence.Epoch,
		CommitSequence: receipt.CommitSequence,
	}
	certificate.CommitProof = w.certificateProof(certificate)
	payload, marshalErr := json.Marshal(certificate)
	if marshalErr != nil {
		w.mu.Unlock()
		return TransferCertificate{}, false, marshalErr
	}
	source.rights = newRights
	w.transfers[transferID] = &transferState{certificate: certificate, inTransit: true}
	outbox := w.addOutboxLocked(receipt, transferMessageKind, fence.Region, destination, payload)
	outbox.MessageID = "transfer:" + transferID
	delete(w.outbox, "event:"+receipt.TransactionID+":"+transferMessageKind)
	w.outbox[outbox.MessageID] = outbox
	w.mu.Unlock()
	return certificate, false, nil
}

func (w *World) ConsumeTransfer(certificate TransferCertificate) (Receipt, bool, error) {
	return w.consumeTransfer("transfer:"+certificate.TransferID, certificate)
}

func (w *World) consumeTransfer(messageID string, certificate TransferCertificate) (Receipt, bool, error) {
	w.mu.Lock()
	destination := w.regions[certificate.DestinationRegion]
	if destination == nil || !destination.running {
		w.mu.Unlock()
		return Receipt{}, false, ErrRegionDown
	}
	if !w.hasQuorumLocked() {
		w.mu.Unlock()
		return Receipt{}, false, ErrNoQuorum
	}
	if !w.verifyCertificateLocked(certificate) {
		w.mu.Unlock()
		return Receipt{}, false, ErrTransferInvalid
	}
	transfer := w.transfers[certificate.TransferID]
	if transfer == nil || !equalCertificate(transfer.certificate, certificate) {
		w.mu.Unlock()
		return Receipt{}, false, ErrTransferConflict
	}
	payload, _ := json.Marshal(certificate)
	hash := payloadHash(payload)
	if existing := w.inbox[messageID]; existing != nil {
		if existing.PayloadHash != hash {
			w.mu.Unlock()
			return Receipt{}, false, ErrTransferConflict
		}
		existing.DuplicateDeliveries++
		receipt := transfer.consumeReceipt
		receipt.Duplicate = true
		crash := consumeCounter(w.consumerCrash, messageID)
		if crash {
			destination.running = false
		}
		w.mu.Unlock()
		if crash {
			w.network.Crash(certificate.DestinationRegion)
			return receipt, true, ErrConsumerCrash
		}
		return receipt, true, nil
	}
	if transfer.consumed || !transfer.inTransit {
		w.mu.Unlock()
		return Receipt{}, false, ErrTransferConflict
	}
	newRights, addErr := destination.rights.Add(certificate.Amount)
	if addErr != nil {
		w.mu.Unlock()
		return Receipt{}, false, addErr
	}
	fingerprint := requestFingerprint("RIGHTS_TRANSFER_IN", certificate.TransferID, certificate.CommitProofString())
	receipt, postErr := w.postLocked("rights-transfer-in:"+certificate.TransferID, "RIGHTS_TRANSFER_IN", fingerprint, []JournalLine{
		{Account: AuthorityTransitAccount, Asset: w.authorityAsset, Side: ledger.Debit, Amount: certificate.Amount},
		{Account: RegionalAuthorityAccount(certificate.DestinationRegion), Asset: w.authorityAsset, Side: ledger.Credit, Amount: certificate.Amount},
	})
	if postErr != nil {
		w.mu.Unlock()
		return Receipt{}, false, postErr
	}
	destination.rights = newRights
	transfer.inTransit = false
	transfer.consumed = true
	transfer.consumeReceipt = receipt
	w.inbox[messageID] = &InboxRecord{MessageID: messageID, PayloadHash: hash, EffectID: receipt.EffectID}
	crash := consumeCounter(w.consumerCrash, messageID)
	if crash {
		destination.running = false
	}
	w.mu.Unlock()
	if crash {
		w.network.Crash(certificate.DestinationRegion)
		return receipt, false, ErrConsumerCrash
	}
	return receipt, false, nil
}

func (certificate TransferCertificate) CommitProofString() string {
	return fmt.Sprintf("%x", certificate.CommitProof[:])
}

func (w *World) CrashConsumerAfterApply(messageID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.consumerCrash[messageID]++
}

func (w *World) Transfer(transferID string) (TransferSnapshot, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	transfer, ok := w.transfers[transferID]
	if !ok {
		return TransferSnapshot{}, false
	}
	return TransferSnapshot{
		Certificate: transfer.certificate, InTransit: transfer.inTransit,
		Consumed: transfer.consumed, SourceAcknowledged: transfer.sourceAcknowledged,
		ConsumeReceipt: transfer.consumeReceipt,
	}, true
}

// DispatchOutbox retries every unacknowledged rights-transfer record. A
// successful Send means the broker accepted a copy, not that the consumer
// applied it. Consequently retries intentionally create at-least-once delivery.
func (w *World) DispatchOutbox() []error {
	w.mu.Lock()
	var records []pendingEnvelope
	for _, record := range w.outbox {
		if record.Kind != transferMessageKind || record.Acknowledged {
			continue
		}
		record.Attempts++
		records = append(records, pendingEnvelope{
			messageID: record.MessageID, source: record.SourceRegion,
			destination: record.DestinationRegion, payload: append([]byte(nil), record.Payload...),
		})
	}
	w.mu.Unlock()

	sort.Slice(records, func(i, j int) bool { return records[i].messageID < records[j].messageID })
	var failures []error
	for _, record := range records {
		err := w.network.Send(simulation.Envelope{
			MessageID: record.messageID, From: record.source, To: record.destination,
			Kind: simulation.Command, CorrelationID: record.messageID, Payload: record.payload,
		})
		if err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

// DeliverMessages executes one deterministic broker/consumer/ACK round.
func (w *World) DeliverMessages() []error {
	envelopes := w.network.Drain()
	var failures []error
	for _, envelope := range envelopes {
		switch envelope.Kind {
		case simulation.Command:
			var certificate TransferCertificate
			if err := json.Unmarshal(envelope.Payload, &certificate); err != nil {
				failures = append(failures, fmt.Errorf("decode %s: %w", envelope.MessageID, err))
				continue
			}
			_, _, err := w.consumeTransfer(envelope.MessageID, certificate)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			ackPayload := certificate.CommitProof[:]
			if err := w.network.Send(simulation.Envelope{
				MessageID: "ack:" + certificate.TransferID, CorrelationID: envelope.MessageID,
				From: certificate.DestinationRegion, To: certificate.SourceRegion,
				Kind: simulation.Ack, Payload: ackPayload,
			}); err != nil {
				failures = append(failures, err)
			}
		case simulation.Ack:
			if err := w.acceptTransferACK(envelope); err != nil {
				failures = append(failures, err)
			}
		default:
			failures = append(failures, fmt.Errorf("unexpected message kind %s", envelope.Kind))
		}
	}
	return failures
}

func (w *World) acceptTransferACK(envelope simulation.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	record := w.outbox[envelope.CorrelationID]
	if record == nil || record.Kind != transferMessageKind || !strings.HasPrefix(envelope.CorrelationID, "transfer:") {
		return ErrTransferInvalid
	}
	transferID := envelope.CorrelationID[len("transfer:"):]
	transfer := w.transfers[transferID]
	if transfer == nil || !transfer.consumed || !equalBytes(envelope.Payload, transfer.certificate.CommitProof[:]) {
		return ErrTransferInvalid
	}
	record.Acknowledged = true
	transfer.sourceAcknowledged = true
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (w *World) PumpUntilSettled(maxRounds int) error {
	for round := 0; round < maxRounds; round++ {
		w.DispatchOutbox()
		w.DeliverMessages()
		w.DeliverMessages()
		if w.allTransfersAcknowledged() {
			return nil
		}
	}
	return errors.New("failuresim: transfer backlog did not settle")
}

// Reconcile drains recoverable at-least-once transfer work and then performs
// an independent invariant audit. It never edits balances or journal history.
func (w *World) Reconcile(maxRounds int) error {
	if err := w.PumpUntilSettled(maxRounds); err != nil {
		return err
	}
	return w.AssertAllFinancialInvariants()
}

func (w *World) allTransfersAcknowledged() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, transfer := range w.transfers {
		if !transfer.sourceAcknowledged {
			return false
		}
	}
	return true
}
