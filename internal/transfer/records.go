package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
)

type storedTransfer struct {
	transferID         string
	requestHash        [32]byte
	payerBookID        string
	payeeBookID        string
	payerTransactionID string
	payeeTransactionID string
}

func (s storedTransfer) receipt() Receipt {
	return Receipt{
		TransferID:         s.transferID,
		PayerTransactionID: s.payerTransactionID,
		PayeeTransactionID: s.payeeTransactionID,
		PayerBookID:        s.payerBookID,
		PayeeBookID:        s.payeeBookID,
		CrossBook:          s.payerBookID != s.payeeBookID,
		Duplicate:          true,
	}
}

// loadTransfer resolves a previously executed transfer by its idempotency
// identity, together with the legs it wrote, so a replay can answer with the
// original result rather than performing a second transfer.
func loadTransfer(ctx context.Context, tx pgx.Tx, scope, key string) (storedTransfer, bool, error) {
	var result storedTransfer
	var hash []byte
	err := tx.QueryRow(ctx, `
SELECT transfer_id, request_hash, payer_book_id, payee_book_id
  FROM transfer_operations
 WHERE idempotency_scope=$1 AND idempotency_key=$2`, scope, key).Scan(
		&result.transferID, &hash, &result.payerBookID, &result.payeeBookID)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedTransfer{}, false, nil
	}
	if err != nil {
		return storedTransfer{}, false, err
	}
	if len(hash) != 32 {
		return storedTransfer{}, false, errors.New("transfer: stored request hash is corrupt")
	}
	copy(result.requestHash[:], hash)

	rows, err := tx.Query(ctx,
		`SELECT leg, ledger_transaction_id FROM transfer_effects WHERE transfer_id=$1`,
		result.transferID)
	if err != nil {
		return storedTransfer{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var leg, transactionID string
		if err := rows.Scan(&leg, &transactionID); err != nil {
			return storedTransfer{}, false, err
		}
		switch leg {
		case legSingle:
			result.payerTransactionID, result.payeeTransactionID = transactionID, transactionID
		case legPayer:
			result.payerTransactionID = transactionID
		case legPayee:
			result.payeeTransactionID = transactionID
		}
	}
	return result, true, rows.Err()
}

func insertTransfer(ctx context.Context, tx pgx.Tx, request Request,
	payer, payee account, region string, hash [32]byte) error {

	_, err := tx.Exec(ctx, `
INSERT INTO transfer_operations (
    transfer_id, idempotency_scope, idempotency_key, request_hash, asset_id,
    payer_account_id, payee_account_id, payer_book_id, payee_book_id,
    authority_region, amount_atoms
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::DECIMAL)`,
		request.TransferID, request.IdempotencyScope, request.IdempotencyKey, hash[:],
		request.AssetID, payer.accountID, payee.accountID, payer.bookID, payee.bookID,
		region, request.AmountAtoms.String())
	return err
}

// transferEvent is the fact downstream read models consume. It names both
// sides, because a transfer changes two balances and a consumer that saw only
// one would leave the other wrong.
type transferEvent struct {
	EventType        string `json:"event_type"`
	TransferID       string `json:"transfer_id"`
	IdempotencyScope string `json:"idempotency_scope"`
	IdempotencyKey   string `json:"idempotency_key"`
	AssetID          string `json:"asset_id"`
	AmountAtoms      string `json:"amount_atoms"`
	Region           string `json:"region"`
	PayerAccountID   string `json:"payer_account_id"`
	PayeeAccountID   string `json:"payee_account_id"`
	PayerBookID      string `json:"payer_book_id"`
	PayeeBookID      string `json:"payee_book_id"`
	CrossBook        bool   `json:"cross_book"`
	Memo             string `json:"memo"`
}

func (s *Service) publish(ctx context.Context, tx pgx.Tx, request Request,
	payer, payee account, posted []postedLeg) error {

	payload, err := json.Marshal(transferEvent{
		EventType: TransferEventType, TransferID: request.TransferID,
		IdempotencyScope: request.IdempotencyScope, IdempotencyKey: request.IdempotencyKey,
		AssetID: request.AssetID, AmountAtoms: request.AmountAtoms.String(),
		Region: s.config.Region, PayerAccountID: payer.accountID, PayeeAccountID: payee.accountID,
		PayerBookID: payer.bookID, PayeeBookID: payee.bookID,
		CrossBook: payer.bookID != payee.bookID, Memo: request.Memo,
	})
	if err != nil {
		return err
	}
	canonical, err := ledger.CanonicalJSON(payload)
	if err != nil {
		return err
	}
	headers, err := json.Marshal(map[string]string{"event_type": TransferEventType})
	if err != nil {
		return err
	}
	// Keyed by transfer rather than by account: the event concerns both
	// parties equally, and keying by one of them would order it against that
	// account's other events while leaving the peer's unordered.
	//
	// The parent transaction is the payer's leg, which is the one whose
	// posting the event ultimately reports.
	parent := posted[0].transactionID
	for _, leg := range posted {
		if leg.plan.leg == legPayer || leg.plan.leg == legSingle {
			parent = leg.transactionID
		}
	}
	_, err = tx.Exec(ctx, `
INSERT INTO outbox_messages (
    event_id, topic, message_key, payload, headers, aggregate_id,
    aggregate_version, parent_transaction_id
) VALUES ($1,$2,$3,$4,$5::JSONB,$6,$7,$8)`,
		request.TransferID+":settled", TransferEventTopic, []byte(request.TransferID),
		canonical, string(headers), request.TransferID, 1, parent)
	return err
}

// Found is a transfer read back after the fact.
type Found struct {
	TransferID         string
	AssetID            string
	PayerAccountID     string
	PayeeAccountID     string
	AmountAtoms        string
	State              string
	PayerBookID        string
	PayeeBookID        string
	PayerTransactionID string
	PayeeTransactionID string
}

// Lookup resolves a transfer by its own identifier or by its idempotency
// identity.
//
// Both routes exist because a caller whose Execute never returned may not know
// which of the two it can rely on: it certainly sent an idempotency key, and
// it may or may not believe its transfer id was accepted. Answering either way
// is what lets an ambiguous outcome be resolved instead of guessed at.
func (s *Service) Lookup(ctx context.Context, transferID, scope, key string) (Found, error) {
	if transferID == "" && (scope == "" || key == "") {
		return Found{}, fmt.Errorf("%w: a transfer id or an idempotency identity is required",
			ErrInvalidRequest)
	}
	var found Found
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
SELECT transfer_id, asset_id, payer_account_id, payee_account_id,
       amount_atoms::STRING, state, payer_book_id, payee_book_id
  FROM transfer_operations
 WHERE ($1 <> '' AND transfer_id = $1)
    OR ($1 = '' AND idempotency_scope = $2 AND idempotency_key = $3)`,
			transferID, scope, key).Scan(
			&found.TransferID, &found.AssetID, &found.PayerAccountID, &found.PayeeAccountID,
			&found.AmountAtoms, &found.State, &found.PayerBookID, &found.PayeeBookID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTransferNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT leg, ledger_transaction_id FROM transfer_effects WHERE transfer_id=$1`,
			found.TransferID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var leg, transactionID string
			if err := rows.Scan(&leg, &transactionID); err != nil {
				return err
			}
			switch leg {
			case legSingle:
				found.PayerTransactionID, found.PayeeTransactionID = transactionID, transactionID
			case legPayer:
				found.PayerTransactionID = transactionID
			case legPayee:
				found.PayeeTransactionID = transactionID
			}
		}
		return rows.Err()
	})
	if err != nil {
		return Found{}, err
	}
	return found, nil
}
