package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
)

// The three shapes a transfer can take. A same-book transfer writes one
// transaction that moves both parties; a cross-book transfer writes one per
// book, each balanced through that book's settlement account.
const (
	legSingle = "SINGLE"
	legPayer  = "PAYER"
	legPayee  = "PAYEE"
)

type account struct {
	accountID string
	bookID    string
	assetID   string
	status    string
}

type legPlan struct {
	leg           string
	bookID        string
	transactionID string
	effectID      string
	kind          string
	metadata      json.RawMessage
	lines         []ledger.Line
}

type postedLeg struct {
	plan          legPlan
	transactionID string
}

func loadAccount(ctx context.Context, tx pgx.Tx, accountID string) (account, error) {
	var result account
	err := tx.QueryRow(ctx, `
SELECT account_id, book_id, asset_id, status FROM accounts WHERE account_id=$1`,
		accountID).Scan(&result.accountID, &result.bookID, &result.assetID, &result.status)
	if errors.Is(err, pgx.ErrNoRows) {
		return account{}, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
	}
	return result, err
}

// checkParties refuses everything the ledger would refuse later, but with an
// answer the caller can act on. The trigger's message is correct and
// unhelpful; "these accounts hold different assets" is neither.
func checkParties(request Request, payer, payee account) error {
	if payer.accountID == payee.accountID {
		return ErrSameAccount
	}
	if payer.assetID != payee.assetID {
		return fmt.Errorf("%w: %s holds %s and %s holds %s",
			ErrAssetMismatch, payer.accountID, payer.assetID, payee.accountID, payee.assetID)
	}
	if payer.assetID != request.AssetID {
		return fmt.Errorf("%w: request names %s but the accounts hold %s",
			ErrAssetMismatch, request.AssetID, payer.assetID)
	}
	for _, party := range []account{payer, payee} {
		if party.status != "ACTIVE" {
			return fmt.Errorf("%w: %s is %s", ErrAccountNotUsable, party.accountID, party.status)
		}
	}
	return nil
}

// planLegs decides the shape of the transfer and builds the postings.
func (s *Service) planLegs(ctx context.Context, tx pgx.Tx, request Request,
	payer, payee account, payerTransactionID, payeeTransactionID string) ([]legPlan, error) {

	metadata, err := json.Marshal(map[string]string{
		"transfer_id":       request.TransferID,
		"idempotency_scope": request.IdempotencyScope,
		"idempotency_key":   request.IdempotencyKey,
		"memo":              request.Memo,
	})
	if err != nil {
		return nil, err
	}

	if payer.bookID == payee.bookID {
		// One book, one transaction: the value never leaves, so no settlement
		// account is involved and nothing needs to net out later.
		return []legPlan{{
			leg: legSingle, bookID: payer.bookID,
			transactionID: payerTransactionID,
			effectID:      request.TransferID + ":single",
			kind:          kindTransfer,
			metadata:      metadata,
			lines: []ledger.Line{
				{
					AccountID: payer.accountID, AssetID: request.AssetID,
					Side: ledger.Debit, AmountAtoms: request.AmountAtoms, Memo: "transfer out",
				},
				{
					AccountID: payee.accountID, AssetID: request.AssetID,
					Side: ledger.Credit, AmountAtoms: request.AmountAtoms, Memo: "transfer in",
				},
			},
		}}, nil
	}

	payerSettlement, err := settlementAccount(ctx, tx, payer.bookID, request.AssetID)
	if err != nil {
		return nil, err
	}
	payeeSettlement, err := settlementAccount(ctx, tx, payee.bookID, request.AssetID)
	if err != nil {
		return nil, err
	}

	// Two balanced transactions. The payer's book loses the value to its
	// settlement account and the payee's book receives it from its own, so
	// each book still balances and the pair of settlement movements cancels.
	return []legPlan{
		{
			leg: legPayer, bookID: payer.bookID,
			transactionID: payerTransactionID,
			effectID:      request.TransferID + ":payer",
			kind:          kindTransfer,
			metadata:      metadata,
			lines: []ledger.Line{
				{
					AccountID: payer.accountID, AssetID: request.AssetID,
					Side: ledger.Debit, AmountAtoms: request.AmountAtoms, Memo: "transfer out",
				},
				{
					AccountID: payerSettlement, AssetID: request.AssetID,
					Side: ledger.Credit, AmountAtoms: request.AmountAtoms, Memo: "due to peer book",
				},
			},
		},
		{
			leg: legPayee, bookID: payee.bookID,
			transactionID: payeeTransactionID,
			effectID:      request.TransferID + ":payee",
			kind:          kindTransferSettlement,
			metadata:      metadata,
			lines: []ledger.Line{
				{
					AccountID: payeeSettlement, AssetID: request.AssetID,
					Side: ledger.Debit, AmountAtoms: request.AmountAtoms, Memo: "due from peer book",
				},
				{
					AccountID: payee.accountID, AssetID: request.AssetID,
					Side: ledger.Credit, AmountAtoms: request.AmountAtoms, Memo: "transfer in",
				},
			},
		},
	}, nil
}

// settlementAccount resolves a book's settlement account from the registry
// rather than from the naming convention, so an account that was never
// registered cannot be used as one by guessing its name.
func settlementAccount(ctx context.Context, tx pgx.Tx, bookID, assetID string) (string, error) {
	var accountID string
	err := tx.QueryRow(ctx, `
SELECT account_id FROM interbook_settlement_accounts WHERE book_id=$1 AND asset_id=$2`,
		bookID, assetID).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s/%s", ErrSettlementMissing, bookID, assetID)
	}
	return accountID, err
}
