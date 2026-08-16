package ledger

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Service struct {
	transactions *store.Runner
	ids          IDGenerator
}

func NewService(transactions *store.Runner, ids IDGenerator) *Service {
	return &Service{transactions: transactions, ids: ids}
}

func (s *Service) NextID(ctx context.Context) (string, error) {
	if s == nil || s.ids == nil {
		return "", errors.New("ledger: durable ID generator is not configured")
	}
	return s.ids.Next(ctx)
}

func (s *Service) RegisterAsset(ctx context.Context, asset Asset) error {
	if asset.AssetID == "" || asset.DisplayCode == "" || asset.AtomicScale < 0 || asset.AtomicScale > 18 {
		return fmt.Errorf("%w: invalid asset", ErrInvalidPosting)
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO assets (asset_id, display_code, atomic_scale)
VALUES ($1, $2, $3)
ON CONFLICT (asset_id) DO NOTHING`, asset.AssetID, asset.DisplayCode, asset.AtomicScale)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var code string
		var scale int64
		if err := tx.QueryRow(ctx, `SELECT display_code, atomic_scale FROM assets WHERE asset_id=$1`, asset.AssetID).Scan(&code, &scale); err != nil {
			return err
		}
		if code != asset.DisplayCode || scale != asset.AtomicScale {
			return fmt.Errorf("%w: asset id exists with different definition", ErrInvalidPosting)
		}
		return nil
	})
}

func (s *Service) CreateBook(ctx context.Context, book Book) error {
	if err := book.Validate(); err != nil {
		return err
	}
	if book.GenesisHash == ([32]byte{}) {
		book.GenesisHash = GenesisHash(book.BookID)
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO books (book_id, legal_entity_id, jurisdiction, last_entry_hash)
VALUES ($1, $2, $3, $4)
ON CONFLICT (book_id) DO NOTHING`, book.BookID, book.LegalEntityID, book.Jurisdiction, book.GenesisHash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var legalEntity, jurisdiction string
		var genesis []byte
		var next int64
		if err := tx.QueryRow(ctx, `
SELECT legal_entity_id, jurisdiction, next_sequence_no, last_entry_hash
FROM books WHERE book_id=$1`, book.BookID).Scan(&legalEntity, &jurisdiction, &next, &genesis); err != nil {
			return err
		}
		if legalEntity != book.LegalEntityID || jurisdiction != book.Jurisdiction || next != 1 || !bytes.Equal(genesis, book.GenesisHash[:]) {
			return fmt.Errorf("%w: book id exists with a different definition or has already posted", ErrInvalidPosting)
		}
		return nil
	})
}

func (s *Service) CreateAccount(ctx context.Context, account Account) error {
	if err := account.Validate(); err != nil {
		return err
	}
	return s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO accounts (
    account_id, book_id, asset_id, account_type, normal_side,
    enforce_spend_limit, credit_limit_atoms
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (account_id) DO NOTHING`,
			account.AccountID, account.BookID, account.AssetID, account.AccountType,
			string(account.NormalSide), account.EnforceSpendLimit, account.CreditLimitAtoms.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var stored Account
			var normal, creditLimit string
			err := tx.QueryRow(ctx, `
SELECT account_id, book_id, asset_id, account_type, normal_side,
       enforce_spend_limit, credit_limit_atoms
FROM accounts WHERE account_id=$1`, account.AccountID).Scan(
				&stored.AccountID, &stored.BookID, &stored.AssetID, &stored.AccountType,
				&normal, &stored.EnforceSpendLimit, &creditLimit)
			stored.NormalSide = Side(normal)
			if err != nil {
				return err
			}
			stored.CreditLimitAtoms, err = ParseAmount(creditLimit)
			if err != nil {
				return err
			}
			if stored.AccountID != account.AccountID || stored.BookID != account.BookID ||
				stored.AssetID != account.AssetID || stored.AccountType != account.AccountType ||
				stored.NormalSide != account.NormalSide ||
				stored.EnforceSpendLimit != account.EnforceSpendLimit ||
				stored.CreditLimitAtoms.Cmp(account.CreditLimitAtoms) != 0 {
				return fmt.Errorf("%w: account id exists with different definition", ErrInvalidPosting)
			}
		}
		_, err = tx.Exec(ctx, `
INSERT INTO account_balances (account_id) VALUES ($1)
ON CONFLICT (account_id) DO NOTHING`, account.AccountID)
		return err
	})
}

func (s *Service) Post(ctx context.Context, request PostRequest) (Receipt, error) {
	var receipt Receipt
	if err := request.Validate(); err != nil {
		return receipt, err
	}
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var err error
		receipt, err = s.PostInTx(ctx, tx, request)
		return err
	})
	if err != nil {
		return Receipt{}, mapDatabaseError(err)
	}
	return receipt, nil
}

// PostInTx is the financial commit primitive. Callers use it inside the same
// serializable transaction that updates hold/payment counters, idempotency
// receipts, FX consumption, and the outbox.
func (s *Service) PostInTx(ctx context.Context, tx pgx.Tx, request PostRequest) (Receipt, error) {
	return s.postInTx(ctx, tx, request, false)
}

// PreparePaymentInTx builds an immutable DRAFT and its lines but deliberately
// does not make them financial authority. record_payment_effect is the only
// payment workload capability that validates the exact template, finalizes
// the DRAFT, and appends its lifecycle fact in one database call.
func (s *Service) PreparePaymentInTx(ctx context.Context, tx pgx.Tx, request PostRequest) (Receipt, error) {
	return s.postInTx(ctx, tx, request, true)
}

func (s *Service) postInTx(ctx context.Context, tx pgx.Tx, request PostRequest, paymentDraft bool) (Receipt, error) {
	var empty Receipt
	if tx == nil {
		return empty, fmt.Errorf("%w: nil database transaction", ErrInvalidPosting)
	}
	if err := request.Validate(); err != nil {
		return empty, err
	}
	metadata, err := CanonicalJSON(request.Metadata)
	if err != nil {
		return empty, err
	}
	request.Metadata = json.RawMessage(metadata)

	if existing, found, err := receiptByEffect(ctx, tx, request); err != nil {
		return empty, err
	} else if found {
		return existing, nil
	}

	var sequence int64
	var previousBytes []byte
	if err := tx.QueryRow(ctx, `
SELECT next_sequence_no, last_entry_hash
FROM books
WHERE book_id=$1`, request.BookID).Scan(&sequence, &previousBytes); err != nil {
		return empty, err
	}
	if len(previousBytes) != 32 {
		return empty, errors.New("ledger: corrupt book chain head")
	}
	var previous [32]byte
	copy(previous[:], previousBytes)
	entryHash, err := HashEntry(previous, sequence, request)
	if err != nil {
		return empty, err
	}

	var reference any
	if request.ReferenceTransactionID != nil {
		reference = *request.ReferenceTransactionID
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO ledger_transactions (
    transaction_id, book_id, operation_id, effect_id, transaction_kind,
    reference_transaction_id, posting_rule_version, schema_version,
    request_hash, metadata, canonical_metadata, status, sequence_no, prev_hash, entry_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::JSONB,
          $11, 'DRAFT', $12, $13, $14)
ON CONFLICT (effect_id) DO NOTHING`,
		request.TransactionID, request.BookID, request.OperationID, request.EffectID,
		request.Kind, reference, request.PostingRuleVersion, request.SchemaVersion,
		request.RequestHash[:], string(metadata), metadata, sequence, previous[:], entryHash[:])
	if err != nil {
		return empty, mapDatabaseError(err)
	}
	if tag.RowsAffected() == 0 {
		existing, found, err := receiptByEffect(ctx, tx, request)
		if err != nil {
			return empty, err
		}
		if !found {
			return empty, errors.New("ledger: effect conflict did not expose committed row")
		}
		return existing, nil
	}

	batch := &pgx.Batch{}
	for index, line := range request.Lines {
		batch.Queue(`
INSERT INTO ledger_lines
    (transaction_id, line_no, account_id, asset_id, side, amount_atoms, memo)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			request.TransactionID, int64(index+1), line.AccountID, line.AssetID,
			string(line.Side), line.AmountAtoms.String(), line.Memo)
	}
	results := tx.SendBatch(ctx, batch)
	for range request.Lines {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return empty, mapDatabaseError(err)
		}
	}
	if err := results.Close(); err != nil {
		return empty, mapDatabaseError(err)
	}

	if paymentDraft {
		return Receipt{
			TransactionID: request.TransactionID,
			BookID:        request.BookID,
			OperationID:   request.OperationID,
			EffectID:      request.EffectID,
			SequenceNo:    sequence,
			EntryHash:     entryHash,
		}, nil
	}

	var finalizedTransactionID *string
	err = tx.QueryRow(ctx, `SELECT public.finalize_ledger_transaction($1)`,
		request.TransactionID).Scan(&finalizedTransactionID)
	if err != nil {
		return empty, mapDatabaseError(err)
	}
	if finalizedTransactionID == nil || *finalizedTransactionID != request.TransactionID {
		return empty, errors.New("ledger: DRAFT to POSTED transition did not affect one row")
	}
	return Receipt{
		TransactionID: request.TransactionID,
		BookID:        request.BookID,
		OperationID:   request.OperationID,
		EffectID:      request.EffectID,
		SequenceNo:    sequence,
		EntryHash:     entryHash,
	}, nil
}

func (s *Service) Balance(ctx context.Context, accountID string) (Balance, error) {
	var result Balance
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var debit, credit, current, limit string
		err := tx.QueryRow(ctx, `
SELECT balance.account_id, balance.debit_atoms::STRING, balance.credit_atoms::STRING,
       balance.current_balance_atoms::STRING, account.credit_limit_atoms::STRING,
       balance.last_sequence_no
FROM account_balances AS balance
JOIN accounts AS account ON account.account_id=balance.account_id
WHERE balance.account_id=$1`, accountID).Scan(
			&result.AccountID, &debit, &credit, &current, &limit, &result.LastSequenceNo)
		if err != nil {
			return err
		}
		if result.DebitAtoms, err = ParseAmount(debit); err != nil {
			return err
		}
		if result.CreditAtoms, err = ParseAmount(credit); err != nil {
			return err
		}
		if result.CurrentBalanceAtoms, err = ParseAmount(current); err != nil {
			return err
		}
		result.CreditLimitAtoms, err = ParseAmount(limit)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Balance{}, ErrAccountNotFound
	}
	return result, err
}

// FoldBalance recomputes the account value from the immutable posted journal.
// Reconciliation compares it with Balance at the same committed watermark; it
// never writes the result back with SET balance.
func (s *Service) FoldBalance(ctx context.Context, accountID string) (Amount, error) {
	var folded Amount
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var value string
		err := tx.QueryRow(ctx, `
SELECT CASE account.normal_side
         WHEN 'DEBIT' THEN
           (coalesce(sum(CASE WHEN txn.status='POSTED' AND line.side='DEBIT' THEN line.amount_atoms ELSE 0 END), 0)
          - coalesce(sum(CASE WHEN txn.status='POSTED' AND line.side='CREDIT' THEN line.amount_atoms ELSE 0 END), 0))::DECIMAL(38,0)
         ELSE
           (coalesce(sum(CASE WHEN txn.status='POSTED' AND line.side='CREDIT' THEN line.amount_atoms ELSE 0 END), 0)
          - coalesce(sum(CASE WHEN txn.status='POSTED' AND line.side='DEBIT' THEN line.amount_atoms ELSE 0 END), 0))::DECIMAL(38,0)
       END::STRING
FROM accounts AS account
LEFT JOIN ledger_lines AS line ON line.account_id=account.account_id
LEFT JOIN ledger_transactions AS txn
       ON txn.transaction_id=line.transaction_id AND txn.status='POSTED'
WHERE account.account_id=$1
GROUP BY account.normal_side`, accountID).Scan(&value)
		if err != nil {
			return err
		}
		folded, err = ParseAmount(value)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Amount{}, ErrAccountNotFound
	}
	return folded, err
}

func (s *Service) LoadTransaction(ctx context.Context, transactionID string) (Transaction, error) {
	var result Transaction
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var reference sql.NullString
		var requestHash, previous, entry []byte
		var metadata []byte
		err := tx.QueryRow(ctx, `
SELECT transaction_id, book_id, operation_id, effect_id, transaction_kind,
       reference_transaction_id, posting_rule_version, schema_version,
       request_hash, metadata, sequence_no, prev_hash, entry_hash, status
FROM ledger_transactions WHERE transaction_id=$1`, transactionID).Scan(
			&result.TransactionID, &result.BookID, &result.OperationID, &result.EffectID,
			&result.Kind, &reference, &result.PostingRuleVersion, &result.SchemaVersion,
			&requestHash, &metadata, &result.SequenceNo, &previous, &entry, &result.Status)
		if err != nil {
			return err
		}
		if len(requestHash) != 32 || len(previous) != 32 || len(entry) != 32 {
			return errors.New("ledger: corrupt hash length")
		}
		copy(result.RequestHash[:], requestHash)
		copy(result.PrevHash[:], previous)
		copy(result.EntryHash[:], entry)
		result.Metadata = append(json.RawMessage(nil), metadata...)
		if reference.Valid {
			result.ReferenceTransactionID = &reference.String
		}

		rows, err := tx.Query(ctx, `
SELECT account_id, asset_id, side, amount_atoms::STRING, memo
FROM ledger_lines WHERE transaction_id=$1 ORDER BY line_no`, transactionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line Line
			var side, amount string
			if err := rows.Scan(&line.AccountID, &line.AssetID, &side, &amount, &line.Memo); err != nil {
				return err
			}
			line.Side = Side(side)
			line.AmountAtoms, err = ParseAmount(amount)
			if err != nil {
				return err
			}
			result.Lines = append(result.Lines, line)
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Transaction{}, ErrTransactionNotFound
	}
	return result, err
}

func receiptByEffect(ctx context.Context, query store.DBTX, request PostRequest) (Receipt, bool, error) {
	var result Receipt
	var storedHash, entryHash []byte
	var status, kind, rule string
	var schemaVersion int64
	var reference sql.NullString
	err := query.QueryRow(ctx, `
SELECT transaction_id, book_id, operation_id, effect_id, sequence_no,
       entry_hash, request_hash, status, transaction_kind,
       posting_rule_version, schema_version, reference_transaction_id
FROM ledger_transactions WHERE effect_id=$1`, request.EffectID).Scan(
		&result.TransactionID, &result.BookID, &result.OperationID, &result.EffectID,
		&result.SequenceNo, &entryHash, &storedHash, &status, &kind, &rule,
		&schemaVersion, &reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	if !bytes.Equal(storedHash, request.RequestHash[:]) || result.BookID != request.BookID ||
		result.OperationID != request.OperationID || kind != request.Kind ||
		rule != request.PostingRuleVersion || schemaVersion != request.SchemaVersion ||
		!sameOptionalReference(reference, request.ReferenceTransactionID) {
		return Receipt{}, false, ErrEffectConflict
	}
	if status != "POSTED" || len(entryHash) != 32 {
		return Receipt{}, false, errors.New("ledger: visible effect has no durable POSTED receipt")
	}
	copy(result.EntryHash[:], entryHash)
	result.Duplicate = true
	return result, true, nil
}

func sameOptionalReference(stored sql.NullString, expected *string) bool {
	if expected == nil {
		return !stored.Valid
	}
	return stored.Valid && stored.String == *expected
}

func mapDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch {
	case strings.Contains(pgErr.Message, "available balance plus explicit credit") ||
		strings.Contains(pgErr.Message, "posting exceeds available"):
		return fmt.Errorf("%w: %v", ErrInsufficientFunds, err)
	case strings.Contains(pgErr.Message, "different book"):
		return fmt.Errorf("%w: %v", ErrCrossBook, err)
	case strings.Contains(pgErr.Message, "asset does not match"):
		return fmt.Errorf("%w: %v", ErrAssetMismatch, err)
	case pgErr.Code == "23505":
		return fmt.Errorf("%w: %v", ErrEffectConflict, err)
	default:
		return err
	}
}

// MapPostingError preserves the ledger domain error contract for a caller
// whose SECURITY DEFINER transition invokes the same ledger finalizer. It does
// not hide an unknown SQL error.
func MapPostingError(err error) error {
	return mapDatabaseError(err)
}
