package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5/pgxpool"
)

const MaxVerificationRange = 100_000

var (
	ErrSequenceGap       = errors.New("audit: journal sequence gap")
	ErrPreviousHash      = errors.New("audit: previous hash mismatch")
	ErrEntryHash         = errors.New("audit: entry hash mismatch")
	ErrHeadMismatch      = errors.New("audit: book head mismatch")
	ErrCanonicalMetadata = errors.New("audit: persisted canonical metadata mismatch")
)

type Range struct {
	BookID       string
	First        int64
	Last         int64
	ExpectedPrev [32]byte
}

type Verification struct {
	BookID   string
	First    int64
	Last     int64
	Count    int
	LastHash [32]byte
	Merkle   [32]byte
}

type SQLReader struct {
	DB *pgxpool.Pool
}

// LoadRange reads one closed range. The range bound is deliberate: audit jobs
// checkpoint progress instead of attempting an unbounded in-memory scan.
func (r SQLReader) LoadRange(ctx context.Context, requested Range) ([]ledger.Transaction, error) {
	if r.DB == nil || requested.BookID == "" || requested.First <= 0 ||
		requested.Last < requested.First || requested.Last-requested.First+1 > MaxVerificationRange {
		return nil, errors.New("audit: invalid verification range")
	}
	rows, err := r.DB.Query(ctx, `
		SELECT t.transaction_id, t.book_id, t.operation_id, t.effect_id,
		       t.transaction_kind, t.reference_transaction_id,
		       t.posting_rule_version, t.schema_version, t.request_hash,
		       t.metadata, t.canonical_metadata, t.sequence_no, t.prev_hash,
		       t.entry_hash, t.status,
		       l.line_no, l.account_id, l.asset_id, l.side, l.amount_atoms, l.memo
		FROM ledger_transactions AS t
		JOIN ledger_lines AS l ON l.transaction_id = t.transaction_id
		WHERE t.book_id = $1 AND t.sequence_no BETWEEN $2 AND $3
		  AND t.status = 'POSTED'
		ORDER BY t.sequence_no, l.line_no`, requested.BookID, requested.First, requested.Last)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []ledger.Transaction
	var current *ledger.Transaction
	for rows.Next() {
		var (
			txID, bookID, operationID, effectID, kind, rule, status string
			reference                                               *string
			schemaVersion, sequenceNo, lineNo                       int64
			amountText                                              string
			requestHash, previousHash, entryHash                    []byte
			metadata, canonicalMetadata                             []byte
			accountID, assetID, side, memo                          string
		)
		if err := rows.Scan(
			&txID, &bookID, &operationID, &effectID, &kind, &reference,
			&rule, &schemaVersion, &requestHash, &metadata,
			&canonicalMetadata, &sequenceNo,
			&previousHash, &entryHash, &status, &lineNo, &accountID,
			&assetID, &side, &amountText, &memo,
		); err != nil {
			return nil, err
		}
		if len(requestHash) != sha256.Size || len(previousHash) != sha256.Size || len(entryHash) != sha256.Size {
			return nil, errors.New("audit: malformed persisted digest")
		}
		verifiedMetadata, err := verifiedCanonicalMetadata(metadata, canonicalMetadata)
		if err != nil {
			return nil, fmt.Errorf("%w: transaction=%s: %v", ErrCanonicalMetadata, txID, err)
		}
		if current == nil || current.TransactionID != txID {
			var requestDigest, previousDigest, entryDigest [32]byte
			copy(requestDigest[:], requestHash)
			copy(previousDigest[:], previousHash)
			copy(entryDigest[:], entryHash)
			transactions = append(transactions, ledger.Transaction{
				PostRequest: ledger.PostRequest{
					TransactionID: txID, BookID: bookID, OperationID: operationID,
					EffectID: effectID, Kind: kind, ReferenceTransactionID: reference,
					PostingRuleVersion: rule, SchemaVersion: schemaVersion,
					RequestHash: requestDigest, Metadata: verifiedMetadata,
				},
				SequenceNo: sequenceNo, PrevHash: previousDigest,
				EntryHash: entryDigest, Status: status,
			})
			current = &transactions[len(transactions)-1]
		}
		if current.SequenceNo != sequenceNo || int64(len(current.Lines)+1) != lineNo {
			return nil, fmt.Errorf("%w: transaction=%s line=%d", ErrSequenceGap, txID, lineNo)
		}
		amount, err := ledger.ParseAmount(amountText)
		if err != nil {
			return nil, fmt.Errorf("audit: invalid persisted amount: %w", err)
		}
		current.Lines = append(current.Lines, ledger.Line{
			AccountID: accountID, AssetID: assetID, Side: ledger.Side(side),
			AmountAtoms: amount, Memo: memo,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return transactions, nil
}

// verifiedCanonicalMetadata binds the verifier to the exact canonical bytes
// persisted by the expanded writer. JSONB semantic equality alone would not
// detect replacement with a different byte serialization. Legacy rows from
// before migration 017 have no byte column and retain the v1 canonicalization
// path.
func verifiedCanonicalMetadata(storedJSON, canonical []byte) ([]byte, error) {
	fromStored, err := ledger.CanonicalJSON(storedJSON)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata JSON: %w", err)
	}
	if canonical == nil {
		return fromStored, nil
	}
	canonicalized, err := ledger.CanonicalJSON(canonical)
	if err != nil {
		return nil, fmt.Errorf("invalid canonical metadata JSON: %w", err)
	}
	if !bytes.Equal(canonical, canonicalized) {
		return nil, errors.New("canonical metadata is not byte-canonical")
	}
	if !bytes.Equal(fromStored, canonical) {
		return nil, errors.New("canonical metadata does not represent metadata")
	}
	return append([]byte(nil), canonical...), nil
}

func VerifyRange(requested Range, transactions []ledger.Transaction) (Verification, error) {
	if len(transactions) == 0 {
		return Verification{}, errors.New("audit: empty verification range")
	}
	if transactions[0].SequenceNo != requested.First ||
		transactions[len(transactions)-1].SequenceNo != requested.Last ||
		len(transactions) != int(requested.Last-requested.First+1) {
		return Verification{}, ErrSequenceGap
	}
	expectedPrevious := requested.ExpectedPrev
	leaves := make([][32]byte, 0, len(transactions))
	for index, transaction := range transactions {
		expectedSequence := requested.First + int64(index)
		if transaction.BookID != requested.BookID || transaction.SequenceNo != expectedSequence {
			return Verification{}, fmt.Errorf("%w: expected=%d actual=%d", ErrSequenceGap, expectedSequence, transaction.SequenceNo)
		}
		if !bytes.Equal(transaction.PrevHash[:], expectedPrevious[:]) {
			return Verification{}, fmt.Errorf("%w: sequence=%d", ErrPreviousHash, transaction.SequenceNo)
		}
		calculated, err := ledger.CanonicalEntryHash(expectedPrevious[:], transaction)
		if err != nil {
			return Verification{}, fmt.Errorf("audit sequence %d: %w", transaction.SequenceNo, err)
		}
		if !bytes.Equal(calculated, transaction.EntryHash[:]) {
			return Verification{}, fmt.Errorf("%w: sequence=%d", ErrEntryHash, transaction.SequenceNo)
		}
		expectedPrevious = transaction.EntryHash
		leaves = append(leaves, transaction.EntryHash)
	}
	return Verification{
		BookID: requested.BookID, First: requested.First, Last: requested.Last,
		Count: len(transactions), LastHash: expectedPrevious, Merkle: MerkleRoot(leaves),
	}, nil
}

func (r SQLReader) VerifyBookHead(ctx context.Context, result Verification) error {
	var nextSequence int64
	var storedHead []byte
	if err := r.DB.QueryRow(ctx, `
		SELECT next_sequence_no, last_entry_hash FROM books WHERE book_id=$1`, result.BookID).
		Scan(&nextSequence, &storedHead); err != nil {
		return err
	}
	if nextSequence != result.Last+1 || !bytes.Equal(storedHead, result.LastHash[:]) {
		return ErrHeadMismatch
	}
	return nil
}
