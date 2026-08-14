// Package repair contains deterministic, restart-safe incident repair jobs.
// A repair never rewrites journal history; it appends a referencing reversal.
package repair

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidIncident  = errors.New("repair: invalid cashback incident")
	ErrNotRepairable    = errors.New("repair: excess cashback is not one exact duplicated grant")
	ErrManifestConflict = errors.New("repair: manifest conflicts with durable facts")
)

// CashbackIncident is bounded by journal sequence, not wall time. This remains
// deterministic with a 15-minute clock jump and pins the buggy posting rule.
type CashbackIncident struct {
	IncidentID       string
	BookID           string
	FirstSequence    int64
	LastSequence     int64
	BuggyRuleVersion string
}

type CashbackManifest struct {
	RepairID                string
	PaymentID               string
	OriginalTransactionID   string
	CaptureTransactionID    string
	PostingRuleVersion      string
	AssetID                 string
	Expected                ledger.Amount
	Actual                  ledger.Amount
	Excess                  ledger.Amount
	CorrectionEffectID      string
	CorrectionTransactionID string
	Status                  string
}

type CashbackRepair struct {
	transactions *store.Runner
	ledger       *ledger.Service
}

func NewCashbackRepair(transactions *store.Runner, journal *ledger.Service) (*CashbackRepair, error) {
	if transactions == nil || transactions.DB == nil || journal == nil {
		return nil, errors.New("repair: transaction runner and ledger are required")
	}
	return &CashbackRepair{transactions: transactions, ledger: journal}, nil
}

// Plan discovers payments touched by the pinned bad deployment, computes
// expected-vs-actual from immutable payment effects, and persists a stable
// manifest. The reference incident is an exact duplicated grant; more complex
// rule mistakes are deliberately quarantined for a separately reviewed
// posting template rather than guessed by automation.
func (r *CashbackRepair) Plan(ctx context.Context, incident CashbackIncident) ([]CashbackManifest, error) {
	if incident.IncidentID == "" || incident.BookID == "" || incident.BuggyRuleVersion == "" ||
		incident.FirstSequence <= 0 || incident.LastSequence < incident.FirstSequence {
		return nil, ErrInvalidIncident
	}
	var manifests []CashbackManifest
	err := r.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		paymentRows, err := tx.Query(ctx, `
SELECT DISTINCT e.payment_id, e.original_transaction_id
FROM payment_effects AS e
JOIN ledger_transactions AS t ON t.transaction_id=e.ledger_transaction_id
WHERE e.effect_kind='CASHBACK' AND t.book_id=$1
  AND t.sequence_no BETWEEN $2 AND $3
  AND t.posting_rule_version=$4 AND t.status='POSTED'
  AND e.original_transaction_id IS NOT NULL
ORDER BY e.payment_id, e.original_transaction_id`, incident.BookID, incident.FirstSequence,
			incident.LastSequence, incident.BuggyRuleVersion)
		if err != nil {
			return err
		}
		type candidate struct{ paymentID, captureTransactionID string }
		var candidates []candidate
		for paymentRows.Next() {
			var item candidate
			if err := paymentRows.Scan(&item.paymentID, &item.captureTransactionID); err != nil {
				paymentRows.Close()
				return err
			}
			candidates = append(candidates, item)
		}
		if err := paymentRows.Err(); err != nil {
			paymentRows.Close()
			return err
		}
		paymentRows.Close()

		for _, candidate := range candidates {
			manifest, repairable, err := r.planCapture(ctx, tx, incident,
				candidate.paymentID, candidate.captureTransactionID)
			if err != nil {
				return err
			}
			if repairable {
				manifests = append(manifests, manifest)
			}
		}
		return nil
	})
	return manifests, err
}

func (r *CashbackRepair) planCapture(
	ctx context.Context,
	tx pgx.Tx,
	incident CashbackIncident,
	paymentID, captureTransactionID string,
) (CashbackManifest, bool, error) {
	var assetID, expectedText, actualText string
	err := tx.QueryRow(ctx, `
SELECT p.asset_id, capture.expected_cashback_atoms::STRING,
       ((SELECT coalesce(sum(cashback.amount_atoms),0)
           FROM payment_effects AS cashback
          WHERE cashback.payment_id=p.payment_id
            AND cashback.effect_kind='CASHBACK'
            AND cashback.original_transaction_id=capture.capture_transaction_id)
        -
        (SELECT coalesce(sum(reversal.amount_atoms),0)
           FROM payment_effects AS cashback
           JOIN payment_effects AS reversal
             ON reversal.payment_id=cashback.payment_id
            AND reversal.effect_kind='REVERSAL'
            AND reversal.original_transaction_id=cashback.ledger_transaction_id
          WHERE cashback.payment_id=p.payment_id
            AND cashback.effect_kind='CASHBACK'
            AND cashback.original_transaction_id=capture.capture_transaction_id))::STRING
FROM payment_operations AS p
JOIN payment_capture_financials AS capture ON capture.payment_id=p.payment_id
WHERE p.payment_id=$1 AND capture.capture_transaction_id=$2`,
		paymentID, captureTransactionID).Scan(&assetID, &expectedText, &actualText)
	if err != nil {
		return CashbackManifest{}, false, err
	}
	expected, err := ledger.ParseAmount(expectedText)
	if err != nil {
		return CashbackManifest{}, false, err
	}
	actual, err := ledger.ParseAmount(actualText)
	if err != nil {
		return CashbackManifest{}, false, err
	}
	if actual.Cmp(expected) <= 0 {
		return CashbackManifest{}, false, nil
	}
	excess, err := actual.Sub(expected)
	if err != nil {
		return CashbackManifest{}, false, err
	}

	// Select one un-reversed grant whose immutable amount is exactly the
	// excess. That is the safe automatic template for a duplicated cashback.
	var originalTransactionID, grantAmount string
	err = tx.QueryRow(ctx, `
SELECT e.ledger_transaction_id, e.amount_atoms::STRING
FROM payment_effects AS e
JOIN ledger_transactions AS t ON t.transaction_id=e.ledger_transaction_id
WHERE e.payment_id=$1 AND e.effect_kind='CASHBACK'
  AND e.original_transaction_id=$2
  AND t.book_id=$3 AND t.sequence_no BETWEEN $4 AND $5
  AND t.posting_rule_version=$6 AND t.status='POSTED'
  AND NOT EXISTS (
      SELECT 1 FROM payment_effects AS reversal
      WHERE reversal.payment_id=e.payment_id AND reversal.effect_kind='REVERSAL'
        AND reversal.original_transaction_id=e.ledger_transaction_id)
ORDER BY t.sequence_no DESC, e.payment_effect_id DESC
LIMIT 1`, paymentID, captureTransactionID, incident.BookID, incident.FirstSequence,
		incident.LastSequence, incident.BuggyRuleVersion).Scan(&originalTransactionID, &grantAmount)
	if errors.Is(err, pgx.ErrNoRows) {
		return CashbackManifest{}, false, ErrNotRepairable
	}
	if err != nil {
		return CashbackManifest{}, false, err
	}
	grant, err := ledger.ParseAmount(grantAmount)
	if err != nil {
		return CashbackManifest{}, false, err
	}
	if grant.Cmp(excess) != 0 {
		return CashbackManifest{}, false, fmt.Errorf("%w: payment=%s expected=%s actual=%s candidate=%s",
			ErrNotRepairable, paymentID, expected, actual, grant)
	}

	repairID := deterministicID("cashback-repair", incident.IncidentID, paymentID,
		captureTransactionID, originalTransactionID, expected.String(), actual.String())
	manifest := CashbackManifest{
		RepairID: repairID, PaymentID: paymentID, OriginalTransactionID: originalTransactionID,
		CaptureTransactionID: captureTransactionID,
		PostingRuleVersion:   incident.BuggyRuleVersion, AssetID: assetID,
		Expected: expected, Actual: actual, Excess: excess,
		CorrectionEffectID: deterministicID("cashback-correction-effect", repairID),
		Status:             "PLANNED",
	}
	manifest.CorrectionTransactionID = deterministicID("cashback-correction-transaction", repairID)

	tag, err := tx.Exec(ctx, `
INSERT INTO cashback_repair_manifests
 (repair_id, original_payment_id, original_transaction_id, capture_transaction_id,
  posting_rule_version, asset_id, expected_atoms, actual_atoms, excess_atoms,
  correction_effect_id, correction_transaction_id, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PLANNED')
ON CONFLICT (repair_id) DO NOTHING`, manifest.RepairID, manifest.PaymentID,
		manifest.OriginalTransactionID, manifest.CaptureTransactionID,
		manifest.PostingRuleVersion, manifest.AssetID,
		manifest.Expected.String(), manifest.Actual.String(), manifest.Excess.String(),
		manifest.CorrectionEffectID, manifest.CorrectionTransactionID)
	if err != nil {
		return CashbackManifest{}, false, err
	}
	if tag.RowsAffected() == 0 {
		stored, err := loadManifest(ctx, tx, repairID, false)
		if err != nil {
			return CashbackManifest{}, false, err
		}
		if !sameManifest(stored, manifest) {
			return CashbackManifest{}, false, ErrManifestConflict
		}
		manifest = stored
	}
	return manifest, true, nil
}

// Execute posts the exact inverse of the duplicated grant and marks the
// manifest in the same serializable transaction. A crash before commit leaves
// both absent; a crash after commit is resolved by the deterministic effect ID.
func (r *CashbackRepair) Execute(ctx context.Context, repairID string) (ledger.Receipt, error) {
	if repairID == "" {
		return ledger.Receipt{}, ErrManifestConflict
	}
	var receipt ledger.Receipt
	err := r.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		manifest, err := loadManifest(ctx, tx, repairID, true)
		if err != nil {
			return err
		}
		if manifest.Status == "POSTED" {
			var entryHash []byte
			err := tx.QueryRow(ctx, `
SELECT transaction_id, book_id, operation_id, effect_id, sequence_no, entry_hash
FROM ledger_transactions WHERE transaction_id=$1 AND status='POSTED'`,
				manifest.CorrectionTransactionID).Scan(&receipt.TransactionID, &receipt.BookID,
				&receipt.OperationID, &receipt.EffectID, &receipt.SequenceNo, &entryHash)
			if err != nil {
				return err
			}
			if len(entryHash) != sha256.Size {
				return ErrManifestConflict
			}
			copy(receipt.EntryHash[:], entryHash)
			receipt.Duplicate = true
			return nil
		}

		var bookID, sourceRule, linkedCaptureID string
		err = tx.QueryRow(ctx, `
SELECT transaction.book_id, transaction.posting_rule_version,
       cashback.original_transaction_id
FROM ledger_transactions AS transaction
JOIN payment_effects AS cashback
  ON cashback.payment_id=$2
 AND cashback.ledger_transaction_id=transaction.transaction_id
 AND cashback.effect_kind='CASHBACK'
WHERE transaction.transaction_id=$1 AND transaction.status='POSTED'`,
			manifest.OriginalTransactionID, manifest.PaymentID).
			Scan(&bookID, &sourceRule, &linkedCaptureID)
		if err != nil {
			return err
		}
		if sourceRule != manifest.PostingRuleVersion || linkedCaptureID != manifest.CaptureTransactionID {
			return ErrManifestConflict
		}

		// Serialize every correction for this payment before re-validating the
		// planned net amount. Different incident manifests can otherwise both
		// observe the same pre-repair value and append two valid inverses.
		var availableAccountID, paymentAssetID, authorityRegion string
		err = tx.QueryRow(ctx, `
SELECT customer_available_account_id, asset_id, coalesce(authority_region,'')
FROM payment_operations WHERE payment_id=$1 FOR UPDATE`, manifest.PaymentID).
			Scan(&availableAccountID, &paymentAssetID, &authorityRegion)
		if err != nil {
			return err
		}
		if paymentAssetID != manifest.AssetID {
			return ErrManifestConflict
		}

		currentActual, err := netCashbackForCapture(ctx, tx, manifest.PaymentID,
			manifest.CaptureTransactionID)
		if err != nil {
			return err
		}
		if currentActual.Cmp(manifest.Actual) != 0 {
			return fmt.Errorf("%w: payment cashback changed after planning", ErrManifestConflict)
		}

		lines, err := inverseTransactionLines(ctx, tx, manifest.OriginalTransactionID,
			manifest.AssetID, manifest.Excess)
		if err != nil {
			return err
		}

		if authorityRegion != "" {
			if _, err := escrow.SpendInTx(ctx, tx, escrow.EffectRequest{
				EffectID: manifest.CorrectionEffectID, AccountID: availableAccountID,
				AssetID: manifest.AssetID, Region: authorityRegion, Amount: manifest.Excess,
			}); err != nil {
				return err
			}
		}
		metadata, _ := json.Marshal(map[string]string{
			"repair_id": repairID, "reason": "duplicate_cashback",
			"original_transaction_id": manifest.OriginalTransactionID,
		})
		requestHash := sha256.Sum256([]byte("cashback-repair-request/v1\x00" + repairID))
		request := ledger.PostRequest{
			TransactionID:          manifest.CorrectionTransactionID,
			BookID:                 bookID,
			OperationID:            deterministicID("cashback-repair-operation", repairID),
			EffectID:               manifest.CorrectionEffectID,
			Kind:                   "CASHBACK_REVERSAL",
			ReferenceTransactionID: &manifest.OriginalTransactionID,
			PostingRuleVersion:     "cashback-repair-v1",
			SchemaVersion:          1,
			RequestHash:            requestHash,
			Metadata:               metadata,
			Lines:                  lines,
		}
		receipt, err = r.ledger.PostInTx(ctx, tx, request)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO payment_effects
 (payment_effect_id, payment_id, effect_kind, amount_atoms,
  ledger_transaction_id, original_transaction_id)
VALUES ($1,$2,'REVERSAL',$3,$4,$5)`, manifest.CorrectionEffectID,
			manifest.PaymentID, manifest.Excess.String(), manifest.CorrectionTransactionID,
			manifest.OriginalTransactionID)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
UPDATE payment_capture_financials
SET cashback_reversed_atoms=cashback_reversed_atoms+$3,
    version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1 AND capture_transaction_id=$2
  AND expected_cashback_atoms=$4`, manifest.PaymentID,
			manifest.CaptureTransactionID, manifest.Excess.String(), manifest.Expected.String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrManifestConflict
		}
		tag, err = tx.Exec(ctx, `
UPDATE payment_operations
SET cashback_reversed_atoms=cashback_reversed_atoms+$2,
    version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1 AND asset_id=$3`, manifest.PaymentID,
			manifest.Excess.String(), manifest.AssetID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrManifestConflict
		}
		tag, err = tx.Exec(ctx, `
UPDATE cashback_repair_manifests
SET status='POSTED'
WHERE repair_id=$1 AND status='PLANNED'`, repairID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrManifestConflict
		}
		return nil
	})
	return receipt, err
}

func loadManifest(ctx context.Context, tx pgx.Tx, repairID string, lock bool) (CashbackManifest, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	var result CashbackManifest
	var expected, actual, excess string
	err := tx.QueryRow(ctx, `
SELECT repair_id, original_payment_id, original_transaction_id,
       capture_transaction_id,
       posting_rule_version, asset_id, expected_atoms::STRING,
       actual_atoms::STRING, excess_atoms::STRING, correction_effect_id,
       coalesce(correction_transaction_id,''), status
FROM cashback_repair_manifests WHERE repair_id=$1`+suffix, repairID).Scan(
		&result.RepairID, &result.PaymentID, &result.OriginalTransactionID,
		&result.CaptureTransactionID, &result.PostingRuleVersion, &result.AssetID,
		&expected, &actual, &excess,
		&result.CorrectionEffectID, &result.CorrectionTransactionID, &result.Status)
	if err != nil {
		return CashbackManifest{}, err
	}
	if result.Expected, err = ledger.ParseAmount(expected); err != nil {
		return CashbackManifest{}, err
	}
	if result.Actual, err = ledger.ParseAmount(actual); err != nil {
		return CashbackManifest{}, err
	}
	result.Excess, err = ledger.ParseAmount(excess)
	return result, err
}

func netCashbackForCapture(
	ctx context.Context,
	tx pgx.Tx,
	paymentID, captureTransactionID string,
) (ledger.Amount, error) {
	var amount string
	err := tx.QueryRow(ctx, `
SELECT ((SELECT coalesce(sum(cashback.amount_atoms),0)
           FROM payment_effects AS cashback
          WHERE cashback.payment_id=$1 AND cashback.effect_kind='CASHBACK'
            AND cashback.original_transaction_id=$2)
        -
        (SELECT coalesce(sum(reversal.amount_atoms),0)
           FROM payment_effects AS cashback
           JOIN payment_effects AS reversal
             ON reversal.payment_id=cashback.payment_id
            AND reversal.effect_kind='REVERSAL'
            AND reversal.original_transaction_id=cashback.ledger_transaction_id
          WHERE cashback.payment_id=$1 AND cashback.effect_kind='CASHBACK'
            AND cashback.original_transaction_id=$2))::STRING`,
		paymentID, captureTransactionID).Scan(&amount)
	if err != nil {
		return ledger.Amount{}, err
	}
	return ledger.ParseAmount(amount)
}

func inverseTransactionLines(ctx context.Context, tx pgx.Tx, transactionID, assetID string, expected ledger.Amount) ([]ledger.Line, error) {
	rows, err := tx.Query(ctx, `
SELECT account_id, asset_id, side, amount_atoms::STRING, memo
FROM ledger_lines WHERE transaction_id=$1 ORDER BY line_no`, transactionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []ledger.Line
	debitTotal := ledger.NewAmountInt64(0)
	creditTotal := ledger.NewAmountInt64(0)
	for rows.Next() {
		var account, asset, side, amountText, memo string
		if err := rows.Scan(&account, &asset, &side, &amountText, &memo); err != nil {
			return nil, err
		}
		if asset != assetID {
			return nil, ErrManifestConflict
		}
		amount, err := ledger.ParseAmount(amountText)
		if err != nil {
			return nil, err
		}
		originalSide := ledger.Side(side)
		inverseSide := ledger.Debit
		if originalSide == ledger.Debit {
			inverseSide = ledger.Credit
			debitTotal, err = debitTotal.Add(amount)
		} else if originalSide == ledger.Credit {
			inverseSide = ledger.Debit
			creditTotal, err = creditTotal.Add(amount)
		} else {
			return nil, ErrManifestConflict
		}
		if err != nil {
			return nil, err
		}
		lines = append(lines, ledger.Line{
			AccountID: account, AssetID: asset, Side: inverseSide,
			AmountAtoms: amount, Memo: "cashback repair: " + memo,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(lines) < 2 || debitTotal.Cmp(expected) != 0 || creditTotal.Cmp(expected) != 0 {
		return nil, ErrNotRepairable
	}
	return lines, nil
}

func deterministicID(domain string, values ...string) string {
	h := sha256.New()
	h.Write([]byte("payment-platform/" + domain + "/v1\x00"))
	for _, value := range values {
		h.Write([]byte(fmt.Sprintf("%08x", len(value))))
		h.Write([]byte(value))
	}
	return domain + "-v1-" + hex.EncodeToString(h.Sum(nil))
}

func sameManifest(left, right CashbackManifest) bool {
	return left.RepairID == right.RepairID && left.PaymentID == right.PaymentID &&
		left.OriginalTransactionID == right.OriginalTransactionID &&
		left.CaptureTransactionID == right.CaptureTransactionID &&
		left.PostingRuleVersion == right.PostingRuleVersion && left.AssetID == right.AssetID &&
		left.Expected.Cmp(right.Expected) == 0 && left.Actual.Cmp(right.Actual) == 0 &&
		left.Excess.Cmp(right.Excess) == 0 &&
		left.CorrectionEffectID == right.CorrectionEffectID &&
		left.CorrectionTransactionID == right.CorrectionTransactionID
}
