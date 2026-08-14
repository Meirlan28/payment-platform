// Package reconciliation verifies derived state against immutable financial
// facts. It never repairs a balance in place: findings are durable evidence and
// any permitted repair is posted later as a new ledger transaction.
package reconciliation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

type Severity string

const (
	SeverityP0  Severity = "P0"
	SeverityLag Severity = "EXPECTED_LAG"
)

type Finding struct {
	Category SeverityCategory  `json:"category"`
	Severity Severity          `json:"severity"`
	BookID   string            `json:"book_id,omitempty"`
	EffectID string            `json:"effect_id,omitempty"`
	AssetID  string            `json:"asset_id,omitempty"`
	Amount   ledger.Amount     `json:"amount_atoms"`
	Details  map[string]string `json:"details"`
}

type SeverityCategory string

const (
	UnbalancedTransaction     SeverityCategory = "UNBALANCED_TRANSACTION"
	JournalReplayMismatch     SeverityCategory = "JOURNAL_REPLAY_MISMATCH"
	JournalSequenceGap        SeverityCategory = "JOURNAL_SEQUENCE_GAP"
	EscrowNotConserved        SeverityCategory = "ESCROW_NOT_CONSERVED"
	PaymentAggregateMismatch  SeverityCategory = "PAYMENT_AGGREGATE_MISMATCH"
	PaymentEffectWithoutProof SeverityCategory = "PAYMENT_EFFECT_WITHOUT_POSTED_LEDGER"
	RefundOverCapture         SeverityCategory = "REFUND_OVER_CAPTURE"
	CashbackRuleExceeded      SeverityCategory = "CASHBACK_RULE_EXCEEDED"
	SuccessWithoutProof       SeverityCategory = "SUCCESS_WITHOUT_DURABLE_PROOF"
	OutboxWithoutParent       SeverityCategory = "OUTBOX_WITHOUT_PARENT_TRANSACTION"
	TransferPending           SeverityCategory = "TRANSFER_PENDING"
	ExternalUnknown           SeverityCategory = "EXTERNAL_EFFECT_UNKNOWN"
	SettlementUnmatched       SeverityCategory = "SETTLEMENT_UNMATCHED"
)

type Report struct {
	RunID      string           `json:"run_id"`
	Status     string           `json:"status"`
	Watermarks map[string]int64 `json:"book_watermarks"`
	Findings   []Finding        `json:"findings"`
}

func (r Report) Safe() bool {
	for _, finding := range r.Findings {
		if finding.Severity == SeverityP0 {
			return false
		}
	}
	return true
}

type Checker struct {
	transactions *store.Runner
}

func NewChecker(transactions *store.Runner) (*Checker, error) {
	if transactions == nil || transactions.DB == nil {
		return nil, errors.New("reconciliation: transaction runner is required")
	}
	return &Checker{transactions: transactions}, nil
}

// Run evaluates every check at one serializable database snapshot and stores
// the report in the same commit. A retry with the same runID returns the
// original report; it never produces a second set of correction candidates.
func (c *Checker) Run(ctx context.Context, runID string) (Report, error) {
	if runID == "" {
		return Report{}, errors.New("reconciliation: run id is required")
	}
	var report Report
	err := c.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		stored, found, err := loadReport(ctx, tx, runID)
		if err != nil {
			return err
		}
		if found {
			report = stored
			return nil
		}

		report = Report{RunID: runID, Status: "RUNNING", Watermarks: make(map[string]int64)}
		if _, err := tx.Exec(ctx, `
INSERT INTO reconciliation_runs (run_id, status)
VALUES ($1, 'RUNNING')`, runID); err != nil {
			return err
		}
		if err := c.loadWatermarks(ctx, tx, &report); err != nil {
			return err
		}
		checks := []func(context.Context, pgx.Tx, *Report) error{
			c.checkLedgerBalance,
			c.checkMaterializedBalances,
			c.checkSequences,
			c.checkEscrow,
			c.checkPaymentAggregates,
			c.checkDurableProofs,
			c.checkProtocolLag,
		}
		for _, check := range checks {
			if err := check(ctx, tx, &report); err != nil {
				return err
			}
		}
		sortFindings(report.Findings)
		if report.Safe() {
			report.Status = "PASSED"
		} else {
			report.Status = "FAILED"
		}
		if err := persistFindings(ctx, tx, report); err != nil {
			return err
		}
		watermarks, err := json.Marshal(report.Watermarks)
		if err != nil {
			return err
		}
		violations, err := json.Marshal(report.Findings)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
UPDATE reconciliation_runs
SET status=$2, completed_at=transaction_timestamp(),
    verified_book_watermarks=$3::JSONB, violations=$4::JSONB
WHERE run_id=$1 AND status='RUNNING'`, runID, report.Status, string(watermarks), string(violations))
		return err
	})
	return report, err
}

func (c *Checker) loadWatermarks(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `SELECT book_id, next_sequence_no-1 FROM books ORDER BY book_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var book string
		var watermark int64
		if err := rows.Scan(&book, &watermark); err != nil {
			return err
		}
		report.Watermarks[book] = watermark
	}
	return rows.Err()
}

func (c *Checker) checkLedgerBalance(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
SELECT t.book_id, t.effect_id, l.asset_id,
       (sum(CASE WHEN l.side='DEBIT' THEN l.amount_atoms ELSE 0 END)
       -sum(CASE WHEN l.side='CREDIT' THEN l.amount_atoms ELSE 0 END))::STRING
FROM ledger_transactions AS t
JOIN ledger_lines AS l ON l.transaction_id=t.transaction_id
WHERE t.status='POSTED'
GROUP BY t.book_id, t.effect_id, l.asset_id
HAVING sum(CASE WHEN l.side='DEBIT' THEN l.amount_atoms ELSE 0 END)
    <> sum(CASE WHEN l.side='CREDIT' THEN l.amount_atoms ELSE 0 END)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var book, effect, asset, amount string
		if err := rows.Scan(&book, &effect, &asset, &amount); err != nil {
			return err
		}
		if err := report.add(UnbalancedTransaction, SeverityP0, book, effect, asset, amount, nil); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkMaterializedBalances(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
WITH replay AS (
  SELECT a.account_id, a.book_id, a.asset_id,
         CASE a.normal_side
           WHEN 'DEBIT' THEN coalesce(sum(CASE WHEN l.side='DEBIT' THEN l.amount_atoms ELSE -l.amount_atoms END),0)
           ELSE coalesce(sum(CASE WHEN l.side='CREDIT' THEN l.amount_atoms ELSE -l.amount_atoms END),0)
         END AS folded
  FROM accounts AS a
  LEFT JOIN ledger_lines AS l ON l.account_id=a.account_id
    AND EXISTS (SELECT 1 FROM ledger_transactions AS t
                WHERE t.transaction_id=l.transaction_id AND t.status='POSTED')
  GROUP BY a.account_id, a.book_id, a.asset_id, a.normal_side
)
SELECT r.book_id, r.account_id, r.asset_id,
       (coalesce(b.current_balance_atoms,0)-r.folded)::STRING,
       b.account_id IS NOT NULL
FROM replay AS r
LEFT JOIN account_balances AS b ON b.account_id=r.account_id
WHERE b.account_id IS NULL OR b.current_balance_atoms <> r.folded`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var book, account, asset, delta string
		var projectionPresent bool
		if err := rows.Scan(&book, &account, &asset, &delta, &projectionPresent); err != nil {
			return err
		}
		if err := report.add(JournalReplayMismatch, SeverityP0, book, account, asset, delta,
			map[string]string{
				"account_id":         account,
				"projection_present": fmt.Sprintf("%t", projectionPresent),
			}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkSequences(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
SELECT b.book_id, (b.next_sequence_no-1)::STRING,
       count(t.transaction_id)::STRING, coalesce(max(t.sequence_no),0)::STRING
FROM books AS b
LEFT JOIN ledger_transactions AS t ON t.book_id=b.book_id AND t.status='POSTED'
GROUP BY b.book_id, b.next_sequence_no
HAVING b.next_sequence_no-1 <> count(t.transaction_id)
    OR b.next_sequence_no-1 <> coalesce(max(t.sequence_no),0)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var book, expected, count, maximum string
		if err := rows.Scan(&book, &expected, &count, &maximum); err != nil {
			return err
		}
		if err := report.add(JournalSequenceGap, SeverityP0, book, book, "", "0",
			map[string]string{"expected": expected, "count": count, "maximum": maximum}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkEscrow(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
SELECT account_id, asset_id,
       (total_authority-unallocated-regional-in_transit-offline_issued)::STRING,
       offline_issued::STRING, folded_offline_issued::STRING
FROM escrow_authority_conservation
WHERE NOT conserved`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var account, asset, residual, materializedOffline, foldedOffline string
		if err := rows.Scan(&account, &asset, &residual, &materializedOffline, &foldedOffline); err != nil {
			return err
		}
		if err := report.add(EscrowNotConserved, SeverityP0, "", account, asset, residual,
			map[string]string{
				"account_id": account, "offline_issued": materializedOffline,
				"folded_offline_issued": foldedOffline,
			}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkPaymentAggregates(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
WITH folded AS (
  SELECT p.payment_id, p.asset_id,
         coalesce(sum(CASE WHEN e.effect_kind='HOLD' THEN e.amount_atoms ELSE 0 END),0) AS authorized,
         coalesce(sum(CASE WHEN e.effect_kind='CAPTURE' THEN e.amount_atoms ELSE 0 END),0) AS captured,
         coalesce(sum(CASE WHEN e.effect_kind='RELEASE' THEN e.amount_atoms
                           WHEN e.effect_kind='REVERSAL' AND original.effect_kind='HOLD'
                           THEN e.amount_atoms ELSE 0 END),0) AS released,
         coalesce(sum(CASE WHEN e.effect_kind='REFUND' THEN e.amount_atoms ELSE 0 END),0) AS refunded,
         coalesce(sum(CASE WHEN e.effect_kind='CHARGEBACK' THEN e.amount_atoms ELSE 0 END),0) AS charged_back,
         coalesce(sum(CASE WHEN e.effect_kind='FEE' THEN e.amount_atoms ELSE 0 END),0) AS fee,
         coalesce(sum(CASE WHEN e.effect_kind='TAX' THEN e.amount_atoms ELSE 0 END),0) AS tax,
         coalesce(sum(CASE WHEN e.effect_kind='CASHBACK' THEN e.amount_atoms ELSE 0 END),0) AS cashback
    FROM payment_operations AS p
    LEFT JOIN payment_effects AS e ON e.payment_id=p.payment_id
    LEFT JOIN payment_effects AS original
      ON original.payment_id=e.payment_id
     AND original.ledger_transaction_id=e.original_transaction_id
   GROUP BY p.payment_id, p.asset_id
), reversed AS (
  SELECT payment_id, coalesce(sum(cashback_reversed_atoms),0) AS cashback_reversed
    FROM payment_capture_financials GROUP BY payment_id
)
SELECT p.payment_id, p.asset_id,
       p.authorized_atoms::STRING, f.authorized::STRING,
       p.captured_atoms::STRING, f.captured::STRING,
       p.released_atoms::STRING, f.released::STRING,
       p.refunded_atoms::STRING, f.refunded::STRING,
       p.charged_back_atoms::STRING, f.charged_back::STRING,
       p.fee_atoms::STRING, f.fee::STRING,
       p.tax_atoms::STRING, f.tax::STRING,
       p.cashback_atoms::STRING, f.cashback::STRING,
       p.cashback_reversed_atoms::STRING, coalesce(r.cashback_reversed,0)::STRING
  FROM payment_operations AS p
  JOIN folded AS f USING (payment_id, asset_id)
  LEFT JOIN reversed AS r USING (payment_id)
 WHERE p.authorized_atoms <> f.authorized
    OR p.captured_atoms <> f.captured
    OR p.released_atoms <> f.released
    OR p.refunded_atoms <> f.refunded
    OR p.charged_back_atoms <> f.charged_back
    OR p.fee_atoms <> f.fee OR p.tax_atoms <> f.tax
    OR p.cashback_atoms <> f.cashback
    OR p.cashback_reversed_atoms <> coalesce(r.cashback_reversed,0)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var payment, asset string
		values := make([]string, 18)
		destinations := []any{&payment, &asset}
		for index := range values {
			destinations = append(destinations, &values[index])
		}
		if err := rows.Scan(destinations...); err != nil {
			rows.Close()
			return err
		}
		details := map[string]string{"payment_id": payment}
		labels := []string{"authorized_stored", "authorized_folded", "captured_stored", "captured_folded",
			"released_stored", "released_folded", "refunded_stored", "refunded_folded",
			"charged_back_stored", "charged_back_folded", "fee_stored", "fee_folded",
			"tax_stored", "tax_folded", "cashback_stored", "cashback_folded",
			"cashback_reversed_stored", "cashback_reversed_folded"}
		for index, label := range labels {
			details[label] = values[index]
		}
		if err := report.add(PaymentAggregateMismatch, SeverityP0, "", payment, asset, "0", details); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
SELECT e.payment_effect_id, p.asset_id
FROM payment_effects AS e
JOIN payment_operations AS p ON p.payment_id=e.payment_id
LEFT JOIN ledger_transactions AS t ON t.transaction_id=e.ledger_transaction_id
WHERE t.transaction_id IS NULL OR t.status <> 'POSTED'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var effect, asset string
		if err := rows.Scan(&effect, &asset); err != nil {
			rows.Close()
			return err
		}
		if err := report.add(PaymentEffectWithoutProof, SeverityP0, "", effect, asset, "0", nil); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
WITH cashback_facts AS (
  SELECT p.payment_id, p.asset_id, p.cashback_rule_atoms,
         coalesce(sum(CASE WHEN e.effect_kind='CASHBACK' THEN e.amount_atoms ELSE 0 END),0)
         - coalesce(sum(CASE WHEN e.effect_kind='REVERSAL' AND original.effect_kind='CASHBACK'
                             THEN e.amount_atoms ELSE 0 END),0) AS net_cashback
  FROM payment_operations AS p
  LEFT JOIN payment_effects AS e ON e.payment_id=p.payment_id
  LEFT JOIN payment_effects AS original
    ON original.payment_id=p.payment_id
   AND original.ledger_transaction_id=e.original_transaction_id
   AND original.effect_kind='CASHBACK'
  GROUP BY p.payment_id, p.asset_id, p.cashback_rule_atoms
)
SELECT payment_id, asset_id, (net_cashback-cashback_rule_atoms)::STRING
FROM cashback_facts
WHERE net_cashback > cashback_rule_atoms`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var payment, asset, excess string
		if err := rows.Scan(&payment, &asset, &excess); err != nil {
			return err
		}
		if err := report.add(CashbackRuleExceeded, SeverityP0, "", payment, asset, excess,
			map[string]string{"payment_id": payment}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkDurableProofs(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
SELECT scope, idempotency_key, operation_id
FROM idempotency_records AS i
WHERE state='SUCCEEDED' AND NOT EXISTS (
    SELECT 1 FROM ledger_transactions AS t
     WHERE t.transaction_id=i.ledger_transaction_id
       AND t.status='POSTED'
       AND t.operation_id=i.operation_id
       AND t.request_hash=i.request_hash
)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var scope, key, operation string
		if err := rows.Scan(&scope, &key, &operation); err != nil {
			rows.Close()
			return err
		}
		if err := report.add(SuccessWithoutProof, SeverityP0, "", operation, "", "0",
			map[string]string{"scope": scope, "idempotency_key": key}); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
SELECT event.event_id, event.topic FROM outbox_messages AS event
LEFT JOIN ledger_transactions AS parent
  ON parent.transaction_id=event.parent_transaction_id AND parent.status='POSTED'
WHERE event.topic='payment-events' AND parent.transaction_id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var event, topic string
		if err := rows.Scan(&event, &topic); err != nil {
			return err
		}
		if err := report.add(OutboxWithoutParent, SeverityP0, "", event, "", "0",
			map[string]string{"topic": topic}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *Checker) checkProtocolLag(ctx context.Context, tx pgx.Tx, report *Report) error {
	rows, err := tx.Query(ctx, `
SELECT transfer_id, asset_id, amount::STRING, source_region, destination_region
FROM escrow_transfers WHERE status='IN_TRANSIT'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var transfer, asset, amount, source, destination string
		if err := rows.Scan(&transfer, &asset, &amount, &source, &destination); err != nil {
			rows.Close()
			return err
		}
		if err := report.add(TransferPending, SeverityLag, "", transfer, asset, amount,
			map[string]string{"source_region": source, "destination_region": destination}); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
SELECT operation_id, rail, status
FROM external_attempts WHERE status IN ('IN_FLIGHT','UNKNOWN')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var operation, rail, status string
		if err := rows.Scan(&operation, &rail, &status); err != nil {
			rows.Close()
			return err
		}
		if err := report.add(ExternalUnknown, SeverityLag, "", operation, "", "0",
			map[string]string{"rail": rail, "status": status}); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = tx.Query(ctx, `
SELECT a.operation_id, a.rail, a.provider_reference
FROM external_attempts AS a
WHERE a.status='SUCCEEDED'
  AND NOT EXISTS (SELECT 1 FROM ledger_transactions AS t
                  WHERE t.operation_id=a.operation_id AND t.status='POSTED')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var operation, rail, reference string
		if err := rows.Scan(&operation, &rail, &reference); err != nil {
			return err
		}
		if err := report.add(SettlementUnmatched, SeverityLag, "", operation, "", "0",
			map[string]string{"rail": rail, "provider_reference": reference}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (r *Report) add(category SeverityCategory, severity Severity, book, effect, asset, amount string, details map[string]string) error {
	parsed, err := ledger.ParseAmount(amount)
	if err != nil {
		return fmt.Errorf("reconciliation %s amount %q: %w", category, amount, err)
	}
	if details == nil {
		details = map[string]string{}
	}
	r.Findings = append(r.Findings, Finding{
		Category: category, Severity: severity, BookID: book, EffectID: effect,
		AssetID: asset, Amount: parsed, Details: details,
	})
	return nil
}

func persistFindings(ctx context.Context, tx pgx.Tx, report Report) error {
	for _, finding := range report.Findings {
		details, err := json.Marshal(finding.Details)
		if err != nil {
			return err
		}
		status := "OPEN"
		if finding.Severity == SeverityLag {
			status = "EXPECTED_LAG"
		}
		breakID := stableBreakID(report.RunID, finding)
		var asset any
		if finding.AssetID != "" {
			asset = finding.AssetID
		}
		var effect any
		if finding.EffectID != "" {
			effect = finding.EffectID
		}
		_, err = tx.Exec(ctx, `
INSERT INTO reconciliation_breaks
 (break_id, run_id, category, effect_id, asset_id, amount_atoms, details, status)
VALUES ($1,$2,$3,$4,$5,$6,$7::JSONB,$8)`, breakID, report.RunID,
			string(finding.Category), effect, asset, finding.Amount.String(), string(details), status)
		if err != nil {
			return err
		}
	}
	return nil
}

func stableBreakID(runID string, finding Finding) string {
	details, _ := json.Marshal(finding.Details)
	digest := sha256.Sum256([]byte(fmt.Sprintf("reconciliation-break/v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		runID, finding.Category, finding.BookID, finding.EffectID, finding.AssetID,
		finding.Amount.String(), details)))
	return "break-v1-" + hex.EncodeToString(digest[:])
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		left := fmt.Sprintf("%s\x00%s\x00%s\x00%s", findings[i].Category, findings[i].BookID, findings[i].EffectID, findings[i].AssetID)
		right := fmt.Sprintf("%s\x00%s\x00%s\x00%s", findings[j].Category, findings[j].BookID, findings[j].EffectID, findings[j].AssetID)
		return left < right
	})
}

func loadReport(ctx context.Context, tx pgx.Tx, runID string) (Report, bool, error) {
	var status string
	var watermarksRaw, findingsRaw []byte
	err := tx.QueryRow(ctx, `
SELECT status, verified_book_watermarks, violations
FROM reconciliation_runs WHERE run_id=$1`, runID).Scan(&status, &watermarksRaw, &findingsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, false, nil
	}
	if err != nil {
		return Report{}, false, err
	}
	if status == "RUNNING" {
		return Report{}, false, errors.New("reconciliation: durable run is unexpectedly still RUNNING")
	}
	report := Report{RunID: runID, Status: status}
	if err := json.Unmarshal(watermarksRaw, &report.Watermarks); err != nil {
		return Report{}, false, err
	}
	if err := json.Unmarshal(findingsRaw, &report.Findings); err != nil {
		return Report{}, false, err
	}
	return report, true, nil
}
