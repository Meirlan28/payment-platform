package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/payment-platform/internal/escrow"
	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

type Service struct {
	transactions *store.Runner
	ledger       *ledger.Service
	idempotency  *idempotency.Service
	ids          ledger.IDGenerator
	claimLease   time.Duration
}

func NewService(
	transactions *store.Runner,
	journal *ledger.Service,
	idem *idempotency.Service,
	ids ledger.IDGenerator,
) *Service {
	return &Service{
		transactions: transactions,
		ledger:       journal,
		idempotency:  idem,
		ids:          ids,
		claimLease:   30 * time.Second,
	}
}

type HoldRequest struct {
	Scope                      string        `json:"scope"`
	IdempotencyKey             string        `json:"idempotency_key"`
	BookID                     string        `json:"book_id"`
	AssetID                    string        `json:"asset_id"`
	CustomerAvailableAccountID string        `json:"customer_available_account_id"`
	CustomerHeldAccountID      string        `json:"customer_held_account_id"`
	MerchantAccountID          string        `json:"merchant_account_id"`
	Amount                     ledger.Amount `json:"amount_atoms"`
	CashbackRuleMaximum        ledger.Amount `json:"cashback_rule_maximum_atoms"`
	PostingRuleVersion         string        `json:"posting_rule_version"`
	AuthorityRegion            string        `json:"authority_region,omitempty"`
}

type CaptureRequest struct {
	Scope                    string        `json:"scope"`
	IdempotencyKey           string        `json:"idempotency_key"`
	PaymentID                string        `json:"payment_id"`
	BookID                   string        `json:"book_id"`
	AssetID                  string        `json:"asset_id"`
	Amount                   ledger.Amount `json:"amount_atoms"`
	Fee                      ledger.Amount `json:"fee_atoms"`
	Tax                      ledger.Amount `json:"tax_atoms"`
	Cashback                 ledger.Amount `json:"cashback_atoms"`
	FeeAccountID             string        `json:"fee_account_id"`
	TaxAccountID             string        `json:"tax_account_id"`
	CashbackExpenseAccountID string        `json:"cashback_expense_account_id"`
	PostingRuleVersion       string        `json:"posting_rule_version"`
}

type ReleaseRequest struct {
	Scope              string        `json:"scope"`
	IdempotencyKey     string        `json:"idempotency_key"`
	PaymentID          string        `json:"payment_id"`
	BookID             string        `json:"book_id"`
	AssetID            string        `json:"asset_id"`
	Amount             ledger.Amount `json:"amount_atoms"`
	PostingRuleVersion string        `json:"posting_rule_version"`
}

type RefundRequest struct {
	Scope                        string        `json:"scope"`
	IdempotencyKey               string        `json:"idempotency_key"`
	PaymentID                    string        `json:"payment_id"`
	BookID                       string        `json:"book_id"`
	AssetID                      string        `json:"asset_id"`
	OriginalCaptureTransactionID string        `json:"original_capture_transaction_id"`
	MerchantDebitAccountID       string        `json:"merchant_debit_account_id"`
	Amount                       ledger.Amount `json:"amount_atoms"`
	PostingRuleVersion           string        `json:"posting_rule_version"`
}

type ChargebackRequest struct {
	Scope                        string        `json:"scope"`
	IdempotencyKey               string        `json:"idempotency_key"`
	PaymentID                    string        `json:"payment_id"`
	BookID                       string        `json:"book_id"`
	AssetID                      string        `json:"asset_id"`
	OriginalCaptureTransactionID string        `json:"original_capture_transaction_id"`
	MerchantReserveAccountID     string        `json:"merchant_reserve_account_id"`
	Amount                       ledger.Amount `json:"amount_atoms"`
	PostingRuleVersion           string        `json:"posting_rule_version"`
}

type Receipt struct {
	PaymentID string         `json:"payment_id"`
	State     State          `json:"state"`
	Amount    ledger.Amount  `json:"amount_atoms"`
	Version   int64          `json:"version"`
	Ledger    ledger.Receipt `json:"ledger"`
	Duplicate bool           `json:"duplicate"`
}

type executionIDs struct {
	OwnerToken    string
	OperationID   string
	EffectID      string
	TransactionID string
	OutboxEventID string
}

type snapshot struct {
	PaymentID                  string
	AssetID                    string
	AvailableAccountID         string
	HeldAccountID              string
	MerchantAccountID          string
	AuthorityRegion            string
	State                      State
	Authorized                 ledger.Amount
	Captured                   ledger.Amount
	Released                   ledger.Amount
	Refunded                   ledger.Amount
	ChargedBack                ledger.Amount
	Fee                        ledger.Amount
	Tax                        ledger.Amount
	Cashback                   ledger.Amount
	CashbackRule               ledger.Amount
	Version                    int64
	HoldID                     string
	AuthorizationTransactionID string
	HoldCaptured               ledger.Amount
	HoldReleased               ledger.Amount
	HoldVersion                int64
}

func (s *Service) Hold(ctx context.Context, request HoldRequest) (Receipt, error) {
	if request.Scope == "" || request.IdempotencyKey == "" || request.BookID == "" ||
		request.AssetID == "" || request.CustomerAvailableAccountID == "" ||
		request.CustomerHeldAccountID == "" || request.MerchantAccountID == "" ||
		request.PostingRuleVersion == "" || request.Amount.Sign() <= 0 ||
		request.CashbackRuleMaximum.Sign() < 0 {
		return Receipt{}, ErrInvalidRequest
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}
	paymentID, err := s.nextID(ctx, "payment_")
	if err != nil {
		return Receipt{}, err
	}
	holdID, err := s.nextID(ctx, "hold_")
	if err != nil {
		return Receipt{}, err
	}

	return s.execute(ctx, request.Scope+"/hold", request.IdempotencyKey, hash, "payment.held",
		func(ctx context.Context, tx pgx.Tx, ids executionIDs) (Receipt, error) {
			if request.AuthorityRegion != "" {
				if _, err := escrow.SpendInTx(ctx, tx, escrow.EffectRequest{
					EffectID: ids.EffectID, AccountID: request.CustomerAvailableAccountID,
					AssetID: request.AssetID, Region: request.AuthorityRegion, Amount: request.Amount,
				}); err != nil {
					return Receipt{}, err
				}
			}
			metadata, _ := json.Marshal(map[string]string{"payment_id": paymentID, "hold_id": holdID})
			journalReceipt, err := s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
				TransactionID:      ids.TransactionID,
				BookID:             request.BookID,
				OperationID:        ids.OperationID,
				EffectID:           ids.EffectID,
				Kind:               "HOLD",
				PostingRuleVersion: request.PostingRuleVersion,
				SchemaVersion:      1,
				RequestHash:        hash,
				Metadata:           metadata,
				Lines: []ledger.Line{
					{AccountID: request.CustomerAvailableAccountID, AssetID: request.AssetID, Side: ledger.Debit, AmountAtoms: request.Amount, Memo: "hold available"},
					{AccountID: request.CustomerHeldAccountID, AssetID: request.AssetID, Side: ledger.Credit, AmountAtoms: request.Amount, Memo: "hold reserved"},
				},
			})
			if err != nil {
				return Receipt{}, err
			}
			_, err = tx.Exec(ctx, `
INSERT INTO payment_operations (
    payment_id, idempotency_scope, idempotency_key, asset_id,
    customer_available_account_id, customer_held_account_id,
    merchant_account_id, authority_region, state, authorized_atoms, cashback_rule_atoms
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'HELD', $9, $10)`,
				paymentID, request.Scope+"/hold", request.IdempotencyKey, request.AssetID,
				request.CustomerAvailableAccountID, request.CustomerHeldAccountID,
				request.MerchantAccountID, nullableString(request.AuthorityRegion),
				request.Amount.String(), request.CashbackRuleMaximum.String())
			if err != nil {
				return Receipt{}, err
			}
			_, err = tx.Exec(ctx, `
INSERT INTO holds (
    hold_id, payment_id, authorization_transaction_id, authorization_atoms
) VALUES ($1, $2, $3, $4)`, holdID, paymentID, journalReceipt.TransactionID, request.Amount.String())
			if err != nil {
				return Receipt{}, err
			}
			if err := insertPaymentEffect(ctx, tx, ids.EffectID, paymentID, "HOLD", request.Amount, journalReceipt.TransactionID, nil); err != nil {
				return Receipt{}, err
			}
			return Receipt{PaymentID: paymentID, State: Held, Amount: request.Amount, Version: 0, Ledger: journalReceipt}, nil
		})
}

// Authorize reserves funds; for an internal wallet the financially meaningful
// authorization is a hold, so both names intentionally share one protocol.
func (s *Service) Authorize(ctx context.Context, request HoldRequest) (Receipt, error) {
	return s.Hold(ctx, request)
}

func (s *Service) Capture(ctx context.Context, request CaptureRequest) (Receipt, error) {
	if request.Scope == "" || request.IdempotencyKey == "" || request.PaymentID == "" ||
		request.BookID == "" || request.AssetID == "" || request.PostingRuleVersion == "" || request.Amount.Sign() <= 0 ||
		request.Fee.Sign() < 0 || request.Tax.Sign() < 0 || request.Cashback.Sign() < 0 {
		return Receipt{}, ErrInvalidRequest
	}
	charges, err := request.Fee.Add(request.Tax)
	if err != nil || charges.Cmp(request.Amount) > 0 {
		return Receipt{}, ErrInvalidRequest
	}
	merchantAmount, err := request.Amount.Sub(charges)
	if err != nil {
		return Receipt{}, err
	}
	if request.Fee.Sign() > 0 && request.FeeAccountID == "" ||
		request.Tax.Sign() > 0 && request.TaxAccountID == "" ||
		request.Cashback.Sign() > 0 && request.CashbackExpenseAccountID == "" {
		return Receipt{}, ErrInvalidRequest
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}
	return s.execute(ctx, request.Scope+"/capture", request.IdempotencyKey, hash, "payment.captured",
		func(ctx context.Context, tx pgx.Tx, ids executionIDs) (Receipt, error) {
			current, err := loadSnapshot(ctx, tx, request.Scope, request.PaymentID)
			if err != nil {
				return Receipt{}, err
			}
			if current.AssetID != request.AssetID {
				return Receipt{}, fmt.Errorf("%w: requested asset does not match payment", ErrInvalidRequest)
			}
			if current.State != Held && current.State != PartiallyCaptured {
				return Receipt{}, fmt.Errorf("%w: %s cannot capture", ErrInvalidTransition, current.State)
			}
			newCaptured, err := current.Captured.Add(request.Amount)
			if err != nil {
				return Receipt{}, err
			}
			newState, err := captureState(current.Authorized, newCaptured, current.Released)
			if err != nil {
				return Receipt{}, err
			}
			newCashback, err := current.Cashback.Add(request.Cashback)
			if err != nil || newCashback.Cmp(current.CashbackRule) > 0 {
				return Receipt{}, ErrCashbackRule
			}

			lines := []ledger.Line{{AccountID: current.HeldAccountID, AssetID: current.AssetID, Side: ledger.Debit, AmountAtoms: request.Amount, Memo: "capture hold"}}
			if merchantAmount.Sign() > 0 {
				lines = append(lines, ledger.Line{AccountID: current.MerchantAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: merchantAmount, Memo: "merchant payable"})
			}
			if request.Fee.Sign() > 0 {
				lines = append(lines, ledger.Line{AccountID: request.FeeAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Fee, Memo: "platform fee"})
			}
			if request.Tax.Sign() > 0 {
				lines = append(lines, ledger.Line{AccountID: request.TaxAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Tax, Memo: "tax withholding"})
			}
			metadata, _ := json.Marshal(map[string]string{"payment_id": request.PaymentID})
			reference := current.AuthorizationTransactionID
			journalReceipt, err := s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
				TransactionID: ids.TransactionID, BookID: request.BookID,
				OperationID: ids.OperationID, EffectID: ids.EffectID, Kind: "CAPTURE",
				ReferenceTransactionID: &reference,
				PostingRuleVersion:     request.PostingRuleVersion, SchemaVersion: 1,
				RequestHash: hash, Metadata: metadata, Lines: lines,
			})
			if err != nil {
				return Receipt{}, err
			}
			var cashbackReceipt ledger.Receipt
			if request.Cashback.Sign() > 0 {
				captureReference := journalReceipt.TransactionID
				cashbackReceipt, err = s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
					TransactionID:          ids.TransactionID + ":cashback",
					BookID:                 request.BookID,
					OperationID:            ids.OperationID + ":cashback",
					EffectID:               ids.EffectID + ":cashback",
					Kind:                   "CASHBACK",
					ReferenceTransactionID: &captureReference,
					PostingRuleVersion:     request.PostingRuleVersion,
					SchemaVersion:          1,
					RequestHash:            hash,
					Metadata:               metadata,
					Lines: []ledger.Line{
						{AccountID: request.CashbackExpenseAccountID, AssetID: current.AssetID, Side: ledger.Debit, AmountAtoms: request.Cashback, Memo: "cashback expense"},
						{AccountID: current.AvailableAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Cashback, Memo: "cashback payable"},
					},
				})
				if err != nil {
					return Receipt{}, err
				}
				if current.AuthorityRegion != "" {
					if _, err := escrow.ReturnInTx(ctx, tx, escrow.EffectRequest{
						EffectID: ids.EffectID + ":cashback", AccountID: current.AvailableAccountID,
						AssetID: current.AssetID, Region: current.AuthorityRegion, Amount: request.Cashback,
					}); err != nil {
						return Receipt{}, err
					}
				}
			}
			holdState := "PARTIALLY_CAPTURED"
			if newState == Captured {
				holdState = "CAPTURED"
			}
			if _, err = tx.Exec(ctx, `
UPDATE holds
SET captured_atoms=$2, state=$3, version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1`, request.PaymentID, newCaptured.String(), holdState); err != nil {
				return Receipt{}, err
			}
			newFee, err := current.Fee.Add(request.Fee)
			if err != nil {
				return Receipt{}, err
			}
			newTax, err := current.Tax.Add(request.Tax)
			if err != nil {
				return Receipt{}, err
			}
			newVersion := current.Version + 1
			if _, err = tx.Exec(ctx, `
UPDATE payment_operations
SET captured_atoms=$2, fee_atoms=$3, tax_atoms=$4, cashback_atoms=$5,
    state=$6, version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1`, request.PaymentID, newCaptured.String(), newFee.String(),
				newTax.String(), newCashback.String(), string(newState)); err != nil {
				return Receipt{}, err
			}
			if err := insertPaymentEffect(ctx, tx, ids.EffectID, request.PaymentID, "CAPTURE", request.Amount, journalReceipt.TransactionID, &reference); err != nil {
				return Receipt{}, err
			}
			// This is the immutable calculated cashback result for this capture.
			// CashbackRule on the payment remains only an authorization-time
			// aggregate ceiling and must never be used as repair ground truth.
			if _, err = tx.Exec(ctx, `
INSERT INTO payment_capture_financials (
    capture_transaction_id, payment_id, capture_effect_id, captured_atoms,
    expected_cashback_atoms
) VALUES ($1,$2,$3,$4,$5)`, journalReceipt.TransactionID, request.PaymentID,
				ids.EffectID, request.Amount.String(), request.Cashback.String()); err != nil {
				return Receipt{}, err
			}
			if request.Fee.Sign() > 0 {
				if err := insertPaymentEffect(ctx, tx, ids.EffectID+":fee", request.PaymentID, "FEE", request.Fee, journalReceipt.TransactionID, &journalReceipt.TransactionID); err != nil {
					return Receipt{}, err
				}
			}
			if request.Tax.Sign() > 0 {
				if err := insertPaymentEffect(ctx, tx, ids.EffectID+":tax", request.PaymentID, "TAX", request.Tax, journalReceipt.TransactionID, &journalReceipt.TransactionID); err != nil {
					return Receipt{}, err
				}
			}
			if request.Cashback.Sign() > 0 {
				if err := insertPaymentEffect(ctx, tx, ids.EffectID+":cashback", request.PaymentID, "CASHBACK", request.Cashback, cashbackReceipt.TransactionID, &journalReceipt.TransactionID); err != nil {
					return Receipt{}, err
				}
			}
			return Receipt{PaymentID: request.PaymentID, State: newState, Amount: request.Amount, Version: newVersion, Ledger: journalReceipt}, nil
		})
}

func (s *Service) Release(ctx context.Context, request ReleaseRequest) (Receipt, error) {
	return s.release(ctx, request, false)
}

func (s *Service) Reversal(ctx context.Context, request ReleaseRequest) (Receipt, error) {
	return s.release(ctx, request, true)
}

func (s *Service) release(ctx context.Context, request ReleaseRequest, reversal bool) (Receipt, error) {
	if request.Scope == "" || request.IdempotencyKey == "" || request.PaymentID == "" ||
		request.BookID == "" || request.AssetID == "" || request.PostingRuleVersion == "" || request.Amount.Sign() <= 0 {
		return Receipt{}, ErrInvalidRequest
	}
	hash, err := idempotency.RequestHash(struct {
		ReleaseRequest
		Reversal bool `json:"reversal"`
	}{request, reversal})
	if err != nil {
		return Receipt{}, err
	}
	kind, topic := "RELEASE", "payment.released"
	if reversal {
		kind, topic = "REVERSAL", "payment.reversed"
	}
	return s.execute(ctx, request.Scope+"/"+kind, request.IdempotencyKey, hash, topic,
		func(ctx context.Context, tx pgx.Tx, ids executionIDs) (Receipt, error) {
			current, err := loadSnapshot(ctx, tx, request.Scope, request.PaymentID)
			if err != nil {
				return Receipt{}, err
			}
			if current.AssetID != request.AssetID {
				return Receipt{}, fmt.Errorf("%w: requested asset does not match payment", ErrInvalidRequest)
			}
			if current.State != Held && current.State != PartiallyCaptured {
				return Receipt{}, fmt.Errorf("%w: %s cannot release", ErrInvalidTransition, current.State)
			}
			if reversal && !current.Captured.IsZero() {
				return Receipt{}, fmt.Errorf("%w: a reversal requires zero captured principal", ErrInvalidTransition)
			}
			newReleased, err := current.Released.Add(request.Amount)
			if err != nil {
				return Receipt{}, err
			}
			used, err := current.Captured.Add(newReleased)
			if err != nil || used.Cmp(current.Authorized) > 0 || reversal && used.Cmp(current.Authorized) != 0 {
				return Receipt{}, ErrOverCapture
			}
			newState := Held
			holdState := "ACTIVE"
			if used.Cmp(current.Authorized) == 0 {
				if current.Captured.IsZero() {
					newState, holdState = Reversed, "RELEASED"
				} else {
					newState, holdState = Captured, "CAPTURED"
				}
			} else if current.Captured.Sign() > 0 {
				newState, holdState = PartiallyCaptured, "PARTIALLY_CAPTURED"
			}
			if current.AuthorityRegion != "" {
				if _, err := escrow.ReturnInTx(ctx, tx, escrow.EffectRequest{
					EffectID: ids.EffectID, AccountID: current.AvailableAccountID,
					AssetID: current.AssetID, Region: current.AuthorityRegion, Amount: request.Amount,
				}); err != nil {
					return Receipt{}, err
				}
			}
			reference := current.AuthorizationTransactionID
			metadata, _ := json.Marshal(map[string]string{"payment_id": request.PaymentID})
			journalReceipt, err := s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
				TransactionID: ids.TransactionID, BookID: request.BookID,
				OperationID: ids.OperationID, EffectID: ids.EffectID, Kind: kind,
				ReferenceTransactionID: &reference,
				PostingRuleVersion:     request.PostingRuleVersion, SchemaVersion: 1,
				RequestHash: hash, Metadata: metadata,
				Lines: []ledger.Line{
					{AccountID: current.HeldAccountID, AssetID: current.AssetID, Side: ledger.Debit, AmountAtoms: request.Amount, Memo: "release hold"},
					{AccountID: current.AvailableAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Amount, Memo: "restore available"},
				},
			})
			if err != nil {
				return Receipt{}, err
			}
			if _, err = tx.Exec(ctx, `
UPDATE holds SET released_atoms=$2, state=$3, version=version+1,
                 updated_at=transaction_timestamp()
WHERE payment_id=$1`, request.PaymentID, newReleased.String(), holdState); err != nil {
				return Receipt{}, err
			}
			newVersion := current.Version + 1
			if _, err = tx.Exec(ctx, `
UPDATE payment_operations SET released_atoms=$2, state=$3, version=version+1,
                              updated_at=transaction_timestamp()
WHERE payment_id=$1`, request.PaymentID, newReleased.String(), string(newState)); err != nil {
				return Receipt{}, err
			}
			if err := insertPaymentEffect(ctx, tx, ids.EffectID, request.PaymentID, kind, request.Amount, journalReceipt.TransactionID, &reference); err != nil {
				return Receipt{}, err
			}
			return Receipt{PaymentID: request.PaymentID, State: newState, Amount: request.Amount, Version: newVersion, Ledger: journalReceipt}, nil
		})
}

func (s *Service) Refund(ctx context.Context, request RefundRequest) (Receipt, error) {
	if request.Scope == "" || request.IdempotencyKey == "" || request.PaymentID == "" ||
		request.BookID == "" || request.AssetID == "" || request.OriginalCaptureTransactionID == "" ||
		request.MerchantDebitAccountID == "" || request.PostingRuleVersion == "" ||
		request.Amount.Sign() <= 0 {
		return Receipt{}, ErrInvalidRequest
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}
	return s.execute(ctx, request.Scope+"/refund", request.IdempotencyKey, hash, "payment.refunded",
		func(ctx context.Context, tx pgx.Tx, ids executionIDs) (Receipt, error) {
			current, err := loadSnapshot(ctx, tx, request.Scope, request.PaymentID)
			if err != nil {
				return Receipt{}, err
			}
			if current.AssetID != request.AssetID {
				return Receipt{}, fmt.Errorf("%w: requested asset does not match payment", ErrInvalidRequest)
			}
			if current.State == Refunded || current.State == ChargedBack {
				return Receipt{}, ErrOverRefund
			}
			if current.State != Captured && current.State != Settled && current.State != PartiallyRefunded && current.State != Disputed {
				return Receipt{}, fmt.Errorf("%w: %s cannot refund", ErrInvalidTransition, current.State)
			}
			folded, err := advanceCaptureReturn(ctx, tx, request.PaymentID,
				request.OriginalCaptureTransactionID, "REFUND", request.Amount)
			if err != nil {
				return Receipt{}, err
			}
			newState, err := refundState(current.Captured, folded.Refunded, folded.ChargedBack)
			if err != nil {
				return Receipt{}, err
			}
			if current.AuthorityRegion != "" {
				if _, err := escrow.ReturnInTx(ctx, tx, escrow.EffectRequest{
					EffectID: ids.EffectID, AccountID: current.AvailableAccountID,
					AssetID: current.AssetID, Region: current.AuthorityRegion, Amount: request.Amount,
				}); err != nil {
					return Receipt{}, err
				}
			}
			reference := request.OriginalCaptureTransactionID
			metadata, _ := json.Marshal(map[string]string{"payment_id": request.PaymentID})
			journalReceipt, err := s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
				TransactionID: ids.TransactionID, BookID: request.BookID,
				OperationID: ids.OperationID, EffectID: ids.EffectID, Kind: "REFUND",
				ReferenceTransactionID: &reference,
				PostingRuleVersion:     request.PostingRuleVersion, SchemaVersion: 1,
				RequestHash: hash, Metadata: metadata,
				Lines: []ledger.Line{
					{AccountID: request.MerchantDebitAccountID, AssetID: current.AssetID, Side: ledger.Debit, AmountAtoms: request.Amount, Memo: "refund funding"},
					{AccountID: current.AvailableAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Amount, Memo: "customer refund"},
				},
			})
			if err != nil {
				return Receipt{}, err
			}
			newVersion := current.Version + 1
			tag, err := tx.Exec(ctx, `
UPDATE payment_operations
SET refunded_atoms=$2, charged_back_atoms=$3, state=$4,
    version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1 AND version=$5
  AND refunded_atoms=$6 AND charged_back_atoms=$7`, request.PaymentID,
				folded.Refunded.String(), folded.ChargedBack.String(), string(newState),
				current.Version, current.Refunded.String(), current.ChargedBack.String())
			if err != nil {
				return Receipt{}, err
			}
			if tag.RowsAffected() != 1 {
				return Receipt{}, fmt.Errorf("%w: payment return projection CAS failed", ErrInvalidTransition)
			}
			if err := insertPaymentEffect(ctx, tx, ids.EffectID, request.PaymentID, "REFUND", request.Amount, journalReceipt.TransactionID, &reference); err != nil {
				return Receipt{}, err
			}
			return Receipt{PaymentID: request.PaymentID, State: newState, Amount: request.Amount, Version: newVersion, Ledger: journalReceipt}, nil
		})
}

func (s *Service) Chargeback(ctx context.Context, request ChargebackRequest) (Receipt, error) {
	if request.Scope == "" || request.IdempotencyKey == "" || request.PaymentID == "" ||
		request.BookID == "" || request.AssetID == "" || request.OriginalCaptureTransactionID == "" ||
		request.MerchantReserveAccountID == "" || request.PostingRuleVersion == "" ||
		request.Amount.Sign() <= 0 {
		return Receipt{}, ErrInvalidRequest
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}
	return s.execute(ctx, request.Scope+"/chargeback", request.IdempotencyKey, hash, "payment.charged_back",
		func(ctx context.Context, tx pgx.Tx, ids executionIDs) (Receipt, error) {
			current, err := loadSnapshot(ctx, tx, request.Scope, request.PaymentID)
			if err != nil {
				return Receipt{}, err
			}
			if current.AssetID != request.AssetID {
				return Receipt{}, fmt.Errorf("%w: requested asset does not match payment", ErrInvalidRequest)
			}
			if current.State == Refunded || current.State == ChargedBack {
				return Receipt{}, ErrOverRefund
			}
			if current.State != Captured && current.State != Settled && current.State != PartiallyRefunded && current.State != Disputed {
				return Receipt{}, fmt.Errorf("%w: %s cannot charge back", ErrInvalidTransition, current.State)
			}
			folded, err := advanceCaptureReturn(ctx, tx, request.PaymentID,
				request.OriginalCaptureTransactionID, "CHARGEBACK", request.Amount)
			if err != nil {
				return Receipt{}, err
			}
			newState, err := refundState(current.Captured, folded.Refunded, folded.ChargedBack)
			if err != nil {
				return Receipt{}, err
			}
			if current.AuthorityRegion != "" {
				if _, err := escrow.ReturnInTx(ctx, tx, escrow.EffectRequest{
					EffectID: ids.EffectID, AccountID: current.AvailableAccountID,
					AssetID: current.AssetID, Region: current.AuthorityRegion, Amount: request.Amount,
				}); err != nil {
					return Receipt{}, err
				}
			}
			reference := request.OriginalCaptureTransactionID
			metadata, _ := json.Marshal(map[string]string{"payment_id": request.PaymentID})
			journalReceipt, err := s.ledger.PostInTx(ctx, tx, ledger.PostRequest{
				TransactionID: ids.TransactionID, BookID: request.BookID,
				OperationID: ids.OperationID, EffectID: ids.EffectID, Kind: "CHARGEBACK",
				ReferenceTransactionID: &reference,
				PostingRuleVersion:     request.PostingRuleVersion, SchemaVersion: 1,
				RequestHash: hash, Metadata: metadata,
				Lines: []ledger.Line{
					{AccountID: request.MerchantReserveAccountID, AssetID: current.AssetID, Side: ledger.Debit, AmountAtoms: request.Amount, Memo: "chargeback funding"},
					{AccountID: current.AvailableAccountID, AssetID: current.AssetID, Side: ledger.Credit, AmountAtoms: request.Amount, Memo: "provisional customer credit"},
				},
			})
			if err != nil {
				return Receipt{}, err
			}

			tag, err := tx.Exec(ctx, `
UPDATE payment_operations
SET refunded_atoms=$2, charged_back_atoms=$3, state=$4,
    version=version+1, updated_at=transaction_timestamp()
WHERE payment_id=$1 AND version=$5
  AND refunded_atoms=$6 AND charged_back_atoms=$7`, request.PaymentID,
				folded.Refunded.String(), folded.ChargedBack.String(), string(newState),
				current.Version, current.Refunded.String(), current.ChargedBack.String())
			if err != nil {
				return Receipt{}, err
			}
			if tag.RowsAffected() != 1 {
				return Receipt{}, fmt.Errorf("%w: payment return projection CAS failed", ErrInvalidTransition)
			}
			newVersion := current.Version + 1
			if err := insertPaymentEffect(ctx, tx, ids.EffectID, request.PaymentID, "CHARGEBACK", request.Amount, journalReceipt.TransactionID, &reference); err != nil {
				return Receipt{}, err
			}
			return Receipt{PaymentID: request.PaymentID, State: newState, Amount: request.Amount, Version: newVersion, Ledger: journalReceipt}, nil
		})
}

// GetForScope returns a payment only to the principal scope that created the
// original hold.  The exact equality predicate is deliberate: payment IDs are
// globally unique locators, not authorization credentials.
func (s *Service) GetForScope(ctx context.Context, scope, paymentID string) (Receipt, error) {
	if scope == "" || paymentID == "" {
		return Receipt{}, ErrInvalidRequest
	}
	var result Receipt
	err := s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		var state, amount string
		err := tx.QueryRow(ctx, `
SELECT payment_id, state, authorized_atoms::STRING, version
FROM payment_operations
WHERE payment_id=$1 AND idempotency_scope=$2`, paymentID, scope+"/hold").Scan(
			&result.PaymentID, &state, &amount, &result.Version)
		if err != nil {
			return err
		}
		result.State = State(state)
		result.Amount, err = ledger.ParseAmount(amount)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Receipt{}, ErrPaymentNotFound
	}
	return result, err
}

func (s *Service) execute(
	ctx context.Context,
	scope, key string,
	requestHash [32]byte,
	topic string,
	operation func(context.Context, pgx.Tx, executionIDs) (Receipt, error),
) (Receipt, error) {
	if s == nil || s.transactions == nil || s.ledger == nil || s.idempotency == nil || s.ids == nil {
		return Receipt{}, errors.New("payment: service is not fully configured")
	}
	ids, err := s.executionIDs(ctx)
	if err != nil {
		return Receipt{}, err
	}
	var result Receipt
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		claim, err := s.idempotency.Claim(ctx, tx, idempotency.ClaimRequest{
			Scope: scope, Key: key, RequestHash: requestHash,
			OwnerToken: ids.OwnerToken, OperationID: ids.OperationID,
			LeaseDuration: s.claimLease,
		})
		if err != nil {
			return err
		}
		if claim.Cached {
			if claim.State == idempotency.Failed {
				return fmt.Errorf("payment: cached terminal failure: %s", stringValue(claim.FailureCode))
			}
			if err := json.Unmarshal(claim.ResponsePayload, &result); err != nil {
				return err
			}
			result.Duplicate = true
			result.Ledger.Duplicate = true
			return nil
		}
		result, err = operation(ctx, tx, ids)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		canonical, err := ledger.CanonicalJSON(payload)
		if err != nil {
			return err
		}
		headers, err := json.Marshal(map[string]string{"event_type": topic})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO outbox_messages (
    event_id, topic, message_key, payload, headers, aggregate_id,
    aggregate_version, parent_transaction_id
) VALUES ($1, 'payment-events', $2, $3, $4::JSONB, $5, $6, $7)`,
			ids.OutboxEventID, []byte(result.PaymentID), canonical, string(headers),
			result.PaymentID, result.Version, result.Ledger.TransactionID)
		if err != nil {
			return err
		}
		return s.idempotency.Complete(ctx, tx, scope, key, ids.OwnerToken,
			result.Ledger.TransactionID, 200, result)
	})
	return result, err
}

func (s *Service) executionIDs(ctx context.Context) (executionIDs, error) {
	var result executionIDs
	var err error
	if result.OwnerToken, err = s.nextID(ctx, "owner_"); err != nil {
		return result, err
	}
	if result.OperationID, err = s.nextID(ctx, "operation_"); err != nil {
		return result, err
	}
	if result.EffectID, err = s.nextID(ctx, "effect_"); err != nil {
		return result, err
	}
	if result.TransactionID, err = s.nextID(ctx, "transaction_"); err != nil {
		return result, err
	}
	if result.OutboxEventID, err = s.nextID(ctx, "event_"); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) nextID(ctx context.Context, prefix string) (string, error) {
	if s == nil || s.ids == nil {
		return "", errors.New("payment: durable ID generator is not configured")
	}
	id, err := s.ids.Next(ctx)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("payment: ID generator returned an empty id")
	}
	return prefix + id, nil
}

func loadSnapshot(ctx context.Context, tx pgx.Tx, scope, paymentID string) (snapshot, error) {
	var result snapshot
	var state string
	var amounts [11]string
	err := tx.QueryRow(ctx, `
SELECT payment.payment_id, payment.asset_id,
       payment.customer_available_account_id, payment.customer_held_account_id,
       payment.merchant_account_id, coalesce(payment.authority_region, ''), payment.state,
       payment.authorized_atoms::STRING, payment.captured_atoms::STRING,
       payment.released_atoms::STRING, payment.refunded_atoms::STRING,
       payment.charged_back_atoms::STRING, payment.fee_atoms::STRING,
       payment.tax_atoms::STRING, payment.cashback_atoms::STRING,
       payment.cashback_rule_atoms::STRING, payment.version,
       hold.hold_id, hold.authorization_transaction_id,
       hold.captured_atoms::STRING, hold.released_atoms::STRING, hold.version
FROM payment_operations AS payment
JOIN holds AS hold ON hold.payment_id=payment.payment_id
WHERE payment.payment_id=$1 AND payment.idempotency_scope=$2
FOR UPDATE`, paymentID, scope+"/hold").Scan(
		&result.PaymentID, &result.AssetID, &result.AvailableAccountID,
		&result.HeldAccountID, &result.MerchantAccountID, &result.AuthorityRegion, &state,
		&amounts[0], &amounts[1], &amounts[2], &amounts[3], &amounts[4],
		&amounts[5], &amounts[6], &amounts[7], &amounts[8], &result.Version,
		&result.HoldID, &result.AuthorizationTransactionID,
		&amounts[9], &amounts[10], &result.HoldVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot{}, ErrPaymentNotFound
	}
	if err != nil {
		return snapshot{}, err
	}
	result.State = State(state)
	targets := []*ledger.Amount{
		&result.Authorized, &result.Captured, &result.Released, &result.Refunded,
		&result.ChargedBack, &result.Fee, &result.Tax, &result.Cashback,
		&result.CashbackRule, &result.HoldCaptured, &result.HoldReleased,
	}
	for index, target := range targets {
		parsed, err := ledger.ParseAmount(amounts[index])
		if err != nil {
			return snapshot{}, err
		}
		*target = parsed
	}
	return result, nil
}

func insertPaymentEffect(
	ctx context.Context, tx pgx.Tx, effectID, paymentID, kind string,
	amount ledger.Amount, transactionID string, original *string,
) error {
	var reference any
	if original != nil {
		reference = *original
	}
	_, err := tx.Exec(ctx, `
INSERT INTO payment_effects (
    payment_effect_id, payment_id, effect_kind, amount_atoms,
    ledger_transaction_id, original_transaction_id
) VALUES ($1, $2, $3, $4, $5, $6)`,
		effectID, paymentID, kind, amount.String(), transactionID, reference)
	return err
}

func validateCaptureReference(ctx context.Context, tx pgx.Tx, paymentID, transactionID string) error {
	var exists bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM payment_effects
    WHERE payment_id=$1 AND ledger_transaction_id=$2 AND effect_kind='CAPTURE'
)`, paymentID, transactionID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: capture reference does not belong to payment", ErrInvalidRequest)
	}
	return nil
}

type captureReturnFold struct {
	Refunded    ledger.Amount
	ChargedBack ledger.Amount
}

// advanceCaptureReturn is the per-capture authority check and aggregate fold.
// The conditional UPDATE is the safety decision; the later fold only projects
// already-bounded capture rows onto payment_operations.
func advanceCaptureReturn(
	ctx context.Context,
	tx pgx.Tx,
	paymentID, captureTransactionID, kind string,
	amount ledger.Amount,
) (captureReturnFold, error) {
	if tx == nil || paymentID == "" || captureTransactionID == "" || amount.Sign() <= 0 ||
		(kind != "REFUND" && kind != "CHARGEBACK") {
		return captureReturnFold{}, ErrInvalidRequest
	}
	var statement string
	switch kind {
	case "REFUND":
		statement = `
UPDATE payment_capture_financials
SET refunded_atoms=refunded_atoms+$3, version=version+1,
    updated_at=transaction_timestamp()
WHERE payment_id=$1 AND capture_transaction_id=$2
  AND refunded_atoms+charged_back_atoms+$3 <= captured_atoms`
	case "CHARGEBACK":
		statement = `
UPDATE payment_capture_financials
SET charged_back_atoms=charged_back_atoms+$3, version=version+1,
    updated_at=transaction_timestamp()
WHERE payment_id=$1 AND capture_transaction_id=$2
  AND refunded_atoms+charged_back_atoms+$3 <= captured_atoms`
	}
	tag, err := tx.Exec(ctx, statement, paymentID, captureTransactionID, amount.String())
	if err != nil {
		return captureReturnFold{}, err
	}
	if tag.RowsAffected() != 1 {
		var exists bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (
    SELECT 1 FROM payment_capture_financials
    WHERE payment_id=$1 AND capture_transaction_id=$2
)`, paymentID, captureTransactionID).Scan(&exists); err != nil {
			return captureReturnFold{}, err
		}
		if !exists {
			return captureReturnFold{}, fmt.Errorf("%w: capture reference does not belong to payment", ErrInvalidRequest)
		}
		return captureReturnFold{}, ErrOverRefund
	}
	var refundedText, chargedBackText string
	if err := tx.QueryRow(ctx, `
SELECT coalesce(sum(refunded_atoms),0)::STRING,
       coalesce(sum(charged_back_atoms),0)::STRING
FROM payment_capture_financials
WHERE payment_id=$1`, paymentID).Scan(&refundedText, &chargedBackText); err != nil {
		return captureReturnFold{}, err
	}
	result := captureReturnFold{}
	if result.Refunded, err = ledger.ParseAmount(refundedText); err != nil {
		return captureReturnFold{}, err
	}
	if result.ChargedBack, err = ledger.ParseAmount(chargedBackText); err != nil {
		return captureReturnFold{}, err
	}
	return result, nil
}

func stringValue(value *string) string {
	if value == nil {
		return "unknown"
	}
	return *value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
