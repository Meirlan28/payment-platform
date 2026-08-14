// Package fx implements immutable, single-use quotes. USD and EUR legs are
// independently double-entry balanced; currencies are never netted together.
package fx

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/example/payment-platform/internal/idempotency"
	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
)

type RoundingRule string

const (
	Floor    RoundingRule = "FLOOR"
	Ceiling  RoundingRule = "CEILING"
	HalfEven RoundingRule = "HALF_EVEN"
)

var (
	ErrInvalidQuote  = errors.New("fx: invalid quote")
	ErrQuoteNotFound = errors.New("fx: quote not found")
	ErrQuoteExpired  = errors.New("fx: quote expired")
	ErrQuoteConsumed = errors.New("fx: quote already consumed by a different effect")
)

type Quote struct {
	QuoteID         string
	BaseAssetID     string
	QuoteAssetID    string
	RateNumerator   ledger.Amount
	RateDenominator ledger.Amount
	BaseAmount      ledger.Amount
	QuoteAmount     ledger.Amount
	RoundingRule    RoundingRule
	ExpiresAt       time.Time
}

type CreateQuoteRequest struct {
	BaseAssetID     string
	QuoteAssetID    string
	RateNumerator   ledger.Amount
	RateDenominator ledger.Amount
	BaseAmount      ledger.Amount
	RoundingRule    RoundingRule
	ExpiresAt       time.Time
}

type ExchangeRequest struct {
	Scope                  string
	IdempotencyKey         string
	QuoteID                string
	BookID                 string
	BaseDebitAccountID     string
	BasePositionAccountID  string
	QuotePositionAccountID string
	QuoteCreditAccountID   string
	PostingRuleVersion     string
}

type Receipt struct {
	QuoteID     string         `json:"quote_id"`
	BaseAmount  ledger.Amount  `json:"base_amount_atoms"`
	QuoteAmount ledger.Amount  `json:"quote_amount_atoms"`
	Ledger      ledger.Receipt `json:"ledger"`
	Duplicate   bool           `json:"duplicate"`
}

type Service struct {
	transactions *store.Runner
	journal      *ledger.Service
	idem         *idempotency.Service
	ids          ledger.IDGenerator
	claimLease   time.Duration
}

func NewService(transactions *store.Runner, journal *ledger.Service, idem *idempotency.Service, ids ledger.IDGenerator) *Service {
	return &Service{transactions: transactions, journal: journal, idem: idem, ids: ids, claimLease: 30 * time.Second}
}

func Convert(base, numerator, denominator ledger.Amount, rule RoundingRule) (ledger.Amount, error) {
	if base.Sign() <= 0 || numerator.Sign() <= 0 || denominator.Sign() <= 0 ||
		(rule != Floor && rule != Ceiling && rule != HalfEven) {
		return ledger.Amount{}, ErrInvalidQuote
	}
	baseInt, ok := new(big.Int).SetString(base.String(), 10)
	if !ok {
		return ledger.Amount{}, ErrInvalidQuote
	}
	numeratorInt, _ := new(big.Int).SetString(numerator.String(), 10)
	denominatorInt, _ := new(big.Int).SetString(denominator.String(), 10)
	product := new(big.Int).Mul(baseInt, numeratorInt)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, denominatorInt, remainder)

	switch rule {
	case Ceiling:
		if remainder.Sign() != 0 {
			quotient.Add(quotient, big.NewInt(1))
		}
	case HalfEven:
		twiceRemainder := new(big.Int).Lsh(new(big.Int).Set(remainder), 1)
		comparison := twiceRemainder.Cmp(denominatorInt)
		if comparison > 0 || comparison == 0 && quotient.Bit(0) == 1 {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	return ledger.ParseAmount(quotient.String())
}

func (s *Service) CreateQuote(ctx context.Context, request CreateQuoteRequest) (Quote, error) {
	if s == nil || s.transactions == nil || s.ids == nil || request.BaseAssetID == "" ||
		request.QuoteAssetID == "" || request.BaseAssetID == request.QuoteAssetID ||
		request.ExpiresAt.IsZero() {
		return Quote{}, ErrInvalidQuote
	}
	quoteAmount, err := Convert(request.BaseAmount, request.RateNumerator, request.RateDenominator, request.RoundingRule)
	if err != nil || quoteAmount.Sign() <= 0 {
		return Quote{}, ErrInvalidQuote
	}
	id, err := s.ids.Next(ctx)
	if err != nil {
		return Quote{}, err
	}
	if id == "" {
		return Quote{}, errors.New("fx: ID generator returned empty id")
	}
	quote := Quote{
		QuoteID:         "quote_" + id,
		BaseAssetID:     request.BaseAssetID,
		QuoteAssetID:    request.QuoteAssetID,
		RateNumerator:   request.RateNumerator,
		RateDenominator: request.RateDenominator,
		BaseAmount:      request.BaseAmount,
		QuoteAmount:     quoteAmount,
		RoundingRule:    request.RoundingRule,
		ExpiresAt:       request.ExpiresAt,
	}
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO fx_quotes (
    quote_id, base_asset_id, quote_asset_id, rate_numerator, rate_denominator,
    base_amount_atoms, quote_amount_atoms, rounding_rule, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			quote.QuoteID, quote.BaseAssetID, quote.QuoteAssetID,
			quote.RateNumerator.String(), quote.RateDenominator.String(),
			quote.BaseAmount.String(), quote.QuoteAmount.String(),
			string(quote.RoundingRule), quote.ExpiresAt)
		return err
	})
	return quote, err
}

func (s *Service) Exchange(ctx context.Context, request ExchangeRequest) (Receipt, error) {
	if s == nil || s.transactions == nil || s.journal == nil || s.idem == nil || s.ids == nil ||
		request.Scope == "" || request.IdempotencyKey == "" || request.QuoteID == "" ||
		request.BookID == "" || request.BaseDebitAccountID == "" ||
		request.BasePositionAccountID == "" || request.QuotePositionAccountID == "" ||
		request.QuoteCreditAccountID == "" || request.PostingRuleVersion == "" {
		return Receipt{}, ErrInvalidQuote
	}
	hash, err := idempotency.RequestHash(request)
	if err != nil {
		return Receipt{}, err
	}
	owner, err := s.nextID(ctx, "owner_")
	if err != nil {
		return Receipt{}, err
	}
	operationID, err := s.nextID(ctx, "operation_")
	if err != nil {
		return Receipt{}, err
	}
	effectID, err := s.nextID(ctx, "effect_")
	if err != nil {
		return Receipt{}, err
	}
	transactionID, err := s.nextID(ctx, "transaction_")
	if err != nil {
		return Receipt{}, err
	}
	eventID, err := s.nextID(ctx, "event_")
	if err != nil {
		return Receipt{}, err
	}

	var result Receipt
	err = s.transactions.RunSerializable(ctx, func(tx pgx.Tx) error {
		claim, err := s.idem.Claim(ctx, tx, idempotency.ClaimRequest{
			Scope: request.Scope + "/fx", Key: request.IdempotencyKey,
			RequestHash: hash, OwnerToken: owner, OperationID: operationID,
			LeaseDuration: s.claimLease,
		})
		if err != nil {
			return err
		}
		if claim.Cached {
			if claim.State != idempotency.Succeeded {
				return errors.New("fx: cached terminal failure")
			}
			if err := json.Unmarshal(claim.ResponsePayload, &result); err != nil {
				return err
			}
			result.Duplicate = true
			result.Ledger.Duplicate = true
			return nil
		}

		quote, expired, err := loadQuoteForUpdate(ctx, tx, request.QuoteID)
		if err != nil {
			return err
		}
		var consumedEffect string
		err = tx.QueryRow(ctx, `SELECT effect_id FROM fx_quote_consumptions WHERE quote_id=$1`, request.QuoteID).Scan(&consumedEffect)
		if err == nil {
			if consumedEffect != effectID {
				return ErrQuoteConsumed
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if expired {
			return ErrQuoteExpired
		}

		metadata, _ := json.Marshal(map[string]string{"quote_id": quote.QuoteID})
		journalReceipt, err := s.journal.PostInTx(ctx, tx, ledger.PostRequest{
			TransactionID: transactionID, BookID: request.BookID,
			OperationID: operationID, EffectID: effectID, Kind: "FX",
			PostingRuleVersion: request.PostingRuleVersion, SchemaVersion: 1,
			RequestHash: hash, Metadata: metadata,
			Lines: []ledger.Line{
				{AccountID: request.BaseDebitAccountID, AssetID: quote.BaseAssetID, Side: ledger.Debit, AmountAtoms: quote.BaseAmount, Memo: "FX base debit"},
				{AccountID: request.BasePositionAccountID, AssetID: quote.BaseAssetID, Side: ledger.Credit, AmountAtoms: quote.BaseAmount, Memo: "FX base position"},
				{AccountID: request.QuotePositionAccountID, AssetID: quote.QuoteAssetID, Side: ledger.Debit, AmountAtoms: quote.QuoteAmount, Memo: "FX quote position"},
				{AccountID: request.QuoteCreditAccountID, AssetID: quote.QuoteAssetID, Side: ledger.Credit, AmountAtoms: quote.QuoteAmount, Memo: "FX quote credit"},
			},
		})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO fx_quote_consumptions (quote_id, effect_id, ledger_transaction_id)
VALUES ($1, $2, $3)`, quote.QuoteID, effectID, journalReceipt.TransactionID)
		if err != nil {
			return err
		}
		result = Receipt{QuoteID: quote.QuoteID, BaseAmount: quote.BaseAmount, QuoteAmount: quote.QuoteAmount, Ledger: journalReceipt}
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		headers, _ := json.Marshal(map[string]string{"event_type": "fx.exchanged"})
		_, err = tx.Exec(ctx, `
INSERT INTO outbox_messages (
    event_id, topic, message_key, payload, headers, aggregate_id,
    aggregate_version, parent_transaction_id
) VALUES ($1, 'payment-events', $2, $3, $4::JSONB, $5, 0, $6)`,
			eventID, []byte(quote.QuoteID), payload, string(headers),
			quote.QuoteID, journalReceipt.TransactionID)
		if err != nil {
			return err
		}
		return s.idem.Complete(ctx, tx, request.Scope+"/fx", request.IdempotencyKey,
			owner, journalReceipt.TransactionID, 200, result)
	})
	return result, err
}

func loadQuoteForUpdate(ctx context.Context, tx pgx.Tx, quoteID string) (Quote, bool, error) {
	var result Quote
	var numerator, denominator, base, quote, rounding string
	var expired bool
	err := tx.QueryRow(ctx, `
SELECT quote_id, base_asset_id, quote_asset_id,
       rate_numerator::STRING, rate_denominator::STRING,
       base_amount_atoms::STRING, quote_amount_atoms::STRING,
       rounding_rule, expires_at, expires_at <= transaction_timestamp()
FROM fx_quotes WHERE quote_id=$1 FOR UPDATE`, quoteID).Scan(
		&result.QuoteID, &result.BaseAssetID, &result.QuoteAssetID,
		&numerator, &denominator, &base, &quote, &rounding,
		&result.ExpiresAt, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return Quote{}, false, ErrQuoteNotFound
	}
	if err != nil {
		return Quote{}, false, err
	}
	if result.RateNumerator, err = ledger.ParseAmount(numerator); err != nil {
		return Quote{}, false, err
	}
	if result.RateDenominator, err = ledger.ParseAmount(denominator); err != nil {
		return Quote{}, false, err
	}
	if result.BaseAmount, err = ledger.ParseAmount(base); err != nil {
		return Quote{}, false, err
	}
	if result.QuoteAmount, err = ledger.ParseAmount(quote); err != nil {
		return Quote{}, false, err
	}
	result.RoundingRule = RoundingRule(rounding)
	return result, expired, nil
}

func (s *Service) nextID(ctx context.Context, prefix string) (string, error) {
	id, err := s.ids.Next(ctx)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("fx: ID generator returned empty id")
	}
	return prefix + id, nil
}
