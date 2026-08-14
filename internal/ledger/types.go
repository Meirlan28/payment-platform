// Package ledger implements an append-only, per-asset double-entry journal.
// Monetary amounts are exact DECIMAL(38,0) atomic units; direction is
// represented only by Side. No API in this package accepts float values.
package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type Side string

const (
	Debit  Side = "DEBIT"
	Credit Side = "CREDIT"
)

var (
	ErrInvalidPosting      = errors.New("ledger: invalid posting")
	ErrUnbalanced          = errors.New("ledger: debits and credits differ for an asset")
	ErrAmountOverflow      = errors.New("ledger: amount exceeds DECIMAL(38,0)")
	ErrEffectConflict      = errors.New("ledger: effect id already exists with a different request")
	ErrTransactionNotFound = errors.New("ledger: transaction not found")
	ErrAccountNotFound     = errors.New("ledger: account not found")
	ErrInsufficientFunds   = errors.New("ledger: available balance plus credit is insufficient")
	ErrCrossBook           = errors.New("ledger: account belongs to a different book")
	ErrAssetMismatch       = errors.New("ledger: account asset mismatch")
)

const MaxAtomicDigits = 38

// IDGenerator is backed in production by durable
// issuer-prefix/incarnation/counter blocks. Financial services must not use a
// random UUID or wall-clock ID as an absolute uniqueness mechanism.
type IDGenerator interface {
	Next(context.Context) (string, error)
}

// Amount is an immutable exact integer number of atomic units. Its zero value
// is valid. Methods never expose or mutate the internal big.Int.
type Amount struct {
	integer *big.Int
}

func NewAmountInt64(value int64) Amount {
	return Amount{integer: new(big.Int).SetInt64(value)}
}

func ParseAmount(value string) (Amount, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, ".eE+") {
		return Amount{}, fmt.Errorf("%w: amount must be a base-10 integer", ErrInvalidPosting)
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || !fitsDecimal38(parsed) {
		return Amount{}, ErrAmountOverflow
	}
	return Amount{integer: parsed}, nil
}

func MustAmount(value string) Amount {
	amount, err := ParseAmount(value)
	if err != nil {
		panic(err)
	}
	return amount
}

func (a Amount) value() *big.Int {
	if a.integer == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(a.integer)
}

func (a Amount) String() string   { return a.value().String() }
func (a Amount) Sign() int        { return a.value().Sign() }
func (a Amount) IsZero() bool     { return a.Sign() == 0 }
func (a Amount) Cmp(b Amount) int { return a.value().Cmp(b.value()) }

func (a Amount) Add(b Amount) (Amount, error) {
	result := new(big.Int).Add(a.value(), b.value())
	if !fitsDecimal38(result) {
		return Amount{}, ErrAmountOverflow
	}
	return Amount{integer: result}, nil
}

func (a Amount) Sub(b Amount) (Amount, error) {
	result := new(big.Int).Sub(a.value(), b.value())
	if !fitsDecimal38(result) {
		return Amount{}, ErrAmountOverflow
	}
	return Amount{integer: result}, nil
}

func (a Amount) Negate() Amount {
	return Amount{integer: new(big.Int).Neg(a.value())}
}

func (a Amount) MarshalJSON() ([]byte, error) {
	// A JSON string prevents downstream decoders from silently converting a
	// 38-digit value through IEEE-754.
	return json.Marshal(a.String())
}

func (a *Amount) UnmarshalJSON(raw []byte) error {
	if a == nil {
		return errors.New("ledger: nil Amount receiver")
	}
	var value string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
	} else {
		value = string(raw)
	}
	parsed, err := ParseAmount(value)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

func fitsDecimal38(value *big.Int) bool {
	if value == nil {
		return true
	}
	abs := new(big.Int).Abs(new(big.Int).Set(value))
	return len(abs.String()) <= MaxAtomicDigits
}

type Line struct {
	AccountID   string `json:"account_id"`
	AssetID     string `json:"asset_id"`
	Side        Side   `json:"side"`
	AmountAtoms Amount `json:"amount_atoms"`
	Memo        string `json:"memo,omitempty"`
}

type PostRequest struct {
	TransactionID          string          `json:"transaction_id"`
	BookID                 string          `json:"book_id"`
	OperationID            string          `json:"operation_id"`
	EffectID               string          `json:"effect_id"`
	Kind                   string          `json:"kind"`
	ReferenceTransactionID *string         `json:"reference_transaction_id,omitempty"`
	PostingRuleVersion     string          `json:"posting_rule_version"`
	SchemaVersion          int64           `json:"schema_version"`
	RequestHash            [32]byte        `json:"-"`
	Metadata               json.RawMessage `json:"metadata,omitempty"`
	Lines                  []Line          `json:"lines"`
}

type Receipt struct {
	TransactionID string   `json:"transaction_id"`
	BookID        string   `json:"book_id"`
	OperationID   string   `json:"operation_id"`
	EffectID      string   `json:"effect_id"`
	SequenceNo    int64    `json:"sequence_no"`
	EntryHash     [32]byte `json:"entry_hash"`
	Duplicate     bool     `json:"duplicate"`
}

// Transaction is the verifier-facing immutable journal representation. The
// embedded request is the complete hashed financial header plus ordered lines.
type Transaction struct {
	PostRequest
	SequenceNo int64
	PrevHash   [32]byte
	EntryHash  [32]byte
	Status     string
}

type Balance struct {
	AccountID           string
	DebitAtoms          Amount
	CreditAtoms         Amount
	CurrentBalanceAtoms Amount
	CreditLimitAtoms    Amount
	LastSequenceNo      int64
}

type Book struct {
	BookID        string
	LegalEntityID string
	Jurisdiction  string
	GenesisHash   [32]byte
}

type Asset struct {
	AssetID     string
	DisplayCode string
	AtomicScale int64
}

type Account struct {
	AccountID         string
	BookID            string
	AssetID           string
	AccountType       string
	NormalSide        Side
	EnforceSpendLimit bool
	CreditLimitAtoms  Amount
}

func (r PostRequest) Validate() error {
	if !validID(r.TransactionID) || !validID(r.BookID) || !validID(r.OperationID) ||
		!validID(r.EffectID) || r.Kind == "" || r.PostingRuleVersion == "" {
		return fmt.Errorf("%w: required transaction header is missing", ErrInvalidPosting)
	}
	if r.SchemaVersion <= 0 {
		return fmt.Errorf("%w: schema version must be positive", ErrInvalidPosting)
	}
	if r.ReferenceTransactionID != nil && !validID(*r.ReferenceTransactionID) {
		return fmt.Errorf("%w: invalid reference transaction id", ErrInvalidPosting)
	}
	if len(r.Lines) < 2 {
		return fmt.Errorf("%w: at least two lines are required", ErrInvalidPosting)
	}
	if _, err := CanonicalJSON(r.Metadata); err != nil {
		return fmt.Errorf("%w: metadata: %v", ErrInvalidPosting, err)
	}

	type totals struct{ debit, credit *big.Int }
	perAsset := make(map[string]totals)
	for index, line := range r.Lines {
		if !validID(line.AccountID) || !validID(line.AssetID) {
			return fmt.Errorf("%w: line %d has missing account or asset", ErrInvalidPosting, index+1)
		}
		if line.Side != Debit && line.Side != Credit {
			return fmt.Errorf("%w: line %d has invalid side", ErrInvalidPosting, index+1)
		}
		if line.AmountAtoms.Sign() <= 0 || !fitsDecimal38(line.AmountAtoms.value()) {
			return fmt.Errorf("%w: line %d amount must be positive", ErrInvalidPosting, index+1)
		}
		t := perAsset[line.AssetID]
		if t.debit == nil {
			t.debit = new(big.Int)
			t.credit = new(big.Int)
		}
		if line.Side == Debit {
			t.debit.Add(t.debit, line.AmountAtoms.value())
		} else {
			t.credit.Add(t.credit, line.AmountAtoms.value())
		}
		if !fitsDecimal38(t.debit) || !fitsDecimal38(t.credit) {
			return fmt.Errorf("%w: total for %s", ErrAmountOverflow, line.AssetID)
		}
		perAsset[line.AssetID] = t
	}
	for asset, total := range perAsset {
		if total.debit.Cmp(total.credit) != 0 {
			return fmt.Errorf("%w: %s debit=%s credit=%s", ErrUnbalanced, asset, total.debit, total.credit)
		}
	}
	return nil
}

func (b Book) Validate() error {
	if !validID(b.BookID) || !validID(b.LegalEntityID) || b.Jurisdiction == "" {
		return fmt.Errorf("%w: invalid book", ErrInvalidPosting)
	}
	return nil
}

func (a Account) Validate() error {
	if !validID(a.AccountID) || !validID(a.BookID) || !validID(a.AssetID) || a.AccountType == "" {
		return fmt.Errorf("%w: invalid account", ErrInvalidPosting)
	}
	if a.NormalSide != Debit && a.NormalSide != Credit {
		return fmt.Errorf("%w: invalid account normal side", ErrInvalidPosting)
	}
	if a.CreditLimitAtoms.Sign() < 0 || !fitsDecimal38(a.CreditLimitAtoms.value()) {
		return fmt.Errorf("%w: negative credit limit", ErrInvalidPosting)
	}
	return nil
}

func validID(value string) bool {
	return value != "" && len(value) <= 512
}
