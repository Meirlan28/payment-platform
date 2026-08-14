// Package idempotency implements durable request ownership and result replay.
// It is not an exactly-once delivery claim: uniqueness of ledger.effect_id is
// the final exactly-once economic-effect guard.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidRequest = errors.New("idempotency: invalid request")
	ErrKeyConflict    = errors.New("idempotency: key reused with different canonical request")
	ErrInProgress     = errors.New("idempotency: matching request is still processing")
	ErrLostClaim      = errors.New("idempotency: processing lease is no longer owned")
)

type State string

const (
	Processing State = "PROCESSING"
	Succeeded  State = "SUCCEEDED"
	Failed     State = "FAILED"
)

type ClaimRequest struct {
	Scope         string
	Key           string
	RequestHash   [32]byte
	OwnerToken    string
	OperationID   string
	LeaseDuration time.Duration
}

type Record struct {
	Scope               string
	Key                 string
	RequestHash         [32]byte
	State               State
	OwnerToken          string
	OperationID         string
	LedgerTransactionID *string
	ResponseCode        *int64
	ResponsePayload     json.RawMessage
	FailureCode         *string
	Acquired            bool
	Cached              bool
}

type Service struct {
	ids ledger.IDGenerator
}

func NewService(ids ledger.IDGenerator) *Service { return &Service{ids: ids} }

func (s *Service) NewOwnerToken(ctx context.Context) (string, error) {
	if s == nil || s.ids == nil {
		return "", errors.New("idempotency: durable ID generator is not configured")
	}
	return s.ids.Next(ctx)
}

// RequestHash returns a stable hash after canonical JSON normalization.
// Monetary request fields should use ledger.Amount, whose JSON representation
// is an exact quoted integer rather than an IEEE-754 number.
func RequestHash(request any) ([32]byte, error) {
	var zero [32]byte
	raw, err := json.Marshal(request)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	canonical, err := ledger.CanonicalJSON(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return sha256.Sum256(canonical), nil
}

func CanonicalBytesHash(raw json.RawMessage) ([32]byte, error) {
	var zero [32]byte
	canonical, err := ledger.CanonicalJSON(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return sha256.Sum256(canonical), nil
}

// Claim must run in the same serializable transaction as the economic effect.
// Lease expiry affects only liveness; unique effect IDs and row serialization
// preserve safety if a lease is taken over early because of a clock fault.
func (s *Service) Claim(ctx context.Context, tx pgx.Tx, request ClaimRequest) (Record, error) {
	if tx == nil || request.Scope == "" || request.Key == "" || request.OwnerToken == "" ||
		request.OperationID == "" || request.LeaseDuration <= 0 {
		return Record{}, ErrInvalidRequest
	}
	leaseMicros := request.LeaseDuration.Microseconds()
	if leaseMicros <= 0 {
		leaseMicros = 1
	}
	_, err := tx.Exec(ctx, `
INSERT INTO idempotency_records (
    scope, idempotency_key, request_hash, state, owner_token,
    lease_expires_at, operation_id
) VALUES ($1, $2, $3, 'PROCESSING', $4,
          transaction_timestamp() + ($5::INT8 * INTERVAL '1 microsecond'), $6)
ON CONFLICT (scope, idempotency_key) DO NOTHING`,
		request.Scope, request.Key, request.RequestHash[:], request.OwnerToken,
		leaseMicros, request.OperationID)
	if err != nil {
		return Record{}, err
	}

	record, leaseExpired, err := loadForUpdate(ctx, tx, request.Scope, request.Key)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(record.RequestHash[:], request.RequestHash[:]) {
		return Record{}, ErrKeyConflict
	}
	if record.State == Succeeded || record.State == Failed {
		record.Cached = true
		return record, nil
	}
	if record.OwnerToken == request.OwnerToken {
		record.Acquired = true
		return record, nil
	}
	if !leaseExpired {
		return Record{}, ErrInProgress
	}

	tag, err := tx.Exec(ctx, `
UPDATE idempotency_records
SET owner_token=$3,
    lease_expires_at=transaction_timestamp() + ($4::INT8 * INTERVAL '1 microsecond'),
    updated_at=transaction_timestamp()
WHERE scope=$1 AND idempotency_key=$2 AND state='PROCESSING'
  AND lease_expires_at <= transaction_timestamp()`,
		request.Scope, request.Key, request.OwnerToken, leaseMicros)
	if err != nil {
		return Record{}, err
	}
	if tag.RowsAffected() != 1 {
		return Record{}, ErrInProgress
	}
	record.OwnerToken = request.OwnerToken
	record.Acquired = true
	return record, nil
}

func (s *Service) Complete(
	ctx context.Context,
	tx pgx.Tx,
	scope, key, ownerToken, ledgerTransactionID string,
	responseCode int64,
	response any,
) error {
	if tx == nil || scope == "" || key == "" || ownerToken == "" || ledgerTransactionID == "" {
		return ErrInvalidRequest
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return err
	}
	canonical, err := ledger.CanonicalJSON(raw)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
UPDATE idempotency_records
SET state='SUCCEEDED', ledger_transaction_id=$4, response_code=$5,
    response_payload=$6::JSONB, failure_code=NULL,
    updated_at=transaction_timestamp()
WHERE scope=$1 AND idempotency_key=$2 AND owner_token=$3 AND state='PROCESSING'`,
		scope, key, ownerToken, ledgerTransactionID, responseCode, string(canonical))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLostClaim
	}
	return nil
}

// Fail persists only a deterministic terminal failure. Transient failures must
// abort the encompassing transaction so a later owner can retry.
func (s *Service) Fail(ctx context.Context, tx pgx.Tx, scope, key, ownerToken, failureCode string, response any) error {
	if tx == nil || scope == "" || key == "" || ownerToken == "" || failureCode == "" {
		return ErrInvalidRequest
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return err
	}
	canonical, err := ledger.CanonicalJSON(raw)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
UPDATE idempotency_records
SET state='FAILED', response_payload=$5::JSONB, failure_code=$4,
    updated_at=transaction_timestamp()
WHERE scope=$1 AND idempotency_key=$2 AND owner_token=$3 AND state='PROCESSING'`,
		scope, key, ownerToken, failureCode, string(canonical))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLostClaim
	}
	return nil
}

func loadForUpdate(ctx context.Context, tx pgx.Tx, scope, key string) (Record, bool, error) {
	var result Record
	var hash []byte
	var state string
	var ledgerTransactionID, failureCode *string
	var responseCode *int64
	var response []byte
	var expired bool
	err := tx.QueryRow(ctx, `
SELECT scope, idempotency_key, request_hash, state, owner_token, operation_id,
       ledger_transaction_id, response_code, response_payload, failure_code,
       lease_expires_at <= transaction_timestamp()
FROM idempotency_records
WHERE scope=$1 AND idempotency_key=$2
FOR UPDATE`, scope, key).Scan(
		&result.Scope, &result.Key, &hash, &state, &result.OwnerToken, &result.OperationID,
		&ledgerTransactionID, &responseCode, &response, &failureCode, &expired)
	if err != nil {
		return Record{}, false, err
	}
	if len(hash) != 32 {
		return Record{}, false, errors.New("idempotency: corrupt request hash")
	}
	copy(result.RequestHash[:], hash)
	result.State = State(state)
	result.LedgerTransactionID = ledgerTransactionID
	result.ResponseCode = responseCode
	result.ResponsePayload = append(json.RawMessage(nil), response...)
	result.FailureCode = failureCode
	return result, expired, nil
}
