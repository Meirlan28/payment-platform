// Package rails isolates external systems whose outcome can be unknown.  The
// durable operation row is created before I/O and fixes one provider reference
// for the lifetime of an economic payment.
package rails

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const outcomePersistenceRetries = 8

var (
	ErrInvalidRequest  = errors.New("rails: invalid request")
	ErrRequestConflict = errors.New("rails: operation id reused with different request")
	ErrRailTimeout     = errors.New("rails: timeout; external outcome is unknown")
	ErrUnknownOutcome  = errors.New("rails: external outcome is unknown")
	ErrStaleAttempt    = errors.New("rails: stale attempt fenced")
)

type Rail string

const (
	Card       Rail = "CARD"
	Bank       Rail = "BANK"
	Blockchain Rail = "BLOCKCHAIN"
	Antifraud  Rail = "ANTIFRAUD"
)

type Outcome string

const (
	OutcomeUnknown   Outcome = "UNKNOWN"
	OutcomeSucceeded Outcome = "SUCCEEDED"
	OutcomeFailed    Outcome = "FAILED"
)

type Request struct {
	OperationID       string
	Rail              Rail
	ProviderReference string
	Payload           []byte
}

type Response struct {
	Outcome           Outcome `json:"outcome"`
	ProviderReference string  `json:"provider_reference"`
	ProviderCode      string  `json:"provider_code,omitempty"`
	Payload           []byte  `json:"payload,omitempty"`
	Duplicate         bool    `json:"duplicate,omitempty"`
}

type Attempt struct {
	Request
	RequestHash  [32]byte
	Status       Outcome
	AttemptToken string
	Attempts     int
	Response     Response
	LastError    string
	Duplicate    bool
}

type ExternalRail interface {
	Submit(context.Context, Request) (Response, error)
	Lookup(context.Context, string) (Response, error)
}

// IdempotentSubmitter is optional.  It permits an explicit recovery retry
// using the exact same provider reference after Lookup returned UNKNOWN.
type IdempotentSubmitter interface {
	ExternalRail
	SupportsIdempotentReference() bool
}

type DB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Processor struct {
	DB    DB
	Rails map[Rail]ExternalRail // immutable dependency configuration
}

// Start persists IN_FLIGHT before making the only initial Submit.  A
// concurrent retry sees that row and returns UNKNOWN/final state; it never
// creates another provider reference or another external economic payment.
func (p Processor) Start(ctx context.Context, request Request) (Attempt, error) {
	if p.DB == nil || request.OperationID == "" || request.Rail == "" || len(request.Payload) == 0 {
		return Attempt{}, ErrInvalidRequest
	}
	rail, ok := p.Rails[request.Rail]
	if !ok || rail == nil {
		return Attempt{}, ErrInvalidRequest
	}
	if request.ProviderReference == "" {
		request.ProviderReference = stableReference(request.Rail, request.OperationID)
	}
	hash := requestHash(request)
	token, err := randomToken()
	if err != nil {
		return Attempt{}, err
	}
	tx, err := p.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
INSERT INTO external_attempts
 (operation_id, rail, provider_reference, request_hash, request_payload,
  status, attempt_token)
VALUES ($1,$2,$3,$4,$5,'IN_FLIGHT',$6)
ON CONFLICT (operation_id) DO NOTHING`, request.OperationID, string(request.Rail),
		request.ProviderReference, hash[:], request.Payload, token)
	if err != nil {
		return Attempt{}, err
	}
	if tag.RowsAffected() == 0 {
		existing, err := loadAttempt(ctx, tx, request.OperationID, true)
		if err != nil {
			return Attempt{}, err
		}
		if existing.Rail != request.Rail || existing.ProviderReference != request.ProviderReference ||
			!bytes.Equal(existing.RequestHash[:], hash[:]) {
			return Attempt{}, ErrRequestConflict
		}
		existing.Duplicate = true
		if err := tx.Commit(ctx); err != nil {
			return Attempt{}, err
		}
		return existing, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, err
	}

	response, submitErr := rail.Submit(ctx, request)
	status := response.Outcome
	if submitErr != nil || status == "" {
		status = OutcomeUnknown
	}
	if status != OutcomeSucceeded && status != OutcomeFailed {
		status = OutcomeUnknown
	}
	attempt, persistErr := p.persistOutcome(ctx, request.OperationID, token, status, response, submitErr)
	if persistErr != nil {
		// External success may already exist.  The durable row remains IN_FLIGHT
		// and must be resolved by provider-reference lookup, never a new payment.
		return Attempt{}, errors.Join(submitErr, persistErr)
	}
	if submitErr != nil {
		return attempt, errors.Join(ErrRailTimeout, submitErr)
	}
	if status == OutcomeUnknown {
		return attempt, ErrUnknownOutcome
	}
	return attempt, nil
}

// Resolve is the mandatory first action for IN_FLIGHT/UNKNOWN attempts after a
// process crash or timeout.
func (p Processor) Resolve(ctx context.Context, operationID string) (Attempt, error) {
	attempt, err := p.Get(ctx, operationID)
	if err != nil {
		return Attempt{}, err
	}
	if attempt.Status == OutcomeSucceeded || attempt.Status == OutcomeFailed {
		return attempt, nil
	}
	rail := p.Rails[attempt.Rail]
	if rail == nil {
		return Attempt{}, ErrInvalidRequest
	}
	response, lookupErr := rail.Lookup(ctx, attempt.ProviderReference)
	status := response.Outcome
	if lookupErr != nil || (status != OutcomeSucceeded && status != OutcomeFailed) {
		status = OutcomeUnknown
	}
	resolved, persistErr := p.persistOutcome(ctx, operationID, attempt.AttemptToken, status, response, lookupErr)
	if persistErr != nil {
		return Attempt{}, errors.Join(lookupErr, persistErr)
	}
	if status == OutcomeUnknown {
		return resolved, errors.Join(ErrUnknownOutcome, lookupErr)
	}
	return resolved, nil
}

// RetrySameReference is opt-in and is rejected unless the rail contract makes
// provider_reference an idempotency key.  It never generates a new reference.
func (p Processor) RetrySameReference(ctx context.Context, operationID string) (Attempt, error) {
	attempt, err := p.Get(ctx, operationID)
	if err != nil {
		return Attempt{}, err
	}
	if attempt.Status != OutcomeUnknown {
		return attempt, nil
	}
	rail, ok := p.Rails[attempt.Rail].(IdempotentSubmitter)
	if !ok || !rail.SupportsIdempotentReference() {
		return attempt, ErrUnknownOutcome
	}
	newToken, err := randomToken()
	if err != nil {
		return Attempt{}, err
	}
	tx, err := p.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
UPDATE external_attempts
SET status='IN_FLIGHT', attempt_token=$3, attempts=attempts+1, updated_at=now()
WHERE operation_id=$1 AND status='UNKNOWN' AND attempt_token=$2`,
		operationID, attempt.AttemptToken, newToken)
	if err != nil {
		return Attempt{}, err
	}
	if tag.RowsAffected() != 1 {
		return Attempt{}, ErrStaleAttempt
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, err
	}
	attempt.AttemptToken, attempt.Attempts = newToken, attempt.Attempts+1
	response, submitErr := rail.Submit(ctx, attempt.Request)
	status := response.Outcome
	if submitErr != nil || (status != OutcomeSucceeded && status != OutcomeFailed) {
		status = OutcomeUnknown
	}
	result, persistErr := p.persistOutcome(ctx, operationID, newToken, status, response, submitErr)
	if persistErr != nil {
		return Attempt{}, errors.Join(submitErr, persistErr)
	}
	if status == OutcomeUnknown {
		return result, errors.Join(ErrUnknownOutcome, submitErr)
	}
	return result, nil
}

func (p Processor) Get(ctx context.Context, operationID string) (Attempt, error) {
	if p.DB == nil || operationID == "" {
		return Attempt{}, ErrInvalidRequest
	}
	tx, err := p.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback(ctx)
	attempt, err := loadAttempt(ctx, tx, operationID, false)
	if err != nil {
		return Attempt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, err
	}
	return attempt, nil
}

func (p Processor) persistOutcome(ctx context.Context, operationID, token string, status Outcome, response Response, cause error) (Attempt, error) {
	var last error
	for retry := 0; retry < outcomePersistenceRetries; retry++ {
		attempt, err := p.persistOutcomeOnce(ctx, operationID, token, status, response, cause)
		if !isSerializationFailure(err) {
			return attempt, err
		}
		last = err
	}
	return Attempt{}, fmt.Errorf("rails: outcome persistence retry limit: %w", last)
}

func (p Processor) persistOutcomeOnce(ctx context.Context, operationID, token string, status Outcome, response Response, cause error) (Attempt, error) {
	tx, err := p.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback(ctx)
	payload, err := json.Marshal(response)
	if err != nil {
		return Attempt{}, err
	}
	lastError := ""
	if cause != nil {
		lastError = cause.Error()
	}
	tag, err := tx.Exec(ctx, `
UPDATE external_attempts
SET status=$3, response_payload=$4, provider_code=$5, last_error=$6,
    updated_at=now(), resolved_at=CASE WHEN $3 IN ('SUCCEEDED','FAILED') THEN now() ELSE NULL END
WHERE operation_id=$1 AND attempt_token=$2
  AND status IN ('IN_FLIGHT','UNKNOWN')`, operationID, token, string(status),
		payload, response.ProviderCode, lastError)
	if err != nil {
		return Attempt{}, err
	}
	if tag.RowsAffected() == 0 {
		// A concurrent resolver may have already made the same attempt terminal.
		// Return that durable first outcome; never rewrite it with a late lookup.
		existing, loadErr := loadAttempt(ctx, tx, operationID, true)
		if loadErr != nil {
			return Attempt{}, loadErr
		}
		if existing.AttemptToken != token ||
			(existing.Status != OutcomeSucceeded && existing.Status != OutcomeFailed) {
			return Attempt{}, ErrStaleAttempt
		}
		if err := tx.Commit(ctx); err != nil {
			return Attempt{}, err
		}
		return existing, nil
	}
	attempt, err := loadAttempt(ctx, tx, operationID, false)
	if err != nil {
		return Attempt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, err
	}
	return attempt, nil
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

func loadAttempt(ctx context.Context, tx pgx.Tx, operationID string, lock bool) (Attempt, error) {
	query := `
SELECT operation_id, rail, provider_reference, request_hash, request_payload,
       status, attempt_token, attempts, response_payload, coalesce(last_error, '')
FROM external_attempts WHERE operation_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var attempt Attempt
	var railName, status string
	var hash, responsePayload []byte
	err := tx.QueryRow(ctx, query, operationID).Scan(&attempt.OperationID, &railName,
		&attempt.ProviderReference, &hash, &attempt.Payload, &status, &attempt.AttemptToken,
		&attempt.Attempts, &responsePayload, &attempt.LastError)
	if err != nil {
		return Attempt{}, err
	}
	if len(hash) != sha256.Size {
		return Attempt{}, errors.New("rails: corrupt request hash")
	}
	copy(attempt.RequestHash[:], hash)
	attempt.Rail, attempt.Status = Rail(railName), Outcome(status)
	if len(responsePayload) > 0 {
		if err := json.Unmarshal(responsePayload, &attempt.Response); err != nil {
			return Attempt{}, err
		}
	}
	return attempt, nil
}

func requestHash(request Request) [32]byte {
	h := sha256.New()
	h.Write([]byte("payment-platform/external-request\x00"))
	h.Write([]byte(request.Rail))
	h.Write([]byte{0})
	h.Write([]byte(request.ProviderReference))
	h.Write([]byte{0})
	h.Write(request.Payload)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func stableReference(rail Rail, operationID string) string {
	sum := sha256.Sum256([]byte("payment-platform/provider-reference/" + string(rail) + "/" + operationID))
	return "pp-" + hex.EncodeToString(sum[:16])
}

func randomToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate attempt token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}
