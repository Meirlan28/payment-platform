// Package messaging provides the SQL half of transactional outbox/inbox.  It
// intentionally promises at-least-once transport and exactly-once database
// effects, never fictitious exactly-once delivery.
package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidMessage  = errors.New("messaging: invalid message")
	ErrPayloadConflict = errors.New("messaging: message id reused with different payload")
	ErrPoisonMessage   = errors.New("messaging: poison message")
	ErrLeaseLost       = errors.New("messaging: publisher lease lost")
)

type DB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Message struct {
	EventID             string
	Topic               string
	Key                 []byte
	Payload             []byte
	Headers             map[string]string
	AggregateID         string
	AggregateVersion    uint64
	ParentTransactionID string
}

func (m Message) Validate() error {
	if m.EventID == "" || m.Topic == "" || m.AggregateID == "" || len(m.Payload) == 0 {
		return ErrInvalidMessage
	}
	return nil
}

// Enqueue must receive the caller's ledger/domain transaction.  Consequently
// the financial commit and the durable intent to publish have one outcome.
func Enqueue(ctx context.Context, tx pgx.Tx, message Message) error {
	if tx == nil {
		return ErrInvalidMessage
	}
	if err := message.Validate(); err != nil {
		return err
	}
	headers, err := json.Marshal(message.Headers)
	if err != nil {
		return fmt.Errorf("marshal headers: %w", err)
	}
	version := int64(message.AggregateVersion)
	if uint64(version) != message.AggregateVersion {
		return ErrInvalidMessage
	}
	normalizedKey := message.Key
	if normalizedKey == nil {
		normalizedKey = []byte{}
	}
	var parent any
	if message.ParentTransactionID != "" {
		parent = message.ParentTransactionID
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO outbox_messages
 (event_id, topic, message_key, payload, headers, aggregate_id,
  aggregate_version, parent_transaction_id)
VALUES ($1,$2,$3,$4,$5::JSONB,$6,$7,$8)
ON CONFLICT (event_id) DO NOTHING`, message.EventID, message.Topic, normalizedKey,
		message.Payload, headers, message.AggregateID, version, parent)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// An identical retry is harmless; reusing an event id for different bytes
	// is a correctness violation and must not be silently treated as duplicate.
	var topic, aggregateID, parentID string
	var storedKey, payload, storedHeaders []byte
	var aggregateVersion int64
	err = tx.QueryRow(ctx, `
SELECT topic, message_key, payload, headers::STRING, aggregate_id,
       aggregate_version, coalesce(parent_transaction_id, '')
FROM outbox_messages WHERE event_id=$1`, message.EventID).Scan(
		&topic, &storedKey, &payload, &storedHeaders, &aggregateID, &aggregateVersion, &parentID)
	if err != nil {
		return err
	}
	var normalizedStored, normalizedIncoming map[string]string
	if err := json.Unmarshal(storedHeaders, &normalizedStored); err != nil {
		return err
	}
	if err := json.Unmarshal(headers, &normalizedIncoming); err != nil {
		return err
	}
	if topic != message.Topic || string(storedKey) != string(normalizedKey) ||
		string(payload) != string(message.Payload) || aggregateID != message.AggregateID ||
		aggregateVersion != version || parentID != message.ParentTransactionID ||
		!equalHeaders(normalizedStored, normalizedIncoming) {
		return ErrPayloadConflict
	}
	return nil
}

func equalHeaders(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

type ClaimedMessage struct {
	Message
	Attempts int
	Owner    string
	Deadline time.Time
}

type Outbox struct {
	DB DB
}

// Claim leases rows.  A publisher crash merely lets the lease expire; a
// publish followed by a crash before MarkPublished intentionally produces a
// duplicate with the same EventID.
func (o Outbox) Claim(ctx context.Context, owner string, limit int, lease time.Duration) ([]ClaimedMessage, error) {
	if o.DB == nil || owner == "" || limit <= 0 || lease <= 0 {
		return nil, ErrInvalidMessage
	}
	tx, err := o.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) // no-op after commit
	leaseMicros := lease.Microseconds()
	if leaseMicros <= 0 {
		return nil, ErrInvalidMessage
	}
	rows, err := tx.Query(ctx, `
WITH candidates AS (
    SELECT event_id
    FROM outbox_messages
    WHERE (status='PENDING' AND available_at <= now())
       OR (status='PUBLISHING' AND locked_until < now())
    ORDER BY available_at, created_at, event_id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE outbox_messages AS o
SET status='PUBLISHING', locked_by=$2,
    locked_until=transaction_timestamp() + ($3::INT8 * INTERVAL '1 microsecond'),
    attempts=o.attempts+1
FROM candidates AS c
WHERE o.event_id=c.event_id
RETURNING o.event_id, o.topic, o.message_key, o.payload, o.headers::STRING,
          o.aggregate_id, o.aggregate_version,
          coalesce(o.parent_transaction_id, ''), o.attempts, o.locked_until`, limit, owner, leaseMicros)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	claimed := make([]ClaimedMessage, 0, limit)
	for rows.Next() {
		var item ClaimedMessage
		var headers []byte
		var aggregateVersion int64
		if err := rows.Scan(&item.EventID, &item.Topic, &item.Key, &item.Payload, &headers,
			&item.AggregateID, &aggregateVersion, &item.ParentTransactionID, &item.Attempts,
			&item.Deadline); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(headers, &item.Headers); err != nil {
			return nil, err
		}
		item.AggregateVersion = uint64(aggregateVersion)
		item.Owner = owner
		claimed = append(claimed, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (o Outbox) MarkPublished(ctx context.Context, eventID, owner string) error {
	return o.updateLease(ctx, eventID, owner, `
UPDATE outbox_messages
SET status='PUBLISHED', published_at=now(), locked_by=NULL, locked_until=NULL,
    last_error=NULL
WHERE event_id=$1 AND status='PUBLISHING' AND locked_by=$2`)
}

func (o Outbox) MarkFailed(ctx context.Context, eventID, owner string, cause error, maxAttempts int, backoff time.Duration) error {
	if maxAttempts <= 0 || cause == nil || backoff < 0 {
		return ErrInvalidMessage
	}
	tx, err := o.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	backoffMicros := backoff.Microseconds()
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
UPDATE outbox_messages
SET status=CASE WHEN attempts >= $3 THEN 'POISON' ELSE 'PENDING' END,
    available_at=transaction_timestamp() + ($4::INT8 * INTERVAL '1 microsecond'),
    locked_by=NULL, locked_until=NULL, last_error=$5
WHERE event_id=$1 AND status='PUBLISHING' AND locked_by=$2`,
		eventID, owner, maxAttempts, backoffMicros, truncateError(cause))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

func (o Outbox) updateLease(ctx context.Context, eventID, owner, statement string) error {
	if o.DB == nil || eventID == "" || owner == "" {
		return ErrInvalidMessage
	}
	tx, err := o.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, statement, eventID, owner)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

func truncateError(err error) string {
	const max = 2048
	value := err.Error()
	if len(value) > max {
		return value[:max]
	}
	return value
}
