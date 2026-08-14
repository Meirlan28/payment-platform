package messaging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

type InboxHandler func(context.Context, pgx.Tx, Message) ([]byte, error)

type ProcessResult struct {
	Duplicate bool
	Poison    bool
	Result    []byte
}

type Inbox struct {
	DB          DB
	Consumer    string
	MaxAttempts int
}

// Process commits the handler's database effect and the APPLIED marker in the
// same transaction.  If the process dies after commit but before Kafka ACK,
// redelivery observes APPLIED and does not run the effect again.
func (i Inbox) Process(ctx context.Context, message Message, handler InboxHandler) (ProcessResult, error) {
	if i.DB == nil || i.Consumer == "" || handler == nil || message.EventID == "" || len(message.Payload) == 0 {
		return ProcessResult{}, ErrInvalidMessage
	}
	maxAttempts := i.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	hash := hashMessage(message)
	tx, err := i.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ProcessResult{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
INSERT INTO transport_inbox_messages (consumer_name, message_id, payload_hash)
VALUES ($1,$2,$3)
ON CONFLICT (consumer_name, message_id) DO NOTHING`, i.Consumer, message.EventID, hash[:])
	if err != nil {
		return ProcessResult{}, err
	}
	var storedHash, storedResult []byte
	var status string
	var attempts int
	err = tx.QueryRow(ctx, `
SELECT payload_hash, status, attempts, result
FROM transport_inbox_messages
WHERE consumer_name=$1 AND message_id=$2
FOR UPDATE`, i.Consumer, message.EventID).Scan(&storedHash, &status, &attempts, &storedResult)
	if err != nil {
		return ProcessResult{}, err
	}
	if !bytes.Equal(storedHash, hash[:]) {
		return ProcessResult{}, ErrPayloadConflict
	}
	switch status {
	case "APPLIED":
		if err := tx.Commit(ctx); err != nil {
			return ProcessResult{}, err
		}
		return ProcessResult{Duplicate: true, Result: storedResult}, nil
	case "POISON":
		if err := tx.Commit(ctx); err != nil {
			return ProcessResult{}, err
		}
		return ProcessResult{Poison: true}, ErrPoisonMessage
	case "FAILED", "PROCESSING":
		// eligible below
	default:
		return ProcessResult{}, fmt.Errorf("unknown inbox status %q", status)
	}

	result, handlerErr := handler(ctx, tx, message)
	if handlerErr != nil {
		// Never commit partial writes made by a failed handler.
		_ = tx.Rollback(ctx)
		poison, recordErr := i.recordFailure(ctx, message.EventID, hash[:], handlerErr, maxAttempts)
		if recordErr != nil {
			return ProcessResult{}, errors.Join(handlerErr, recordErr)
		}
		if poison {
			return ProcessResult{Poison: true}, errors.Join(ErrPoisonMessage, handlerErr)
		}
		return ProcessResult{}, handlerErr
	}
	tag, err := tx.Exec(ctx, `
UPDATE transport_inbox_messages
SET status='APPLIED', attempts=attempts+1, result=$3, last_error=NULL, applied_at=now()
WHERE consumer_name=$1 AND message_id=$2`, i.Consumer, message.EventID, result)
	if err != nil {
		return ProcessResult{}, err
	}
	if tag.RowsAffected() != 1 {
		return ProcessResult{}, errors.New("messaging: inbox row disappeared")
	}
	if err := tx.Commit(ctx); err != nil {
		return ProcessResult{}, err
	}
	return ProcessResult{Result: result}, nil
}

func (i Inbox) recordFailure(ctx context.Context, messageID string, hash []byte, cause error, maxAttempts int) (bool, error) {
	tx, err := i.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var status string
	err = tx.QueryRow(ctx, `
INSERT INTO transport_inbox_messages
 (consumer_name, message_id, payload_hash, status, attempts, last_error)
VALUES ($1,$2,$3,CASE WHEN $4 <= 1 THEN 'POISON' ELSE 'FAILED' END,1,$5)
ON CONFLICT (consumer_name, message_id) DO UPDATE
SET attempts=transport_inbox_messages.attempts+1,
    status=CASE WHEN transport_inbox_messages.attempts+1 >= $4 THEN 'POISON' ELSE 'FAILED' END,
    last_error=$5
WHERE transport_inbox_messages.status <> 'APPLIED'
RETURNING status`, i.Consumer, messageID, hash, maxAttempts, truncateError(cause)).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		// A concurrent successful application won.  Its durable APPLIED marker
		// is stronger than this failed delivery.
		return false, tx.Commit(ctx)
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return status == "POISON", nil
}

func hashMessage(message Message) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("payment-platform/transport-message/v1\x00"))
	writeHashBytes := func(value []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(value)
	}
	for _, value := range []string{
		message.EventID, message.Topic, message.AggregateID,
		message.ParentTransactionID,
	} {
		writeHashBytes([]byte(value))
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], message.AggregateVersion)
	_, _ = h.Write(version[:])
	writeHashBytes(message.Key)
	writeHashBytes(message.Payload)
	keys := make([]string, 0, len(message.Headers))
	for key := range message.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	binary.BigEndian.PutUint64(version[:], uint64(len(keys)))
	_, _ = h.Write(version[:])
	for _, key := range keys {
		writeHashBytes([]byte(key))
		writeHashBytes([]byte(message.Headers[key]))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
