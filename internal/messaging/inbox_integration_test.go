//go:build integration

package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConsumerCrashAfterCommitBeforeAck(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS transport_inbox_test_effects (
  effect_id STRING PRIMARY KEY,
  payload BYTES NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	suffix := messagingSuffix(t)
	message := Message{EventID: "event-" + suffix, Topic: "test", AggregateID: "aggregate-" + suffix, Payload: []byte("effect")}
	inbox := Inbox{DB: pool, Consumer: "consumer-" + suffix, MaxAttempts: 3}
	handler := func(ctx context.Context, tx pgx.Tx, message Message) ([]byte, error) {
		_, err := tx.Exec(ctx, `
INSERT INTO transport_inbox_test_effects(effect_id,payload) VALUES($1,$2)`, message.EventID, message.Payload)
		return []byte("durable-result"), err
	}
	first, err := inbox.Process(ctx, message, handler)
	if err != nil || first.Duplicate {
		t.Fatalf("first process = %#v, %v", first, err)
	}
	// No broker ACK is made: this is the post-commit consumer crash boundary.
	second, err := inbox.Process(ctx, message, handler)
	if err != nil || !second.Duplicate || string(second.Result) != "durable-result" {
		t.Fatalf("redelivery = %#v, %v", second, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM transport_inbox_test_effects WHERE effect_id=$1`, message.EventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("economic effect count = %d", count)
	}
}

func TestFailedHandlerCannotCommitPartialEffect(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS transport_inbox_test_effects (
  effect_id STRING PRIMARY KEY,
  payload BYTES NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	suffix := messagingSuffix(t)
	message := Message{EventID: "failing-" + suffix, Topic: "test", AggregateID: "a", Payload: []byte("partial")}
	inbox := Inbox{DB: pool, Consumer: "consumer-" + suffix, MaxAttempts: 3}
	_, err = inbox.Process(ctx, message, func(ctx context.Context, tx pgx.Tx, message Message) ([]byte, error) {
		if _, err := tx.Exec(ctx, `INSERT INTO transport_inbox_test_effects(effect_id,payload) VALUES($1,$2)`, message.EventID, message.Payload); err != nil {
			return nil, err
		}
		return nil, errors.New("crash before transaction commit")
	})
	if err == nil {
		t.Fatal("failed handler reported success")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM transport_inbox_test_effects WHERE effect_id=$1`, message.EventID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial effect escaped rollback: %d", count)
	}
}

func TestOutboxLeasesUseDatabaseClock(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; CockroachDB integration test skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := messagingSuffix(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{EventID: "outbox-" + suffix, Topic: "test", AggregateID: "a", Payload: []byte("payload")}
	if err := Enqueue(ctx, tx, message); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	outbox := Outbox{DB: pool}
	current, err := claimEvent(ctx, outbox, "publisher-a", message.EventID)
	if err != nil || current.Deadline.IsZero() {
		t.Fatalf("claim = %#v, %v", current, err)
	}
	if err := outbox.MarkFailed(ctx, message.EventID, "publisher-a", errors.New("broker unavailable"), 3, 0); err != nil {
		t.Fatal(err)
	}
	// A later transaction may be assigned to a Cockroach node whose physical
	// clock is a few milliseconds behind; lease correctness is DB-time based,
	// and the row becomes eligible as the cluster HLC advances.
	time.Sleep(20 * time.Millisecond)
	_, err = claimEvent(ctx, outbox, "publisher-b", message.EventID)
	if err != nil {
		t.Fatalf("server-clock retry claim: %v", err)
	}
	if err := outbox.MarkPublished(ctx, message.EventID, "publisher-b"); err != nil {
		t.Fatal(err)
	}
}

func findClaim(claimed []ClaimedMessage, eventID string) (ClaimedMessage, bool) {
	for _, message := range claimed {
		if message.EventID == eventID {
			return message, true
		}
	}
	return ClaimedMessage{}, false
}

func claimEvent(ctx context.Context, outbox Outbox, owner, eventID string) (ClaimedMessage, error) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		claimed, err := outbox.Claim(ctx, owner, 1000, 30*time.Second)
		if err != nil {
			return ClaimedMessage{}, err
		}
		if current, found := findClaim(claimed, eventID); found {
			return current, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ClaimedMessage{}, errors.New("event did not become claimable on database clock")
}

func messagingSuffix(t *testing.T) string {
	t.Helper()
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
