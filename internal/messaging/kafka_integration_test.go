//go:build integration

package messaging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestKafkaAtLeastOnceTransportCommitsInboxEffectBeforeOffset(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	brokers := splitBrokers(os.Getenv("KAFKA_BROKERS"))
	if dsn == "" || len(brokers) == 0 {
		t.Skip("DATABASE_URL and KAFKA_BROKERS are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS kafka_integration_effects (
  effect_id STRING PRIMARY KEY,
  payload BYTES NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	suffix := kafkaSuffix(t)
	clientConfig := KafkaClientConfig{
		Brokers: brokers, ClientID: "integration-" + suffix, AllowPlaintext: true,
	}
	producer, err := NewKafkaProducer(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	if err := producer.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	message := Message{
		EventID: "kafka-event-" + suffix, Topic: "payment-events",
		Key: []byte("aggregate-" + suffix), Payload: []byte("durable-effect"),
		Headers:     map[string]string{"event_type": "integration.effect"},
		AggregateID: "aggregate-" + suffix, AggregateVersion: 1,
		ParentTransactionID: "transaction-" + suffix,
	}
	if err := producer.Publish(ctx, message); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewKafkaConsumer(KafkaConsumerConfig{
		Client: clientConfig, Group: "integration-group-" + suffix,
		Topics: []string{"payment-events"}, Inbox: Inbox{DB: pool, Consumer: "integration-" + suffix},
		Handler: func(ctx context.Context, tx pgx.Tx, delivered Message) ([]byte, error) {
			if delivered.EventID != message.EventID {
				return []byte("ignored"), nil
			}
			_, err := tx.Exec(ctx, `
INSERT INTO kafka_integration_effects(effect_id,payload) VALUES($1,$2)
ON CONFLICT (effect_id) DO NOTHING`, delivered.EventID, delivered.Payload)
			return []byte("applied"), err
		},
		DLQ: producer, DLQTopic: "payment-events-dlq", StartFromOldest: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	runError := make(chan error, 1)
	go func() { runError <- consumer.Run(ctx) }()
	for {
		var committed int
		queryErr := pool.QueryRow(context.Background(), `
SELECT count(*) FROM kafka_integration_effects WHERE effect_id=$1`, message.EventID).Scan(&committed)
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		if committed == 1 {
			cancel()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Kafka event was not consumed before deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := <-runError; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var effects, inboxReceipts int
	if err := pool.QueryRow(context.Background(), `
SELECT count(*) FROM kafka_integration_effects WHERE effect_id=$1`, message.EventID).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `
SELECT count(*) FROM transport_inbox_messages
WHERE consumer_name=$1 AND message_id=$2 AND status='APPLIED'`,
		"integration-"+suffix, message.EventID).Scan(&inboxReceipts); err != nil {
		t.Fatal(err)
	}
	if effects != 1 || inboxReceipts != 1 {
		t.Fatalf("effect=%d durable inbox receipt=%d", effects, inboxReceipts)
	}
}

func splitBrokers(value string) []string {
	var result []string
	for _, broker := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(broker); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func kafkaSuffix(t *testing.T) string {
	t.Helper()
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
