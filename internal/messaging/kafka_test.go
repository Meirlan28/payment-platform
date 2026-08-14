package messaging

import (
	"crypto/tls"
	"testing"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestKafkaRecordRoundTrip(t *testing.T) {
	original := Message{
		EventID: "event-1", Topic: "payment-events", Key: []byte("payment-1"),
		Payload:     []byte(`{"state":"CAPTURED"}`),
		Headers:     map[string]string{"event_type": "payment.captured"},
		AggregateID: "payment-1", AggregateVersion: 7,
		ParentTransactionID: "transaction-1",
	}
	decoded, err := decodeRecord(encodeRecord(original))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.EventID != original.EventID || decoded.AggregateID != original.AggregateID ||
		decoded.AggregateVersion != original.AggregateVersion ||
		decoded.ParentTransactionID != original.ParentTransactionID ||
		string(decoded.Payload) != string(original.Payload) ||
		decoded.Headers["event_type"] != "payment.captured" {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
}

func TestMalformedKafkaRecordGetsDeterministicDLQIdentity(t *testing.T) {
	consumer := &KafkaConsumer{dlqTopic: "payment-events-dlq"}
	record := &kgo.Record{
		Topic: "payment-events", Partition: 17, Offset: 991,
		Key: []byte("key"), Value: []byte("untrusted-wire-payload"),
	}
	first := consumer.corruptRecordDLQ(record)
	second := consumer.corruptRecordDLQ(record)
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	if first.EventID != second.EventID || first.EventID != "dlq-corrupt:payment-events/17/991" {
		t.Fatalf("DLQ coordinate is not deterministic: %#v", first)
	}
	if first.Headers["failure_class"] != "MALFORMED_TRANSPORT_RECORD" ||
		string(first.Payload) != string(record.Value) {
		t.Fatalf("malformed record evidence was lost: %#v", first)
	}
}

func TestKafkaProductionConfigRequiresTLS(t *testing.T) {
	_, err := (KafkaClientConfig{Brokers: []string{"broker:9093"}, ClientID: "test"}).options()
	if err == nil {
		t.Fatal("production config without TLS must fail")
	}
	_, err = (KafkaClientConfig{
		Brokers: []string{"broker:9093"}, ClientID: "test",
		TLS: &tls.Config{MinVersion: tls.VersionTLS13},
	}).options()
	if err != nil {
		t.Fatal(err)
	}
}
