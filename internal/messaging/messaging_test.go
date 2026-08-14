package messaging

import (
	"errors"
	"testing"
)

func TestMessageValidationAndHash(t *testing.T) {
	message := Message{
		EventID: "e1", Topic: "payments", AggregateID: "p1", AggregateVersion: 7,
		ParentTransactionID: "tx-1", Headers: map[string]string{"event_type": "payment.captured"},
		Payload: []byte("capture"),
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	first := hashMessage(message)
	message.Payload = []byte("refund")
	second := hashMessage(message)
	if first == second {
		t.Fatal("different economic payloads have equal inbox hash")
	}
	message.Payload = []byte("capture")
	message.Headers["event_type"] = "payment.refunded"
	if first == hashMessage(message) {
		t.Fatal("semantic header substitution was not detected")
	}
	message.Headers = map[string]string{"event_type": "payment.captured"}
	message.ParentTransactionID = "tx-2"
	if first == hashMessage(message) {
		t.Fatal("parent transaction substitution was not detected")
	}
	message.EventID = ""
	if err := message.Validate(); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("invalid message error = %v", err)
	}
}

func TestHeadersComparedAsMaps(t *testing.T) {
	if !equalHeaders(map[string]string{"a": "1", "b": "2"}, map[string]string{"b": "2", "a": "1"}) {
		t.Fatal("header map order affected equality")
	}
	if equalHeaders(map[string]string{"a": "1"}, map[string]string{"a": "2"}) {
		t.Fatal("different headers compared equal")
	}
}
