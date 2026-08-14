package simulation

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestPartitionDuplicateReorderAndLostResponse(t *testing.T) {
	network := NewNetwork(42)
	network.Partition("A", "B")
	if err := network.Send(Envelope{MessageID: "blocked", From: "A", To: "B", Kind: Command}); !errors.Is(err, ErrPartitioned) {
		t.Fatalf("partition send: %v", err)
	}
	network.Heal("A", "B")
	network.SetReorder(true)
	network.DuplicateNext("one", 1)
	if err := network.Send(Envelope{MessageID: "one", From: "A", To: "B", Kind: Event, Payload: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if err := network.Send(Envelope{MessageID: "two", From: "A", To: "B", Kind: Event, Payload: []byte("2")}); err != nil {
		t.Fatal(err)
	}
	network.LoseResponse("request-1")
	if err := network.Send(Envelope{MessageID: "response-1", CorrelationID: "request-1", From: "B", To: "A", Kind: Response}); !errors.Is(err, ErrPacketLost) {
		t.Fatalf("response was not lost: %v", err)
	}
	deliveries := network.Drain()
	if len(deliveries) != 3 {
		t.Fatalf("got %d deliveries, want 3", len(deliveries))
	}
	if deliveries[0].MessageID != "two" || deliveries[1].MessageID != "one" || deliveries[2].MessageID != "one" {
		t.Fatalf("unexpected deterministic reorder: %#v", deliveries)
	}
	if deliveries[1].Delivery == deliveries[2].Delivery {
		t.Fatal("duplicate delivery numbers were not distinguished")
	}
}

func TestThirtyPercentLossIsReplayable(t *testing.T) {
	run := func() []bool {
		network := NewNetwork(777)
		network.SetDropPercent(30)
		outcomes := make([]bool, 1000)
		for index := range outcomes {
			err := network.Send(Envelope{MessageID: string(rune(index + 1)), From: "A", To: "B", Kind: Event})
			outcomes[index] = err == nil
		}
		return outcomes
	}
	first, second := run(), run()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same seed did not replay packet loss")
	}
	lost := 0
	for _, delivered := range first {
		if !delivered {
			lost++
		}
	}
	if lost < 250 || lost > 350 {
		t.Fatalf("loss distribution is implausible: %d/1000", lost)
	}
}

func TestClockSkewAndRestartFence(t *testing.T) {
	network := NewNetwork(1)
	cluster, err := NewCluster(network, "A", "B")
	if err != nil {
		t.Fatal(err)
	}
	oldFence, err := cluster.Fence("A")
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.Crash("A"); err != nil {
		t.Fatal(err)
	}
	if err := cluster.Restart("A"); err != nil {
		t.Fatal(err)
	}
	if cluster.Valid(oldFence) {
		t.Fatal("pre-crash worker fence remained valid")
	}
	if err := cluster.Send(oldFence, Envelope{MessageID: "stale", From: "A", To: "B"}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("stale worker not fenced: %v", err)
	}
	base := time.Unix(0, 0)
	network.ClockSkew("A", 15*time.Minute)
	network.ClockSkew("B", -15*time.Minute)
	if network.Now("A", base).Sub(network.Now("B", base)) != 30*time.Minute {
		t.Fatal("clock skew injection failed")
	}
}
