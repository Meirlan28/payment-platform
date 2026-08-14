// Package simulation contains deterministic fault injectors.  It is the only
// package (along with scripted rails) allowed to model transport state in
// memory; production money/progress remains SQL-backed.
package simulation

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrPartitioned = errors.New("simulation: link is partitioned")
	ErrPacketLost  = errors.New("simulation: packet lost")
	ErrNodeDown    = errors.New("simulation: node is down")
)

type MessageKind string

const (
	Command  MessageKind = "COMMAND"
	Event    MessageKind = "EVENT"
	Response MessageKind = "RESPONSE"
	Ack      MessageKind = "ACK"
)

type Envelope struct {
	MessageID     string
	From          string
	To            string
	Kind          MessageKind
	CorrelationID string
	Payload       []byte
	Sequence      uint64
	Delivery      uint32
}

type link struct{ left, right string }

func canonicalLink(a, b string) link {
	if a < b {
		return link{a, b}
	}
	return link{b, a}
}

type Network struct {
	mu             sync.Mutex
	seed           uint64
	sequence       uint64
	tick           uint64
	dropPercent    uint8
	duplicateEvery uint64
	reorder        bool
	partitions     map[link]bool
	down           map[string]bool
	clockSkew      map[string]time.Duration
	dropNext       map[string]int
	duplicateNext  map[string]int
	loseResponse   map[string]int
	queue          []Envelope
}

func NewNetwork(seed uint64) *Network {
	return &Network{
		seed: seed, partitions: make(map[link]bool), down: make(map[string]bool),
		clockSkew: make(map[string]time.Duration), dropNext: make(map[string]int),
		duplicateNext: make(map[string]int), loseResponse: make(map[string]int),
	}
}

func (n *Network) Partition(a, b string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.partitions[canonicalLink(a, b)] = true
}

func (n *Network) Heal(a, b string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.partitions, canonicalLink(a, b))
}

func (n *Network) HealAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.partitions = make(map[link]bool)
}

func (n *Network) SetDropPercent(percent uint8) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if percent > 100 {
		percent = 100
	}
	n.dropPercent = percent
}

func (n *Network) SetDuplicateEvery(every uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.duplicateEvery = every
}

func (n *Network) SetReorder(enabled bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reorder = enabled
}

func (n *Network) DropNext(messageID string, count int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if count > 0 {
		n.dropNext[messageID] += count
	}
}

func (n *Network) DuplicateNext(messageID string, extraDeliveries int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if extraDeliveries > 0 {
		n.duplicateNext[messageID] += extraDeliveries
	}
}

// LoseResponse drops the next response correlated to requestID while leaving
// the committed command/effect untouched.
func (n *Network) LoseResponse(requestID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.loseResponse[requestID]++
}

func (n *Network) Crash(node string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.down[node] = true
}

func (n *Network) Restart(node string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.down, node)
}

func (n *Network) ClockSkew(node string, skew time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.clockSkew[node] = skew
}

func (n *Network) Now(node string, base time.Time) time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return base.Add(n.clockSkew[node])
}

// Send decides all faults from seed+monotonic sequence, so the same scenario
// is exactly replayable and independent of goroutine scheduling.
func (n *Network) Send(envelope Envelope) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if envelope.MessageID == "" || envelope.From == "" || envelope.To == "" {
		return errors.New("simulation: invalid envelope")
	}
	if n.down[envelope.From] || n.down[envelope.To] {
		return ErrNodeDown
	}
	if n.partitions[canonicalLink(envelope.From, envelope.To)] {
		return ErrPartitioned
	}
	if envelope.Kind == Response && n.loseResponse[envelope.CorrelationID] > 0 {
		n.loseResponse[envelope.CorrelationID]--
		return ErrPacketLost
	}
	if n.dropNext[envelope.MessageID] > 0 {
		n.dropNext[envelope.MessageID]--
		return ErrPacketLost
	}
	n.sequence++
	envelope.Sequence = n.sequence
	if deterministicPercent(n.seed, n.sequence, envelope.MessageID) < n.dropPercent {
		return ErrPacketLost
	}
	envelope.Payload = append([]byte(nil), envelope.Payload...)
	n.queue = append(n.queue, envelope)
	extra := n.duplicateNext[envelope.MessageID]
	delete(n.duplicateNext, envelope.MessageID)
	if n.duplicateEvery > 0 && n.sequence%n.duplicateEvery == 0 {
		extra++
	}
	for delivery := 1; delivery <= extra; delivery++ {
		duplicate := envelope
		duplicate.Delivery = uint32(delivery)
		duplicate.Payload = append([]byte(nil), envelope.Payload...)
		n.queue = append(n.queue, duplicate)
	}
	return nil
}

// Drain returns every currently deliverable packet.  Reorder mode deliberately
// reverses causally unrelated insertion order while retaining message IDs.
func (n *Network) Drain() []Envelope {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tick++
	result := make([]Envelope, 0, len(n.queue))
	remaining := n.queue[:0]
	for _, envelope := range n.queue {
		if n.down[envelope.To] || n.partitions[canonicalLink(envelope.From, envelope.To)] {
			remaining = append(remaining, envelope)
			continue
		}
		envelope.Payload = append([]byte(nil), envelope.Payload...)
		result = append(result, envelope)
	}
	n.queue = remaining
	if n.reorder {
		sort.SliceStable(result, func(i, j int) bool {
			if result[i].Sequence == result[j].Sequence {
				return result[i].Delivery > result[j].Delivery
			}
			return result[i].Sequence > result[j].Sequence
		})
	}
	return result
}

func (n *Network) Pending() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.queue)
}

func deterministicPercent(seed, sequence uint64, messageID string) uint8 {
	var prefix [16]byte
	binary.BigEndian.PutUint64(prefix[:8], seed)
	binary.BigEndian.PutUint64(prefix[8:], sequence)
	h := sha256.New()
	h.Write(prefix[:])
	h.Write([]byte(messageID))
	sum := h.Sum(nil)
	return uint8(binary.BigEndian.Uint64(sum[:8]) % 100)
}
