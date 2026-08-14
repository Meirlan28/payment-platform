package messaging

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Producer is the production Kafka boundary.  Implementations should enable
// Kafka idempotent production, but consumers must still deduplicate EventID.
type Producer interface {
	Publish(context.Context, Message) error
}

type Publisher struct {
	Outbox      Outbox
	Producer    Producer
	Owner       string
	BatchSize   int
	Lease       time.Duration
	MaxAttempts int
	Backoff     func(attempt int) time.Duration
}

type PublishStats struct {
	Claimed   int
	Published int
	Failed    int
}

func (p Publisher) RunOnce(ctx context.Context) (PublishStats, error) {
	if p.Producer == nil || p.Owner == "" {
		return PublishStats{}, ErrInvalidMessage
	}
	batch := p.BatchSize
	if batch <= 0 {
		batch = 100
	}
	lease := p.Lease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	maxAttempts := p.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 20
	}
	claimed, err := p.Outbox.Claim(ctx, p.Owner, batch, lease)
	if err != nil {
		return PublishStats{}, err
	}
	stats := PublishStats{Claimed: len(claimed)}
	var failures []error
	for _, item := range claimed {
		if err := p.Producer.Publish(ctx, item.Message); err != nil {
			stats.Failed++
			backoff := time.Second
			if p.Backoff != nil {
				backoff = p.Backoff(item.Attempts)
			}
			failureLimit := maxAttempts
			if !errors.Is(err, ErrInvalidMessage) {
				// Broker/network/authentication errors are not poison payloads.
				// Retiring a valid financial event after an arbitrary retry count
				// would turn a long outage into permanent data loss. INT8's maximum
				// is operationally an infinite retry budget; alerts and backpressure
				// remain the liveness controls.
				failureLimit = int(^uint(0) >> 1)
			}
			markErr := p.Outbox.MarkFailed(ctx, item.EventID, p.Owner, err, failureLimit, backoff)
			failures = append(failures, fmt.Errorf("publish %s: %w", item.EventID, errors.Join(err, markErr)))
			continue
		}
		if err := p.Outbox.MarkPublished(ctx, item.EventID, p.Owner); err != nil {
			// The message may already be in Kafka.  Leaving it unmarked is the
			// safe choice: another attempt will publish the same EventID.
			stats.Failed++
			failures = append(failures, fmt.Errorf("mark %s published: %w", item.EventID, err))
			continue
		}
		stats.Published++
	}
	return stats, errors.Join(failures...)
}
