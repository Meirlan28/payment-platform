//go:build integration

package rails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProcessorSuccessWithLostResponseDoesNotResubmit(t *testing.T) {
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
	simulator := NewCardSimulator()
	operationID := "processor-" + railSuffix(t)
	simulator.Script(operationID, Behavior{Mode: BehaviorSuccessLostResponse, Code: "00"})
	processor := Processor{DB: pool, Rails: map[Rail]ExternalRail{Card: simulator}}
	request := Request{OperationID: operationID, Rail: Card, Payload: []byte(`{"amount":"25"}`)}
	first, err := processor.Start(ctx, request)
	if !errors.Is(err, ErrRailTimeout) || first.Status != OutcomeUnknown {
		t.Fatalf("lost response result = %#v, %v", first, err)
	}
	request.ProviderReference = first.ProviderReference
	retry, err := processor.Start(ctx, request)
	if err != nil || !retry.Duplicate || retry.Status != OutcomeUnknown {
		t.Fatalf("client retry = %#v, %v", retry, err)
	}
	if simulator.SubmitCount(first.ProviderReference) != 1 {
		t.Fatal("client retry submitted a second external payment")
	}
	resolved, err := processor.Resolve(ctx, operationID)
	if err != nil || resolved.Status != OutcomeSucceeded {
		t.Fatalf("reference lookup = %#v, %v", resolved, err)
	}
}

func TestConcurrentResolveCannotRegressTerminalOutcome(t *testing.T) {
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

	operationID := "concurrent-resolve-" + railSuffix(t)
	rail := newConflictingLookupRail()
	processor := Processor{DB: pool, Rails: map[Rail]ExternalRail{Card: rail}}
	started, err := processor.Start(ctx, Request{
		OperationID: operationID,
		Rail:        Card,
		Payload:     []byte(`{"amount":"25"}`),
	})
	if !errors.Is(err, ErrUnknownOutcome) || started.Status != OutcomeUnknown {
		t.Fatalf("start unknown = %#v, %v", started, err)
	}

	results := make(chan Attempt, 2)
	errorsSeen := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			attempt, resolveErr := processor.Resolve(ctx, operationID)
			results <- attempt
			errorsSeen <- resolveErr
		}()
	}
	workers.Wait()
	close(results)
	close(errorsSeen)
	for resolveErr := range errorsSeen {
		if resolveErr != nil {
			t.Fatalf("concurrent resolve: %v", resolveErr)
		}
	}

	final, err := processor.Get(ctx, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != OutcomeSucceeded && final.Status != OutcomeFailed {
		t.Fatalf("durable state is not terminal: %#v", final)
	}
	for result := range results {
		if result.Status != final.Status {
			t.Fatalf("resolver observed %s after durable first-terminal %s", result.Status, final.Status)
		}
	}

	opposite := OutcomeSucceeded
	if final.Status == OutcomeSucceeded {
		opposite = OutcomeFailed
	}
	if _, err := pool.Exec(ctx, `
UPDATE external_attempts
SET status=$2, response_payload='{}'::BYTES, resolved_at=now(), updated_at=now()
WHERE operation_id=$1`, operationID, string(opposite)); err == nil {
		t.Fatal("database accepted terminal outcome regression")
	}
	afterRejectedMutation, err := processor.Get(ctx, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if afterRejectedMutation.Status != final.Status {
		t.Fatalf("terminal outcome changed from %s to %s", final.Status, afterRejectedMutation.Status)
	}
}

type conflictingLookupRail struct {
	lookups atomic.Int32
	release chan struct{}
	once    sync.Once
}

func newConflictingLookupRail() *conflictingLookupRail {
	return &conflictingLookupRail{release: make(chan struct{})}
}

func (r *conflictingLookupRail) Submit(_ context.Context, request Request) (Response, error) {
	return Response{Outcome: OutcomeUnknown, ProviderReference: request.ProviderReference}, nil
}

func (r *conflictingLookupRail) Lookup(_ context.Context, providerReference string) (Response, error) {
	ordinal := r.lookups.Add(1)
	if ordinal >= 2 {
		r.once.Do(func() { close(r.release) })
	}
	<-r.release
	outcome, code := OutcomeSucceeded, "APPROVED"
	if ordinal%2 == 0 {
		outcome, code = OutcomeFailed, "DECLINED"
	}
	return Response{Outcome: outcome, ProviderReference: providerReference, ProviderCode: code}, nil
}

func railSuffix(t *testing.T) string {
	t.Helper()
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value[:])
}
