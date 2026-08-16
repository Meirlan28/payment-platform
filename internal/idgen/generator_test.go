package idgen

import (
	"context"
	"errors"
	"testing"

	"github.com/example/payment-platform/internal/store"
)

func TestFirstIDRequiresDurableBlockReservation(t *testing.T) {
	reservations := 0
	generator := &Generator{
		issuer: "region-a", blockSize: 16,
		reserve: func(context.Context) (counterBlock, error) {
			reservations++
			return counterBlock{incarnation: 7, first: 41, last: 56}, nil
		},
	}

	got, err := generator.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("first ID used no durable reservation: calls=%d", reservations)
	}
	if got != "region-a-0000000000000007-0000000000000029" {
		t.Fatalf("unexpected first ID %q", got)
	}
}

func TestAmbiguousReservationIsNeverInstalledInMemory(t *testing.T) {
	ambiguous := errors.New("connection lost while COMMIT was in flight")
	reservations := 0
	generator := &Generator{
		issuer: "region-b", blockSize: 8,
		reserve: func(context.Context) (counterBlock, error) {
			reservations++
			if reservations == 1 {
				return counterBlock{incarnation: 3, first: 100, last: 107},
					errors.Join(store.ErrAmbiguousCommit, ambiguous)
			}
			return counterBlock{incarnation: 3, first: 108, last: 115}, nil
		},
	}

	if _, err := generator.Next(context.Background()); !errors.Is(err, store.ErrAmbiguousCommit) {
		t.Fatalf("ambiguous reservation error was hidden: %v", err)
	}
	if generator.next != 0 || generator.end != 0 || generator.incarnation != 0 {
		t.Fatalf("ambiguous block leaked into cache: next=%d end=%d incarnation=%d",
			generator.next, generator.end, generator.incarnation)
	}

	got, err := generator.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reservations != 2 {
		t.Fatalf("ambiguous block was reused without a new reservation: calls=%d", reservations)
	}
	if got != "region-b-0000000000000003-000000000000006c" {
		t.Fatalf("unexpected ID after ambiguous reservation %q", got)
	}
}

func TestCachedBlockIsConsumedWithoutAnotherReservation(t *testing.T) {
	reservations := 0
	generator := &Generator{
		issuer: "region-c", blockSize: 2,
		reserve: func(context.Context) (counterBlock, error) {
			reservations++
			return counterBlock{incarnation: 1, first: 9, last: 10}, nil
		},
	}

	first, err := generator.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reservations != 1 || first == second {
		t.Fatalf("invalid cached block behavior: calls=%d first=%q second=%q",
			reservations, first, second)
	}
}
