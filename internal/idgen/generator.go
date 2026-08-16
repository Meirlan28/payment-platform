package idgen

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Generator allocates disjoint counter blocks in a serializable transaction.
// Wall time is intentionally absent from the identifier and from the lease.
// Unused values are burned on process failure and are never reassigned.
type Generator struct {
	db        *pgxpool.Pool
	issuer    string
	blockSize int64
	reserve   func(context.Context) (counterBlock, error)

	mu          sync.Mutex
	incarnation int64
	next        int64
	end         int64
}

type counterBlock struct {
	incarnation int64
	first       int64
	last        int64
}

func New(db *pgxpool.Pool, issuer string, blockSize int64) (*Generator, error) {
	if db == nil {
		return nil, errors.New("id generator database is required")
	}
	if issuer == "" {
		return nil, errors.New("issuer prefix is required")
	}
	if blockSize <= 0 {
		return nil, errors.New("block size must be positive")
	}
	return &Generator{db: db, issuer: issuer, blockSize: blockSize}, nil
}

func (g *Generator) Next(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	// The zero value is deliberately not a valid cached block. In particular,
	// a newly started process must never emit issuer/0/0 before it has durably
	// reserved a range from CockroachDB.
	if g.next == 0 || g.next > g.end {
		if err := g.allocate(ctx); err != nil {
			return "", err
		}
	}
	counter := g.next
	g.next++
	return fmt.Sprintf("%s-%016x-%016x", g.issuer, uint64(g.incarnation), uint64(counter)), nil
}

func (g *Generator) allocate(ctx context.Context) error {
	reserve := g.reserve
	if reserve == nil {
		reserve = g.reserveBlock
	}
	block, err := reserve(ctx)
	if err != nil {
		// A COMMIT acknowledgement may have been lost. The candidate range is
		// therefore burned rather than cached: a later reservation can safely
		// skip it if the first COMMIT actually won, or reuse it through the DB
		// counter if the first transaction aborted.
		return err
	}
	if block.incarnation <= 0 || block.first <= 0 || block.last < block.first {
		return errors.New("invalid counter block returned by authority")
	}
	g.incarnation, g.next, g.end = block.incarnation, block.first, block.last
	return nil
}

func (g *Generator) reserveBlock(ctx context.Context) (counterBlock, error) {
	var candidate counterBlock
	err := store.NewRunner(g.db).RunSerializable(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE id_issuers
			SET next_counter = next_counter + $2
			WHERE issuer_prefix = $1 AND retired = false
			RETURNING incarnation, next_counter - $2, next_counter - 1`,
			g.issuer, g.blockSize).Scan(
			&candidate.incarnation, &candidate.first, &candidate.last)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("issuer %q does not exist or is retired", g.issuer)
		}
		if err != nil {
			return fmt.Errorf("allocate ID block: %w", err)
		}
		if candidate.incarnation <= 0 || candidate.first <= 0 || candidate.last < candidate.first {
			return errors.New("invalid counter block returned by authority")
		}
		return nil
	})
	if err != nil {
		return counterBlock{}, err
	}
	return candidate, nil
}
