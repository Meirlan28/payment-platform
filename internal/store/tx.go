// Package store contains the CockroachDB transaction boundary used by all
// correctness-critical services.
package store

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	serializationFailureCode = "40001"
	ambiguousResultCode      = "40003"
)

var ErrAmbiguousCommit = errors.New("store: transaction commit result is ambiguous")

// Beginner is implemented by *pgxpool.Pool. Keeping this interface small lets
// services be tested without making the storage abstraction pretend to be a
// consensus implementation.
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// DBTX is the common query surface implemented by pgx.Tx and pgxpool.Pool.
// Correctness-critical mutations accept a pgx.Tx, while read-only helpers can
// use this narrower interface.
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Runner struct {
	DB          Beginner
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

func NewRunner(db Beginner) *Runner {
	return &Runner{
		DB:          db,
		MaxAttempts: 8,
		BaseBackoff: 2 * time.Millisecond,
		MaxBackoff:  250 * time.Millisecond,
	}
}

// RunSerializable executes fn in a fresh SERIALIZABLE transaction and retries
// only SQLSTATE 40001. The callback must be deterministic and must not perform
// irreversible I/O. All messages are instead written to the transactional
// outbox by the callback.
//
// An ambiguous COMMIT is deliberately not retried here. The caller receives
// ErrAmbiguousCommit and must retry the original API request with the same
// idempotency key/effect ID; that retry reads the durable receipt if commit won.
func (r *Runner) RunSerializable(ctx context.Context, fn func(pgx.Tx) error) error {
	if r == nil || r.DB == nil {
		return errors.New("store: nil transaction database")
	}
	if fn == nil {
		return errors.New("store: nil transaction callback")
	}
	attempts := r.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}

	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := r.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return fmt.Errorf("begin serializable transaction: %w", err)
		}

		err = fn(tx)
		if err != nil {
			_ = tx.Rollback(ctx)
			if IsAmbiguousResult(err) {
				return fmt.Errorf("%w: %v", ErrAmbiguousCommit, err)
			}
			if !IsSerializationFailure(err) {
				return err
			}
		} else {
			commitErr := tx.Commit(ctx)
			if commitErr == nil {
				return nil
			}
			if !IsSerializationFailure(commitErr) {
				// A connection loss, deadline, node crash, or 40003 while COMMIT
				// is in flight cannot prove abort. Never execute fn again here.
				return fmt.Errorf("%w: %v", ErrAmbiguousCommit, commitErr)
			}
			err = commitErr
		}
		_ = tx.Rollback(ctx)
		last = err
		if attempt+1 < attempts {
			if err := r.wait(ctx, attempt); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("store: serializable retry budget exhausted: %w", last)
}

func IsSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == serializationFailureCode
}

func IsAmbiguousResult(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == ambiguousResultCode
}

func (r *Runner) wait(ctx context.Context, attempt int) error {
	base := r.BaseBackoff
	if base <= 0 {
		base = time.Millisecond
	}
	maximum := r.MaxBackoff
	if maximum <= 0 {
		maximum = 250 * time.Millisecond
	}
	delay := base
	for i := 0; i < attempt && delay < maximum/2; i++ {
		delay *= 2
	}
	if delay > maximum {
		delay = maximum
	}

	// Integer-only full jitter; it is unrelated to monetary arithmetic and
	// avoids synchronized retry storms.
	var random [8]byte
	if _, err := rand.Read(random[:]); err == nil && delay > 0 {
		delay = time.Duration(binary.BigEndian.Uint64(random[:]) % uint64(delay+1))
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
