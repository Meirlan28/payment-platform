package store

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestErrorClassification(t *testing.T) {
	serialization := &pgconn.PgError{Code: "40001"}
	ambiguous := &pgconn.PgError{Code: "40003"}
	ordinary := &pgconn.PgError{Code: "23505"}

	if !IsSerializationFailure(serialization) || IsSerializationFailure(ordinary) {
		t.Fatal("serialization error classification is unsafe")
	}
	if !IsAmbiguousResult(ambiguous) || IsAmbiguousResult(ordinary) {
		t.Fatal("ambiguous result classification is unsafe")
	}
	if IsSerializationFailure(errors.New("restart transaction in text only")) {
		t.Fatal("retry decisions must use SQLSTATE, not error text")
	}
}
