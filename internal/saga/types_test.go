package saga

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func noopAction(context.Context, pgx.Tx, ActionContext) (ActionResult, error) {
	return Done(nil), nil
}

func TestDefinitionValidation(t *testing.T) {
	valid := Definition{Name: "payment", Steps: []Step{{Name: "reserve", Execute: noopAction}, {Name: "settle", Execute: noopAction}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	duplicate := Definition{Name: "payment", Steps: []Step{{Name: "reserve", Execute: noopAction}, {Name: "reserve", Execute: noopAction}}}
	if err := duplicate.Validate(); !errors.Is(err, ErrInvalidSaga) {
		t.Fatalf("duplicate step error = %v", err)
	}
	missingAction := Definition{Name: "payment", Steps: []Step{{Name: "reserve"}}}
	if err := missingAction.Validate(); !errors.Is(err, ErrInvalidSaga) {
		t.Fatalf("missing action error = %v", err)
	}
}

func TestPermanentErrorClassification(t *testing.T) {
	transient := errors.New("retry")
	if isPermanent(transient) {
		t.Fatal("transient error classified permanent")
	}
	if !isPermanent(Permanent(transient)) {
		t.Fatal("permanent error not classified")
	}
}
