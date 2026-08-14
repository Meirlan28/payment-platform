// Package saga implements durable orchestration of local atomic actions and
// remote, message-driven actions.  Compensation appends inverse effects; it
// never rewrites a completed financial fact.
package saga

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidSaga        = errors.New("saga: invalid definition or instance")
	ErrDefinitionMissing  = errors.New("saga: definition not registered")
	ErrDefinitionConflict = errors.New("saga: id reused with different definition or input")
	ErrNotWaiting         = errors.New("saga: step is not waiting")
)

type DB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Status string

const (
	Running      Status = "RUNNING"
	Compensating Status = "COMPENSATING"
	Completed    Status = "COMPLETED"
	Compensated  Status = "COMPENSATED"
	Failed       Status = "FAILED"
)

type StepStatus string

const (
	StepPending            StepStatus = "PENDING"
	StepWaiting            StepStatus = "WAITING"
	StepCompleted          StepStatus = "COMPLETED"
	StepFailed             StepStatus = "FAILED"
	StepCompensated        StepStatus = "COMPENSATED"
	StepCompensationFailed StepStatus = "COMPENSATION_FAILED"
)

type Instance struct {
	ID          string
	Type        string
	Definition  string
	Status      Status
	Input       []byte
	Result      []byte
	CurrentStep int
	Version     uint64
	LastError   string
}

type StepRecord struct {
	SagaID    string
	Ordinal   int
	Name      string
	EffectID  string
	Status    StepStatus
	Attempts  int
	Output    []byte
	LastError string
}

type ActionContext struct {
	Instance Instance
	Step     StepRecord
}

// Action executes inside the same serializable pgx transaction that records
// step progress.  A remote action must enqueue its command in the outbox and
// return Wait(), then an inbox handler calls CompleteWaitingInTx.
type Action func(context.Context, pgx.Tx, ActionContext) (ActionResult, error)

type ActionResult struct {
	Output []byte
	Wait   bool
}

func Done(output []byte) ActionResult  { return ActionResult{Output: output} }
func Await(output []byte) ActionResult { return ActionResult{Output: output, Wait: true} }

type Step struct {
	Name       string
	Execute    Action
	Compensate Action
}

type Definition struct {
	Name  string
	Steps []Step
}

func (d Definition) Validate() error {
	if d.Name == "" || len(d.Steps) == 0 {
		return ErrInvalidSaga
	}
	seen := make(map[string]struct{}, len(d.Steps))
	for _, step := range d.Steps {
		if step.Name == "" || step.Execute == nil {
			return ErrInvalidSaga
		}
		if _, exists := seen[step.Name]; exists {
			return fmt.Errorf("%w: duplicate step %q", ErrInvalidSaga, step.Name)
		}
		seen[step.Name] = struct{}{}
	}
	return nil
}

type permanentError struct{ error }

// Permanent asks the orchestrator to begin compensation instead of retrying.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{error: err}
}

func isPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

type TickResult struct {
	Instance Instance
	Progress bool
	Waiting  bool
}
