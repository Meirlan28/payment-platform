package saga

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Orchestrator struct {
	db          DB
	definitions map[string]Definition // immutable configuration, not saga state
	retries     int
}

func New(db DB, definitions ...Definition) (*Orchestrator, error) {
	if db == nil {
		return nil, ErrInvalidSaga
	}
	registry := make(map[string]Definition, len(definitions))
	for _, definition := range definitions {
		if err := definition.Validate(); err != nil {
			return nil, err
		}
		if _, exists := registry[definition.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate definition %q", ErrInvalidSaga, definition.Name)
		}
		registry[definition.Name] = definition
	}
	return &Orchestrator{db: db, definitions: registry, retries: 8}, nil
}

// Start is idempotent on sagaID.  Step effect ids are deterministic and remain
// the downstream economic idempotency keys across every coordinator restart.
func (o *Orchestrator) Start(ctx context.Context, sagaID, sagaType, definitionName string, input []byte) (Instance, error) {
	definition, ok := o.definitions[definitionName]
	if !ok || sagaID == "" || sagaType == "" || len(input) == 0 {
		return Instance{}, ErrInvalidSaga
	}
	var result Instance
	err := o.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
INSERT INTO saga_instances (saga_id, saga_type, definition, status, input)
VALUES ($1,$2,$3,'RUNNING',$4)
ON CONFLICT (saga_id) DO NOTHING`, sagaID, sagaType, definitionName, input)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			existing, err := loadInstance(ctx, tx, sagaID, true)
			if err != nil {
				return err
			}
			if existing.Type != sagaType || existing.Definition != definitionName || !bytes.Equal(existing.Input, input) {
				return ErrDefinitionConflict
			}
			result = existing
			return nil
		}
		for ordinal, step := range definition.Steps {
			effectID := fmt.Sprintf("saga/%s/step/%d/%s", sagaID, ordinal, step.Name)
			if _, err := tx.Exec(ctx, `
INSERT INTO saga_steps (saga_id, ordinal, step_name, effect_id, status)
VALUES ($1,$2,$3,$4,'PENDING')`, sagaID, ordinal, step.Name, effectID); err != nil {
				return err
			}
		}
		var errLoad error
		result, errLoad = loadInstance(ctx, tx, sagaID, false)
		return errLoad
	})
	return result, err
}

// Tick executes at most one local action/compensation.  Repeated calls after a
// crash resume from durable rows.  Concurrent coordinators serialize on the
// saga row; a stale transaction cannot commit after its serialization epoch.
func (o *Orchestrator) Tick(ctx context.Context, sagaID string) (TickResult, error) {
	if sagaID == "" {
		return TickResult{}, ErrInvalidSaga
	}
	var result TickResult
	err := o.inTx(ctx, func(tx pgx.Tx) error {
		instance, err := loadInstance(ctx, tx, sagaID, true)
		if err != nil {
			return err
		}
		definition, ok := o.definitions[instance.Definition]
		if !ok {
			return ErrDefinitionMissing
		}
		result.Instance = instance
		switch instance.Status {
		case Completed, Compensated, Failed:
			return nil
		case Compensating:
			return o.compensateOne(ctx, tx, definition, instance, &result)
		case Running:
			return o.executeOne(ctx, tx, definition, instance, &result)
		default:
			return fmt.Errorf("unknown saga status %q", instance.Status)
		}
	})
	if err == nil {
		return result, nil
	}

	var actionErr actionFailure
	if !errors.As(err, &actionErr) {
		return TickResult{}, err
	}
	// Action changes were rolled back.  Failure metadata is written separately
	// so partial handler mutations can never leak into the committed state.
	instance, recordErr := o.recordActionFailure(ctx, actionErr)
	return TickResult{Instance: instance, Progress: true}, errors.Join(actionErr.cause, recordErr)
}

func (o *Orchestrator) executeOne(ctx context.Context, tx pgx.Tx, definition Definition, instance Instance, result *TickResult) error {
	if instance.CurrentStep >= len(definition.Steps) {
		if err := completeSaga(ctx, tx, instance.ID, nil); err != nil {
			return err
		}
		instance.Status = Completed
		result.Instance, result.Progress = instance, true
		return nil
	}
	record, err := loadStep(ctx, tx, instance.ID, instance.CurrentStep)
	if err != nil {
		return err
	}
	if record.Status == StepWaiting {
		result.Waiting = true
		return nil
	}
	if record.Status != StepPending && record.Status != StepFailed {
		return fmt.Errorf("saga current step %d has status %s", record.Ordinal, record.Status)
	}
	step := definition.Steps[record.Ordinal]
	actionResult, err := step.Execute(ctx, tx, ActionContext{Instance: instance, Step: record})
	if err != nil {
		return actionFailure{sagaID: instance.ID, ordinal: record.Ordinal, compensation: false, permanent: isPermanent(err), cause: err}
	}
	status := StepCompleted
	if actionResult.Wait {
		status = StepWaiting
	}
	_, err = tx.Exec(ctx, `
UPDATE saga_steps
SET status=$3, attempts=attempts+1, output=$4, last_error=NULL,
    completed_at=CASE WHEN $3='COMPLETED' THEN now() ELSE completed_at END
WHERE saga_id=$1 AND ordinal=$2`, instance.ID, record.Ordinal, string(status), actionResult.Output)
	if err != nil {
		return err
	}
	if status == StepWaiting {
		_, err = tx.Exec(ctx, `
UPDATE saga_instances SET version=version+1, updated_at=now()
WHERE saga_id=$1`, instance.ID)
		instance.Version++
		result.Instance, result.Progress, result.Waiting = instance, true, true
		return err
	}
	return advanceInstance(ctx, tx, definition, instance, actionResult.Output, result)
}

func advanceInstance(ctx context.Context, tx pgx.Tx, definition Definition, instance Instance, output []byte, result *TickResult) error {
	next := instance.CurrentStep + 1
	status := Running
	var sagaResult []byte
	if next == len(definition.Steps) {
		status, sagaResult = Completed, output
	}
	_, err := tx.Exec(ctx, `
UPDATE saga_instances
SET current_step=$2, status=$3, result=$4, version=version+1,
    last_error=NULL, updated_at=now()
WHERE saga_id=$1`, instance.ID, next, string(status), sagaResult)
	if err != nil {
		return err
	}
	instance.CurrentStep, instance.Status, instance.Result = next, status, sagaResult
	instance.Version++
	result.Instance, result.Progress = instance, true
	return nil
}

func (o *Orchestrator) compensateOne(ctx context.Context, tx pgx.Tx, definition Definition, instance Instance, result *TickResult) error {
	record, found, err := lastCompensatableStep(ctx, tx, instance.ID)
	if err != nil {
		return err
	}
	if !found {
		_, err := tx.Exec(ctx, `
UPDATE saga_instances
SET status='COMPENSATED', version=version+1, updated_at=now()
WHERE saga_id=$1`, instance.ID)
		if err != nil {
			return err
		}
		instance.Status, instance.Version = Compensated, instance.Version+1
		result.Instance, result.Progress = instance, true
		return nil
	}
	step := definition.Steps[record.Ordinal]
	if step.Compensate != nil {
		if _, err := step.Compensate(ctx, tx, ActionContext{Instance: instance, Step: record}); err != nil {
			return actionFailure{sagaID: instance.ID, ordinal: record.Ordinal, compensation: true, permanent: false, cause: err}
		}
	}
	_, err = tx.Exec(ctx, `
UPDATE saga_steps
SET status='COMPENSATED', attempts=attempts+1, last_error=NULL, compensated_at=now()
WHERE saga_id=$1 AND ordinal=$2`, instance.ID, record.Ordinal)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
UPDATE saga_instances SET version=version+1, updated_at=now() WHERE saga_id=$1`, instance.ID)
	if err != nil {
		return err
	}
	instance.Version++
	result.Instance, result.Progress = instance, true
	return nil
}

// CompleteWaitingInTx is called by the durable inbox handler that receives a
// remote result.  The result's local effects and saga advance therefore share
// the inbox transaction.
func CompleteWaitingInTx(ctx context.Context, tx pgx.Tx, sagaID string, ordinal int, output []byte, apply func(context.Context, pgx.Tx) error) error {
	if tx == nil || sagaID == "" || ordinal < 0 {
		return ErrInvalidSaga
	}
	instance, err := loadInstance(ctx, tx, sagaID, true)
	if err != nil {
		return err
	}
	record, err := loadStep(ctx, tx, sagaID, ordinal)
	if err != nil {
		return err
	}
	if record.Status == StepCompleted || record.Status == StepCompensated {
		return nil // duplicate remote message
	}
	if record.Status != StepWaiting || instance.CurrentStep != ordinal || instance.Status != Running {
		return ErrNotWaiting
	}
	if apply != nil {
		if err := apply(ctx, tx); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
UPDATE saga_steps SET status='COMPLETED', output=$3, completed_at=now(), last_error=NULL
WHERE saga_id=$1 AND ordinal=$2 AND status='WAITING'`, sagaID, ordinal, output)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
UPDATE saga_instances
SET current_step=current_step+1, version=version+1, updated_at=now()
WHERE saga_id=$1 AND current_step=$2 AND status='RUNNING'`, sagaID, ordinal)
	return err
}

type actionFailure struct {
	sagaID       string
	ordinal      int
	compensation bool
	permanent    bool
	cause        error
}

func (e actionFailure) Error() string { return e.cause.Error() }
func (e actionFailure) Unwrap() error { return e.cause }

func (o *Orchestrator) recordActionFailure(ctx context.Context, failure actionFailure) (Instance, error) {
	var result Instance
	err := o.inTx(ctx, func(tx pgx.Tx) error {
		instance, err := loadInstance(ctx, tx, failure.sagaID, true)
		if err != nil {
			return err
		}
		stepStatus := StepFailed
		if failure.compensation {
			stepStatus = StepCompensationFailed
		}
		_, err = tx.Exec(ctx, `
UPDATE saga_steps
SET status=$3, attempts=attempts+1, last_error=$4
WHERE saga_id=$1 AND ordinal=$2`, failure.sagaID, failure.ordinal,
			string(stepStatus), truncate(failure.cause.Error()))
		if err != nil {
			return err
		}
		newStatus := instance.Status
		if failure.permanent && !failure.compensation {
			newStatus = Compensating
		}
		_, err = tx.Exec(ctx, `
UPDATE saga_instances
SET status=$2, version=version+1, last_error=$3, updated_at=now()
WHERE saga_id=$1`, failure.sagaID, string(newStatus), truncate(failure.cause.Error()))
		if err != nil {
			return err
		}
		instance.Status, instance.Version, instance.LastError = newStatus, instance.Version+1, truncate(failure.cause.Error())
		result = instance
		return nil
	})
	return result, err
}

func loadInstance(ctx context.Context, tx pgx.Tx, sagaID string, forUpdate bool) (Instance, error) {
	query := `
SELECT saga_id, saga_type, definition, status, input, result, current_step, version,
       coalesce(last_error, '')
FROM saga_instances WHERE saga_id=$1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var instance Instance
	var status string
	var version int64
	err := tx.QueryRow(ctx, query, sagaID).Scan(&instance.ID, &instance.Type, &instance.Definition,
		&status, &instance.Input, &instance.Result, &instance.CurrentStep, &version, &instance.LastError)
	instance.Status, instance.Version = Status(status), uint64(version)
	return instance, err
}

func loadStep(ctx context.Context, tx pgx.Tx, sagaID string, ordinal int) (StepRecord, error) {
	var record StepRecord
	var status string
	err := tx.QueryRow(ctx, `
SELECT saga_id, ordinal, step_name, effect_id, status, attempts, output,
       coalesce(last_error, '')
FROM saga_steps WHERE saga_id=$1 AND ordinal=$2 FOR UPDATE`, sagaID, ordinal).Scan(
		&record.SagaID, &record.Ordinal, &record.Name, &record.EffectID, &status,
		&record.Attempts, &record.Output, &record.LastError)
	record.Status = StepStatus(status)
	return record, err
}

func lastCompensatableStep(ctx context.Context, tx pgx.Tx, sagaID string) (StepRecord, bool, error) {
	var record StepRecord
	var status string
	err := tx.QueryRow(ctx, `
SELECT saga_id, ordinal, step_name, effect_id, status, attempts, output,
       coalesce(last_error, '')
FROM saga_steps
WHERE saga_id=$1 AND status IN ('COMPLETED', 'COMPENSATION_FAILED')
ORDER BY ordinal DESC LIMIT 1 FOR UPDATE`, sagaID).Scan(
		&record.SagaID, &record.Ordinal, &record.Name, &record.EffectID, &status,
		&record.Attempts, &record.Output, &record.LastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return StepRecord{}, false, nil
	}
	record.Status = StepStatus(status)
	return record, err == nil, err
}

func completeSaga(ctx context.Context, tx pgx.Tx, sagaID string, output []byte) error {
	_, err := tx.Exec(ctx, `
UPDATE saga_instances SET status='COMPLETED', result=$2, version=version+1, updated_at=now()
WHERE saga_id=$1`, sagaID, output)
	return err
}

func (o *Orchestrator) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	var last error
	for attempt := 0; attempt < o.retries; attempt++ {
		tx, err := o.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return err
		}
		err = fn(tx)
		if err == nil {
			err = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if !serializationFailure(err) {
			return err
		}
		last = err
	}
	return fmt.Errorf("saga transaction retry limit: %w", last)
}

func serializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

func truncate(value string) string {
	if len(value) > 2048 {
		return value[:2048]
	}
	return value
}
