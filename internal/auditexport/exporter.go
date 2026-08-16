package auditexport

import (
	"context"
	"errors"
	"fmt"
)

type receiptRepository interface {
	HasReceipt(context.Context, string, string, int64) (bool, error)
	LoadReceipt(context.Context, string, string, int64) (Receipt, error)
	RecordReceipt(context.Context, Receipt) error
	RecordConflict(context.Context, *ConflictError) error
}

type ExportObserver interface {
	ExportFailure(sinkID string)
	WORMConflict(sinkID string)
}

type Exporter struct {
	repository receiptRepository
	sinks      []Sink
	observer   ExportObserver

	// Tests use this crash point to model a successful immutable PUT followed
	// by process death before the Cockroach receipt transaction.
	afterEnsure func(SinkDescriptor, Artifact, ObjectEvidence) error
}

func NewExporter(repository receiptRepository, sinks []Sink, observer ExportObserver) (*Exporter, error) {
	if repository == nil {
		return nil, errors.New("audit export: receipt repository is required")
	}
	if err := validateTwoIndependentSinks(sinks); err != nil {
		return nil, err
	}
	return &Exporter{repository: repository, sinks: append([]Sink(nil), sinks...), observer: observer}, nil
}

func (e *Exporter) SinkDescriptors() []SinkDescriptor {
	result := make([]SinkDescriptor, 0, len(e.sinks))
	for _, sink := range e.sinks {
		result = append(result, sink.Descriptor())
	}
	return result
}

func (e *Exporter) Probe(ctx context.Context) error {
	var failures []error
	for _, sink := range e.sinks {
		if err := sink.Probe(ctx); err != nil {
			e.failure(sink.Descriptor().ID)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Export is at-least-once. Even an existing receipt is independently checked
// against provider HEAD evidence; without a receipt, the sink resolves PUT
// ambiguity by HEAD/checksum before the append-only receipt is recorded.
func (e *Exporter) Export(ctx context.Context, artifact Artifact) error {
	var failures []error
	for _, sink := range e.sinks {
		descriptor := sink.Descriptor()
		recorded, err := e.repository.HasReceipt(ctx, descriptor.ID, artifact.BookID, artifact.LastSequence)
		if err != nil {
			e.failure(descriptor.ID)
			failures = append(failures, fmt.Errorf("audit export: lookup %s receipt: %w", descriptor.ID, err))
			continue
		}
		if recorded {
			if err := e.verifyOne(ctx, sink, artifact); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		evidence, err := sink.Ensure(ctx, artifact)
		if err != nil {
			var conflict *ConflictError
			if errors.As(err, &conflict) {
				if persistErr := e.recordConflict(ctx, conflict); persistErr != nil {
					err = errors.Join(err, persistErr)
				}
			} else {
				e.failure(descriptor.ID)
			}
			failures = append(failures, err)
			continue
		}
		if e.afterEnsure != nil {
			if err := e.afterEnsure(descriptor, artifact, evidence); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		receipt := Receipt{
			SinkID: descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ContentSHA256: artifact.SHA256, Bucket: descriptor.Bucket,
			EndpointAuthority: descriptor.EndpointAuthority,
			ProviderIdentity:  evidence.ProviderIdentity,
			VersionID:         evidence.VersionID, ETag: evidence.ETag,
			RetentionUntil: evidence.RetentionUntil,
		}
		if err := e.repository.RecordReceipt(ctx, receipt); err != nil {
			if errors.Is(err, ErrManifestConflict) {
				conflict := &ConflictError{
					SinkID: descriptor.ID, BookID: artifact.BookID,
					LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
					ExpectedSHA256: artifact.SHA256,
					Reason:         "durable receipt differs from verified provider evidence",
				}
				failures = append(failures, errors.Join(conflict, e.recordConflict(ctx, conflict)))
			} else {
				e.failure(descriptor.ID)
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// Verify requires both append-only receipts and independent provider HEAD
// evidence. It performs no PUT and is used by latest-anchor and rotating
// historical scrubs, so a forged raw receipt makes readiness fail closed.
func (e *Exporter) Verify(ctx context.Context, artifact Artifact) error {
	var failures []error
	for _, sink := range e.sinks {
		if err := e.verifyOne(ctx, sink, artifact); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (e *Exporter) verifyOne(ctx context.Context, sink Sink, artifact Artifact) error {
	descriptor := sink.Descriptor()
	receipt, err := e.repository.LoadReceipt(ctx, descriptor.ID, artifact.BookID, artifact.LastSequence)
	if err != nil {
		e.failure(descriptor.ID)
		return fmt.Errorf("audit export: load %s receipt for external verification: %w", descriptor.ID, err)
	}
	evidence, err := sink.Verify(ctx, artifact)
	if err != nil {
		var conflict *ConflictError
		if errors.As(err, &conflict) {
			return errors.Join(err, e.recordConflict(ctx, conflict))
		} else {
			e.failure(descriptor.ID)
		}
		return err
	}
	if receipt.SinkID != descriptor.ID || receipt.BookID != artifact.BookID ||
		receipt.LastSequence != artifact.LastSequence ||
		receipt.ObjectKey != artifact.ObjectKey ||
		receipt.ContentSHA256 != artifact.SHA256 ||
		receipt.Bucket != descriptor.Bucket ||
		receipt.EndpointAuthority != descriptor.EndpointAuthority ||
		receipt.ProviderIdentity != evidence.ProviderIdentity ||
		receipt.VersionID != evidence.VersionID || receipt.ETag != evidence.ETag ||
		evidence.RetentionUntil.Before(receipt.RetentionUntil) {
		conflict := &ConflictError{
			SinkID: descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256,
			Reason:         "database receipt and external provider evidence differ",
		}
		return errors.Join(conflict, e.recordConflict(ctx, conflict))
	}
	return nil
}

func (e *Exporter) recordConflict(ctx context.Context, conflict *ConflictError) error {
	e.conflict(conflict.SinkID)
	if err := e.repository.RecordConflict(ctx, conflict); err != nil {
		e.failure(conflict.SinkID)
		return err
	}
	return nil
}

func (e *Exporter) failure(sinkID string) {
	if e.observer != nil {
		e.observer.ExportFailure(sinkID)
	}
}

func (e *Exporter) conflict(sinkID string) {
	if e.observer != nil {
		e.observer.WORMConflict(sinkID)
	}
}
