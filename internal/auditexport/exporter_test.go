package auditexport

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type memoryReceiptRepository struct {
	mu        sync.Mutex
	receipts  map[string]Receipt
	conflicts map[[32]byte]*ConflictError
}

func newMemoryReceiptRepository() *memoryReceiptRepository {
	return &memoryReceiptRepository{receipts: make(map[string]Receipt), conflicts: make(map[[32]byte]*ConflictError)}
}

func (r *memoryReceiptRepository) HasReceipt(_ context.Context, sink, book string, last int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, found := r.receipts[receiptKey(sink, book, last)]
	return found, nil
}

func (r *memoryReceiptRepository) LoadReceipt(_ context.Context, sink, book string, last int64) (Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	receipt, found := r.receipts[receiptKey(sink, book, last)]
	if !found {
		return Receipt{}, errors.New("receipt not found")
	}
	return receipt, nil
}

func (r *memoryReceiptRepository) RecordReceipt(_ context.Context, receipt Receipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := receiptKey(receipt.SinkID, receipt.BookID, receipt.LastSequence)
	if existing, found := r.receipts[key]; found && !receiptEqual(existing, receipt) {
		return ErrManifestConflict
	}
	r.receipts[key] = receipt
	return nil
}

func (r *memoryReceiptRepository) RecordConflict(_ context.Context, conflict *ConflictError) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conflicts[conflict.IncidentID()] = conflict
	return nil
}

func receiptKey(sink, book string, last int64) string {
	return sink + "\x00" + book + "\x00" + string(rune(last))
}

type memorySink struct {
	descriptor  SinkDescriptor
	mu          sync.Mutex
	objects     map[string][32]byte
	ensureCalls int
	probeErr    error
	conflict    bool
}

func (s *memorySink) Descriptor() SinkDescriptor  { return s.descriptor }
func (s *memorySink) Probe(context.Context) error { return s.probeErr }
func (s *memorySink) Ensure(_ context.Context, artifact Artifact) (ObjectEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureCalls++
	if s.probeErr != nil {
		return ObjectEvidence{}, s.probeErr
	}
	if s.conflict {
		observed := [32]byte{99}
		return ObjectEvidence{}, &ConflictError{
			SinkID: s.descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256, ObservedSHA256: &observed,
			Reason: "test conflict",
		}
	}
	if existing, found := s.objects[artifact.ObjectKey]; found && existing != artifact.SHA256 {
		return ObjectEvidence{}, ErrWORMConflict
	}
	s.objects[artifact.ObjectKey] = artifact.SHA256
	return ObjectEvidence{
		VersionID: "version-1", ETag: "etag-1",
		ProviderIdentity: "identity-" + s.descriptor.ID,
		RetentionUntil:   artifact.RetainUntil.Add(time.Hour),
	}, nil
}

func (s *memorySink) Verify(_ context.Context, artifact Artifact) (ObjectEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureCalls++
	if s.probeErr != nil {
		return ObjectEvidence{}, s.probeErr
	}
	digest, found := s.objects[artifact.ObjectKey]
	if !found {
		return ObjectEvidence{}, &ConflictError{
			SinkID: s.descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256, Reason: "receipt points to missing object",
		}
	}
	if digest != artifact.SHA256 || s.conflict {
		observed := digest
		return ObjectEvidence{}, &ConflictError{
			SinkID: s.descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ExpectedSHA256: artifact.SHA256, ObservedSHA256: &observed,
			Reason: "verified object differs",
		}
	}
	return ObjectEvidence{
		VersionID: "version-1", ETag: "etag-1",
		ProviderIdentity: "identity-" + s.descriptor.ID,
		RetentionUntil:   artifact.RetainUntil.Add(time.Hour),
	}, nil
}

func fixtureArtifact() Artifact {
	body := []byte("manifest\n")
	return Artifact{
		BookID: "book-1", LastSequence: 100, Format: ManifestFormat,
		ObjectKey: "audit/key", Bytes: body,
		SHA256: sha256.Sum256(body), RetainUntil: time.Date(2036, 8, 16, 0, 0, 0, 0, time.UTC),
	}
}

func fixtureSinks() (*memorySink, *memorySink) {
	return &memorySink{
			descriptor: SinkDescriptor{ID: "a", EndpointAuthority: "worm-a.example", Bucket: "audit-a", IdentityDomain: "account-a"},
			objects:    make(map[string][32]byte),
		}, &memorySink{
			descriptor: SinkDescriptor{ID: "b", EndpointAuthority: "worm-b.example", Bucket: "audit-b", IdentityDomain: "account-b"},
			objects:    make(map[string][32]byte),
		}
}

func TestExporterRecoversCrashAfterPutBeforeReceipt(t *testing.T) {
	repository := newMemoryReceiptRepository()
	left, right := fixtureSinks()
	exporter, err := NewExporter(repository, []Sink{left, right}, nil)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated process death after immutable put")
	exporter.afterEnsure = func(descriptor SinkDescriptor, _ Artifact, _ ObjectEvidence) error {
		if descriptor.ID == "a" {
			return crash
		}
		return nil
	}
	artifact := fixtureArtifact()
	if err := exporter.Export(context.Background(), artifact); !errors.Is(err, crash) {
		t.Fatalf("expected crash point, got %v", err)
	}
	if len(left.objects) != 1 || len(repository.receipts) != 1 {
		t.Fatalf("expected object without left receipt and completed right receipt: objects=%d receipts=%d", len(left.objects), len(repository.receipts))
	}
	restarted, err := NewExporter(repository, []Sink{left, right}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Export(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if len(left.objects) != 1 || len(repository.receipts) != 2 {
		t.Fatalf("restart did not HEAD/recover exact object: objects=%d receipts=%d", len(left.objects), len(repository.receipts))
	}
	leftCalls, rightCalls := left.ensureCalls, right.ensureCalls
	if err := restarted.Export(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if left.ensureCalls != leftCalls+1 || right.ensureCalls != rightCalls+1 ||
		len(left.objects) != 1 || len(right.objects) != 1 {
		t.Fatal("durable duplicate did not perform non-mutating external HEAD verification")
	}
}

func TestExporterContinuesOtherSinkWhenOneIsDown(t *testing.T) {
	repository := newMemoryReceiptRepository()
	left, right := fixtureSinks()
	left.probeErr = errors.New("sink a unavailable")
	exporter, err := NewExporter(repository, []Sink{left, right}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(context.Background(), fixtureArtifact()); err == nil {
		t.Fatal("expected one-sink failure")
	}
	if _, found := repository.receipts[receiptKey("b", "book-1", 100)]; !found {
		t.Fatal("healthy independent sink did not receive its receipt")
	}
	if _, found := repository.receipts[receiptKey("a", "book-1", 100)]; found {
		t.Fatal("failed sink received a false receipt")
	}
}

func TestExporterPersistsP0Conflict(t *testing.T) {
	repository := newMemoryReceiptRepository()
	left, right := fixtureSinks()
	left.conflict = true
	exporter, err := NewExporter(repository, []Sink{left, right}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = exporter.Export(context.Background(), fixtureArtifact())
	if !errors.Is(err, ErrWORMConflict) {
		t.Fatalf("expected P0 WORM conflict, got %v", err)
	}
	if len(repository.conflicts) != 1 {
		t.Fatalf("conflict evidence count=%d", len(repository.conflicts))
	}
}

func TestForgedRawReceiptCannotSuppressExternalVerification(t *testing.T) {
	repository := newMemoryReceiptRepository()
	left, right := fixtureSinks()
	metrics := NewMetrics(prometheus.NewRegistry())
	artifact := fixtureArtifact()
	for _, sink := range []*memorySink{left, right} {
		descriptor := sink.Descriptor()
		repository.receipts[receiptKey(descriptor.ID, artifact.BookID, artifact.LastSequence)] = Receipt{
			SinkID: descriptor.ID, BookID: artifact.BookID,
			LastSequence: artifact.LastSequence, ObjectKey: artifact.ObjectKey,
			ContentSHA256: artifact.SHA256, Bucket: descriptor.Bucket,
			EndpointAuthority: descriptor.EndpointAuthority,
			ProviderIdentity:  "identity-" + descriptor.ID,
			VersionID:         "forged", ETag: "forged", RetentionUntil: artifact.RetainUntil,
		}
	}
	exporter, err := NewExporter(repository, []Sink{left, right}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	err = exporter.Verify(context.Background(), artifact)
	if !errors.Is(err, ErrWORMConflict) {
		t.Fatalf("forged receipt did not fail closed as P0: %v", err)
	}
	if len(repository.conflicts) != 2 {
		t.Fatalf("expected one durable P0 per missing sink object, got %d", len(repository.conflicts))
	}
	if len(left.objects) != 0 || len(right.objects) != 0 {
		t.Fatal("verification unexpectedly healed/created an object for a forged receipt")
	}
	worker := &Worker{ready: true, Metrics: metrics}
	_ = worker.fail(err)
	if worker.Ready() {
		t.Fatal("P0 external verification failure left worker ready")
	}
	for _, sinkID := range []string{"a", "b"} {
		if got := testutil.ToFloat64(metrics.WORMConflicts.WithLabelValues(sinkID)); got != 1 {
			t.Fatalf("sink %s P0 metric=%v", sinkID, got)
		}
	}
}

func TestExporterRequiresExactlyTwoIndependentSinks(t *testing.T) {
	repository := newMemoryReceiptRepository()
	left, right := fixtureSinks()
	if _, err := NewExporter(repository, []Sink{left}, nil); err == nil {
		t.Fatal("one sink accepted")
	}
	right.descriptor.IdentityDomain = left.descriptor.IdentityDomain
	if _, err := NewExporter(repository, []Sink{left, right}, nil); err == nil {
		t.Fatal("same identity domain accepted")
	}
}
