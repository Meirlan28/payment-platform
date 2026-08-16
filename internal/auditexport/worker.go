package auditexport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/example/payment-platform/internal/audit"
)

const maxMetricBooks = 4096

type healthSigner interface {
	audit.CheckpointSigner
	Health(context.Context) error
}

type WorkerConfig struct {
	SigningKeyID      string
	MaxRangeEntries   int64
	MaxReadyBacklog   int64
	MaxPendingPerBook int
	Concurrency       int
	ShardCount        uint64
	ShardIndex        uint64
}

type Worker struct {
	Repository   Repository
	Checkpointer audit.Checkpointer
	Signer       healthSigner
	Exporter     *Exporter
	Metrics      *Metrics
	Config       WorkerConfig

	mu          sync.RWMutex
	ready       bool
	lastSuccess time.Time
	lastError   error
	scrubMu     sync.Mutex
	scrubCursor map[string]int64
}

func NewWorker(repository Repository, signer healthSigner, exporter *Exporter, metrics *Metrics, config WorkerConfig) (*Worker, error) {
	if repository.DB == nil || signer == nil || exporter == nil ||
		config.SigningKeyID == "" || config.MaxRangeEntries <= 0 ||
		config.MaxRangeEntries > audit.MaxVerificationRange ||
		config.MaxReadyBacklog < 0 || config.MaxPendingPerBook <= 0 ||
		config.MaxPendingPerBook > 1024 || config.Concurrency <= 0 ||
		config.Concurrency > 256 || config.ShardCount == 0 ||
		config.ShardIndex >= config.ShardCount {
		return nil, errors.New("audit export: invalid worker configuration")
	}
	return &Worker{
		Repository:   repository,
		Checkpointer: audit.Checkpointer{DB: repository.DB, Signer: signer},
		Signer:       signer, Exporter: exporter, Metrics: metrics, Config: config,
		scrubCursor: make(map[string]int64),
	}, nil
}

func (w *Worker) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ready
}

func (w *Worker) LastStatus() (time.Time, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastSuccess, w.lastError
}

func (w *Worker) RunCycle(ctx context.Context) error {
	w.setReady(false, nil)
	if err := w.Repository.Ping(ctx); err != nil {
		return w.fail(err)
	}
	if err := w.Signer.Health(ctx); err != nil {
		return w.fail(err)
	}
	if err := w.probeSinks(ctx); err != nil {
		return w.fail(err)
	}
	books, err := w.Repository.ListBooks(ctx)
	if err != nil {
		return w.fail(err)
	}
	books = w.shardBooks(books)
	if len(books) > maxMetricBooks {
		return w.fail(fmt.Errorf("audit export: shard contains %d books; metric cardinality bound is %d", len(books), maxMetricBooks))
	}

	jobs := make(chan BookHead)
	var wait sync.WaitGroup
	var failuresMu sync.Mutex
	var failures []error
	workerCount := min(w.Config.Concurrency, max(1, len(books)))
	for range workerCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for book := range jobs {
				if err := w.processBook(ctx, book); err != nil {
					failuresMu.Lock()
					failures = append(failures, err)
					failuresMu.Unlock()
				}
			}
		}()
	}
	for _, book := range books {
		select {
		case jobs <- book:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			return w.fail(ctx.Err())
		}
	}
	close(jobs)
	wait.Wait()
	if len(failures) != 0 {
		return w.fail(errors.Join(failures...))
	}
	if err := w.observeLagAndGate(ctx); err != nil {
		return w.fail(err)
	}
	w.mu.Lock()
	w.ready = true
	w.lastSuccess = time.Now().UTC()
	w.lastError = nil
	w.mu.Unlock()
	if w.Metrics != nil {
		w.Metrics.WorkerReady.Set(1)
		w.Metrics.Cycles.WithLabelValues("success").Inc()
	}
	return nil
}

func (w *Worker) processBook(ctx context.Context, book BookHead) error {
	descriptors := w.Exporter.SinkDescriptors()
	pending, err := w.Repository.PendingCheckpoints(
		ctx, book.BookID, descriptors[0].ID, descriptors[1].ID,
		w.Config.MaxPendingPerBook,
	)
	if err != nil {
		return fmt.Errorf("audit export: book %s pending: %w", book.BookID, err)
	}
	for _, checkpoint := range pending {
		if err := w.Checkpointer.VerifyStored(ctx, checkpoint); err != nil {
			return err
		}
		artifact, err := BuildManifest(checkpoint)
		if err != nil {
			return err
		}
		artifact, err = w.Repository.EnsureManifest(ctx, artifact)
		if err != nil {
			return err
		}
		if err := w.Exporter.Export(ctx, artifact); err != nil {
			return err
		}
	}
	latest, err := w.Repository.LatestCheckpoint(ctx, book.BookID)
	if err != nil {
		return err
	}
	if len(pending) == 0 && latest < book.ClosedLastSequence {
		last := min(book.ClosedLastSequence, latest+w.Config.MaxRangeEntries)
		checkpoint, err := w.Checkpointer.Create(ctx, book.BookID, latest+1, last, w.Config.SigningKeyID)
		if err != nil {
			return fmt.Errorf("audit export: checkpoint book=%s range=%d..%d: %w", book.BookID, latest+1, last, err)
		}
		artifact, err := w.verifiedArtifact(ctx, checkpoint)
		if err != nil {
			return err
		}
		if err := w.Exporter.Export(ctx, artifact); err != nil {
			return err
		}
		latest = checkpoint.LastSequence
	}
	if latest == 0 {
		return nil
	}
	// A raw receipt is never trusted as proof. Re-HEAD the latest external
	// anchor every cycle before this shard can become ready.
	latestCheckpoint, err := w.Repository.LoadCheckpoint(ctx, book.BookID, latest)
	if err != nil {
		return err
	}
	latestArtifact, err := w.verifiedArtifact(ctx, latestCheckpoint)
	if err != nil {
		return err
	}
	if err := w.Exporter.Verify(ctx, latestArtifact); err != nil {
		return err
	}
	// One older checkpoint per book per cycle is a bounded, rotating external
	// scrub. A restart begins again at the oldest retained anchor.
	w.scrubMu.Lock()
	after := w.scrubCursor[book.BookID]
	w.scrubMu.Unlock()
	historical, found, err := w.Repository.NextHistoricalCheckpoint(ctx, book.BookID, after, latest)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	historicalArtifact, err := w.verifiedArtifact(ctx, historical)
	if err != nil {
		return err
	}
	if err := w.Exporter.Verify(ctx, historicalArtifact); err != nil {
		return err
	}
	w.scrubMu.Lock()
	w.scrubCursor[book.BookID] = historical.LastSequence
	w.scrubMu.Unlock()
	return nil
}

func (w *Worker) verifiedArtifact(ctx context.Context, checkpoint audit.Checkpoint) (Artifact, error) {
	if err := w.Checkpointer.VerifyStored(ctx, checkpoint); err != nil {
		return Artifact{}, err
	}
	artifact, err := BuildManifest(checkpoint)
	if err != nil {
		return Artifact{}, err
	}
	return w.Repository.EnsureManifest(ctx, artifact)
}

func (w *Worker) observeLagAndGate(ctx context.Context) error {
	books, err := w.Repository.ListBooks(ctx)
	if err != nil {
		return err
	}
	books = w.shardBooks(books)
	descriptors := w.Exporter.SinkDescriptors()
	var lagFailures []error
	for _, book := range books {
		checkpointLag := book.ClosedLastSequence - book.CheckpointedLast
		bookLabel := metricBookLabel(book.BookID)
		if w.Metrics != nil {
			w.Metrics.CheckpointLagEntries.WithLabelValues(bookLabel).Set(float64(checkpointLag))
		}
		if checkpointLag > w.Config.MaxReadyBacklog {
			lagFailures = append(lagFailures, fmt.Errorf(
				"audit export: book %s closed-range backlog %d exceeds readiness bound %d",
				book.BookID, checkpointLag, w.Config.MaxReadyBacklog))
		}
		for _, sink := range descriptors {
			exported, err := w.Repository.ExportedLast(ctx, sink.ID, book.BookID)
			if err != nil {
				lagFailures = append(lagFailures, err)
				continue
			}
			exportLag := book.CheckpointedLast - exported
			if w.Metrics != nil {
				w.Metrics.ExportLagEntries.WithLabelValues(sink.ID, bookLabel).Set(float64(exportLag))
			}
			if exportLag != 0 {
				lagFailures = append(lagFailures, fmt.Errorf(
					"audit export: sink %s book %s export lag is %d entries",
					sink.ID, book.BookID, exportLag))
			}
		}
	}
	return errors.Join(lagFailures...)
}

func metricBookLabel(bookID string) string {
	digest := sha256.Sum256([]byte(bookID))
	return fmt.Sprintf("%x", digest)
}

func (w *Worker) probeSinks(ctx context.Context) error {
	var failures []error
	for _, sink := range w.Exporter.sinks {
		err := sink.Probe(ctx)
		if w.Metrics != nil {
			value := 1.0
			if err != nil {
				value = 0
				w.Metrics.ExportFailure(sink.Descriptor().ID)
			}
			w.Metrics.SinkReady.WithLabelValues(sink.Descriptor().ID).Set(value)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (w *Worker) shardBooks(books []BookHead) []BookHead {
	result := make([]BookHead, 0, len(books))
	for _, book := range books {
		digest := sha256.Sum256([]byte(book.BookID))
		shard := binary.BigEndian.Uint64(digest[:8]) % w.Config.ShardCount
		if shard == w.Config.ShardIndex {
			result = append(result, book)
		}
	}
	return result
}

func (w *Worker) fail(err error) error {
	w.setReady(false, err)
	if w.Metrics != nil {
		w.Metrics.WorkerReady.Set(0)
		w.Metrics.Cycles.WithLabelValues("failure").Inc()
	}
	return err
}

func (w *Worker) setReady(ready bool, err error) {
	w.mu.Lock()
	w.ready = ready
	w.lastError = err
	w.mu.Unlock()
}
