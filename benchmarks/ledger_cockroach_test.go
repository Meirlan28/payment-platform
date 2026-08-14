package benchmarks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type serializationTracer struct {
	failures atomic.Uint64
}

func (*serializationTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (t *serializationTracer) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if store.IsSerializationFailure(data.Err) {
		t.failures.Add(1)
	}
}

type benchmarkIDs struct {
	prefix string
	next   atomic.Uint64
}

func (g *benchmarkIDs) Next(context.Context) (string, error) {
	return fmt.Sprintf("%s-%d", g.prefix, g.next.Add(1)), nil
}

type ledgerHarness struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	journal *ledger.Service
	tracer  *serializationTracer
	prefix  string
	assetID string
	books   []benchmarkBook
	request atomic.Uint64
}

type benchmarkBook struct {
	bookID   string
	debitID  string
	creditID string
}

func newLedgerHarness(b *testing.B, bookCount int) *ledgerHarness {
	b.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		b.Skip("DATABASE_URL is not set; CockroachDB benchmark skipped")
	}
	if bookCount < 1 {
		b.Fatal("book count must be positive")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		b.Fatal(err)
	}
	connections := int32(runtime.GOMAXPROCS(0) * 2)
	if connections < 4 {
		connections = 4
	}
	if connections > 128 {
		connections = 128
	}
	config.MaxConns = connections
	tracer := &serializationTracer{}
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		b.Fatal(err)
	}

	prefix := "bench-" + randomSuffix(b)
	ids := &benchmarkIDs{prefix: prefix}
	runner := store.NewRunner(pool)
	journal := ledger.NewService(runner, ids)
	assetID := prefix + "-asset"
	if err := journal.RegisterAsset(ctx, ledger.Asset{
		AssetID: assetID, DisplayCode: "B" + prefix, AtomicScale: 0,
	}); err != nil {
		b.Fatal(err)
	}
	harness := &ledgerHarness{
		ctx: ctx, pool: pool, journal: journal, tracer: tracer,
		prefix: prefix, assetID: assetID,
	}
	for index := 0; index < bookCount; index++ {
		book := benchmarkBook{
			bookID:   fmt.Sprintf("%s-book-%d", prefix, index),
			debitID:  fmt.Sprintf("%s-debit-%d", prefix, index),
			creditID: fmt.Sprintf("%s-credit-%d", prefix, index),
		}
		if err := journal.CreateBook(ctx, ledger.Book{
			BookID: book.bookID, LegalEntityID: prefix + "-entity", Jurisdiction: "BENCH",
		}); err != nil {
			b.Fatal(err)
		}
		for _, account := range []ledger.Account{
			{AccountID: book.debitID, BookID: book.bookID, AssetID: assetID,
				AccountType: "BENCHMARK", NormalSide: ledger.Debit},
			{AccountID: book.creditID, BookID: book.bookID, AssetID: assetID,
				AccountType: "BENCHMARK", NormalSide: ledger.Credit},
		} {
			if err := journal.CreateAccount(ctx, account); err != nil {
				b.Fatal(err)
			}
		}
		harness.books = append(harness.books, book)
	}
	return harness
}

func randomSuffix(b *testing.B) string {
	b.Helper()
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		b.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

func (h *ledgerHarness) postRequest(bookIndex int) ledger.PostRequest {
	sequence := h.request.Add(1)
	book := h.books[bookIndex%len(h.books)]
	id := fmt.Sprintf("%s-post-%d", h.prefix, sequence)
	requestHash := sha256.Sum256([]byte("benchmark-request/v1\x00" + id))
	return ledger.PostRequest{
		TransactionID: id + "-tx", BookID: book.bookID, OperationID: id + "-operation",
		EffectID: id + "-effect", Kind: "BENCHMARK_POST", PostingRuleVersion: "benchmark-v1",
		SchemaVersion: 1, RequestHash: requestHash,
		Lines: []ledger.Line{
			{AccountID: book.debitID, AssetID: h.assetID, Side: ledger.Debit,
				AmountAtoms: ledger.NewAmountInt64(1)},
			{AccountID: book.creditID, AssetID: h.assetID, Side: ledger.Credit,
				AmountAtoms: ledger.NewAmountInt64(1)},
		},
	}
}

type exactLatencies struct {
	mu     sync.Mutex
	values []int64
}

func (l *exactLatencies) appendLocal(values []int64) {
	l.mu.Lock()
	l.values = append(l.values, values...)
	l.mu.Unlock()
}

func (l *exactLatencies) report(b *testing.B) {
	sort.Slice(l.values, func(i, j int) bool { return l.values[i] < l.values[j] })
	if len(l.values) == 0 {
		return
	}
	percentile := func(numerator int) float64 {
		index := (len(l.values)*numerator + 99) / 100
		if index < 1 {
			index = 1
		}
		if index > len(l.values) {
			index = len(l.values)
		}
		return float64(l.values[index-1]) / float64(time.Microsecond)
	}
	b.ReportMetric(percentile(50), "p50_us")
	b.ReportMetric(percentile(95), "p95_us")
	b.ReportMetric(percentile(99), "p99_us")
}

func runConcurrentPosts(b *testing.B, harness *ledgerHarness, workers int, bookFor func(uint64) int, duplicate *ledger.PostRequest) {
	b.Helper()
	if workers < 1 {
		b.Fatal("workers must be positive")
	}
	var next atomic.Uint64
	var successes atomic.Uint64
	var retryExhausted atomic.Uint64
	latencies := &exactLatencies{}
	errorsFound := make(chan error, 1)
	harness.tracer.failures.Store(0)
	b.ReportAllocs()
	b.ResetTimer()
	started := time.Now()
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			local := make([]int64, 0, (b.N/workers)+1)
			for {
				index := next.Add(1) - 1
				if index >= uint64(b.N) {
					break
				}
				request := ledger.PostRequest{}
				if duplicate == nil {
					request = harness.postRequest(bookFor(index))
				} else {
					request = *duplicate
				}
				begin := time.Now()
				receipt, err := harness.journal.Post(harness.ctx, request)
				local = append(local, time.Since(begin).Nanoseconds())
				if err != nil {
					if store.IsSerializationFailure(err) {
						retryExhausted.Add(1)
						continue
					}
					select {
					case errorsFound <- err:
					default:
					}
					continue
				}
				if duplicate != nil && !receipt.Duplicate {
					select {
					case errorsFound <- fmt.Errorf("effect retry did not return duplicate receipt"):
					default:
					}
					break
				}
				successes.Add(1)
			}
			latencies.appendLocal(local)
		}()
	}
	wait.Wait()
	elapsed := time.Since(started)
	b.StopTimer()
	select {
	case err := <-errorsFound:
		b.Fatal(err)
	default:
	}
	latencies.report(b)
	completed := successes.Load()
	if elapsed > 0 {
		b.ReportMetric(float64(completed)/elapsed.Seconds(), "posts/s")
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "attempts/s")
	}
	if b.N > 0 {
		b.ReportMetric(float64(completed)/float64(b.N), "success/op")
		b.ReportMetric(float64(retryExhausted.Load())/float64(b.N), "retry_exhausted/op")
		b.ReportMetric(float64(harness.tracer.failures.Load())/float64(b.N), "crdb_40001/attempt")
	}
}

func BenchmarkLedgerPostCockroach(b *testing.B) {
	b.Run("same_book/workers_1", func(b *testing.B) {
		harness := newLedgerHarness(b, 1)
		runConcurrentPosts(b, harness, 1, func(uint64) int { return 0 }, nil)
	})
	b.Run("same_book/workers_16", func(b *testing.B) {
		harness := newLedgerHarness(b, 1)
		runConcurrentPosts(b, harness, 16, func(uint64) int { return 0 }, nil)
	})
	b.Run("sharded_32_books/workers_32", func(b *testing.B) {
		harness := newLedgerHarness(b, 32)
		runConcurrentPosts(b, harness, 32, func(index uint64) int { return int(index % 32) }, nil)
	})
	b.Run("effect_dedup/workers_32", func(b *testing.B) {
		harness := newLedgerHarness(b, 1)
		request := harness.postRequest(0)
		if _, err := harness.journal.Post(harness.ctx, request); err != nil {
			b.Fatal(err)
		}
		runConcurrentPosts(b, harness, 32, func(uint64) int { return 0 }, &request)
	})
}
