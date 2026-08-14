# CockroachDB ledger benchmark

This package measures the real `ledger.Service.Post` path against the
`DATABASE_URL` CockroachDB cluster. It does not replace a production load test
and it does not claim that a laptop Compose cluster can sustain the platform
target.

The benchmark reports standard `ns/op` and allocations plus exact client-side
`p50_us`, `p95_us`, `p99_us`, attempted `attempts/s`, successful `posts/s`,
`success/op`, exhausted retry-budget rate, and client-observed SQLSTATE 40001
rate. The benchmark uses the production runner's eight-attempt retry budget;
expected serialization exhaustion is measured instead of hidden by an
unbounded retry loop. Cases isolate one-book hash-chain contention, a 32-book
sharded workload, and idempotent effect lookup. Setup is outside the timer.

Run it only against a dedicated database after applying every migration:

```sh
DATABASE_URL='postgresql://...' go test -run '^$' -bench BenchmarkLedgerPostCockroach -benchmem ./benchmarks
```

Feed the measured sustainable per-book rate into `EstimateLedgerShards` with
an explicit utilization ceiling and surviving-capacity fraction. Hardware,
replica placement, SQL latency, connection limits, payload mix, hot-account
distribution, and failure mode are therefore inputs, not hidden assumptions.
