# Локальный измеренный baseline ledger

Дата завершения: `2026-08-10T15:12:43+05:00` (`Asia/Almaty`).

Это сохранённый результат реального запуска CockroachDB-backed benchmark, а
не расчётная производительность и не доказательство production SLO. Один
локальный хост не моделирует межконтинентальный RTT, packet loss, потерю трёх
ЦОД или production replication factor.

## Команда

```sh
docker compose run --rm go-toolchain \
  go test -run '^$' -bench '^BenchmarkLedgerPostCockroach$' \
  -benchtime=100x -count=1 -benchmem ./benchmarks
```

В каждом case выполнено ровно 100 клиентских попыток. Поэтому percentile —
полезный smoke-baseline, но выборка слишком мала для заявления p99 SLO. Setup
books/accounts и исходный effect для dedup сделаны вне таймера.

## Фактический вывод

```text
goos: linux
goarch: amd64
pkg: github.com/example/payment-platform/benchmarks
cpu: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
BenchmarkLedgerPostCockroach/same_book/workers_1-8          100  257490957 ns/op   3.884 attempts/s  0 crdb_40001/attempt  249025 p50_us   428232 p95_us    494735 p99_us     3.884 posts/s   0 retry_exhausted/op     1.000 success/op  10135 B/op   226 allocs/op
BenchmarkLedgerPostCockroach/same_book/workers_16-8         100  376608177 ns/op   2.655 attempts/s  5.140 crdb_40001/attempt 5350455 p50_us 10780932 p95_us  11210214 p99_us     1.248 posts/s   0.5300 retry_exhausted/op  0.4700 success/op  93326 B/op  1687 allocs/op
BenchmarkLedgerPostCockroach/sharded_32_books/workers_32-8  100   58631682 ns/op  17.06 attempts/s   0 crdb_40001/attempt 1718295 p50_us  2518690 p95_us   2572711 p99_us    17.06 posts/s   0 retry_exhausted/op     1.000 success/op  28267 B/op   375 allocs/op
BenchmarkLedgerPostCockroach/effect_dedup/workers_32-8      100    1157534 ns/op 863.9 attempts/s    0 crdb_40001/attempt   31928 p50_us    47690 p95_us     49068 p99_us   863.9 posts/s   0 retry_exhausted/op     1.000 success/op  17492 B/op   157 allocs/op
PASS
ok  github.com/example/payment-platform/benchmarks  75.363s
```

`ns/op` — wall-clock benchmark time, делённое на число попыток с учётом
параллелизма. `p50_us`/`p95_us`/`p99_us` — индивидуальная end-to-end latency
вызова `ledger.Service.Post`. `posts/s` считает только успешные durable POSTED
receipts. `retry_exhausted/op` — доля запросов, исчерпавших production budget в
8 SERIALIZABLE attempts. `crdb_40001/attempt` — число наблюдавшихся SQLSTATE
40001, делённое на 100 API attempts.

## Топология и версии

- Один физический хост: Intel Core i7-8650U, 4 core / 8 thread, 31.05 GiB RAM.
- Три контейнера CockroachDB `v26.2.0`, по одному в `test-a/test-b/test-c`, но
  все на одном Docker host и bridge network.
- Database zone наследует `num_replicas = 3`; это integration RF3, не
  production RF7/Q4.
- Три Kafka `4.3.1` broker/controller были запущены, но ledger benchmark Kafka
  не вызывает.
- Go toolchain `go1.26.5 linux/amd64`.
- Docker Engine `29.4.2`, Docker Compose `5.1.2`.
- Compose Cockroach использует `--insecure`; production TLS/mTLS этим запуском
  не измерялись.
- На момент post-run snapshot Cockroach containers использовали примерно
  11.5–11.8% CPU каждый; Kafka также работала в фоне. Эксклюзивного host
  reservation и изоляции шума не было.

## Интерпретация без экстраполяции

Один book имеет единственную hash-chain head и закономерно становится hot
serialization point: при 16 workers 53% попыток исчерпали ограниченный retry
budget. Разнесение 100 попыток по 32 books устранило наблюдавшиеся 40001 в этом
коротком запуске, но latency остаётся свойством именно этого слабого локального
стенда. Dedup измеряет read-existing-receipt path, а не новый финансовый post.

Эти числа нельзя линейно умножать до глобального target. Для capacity plan надо
повторить длительный benchmark на production-equivalent hardware, RF7/Q4,
реальном распределении hot accounts/books, TLS, multi-region latency и
заданном failure mode, затем передать нижнюю доверительную границу measured
per-shard TPS в `EstimateLedgerShards` вместе с utilization headroom и долей
surviving capacity.
