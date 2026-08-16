# Global payment platform — executable correctness core

Это production-oriented reference implementation денежного ядра для
глобальной платёжной платформы. Источник истины — append-only double-entry
ledger в CockroachDB 26.2 `SERIALIZABLE`/Raft; Kafka 4.3 KRaft переносит события
at-least-once, но не определяет баланс. Код и тесты реализуют idempotency,
payment lifecycle, escrow, offline allowances, FX, saga/external `UNKNOWN`,
refund/chargeback/reversal, reconciliation, PII separation, audit/Merkle,
schema cutover и controlled cashback repair. Production path также
фиксирует canonical ledger bytes для DB-side hash verification,
проверяет secure-element offline presentations и разделяет
runtime database capabilities по workload identities.

Это не заявление о готовности обслуживать 2 млн ops/s. Локальный benchmark на
одном laptop с plaintext RF3 не подтверждает production RF7/Q4 capacity,
межконтинентальный p99, семь девяток или отказ трёх DC. Точные достижимые
гарантии и невозможности зафиксированы в
[FINAL SYSTEM CONTRACT](docs/final-system-contract.md).

## Архитектурный контракт

- Денежный commit — только balanced `POSTED` transaction и durable receipt из
  CockroachDB. Перед posting DB восстанавливает framing из
  persisted header/canonical metadata/ordered lines и проверяет transaction
  hash; materialized balance является проверяемой проекцией journal.
- Каждая mutation имеет scope `(mTLS principal, RPC, idempotency key)`, canonical
  payload hash и stable operation/effect IDs. Timeout не означает abort.
- API: `Authorize`, `Capture`, `Release`, `Reversal`, `Refund`, `Chargeback`,
  `GetPayment`; Money передаётся decimal integer string атомарных единиц.
- Concurrent spend сериализуется локальной authority. Progress разных sides
  partition достигается только заранее распределёнными escrow rights/offline
  allowances; без этого CAP делает одновременные availability и no-overdraft
  невозможными.
- Financial transaction и outbox intent коммитятся атомарно. Publisher использует
  TLS 1.3, mTLS/SCRAM, Kafka `acks=all`/idempotence и DB-clock leases. Consumer
  обязан deduplicate event ID в одной transaction со своим эффектом.
- PII/token mapping и encryption keys отделены от immutable ledger; GDPR deletion
  не переписывает финансовый audit.

Полное отображение протоколов на production stack: [production mapping](docs/production-mapping.md).
Операции и инциденты: [runbook](docs/operations.md). Security boundary:
[threat model](docs/threat-model.md).

## Требования к локальному запуску

- Docker Engine с Compose v2;
- GNU Make — только удобный frontend; все build/test команды выполняются в
  pinned containers;
- примерно 12 GiB свободной RAM/диска для Cockroach/Kafka и race tests.

Go line: `1.26.x` (`go1.26.5` в container), CockroachDB `v26.2.0`, Kafka
`4.3.1`. Docker Compose — **только isolated integration topology**: три
Cockroach nodes RF3 с `--insecure` и три Kafka KRaft nodes PLAINTEXT. Его нельзя
подключать к production data, credentials или rails.

## Точные команды

Запустить integration dependencies и применить ordered checksum-verified
migrations:

```bash
make up
make migrate
```

Эквивалент без Make:

```bash
docker compose up -d --wait cockroach-1 cockroach-2 cockroach-3 kafka-1 kafka-2 kafka-3
docker compose run --rm migrator
```

Проверки:

```bash
make lint
make test-unit
make test-integration
make test-chaos
make test
```

`make test-integration` запускает tagged Cockroach/Kafka tests для
schema migrator, `internal/...` и end-to-end reference migration. Последний
можно повторить изолированно:

```bash
docker compose run --rm go-toolchain \
  go test -race -count=1 -tags=integration ./tests/integration/...
```

Property/chaos suite с deterministic seeds можно повторить отдельно:

```bash
docker compose run --rm go-toolchain \
  go test -race -count=1 ./tests/chaos/...
```

Локальный Cockroach-backed benchmark:

```bash
make benchmark
```

Для сравнимого сохранённому smoke-run запуска:

```bash
docker compose run --rm go-toolchain \
  go test -run '^$' -bench '^BenchmarkLedgerPostCockroach$' \
  -benchtime=100x -count=1 -benchmem ./benchmarks
```

Outbox publisher в integration profile:

```bash
docker compose --profile application up -d --wait outbox-publisher
docker compose logs -f --tail=200 outbox-publisher
```

Остановить containers, сохранив named volumes:

```bash
make down
```

`docker compose down -v` удаляет локальные test volumes и не является обычной
командой teardown.

Генерация protobuf и сборка production images:

```bash
make generate
docker build --target runtime -t payment-api:local .
docker build --target publisher -t outbox-publisher:local .
docker build --target reconciliation -t reconciliation-worker:local .
docker build --target reference-migration -t reference-migration:local .
docker build --target migrator -t schema-migrator:local .
```

`payment-api` намеренно не имеет plaintext/local-auth fallback: для запуска ему
нужны Cockroach verify-full и server/client CA certificates. Production запуск
описан только через Kubernetes manifests.

## Production deployment

Production manifests находятся в `deploy/` и намеренно fail-closed:
`registry.invalid/...replace-with-signed-digest`, отсутствующие private DC CIDR,
backend egress и trust bootstrap должен заменить environment release pipeline.
Секретных значений в репозитории нет.

- `deploy/kubernetes/cockroach/overlays/dc-01..dc-12`: 12 sites, по три nodes,
  locality labels, TLS, PDB/anti-affinity; zone policy RF7/Q4 задаётся bootstrap.
- `deploy/kubernetes/kafka`: Strimzi Kafka 4.3.1 KRaft, 7 controllers, 12 brokers,
  TLS/mTLS/SCRAM, topic RF7/MISR4, unclean election disabled.
- `deploy/kubernetes`: payment API, outbox publisher и reconciliation worker,
  mTLS certificates, per-workload least-privilege database identities, OTel
  sidecars, PDB, topology spread, default-deny NetworkPolicy и Prometheus
  financial alerts.
- `deploy/vault`: seven-voter Vault Enterprise Raft, TLS, HSM/PKCS#11 auto-unseal,
  retained data/audit PVC и secret references.
- `deploy/otel`: mTLS gateway, privacy processors, bounded queues и monitoring.

Прямо применять base manifests нельзя. Первый deployment, database identity
bootstrap, Kafka topic sizing, migration Jobs, schema cutover и rollback gates
даны пошагово в [operations.md](docs/operations.md).
Production migration Job требует exact checked-in target filename; migrator
пишет durable receipt для каждого DDL statement и не делает
автоматический replay после ambiguous outcome.

## Что измерено, а что нет

На 2026-08-10 в локальной Compose topology выполнены:

- `go test -race -count=1 ./...`: PASS, включая 24×300 randomized invariant
  sequences и deterministic chaos;
- YAML parse, Kustomize build и `kubeconform -strict`: 0 invalid resources для
  application, Kafka, OTel и sampled Cockroach DC overlays; CRD schemas,
  отсутствующие локально, были явно skipped;
- Vault chart `0.32.0` render: 12 Kubernetes resources, 0 invalid;
- real Cockroach-backed benchmark: сохранён в
  [benchmarks/results-local.md](benchmarks/results-local.md).

Это результаты конкретных завершённых запусков, а не «зелёный статус навсегда».
Release verification для текущего hardening на 2026-08-16: **PENDING**.
Пока не зафиксированы свежий full race/integration run, clean-database
migration через все gates, no-op checksum replay и manifest validation,
release gate остаётся закрыт. Этот абзац не является отчётом о
пройденных проверках и должен быть заменён фактическим evidence
перед release.

Сохранённый smoke benchmark (100 attempts/case) показал приблизительно 3.884
successful posts/s для одного book/одного worker, 1.248 posts/s и 53% exhausted
retry budget при 16 workers на одном hot book, 17.06 posts/s на 32 books и
863.9 dedup lookups/s. Это характеристика laptop RF3 стенда, не capacity forecast.

Не измерены и потому не заявлены: 2M ops/s, RF7/Q4 production p99, произвольный
continental partition, реальная потеря трёх DC, 99.99999%, HSM latency,
jurisdiction egress proof и 48-hour backlog recovery. Их release gate требует
production-equivalent benchmark, chaos, isolated restore и signed invariant
report.

## Структура репозитория

```text
cmd/                 API, publisher, migrator и controlled migration tools
internal/            correctness protocols и production Cockroach/Kafka adapters
proto/ + gen/        protobuf/gRPC contracts и generated Go bindings
migrations/          immutable ordered Cockroach SQL
tests/chaos/         failure scenarios и randomized invariant sequences
tests/integration/   full schema cutover workflow
benchmarks/          real Cockroach ledger benchmark и measured local result
deploy/              production-only Kubernetes/Vault/OTel manifests
docs/                system contract, production mapping, operations, threats
```

Главное правило для изменений: денежная ошибка исправляется новой balanced,
idempotent, linked transaction. Старые migrations, posted journal и audit
history не редактируются.
