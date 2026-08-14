# Production mapping

Этот документ фиксирует обязательное отображение протоколов из [final-system-contract.md](./final-system-contract.md) на production-grade компоненты. Он не разрешает заменять финансовую authority на SQLite, process memory, map, file-backed mock или «Kafka как ledger».

## 1. Зафиксированный production stack

| Область | Обязательный компонент | Роль |
|---|---|---|
| Runtime | **Go 1.26.x** | Все stateless services, workers, protocol/state-machine libraries и operational tools |
| Financial SQL authority | **CockroachDB 26.2 Regular** | SERIALIZABLE transactions, Raft ranges, ledger, idempotency, escrow, inbox/outbox и durable saga state |
| Ledger replication | **custom RF7/Q4 placement** | 7 voting replicas в distinct DC/failure domains; quorum 4 |
| Async transport | **Apache Kafka 4.3, KRaft mode** | At-least-once events; не источник истины о деньгах |
| Contracts | **Protocol Buffers + gRPC** | Versioned internal API/event schemas, deadlines, typed error/status contract |
| Telemetry | **OpenTelemetry + Prometheus** | Distributed traces, metrics, exemplars и financial-invariant alerts |
| Secrets/keys | **Vault + jurisdiction-local KMS/HSM** | Dynamic credentials, envelope encryption, tokenization, signatures, key rotation |
| Immutable archive | S3-compatible object storage с WORM/Object Lock и external checkpoint anchoring | 10-летний audit, backups, signed Merkle manifests |

Каждый artifact pin-ится точной patch-версией и digest в release manifest. `1.26.x`, `26.2 Regular` и `4.3` задают compatibility line; production rollout использует одобренный security-patched build этой линии.

Docker Compose предназначен для воспроизводимого запуска тех же CockroachDB/Kafka/protobuf services разработчиком. Он не меняет protocol semantics. Финансовые integration/chaos tests MUST выполняться против настоящего CockroachDB, а messaging tests — против настоящего Kafka KRaft.

## 2. Ячейки, дата-центры и placement

Платформа состоит из sovereign/regional **cells**. Cell является failure-, security- и residency-boundary. Внутри неё находятся:

- API/payment command services;
- ledger/escrow ranges CockroachDB;
- regional Kafka cluster или regional ingress в Kafka fabric;
- saga и rail workers;
- jurisdiction-local Vault/KMS/HSM;
- PII/Card Vault только для разрешённых data classes.

### 2.1 RF7/Q4

Каждый authoritative Cockroach range с финансовыми данными имеет replication factor 7. Custom placement constraints обеспечивают:

1. не более одной voting replica этого range в одном DC/failure domain;
2. семь replicas в семи явно перечисленных DC;
3. majority quorum `floor(7/2)+1=4`;
4. leaseholder preference около home authority только если четвёртый durable acknowledgment укладывается в latency budget;
5. запрет временного понижения RF/quorum во время деградации;
6. continuous audit фактического replica placement против policy.

RF7 — свойство **каждого range**, а не среднее число копий по cluster. `SUCCESS` нельзя вернуть, пока запись не прошла Raft commit quorum и SERIALIZABLE SQL transaction не завершилась.

Если network component видит меньше четырёх replicas нужного range, он read-only/Unavailable для этой authority. Он не создаёт независимого альтернативного ledger. Двусторонний partition progress достигается размещением **разных regional escrow authorities** в разных Raft ranges с разными quorum placements, а не split-brain одного range.

С учётом 12 DC production не обещает, что любой произвольный разрез сети оставит quorum каждой authority на обеих сторонах. Поддерживаемые partition topologies и home-cell placements должны быть перечислены в deployment policy и проверены fault-domain simulator до rollout.

### 2.2 Clock skew

CockroachDB зависит от bounded relative clock offset для HLC. Production MUST использовать NTP/PTP monitoring и Cockroach clock-offset guard. Узел с отклонением порядка ±15 минут изолируется/останавливается и считается failed replica; нельзя увеличивать `max-offset` до 15 минут ради availability.

При не более трёх таких отказах RF7 сохраняет quorum. Если clock-fault затронул больше трёх replicas одного range, progress этого range не гарантируется, но safety не ослабляется.

Business correctness не опирается на HLC timestamp:

- uniqueness: issuer namespace + incarnation + durable counter;
- ledger order: book/range sequence и Raft order;
- stale worker fencing: durable epoch/generation;
- hold/quote expiry: авторитетная state transition с time uncertainty; финансовые строки не удаляются по TTL;
- reconciliation: sequence/watermark, а не сравнение wall-clock timestamps.

## 3. Отображение компонентов

| Protocol/application primitive | Production implementation | Недопустимая подмена |
|---|---|---|
| Atomic posting batch | CockroachDB 26.2 SERIALIZABLE transaction | Несвязанные SQL commits |
| Linearizable ledger shard | Cockroach Raft range, RF7/Q4 | Single-process mutex, SQLite |
| Balance guard | Conditional row/version update в той же SERIALIZABLE transaction | Проверка stale read model перед отдельным write |
| Economic idempotency | Unique SQL key + payload hash + result, атомарно с effect | TTL cache, Kafka producer dedup |
| Escrow spend | Serializable conditional decrement regional rights | Eventually consistent counter/PN-counter |
| Rights transfer | Durable source `IN_TRANSIT` posting + signed certificate + idempotent destination consumption | Delete at source / insert at destination без transfer identity |
| Interbook payment | Clearing accounts + certificate/saga | WAN distributed lock |
| Command/event dual write | Transactional outbox в той же SQL transaction | `COMMIT; publish Kafka` |
| Consumer dedup | Cockroach inbox unique key, атомарно с consumer effect | Kafka offset commit как единственная защита |
| Long-running process | Durable Cockroach saga state + fenced worker generation | Goroutine/process memory |
| Event transport | Kafka 4.3 KRaft, at-least-once | Kafka как financial source of truth |
| Synchronous service API | protobuf/gRPC | Неversioned JSON между core services |
| Audit integrity | Hash chain + signed Merkle checkpoints + WORM | Editable operational logs |
| PII deletion | Separate encrypted identity mapping + key destruction | Удаление/редактирование ledger rows |
| Metrics/traces | OpenTelemetry → Prometheus/trace backend | PII-bearing ad-hoc logs |

## 4. Go service topology

Services компилируются Go 1.26.x и используют общие correctness-critical libraries, а не копируют posting logic.

### 4.1 `payment-api`

- аутентифицирует tenant/client;
- требует idempotency key;
- нормализует protobuf request в versioned canonical business representation;
- вычисляет payload hash;
- детерминированно маршрутизирует запрос в home authority;
- после client deadline не считает операцию отменённой: клиент обязан узнать результат тем же key.

Публичный HTTP/JSON слой MAY транскодировать в protobuf, но internal contract и canonical hash определяются protobuf domain schema. Unknown fields, map ordering, Unicode/decimal normalization должны иметь явные правила; «hash сырых JSON bytes» запрещён.

### 4.2 `ledger-service`

Это единственный service role с правом создавать `POSTED` financial transactions. Одна SERIALIZABLE SQL transaction:

1. захватывает `(tenant, endpoint, idempotency_key)`;
2. проверяет canonical payload hash;
3. загружает accounts, holds, quote и lifecycle counters;
4. применяет versioned posting template;
5. проверяет per-asset debit/credit equality и semantic invariants;
6. вставляет immutable transaction/lines/effects;
7. условно обновляет materialized balances/limits;
8. вставляет durable receipt и outbox rows;
9. commits через RF7/Q4.

Cockroach retryable serialization error (`SQLSTATE 40001`) обрабатывается повтором **всей** чистой transaction closure с тем же operation/effect IDs. В closure запрещены сетевые вызовы, random ID generation без заранее зафиксированного ID и irreversible side effects.

Database defenses:

- unique constraints на idempotency/effect/certificate/refund keys;
- `CHECK amount_atoms > 0`, valid side/status/type и scale/version constraints;
- foreign keys на book/account/asset/original operation;
- immutable-table role grants: application roles не имеют произвольных `UPDATE/DELETE` journal rows;
- отдельный break-glass role с HSM-backed approval и полным audit, не используемый сервисами;
- periodic full replay/Merkle verification обнаруживает direct-storage tamper.

Межстрочное равенство debit/credit проверяет одна общая posting library до finalization; только validated batch получает статус `POSTED` и влияет на balance. Неполный staging batch не является ledger fact. Direct SQL access вне ledger role находится за пределами ordinary API и обнаруживается audit verification.

### 4.3 `escrow-service`

Regional rights хранятся в home ranges. Spend выполняет conditional decrement и ledger hold/debit в одной SERIALIZABLE transaction.

Transfer rights выполняется протоколом:

1. source transaction: `regional_available → rights_in_transit`, создаёт immutable certificate body/hash/signature request;
2. HSM подписывает canonical certificate, а durable signature связывается с source transaction;
3. Kafka/outbox доставляет certificate сколько угодно раз;
4. destination transaction имеет unique `(source_authority, certificate_id)` и делает `inbound_clearing → regional_available` ровно один раз;
5. ACK только переводит orchestration state; потеря ACK не меняет amount.

Certificate содержит source/destination authority, asset, amount atoms, generation, source sequence, expiry policy и unique ID. Destination проверяет подпись, asset scale, placement generation и fencing epoch.

В глобальной escrow-свёртке certificate имеет ровно одно текущее место: source right до issuance, unconsumed in-transit right после issuance либо destination right после committed consumption. Source UI/state может отставать до ACK, но consumed certificate больше не входит в authoritative `rights_in_transit`. Возврат на source разрешён только через отдельный proof-of-non-consumption/fenced transfer, а не по локальному timeout.

Offline allowance является таким же отдельным escrow bucket: его issuance атомарно уменьшает regional right. Ни устройство, ни merchant не могут выпустить allowance самостоятельно; aggregate issued allowances входят в global escrow conservation check.

### 4.4 `saga-service`

Saga state, steps, attempts, compensation state и worker generation находятся в CockroachDB. Worker получает lease/fence, но каждый side effect дополнительно защищён effect ID; lease сам по себе не обеспечивает exactly-once.

Типичный payment batch локально атомарно создаёт customer hold/capture, FX positions, fee, tax, cashback, merchant/interbook payable и outbox. Только внешние rail calls, удалённое settlement, slow fraud и webhook являются saga steps.

Coordinator crash оставляет durable step. Новый worker продолжает с тем же step/effect/provider reference. Stale worker с прошлой generation не может изменить state, а duplicate external response проходит inbox dedup.

### 4.5 Rail adapters

Для card, bank и crypto существуют отдельные adapters. Перед первым network call durable transaction сохраняет intent и provider reference. Состояния как минимум: `NOT_SENT`, `SENDING`, `UNKNOWN`, `SUCCEEDED`, `FAILED`, `RECONCILING`.

После timeout adapter:

- не создаёт новый provider reference;
- выполняет inquiry;
- повторяет тот же reference только при документированной идемпотентности provider;
- иначе оставляет `UNKNOWN` до settlement/file/webhook reconciliation.

Blockchain adapter отдельно хранит chain ID, wallet, nonce, transaction hash, observed block и finality policy. Reorg не удаляет старый observation; он создаёт новый state/effect.

### 4.6 `reconciliation-service`

Работает по immutable ranges и explicit watermarks. Он:

- сверяет sequence continuity, hash chain и signed Merkle roots;
- пересчитывает balances на одном watermark;
- сопоставляет source/destination certificates;
- дедуплицирует external messages через inbox identity;
- сопоставляет ledger clearing accounts с processor/bank/blockchain statements;
- публикует discrepancy report;
- создаёт correction command только через тот же ledger API и approved posting template.

У service role отсутствует право `UPDATE balances` и `UPDATE/DELETE journal`.

### 4.7 `identity-vault` и `card-vault`

Это отдельные deployment, database, network policy и key hierarchy.

- Ledger видит только pseudonymous party/account token.
- Identity mapping шифруется jurisdiction-local KMS key.
- PAN tokenization/signing keys находятся в HSM; CVV/full track после authorization не сохраняются.
- Crypto-shredding уничтожает mapping key/version и mapping rows согласно retention policy, не изменяя ledger.
- Backup, log, trace и support tooling подчиняются той же residency policy, что и primary data.

Для страны, требующей in-country storage, cell и KMS/HSM должны физически находиться в этой юрисдикции. Если среди исходных 12 DC такого placement нет, нужен sovereign partner cell сверх них либо рынок не включается.

## 5. CockroachDB schema/sharding contract

### 5.1 Logical ownership

Каждый account принадлежит ровно одному `book`, `legal_entity`, `asset` и authority generation. Hot transaction должен затрагивать минимальное число ranges. Routing key включает home cell/book shard; он не зависит от wall clock.

Глобальные hot accounts запрещены. Platform fee, tax, cashback, FX inventory и clearing accounts разбиваются минимум по `(legal_entity, asset, cell, shard_bucket)`, затем консолидируются append-only interbook postings.

### 5.2 SERIALIZABLE boundary

Строго атомарно в одном SQL transaction находятся:

- idempotency claim/result;
- payment/lifecycle transition;
- ledger header и lines;
- holds/capture/refund counters;
- materialized balances;
- FX quote consumption;
- local limit/escrow decrement;
- transactional outbox creation.

Если операция пересекает authority/cell boundary и quorum недоступен, она разбивается на source commit, in-transit/certificate и destination commit. Cockroach multi-range transaction MAY использоваться, только когда все ranges доступны и latency/capacity budget это допускает; он не является способом преодолеть continental partition.

### 5.3 Schema migration

Все migrations следуют `expand → shadow → verify → cutover → contract`:

1. добавить backward-compatible columns/tables/indexes;
2. сначала развернуть readers обеих версий;
3. построить новую projection replay из journal;
4. сравнить old/new на одинаковом sequence watermark;
5. переключить writer/posting-rule version через fenced configuration generation;
6. сохранить rollback reader;
7. contract старую projection только после retention/verification gate.

Historical financial facts не backfill-ятся новой семантикой. Изменение chart of accounts выполняется новой transfer/correction transaction.

## 6. Kafka 4.3 KRaft contract

Kafka переносит immutable notifications/tasks, но ledger/outbox остаётся replay source. Рекомендуемая topology — regional KRaft clusters, чтобы глобальный Kafka quorum не стоял в synchronous authorization path.

### 6.1 Producer/outbox

Outbox row создаётся атомарно с financial transaction. Publisher читает committed rows, публикует protobuf event с постоянным `event_id`, затем отмечает delivery attempt. Crash в любой точке допускает duplicate publication.

Kafka producers используют `acks=all`, idempotent producer и bounded retry как дополнительную транспортную защиту, но correctness не зависит от Kafka producer session или transactional ID.

### 6.2 Broker durability

Для event classes, которым требуется broker-level survival любых трёх DC, topic partition использует RF7, `min.insync.replicas=4`, `acks=all`, placement по distinct DC и запрет unclean leader election. Если такой WAN ack нарушает latency, topic остаётся regional, а cross-region replication асинхронна; потерянное событие восстанавливается из Cockroach outbox.

KRaft controller quorum также размещается по независимым failure domains и не совмещается логически с data quorum assumption. Потеря Kafka control plane не отменяет ledger commit: payment path накапливает outbox до bounded storage/admission limit.

### 6.3 Consumer/inbox

Consumer в одной Cockroach transaction:

1. вставляет `(consumer, event_id)` в inbox;
2. применяет локальный state/effect;
3. создаёт следующий outbox при необходимости;
4. commits;
5. только затем подтверждает Kafka offset.

Crash после SQL commit до offset ACK создаёт redelivery и inbox no-op. Permanent validation error попадает в quarantine/DLQ с original bytes, schema ID, reason и audit link; poison message не блокирует финансовый journal.

Kafka ordering гарантируется только внутри partition. Каждый event несёт aggregate ID, generation и sequence; consumer буферизует gap либо запрашивает replay, но не применяет out-of-order invalid state transition.

## 7. Protobuf/gRPC contract

Все financial commands содержат:

- `tenant_id`;
- `idempotency_key`;
- `operation_id/effect_id` либо данные для их детерминированного вывода;
- точный `Money { asset_id, amount_atoms, scale_version }`;
- expected state/generation там, где нужен compare-and-set;
- trace context, не участвующий в экономической identity.

Decimal rate передаётся как normalized integer numerator/denominator либо coefficient+scale, но не `double`. Breaking field reuse запрещён; удалённые field numbers резервируются. Events используют versioned envelope и causal parent IDs.

gRPC deadline ограничивает ожидание caller, но не откатывает уже committed effect. Канонические статусы:

- `OK` + receipt — proven `SUCCESS`;
- `ALREADY_EXISTS/FAILED_PRECONDITION` — key reused with different payload или invalid state;
- `RESOURCE_EXHAUSTED` — rights/limit/capacity exhausted;
- `UNAVAILABLE/DEADLINE_EXCEEDED` — outcome может быть неизвестен, retry только с тем же key;
- domain `PENDING/UNKNOWN` — durable operation существует, terminal evidence нет.

## 8. Vault, KMS и HSM

Vault выдаёт short-lived workload identities и dynamic Cockroach/Kafka credentials. Static credentials в image/config запрещены.

KMS выполняет envelope encryption per jurisdiction/data class. HSM выполняет:

- подпись rights transfer certificates;
- подпись Merkle checkpoints;
- card tokenization/cryptographic operations;
- approval keys для incident repair manifests.

Key version записывается в immutable record. Rotation не переписывает financial facts. Destruction key требует maker-checker/legal retention workflow. Потеря единственного ключа недопустима: recovery shares/replicas размещаются независимо, но residency boundary не нарушается.

Сбой Vault/KMS/HSM не разрешает plaintext fallback или unsigned certificate. Система останавливает соответствующий новый effect, сохраняя чтение/reconciliation там, где это безопасно.

## 9. Audit и tamper evidence

Каждая committed transaction включает previous hash либо входит в ordered hash segment. Закрытый segment получает Merkle root, sequence interval, schema/rule versions и HSM signature. Manifest записывается:

1. в Cockroach checkpoint table;
2. в jurisdiction-compliant WORM Object Lock archive;
3. во внешний независимый anchor/auditor channel.

Verifier читает journal заново, пересчитывает line hash, chain и root, проверяет signature и отсутствие sequence gaps. Изменение старой SQL row должно дать mismatch. Operational logs не заменяют это доказательство.

## 10. Observability и доказательства инвариантов

Go services инструментируются OpenTelemetry. Prometheus получает как минимум:

| Metric | Семантика / alert |
|---|---|
| `ledger_balance_residual` | MUST быть 0 по asset/book/watermark; `SEV-0` при ненуле |
| `journal_replay_delta` | MUST быть 0 на одном watermark; `SEV-0` |
| `duplicate_effect_conflict` | Same key, different hash; security/client alert, effect не применять |
| `escrow_conservation_delta` | MUST быть 0; `SEV-0` |
| `sequence_gap` | 0 после допустимого reorder window; gap за declared watermark — `SEV-0` |
| `outbox_lag` | Age/sequence/value backlog; capacity alert |
| `reconciliation_lag` | Age/value от verified watermark |
| `in_transit_value` | Amount и age по asset/corridor |
| `unknown_external_effects` | Count/value/age по provider |
| `refund_overcapture_attempt` | Отклонённые concurrent over-refunds; spike alert |
| `cashback_rule_violation` | MUST быть 0 для closed verified ranges; `SEV-0` |

Дополнительно экспортируются раздельные watermarks:

```text
raft_quorum_committed
replica_durable
wal_archived
outbox_published
projection_applied
consumer_processed
partner_acked
reconciliation_verified
```

Lag отличается от потери так:

- downstream watermark меньше sequence — наблюдаемый lag;
- downstream объявил watermark выше sequence, но record отсутствует — gap/corruption;
- Merkle roots расходятся на одинаковом closed range — corruption/data loss incident;
- external settlement не пришёл внутри договорного окна — external reconciliation break, не автоматическое доказательство внутренней потери.

Prometheus metric не является финансовым доказательством. Signed invariant report для закрытого range сохраняется в WORM и содержит input watermarks, Merkle roots, residuals и verifier build digest.

Trace/log attributes MUST NOT содержать PAN, имя, email, адрес, KYC document или raw provider secret. High-cardinality financial IDs передаются как controlled exemplars/audit links, а не unrestricted labels.

## 11. Capacity и sharding в production

Production admission controller обеспечивает aggregate peak budget и региональные budgets, сумма которых не превосходит global contract. Без preallocation во время partition два региона могут независимо принять каждый свой nominal peak.

Обязательная проверка capacity:

\[
\min_{|F|=3}\sum_{i\notin F}c_i\ge2{,}000{,}000\ ops/s.
\]

Равномерная теоретическая нижняя граница — 222,223 useful ops/s на DC и 2,666,667 ops/s по fleet до headroom. Production sizing добавляет headroom из benchmark/queueing measurements.

Benchmark проводится на:

- Cockroach 26.2 Regular RF7/Q4, реальных inter-DC RTT и storage class;
- полном posting mix, а не single-row insert;
- contention profiles для customer и platform accounts;
- idempotent retry/duplicate workload;
- three-DC loss и leader relocation;
- 30% loss/reorder profiles;
- outbox/Kafka consumers и reconciliation catch-up одновременно с live traffic.

Если shard даёт `s` sustainable payment ops/s при допустимой utilization `ρ`, deployment требует минимум `ceil(2,000,000/(ρs))` shards плюс проверку worst-case placement после трёх DC failures.

После 48h worst-case partition накапливается 345.6 млрд deferred items при одном item на operation. Storage reservations и Kafka/outbox retention выводятся из фактического encoded size. Recovery pool обязан иметь `μ>λ`; для catch-up за `D` его throughput не меньше `λ+B/D`.

## 12. Deployment gates

Release не допускается в production, пока pipeline не подтвердил:

1. все unit/property/state-machine tests;
2. integration tests на CockroachDB 26.2 SERIALIZABLE и Kafka 4.3 KRaft;
3. concurrent spend/refund/idempotency tests;
4. crash before commit и crash after commit before response;
5. stale worker fencing;
6. duplicate/reordered Kafka events и consumer crash after effect before ACK;
7. rights transfer с lost message/ACK и duplicate certificate;
8. partition + regional escrow exhaustion;
9. three-DC failure при RF7/Q4;
10. ±15-minute clock fault с quarantine, без financial corruption;
11. external success + lost response → same reference/`UNKNOWN`;
12. full journal replay, escrow conservation и Merkle tamper test;
13. cashback repair повторно запускается как no-op;
14. migration shadow projection совпадает на одном watermark;
15. residency/PII egress policy и telemetry redaction.

Failure тест считается успешным не потому, что каждый запрос получил `SUCCESS`, а потому, что система либо сделала доказанный durable effect, либо безопасно отказала/оставила `PENDING`, и после `heal → reconcile → assert_global_invariants` все финансовые инварианты проходят.

## 13. Итоговое соответствие

Production стек реализует разные задачи разными механизмами:

- CockroachDB RF7/Q4 даёт strict financial authority и RPO=0 внутри failure boundary;
- escrow даёт ограниченный автономный progress без split-brain balance;
- Kafka KRaft даёт масштабируемую at-least-once доставку, но не финансовую истину;
- inbox/outbox и stable effect IDs дают exactly-once economic effect;
- durable saga управляет неатомарными внешними процессами;
- protobuf/gRPC фиксирует versioned денежный contract без floating point;
- Vault/KMS/HSM разделяют секреты, residency keys и доказуемые подписи;
- OpenTelemetry/Prometheus показывают lag и нарушения, а signed WORM reports служат audit evidence.

Ни один production mapping не ослабляет [FINAL SYSTEM CONTRACT](./final-system-contract.md#15-final-system-contract): при невозможности одновременно сохранить safety и progress система обязана остановить/отложить конкретный effect, а не выдать недоказанный `SUCCESS`.
