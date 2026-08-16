# Threat model production-платформы

Этот документ описывает security boundary реализации. Финансовые гарантии и
граница отказов заданы в [FINAL SYSTEM CONTRACT](./final-system-contract.md),
операционные действия — в [runbook](./operations.md). Threat model не делает
CockroachDB, Kafka, облако или администратора Byzantine-tolerant: компрометация
quorum/root/HSM относится к отдельной границе ниже.

## 1. Защищаемые свойства

Приоритет свойств фиксирован:

1. не создать, не уничтожить и не списать дважды economic value;
2. не выдать `SUCCESS` без durable receipt из authoritative ledger;
3. сохранить append-only provenance, causal links и 10-летний audit;
4. не раскрыть PAN, KYC, PII, ключи и provider credentials;
5. доказать residency и применить GDPR deletion без переписывания ledger;
6. сохранить bounded availability, не ослабляя первые пять свойств.

Критические assets: ledger journal и balances, escrow rights/certificates,
idempotency records, offline allowances, signing/seal keys, Cockroach/Kafka/Vault
CA, provider references, PII token mappings, audit checkpoints, schema/rule/image
versions и права операторов.

## 2. Trust boundaries и поток данных

```text
untrusted client/merchant
  -> jurisdiction ingress/WAF
  -> mTLS gRPC payment-api
  -> Cockroach RF7/Q4 authority + transactional outbox
  -> outbox-publisher -> Kafka TLS/SASL
  -> inbox-deduplicating workers / external rails

PII/card data -> jurisdiction-local token vault/KMS
telemetry -> loopback OTel sidecar -> mTLS OTel gateway -> approved backend
audit -> signed checkpoint -> jurisdiction-approved WORM
```

Ни Kafka acknowledgement, ни webhook, ни UI projection, ни Prometheus не
являются доказательством денежного commit. Trust между cells передаётся только
через проверяемый certificate/effect ID, payload hash, fencing generation и
подписанный checkpoint.

## 3. Акторы и допущения

Рассматриваются: внешний атакующий, злонамеренный/взломанный клиент или merchant,
повторитель трафика, скомпрометированный service pod, Kafka consumer, оператор,
CI/supply-chain actor, cloud/storage actor, insider с одной ролью и ошибочный
релиз. Также рассматриваются crash, reorder, duplicate, 30% packet loss, часы
±15 минут, потеря трёх DC и 48-часовой partition.

Обычная модель предполагает:

- криптография и HSM не сломаны;
- атакующий не контролирует Cockroach quorum, Vault root/recovery ceremony и
  release quorum одновременно;
- kernels, CNI и admission control обеспечивают заявленную изоляцию;
- внешний банк/rail может ошибиться или обанкротиться, но его statement можно
  получить для reconciliation;
- PAN/CVV не попадают в этот ledger: они токенизируются в PCI boundary; CVV не
  хранится после authorization.

Компрометация четырёх voting replicas одного range, HSM signing key с правом
произвольной подписи, platform CA или двух-person release quorum может нарушить
safety. Защита здесь — разделение полномочий, tamper evidence, внешний anchor,
restore и incident response, а не ложное обещание BFT.

## 4. Идентичность и авторизация

- Public/internal API принимает TLS 1.3 и требует verified client certificate.
- Principal извлекается только из peer certificate с **ровно одним** SPIFFE URI
  SAN; client metadata не может подменить principal.
- Mutation scope связывает principal, RPC, authority/book/account ownership и
  idempotency scope. `Authorize`, `Capture`, `Release`, `Reversal`, `Refund` и
  `Chargeback` проверяют capability до эффекта; `GetPayment` не раскрывает чужую
  операцию.
- Capability/revocation — monotonic append-only facts. Stale pod/credential не
  обходит более новую fencing generation.
- Cockroach TLS certificate CN совпадает с LOGIN user. LOGIN users получают
  только NOLOGIN capability roles; пароли в Git отсутствуют.
- `payment_api` получает только композицию `payment_journal_runtime`,
  `payment_runtime`, `payment_escrow_runtime`, `idempotency_runtime`,
  `outbox_enqueue_runtime`, `id_allocator` и `payment_authorizer`;
  `outbox_publisher` — только outbox claim/update. FX, escrow transfer, offline,
  inbox/saga, external rail, cashback repair и reference migration используют
  отдельные LOGIN identities и непересекающиеся NOLOGIN capabilities. Schema
  migration использует короткоживущий root cert в отдельном reviewed Job.
- `payment_journal_runtime` может записать только нефинансовый `DRAFT`; у него
  нет `EXECUTE` ни generic, ни payment finalizer. Единственный
  `record_payment_effect` внутри одного `SECURITY DEFINER` вызова проверяет
  canonical request hash, principal/account intent, kind-specific line
  distribution и lifecycle counters, переводит DRAFT в `POSTED` и добавляет
  immutable effect; для `CAPTURE` там же создаётся ровно одна financial row.
  Finalizer-owned marker нельзя подать в `INSERT`, поэтому даже оставшийся у
  другого workload `ledger_writer` не может изготовить payment proof.
- `payment_escrow_runtime` не имеет `INSERT/UPDATE` на authority tables. Он
  вызывает только `SECURITY DEFINER` переход, который заново вычисляет request
  hash и принимает exact effect из предыдущей payment boundary; receipt и
  authority delta коммитятся в той же SERIALIZABLE transaction. Все relations
  внутри функций schema-qualified, поскольку CockroachDB этой версии не
  поддерживает function-level fixed `search_path`.
- После payment contract `cashback_repair_runtime` не может вызвать generic
  escrow `RETURN`: ему оставлен только manifest-bound `SPEND`, который требует
  exact `PLANNED` repair manifest, его `CASHBACK_REVERSAL` journal и связанный
  immutable `REVERSAL` effect. Сам `cashback_repair_worker` всё ещё получает
  `ledger_writer` и поэтому является явно признанной financial TCB для
  value-reducing compensating postings. Компрометация этого workload может
  создать некорректную, но balanced correction; она не получает escrow-mint
  capability и должна выявляться reconciliation/WORM audit. Полное исключение
  repair worker из TCB требует отдельной kind-specific posting procedure.
- `offline_runtime` после contract также не имеет raw `INSERT/UPDATE` на
  authority/allowance/receipt/proof tables. SECURITY DEFINER procedures
  самостоятельно связывают canonical allowance/presentation/closure bytes,
  hashes, signature-envelope hash, logical key window, POSTED ledger effect и
  conservative authority delta. SQL намеренно **не** выполняет Ed25519/HSM
  verification: verified opaque value создаёт доверенный HSM/secure-element
  adapter до retryable DB transaction. Компрометация этого adapter, обход его
  вызова или arbitrary-code execution с правом вызывать procedures может
  подделать authenticity при сохранении DB conservation; это вне
  non-Byzantine safety claim и является P0 containment boundary.
- Kubernetes service accounts не дают DB privilege сами по себе и не монтируются
  туда, где не нужны. Vault/cert-manager auth ограничен namespace, audience,
  role и issuance policy.

## 5. Основные угрозы и меры

| Угроза | Предотвращение/обнаружение | Остаточный риск/реакция |
|---|---|---|
| Replay или потерянный ответ | Durable `(principal, RPC, idempotency_key)`, canonical payload hash, stable effect ID | Тот же key с иным payload отклоняется; timeout остаётся `UNKNOWN` до lookup |
| Два concurrent debit | SERIALIZABLE transaction, conditional balance/escrow decrement, unique effect | Serialization exhaustion снижает availability, но не safety |
| Retry в другом регионе | Deterministic authority routing и глобальный idempotency record | Без quorum authority ответ pending/unavailable; replacement effect запрещён |
| Split brain/stale worker | RF7/Q4, Raft term, durable worker/authority fence | Произвольный partition не даёт quorum обоим sides одного range |
| Forged/replayed rights transfer | HSM signature, source `IN_TRANSIT`, certificate hash, destination unique consumption, generation fence | Украденный signing key — P0 key compromise |
| Offline clone/replay | Secure-element presentation связывает exact allowance, merchant/domain/challenge/counter; permanent dedup; возврат authority требует namespace-bound closure от каждого domain; append-only key windows отклоняют retired/revoked key на последующем logical epoch | Полностью офлайн merchant не знает глобальный state; acceptance provisional/bounded. Ради historical verification старый key остаётся valid внутри прежнего logical window: компрометированный private key может подделать backdated evidence этого окна, поэтому HSM compromise требует P0 containment/reconciliation, а не обещания SQL-BFT |
| Partial multi-effect payment | Все local monetary lines/limits/outbox в одной DB transaction; external work — saga | Compensation создаёт новую posting, history не удаляется |
| Crash после Kafka publish до DB mark | Event ID стабилен; Kafka idempotent producer; consumer inbox+effect dedup | Delivery at-least-once, не «exactly once transport» |
| Kafka tamper/reorder/poison | TLS/SASL ACL, RF7/MISR4, payload schema/hash, aggregate version, DLQ policy | Kafka не authority; replay из outbox; poison не пропускается молча |
| Direct DB mutation | Workload-specific roles, payment template+effect boundary, EXECUTE-only escrow transition, immutable triggers/finalizer, SQL audit, hash chain/Merkle/WORM | `ledger_writer` остаётся TCB только у явно перечисленных non-payment workloads, включая value-reducing cashback repair; `payment_api` его не получает. Repair имеет только manifest-bound escrow SPEND, не RETURN. Cockroach видит workload и immutable principal capabilities, но не независимо завершённый клиентский TLS handshake: полностью захваченный payment pod способен инициировать допустимую lifecycle-команду в пределах этой роли, однако не arbitrary journal/mint. Root/quorum actor может повредить live data; external anchor выявляет divergence |
| Buggy posting/rule | Pinned rule/build/schema version, canary/shadow, invariants, signed repair manifest | Business-correct but balanced bug исправляется compensating entries |
| Refund/chargeback abuse | Ownership capability, original capture link, cumulative bound under SERIALIZABLE | Юридический loss/insolvency отражается отдельным account, не стиранием payable |
| Clock manipulation | Деньги упорядочиваются sequence/Raft/fence; skewed DB node quarantined | Clock-based expiry не является единственной защитой |
| PII/PAN exfiltration | Tokenization, jurisdiction cell, envelope encryption, egress deny, telemetry scrub | Traffic analysis и операторский доступ требуют отдельного legal/security audit |
| GDPR deletion vs audit | Ledger хранит opaque subject token; mapping/key удаляются с receipt | Legal hold может ограничить deletion и должен быть явно зафиксирован |
| Secret theft | Vault HA, HSM auto-unseal, short-lived certs, rotation, no plaintext manifests | Уже подписанные/committed facts остаются valid; scope incident определяется key version |
| Supply-chain compromise | Pinned digest, signature/provenance/SBOM, isolated build, admission policy, canary | Placeholder/tag без approved digest fail-closed и не допускается в release |
| DoS/2M overload | Per-principal/account rate and escrow budgets, bounded queues, admission, topology spread | Safety сохраняется ценой `RESOURCE_EXHAUSTED/PENDING`; hard latency не обещается вне envelope |
| Metrics/log injection | Structured bounded fields, no raw request/PAN, attribute scrub, cardinality limits | Telemetry не используется как financial proof |
| Backup theft/tamper | Jurisdiction KMS encryption, immutable storage, signed manifest, isolated restore drill | Key loss делает backup невосстановимым; recovery ceremony тестируется заранее |

## 6. Ключи и trust hierarchy

Platform root, Cockroach node/client CA, workload/SPIFFE CA, escrow/offline signing,
audit checkpoint signing, PII envelope keys и WORM credentials — разные key
purposes и policies. Они не используют один wildcard key.

Vault — семь Raft voters, TLS everywhere и HSM/PKCS#11 auto-unseal. HSM PIN и
Enterprise license приходят только из secret references. CA/signing key rotation
имеет overlap: новые signatures используют новую version, verifier принимает
разрешённые исторические versions, пока retention/legal policy требует их.
Удаление PII DEK не удаляет audit signing key.

Break-glass требует maker/checker, time-bound identity, записанный ticket и два
независимых audit sinks. Break-glass не получает механизм UPDATE posted journal;
исправление проводится через штатную correction posting.

## 7. Data residency и privacy proof

Каждый record классифицируется до persistence: financial opaque fact, PII, PAN,
KYC, telemetry либо audit evidence. Placement policy связывает jurisdiction с
разрешёнными DB ranges, object buckets, Kafka topics, Vault mounts и egress CIDR.
Default deny не считается достаточным доказательством: регулятор получает signed
inventory из admission logs, flow logs, KMS key locality, backup/object policy и
checkpoint manifest.

Financial journal не содержит имени/email/PAN; только случайный opaque subject
token и необходимые правовые атрибуты. GDPR deletion удаляет/token-crypto-shreds
mapping в jurisdiction vault и пишет отдельный deletion receipt. Journal,
балансирующие lines и audit hashes не меняются.

## 8. Deployment controls

- Namespace работает с Pod Security `restricted`; containers non-root,
  `readOnlyRootFilesystem`, seccomp RuntimeDefault, dropped capabilities,
  resources/probes и no automatic service-account token.
- PDB, required pod anti-affinity и topology spread сохраняют failure-domain
  separation; release не проходит при insufficient labels/capacity.
- NetworkPolicy default-deny разрешает только DNS, Cockroach, Kafka, mTLS OTel и
  явный ingress. Реальные cross-DC CIDR и backend egress добавляются только
  jurisdiction overlays; репозиторий намеренно fail-closed.
- Loopback `/ready`, `/live`, `/metrics` не публикуются. Signed static
  `local-http-prober` делает exec check внутри pod; OTel sidecar экспортирует
  scrubbed metrics на отдельном port.
- Production image placeholders должны быть заменены signed digests. Compose
  plaintext RF3 предназначен только для integration и не пересекается с prod.

## 9. Security verification и evidence

Release gate включает:

- unit/property/model tests для double spend, replay, fencing, refund bounds,
  escrow conservation и clock independence;
- Cockroach integration tests под runtime roles, включая запрещённые прямые
  mutations;
- duplicate/reorder/lost response/crash-after-commit и 30% loss chaos;
- `kubeconform`, server-side dry-run, policy scan, image signature/SBOM verify;
- TLS negative tests: no cert, wrong CA, zero/multiple SPIFFE URI, expired cert;
- authorization matrix для всех семи RPC и cross-principal/account attempts;
- restore + full replay/Merkle на одном watermark;
- residency test: synthetic tagged subject и доказательство отсутствия egress;
- Vault/HSM unseal, rotation, revoke и audit-continuity drills.

Security alerts: unexpected certificate/token issuance, DB root use, role grant,
NetworkPolicy/admission change, image digest drift, audit sink gap, signature or
Merkle mismatch, principal-scope denial spike, PAN-like telemetry detection,
secret expiry и HSM/Vault seal change. Financial alerts перечислены в runbook.

## 10. Incident boundary

При подозрении на key/CA/quorum/root compromise новые affected operations
останавливаются по минимально доказанной authority boundary. Сохраняются Raft
indices, immutable journal prefix, audit checkpoints, certificate serial/key
versions и flow/admission evidence. Нельзя массово revoke исторические keys,
пока не доказано, какие retained facts ими проверяются.

После containment выполняются независимый replay, external reconciliation,
escrow conservation и residency review. Доказанная денежная ошибка исправляется
новой linked transaction; security incident никогда не оправдывает редактирование
истории.

## 11. Явно не обещано

- BFT safety при компрометации consensus majority;
- доступность любого account в обеих половинах любого partition без escrow;
- отсутствие перерасхода у полностью офлайн acceptance без bounded allowance;
- корректность/платёжеспособность внешнего банка;
- hard p99 100 ms при adversarial loss, недоступном quorum или slow rail/fraud;
- production SLO/capacity по локальному Compose benchmark.

Эти ограничения — часть security contract: система fail-closed или возвращает
`PENDING/UNKNOWN`, а не скрыто ослабляет финансовые инварианты.
