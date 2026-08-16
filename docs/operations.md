# Production operations runbook

Этот runbook действует вместе с [FINAL SYSTEM CONTRACT](./final-system-contract.md) и [production mapping](./production-mapping.md). При конфликте availability и financial safety оператор сохраняет safety, даже если конкретная authority временно перестанет подтверждать платежи.

## 1. Непереступаемые правила

Оператору и автоматике запрещено:

- возвращать или вручную выставлять `SUCCESS` без durable ledger receipt;
- повторять внешний платёж с новым provider reference после timeout/`UNKNOWN`;
- уменьшать Cockroach RF7/Q4, Kafka RF7/MISR4 либо включать unclean leader election для «быстрого восстановления»;
- вручную делать `UPDATE account_balances`, `UPDATE/DELETE ledger_lines` или менять `POSTED` transaction;
- возвращать escrow certificate по одному timeout без proof of non-consumption и fencing destination generation;
- использовать wall clock для определения победителя конфликтующих financial facts;
- удалять PVC, WORM segment, audit key, HSM key version или Raft peer без destructive-action review;
- копировать production PII, PAN, KYC либо database snapshot в integration/incident workspace;
- отключать TLS verification, mTLS client authentication или HSM auto-unseal fallback’ом на plaintext/Shamir.

Любое исправление денег — новый idempotent, balanced ledger effect через штатный posting path.

## 2. Production prerequisites

Перед первым rollout release owner фиксирует в change record:

1. 12 DC IDs, private CIDRs, Kubernetes contexts и Cockroach locality mapping.
2. Node labels `payment.example/dc` и storage class `encrypted-local-ssd-retained`.
3. Реальные p99 RTT/fsync до четвёртой Cockroach replica и доказательство 100-ms eligible-path budget либо явный отказ от этого SLO.
4. Capacity inequality `min surviving-nine capacity >= 2,000,000 ops/s` на реальном transaction mix.
5. Signed image digests/SBOM/provenance для Go services, Cockroach, Kafka/Strimzi, Vault-HSM и OTel Collector.
6. Vault/HSM key ownership, recovery custodians, certificate chains и expiry monitors.
7. Jurisdiction/data-class placement matrix, egress policy и WORM destinations.
8. Kafka partition count, выведенный из benchmark, а не выбранный приблизительно.
9. 48-hour outbox/reconciliation storage budget и recovery throughput `mu > live_rate`.
10. Последний успешный isolated restore и three-DC chaos report.

Compose не удовлетворяет этим prerequisites: это plaintext integration topology из трёх Cockroach и трёх Kafka containers.

## 3. Validation перед apply

Задайте только несекретные context names:

```bash
export PAYMENTS_CONTEXT=payments-control
export PAYMENTS_NAMESPACE=payments
```

Проверьте клиентские версии и server-side schemas:

```bash
kubectl --context "$PAYMENTS_CONTEXT" version
kubectl --context "$PAYMENTS_CONTEXT" get nodes -L payment.example/dc
kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server -k deploy/kubernetes
kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server -k deploy/otel
kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server -k deploy/kubernetes/kafka
```

Проверка должна fail, пока release pipeline не заменил `registry.invalid/...replace-with-signed-digest`, не созданы trust bootstrap resources и не установлены CRD cert-manager, cert-manager CSI, Prometheus Operator, Multi-Cluster Services и Strimzi.

Для Vault сначала render, затем policy/admission scan:

```bash
helm template vault hashicorp/vault --version 0.32.0 \
  --namespace vault --values deploy/vault/helm-values.yaml > /secure-review/vault-rendered.yaml
```

`/secure-review` — encrypted access-controlled workspace; rendered files могут содержать resource references, но не должны содержать secret values.

## 4. Порядок первого production deployment

### 4.1 Trust/Vault

1. Offline/platform bootstrap предоставляет `vault-server-tls`, HSM PIN reference и Enterprise license reference.
2. Установить семь Vault Raft voters по [deploy/vault/README.md](../deploy/vault/README.md).
3. Провести maker-checker `vault operator init`; recovery shares никогда не попадают в CI/logs.
4. Настроить Kubernetes auth, PKI roles, Transit signing keys, database roles, два audit sinks и WORM snapshots.
5. Проверить HSM seal, Raft quorum, certificate issuance и restore до запуска Cockroach.

### 4.2 CockroachDB

Применить ровно один site overlay в соответствующий context:

```bash
for site_number in 01 02 03 04 05 06 07 08 09 10 11 12; do
  kubectl --context "payments-dc-${site_number}" apply -k \
    "deploy/kubernetes/cockroach/overlays/dc-${site_number}"
done
```

Команда предполагает заранее настроенные 12 contexts; она не создаёт cloud resources. Перед bootstrap должны резолвиться все `*.cockroach.dc-NN.payments.internal`, а network overlays должны разрешать private RPC 26357.

После доступности всех sites однократно:

```bash
kubectl --context payments-dc-01 apply -f deploy/kubernetes/cockroach/bootstrap.yaml
kubectl --context payments-dc-01 -n payments wait \
  --for=condition=complete job/cockroach-bootstrap --timeout=15m
kubectl --context payments-dc-01 -n payments logs job/cockroach-bootstrap
```

Не открывать admission, пока default zone не показывает `num_replicas=7`, `num_voters=7`, нет under-replicated ranges и каждые семь voters находятся в семи разных `dc` localities.

### 4.3 Migrations

Migration image содержит ordered, checksum-verified SQL. Migrator v2
лексически разделяет файл на reviewed statements и выполняет каждый
отдельной implicit transaction. Перед DDL он durable-записывает
`schema_migration_attempts.status='ACTIVE'` и `schema_migration_steps` с
порядковым номером и SHA-256 statement; после однозначного
commit записывает `APPLIED`. Финальная `schema_migrations` receipt с
`executor_version='schema-migrator/v2'` коммитится только при
`APPLIED` receipt для каждого statement.

`MIGRATION_TARGET_VERSION` в production обязан быть точным именем
файла, например `017_ledger_canonical_metadata_expand.sql`. Target
означает «применить все ещё не применённые migrations до и включая
этот файл», а не «выполнить только один файл». Пустое, неизвестное
или неточное имя в production запрещено. Checked-in Job содержит
намеренно невалидный placeholder и до render завершается fail closed.
Сам binary также отклоняет пустой target. Единственное исключение — точное
`MIGRATION_APPLY_ALL_ACK=APPLY_ALL_CHECKED_IN_MIGRATIONS_FOR_EPHEMERAL_INTEGRATION`,
заданное только в isolated Docker Compose topology; production Job этого env
не имеет.

Для каждого release:

1. Снять/проверить backup и migration checksum diff.
2. Проверить expand/backward compatibility двумя версиями reader.
3. В change record закрепить exact target filename, SHA-256 целевого
   migration file и digest migration image. Сверить, что все более
   ранние `schema_migrations` receipts имеют ожидаемые checksums.
4. Убедиться, что для целевой версии нет attempt без финальной
   receipt; любой такой row закрывает gate и переводится в
   maker-checker recovery ниже.
5. В rendered copy заменить Job name `schema-migrator-release-id` на
   immutable release ID, image placeholder на approved digest и
   `MIGRATION_TARGET_VERSION` на exact target filename. Применять
   только rendered, signed release artifact, не редактировать tracked template.
6. Server-side dry-run, затем один Job:

```bash
export MIGRATION_RELEASE_ID=replace-with-immutable-release-id
export MIGRATION_TARGET_VERSION=replace-with-exact-reviewed-migration-filename

kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server \
  -f "/secure-review/schema-migrator-${MIGRATION_RELEASE_ID}.yaml"
kubectl --context "$PAYMENTS_CONTEXT" apply \
  -f "/secure-review/schema-migrator-${MIGRATION_RELEASE_ID}.yaml"
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" wait \
  --for=condition=complete "job/schema-migrator-${MIGRATION_RELEASE_ID}" --timeout=30m
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" logs \
  "job/schema-migrator-${MIGRATION_RELEASE_ID}"
```

`MIGRATION_TARGET_VERSION` в shell выше — только контрольная
переменная: release renderer обязан также записать это же значение в
Job `env`; `kubectl` не подставляет shell variables в YAML. Повторно
использовать имя завершённого Job нельзя. Checksum mismatch — P0
change-control failure: не изменять старый SQL, а добавить новую
migration.

#### Ambiguous/failed DDL recovery

Если process умер между DDL commit и `APPLIED` receipt, step останется
`ACTIVE`; явная DDL ошибка обычно оставит `FAILED`. В обоих
случаях мигратор намеренно откажется от automatic replay: даже
error response не доказывает, что CockroachDB не закоммитил schema change.

Порядок recovery:

1. Закрыть rollout и сохранить Job logs, Cockroach schema-change jobs,
   migration image digest, file/statement checksums и timestamps из DB clock.
2. Maker связывает `(version, ordinal, statement_checksum)` с точным
   statement из signed image и проверяет его конкретные postconditions через
   `SHOW CREATE`, `SHOW JOBS`/job details и system catalog. Проверка «объект
   существует» недостаточна: нужны columns, constraints, validation
   state, privileges, function body/hash и все прочие эффекты именно этого
   statement.
3. Независимый checker повторяет проверку и подписывает
   incident record. До двух совпавших conclusions outcome считается
   ambiguous, и payment rollout остаётся закрыт.
4. Если `FAILED` statement доказанно не дал нужный
   postcondition, его exact SQL выполняет только incident-specific
   signed one-off Job после исправления root cause. Job снова проверяет
   exact statement hash и доводит схему до однозначного postcondition;
   это не retry стандартного migration Job.
5. Standard migrator не содержит generic `force`, `repair`, `resume` или
   «считать statement применённым»: универсальный approval-файл без
   schema-specific verifier был бы привилегированным способом пропустить DDL.
   После maker-checker расследования recovery выполняется только отдельным
   incident-specific executable artifact. Он обязан быть привязан к exact
   database identity, previous owner, version/ordinal/checksums, observed
   status/error, одноразовому nonce и двум независимым криптографическим
   approvals; внутри него зашит verifier полных postconditions именно этого
   statement.
6. One-off artifact проходит отдельный security/change review, подписывается,
   запускается с immutable Job name, проверяет/доводит все оставшиеся exact
   postconditions этой migration и атомарно сохраняет schema-specific recovery
   evidence вместе с согласованными step/attempt/final receipts. После этого
   standard migrator обязан пройти checksum no-op; любые дополнительные
   изменения выполняются только новой migration с новым номером. Старый
   attempt автоматически не переигрывается.

Прямой `UPDATE`/`DELETE` `schema_migration_attempts` или
`schema_migration_steps`, а также повтор standard Job запрещены. Репозиторий
намеренно не поставляет общий recovery bypass. До завершения подписанного
incident-specific recovery release gate остаётся закрыт; совместимый старый
payment binary продолжает обслуживать трафик, пока contract migration не
применена.

#### Ledger hash verification rollout (017/018)

`017_ledger_canonical_metadata_expand.sql` и
`018_ledger_hash_verification.sql` — разные production gates, а не один
неразрывный rollout:

1. Отдельным immutable Job с target
   `017_ledger_canonical_metadata_expand.sql` применить expand; старая
   схема остаётся читаемой.
2. Развернуть writer, который для каждого нового DRAFT сохраняет точные
   `CanonicalJSON` UTF-8 bytes вместе с `metadata` и `entry_hash`.
3. Дождаться завершения старых writers и drain всех начатых транзакций. На
   каждой jurisdiction/cell база должна вернуть `0`:

   ```sql
   SELECT count(*)
   FROM ledger_transactions
   WHERE status = 'DRAFT' AND canonical_metadata IS NULL;
   ```

4. Прогнать audit verifier на canary book и только затем отдельным
   immutable Job с target `018_ledger_hash_verification.sql` применить
   enforce. После него и INSERT, и finalization без canonical bytes fail
   closed. Между Job для `017` и Job для `018` должен быть
   отдельный signed release decision.

Старые `POSTED` строки с `canonical_metadata IS NULL` остаются неизменяемыми и
проверяются прежним v1 audit fold. Старый NULL-DRAFT после enforce нельзя
финализировать автоматически: это P0 rollout error и maker-checker recovery,
а не основание временно возвращать unverified path.

DB проверяет, что сохранённые bytes являются UTF-8 JSON, семантически равным
`metadata`, и самостоятельно хэширует именно эти bytes. Уникальную Go-сериализацию
обеспечивает writer; независимый audit verifier заново применяет
`CanonicalJSON(metadata)`, поэтому иная, хотя семантически эквивалентная,
сериализация становится hash mismatch/P0, а не скрытым вариантом истории.

#### Runtime role split rollout (019/020)

`019_runtime_least_privilege.sql` — expand, а
`020_runtime_privilege_contract.sql` — отдельный необратимый contract gate:

1. Применить только `019`; старый binary продолжает использовать ещё не
   отозванные legacy grants. Выполнить identity bootstrap ниже и проверить
   membership каждой workload identity.
2. Развернуть procedure-aware binary, который вызывает уже существующий
   `apply_payment_escrow_effect`, затем дождаться drain всех старых payment
   writers. Проверить, что canary API
   выполняет hold с authority и retry через EXECUTE-only transition.
3. Применить `020`: он снимает с `ledger_writer` все payment/FX/escrow/offline/
   inbox/saga/rail grants. После этого raw authority mutation от `payment_api`
   обязана возвращать permission denied.
4. Fresh install до запуска workloads может применить `019` и `020` подряд.

Pipeline формирует для каждого gate отдельный migration artifact; нельзя
запускать полный каталог 001–020 одним upgrade Job на живой старой версии.
После contract допустим rollback только на совместимый procedure-aware binary;
возврат широких DB grants не является rollback-механизмом.

#### Payment posting boundary rollout (021/022)

`021_payment_posting_boundary_expand.sql` и
`022_payment_posting_boundary_contract.sql` — отдельные release gates. Их
нельзя применять одним upgrade Job при работающей версии, которая пишет
`payment_effects` напрямую:

1. Применить exact target `021_payment_posting_boundary_expand.sql`. Он создаёт
   `payment_journal_runtime`, payment-template finalizer, общий
   `record_payment_effect`, append-only canonical-hash receipts и выполняет
   первый strict catch-up `payment_capture_financials`. Там же заранее
   устанавливается manifest-bound, SPEND-only transition для cashback repair.
   Legacy grants пока не снимаются.
2. Временно добавить `payment_journal_runtime` к существующему `payment_api`,
   сохранив `ledger_writer` только на время mixed-version окна. Развернуть
   binary, который создаёт нефинансовый DRAFT через `PreparePaymentInTx`, а
   затем одним вызовом `record_payment_effect` валидирует шаблон, finalizes и
   пишет effect/CAPTURE financial row. Проверить canary HOLD, CAPTURE с
   fee+tax+cashback, RELEASE, REFUND и retry.
3. Дождаться полного drain старых pod и начатых ими SERIALIZABLE transactions.
   До contract неоднозначный legacy cashback должен быть равен нулю:

   ```sql
   SELECT count(*)
   FROM payment_effects AS capture
   WHERE capture.effect_kind='CAPTURE'
     AND NOT EXISTS (
       SELECT 1 FROM payment_capture_financials AS financial
       WHERE financial.payment_id=capture.payment_id
         AND financial.capture_effect_id=capture.payment_effect_id)
     AND (SELECT count(*) FROM payment_effects AS cashback
          JOIN ledger_transactions AS journal
            ON journal.transaction_id=cashback.ledger_transaction_id
           AND journal.effect_id=cashback.payment_effect_id
           AND journal.status='POSTED'
          WHERE cashback.payment_id=capture.payment_id
            AND cashback.effect_kind='CASHBACK'
            AND cashback.original_transaction_id=capture.ledger_transaction_id) > 1;
   ```

4. Final identity bootstrap обязан выполнить
   `REVOKE ledger_writer FROM payment_api` и оставить
   `payment_journal_runtime`; затем проверить `SHOW GRANTS ON ROLE payment_api`.
   Только после этого применить exact target
   `022_payment_posting_boundary_contract.sql`.
5. `022` повторяет catch-up за всё old-writer окно, повторно заполняет
   canonical-hash receipts, делает 1:1 assertion для каждого CAPTURE и лишь
   затем снимает raw `INSERT` в `payment_effects` и
   `payment_capture_financials`. Он также отзывает у
   `cashback_repair_runtime` generic payment escrow transition и оставляет
   только manifest-bound SPEND wrapper. Проверить, что прямой вызов generic
   `RETURN` под repair role получает SQLSTATE `42501`, а positive repair с
   authority проходит. Crash до REVOKE сохраняет legacy path; crash после
   REVOKE оставляет уже установленный и проверенный replacement path.
6. Fresh install до запуска workload применяет `021`, затем `022`, после чего
   запускает финальный identity bootstrap. После `022` rollback на writer,
   вызывающий generic finalizer/raw effect INSERT, запрещён.

Checked-in `database-identities-bootstrap.yaml` отражает конечное состояние
после `022`; временный mixed-version grant создаётся отдельным reviewed release
artifact и не должен оставаться в Git как steady-state policy.

`cashback_repair_worker` после этого всё ещё композиционно получает
`ledger_writer`: это осознанная financial TCB для balanced, value-reducing
correction journal, а не доверие на mint escrow authority. Его generic RETURN
обязательно остаётся отозванным; дальнейшее исключение worker из TCB требует
отдельного expand/contract с kind-specific correction posting procedure.

#### Offline authority rollout (015/023/024)

Offline contract разворачивается тремя отдельными exact-target Job. `015` —
только backward-compatible expand: все presentation/closure columns nullable,
а guard из `009` не заменяется. `023` добавляет append-only key windows и
SECURITY DEFINER procedures, сохраняя legacy grants. `024` сначала усиливает
DB guards и только последними statements отзывает raw financial authority.

Порядок обязателен:

1. Применить exact target `015_offline_presentations.sql`. Старый writer после
   `015` обязан пройти issue/redeem/terminate compatibility test; полностью
   legacy receipt, у которого все v2 fields `NULL`, остаётся допустимым
   immutable audit fact. Не запускать новый procedure-aware writer: до `023`
   отсутствие required functions является ожидаемым fail-closed readiness.
2. Применить exact target `023_offline_authority_expand.sql`. Проверить, что
   старый writer всё ещё работает, а его direct domain INSERT атомарно создаёт
   initial key activation. Затем развернуть новый writer, выполнить canary
   issue → lost-ACK retry → presentation redemption и closure termination.
3. Снять два последовательных snapshot с интервалом не меньше максимального
   request/transaction retry window. Между snapshot не должно появиться новых
   fully-legacy receipts, а partial-v2 count обязан быть `0`:

   ```sql
   SELECT count(*) AS fully_legacy_receipts,
          max(redeemed_at) AS last_legacy_receipt_db_time
   FROM offline_redemption_receipts
   WHERE presentation_payload_hash IS NULL
     AND presentation_hash IS NULL
     AND merchant_account_id IS NULL
     AND acceptance_domain IS NULL
     AND challenge_hash IS NULL
     AND merchant_challenge IS NULL
     AND settlement_epoch IS NULL
     AND upload_fence IS NULL
     AND presentation_counter IS NULL
     AND device_identity_hash IS NULL
     AND device_key_id IS NULL
     AND presentation_payload IS NULL
     AND presentation_signature IS NULL;

   SELECT count(*) AS partial_v2_receipts
   FROM offline_redemption_receipts
   WHERE (presentation_payload_hash IS NOT NULL
          OR presentation_hash IS NOT NULL
          OR merchant_account_id IS NOT NULL
          OR acceptance_domain IS NOT NULL
          OR challenge_hash IS NOT NULL
          OR merchant_challenge IS NOT NULL
          OR settlement_epoch IS NOT NULL
          OR upload_fence IS NOT NULL
          OR presentation_counter IS NOT NULL
          OR device_identity_hash IS NOT NULL
          OR device_key_id IS NOT NULL
          OR presentation_payload IS NOT NULL
          OR presentation_signature IS NOT NULL)
     AND (presentation_payload_hash IS NULL
          OR presentation_hash IS NULL
          OR merchant_account_id IS NULL
          OR acceptance_domain IS NULL
          OR challenge_hash IS NULL
          OR merchant_challenge IS NULL
          OR settlement_epoch IS NULL
          OR upload_fence IS NULL
          OR presentation_counter IS NULL
          OR device_identity_hash IS NULL
          OR device_key_id IS NULL
          OR presentation_payload IS NULL
          OR presentation_signature IS NULL);
   ```

4. Доказать drain старого deployment одновременно на orchestration и DB
   уровнях: old ReplicaSet имеет `0` pods, а cluster sessions не содержат его
   immutable application name/digest. Имя нового writer обязано включать
   release digest и marker `offline-procedure-v2`; пустой/generic
   `application_name` закрывает gate.

   ```sql
   SELECT application_name, count(*)
   FROM crdb_internal.cluster_sessions
   WHERE application_name NOT LIKE '%offline-procedure-v2%'
     AND application_name LIKE '%offline%'
   GROUP BY application_name;
   ```

   Ожидается zero rows. Один только стабильный receipt count не доказывает
   drain: старый writer мог оставаться idle.
5. Key-history gates на той же SERIALIZABLE snapshot обязаны вернуть `0`:

   ```sql
   SELECT count(*) AS domains_without_exact_initial_activation
   FROM offline_acceptance_domains AS domain
   WHERE NOT EXISTS (
     SELECT 1
     FROM offline_acceptance_domain_key_activations AS activation
     WHERE activation.acceptance_domain=domain.acceptance_domain
       AND activation.key_id=domain.closure_key_id
       AND activation.activated_epoch=domain.first_settlement_epoch
   );

   SELECT count(*) AS overlapping_key_windows
   FROM offline_acceptance_domain_key_activations AS left_key
   JOIN offline_acceptance_domain_key_activations AS right_key
     ON right_key.acceptance_domain=left_key.acceptance_domain
    AND right_key.activated_epoch>left_key.activated_epoch
   LEFT JOIN offline_acceptance_domain_key_terminations AS left_end
     ON left_end.acceptance_domain=left_key.acceptance_domain
    AND left_end.key_id=left_key.key_id
   WHERE left_end.terminated_epoch IS NULL
      OR left_end.terminated_epoch>right_key.activated_epoch;
   ```

6. Maker и независимый checker фиксируют оба snapshot, session/pod evidence,
   exact checksums `015`/`023`/`024`, canary receipts и key-rotation tests.
   Только затем отдельным Job применить exact target
   `024_offline_authority_contract.sql`. Встроенный
   `assert_offline_authority_contract_ready()` повторно блокирует partial rows,
   missing initial activations и overlap до первого enforcement statement.
7. После `024` проверить `SELECT public.assert_offline_authority_contract_ready()`
   равно `true`; `SHOW GRANTS` не содержит `INSERT`/`UPDATE` на offline/escrow
   financial tables для `offline_runtime` и raw key/domain `INSERT` для
   `offline_configuration_runtime`; procedures имеют только ожидаемый
   `EXECUTE`. Negative canary под этими ролями обязан получить SQLSTATE `42501`
   на raw mint и semantic rejection на unlinked procedure call. Новый v1
   receipt, inconsistent canonical payload/hash/envelope, overlapping rotation
   и closure от retired/revoked key на более позднем logical epoch должны быть
   отклонены; historical evidence внутри старого key window остаётся valid.

Crash после любого statement безопасен: `015`/`023` ничего не отзывают; в
`024` существующий receipt trigger меняет функцию через `CREATE OR REPLACE`,
без `DROP`-окна, новые closure/proof guards создаются до revoke. После `024`
rollback означает только предыдущий procedure-aware binary. Он не удаляет
append-only key events и не возвращает raw grants; grant restoration — новый
security-reviewed forward migration, а не rollback command.

#### Runtime database identities

SQL migrations создают только NOLOGIN capability roles. После migrations
однократно на jurisdiction/cell release pipeline рендерит immutable name,
approved Cockroach image digest и ticket в
`deploy/kubernetes/database-identities-bootstrap.yaml`, затем выполняет:

```bash
kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server \
  -f deploy/kubernetes/database-identities-bootstrap.yaml
kubectl --context "$PAYMENTS_CONTEXT" apply \
  -f deploy/kubernetes/database-identities-bootstrap.yaml
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" wait \
  --for=condition=complete job/database-identities-bootstrap-release-id --timeout=10m
```

Job использует короткоживущий root certificate только для `CREATE USER`,
`GRANT` и reviewed `REVOKE`. `payment_api` получает композицию
`payment_journal_runtime`, `payment_runtime`,
`payment_escrow_runtime`, `idempotency_runtime`, `outbox_enqueue_runtime`,
`id_allocator`, `payment_authorizer`; publisher, FX, escrow transfer, offline,
offline configuration, inbox+saga workflow, rail, cashback repair,
reconciliation и reference migration получают отдельные LOGIN identities из
manifest. Certificate CN должен точно совпадать с LOGIN user. Пароли не
создаются. После выполнения сверить membership через `SHOW GRANTS`, сохранить
вывод без certificate material и дождаться expiry root cert. Любой
дополнительный grant требует security review.

### 4.4 Kafka

Установить Strimzi-compatible Kafka 4.3.1 KRaft resources:

```bash
kubectl --context "$PAYMENTS_CONTEXT" apply -k deploy/kubernetes/kafka
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" wait \
  kafka/payments-kafka --for=condition=Ready --timeout=30m
```

После benchmark создать `payment-events` и DLQ с измеренным числом partitions, RF7, MISR4 по [Kafka deployment README](../deploy/kubernetes/kafka/README.md). Producer contract: TLS/SASL, `acks=all`, idempotence enabled, stable event ID. Kafka outage не отменяет Cockroach commit/outbox.

### 4.5 OTel, API и outbox publisher

Namespace `payments` нужен sidecar ConfigMap, поэтому сначала создать namespace,
затем observability gateway/config и только потом application:

```bash
kubectl --context "$PAYMENTS_CONTEXT" apply -f deploy/kubernetes/namespace.yaml
kubectl --context "$PAYMENTS_CONTEXT" apply -k deploy/otel
kubectl --context "$PAYMENTS_CONTEXT" apply -k deploy/kubernetes
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" rollout status \
  deployment/payment-api --timeout=15m
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" rollout status \
  deployment/outbox-publisher --timeout=15m
```

Проверить, что gRPC 8443 отклоняет соединение без trusted client certificate и клиентский сертификат даёт ровно один URI SAN вида `spiffe://...`. Metrics endpoint приложения остаётся loopback; наружу его отдаёт OTel sidecar на 8889 без PII labels.

API реализует `Authorize`, `Capture`, `Release`, `Reversal`, `Refund`,
`Chargeback`, `GetPayment`. Для шести mutations negative tests обязаны доказать
principal/account/book capability fencing; principal берётся только из peer
certificate. Publisher использует TLS 1.3, Kafka mTLS+SCRAM, `acks=all`,
idempotent producer и DB-clock outbox leases. Его crash между Kafka ACK и DB
mark означает допустимый duplicate с тем же event ID.

`/ready`, `/live` и `/metrics` обоих Go binaries слушают только
`127.0.0.1:9090`. Обычный kubelet HTTP probe в этот network namespace не
попадает. Поэтому pod содержит signed static `local-http-prober`: команда
`idle` не открывает listener, а `check --url=<loopback URL> --timeout=250ms`
возвращает 0 только при HTTP 2xx. Readiness всего pod зависит от `/ready` (в том
числе DB ping), liveness — от `/live`; Service и NetworkPolicy порт 9090 не
экспортируют. Digest/SBOM prober является обязательным release artifact.

## 5. Release gate

Перед снятием zero-traffic gate обязательны:

- rendered migration Job не содержит placeholders; его exact
  `MIGRATION_TARGET_VERSION`, image digest и file checksum совпадают с
  signed change record;
- все migrations до текущего gate имеют ожидаемые checksums и
  финальные `schema_migrations` receipts; для каждой migration,
  выполненной migrator v2, все statement receipts имеют `APPLIED`,
  а unresolved `ACTIVE`/`FAILED` attempt без финальной receipt отсутствует;
- для staged rollout точно зафиксировано, какой expand/enforce/contract
  gate разрешён сейчас; отсутствие более поздней migration в
  такой точке является ожидаемым, а не checksum failure;
- Cockroach RF7/Q4 placement verified, no unavailable/under-replicated ranges;
- Kafka семь controllers/четыре quorum, topics RF7/MISR4, unclean election false;
- Vault unsealed, семь Raft peers, HSM seal active, два audit sinks работают;
- certificates имеют запас больше двух окон аварийного rollout;
- invariant gauges равны нулю на одном closed watermark;
- synthetic authorize → timeout-safe retry → capture → concurrent refund проходит;
- authorization matrix всех семи RPC отклоняет cross-principal/account access;
- outbox publication и inbox duplicate no-op подтверждены;
- rollback старого reader совместим с новой expand schema;
- Prometheus `MetricsAbsent` и все P0 alerts доставляются независимым каналом;
- региональные escrow/admission budgets загружены и их сумма прошла conservation check.

Rollout начинается одним authority/shard canary. Сравнить decision vectors, ledger hashes и projections, затем расширять по cell. Нельзя dual-write в два канонических ledger.

## 6. Нормальное наблюдение

### 6.1 Watermarks

Дашборд обязан показывать:

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

Каждое сравнение баланса/хэша указывает book/range и один `as_of` watermark. Сравнение разных watermarks не является доказательством потери.

### 6.2 Нулевые financial metrics

Эти значения обязаны быть нулём для closed verified ranges:

- `payments_ledger_balance_residual_atoms`;
- `payments_journal_replay_delta_atoms`;
- `payments_escrow_conservation_delta_atoms`;
- `payments_sequence_gap`;
- `payments_cashback_rule_violation_total` increase;
- `payments_financial_invariant_violation_total{severity="P0"}` increase.

Prometheus не является доказательством сам по себе. Signed invariant report, input watermark, Merkle root и verifier build digest сохраняются в WORM.

### 6.3 Capacity

Для DC capacity `c_i`:

\[
\min_{|F|=3}\sum_{i\notin F} c_i \ge 2{,}000{,}000.
\]

При равных DC нижняя граница — 222,223 useful ops/s на DC и 2,666,667 по fleet до headroom. Реальное число shards:

\[
N\ge\lceil2{,}000{,}000/(\rho s)\rceil,
\]

где `s` измерено на RF7/Q4 с production transaction mix, `rho` — принятый utilization ceiling.

Для backlog `B`, live deferred rate `lambda` и recovery capacity `mu`:

\[
T_{catchup}\ge B/(\mu-\lambda),\quad \mu>\lambda.
\]

Если `mu<=lambda`, scaling/admission меняют до heal; retries проблему не решат.

## 7. Financial invariant P0

### Financial invariant P0

Триггеры: residual, replay delta на одном watermark, escrow delta, gap ниже closed watermark, conflicting payload hash для уже committed effect либо tamper/Merkle mismatch.

1. Page Incident Commander, ledger owner, security и finance controller.
2. Сохранить request/effect IDs, build/rule/schema versions, Raft indices, range IDs, watermarks и signed checkpoints. Не включать PII в incident channel.
3. Остановить admission **только** затронутого posting rule/book/authority, если граница доказана. При неизвестной границе остановить новые monetary writes затронутого asset/legal entity. Read/status остаются доступны.
4. Не запускать автоматическую correction и не менять materialized balances.
5. Проверить раздел 8: lag или реальная потеря/коррупция.
6. Если физически несбалансированный `POSTED` fact подтверждён, изолировать range, сравнить quorum replicas и WORM, восстановить корректный immutable prefix. Не маскировать suspense posting’ом.
7. Если journal корректен, но business rule ошибочен, сформировать maker-checker repair manifest и только затем новые deterministic correction effects.
8. Перед reopen выполнить full replay, Merkle, escrow, lifecycle, idempotency и external reconciliation на closed watermark.
9. Сохранить signed incident invariant report и postmortem.

## 8. Replication lag или data loss

### Replication lag or data loss

Порядок диагностики:

1. Найти transaction sequence/commit token из durable receipt.
2. Сравнить `raft_quorum_committed` с receipt sequence.
3. Если projection/consumer watermark меньше sequence — это lag; не создавать correction.
4. Если consumer декларирует watermark выше sequence, но record отсутствует — gap/corruption P0.
5. Сравнить Merkle roots только для одинакового closed range.
6. Совпадающий ledger root + отстающий UI означает projection incident.
7. Разные roots на одинаковом range означают tamper/storage/corruption incident.
8. Internal capture без partner settlement в пределах договорного окна — pending reconciliation; за окном — reconciliation break, но не доказательство потери ledger money.

Запрещено «чинить» lag новой денежной проводкой.

## 9. Потеря дата-центров

### Один–три DC

1. Подтвердить точный failure set и отделить crash от network partition.
2. Проверить, что каждый affected RF7 range сохранил минимум четыре reachable voters.
3. Снять admission с failed sites; surviving sites принимают только свои escrow budgets.
4. Не force-decommission transient nodes и не понижать RF.
5. Контролировать p99 `D_(4)`, serialization retries, under-replicated ranges, Kafka ISR, Vault Raft peers и capacity surviving-nine.
6. Re-replicate только когда failure объявлен permanent и новая replica попадёт в независимый DC; не выполнять массовый rebalance во время нестабильной сети.

При четырёх потерянных voters конкретного range writes останавливаются. Наличие одной копии не даёт права формировать новый quorum вручную.

### Continental partition

1. Не перемещать права между недостижимыми sides.
2. Каждый region расходует только committed `regional_available`; exhausted account получает `PENDING/DECLINED`.
3. Offline acceptance остаётся `PROVISIONAL_OFFLINE` и ограничено allowance.
4. Ограничить aggregate admission заранее выданными regional rate budgets.
5. Резервировать worst-case 48h backlog: 345.6 млрд items при 2M/s и одном item/operation.
6. После heal сначала обменяться signed watermarks/checkpoints, затем replay certificates/events, затем reconciliation. Client webhooks идут после доказанного financial state.
7. Catch-up rate ограничить так, чтобы live authorization quorum не испытывал starvation.

Не обещается progress side, на которой нет quorum соответствующей regional authority.

## 10. Packet loss и clock fault

### 30% packet loss/reorder

- Транспорт повторяет тот же command/event ID с bounded exponential backoff+jitter.
- Caller timeout не означает abort; status/retry использует тот же idempotency key.
- Нельзя failover’ить economic operation к новой authority/reference.
- При длинном burst hard p99 100 ms не действует; ответ остаётся `PENDING/UNKNOWN`.

### Clock skew ±15 минут

1. Cockroach clock-offset guard должен quarantine/terminate skewed node.
2. Не увеличивать max clock offset до 15 минут.
3. Если отказали ≤3 voters, RF7 продолжает; иначе authority безопасно останавливается.
4. Исправить NTP/PTP вне процесса, заменить/restart node и дождаться catch-up.
5. Проверить fencing epochs, quote/hold decisions и отсутствие time-based TTL deletion.
6. Reconciliation упорядочивает facts по sequence/causal ID, не timestamp.

## 11. Kafka incident

При Kafka/KRaft outage:

1. Ledger commits продолжают создавать transactional outbox, пока его storage/value/age budget не исчерпан.
2. Не публиковать напрямую после DB commit и не отмечать outbox `PUBLISHED` вручную.
3. Не включать unclean leader election и не уменьшать MISR.
4. При достижении admission threshold ограничить операции, создающие async backlog; existing committed money не откатывать.
5. После recovery publisher отправляет постоянные event IDs at-least-once; consumer inbox делает duplicate no-op.
6. Проверить parent transaction для каждого published event и consumer watermarks до reopen dependent workflows.

## 12. Vault/HSM/PKI incident

При недоступности Vault/HSM:

- существующие pods работают только до expiry уже выданных certificates/leases;
- новые unsigned transfer certificates, root/client certificates и key operations запрещены;
- plaintext listener, static fallback credentials и отключение verification запрещены;
- если certificate expiry приблизился к минимальному safe rollout window, остановить новые зависимые effects до восстановления;
- восстановить HSM quorum/network, затем Vault Raft; не reinitialize cluster;
- проверить audit continuity, seal status, Raft peer set и unexpected token/certificate issuance;
- при подозрении на HSM PIN/node compromise считать seal keys скомпрометированными и следовать security incident ceremony, а не обычной rotation.

## 13. Ambiguous commit и внешний `UNKNOWN`

### Внутренний commit

При SQLSTATE `40003`, connection loss во время COMMIT или client timeout:

1. Не выполнять transaction closure заново с новыми IDs.
2. Повторить исходный API request с тем же `(principal, endpoint, idempotency_key)` и canonical payload.
3. Если receipt найден — вернуть его; если processing доказан не полностью — `PENDING/UNKNOWN`.
4. Другой регион детерминированно обращается к той же authority; он не создаёт replacement.

### Внешний rail

1. Сохранить original provider reference и durable `SENDING/UNKNOWN` intent.
2. Выполнить status inquiry.
3. Повторять submit только если provider документирует идемпотентность **того же** reference.
4. Иначе ждать webhook/statement/clearing reconciliation.
5. Duplicate webhook проходит inbox dedup; late fraud verdict создаёт dispute/freeze/loss entry.

## 14. Saga coordinator/stale worker

- Saga progress и worker generation читаются из Cockroach.
- Новый worker продолжает тот же step/effect/provider reference.
- Worker с устаревшим fence не имеет права commit state.
- Crash после local effect до ACK приводит к redelivery и inbox/effect no-op.
- Prepared distributed transaction не получает heuristic abort/commit; она ждёт replicated coordinator decision.
- Compensation — новая linked posting, не удаление исходного шага.

## 15. Cashback incident

### Cashback incident

Если buggy build/rule три часа начислял cashback дважды:

1. Остановить только affected cashback rule generation; capture principal не откатывать.
2. Найти диапазон по `posting_rule_version`, build ID и ledger sequences. Wall-clock interval — только подсказка.
3. Для каждой operation вычислить expected и actual по закреплённой старой rule version.
4. Создать reviewable manifest с `correction_effect_id = repair/<incident>/<original_effect>/cashback`.
5. Сверить суммы manifest по asset и legal entity; maker и независимый checker подписывают manifest HSM keys.
6. Dry-run не делает postings. Apply создаёт только новые balanced correction transactions.
7. Повторный apply должен вернуть существующие effects/no-op.
8. Если пользователь уже потратил cashback, debit идёт в permitted customer receivable либо platform incident loss по юридической политике.
9. Full replay должен дать zero cashback rule violation для repaired expected view и zero financial residual.

Reference implementation предоставляет library/tests для repair, а не production admin CLI; до появления signed command tool production apply выполняется только через reviewed ledger command service, никогда direct SQL.

## 16. Refund, reversal и chargeback operations

- Concurrent refund использует serializable `refunded + charged_back <= captured`; rejected attempts не retry’ятся с новым ID как новая сумма.
- Reversal hold создаёт release effect; post-capture reversal создаёт compensating transaction.
- Unsupported asset остаётся `CLOSED_FOR_NEW_BUSINESS`, но historical ledger readable. FX refund использует явно выбранную legal policy и новую immutable quote.
- Bank insolvency/merchant shortfall создаёт receivable/reserve impairment/loss, не исчезновение payable.
- Chargeback provisional credit и final decision — разные linked effects.

## 17. Schema migration и rollback

Всегда `expand → shadow → verify → cutover → contract`:

1. Expand schema backward-compatible.
2. Старый и новый reader одновременно читают новую schema.
3. Shadow projection строится replay из immutable journal.
4. Сравнение old/new выполняется на одном watermark.
5. Fenced writer/rule generation переключается на sequence boundary.
6. Rollback возвращает reader/writer binary, но не удаляет committed new facts.
7. Contract выполняется после retention window и последнего совместимого rollback point.

Нельзя менять checksum применённой migration или backfill’ить historical facts новой бизнес-семантикой.

### Controlled reference migration

`cmd/reference-migration` выполняет restart-safe
`expand → shadow/backfill → verify → cutover → contract`. Template
`deploy/kubernetes/reference-migration-job.yaml` исключён из default
kustomization и с placeholder action намеренно завершается ошибкой. Release
pipeline создаёт **отдельный immutable Job** на каждую команду, заменяет name,
action, generation, expected state version, consumer и signed image digest.

Последовательность для новой generation:

1. `status`; записать `state_version` и active/read generation.
2. `start --expected-version=<observed>`; повтор той же команды безопасен.
3. Повторять bounded `backfill --generation=<g> --max-batches=<N>` до
   `complete=true`; не использовать unbounded Job без resource window.
4. `verify --generation=<g> --expected-version=<observed>`; source/projected
   row counts и digests должны совпасть.
5. До cutover выполнить `register-consumer` для каждого deployment consumer.
6. `cutover --generation=<g> --expected-version=<observed>` только после shadow
   verification и reader canary.
7. Каждый required consumer после фактического rollout выполняет
   `ack-consumer --consumer=<immutable deployment ID> --generation=<g>`.
8. `contract --generation=<g> --expected-version=<observed>` обязан получить
   `ErrContractBlocked`, пока хотя бы один required consumer не ACK. Contract
   допускается после rollback/retention window.

Для каждого шага:

```bash
kubectl --context "$PAYMENTS_CONTEXT" apply --server-side --dry-run=server \
  -f /secure-review/reference-migration-rendered.yaml
kubectl --context "$PAYMENTS_CONTEXT" apply \
  -f /secure-review/reference-migration-rendered.yaml
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" wait \
  --for=condition=complete job/reference-migration-release-id-phase --timeout=2h
kubectl --context "$PAYMENTS_CONTEXT" -n "$PAYMENTS_NAMESPACE" logs \
  job/reference-migration-release-id-phase
```

JSON output, manifest digest, state before/after и approvers сохраняются в change
record. Никогда не «угадывать» `expected-version`: конфликт означает новый
status/review. LOGIN `reference_migration` имеет только
`reference_migration_operator`; root/`ledger_writer` этому Job не выдаются.

## 18. Backup и restore

Backup считается пригодным только после restore drill:

1. Cockroach scheduled full+incremental backups шифруются jurisdiction KMS/HSM и пишутся в immutable cross-failure-domain storage, разрешённый residency policy.
2. WORM audit/Merkle manifests копируются независимо от DB backup.
3. Vault Raft snapshots шифруются отдельно; HSM key recovery тестируется без экспорта key material.
4. Kafka не является backup ledger; outbox восстанавливает events.
5. Restore идёт в isolated namespace/network без real rail credentials/webhook egress.
6. После restore выполнить journal replay, balances, hashes, lifecycle, idempotency, escrow и outbox-parent checks.
7. RPO=0 для committed `SUCCESS` после ≤3 DC failures достигается live RF7 quorum, не asynchronous backup. Disaster beyond boundary имеет RPO archive lag, измеренный последним verified watermark.

## 19. Destructive-action checklist

Перед node decommission, PVC/key deletion, CA retirement либо WORM retention change:

- два независимых approvers;
- точный resource ID, locality и ownership;
- quorum simulation после действия;
- verified backup/restore timestamp и hash;
- отсутствие единственной surviving committed copy;
- отсутствие ciphertext/checkpoint, требующего удаляемый key version;
- residency/legal hold approval;
- rollback/replacement plan;
- audit ticket с command transcript без secrets.

Broad recursive deletion, globbed PVC deletion и `kubectl delete --all` запрещены.

## 20. После инцидента

Закрывать инцидент можно только когда:

- invariant checker `PASS` на declared watermark;
- reconciliation breaks классифицированы и имеют linked evidence/corrections;
- no sequence/Merkle gaps;
- escrow conservation zero;
- unknown external effects находятся в согласованном SLA либо закрыты;
- projections догнали ledger;
- signed report ушёл в WORM;
- временные credentials/recovery access отозваны;
- capacity и error budget пересчитаны;
- fault scenario добавлен в deterministic/property/chaos suite.
