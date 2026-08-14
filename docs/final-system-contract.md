# Максимально сильный реализуемый контракт системы

Статус документа: **нормативная спецификация**. Термины MUST, MUST NOT, SHOULD и MAY имеют смысл требований. Если архитектурное описание, код или эксплуатационный runbook противоречат этому документу, действует этот документ.

## 1. Что именно является предметом гарантии

Платформа различает три результата запроса:

- `SUCCESS`: соответствующий денежный effect зафиксирован в авторитетном ledger; существует durable commit proof и сохранённый receipt;
- `DECLINED`: денежный effect не создавался; отказ является окончательным для данного запроса;
- `PENDING`/`UNKNOWN`: окончательный результат пока не доказан. Это **не** разрешение повторить экономическую операцию с новым идентификатором и **не** обещание последующего успеха.

Сетевой HTTP/gRPC-ответ сам по себе не является финансовым фактом. Источник истины о деньгах — committed prefix неизменяемого double-entry ledger. Kafka, read model, кэш, webhook, saga-state, поисковый индекс и ответ внешнего процессора источниками истины внутреннего денежного состояния не являются.

Доступность также измеряется раздельно:

1. **API availability** — способность вернуть синтаксически корректный ответ, включая `PENDING` и обоснованный `DECLINED`.
2. **Decision availability** — способность дать окончательный `SUCCESS` или `DECLINED`.
3. **Approval availability** — способность безопасно подтвердить платёж. Именно она ограничивается quorum, escrow, кредитом, внешним rail и risk policy. Сервис, всегда возвращающий `DECLINED`, не считается финансово доступным.

## 2. Абсолютно приоритетные safety-инварианты

При всех сбоях в заявленной failure model система MUST сохранять следующие свойства.

### 2.1 Ledger safety

Для каждого committed `ledger_transaction` и каждой тройки `(book, legal_entity, asset)`:

\[
\sum debit\_atoms = \sum credit\_atoms.
\]

Суммы представлены целыми атомарными единицами либо точным decimal с фиксированным scale. IEEE-754 floating point для денег запрещён. USD и EUR балансируются независимо; они не могут компенсировать друг друга в одном уравнении.

Баланс счёта на sequence `n` определяется только свёрткой журнала:

\[
B_a(n)=B_a(0)+\sum_{i\le n} credit_i(a)-\sum_{i\le n} debit_i(a).
\]

Материализованный баланс — синхронно обновляемая проекция этого журнала. Он MUST быть воспроизводим из journal и MUST NOT исправляться оператором через `SET balance`.

### 2.2 Economic-effect safety

Для любого устойчивого `effect_id`:

\[
committed\_effect\_count(effect\_id)\le 1.
\]

At-least-once доставка допускается; повторное экономическое применение не допускается. Для неограниченно поздних повторов дедупликационный факт должен храниться не меньше максимального срока возможного replay. Если replay не ограничен протоколом, effect identity/tombstone хранится бессрочно.

Double entry само по себе не доказывает корректный экономический смысл: ошибочный cashback может быть сбалансирован расходом платформы. Поэтому каждый рост redeemable customer/merchant liability MUST иметь разрешённый posting-template source в том же batch:

- уменьшение другой redeemable liability;
- увеличение подтверждённого external/custody asset или rail receivable;
- увеличение явно одобренного credit receivable;
- уменьшение platform equity через versioned и лимитированный fee/cashback/loss rule.

Произвольный `suspense`, технический clearing account или новая неподтверждённая external receivable не могут служить источником spendable funds. Account types, допустимые направления и semantic rule version являются частью commit validation.

### 2.3 Spending safety

Для каждого счёта и актива:

\[
confirmed\_spend \le available\_balance + explicit\_credit\_limit.
\]

Кредит является отдельным, заранее выданным и учитываемым правом, а не неявным отрицательным балансом. Любое списание должно атомарно потребить баланс, hold, escrow right либо explicit credit.

### 2.4 Lifecycle safety

Как минимум выполняются:

\[
captured \le authorized,
\]

\[
\sum refunds + \sum principal\_chargebacks \le captured
\]

для тех видов dispute, где политика не создаёт отдельное новое требование. Исключения моделируются явным receivable/loss posting, а не превышением счётчика исходной операции.

Cashback, fee и tax проверяются не только бухгалтерским равенством, но и versioned semantic rule:

\[
cashback(operation,rule\_version)\le allowed\_cashback(operation,rule\_version).
\]

### 2.5 Success durability

После возврата `SUCCESS` MUST существовать:

- quorum-committed ledger record;
- durable idempotency result/receipt с тем же payload hash;
- достаточное число независимых durable copies согласно разделу 5;
- однозначная связь между receipt, operation, effect и ledger transaction.

Ни ошибка application server сразу после commit, ни потеря ответа не меняют этот факт.

### 2.6 Append-only correction

Refund, reversal, chargeback, compensation, repair и reconciliation correction — новые сбалансированные ledger transactions со ссылкой на исходный факт. Committed history не обновляется и не удаляется.

## 3. Assumptions и точная failure boundary

Гарантии ниже условны даже тогда, когда в тексте для краткости сказано «гарантируется».

### 3.1 Входящие в контракт assumptions

1. Есть 12 отдельных дата-центров, и отказ одного DC не уничтожает durable storage другого.
2. В рамках одного ledger consensus group одновременно происходит не более трёх **crash-stop/DC-loss** отказов из семи голосующих реплик.
3. Durable acknowledgment действительно означает запись на устойчивый носитель; запрещены unsafe fsync/acknowledgment modes.
4. Consensus/storage primitive реализует linearizable/serializable semantics и fencing старых лидеров согласно спецификации.
5. Криптография, HSM/KMS, хэши и подписи не скомпрометированы; ключи восстановления доступны согласно отдельной процедуре.
6. Идентификаторы issuer namespaces не переиспользуются. Идентификаторы внешнего economic request стабильны при retry.
7. Сумма и размер одной операции ограничены опубликованными лимитами. Без конечного верхнего предела нельзя вывести конечную capacity или escrow guarantee.
8. Внешний банк, card processor или blockchain может быть недоступен и может оставить эффект в `UNKNOWN`, но не может изменить уже committed внутреннюю историю.
9. После восстановления liveness сеть в итоге становится sufficiently synchronous: quorum-сообщения доставляются за конечное время. До этого момента safety сохраняется, progress может отсутствовать.
10. Для заявленного 48-часового автономного режима escrow/credit и storage capacity выделены **до** partition.

### 3.2 Не входящие в стандартную гарантию

- одновременная потеря более трёх DC, если она уничтожает все durable copies конкретного committed range;
- Byzantine-поведение consensus replicas, сговор операторов или успешная компрометация HSM;
- необнаружимая ошибка CPU/RAM/storage во всех независимых копиях и audit archives;
- физическое уничтожение всех failure domains и offline/WORM backups;
- бесконечный размер запроса, бесконечный денежный спрос или нагрузка выше admission contract;
- платёжеспособность банков, карточных сетей, stablecoin issuer или custodian;
- юридическая возможность refund в активе/юрисдикции, в которой это запрещено;
- точное время wall clock при разрешённом skew ±15 минут.

Для Byzantine tolerance при `f=3` недостаточно RF7/Q4. Классическая BFT-граница требует как минимум `3f+1=10` реплик и quorum порядка `2f+1=7`, плюс другой протокол. Настоящий контракт — crash-fault tolerant, а tamper-evident audit обнаруживает повреждение постфактум, но не превращает crash consensus в BFT consensus.

## 4. Фундаментальные невозможности

### 4.1 Один баланс, две стороны partition, отсутствие escrow

Пусть до partition доступно 100. На стороне A независимо запрашивают списание 80, на стороне B — списание 80. Состояния, видимые A, неразличимы между мирами «запрос в B отсутствует» и «B уже подтвердил 80». То же верно для B.

Если обе стороны обязаны подтвердить локально допустимый запрос, они подтвердят 160. Если перерасход запрещён, хотя бы одна сторона обязана отказаться/ждать либо заранее владеть ограниченным spending right. Следовательно, одновременно невозможны:

1. независимый прогресс обоих компонентов partition для одного и того же неразделённого права;
2. отсутствие overdraft;
3. отсутствие заранее распределённых rights/credit.

Это не недостаток реализации, а CAP/indistinguishability boundary.

### 4.2 Consensus не имеет конечного безусловного RTO

В полностью асинхронной сети задержанный узел неотличим от погибшего. При хотя бы одном crash нельзя одновременно гарантировать deterministic consensus safety и завершение за фиксированное время для каждого исполнения. Timeout — предположение о сети, а не доказательство смерти. Поэтому конечный hard RTO существует только после явно заданной bound на задержку/потерю после Global Stabilization Time.

Ограничение «не более 30% packet loss» само по себе такой bound не даёт: допустим arbitrarily long burst, после которого доставлены остальные 70%. Значит, оно не задаёт максимальную задержку отдельного сообщения и не доказывает p99 ≤ 100 ms.

### 4.3 Две автономные стороны плюс отказ трёх DC

Чтобы одна сторона продолжала linearizable writes после любых трёх локальных DC failures, ей нужно минимум семь voting failure domains: `n >= 2f+1 = 7`. Чтобы **две непересекающиеся стороны** произвольного partition обе сохраняли такое свойство, требуется минимум:

\[
2(2f+1)=2\cdot 7=14\ DC.
\]

Доступно 12. Поэтому контракт не обещает одновременный progress обеих сторон произвольного partition, если три отказа могут целиком прийтись на любую сторону. Максимум: каждая сторона продолжает только для тех независимых regional authorities, чей quorum остаётся доступным, и только в пределах их escrow rights.

Даже для durable `SUCCESS`, который должен пережить последующую потерю любых трёх DC, в каждом автономном компоненте нужны четыре distinct-DC durable copies. Два компонента требуют минимум восьми живых DC. Partition `3/9`, а также `6/6` плюс потеря трёх DC на одной стороне, не позволяет слабой стороне дать такой `SUCCESS`.

### 4.4 150 sovereign jurisdictions на 12 DC

Если каждая из 150 стран требует, чтобы даже pseudonymous financial record физически никогда не покидал страну, минимум нужен local sovereign storage/compute domain в каждой стране. Для RPO=0 после потери любых трёх local DC понадобилось бы по четыре durable domains на страну; для continued consensus writes — по семь.

Двенадцать глобальных DC физически этого не обеспечивают. Максимальный контракт допускает один из вариантов:

- локальные sovereign cells/лицензированные партнёры сверх исходных 12 DC;
- вывод за границу только юридически разрешённых, доказуемо не-Personal Data токенов;
- отсутствие сервиса в юрисдикции, требования которой нельзя выполнить.

Маркетинговое обещание «150 стран» не отменяет эту границу.

## 5. Quorum, durability и минимальное число DC

Пусть `f=3` — максимальное число crash-failed DC.

### 5.1 Только сохранность уже committed записи

Если `w` независимых DC имеют durable copy при выдаче `SUCCESS`, после произвольной потери трёх останется хотя бы одна копия тогда и только тогда, когда:

\[
w \ge f+1 = 4.
\]

Три acknowledgments недостаточны: adversary может уничтожить именно эти три DC.

### 5.2 Сохранность и продолжение linearizable writes

Для majority consensus нужны:

\[
n\ge 2f+1=7,
\qquad
q=\left\lfloor\frac n2\right\rfloor+1=4.
\]

После отказа любых трёх из семи остаются четыре, то есть quorum. Любые два quorum пересекаются:

\[
|Q_1\cap Q_2|\ge 2q-n=1.
\]

Production ledger range поэтому использует RF7/Q4 с каждой voting replica в отдельном DC/failure domain. Реплики одного диапазона в одном DC не считаются независимыми для этой гарантии.

### 5.3 Что именно означает RPO=0

Для внутренних операций со статусом `SUCCESS` ledger RPO равен нулю при потере любых трёх DC **внутри assumptions раздела 3**. Асинхронные projections, Kafka и webhook могут отстать, но восстанавливаются из ledger/outbox.

Для `PENDING`, in-flight запроса до quorum commit и внешнего rail effect в `UNKNOWN` RPO=0 не заявляется как «известный конечный результат». При этом committed intent, stable provider reference и все полученные evidence не теряются.

## 6. Нижняя граница latency

Пусть:

- `T_client` — путь client → authoritative gateway/leader;
- `T_app` — валидация, posting rules и локальная работа;
- `D_i` — время от отправки Raft append до durable acknowledgment из i-го distinct DC, включая сеть и storage;
- `D_(4)` — четвёртая порядковая статистика среди семи durable replica acknowledgments, считая local leader;
- `T_reply` — путь ответа клиенту.

Тогда для `SUCCESS`, переживающего три DC failures:

\[
T_{success}\ge T_{client}+T_{app}+D_{(4)}+T_{reply}.
\]

Ни sharding, ни кэш не могут убрать `D_(4)`. Если p99 этой суммы превышает 100 ms, p99 authorization ≤100 ms физически недостижим при требуемой durability. В частности, нельзя одновременно требовать четыре межконтинентальных durable acknowledgments и latency меньше фактического времени до четвёртого DC.

Контракт `p99 ≤ 100 ms` допустим только как условный SLO для **internal authorization fast path** при всех условиях:

- authoritative RF7/Q4 placement имеет измеренный `D_(4)` внутри latency budget;
- клиент направлен к доступной authority;
- требуемые escrow rights/credit уже локальны;
- нет ожидания slow antifraud, банка, карточной сети или blockchain finality;
- нагрузка находится внутри admission/capacity envelope;
- request не попал в recovery, hotspot или overload class.

Для каждого запроса под adversarial 30% loss hard 100 ms не гарантируется. Такие запросы получают `PENDING`/timeout, а не ложный `SUCCESS`.

Clock skew ±15 минут не влияет на ledger order: порядок задают consensus log index, transaction sequence, fencing epoch и causal references. Wall clock — атрибут наблюдаемости. Истечение FX quote/hold проверяет авторитетная state machine с conservative time uncertainty; при сомнении система безопасно отказывает или задерживает release.

## 7. Capacity: математические условия

### 7.1 Вычислительная ёмкость после потери трёх DC

Пусть `c_i` — устойчивая полезная capacity i-го DC в payment operations/sec для заданного реального transaction mix, включая replication overhead, а `λ=2,000,000 ops/s`.

Необходимое условие сохранения пика после любых трёх отказов:

\[
\min_{F\subseteq\{1..12\}, |F|=3}\sum_{i\notin F}c_i\ge \lambda.
\]

Эквивалентно, total capacity минус сумма трёх крупнейших `c_i` должна быть не меньше двух миллионов.

При одинаковых DC:

\[
c\ge\frac{2{,}000{,}000}{9}\approx222{,}223\ ops/s,
\]

а установленная fleet capacity должна быть не меньше:

\[
12c\ge 2{,}666{,}667\ ops/s.
\]

Это нижняя граница без operational headroom. Если выбран коэффициент headroom `h>1`, обе правые части умножаются на `h`. Значение `h` выводится из benchmark/queueing SLO, а не выбирается этим документом произвольно.

Если средняя операция создаёт `l` ledger lines и `e` durable outbox events, минимальные write rates составляют соответственно `2,000,000·l` lines/s и `2,000,000·e` events/s. Поэтому «2M API calls/s» нельзя подменять «2M single-row writes/s».

Пусть один production shard устойчиво обрабатывает `s` операций/с на целевом transaction mix при целевой максимальной утилизации `ρ<1`. Тогда:

\[
N_{shards}\ge\left\lceil\frac{2{,}000{,}000}{\rho s}\right\rceil.
\]

Число `s` MUST происходить из reproducible benchmark на RF7/Q4, а не из single-node теста.

### 7.2 Partition backlog

Продолжительность `H=48h=172,800s`. При **совокупном** admission rate `λ=2,000,000 ops/s` и worst case, где каждая операция создаёт одну единицу deferred inter-region work:

\[
B_{ops}=\lambda H
=2{,}000{,}000\cdot172{,}800
=345{,}600{,}000{,}000.
\]

То есть верхняя граница — 345,6 млрд deferred work items. Если одна операция создаёт `e_d` таких items, backlog равен `345.6e9·e_d`. Если средний сериализованный размер item равен `z` bytes, необходимое место без учёта replication/compression:

\[
B_{bytes}=345.6\cdot10^9\,e_d z.
\]

Если каждой стороне позволить независимо принимать до 2M/s, aggregate admission становится 4M/s, а backlog — 691,2 млрд. Поэтому 2M/s как глобальная hard capacity во время partition также требует заранее распределённых regional admission budgets; иначе это только ожидаемый, а не максимальный aggregate peak.

### 7.3 Recovery throughput

Пусть после heal pipeline имеет throughput `μ`, а новый traffic продолжает создавать deferred work со скоростью `λ_d`. Backlog когда-либо уменьшается только если:

\[
\mu>\lambda_d.
\]

Минимальное время catch-up:

\[
T_{catchup}\ge\frac{B}{\mu-\lambda_d}.
\]

Чтобы догнать backlog за заданный срок `D`:

\[
\mu\ge\lambda_d+\frac BD.
\]

В частном worst case `B=λ_dH`:

\[
\mu\ge\lambda_d\left(1+\frac HD\right).
\]

Если `μ≤λ_d`, конечного reconciliation RTO не существует независимо от количества retries.

## 8. Escrow и предел автономного расходования

Для каждого `(owner/account, asset, spending-authority-generation)` выполняется:

\[
U+\sum_r R_r+\sum_t T_t=S,
\]

где:

- `U` — unallocated authority;
- `R_r` — доступное, ещё не зарезервированное право региона `r`, уже включающее выделенную этому региону часть explicit credit;
- `T_t` — право в состоянии in-transit;
- `S` — текущая неистраченная spending authority: funded available balance плюс явно выданный credit, за вычетом уже подтверждённого расхода/hold.

Локально подтверждённое расходование региона за partition horizon ограничено:

При отсутствии новых обеспеченных поступлений, release и новых explicit credit grants:

\[
Spend_r(H)\le R_r(0).
\]

Новые локально committed поступления или credit grants могут увеличить и `R_r`, и `S` только одной сбалансированной авторитетной проводкой. Один и тот же credit не учитывается второй раз поверх `R_r`.

Если прогнозируемая monetary demand rate региона равна `v_r(t)`, необходимое и достаточное по объёму начальное право для полного обслуживания спроса без пополнения:

\[
R_r(0)\ge\int_0^H v_r(t)dt.
\]

При постоянной верхней границе `v_{r,max}`:

\[
R_r(0)\ge v_{r,max}H.
\]

Одновременно обеспечить все regional maxima возможно только если:

\[
\sum_r v_{r,max}H\le S.
\]

Нет универсального ненулевого maximum autonomous spending без заранее выделенного права. При исчерпании `R_r` новый платёж MUST стать `DECLINED` или `PENDING`; borrowing из недоступного региона без transfer certificate запрещён.

Передача rights имеет состояния `AVAILABLE_SOURCE → IN_TRANSIT → AVAILABLE_DESTINATION`. Источник сначала необратимо уменьшает своё право и создаёт одноразовый durable certificate. Destination идемпотентно потребляет certificate. `T_t` считается частью суммы только пока для certificate нет committed consumption fact; source projection может всё ещё показывать «ожидает ACK», но merged authoritative state уже не считает consumed certificate in-transit. Потерянный ACK поэтому не создаёт второе право. Вернуть certificate источнику можно только после fencing destination generation и доказательства неприменения; timeout сам по себе таким доказательством не является.

### 8.1 Offline payments

Offline устройство/merchant может расходовать только заранее подписанный allowance `A_d` с уникальными serials и, для сильной защиты, non-clonable secure element/monotonic counter:

\[
OfflineAccepted_d\le A_d.
\]

Allowance выпускается только через атомарное перемещение authority из `R_source` в offline bucket `O_d`. Расширенный conservation invariant имеет вид `U + ΣR + ΣT + ΣO = S`; сумма сертификатов не может превышать surrendered online rights.

До online redemption такой платёж имеет статус `PROVISIONAL_OFFLINE`, а не ledger `SUCCESS`. Абсолютно предотвратить двойную трату клонированного bearer token без online coordination или доверенного hardware невозможно. Контракт ограничивает maximum loss размером allowance/merchant risk limit, но не обещает нулевой fraud loss для произвольного клонированного устройства.

## 9. Consistency contract

| Объект/решение | Модель |
|---|---|
| Ledger journal, balances, holds | SERIALIZABLE/linearizable authority |
| Idempotency claim и durable result | Та же транзакционная authority, что и effect |
| Capture/refund/chargeback counters | Строгая serializable условная запись |
| Regional escrow consumption | Строгая внутри regional authority |
| Rights transfer | Два локальных строгих шага плюс monotonic in-transit certificate; eventual completion |
| Payment state transitions | Строгие и versioned; invalid transition запрещён |
| FX quote consumption | Строгая одноразовая/idempotent state transition |
| Transactional outbox creation | Атомарно с родительским ledger commit |
| Kafka delivery, inbox, webhook | At-least-once; exactly-once economic effect через inbox/effect key |
| Межрегиональное settlement | Eventual, со сбалансированными clearing/in-transit accounts |
| Search, UI read models, analytics | Eventual с обязательным watermark/`as_of` |
| Slow antifraud | Eventual; поздний verdict создаёт новый dispute/freeze/loss effect |
| Bank/card/blockchain state | Внешняя eventual reconciliation; может оставаться `UNKNOWN` |

Stale projection MUST NOT авторизовывать spend. Read-your-writes после `SUCCESS` обеспечивается чтением authority либо commit token/watermark.

Глобальная транзакция через независимые, недоступные во время partition authorities не обещается. Локально связанные проводки fee/tax/cashback/merchant payable группируются в один ledger batch, если принадлежат одной authority. Остальное выполняется durable saga с compensating entries.

### 9.1 Границы механизмов

- **Consensus** выбирает единственный порядок записей внутри authority и выдаёт fencing epoch. Он не делает один range доступным в двух minority partitions.
- **Escrow** разделяет только коммутативное ограниченное spending authority и поэтому разрешает безопасный локальный progress.
- **Saga** управляет межрегиональными и внешними шагами. Каждый шаг — локальная атомарная transaction; compensation — новый economic effect, а не rollback истории.
- **2PC** MAY быть внутренней деталью CockroachDB для доступных ranges, но application-level WAN 2PC через независимые rails/cells запрещён. После durable `PREPARE` нельзя эвристически решить outcome: при потере coordinator/quorum участник блокируется до восстановления authoritative decision. Coordinator state должен быть consensus-replicated.
- **CRDT** MAY использоваться для telemetry, mergeable observations и монотонных множеств receipt IDs. PN-counter/LWW-register не может представлять spendable balance, hold, refund capacity или escrow ownership.

## 10. Идентификаторы, retry и clocks

Глобальная уникальность не зависит от wall clock. Технический ID формируется как непереиспользуемый `issuer_namespace || incarnation || monotonic_counter`; counter ranges выдаются durable consensus, а неиспользованный хвост после crash сжигается. Для идемпотентности авторитетным ключом остаётся точный tuple `(tenant, endpoint, idempotency_key)`, защищённый unique constraint и canonical request hash.

Retry с тем же key и другим payload получает conflict. Retry с тем же payload:

- возвращает исходный durable receipt, если effect committed;
- продолжает/наблюдает исходную processing record;
- возвращает `PENDING/UNKNOWN`, если результат нельзя доказать;
- никогда не создаёт новый economic effect.

Если первый запрос committed, ответ потерян, а retry пришёл в другой регион, deterministic routing ведёт его к той же authority/effect namespace. При недоступности authority другой регион не «угадывает» результат и не создаёт replacement payment.

Для external rail сохраняется один provider reference до первой отправки. После timeout выполняется status inquiry/reconciliation либо повтор с **тем же** reference, если provider контрактно идемпотентен. Новый reference запрещён, пока доказано отсутствие первого эффекта не будет получено.

## 11. RPO, RTO, availability и recovery guarantee

### 11.1 RPO

- Internal ledger `SUCCESS`: **RPO=0** при потере любых трёх DC конкретной RF7 group и assumptions раздела 3.
- Derived projections/outbox consumers: логический RPO=0; физическое отставание измеряется watermark и replay.
- External effect: intent/evidence RPO=0, но конечный provider outcome может быть `UNKNOWN` до reconciliation.
- При потере четырёх и более DC гарантия зависит от того, сохранилась ли хотя бы одна корректная durable copy и достижим ли quorum; универсальный RPO=0 не заявляется.

### 11.2 RTO

Безусловный конечный RTO при асинхронной сети не существует. После восстановления reachable quorum:

\[
RTO_{leader}\ge T_{detect}+T_{elect}+T_{route},
\]

а верхняя граница возможна только при bounds на эти компоненты. Конкретные секунды являются эксплуатационным SLO, который должен подтверждаться chaos tests; из исходных условий они математически не выводятся.

Для reconciliation/catch-up действует формула раздела 7.3. Для account, чья authority недоступна и escrow исчерпан, decision RTO равен времени до quorum recovery/rights transfer и может достигать всей длительности partition.

### 11.3 Availability

`99.99999%` соответствует не более примерно 3.1536 секунды недоступности за 365 дней. Это может быть только измеряемым SLO с чётким denominator и eligibility conditions; исходная adversarial failure model не позволяет обещать такой hard bound end-to-end.

Максимальная safety-preserving liveness guarantee:

> Валидная внутренняя операция завершается, если её authoritative quorum доступен, необходимые rights/credit доступны локально, нагрузка ниже admission capacity и сеть после некоторого момента доставляет сообщения. Во всех остальных случаях система сохраняет safety и возвращает/удерживает `PENDING` либо `DECLINED`, но не обязана подтвердить платёж.

Сбой одного региона не блокирует несвязанные regional authorities. Сбой/partition одной внешней сети не блокирует internal wallet и другие rails, но может остановить операции, которым именно этот rail необходим.

## 12. Reconciliation proof obligation

Reconciliation MUST:

1. сравнить signed range/sequence watermarks и Merkle checkpoints;
2. найти gaps, duplicate IDs, unmatched certificates и external settlements;
3. повторно доставить существующий immutable fact либо создать новую approved correction transaction;
4. никогда не выполнять `SET balance` и не удалять исходный transaction;
5. повторно проверить ledger, lifecycle, idempotency и escrow invariants.

Почему reconciliation не создаёт и не уничтожает деньги: genesis сбалансирован; каждый разрешённый posting vector имеет нулевую сумму по каждому asset; duplicate effect — no-op; transfer перемещает authority из `R_source` в `T`, затем из `T` в `R_destination`; correction также имеет нулевую сумму. По индукции любая последовательность таких переходов сохраняет баланс и escrow conservation.

Если два immutable факта конфликтуют, система не выбирает победителя по wall clock. Она помещает exposure в явный suspense/receivable/loss account и требует доказуемую compensating transaction.

## 13. Audit, GDPR, PCI DSS и residency

Ledger содержит pseudonymous party/account IDs, amounts, assets, rules и causal references; в нём запрещены имя, email, адрес, PAN, CVV и KYC documents. PII и card vault отделены по ключам, ACL, сети и юрисдикции.

Crypto-shredding удаляет PII mapping/key, не меняя financial journal. Если закон требует хранить конкретные PII 10 лет, право удаления исполняется в пределах применимого legal-retention exception; обещать одновременно физическое удаление этих же байтов и их обязательное хранение невозможно.

Audit journal защищается hash chain, signed Merkle checkpoints и независимым WORM archive. Это делает изменение обнаружимым. Абсолютная «невозможность изменения» требует также разделения полномочий и внешнего anchoring: один администратор не должен уметь переписать и данные, и все checkpoints.

Residency claim делается отдельно по data class и стране. В production evidence входят placement policy, jurisdiction-local KMS/HSM, egress deny policy, access/network logs, signed manifests и audit report. Merkle proof доказывает содержимое/неизменность, но один хэш не доказывает отрицательный факт «копия никогда не покидала страну».

## 14. Таблица исходных требований

| Original requirement | Achievable? | Maximum realistic guarantee | Reason |
|---|---:|---|---|
| 2,000,000 payment ops/s peak | Условно | Aggregate sustained peak после трёх DC failures, если выполнена capacity inequality и число shards выведено из RF7 benchmark | Число DC само по себе не задаёт TPS; transaction mix и write amplification обязательны |
| Клиенты в 150 странах | Условно | API/rail coverage только там, где есть лицензия, rail и выполнима residency policy | Географический охват не следует из архитектуры |
| 12 DC | Да | 12 independent failure domains; RF7/Q4 per range | Не гарантирует любую комбинацию sovereign placement и двух автономных fault-tolerant сторон |
| Отказ любых трёх DC | Да, условно | RPO=0 и progress для RF7 range, если четыре оставшиеся replica достижимы | `n=2f+1=7`, `q=4` |
| Одновременно partition и три DC failures, обе стороны продолжают | Нет без оговорок | Каждая сторона продолжает только для independent authorities с reachable quorum и escrow | Для обеих сторон с tolerance `f=3` нужно минимум 14 DC |
| Continental partition до 48 часов | Да, ограниченно | Автономные платежи в пределах preallocated rights/credit и storage/admission budgets | Неограниченный общий balance нельзя безопасно расходовать с двух сторон |
| 30% packet loss | Safety — да; hard latency — нет | Retry/at-least-once сохраняют safety; progress после eventual delivery | Процент loss не ограничивает длину burst |
| Duplicate/reordered messages | Да | Exactly-once economic effect; transport at-least-once | Durable effect/inbox IDs и state-machine ordering |
| Clock skew ±15 минут | Да для денег | Correctness/order не зависят от wall clock; time policies консервативны | Consensus sequence/fencing вместо timestamps |
| Lost response после commit | Да | Retry возвращает тот же receipt либо `PENDING`; effect один | Durable idempotency record атомарен с effect |
| Crash сразу после DB commit | Да | Новый worker читает committed effect/result и outbox | Ответ сервера не является commit proof |
| `99.99999%` availability | Не как безусловная гарантия | Измеряемый conditional SLO; safety-preserving liveness при quorum/rights/capacity | 3.1536 s/year несовместимы с разрешённым 48h partition для любой authority |
| Authorization p99 ≤100 ms | Условно | Только internal eligible fast path при `D_(4)` в budget | Quorum RTT/storage — физическая нижняя граница; rails/fraud могут быть медленнее |
| Ни одна committed операция не исчезает | Да, в failure boundary | RPO=0 для `SUCCESS`, четыре durable DC copies, RF7/Q4 | Сильнее невозможно при уничтожении всех copies/ключей |
| Один effect не применяется дважды | Да | Unique effect identity во всех financial boundaries, permanent dedup horizon | Exactly-once transport не требуется |
| Деньги не создаются/уничтожаются ошибкой | Да для posting model | Per-asset double entry, posting templates, semantic invariants, append-only correction | Не гарантирует solvency внешнего банка или экономическую стоимость FX |
| Нет overdraft | Да | Spend не превышает funded rights + explicit credit | Во время partition требует escrow/credit |
| Payments на обеих сторонах без preallocation | Нет | Только read/decline/pending; success требует rights | CAP/indistinguishability proof |
| Cards | Условно | Idempotent auth/capture/clearing saga; `UNKNOWN` при неопределённом provider result | Внешний processor не входит в atomic transaction |
| Bank transfers | Условно | Reserve/send/reconcile с stable reference | Банк может быть недоступен/банкрот |
| Crypto | Условно | Intent/nonce строгие; settlement после configured finality; reorg — новый effect | Публичная сеть имеет собственную finality model |
| Internal wallets | Да | Строгий локальный ledger fast path либо certificate-based interbook saga | Один shard atomic; cross-shard eventual settlement |
| Offline payments | Только ограниченно | Preallocated signed allowance; provisional до redemption | Без online coordination/secure hardware zero double-spend невозможен |
| Any-to-any FX | Условно | Immutable quote, отдельный per-asset balance, explicit rounding/position | Нужны liquidity, supported asset и legal permission |
| Refund через шесть месяцев | Условно | Новая linked entry; closed asset остаётся readable; contractual/current FX recorded explicitly | Нельзя гарантировать доступность rail/банка/старой валюты |
| Reversal/chargeback | Да как accounting workflow | Append-only compensations, reserve/receivable/loss accounts | Финансовая корректность не устраняет credit loss |
| Slow/late antifraud | Да | Fast risk budget либо `PENDING`; late verdict создаёт dispute/freeze/loss | Нельзя ждать 5 s и одновременно всегда отвечать за 100 ms |
| Immutable 10-year audit | Да, условно | Hash/Merkle/signature + WORM + external anchoring, проверяемая целостность | Физическая абсолютность зависит от ключей и независимых archives |
| GDPR deletion + immutable finance | Да с разделением | Удаление/crypto-shredding PII mapping; lawful financial minimum остаётся | Legal retention exceptions и data minimization должны быть согласованы |
| PCI DSS | Да как control program | Separate CDE/card vault; ledger без PAN/CVV; audited controls | Compliance — не свойство одного алгоритма |
| Доказать residency для каждой страны | Условно | Sovereign cell и evidence package для конкретного data class | 12 DC недостаточно, если все 150 требуют in-country storage |
| Reconciliation не меняет историю | Да | Range comparison + replay + new correction entries only | Индуктивное сохранение double-entry/escrow invariants |
| Конечный RTO при любой допустимой сети | Нет | Conditional RTO после reachable quorum; catch-up по `B/(μ-λ)` | FLP/asynchrony и unbounded loss bursts |

## 15. FINAL SYSTEM CONTRACT

Ниже — краткая версия, на которую должны ссылаться код, тесты и эксплуатационные SLO.

1. **Authority.** Единственный внутренний источник истины о деньгах — append-only, per-asset balanced ledger transaction, committed SERIALIZABLE consensus authority.
2. **Success.** `SUCCESS` разрешён только после durable RF7/Q4 commit как минимум в четырёх distinct DC и сохранения immutable receipt. Иначе результат — `PENDING`, `UNKNOWN` или `DECLINED`.
3. **Durability.** Для `SUCCESS` гарантируется ledger RPO=0 при crash-loss любых трёх DC конкретной replica group, при сохранности assumptions раздела 3.
4. **No duplicate effect.** Каждый economic boundary использует постоянный `effect_id`; transport остаётся at-least-once, application effect — at-most-once. Retry с иным payload под тем же key отклоняется.
5. **No overdraft.** Подтверждённый spend никогда не превышает funded balance плюс явно выданный credit. Во время partition это обеспечивается preallocated escrow rights.
6. **Partition progress.** Независимый регион продолжает платежи только в пределах собственных rights и только при reachable quorum своей authority. Исчерпание rights или потеря quorum не ослабляет safety.
7. **No universal two-sided availability.** При 12 DC не гарантируется прогресс обеих сторон произвольного partition одновременно с tolerance любых трёх DC. Для двух таких независимых сторон минимум нужен 14 DC.
8. **Latency.** Authorization p99 ≤100 ms — условный SLO только для eligible internal fast path. Hard bound при adversarial loss, cross-continent quorum, external rail или slow fraud не обещается.
9. **Capacity.** Пик 2M ops/s гарантируется только после benchmark, sharding и выполнения `min surviving-nine capacity ≥ 2M/s`; backlog 48h в worst case равен 345.6 млрд deferred items на один item/operation.
10. **Recovery.** Safety действует во время partition. Конечный progress начинается после восстановления quorum/eventual delivery. Catch-up возможен только при `μ>λ`; его нижняя граница — `B/(μ-λ)`.
11. **External effects.** Внешние rail calls используют stable reference и durable intent. Timeout после внешнего success даёт `UNKNOWN`, но никогда не разрешает новый economic reference без proof of non-execution.
12. **Corrections.** Refund, reversal, chargeback, late-fraud action, incident repair и reconciliation — только новые balanced entries. История и materialized balance вручную не переписываются.
13. **Time.** Финансовый порядок, уникальность и fencing не зависят от синхронных часов. Wall clock skew может уменьшить availability time-based features, но не financial safety.
14. **Privacy.** Ledger не содержит прямых PII/PAN/KYC. PII удаляется/crypto-shreds отдельно; обязательный финансовый audit сохраняется в минимально необходимом pseudonymous виде.
15. **Residency.** Residency обещается только для явно перечисленных data classes и юрисдикций, обеспеченных sovereign placement. Если закон требует local cell, 12 глобальных DC не считаются заменой.
16. **Failure outside contract.** При >3 DC losses, Byzantine compromise, уничтожении всех copies/keys или нагрузке вне admission envelope система гарантирует best effort detection/recovery, но не заявляет прежние RPO/RTO/availability. Она всё равно MUST предпочитать остановку ложному финансовому `SUCCESS`.

Этот набор является максимально сильным непротиворечивым контрактом: он не ослабляет financial safety ради availability и не выдаёт статистический SLO за доказуемое свойство асинхронной распределённой системы.
