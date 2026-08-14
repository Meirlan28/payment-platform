package failuresim

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/example/payment-platform/internal/ledger"
	"github.com/example/payment-platform/internal/simulation"
)

const authorityAssetPrefix = "AUTHORITY/"

type regionState struct {
	epoch   uint64
	running bool
	rights  ledger.Amount
}

type effectRecord struct {
	fingerprint [32]byte
	receipt     Receipt
}

type idempotencyRecord struct {
	requestHash [32]byte
	receipt     Receipt
}

type paymentState struct {
	operationID string
	region      string
	authorized  ledger.Amount
	captured    ledger.Amount
	refunded    ledger.Amount
	reversed    ledger.Amount
	chargedBack ledger.Amount
	state       PaymentState
	receipt     Receipt
}

type transferState struct {
	certificate        TransferCertificate
	inTransit          bool
	consumed           bool
	sourceAcknowledged bool
	consumeReceipt     Receipt
}

type sagaState struct {
	snapshot SagaSnapshot
}

type fraudVerdictState struct {
	snapshot FraudVerdictSnapshot
}

// World is a deterministic, crash-durable protocol model. Its maps represent
// durable consensus state; process crash flags are deliberately separate and
// never clear committed records.
type World struct {
	mu sync.Mutex

	asset          string
	authorityAsset string
	creditLimit    ledger.Amount
	unallocated    ledger.Amount
	authorityTotal ledger.Amount
	certificateKey []byte

	regions       map[string]*regionState
	balances      map[string]ledger.Amount
	journal       []JournalTransaction
	effects       map[string]effectRecord
	idempotency   map[string]idempotencyRecord
	payments      map[string]*paymentState
	refunds       map[string]ledger.Amount
	cashbackRules map[string]ledger.Amount
	cashbackPaid  map[string]ledger.Amount

	transfers map[string]*transferState
	outbox    map[string]*OutboxRecord
	inbox     map[string]*InboxRecord

	sequence uint64
	headHash [32]byte

	loseResponses     map[string]int
	crashBeforeCommit map[string]int
	crashAfterCommit  map[string]int
	consumerCrash     map[string]int

	coordinatorRunning    bool
	coordinatorCrashAfter map[string]int
	sagas                 map[string]*sagaState

	logicalTick   uint64
	fraudVerdicts map[string]*fraudVerdictState

	dcHealthy map[string]bool
	replicas  []string
	quorum    int

	network *simulation.Network
}

func NewWorld(config Config, seed uint64) (*World, error) {
	if config.Asset == "" || config.InitialBalance.Sign() < 0 || config.CreditLimit.Sign() < 0 ||
		config.Unallocated.Sign() < 0 {
		return nil, ErrInvalidConfiguration
	}
	authority, err := config.InitialBalance.Add(config.CreditLimit)
	if err != nil {
		return nil, fmt.Errorf("authority total: %w", err)
	}

	regions := make(map[string]*regionState, len(config.RegionalRights)+3)
	for _, name := range []string{"A", "B", "C"} {
		regions[name] = &regionState{epoch: 1, running: true}
	}
	rightsTotal := config.Unallocated
	for name, amount := range config.RegionalRights {
		if name == "" || amount.Sign() < 0 {
			return nil, ErrInvalidConfiguration
		}
		rightsTotal, err = rightsTotal.Add(amount)
		if err != nil {
			return nil, fmt.Errorf("regional rights total: %w", err)
		}
		regions[name] = &regionState{epoch: 1, running: true, rights: amount}
	}
	if rightsTotal.Cmp(authority) != 0 {
		return nil, fmt.Errorf("%w: unallocated + regional rights = %s, balance + credit = %s",
			ErrInvalidConfiguration, rightsTotal.String(), authority.String())
	}

	key := append([]byte(nil), config.CertificateKey...)
	if len(key) == 0 {
		sum := sha256.Sum256([]byte("payment-platform/failuresim/deterministic-certificate-key/v1"))
		key = append([]byte(nil), sum[:]...)
	}

	world := &World{
		asset: config.Asset, authorityAsset: authorityAssetPrefix + config.Asset,
		creditLimit: config.CreditLimit, unallocated: config.Unallocated,
		authorityTotal: authority, certificateKey: key, regions: regions,
		balances: make(map[string]ledger.Amount), journal: make([]JournalTransaction, 0, 64),
		effects: make(map[string]effectRecord), idempotency: make(map[string]idempotencyRecord),
		payments: make(map[string]*paymentState), refunds: make(map[string]ledger.Amount),
		cashbackRules: make(map[string]ledger.Amount), cashbackPaid: make(map[string]ledger.Amount),
		transfers: make(map[string]*transferState), outbox: make(map[string]*OutboxRecord),
		inbox: make(map[string]*InboxRecord), loseResponses: make(map[string]int),
		crashBeforeCommit: make(map[string]int), crashAfterCommit: make(map[string]int),
		consumerCrash: make(map[string]int), coordinatorRunning: true,
		coordinatorCrashAfter: make(map[string]int), sagas: make(map[string]*sagaState),
		fraudVerdicts: make(map[string]*fraudVerdictState), dcHealthy: make(map[string]bool, 12),
		network: simulation.NewNetwork(seed),
	}
	for index := 1; index <= 12; index++ {
		world.dcHealthy[fmt.Sprintf("dc%02d", index)] = true
	}
	for index := 1; index <= 7; index++ {
		world.replicas = append(world.replicas, fmt.Sprintf("dc%02d", index))
	}
	world.quorum = 4

	lines := make([]JournalLine, 0, 6+len(regions))
	if config.InitialBalance.Sign() > 0 {
		lines = append(lines,
			JournalLine{Account: FundingAccount, Asset: world.asset, Side: ledger.Debit, Amount: config.InitialBalance},
			JournalLine{Account: UserAccount, Asset: world.asset, Side: ledger.Credit, Amount: config.InitialBalance},
		)
	}
	if authority.Sign() > 0 {
		lines = append(lines, JournalLine{Account: AuthorityIssuerAccount, Asset: world.authorityAsset, Side: ledger.Debit, Amount: authority})
		if config.Unallocated.Sign() > 0 {
			lines = append(lines, JournalLine{Account: AuthorityUnallocatedAccount, Asset: world.authorityAsset, Side: ledger.Credit, Amount: config.Unallocated})
		}
		names := sortedRegionNames(regions)
		for _, name := range names {
			if regions[name].rights.Sign() > 0 {
				lines = append(lines, JournalLine{Account: RegionalAuthorityAccount(name), Asset: world.authorityAsset, Side: ledger.Credit, Amount: regions[name].rights})
			}
		}
	}
	if len(lines) > 0 {
		fingerprint := requestFingerprint("GENESIS", config.Asset, config.InitialBalance.String(), config.CreditLimit.String())
		if _, err := world.postLocked("genesis", "GENESIS", fingerprint, lines); err != nil {
			return nil, fmt.Errorf("post genesis: %w", err)
		}
	}
	return world, nil
}

func sortedRegionNames(regions map[string]*regionState) []string {
	names := make([]string, 0, len(regions))
	for name := range regions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func requestFingerprint(parts ...string) [32]byte {
	h := sha256.New()
	h.Write([]byte("payment-platform/failuresim/request/v1\x00"))
	var size [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (w *World) postLocked(effectID, kind string, fingerprint [32]byte, lines []JournalLine) (Receipt, error) {
	if effectID == "" || kind == "" || len(lines) < 2 {
		return Receipt{}, ErrEffectConflict
	}
	if existing, ok := w.effects[effectID]; ok {
		if existing.fingerprint != fingerprint {
			return Receipt{}, ErrEffectConflict
		}
		receipt := existing.receipt
		receipt.Duplicate = true
		return receipt, nil
	}

	type totals struct{ debit, credit ledger.Amount }
	perAsset := make(map[string]totals)
	prospective := make(map[string]ledger.Amount)
	for _, line := range lines {
		if line.Account == "" || line.Asset == "" || line.Amount.Sign() <= 0 ||
			(line.Side != ledger.Debit && line.Side != ledger.Credit) {
			return Receipt{}, ledger.ErrInvalidPosting
		}
		total := perAsset[line.Asset]
		var err error
		if line.Side == ledger.Debit {
			total.debit, err = total.debit.Add(line.Amount)
		} else {
			total.credit, err = total.credit.Add(line.Amount)
		}
		if err != nil {
			return Receipt{}, err
		}
		perAsset[line.Asset] = total

		balance, ok := prospective[line.Account]
		if !ok {
			balance = w.balances[line.Account]
		}
		if line.Side == ledger.Credit {
			balance, err = balance.Add(line.Amount)
		} else {
			balance, err = balance.Sub(line.Amount)
		}
		if err != nil {
			return Receipt{}, err
		}
		prospective[line.Account] = balance
	}
	for asset, total := range perAsset {
		if total.debit.Cmp(total.credit) != 0 {
			return Receipt{}, fmt.Errorf("%w: %s", ledger.ErrUnbalanced, asset)
		}
	}

	sequence := w.sequence + 1
	transactionID := fmt.Sprintf("tx-%020d", sequence)
	transaction := JournalTransaction{
		Sequence: sequence, ID: transactionID, EffectID: effectID, Kind: kind,
		RequestHash: fingerprint, PreviousHash: w.headHash,
		Lines: cloneLines(lines),
	}
	transaction.Hash = hashTransaction(transaction)
	receipt := Receipt{EffectID: effectID, TransactionID: transactionID, CommitSequence: sequence}

	for account, balance := range prospective {
		w.balances[account] = balance
	}
	w.sequence = sequence
	w.headHash = transaction.Hash
	w.journal = append(w.journal, transaction)
	w.effects[effectID] = effectRecord{fingerprint: fingerprint, receipt: receipt}
	return receipt, nil
}

func hashTransaction(transaction JournalTransaction) [32]byte {
	h := sha256.New()
	h.Write([]byte("payment-platform/failuresim/journal/v1\x00"))
	h.Write(transaction.PreviousHash[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], transaction.Sequence)
	h.Write(number[:])
	for _, value := range []string{transaction.ID, transaction.EffectID, transaction.Kind} {
		writeLengthPrefixed(h, []byte(value))
	}
	h.Write(transaction.RequestHash[:])
	for _, line := range transaction.Lines {
		for _, value := range []string{line.Account, line.Asset, string(line.Side), line.Amount.String()} {
			writeLengthPrefixed(h, []byte(value))
		}
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

type byteWriter interface{ Write([]byte) (int, error) }

func writeLengthPrefixed(writer byteWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func cloneLines(lines []JournalLine) []JournalLine {
	result := make([]JournalLine, len(lines))
	copy(result, lines)
	return result
}

func (w *World) hasQuorumLocked() bool {
	healthy := 0
	for _, dc := range w.replicas {
		if w.dcHealthy[dc] {
			healthy++
		}
	}
	return healthy >= w.quorum
}

func (w *World) requireWriterLocked(fence Fence) (*regionState, error) {
	region, ok := w.regions[fence.Region]
	if !ok || !region.running {
		return nil, ErrRegionDown
	}
	if region.epoch != fence.Epoch {
		return nil, ErrStaleEpoch
	}
	if !w.hasQuorumLocked() {
		return nil, ErrNoQuorum
	}
	return region, nil
}

func (w *World) Fence(region string) (Fence, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	state, ok := w.regions[region]
	if !ok || !state.running {
		return Fence{}, ErrRegionDown
	}
	return Fence{Region: region, Epoch: state.epoch}, nil
}

func (w *World) CrashRegion(region string) error {
	w.mu.Lock()
	state, ok := w.regions[region]
	if !ok {
		w.mu.Unlock()
		return ErrRegionDown
	}
	state.running = false
	w.mu.Unlock()
	w.network.Crash(region)
	return nil
}

func (w *World) RestartRegion(region string) error {
	w.mu.Lock()
	state, ok := w.regions[region]
	if !ok {
		w.mu.Unlock()
		return ErrRegionDown
	}
	state.epoch++
	state.running = true
	w.mu.Unlock()
	w.network.Restart(region)
	return nil
}

func (w *World) CrashDC(dc string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.dcHealthy[dc]; !ok {
		return ErrInvalidConfiguration
	}
	w.dcHealthy[dc] = false
	return nil
}

func (w *World) RestartDC(dc string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.dcHealthy[dc]; !ok {
		return ErrInvalidConfiguration
	}
	w.dcHealthy[dc] = true
	return nil
}

func (w *World) Network() *simulation.Network { return w.network }

func (w *World) Partition(a, b string)                       { w.network.Partition(a, b) }
func (w *World) Heal(a, b string)                            { w.network.Heal(a, b) }
func (w *World) HealAll()                                    { w.network.HealAll() }
func (w *World) SetPacketLoss(percent uint8)                 { w.network.SetDropPercent(percent) }
func (w *World) SetReordering(enabled bool)                  { w.network.SetReorder(enabled) }
func (w *World) SetDuplicateEvery(every uint64)              { w.network.SetDuplicateEvery(every) }
func (w *World) ClockSkew(region string, skew time.Duration) { w.network.ClockSkew(region, skew) }
func (w *World) RegionalTime(region string, base time.Time) time.Time {
	return w.network.Now(region, base)
}

func (w *World) LoseResponse(idempotencyKey string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.loseResponses[idempotencyKey]++
}

func (w *World) CrashBeforeCommit(idempotencyKey string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.crashBeforeCommit[idempotencyKey]++
}

func (w *World) CrashAfterCommit(idempotencyKey string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.crashAfterCommit[idempotencyKey]++
}

func (w *World) Region(region string) (RegionSnapshot, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	state, ok := w.regions[region]
	if !ok {
		return RegionSnapshot{}, false
	}
	return RegionSnapshot{Region: region, Epoch: state.epoch, Running: state.running, Rights: state.rights}, true
}

func (w *World) Balance(account string) ledger.Amount {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.balances[account]
}

func (w *World) Rights(region string) ledger.Amount {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state := w.regions[region]; state != nil {
		return state.rights
	}
	return ledger.Amount{}
}

func (w *World) Journal() []JournalTransaction {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]JournalTransaction, len(w.journal))
	for index, transaction := range w.journal {
		result[index] = transaction
		result[index].Lines = cloneLines(transaction.Lines)
	}
	return result
}

func (w *World) EffectCount(effectID string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	count := 0
	for _, transaction := range w.journal {
		if transaction.EffectID == effectID {
			count++
		}
	}
	return count
}

func (w *World) Payment(operationID string) (PaymentSnapshot, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	payment, ok := w.payments[operationID]
	if !ok {
		return PaymentSnapshot{}, false
	}
	return payment.snapshot(), true
}

func (p *paymentState) snapshot() PaymentSnapshot {
	return PaymentSnapshot{
		OperationID: p.operationID, Region: p.region, Authorized: p.authorized,
		Captured: p.captured, Refunded: p.refunded, Reversed: p.reversed,
		ChargedBack: p.chargedBack, State: p.state, Receipt: p.receipt,
	}
}

func (w *World) GrossCaptured() ledger.Amount {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := ledger.Amount{}
	for _, payment := range w.payments {
		total, _ = total.Add(payment.captured)
	}
	return total
}

func (w *World) canonicalCertificatePayload(certificate TransferCertificate) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("payment-platform/failuresim/transfer-certificate/v1\x00")
	for _, value := range []string{
		certificate.TransferID, certificate.Asset, certificate.SourceRegion,
		certificate.DestinationRegion, certificate.Amount.String(),
	} {
		writeLengthPrefixed(&buffer, []byte(value))
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], certificate.SourceEpoch)
	buffer.Write(number[:])
	binary.BigEndian.PutUint64(number[:], certificate.CommitSequence)
	buffer.Write(number[:])
	return buffer.Bytes()
}

func (w *World) certificateProof(certificate TransferCertificate) [32]byte {
	mac := hmac.New(sha256.New, w.certificateKey)
	mac.Write(w.canonicalCertificatePayload(certificate))
	var proof [32]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func (w *World) verifyCertificateLocked(certificate TransferCertificate) bool {
	if certificate.TransferID == "" || certificate.Asset != w.asset || certificate.SourceRegion == "" ||
		certificate.DestinationRegion == "" || certificate.SourceRegion == certificate.DestinationRegion ||
		certificate.Amount.Sign() <= 0 || certificate.SourceEpoch == 0 || certificate.CommitSequence == 0 {
		return false
	}
	expected := w.certificateProof(certificate)
	return hmac.Equal(expected[:], certificate.CommitProof[:])
}

func equalCertificate(left, right TransferCertificate) bool {
	return left.TransferID == right.TransferID && left.Asset == right.Asset &&
		left.SourceRegion == right.SourceRegion && left.DestinationRegion == right.DestinationRegion &&
		left.Amount.Cmp(right.Amount) == 0 && left.SourceEpoch == right.SourceEpoch &&
		left.CommitSequence == right.CommitSequence && left.CommitProof == right.CommitProof
}

func amountSum(values ...ledger.Amount) (ledger.Amount, error) {
	total := ledger.Amount{}
	var err error
	for _, value := range values {
		total, err = total.Add(value)
		if err != nil {
			return ledger.Amount{}, err
		}
	}
	return total, nil
}

func isExpectedOperationalError(err error) bool {
	return errors.Is(err, ErrInsufficientFunds) || errors.Is(err, ErrInsufficientRights) ||
		errors.Is(err, ErrRegionDown) || errors.Is(err, ErrNoQuorum) || errors.Is(err, ErrStaleEpoch)
}
