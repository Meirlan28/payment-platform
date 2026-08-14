package messaging

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

type KafkaClientConfig struct {
	Brokers         []string
	ClientID        string
	TLS             *tls.Config
	SASLUsername    string
	SASLPassword    string
	AllowPlaintext  bool // integration topology only; production leaves false
	DialTimeout     time.Duration
	DeliveryTimeout time.Duration
	RequestTimeout  time.Duration
}

func (c KafkaClientConfig) options() ([]kgo.Opt, error) {
	if len(c.Brokers) == 0 || c.ClientID == "" {
		return nil, errors.New("messaging: Kafka brokers and client id are required")
	}
	if c.TLS == nil && !c.AllowPlaintext {
		return nil, errors.New("messaging: Kafka TLS is required")
	}
	if c.TLS != nil && c.TLS.MinVersion < tls.VersionTLS12 {
		return nil, errors.New("messaging: Kafka TLS minimum must be TLS 1.2 or newer")
	}
	if (c.SASLUsername == "") != (c.SASLPassword == "") {
		return nil, errors.New("messaging: both Kafka SASL username and password are required")
	}
	dialTimeout := c.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	deliveryTimeout := c.DeliveryTimeout
	if deliveryTimeout <= 0 {
		deliveryTimeout = 30 * time.Second
	}
	requestTimeout := c.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 10 * time.Second
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.Brokers...),
		kgo.ClientID(c.ClientID),
		kgo.DialTimeout(dialTimeout),
		kgo.RequestTimeoutOverhead(requestTimeout),
		kgo.RecordDeliveryTimeout(deliveryTimeout),
		kgo.MetadataMinAge(2 * time.Second),
		kgo.MetadataMaxAge(2 * time.Minute),
	}
	if c.TLS != nil {
		opts = append(opts, kgo.DialTLSConfig(c.TLS.Clone()))
	}
	if c.SASLUsername != "" {
		opts = append(opts, kgo.SASL(scram.Auth{
			User: c.SASLUsername, Pass: c.SASLPassword,
		}.AsSha512Mechanism()))
	}
	return opts, nil
}

// KafkaProducer is an acks=all idempotent franz-go producer. Idempotent write
// is franz-go's safe default and is deliberately not disabled. The outbox and
// inbox remain the economic exactly-once boundary even if Kafka redelivers.
type KafkaProducer struct {
	client *kgo.Client
}

func NewKafkaProducer(config KafkaClientConfig) (*KafkaProducer, error) {
	opts, err := config.options()
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression(), kgo.Lz4Compression()),
		kgo.ProducerBatchMaxBytes(1<<20),
	)
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("messaging: create Kafka producer: %w", err)
	}
	return &KafkaProducer{client: client}, nil
}

func (p *KafkaProducer) Ping(ctx context.Context) error {
	if p == nil || p.client == nil {
		return errors.New("messaging: Kafka producer is closed")
	}
	return p.client.Ping(ctx)
}

func (p *KafkaProducer) Publish(ctx context.Context, message Message) error {
	if p == nil || p.client == nil {
		return errors.New("messaging: Kafka producer is closed")
	}
	if err := message.Validate(); err != nil {
		return err
	}
	record := encodeRecord(message)
	result := p.client.ProduceSync(ctx, record)
	if err := result.FirstErr(); err != nil {
		return fmt.Errorf("messaging: Kafka publish %s: %w", message.EventID, err)
	}
	return nil
}

func (p *KafkaProducer) Close() {
	if p != nil && p.client != nil {
		p.client.Close()
		p.client = nil
	}
}

func encodeRecord(message Message) *kgo.Record {
	headers := make(map[string]string, len(message.Headers)+5)
	for key, value := range message.Headers {
		headers[key] = value
	}
	headers["event_id"] = message.EventID
	headers["aggregate_id"] = message.AggregateID
	headers["aggregate_version"] = strconv.FormatUint(message.AggregateVersion, 10)
	headers["parent_transaction_id"] = message.ParentTransactionID
	if _, ok := headers["schema_version"]; !ok {
		headers["schema_version"] = "1"
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	record := &kgo.Record{
		Topic: message.Topic,
		Key:   append([]byte(nil), message.Key...),
		Value: append([]byte(nil), message.Payload...),
	}
	for _, key := range keys {
		record.Headers = append(record.Headers, kgo.RecordHeader{Key: key, Value: []byte(headers[key])})
	}
	return record
}

type KafkaConsumerConfig struct {
	Client   KafkaClientConfig
	Group    string
	Topics   []string
	Inbox    Inbox
	Handler  InboxHandler
	DLQ      Producer
	DLQTopic string
	MaxPoll  int
	// StartFromOldest is used for explicitly approved replay/new consumer
	// groups. Normal production groups resume committed offsets.
	StartFromOldest bool
}

type KafkaConsumer struct {
	client   *kgo.Client
	inbox    Inbox
	handler  InboxHandler
	dlq      Producer
	dlqTopic string
	maxPoll  int
}

func NewKafkaConsumer(config KafkaConsumerConfig) (*KafkaConsumer, error) {
	if config.Group == "" || len(config.Topics) == 0 || config.Inbox.DB == nil ||
		config.Inbox.Consumer == "" || config.Handler == nil || config.DLQ == nil ||
		config.DLQTopic == "" {
		return nil, errors.New("messaging: incomplete Kafka consumer configuration")
	}
	opts, err := config.Client.options()
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		kgo.ConsumerGroup(config.Group),
		kgo.ConsumeTopics(config.Topics...),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.Balancers(kgo.CooperativeStickyBalancer()),
		kgo.FetchMaxBytes(32<<20),
	)
	if config.StartFromOldest {
		opts = append(opts, kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("messaging: create Kafka consumer: %w", err)
	}
	maximum := config.MaxPoll
	if maximum <= 0 {
		maximum = 100
	}
	return &KafkaConsumer{
		client: client, inbox: config.Inbox, handler: config.Handler,
		dlq: config.DLQ, dlqTopic: config.DLQTopic, maxPoll: maximum,
	}, nil
}

// Run consumes at least once. Offset commit always follows Inbox.Process's
// database commit; a crash in between causes a harmless redelivery.
func (c *KafkaConsumer) Run(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("messaging: Kafka consumer is closed")
	}
	for {
		fetches := c.client.PollRecords(ctx, c.maxPoll)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errs := fetches.Errors(); len(errs) > 0 {
			c.client.AllowRebalance()
			return fmt.Errorf("messaging: Kafka poll: %v", errs)
		}
		var batchErr error
		fetches.EachRecord(func(record *kgo.Record) {
			if batchErr != nil {
				return
			}
			message, err := decodeRecord(record)
			if err != nil {
				// A malformed record cannot enter the inbox because it has no
				// trustworthy EventID. Move the exact broker coordinate and raw
				// payload to the configured DLQ, then commit only after the DLQ
				// publish succeeds. Otherwise one corrupt record would pin the
				// consumer partition forever.
				if publishErr := c.dlq.Publish(ctx, c.corruptRecordDLQ(record)); publishErr != nil {
					batchErr = errors.Join(err, publishErr)
					return
				}
				if commitErr := c.client.CommitRecords(ctx, record); commitErr != nil {
					batchErr = errors.Join(err, commitErr)
				}
				return
			}
			result, err := c.inbox.Process(ctx, message, c.handler)
			if err != nil && !result.Poison {
				batchErr = err
				return
			}
			if result.Poison {
				dlq := message
				dlq.Topic = c.dlqTopic
				dlq.EventID = "dlq:" + message.EventID
				if dlq.Headers == nil {
					dlq.Headers = map[string]string{}
				}
				dlq.Headers["original_event_id"] = message.EventID
				dlq.Headers["failure_class"] = "POISON"
				if publishErr := c.dlq.Publish(ctx, dlq); publishErr != nil {
					batchErr = publishErr
					return
				}
			}
			// Blocking commit failure is safe: the APPLIED inbox row wins on
			// redelivery. It is surfaced so a supervisor can replace the worker.
			if err := c.client.CommitRecords(ctx, record); err != nil {
				batchErr = fmt.Errorf("messaging: commit Kafka offset: %w", err)
			}
		})
		c.client.AllowRebalance()
		if batchErr != nil {
			return batchErr
		}
	}
}

func (c *KafkaConsumer) corruptRecordDLQ(record *kgo.Record) Message {
	coordinate := record.Topic + "/" + strconv.FormatInt(int64(record.Partition), 10) + "/" + strconv.FormatInt(record.Offset, 10)
	payload := append([]byte(nil), record.Value...)
	if len(payload) == 0 {
		payload = []byte("<empty Kafka value>")
	}
	return Message{
		EventID: "dlq-corrupt:" + coordinate, Topic: c.dlqTopic,
		Key: append([]byte(nil), record.Key...), Payload: payload,
		Headers: map[string]string{
			"failure_class":    "MALFORMED_TRANSPORT_RECORD",
			"source_topic":     record.Topic,
			"source_partition": strconv.FormatInt(int64(record.Partition), 10),
			"source_offset":    strconv.FormatInt(record.Offset, 10),
		},
		AggregateID: "transport/" + coordinate,
	}
}

func (c *KafkaConsumer) Close() {
	if c != nil && c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

func decodeRecord(record *kgo.Record) (Message, error) {
	if record == nil || record.Topic == "" || len(record.Value) == 0 {
		return Message{}, ErrInvalidMessage
	}
	headers := make(map[string]string, len(record.Headers))
	for _, header := range record.Headers {
		if _, duplicate := headers[header.Key]; duplicate {
			return Message{}, fmt.Errorf("%w: duplicate header %q", ErrInvalidMessage, header.Key)
		}
		headers[header.Key] = string(header.Value)
	}
	eventID := headers["event_id"]
	aggregateID := headers["aggregate_id"]
	version, err := strconv.ParseUint(headers["aggregate_version"], 10, 64)
	if err != nil {
		return Message{}, fmt.Errorf("%w: aggregate version", ErrInvalidMessage)
	}
	delete(headers, "event_id")
	delete(headers, "aggregate_id")
	delete(headers, "aggregate_version")
	parent := headers["parent_transaction_id"]
	delete(headers, "parent_transaction_id")
	message := Message{
		EventID: eventID, Topic: record.Topic, Key: append([]byte(nil), record.Key...),
		Payload: append([]byte(nil), record.Value...), Headers: headers,
		AggregateID: aggregateID, AggregateVersion: version,
		ParentTransactionID: parent,
	}
	if err := message.Validate(); err != nil {
		return Message{}, err
	}
	return message, nil
}
