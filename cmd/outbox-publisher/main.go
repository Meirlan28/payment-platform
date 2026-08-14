package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/payment-platform/internal/messaging"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type config struct {
	databaseURL      string
	brokers          []string
	clientID         string
	owner            string
	region           string
	environment      string
	metricsAddress   string
	kafkaCA          string
	kafkaCertificate string
	kafkaKey         string
	kafkaServerName  string
	saslUsername     string
	saslPassword     string
	batchSize        int
	maxAttempts      int
	pollInterval     time.Duration
	lease            time.Duration
	databasePoolSize int32
}

type publisherMetrics struct {
	cycles    *prometheus.CounterVec
	claimed   prometheus.Counter
	published prometheus.Counter
	failed    prometheus.Counter
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("outbox publisher stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configuration, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	poolConfiguration, err := pgxpool.ParseConfig(configuration.databaseURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if strings.EqualFold(configuration.environment, "production") &&
		(poolConfiguration.ConnConfig.TLSConfig == nil || poolConfiguration.ConnConfig.TLSConfig.InsecureSkipVerify) {
		return errors.New("production CockroachDB TLS must verify the server certificate and hostname")
	}
	poolConfiguration.MaxConns = configuration.databasePoolSize
	poolConfiguration.MinConns = max(2, configuration.databasePoolSize/10)
	poolConfiguration.MaxConnLifetime = 30 * time.Minute
	poolConfiguration.MaxConnLifetimeJitter = 5 * time.Minute
	poolConfiguration.MaxConnIdleTime = 5 * time.Minute
	poolConfiguration.HealthCheckPeriod = 15 * time.Second
	poolConfiguration.ConnConfig.RuntimeParams["application_name"] = "outbox-publisher/" + configuration.region
	pool, err := pgxpool.NewWithConfig(ctx, poolConfiguration)
	if err != nil {
		return fmt.Errorf("open CockroachDB pool: %w", err)
	}
	defer pool.Close()

	producerTLS, err := kafkaTLS(configuration)
	if err != nil {
		return err
	}
	producer, err := messaging.NewKafkaProducer(messaging.KafkaClientConfig{
		Brokers: configuration.brokers, ClientID: configuration.clientID,
		TLS: producerTLS, SASLUsername: configuration.saslUsername,
		SASLPassword:   configuration.saslPassword,
		AllowPlaintext: strings.EqualFold(configuration.environment, "integration"),
		DialTimeout:    5 * time.Second, RequestTimeout: 10 * time.Second,
		DeliveryTimeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer producer.Close()

	startup, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	err = errors.Join(pool.Ping(startup), producer.Ping(startup))
	cancelStartup()
	if err != nil {
		return fmt.Errorf("dependency readiness: %w", err)
	}

	registry := prometheus.NewRegistry()
	metrics := newPublisherMetrics(registry)
	metricsServer := newMetricsServer(configuration.metricsAddress, pool, registry)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("local metrics server ready", "address", configuration.metricsAddress)
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErrors <- serveErr
		}
	}()

	publisher := messaging.Publisher{
		Outbox: messaging.Outbox{DB: pool}, Producer: producer,
		Owner: configuration.owner, BatchSize: configuration.batchSize,
		Lease: configuration.lease, MaxAttempts: configuration.maxAttempts,
		Backoff: boundedBackoff(configuration.owner),
	}
	logger.Info("outbox publisher ready", "region", configuration.region, "owner", configuration.owner)

	for {
		stats, publishErr := publisher.RunOnce(ctx)
		metrics.claimed.Add(float64(stats.Claimed))
		metrics.published.Add(float64(stats.Published))
		metrics.failed.Add(float64(stats.Failed))
		if publishErr != nil {
			metrics.cycles.WithLabelValues("error").Inc()
			logger.Error("outbox publish cycle failed", "error", publishErr,
				"claimed", stats.Claimed, "published", stats.Published, "failed", stats.Failed)
		} else {
			metrics.cycles.WithLabelValues("success").Inc()
		}

		wait := configuration.pollInterval
		if stats.Claimed == configuration.batchSize {
			wait = 0
		}
		if wait == 0 {
			select {
			case <-ctx.Done():
				return shutdownMetrics(metricsServer)
			case serveErr := <-serverErrors:
				return fmt.Errorf("metrics server: %w", serveErr)
			default:
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return shutdownMetrics(metricsServer)
		case serveErr := <-serverErrors:
			timer.Stop()
			return fmt.Errorf("metrics server: %w", serveErr)
		case <-timer.C:
		}
	}
}

func loadConfig() (config, error) {
	result := config{
		databaseURL: os.Getenv("DATABASE_URL"), clientID: os.Getenv("KAFKA_CLIENT_ID"),
		owner: os.Getenv("PUBLISHER_OWNER"), region: os.Getenv("REGION_ID"),
		environment: os.Getenv("ENVIRONMENT"), metricsAddress: valueOr("METRICS_ADDRESS", "127.0.0.1:9090"),
		kafkaCA: os.Getenv("KAFKA_CA_FILE"), kafkaCertificate: os.Getenv("KAFKA_CERT_FILE"),
		kafkaKey: os.Getenv("KAFKA_KEY_FILE"), kafkaServerName: os.Getenv("KAFKA_SERVER_NAME"),
		saslUsername: os.Getenv("KAFKA_SASL_USERNAME"), saslPassword: os.Getenv("KAFKA_SASL_PASSWORD"),
		batchSize: 500, maxAttempts: 50, pollInterval: 250 * time.Millisecond,
		lease: 45 * time.Second, databasePoolSize: 32,
	}
	for _, broker := range strings.Split(os.Getenv("KAFKA_BROKERS"), ",") {
		if value := strings.TrimSpace(broker); value != "" {
			result.brokers = append(result.brokers, value)
		}
	}
	var err error
	if result.batchSize, err = integerEnv("PUBLISH_BATCH_SIZE", result.batchSize, 1, 10_000); err != nil {
		return config{}, err
	}
	if result.maxAttempts, err = integerEnv("PUBLISH_MAX_ATTEMPTS", result.maxAttempts, 1, 10_000); err != nil {
		return config{}, err
	}
	poolSize, err := integerEnv("DB_MAX_CONNECTIONS", int(result.databasePoolSize), 4, 4096)
	if err != nil {
		return config{}, err
	}
	result.databasePoolSize = int32(poolSize)
	if result.databaseURL == "" || len(result.brokers) == 0 || result.clientID == "" ||
		result.owner == "" || result.region == "" {
		return config{}, errors.New("DATABASE_URL, KAFKA_BROKERS, KAFKA_CLIENT_ID, PUBLISHER_OWNER and REGION_ID are required")
	}
	if strings.EqualFold(result.environment, "production") {
		if strings.Contains(strings.ToLower(result.databaseURL), "sslmode=disable") {
			return config{}, errors.New("production CockroachDB connection must verify TLS")
		}
		if result.kafkaCA == "" || result.kafkaCertificate == "" || result.kafkaKey == "" {
			return config{}, errors.New("production Kafka requires CA and client certificate files")
		}
	} else if !strings.EqualFold(result.environment, "integration") {
		return config{}, errors.New("ENVIRONMENT must be production or integration")
	}
	if (result.saslUsername == "") != (result.saslPassword == "") {
		return config{}, errors.New("both Kafka SASL username and password are required")
	}
	host, _, err := net.SplitHostPort(result.metricsAddress)
	if err != nil {
		return config{}, fmt.Errorf("METRICS_ADDRESS: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return config{}, errors.New("metrics endpoint must bind loopback; scrape through the colocated collector")
	}
	return result, nil
}

func kafkaTLS(configuration config) (*tls.Config, error) {
	if configuration.kafkaCA == "" && configuration.kafkaCertificate == "" && configuration.kafkaKey == "" {
		return nil, nil
	}
	if configuration.kafkaCA == "" || configuration.kafkaCertificate == "" || configuration.kafkaKey == "" {
		return nil, errors.New("Kafka CA, certificate and key must be configured together")
	}
	caPEM, err := os.ReadFile(configuration.kafkaCA)
	if err != nil {
		return nil, fmt.Errorf("read Kafka CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Kafka CA file contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(configuration.kafkaCertificate, configuration.kafkaKey)
	if err != nil {
		return nil, fmt.Errorf("load Kafka client certificate: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{certificate}, ServerName: configuration.kafkaServerName,
	}, nil
}

func newPublisherMetrics(registerer prometheus.Registerer) publisherMetrics {
	metrics := publisherMetrics{
		cycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "outbox_publisher", Name: "cycles_total",
			Help: "Outbox publisher cycles by bounded result class.",
		}, []string{"result"}),
		claimed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "outbox_publisher", Name: "claimed_total",
			Help: "Durable outbox rows claimed for delivery.",
		}),
		published: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "outbox_publisher", Name: "published_total",
			Help: "Outbox rows acknowledged by Kafka and marked published.",
		}),
		failed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "payments", Subsystem: "outbox_publisher", Name: "failed_total",
			Help: "Outbox rows whose publish or durable acknowledgement attempt failed.",
		}),
	}
	registerer.MustRegister(metrics.cycles, metrics.claimed, metrics.published, metrics.failed)
	return metrics
}

func newMetricsServer(address string, pool *pgxpool.Pool, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/live", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/ready", func(response http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 250*time.Millisecond)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(response, "not ready", http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	return &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
	}
}

func shutdownMetrics(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func boundedBackoff(owner string) func(int) time.Duration {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(owner))
	jitterMillis := time.Duration(hash.Sum32()%1000) * time.Millisecond
	return func(attempt int) time.Duration {
		if attempt < 1 {
			attempt = 1
		}
		exponent := min(attempt-1, 7)
		return min(time.Second*time.Duration(1<<exponent)+jitterMillis, 2*time.Minute)
	}
}

func integerEnv(name string, fallback, minimum, maximum int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func valueOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
