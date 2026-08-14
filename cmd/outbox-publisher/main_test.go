package main

import (
	"testing"
	"time"
)

func TestProductionConfigurationRejectsInsecureDependencies(t *testing.T) {
	setRequiredPublisherEnvironment(t)
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("DATABASE_URL", "postgresql://writer@db/payments?sslmode=disable")
	if _, err := loadConfig(); err == nil {
		t.Fatal("production CockroachDB plaintext was accepted")
	}

	t.Setenv("DATABASE_URL", "postgresql://writer@db/payments?sslmode=verify-full")
	if _, err := loadConfig(); err == nil {
		t.Fatal("production Kafka without mTLS files was accepted")
	}
}

func TestIntegrationConfigurationRequiresExplicitEnvironment(t *testing.T) {
	setRequiredPublisherEnvironment(t)
	t.Setenv("ENVIRONMENT", "integration")
	configuration, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.brokers) != 3 || configuration.batchSize <= 0 {
		t.Fatalf("invalid integration config: %#v", configuration)
	}
}

func TestPublisherBackoffIsBoundedAndStablePerOwner(t *testing.T) {
	first := boundedBackoff("pod-a")
	second := boundedBackoff("pod-a")
	if first(8) != second(8) {
		t.Fatal("owner backoff jitter is not deterministic")
	}
	if first(1) < time.Second || first(10_000) > 2*time.Minute {
		t.Fatalf("backoff outside bounds: first=%s capped=%s", first(1), first(10_000))
	}
}

func setRequiredPublisherEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgresql://root@cockroach-1:26257/payment_platform?sslmode=disable")
	t.Setenv("KAFKA_BROKERS", "kafka-1:9092,kafka-2:9092,kafka-3:9092")
	t.Setenv("KAFKA_CLIENT_ID", "outbox-test")
	t.Setenv("PUBLISHER_OWNER", "pod-test")
	t.Setenv("REGION_ID", "test-a")
	t.Setenv("METRICS_ADDRESS", "127.0.0.1:9090")
	t.Setenv("KAFKA_CA_FILE", "")
	t.Setenv("KAFKA_CERT_FILE", "")
	t.Setenv("KAFKA_KEY_FILE", "")
}
