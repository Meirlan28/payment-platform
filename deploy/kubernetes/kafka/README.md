# Kafka 4.3 KRaft production topology

Манифест рассчитан на Strimzi с поддержкой Kafka 4.3.1 и KRaft node pools:

- 7 dedicated controllers, quorum 4;
- 12 brokers, по одному fault-domain slot на `payment.example/dc`;
- rack awareness по DC;
- topic RF7 и `min.insync.replicas=4`;
- `acks=all` обязательно на producer;
- unclean leader election и auto topic creation выключены;
- только TLS listeners: mTLS 9093 либо SASL/SCRAM-SHA-512 поверх TLS 9094;
- ACL и operator-generated credential Secrets.

Kafka не входит в commit proof денежных операций. При потере broker cluster durable Cockroach outbox остаётся replay source.

До применения проверьте, что Strimzi operator поддерживает поля `version: 4.3.1` и `metadataVersion: 4.3-IV0`, а все 12 DC labels реально присутствуют:

Release overlay обязан заменить `registry.invalid/...replace-with-signed-digest`
на digest одобренного Kafka 4.3.1 image, совместимого с pinned Strimzi operator;
mutable operator image mapping не считается production pinning.

```bash
kubectl get nodes -L payment.example/dc
kubectl apply --server-side --dry-run=server -k deploy/kubernetes/kafka
kubectl apply -k deploy/kubernetes/kafka
```

Topic manifests намеренно не содержат выдуманное число partitions. После benchmark вычислите `P = ceil(lambda_events / (rho * sustainable_events_per_partition))`, зафиксируйте P в release evidence и создайте topics с RF7/MISR4:

```bash
kafka-topics.sh --bootstrap-server payments-kafka-kafka-sasl-bootstrap.payments.svc:9094 \
  --command-config /etc/kafka/admin.properties \
  --create --topic payment-events --partitions "$PAYMENT_EVENT_PARTITIONS" \
  --replication-factor 7 --config min.insync.replicas=4

kafka-topics.sh --bootstrap-server payments-kafka-kafka-sasl-bootstrap.payments.svc:9094 \
  --command-config /etc/kafka/admin.properties \
  --create --topic payment-events-dlq --partitions "$PAYMENT_DLQ_PARTITIONS" \
  --replication-factor 7 --config min.insync.replicas=4
```

`num.partitions=1` является fail-safe для случайного topic creation, которое дополнительно запрещено; это не production sizing value.
