# CockroachDB production placement

Это не локальный StatefulSet. Каталог описывает один CockroachDB 26.2 Regular cluster, растянутый на 12 private DC Kubernetes contexts. Каждый site overlay задаёт locality и отдельный per-pod certificate; range policy после bootstrap — RF7, семь voters, majority quorum 4.

## Обязательные prerequisites

- private routed pod/node network и private DNS для `*.cockroach.dc-NN.payments.internal`;
- Kubernetes clusters с меткой node pool `payment.example/workload=financial-stateful`;
- CockroachDB 26.2 license/entitlement и approved Regular build;
- cert-manager, cert-manager CSI driver и Vault-backed issuers;
- Multi-Cluster Services API либо эквивалентный private service export;
- encrypted retained StorageClass `encrypted-local-ssd-retained`;
- environment NetworkPolicy/Cilium overlay, разрешающий RPC 26357 и SQL 26257 только между 12 private DC CIDRs;
- минимум семь независимых control-plane failure domains для management plane, если от него требуется пережить любые три DC failures.

`base` нельзя применять напрямую: `dc-00` является fail-closed placeholder. Каждый context получает ровно свой overlay:

Перед apply release pipeline заменяет Cockroach
`registry.invalid/...replace-with-signed-digest` на подписанный approved digest
линии 26.2 Regular и прикладывает SBOM/provenance к change record.

```bash
kubectl --context payments-dc-01 apply -k deploy/kubernetes/cockroach/overlays/dc-01
kubectl --context payments-dc-02 apply -k deploy/kubernetes/cockroach/overlays/dc-02
# ... продолжить до dc-12
kubectl --context payments-dc-12 apply -k deploy/kubernetes/cockroach/overlays/dc-12
```

Три pod на site — минимальный operational baseline, не capacity assertion. Range allocator видит locality `region,dc`; RF7 размещает семь voters по distinct DC. Перед приёмом трафика обязательна фактическая проверка, что ни один range не имеет двух voters в одном `dc`.

После доступности всех site endpoints designated operator однократно выполняет:

```bash
kubectl --context payments-dc-01 apply -f deploy/kubernetes/cockroach/bootstrap.yaml
kubectl --context payments-dc-01 -n payments wait --for=condition=complete job/cockroach-bootstrap --timeout=15m
kubectl --context payments-dc-01 -n payments logs job/cockroach-bootstrap
```

Bootstrap создаёт database и устанавливает default `num_replicas=7,num_voters=7`; Q4 является majority Raft quorum. Job не включён в GitOps kustomization намеренно. Перед запуском migrations проверьте отсутствие under-replicated ranges и placement по runbook [operations.md](../../../docs/operations.md).

Не понижайте RF/MISR при аварии и не применяйте `kubectl delete pvc`, `--all` либо forced decommission без подтверждённого backup и quorum review.
