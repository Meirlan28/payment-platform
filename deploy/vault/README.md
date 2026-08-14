# Vault HA Raft + HSM

Production topology uses the official Vault Helm chart `0.32.0`, seven Raft voters and Vault Enterprise 1.21.4 with PKCS#11 auto-unseal/seal-wrap. The image must contain the approved vendor PKCS#11 library and is replaced by a signed digest in the release pipeline.

## Bootstrap prerequisites

The following resources are supplied by an offline/platform trust bootstrap, never as plaintext Git values:

- `vault/vault-server-tls`: `tls.crt`, `tls.key`, `ca.crt`, valid for every `vault-N.vault-internal` name and `vault-active.vault.svc.cluster.local`;
- `vault/vault-hsm-runtime`: key `pin`, delivered by the HSM secret bootstrap mechanism;
- `vault/vault-enterprise-license`: key `license`;
- pre-created non-exportable HSM encryption and HMAC keys with labels from `helm-values.yaml`;
- environment-specific NetworkPolicy egress for the redundant HSM endpoints and Kubernetes API;
- encrypted retained StorageClass and seven nodes in distinct `payment.example/dc` failure domains.

PKCS#11 auto-unseal/seal-wrap is a Vault Enterprise capability. `VAULT_HSM_GENERATE_KEY=false` is intentional: key creation happens in an audited HSM ceremony, not during pod startup.

## Install

Review the rendered resources before applying them:

```bash
kubectl apply -f deploy/vault/namespace.yaml
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm template vault hashicorp/vault --version 0.32.0 \
  --namespace vault --values deploy/vault/helm-values.yaml > /secure-review/vault-rendered.yaml
```

After the security reviewer has verified image digest, TLS Secret references, HSM/network overlays, anti-affinity and PVC retention:

```bash
helm upgrade --install vault hashicorp/vault --version 0.32.0 \
  --namespace vault --values deploy/vault/helm-values.yaml \
  --atomic --timeout 20m
kubectl apply -f deploy/vault/network-policy.yaml
kubectl -n vault rollout status statefulset/vault --timeout=20m
```

The first `vault operator init` is a maker-checker ceremony from a hardened admin workstation. Recovery shares and the initial root token go directly to separate custodians/HSM-backed storage; they MUST NOT enter a shell history, CI log, Kubernetes Secret or ticket. Revoke the initial root token after policies/auth methods are established.

Enable file audit to the dedicated audit PVC and a second remote/WORM sink. A Vault server is not production-ready until both audit sinks, Kubernetes auth, PKI roles, Transit keys, database roles and periodic Raft snapshots have passed restore testing.

Apply `payment-platform-policy.hcl` only to runtime workload identities and `cert-manager-policy.hcl` only to cert-manager issuers. Node issuance, client issuance and privileged `CN=root` issuance MUST be separate Vault PKI roles; the latter is limited to bootstrap/migration service accounts and short TTLs.

## Availability and rotation

- Seven Raft voters tolerate three crash failures; quorum is four.
- PDB permits at most three voluntary disruptions, but operators replace one voter at a time and wait for Raft health.
- HSM is a runtime dependency for seal wrapping. HSM loss must never trigger plaintext/Shamir fallback.
- Rotate TLS before 2/3 of its lifetime and verify every listener with the new trust bundle before retiring the old CA.
- Rotate HSM key labels by adding a new version and performing Vault seal rewrap. Old keys remain available until every ciphertext is rewrapped and independently verified.
- Snapshot Raft storage on schedule, encrypt it with a jurisdiction-local KMS/HSM key, write it to WORM, and run quarterly isolated restore drills.

Never use `helm uninstall`, delete Vault PVCs, force-remove Raft peers or rotate HSM keys during an incident without the destructive-action checklist in [operations.md](../../docs/operations.md).

