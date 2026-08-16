# Financial services receive narrowly scoped capabilities. This policy cannot
# alter Cockroach ledger rows; it only obtains/uses credentials and keys.
path "pki_workloads/issue/payment-platform" {
  capabilities = ["update"]
}

path "pki_cockroach/issue/client" {
  capabilities = ["update"]
}

path "transit/sign/escrow-transfer" {
  capabilities = ["update"]
}

path "transit/verify/escrow-transfer" {
  capabilities = ["update"]
}

path "transit/sign/audit-checkpoint" {
  capabilities = ["update"]
}

path "transit/verify/audit-checkpoint" {
  capabilities = ["update"]
}

# Read is used only by readiness to pin rsa-4096, non-exportable,
# non-deletable key policy before accepting checkpoint work.
path "transit/keys/audit-checkpoint" {
  capabilities = ["read"]
}

path "sys/managed-keys/pkcs11/audit-checkpoint-hsm" {
  capabilities = ["read"]
}

path "database/creds/payment-api" {
  capabilities = ["read"]
}

path "kv/data/payment-platform/*" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
