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

path "database/creds/payment-api" {
  capabilities = ["read"]
}

path "kv/data/payment-platform/*" {
  capabilities = ["read"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

