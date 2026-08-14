#!/bin/sh
set -eu

# Developer convenience wrapper. Production and Compose execute the pinned,
# checksum-verifying /schema-migrator binary built from cmd/schema-migrator.
exec go run ./cmd/schema-migrator
