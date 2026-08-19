# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-bookworm AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

FROM source AS migrator-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/schema-migrator ./cmd/schema-migrator

FROM gcr.io/distroless/static-debian12:nonroot AS migrator
COPY --from=migrator-build /out/schema-migrator /schema-migrator
COPY --from=source --chown=nonroot:nonroot /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/schema-migrator"]

FROM source AS api-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/payment-api ./cmd/payment-api

FROM source AS publisher-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/outbox-publisher ./cmd/outbox-publisher

FROM source AS reference-migration-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/reference-migration ./cmd/reference-migration

FROM source AS reconciliation-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/reconciliation-worker ./cmd/reconciliation-worker

FROM source AS audit-checkpointer-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/audit-checkpointer ./cmd/audit-checkpointer

FROM source AS account-provisioning-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/account-provisioning-api ./cmd/account-provisioning-api

FROM source AS funding-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/funding-api ./cmd/funding-api

FROM source AS transfer-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/transfer-api ./cmd/transfer-api

FROM source AS ledger-query-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/ledger-query-api ./cmd/ledger-query-api

FROM source AS dev-seed-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/dev-seed ./cmd/dev-seed

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=api-build /out/payment-api /payment-api
USER nonroot:nonroot
ENTRYPOINT ["/payment-api"]

FROM gcr.io/distroless/static-debian12:nonroot AS publisher
COPY --from=publisher-build /out/outbox-publisher /outbox-publisher
USER nonroot:nonroot
ENTRYPOINT ["/outbox-publisher"]

FROM gcr.io/distroless/static-debian12:nonroot AS reference-migration
COPY --from=reference-migration-build /out/reference-migration /reference-migration
USER nonroot:nonroot
ENTRYPOINT ["/reference-migration"]

FROM gcr.io/distroless/static-debian12:nonroot AS reconciliation
COPY --from=reconciliation-build /out/reconciliation-worker /reconciliation-worker
USER nonroot:nonroot
ENTRYPOINT ["/reconciliation-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS audit-checkpointer
COPY --from=audit-checkpointer-build /out/audit-checkpointer /audit-checkpointer
USER nonroot:nonroot
ENTRYPOINT ["/audit-checkpointer"]

FROM gcr.io/distroless/static-debian12:nonroot AS account-provisioning
COPY --from=account-provisioning-build /out/account-provisioning-api /account-provisioning-api
USER nonroot:nonroot
ENTRYPOINT ["/account-provisioning-api"]

FROM gcr.io/distroless/static-debian12:nonroot AS funding
COPY --from=funding-build /out/funding-api /funding-api
USER nonroot:nonroot
ENTRYPOINT ["/funding-api"]

FROM gcr.io/distroless/static-debian12:nonroot AS transfer
COPY --from=transfer-build /out/transfer-api /transfer-api
USER nonroot:nonroot
ENTRYPOINT ["/transfer-api"]

FROM gcr.io/distroless/static-debian12:nonroot AS ledger-query
COPY --from=ledger-query-build /out/ledger-query-api /ledger-query-api
USER nonroot:nonroot
ENTRYPOINT ["/ledger-query-api"]

# dev-seed is a fixture tool for local and integration environments only. It is
# built as its own target so it is never present in a production service image.
FROM gcr.io/distroless/static-debian12:nonroot AS dev-seed
COPY --from=dev-seed-build /out/dev-seed /dev-seed
USER nonroot:nonroot
ENTRYPOINT ["/dev-seed"]
