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
