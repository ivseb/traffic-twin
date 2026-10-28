# syntax=docker/dockerfile:1
#
# Multi-stage build: UI (Node) -> tt binary (Go, static, no cgo) -> distroless.
# Base images are pinned by digest; bump tag and digest together.

# ---- UI -------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY ui/ ./
# vite writes to ../internal/ui/dist, i.e. /src/internal/ui/dist
RUN npm run build

# ---- Go -------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=ui /src/internal/ui/dist/ internal/ui/dist/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/tt ./cmd/tt

# ---- Runtime --------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
LABEL org.opencontainers.image.title="traffic-twin" \
      org.opencontainers.image.source="https://github.com/ivseb/traffic-twin" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/tt /usr/local/bin/tt
USER nonroot:nonroot
EXPOSE 7070
ENTRYPOINT ["/usr/local/bin/tt"]
# Mount the configuration (deploy/examples/core.production.yaml) and the
# certificates; tt-core refuses a non-loopback listener without TLS and
# needs a separate tt keyguard (keyguard.url).
CMD ["core", "-config", "/etc/tt/core.yaml"]
