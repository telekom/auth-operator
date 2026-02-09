# Build stage
# Go version is read from go.mod via GO_VERSION build arg
# Default fallback if not provided (should match go.mod)
ARG GO_VERSION=1.25
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG REPOSITORY=https://github.com/telekom/auth-operator

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Ensure LICENSES directory exists for the runtime stage COPY
RUN mkdir -p /src/LICENSES

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -ldflags="-s -w \
	-X github.com/telekom/auth-operator/pkg/system.Version=$VERSION \
	-X github.com/telekom/auth-operator/pkg/system.Commit=$COMMIT \
	-X github.com/telekom/auth-operator/pkg/system.Repository=$REPOSITORY" \
	-o /out/auth-operator ./main.go

# Runtime stage (distroless)
FROM gcr.io/distroless/static-debian12

# OCI image labels (may be overridden by docker/metadata-action in CI)
LABEL org.opencontainers.image.title="auth-operator" \
      org.opencontainers.image.description="A Kubernetes operator for managing RBAC with RoleDefinitions, BindDefinitions, and WebhookAuthorizers" \
      org.opencontainers.image.url="https://github.com/telekom/auth-operator" \
      org.opencontainers.image.source="https://github.com/telekom/auth-operator" \
      org.opencontainers.image.vendor="Deutsche Telekom AG" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12"

WORKDIR /

COPY --from=build /out/auth-operator ./auth-operator
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /src/LICENSES/ /licenses/LICENSES/
USER 65532:65532
ENTRYPOINT ["/auth-operator"]
