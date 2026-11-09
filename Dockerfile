# Build stage
# Literal tag and digest so Dependabot (docker ecosystem) can update both; it
# cannot resolve build-arg interpolation in FROM. The tag must equal go.mod's
# toolchain (or go) version; CI's Lint job enforces this.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

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

# Secure metrics generates certificates below this path at runtime. Keep the
# directory writable for the non-root runtime user in the scratch image.
RUN mkdir -p /out/tmp/k8s-metrics-server && chown 65532:65532 /out/tmp/k8s-metrics-server && chmod 0700 /out/tmp/k8s-metrics-server

# Runtime stage: the binary is fully static, so use scratch to avoid shipping
# an independently-updated Debian package set in the runtime image.
FROM scratch

# OCI image labels (may be overridden by docker/metadata-action in CI)
LABEL org.opencontainers.image.title="auth-operator" \
      org.opencontainers.image.description="A Kubernetes operator for managing RBAC with RoleDefinitions, BindDefinitions, and WebhookAuthorizers" \
      org.opencontainers.image.url="https://github.com/telekom/auth-operator" \
      org.opencontainers.image.source="https://github.com/telekom/auth-operator" \
      org.opencontainers.image.vendor="Deutsche Telekom AG" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="scratch"

WORKDIR /

COPY --from=build /out/auth-operator ./auth-operator
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /src/LICENSES/ /licenses/LICENSES/
COPY --from=build --chown=65532:65532 /out/tmp/ /tmp/
USER 65532:65532
ENTRYPOINT ["/auth-operator"]
