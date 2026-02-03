# Build stage
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

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

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -ldflags="-s -w \
	-X github.com/telekom/auth-operator/pkg/system.Version=$VERSION \
	-X github.com/telekom/auth-operator/pkg/system.Commit=$COMMIT \
	-X github.com/telekom/auth-operator/pkg/system.Repository=$REPOSITORY" \
	-o /out/auth-operator ./main.go

# Runtime stage (distroless)
FROM gcr.io/distroless/static-debian12

WORKDIR /

COPY --from=build /out/auth-operator ./auth-operator
USER 65532:65532
ENTRYPOINT ["/auth-operator"]
