# syntax=docker/dockerfile:1

# Build on the native platform and cross-compile, which is much faster than
# emulating the target architecture.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH

# The Go toolchain stamps the binary's version from git, so the build
# context includes .git (see .dockerignore).
RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=true -ldflags "-s -w" \
    -o /out/samesame ./cmd/samesame

# Static binary, no shell, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/samesame /usr/local/bin/samesame

# Mount the folder of .pem private keys here, and set SAMESAME_AUTHORITY to
# the host (or comma-separated hosts) verifiers fetch the directory from.
ENV SAMESAME_KEYS=/keys \
    SAMESAME_BIND=:8080
VOLUME /keys
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/samesame"]
CMD ["serve"]
