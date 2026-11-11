# vault-estate in a container: the static binary on distroless, which
# carries CA certificates for Vault over TLS and runs as nonroot.
#
#   docker run --rm ghcr.io/nicholasjackson/vault-estate show -name noths
#
# The binary is cross-compiled on the build platform, so a multi-platform
# build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/vault-estate .

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/vault-estate /usr/local/bin/vault-estate

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/vault-estate"]
CMD ["help"]
