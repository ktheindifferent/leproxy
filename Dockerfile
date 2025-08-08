# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty)" \
    -o leproxy .

# Runtime stage
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/leproxy /leproxy

VOLUME ["/var/cache/letsencrypt", "/var/cache/dbproxy-certs", "/etc/leproxy"]

EXPOSE 80 443

ENTRYPOINT ["/leproxy"]
CMD ["-addr", ":443", "-http", ":80", "-map", "/etc/leproxy/mapping.yml", "-cacheDir", "/var/cache/letsencrypt"]