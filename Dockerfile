# ─── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Build a fully static binary (embedded wordlists ship inside it).
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/capsaicin ./cmd/capsaicin

# ─── Runtime stage ───────────────────────────────────────────────────────────
FROM alpine:3.20

# CA certificates for TLS to real targets; a non-root user for least privilege.
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 capsaicin

COPY --from=build /out/capsaicin /usr/local/bin/capsaicin
COPY --from=build /src/templates /opt/capsaicin/templates

USER capsaicin
ENTRYPOINT ["capsaicin"]
CMD ["--help"]
