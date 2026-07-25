# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# -ldflags="-s -w" strips debug symbols; -trimpath removes local paths;
# -pgo=auto uses default.pgo when present (Go 1.21+), otherwise builds normally.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -pgo=auto -ldflags="-s -w" -o /out/dingbap .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget \
  && adduser -D -H -u 1000 dingbap \
  && mkdir -p /data \
  && chown dingbap:dingbap /data

COPY --from=build /out/dingbap /usr/local/bin/dingbap

USER dingbap
WORKDIR /data

ENV DINGBAP_STORAGE_DIR=/data
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/login >/dev/null || exit 1

ENTRYPOINT ["dingbap"]
CMD ["-port", "8080", "-storage-dir", "/data"]
