FROM golang:1.25-alpine AS build

RUN apk add --no-cache build-base file-dev

WORKDIR /src/services/api

COPY services/api/go.mod services/api/go.sum ./
RUN go mod download

COPY services/api ./
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/malcore-api ./cmd/api
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/malcore-worker ./cmd/worker

FROM alpine:3.22

RUN apk add --no-cache ca-certificates file-libs \
    && addgroup -S malcore \
    && adduser -S malcore -G malcore \
    && mkdir -p /app/storage \
    && chown -R malcore:malcore /app

WORKDIR /app

COPY --from=build /out/malcore-api /app/malcore-api
COPY --from=build /out/malcore-worker /app/malcore-worker

USER malcore

EXPOSE 8080

CMD ["/app/malcore-api"]
