# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server ./cmd/server

# Production stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata postgresql16-client

RUN adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=builder /app/server .
COPY --from=builder /app/migrations ./migrations

EXPOSE 3333

USER appuser

CMD ["./server"]
