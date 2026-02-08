# Stage 1: Build Go binary
FROM golang:1.25-alpine AS go-builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server ./cmd/server

# Stage 2: Build Next.js dashboard
FROM node:20-alpine AS next-builder

WORKDIR /app

# Cache dependencies
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci

# Build dashboard with empty API URL (same-origin in production)
COPY dashboard/ .
ENV NEXT_PUBLIC_API_URL=""
RUN npm run build

# Stage 3: Production
FROM node:20-alpine

RUN apk --no-cache add ca-certificates tzdata postgresql16-client

RUN adduser -D -u 1000 appuser

WORKDIR /app

# Go binary and migrations
COPY --from=go-builder /app/server .
COPY --from=go-builder /app/migrations ./migrations

# Next.js standalone output
COPY --from=next-builder /app/.next/standalone ./dashboard
COPY --from=next-builder /app/.next/static ./dashboard/.next/static
COPY --from=next-builder /app/public ./dashboard/public

# Entrypoint script
COPY .deploy/_shared/entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 3333

USER appuser

CMD ["./entrypoint.sh"]
