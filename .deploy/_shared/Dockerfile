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
# NOTE: Consider pinning to specific patch version (e.g., node:20.18.1-alpine3.20) for reproducible builds
FROM node:20-alpine

ARG PG_VERSION=16
RUN apk --no-cache add ca-certificates tzdata postgresql${PG_VERSION}-client

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

# Ensure imports directory is writable
RUN mkdir -p /tmp/imports && chown node:node /tmp/imports

EXPOSE 3333

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3333/health || exit 1

USER node

CMD ["./entrypoint.sh"]
