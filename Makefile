.PHONY: build up down logs restart shell dev test \
       prod-build prod-up prod-down prod-logs prod-restart \
       encrypt decrypt

# ── Local environment ──────────────────────────────────────────────

build:
	docker compose -f .deploy/local/docker-compose.yaml build

up:
	docker compose -f .deploy/local/docker-compose.yaml up -d

down:
	docker compose -f .deploy/local/docker-compose.yaml down

logs:
	docker compose -f .deploy/local/docker-compose.yaml logs -f

restart:
	docker compose -f .deploy/local/docker-compose.yaml restart

shell:
	docker exec -it dupabase sh

# ── Production environment ─────────────────────────────────────────

prod-build:
	docker compose -f .deploy/prod/docker-compose.yaml build

prod-up:
	docker compose -f .deploy/prod/docker-compose.yaml up -d

prod-down:
	docker compose -f .deploy/prod/docker-compose.yaml down

prod-logs:
	docker compose -f .deploy/prod/docker-compose.yaml logs -f

prod-restart:
	docker compose -f .deploy/prod/docker-compose.yaml restart

# ── Encrypt / Decrypt .env files ───────────────────────────────────
# Usage:
#   make encrypt ENV=prod                  (encrypts .deploy/prod/.env → .deploy/prod/.env.encrypted)
#   make decrypt ENV=prod                  (decrypts .deploy/prod/.env.encrypted → .deploy/prod/.env)
#   ENCRYPTION_KEY=secret make decrypt ENV=prod   (non-interactive, for CI)

ENV ?= prod

encrypt:
	@if [ ! -f .deploy/$(ENV)/.env ]; then \
		echo "Error: .deploy/$(ENV)/.env not found"; exit 1; \
	fi
	@openssl enc -aes-256-cbc -pbkdf2 -salt \
		-in .deploy/$(ENV)/.env \
		-out .deploy/$(ENV)/.env.encrypted \
		$(if $(ENCRYPTION_KEY),-pass pass:$(ENCRYPTION_KEY),-pass stdin)
	@echo "Encrypted: .deploy/$(ENV)/.env → .deploy/$(ENV)/.env.encrypted"

decrypt:
	@if [ ! -f .deploy/$(ENV)/.env.encrypted ]; then \
		echo "Error: .deploy/$(ENV)/.env.encrypted not found"; exit 1; \
	fi
	@openssl enc -aes-256-cbc -pbkdf2 -d \
		-in .deploy/$(ENV)/.env.encrypted \
		-out .deploy/$(ENV)/.env \
		$(if $(ENCRYPTION_KEY),-pass pass:$(ENCRYPTION_KEY),-pass stdin)
	@echo "Decrypted: .deploy/$(ENV)/.env.encrypted → .deploy/$(ENV)/.env"

# ── Development (no Docker) ────────────────────────────────────────

dev:
	go run ./cmd/server

test:
	node tests/test_supabase_client.mjs
