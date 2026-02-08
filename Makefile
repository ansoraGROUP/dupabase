.PHONY: build up down logs restart shell dev test \
       prod-build prod-up prod-down prod-logs prod-restart \
       encrypt decrypt help

# ── Local environment ──────────────────────────────────────────────

build: ## Build local containers
	docker compose -f .deploy/local/docker-compose.yaml build

up: ## Start local containers
	docker compose -f .deploy/local/docker-compose.yaml up -d

down: ## Stop local containers
	docker compose -f .deploy/local/docker-compose.yaml down

logs: ## View local container logs
	docker compose -f .deploy/local/docker-compose.yaml logs -f

restart: ## Restart local containers
	docker compose -f .deploy/local/docker-compose.yaml restart

shell: ## Shell into container
	docker exec -it dupabase sh

# ── Production environment ─────────────────────────────────────────

prod-build: ## Build production containers
	docker compose -f .deploy/prod/docker-compose.yaml build

prod-up: ## Start production containers
	docker compose -f .deploy/prod/docker-compose.yaml up -d

prod-down: ## Stop production containers
	docker compose -f .deploy/prod/docker-compose.yaml down

prod-logs: ## View production container logs
	docker compose -f .deploy/prod/docker-compose.yaml logs -f

prod-restart: ## Restart production containers
	docker compose -f .deploy/prod/docker-compose.yaml restart

# ── Encrypt / Decrypt .env files ───────────────────────────────────
# Usage:
#   ENCRYPTION_KEY=secret make encrypt ENV=prod
#   ENCRYPTION_KEY=secret make decrypt ENV=prod

ENV ?= prod

encrypt: ## Encrypt .deploy/$(ENV)/.env → .deploy/$(ENV)/.env.encrypted
	@test -n "$(ENCRYPTION_KEY)" || (echo "Error: ENCRYPTION_KEY not set" && exit 1)
	openssl aes-256-cbc -md sha512 -salt -pass pass:"$(ENCRYPTION_KEY)" \
		-in .deploy/$(ENV)/.env -out .deploy/$(ENV)/.env.encrypted
	@echo "Encrypted: .deploy/$(ENV)/.env → .deploy/$(ENV)/.env.encrypted"

decrypt: ## Decrypt .deploy/$(ENV)/.env.encrypted → .deploy/$(ENV)/.env
	@test -n "$(ENCRYPTION_KEY)" || (echo "Error: ENCRYPTION_KEY not set" && exit 1)
	openssl aes-256-cbc -md sha512 -salt -pass pass:"$(ENCRYPTION_KEY)" \
		-in .deploy/$(ENV)/.env.encrypted -out .deploy/$(ENV)/.env -d
	@echo "Decrypted: .deploy/$(ENV)/.env.encrypted → .deploy/$(ENV)/.env"

# ── Development (no Docker) ────────────────────────────────────────

dev: ## Run Go server locally
	go run ./cmd/server

test: ## Run tests
	node tests/test_supabase_client.mjs

# ── Help ───────────────────────────────────────────────────────────

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
