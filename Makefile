.PHONY: build up down logs restart shell

# Local environment
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

# Development (no Docker)
dev:
	go run ./cmd/server

test:
	node tests/test_supabase_client.mjs
