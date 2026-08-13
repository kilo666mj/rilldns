.PHONY: test build blocklists up down logs smoke check

test:
	go test ./...

build:
	mkdir -p bin
	go build -o bin/blocklist-merge ./cmd/blocklist-merge
	go build -o bin/rill-api ./cmd/rill-api
	go build -o bin/rill-mcp ./cmd/rill-mcp
	go build -o bin/rill-reconcile ./cmd/rill-reconcile
	go build -o bin/rill-diff ./cmd/rill-diff
	go build -o bin/rill-secondary ./cmd/rill-secondary
	go build -o bin/rill-notify ./cmd/rill-notify
	go build -o bin/rill-zone-status ./cmd/rill-zone-status
	go build -o bin/rill-blocklist-refresh ./cmd/rill-blocklist-refresh
	go build -o bin/rill-telemetry ./cmd/rill-telemetry

blocklists:
	./scripts/update-blocklists.sh

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f rilldns

smoke:
	./scripts/smoke-test.sh

check: test blocklists
	docker compose config --quiet
