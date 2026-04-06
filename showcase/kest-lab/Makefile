.PHONY: up down register shell status setup-agent

up:
	docker compose up -d spire-server
	@echo "Waiting for spire-server..."
	@sleep 5
	@make setup-agent
	docker compose up -d spire-agent opa cedar-agent otel-collector hop1 hop2 hop3
	@echo "Waiting for sidecars..."
	@sleep 5

down:
	docker compose down -v

status:
	docker compose ps
	@echo "\n--- Health Checks ---"
	@curl -s -o /dev/null -w "OPA: %{http_code}\n" http://localhost:8181/health
	@curl -s -o /dev/null -w "Cedar-Agent: %{http_code}\n" http://localhost:8180/health || echo "Cedar-Agent: FAILED"

setup-agent:
	@echo "Bootstrapping SPIRE Agent..."
	# 1. Export trust bundle from server
	docker compose exec spire-server bin/spire-server bundle show -format pem > spire/agent/trust-bundle.pem
	# 2. Generate join token
	$(eval TOKEN := $(shell docker compose exec spire-server bin/spire-server token generate -spiffeID spiffe://kest.internal/agent/my-node | cut -d' ' -f2))
	@echo "Generated Join Token: $(TOKEN)"

register:
	@echo "Registering Workloads..."
	@for hop in hop1 hop2 hop3; do \
		docker compose exec spire-server bin/spire-server entry create \
			-parentID spiffe://kest.internal/agent/my-node \
			-spiffeID spiffe://kest.internal/workload/$$hop \
			-selector unix:uid:0; \
	done

verify:
	@echo "Starting E2E Verification..."
	python3 e2e_test.py

shell:
	docker compose exec hop1 bash
