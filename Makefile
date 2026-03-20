.PHONY: help install start stop test logs clean daemon agent

help:
	@echo "Wyatt v0.2.0 - Runtime Policy Enforcement Daemon"
	@echo ""
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make start      - Start OPA sidecar (Docker)"
	@echo "  make stop       - Stop OPA sidecar"
	@echo "  make daemon     - Run Wyatt daemon (Terminal 1)"
	@echo "  make agent      - Run DevOps agent (Terminal 2)"
	@echo "  make test       - Run all tests"
	@echo "  make logs       - Show OPA logs"
	@echo "  make clean      - Clean up containers and cache"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make start       # Start OPA"
	@echo "  2. make daemon      # Terminal 1: Wyatt daemon"
	@echo "  3. make agent       # Terminal 2: DevOps agent"

install:
	python3 -m pip install -e ".[dev]"

start:
	docker-compose up -d
	@echo "Waiting for OPA sidecar to become healthy..."
	@for i in $$(seq 1 15); do \
		if curl -s -f http://localhost:8181/health > /dev/null; then \
			echo "OPA is genuinely ready at http://localhost:8181"; \
			exit 0; \
		fi; \
		echo "Polling OPA health check... ($$i/15)"; \
		sleep 1; \
	done; \
	echo "Error: OPA failed to start within 15 seconds"; \
	exit 1

stop:
	docker-compose down

daemon:
	PYTHONPATH=src python3 run_wyatt.py

agent:
	PYTHONPATH=src python3 run_agent.py

test:
	PYTHONPATH=src python3 -m pytest tests/ -v

logs:
	docker-compose logs -f opa

clean:
	docker-compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -f /tmp/wyatt.sock
