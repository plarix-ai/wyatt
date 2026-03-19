.PHONY: help install start stop run test logs clean

help:
	@echo "Wyatt v0.1.0 - Runtime Policy Enforcement Daemon"
	@echo ""
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make start      - Start OPA sidecar"
	@echo "  make stop       - Stop OPA sidecar"
	@echo "  make run        - Run the example agent"
	@echo "  make test       - Run all tests"
	@echo "  make logs       - Show OPA logs"
	@echo "  make clean      - Clean up containers and cache"

install:
	pip install httpx pydantic structlog pytest pytest-asyncio

start:
	docker compose up -d
	@echo "OPA is starting... waiting for health check..."
	@sleep 3
	@docker compose ps
	@echo ""
	@echo "OPA is ready at http://localhost:8181"

stop:
	docker compose down

run:
	PYTHONPATH=. python3 examples/simple_agent.py

test:
	PYTHONPATH=. python3 -m pytest tests/ -v

logs:
	docker compose logs -f opa

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
