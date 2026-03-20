#!/bin/bash
# Run SQL Agent chatbot
# Requires: OPA running on :8181, DEEPSEEK_API_KEY set

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WYATT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load .env if exists
if [ -f "$WYATT_ROOT/.env" ]; then
    export $(grep -v '^#' "$WYATT_ROOT/.env" | xargs)
fi

# Check OPA
if ! curl -s http://localhost:8181/health > /dev/null 2>&1; then
    echo "ERROR: OPA not running on localhost:8181"
    echo "Start with: docker-compose up -d (from $WYATT_ROOT)"
    exit 1
fi

# Check API key
if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo "ERROR: DEEPSEEK_API_KEY not set"
    echo "Add to $WYATT_ROOT/.env"
    exit 1
fi

# Run
cd "$SCRIPT_DIR"
exec python3 main.py "$@"
