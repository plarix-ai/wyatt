#!/bin/bash
# Run SQL Agent chatbot
# Requires: OPA running on :8181, DEEPSEEK_API_KEY in .env

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if exists
if [ -f ../.env ]; then
    export $(grep -v '^#' ../.env | xargs)
fi

# Check OPA
if ! curl -s http://localhost:8181/health > /dev/null 2>&1; then
    echo "ERROR: OPA not running on localhost:8181"
    echo "Start OPA: ./start_opa.sh"
    exit 1
fi

# Check API key
if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo "ERROR: DEEPSEEK_API_KEY not set"
    echo "Copy .env.example to .env and add your key"
    exit 1
fi

# Run agent
python3 -c "
import sys
sys.path.insert(0, '.')
from main import main
main()
" "$@"
