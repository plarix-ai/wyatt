#!/bin/bash
# Start OPA server with Wyatt policies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$SCRIPT_DIR/src/wyatt/policies"

echo "Starting OPA server..."
echo "Policy directory: $POLICY_DIR"
echo "Endpoint: http://localhost:8181"
echo ""

opa run --server --addr :8181 "$POLICY_DIR"
