"""
Pytest configuration and shared fixtures.

This file is automatically loaded by pytest.
"""

import pytest


@pytest.fixture(scope="session", autouse=True)
def check_opa_running():
    """
    Verify OPA is running before tests start.

    This runs once per test session automatically.
    """
    import httpx

    try:
        response = httpx.get("http://localhost:8181/health", timeout=2.0)
        response.raise_for_status()
    except Exception as e:
        pytest.skip(f"OPA not running. Start with 'make start'. Error: {e}")
