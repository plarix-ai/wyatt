"""
Tests for boundary enforcement.

Tests the BoundaryEnforcer with all 4 AFB04 sub-boundaries:
- TOOL: agent-tool allowlist
- DATA: argument-level path restrictions and traversal detection
- EXEC: execution constraints
- CTX: output redaction
"""

import pytest

from core.boundaries import BoundaryEnforcer, create_default_config
from core.models import (
    AFBType,
    BoundaryConfig,
    DataBoundaryRule,
    Verdict,
)


@pytest.fixture
def config():
    """Default boundary configuration for tests."""
    return create_default_config()


@pytest.fixture
def enforcer(config):
    """BoundaryEnforcer with default config."""
    return BoundaryEnforcer(config)


# =============================================================================
# TOOL Boundary Tests
# =============================================================================


class TestToolBoundary:
    """Tests for the TOOL sub-boundary of AFB04."""

    def test_permits_allowed_tool(self, enforcer):
        """Agent with tool in allowlist should be permitted."""
        decision = enforcer.check_tool_boundary("devops-agent", "read_file")
        assert decision.verdict == Verdict.ALLOW
        assert decision.afb == AFBType.TOOL

    def test_denies_disallowed_tool(self, enforcer):
        """Agent attempting unauthorized tool should be denied."""
        decision = enforcer.check_tool_boundary("devops-agent", "delete_file")
        assert decision.verdict == Verdict.DENY
        assert "not in allowlist" in decision.reason

    def test_denies_unknown_agent(self, enforcer):
        """Unknown agent should be denied any tool."""
        decision = enforcer.check_tool_boundary("unknown-hacker", "read_file")
        assert decision.verdict == Verdict.DENY

    def test_each_agent_has_own_allowlist(self, enforcer):
        """Different agents have different tool allowlists."""
        # agent-001 can read_file but NOT list_directory
        d1 = enforcer.check_tool_boundary("agent-001", "read_file")
        d2 = enforcer.check_tool_boundary("agent-001", "list_directory")
        assert d1.verdict == Verdict.ALLOW
        assert d2.verdict == Verdict.DENY

        # devops-agent can do both
        d3 = enforcer.check_tool_boundary("devops-agent", "read_file")
        d4 = enforcer.check_tool_boundary("devops-agent", "list_directory")
        assert d3.verdict == Verdict.ALLOW
        assert d4.verdict == Verdict.ALLOW


# =============================================================================
# DATA Boundary Tests
# =============================================================================


class TestDataBoundary:
    """Tests for the DATA sub-boundary of AFB04."""

    def test_allows_safe_path(self, enforcer):
        """Reading from /tmp/* should be allowed."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/tmp/app.log"}
        )
        assert decision.verdict == Verdict.ALLOW

    def test_denies_etc_path(self, enforcer):
        """Reading from /etc/* should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/etc/shadow"}
        )
        assert decision.verdict == Verdict.DENY
        assert "deny pattern" in decision.reason

    def test_denies_root_path(self, enforcer):
        """Reading from /root/* should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/root/.bashrc"}
        )
        assert decision.verdict == Verdict.DENY

    def test_denies_key_files(self, enforcer):
        """Reading .key files should be denied regardless of path."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/home/user/server.key"}
        )
        assert decision.verdict == Verdict.DENY

    def test_denies_pem_files(self, enforcer):
        """Reading .pem files should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/tmp/cert.pem"}
        )
        assert decision.verdict == Verdict.DENY

    def test_denies_shadow_in_name(self, enforcer):
        """Any file with 'shadow' in name should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/tmp/shadow_copy"}
        )
        assert decision.verdict == Verdict.DENY

    def test_denies_path_traversal_dotdot(self, enforcer):
        """Path traversal with .. should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "../../etc/passwd"}
        )
        assert decision.verdict == Verdict.DENY
        assert "traversal" in decision.reason

    def test_denies_path_traversal_encoded(self, enforcer):
        """URL-encoded path traversal should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "%2e%2e/%2e%2e/etc/passwd"}
        )
        assert decision.verdict == Verdict.DENY
        assert "traversal" in decision.reason

    def test_denies_null_byte_injection(self, enforcer):
        """Null byte injection should be denied."""
        decision = enforcer.check_data_boundary(
            "devops-agent", "read_file", {"path": "/tmp/safe.txt\x00../../etc/shadow"}
        )
        assert decision.verdict == Verdict.DENY
        assert "traversal" in decision.reason

    def test_no_rules_allows_by_default(self):
        """If no data rules configured, arguments pass through."""
        config = BoundaryConfig(
            tool_allowlist={"test-agent": ["some_tool"]},
            data_rules=[],
        )
        enforcer = BoundaryEnforcer(config)
        decision = enforcer.check_data_boundary(
            "test-agent", "some_tool", {"any_arg": "any_value"}
        )
        assert decision.verdict == Verdict.ALLOW
        assert "no data rules" in decision.reason

    def test_list_directory_path_rules(self, enforcer):
        """list_directory should respect its own data boundary rules."""
        # /tmp is allowed
        d1 = enforcer.check_data_boundary(
            "devops-agent", "list_directory", {"path": "/tmp"}
        )
        assert d1.verdict == Verdict.ALLOW

        # /root is denied
        d2 = enforcer.check_data_boundary(
            "devops-agent", "list_directory", {"path": "/root"}
        )
        assert d2.verdict == Verdict.DENY


# =============================================================================
# EXEC Boundary Tests
# =============================================================================


class TestExecBoundary:
    """Tests for the EXEC sub-boundary of AFB04."""

    def test_exec_boundary_allows_by_default(self, enforcer):
        """Exec boundary allows by default with timeout info."""
        decision = enforcer.check_exec_boundary(
            "devops-agent", "read_file", {"path": "/tmp/test"}
        )
        assert decision.verdict == Verdict.ALLOW
        assert "timeout" in decision.reason


# =============================================================================
# CTX Boundary Tests
# =============================================================================


class TestCtxBoundary:
    """Tests for the CTX sub-boundary of AFB04."""

    def test_redacts_passwords(self, enforcer):
        """Output containing passwords should be redacted."""
        output = "config loaded\npassword = mysecretpass123\nserver started"
        verdict, filtered = enforcer.check_ctx_boundary(output)
        assert verdict == Verdict.REDACT
        assert "mysecretpass123" not in filtered
        assert "[REDACTED]" in filtered

    def test_redacts_api_keys(self, enforcer):
        """Output containing API keys should be redacted."""
        output = "api_key = sk-live-abc123\nready"
        verdict, filtered = enforcer.check_ctx_boundary(output)
        assert verdict == Verdict.REDACT
        assert "sk-live-abc123" not in filtered

    def test_redacts_secrets(self, enforcer):
        """Output containing secrets should be redacted."""
        output = "secret = jwt_signing_key_here\ndone"
        verdict, filtered = enforcer.check_ctx_boundary(output)
        assert verdict == Verdict.REDACT
        assert "jwt_signing_key_here" not in filtered

    def test_allows_clean_output(self, enforcer):
        """Output without sensitive patterns should pass through."""
        output = "server started on port 8080\nall systems operational"
        verdict, filtered = enforcer.check_ctx_boundary(output)
        assert verdict == Verdict.ALLOW
        assert filtered == output

    def test_no_redact_patterns_allows_all(self):
        """With no redact patterns, all output passes through."""
        config = BoundaryConfig(redact_patterns=[])
        enforcer = BoundaryEnforcer(config)
        verdict, filtered = enforcer.check_ctx_boundary("password = secret123")
        assert verdict == Verdict.ALLOW


# =============================================================================
# Full Chain Tests (check_all)
# =============================================================================


class TestCheckAll:
    """Tests for the full AFB04 boundary chain."""

    def test_full_chain_allow(self, enforcer):
        """Full chain with valid agent, tool, and args should ALLOW."""
        decisions = enforcer.check_all(
            "devops-agent", "read_file", {"path": "/tmp/test.log"}
        )
        assert all(d.verdict == Verdict.ALLOW for d in decisions)
        # Should have TOOL, DATA, EXEC
        afbs = [d.afb for d in decisions]
        assert AFBType.TOOL in afbs
        assert AFBType.DATA in afbs
        assert AFBType.EXEC in afbs

    def test_full_chain_stops_at_tool_deny(self, enforcer):
        """Chain should stop at TOOL boundary if tool is not permitted."""
        decisions = enforcer.check_all(
            "devops-agent", "delete_file", {"path": "/tmp/test"}
        )
        assert len(decisions) == 1
        assert decisions[0].verdict == Verdict.DENY
        assert decisions[0].afb == AFBType.TOOL

    def test_full_chain_stops_at_data_deny(self, enforcer):
        """Chain should stop at DATA boundary if path is forbidden."""
        decisions = enforcer.check_all(
            "devops-agent", "read_file", {"path": "/etc/shadow"}
        )
        assert len(decisions) == 2
        assert decisions[0].verdict == Verdict.ALLOW  # TOOL ok
        assert decisions[1].verdict == Verdict.DENY  # DATA denied
        assert decisions[1].afb == AFBType.DATA

    def test_unknown_agent_denied_at_tool(self, enforcer):
        """Unknown agent should be denied at TOOL boundary."""
        decisions = enforcer.check_all(
            "unknown-agent", "read_file", {"path": "/tmp/test"}
        )
        assert len(decisions) == 1
        assert decisions[0].verdict == Verdict.DENY
        assert decisions[0].afb == AFBType.TOOL
