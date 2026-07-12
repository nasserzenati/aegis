"""Tests du policy engine — deterministe, aucun LLM requis."""

import pytest

from aegis.gateway.policy import PolicyEngine

POLICY = "policies/default.yaml"


@pytest.fixture
def engine():
    return PolicyEngine(POLICY, agent="summarizer")


def test_allowed_tool_passes(engine):
    d = engine.check("read_text_file", {"path": "demo/workspace/notes.txt"})
    assert d.allowed


def test_denied_tool_is_blocked(engine):
    d = engine.check("write_file", {"path": "demo/workspace/x.txt"})
    assert not d.allowed
    assert "interdite" in d.reason


def test_unknown_tool_blocked_by_default_deny(engine):
    d = engine.check("send_email", {"to": "someone@example.com"})
    assert not d.allowed
    assert "allowlist" in d.reason


def test_confidential_tag_is_blocked(engine):
    d = engine.check("read_text_file",
                     {"path": "demo/workspace/confidential_roadmap.txt"})
    assert not d.allowed
    assert "confidential" in d.reason


def test_path_traversal_is_blocked(engine):
    for path in ["../../etc/passwd", "demo/../../secrets", "..", "a/.."]:
        d = engine.check("read_text_file", {"path": path})
        assert not d.allowed, f"traversal accepte: {path}"


def test_dots_inside_filename_are_fine(engine):
    d = engine.check("read_text_file", {"path": "demo/notes..final.txt"})
    assert d.allowed


def test_session_quota_is_enforced(engine):
    for _ in range(engine.max_calls):
        assert engine.check("read_text_file", {"path": "demo/a.txt"}).allowed
    d = engine.check("read_text_file", {"path": "demo/a.txt"})
    assert not d.allowed
    assert "quota" in d.reason


def test_denied_calls_do_not_consume_quota(engine):
    for _ in range(5):
        engine.check("write_file", {"path": "x"})
    assert engine.calls_made == 0


def test_unknown_agent_raises():
    with pytest.raises(ValueError):
        PolicyEngine(POLICY, agent="nonexistent")
