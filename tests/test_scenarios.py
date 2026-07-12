"""Tests des scenarios de demo (la demo hebergee repose dessus) — sans LLM."""

import pytest

import aegis.audit.logger as logger
from aegis.demo.scenarios import SCENARIOS, replay, seed_if_empty


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "audit_demo.db"
    monkeypatch.setattr(logger, "DB_PATH", str(db))
    return db


EXPECTED = {
    "happy": {"allow"},
    "forbidden_write": {"deny"},
    "injection": {"firewall"},
    "confidential": {"deny"},
    "pii_exfil": {"allow", "egress"},
}


def test_every_scenario_triggers_its_protection(tmp_db):
    for name, expected in EXPECTED.items():
        replay(name)
        import sqlite3
        with sqlite3.connect(tmp_db) as c:
            decisions = {r[0] for r in c.execute(
                "SELECT decision FROM events WHERE decision NOT IN ('trace')")}
        assert expected <= decisions, f"{name}: attendu {expected}, vu {decisions}"
    assert logger.verify_chain()["ok"]


def test_seed_if_empty_populates_then_stops(tmp_db):
    assert logger.count_events() == 0
    assert seed_if_empty() is True
    n = logger.count_events()
    assert n > 0
    # Deja peuplee : le seed ne double pas les donnees.
    assert seed_if_empty() is False
    assert logger.count_events() == n


def test_replayed_answers_are_sanitized(tmp_db):
    answer = replay("pii_exfil")
    assert "sarah.lopez@acme-pharma.com" not in answer
    assert "tracker.example.net" not in answer
