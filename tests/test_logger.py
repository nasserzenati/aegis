"""Tests de l'audit logger sur une base temporaire — aucun LLM requis."""

import sqlite3

import pytest

import aegis.audit.logger as logger


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "audit_test.db"
    monkeypatch.setattr(logger, "DB_PATH", str(db))
    return db


def test_events_are_logged_and_aggregated(tmp_db):
    logger.log_event("summarizer", "read_text_file", "allow", "ok", 120,
                     session_id="s1", pii_redacted=2)
    logger.log_event("summarizer", "write_file", "deny", "outil interdit", 0,
                     session_id="s1")
    logger.log_event("summarizer", "read_text_file", "firewall",
                     "injection suspecte", 95, session_id="s2")

    m = logger.get_metrics()
    assert m["actions_allowed"] == 1
    assert m["actions_denied"] == 1
    assert m["injections_blocked"] == 1
    assert m["total_blocked"] == 2
    assert m["pii_redacted"] == 2
    assert m["sessions"] == 2
    assert m["avg_latency_ms"] == 120
    assert m["minutes_saved"] == 1.5


def test_empty_db_gives_zero_metrics(tmp_db):
    m = logger.get_metrics()
    assert m["actions_allowed"] == 0
    assert m["total_blocked"] == 0
    assert m["minutes_saved"] == 0


def test_old_schema_is_migrated(tmp_db):
    # Simule une base creee avant les colonnes session_id / pii_redacted.
    with sqlite3.connect(tmp_db) as c:
        c.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, agent TEXT, tool TEXT,
                decision TEXT, reason TEXT, latency_ms INTEGER
            )
        """)
        c.execute("INSERT INTO events (ts, agent, tool, decision, reason, "
                  "latency_ms) VALUES ('t', 'a', 'read', 'allow', 'ok', 50)")

    # init_db (via log_event) doit ajouter les colonnes sans perdre les donnees.
    logger.log_event("summarizer", "read_text_file", "allow", "ok", 100,
                     session_id="s1", pii_redacted=1)
    m = logger.get_metrics()
    assert m["actions_allowed"] == 2
    assert m["pii_redacted"] == 1
