"""Tests du chainage de hash de l'audit — l'inviolabilite du journal."""

import sqlite3

import pytest

import aegis.audit.logger as logger


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "audit_chain.db"
    monkeypatch.setattr(logger, "DB_PATH", str(db))
    return db


def _log_three():
    logger.log_event("summarizer", "read_text_file", "allow", "ok", 100,
                     session_id="s1")
    logger.log_event("summarizer", "write_file", "deny", "outil interdit", 0,
                     session_id="s1")
    logger.log_event("summarizer", "final_answer", "trace", "resume...", 0,
                     session_id="s1")


def test_intact_chain_verifies(tmp_db):
    _log_three()
    result = logger.verify_chain()
    assert result["ok"]
    assert result["checked"] == 3


def test_tampered_row_is_detected(tmp_db):
    _log_three()
    # Un auditeur veut savoir si quelqu'un a reecrit l'histoire :
    # on falsifie une decision "deny" en "allow" directement en SQL.
    with sqlite3.connect(tmp_db) as c:
        c.execute("UPDATE events SET decision = 'allow' WHERE decision = 'deny'")
    result = logger.verify_chain()
    assert not result["ok"]
    assert result["first_bad_id"] == 2


def test_deleted_row_is_detected(tmp_db):
    _log_three()
    with sqlite3.connect(tmp_db) as c:
        c.execute("DELETE FROM events WHERE id = 2")
    result = logger.verify_chain()
    assert not result["ok"]


def test_legacy_rows_without_hash_are_skipped(tmp_db):
    # Une base d'avant le chainage : lignes sans hash, puis lignes chainees.
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
    logger.log_event("summarizer", "read_text_file", "allow", "ok", 100)
    result = logger.verify_chain()
    assert result["ok"]
    assert result["checked"] == 1  # la ligne legacy est hors garantie
