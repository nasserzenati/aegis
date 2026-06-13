"""
Aegis — audit logger (J4).
Chaque decision (allow / deny / firewall) ecrite dans une base SQLite.
En environnement regule, l'audit trail est une obligation, pas un bonus.
Sert aussi a calculer le ROI (taches, blocages, temps gagne).
"""

import sqlite3
import time
from datetime import datetime, timezone

DB_PATH = "audit.db"

# Estimation simple : chaque action d'agent reussie ~ X secondes economisees
# par un humain. Hypothese assumee, ajustable, documentee.
SECONDS_SAVED_PER_ACTION = 90


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT,
                agent     TEXT,
                tool      TEXT,
                decision  TEXT,      -- allow | deny | firewall
                reason    TEXT,
                latency_ms INTEGER
            )
        """)


def log_event(agent, tool, decision, reason, latency_ms=0):
    init_db()
    with _conn() as c:
        c.execute(
            "INSERT INTO events (ts, agent, tool, decision, reason, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), agent, tool,
             decision, reason, latency_ms),
        )


def get_metrics():
    """Agrege les evenements en chiffres ROI/securite."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT decision, COUNT(*) FROM events GROUP BY decision"
        ).fetchall()
    counts = {d: n for d, n in rows}
    allowed = counts.get("allow", 0)
    blocked = counts.get("deny", 0) + counts.get("firewall", 0)
    return {
        "actions_allowed": allowed,
        "actions_denied": counts.get("deny", 0),
        "injections_blocked": counts.get("firewall", 0),
        "total_blocked": blocked,
        "minutes_saved": round(allowed * SECONDS_SAVED_PER_ACTION / 60, 1),
    }


if __name__ == "__main__":
    # Preuve autonome : python -m aegis.audit.logger
    log_event("summarizer", "read_text_file", "allow", "ok", 120)
    log_event("summarizer", "write_file", "deny", "outil interdit", 2)
    log_event("summarizer", "read_text_file", "firewall", "injection suspecte", 95)
    print(get_metrics())
