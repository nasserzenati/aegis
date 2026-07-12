"""
Aegis — audit logger (J4, enrichi).
Chaque decision (allow / deny / firewall) ecrite dans une base SQLite.
En environnement regule, l'audit trail est une obligation, pas un bonus.
Sert aussi a calculer le ROI (taches, blocages, temps gagne).

Enrichissements :
  - session_id : regrouper les evenements par run d'agent ;
  - pii_redacted : nombre de PII masquees sur la sortie d'un outil ;
  - AEGIS_DB_PATH : chemin de la base configurable (tests, CI) ;
  - migration douce : les colonnes manquantes sont ajoutees a la volee ;
  - chainage de hash : chaque evenement embarque sha256(prev_hash + champs).
    Modifier ou supprimer une ligne casse la chaine a partir de ce point,
    et verify_chain() le detecte. C'est ce qui transforme "un log" en
    "une preuve" — la difference qui compte pour un auditeur.
    (Limite assumee : ecrivain unique ; pas de lock multi-process en v1.)
"""

import hashlib
import os
import sqlite3
from datetime import datetime, timezone

GENESIS = "0" * 64

DB_PATH = os.environ.get("AEGIS_DB_PATH", "audit.db")

# Estimation simple : chaque action d'agent reussie ~ X secondes economisees
# par un humain. Hypothese assumee, ajustable, documentee.
SECONDS_SAVED_PER_ACTION = 90


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT,
                agent       TEXT,
                tool        TEXT,
                decision    TEXT,      -- allow | deny | firewall | egress | error | trace
                reason      TEXT,
                latency_ms  INTEGER,
                session_id  TEXT,
                pii_redacted INTEGER DEFAULT 0,
                prev_hash   TEXT,
                hash        TEXT
            )
        """)
        # Migration douce d'une base creee avant ces colonnes.
        existing = {row[1] for row in c.execute("PRAGMA table_info(events)")}
        for col, decl in [("session_id", "TEXT"),
                          ("pii_redacted", "INTEGER DEFAULT 0"),
                          ("prev_hash", "TEXT"),
                          ("hash", "TEXT")]:
            if col not in existing:
                c.execute(f"ALTER TABLE events ADD COLUMN {col} {decl}")


def _event_hash(prev_hash, ts, agent, tool, decision, reason,
                latency_ms, session_id, pii_redacted):
    payload = "|".join(str(x) for x in (
        prev_hash, ts, agent, tool, decision, reason,
        latency_ms, session_id, pii_redacted))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(agent, tool, decision, reason, latency_ms=0,
              session_id=None, pii_redacted=0):
    init_db()
    ts = datetime.now(timezone.utc).isoformat()
    with _conn() as c:
        row = c.execute(
            "SELECT hash FROM events WHERE hash IS NOT NULL "
            "ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else GENESIS
        h = _event_hash(prev_hash, ts, agent, tool, decision, reason,
                        latency_ms, session_id, pii_redacted)
        c.execute(
            "INSERT INTO events "
            "(ts, agent, tool, decision, reason, latency_ms, session_id, "
            " pii_redacted, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, agent, tool, decision, reason, latency_ms,
             session_id, pii_redacted, prev_hash, h),
        )


def verify_chain():
    """Reparcourt la chaine de hash. Renvoie {ok, checked, first_bad_id}.

    Les lignes anterieures au chainage (hash NULL) sont ignorees : la
    garantie d'integrite commence a la premiere ligne chainee.
    """
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, agent, tool, decision, reason, latency_ms, "
            "session_id, pii_redacted, prev_hash, hash FROM events "
            "WHERE hash IS NOT NULL ORDER BY id").fetchall()
    prev = GENESIS
    for (rid, ts, agent, tool, decision, reason, latency_ms,
         session_id, pii_redacted, prev_hash, h) in rows:
        expected = _event_hash(prev, ts, agent, tool, decision, reason,
                               latency_ms, session_id, pii_redacted)
        if prev_hash != prev or h != expected:
            return {"ok": False, "checked": len(rows), "first_bad_id": rid}
        prev = h
    return {"ok": True, "checked": len(rows), "first_bad_id": None}


def get_metrics():
    """Agrege les evenements en chiffres ROI/securite."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT decision, COUNT(*) FROM events GROUP BY decision"
        ).fetchall()
        pii = c.execute(
            "SELECT COALESCE(SUM(pii_redacted), 0) FROM events"
        ).fetchone()[0]
        avg_latency = c.execute(
            "SELECT COALESCE(AVG(latency_ms), 0) FROM events "
            "WHERE decision = 'allow' AND latency_ms > 0"
        ).fetchone()[0]
        sessions = c.execute(
            "SELECT COUNT(DISTINCT session_id) FROM events "
            "WHERE session_id IS NOT NULL"
        ).fetchone()[0]
    counts = {d: n for d, n in rows}
    allowed = counts.get("allow", 0)
    blocked = counts.get("deny", 0) + counts.get("firewall", 0)
    return {
        "actions_allowed": allowed,
        "actions_denied": counts.get("deny", 0),
        "injections_blocked": counts.get("firewall", 0),
        "egress_sanitized": counts.get("egress", 0),
        "errors": counts.get("error", 0),
        "total_blocked": blocked,
        "pii_redacted": pii,
        "sessions": sessions,
        "avg_latency_ms": round(avg_latency),
        "minutes_saved": round(allowed * SECONDS_SAVED_PER_ACTION / 60, 1),
    }


def count_events() -> int:
    init_db()
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM events").fetchone()[0]


if __name__ == "__main__":
    # Preuve autonome : python -m aegis.audit.logger
    log_event("summarizer", "read_text_file", "allow", "ok", 120,
              session_id="demo", pii_redacted=2)
    log_event("summarizer", "write_file", "deny", "outil interdit", 2,
              session_id="demo")
    log_event("summarizer", "read_text_file", "firewall", "injection suspecte", 95,
              session_id="demo")
    print(get_metrics())
