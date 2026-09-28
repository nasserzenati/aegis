"""
Aegis — garde RAG (control plane pour un assistant documentaire).

Le cas d'usage d'origine d'Aegis est un agent qui appelle des OUTILS (MCP).
Un assistant RAG n'appelle pas d'outils : il RECUPERE des extraits de
documents et les injecte dans le contexte du modele. Les memes principes
s'appliquent, a d'autres points de controle :

  1. Politique par ROLE et par CLASSIFICATION : un extrait n'entre dans le
     contexte que si le role de l'utilisateur est autorise a lire son niveau
     (public / interne / confidentiel...). Default-deny : un role inconnu ou
     un niveau non liste est refuse. Les versions remplacees peuvent etre
     exclues par la politique.
  2. Firewall sur chaque extrait AVANT le contexte : granularite "chunk"
     (l'extrait suspect est retire en entier) ou "line" (seules les lignes
     suspectes sont retirees, le reste de l'extrait legitime est conserve).
  3. Redaction PII sur chaque extrait admis.
  4. Egress sur la reponse finale (mode strict par defaut en banque).
  5. Audit hash-chaine de chaque decision + trace question/reponse.

Comme ailleurs dans Aegis : le LLM propose, la politique dispose. Le filtrage
d'acces se fait AVANT la generation ; on ne demande jamais au modele d'etre
discret.

Limites (assumees) : le role est fourni par l'appelant (pas encore relie a un
annuaire / IAM) ; la classification vient des metadonnees d'ingestion.
"""

import uuid
from dataclasses import dataclass, field

import yaml

from aegis.audit.logger import log_event
from aegis.gateway.egress import EgressResult, screen
from aegis.gateway.firewall import neutralize, scan
from aegis.gateway.redact import redact


@dataclass
class ChunkVerdict:
    allowed: bool
    reason: str
    text: str = ""
    pii_redacted: int = 0
    lines_removed: int = 0


@dataclass
class FilterReport:
    kept: list = field(default_factory=list)       # [(chunk, score)]
    denied_access: int = 0
    denied_version: int = 0
    firewall_blocked: int = 0
    lines_removed: int = 0
    pii_redacted: int = 0


class RagGuard:
    def __init__(self, policy_path: str, role: str, session_id: str | None = None,
                 agent_prefix: str = "rag"):
        with open(policy_path, encoding="utf-8") as f:
            policy = yaml.safe_load(f)
        roles = policy.get("rag_roles", {})
        if role not in roles:
            raise ValueError(f"Aucune politique RAG pour le role '{role}' (default-deny)")
        rules = roles[role]
        self.role = role
        self.agent = f"{agent_prefix}:{role}"
        self.allowed_levels = {str(x).lower() for x in rules.get("allowed_levels", [])}
        self.max_chunks = int(rules.get("max_chunks", 5))
        opts = policy.get("rag_options", {})
        self.exclude_superseded = bool(opts.get("exclude_superseded", True))
        self.granularity = opts.get("firewall_granularity", "chunk")
        self.block_all_urls = bool(opts.get("egress_block_all_urls", True))
        self.session_id = session_id or uuid.uuid4().hex[:12]

    # ---- 1-3 : ce qui ENTRE dans le contexte ---------------------------
    def check_chunk(self, chunk: dict) -> ChunkVerdict:
        source = str(chunk.get("fichier") or chunk.get("source") or "document")
        level = str(chunk.get("niveau") or chunk.get("classification") or "").lower()
        if level not in self.allowed_levels:
            reason = f"niveau '{level or 'non classe'}' interdit pour le role {self.role}"
            log_event(self.agent, source, "deny", reason, session_id=self.session_id)
            return ChunkVerdict(False, reason)
        if self.exclude_superseded and str(chunk.get("en_vigueur", "")).lower() == "non":
            reason = "version remplacee exclue par la politique"
            log_event(self.agent, source, "deny", reason, session_id=self.session_id)
            return ChunkVerdict(False, reason)

        text = str(chunk.get("texte") or chunk.get("text") or "")
        removed = 0
        if self.granularity == "line":
            kept_lines = []
            for line in text.split("\n"):
                if scan(line).safe:
                    kept_lines.append(line)
                else:
                    removed += 1
            if removed:
                log_event(self.agent, source, "firewall",
                          f"{removed} ligne(s) suspecte(s) retiree(s) de l'extrait",
                          session_id=self.session_id)
            text = "\n".join(kept_lines)
            # filet : une injection repartie sur plusieurs lignes
            text, result = neutralize(text)
            if not result.safe:
                log_event(self.agent, source, "firewall", result.reason,
                          session_id=self.session_id)
                return ChunkVerdict(False, result.reason, lines_removed=removed)
        else:
            text, result = neutralize(text)
            if not result.safe:
                log_event(self.agent, source, "firewall", result.reason,
                          session_id=self.session_id)
                return ChunkVerdict(False, result.reason)

        red = redact(text)
        log_event(self.agent, source, "allow", "extrait admis dans le contexte",
                  session_id=self.session_id, pii_redacted=red.total)
        return ChunkVerdict(True, "ok", red.text, red.total, removed)

    def filter(self, ranked: list) -> FilterReport:
        """ranked = [(chunk_dict, score)] tries par pertinence. Renvoie au plus
        max_chunks extraits admis, texte nettoye et redige."""
        rep = FilterReport()
        for chunk, score in ranked:
            if len(rep.kept) >= self.max_chunks:
                break
            v = self.check_chunk(chunk)
            rep.lines_removed += v.lines_removed
            if v.allowed:
                rep.kept.append(({**chunk, "texte": v.text}, score))
                rep.pii_redacted += v.pii_redacted
            elif v.reason.startswith("niveau"):
                rep.denied_access += 1
            elif v.reason.startswith("version"):
                rep.denied_version += 1
            else:
                rep.firewall_blocked += 1
        return rep

    # ---- 4-5 : ce qui SORT ------------------------------------------------
    def screen_answer(self, answer: str) -> EgressResult:
        result = screen(answer, block_all_urls=self.block_all_urls)
        if not result.clean:
            log_event(self.agent, "final_answer", "egress", result.summary,
                      session_id=self.session_id, pii_redacted=result.pii_redacted)
        return result

    def trace(self, question: str, answer: str, latency_ms: int = 0):
        log_event(self.agent, "rag_query", "trace",
                  f"Q: {question[:300]} || R: {answer[:600]}",
                  latency_ms=latency_ms, session_id=self.session_id)
