"""
Aegis — redaction PII (roadmap J5+).

But : masquer les donnees personnelles (emails, telephones, IBAN, cartes)
dans la SORTIE des outils avant qu'elle n'atteigne le contexte du LLM.
Meme si le modele est local, le principe de minimisation s'applique :
le LLM n'a pas besoin d'un numero de carte pour resumer un document,
et tout ce qui entre dans le contexte peut en ressortir.

v1 assumee : regex simples et lisibles. Limites documentees :
  - le motif "telephone" peut attraper d'autres suites de chiffres ;
  - pas de NER / detection de noms propres (piste v2, modele local leger).
"""

import re
from dataclasses import dataclass, field

# Ordre important : les motifs les plus specifiques d'abord (un IBAN ou
# une carte contient des chiffres qu'un motif "telephone" gober ait sinon).
PII_PATTERNS = [
    ("iban",  re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")),
    ("card",  re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # Telephone : indicatif +XX ou 0 initial, puis groupes de chiffres.
    # Plus strict que la v1, qui masquait aussi des references legales
    # (RS 955.033.0) et des dates (31.12.2025) — genant sur un corpus bancaire.
    ("phone", re.compile(
        r"(?<![\w/.'])(?!\d{1,2}\.\d{1,2}\.\d{2,4}\b)"
        r"(?:\+\d{1,3}[ .-]?|0)\d{1,3}(?:[ .-]?\d{2,4}){3,4}(?![\w/.'])")),
]


@dataclass
class RedactionResult:
    text: str
    counts: dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def summary(self) -> str:
        if not self.total:
            return "aucune PII"
        parts = [f"{n} {kind}" for kind, n in self.counts.items()]
        return f"{self.total} PII masquee(s): {', '.join(parts)}"


def redact(text: str) -> RedactionResult:
    """Remplace chaque PII par un marqueur [KIND_REDACTED]."""
    counts = {}
    for kind, pattern in PII_PATTERNS:
        text, n = pattern.subn(f"[{kind.upper()}_REDACTED]", text)
        if n:
            counts[kind] = n
    return RedactionResult(text=text, counts=counts)


if __name__ == "__main__":
    # Preuve autonome, aucun LLM requis : python -m aegis.gateway.redact
    sample = (
        "Contact: Sarah Lopez, sarah.lopez@acme.com, +33 6 12 34 56 78.\n"
        "Facturation: IBAN FR76 3000 6000 0112 3456 7890 189, "
        "carte 4970 1234 5678 9010.\n"
        "Note interne sans PII: livrer le dashboard vendredi."
    )
    r = redact(sample)
    print(r.text)
    print("->", r.summary)
