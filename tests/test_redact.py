"""Tests de la redaction PII — deterministe, aucun LLM requis."""

from aegis.gateway.redact import redact


def test_email_is_redacted():
    r = redact("Contact: sarah.lopez@acme.com pour le suivi.")
    assert "sarah.lopez@acme.com" not in r.text
    assert "[EMAIL_REDACTED]" in r.text
    assert r.counts == {"email": 1}


def test_phone_is_redacted():
    r = redact("Appeler le +33 6 12 34 56 78 avant midi.")
    assert "[PHONE_REDACTED]" in r.text
    assert r.counts.get("phone") == 1


def test_iban_and_card_are_redacted():
    r = redact("IBAN FR76 3000 6000 0112 3456 7890 189, "
               "carte 4970 1234 5678 9010.")
    assert "[IBAN_REDACTED]" in r.text
    assert "[CARD_REDACTED]" in r.text
    # L'IBAN doit etre absorbe en entier (pas de reliquat de chiffres).
    assert "189" not in r.text


def test_clean_text_is_untouched():
    original = "Livrer le dashboard vendredi, relire la politique."
    r = redact(original)
    assert r.text == original
    assert r.total == 0
    assert r.summary == "aucune PII"


def test_multiple_pii_are_counted():
    r = redact("a@b.com et c@d.org, tel 06 12 34 56 78.")
    assert r.counts["email"] == 2
    assert r.total == 3


def test_dates_and_versions_are_not_redacted():
    # Garde-fous contre les faux positifs numeriques evidents.
    r = redact("Version 1.2.3 publiee le 12/07/2026, build 20260712.")
    assert r.total == 0, r.summary
