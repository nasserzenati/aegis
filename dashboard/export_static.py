"""
Aegis — export statique du dashboard.

Pourquoi : Streamlit Community Cloud endort les apps gratuites ; le reveil
prend 2-3 minutes — inacceptable pour un portfolio. Ce script fige le
dashboard en UN fichier HTML autonome (CSS inline, graphiques en SVG generes
en Python, zero JS externe, zero serveur) qui s'ouvre instantanement partout :
GitHub Pages, Netlify, ou directement dans l'hebergement du portfolio.

Usage :
    python dashboard/export_static.py            # -> docs/demo/index.html
    python dashboard/export_static.py sortie.html
"""

import html
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.audit.logger import get_metrics, verify_chain, DB_PATH

# Palette validee (contraste >= 3:1 sur #0B1220, separation CVD).
COLORS = {"allow": "#0D9488", "deny": "#D97706",
          "firewall": "#EF4444", "egress": "#8B5CF6"}
LABELS = {"allow": "Autorisé", "deny": "Bloqué (policy)",
          "firewall": "Injection neutralisée", "egress": "Sortie assainie",
          "error": "Erreur", "trace": "Trace de session"}
DECISIONS = ["allow", "deny", "firewall", "egress"]


def load_events():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(
            "SELECT ts, agent, tool, decision, reason, latency_ms, "
            "session_id, pii_redacted FROM events ORDER BY id DESC")]


def bar_chart_svg(counts: dict) -> str:
    """Barres verticales des decisions, labels directs, sans lib externe."""
    keys = [k for k in DECISIONS if counts.get(k)]
    if not keys:
        return ""
    w, h, pad_b, pad_t = 560, 300, 34, 26
    bw, gap = 64, 40
    total_w = len(keys) * bw + (len(keys) - 1) * gap
    x0 = (w - total_w) / 2
    vmax = max(counts[k] for k in keys)
    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" '
             f'aria-label="Répartition des décisions">']
    for i, k in enumerate(keys):
        v = counts[k]
        bh = (h - pad_b - pad_t) * v / vmax
        x = x0 + i * (bw + gap)
        y = h - pad_b - bh
        parts.append(
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{bw}" height="{bh:.0f}" '
            f'rx="4" fill="{COLORS[k]}"/>'
            f'<text x="{x + bw/2:.0f}" y="{y - 8:.0f}" text-anchor="middle" '
            f'fill="#E2E8F0" font-size="15" font-weight="600">{v}</text>'
            f'<text x="{x + bw/2:.0f}" y="{h - 12}" text-anchor="middle" '
            f'fill="#94A3B8" font-size="13">{k}</text>')
    parts.append("</svg>")
    return "".join(parts)


def timeline_svg(events: list) -> str:
    """Un point par decision, positionne dans le temps, par ligne de decision."""
    evs = [e for e in events if e["decision"] in DECISIONS]
    if not evs:
        return ""
    times = [datetime.fromisoformat(e["ts"]) for e in evs]
    t0, t1 = min(times), max(times)
    span = (t1 - t0).total_seconds() or 1
    w, h, pad_l, pad_r = 620, 300, 76, 24
    rows = {k: 52 + i * 62 for i, k in enumerate(DECISIONS)}
    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" '
             f'aria-label="Chronologie des décisions">']
    for k, y in rows.items():
        parts.append(
            f'<line x1="{pad_l}" y1="{y}" x2="{w - pad_r}" y2="{y}" '
            f'stroke="#1E2A47" stroke-width="1"/>'
            f'<text x="{pad_l - 10}" y="{y + 4}" text-anchor="end" '
            f'fill="#94A3B8" font-size="12">{k}</text>')
    for e, t in zip(evs, times):
        x = pad_l + (w - pad_l - pad_r) * (t - t0).total_seconds() / span
        y = rows[e["decision"]]
        title = html.escape(f'{e["tool"]} — {e["reason"]}')
        parts.append(
            f'<circle cx="{x:.0f}" cy="{y}" r="7" fill="{COLORS[e["decision"]]}" '
            f'stroke="#0B1220" stroke-width="1.5"><title>{title}</title></circle>')
    parts.append(
        f'<text x="{pad_l}" y="{h - 10}" fill="#64748B" font-size="11">'
        f'{t0.strftime("%d %b %H:%M")}</text>'
        f'<text x="{w - pad_r}" y="{h - 10}" text-anchor="end" fill="#64748B" '
        f'font-size="11">{t1.strftime("%d %b %H:%M")}</text></svg>')
    return "".join(parts)


def sec_feed_html(events: list) -> str:
    sec = [e for e in events if e["decision"] in
           ("deny", "firewall", "egress", "error")]
    if not sec:
        return '<p class="ok">Aucun événement de sécurité.</p>'
    cards = []
    for e in sec:
        c = COLORS.get(e["decision"], "#64748B")
        when = datetime.fromisoformat(e["ts"]).strftime("%d %b %H:%M:%S")
        cards.append(
            f'<div class="sec-card" style="--c:{c}">'
            f'<span class="when">{when}</span>'
            f'<span class="tag">{LABELS[e["decision"]].upper()}</span> · '
            f'<code>{html.escape(e["tool"])}</code>'
            f'<div class="why">{html.escape(e["reason"])}</div></div>')
    return "".join(cards)


def journal_html(events: list) -> str:
    rows = []
    for e in events:
        when = datetime.fromisoformat(e["ts"]).strftime("%d %b %Y %H:%M:%S")
        badge = (f'<span class="badge" style="--c:{COLORS.get(e["decision"], "#64748B")}">'
                 f'{e["decision"]}</span>')
        rows.append(
            f'<tr><td>{when}</td><td><code>{html.escape(e["tool"])}</code></td>'
            f'<td>{badge}</td><td class="reason">{html.escape(e["reason"])}</td>'
            f'<td>{e["latency_ms"] or ""}</td>'
            f'<td>{e["session_id"] or ""}</td>'
            f'<td>{e["pii_redacted"] or ""}</td></tr>')
    return ("<table><thead><tr><th>horodatage (UTC)</th><th>outil</th>"
            "<th>décision</th><th>raison</th><th>ms</th><th>session</th>"
            "<th>PII</th></tr></thead><tbody>" + "".join(rows)
            + "</tbody></table>")


def render() -> str:
    m = get_metrics()
    chain = verify_chain()
    events = load_events()
    counts = {}
    for e in events:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1

    if chain["ok"]:
        chain_chip = (f'<span class="chip">🔗 chaîne d\'audit <b>intègre</b> '
                      f'({chain["checked"]} événements scellés)</span>')
    else:
        chain_chip = (f'<span class="chip" style="border-color:#7F1D1D">'
                      f'⚠️ chaîne <b>ALTÉRÉE</b> (id {chain["first_bad_id"]})</span>')

    kpis = [
        ("Actions autorisées", m["actions_allowed"], COLORS["allow"],
         "conformes à la politique"),
        ("Bloquées (policy)", m["actions_denied"], COLORS["deny"],
         "avant toute exécution"),
        ("Injections neutralisées", m["injections_blocked"], COLORS["firewall"],
         "jamais vues par le modèle"),
        ("Sorties assainies", m["egress_sanitized"], COLORS["egress"],
         "exfiltration coupée en sortie"),
        ("PII masquées", m["pii_redacted"], "#3B82F6",
         "emails, téléphones, IBAN…"),
        ("Temps gagné", f'{m["minutes_saved"]} min', "#64748B",
         "à ~90 s / action automatisée"),
    ]
    kpi_html = "".join(
        f'<div class="card" style="--accent:{c}"><div class="lbl">{lbl}</div>'
        f'<div class="val">{val}</div><div class="hint">{hint}</div></div>'
        for lbl, val, c, hint in kpis)

    stamp = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis — Control Plane (démo)</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0B1220; color: #CBD5E1;
    font: 15px/1.6 Inter, -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif; }}
  .wrap {{ max-width: 1240px; margin: 0 auto; padding: 2.5rem 1.4rem 4rem; }}
  h1 {{ font-size: 2.2rem; font-weight: 750; letter-spacing: -.02em;
    background: linear-gradient(90deg, #2DD4BF, #60A5FA);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .sub {{ color: #94A3B8; margin-top: .4rem; max-width: 62rem; }}
  .chips {{ display: flex; gap: .5rem; flex-wrap: wrap; margin: .9rem 0 1.6rem; }}
  .chip {{ font-size: .78rem; background: #16203A; border: 1px solid #243350;
    border-radius: 999px; padding: .25rem .75rem; }}
  .chip b {{ color: #E2E8F0; }}
  .kpis {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: .8rem; }}
  .card {{ background: linear-gradient(180deg, #16203A, #121A30);
    border: 1px solid #1E2A47; border-top: 3px solid var(--accent);
    border-radius: 14px; padding: 1rem 1.1rem; }}
  .card .lbl {{ color: #94A3B8; font-size: .72rem; text-transform: uppercase;
    letter-spacing: .06em; margin-bottom: .25rem; }}
  .card .val {{ font-size: 1.9rem; font-weight: 750; color: #F1F5F9;
    font-variant-numeric: tabular-nums; }}
  .card .hint {{ color: #64748B; font-size: .74rem; margin-top: .25rem; }}
  h2 {{ color: #F1F5F9; font-size: 1.25rem; margin: 2.4rem 0 1rem; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1.2fr; gap: 1.4rem; }}
  .panel {{ background: #0E1628; border: 1px solid #1E2A47; border-radius: 14px;
    padding: 1.2rem; }}
  svg {{ width: 100%; height: auto; display: block; }}
  .sec-card {{ background: #131C33; border: 1px solid #243350;
    border-left: 4px solid var(--c); border-radius: 10px;
    padding: .7rem 1rem; margin-bottom: .6rem; }}
  .sec-card .tag {{ font-weight: 700; font-size: .78rem; color: var(--c); }}
  .sec-card .when {{ color: #64748B; font-size: .76rem; float: right; }}
  .sec-card .why {{ color: #CBD5E1; font-size: .85rem; margin-top: .2rem; }}
  code {{ font-family: ui-monospace, Menlo, monospace; background: #0B1220;
    border: 1px solid #243350; padding: .06rem .4rem; border-radius: 5px;
    font-size: .82em; color: #E2E8F0; }}
  .tablewrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .82rem; }}
  th, td {{ text-align: left; padding: .5rem .65rem;
    border-bottom: 1px solid #1E2A47; vertical-align: top; }}
  th {{ color: #94A3B8; font-weight: 600; font-size: .72rem;
    text-transform: uppercase; letter-spacing: .05em; }}
  td.reason {{ color: #94A3B8; max-width: 34rem; }}
  .badge {{ color: var(--c); font-weight: 700; }}
  .ok {{ color: #2DD4BF; }}
  .footer {{ margin-top: 2.5rem; color: #64748B; font-size: .8rem; }}
  @media (max-width: 980px) {{ .kpis {{ grid-template-columns: repeat(3, 1fr); }}
    .grid2 {{ grid-template-columns: 1fr; }} }}
  @media (max-width: 560px) {{ .kpis {{ grid-template-columns: repeat(2, 1fr); }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ Aegis — agentic control plane</h1>
  <p class="sub">Le LLM propose, la politique dispose. Policy engine ·
  firewall anti-injection · redaction PII · contrôle de sortie · audit trail
  scellé — modèle local (Ollama), les données ne quittent jamais la machine.</p>
  <div class="chips">
    <span class="chip"><b>{m["sessions"]}</b> sessions d'agent</span>
    <span class="chip"><b>{len(events)}</b> décisions auditées</span>
    <span class="chip">latence outil moyenne <b>{m["avg_latency_ms"]} ms</b></span>
    {chain_chip}
  </div>

  <div class="kpis">{kpi_html}</div>

  <div class="grid2">
    <div>
      <h2>Répartition des décisions</h2>
      <div class="panel">{bar_chart_svg(counts)}</div>
    </div>
    <div>
      <h2>Chronologie des décisions</h2>
      <div class="panel">{timeline_svg(events)}</div>
    </div>
  </div>

  <h2>Événements de sécurité</h2>
  {sec_feed_html(events)}

  <h2>Journal d'audit</h2>
  <p class="sub" style="margin-bottom:.8rem">En environnement régulé, cette
  trace n'est pas un bonus : c'est une obligation. Chaque ligne est scellée
  par chaînage de hash.</p>
  <div class="panel tablewrap">{journal_html(events)}</div>

  <div class="footer">Snapshot statique du dashboard Aegis, généré le {stamp}
  depuis <code>audit.db</code> — données de démonstration.
  Version interactive : <code>streamlit run dashboard/app.py</code>.</div>
</div>
</body>
</html>
"""


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/demo/index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(), encoding="utf-8")
    print(f"Export statique -> {out} ({out.stat().st_size / 1024:.0f} Ko)")
