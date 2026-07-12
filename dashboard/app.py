"""Aegis — dashboard ROI & securite (v2)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3

import altair as alt
import pandas as pd
import streamlit as st

from aegis.audit.logger import get_metrics, verify_chain, count_events, DB_PATH
from aegis.demo.scenarios import SCENARIOS, replay, replay_all, seed_if_empty

st.set_page_config(page_title="Aegis — Control Plane", page_icon="🛡️", layout="wide")

# Deploiement neuf (Streamlit Cloud) : la base est vide -> on la peuple en
# rejouant les scenarios une fois, pour que la demo raconte quelque chose.
if seed_if_empty():
    st.toast("Base vide : les 5 scénarios ont été rejoués pour peupler la démo.")

# Couleurs de decision (statut) — palette validee sur surface #0B1220
# (bande de luminosite OKLCH, separation CVD, contraste >= 3:1).
C_ALLOW, C_DENY, C_FIREWALL, C_EGRESS, C_ACCENT = (
    "#0D9488", "#D97706", "#EF4444", "#8B5CF6", "#3B82F6")
DECISIONS = ["allow", "deny", "firewall", "egress"]
DECISION_SCALE = alt.Scale(domain=DECISIONS,
                           range=[C_ALLOW, C_DENY, C_FIREWALL, C_EGRESS])
DECISION_LABEL = {"allow": "Autorisé", "deny": "Bloqué (policy)",
                  "firewall": "Injection neutralisée",
                  "egress": "Sortie assainie", "error": "Erreur",
                  "trace": "Trace de session"}

st.markdown("""
<style>
.block-container { padding-top: 2.2rem; max-width: 1240px; }

.aegis-hero { margin-bottom: 1.4rem; }
.aegis-hero h1 { font-size: 2.3rem; font-weight: 750; margin: 0; letter-spacing: -.02em;
  background: linear-gradient(90deg, #2DD4BF, #60A5FA);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.aegis-hero .sub { color: #94A3B8; font-size: .97rem; margin-top: .35rem; }
.aegis-chips { display: flex; gap: .5rem; flex-wrap: wrap; margin-top: .8rem; }
.aegis-chip { font-size: .78rem; color: #CBD5E1; background: #16203A;
  border: 1px solid #243350; border-radius: 999px;
  padding: .25rem .75rem; }
.aegis-chip b { color: #E2E8F0; font-weight: 600; }

.aegis-card { background: linear-gradient(180deg, #16203A, #121A30);
  border: 1px solid #1E2A47; border-top: 3px solid var(--accent);
  border-radius: 14px; padding: 1.05rem 1.25rem; height: 100%; }
.aegis-card .lbl { color: #94A3B8; font-size: .78rem; text-transform: uppercase;
  letter-spacing: .06em; margin-bottom: .25rem; }
.aegis-card .val { font-size: 2.15rem; font-weight: 750; color: #F1F5F9;
  line-height: 1.15; font-variant-numeric: tabular-nums; }
.aegis-card .hint { color: #64748B; font-size: .78rem; margin-top: .3rem; }

.sec-card { background: #131C33; border: 1px solid #243350;
  border-left: 4px solid var(--c); border-radius: 10px;
  padding: .75rem 1rem; margin-bottom: .6rem; }
.sec-card .tag { font-weight: 700; font-size: .8rem; color: var(--c);
  letter-spacing: .03em; }
.sec-card .when { color: #64748B; font-size: .78rem; float: right; }
.sec-card code { background: #0B1220; padding: .1rem .45rem; border-radius: 5px;
  color: #E2E8F0; }
.sec-card .why { color: #CBD5E1; font-size: .88rem; margin-top: .25rem; }

.pillar { background: #131C33; border: 1px solid #243350; border-radius: 12px;
  padding: 1rem 1.2rem; height: 100%; }
.pillar h4 { margin: 0 0 .4rem; color: #F1F5F9; font-size: 1rem; }
.pillar p { color: #94A3B8; font-size: .86rem; margin: 0; line-height: 1.5; }
</style>
""", unsafe_allow_html=True)

# ---------- sidebar : rejouer la boucle gouvernee, sans LLM ----------

with st.sidebar:
    st.markdown("## 🛡️ Aegis")
    st.caption("Le LLM propose, la politique dispose.")
    st.divider()
    st.markdown("### 🎬 Rejouer un scénario")
    st.caption("Chaque scénario rejoue la **vraie boucle gouvernée** "
               "(policy → firewall → redaction → egress → audit scellé) "
               "avec un LLM simulé — aucun modèle requis. Les événements "
               "s'ajoutent en direct au journal.")
    choice = st.selectbox(
        "Scénario", options=list(SCENARIOS),
        format_func=lambda k: SCENARIOS[k]["label"], label_visibility="collapsed")
    st.caption(SCENARIOS[choice]["description"])
    if st.button("▶ Rejouer ce scénario", use_container_width=True, type="primary"):
        with st.spinner("Run de l'agent en cours…"):
            answer = replay(choice)
        st.session_state["last_answer"] = answer
        st.rerun()
    if st.button("Rejouer les 5 scénarios", use_container_width=True):
        with st.spinner("5 runs en cours…"):
            replay_all()
        st.rerun()
    if "last_answer" in st.session_state:
        st.success(f'Réponse rendue : « {st.session_state["last_answer"]} »')
    st.divider()
    st.markdown(
        "[Code source](https://github.com/nasserzenati/aegis) · "
        "[Documentation](https://nasserzenati.github.io/portfolio/aegis/docs/)")
    st.caption("En local, l'agent tourne sur un vrai LLM : "
               "`python -m aegis.agent.loop`")

# ---------- donnees ----------

m = get_metrics()
chain = verify_chain()

with sqlite3.connect(DB_PATH) as conn:
    df = pd.read_sql_query(
        "SELECT ts, agent, tool, decision, reason, latency_ms, "
        "session_id, pii_redacted FROM events ORDER BY id DESC", conn)
if not df.empty:
    df["ts"] = pd.to_datetime(df["ts"], format="ISO8601", utc=True)

# Les traces de session (requete/reponse) vivent dans le journal,
# pas dans les graphiques de decisions.
df_decisions = df[df["decision"].isin(DECISIONS)] if not df.empty else df

if chain["ok"]:
    chain_chip = (f'<span class="aegis-chip" style="border-color:#134E4A">'
                  f'🔗 chaîne d\'audit <b>intègre</b> '
                  f'({chain["checked"]} événements scellés)</span>')
else:
    chain_chip = (f'<span class="aegis-chip" style="border-color:#7F1D1D">'
                  f'⚠️ chaîne d\'audit <b>ALTÉRÉE</b> '
                  f'(première rupture : id {chain["first_bad_id"]})</span>')

# ---------- hero ----------

st.markdown(f"""
<div class="aegis-hero">
  <h1>🛡️ Aegis — agentic control plane</h1>
  <div class="sub">Le LLM propose, la politique dispose. Policy engine ·
  firewall anti-injection · redaction PII · contrôle de sortie · audit trail
  scellé — modèle local (Ollama), les données ne quittent jamais la machine.</div>
  <div class="aegis-chips">
    <span class="aegis-chip"><b>{m["sessions"]}</b> sessions d'agent</span>
    <span class="aegis-chip"><b>{len(df)}</b> décisions auditées</span>
    <span class="aegis-chip">latence outil moyenne <b>{m["avg_latency_ms"]} ms</b></span>
    {chain_chip}
  </div>
</div>
""", unsafe_allow_html=True)

# ---------- KPI ----------

def card(col, label, value, accent, hint=""):
    col.markdown(
        f'<div class="aegis-card" style="--accent:{accent}">'
        f'<div class="lbl">{label}</div><div class="val">{value}</div>'
        f'<div class="hint">{hint}</div></div>',
        unsafe_allow_html=True)

c1, c2, c3, c4, c5, c6 = st.columns(6)
card(c1, "Actions autorisées", m["actions_allowed"], C_ALLOW,
     "conformes à la politique")
card(c2, "Bloquées (policy)", m["actions_denied"], C_DENY,
     "avant toute exécution")
card(c3, "Injections neutralisées", m["injections_blocked"], C_FIREWALL,
     "jamais vues par le modèle")
card(c4, "Sorties assainies", m["egress_sanitized"], C_EGRESS,
     "exfiltration coupée en sortie")
card(c5, "PII masquées", m["pii_redacted"], C_ACCENT,
     "emails, téléphones, IBAN…")
card(c6, "Temps gagné", f'{m["minutes_saved"]} min', "#64748B",
     "à ~90 s / action automatisée")

st.write("")

if df.empty:
    st.info("Aucune donnée pour l'instant — lance l'agent pour générer des "
            "événements :  `python -m aegis.agent.loop ./demo/workspace`")
    st.stop()

# ---------- onglets ----------

tab_overview, tab_security, tab_journal = st.tabs(
    ["Vue d'ensemble", "Sécurité", "Journal d'audit"])

axis_style = dict(labelColor="#94A3B8", titleColor="#94A3B8",
                  gridColor="#1E2A47", domainColor="#334155", tickColor="#334155")


def themed(chart):
    return (chart
            .configure_view(strokeWidth=0)
            .configure_axis(**axis_style)
            .configure_legend(labelColor="#CBD5E1", titleColor="#94A3B8"))


with tab_overview:
    left, right = st.columns([1, 1.35])

    with left:
        st.subheader("Répartition des décisions")
        vc = df_decisions["decision"].value_counts()
        chart_df = pd.DataFrame({"decision": vc.index, "count": vc.values})
        bars = (alt.Chart(chart_df)
                .mark_bar(cornerRadiusEnd=4, size=52)
                .encode(
                    x=alt.X("decision:N", title=None, sort=DECISIONS,
                            axis=alt.Axis(labelAngle=0, labelFontSize=13)),
                    y=alt.Y("count:Q", title=None,
                            axis=alt.Axis(tickMinStep=1, format="d")),
                    color=alt.Color("decision:N", scale=DECISION_SCALE, legend=None),
                    tooltip=[alt.Tooltip("decision:N", title="décision"),
                             alt.Tooltip("count:Q", title="événements")]))
        labels = (alt.Chart(chart_df)
                  .mark_text(dy=-8, color="#E2E8F0", fontSize=13, fontWeight=600)
                  .encode(x=alt.X("decision:N", sort=DECISIONS),
                          y="count:Q", text="count:Q"))
        st.altair_chart(themed((bars + labels).properties(height=320)),
                        use_container_width=True)

    with right:
        st.subheader("Chronologie des décisions")
        st.caption("Chaque point est une décision d'Aegis ; survole pour le détail.")
        timeline = (alt.Chart(df_decisions)
                    .mark_circle(size=130, opacity=0.9, stroke="#0B1220", strokeWidth=1)
                    .encode(
                        x=alt.X("ts:T", title=None,
                                axis=alt.Axis(format="%d %b %H:%M", labelFontSize=11)),
                        y=alt.Y("decision:N", title=None,
                                sort=DECISIONS,
                                axis=alt.Axis(labelFontSize=12)),
                        color=alt.Color("decision:N", scale=DECISION_SCALE, legend=None),
                        tooltip=[
                            alt.Tooltip("ts:T", title="quand", format="%d %b %H:%M:%S"),
                            alt.Tooltip("tool:N", title="outil"),
                            alt.Tooltip("decision:N", title="décision"),
                            alt.Tooltip("reason:N", title="raison"),
                            alt.Tooltip("latency_ms:Q", title="latence (ms)")]))
        st.altair_chart(themed(timeline.properties(height=320)),
                        use_container_width=True)

    st.subheader("Latence par outil (actions autorisées)")
    lat = (df[(df["decision"] == "allow") & (df["latency_ms"] > 0)]
           .groupby("tool", as_index=False)["latency_ms"].mean()
           .sort_values("latency_ms", ascending=False))
    if lat.empty:
        st.caption("Pas encore d'action autorisée avec une latence mesurée.")
    else:
        lat_chart = (alt.Chart(lat)
                     .mark_bar(cornerRadiusEnd=4, size=18, color=C_ACCENT)
                     .encode(
                         x=alt.X("latency_ms:Q", title="latence moyenne (ms)"),
                         y=alt.Y("tool:N", title=None, sort="-x",
                                 axis=alt.Axis(labelFontSize=12, labelLimit=220)),
                         tooltip=[alt.Tooltip("tool:N", title="outil"),
                                  alt.Tooltip("latency_ms:Q", title="ms", format=".0f")]))
        st.altair_chart(themed(lat_chart.properties(
            height=max(140, 52 * len(lat)))), use_container_width=True)

with tab_security:
    st.subheader("Événements de sécurité")
    st.caption("Tout ce qu'Aegis a intercepté — chaque blocage est motivé "
               "par une règle déterministe, pas par le modèle.")
    sec_colors = {"deny": C_DENY, "firewall": C_FIREWALL,
                  "egress": C_EGRESS, "error": "#64748B"}
    sec = df[df["decision"].isin(sec_colors)]
    if sec.empty:
        st.success("Aucun événement de sécurité sur la période.")
    else:
        for _, r in sec.iterrows():
            c = sec_colors[r["decision"]]
            when = r["ts"].strftime("%d %b %H:%M:%S")
            st.markdown(
                f'<div class="sec-card" style="--c:{c}">'
                f'<span class="when">{when}</span>'
                f'<span class="tag">{DECISION_LABEL[r["decision"]].upper()}</span> · '
                f'<code>{r["tool"]}</code>'
                f'<div class="why">{r["reason"]}</div></div>',
                unsafe_allow_html=True)

    st.write("")
    st.subheader("Les quatre points de contrôle")
    p1, p2, p3, p4 = st.columns(4)
    p1.markdown("""<div class="pillar"><h4>1 · Policy engine</h4>
      <p>Avant exécution : l'agent a-t-il le droit d'appeler CET outil sur CES
      données ? Allowlist, denylist, quotas, tags interdits, anti-traversal —
      default-deny, 100 % déterministe.</p></div>""", unsafe_allow_html=True)
    p2.markdown("""<div class="pillar"><h4>2 · Firewall anti-injection</h4>
      <p>Après exécution : la sortie de l'outil est scannée (règles pondérées,
      normalisation Unicode, payloads base64) avant d'atteindre le contexte du
      modèle. Une injection indirecte est neutralisée à la source.</p></div>""",
      unsafe_allow_html=True)
    p3.markdown("""<div class="pillar"><h4>3 · Redaction PII</h4>
      <p>Emails, téléphones, IBAN et cartes sont masqués dans le contenu que
      lit le modèle. Minimisation des données : ce qui n'entre pas dans le
      contexte ne peut pas fuiter.</p></div>""", unsafe_allow_html=True)
    p4.markdown("""<div class="pillar"><h4>4 · Contrôle de sortie</h4>
      <p>La réponse finale est assainie avant de quitter l'agent : images
      distantes (exfiltration zéro-clic), URLs à query string et PII sont
      supprimées. Si une injection survit, son canal de sortie est coupé.</p>
      </div>""", unsafe_allow_html=True)

with tab_journal:
    st.subheader("Journal d'audit")
    st.caption("En environnement régulé, cette trace n'est pas un bonus : "
               "c'est une obligation.")

    f1, f2, f3 = st.columns([1, 1, 1])
    sel_decisions = f1.multiselect(
        "Décision", options=sorted(df["decision"].unique()),
        default=sorted(df["decision"].unique()))
    sel_tools = f2.multiselect(
        "Outil", options=sorted(df["tool"].unique()),
        default=sorted(df["tool"].unique()))
    sessions = sorted(df["session_id"].dropna().unique())
    sel_sessions = f3.multiselect("Session", options=sessions, default=sessions)

    view = df[df["decision"].isin(sel_decisions) & df["tool"].isin(sel_tools)]
    if sessions:
        view = view[view["session_id"].isin(sel_sessions) | view["session_id"].isna()]

    st.dataframe(
        view, use_container_width=True, hide_index=True,
        column_config={
            "ts": st.column_config.DatetimeColumn("horodatage (UTC)",
                                                  format="DD MMM YYYY, HH:mm:ss"),
            "agent": "agent",
            "tool": "outil",
            "decision": "décision",
            "reason": "raison",
            "latency_ms": st.column_config.NumberColumn("latence (ms)"),
            "session_id": "session",
            "pii_redacted": st.column_config.NumberColumn("PII masquées"),
        })
    st.download_button(
        "⬇️ Exporter le journal (CSV)",
        view.to_csv(index=False).encode("utf-8"),
        file_name="aegis_audit_log.csv", mime="text/csv")

    with st.expander("🔗 Intégrité de la chaîne de hash"):
        st.markdown(
            "Chaque événement embarque `sha256(hash précédent + tous les "
            "champs)`. Modifier ou supprimer une ligne — même directement en "
            "SQL — casse la chaîne à partir de ce point. C'est la différence "
            "entre *un log* et *une preuve*.")
        if chain["ok"]:
            st.success(f"Chaîne intègre — {chain['checked']} événements "
                       "scellés vérifiés.")
        else:
            st.error(f"Chaîne ALTÉRÉE — première rupture à l'événement "
                     f"id {chain['first_bad_id']}.")
