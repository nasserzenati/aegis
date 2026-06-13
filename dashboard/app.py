"""Aegis — dashboard ROI & securite (J4, version soignee)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
import pandas as pd
import altair as alt
import streamlit as st

from aegis.audit.logger import get_metrics, DB_PATH

st.set_page_config(page_title="Aegis — Control Plane", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container { padding-top: 2.5rem; max-width: 1200px; }
.aegis-header { display:flex; align-items:center; gap:.7rem; }
.aegis-header h1 { font-size:2.2rem; font-weight:700; margin:0;
  background:linear-gradient(90deg,#2DD4BF,#60A5FA);
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.aegis-sub { color:#94A3B8; font-size:.95rem; margin:.2rem 0 1.6rem; }
.aegis-card { background:#16203A; border-radius:12px; padding:1.1rem 1.3rem;
  border-left:4px solid var(--accent); height:100%; }
.aegis-card .lbl { color:#94A3B8; font-size:.82rem; text-transform:uppercase;
  letter-spacing:.04em; }
.aegis-card .val { font-size:2.1rem; font-weight:700; color:#F1F5F9; line-height:1.2; }
.sec-card { background:#1B2236; border:1px solid #334155; border-left:4px solid var(--c);
  border-radius:10px; padding:.7rem 1rem; margin-bottom:.6rem; }
.sec-card .tag { font-weight:700; color:var(--c); }
.sec-card code { background:#0B1220; padding:.1rem .4rem; border-radius:5px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="aegis-header"><span style="font-size:2.2rem">🛡️</span>
<h1>Aegis — agentic control plane</h1></div>
<div class="aegis-sub">Policy enforcement · injection firewall · audit trail · ROI &nbsp;|&nbsp;
local model (Ollama) — données jamais hors machine</div>
""", unsafe_allow_html=True)

m = get_metrics()

def card(col, label, value, accent):
    col.markdown(
        f'<div class="aegis-card" style="--accent:{accent}">'
        f'<div class="lbl">{label}</div><div class="val">{value}</div></div>',
        unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
card(c1, "Actions autorisées", m["actions_allowed"], "#2DD4BF")
card(c2, "Bloquées (policy)",   m["actions_denied"],  "#F59E0B")
card(c3, "Injections neutralisées", m["injections_blocked"], "#EF4444")
card(c4, "Temps gagné (min)",   m["minutes_saved"],   "#60A5FA")

st.write("")
st.divider()

with sqlite3.connect(DB_PATH) as conn:
    df = pd.read_sql_query(
        "SELECT ts, agent, tool, decision, reason, latency_ms "
        "FROM events ORDER BY id DESC", conn)

left, right = st.columns([1.1, 1])

with left:
    st.subheader("Répartition des décisions")
    if df.empty:
        st.info("Aucune donnée — lance l'agent pour générer des événements.")
    else:
        vc = df["decision"].value_counts()
        chart_df = pd.DataFrame({"decision": vc.index, "count": vc.values})
        scale = alt.Scale(domain=["allow", "deny", "firewall"],
                          range=["#2DD4BF", "#F59E0B", "#EF4444"])
        chart = (alt.Chart(chart_df).mark_bar(cornerRadiusEnd=6, size=70)
                 .encode(x=alt.X("decision:N", title=None,
                                 axis=alt.Axis(labelAngle=0, labelFontSize=13)),
                         y=alt.Y("count:Q", title=None),
                         color=alt.Color("decision:N", scale=scale, legend=None),
                         tooltip=["decision", "count"])
                 .properties(height=300))
        st.altair_chart(chart, use_container_width=True)

with right:
    st.subheader("Événements de sécurité")
    sec = df[df["decision"].isin(["deny", "firewall"])]
    if sec.empty:
        st.success("Aucun événement de sécurité.")
    else:
        for _, r in sec.iterrows():
            c = "#EF4444" if r["decision"] == "firewall" else "#F59E0B"
            st.markdown(
                f'<div class="sec-card" style="--c:{c}">'
                f'<span class="tag">{r["decision"].upper()}</span> · '
                f'<code>{r["tool"]}</code><br>'
                f'<span style="color:#CBD5E1;font-size:.9rem">{r["reason"]}</span></div>',
                unsafe_allow_html=True)

st.divider()
st.subheader("Journal d'audit")
st.caption("En environnement régulé, cette trace n'est pas un bonus : c'est une obligation.")
st.dataframe(df, use_container_width=True, hide_index=True)
