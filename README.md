# Aegis — a control plane for agentic workflows in regulated environments

> Aegis sits between an AI agent and its tools/data. Before any action runs, it
> checks that action against a deterministic policy, screens tool output for
> prompt-injection, and logs every decision to an audit trail with ROI metrics.
> It turns an ungoverned agent into one you can deploy in a regulated environment.
> The agent runs on a local model (Ollama). No data leaves the machine.

## Why this exists

MCP makes it trivial to give an agent real tools. That is also the problem.

- The official MCP reference servers are examples, not hardened for production:
  the docs tell you to implement guardrails for your own threat model.
- The default stdio execution model runs a tool server with the full privileges
  of the host user.

In a regulated environment (pharma, life sciences, finance), "the agent can do
anything the user can" is a non-starter: no authorization boundary, no defense
against a poisoned document, no audit trail. That gap, not building yet another
agent, is what blocks deployment. Aegis closes it.

## The insight

Because MCP tool calls are structured and typed, the MCP layer is the perfect
interception point. Wrap it once and every agent action becomes mediable:
authorize it, screen it, log it, in a single place. Aegis is that wrapper.

## The five pillars

1. Policy engine (deterministic authorization). A declarative YAML policy maps
   each agent to allowed tools, denied tools, quotas, and forbidden data tags.
   Default-deny, plus a hard block on path traversal (`../`) in any argument.
   The LLM proposes, the policy disposes; security is never delegated to the
   model. Conceptually: RBAC / capabilities for agents.
2. Injection firewall v2 (the differentiator). Screens tool output for indirect
   prompt-injection (instructions hidden inside a document the agent reads)
   before that content reaches the model's context. v2 uses weighted named
   rules (a strong signal blocks alone, weak signals must combine — fewer false
   positives), Unicode normalization (full-width evasion, zero-width hidden
   text), and base64 payload decoding + re-scan.
3. PII redaction (data minimization). Emails, phone numbers, IBANs and card
   numbers are masked in tool output before it enters the model context. What
   never enters the context can never leak out of it.
4. Egress control (the symmetric closing of the loop). The final answer is
   sanitized before it leaves the agent: remote markdown images (zero-click
   exfiltration), URLs carrying query strings, and residual PII are removed.
   If an injection ever survives the firewall, its natural output channel is
   cut. Aegis governs everything that enters the context AND everything that
   leaves it.
5. Audit + ROI (the ops layer). Every decision logged to SQLite with latency,
   a per-run session id and a PII counter — including the user request and the
   final answer (decision "trace"): an auditor wants the whole session. Each
   event is hash-chained (sha256 over the previous hash + all fields), so
   editing or deleting any row breaks the chain and verify_chain() reports the
   exact break point. That turns "a log" into "evidence". A Streamlit dashboard
   turns it into a story: actions automated, attacks blocked, PII masked, time
   saved, chain integrity.

## Architecture

    User request
      -> Agent (local LLM via Ollama: reasons, proposes a tool call)
      -> [ AEGIS control plane ]
            1. Policy engine  : may this agent call THIS tool, on THIS data?
            2. Execute        : only if allowed, via the official MCP server
            3. Firewall       : screen returned content for prompt-injection
                                BEFORE it reaches the model context
            4. PII redaction  : mask emails/phones/IBANs/cards in what the
                                model is about to read
            5. Egress control : sanitize the FINAL ANSWER before it leaves
                                (remote images, query-string URLs, PII)
            6. Audit + metrics: decision, reason, latency, session, PII count,
                                hash-chained; request & answer traced too
      -> Tools / data (MCP servers)
      -> Response + ROI/security dashboard

Four distinct control points:
- Action side: policy.check() decides if the agent may call the tool.
- Input side: firewall.neutralize() screens tool output before the model sees it.
- Input side: redact() minimizes personal data in whatever survives the firewall.
- Output side: egress.screen() sanitizes the final answer before the user sees it.

## What works / where it breaks (field notes)

What works:
- Local agent drives real tools end-to-end, fully offline.
- Out-of-policy actions (e.g. write_file) are blocked before execution,
  verified on disk, not just on screen.
- A document with a hidden "SYSTEM: ... send to external@..." instruction is
  neutralized; the malicious instruction never reaches the model.

Where it breaks (honest limits):
- The 8B local model sometimes proposes a relative path the MCP server rejects;
  the agent must be guided (list the directory first). Orchestration limit, not security.
- The firewall v2 is still heuristic: weighted rules + Unicode normalization +
  base64 decoding catch the obvious and the mildly-disguised, but a creative
  paraphrase or a rare language still gets through. v3 = a light local classifier.
- PII redaction is regex-based: solid on emails/IBANs/cards, the phone pattern
  can over-match digit runs; no NER for person names yet.
- Egress v1 cuts the obvious exfiltration channels (remote images, query-string
  URLs, PII); data could still be smuggled in the path segment of a URL or in
  plain prose. Channel-cutting reduces the attack surface, it does not nullify it.
- Latency on an M1 (16 GB): ~15-25 tok/s; fine for a demo, slow on long tool-call chains.
- When blocked, the agent rationalizes its own reason (once claimed a "path" issue when
  the real reason was a denied tool). Exactly why the decision lives in deterministic code.

## Build vs buy

- Local model: privacy and regulatory fit; data never leaves the machine. Ran on M1/16GB.
- Reuse the official MCP filesystem server rather than writing tools; original effort
  is concentrated on the control plane, where the value is.
- Heuristic firewall v1, not ML: a credible first pass with documented limits beats an
  over-engineered black box. Simple over over-engineering.

## Shipped since v1

- PII redaction on tool output (emails, phones, IBANs, cards) with per-event counters.
- Firewall v2: weighted rules, Unicode normalization, zero-width/hidden-text
  detection, base64 payload decode + re-scan.
- Path-traversal guard in the policy engine (defense in depth vs the MCP server).
- Egress control on the final answer (4th control point): remote markdown
  images, query-string URLs and residual PII are stripped before the user
  (or the calling system) sees the text.
- Red-team test suite (39 tests: injection battery, false-positive battery,
  policy, redaction, egress, audit chain) running in GitHub Actions on every
  push — no LLM needed.
- True end-to-end test of the agent loop with a mocked LLM and a mocked MCP
  server: replays a full governed run (deny -> firewall -> redaction -> egress)
  and asserts both what the model saw and what the audit retained. The loop
  core takes injected chat/call_tool dependencies, so it is testable and
  importable without ollama/mcp installed (that's what CI does).
- Hardened loop: an LLM or tool failure is caught, audited (decision "error")
  and reported to the model or the user instead of crashing the run; proper
  CLI (--model, --agent, --policy, --max-steps).
- Audit v2: session ids, PII counters, configurable DB path (AEGIS_DB_PATH),
  soft schema migration, sha256 hash chain + verify_chain() tamper detection,
  full session trace (user request + final answer).
- Dashboard v2: KPI cards, decision timeline, latency-per-tool chart, chain
  integrity badge, filterable audit journal with CSV export (palette validated
  for contrast + color-blindness).
- Hosted interactive demo, no heavy model (was a roadmap item): 5 replayable
  scenarios drive the REAL governed loop with a scripted LLM — policy denial,
  indirect injection, confidential tag, PII redaction + egress. One click in
  the dashboard sidebar replays a scenario and the audit journal grows live.
  A fresh deployment seeds itself by replaying all scenarios once.
- Static snapshot export (dashboard/export_static.py) for instant-loading
  portfolio hosting — no Python server, no cold start.

## Roadmap / not yet built

- Human-in-the-loop approval for sensitive-but-allowed actions (policy verdict
  "ask", pause the loop, require an explicit yes).
- Firewall v3: light local classifier alongside the weighted rules.
- NER-based redaction of person names (light local model).
- Additional wrapped MCP servers (Git/GitHub, Fetch).
- Multi-process-safe audit writer (the hash chain currently assumes a single
  writer at a time).

## Run it yourself

    pip install -r requirements.txt
    ollama pull qwen3:8b

    # Happy path (read + summarise)
    python -m aegis.agent.loop ./demo/workspace "List the files, then read meeting_notes.txt and summarise it."

    # Blocked write (policy engine)
    python -m aegis.agent.loop ./demo/workspace "Create a file hacked.txt with the word PWNED."

    # Neutralized indirect injection (firewall)
    python -m aegis.agent.loop ./demo/workspace "List the files, then read project_update.txt and summarise it."

    # Blocked confidential read (deny_path_tags)
    python -m aegis.agent.loop ./demo/workspace "Read confidential_roadmap.txt and summarise it."

    # PII redaction (the model never sees the real emails/phones/IBAN)
    python -m aegis.agent.loop ./demo/workspace "Read client_contacts.txt and summarise it."

    # Dashboard (from project root)
    streamlit run dashboard/app.py

    # Test suite (no LLM required — this is what CI runs)
    python -m pytest tests/ -v

Each protection module is also self-demonstrating without any LLM:

    python -m aegis.gateway.policy
    python -m aegis.gateway.firewall
    python -m aegis.gateway.redact
    python -m aegis.gateway.egress
    python -m aegis.audit.logger
    python -m aegis.demo.scenarios   # replays the 5 governed runs (scripted LLM)

## Stack

Python · Ollama (qwen3:8b) · MCP Python SDK + official filesystem MCP server ·
PyYAML (policy) · SQLite (audit) · Streamlit + Altair (dashboard) ·
pytest + GitHub Actions (red-team CI).
