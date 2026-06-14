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

## The three pillars

1. Policy engine (deterministic authorization). A declarative YAML policy maps
   each agent to allowed tools, denied tools, quotas, and forbidden data tags.
   Default-deny. The LLM proposes, the policy disposes; security is never
   delegated to the model. Conceptually: RBAC / capabilities for agents.
2. Injection firewall (the differentiator). Screens tool output for indirect
   prompt-injection (instructions hidden inside a document the agent reads)
   before that content reaches the model's context. The trap most people miss.
3. Audit + ROI (the ops layer). Every decision logged to SQLite with latency.
   A Streamlit dashboard turns the log into a story: actions automated, attacks
   blocked, time saved. In regulated settings the audit trail is a legal obligation.

## Architecture

    User request
      -> Agent (local LLM via Ollama: reasons, proposes a tool call)
      -> [ AEGIS control plane ]
            1. Policy engine  : may this agent call THIS tool, on THIS data?
            2. Execute        : only if allowed, via the official MCP server
            3. Firewall       : screen returned content for prompt-injection
                                BEFORE it reaches the model context
            4. Audit + metrics: decision, reason, latency, time saved
      -> Tools / data (MCP servers)
      -> Response + ROI/security dashboard

Two distinct control points:
- Output side: policy.check() decides if the agent may call the tool.
- Input side: firewall.neutralize() screens tool output before the model sees it.

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
- The firewall v1 is heuristic (regex): catches obvious instruction-override and
  exfiltration patterns, bypassable by paraphrase or encoding. v2 = a light classifier.
- Latency on an M1 (16 GB): ~15-25 tok/s; fine for a demo, slow on long tool-call chains.
- When blocked, the agent rationalizes its own reason (once claimed a "path" issue when
  the real reason was a denied tool). Exactly why the decision lives in deterministic code.

## Build vs buy

- Local model: privacy and regulatory fit; data never leaves the machine. Ran on M1/16GB.
- Reuse the official MCP filesystem server rather than writing tools; original effort
  is concentrated on the control plane, where the value is.
- Heuristic firewall v1, not ML: a credible first pass with documented limits beats an
  over-engineered black box. Simple over over-engineering.

## Roadmap / not yet built

- PII redaction on tool output.
- Firewall v2: light local classifier alongside the regex rules.
- Hosted, sandboxed interactive demo (firewall + policy engine, no heavy model).
- Red-team test suite in CI (replay a battery of injections, prove the firewall holds).
- Additional wrapped MCP servers (Git/GitHub, Fetch).

## Run it yourself

    pip install -r requirements.txt
    ollama pull qwen3:8b

    # Happy path (read + summarise)
    python -m aegis.agent.loop ./demo/workspace "List the files, then read meeting_notes.txt and summarise it."

    # Blocked write (policy engine)
    python -m aegis.agent.loop ./demo/workspace "Create a file hacked.txt with the word PWNED."

    # Neutralized indirect injection (firewall)
    python -m aegis.agent.loop ./demo/workspace "List the files, then read project_update.txt and summarise it."

    # Dashboard (from project root)
    streamlit run dashboard/app.py

## Stack

Python · Ollama (qwen3:8b) · MCP Python SDK + official filesystem MCP server ·
PyYAML (policy) · SQLite (audit) · Streamlit + Altair (dashboard).
