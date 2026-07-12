"""
Aegis — boucle agent : policy (J2) + firewall (J3) + audit (J4) + PII (J5+)
+ controle de sortie (egress) + trace de session.

Quatre points de controle sur chaque run :
  1. policy.check()      — l'agent a-t-il le droit de FAIRE ca ?
  2. firewall.neutralize() — ce que l'outil renvoie est-il piege ?
  3. redact()            — minimiser les PII qui entrent dans le contexte
  4. egress.screen()     — assainir la reponse finale qui SORT de l'agent

La requete utilisateur et la reponse finale sont elles-memes auditees
(decision "trace") : un auditeur veut la session complete, pas des extraits.

Le coeur (run_agent_core) ne depend ni d'Ollama ni de MCP : les deux sont
injectes, donc testables avec des faux (tests/test_loop.py) et importables
en CI sans ces paquets.

Run:
    python -m aegis.agent.loop ./demo/workspace "Read meeting_notes.txt"
    python -m aegis.agent.loop --help
"""

import argparse
import asyncio
import time
import uuid

from aegis.gateway.policy import PolicyEngine
from aegis.gateway.firewall import neutralize
from aegis.gateway.redact import redact
from aegis.gateway.egress import screen as egress_screen
from aegis.audit.logger import log_event

DEFAULT_MODEL = "qwen3:8b"
DEFAULT_MAX_STEPS = 6
DEFAULT_AGENT = "summarizer"
DEFAULT_POLICY = "policies/default.yaml"

SYSTEM_PROMPT = (
    "You are a minimal assistant. Use the provided tools to read and write "
    "files when the task requires it. Answer concisely when done."
)

_TRACE_LIMIT = 500  # taille max d'un champ trace dans l'audit


def mcp_tools_to_ollama(mcp_tools) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema,
            },
        }
        for t in mcp_tools.tools
    ]


async def run_agent_core(user_request, *, chat, call_tool, tools,
                         policy, agent_name=DEFAULT_AGENT,
                         max_steps=DEFAULT_MAX_STEPS, session_id=None) -> str:
    """Le coeur de la boucle, sans dependance directe a Ollama ni MCP.

    chat(messages, tools)   -> message {content, tool_calls} (async)
    call_tool(name, args)   -> texte renvoye par l'outil (async)
    """
    session_id = session_id or uuid.uuid4().hex[:8]
    log_event(agent_name, "user_request", "trace",
              user_request[:_TRACE_LIMIT], 0, session_id=session_id)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_request},
    ]

    def finish(answer: str) -> str:
        # --- SORTIE FINALE : egress (4e point de controle) ---
        result = egress_screen(answer)
        if not result.clean:
            print(f"[AEGIS EGRESS] {result.summary}")
            log_event(agent_name, "final_answer", "egress", result.summary,
                      0, session_id=session_id, pii_redacted=result.pii_redacted)
        log_event(agent_name, "final_answer", "trace",
                  result.text[:_TRACE_LIMIT], 0, session_id=session_id)
        return result.text

    for _ in range(max_steps):
        try:
            msg = await chat(messages, tools)
        except Exception as e:
            reason = f"LLM indisponible: {type(e).__name__}: {e}"
            print(f"[AEGIS ERROR] {reason}")
            log_event(agent_name, "llm_chat", "error", reason[:_TRACE_LIMIT],
                      0, session_id=session_id)
            return finish("Aegis: run aborted, the model backend failed. "
                          "No further tool call was attempted.")
        messages.append(msg)

        tool_calls = msg.get("tool_calls") if isinstance(msg, dict) \
            else getattr(msg, "tool_calls", None)
        content = msg.get("content") if isinstance(msg, dict) \
            else getattr(msg, "content", "")

        if not tool_calls:
            answer = finish(content or "")
            print("\n=== FINAL ANSWER ===\n", answer)
            return answer

        for call in tool_calls:
            fn = call["function"] if isinstance(call, dict) else call.function
            name = fn["name"] if isinstance(fn, dict) else fn.name
            args = fn["arguments"] if isinstance(fn, dict) else fn.arguments

            # --- SORTIE : autorisation (J2) ---
            decision = policy.check(name, args)
            if not decision.allowed:
                print(f"[AEGIS  DENY] {name}({args}) -> {decision.reason}")
                log_event(agent_name, name, "deny", decision.reason, 0,
                          session_id=session_id)
                messages.append({
                    "role": "tool",
                    "name": name,
                    "content": f"BLOCKED BY AEGIS: {decision.reason}",
                })
                continue
            print(f"[AEGIS ALLOW] {name}({args})")

            # --- execution + mesure latence, sans mourir sur un outil casse ---
            t0 = time.perf_counter()
            try:
                text = await call_tool(name, args)
            except Exception as e:
                latency_ms = int((time.perf_counter() - t0) * 1000)
                reason = f"outil en echec: {type(e).__name__}: {e}"
                print(f"[AEGIS ERROR] {name}: {reason}")
                log_event(agent_name, name, "error", reason[:_TRACE_LIMIT],
                          latency_ms, session_id=session_id)
                messages.append({
                    "role": "tool", "name": name,
                    "content": f"TOOL ERROR (reported by Aegis): {reason}",
                })
                continue
            latency_ms = int((time.perf_counter() - t0) * 1000)

            # --- ENTREE 1 : firewall injection (J3) ---
            text, scan_result = neutralize(text)
            if not scan_result.safe:
                print(f"[AEGIS FIREWALL] {name}: {scan_result.reason}")
                log_event(agent_name, name, "firewall", scan_result.reason,
                          latency_ms, session_id=session_id)
                messages.append({"role": "tool", "name": name, "content": text})
                continue

            # --- ENTREE 2 : redaction PII (J5+) ---
            redaction = redact(text)
            text = redaction.text
            if redaction.total:
                print(f"[AEGIS REDACT] {name}: {redaction.summary}")
            log_event(agent_name, name, "allow",
                      "ok" if not redaction.total else redaction.summary,
                      latency_ms, session_id=session_id,
                      pii_redacted=redaction.total)

            messages.append({"role": "tool", "name": name, "content": text})

    return finish("Stopped: hit MAX_STEPS without a final answer.")


async def run_agent(user_request: str, allowed_dir: str,
                    model=DEFAULT_MODEL, agent_name=DEFAULT_AGENT,
                    policy_path=DEFAULT_POLICY,
                    max_steps=DEFAULT_MAX_STEPS) -> str:
    """Cable le coeur sur les vraies dependances (Ollama + MCP filesystem)."""
    # Imports paresseux : le module reste importable (et le coeur testable)
    # sans ollama ni mcp installes — c'est ce que fait la CI.
    from ollama import AsyncClient
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    policy = PolicyEngine(policy_path, agent=agent_name)
    session_id = uuid.uuid4().hex[:8]
    print(f"[aegis] session {session_id} · model {model} · agent {agent_name}")

    server = StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", allowed_dir],
    )

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = mcp_tools_to_ollama(await session.list_tools())
            print(f"[mcp] tools available: {[t['function']['name'] for t in tools]}")

            client = AsyncClient()

            async def chat(messages, tools):
                resp = await client.chat(model=model, messages=messages,
                                         tools=tools, think=False)
                return resp.message

            async def call_tool(name, args):
                result = await session.call_tool(name, args)
                return "".join(block.text for block in result.content
                               if getattr(block, "text", None))

            return await run_agent_core(
                user_request, chat=chat, call_tool=call_tool, tools=tools,
                policy=policy, agent_name=agent_name,
                max_steps=max_steps, session_id=session_id)


def main():
    parser = argparse.ArgumentParser(
        prog="python -m aegis.agent.loop",
        description="Agent local (Ollama + MCP filesystem) gouverne par Aegis.")
    parser.add_argument("workspace", nargs="?", default="./demo/workspace",
                        help="repertoire autorise (defaut: ./demo/workspace)")
    parser.add_argument("task", nargs="?", default=(
        "List the files in the workspace, then read any .txt file and "
        "summarise it in two sentences."), help="tache confiee a l'agent")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--agent", default=DEFAULT_AGENT,
                        help="nom de l'agent dans le fichier de politique")
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    a = parser.parse_args()
    asyncio.run(run_agent(a.task, a.workspace, model=a.model,
                          agent_name=a.agent, policy_path=a.policy,
                          max_steps=a.max_steps))


if __name__ == "__main__":
    main()
