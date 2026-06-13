"""
Aegis — J3: agent loop with policy engine (J2) + injection firewall (J3).

Deux points de controle distincts :
  - SORTIE : policy.check() decide si l'agent a le DROIT d'appeler l'outil.
  - ENTREE : firewall.neutralize() scanne le CONTENU renvoye par l'outil
             AVANT qu'il n'atteigne le contexte du LLM (injection indirecte).

Run:
    python -m aegis.agent.loop ./demo/workspace
"""

import asyncio
import sys

from ollama import AsyncClient
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aegis.gateway.policy import PolicyEngine
from aegis.gateway.firewall import neutralize

MODEL = "qwen3:8b"
MAX_STEPS = 6
AGENT_NAME = "summarizer"
POLICY_PATH = "policies/default.yaml"


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


async def run_agent(user_request: str, allowed_dir: str) -> str:
    policy = PolicyEngine(POLICY_PATH, agent=AGENT_NAME)

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
            messages = [
                {"role": "system", "content":
                    "You are a minimal assistant. Use the provided tools to "
                    "read and write files when the task requires it. Answer "
                    "concisely when done."},
                {"role": "user", "content": user_request},
            ]

            for _ in range(MAX_STEPS):
                resp = await client.chat(
                    model=MODEL,
                    messages=messages,
                    tools=tools,
                    think=False,
                )
                msg = resp.message
                messages.append(msg)

                if not msg.tool_calls:
                    print("\n=== FINAL ANSWER ===\n", msg.content)
                    return msg.content

                for call in msg.tool_calls:
                    name = call.function.name
                    args = call.function.arguments

                    # --- AEGIS controle SORTIE : autorisation (J2) ---
                    decision = policy.check(name, args)
                    if not decision.allowed:
                        print(f"[AEGIS  DENY] {name}({args}) -> {decision.reason}")
                        messages.append({
                            "role": "tool",
                            "name": name,
                            "content": f"BLOCKED BY AEGIS: {decision.reason}",
                        })
                        continue
                    print(f"[AEGIS ALLOW] {name}({args})")

                    result = await session.call_tool(name, args)
                    text = "".join(
                        block.text for block in result.content
                        if getattr(block, "text", None)
                    )

                    # --- AEGIS controle ENTREE : firewall injection (J3) ---
                    text, scan_result = neutralize(text)
                    if not scan_result.safe:
                        print(f"[AEGIS FIREWALL] {name}: {scan_result.reason}")

                    messages.append({"role": "tool", "name": name, "content": text})

            return "Stopped: hit MAX_STEPS without a final answer."


if __name__ == "__main__":
    workspace = sys.argv[1] if len(sys.argv) > 1 else "./demo/workspace"
    task = sys.argv[2] if len(sys.argv) > 2 else (
        "List the files in the workspace, then read any .txt file and "
        "summarise it in two sentences."
    )
    asyncio.run(run_agent(task, workspace))
