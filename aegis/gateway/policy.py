"""
Aegis — policy engine (J2).
Le LLM propose un appel d'outil ; ce code DETERMINISTE dispose.
Point d'autorisation unique, branché dans la boucle au ">>> AEGIS SEAM <<<".

Limite v1 (assumee, a documenter) : les "tags" de chemin sont detectes par
simple recherche de sous-chaine (ex: un chemin contenant "confidential").
Un vrai systeme resoudrait les tags via un catalogue de donnees / metadata.
"""

from dataclasses import dataclass
import yaml


@dataclass
class Decision:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(self, policy_path: str, agent: str):
        self.agent = agent
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
        rules = policy.get("agents", {}).get(agent)
        if rules is None:
            raise ValueError(f"Aucune politique definie pour l'agent '{agent}'")
        self.allowed_tools = set(rules.get("allowed_tools", []))
        self.denied_tools = set(rules.get("denied_tools", []))
        self.max_calls = rules.get("max_calls_per_session")
        self.deny_path_tags = [t.lower() for t in rules.get("deny_path_tags", [])]
        self.calls_made = 0

    def check(self, tool: str, args: dict) -> Decision:
        # 1. La denylist gagne toujours.
        if tool in self.denied_tools:
            return Decision(False, f"outil '{tool}' sur la liste interdite")

        # 2. Default-deny : si une allowlist existe, l'outil DOIT y figurer.
        if self.allowed_tools and tool not in self.allowed_tools:
            return Decision(False, f"outil '{tool}' absent de l'allowlist")

        # 3. Quota de session.
        if self.max_calls is not None and self.calls_made >= self.max_calls:
            return Decision(False, f"quota de session atteint ({self.max_calls})")

        # 4. Tags de chemin interdits (v1 : sous-chaine dans un argument).
        for value in args.values():
            text = str(value).lower()
            for tag in self.deny_path_tags:
                if tag in text:
                    return Decision(False, f"acces aux donnees '{tag}' interdit")

        # Autorise -> ca consomme une unite du quota.
        self.calls_made += 1
        return Decision(True, "ok")


if __name__ == "__main__":
    # Preuve autonome : AUCUN LLM requis. Lancer : python -m aegis.gateway.policy
    engine = PolicyEngine("policies/default.yaml", agent="summarizer")
    scenarios = [
        ("read_text_file", {"path": "demo/workspace/meeting_notes.txt"}),
        ("write_file",     {"path": "demo/workspace/x.txt"}),
        ("send_email",     {"to": "external@example.com"}),
        ("read_text_file", {"path": "demo/workspace/confidential_roadmap.txt"}),
    ]
    for tool, args in scenarios:
        d = engine.check(tool, args)
        flag = "ALLOW" if d.allowed else "DENY "
        print(f"[{flag}] {tool:16} -> {d.reason}")
