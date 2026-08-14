"""Base + session allowlist for HITL / auto path execution."""

from __future__ import annotations

from V5.models import AttackPath, PathStep

BASE_ALLOWLIST: frozenset[str] = frozenset({"nmap", "curl", "dirb", "wpscan"})

# Tools that require allow_auto_exploits (+ lab_ack) before subprocess auto-run.
NEVER_AUTORUN_PREFIXES: tuple[str, ...] = ("exploit/", "auxiliary/", "post/", "payload/")
NEVER_AUTORUN_TOOLS: frozenset[str] = frozenset(
    {"msfconsole", "metasploit", "msfvenom", "sqlmap"}
)


class AllowlistState:
    def __init__(
        self,
        *,
        base: frozenset[str] | set[str] | None = None,
        session: set[str] | None = None,
    ) -> None:
        self.base: set[str] = set(base if base is not None else BASE_ALLOWLIST)
        self.session: set[str] = set(session or ())

    def effective(self) -> set[str]:
        return set(self.base) | set(self.session)

    def contains(self, tool: str) -> bool:
        return _normalize_tool(tool) in {_normalize_tool(item) for item in self.effective()}

    def promote(self, tool: str) -> None:
        self.session.add(_normalize_tool(tool))

    def promote_missing_from_path(self, path: AttackPath) -> list[str]:
        """Promote every tool on the path that is not yet allowlisted. Returns promoted tools."""

        promoted: list[str] = []
        for tool in self.missing_from_path(path):
            self.promote(tool)
            promoted.append(tool)
        return promoted

    def missing_from_path(self, path: AttackPath) -> list[str]:
        missing: list[str] = []
        seen: set[str] = set()
        for step in path.steps:
            tool = _normalize_tool(step.tool)
            if tool in seen:
                continue
            seen.add(tool)
            if not self.contains(tool):
                missing.append(step.tool)
        return missing

    def risk_note(self, tool: str) -> str:
        normalized = _normalize_tool(tool)
        if _is_exploit_family(normalized):
            return "exploit_framework — auto-run only with --allow-auto-exploits + lab ack"
        if normalized in {"hydra", "medusa", "ncrack"}:
            return "bruteforce — auto-run only after promotion and only with a safe template"
        if normalized in {"john", "hashcat"}:
            return "credential cracking — typically human-assisted"
        if normalized in BASE_ALLOWLIST:
            return "base inventory tool"
        return "non-base tool proposed by the LLM draft"


def can_autorun(
    tool: str,
    allowlist: AllowlistState,
    *,
    has_template: bool,
    allow_auto_exploits: bool = False,
) -> bool:
    """True when the runtime may spawn a subprocess for this tool."""

    if not allowlist.contains(tool):
        return False
    if not has_template:
        return False
    if _is_exploit_family(_normalize_tool(tool)):
        return bool(allow_auto_exploits)
    return True


def promotion_auto_run_eligible(
    tool: str,
    *,
    has_template: bool,
    allow_auto_exploits: bool = False,
) -> bool:
    if _is_exploit_family(_normalize_tool(tool)):
        return bool(allow_auto_exploits) and has_template
    return has_template


def _normalize_tool(tool: str) -> str:
    return tool.strip().lower()


def _is_exploit_family(tool: str) -> bool:
    if tool in NEVER_AUTORUN_TOOLS:
        return True
    return any(tool.startswith(prefix) for prefix in NEVER_AUTORUN_PREFIXES)


def step_tool_key(step: PathStep) -> str:
    return _normalize_tool(step.tool)
