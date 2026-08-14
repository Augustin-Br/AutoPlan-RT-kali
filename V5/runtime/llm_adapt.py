"""Optional LLM next-tool proposal when deterministic policies are stuck."""

from __future__ import annotations

import json
import re

from V5.models import PathStep
from V5.runtime.adapt import AdaptDecision, is_local_privesc
from V5.runtime.allowlist import _normalize_tool
from V5.runtime.command_suggest import has_autorun_template, module_needs_login_credentials
from V5.runtime.world import WorldState

# Generic recon/bruteforce only — exploit modules must come from the scenario path.
_ALLOWED_FALLBACK = (
    "nmap",
    "curl",
    "dirb",
    "wpscan",
    "hydra",
)


def propose_llm_decision(
    world: WorldState,
    remaining: list[PathStep],
    *,
    allow_auto_exploits: bool,
) -> AdaptDecision | None:
    try:
        from V2.llm_provider import build_chat_client, response_content_to_text
    except Exception:
        return None

    allowed = list(_ALLOWED_FALLBACK)
    for step in remaining:
        tool = step.tool
        if tool not in allowed:
            allowed.append(tool)
    allowed_l = {item.lower() for item in allowed}

    prompt = (
        "Authorized isolated-lab pentest helper. Propose ONE next tool.\n"
        "Follow the remaining scenario toward root_access. Adapt if the last action failed.\n"
        "Prefer scenario exploit modules when credentials or a shell already exist.\n"
        "Never invent shell payloads. Never invent Metasploit module names. Never output a command line.\n"
        "Never propose local privilege-escalation modules unless a shell session already exists.\n"
        f"World: {json.dumps(world.snapshot(), ensure_ascii=False)}\n"
        f"Remaining scenario tools: {[s.tool for s in remaining]}\n"
        f"Allowed tools: {allowed}\n"
        'Return JSON only: {"tool": "...", "reason": "..."}\n'
    )
    try:
        client = build_chat_client(temperature=0.1)
        text = response_content_to_text(
            client.invoke("Return only valid JSON.\n\n" + prompt)
        )
    except Exception:
        return None
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    tool = str(payload.get("tool") or "").strip()
    if not tool or tool.lower() not in allowed_l:
        return None
    if not has_autorun_template(tool, allow_auto_exploits=allow_auto_exploits):
        return None
    if _normalize_tool(tool) in {"hydra"} and "hydra_pass" in world.tried and not world.credentials:
        return None
    if module_needs_login_credentials(tool) and not world.credentials:
        return None
    if is_local_privesc(tool) and not world.has_shell:
        return None
    if f"missing:{_normalize_tool(tool)}" in world.tried:
        return None
    reason = str(payload.get("reason") or "llm adapt")[:200]
    step = PathStep(
        step_index=98,
        tool=tool,
        target_ip=world.target_ip,
        port=world.port or 80,
        service="HTTP",
        produces_fact="service_intelligence",
        justification=reason,
    )
    return AdaptDecision(step=step, note=reason, source="llm")
