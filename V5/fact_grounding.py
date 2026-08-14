"""Symbolic grounding of produces_fact against evidence graph kinds."""

from __future__ import annotations

from V5.models import PathStep

WEB_CREDENTIAL_KINDS = frozenset(
    {
        "login_surface",
        "webmail_surface",
        "encoded_resource",
        "wordlist_resource",
        "sensitive_resource",
        "backdoor_credential",
        "ftp_credential_clue",
        "upload_surface",
        "config_file",
    }
)
WEB_SHELL_KINDS = frozenset({"admin_capability"})
LOCAL_CREDENTIAL_KINDS = frozenset({"local_hash", "local_user", "local_secret"})
PRIVESC_KINDS = frozenset({"suid_binary", "privilege_escalation_hint", "sudo_rights"})

WEB_CLIENT_TOOLS = frozenset({"curl", "wpscan", "nmap", "nmap_sv", "nmap_syn_scan", "ftp_banner_check"})
CREDENTIAL_TOOLS = frozenset({"hydra", "john", "hashcat"})
REMOTE_ACCESS_TOOLS = frozenset({"ssh", "auxiliary/scanner/ssh/ssh_login"})
LOCAL_PRIVESC_EXPLOITS = frozenset({"exploit/unix/local/setuid_nmap"})


def _tool_norm(tool: str) -> str:
    return tool.lower().replace("-", "_")


def _is_exploit_tool(step: PathStep) -> bool:
    tool = _tool_norm(step.tool)
    return step.tool_type == "exploit_framework" or tool.startswith(("exploit/", "auxiliary/", "post/"))


def _can_grant_shell_access(step: PathStep) -> bool:
    """Only real exploit/post modules may produce shell_access."""
    tool = _tool_norm(step.tool)
    return tool.startswith(("exploit/", "post/"))


def _is_ssh_remote_step(step: PathStep) -> bool:
    tool = _tool_norm(step.tool)
    return tool in REMOTE_ACCESS_TOOLS or tool.startswith("auxiliary/scanner/ssh")


def _credential_from_local_tool(step: PathStep) -> bool:
    return _tool_norm(step.tool) in CREDENTIAL_TOOLS


def _web_credential_step(step: PathStep, evidence_by_id: dict[str, str]) -> bool:
    kinds = _cited_kinds(step, evidence_by_id)
    return bool(kinds.intersection(WEB_CREDENTIAL_KINDS))


def _is_web_client_step(step: PathStep) -> bool:
    tool = _tool_norm(step.tool)
    if tool in WEB_CLIENT_TOOLS or step.tool_type in {"web_client", "scanner", "enumeration"}:
        return True
    return step.port in {80, 443} or (step.service or "").upper() in {"HTTP", "HTTPS"}


def _cited_kinds(step: PathStep, evidence_by_id: dict[str, str]) -> set[str]:
    return {evidence_by_id[eid] for eid in step.evidence_ids if eid in evidence_by_id}


def assess_step_fact_grounding(
    step: PathStep,
    *,
    accumulated_facts: set[str],
    credential_from_local: bool,
    evidence_by_id: dict[str, str],
    valid_evidence_ids: set[str],
) -> tuple[list[str], bool]:
    """Return hard-reject reason codes for one step and updated local-credential flag."""
    reasons: list[str] = []
    idx = step.step_index
    fact = step.produces_fact
    if not fact:
        return reasons, credential_from_local

    if step.evidence_ids:
        hits = [eid for eid in step.evidence_ids if eid in valid_evidence_ids]
        if not hits:
            reasons.append(f"step_{idx}_unknown_evidence")
            return reasons, credential_from_local

    kinds = _cited_kinds(step, evidence_by_id)
    tool = _tool_norm(step.tool)
    exploit = _is_exploit_tool(step)
    web_client = _is_web_client_step(step)
    next_local_cred = credential_from_local

    if fact == "service_intelligence":
        return reasons, next_local_cred

    if fact == "credential_access":
        if _credential_from_local_tool(step):
            next_local_cred = True
        elif web_client and not exploit and _web_credential_step(step, evidence_by_id):
            next_local_cred = False
        if tool in CREDENTIAL_TOOLS or tool in REMOTE_ACCESS_TOOLS:
            if "shell_access" in accumulated_facts and not kinds.intersection(LOCAL_CREDENTIAL_KINDS):
                if step.evidence_ids and not kinds:
                    reasons.append(f"step_{idx}_fact_evidence_mismatch:credential_access")
            return reasons, next_local_cred
        if web_client and not exploit:
            if kinds.intersection(WEB_CREDENTIAL_KINDS):
                return reasons, next_local_cred
            if "credential_access" in accumulated_facts:
                return reasons, next_local_cred
            reasons.append(f"step_{idx}_fact_ungrounded:credential_access")
        return reasons, next_local_cred

    if fact == "shell_access":
        if _can_grant_shell_access(step):
            return reasons, next_local_cred
        if web_client:
            reasons.append(f"step_{idx}_web_client_cannot_grant:shell_access")
            return reasons, next_local_cred
        if _is_ssh_remote_step(step) or tool.startswith("auxiliary/scanner/"):
            reasons.append(f"step_{idx}_scanner_cannot_grant:shell_access")
            return reasons, next_local_cred
        return reasons, next_local_cred

    if fact == "pivot":
        if "credential_access" not in accumulated_facts and "shell_access" not in accumulated_facts:
            reasons.append(f"step_{idx}_fact_prerequisite_missing:pivot")
            return reasons, next_local_cred
        if _is_ssh_remote_step(step):
            if not credential_from_local and not kinds.intersection(LOCAL_CREDENTIAL_KINDS):
                reasons.append(f"step_{idx}_ssh_requires_local_credentials:pivot")
        return reasons, next_local_cred

    if fact == "root_access":
        if tool in {_tool_norm(item) for item in LOCAL_PRIVESC_EXPLOITS} or tool.startswith("exploit/unix/local/"):
            if "pivot" not in accumulated_facts and "shell_access" not in accumulated_facts:
                reasons.append(f"step_{idx}_fact_prerequisite_missing:root_access")
            elif "pivot" not in accumulated_facts:
                reasons.append(f"step_{idx}_privesc_requires_pivot:root_access")
            return reasons, next_local_cred
        if not exploit and tool not in {_tool_norm(item) for item in LOCAL_PRIVESC_EXPLOITS}:
            if "pivot" not in accumulated_facts and "shell_access" not in accumulated_facts:
                reasons.append(f"step_{idx}_fact_prerequisite_missing:root_access")
        return reasons, next_local_cred

    return reasons, next_local_cred


def assess_path_fact_grounding(
    steps: list[PathStep],
    *,
    evidence_by_id: dict[str, str],
    valid_evidence_ids: set[str],
) -> list[str]:
    accumulated: set[str] = set()
    credential_from_local = False
    reasons: list[str] = []
    for step in sorted(steps, key=lambda item: item.step_index):
        step_reasons, credential_from_local = assess_step_fact_grounding(
            step,
            accumulated_facts=accumulated,
            credential_from_local=credential_from_local,
            evidence_by_id=evidence_by_id,
            valid_evidence_ids=valid_evidence_ids,
        )
        reasons.extend(step_reasons)
        if step.produces_fact:
            accumulated.add(step.produces_fact)
    return reasons
