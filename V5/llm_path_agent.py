"""LLM path builder — proposes ordered tool-based attack paths with RAG context."""

from __future__ import annotations

import json
import time
from typing import Any

from V2.llm_provider import build_chat_client, resolve_llm_config, response_content_to_text
from V2.models import ServiceFinding
from V2.rag_adapter import RAGAdapter
from V5.infra_loader import normalize_for_prompt
from V5.knowledge_graph import KNOWLEDGE_LEVEL_GUIDE
from V5.models import LLMPathProposal, LLMPathResponse, LoopPromptContext, PathStep, V5InfraDocument
from V5.tool_registry import ToolRegistry

_FACT_GROUNDING_RULES = """\
- FACT TO TOOL MAPPING (hard rejects if violated):
  * hydra, john, hashcat → credential_access ONLY (never shell_access or root_access).
  * bare ssh or auxiliary/scanner/ssh/* → pivot ONLY (never shell_access).
  * shell_access → ONLY exploit/* or post/* (e.g. exploit/multi/ssh/sshexec, exploit/multi/http/*).
  * john/hashcat steps: set port to 22 or null — NOT 80/443 (HTTP ports classify the step as web_client).
  * root_access after shell_access: prefer exploit/linux/local/* or post/linux/* privesc modules.
  * exploit/unix/local/* for root_access requires a prior pivot step (ssh with produces_fact=pivot counts).
  * credential_access via curl/wpscan: cite login_surface, wordlist_resource, sensitive_resource, config_file, or similar — copy exact evidence IDs from the graph.
  * After a web exploit grants shell_access, database privesc modules (exploit/multi/mysql/*) may follow directly without a curl credential step.
- Use progression: service_intelligence → credential_access → pivot and/or shell_access → root_access.
"""


class LLMPathAgent:
    def __init__(
        self,
        *,
        model: str | None = None,
        provider: str | None = None,
        temperature: float = 0.0,
        chat_client: Any | None = None,
        tool_registry: ToolRegistry | None = None,
        use_llm: bool = False,
    ) -> None:
        self.provider, self.model = resolve_llm_config(provider=provider, model=model)
        self.temperature = temperature
        self.chat_client = chat_client
        self.tool_registry = tool_registry or ToolRegistry.load()
        self.use_llm = use_llm or chat_client is not None

    def generate(
        self,
        infra: V5InfraDocument,
        *,
        rag: RAGAdapter,
        evidence_payload: dict[str, Any],
        existing_path_summaries: list[str] | None = None,
        round_index: int = 1,
        loop_context: LoopPromptContext | None = None,
        rag_per_service_k: int = 8,
        rag_module_prompt_limit: int = 40,
    ) -> LLMPathResponse:
        prompt = self._build_prompt(
            infra,
            rag=rag,
            evidence_payload=evidence_payload,
            existing_path_summaries=existing_path_summaries or [],
            round_index=round_index,
            loop_context=loop_context,
            rag_per_service_k=rag_per_service_k,
            rag_module_prompt_limit=rag_module_prompt_limit,
        )
        if not self.use_llm:
            return _mock_response(infra, round_index=round_index, existing=existing_path_summaries or [])
        text = self._invoke(prompt)
        return self._parse_response(text)

    def _invoke(self, prompt: str) -> str:
        client = self.chat_client or build_chat_client(
            provider=self.provider,
            model=self.model,
            temperature=self.temperature,
        )
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = client.invoke(
                    "Return only valid JSON for V5 path proposals.\n\n" + prompt
                )
                return response_content_to_text(response)
            except Exception as exc:
                last_error = exc
                message = str(exc)
                if "429" in message or "RESOURCE_EXHAUSTED" in message:
                    time.sleep(30 * (attempt + 1))
                    continue
                raise
        assert last_error is not None
        raise last_error

    def _build_prompt(
        self,
        infra: V5InfraDocument,
        *,
        rag: RAGAdapter,
        evidence_payload: dict[str, Any],
        existing_path_summaries: list[str],
        round_index: int,
        loop_context: LoopPromptContext | None = None,
        rag_per_service_k: int = 8,
        rag_module_prompt_limit: int = 40,
    ) -> str:
        infra_view = normalize_for_prompt(infra)
        rag_modules: list[str] = []
        per_service_k = max(1, rag_per_service_k)
        prompt_limit = max(1, rag_module_prompt_limit)
        for machine in infra.machines:
            for service in machine.services:
                finding = ServiceFinding(
                    target_id=machine.id,
                    target_ip=machine.ip,
                    port=service.port,
                    service=service.service,
                    version=service.version,
                    cve=str(service.cve) if service.cve else None,
                    notes=service.service_observations,
                )
                payload = rag.query_service(
                    finding,
                    objective=infra.attack_objective,
                    top_k=per_service_k,
                )
                rag_modules.extend(payload.candidate_modules[:per_service_k])
        known_tools = self.tool_registry.known_tool_ids()
        objective_hints = _objective_hints(infra_view)
        loop_block = _loop_context_block(loop_context, round_index)
        knowledge_guide = "\n".join(f"- {text}" for text in KNOWLEDGE_LEVEL_GUIDE.values())
        return (
            "You are the V5 attack-path builder for authorized blue-team scenario generation.\n"
            "Build ORDERED multi-step paths using real tools (nmap, hydra, curl, john, ssh, msf modules, etc.).\n"
            "You may propose tools beyond a fixed library if they are realistic; cite MITRE technique IDs.\n"
            "Never generate shell commands. Never claim successful compromise.\n"
            "Prefer Metasploit module paths listed in pistes_documentees when present; "
            "do not invent module names that are not in RAG or pistes.\n"
            "Each step must reference evidence IDs when available.\n"
            "\n"
            "ATTACKER KNOWLEDGE LEVELS (declare per step; validated against produces_fact):\n"
            f"{knowledge_guide}\n"
            "- declared_knowledge_level must be NON-DECREASING along the path (K0→K1→…→K5).\n"
            "- justification: one short sentence why this step reaches the declared K given produces_fact.\n"
            "\n"
            "VALIDATOR CONSTRAINTS (paths violating these are REJECTED):\n"
            "- nmap, curl, wpscan and other scanners/enumeration tools MUST NOT use produces_fact=root_access.\n"
            "- root_access requires a privesc exploit or post module, not recon.\n"
            "- declared_knowledge_level must match produces_fact (±1 level); over-claiming (declared >> inferred, gap ≥2) is rejected.\n"
            "- FACT GROUNDING (produces_fact must match cited evidence kinds):\n"
            "  * cms_surface/technology alone does NOT ground credential_access — use service_intelligence instead.\n"
            "  * Never cite invented evidence_id values; copy exact IDs from Evidence graph.\n"
            f"{_FACT_GROUNDING_RULES}"
            "- port must be 1-65535 or null; never use port=0.\n"
            "- hydra: port and service MUST match (ssh→22, ftp→21, http/wordpress→80 or 443). "
            "Never set hydra port=22 with service HTTP. Never use hydra service value 'http' "
            "(invalid Hydra module); use ssh or describe the web login on port 80/443.\n"
            "\n"
            f"{objective_hints}\n"
            f"{loop_block}\n"
            "Return JSON with path_proposals (ordered steps with tool, mitre_technique_id, produces_fact, declared_knowledge_level, justification).\n"
            "Schema:\n"
            "{\n"
            '  "reasoning_summary": "string",\n'
            '  "exhausted": false,\n'
            '  "stop_reason": null,\n'
            '  "path_proposals": [\n'
            "    {\n"
            '      "path_id": "string",\n'
            '      "title": "string",\n'
            '      "target_ip": "192.168.x.x",\n'
            '      "final_fact": "root_access|credential_access|pivot",\n'
            '      "steps": [\n'
            "        {\n"
            '          "step_index": 1,\n'
            '          "tool": "nmap|hydra|exploit/...",\n'
            '          "tool_type": "scanner|bruteforce|exploit_framework|enumeration|web_client",\n'
            '          "mitre_technique_id": "T1046",\n'
            '          "target_ip": "192.168.x.x",\n'
            '          "port": 21,\n'
            '          "service": "FTP",\n'
            '          "produces_fact": "service_intelligence|credential_access|pivot|shell_access|root_access",\n'
            '          "declared_knowledge_level": 0,\n'
            '          "justification": "short reason for K level after this step",\n'
            '          "depends_on_step": null,\n'
            '          "evidence_ids": ["evidence_id_from_graph"],\n'
            '          "estimated_destructiveness": 0.3\n'
            "        }\n"
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}\n"
            f"Round: {round_index}\n"
            f"Attack objective: {infra_view['attack_objective']}\n"
            f"Security notes: {infra_view.get('security_notes')}\n"
            f"Documented lab leads: {json.dumps(infra_view.get('pistes_documentees') or [], ensure_ascii=False)}\n"
            f"Network policies: {json.dumps(infra_view.get('network_policies', []), ensure_ascii=False)}\n"
            f"Infrastructure: {json.dumps(infra_view['machines'], ensure_ascii=False)}\n"
            f"Evidence graph: {json.dumps(evidence_payload, ensure_ascii=False)}\n"
            f"RAG candidate modules ({min(len(set(rag_modules)), prompt_limit)} shown): "
            f"{json.dumps(sorted(set(rag_modules))[:prompt_limit], ensure_ascii=False)}\n"
            f"Known tools (not exhaustive): {json.dumps(known_tools[:40], ensure_ascii=False)}\n"
            f"Already accepted paths (avoid near-duplicates): {json.dumps(existing_path_summaries, ensure_ascii=False)}\n"
            "If no new plausible path exists, set exhausted=true and stop_reason=llm_exhausted.\n"
        )

    def _parse_response(self, text: str) -> LLMPathResponse:
        payload = json.loads(_extract_json(text))
        _sanitize_llm_payload(payload)
        return LLMPathResponse.model_validate(payload)


def _extract_json(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("No JSON object found in LLM response")
    return text[start : end + 1]


def _tool_norm(tool: str) -> str:
    return tool.lower().replace("-", "_")


def _normalize_step_produces_facts(steps: list[dict]) -> None:
    """Align common LLM produces_fact mistakes with the frozen fact-grounding model."""
    ordered = sorted(steps, key=lambda item: int(item.get("step_index") or 0))
    accumulated: set[str] = set()
    for step in ordered:
        tool = _tool_norm(str(step.get("tool", "")).strip())
        fact = step.get("produces_fact")
        if not fact:
            continue

        if fact == "shell_access":
            if tool in {"ssh"} or tool.startswith("auxiliary/scanner/ssh"):
                step["produces_fact"] = "pivot"
                fact = "pivot"
            elif tool in {"hydra", "john", "hashcat"}:
                step["produces_fact"] = "credential_access"
                fact = "credential_access"

        if tool in {"john", "hashcat", "hydra"} and step.get("port") in {80, 443}:
            step["port"] = 22 if tool == "hydra" else None

        if (
            fact == "credential_access"
            and tool == "curl"
            and not (step.get("evidence_ids") or [])
            and "shell_access" in accumulated
        ):
            step["produces_fact"] = "service_intelligence"
            fact = "service_intelligence"

        if (
            fact == "root_access"
            and tool.startswith("exploit/unix/local/")
            and "shell_access" in accumulated
            and "pivot" not in accumulated
        ):
            step["tool"] = "exploit/linux/local/desktop_privilege_escalation"
            tool = _tool_norm(step["tool"])

        accumulated.add(fact)


def _sanitize_llm_payload(payload: dict) -> None:
    """Fix common LLM JSON issues before Pydantic validation."""
    for proposal in payload.get("path_proposals", []) or []:
        steps = proposal.get("steps", []) or []
        _normalize_step_produces_facts(steps)
        for step in steps:
            if step.get("knowledge_level") is not None and step.get("declared_knowledge_level") is None:
                step["declared_knowledge_level"] = step.pop("knowledge_level")
            declared = step.get("declared_knowledge_level")
            if declared is not None:
                try:
                    step["declared_knowledge_level"] = max(0, min(5, int(declared)))
                except (TypeError, ValueError):
                    step.pop("declared_knowledge_level", None)
            port = step.get("port")
            if port is None or (isinstance(port, int) and port < 1):
                step["port"] = None
            tool = str(step.get("tool", "")).strip()
            tool_type = step.get("tool_type")
            if tool_type not in {
                "scanner",
                "exploit_framework",
                "bruteforce",
                "web_client",
                "shell",
                "credential",
                "enumeration",
                "other",
            }:
                step.pop("tool_type", None)
            if tool.startswith(("exploit/", "auxiliary/", "post/")):
                step["tool_type"] = step.get("tool_type") or "exploit_framework"
            elif tool in {"nmap", "nmap_sV", "nmap_syn_scan"}:
                step["tool_type"] = step.get("tool_type") or "scanner"
            elif tool == "hydra":
                step["tool_type"] = step.get("tool_type") or "bruteforce"
            elif tool == "curl":
                step["tool_type"] = step.get("tool_type") or "web_client"
            elif tool in {"john", "hashcat"}:
                step["tool_type"] = step.get("tool_type") or "credential"
            elif tool in {"ssh", "auxiliary/scanner/ssh/ssh_login"}:
                step["tool_type"] = step.get("tool_type") or "bruteforce"
            elif "setuid_nmap" in tool or tool == "exploit/unix/local/setuid_nmap":
                step["tool_type"] = "exploit_framework"


def _loop_context_block(loop_context: LoopPromptContext | None, round_index: int) -> str:
    if round_index <= 1 or not loop_context:
        return "LOOP CONTEXT: initial round — no prior validated attacker knowledge yet."
    lines = [
        "LOOP CONTEXT (validated attacker state from prior accepted paths):",
        f"- Current knowledge level: {loop_context.knowledge_label} (K{loop_context.knowledge_level})",
        f"- Accumulated facts: {json.dumps(loop_context.known_facts, ensure_ascii=False)}",
        "Propose NEW paths that extend these facts; do not repeat rejected patterns below.",
    ]
    if loop_context.rejected_summaries:
        lines.append("- All rejected scenarios so far (avoid repeating these mistakes):")
        for item in loop_context.rejected_summaries:
            lines.append(f"  * {item}")
    lines.append(
        "- Diversity: propose a NEW complete path — different first tool (wpscan/hydra/nmap), "
        "different web exploit module, or different credential source. Do not repeat an accepted tool sequence."
    )
    return "\n".join(lines) + "\n"


def _objective_hints(infra_view: dict) -> str:
    """Context-specific hints derived from infra notes (no per-VM attack chains)."""
    blob = json.dumps(infra_view, ensure_ascii=False).lower()
    hints: list[str] = []
    if "root_access" in (infra_view.get("attack_objective") or "").lower() or "root compromise" in blob:
        hints.append(
            "Objective requires root_access on the final step via a credible privesc exploit or post module, not recon tools."
        )
    pistes = infra_view.get("pistes_documentees") or []
    if pistes:
        hints.append(
            "Use documented lab leads (pistes_documentees) as preferred tool/module names; stay consistent with observed services."
        )
    if not hints:
        return ""
    return "SCENARIO HINTS:\n- " + "\n- ".join(hints) + "\n"


def _mock_response(infra: V5InfraDocument, *, round_index: int, existing: list[str]) -> LLMPathResponse:
    """Deterministic fallback when no API key — useful for tests and offline demos."""
    if round_index > 2 or any("ftp" in item.lower() for item in existing):
        return LLMPathResponse(reasoning_summary="No more distinct paths", exhausted=True, stop_reason="llm_exhausted")
    target_ip = infra.machines[0].ip
    ftp_path = LLMPathProposal(
        path_id=f"mock-ftp-{round_index}",
        title="FTP banner then vsftpd backdoor",
        target_ip=target_ip,
        final_fact="root_access",
        steps=[
            PathStep(
                step_index=1,
                tool="ftp_banner_check",
                tool_type="enumeration",
                mitre_technique_id="T1046",
                target_ip=target_ip,
                port=21,
                service="FTP",
                produces_fact="service_intelligence",
            ),
            PathStep(
                step_index=2,
                tool="exploit/unix/ftp/vsftpd_234_backdoor",
                tool_type="exploit_framework",
                mitre_technique_id="T1190",
                target_ip=target_ip,
                port=21,
                service="FTP",
                depends_on_step=1,
                produces_fact="root_access",
                estimated_destructiveness=0.75,
            ),
        ],
    )
    hydra_path = LLMPathProposal(
        path_id=f"mock-hydra-{round_index}",
        title="Scan then hydra FTP",
        target_ip=target_ip,
        final_fact="credential_access",
        steps=[
            PathStep(step_index=1, tool="nmap", tool_type="scanner", mitre_technique_id="T1046", target_ip=target_ip, port=21, service="FTP", produces_fact="service_intelligence"),
            PathStep(step_index=2, tool="hydra", tool_type="bruteforce", mitre_technique_id="T1110", target_ip=target_ip, port=21, service="FTP", depends_on_step=1, produces_fact="credential_access", estimated_destructiveness=0.35),
        ],
    )
    return LLMPathResponse(
        reasoning_summary="Mock paths for offline V5 pipeline",
        path_proposals=[ftp_path] if round_index == 1 else [hydra_path],
    )
