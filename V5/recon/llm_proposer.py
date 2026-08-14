"""LLM scan proposer — structured template proposals only (no shell)."""

from __future__ import annotations

import json
import re
from typing import Any

from V2.llm_provider import build_chat_client, resolve_llm_config, response_content_to_text
from V2.recon_models import ReconObservation
from V5.recon.models import ScanProposal, ScanProposalBatch
from V5.recon.policy_catalog import catalog_prompt_block, suggest_applicable_templates


class ReconLLMProposer:
    def __init__(
        self,
        *,
        provider: str | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        chat_client: Any | None = None,
        use_llm: bool = False,
    ) -> None:
        self.provider, self.model = resolve_llm_config(provider=provider, model=model)
        self.temperature = temperature
        self.chat_client = chat_client
        self.use_llm = use_llm or chat_client is not None

    def propose(
        self,
        *,
        target_ips: list[str],
        observations: list[ReconObservation],
        already_used_templates: set[str],
        aggressive: bool = False,
        max_proposals: int = 5,
    ) -> ScanProposalBatch:
        prompt = self._build_prompt(
            target_ips=target_ips,
            observations=observations,
            already_used_templates=already_used_templates,
            aggressive=aggressive,
            max_proposals=max_proposals,
        )
        if not self.use_llm:
            return self._heuristic_batch(
                target_ips=target_ips,
                observations=observations,
                already_used_templates=already_used_templates,
                aggressive=aggressive,
                max_proposals=max_proposals,
            )
        text = self._invoke(prompt)
        return self._parse(text)

    def _invoke(self, prompt: str) -> str:
        client = self.chat_client or build_chat_client(
            provider=self.provider,
            model=self.model,
            temperature=self.temperature,
        )
        response = client.invoke(prompt)
        return response_content_to_text(response)

    def _build_prompt(
        self,
        *,
        target_ips: list[str],
        observations: list[ReconObservation],
        already_used_templates: set[str],
        aggressive: bool,
        max_proposals: int,
    ) -> str:
        obs_payload = [
            {
                "target_ip": item.target_ip,
                "port": item.port,
                "service": item.service,
                "version": item.version,
                "product": item.product,
                "detected_technologies": item.detected_technologies[:8],
                "web_paths": item.web_paths[:12],
            }
            for item in observations[:80]
        ]
        hints = suggest_applicable_templates(
            observations,
            aggressive=aggressive,
            already_used=already_used_templates,
        )
        return f"""You are a bounded lab reconnaissance planner for an authorized CyberRange.
Propose additional SAFE inventory scans only. Do NOT propose exploits, brute force, Metasploit, sqlmap, or vuln scripts.
Return JSON only with this schema:
{{
  "proposals": [
    {{
      "template_id": "<from catalog>",
      "target_ip": "<lab ip>",
      "ports": [<int>, ...],
      "rationale": "<short>",
      "base_path": null,
      "hostname": null
    }}
  ],
  "stop_reason": null
}}
Rules:
- At most {max_proposals} proposals.
- Only use template_id values from the catalog.
- Target IPs must be in: {target_ips}
- Prefer templates not already used: {sorted(already_used_templates)}
- If nothing useful remains, return {{"proposals": [], "stop_reason": "no_more_scans"}}.

{catalog_prompt_block(aggressive=aggressive)}

Suggested remaining templates: {hints}

Current observations JSON:
{json.dumps(obs_payload, ensure_ascii=False, indent=2)}
"""

    def _parse(self, text: str) -> ScanProposalBatch:
        payload = _extract_json_object(text)
        if not payload:
            return ScanProposalBatch(proposals=[], stop_reason="parse_error")
        try:
            return ScanProposalBatch.model_validate(payload)
        except Exception:
            proposals_raw = payload.get("proposals") if isinstance(payload, dict) else None
            if not isinstance(proposals_raw, list):
                return ScanProposalBatch(proposals=[], stop_reason="parse_error")
            proposals: list[ScanProposal] = []
            for item in proposals_raw:
                try:
                    proposals.append(ScanProposal.model_validate(item))
                except Exception:
                    continue
            return ScanProposalBatch(
                proposals=proposals,
                stop_reason=payload.get("stop_reason") if isinstance(payload, dict) else None,
            )

    def _heuristic_batch(
        self,
        *,
        target_ips: list[str],
        observations: list[ReconObservation],
        already_used_templates: set[str],
        aggressive: bool,
        max_proposals: int,
    ) -> ScanProposalBatch:
        hints = suggest_applicable_templates(
            observations,
            aggressive=aggressive,
            already_used=already_used_templates,
        )
        proposals: list[ScanProposal] = []
        for template_id in hints[:max_proposals]:
            ip = target_ips[0] if target_ips else None
            if ip is None:
                break
            ports = sorted(
                {
                    observation.port
                    for observation in observations
                    if observation.target_ip == ip
                }
            )
            proposals.append(
                ScanProposal(
                    template_id=template_id,
                    target_ip=ip,
                    ports=ports[:5],
                    rationale=f"Heuristic offline proposal for {template_id}.",
                )
            )
        if not proposals:
            return ScanProposalBatch(proposals=[], stop_reason="no_more_scans")
        return ScanProposalBatch(proposals=proposals)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
