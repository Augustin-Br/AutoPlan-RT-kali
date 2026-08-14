"""Probabilistic and symbolic validation for LLM-proposed paths."""

from __future__ import annotations

from dataclasses import dataclass

from V5.capec_kb import CapecKnowledgeBase
from V5.fact_grounding import assess_path_fact_grounding
from V5.infra_loader import normalize_for_prompt
from V5.knowledge_graph import assess_knowledge_alignment
from V5.mitre_kb import MitreKnowledgeBase
from V5.models import LLMPathProposal, PlausibilityBreakdown, ValidatedPathRecord, V5InfraDocument
from V5.pattern_store import PatternStore
from V5.tool_registry import ToolRegistry

DEFAULT_WEIGHTS = {
    "tool": 0.30,
    "mitre": 0.30,
    "capec": 0.15,
    "evidence": 0.15,
    "pattern": 0.05,
    "defense": 0.05,
}

NON_PRIVILEGE_TOOLS = frozenset({"nmap", "nmap_sv", "nmap_syn_scan", "curl", "ftp_banner_check", "ssh_banner_check"})
NON_PRIVILEGE_TYPES = frozenset({"scanner", "enumeration", "web_client"})


@dataclass(frozen=True)
class ValidatorOptions:
    """Counterfactual toggles for offline robustness studies only; defaults match the frozen validator."""

    enforce_topology: bool = True
    enforce_fact_grounding: bool = True
    enforce_defense_port_policy: bool = True
    enforce_defense_global: bool = True
    enforce_recon_cannot_grant_root: bool = True
    enforce_unknown_tool: bool = True
    enforce_knowledge_hard: bool = True


DEFAULT_VALIDATOR_OPTIONS = ValidatorOptions()


class PathValidator:
    def __init__(
        self,
        *,
        tool_registry: ToolRegistry,
        mitre_kb: MitreKnowledgeBase,
        pattern_store: PatternStore,
        capec_kb: CapecKnowledgeBase | None = None,
        plausibility_threshold: float = 0.60,
        weights: dict[str, float] | None = None,
        options: ValidatorOptions | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.mitre_kb = mitre_kb
        self.pattern_store = pattern_store
        self.capec_kb = capec_kb or CapecKnowledgeBase.load()
        self.plausibility_threshold = plausibility_threshold
        self.weights = weights or DEFAULT_WEIGHTS
        self.options = options or DEFAULT_VALIDATOR_OPTIONS

    def validate(
        self,
        path: LLMPathProposal,
        *,
        infra: V5InfraDocument,
        evidence_ids: set[str],
        evidence_by_id: dict[str, str] | None = None,
        known_facts: set[str] | None = None,
    ) -> ValidatedPathRecord:
        facts = set(known_facts or [])
        hard_rejects: list[str] = []
        tool_scores: list[float] = []
        mitre_scores: list[float] = []
        evidence_hits = 0
        evidence_total = 0

        observed_ips = {machine.ip for machine in infra.machines}
        if self.options.enforce_topology and path.target_ip not in observed_ips:
            hard_rejects.append("target_ip_not_in_topology")

        for step in sorted(path.steps, key=lambda item: item.step_index):
            if self.options.enforce_topology and step.target_ip not in observed_ips:
                hard_rejects.append(f"step_{step.step_index}_unknown_target")
            if self.options.enforce_defense_port_policy:
                step_defense_violations = self._step_defense_violations(step, infra)
                for violation in step_defense_violations:
                    hard_rejects.append(f"step_{step.step_index}_{violation}")
            tool_score, _ = self.tool_registry.tool_plausibility(step.tool)
            tool_scores.append(tool_score)
            if self.options.enforce_unknown_tool and tool_score <= 0.0:
                hard_rejects.append(f"step_{step.step_index}_unknown_tool:{step.tool}")
            tool_norm = step.tool.lower().replace("-", "_")
            if (
                self.options.enforce_recon_cannot_grant_root
                and step.produces_fact == "root_access"
                and (tool_norm in NON_PRIVILEGE_TOOLS or step.tool_type in NON_PRIVILEGE_TYPES)
            ):
                hard_rejects.append(f"step_{step.step_index}_recon_cannot_grant_root:{step.tool}")
            mitre_scores.append(
                self.mitre_kb.mitre_plausibility(
                    technique_id=step.mitre_technique_id,
                    tool_name=step.tool,
                    known_facts=facts,
                    step_index=step.step_index,
                )
            )
            if step.evidence_ids:
                evidence_total += len(step.evidence_ids)
                evidence_hits += sum(1 for eid in step.evidence_ids if eid in evidence_ids)
            if step.produces_fact:
                facts.add(step.produces_fact)

        if self.options.enforce_fact_grounding and evidence_by_id is not None:
            for reason in assess_path_fact_grounding(
                path.steps,
                evidence_by_id=evidence_by_id,
                valid_evidence_ids=evidence_ids,
            ):
                hard_rejects.append(reason)

        defense_score = self._defense_plausibility(path, infra)
        if self.options.enforce_defense_global and defense_score < 0.5:
            hard_rejects.append("defense_policy_violation")

        knowledge_alignment_score, knowledge_issues, knowledge_hard = assess_knowledge_alignment(
            path.steps,
            final_fact=path.final_fact,
        )
        if self.options.enforce_knowledge_hard:
            for reason in knowledge_hard:
                hard_rejects.append(reason)

        pattern_score = self.pattern_store.pattern_plausibility(path.steps, tool_registry=self.tool_registry)
        capec_score = self.capec_kb.capec_plausibility(path.steps, known_facts=set(known_facts or []))
        evidence_score = (evidence_hits / evidence_total) if evidence_total else 0.5
        tool_score = sum(tool_scores) / len(tool_scores) if tool_scores else 0.0
        mitre_score = sum(mitre_scores) / len(mitre_scores) if mitre_scores else 0.0

        breakdown = PlausibilityBreakdown(
            tool_score=round(tool_score, 4),
            mitre_score=round(mitre_score, 4),
            pattern_score=round(pattern_score, 4),
            capec_score=round(capec_score, 4),
            evidence_score=round(evidence_score, 4),
            defense_score=round(defense_score, 4),
            knowledge_alignment_score=knowledge_alignment_score,
            hard_reject_reasons=hard_rejects,
            knowledge_alignment_issues=knowledge_issues,
        )
        composite = (
            self.weights["tool"] * tool_score
            + self.weights["mitre"] * mitre_score
            + self.weights["pattern"] * pattern_score
            + self.weights["capec"] * capec_score
            + self.weights["evidence"] * evidence_score
            + self.weights["defense"] * defense_score
        )
        breakdown.composite = round(composite, 4)

        rejection_reasons = list(hard_rejects)
        if breakdown.composite < self.plausibility_threshold:
            rejection_reasons.append(f"plausibility_below_threshold:{breakdown.composite}")

        status = "accepted" if not rejection_reasons else "rejected"
        return ValidatedPathRecord(path=path, status=status, plausibility=breakdown, rejection_reasons=rejection_reasons)

    def _defense_plausibility(self, path: LLMPathProposal, infra: V5InfraDocument) -> float:
        if self._defense_violations(path, infra):
            return 0.0
        context = normalize_for_prompt(infra)
        if not context.get("security_notes") and not context.get("network_policies"):
            return 1.0
        notes_blob = " ".join(
            filter(
                None,
                [
                    infra.security_notes or "",
                    *(machine.security_notes or "" for machine in infra.machines),
                ],
            )
        ).lower()
        if "interdit" in notes_blob or "deny" in notes_blob or "block" in notes_blob:
            if "lateral" in notes_blob and len({step.target_ip for step in path.steps}) > 1:
                return 0.2
        return 1.0

    def _machine_zone(self, infra: V5InfraDocument, target_ip: str) -> str | None:
        for machine in infra.machines:
            if machine.ip == target_ip:
                return machine.zone
        return None

    def _policy_applies(self, policy, *, target_ip: str, target_zone: str | None) -> bool:
        if policy.to_ip and policy.to_ip != target_ip:
            return False
        if policy.to_zone and target_zone and policy.to_zone != target_zone:
            return False
        return bool(policy.to_ip or policy.to_zone or policy.allowed_ports or policy.denied_ports or policy.deny_all_else)

    def _step_defense_violations(self, step, infra: V5InfraDocument) -> list[str]:
        if not step.port:
            return []
        violations: list[str] = []
        zone = self._machine_zone(infra, step.target_ip)
        for policy in infra.network_policies:
            if not self._policy_applies(policy, target_ip=step.target_ip, target_zone=zone):
                continue
            if step.port in policy.denied_ports:
                violations.append(f"defense_port_denied:{step.port}")
            if policy.deny_all_else and policy.allowed_ports and step.port not in policy.allowed_ports:
                violations.append(f"defense_port_not_allowed:{step.port}")
        return violations

    def _defense_violations(self, path: LLMPathProposal, infra: V5InfraDocument) -> list[str]:
        violations: list[str] = []
        for step in path.steps:
            violations.extend(self._step_defense_violations(step, infra))
        return violations
