"""Knowledge-state graph — nodes show attacker knowledge level."""

from __future__ import annotations

import hashlib

from V5.models import KnowledgeEdge, KnowledgeGraph, KnowledgeNode, LLMPathProposal, PathStep, ValidatedPathRecord

LEVEL_LABELS = {
    0: "K0 External recon",
    1: "K1 Service intelligence",
    2: "K2 Access attempt",
    3: "K3 Post-exploitation",
    4: "K4 Privilege escalation",
    5: "K5 Objective reached",
}

KNOWLEDGE_LEVEL_GUIDE = {
    0: "K0 — no foothold yet; external recon only (produces_fact: service_intelligence)",
    1: "K1 — service intelligence (versions, banners, paths; still service_intelligence facts)",
    2: "K2 — initial access attempt (credential_access before shell)",
    3: "K3 — post-exploitation (shell_access, credential_access, pivot)",
    4: "K4 — privilege escalation in progress (privesc facts, not yet root_access)",
    5: "K5 — objective reached (final_fact root_access / objective)",
}


def fact_set_hash(facts: list[str]) -> str:
    digest = hashlib.sha1("|".join(sorted(set(facts))).encode("utf-8")).hexdigest()
    return digest[:10]


FACT_KNOWLEDGE_LEVEL: dict[str, int] = {
    "service_intelligence": 1,
    "credential_access": 2,
    "shell_access": 3,
    "pivot": 4,
    "root_access": 5,
}


def infer_knowledge_level(facts: list[str], final_fact: str | None = None) -> int:
    """Infer K from accumulated produces_fact vocabulary (monotonic K0–K5 ladder)."""
    level = 0
    for fact in facts:
        level = max(level, FACT_KNOWLEDGE_LEVEL.get(fact, 0))
    if final_fact:
        level = max(level, FACT_KNOWLEDGE_LEVEL.get(final_fact, 0))
    return level


def step_graph_facts(step: PathStep, evidence_by_id: dict[str, str] | None = None) -> list[str]:
    """Rich graph facts for node identity (K inference still uses produces_fact tokens only)."""
    facts: list[str] = []
    if step.produces_fact:
        facts.append(step.produces_fact)
    tool = step.tool.lower().replace("-", "_")
    short_tool = tool.rsplit("/", 1)[-1] if "/" in tool else tool

    if step.produces_fact == "service_intelligence":
        facts.append(f"recon:{short_tool}")
    elif step.produces_fact == "credential_access":
        if evidence_by_id:
            for evidence_id in step.evidence_ids:
                kind = evidence_by_id.get(evidence_id)
                if kind:
                    facts.append(f"source:{kind}")
        if short_tool not in {"curl", "wpscan", "nmap", "hydra"}:
            facts.append(f"cred_tool:{short_tool}")
    elif step.produces_fact == "shell_access" and tool.startswith(("exploit/", "post/")):
        facts.append(f"exploit:{short_tool}")
    elif step.produces_fact == "pivot":
        facts.append(f"access:{short_tool}")
    elif step.produces_fact == "root_access" and tool.startswith(("exploit/", "post/")):
        facts.append(f"privesc:{short_tool}")
    return facts


def produces_facts_only(facts: list[str]) -> list[str]:
    return [fact for fact in facts if fact in FACT_KNOWLEDGE_LEVEL]


_PRIVILEGE_PEAK: dict[str, tuple[str, str]] = {
    "service_intelligence": ("external recon only", "recon externe uniquement"),
    "credential_access": ("credentials (no shell yet)", "credentials (pas de shell)"),
    "shell_access": ("limited shell (RCE/web)", "shell limité (RCE/web)"),
    "pivot": ("user session (pivot)", "session utilisateur (pivot)"),
    "root_access": ("root access", "accès root"),
}

_PRIVILEGE_GAIN: dict[str, tuple[str, str]] = {
    "service_intelligence": ("+recon", "+recon"),
    "credential_access": ("+credentials", "+credentials"),
    "shell_access": ("+shell", "+shell"),
    "pivot": ("+user session", "+session user"),
    "root_access": ("+root", "+root"),
}


def _locale_text(locale: str, pair: tuple[str, str]) -> str:
    return pair[1] if locale == "fr" else pair[0]


def intruder_privilege_summary(facts: list[str], *, locale: str = "en") -> str:
    """Human-readable attacker privilege state from accumulated graph facts."""
    kfacts = produces_facts_only(facts)
    if not kfacts:
        return "aucun accès (externe)" if locale == "fr" else "no access (external)"

    peak = max(kfacts, key=lambda fact: FACT_KNOWLEDGE_LEVEL.get(fact, 0))
    summary = _locale_text(locale, _PRIVILEGE_PEAK.get(peak, (peak, peak)))

    hints: list[str] = []
    if peak == "root_access":
        for fact in facts:
            if fact.startswith("privesc:"):
                hints.append(fact.split(":", 1)[1].replace("_", " "))
                break
    if peak in {"pivot", "root_access"}:
        for fact in facts:
            if fact.startswith("access:"):
                hints.append(fact.split(":", 1)[1].upper())
                break
    if peak in {"shell_access", "pivot", "root_access"}:
        for fact in facts:
            if fact.startswith("exploit:"):
                hints.append(fact.split(":", 1)[1].replace("_", " "))
                break
    if peak in {"credential_access", "shell_access"}:
        for fact in facts:
            if fact.startswith("source:"):
                hints.append(fact.split(":", 1)[1].replace("_", " "))
    if peak == "pivot" and not any(h == "SSH" for h in hints):
        for fact in facts:
            if fact.startswith("cred_tool:"):
                hints.append(fact.split(":", 1)[1])
                break

    if hints:
        detail = ", ".join(dict.fromkeys(hints[:2]))
        return f"{summary} ({detail})"
    return summary


def privilege_gain_label(produces_fact: str | None, *, locale: str = "en") -> str:
    if not produces_fact:
        return ""
    pair = _PRIVILEGE_GAIN.get(produces_fact)
    return _locale_text(locale, pair) if pair else ""


class KnowledgeGraphBuilder:
    def __init__(self) -> None:
        self.graph = KnowledgeGraph(nodes=[KnowledgeNode(node_id="K0:root", knowledge_level=0, facts=[], label=LEVEL_LABELS[0])])
        self._node_index: dict[tuple[int, str], str] = {(0, ""): "K0:root"}

    def integrate(
        self,
        record: ValidatedPathRecord,
        *,
        edge_costs: list[dict[str, float]] | None = None,
        evidence_by_id: dict[str, str] | None = None,
    ) -> list[KnowledgeEdge]:
        if record.status != "accepted":
            return []
        path = record.path
        current_node_id = "K0:root"
        current_k_facts: list[str] = []
        current_graph_facts: list[str] = []
        created_edges: list[KnowledgeEdge] = []
        for index, step in enumerate(sorted(path.steps, key=lambda item: item.step_index)):
            if step.produces_fact:
                current_k_facts.append(step.produces_fact)
            current_graph_facts.extend(step_graph_facts(step, evidence_by_id))
            level = infer_knowledge_level(
                current_k_facts,
                path.final_fact if index == len(path.steps) - 1 else None,
            )
            node_key = (level, fact_set_hash(current_graph_facts))
            target_node_id = self._node_index.get(node_key)
            if not target_node_id:
                target_node_id = f"K{level}:{node_key[1]}"
                self._node_index[node_key] = target_node_id
                self.graph.nodes.append(
                    KnowledgeNode(
                        node_id=target_node_id,
                        knowledge_level=level,
                        facts=sorted(set(current_graph_facts)),
                        label=LEVEL_LABELS.get(level, f"K{level}"),
                    )
                )
            if target_node_id == current_node_id:
                step_node_id = f"{current_node_id}@step{step.step_index}"
                if not any(node.node_id == step_node_id for node in self.graph.nodes):
                    self.graph.nodes.append(
                        KnowledgeNode(
                            node_id=step_node_id,
                            knowledge_level=level,
                            facts=sorted(set(current_graph_facts)),
                            label=LEVEL_LABELS.get(level, f"K{level}"),
                        )
                    )
                target_node_id = step_node_id
            edge = KnowledgeEdge(
                edge_id=f"{path.path_id}:step:{step.step_index}",
                source_id=current_node_id,
                target_id=target_node_id,
                step=step,
                path_id=path.path_id,
                cost=(edge_costs[index] if edge_costs and index < len(edge_costs) else {}),
                plausibility=record.plausibility.composite,
            )
            self.graph.edges.append(edge)
            created_edges.append(edge)
            current_node_id = target_node_id
        return created_edges

    def accumulated_facts(self) -> set[str]:
        facts: set[str] = set()
        for node in self.graph.nodes:
            facts.update(node.facts)
        return facts

    def max_knowledge_level(self) -> int:
        if not self.graph.nodes:
            return 0
        return max(node.knowledge_level for node in self.graph.nodes)


def assess_knowledge_alignment(
    steps: list[PathStep],
    *,
    final_fact: str | None = None,
) -> tuple[float, list[str], list[str]]:
    """Compare LLM-declared K levels with symbolically inferred levels.

    Returns (alignment_score, issues, hard_reject_reasons).
    Score is neutral 0.5 when no step declares a level (backward compatible).

    Hard rejects: non-monotonic declared K, or over-claiming (declared > inferred
    with gap >= 2). Under-claiming is audited via issues/score only.
    """
    sorted_steps = sorted(steps, key=lambda item: item.step_index)
    issues: list[str] = []
    hard_rejects: list[str] = []
    step_scores: list[float] = []
    facts: list[str] = []
    prev_declared: int | None = None
    declared_count = 0

    for index, step in enumerate(sorted_steps):
        if step.produces_fact:
            facts.append(step.produces_fact)
        inferred = infer_knowledge_level(
            facts,
            final_fact if index == len(sorted_steps) - 1 else None,
        )
        declared = step.declared_knowledge_level
        if declared is None:
            continue
        declared_count += 1
        if prev_declared is not None and declared < prev_declared:
            reason = f"step_{step.step_index}_knowledge_level_non_monotonic"
            issues.append(reason)
            hard_rejects.append(reason)
        prev_declared = declared
        gap = abs(declared - inferred)
        if gap == 0:
            step_scores.append(1.0)
        elif gap == 1:
            step_scores.append(0.75)
            issues.append(
                f"step_{step.step_index}_knowledge_level_mismatch:declared=K{declared},inferred=K{inferred}"
            )
        else:
            step_scores.append(0.35)
            reason = f"step_{step.step_index}_knowledge_level_mismatch:declared=K{declared},inferred=K{inferred}"
            issues.append(reason)
            if declared > inferred:
                hard_rejects.append(reason)

    if declared_count == 0:
        return 0.5, [], []
    score = round(sum(step_scores) / len(step_scores), 4)
    return score, issues, hard_rejects


def path_similarity(left: LLMPathProposal, right: LLMPathProposal) -> float:
    """Ordered tool-sequence similarity: matching tools at same index / max length."""
    left_tools = [step.tool.lower() for step in left.steps]
    right_tools = [step.tool.lower() for step in right.steps]
    if left_tools == right_tools:
        return 1.0
    max_len = max(len(left_tools), len(right_tools))
    if not max_len:
        return 1.0
    matches = sum(1 for left, right in zip(left_tools, right_tools) if left == right)
    return matches / max_len
