"""Iterative LLM path loop with explicit stop conditions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from V2.rag_adapter import RAGAdapter
from V4.evidence_extractor import evidence_prompt_payload, extract_evidence_graph
from V5.capec_kb import CapecKnowledgeBase
from V5.cost_estimator import build_attack_path, estimate_edge_cost
from V5.infra_loader import load_v5_infra, to_v2_infra_input
from V5.knowledge_graph import KnowledgeGraphBuilder, path_similarity
from V5.llm_path_agent import LLMPathAgent
from V5.mitre_kb import MitreKnowledgeBase
from V5.models import LoopPromptContext, V5InfraDocument, V5Result
from V5.path_optimizer import estimate_max_paths, rank_paths
from V5.path_validator import PathValidator
from V5.rejection_counters import empty_rejection_counters, increment_rejection_counters
from V5.pattern_store import PatternStore
from V5.tool_registry import ToolRegistry


@dataclass
class PathLoopConfig:
    max_llm_rounds: int = 0
    max_consecutive_failures: int = 5
    max_similarity_rejections: int = 10
    similarity_threshold: float = 0.85
    plausibility_threshold: float = 0.60
    strategy: str = "balanced"
    top_k: int = 5
    rag_per_service_k: int = 8
    rag_module_prompt_limit: int = 40


@dataclass
class PathLoopState:
    accepted_paths: list = field(default_factory=list)
    rejected_records: list = field(default_factory=list)
    rounds: int = 0
    consecutive_failures: int = 0
    similarity_rejection_streak: int = 0
    stop_reason: str | None = None
    trace: dict[str, Any] = field(default_factory=dict)


class PathLoopOrchestrator:
    def __init__(
        self,
        *,
        tool_registry: ToolRegistry | None = None,
        mitre_kb: MitreKnowledgeBase | None = None,
        pattern_store: PatternStore | None = None,
        capec_kb: CapecKnowledgeBase | None = None,
        llm_agent: LLMPathAgent | None = None,
        validator: PathValidator | None = None,
    ) -> None:
        self.tool_registry = tool_registry or ToolRegistry.load()
        self.mitre_kb = mitre_kb or MitreKnowledgeBase.load()
        self.pattern_store = pattern_store or PatternStore.load()
        self.capec_kb = capec_kb or CapecKnowledgeBase.load()
        self.llm_agent = llm_agent or LLMPathAgent(tool_registry=self.tool_registry)
        self.validator = validator or PathValidator(
            tool_registry=self.tool_registry,
            mitre_kb=self.mitre_kb,
            pattern_store=self.pattern_store,
            capec_kb=self.capec_kb,
        )
        self.graph_builder = KnowledgeGraphBuilder()

    def run(
        self,
        infra: V5InfraDocument,
        *,
        rag: RAGAdapter,
        config: PathLoopConfig | None = None,
    ) -> V5Result:
        cfg = config or PathLoopConfig()
        state = PathLoopState()
        self.validator.plausibility_threshold = cfg.plausibility_threshold
        state.trace["rejection_counters"] = empty_rejection_counters()
        state.trace["loop_config"] = {
            "max_llm_rounds": cfg.max_llm_rounds,
            "max_consecutive_failures": cfg.max_consecutive_failures,
            "max_similarity_rejections": cfg.max_similarity_rejections,
            "similarity_threshold": cfg.similarity_threshold,
            "plausibility_threshold": cfg.plausibility_threshold,
        }
        infra_doc = to_v2_infra_input(infra)
        evidence_graph = extract_evidence_graph(infra_doc)
        evidence_index = evidence_graph.by_id()
        evidence_ids = set(evidence_index.keys())
        evidence_by_id = {item_id: item.kind for item_id, item in evidence_index.items()}
        evidence_payload = evidence_prompt_payload(evidence_graph)
        service_count = sum(len(machine.services) for machine in infra.machines)
        state.trace["estimated_max_paths"] = estimate_max_paths(
            machine_count=len(infra.machines),
            service_count=service_count,
        )

        while not state.stop_reason:
            if cfg.max_llm_rounds > 0 and state.rounds >= cfg.max_llm_rounds:
                state.stop_reason = "max_rounds"
                break
            if cfg.max_consecutive_failures > 0 and state.consecutive_failures >= cfg.max_consecutive_failures:
                state.stop_reason = "consecutive_failures"
                break
            if (
                cfg.max_similarity_rejections > 0
                and state.similarity_rejection_streak >= cfg.max_similarity_rejections
            ):
                state.stop_reason = "similarity_exhausted"
                break

            state.rounds += 1
            summaries = [f"{record.path.path_id}:{','.join(step.tool for step in record.path.steps)}" for record in state.accepted_paths]
            prompt_context = self._build_prompt_context(state)
            try:
                response = self.llm_agent.generate(
                    infra,
                    rag=rag,
                    evidence_payload=evidence_payload,
                    existing_path_summaries=summaries,
                    round_index=state.rounds,
                    loop_context=prompt_context,
                    rag_per_service_k=cfg.rag_per_service_k,
                    rag_module_prompt_limit=cfg.rag_module_prompt_limit,
                )
            except Exception as exc:
                state.consecutive_failures += 1
                state.trace.setdefault("llm_errors", []).append(str(exc))
                continue
            if response.exhausted or response.stop_reason == "llm_exhausted":
                state.stop_reason = "llm_exhausted"
                break
            if not response.path_proposals:
                state.consecutive_failures += 1
                continue

            round_accepted = 0
            round_failures = 0
            for proposal in response.path_proposals:
                record = self.validator.validate(
                    proposal,
                    infra=infra,
                    evidence_ids=evidence_ids,
                    evidence_by_id=evidence_by_id,
                )
                if any(
                    path_similarity(proposal, accepted.path) >= cfg.similarity_threshold
                    for accepted in state.accepted_paths
                ):
                    record.status = "rejected"
                    if "too_similar_to_existing_path" not in record.rejection_reasons:
                        record.rejection_reasons.append("too_similar_to_existing_path")
                if record.status == "accepted":
                    edge_costs = [estimate_edge_cost(step, tool_registry=self.tool_registry) for step in record.path.steps]
                    self.graph_builder.integrate(
                        record,
                        edge_costs=edge_costs,
                        evidence_by_id=evidence_by_id,
                    )
                    state.accepted_paths.append(record)
                    round_accepted += 1
                else:
                    state.rejected_records.append(record)
                    increment_rejection_counters(state.trace, record.rejection_reasons)
                    if "too_similar_to_existing_path" in record.rejection_reasons:
                        state.similarity_rejection_streak += 1
                    round_failures += 1

            if round_accepted:
                state.consecutive_failures = 0
                state.similarity_rejection_streak = 0
            elif round_failures:
                state.consecutive_failures += 1

            if (
                cfg.max_similarity_rejections > 0
                and state.similarity_rejection_streak >= cfg.max_similarity_rejections
            ):
                state.stop_reason = "similarity_exhausted"
                break

        attack_paths = [build_attack_path(record, tool_registry=self.tool_registry, strategy=cfg.strategy) for record in state.accepted_paths]
        ranked = rank_paths(attack_paths, strategy=cfg.strategy, top_k=cfg.top_k)
        state.trace.update(
            {
                "llm_mode": "live" if self.llm_agent.use_llm else "mock",
                "llm_provider": getattr(self.llm_agent, "provider", None),
                "llm_model": getattr(self.llm_agent, "model", None),
                "infra": None,
                "rounds": state.rounds,
                "accepted_count": len(state.accepted_paths),
                "rejected_count": len(state.rejected_records),
                "similarity_rejection_streak": state.similarity_rejection_streak,
                "stop_reason": state.stop_reason,
            }
        )
        return V5Result(
            graph=self.graph_builder.graph,
            accepted_paths=attack_paths,
            rejected_records=state.rejected_records,
            ranked_paths=ranked,
            strategy=cfg.strategy,
            trace=state.trace,
        )

    def _build_prompt_context(self, state: PathLoopState) -> LoopPromptContext:
        from V5.knowledge_graph import LEVEL_LABELS

        facts = sorted(self.graph_builder.accumulated_facts())
        level = self.graph_builder.max_knowledge_level()
        rejected_summaries: list[str] = []
        for record in state.rejected_records:
            tools = " -> ".join(step.tool for step in record.path.steps)
            reasons = "; ".join(record.rejection_reasons)
            rejected_summaries.append(f"{tools} | rejected: {reasons}")
        return LoopPromptContext(
            known_facts=facts,
            knowledge_level=level,
            knowledge_label=LEVEL_LABELS.get(level, f"K{level}"),
            rejected_summaries=rejected_summaries,
        )


def run_from_infra_path(
    infra_path: str,
    *,
    rag: RAGAdapter,
    config: PathLoopConfig | None = None,
    llm_agent: LLMPathAgent | None = None,
) -> V5Result:
    infra = load_v5_infra(infra_path)
    orchestrator = PathLoopOrchestrator(llm_agent=llm_agent)
    return orchestrator.run(infra, rag=rag, config=config)
