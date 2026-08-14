"""V5 data models — knowledge-state graph and LLM-built paths."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

KnowledgeLevel = Literal[0, 1, 2, 3, 4, 5]
Confidence = Literal["low", "medium", "high"]
ValidationStatus = Literal["accepted", "rejected", "pending"]
StopReason = Literal[
    "max_rounds",
    "consecutive_failures",
    "similarity_exhausted",
    "llm_exhausted",
    "manual",
]


class NetworkPolicy(BaseModel):
    """Structured defensive rule between zones or hosts."""

    from_zone: str | None = None
    to_zone: str | None = None
    from_ip: str | None = None
    to_ip: str | None = None
    allowed_ports: list[int] = Field(default_factory=list)
    denied_ports: list[int] = Field(default_factory=list)
    deny_all_else: bool = False
    description: str | None = None


class V5ServiceInput(BaseModel):
    port: int = Field(ge=1, le=65535)
    service: str = Field(min_length=1)
    version: str | None = None
    cve: str | list[str] | None = None
    service_observations: str | None = Field(default=None, alias="notes")

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @field_validator("cve", mode="before")
    @classmethod
    def normalize_empty_cve(cls, value: object) -> object:
        if value == "":
            return None
        return value


class V5MachineInput(BaseModel):
    id: str = Field(min_length=1)
    ip: str = Field(min_length=1)
    zone: str | None = None
    os: str | None = None
    services: list[V5ServiceInput] = Field(default_factory=list)
    regles_firewall: str | None = None
    security_notes: str | None = None

    model_config = ConfigDict(extra="allow")


class V5InfraDocument(BaseModel):
    """Extended infrastructure schema for V5 (backward-compatible aliases)."""

    entreprise: str | None = None
    reseaux: list[dict[str, Any]] = Field(default_factory=list)
    machines: list[V5MachineInput] = Field(default_factory=list)
    attaquant: dict[str, Any] | None = None
    attack_objective: str = Field(default="", alias="objective")
    scenario_objective: str | None = Field(default=None, alias="scenario_objective")
    apt_profile: str | None = None
    pistes_documentees: list[dict[str, Any]] = Field(default_factory=list)
    security_notes: str | None = None
    network_policies: list[NetworkPolicy] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    @model_validator(mode="after")
    def unify_objective(self) -> "V5InfraDocument":
        if not self.attack_objective:
            self.attack_objective = self.scenario_objective or ""
        return self


class PathStep(BaseModel):
    """One ordered action in an LLM-proposed path."""

    step_index: int = Field(ge=1)
    tool: str = Field(min_length=1, description="CLI tool or module name, e.g. hydra, nmap, exploit/...")
    tool_type: Literal[
        "scanner",
        "exploit_framework",
        "bruteforce",
        "web_client",
        "shell",
        "credential",
        "enumeration",
        "other",
    ] = "other"
    mitre_technique_id: str | None = Field(default=None, description="e.g. T1046")
    mitre_tactic: str | None = None
    target_ip: str
    port: int | None = Field(default=None, ge=1, le=65535)
    service: str | None = None
    produces_fact: str | None = None
    depends_on_step: int | None = Field(default=None, ge=1)
    evidence_ids: list[str] = Field(default_factory=list)
    justification: str | None = None
    declared_knowledge_level: KnowledgeLevel | None = Field(
        default=None,
        description="LLM-declared attacker knowledge level K0–K5 after this step (verified symbolically).",
    )
    estimated_destructiveness: float = Field(default=0.3, ge=0.0, le=1.0)


class LLMPathProposal(BaseModel):
    """Untrusted ordered path from the LLM."""

    path_id: str
    title: str | None = None
    hypothesis_summary: str | None = None
    target_ip: str
    final_fact: str | None = None
    expected_knowledge_level: KnowledgeLevel = 5
    confidence: Confidence = "medium"
    steps: list[PathStep] = Field(default_factory=list)
    stop_reason: StopReason | None = None
    evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_steps(self) -> "LLMPathProposal":
        if not self.steps:
            raise ValueError("LLMPathProposal requires at least one step")
        return self


class LLMPathResponse(BaseModel):
    reasoning_summary: str = ""
    path_proposals: list[LLMPathProposal] = Field(default_factory=list)
    stop_reason: StopReason | None = None
    exhausted: bool = False


class LoopPromptContext(BaseModel):
    """Incremental loop state injected into the LLM prompt each round."""

    known_facts: list[str] = Field(default_factory=list)
    knowledge_level: int = 0
    knowledge_label: str = "K0 External recon"
    rejected_summaries: list[str] = Field(default_factory=list)


class PlausibilityBreakdown(BaseModel):
    tool_score: float = 0.0
    mitre_score: float = 0.0
    pattern_score: float = 0.0
    capec_score: float = 0.0
    evidence_score: float = 0.0
    defense_score: float = 0.0
    knowledge_alignment_score: float = 0.0
    composite: float = 0.0
    hard_reject_reasons: list[str] = Field(default_factory=list)
    knowledge_alignment_issues: list[str] = Field(default_factory=list)


class ValidatedPathRecord(BaseModel):
    path: LLMPathProposal
    status: ValidationStatus
    plausibility: PlausibilityBreakdown
    rejection_reasons: list[str] = Field(default_factory=list)


class KnowledgeNode(BaseModel):
    node_id: str
    knowledge_level: KnowledgeLevel
    facts: list[str] = Field(default_factory=list)
    label: str | None = None


class KnowledgeEdge(BaseModel):
    edge_id: str
    source_id: str
    target_id: str
    step: PathStep
    path_id: str
    cost: dict[str, float] = Field(default_factory=dict)
    plausibility: float = 0.0


class KnowledgeGraph(BaseModel):
    nodes: list[KnowledgeNode] = Field(default_factory=list)
    edges: list[KnowledgeEdge] = Field(default_factory=list)


class AttackPath(BaseModel):
    path_id: str
    steps: list[PathStep]
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    total_cost: dict[str, float] = Field(default_factory=dict)
    plausibility: float = 0.0
    strategy_score: float = 0.0
    strategy: str = "balanced"


class V5Result(BaseModel):
    graph: KnowledgeGraph
    accepted_paths: list[AttackPath] = Field(default_factory=list)
    rejected_records: list[ValidatedPathRecord] = Field(default_factory=list)
    ranked_paths: list[AttackPath] = Field(default_factory=list)
    strategy: str = "balanced"
    trace: dict[str, Any] = Field(default_factory=dict)

    def model_dump_for_export(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
