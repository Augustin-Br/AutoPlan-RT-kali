"""Pydantic models for the V4 symbolic attack graph."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


AccessLevel = Literal["none", "network", "user", "root"]
NodeType = Literal["attacker", "host", "service", "credential", "data", "objective", "state"]
TechniqueType = Literal[
    "scan",
    "enumeration",
    "exploit",
    "web_investigation",
    "credential",
    "pivot",
]
SourceType = Literal["deterministic", "rag", "llm_hypothesis", "learned_cost"]
ValidationStatus = Literal["accepted", "rejected", "unvalidated"]
LLMRelevanceStatus = Literal[
    "not_assessed",
    "accepted_and_relevant",
    "accepted_but_not_relevant",
    "rejected",
]
Confidence = Literal["low", "medium", "high"]
PathStrategy = Literal["success", "stealth", "balanced", "fast", "cheap"]
EvidenceKind = Literal[
    "web_path",
    "login_surface",
    "wordlist_resource",
    "config_file",
    "source_metadata",
    "upload_surface",
    "file_parameter",
    "cms_surface",
    "database_service",
    "server_status",
    "soft_404",
    "technology",
    "sensitive_resource",
    "encoded_resource",
    "admin_capability",
    "local_user",
    "local_hash",
    "ssh_service",
    "suid_binary",
    "privilege_escalation_hint",
    "ftp_service",
    "ftp_credential_clue",
    "sql_injection_parameter",
    "webmail_surface",
    "mail_secret",
    "backdoor_surface",
    "backdoor_credential",
    "local_secret",
    "sudo_rights",
    "local_suid_helper_binary",
    "path_hijack_privilege_escalation",
    "local_command_injection_binary",
]
EvidenceSource = Literal["deterministic", "llm_extracted_candidate"]
WorkflowValidationStatus = Literal["accepted", "rejected"]


ACCESS_RANK: dict[str, int] = {
    "none": 0,
    "network": 1,
    "user": 2,
    "root": 3,
}


class Preconditions(BaseModel):
    """Facts that must be true before a symbolic action can enter the graph."""

    requires_access: AccessLevel = "network"
    requires_credentials: bool = False
    requires_prior_recon: bool = False
    required_credentials: list[str] = Field(default_factory=list)
    required_facts: list[str] = Field(default_factory=list)
    required_zones: list[str] = Field(default_factory=list)
    allowed_services: list[str] = Field(default_factory=list)


class Postconditions(BaseModel):
    """Symbolic effects added to the graph if the action succeeds."""

    grants_access: AccessLevel = "none"
    grants_credentials: list[str] = Field(default_factory=list)
    grants_information: list[str] = Field(default_factory=list)
    grants_pivot: bool = False
    reachable_zones: list[str] = Field(default_factory=list)
    discovered_services: list[str] = Field(default_factory=list)
    objective_tags: list[str] = Field(default_factory=list)


class CostVector(BaseModel):
    """Estimated operational footprint for one symbolic action."""

    success_probability: float = Field(ge=0.0, le=1.0)
    detection_probability: float = Field(ge=0.0, le=1.0)
    log_count_estimate: int = Field(ge=0)
    request_count: int = Field(ge=0)
    bandwidth_bytes: int = Field(ge=0)
    cpu_seconds: float = Field(ge=0.0)
    time_minutes: float = Field(ge=0.0)
    operational_risk: float = Field(ge=0.0, le=1.0)
    disk_artifact_count: int = Field(default=0, ge=0)
    memory_only_execution: bool = False
    service_crash_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_complexity: float = Field(default=0.3, ge=0.0, le=1.0)
    confidence: Confidence = "medium"
    log_sources: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    detection_likelihood: Literal["low", "medium", "high"] = "medium"
    rationale: str | None = None
    attacker_risk: float = Field(default=0.0, ge=0.0, le=1.0)


class AttackGraphNode(BaseModel):
    id: str = Field(min_length=1)
    node_type: NodeType
    machine_id: str | None = None
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    service: str | None = None
    version: str | None = None
    zone: str | None = None
    access_level: AccessLevel = "none"
    known_cves: list[str] = Field(default_factory=list)
    known_modules: list[str] = Field(default_factory=list)
    app_matches: list[str] = Field(default_factory=list)
    facts: list[str] = Field(default_factory=list)
    label: str | None = None

    @field_validator("service")
    @classmethod
    def normalize_service(cls, value: str | None) -> str | None:
        return value.strip() if isinstance(value, str) and value.strip() else value


class AttackGraphEdge(BaseModel):
    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    target_service_id: str | None = None
    target_machine_id: str | None = None
    technique: str = Field(min_length=1)
    technique_type: TechniqueType
    preconditions: Preconditions
    postconditions: Postconditions
    cost: CostVector
    commands: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    source_type: SourceType = "deterministic"
    validation_status: ValidationStatus = "accepted"
    llm_relevance_status: LLMRelevanceStatus = "not_assessed"
    llm_relevance_reason: str | None = None
    source_path_id: str | None = None
    step_index: int | None = Field(default=None, ge=1)
    depends_on_step: int | None = Field(default=None, ge=1)
    unlocks_fact: str | None = None
    description: str | None = None


class AttackState(BaseModel):
    """Compact symbolic state used by graph expansion."""

    id: str = "state:0"
    depth: int = Field(default=0, ge=0)
    access_by_host: dict[str, AccessLevel] = Field(default_factory=dict)
    known_credentials: list[str] = Field(default_factory=list)
    known_facts: list[str] = Field(default_factory=list)
    reachable_zones: list[str] = Field(default_factory=list)
    reached_nodes: list[str] = Field(default_factory=list)

    def access_for(self, host_id: str | None) -> AccessLevel:
        if not host_id:
            return "network"
        return self.access_by_host.get(host_id, "network")

    def with_edge_effects(self, edge: AttackGraphEdge, target_node: AttackGraphNode | None) -> "AttackState":
        host_id = target_node.machine_id if target_node else None
        access_by_host = dict(self.access_by_host)
        if host_id:
            current = access_by_host.get(host_id, "network")
            if ACCESS_RANK[edge.postconditions.grants_access] > ACCESS_RANK[current]:
                access_by_host[host_id] = edge.postconditions.grants_access

        known_credentials = list(
            dict.fromkeys(self.known_credentials + edge.postconditions.grants_credentials)
        )
        known_facts = list(
            dict.fromkeys(
                self.known_facts
                + edge.postconditions.grants_information
                + edge.postconditions.discovered_services
                + edge.postconditions.objective_tags
                + _workflow_step_effects(edge)
            )
        )
        reachable_zones = list(dict.fromkeys(self.reachable_zones + edge.postconditions.reachable_zones))
        reached_nodes = list(dict.fromkeys(self.reached_nodes + [edge.target]))
        return AttackState(
            id=f"state:{self.depth + 1}:{edge.id}",
            depth=self.depth + 1,
            access_by_host=access_by_host,
            known_credentials=known_credentials,
            known_facts=known_facts,
            reachable_zones=reachable_zones,
            reached_nodes=reached_nodes,
        )

    def fingerprint(self) -> tuple:
        return (
            tuple(sorted(self.access_by_host.items())),
            tuple(sorted(self.known_credentials)),
            tuple(sorted(self.known_facts)),
            tuple(sorted(self.reachable_zones)),
            tuple(sorted(self.reached_nodes)),
        )


class AttackGraph(BaseModel):
    nodes: dict[str, AttackGraphNode] = Field(default_factory=dict)
    edges: list[AttackGraphEdge] = Field(default_factory=list)
    objective: str = ""
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    model_config = ConfigDict(validate_assignment=True)

    def add_node(self, node: AttackGraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackGraphEdge) -> bool:
        if edge.id in {item.id for item in self.edges}:
            return False
        self.edges.append(edge)
        return True

    def outgoing(self, source: str) -> list[AttackGraphEdge]:
        return [edge for edge in self.edges if edge.source == source]

    def incoming(self, target: str) -> list[AttackGraphEdge]:
        return [edge for edge in self.edges if edge.target == target]


class AttackPath(BaseModel):
    edges: list[AttackGraphEdge]
    total_success_probability: float = Field(ge=0.0, le=1.0)
    total_attacker_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    total_log_count: int = Field(ge=0)
    total_requests: int = Field(ge=0)
    total_bandwidth_bytes: int = Field(ge=0)
    total_cpu_seconds: float = Field(ge=0.0)
    total_time_minutes: float = Field(ge=0.0)
    total_detection_probability: float = Field(ge=0.0, le=1.0)
    total_disk_artifact_count: int = Field(default=0, ge=0)
    memory_only_execution: bool = False
    total_service_crash_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    max_attack_complexity: float = Field(default=0.0, ge=0.0, le=1.0)
    path_score: float
    strategy: str
    justification: str

    @model_validator(mode="after")
    def require_edges(self) -> "AttackPath":
        if not self.edges:
            raise ValueError("AttackPath requires at least one edge")
        return self


class EvidenceItem(BaseModel):
    """Structured static evidence extracted from service notes for LLM planning."""

    id: str = Field(min_length=1)
    target_id: str
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str
    kind: EvidenceKind
    value: str
    tags: list[str] = Field(default_factory=list)
    status: str | None = None
    source_text: str | None = None
    source: EvidenceSource = "deterministic"


class EvidenceGraph(BaseModel):
    """Auditable evidence layer given to the workflow-planning LLM."""

    items: list[EvidenceItem] = Field(default_factory=list)

    def by_id(self) -> dict[str, EvidenceItem]:
        return {item.id: item for item in self.items}

    def ids(self) -> set[str]:
        return {item.id for item in self.items}


class LLMEvidenceCandidate(BaseModel):
    """Untrusted evidence candidate extracted by the LLM from service notes."""

    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    kind: EvidenceKind
    value: str = Field(min_length=1)
    source_quote: str = Field(min_length=1)
    confidence: Confidence = "medium"
    tags: list[str] = Field(default_factory=list)
    rationale: str | None = None


class LLMEvidenceExtractionResponse(BaseModel):
    """LLM output for candidate evidence extraction before validation."""

    reasoning_summary: str = "Candidats de preuves applicatives extraits pour validation."
    candidates: list[LLMEvidenceCandidate] = Field(default_factory=list)


class LLMActionProposal(BaseModel):
    """Untrusted action proposal returned by the LLM before validation."""

    source: str = "attacker"
    source_path_id: str | None = None
    step_index: int | None = Field(default=None, ge=1)
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    technique: str
    technique_type: TechniqueType
    preconditions: Preconditions = Field(default_factory=Preconditions)
    postconditions: Postconditions = Field(default_factory=Postconditions)
    estimated_cost: CostVector | None = None
    intended_goal_fact: str | None = None
    unlocks_fact: str | None = None
    depends_on_step: int | None = Field(default=None, ge=1)
    objective_relevance: str | None = None
    justification: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class LLMPathStep(BaseModel):
    """One untrusted step in an LLM-proposed attack path."""

    step_index: int = Field(ge=1)
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    technique: str
    technique_type: TechniqueType
    preconditions: Preconditions = Field(default_factory=Preconditions)
    postconditions: Postconditions = Field(default_factory=Postconditions)
    intended_goal_fact: str | None = None
    unlocks_fact: str | None = None
    depends_on_step: int | None = Field(default=None, ge=1)
    objective_relevance: str | None = None
    justification: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class LLMPathProposal(BaseModel):
    """Untrusted LLM-proposed path, validated step by step before graph insertion."""

    path_id: str
    objective: str | None = None
    strategy_rationale: str | None = None
    intended_goal_fact: str | None = None
    steps: list[LLMPathStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_steps(self) -> "LLMPathProposal":
        if not self.steps:
            raise ValueError("LLMPathProposal requires at least one step")
        return self


class LLMWorkflowStep(BaseModel):
    """One step in an LLM semantic workflow before conversion to graph actions."""

    step_index: int = Field(ge=1)
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    technique: str
    technique_type: TechniqueType = "web_investigation"
    preconditions: Preconditions = Field(default_factory=Preconditions)
    postconditions: Postconditions = Field(default_factory=Postconditions)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    produces_fact: str | None = None
    depends_on_step: int | None = Field(default=None, ge=1)
    objective_relevance: str | None = None
    justification: str | None = None


class LLMWorkflowProposal(BaseModel):
    """Untrusted LLM-proposed application workflow grounded in evidence IDs."""

    workflow_id: str
    title: str | None = None
    hypothesis_type: str
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    final_fact: str | None = None
    confidence: Confidence = "medium"
    evidence_ids: list[str] = Field(default_factory=list)
    steps: list[LLMWorkflowStep] = Field(default_factory=list)
    expected_outcome: Literal["candidate", "reject"] = "candidate"
    rejection_reason: str | None = None

    @model_validator(mode="after")
    def require_steps(self) -> "LLMWorkflowProposal":
        if not self.steps:
            raise ValueError("LLMWorkflowProposal requires at least one step")
        return self


class V4AttackGraphResult(BaseModel):
    graph: AttackGraph
    paths: list[AttackPath] = Field(default_factory=list)
    strategy: str = "balanced"
    top_k: int = Field(default=3, ge=1)
    llm_enabled: bool = False
    trace: dict = Field(default_factory=dict)

    def model_dump_for_export(self) -> dict:
        return self.model_dump(mode="json")


def _workflow_step_effects(edge: AttackGraphEdge) -> list[str]:
    effects: list[str] = []
    if edge.source_path_id and edge.step_index:
        effects.append(f"llm_step:{edge.source_path_id}:{edge.step_index}")
    if edge.unlocks_fact:
        effects.append(edge.unlocks_fact)
    return effects

