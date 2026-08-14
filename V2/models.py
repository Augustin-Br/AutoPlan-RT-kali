"""Data models for the focused V2 attack-vector selector."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Confidence = Literal["low", "medium", "high"]
Complexity = Literal["low", "medium", "high", "unknown"]
ObjectiveFit = Literal["low", "medium", "high"]
NoiseLevel = Literal["low", "medium", "high"]
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class InfraServiceInput(BaseModel):
    port: int = Field(ge=1, le=65535)
    service: str = Field(min_length=1)
    version: str | None = None
    cve: str | list[str] | None = None
    notes: str | None = None

    @field_validator("cve", mode="before")
    @classmethod
    def normalize_empty_cve(cls, value: object) -> object:
        if value == "":
            return None
        return value


class InfraMachineInput(BaseModel):
    id: str = Field(min_length=1)
    ip: str = Field(min_length=1)
    zone: str | None = None
    os: str | None = None
    services: list[InfraServiceInput] = Field(default_factory=list)
    regles_firewall: str | None = None


class InfraDocumentInput(BaseModel):
    """Subset of the V1 infrastructure schema needed by V2."""

    entreprise: str | None = None
    reseaux: list[dict] = Field(default_factory=list)
    machines: list[InfraMachineInput] = Field(default_factory=list)
    attaquant: dict | None = None
    scenario_objective: str = Field(default="", alias="objective")
    apt_profile: str | None = None
    pistes_documentees: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class ServiceFinding(BaseModel):
    target_id: str
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str
    version: str | None = None
    cve: str | None = None
    notes: str | None = None


class ExpectedSOCLog(BaseModel):
    source: str
    event_type: str
    expected_signal: str
    confidence: Confidence = "medium"
    rationale: str | None = None


class AttackVectorCandidate(BaseModel):
    target_id: str
    target_ip: str
    port: int = Field(ge=1, le=65535)
    service: str
    version: str | None = None
    vulnerability: str | None = None
    metasploit_module: str | None = None
    module_exists: bool = False
    confidence: Confidence = "medium"
    complexity: Complexity = "unknown"
    expected_impact: str
    objective_fit: ObjectiveFit = "medium"
    noise_level: NoiseLevel = "medium"
    attack_relevance_score: int = Field(default=0, ge=0, le=100)
    score: int = Field(ge=0, le=100)
    selection_score: int = Field(default=0, ge=0, le=100)
    sort_strategy: str = "balanced"
    sort_explanation: str | None = None
    justification: str
    recommended_recon_commands: list[str] = Field(default_factory=list)
    next_manual_validation_steps: list[str] = Field(default_factory=list)
    soc_telemetry: list[str] = Field(default_factory=list)
    soc_log_sources: list[str] = Field(default_factory=list)
    soc_noise_score: int = Field(default=50, ge=0, le=100)
    soc_noise_level: NoiseLevel = "medium"
    detection_likelihood: NoiseLevel = "medium"
    log_volume_estimate: NoiseLevel = "medium"
    soc_rationale: str | None = None
    expected_soc_logs: list[ExpectedSOCLog] = Field(default_factory=list)
    soc_detection_hints: list[str] = Field(default_factory=list)
    soc_log_examples: list[str] = Field(default_factory=list)
    soc_mitre_tactics: list[str] = Field(default_factory=list)
    soc_observable_events: list[str] = Field(default_factory=list)
    scoring_details: list[str] = Field(default_factory=list)
    application_evidence: list[str] = Field(default_factory=list)
    rag_context: list[str] = Field(default_factory=list)


class LLMAgentReview(BaseModel):
    enabled: bool = False
    model: str | None = None
    status: Literal["not_requested", "applied", "rejected", "failed"] = "not_requested"
    selected_candidate: str | None = None
    summary: str | None = None
    guardrails: list[str] = Field(default_factory=list)


class AttackVectorRanking(BaseModel):
    objective: str
    best_vector: AttackVectorCandidate | None
    alternatives: list[AttackVectorCandidate] = Field(default_factory=list)
    rejected_vectors: list[AttackVectorCandidate] = Field(default_factory=list)
    sort_strategy: str = "balanced"
    selection_score_explanation: str | None = None
    score_semantics: dict[str, str] = Field(default_factory=dict)
    reasoning_summary: str
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recon_used: bool = False
    recon_evidence: list[dict] = Field(default_factory=list)
    recon_limitations: list[str] = Field(default_factory=list)
    llm_agent: LLMAgentReview | None = None


def load_infra_document(path: str | Path) -> InfraDocumentInput:
    import json

    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return InfraDocumentInput.model_validate(raw)


def extract_service_findings(infra: InfraDocumentInput) -> list[ServiceFinding]:
    findings: list[ServiceFinding] = []
    for machine in infra.machines:
        for service in machine.services:
            cve = service.cve
            if isinstance(cve, list):
                cve_text = ", ".join(str(item) for item in cve if item)
            else:
                cve_text = cve
            if not cve_text and service.notes:
                cves_from_notes = _CVE_RE.findall(service.notes)
                if cves_from_notes:
                    cve_text = ", ".join(dict.fromkeys(cves_from_notes))
            findings.append(
                ServiceFinding(
                    target_id=machine.id,
                    target_ip=machine.ip,
                    port=service.port,
                    service=service.service,
                    version=service.version,
                    cve=cve_text,
                    notes=service.notes,
                )
            )
    return findings

