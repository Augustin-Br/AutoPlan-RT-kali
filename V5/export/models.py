"""Schemas for CyberRange scenario packs derived from V5 ranked_paths."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class CRActionParameter(BaseModel):
    name: str
    value: str | int | None = None
    description: str | None = None


class CRAction(BaseModel):
    """One LADE-oriented action mapped from a V5 PathStep."""

    name: str
    step_index: int
    tool: str
    tool_type: str
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    target_ip: str
    port: int | None = None
    service: str | None = None
    command: str
    parameters: list[CRActionParameter] = Field(default_factory=list)
    justification: str | None = None
    produces_fact: str | None = None
    autorun_eligible: bool = False
    requires_human: bool = True
    evidence_ids: list[str] = Field(default_factory=list)


class CRScenarioPath(BaseModel):
    path_id: str
    rank: int
    strategy: str = "balanced"
    plausibility: float = 0.0
    strategy_score: float = 0.0
    actions: list[CRAction] = Field(default_factory=list)


class InfinityObjective(BaseModel):
    objective_id: str
    title: str
    description: str
    validation: Literal["flag", "manual", "trainer"] = "manual"
    flag_placeholder: str | None = None
    related_path_id: str | None = None
    related_fact: str | None = None


class CRScenarioPack(BaseModel):
    """Portable pack: V5 ranked paths → LADE actions / Infinity objective stubs."""

    schema_version: Literal["cr_pack_v1"] = "cr_pack_v1"
    source_result: str | None = None
    attack_objective: str = ""
    attaquant_ip: str | None = None
    strategy: str = "balanced"
    top_k: int = 5
    scenarios: list[CRScenarioPath] = Field(default_factory=list)
    infinity_objectives: list[InfinityObjective] = Field(default_factory=list)
    roadmap_note: str = (
        "This pack is a data bridge for LADE Actions/Scenarios and Infinity stubs. "
        "It does not claim autonomous CyberRange control; exploits remain human-gated."
    )
    meta: dict[str, Any] = Field(default_factory=dict)
