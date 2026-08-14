"""Models for the optional V5 autonomous reconnaissance phase."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from V2.recon_models import ReconCommandPlan, ReconReport
from V5.models import V5InfraDocument

ReconLevel = Literal[0, 1, 2]


class ReconBudget(BaseModel):
    max_commands: int = Field(default=40, ge=1)
    max_seconds: float = Field(default=600.0, gt=0)
    max_llm_rounds: int = Field(default=3, ge=0)


class ReconRunConfig(BaseModel):
    """Operator knobs for the recon phase (separate from the attack-path loop)."""

    level: ReconLevel = 0
    execute: bool = False
    aggressive: bool = False
    scan_tools: tuple[str, ...] = ("nmap", "curl", "dirb", "wpscan")
    scan_timeout_seconds: int = Field(default=90, ge=5)
    budget: ReconBudget = Field(default_factory=ReconBudget)
    web_probe: bool = True
    smb_probe: bool = True
    protocol_probe: bool = True
    objective: str = "Identify and draft plausible attack scenarios for authorized SOC training."
    target_hostnames: tuple[str, ...] = ()
    llm_provider: str | None = None
    llm_model: str | None = None


class ScanProposal(BaseModel):
    """LLM-proposed scan: template id only — never a free-form shell command."""

    template_id: str
    target_ip: str
    ports: list[int] = Field(default_factory=list)
    rationale: str = ""
    base_path: str | None = None
    hostname: str | None = None


class ScanProposalBatch(BaseModel):
    proposals: list[ScanProposal] = Field(default_factory=list)
    stop_reason: str | None = None


class InfraDiff(BaseModel):
    ports_added: list[dict[str, Any]] = Field(default_factory=list)
    ports_updated: list[dict[str, Any]] = Field(default_factory=list)
    machines_added: list[str] = Field(default_factory=list)
    notes_enriched: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class ReconPhaseResult(BaseModel):
    """Full audit artifact for one recon phase."""

    config: ReconRunConfig
    seed_mode: Literal["target_ip", "infra"]
    seed_ips: list[str] = Field(default_factory=list)
    reports: list[ReconReport] = Field(default_factory=list)
    infra_before: V5InfraDocument | None = None
    infra_after: V5InfraDocument
    diff: InfraDiff = Field(default_factory=InfraDiff)
    commands_planned: list[ReconCommandPlan] = Field(default_factory=list)
    commands_executed: list[ReconCommandPlan] = Field(default_factory=list)
    commands_skipped: list[ReconCommandPlan] = Field(default_factory=list)
    proposals_accepted: list[ScanProposal] = Field(default_factory=list)
    proposals_rejected: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    stop_reason: str = "completed"
    elapsed_seconds: float = 0.0

    def trace_payload(self) -> dict[str, Any]:
        return {
            "seed_mode": self.seed_mode,
            "seed_ips": self.seed_ips,
            "level": self.config.level,
            "execute": self.config.execute,
            "aggressive": self.config.aggressive,
            "stop_reason": self.stop_reason,
            "elapsed_seconds": self.elapsed_seconds,
            "commands_planned": len(self.commands_planned),
            "commands_executed": len(self.commands_executed),
            "commands_skipped": len(self.commands_skipped),
            "proposals_accepted": [p.model_dump() for p in self.proposals_accepted],
            "proposals_rejected": self.proposals_rejected,
            "diff": self.diff.model_dump(),
            "limitations": self.limitations,
        }
