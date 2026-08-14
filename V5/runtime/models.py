"""Models for HITL ranked-path runtime sessions."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from V5.models import AttackPath, PathStep

OperatorStepAction = Literal["y", "n", "skip", "abort"]
AllowlistAction = Literal["add", "skip", "skip_all", "abort_path"]
StepMode = Literal["auto", "manual"]
StepStatus = Literal["success", "fail", "skipped", "rejected", "aborted"]
PathAttemptStatus = Literal["success", "blocked", "aborted", "skipped"]


class AllowlistDecision(BaseModel):
    tool: str
    action: AllowlistAction
    note: str | None = None
    auto_run_eligible_after: bool = False


class StepOutcome(BaseModel):
    path_id: str
    path_rank: int
    step_index: int
    tool: str
    mode: StepMode
    action: OperatorStepAction
    status: StepStatus
    suggested_command: str | None = None
    executed_command: str | None = None
    exit_code: int | None = None
    operator_note: str | None = None
    stdout_excerpt: str | None = None


class PathAttempt(BaseModel):
    path_id: str
    path_rank: int
    status: PathAttemptStatus
    allowlist_decisions: list[AllowlistDecision] = Field(default_factory=list)
    step_outcomes: list[StepOutcome] = Field(default_factory=list)
    reason: str | None = None


class RuntimeSession(BaseModel):
    lab_ack: bool = False
    base_allowlist: list[str] = Field(default_factory=list)
    session_allowlist: list[str] = Field(default_factory=list)
    attempts: list[PathAttempt] = Field(default_factory=list)
    stop_reason: str = "completed"
    successful_path_id: str | None = None
    trace: dict[str, Any] = Field(default_factory=dict)

    def effective_allowlist(self) -> set[str]:
        return set(self.base_allowlist) | set(self.session_allowlist)


class RuntimeConfig(BaseModel):
    top_k: int = 5
    timeout_seconds: int = 90
    exploit_timeout_seconds: int = 300
    lab_ack: bool = False
    # Lab-only autonomous agent mode (requires --i-understand-lab-only at CLI).
    auto_execute: bool = False
    allow_auto_exploits: bool = False
    auto_promote_missing_tools: bool = False
    max_step_retries: int = 2
    skip_failed_recon: bool = True
