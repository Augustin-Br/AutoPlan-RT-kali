"""Pydantic models for bounded reconnaissance planning."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


SafetyStatus = Literal["allowed", "skipped", "blocked"]


class WebPageFinding(BaseModel):
    hostname: str | None = None
    path: str
    url: str
    status_code: int | None = None
    content_length: int | None = None
    title: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    meta_generator: str | None = None
    forms: list[str] = Field(default_factory=list)
    form_actions: list[str] = Field(default_factory=list)
    form_methods: list[str] = Field(default_factory=list)
    form_parameters: list[str] = Field(default_factory=list)
    input_fields: list[str] = Field(default_factory=list)
    query_parameters: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)
    detected_technologies: list[str] = Field(default_factory=list)
    extracted_versions: list[str] = Field(default_factory=list)
    interesting_reasons: list[str] = Field(default_factory=list)
    workflow_tags: list[str] = Field(default_factory=list)
    content_fingerprint: str | None = None
    raw_content: str | None = None
    soft_404: bool = False
    soft_404_reason: str | None = None
    low_content: bool = False
    low_content_reason: str | None = None
    selected_by: Literal["heuristic", "llm"] = "heuristic"
    discovery_source: str = "dirb"


class ReconCommandPlan(BaseModel):
    tool: str
    target_ip: str
    hostname: str | None = None
    ports: list[int] = Field(default_factory=list)
    profile: str = "safe"
    command: str
    rationale: str
    safety_status: SafetyStatus = "allowed"
    exit_code: int | None = None
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    duration_seconds: float | None = None


class ReconObservation(BaseModel):
    target_ip: str
    port: int
    hostname: str | None = None
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    product: str | None = None
    cpe: list[str] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)
    ftp_anonymous: bool | None = None
    ftp_features: list[str] = Field(default_factory=list)
    ssh_hostkeys: list[str] = Field(default_factory=list)
    ssh_algorithms: list[str] = Field(default_factory=list)
    db_info: dict[str, str] = Field(default_factory=dict)
    rpc_services: list[str] = Field(default_factory=list)
    nfs_exports: list[str] = Field(default_factory=list)
    tls_cert: dict[str, str] = Field(default_factory=dict)
    tls_ciphers: list[str] = Field(default_factory=list)
    smb_os: str | None = None
    smb_computer_name: str | None = None
    smb_domain: str | None = None
    smb_workgroup: str | None = None
    smb_dialects: list[str] = Field(default_factory=list)
    smb_security_mode: dict[str, str] = Field(default_factory=dict)
    web_headers: dict[str, str] = Field(default_factory=dict)
    web_paths: list[str] = Field(default_factory=list)
    web_vhosts: list[str] = Field(default_factory=list)
    web_pages: list[WebPageFinding] = Field(default_factory=list)
    detected_technologies: list[str] = Field(default_factory=list)
    raw_evidence_ref: str | None = None


class ReconReport(BaseModel):
    infra_path: str
    generated_at: datetime
    commands_planned: list[ReconCommandPlan] = Field(default_factory=list)
    commands_executed: list[ReconCommandPlan] = Field(default_factory=list)
    observations: list[ReconObservation] = Field(default_factory=list)
    skipped_commands: list[ReconCommandPlan] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
