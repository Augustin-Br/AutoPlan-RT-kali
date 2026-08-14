"""Closed catalog of allowlisted recon scan templates.

The LLM may only propose template_id + parameters. Commands are built here
(or via V2 recon_policy helpers), never from free-form shell text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from V2.recon_models import ReconCommandPlan, ReconObservation
from V2.recon_policy import (
    build_http_followup_plan,
    build_protocol_followup_plan,
    build_smb_followup_plan,
    build_web_probe_plan,
    build_wpscan_followup_plan,
    command_is_safe,
    is_private_lab_target,
)
from V5.recon.models import ScanProposal

HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 5601, 7000, 8000, 8080, 8180, 8443, 9000}


@dataclass(frozen=True)
class ScanTemplate:
    template_id: str
    description: str
    tools: tuple[str, ...]
    aggressive_only: bool = False


TEMPLATES: dict[str, ScanTemplate] = {
    "nmap_sv_light": ScanTemplate(
        "nmap_sv_light",
        "Lightweight nmap service/version scan on the target IP.",
        ("nmap",),
    ),
    "nmap_sv_ports": ScanTemplate(
        "nmap_sv_ports",
        "nmap -sV restricted to explicit ports.",
        ("nmap",),
    ),
    "curl_headers": ScanTemplate(
        "curl_headers",
        "HTTP(S) response headers via curl -I.",
        ("curl",),
    ),
    "dirb_web_probe": ScanTemplate(
        "dirb_web_probe",
        "Bounded dirb directory discovery (-S -r).",
        ("dirb",),
    ),
    "wpscan_enum": ScanTemplate(
        "wpscan_enum",
        "WPScan plugin/theme(/user) enumeration after WordPress evidence.",
        ("wpscan",),
    ),
    "wpscan_enum_users": ScanTemplate(
        "wpscan_enum_users",
        "WPScan with user enumeration (aggressive profile).",
        ("wpscan",),
        aggressive_only=True,
    ),
    "smb_metadata": ScanTemplate(
        "smb_metadata",
        "Nmap SMB OS/protocol/security-mode scripts (non-vuln).",
        ("nmap",),
    ),
    "ftp_metadata": ScanTemplate(
        "ftp_metadata",
        "Nmap ftp-anon/ftp-syst metadata scripts.",
        ("nmap",),
    ),
    "ssh_metadata": ScanTemplate(
        "ssh_metadata",
        "Nmap SSH hostkey/algorithm enumeration.",
        ("nmap",),
    ),
    "db_metadata": ScanTemplate(
        "db_metadata",
        "Nmap MySQL/PgSQL/MSSQL info scripts.",
        ("nmap",),
    ),
    "tls_metadata": ScanTemplate(
        "tls_metadata",
        "Nmap ssl-cert/ssl-enum-ciphers on TLS ports.",
        ("nmap",),
    ),
}


def list_templates(*, aggressive: bool = False) -> list[ScanTemplate]:
    return [
        template
        for template in TEMPLATES.values()
        if aggressive or not template.aggressive_only
    ]


def catalog_prompt_block(*, aggressive: bool = False) -> str:
    lines = ["Available recon templates (propose only these template_id values):"]
    for template in list_templates(aggressive=aggressive):
        flag = " [aggressive]" if template.aggressive_only else ""
        lines.append(f"- {template.template_id}{flag}: {template.description}")
    return "\n".join(lines)


def compile_proposal(
    proposal: ScanProposal,
    *,
    aggressive: bool = False,
    profile: str = "safe",
    sort_strategy: str = "success",
) -> tuple[list[ReconCommandPlan], str | None]:
    """Compile a proposal into safe ReconCommandPlan list, or return a rejection reason."""

    template = TEMPLATES.get(proposal.template_id)
    if template is None:
        return [], f"unknown_template:{proposal.template_id}"
    if template.aggressive_only and not aggressive:
        return [], f"aggressive_required:{proposal.template_id}"
    if not is_private_lab_target(proposal.target_ip):
        return [], f"non_lab_target:{proposal.target_ip}"

    builder = _BUILDERS.get(proposal.template_id)
    if builder is None:
        return [], f"no_builder:{proposal.template_id}"

    plans = builder(proposal, profile=profile, sort_strategy=sort_strategy)
    safe: list[ReconCommandPlan] = []
    for plan in plans:
        if not plan.command or not command_is_safe(plan.command):
            return [], f"unsafe_command:{proposal.template_id}"
        safe.append(plan)
    if not safe:
        return [], f"empty_plan:{proposal.template_id}"
    return safe, None


def suggest_applicable_templates(
    observations: list[ReconObservation],
    *,
    aggressive: bool = False,
    already_used: set[str] | None = None,
) -> list[str]:
    """Heuristic hints for the LLM / operator about remaining useful templates."""

    used = already_used or set()
    ids: list[str] = []
    ports_by_service: dict[str, set[int]] = {}
    for observation in observations:
        key = (observation.service or "").lower()
        ports_by_service.setdefault(key, set()).add(observation.port)
        if observation.port in HTTP_LIKE_PORTS or "http" in key:
            ports_by_service.setdefault("http", set()).add(observation.port)
        techs = " ".join(observation.detected_technologies).lower()
        if "wordpress" in techs or any("wp-" in path.lower() for path in observation.web_paths):
            ports_by_service.setdefault("wordpress", set()).add(observation.port)

    def _add(template_id: str) -> None:
        if template_id in used:
            return
        template = TEMPLATES.get(template_id)
        if template is None:
            return
        if template.aggressive_only and not aggressive:
            return
        ids.append(template_id)

    if ports_by_service.get("http") or ports_by_service.get("https"):
        _add("curl_headers")
        _add("dirb_web_probe")
    if ports_by_service.get("wordpress"):
        _add("wpscan_enum")
        _add("wpscan_enum_users")
    if any(port in {139, 445} for ports in ports_by_service.values() for port in ports):
        _add("smb_metadata")
    if any(port == 21 or "ftp" in service for service, ports in ports_by_service.items() for port in ports):
        _add("ftp_metadata")
    if any(port == 22 or "ssh" in service for service, ports in ports_by_service.items() for port in ports):
        _add("ssh_metadata")
    if any(
        port in {3306, 5432, 1433} or service in {"mysql", "postgresql", "ms-sql", "mssql"}
        for service, ports in ports_by_service.items()
        for port in ports
    ):
        _add("db_metadata")
    if any(port in {443, 8443, 465, 993, 995} for ports in ports_by_service.values() for port in ports):
        _add("tls_metadata")
    return ids


BuilderFn = Callable[..., list[ReconCommandPlan]]


def _build_nmap_sv_light(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    return [
        ReconCommandPlan(
            tool="nmap",
            target_ip=proposal.target_ip,
            ports=[],
            profile=profile,
            command=f"nmap -sV --version-light -Pn {proposal.target_ip}",
            rationale=proposal.rationale or "Lightweight service/version detection.",
            safety_status="allowed",
        )
    ]


def _build_nmap_sv_ports(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    if not proposal.ports:
        return []
    ports = ",".join(str(port) for port in sorted(set(proposal.ports)))
    return [
        ReconCommandPlan(
            tool="nmap",
            target_ip=proposal.target_ip,
            ports=sorted(set(proposal.ports)),
            profile=profile,
            command=f"nmap -sV -Pn -p {ports} {proposal.target_ip}",
            rationale=proposal.rationale or "Service/version detection on explicit ports.",
            safety_status="allowed",
        )
    ]


def _build_curl_headers(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [80]
    return build_http_followup_plan(proposal.target_ip, ports, profile=profile)


def _build_dirb(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [80]
    hostnames = (proposal.hostname,) if proposal.hostname else ()
    return build_web_probe_plan(proposal.target_ip, ports, hostnames=hostnames, profile=profile)


def _build_wpscan(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    if not proposal.ports:
        return []
    return build_wpscan_followup_plan(
        proposal.target_ip,
        proposal.ports[0],
        base_path=proposal.base_path or "/",
        sort_strategy=sort_strategy,
        profile=profile,
    )


def _build_wpscan_users(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    return _build_wpscan(proposal, profile=profile, sort_strategy="success")


def _build_smb(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [445]
    return build_smb_followup_plan(proposal.target_ip, ports, profile=profile)


def _build_ftp(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [21]
    return build_protocol_followup_plan(proposal.target_ip, {"ftp": ports}, profile=profile)


def _build_ssh(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [22]
    return build_protocol_followup_plan(proposal.target_ip, {"ssh": ports}, profile=profile)


def _build_db(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [3306]
    return build_protocol_followup_plan(proposal.target_ip, {"db": ports}, profile=profile)


def _build_tls(proposal: ScanProposal, *, profile: str, sort_strategy: str) -> list[ReconCommandPlan]:
    del sort_strategy
    ports = proposal.ports or [443]
    return build_protocol_followup_plan(proposal.target_ip, {"tls": ports}, profile=profile)


_BUILDERS: dict[str, BuilderFn] = {
    "nmap_sv_light": _build_nmap_sv_light,
    "nmap_sv_ports": _build_nmap_sv_ports,
    "curl_headers": _build_curl_headers,
    "dirb_web_probe": _build_dirb,
    "wpscan_enum": _build_wpscan,
    "wpscan_enum_users": _build_wpscan_users,
    "smb_metadata": _build_smb,
    "ftp_metadata": _build_ftp,
    "ssh_metadata": _build_ssh,
    "db_metadata": _build_db,
    "tls_metadata": _build_tls,
}
