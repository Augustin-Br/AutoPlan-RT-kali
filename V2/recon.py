"""Bounded reconnaissance planning and safe execution entry points."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib import error, request

from V2.recon_models import ReconCommandPlan, ReconObservation, ReconReport
from V2.recon_parser import (
    parse_curl_headers,
    parse_nmap_protocol_metadata,
    parse_nmap_smb_metadata,
    parse_nmap_sv,
)
from V2.recon_policy import (
    DEFAULT_TOOLS,
    IP_ONLY_SAFE_TOOLS,
    DEFAULT_VHOST_PREFIXES,
    build_command_plan,
    build_http_followup_plan,
    build_ip_command_plan,
    build_protocol_followup_plan,
    build_smb_followup_plan,
    build_web_probe_plan,
    build_wpscan_followup_plan,
    command_is_safe,
)
from V2.web_enrichment import WebPathCandidate, fetch_web_page_findings, parse_dirb_candidates, select_web_candidates

DEFAULT_SCAN_TIMEOUT_SECONDS = 90
HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 5601, 7000, 8000, 8080, 8180, 8443, 9000}
NON_HTTP_TLS_PORTS = {465, 636, 993, 995}
FALLBACK_WEB_PATHS = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/login",
    "/login.php",
    "/admin",
    "/admin.php",
    "/dashboard",
    "/api",
    "/config",
    "/backup",
    "/uploads",
)
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a bounded reconnaissance plan for a CyberRange topology.")
    parser.add_argument("--infra", required=True, help="Path to the infrastructure JSON.")
    parser.add_argument("--output", help="Path to write the ReconReport JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Plan only; do not execute network commands.")
    parser.add_argument("--scan-tools", default=",".join(DEFAULT_TOOLS), help="Comma-separated tools, default nmap,curl.")
    return parser


def build_recon_report(
    infra_path: str | Path,
    *,
    dry_run: bool = True,
    scan_tools: tuple[str, ...] = DEFAULT_TOOLS,
) -> ReconReport:
    if not dry_run:
        raise RuntimeError("Recon execution is intentionally not implemented; use dry_run=True.")
    planned, skipped = build_command_plan(str(infra_path), tools=scan_tools)
    unsafe = [command for command in planned if not command_is_safe(command.command)]
    if unsafe:
        skipped.extend(command.model_copy(update={"safety_status": "blocked"}) for command in unsafe)
        planned = [command for command in planned if command not in unsafe]
    return ReconReport(
        infra_path=str(infra_path),
        generated_at=datetime.now(),
        commands_planned=planned,
        commands_executed=[],
        observations=[],
        skipped_commands=skipped,
        limitations=[
            "Dry-run only: no network command was executed.",
            "Only commands built from the JSON topology and allowlisted tools are planned.",
            "Forbidden tooling includes Metasploit, brute force, sqlmap, payloads, reverse shells and vuln scripts.",
        ],
    )


def build_target_recon_report(
    target_ip: str,
    *,
    execute: bool = False,
    scan_tools: tuple[str, ...] = IP_ONLY_SAFE_TOOLS,
    scan_profile: str = "safe",
    target_hostnames: tuple[str, ...] = (),
    web_probe: bool = True,
    web_enrich: bool = True,
    web_triage_llm: bool = False,
    web_max_pages: int = 8,
    web_deep: bool = True,
    web_deep_max_pages: int = 12,
    smb_probe: bool = True,
    protocol_probe: bool = True,
    llm_model: str | None = None,
    llm_provider: str | None = None,
    sort_strategy: str = "success",
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> ReconReport:
    planned, skipped = build_ip_command_plan(target_ip, tools=scan_tools, profile=scan_profile)
    unsafe = [command for command in planned if not command_is_safe(command.command)]
    if unsafe:
        skipped.extend(command.model_copy(update={"safety_status": "blocked"}) for command in unsafe)
        planned = [command for command in planned if command not in unsafe]

    limitations = [
        "IP-only reconnaissance: inventory facts are inferred from bounded scan output, not from a user JSON topology.",
        "Only code-generated allowlisted commands are eligible; LLM-generated commands are never executed.",
        "Recon evidence can suggest exposed services and versions, but does not confirm exploitability or compromise.",
    ]
    if not execute:
        return ReconReport(
            infra_path=f"scan-only:{target_ip}",
            generated_at=datetime.now(),
            commands_planned=planned,
            commands_executed=[],
            observations=[],
            skipped_commands=skipped,
            limitations=[
                "Dry-run only: no network command was executed.",
                *limitations,
            ],
        )

    observations: list[ReconObservation] = []
    commands_planned = list(planned)
    commands_executed: list[ReconCommandPlan] = []
    queue = list(planned)
    allowed_scan_tools = {tool.strip().lower() for tool in scan_tools}
    index = 0

    while index < len(queue):
        command = queue[index]
        index += 1
        if command.tool == "dirb":
            executed, parsed = _execute_web_probe(
                command,
                target_hostnames=target_hostnames,
                web_enrich=web_enrich,
                web_triage_llm=web_triage_llm,
                web_max_pages=web_max_pages,
                web_deep=web_deep,
                web_deep_max_pages=web_deep_max_pages,
                llm_model=llm_model,
                llm_provider=llm_provider,
                timeout_seconds=min(timeout_seconds, 30),
            )
            commands_executed.append(executed)
            observations.append(parsed)
            if "wpscan" in allowed_scan_tools:
                followups = _wpscan_followups_for_observation(parsed, sort_strategy=sort_strategy)
                _queue_unique_followups(followups, commands_planned=commands_planned, queue=queue)
            continue
        if command.tool == "wpscan":
            executed, stdout, stderr = _execute_command(command, timeout_seconds=timeout_seconds)
            if executed.safety_status != "allowed" and executed.exit_code is None:
                skipped.append(executed)
                limitations.append(executed.rationale)
                continue
            commands_executed.append(executed)
            if executed.exit_code not in {0, None}:
                limitations.append(
                    f"WPScan command returned non-zero exit code {executed.exit_code}: {executed.command}"
                )
            if stderr and executed.exit_code not in {0, None}:
                limitations.append("Recon stderr observed for WPScan; see command metadata.")
            observations.append(_parse_wpscan_observation(executed, stdout, stderr))
            continue
        if _is_smb_probe_command(command):
            executed, stdout, stderr = _execute_command(command, timeout_seconds=min(timeout_seconds, 75))
            if executed.safety_status != "allowed" and executed.exit_code is None:
                skipped.append(executed)
                limitations.append(executed.rationale)
                continue
            commands_executed.append(executed)
            if executed.exit_code not in {0, None}:
                limitations.append(
                    f"SMB metadata command returned non-zero exit code {executed.exit_code}: {executed.command}"
                )
            if stderr and executed.exit_code not in {0, None}:
                limitations.append("Recon stderr observed for SMB metadata nmap; see command metadata.")
            observations.extend(
                parse_nmap_smb_metadata(
                    stdout,
                    target_ip=target_ip,
                    ports=command.ports,
                    evidence_ref=executed.stdout_ref,
                )
            )
            continue
        protocol_probe_name = _protocol_probe_name(command)
        if protocol_probe_name:
            executed, stdout, stderr = _execute_command(command, timeout_seconds=min(timeout_seconds, 75))
            if executed.safety_status != "allowed" and executed.exit_code is None:
                skipped.append(executed)
                limitations.append(executed.rationale)
                continue
            commands_executed.append(executed)
            if executed.exit_code not in {0, None}:
                limitations.append(
                    f"{protocol_probe_name.upper()} metadata command returned non-zero exit code "
                    f"{executed.exit_code}: {executed.command}"
                )
            if stderr and executed.exit_code not in {0, None}:
                limitations.append(f"Recon stderr observed for {protocol_probe_name} metadata nmap.")
            observations.extend(
                parse_nmap_protocol_metadata(
                    stdout,
                    target_ip=target_ip,
                    ports=command.ports,
                    probe=protocol_probe_name,
                    evidence_ref=executed.stdout_ref,
                )
            )
            continue

        executed, stdout, stderr = _execute_command(command, timeout_seconds=timeout_seconds)
        if executed.safety_status != "allowed" and executed.exit_code is None:
            skipped.append(executed)
            limitations.append(executed.rationale)
            continue
        commands_executed.append(executed)
        if executed.exit_code not in {0, None}:
            limitations.append(
                f"Recon command returned non-zero exit code {executed.exit_code}: {executed.command}"
            )
        if stderr and executed.exit_code not in {0, None}:
            limitations.append(f"Recon stderr observed for {executed.tool}; see command metadata.")

        if command.tool == "nmap":
            parsed = parse_nmap_sv(stdout, target_ip=target_ip, evidence_ref=executed.stdout_ref)
            observations.extend(parsed)
            http_ports = _http_ports(parsed)
            if "curl" in allowed_scan_tools:
                followups = build_http_followup_plan(
                    target_ip,
                    http_ports,
                    profile=command.profile,
                )
                followups = [item for item in followups if command_is_safe(item.command)]
                commands_planned.extend(followups)
                queue.extend(followups)
            if web_probe and http_ports and "dirb" in allowed_scan_tools:
                web_followups = build_web_probe_plan(
                    target_ip,
                    http_ports,
                    hostnames=target_hostnames,
                    profile=command.profile,
                )
                web_followups = [item for item in web_followups if command_is_safe(item.command)]
                commands_planned.extend(web_followups)
                queue.extend(web_followups)
            if smb_probe:
                smb_followups = build_smb_followup_plan(
                    target_ip,
                    _smb_ports(parsed),
                    profile=command.profile,
                )
                smb_followups = [item for item in smb_followups if command_is_safe(item.command)]
                commands_planned.extend(smb_followups)
                queue.extend(smb_followups)
            if protocol_probe:
                protocol_followups = build_protocol_followup_plan(
                    target_ip,
                    _protocol_ports(parsed),
                    profile=command.profile,
                )
                protocol_followups = [item for item in protocol_followups if command_is_safe(item.command)]
                commands_planned.extend(protocol_followups)
                queue.extend(protocol_followups)
        elif command.tool == "curl" and command.ports:
            observations.append(
                parse_curl_headers(
                    stdout,
                    target_ip=target_ip,
                    port=command.ports[0],
                    evidence_ref=executed.stdout_ref,
                )
            )

    return ReconReport(
        infra_path=f"scan-only:{target_ip}",
        generated_at=datetime.now(),
        commands_planned=commands_planned,
        commands_executed=commands_executed,
        observations=_dedupe_observations(observations),
        skipped_commands=skipped,
        limitations=list(dict.fromkeys(limitations)),
    )


def _queue_unique_followups(
    followups: list[ReconCommandPlan],
    *,
    commands_planned: list[ReconCommandPlan],
    queue: list[ReconCommandPlan],
) -> None:
    existing = {command.command for command in commands_planned}
    for followup in followups:
        if followup.command in existing or not command_is_safe(followup.command):
            continue
        commands_planned.append(followup)
        queue.append(followup)
        existing.add(followup.command)


def _wpscan_followups_for_observation(
    observation: ReconObservation,
    *,
    sort_strategy: str,
) -> list[ReconCommandPlan]:
    if not _observation_has_wordpress(observation):
        return []
    return build_wpscan_followup_plan(
        observation.target_ip,
        observation.port,
        base_path=_wordpress_base_path_from_observation(observation),
        sort_strategy=sort_strategy,
        profile="safe",
    )


def _execute_command(
    command: ReconCommandPlan,
    *,
    timeout_seconds: int,
) -> tuple[ReconCommandPlan, str, str]:
    if not command.command or not command_is_safe(command.command):
        return (
            command.model_copy(
                update={
                    "safety_status": "blocked",
                    "rationale": f"{command.rationale} Command failed safety validation before execution.",
                }
            ),
            "",
            "",
        )
    if shutil.which(command.tool) is None:
        return (
            command.model_copy(
                update={
                    "safety_status": "skipped",
                    "rationale": f"{command.rationale} Tool not found on PATH: {command.tool}.",
                }
            ),
            "",
            "",
        )

    start = time.monotonic()
    try:
        result = subprocess.run(
            shlex.split(command.command),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - start, 3)
        return (
            command.model_copy(
                update={
                    "safety_status": "blocked",
                    "stdout_ref": f"{command.tool}:{command.target_ip}:timeout_stdout",
                    "stderr_ref": f"{command.tool}:{command.target_ip}:timeout_stderr",
                    "duration_seconds": duration,
                    "rationale": f"{command.rationale} Command timed out after {timeout_seconds}s.",
                }
            ),
            _coerce_output(exc.stdout),
            _coerce_output(exc.stderr),
        )

    duration = round(time.monotonic() - start, 3)
    return (
        command.model_copy(
            update={
                "exit_code": result.returncode,
                "stdout_ref": f"{command.tool}:{command.target_ip}:stdout",
                "stderr_ref": f"{command.tool}:{command.target_ip}:stderr",
                "duration_seconds": duration,
            }
        ),
        result.stdout or "",
        result.stderr or "",
    )


def _execute_web_probe(
    command: ReconCommandPlan,
    *,
    target_hostnames: tuple[str, ...],
    web_enrich: bool,
    web_triage_llm: bool,
    web_max_pages: int,
    web_deep: bool,
    web_deep_max_pages: int,
    llm_model: str | None,
    llm_provider: str | None,
    timeout_seconds: int,
) -> tuple[ReconCommandPlan, ReconObservation]:
    port = command.ports[0] if command.ports else 80
    scheme = "https" if port == 443 else "http"
    if shutil.which("dirb") is not None:
        executed, stdout, _ = _execute_command(command, timeout_seconds=timeout_seconds)
        return (
            executed,
            _parse_dirb_observation(
                executed,
                stdout,
                scheme=scheme,
                web_enrich=web_enrich,
                web_triage_llm=web_triage_llm,
                web_max_pages=web_max_pages,
                web_deep=web_deep,
                web_deep_max_pages=web_deep_max_pages,
                llm_model=llm_model,
                llm_provider=llm_provider,
            ),
        )

    started = time.monotonic()
    hosts = tuple(
        host
        for host in dict.fromkeys([command.hostname, *target_hostnames, command.target_ip])
        if host
    )
    paths = FALLBACK_WEB_PATHS
    path_hits: list[str] = []
    path_candidates: list[WebPathCandidate] = []
    technologies: list[str] = []
    headers: dict[str, str] = {}

    for host in hosts:
        for path in paths:
            result = _fetch_http_probe(
                scheme=scheme,
                target_ip=command.target_ip,
                port=port,
                host_header=host,
                path=path,
                timeout_seconds=min(timeout_seconds, 8),
            )
            if result is None:
                continue
            status, length, title, result_headers = result
            if not headers:
                headers = result_headers
                technologies.extend(_technologies_from_headers(result_headers))
            if _interesting_http_status(status):
                path_hits.append(_format_web_path(host, path, status, length, title))
                path_candidates.append(
                    WebPathCandidate(
                        url=f"{scheme}://{command.target_ip}:{port}{path}",
                        path=path,
                        status_code=status,
                        content_length=length,
                        hostname=host if host != command.target_ip else command.hostname,
                        discovery_source="fallback",
                    )
                )

    vhost_hits: list[str] = []
    for hostname in target_hostnames:
        for prefix in DEFAULT_VHOST_PREFIXES:
            vhost = f"{prefix}.{hostname}"
            result = _fetch_http_probe(
                scheme=scheme,
                target_ip=command.target_ip,
                port=port,
                host_header=vhost,
                path="/",
                timeout_seconds=min(timeout_seconds, 8),
            )
            if result is None:
                continue
            status, length, title, _ = result
            if _interesting_http_status(status):
                vhost_hits.append(_format_web_vhost(vhost, status, length, title))

    duration = round(time.monotonic() - started, 3)
    evidence = f"webprobe:{command.target_ip}:{port}:summary"
    selected, selected_by = select_web_candidates(
        path_candidates,
        max_pages=web_max_pages,
        use_llm=web_triage_llm,
        llm_model=llm_model,
        llm_provider=llm_provider,
    )
    # Ensure /robots.txt and /sitemap.xml are always selected in active recon
    forced_paths = {"/robots.txt", "/sitemap.xml"}
    existing_selected = {c.path for c in selected}
    for req_path in sorted(forced_paths):
        if req_path not in existing_selected:
            found = None
            for c in path_candidates:
                if c.path == req_path:
                    found = c
                    break
            if found:
                selected.insert(0, found)
            else:
                selected.insert(
                    0,
                    WebPathCandidate(
                        url=f"{scheme}://{command.target_ip}:{port}{req_path}",
                        path=req_path,
                        status_code=None,
                        content_length=None,
                        hostname=command.hostname or (target_hostnames[0] if target_hostnames else None),
                        discovery_source="required",
                    )
                )
    web_pages = (
        fetch_web_page_findings(
            selected,
            target_ip=command.target_ip,
            port=port,
            hostname=command.hostname or (target_hostnames[0] if target_hostnames else None),
            selected_by=selected_by,
            deep=web_deep,
            max_total_pages=web_deep_max_pages,
            timeout_seconds=8,
        )
        if web_enrich
        else []
    )
    return (
        command.model_copy(
            update={
                "exit_code": 0,
                "stdout_ref": evidence,
                "duration_seconds": duration,
                "rationale": f"{command.rationale} dirb not found; used built-in fallback path probe.",
            }
        ),
        ReconObservation(
            target_ip=command.target_ip,
            hostname=command.hostname or (target_hostnames[0] if target_hostnames else None),
            port=port,
            protocol="tcp",
            service="HTTP" if scheme == "http" else "HTTPS",
            web_headers=headers,
            web_paths=list(dict.fromkeys(path_hits)),
            web_vhosts=list(dict.fromkeys(vhost_hits)),
            web_pages=web_pages,
            detected_technologies=list(dict.fromkeys(technologies)),
            raw_evidence_ref=evidence,
        ),
    )


def _parse_dirb_observation(
    command: ReconCommandPlan,
    stdout: str,
    *,
    scheme: str,
    web_enrich: bool,
    web_triage_llm: bool,
    web_max_pages: int,
    web_deep: bool,
    web_deep_max_pages: int,
    llm_model: str | None,
    llm_provider: str | None,
) -> ReconObservation:
    port = command.ports[0] if command.ports else 80
    candidates = parse_dirb_candidates(stdout, hostname=command.hostname)
    path_hits = [
        (
            f"{command.hostname or command.target_ip} {candidate.path} "
            f"status={candidate.status_code or 'directory'} length={candidate.content_length or 'unknown'}"
        )
        for candidate in candidates
    ]
    selected, selected_by = select_web_candidates(
        candidates,
        max_pages=web_max_pages,
        use_llm=web_triage_llm,
        llm_model=llm_model,
        llm_provider=llm_provider,
    )
    # Ensure /robots.txt and /sitemap.xml are always selected in active recon
    forced_paths = {"/robots.txt", "/sitemap.xml"}
    existing_selected = {c.path for c in selected}
    for req_path in sorted(forced_paths):
        if req_path not in existing_selected:
            found = None
            for c in candidates:
                if c.path == req_path:
                    found = c
                    break
            if found:
                selected.insert(0, found)
            else:
                selected.insert(
                    0,
                    WebPathCandidate(
                        url=f"{scheme}://{command.target_ip}:{port}{req_path}",
                        path=req_path,
                        status_code=None,
                        content_length=None,
                        hostname=command.hostname,
                        discovery_source="required",
                    )
                )
    web_pages = (
        fetch_web_page_findings(
            selected,
            target_ip=command.target_ip,
            port=port,
            hostname=command.hostname,
            selected_by=selected_by,
            deep=web_deep,
            max_total_pages=web_deep_max_pages,
            timeout_seconds=8,
        )
        if web_enrich
        else []
    )
    vhost_hits = _probe_vhosts_for_dirb_command(command, scheme=scheme) if web_deep else []
    return ReconObservation(
        target_ip=command.target_ip,
        hostname=command.hostname,
        port=port,
        protocol="tcp",
        service="HTTP" if scheme == "http" else "HTTPS",
        web_paths=list(dict.fromkeys(path_hits)),
        web_vhosts=vhost_hits,
        web_pages=web_pages,
        raw_evidence_ref=command.stdout_ref or f"dirb:{command.target_ip}:{port}:stdout",
    )


def _parse_wpscan_observation(command: ReconCommandPlan, stdout: str, stderr: str) -> ReconObservation:
    port = command.ports[0] if command.ports else 80
    summary = _summarize_wpscan_output(stdout)
    if not summary and stderr:
        summary = _summarize_wpscan_output(stderr)
    if not summary:
        summary = "WPScan executed; no concise WordPress findings were parsed from tool output."
    return ReconObservation(
        target_ip=command.target_ip,
        hostname=command.hostname,
        port=port,
        protocol="tcp",
        service="HTTPS" if port == 443 else "HTTP",
        scripts={"wpscan": summary},
        detected_technologies=["WordPress"],
        raw_evidence_ref=command.stdout_ref or f"wpscan:{command.target_ip}:{port}:stdout",
    )


def _summarize_wpscan_output(output: str) -> str:
    interesting: list[str] = []
    for raw_line in output.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        lowered = line.lower()
        if any(
            marker in lowered
            for marker in (
                "wordpress version",
                "interesting finding",
                "xml-rpc",
                "wp-cron",
                "theme",
                "plugin",
                "user(s) identified",
                "users identified",
                "enumerating",
                "identified the following",
            )
        ):
            interesting.append(line.lstrip("[+] ").strip())
    return "; ".join(list(dict.fromkeys(interesting))[:12])


def _observation_has_wordpress(observation: ReconObservation) -> bool:
    haystack_parts: list[str] = [observation.service or "", observation.version or ""]
    haystack_parts.extend(observation.detected_technologies)
    haystack_parts.extend(observation.web_paths)
    for page in observation.web_pages:
        haystack_parts.extend(
            [
                page.path,
                page.title or "",
                page.meta_generator or "",
                " ".join(page.links),
                " ".join(page.scripts),
                " ".join(page.detected_technologies),
                " ".join(page.extracted_versions),
            ]
        )
    haystack = " ".join(haystack_parts).lower()
    return "wordpress" in haystack or "wp-login" in haystack or "wp-content" in haystack


def _wordpress_base_path_from_observation(observation: ReconObservation) -> str:
    candidates: list[str] = []
    for page in observation.web_pages:
        candidates.append(page.path)
        candidates.extend(page.links)
        candidates.extend(page.scripts)
    for item in candidates:
        path = _path_part(item)
        if path and any(token in path.lower() for token in ("wp-login.php", "wp-admin", "wp-content", "wp-includes")):
            return _wordpress_base_path_from_path(path)
    return "/"


def _path_part(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        match = re.search(r"https?://[^/]+(?P<path>/.*)$", value)
        return match.group("path") if match else "/"
    return value if value.startswith("/") else f"/{value}"


def _wordpress_base_path_from_path(path: str) -> str:
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return "/"
    wordpress_markers = {"wp-admin", "wp-content", "wp-includes", "wp-login.php"}
    for index, segment in enumerate(segments):
        if segment.lower() in wordpress_markers:
            base_segments = segments[:index]
            return "/" + "/".join(base_segments) + "/" if base_segments else "/"
    return "/"


def _probe_vhosts_for_dirb_command(command: ReconCommandPlan, *, scheme: str) -> list[str]:
    if not command.hostname:
        return []
    port = command.ports[0] if command.ports else 80
    hits: list[str] = []
    for prefix in DEFAULT_VHOST_PREFIXES:
        vhost = f"{prefix}.{command.hostname}"
        result = _fetch_http_probe(
            scheme=scheme,
            target_ip=command.target_ip,
            port=port,
            host_header=vhost,
            path="/",
            timeout_seconds=5,
        )
        if result is None:
            continue
        status, length, title, _ = result
        if _interesting_http_status(status):
            hits.append(_format_web_vhost(vhost, status, length, title))
    return list(dict.fromkeys(hits))


def _fetch_http_probe(
    *,
    scheme: str,
    target_ip: str,
    port: int,
    host_header: str,
    path: str,
    timeout_seconds: int,
) -> tuple[int, int, str | None, dict[str, str]] | None:
    url = f"{scheme}://{target_ip}:{port}{path}"
    req = request.Request(url, headers={"Host": host_header, "User-Agent": "AutoPlan-RT-safe-webprobe"})
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read(4096)
            headers = {key: value for key, value in response.headers.items()}
            return response.status, len(body), _extract_title(body), headers
    except error.HTTPError as exc:
        body = exc.read(4096)
        headers = {key: value for key, value in exc.headers.items()}
        return exc.code, len(body), _extract_title(body), headers
    except Exception:
        return None


def _extract_title(body: bytes) -> str | None:
    text = body.decode(errors="ignore")
    lower = text.lower()
    start = lower.find("<title>")
    end = lower.find("</title>", start + 7)
    if start == -1 or end == -1:
        return None
    return " ".join(text[start + 7 : end].strip().split())[:80] or None


def _technologies_from_headers(headers: dict[str, str]) -> list[str]:
    technologies: list[str] = []
    for key in ("Server", "X-Powered-By"):
        value = headers.get(key)
        if value:
            technologies.append(value)
    return technologies


def _interesting_http_status(status: int) -> bool:
    return status in {200, 204, 301, 302, 307, 308, 401, 403}


def _format_web_path(host: str, path: str, status: int, length: int, title: str | None) -> str:
    title_part = f" title={title!r}" if title else ""
    return f"{host} {path} status={status} length={length}{title_part}"


def _format_web_vhost(vhost: str, status: int, length: int, title: str | None) -> str:
    title_part = f" title={title!r}" if title else ""
    return f"{vhost} status={status} length={length}{title_part}"


def _http_ports(observations: list[ReconObservation]) -> list[int]:
    ports: list[int] = []
    for observation in observations:
        service = (observation.service or "").lower()
        version = (observation.version or "").lower()
        if observation.port in NON_HTTP_TLS_PORTS:
            continue
        if observation.port in HTTP_LIKE_PORTS or "http" in service or "http" in version:
            ports.append(observation.port)
    return sorted(set(ports))


def _smb_ports(observations: list[ReconObservation]) -> list[int]:
    ports: list[int] = []
    for observation in observations:
        service = (observation.service or "").lower()
        version = (observation.version or "").lower()
        if observation.port in {139, 445} or "smb" in service or "microsoft-ds" in service or "netbios" in service:
            ports.append(observation.port)
        elif "smb" in version or "microsoft-ds" in version or "netbios" in version:
            ports.append(observation.port)
    return sorted(set(ports))


def _protocol_ports(observations: list[ReconObservation]) -> dict[str, list[int]]:
    probes: dict[str, list[int]] = {"ftp": [], "ssh": [], "db": [], "rpc_nfs": [], "tls": []}
    for observation in observations:
        service = (observation.service or "").lower()
        version = (observation.version or "").lower()
        port = observation.port
        blob = f"{service} {version}"
        if port == 21 or "ftp" in blob:
            probes["ftp"].append(port)
        if port == 22 or "ssh" in blob:
            probes["ssh"].append(port)
        if port in {3306, 5432, 1433} or any(token in blob for token in ("mysql", "postgres", "ms-sql", "mssql")):
            probes["db"].append(port)
        if port in {111, 2049} or any(token in blob for token in ("rpcbind", "nfs", "mountd")):
            probes["rpc_nfs"].append(port)
        if port in {443, 465, 636, 993, 995, 8443} or "ssl" in blob or "https" in blob:
            probes["tls"].append(port)
    return {probe: sorted(set(ports)) for probe, ports in probes.items() if ports}


def _is_smb_probe_command(command: ReconCommandPlan) -> bool:
    return command.tool == "nmap" and "smb-os-discovery" in command.command


def _protocol_probe_name(command: ReconCommandPlan) -> str | None:
    if command.tool != "nmap":
        return None
    script_map = {
        "ftp-anon": "ftp",
        "ssh2-enum-algos": "ssh",
        "mysql-info": "db",
        "rpcinfo": "rpc_nfs",
        "ssl-cert": "tls",
    }
    for marker, probe in script_map.items():
        if marker in command.command:
            return probe
    return None


def _dedupe_observations(observations: list[ReconObservation]) -> list[ReconObservation]:
    deduped: dict[tuple[str, int, str], ReconObservation] = {}
    for observation in observations:
        key = (observation.target_ip, observation.port, (observation.service or "").lower())
        if key not in deduped:
            deduped[key] = observation
            continue
        existing = deduped[key]
        deduped[key] = existing.model_copy(
            update={
                "version": existing.version or observation.version,
                "product": existing.product or observation.product,
                "scripts": {**observation.scripts, **existing.scripts},
                "ftp_anonymous": existing.ftp_anonymous if existing.ftp_anonymous is not None else observation.ftp_anonymous,
                "ftp_features": list(dict.fromkeys(existing.ftp_features + observation.ftp_features)),
                "ssh_hostkeys": list(dict.fromkeys(existing.ssh_hostkeys + observation.ssh_hostkeys)),
                "ssh_algorithms": list(dict.fromkeys(existing.ssh_algorithms + observation.ssh_algorithms)),
                "db_info": {**observation.db_info, **existing.db_info},
                "rpc_services": list(dict.fromkeys(existing.rpc_services + observation.rpc_services)),
                "nfs_exports": list(dict.fromkeys(existing.nfs_exports + observation.nfs_exports)),
                "tls_cert": {**observation.tls_cert, **existing.tls_cert},
                "tls_ciphers": list(dict.fromkeys(existing.tls_ciphers + observation.tls_ciphers)),
                "web_headers": {**observation.web_headers, **existing.web_headers},
                "smb_os": existing.smb_os or observation.smb_os,
                "smb_computer_name": existing.smb_computer_name or observation.smb_computer_name,
                "smb_domain": existing.smb_domain or observation.smb_domain,
                "smb_workgroup": existing.smb_workgroup or observation.smb_workgroup,
                "smb_dialects": list(dict.fromkeys(existing.smb_dialects + observation.smb_dialects)),
                "smb_security_mode": {**observation.smb_security_mode, **existing.smb_security_mode},
                "web_paths": list(dict.fromkeys(existing.web_paths + observation.web_paths)),
                "web_vhosts": list(dict.fromkeys(existing.web_vhosts + observation.web_vhosts)),
                "web_pages": existing.web_pages + observation.web_pages,
                "detected_technologies": list(
                    dict.fromkeys(existing.detected_technologies + observation.detected_technologies)
                ),
            }
        )
    return list(deduped.values())


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.dry_run:
        raise SystemExit("--dry-run is required in the current safe implementation.")
    tools = tuple(item.strip() for item in args.scan_tools.split(",") if item.strip())
    report = build_recon_report(args.infra, dry_run=True, scan_tools=tools)
    payload = report.model_dump(mode="json")
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
