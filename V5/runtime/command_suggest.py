"""Suggest lab commands from PathStep without trusting free-form LLM shell."""

from __future__ import annotations

import os

from V5.models import PathStep
from V5.runtime.allowlist import _is_exploit_family, _normalize_tool

# Tools for which we ship a deterministic auto-run template (non-exploit).
TEMPLATED_AUTORUN_TOOLS: frozenset[str] = frozenset(
    {
        "nmap",
        "curl",
        "dirb",
        "wpscan",
        "hydra",
    }
)


def has_autorun_template(tool: str, *, allow_auto_exploits: bool = False) -> bool:
    normalized = _normalize_tool(tool)
    if _is_exploit_family(normalized):
        return bool(allow_auto_exploits)
    return normalized in TEMPLATED_AUTORUN_TOOLS


def suggest_command(step: PathStep, *, for_auto_exploit: bool = False) -> str:
    tool = _normalize_tool(step.tool)
    ip = step.target_ip
    port = step.port

    if tool == "nmap":
        if port:
            return f"nmap -sV -Pn -p {port} {ip}"
        return f"nmap -sV --version-light -Pn {ip}"

    if tool == "curl":
        scheme = "https" if port in {443, 8443} else "http"
        port_part = f":{port}" if port else ""
        return f"curl -I --max-time 10 {scheme}://{ip}{port_part}/"

    if tool == "dirb":
        scheme = "https" if port in {443, 8443} else "http"
        port_part = f":{port}" if port else ""
        return f"dirb {scheme}://{ip}{port_part}/ -S -r"

    if tool == "wpscan":
        scheme = "https" if port in {443, 8443} else "http"
        port_part = f":{port}" if port else ""
        return f"wpscan --url {scheme}://{ip}{port_part}/ --enumerate vp,vt --no-update"

    if tool == "hydra":
        # Placeholder lists only — operator must ensure lab wordlists exist.
        hydra_mod = _hydra_module(step)
        port_flag = f"-s {port} " if port else ""
        return (
            f"hydra {port_flag}-L users.txt -P passwords.txt {ip} {hydra_mod} "
            f"# REVIEW: lab wordlists required; promoted tools only"
        )

    if _is_exploit_family(tool) or tool.startswith("exploit/") or "/" in tool:
        module = step.tool
        if for_auto_exploit:
            port_set = f"set RPORT {port}; " if port else ""
            lhost = os.environ.get("AUTOPLAN_LHOST", "").strip()
            lhost_set = f"set LHOST {lhost}; " if lhost else ""
            # SRVHOST/SRVPORT avoid OptionValidateError on HTTP payloads.
            return (
                f"msfconsole -q -x 'use {module}; set RHOSTS {ip}; {port_set}"
                f"{lhost_set}set SRVHOST 0.0.0.0; set SRVPORT 8080; "
                f"check; run; exit'"
            )
        port_txt = f"RPORT={port}" if port else "RPORT=<port>"
        return (
            f"msfconsole -q -x 'use {module}; set RHOSTS {ip}; set {port_txt}; "
            f"check; # run manually after review'"
        )

    if tool in {"john", "hashcat"}:
        return f"{tool} <hashfile>  # human-assisted; provide lab hash file"

    if tool == "ssh":
        return f"ssh user@{ip}" + (f" -p {port}" if port else "")

    return f"# manual step: tool={step.tool} target={ip} port={port} fact={step.produces_fact}"


def _hydra_module(step: PathStep) -> str:
    """Map a PathStep service/port to a real Hydra module (bare 'http' is invalid)."""
    service = (step.service or "").lower()
    port = step.port
    if any(token in service for token in ("http", "https", "wordpress", "www")):
        if port in {443, 8443} or "https" in service:
            return "https-get"
        return "http-get"
    if "ssh" in service or port == 22:
        return "ssh"
    if "ftp" in service or port == 21:
        return "ftp"
    if port in {443, 8443}:
        return "https-get"
    if port in {80, 8080}:
        return "http-get"
    return service or "ssh"


def compile_autorun_command(step: PathStep, *, allow_auto_exploits: bool = False) -> str | None:
    """Return an executable command string, or None if not auto-runnable."""

    tool = _normalize_tool(step.tool)
    if _is_exploit_family(tool):
        if not allow_auto_exploits:
            return None
        return suggest_command(step, for_auto_exploit=True)

    if not has_autorun_template(step.tool, allow_auto_exploits=allow_auto_exploits):
        return None
    suggested = suggest_command(step)
    # Strip review comments for execution
    command = suggested.split("#", 1)[0].strip()
    if not command:
        return None
    return command
