"""Execute allowlisted step commands in an authorized lab only."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass

from V2.recon_policy import is_private_lab_target
from V5.models import PathStep
from V5.runtime.allowlist import AllowlistState, _is_exploit_family, _normalize_tool, can_autorun
from V5.runtime.command_suggest import CredentialPair, compile_autorun_command, has_autorun_template

# Always blocked even when allow_auto_exploits (no reverse-shell helpers).
_ALWAYS_FORBIDDEN = (
    "/bin/bash -i",
    "nc -e",
    "ncat -e",
    "bash -i >& /dev/tcp",
)

# Blocked unless allow_auto_exploits + lab_ack (passed by caller).
_EXPLOIT_TOKENS = (
    "metasploit",
    "msfconsole",
    "msfvenom",
    "sqlmap",
)

_HYDRA_LOGIN_RE = re.compile(r"login:\s+(\S+)\s+password:\s+(\S+)", re.IGNORECASE)
HYDRA_MAX_UNIQUE_CREDENTIALS = 3


def _tail_excerpt(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def runtime_command_is_safe(command: str, *, allow_auto_exploits: bool = False) -> bool:
    text = command.lower()
    if any(token in text for token in _ALWAYS_FORBIDDEN):
        return False
    if allow_auto_exploits:
        return True
    return not any(token in text for token in _EXPLOIT_TOKENS)


@dataclass
class ExecResult:
    ok: bool
    command: str | None
    exit_code: int | None = None
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    error: str | None = None
    credentials: list[CredentialPair] | None = None


def run_step_if_allowed(
    step: PathStep,
    allowlist: AllowlistState,
    *,
    timeout_seconds: int = 90,
    allow_auto_exploits: bool = False,
    command_override: str | None = None,
    credentials: list[CredentialPair] | None = None,
) -> ExecResult:
    templated = has_autorun_template(step.tool, allow_auto_exploits=allow_auto_exploits)
    if not can_autorun(
        step.tool,
        allowlist,
        has_template=templated,
        allow_auto_exploits=allow_auto_exploits,
    ):
        return ExecResult(ok=False, command=None, error="not_autorun_eligible")

    if not is_private_lab_target(step.target_ip):
        return ExecResult(ok=False, command=None, error="non_lab_target")

    command = command_override or compile_autorun_command(
        step, allow_auto_exploits=allow_auto_exploits, credentials=credentials
    )
    if not command:
        return ExecResult(ok=False, command=None, error="no_template")

    if not runtime_command_is_safe(command, allow_auto_exploits=allow_auto_exploits):
        return ExecResult(ok=False, command=command, error="unsafe_command")

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        return ExecResult(ok=False, command=command, error=f"bad_command:{exc}")

    if not argv:
        return ExecResult(ok=False, command=command, error="empty_command")

    binary = argv[0]
    if shutil.which(binary) is None:
        return ExecResult(ok=False, command=command, error=f"tool_missing:{binary}")

    # Exploit modules can take longer than recon tools.
    if _is_exploit_family(_normalize_tool(step.tool)):
        timeout_seconds = max(timeout_seconds, 120)

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExecResult(ok=False, command=command, error="timeout", exit_code=None)
    except OSError as exc:
        return ExecResult(ok=False, command=command, error=str(exc))

    full_stdout = completed.stdout or ""
    full_stderr = completed.stderr or ""
    error = classify_command_result(
        command,
        returncode=completed.returncode,
        stdout=full_stdout,
        stderr=full_stderr,
    )
    ok = error is None
    hydra_creds = parse_hydra_credentials(full_stdout) if argv0_of(command) == "hydra" else None
    return ExecResult(
        ok=ok,
        command=command,
        exit_code=completed.returncode,
        stdout_excerpt=_tail_excerpt(full_stdout, 2000) or None,
        stderr_excerpt=_tail_excerpt(full_stderr, 500) or None,
        error=error,
        credentials=hydra_creds or None,
    )


def argv0_of(command: str | None) -> str:
    return (command or "").strip().split(" ", 1)[0].lower()


_MSF_FAIL_MARKERS = (
    "optionvalidateerror",
    "failed to load module",
    "exploit failed",
    "exploit aborted",
    "no session was created",
    "cannot exploit",
    "unknown command",
    "there is no service",
)


def classify_command_result(
    command: str,
    *,
    returncode: int | None,
    stdout: str | None,
    stderr: str | None,
) -> str | None:
    """Return an error token if the process did not achieve a useful lab outcome.

    Exit code 0 is not enough: msfconsole often exits 0 after OptionValidateError.
    """
    blob = f"{stdout or ''}\n{stderr or ''}".lower()
    argv0 = (command or "").strip().split(" ", 1)[0].lower()
    command_l = (command or "").lower()
    is_msf = "msfconsole" in command_l
    is_aux = "auxiliary/" in command_l

    if returncode not in {0, None}:
        return f"exit:{returncode}"

    for marker in _MSF_FAIL_MARKERS:
        if marker in blob:
            return f"unsuccessful:{marker}"

    if is_msf and not is_aux:
        if "session opened" not in blob and "meterpreter session" not in blob:
            return "msf_no_session"

    if argv0 == "nmap":
        if "open" not in blob and ("filtered" in blob or "closed" in blob or "0 hosts up" in blob):
            return "nmap_no_open_ports"

    if argv0 == "hydra":
        if "there is no service" in blob:
            return "hydra_no_credentials"
        creds = parse_hydra_credentials(stdout)
        if len(creds) > HYDRA_MAX_UNIQUE_CREDENTIALS:
            return "hydra_false_positives"
        if not creds:
            return "hydra_no_credentials"

    return None


def parse_hydra_credentials(stdout: str | None) -> list[CredentialPair]:
    """Unique (user, password) pairs Hydra reported as valid."""
    if not stdout:
        return []
    seen: set[CredentialPair] = set()
    out: list[CredentialPair] = []
    for match in _HYDRA_LOGIN_RE.finditer(stdout):
        pair = (match.group(1), match.group(2))
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out
