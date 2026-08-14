"""Deterministic command repairs after a failed auto-run (lab only)."""

from __future__ import annotations

from V5.runtime.wordlists import ensure_lab_wordlists

# Recon tools that may fail without invalidating later path steps.
SKIPPABLE_RECON_TOOLS = frozenset({"wpscan", "dirb"})


def suggest_repaired_command(command: str | None, stdout: str | None, stderr: str | None) -> str | None:
    """Return an alternate command, or None if nothing obvious to fix."""
    if not command:
        return None
    blob = f"{stdout or ''}\n{stderr or ''}".lower()
    repaired = command

    if "file for passwords not found" in blob or "file for logins not found" in blob:
        users, passwords = ensure_lab_wordlists(use_llm=True)
        repaired = _replace_flag_value(repaired, "-P", passwords)
        repaired = _replace_flag_value(repaired, "-L", users)
        return repaired.strip()

    if "database file is missing" in blob or "update required" in blob:
        repaired = repaired.replace(" --no-update", "").replace("--no-update", "")

    if repaired.strip() == command.strip():
        return None
    return repaired.strip()


def _replace_flag_value(command: str, flag: str, new_value: str) -> str:
    parts = command.split()
    out: list[str] = []
    skip = False
    for i, token in enumerate(parts):
        if skip:
            skip = False
            continue
        if token == flag and i + 1 < len(parts):
            out.extend([flag, new_value])
            skip = True
            continue
        out.append(token)
    return " ".join(out)
