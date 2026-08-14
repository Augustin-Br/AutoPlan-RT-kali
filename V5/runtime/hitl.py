"""Human-in-the-loop prompts (interactive + scripted for tests)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from V5.models import AttackPath, PathStep
from V5.runtime.allowlist import AllowlistState, promotion_auto_run_eligible
from V5.runtime.command_suggest import has_autorun_template, suggest_command
from V5.runtime.models import AllowlistAction, AllowlistDecision, OperatorStepAction


class OperatorIO:
    """Reads operator decisions from stdin or a pre-recorded script queue."""

    def __init__(
        self,
        *,
        script: list[str] | None = None,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self._script = list(script or [])
        self._stdin = stdin
        self._stdout = stdout

    @classmethod
    def from_script_file(cls, path: str | Path, **kwargs: Any) -> "OperatorIO":
        lines: list[str] = []
        text = Path(path).read_text(encoding="utf-8")
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                payload = json.loads(line)
                lines.append(str(payload.get("answer", "")).strip())
            else:
                lines.append(line)
        return cls(script=lines, **kwargs)

    def emit(self, message: str) -> None:
        if self._stdout is not None:
            self._stdout.write(message + "\n")
            self._stdout.flush()
        else:
            print(message)

    def ask(self, prompt: str) -> str:
        self.emit(prompt)
        if self._script:
            answer = self._script.pop(0)
            self.emit(f"  -> {answer}")
            return answer.strip().lower()
        if self._stdin is not None:
            return self._stdin.readline().strip().lower()
        return input().strip().lower()


def review_allowlist_for_path(
    path: AttackPath,
    allowlist: AllowlistState,
    io: OperatorIO,
    *,
    path_rank: int,
    allow_auto_exploits: bool = False,
) -> tuple[list[AllowlistDecision], bool]:
    """Prompt operator to promote missing tools. Returns (decisions, abort_path)."""

    missing = allowlist.missing_from_path(path)
    decisions: list[AllowlistDecision] = []
    if not missing:
        io.emit(f"[path #{path_rank} {path.path_id}] All tools already on effective allowlist.")
        return decisions, False

    io.emit(
        f"[path #{path_rank} {path.path_id}] Tools outside allowlist "
        f"(effective={sorted(allowlist.effective())}):"
    )
    skip_all = False
    for tool in missing:
        if skip_all:
            decisions.append(
                AllowlistDecision(
                    tool=tool,
                    action="skip",
                    note="skip_all",
                    auto_run_eligible_after=False,
                )
            )
            continue
        risk = allowlist.risk_note(tool)
        templated = has_autorun_template(tool, allow_auto_exploits=allow_auto_exploits)
        eligible = promotion_auto_run_eligible(
            tool, has_template=templated, allow_auto_exploits=allow_auto_exploits
        )
        warn = (
            "auto-run OK after add"
            if eligible
            else "tracking only / human-assisted (no auto-run template or exploit without --allow-auto-exploits)"
        )
        answer = io.ask(
            f"  Promote '{tool}' into session allowlist? "
            f"[{risk}; {warn}] (add/skip/skip-all/abort-path)"
        )
        action = _parse_allowlist_action(answer)
        if action == "abort_path":
            decisions.append(AllowlistDecision(tool=tool, action=action, note="operator_abort"))
            return decisions, True
        if action == "skip_all":
            skip_all = True
            decisions.append(
                AllowlistDecision(tool=tool, action="skip", note="skip_all", auto_run_eligible_after=False)
            )
            continue
        if action == "add":
            allowlist.promote(tool)
            decisions.append(
                AllowlistDecision(
                    tool=tool,
                    action="add",
                    auto_run_eligible_after=eligible,
                    note=None if eligible else "promoted_but_manual_only",
                )
            )
        else:
            decisions.append(AllowlistDecision(tool=tool, action="skip", auto_run_eligible_after=False))

    io.emit(f"  Session allowlist now: {sorted(allowlist.session)}")
    confirm = io.ask(
        f"Start path #{path_rank} with effective allowlist={sorted(allowlist.effective())}? (y/n)"
    )
    if confirm not in {"y", "yes"}:
        return decisions, True
    return decisions, False


def ask_step_action(
    *,
    path: AttackPath,
    path_rank: int,
    step: PathStep,
    mode: str,
    io: OperatorIO,
    allow_auto_exploits: bool = False,
) -> OperatorStepAction:
    suggested = suggest_command(step, for_auto_exploit=allow_auto_exploits and mode == "auto")
    io.emit(
        f"\n[path #{path_rank} {path.path_id}] step {step.step_index}: "
        f"tool={step.tool} target={step.target_ip} port={step.port} "
        f"fact={step.produces_fact} mode={mode}"
    )
    io.emit(f"  suggested: {suggested}")
    answer = io.ask("  Approve step? (y/n/skip/abort)")
    if answer in {"y", "yes"}:
        return "y"
    if answer in {"n", "no"}:
        return "n"
    if answer in {"skip", "s"}:
        return "skip"
    if answer in {"abort", "a", "q", "quit"}:
        return "abort"
    io.emit("  Unrecognized input; treating as 'n'.")
    return "n"


def ask_manual_outcome(io: OperatorIO) -> tuple[bool, str | None]:
    answer = io.ask("  Manual outcome? (success/fail) optional note after space")
    parts = answer.split(None, 1)
    status = parts[0] if parts else ""
    note = parts[1] if len(parts) > 1 else None
    if status in {"success", "ok", "s", "y", "yes"}:
        return True, note
    return False, note or status


def _parse_allowlist_action(answer: str) -> AllowlistAction:
    if answer in {"add", "a", "y", "yes"}:
        return "add"
    if answer in {"skip-all", "skip_all", "all"}:
        return "skip_all"
    if answer in {"abort-path", "abort_path", "abort", "q"}:
        return "abort_path"
    return "skip"
