"""Orchestrate HITL or autonomous lab execution over ranked AttackPaths."""

from __future__ import annotations

from V5.models import AttackPath, PathStep
from V5.runtime.allowlist import AllowlistState, BASE_ALLOWLIST, _is_exploit_family, _normalize_tool, can_autorun
from V5.runtime.command_suggest import has_autorun_template, suggest_command
from V5.runtime.executor import run_step_if_allowed
from V5.runtime.hitl import OperatorIO, ask_manual_outcome, ask_step_action, review_allowlist_for_path
from V5.runtime.repair import SKIPPABLE_RECON_TOOLS, suggest_repaired_command
from V5.runtime.wordlists import ensure_lab_wordlists
from V5.runtime.models import AllowlistDecision, PathAttempt, RuntimeConfig, RuntimeSession, StepOutcome


class RuntimeOrchestrator:
    def __init__(self, io: OperatorIO, *, config: RuntimeConfig | None = None) -> None:
        self.io = io
        self.config = config or RuntimeConfig()
        self.allowlist = AllowlistState()

    def run(self, ranked_paths: list[AttackPath]) -> RuntimeSession:
        if not self.config.lab_ack:
            raise ValueError("lab acknowledgement required (--i-understand-lab-only)")
        if self.config.allow_auto_exploits and not self.config.lab_ack:
            raise ValueError("allow_auto_exploits requires lab acknowledgement")
        if self.config.auto_execute and not self.config.lab_ack:
            raise ValueError("auto_execute requires lab acknowledgement")

        paths = ranked_paths[: self.config.top_k] if self.config.top_k > 0 else list(ranked_paths)
        session = RuntimeSession(
            lab_ack=True,
            base_allowlist=sorted(BASE_ALLOWLIST),
            session_allowlist=[],
            trace={
                "auto_execute": self.config.auto_execute,
                "allow_auto_exploits": self.config.allow_auto_exploits,
                "auto_promote_missing_tools": self.config.auto_promote_missing_tools
                or self.config.auto_execute,
            },
        )
        if not paths:
            session.stop_reason = "no_paths"
            return session

        mode_label = "AUTO" if self.config.auto_execute else "HITL"
        self.io.emit(
            f"{mode_label} runtime: {len(paths)} ranked path(s); "
            f"base allowlist={sorted(BASE_ALLOWLIST)}; "
            f"allow_auto_exploits={self.config.allow_auto_exploits}"
        )

        auto_promote = self.config.auto_promote_missing_tools or self.config.auto_execute

        for rank, path in enumerate(paths, start=1):
            chain = " -> ".join(step.tool for step in path.steps)
            self.io.emit(
                f"\n=== Trying path #{rank} {path.path_id} "
                f"(score={path.strategy_score:.3f}, plaus={path.plausibility:.3f}) ==="
            )
            self.io.emit(f"  chain: {chain}")

            if auto_promote:
                decisions = self._auto_promote_path(path, path_rank=rank)
                abort_path = False
            else:
                decisions, abort_path = review_allowlist_for_path(
                    path,
                    self.allowlist,
                    self.io,
                    path_rank=rank,
                    allow_auto_exploits=self.config.allow_auto_exploits,
                )
            session.session_allowlist = sorted(self.allowlist.session)
            if abort_path:
                session.attempts.append(
                    PathAttempt(
                        path_id=path.path_id,
                        path_rank=rank,
                        status="aborted",
                        allowlist_decisions=decisions,
                        reason="operator_aborted_before_steps",
                    )
                )
                continue

            attempt = PathAttempt(
                path_id=path.path_id,
                path_rank=rank,
                status="blocked",
                allowlist_decisions=decisions,
            )
            blocked = False
            aborted = False

            for step in path.steps:
                templated = has_autorun_template(
                    step.tool, allow_auto_exploits=self.config.allow_auto_exploits
                )
                mode = (
                    "auto"
                    if can_autorun(
                        step.tool,
                        self.allowlist,
                        has_template=templated,
                        allow_auto_exploits=self.config.allow_auto_exploits,
                    )
                    else "manual"
                )

                if self.config.auto_execute:
                    # In auto mode, skip prompts; only run autorun-eligible steps.
                    if mode != "auto":
                        attempt.step_outcomes.append(
                            StepOutcome(
                                path_id=path.path_id,
                                path_rank=rank,
                                step_index=step.step_index,
                                tool=step.tool,
                                mode=mode,
                                action="n",
                                status="rejected",
                                suggested_command=suggest_command(
                                    step, for_auto_exploit=self.config.allow_auto_exploits
                                ),
                                operator_note="auto_execute_skipped_non_autorun",
                            )
                        )
                        blocked = True
                        attempt.reason = "auto_execute_non_autorun_step"
                        self.io.emit(
                            f"  Auto mode cannot run tool={step.tool} (no template / not allowlisted); "
                            "falling back to next path."
                        )
                        break
                    action = "y"
                    self.io.emit(
                        f"\n[path #{rank} {path.path_id}] step {step.step_index}: "
                        f"AUTO tool={step.tool} target={step.target_ip}"
                    )
                else:
                    action = ask_step_action(
                        path=path,
                        path_rank=rank,
                        step=step,
                        mode=mode,
                        io=self.io,
                        allow_auto_exploits=self.config.allow_auto_exploits,
                    )

                if action == "abort":
                    attempt.step_outcomes.append(
                        StepOutcome(
                            path_id=path.path_id,
                            path_rank=rank,
                            step_index=step.step_index,
                            tool=step.tool,
                            mode=mode,
                            action=action,
                            status="aborted",
                            suggested_command=suggest_command(step),
                        )
                    )
                    aborted = True
                    break
                if action == "n":
                    attempt.step_outcomes.append(
                        StepOutcome(
                            path_id=path.path_id,
                            path_rank=rank,
                            step_index=step.step_index,
                            tool=step.tool,
                            mode=mode,
                            action=action,
                            status="rejected",
                            suggested_command=suggest_command(step),
                            operator_note="operator_rejected_step",
                        )
                    )
                    blocked = True
                    attempt.reason = "operator_rejected_step"
                    break
                if action == "skip":
                    attempt.step_outcomes.append(
                        StepOutcome(
                            path_id=path.path_id,
                            path_rank=rank,
                            step_index=step.step_index,
                            tool=step.tool,
                            mode=mode,
                            action=action,
                            status="skipped",
                            suggested_command=suggest_command(step),
                        )
                    )
                    continue

                # action == y
                if mode == "auto":
                    timeout = self._timeout_for_step(step)
                    if self.config.auto_execute and _normalize_tool(step.tool) == "hydra":
                        users, passwords = ensure_lab_wordlists(use_llm=True)
                        self.io.emit(f"  Hydra wordlists: -L {users} -P {passwords}")
                    result = run_step_if_allowed(
                        step,
                        self.allowlist,
                        timeout_seconds=timeout,
                        allow_auto_exploits=self.config.allow_auto_exploits,
                    )
                    retries = 0
                    max_retries = int(getattr(self.config, "max_step_retries", 2) or 0)
                    while (
                        not result.ok
                        and retries < max_retries
                        and self.config.auto_execute
                    ):
                        repaired = suggest_repaired_command(
                            result.command,
                            result.stdout_excerpt,
                            result.stderr_excerpt or result.error,
                        )
                        if not repaired:
                            break
                        retries += 1
                        self.io.emit(f"  Auto-repair retry {retries}: {repaired}")
                        result = run_step_if_allowed(
                            step,
                            self.allowlist,
                            timeout_seconds=timeout,
                            allow_auto_exploits=self.config.allow_auto_exploits,
                            command_override=repaired,
                        )
                    if result.ok:
                        attempt.step_outcomes.append(
                            StepOutcome(
                                path_id=path.path_id,
                                path_rank=rank,
                                step_index=step.step_index,
                                tool=step.tool,
                                mode=mode,
                                action=action,
                                status="success",
                                suggested_command=suggest_command(
                                    step, for_auto_exploit=self.config.allow_auto_exploits
                                ),
                                executed_command=result.command,
                                exit_code=result.exit_code,
                                stdout_excerpt=result.stdout_excerpt,
                            )
                        )
                    elif (
                        self.config.auto_execute
                        and self.config.skip_failed_recon
                        and _normalize_tool(step.tool) in SKIPPABLE_RECON_TOOLS
                    ):
                        attempt.step_outcomes.append(
                            StepOutcome(
                                path_id=path.path_id,
                                path_rank=rank,
                                step_index=step.step_index,
                                tool=step.tool,
                                mode=mode,
                                action="skip",
                                status="skipped",
                                suggested_command=suggest_command(
                                    step, for_auto_exploit=self.config.allow_auto_exploits
                                ),
                                executed_command=result.command,
                                exit_code=result.exit_code,
                                operator_note=f"skipped_after_fail:{result.error}",
                                stdout_excerpt=result.stderr_excerpt or result.stdout_excerpt,
                            )
                        )
                        self.io.emit(
                            f"  Recon tool {step.tool} failed; skipping and continuing the path."
                        )
                    else:
                        attempt.step_outcomes.append(
                            StepOutcome(
                                path_id=path.path_id,
                                path_rank=rank,
                                step_index=step.step_index,
                                tool=step.tool,
                                mode=mode,
                                action=action,
                                status="fail",
                                suggested_command=suggest_command(
                                    step, for_auto_exploit=self.config.allow_auto_exploits
                                ),
                                executed_command=result.command,
                                exit_code=result.exit_code,
                                operator_note=result.error,
                                stdout_excerpt=result.stderr_excerpt or result.stdout_excerpt,
                            )
                        )
                        blocked = True
                        attempt.reason = result.error or "auto_run_failed"
                        self.io.emit(f"  Auto-run failed ({result.error}); falling back to next path.")
                        break
                else:
                    ok, note = ask_manual_outcome(self.io)
                    attempt.step_outcomes.append(
                        StepOutcome(
                            path_id=path.path_id,
                            path_rank=rank,
                            step_index=step.step_index,
                            tool=step.tool,
                            mode=mode,
                            action=action,
                            status="success" if ok else "fail",
                            suggested_command=suggest_command(step),
                            operator_note=note,
                        )
                    )
                    if not ok:
                        blocked = True
                        attempt.reason = "manual_fail"
                        self.io.emit("  Manual step failed; falling back to next path.")
                        break

            if aborted:
                attempt.status = "aborted"
                session.attempts.append(attempt)
                session.session_allowlist = sorted(self.allowlist.session)
                session.stop_reason = "operator_abort"
                return session

            if blocked:
                attempt.status = "blocked"
                session.attempts.append(attempt)
                self.io.emit(f"  Path #{rank} blocked → trying next ranked path.")
                continue

            attempt.status = "success"
            session.attempts.append(attempt)
            session.successful_path_id = path.path_id
            session.session_allowlist = sorted(self.allowlist.session)
            session.stop_reason = "path_success"
            self.io.emit(f"  Path #{rank} completed successfully.")
            return session

        session.session_allowlist = sorted(self.allowlist.session)
        session.stop_reason = "paths_exhausted"
        return session

    def _auto_promote_path(self, path: AttackPath, *, path_rank: int) -> list[AllowlistDecision]:
        promoted = self.allowlist.promote_missing_from_path(path)
        decisions: list[AllowlistDecision] = []
        for tool in promoted:
            templated = has_autorun_template(
                tool, allow_auto_exploits=self.config.allow_auto_exploits
            )
            eligible = can_autorun(
                tool,
                self.allowlist,
                has_template=templated,
                allow_auto_exploits=self.config.allow_auto_exploits,
            )
            decisions.append(
                AllowlistDecision(
                    tool=tool,
                    action="add",
                    note="auto_promote",
                    auto_run_eligible_after=eligible,
                )
            )
            self.io.emit(f"[path #{path_rank}] auto-promoted '{tool}' (autorun_eligible={eligible})")
        if not promoted:
            self.io.emit(f"[path #{path_rank}] All tools already on effective allowlist.")
        else:
            self.io.emit(f"  Session allowlist now: {sorted(self.allowlist.session)}")
        return decisions

    def _timeout_for_step(self, step: PathStep) -> int:
        if _is_exploit_family(_normalize_tool(step.tool)):
            return max(self.config.timeout_seconds, self.config.exploit_timeout_seconds)
        return self.config.timeout_seconds
