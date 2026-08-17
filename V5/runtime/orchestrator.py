"""Orchestrate HITL or autonomous lab execution over ranked AttackPaths."""

from __future__ import annotations

from V5.knowledge_graph import KnowledgeGraphBuilder
from V5.models import (
    AttackPath,
    KnowledgeGraph,
    LLMPathProposal,
    PathStep,
    PlausibilityBreakdown,
    ValidatedPathRecord,
)
from V5.runtime.adapt import AdaptDecision, choose_next
from V5.runtime.allowlist import AllowlistState, BASE_ALLOWLIST, _is_exploit_family, _normalize_tool, can_autorun
from V5.runtime.command_suggest import (
    WP_TARGETURI_CANDIDATES,
    has_autorun_template,
    module_needs_login_credentials,
    next_wp_target_uri,
    normalize_target_uri,
    suggest_command,
)
from V5.runtime.executor import ExecResult, run_step_if_allowed
from V5.runtime.hitl import OperatorIO, ask_manual_outcome, ask_step_action, review_allowlist_for_path
from V5.runtime.llm_adapt import propose_llm_decision
from V5.runtime.repair import SKIPPABLE_RECON_TOOLS, suggest_repaired_command
from V5.runtime.wordlists import ensure_lab_wordlists
from V5.runtime.world import WorldState, ingest_result
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

        if self.config.auto_execute and getattr(self.config, "adapt", False):
            return self._run_adaptive(paths, session)

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
            path_credentials: list[tuple[str, str]] = []

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
                    if (
                        self.config.auto_execute
                        and module_needs_login_credentials(step.tool)
                        and not path_credentials
                    ):
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
                                operator_note="missing_credentials",
                            )
                        )
                        blocked = True
                        attempt.reason = "missing_credentials"
                        self.io.emit(
                            f"  {step.tool} needs USERNAME/PASSWORD from Hydra; "
                            "no accepted credentials — next path."
                        )
                        break
                    timeout = self._timeout_for_step(step)
                    if self.config.auto_execute and _normalize_tool(step.tool) == "hydra":
                        users, passwords = ensure_lab_wordlists(use_llm=True)
                        self.io.emit(f"  Hydra wordlists: -L {users} -P {passwords}")
                    result = run_step_if_allowed(
                        step,
                        self.allowlist,
                        timeout_seconds=timeout,
                        allow_auto_exploits=self.config.allow_auto_exploits,
                        credentials=path_credentials or None,
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
                            credentials=path_credentials or None,
                        )
                    if result.ok:
                        if result.credentials:
                            path_credentials = list(result.credentials)
                            self.io.emit(
                                f"  Hydra accepted {len(path_credentials)} unique credential pair(s)"
                            )
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
                                    step,
                                    for_auto_exploit=self.config.allow_auto_exploits,
                                    credentials=path_credentials or None,
                                ),
                                executed_command=result.command,
                                exit_code=result.exit_code,
                                stdout_excerpt=result.stdout_excerpt,
                            )
                        )
                    elif (
                        self.config.auto_execute
                        and getattr(self.config, "skip_failed_recon", True)
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

    def _run_adaptive(self, paths: list[AttackPath], session: RuntimeSession) -> RuntimeSession:
        """Follow the top scenario, adapting after each action toward root."""
        primary = paths[0]
        remaining = list(primary.steps)
        decisions: list[AllowlistDecision] = []
        for rank, path in enumerate(paths, start=1):
            decisions.extend(self._auto_promote_path(path, path_rank=rank))
        session.session_allowlist = sorted(self.allowlist.session)
        session.trace["adapt"] = True

        target_ip = remaining[0].target_ip if remaining else "127.0.0.1"
        port = (remaining[0].port or 80) if remaining else 80
        world = WorldState(target_ip=target_ip, port=port)
        attempt = PathAttempt(
            path_id=primary.path_id,
            path_rank=1,
            status="blocked",
            allowlist_decisions=decisions,
        )
        self.io.emit(
            f"\n=== Adaptive loop on {primary.path_id} "
            f"(max_actions={'unlimited' if not getattr(self.config, 'max_actions', 0) else self.config.max_actions}) ==="
        )
        self.io.emit(f"  scenario: {' -> '.join(step.tool for step in remaining)}")

        extra_paths = list(paths[1:])
        max_actions = int(getattr(self.config, "max_actions", 0) or 0)
        action_index = 0

        while True:
            action_index += 1
            if max_actions > 0 and action_index > max_actions:
                self.io.emit(f"  Reached max_actions={max_actions}.")
                break
            if world.has_root:
                break
            decision = choose_next(world, remaining, last_error=world.last_error)
            if decision is None and extra_paths:
                nxt = extra_paths.pop(0)
                self.io.emit(f"  Merge tools from fallback path {nxt.path_id}")
                remaining.extend(nxt.steps)
                decision = choose_next(world, remaining, last_error=world.last_error)
            if decision is None and getattr(self.config, "use_llm_adapt", True):
                decision = propose_llm_decision(
                    world,
                    remaining,
                    allow_auto_exploits=self.config.allow_auto_exploits,
                )
                if decision:
                    key = f"llm:{_normalize_tool(decision.step.tool)}"
                    if key in world.tried:
                        self.io.emit(f"  LLM repeated {decision.step.tool}; stopping adapt proposals for it.")
                        decision = None
                    else:
                        world.tried.add(key)
                        self.io.emit(f"  LLM adapt: {decision.step.tool} ({decision.note})")
            if decision is None:
                self.io.emit("  No further adaptive action.")
                break

            if decision.consumes_plan:
                _consume_tool(remaining, decision.step.tool)
            if decision.skip:
                attempt.step_outcomes.append(
                    StepOutcome(
                        path_id=primary.path_id,
                        path_rank=1,
                        step_index=action_index,
                        tool=decision.step.tool,
                        mode="auto",
                        action="skip",
                        status="skipped",
                        operator_note=decision.note,
                        adapt_source=decision.source,
                        produces_fact=decision.step.produces_fact,
                    )
                )
                continue

            budget = f"{action_index}" if max_actions <= 0 else f"{action_index}/{max_actions}"
            self.io.emit(
                f"\n[adapt {budget} {decision.source}] "
                f"{decision.step.tool} — {decision.note}"
            )
            if not self.allowlist.contains(decision.step.tool):
                self.allowlist.promote(decision.step.tool)
            outcome, result = self._autorun_adaptive_step(
                primary.path_id,
                action_index,
                decision,
                world,
            )
            attempt.step_outcomes.append(outcome)
            ingest_result(world, result.command if result else None, result)
            if world.has_root:
                break

        attempt.reason = (
            "root_access"
            if world.has_root
            else ("shell_access" if world.has_shell else (world.last_error or "adapted_exhausted"))
        )
        if world.has_root:
            attempt.status = "success"
            session.successful_path_id = primary.path_id
            session.stop_reason = "root_access"
        elif world.has_shell:
            attempt.status = "success"
            session.successful_path_id = primary.path_id
            session.stop_reason = "shell_access"
        else:
            attempt.status = "blocked"
            session.stop_reason = "paths_exhausted"
        session.attempts.append(attempt)
        session.session_allowlist = sorted(self.allowlist.session)
        drafted = " -> ".join(step.tool for step in primary.steps)
        executed_tools, executed_detail = _summarize_executed_chain(attempt.step_outcomes)
        observed_path, observed_graph = _observed_path_and_graph(
            attempt.step_outcomes,
            world,
            drafted_path_id=primary.path_id,
        )
        session.trace["world"] = world.snapshot()
        session.trace["drafted_chain"] = drafted
        session.trace["executed_chain"] = executed_tools
        session.trace["executed_detail"] = executed_detail
        if observed_path is not None:
            session.trace["observed_path"] = observed_path.model_dump(mode="json")
        if observed_graph is not None:
            session.trace["observed_graph"] = observed_graph.model_dump(mode="json")
        self.io.emit(f"  Drafted scenario: {drafted}")
        self.io.emit(f"  Executed chain:   {executed_tools or '(none)'}")
        if executed_detail:
            self.io.emit(f"  Executed detail:  {executed_detail}")
        self.io.emit(
            f"  Adaptive stop={session.stop_reason} facts={world.facts} "
            f"shell={world.has_shell} root={world.has_root}"
        )
        return session

    def _autorun_adaptive_step(
        self,
        path_id: str,
        action_index: int,
        decision: AdaptDecision,
        world: WorldState,
    ) -> tuple[StepOutcome, ExecResult]:
        step = decision.step
        if _normalize_tool(step.tool) == "hydra":
            users, passwords = ensure_lab_wordlists(use_llm=True)
            self.io.emit(f"  Hydra wordlists: -L {users} -P {world.wordlist_path or passwords}")
        timeout = self._timeout_for_step(step)
        target_uri = normalize_target_uri(world.target_uri)
        skip_wpcheck = bool(decision.skip_wpcheck)
        world.tried.add(f"targeturi:{target_uri}")
        result = run_step_if_allowed(
            step,
            self.allowlist,
            timeout_seconds=timeout,
            allow_auto_exploits=self.config.allow_auto_exploits,
            command_override=decision.command_override,
            credentials=world.credentials or None,
            followup_module=None,
            target_uri=target_uri,
            skip_wpcheck=skip_wpcheck,
        )
        retries = 0
        max_retries = int(getattr(self.config, "max_step_retries", 2) or 0)
        # WP fingerprint failures get dedicated URI/WPCHECK retries beyond generic repairs.
        wp_budget = 1 + len(
            [candidate for candidate in WP_TARGETURI_CANDIDATES if candidate != target_uri]
        )
        while not result.ok and retries < max(max_retries, wp_budget if _needs_wp_bypass(result) else 0):
            repaired = suggest_repaired_command(
                result.command,
                result.stdout_excerpt,
                result.stderr_excerpt or result.error,
            )
            if _needs_wp_bypass(result):
                retries += 1
                if not skip_wpcheck:
                    skip_wpcheck = True
                    self.io.emit(
                        f"  Auto-repair retry {retries}: MSF WPCHECK false TARGETURI={target_uri}"
                    )
                else:
                    nxt = next_wp_target_uri(target_uri, world.tried)
                    if not nxt:
                        break
                    target_uri = nxt
                    world.target_uri = nxt
                    world.tried.add(f"targeturi:{nxt}")
                    self.io.emit(
                        f"  Auto-repair retry {retries}: MSF WPCHECK false TARGETURI={target_uri}"
                    )
                result = run_step_if_allowed(
                    step,
                    self.allowlist,
                    timeout_seconds=timeout,
                    allow_auto_exploits=self.config.allow_auto_exploits,
                    command_override=None,
                    credentials=world.credentials or None,
                    followup_module=None,
                    target_uri=target_uri,
                    skip_wpcheck=True,
                )
                continue
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
                credentials=world.credentials or None,
                followup_module=None,
                target_uri=target_uri,
                skip_wpcheck=skip_wpcheck,
            )
        status = "success" if result.ok else "fail"
        if (
            not result.ok
            and getattr(self.config, "skip_failed_recon", True)
            and _normalize_tool(step.tool) in SKIPPABLE_RECON_TOOLS
        ):
            status = "skipped"
        suggested = decision.command_override or suggest_command(
            step,
            for_auto_exploit=self.config.allow_auto_exploits,
            credentials=world.credentials or None,
            followup_module=None,
            target_uri=target_uri,
            skip_wpcheck=skip_wpcheck,
        )
        outcome = StepOutcome(
            path_id=path_id,
            path_rank=1,
            step_index=action_index,
            tool=step.tool,
            mode="auto",
            action="y",
            status=status,
            suggested_command=suggested,
            executed_command=result.command,
            exit_code=result.exit_code,
            operator_note=result.error or decision.note,
            stdout_excerpt=result.stdout_excerpt,
            adapt_source=decision.source,
            produces_fact=step.produces_fact,
        )
        return outcome, result

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
        tool = _normalize_tool(step.tool)
        if tool == "hydra":
            hydra_timeout = int(getattr(self.config, "hydra_timeout_seconds", 1500) or 1500)
            return max(self.config.timeout_seconds, hydra_timeout)
        if _is_exploit_family(tool):
            return max(self.config.timeout_seconds, self.config.exploit_timeout_seconds)
        return self.config.timeout_seconds


def _consume_tool(remaining: list[PathStep], tool: str) -> None:
    key = _normalize_tool(tool)
    for index, step in enumerate(remaining):
        if _normalize_tool(step.tool) == key:
            remaining.pop(index)
            return


def _needs_wp_bypass(result: ExecResult) -> bool:
    blob = f"{result.stdout_excerpt or ''}\n{result.error or ''}".lower()
    return "does not appear to be using wordpress" in blob


def _summarize_executed_chain(outcomes: list[StepOutcome]) -> tuple[str, str]:
    tools: list[str] = []
    detail: list[str] = []
    for outcome in outcomes:
        if outcome.status == "skipped":
            continue
        tools.append(outcome.tool)
        source = outcome.adapt_source or "run"
        detail.append(f"{outcome.tool}[{source}:{outcome.status}]")
    return " -> ".join(tools), " -> ".join(detail)


def _observed_path_and_graph(
    outcomes: list[StepOutcome],
    world: WorldState,
    *,
    drafted_path_id: str,
) -> tuple[AttackPath | None, KnowledgeGraph | None]:
    steps: list[PathStep] = []
    for index, outcome in enumerate(outcomes, start=1):
        if outcome.status != "success":
            continue
        fact = outcome.produces_fact or _fact_for_observed_tool(outcome.tool, world)
        steps.append(
            PathStep(
                step_index=index,
                tool=outcome.tool,
                tool_type=_tool_type_for_observed(outcome.tool),
                target_ip=world.target_ip,
                port=world.port or 80,
                produces_fact=fact,
                justification=outcome.operator_note or outcome.adapt_source or "observed",
            )
        )
    if not steps:
        return None, None
    final = steps[-1].produces_fact
    if world.has_root:
        final = "root_access"
    elif world.has_shell:
        final = "shell_access"
    path = AttackPath(
        path_id="observed:adaptive",
        steps=steps,
        plausibility=1.0,
        strategy_score=1.0,
        strategy="observed",
    )
    proposal = LLMPathProposal(
        path_id=path.path_id,
        title="Runtime-observed adaptive chain",
        hypothesis_summary=f"Executed from drafted {drafted_path_id}",
        target_ip=world.target_ip,
        final_fact=final,
        steps=steps,
        confidence="high",
    )
    record = ValidatedPathRecord(
        path=proposal,
        status="accepted",
        plausibility=PlausibilityBreakdown(composite=1.0),
    )
    builder = KnowledgeGraphBuilder()
    builder.integrate(record)
    path.edges = list(builder.graph.edges)
    return path, builder.graph


def _fact_for_observed_tool(tool: str, world: WorldState) -> str:
    lowered = tool.lower()
    if world.has_root and (
        lowered.startswith(("exploit/linux/local/", "exploit/unix/local/"))
        or "nmap_interactive" in lowered
    ):
        return "root_access"
    if world.has_shell and ("exploit/" in lowered or lowered.startswith("exploit")):
        return "shell_access"
    if _normalize_tool(tool) == "hydra":
        return "credential_access" if world.credentials else "service_intelligence"
    return "service_intelligence"


def _tool_type_for_observed(tool: str) -> str:
    lowered = _normalize_tool(tool)
    if lowered == "hydra":
        return "bruteforce"
    if lowered in {"curl", "wpscan", "dirb"}:
        return "web_client"
    if lowered == "nmap":
        return "scanner"
    if "exploit/" in lowered or lowered.startswith("exploit"):
        return "exploit_framework"
    return "other"
