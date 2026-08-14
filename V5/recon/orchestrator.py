"""Orchestrate L0–L2 recon, then hand an enriched V5InfraDocument to the path loop."""

from __future__ import annotations

from datetime import datetime

from V2.recon_models import ReconObservation, ReconReport
from V2.recon_policy import is_private_lab_target
from V5.models import V5InfraDocument
from V5.recon.adapter import (
    diff_infras,
    empty_seed_infra,
    merge_v5_infras,
    recon_report_to_v5,
)
from V5.recon.executor import (
    BudgetTracker,
    execute_command_plans,
    merge_reports,
    run_l1_target_recon,
)
from V5.recon.llm_proposer import ReconLLMProposer
from V5.recon.models import ReconPhaseResult, ReconRunConfig, ScanProposal
from V5.recon.policy_catalog import compile_proposal


class ReconOrchestrator:
    def __init__(self, proposer: ReconLLMProposer | None = None) -> None:
        self.proposer = proposer

    def run(
        self,
        *,
        config: ReconRunConfig,
        seed_infra: V5InfraDocument | None = None,
        target_ip: str | None = None,
    ) -> ReconPhaseResult:
        if target_ip and seed_infra is not None:
            raise ValueError("Provide either target_ip or seed_infra, not both.")
        if not target_ip and seed_infra is None:
            raise ValueError("Provide target_ip or seed_infra.")

        budget = BudgetTracker(config.budget)
        limitations: list[str] = []
        reports: list[ReconReport] = []
        proposals_accepted: list[ScanProposal] = []
        proposals_rejected: list[dict] = []
        used_templates: set[str] = set()

        if target_ip:
            seed_mode = "target_ip"
            if not is_private_lab_target(target_ip):
                empty = empty_seed_infra(target_ip=target_ip, objective=config.objective)
                return ReconPhaseResult(
                    config=config,
                    seed_mode=seed_mode,
                    seed_ips=[target_ip],
                    reports=[],
                    infra_before=empty,
                    infra_after=empty,
                    limitations=["Blocked non-lab target IP."],
                    stop_reason="blocked_target",
                    elapsed_seconds=budget.elapsed_seconds,
                )
            infra_before = empty_seed_infra(target_ip=target_ip, objective=config.objective)
            seed_ips = [target_ip]
        else:
            assert seed_infra is not None
            seed_mode = "infra"
            infra_before = seed_infra.model_copy(deep=True)
            seed_ips = [machine.ip for machine in seed_infra.machines if is_private_lab_target(machine.ip)]
            if not seed_ips:
                limitations.append("No private/lab machine IPs found in seed infra.")

        # --- L0/L1 deterministic recon ---
        for ip in seed_ips:
            if not budget.allow_more() and config.execute and config.level >= 1:
                limitations.append(budget.stop_reason() or "budget_exhausted")
                break
            report = run_l1_target_recon(ip, config, budget=budget)
            reports.append(report)
            used_templates.add("nmap_sv_light")

        merged_l1 = merge_reports(
            reports,
            infra_path=(
                f"scan-only:{','.join(seed_ips)}"
                if seed_mode == "target_ip"
                else f"infra-enrich:{','.join(seed_ips)}"
            ),
        )
        limitations.extend(merged_l1.limitations)

        infra_after = infra_before.model_copy(deep=True)
        for ip in seed_ips:
            if not any(obs.target_ip == ip for obs in merged_l1.observations) and not config.execute:
                # Plan-only: keep seed; still attach planned commands via reports.
                continue
            enriched = recon_report_to_v5(
                _filter_report(merged_l1, ip),
                target_ip=ip,
                objective=config.objective or infra_before.attack_objective,
            )
            infra_after = merge_v5_infras(infra_after, enriched)

        stop_reason = "completed"
        if config.level == 0 or not config.execute:
            stop_reason = "plan_only"
        budget_stop = budget.stop_reason()
        if budget_stop:
            stop_reason = budget_stop

        # --- L2 LLM / heuristic additional scans ---
        if config.level >= 2 and config.execute and stop_reason not in {"budget_max_commands", "budget_max_seconds"}:
            proposer = self.proposer or ReconLLMProposer(
                provider=config.llm_provider,
                model=config.llm_model,
                use_llm=False,
            )
            llm_rounds = 0
            while llm_rounds < config.budget.max_llm_rounds and budget.allow_more():
                llm_rounds += 1
                observations = list(merged_l1.observations)
                batch = proposer.propose(
                    target_ips=seed_ips,
                    observations=observations,
                    already_used_templates=used_templates,
                    aggressive=config.aggressive,
                    max_proposals=5,
                )
                if not batch.proposals:
                    stop_reason = batch.stop_reason or "no_more_scans"
                    break

                compiled_plans = []
                for proposal in batch.proposals:
                    plans, reason = compile_proposal(
                        proposal,
                        aggressive=config.aggressive,
                        sort_strategy="success" if config.aggressive else "stealth",
                    )
                    if reason or not plans:
                        proposals_rejected.append(
                            {"proposal": proposal.model_dump(), "reason": reason or "empty_plan"}
                        )
                        continue
                    # Skip exact command duplicates already executed/planned
                    existing_cmds = {
                        cmd.command
                        for report in reports
                        for cmd in (report.commands_planned + report.commands_executed)
                    }
                    new_plans = [plan for plan in plans if plan.command not in existing_cmds]
                    if not new_plans:
                        proposals_rejected.append(
                            {"proposal": proposal.model_dump(), "reason": "already_executed_or_planned"}
                        )
                        continue
                    proposals_accepted.append(proposal)
                    used_templates.add(proposal.template_id)
                    compiled_plans.extend(new_plans)

                if not compiled_plans:
                    stop_reason = "no_new_compilable_proposals"
                    break

                executed, new_obs, skipped, exec_limits = execute_command_plans(
                    compiled_plans,
                    timeout_seconds=config.scan_timeout_seconds,
                    budget=budget,
                )
                limitations.extend(exec_limits)
                follow_report = ReconReport(
                    infra_path=f"l2-proposals:{','.join(seed_ips)}",
                    generated_at=datetime.now(),
                    commands_planned=compiled_plans,
                    commands_executed=executed,
                    observations=new_obs,
                    skipped_commands=skipped,
                    limitations=exec_limits,
                )
                reports.append(follow_report)
                merged_l1 = merge_reports(reports, infra_path=merged_l1.infra_path)
                for ip in seed_ips:
                    enriched = recon_report_to_v5(
                        _filter_report(merged_l1, ip),
                        target_ip=ip,
                        objective=config.objective or infra_before.attack_objective,
                    )
                    infra_after = merge_v5_infras(infra_after, enriched)

                if budget.stop_reason():
                    stop_reason = budget.stop_reason() or stop_reason
                    break
            else:
                if llm_rounds >= config.budget.max_llm_rounds and stop_reason == "completed":
                    stop_reason = "llm_rounds_exhausted"

        final_report = merge_reports(reports, infra_path=merged_l1.infra_path if reports else "recon:empty")
        return ReconPhaseResult(
            config=config,
            seed_mode=seed_mode,
            seed_ips=seed_ips,
            reports=reports,
            infra_before=infra_before,
            infra_after=infra_after,
            diff=diff_infras(infra_before, infra_after),
            commands_planned=final_report.commands_planned,
            commands_executed=final_report.commands_executed,
            commands_skipped=final_report.skipped_commands,
            proposals_accepted=proposals_accepted,
            proposals_rejected=proposals_rejected,
            limitations=list(dict.fromkeys(limitations + final_report.limitations)),
            stop_reason=stop_reason,
            elapsed_seconds=budget.elapsed_seconds,
        )


def _filter_report(report: ReconReport, target_ip: str) -> ReconReport:
    return report.model_copy(
        update={
            "observations": [obs for obs in report.observations if obs.target_ip == target_ip],
            "infra_path": f"scan-only:{target_ip}",
        }
    )
