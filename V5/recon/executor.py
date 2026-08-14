"""Execute bounded recon plans by wrapping V2 scan-only execution."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from V2.recon import _dedupe_observations, _execute_command, build_target_recon_report
from V2.recon_models import ReconCommandPlan, ReconObservation, ReconReport
from V2.recon_parser import (
    parse_curl_headers,
    parse_nmap_protocol_metadata,
    parse_nmap_smb_metadata,
    parse_nmap_sv,
)
from V2.recon_policy import command_is_safe, is_private_lab_target
from V5.recon.models import ReconBudget, ReconRunConfig


@dataclass
class BudgetTracker:
    budget: ReconBudget
    started_at: float = field(default_factory=time.monotonic)
    commands_used: int = 0

    def allow_more(self) -> bool:
        if self.commands_used >= self.budget.max_commands:
            return False
        if (time.monotonic() - self.started_at) >= self.budget.max_seconds:
            return False
        return True

    def consume(self, n: int = 1) -> None:
        self.commands_used += n

    def stop_reason(self) -> str | None:
        if self.commands_used >= self.budget.max_commands:
            return "budget_max_commands"
        if (time.monotonic() - self.started_at) >= self.budget.max_seconds:
            return "budget_max_seconds"
        return None

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at


def run_l1_target_recon(
    target_ip: str,
    config: ReconRunConfig,
    *,
    budget: BudgetTracker | None = None,
) -> ReconReport:
    """Run deterministic V2 IP recon (plan-only or execute)."""

    if not is_private_lab_target(target_ip):
        return ReconReport(
            infra_path=f"scan-only:{target_ip}",
            generated_at=__import__("datetime").datetime.now(),
            commands_planned=[],
            commands_executed=[],
            observations=[],
            skipped_commands=[
                ReconCommandPlan(
                    tool="nmap",
                    target_ip=target_ip,
                    command="",
                    rationale="Target IP is not a private or loopback lab address.",
                    safety_status="blocked",
                )
            ],
            limitations=["Blocked non-lab target."],
        )

    execute = bool(config.execute and config.level >= 1)
    # aggressive → fuller WPScan enum (vp,vt,u); otherwise stealth (vp,vt).
    sort_strategy = "success" if config.aggressive else "stealth"
    report = build_target_recon_report(
        target_ip,
        execute=execute,
        scan_tools=config.scan_tools,
        scan_profile="safe",
        target_hostnames=config.target_hostnames,
        web_probe=config.web_probe,
        web_enrich=True,
        web_triage_llm=False,
        smb_probe=config.smb_probe,
        protocol_probe=config.protocol_probe,
        sort_strategy=sort_strategy,
        timeout_seconds=config.scan_timeout_seconds,
    )
    if budget is not None:
        budget.consume(len(report.commands_executed) if execute else 0)
    return report


def execute_command_plans(
    plans: list[ReconCommandPlan],
    *,
    timeout_seconds: int,
    budget: BudgetTracker,
) -> tuple[list[ReconCommandPlan], list[ReconObservation], list[ReconCommandPlan], list[str]]:
    """Execute pre-compiled allowlisted plans (L2 proposals), with budget."""

    executed: list[ReconCommandPlan] = []
    skipped: list[ReconCommandPlan] = []
    observations: list[ReconObservation] = []
    limitations: list[str] = []

    for plan in plans:
        if not budget.allow_more():
            limitations.append(budget.stop_reason() or "budget_exhausted")
            break
        if not plan.command or not command_is_safe(plan.command):
            blocked = plan.model_copy(update={"safety_status": "blocked"})
            skipped.append(blocked)
            limitations.append(f"Blocked unsafe or empty command for {plan.tool}.")
            continue
        if not is_private_lab_target(plan.target_ip):
            skipped.append(plan.model_copy(update={"safety_status": "blocked"}))
            limitations.append(f"Blocked non-lab target {plan.target_ip}.")
            continue

        done, stdout, stderr = _execute_command(plan, timeout_seconds=timeout_seconds)
        budget.consume(1)
        if done.safety_status != "allowed" and done.exit_code is None:
            skipped.append(done)
            limitations.append(done.rationale)
            continue
        executed.append(done)
        if done.exit_code not in {0, None}:
            limitations.append(
                f"Command returned non-zero exit code {done.exit_code}: {done.command}"
            )
        if stderr and done.exit_code not in {0, None}:
            limitations.append(f"stderr observed for {done.tool}.")

        observations.extend(_parse_plan_output(done, stdout))

    return executed, _dedupe_observations(observations), skipped, limitations


def merge_reports(reports: list[ReconReport], *, infra_path: str) -> ReconReport:
    from datetime import datetime

    if not reports:
        return ReconReport(
            infra_path=infra_path,
            generated_at=datetime.now(),
            limitations=["No recon reports produced."],
        )
    planned: list[ReconCommandPlan] = []
    executed: list[ReconCommandPlan] = []
    skipped: list[ReconCommandPlan] = []
    observations: list[ReconObservation] = []
    limitations: list[str] = []
    for report in reports:
        planned.extend(report.commands_planned)
        executed.extend(report.commands_executed)
        skipped.extend(report.skipped_commands)
        observations.extend(report.observations)
        limitations.extend(report.limitations)
    return ReconReport(
        infra_path=infra_path,
        generated_at=datetime.now(),
        commands_planned=planned,
        commands_executed=executed,
        observations=_dedupe_observations(observations),
        skipped_commands=skipped,
        limitations=list(dict.fromkeys(limitations)),
    )


def _parse_plan_output(plan: ReconCommandPlan, stdout: str) -> list[ReconObservation]:
    if plan.tool == "curl" and plan.ports:
        return [
            parse_curl_headers(
                stdout,
                target_ip=plan.target_ip,
                port=plan.ports[0],
                evidence_ref=plan.stdout_ref,
            )
        ]
    if plan.tool == "nmap":
        cmd = plan.command.lower()
        if "smb-os-discovery" in cmd or "smb-protocols" in cmd:
            return parse_nmap_smb_metadata(
                stdout,
                target_ip=plan.target_ip,
                ports=plan.ports,
                evidence_ref=plan.stdout_ref,
            )
        for probe, token in (
            ("ftp", "ftp-anon"),
            ("ssh", "ssh2-enum-algos"),
            ("db", "mysql-info"),
            ("rpc_nfs", "rpcinfo"),
            ("tls", "ssl-cert"),
        ):
            if token in cmd:
                return parse_nmap_protocol_metadata(
                    stdout,
                    target_ip=plan.target_ip,
                    ports=plan.ports,
                    probe=probe,
                    evidence_ref=plan.stdout_ref,
                )
        return parse_nmap_sv(stdout, target_ip=plan.target_ip, evidence_ref=plan.stdout_ref)
    # dirb/wpscan: keep a minimal observation stub so ports remain known
    if plan.ports:
        return [
            ReconObservation(
                target_ip=plan.target_ip,
                port=plan.ports[0],
                hostname=plan.hostname,
                service="http" if plan.tool in {"dirb", "wpscan"} else None,
                raw_evidence_ref=plan.stdout_ref,
                web_paths=[f"{plan.tool} executed"] if stdout.strip() else [],
            )
        ]
    return []
