"""Build and write CyberRange scenario packs from V5 ranked_paths."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from V5.export.models import (
    CRAction,
    CRActionParameter,
    CRScenarioPack,
    CRScenarioPath,
    InfinityObjective,
)
from V5.models import AttackPath, PathStep, V5Result
from V5.runtime.allowlist import _is_exploit_family, _normalize_tool
from V5.runtime.command_suggest import has_autorun_template, suggest_command


def _slug(text: str, *, max_len: int = 48) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_")
    return (cleaned or "step")[:max_len]


def _action_name(step: PathStep, path_id: str) -> str:
    tool = _normalize_tool(step.tool).replace("/", "_")
    return f"{_slug(path_id, max_len=24)}_s{step.step_index}_{_slug(tool, max_len=28)}"


def _parameters_for_step(step: PathStep) -> list[CRActionParameter]:
    params = [
        CRActionParameter(name="target_ip", value=step.target_ip, description="Host IP on the CyberRange topo"),
        CRActionParameter(name="tool", value=step.tool),
    ]
    if step.port is not None:
        params.append(CRActionParameter(name="port", value=step.port))
    if step.service:
        params.append(CRActionParameter(name="service", value=step.service))
    return params


def path_step_to_action(step: PathStep, *, path_id: str) -> CRAction:
    command = suggest_command(step)
    exploit = _is_exploit_family(_normalize_tool(step.tool))
    autorun = (not exploit) and has_autorun_template(step.tool)
    return CRAction(
        name=_action_name(step, path_id),
        step_index=step.step_index,
        tool=step.tool,
        tool_type=step.tool_type,
        mitre_technique_id=step.mitre_technique_id,
        mitre_tactic=step.mitre_tactic,
        target_ip=step.target_ip,
        port=step.port,
        service=step.service,
        command=command,
        parameters=_parameters_for_step(step),
        justification=step.justification,
        produces_fact=step.produces_fact,
        autorun_eligible=autorun,
        requires_human=exploit or not autorun,
        evidence_ids=list(step.evidence_ids),
    )


def _attacker_ip_from_payload(payload: dict[str, Any]) -> str | None:
    trace = payload.get("trace") or {}
    infra = trace.get("infra_document") or trace.get("infra")
    if isinstance(infra, dict):
        att = infra.get("attaquant") or {}
        if isinstance(att, dict):
            return att.get("ip_machine_ecoute") or att.get("ip")
    return None


def _attack_objective_from_payload(payload: dict[str, Any]) -> str:
    trace = payload.get("trace") or {}
    for key in ("attack_objective", "objective", "scenario_objective"):
        value = trace.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    infra = trace.get("infra_document")
    if isinstance(infra, dict):
        for key in ("attack_objective", "objective", "scenario_objective"):
            value = infra.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    recon = trace.get("recon") or {}
    if isinstance(recon, dict):
        value = recon.get("objective")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def load_ranked_paths_payload(path: str | Path) -> tuple[list[AttackPath], dict[str, Any]]:
    """Load ranked paths from a V5Result JSON or a bare {ranked_paths: [...]} file."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if "ranked_paths" in payload and "graph" in payload:
        result = V5Result.model_validate(payload)
        return result.ranked_paths, payload
    if "ranked_paths" in payload:
        paths = [AttackPath.model_validate(item) for item in payload["ranked_paths"]]
        return paths, payload
    if "accepted_paths" in payload:
        paths = [AttackPath.model_validate(item) for item in payload["accepted_paths"]]
        return paths, payload
    raise ValueError(f"No ranked_paths/accepted_paths in {path}")


def build_infinity_objectives(
    *,
    attack_objective: str,
    scenarios: list[CRScenarioPath],
) -> list[InfinityObjective]:
    objectives: list[InfinityObjective] = [
        InfinityObjective(
            objective_id="obj_mission",
            title="Mission objective",
            description=attack_objective or "Complete the ranked red-team training path under instructor review.",
            validation="manual",
            flag_placeholder=None,
        )
    ]
    if not scenarios:
        return objectives
    top = scenarios[0]
    seen_facts: set[str] = set()
    for action in top.actions:
        fact = (action.produces_fact or "").strip()
        if not fact or fact in seen_facts:
            continue
        seen_facts.add(fact)
        objectives.append(
            InfinityObjective(
                objective_id=f"obj_{_slug(fact)}",
                title=f"Reach fact: {fact}",
                description=(
                    f"After step {action.step_index} ({action.tool}) on {action.target_ip}, "
                    f"the trainee/operator should have established: {fact}."
                ),
                validation="flag",
                flag_placeholder=f"FLAG{{{_slug(fact).upper()}}}",
                related_path_id=top.path_id,
                related_fact=fact,
            )
        )
    last = top.actions[-1] if top.actions else None
    if last:
        objectives.append(
            InfinityObjective(
                objective_id="obj_path_complete",
                title=f"Complete path {top.path_id}",
                description=f"Finish the top-ranked path ending with {last.tool} → {last.produces_fact or 'final state'}.",
                validation="trainer",
                related_path_id=top.path_id,
                related_fact=last.produces_fact,
            )
        )
    return objectives


def build_cr_scenario_pack(
    ranked_paths: list[AttackPath],
    *,
    top_k: int = 5,
    strategy: str = "balanced",
    attack_objective: str = "",
    attaquant_ip: str | None = None,
    source_result: str | None = None,
    meta: dict[str, Any] | None = None,
) -> CRScenarioPack:
    selected = ranked_paths[:top_k] if top_k > 0 else list(ranked_paths)
    scenarios: list[CRScenarioPath] = []
    for rank, path in enumerate(selected, start=1):
        actions = [path_step_to_action(step, path_id=path.path_id) for step in path.steps]
        scenarios.append(
            CRScenarioPath(
                path_id=path.path_id,
                rank=rank,
                strategy=path.strategy or strategy,
                plausibility=path.plausibility,
                strategy_score=path.strategy_score,
                actions=actions,
            )
        )
    return CRScenarioPack(
        source_result=source_result,
        attack_objective=attack_objective,
        attaquant_ip=attaquant_ip,
        strategy=strategy,
        top_k=top_k if top_k > 0 else len(scenarios),
        scenarios=scenarios,
        infinity_objectives=build_infinity_objectives(
            attack_objective=attack_objective,
            scenarios=scenarios,
        ),
        meta=meta or {},
    )


def build_playbook_v1_dict(pack: CRScenarioPack) -> dict[str, Any]:
    """Map top scenario to a V1-compatible ScenarioEnvelope-shaped dict (draft only)."""

    if not pack.scenarios:
        playbook_steps: list[dict[str, Any]] = []
        source_ip = pack.attaquant_ip or "0.0.0.0"
    else:
        top = pack.scenarios[0]
        source_ip = pack.attaquant_ip or "0.0.0.0"
        playbook_steps = []
        for action in top.actions:
            playbook_steps.append(
                {
                    "step": action.step_index,
                    "action_name": action.name,
                    "mitre_id": action.mitre_technique_id or "T1046",
                    "source_ip": source_ip,
                    "target_ip": action.target_ip,
                    "execution_context": "local",
                    "exact_command": action.command,
                    "run_in_background": False,
                    "verification_command": "true",
                    "expected_output": "",
                    "soc_expected_telemetry": (
                        f"Review telemetry for {action.tool} against {action.target_ip}"
                        + (f":{action.port}" if action.port else "")
                    ),
                    "register_compromised_host": action.tool_type in {"exploit_framework", "shell"},
                }
            )
    return {
        "schema_version": 2,
        "entreprise": "CyberRange export from AutoPlan-RT V5",
        "attaquant_ip": source_ip,
        "scenario_objective": pack.attack_objective or "Instructor-reviewed red-team draft",
        "apt_profile": "lab_training",
        "mission_complete": False,
        "total_attempted_steps": 0,
        "successful_steps": 0,
        "playbook": {"playbook": playbook_steps},
        "_note": (
            "Draft mapping from V5 PathStep via suggest_command. "
            "verification_command/soc fields are placeholders for instructor edit."
        ),
    }


def render_lade_checklist(pack: CRScenarioPack) -> str:
    lines = [
        "# LADE checklist — AutoPlan-RT CR pack",
        "",
        "Short operator procedure (not a full LADE tutorial).",
        "",
        f"- **Objective:** {pack.attack_objective or '(none in source)'}",
        f"- **Attacker IP (if known):** `{pack.attaquant_ip or 'set on Kali host'}`",
        f"- **Source result:** `{pack.source_result or 'n/a'}`",
        f"- **Paths exported:** {len(pack.scenarios)} (top-k={pack.top_k})",
        "",
        "## 1. Topology (minimal)",
        "",
        "1. Open a workzone.",
        "2. Deploy an attacker host (Kali) and the target(s) whose IPs match the pack commands.",
        "3. Ensure Kali can reach each `target_ip` used below.",
        "",
        "## 2. Create LADE actions from path #1",
        "",
    ]
    if not pack.scenarios:
        lines.append("_No ranked paths in pack._")
        return "\n".join(lines) + "\n"

    top = pack.scenarios[0]
    lines.append(f"Use scenario **#{top.rank}** `{top.path_id}` (plausibility={top.plausibility:.3f}).")
    lines.append("")
    lines.append("For each action: **Actions → Create action** in your personal bundle, paste the command, save.")
    lines.append("")
    for action in top.actions:
        human = "HUMAN REQUIRED" if action.requires_human else "templated / autorun-eligible"
        lines.extend(
            [
                f"### Step {action.step_index}: `{action.name}`",
                f"- Tool: `{action.tool}` ({human})",
                f"- MITRE: `{action.mitre_technique_id or 'n/a'}`",
                f"- Target: `{action.target_ip}`" + (f":{action.port}" if action.port else ""),
                f"- Command:",
                "```bash",
                action.command,
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## 3. Create one LADE scenario",
            "",
            "1. **Scenarios → Create scenario** in your bundle.",
            "2. Add the actions above **in order** (step_index ascending).",
            "3. Run on the attacker host; stop on failure and note gaps (missing tool, wrong IP, exploit).",
            "",
            "## 4. Optional next steps toward autonomy",
            "",
            "1. Replay the same result with `V5.runtime` HITL from Kali (`--from-result`, `--i-understand-lab-only`).",
            "2. When LADE CLI is available: `lade host list` / drive actions from the pack JSON.",
            "3. Feed recon diffs back into `V5.cli` for replan.",
            "",
            "## 5. Journal for the internship report",
            "",
            "Record date, workzone name, IPs, which path rank worked, and deviations vs the draft.",
            "",
        ]
    )
    return "\n".join(lines)


def write_cr_scenario_pack(pack: CRScenarioPack, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "scenario_pack.json").write_text(
        json.dumps(pack.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (out / "infinity_objectives.json").write_text(
        json.dumps(
            [obj.model_dump(mode="json") for obj in pack.infinity_objectives],
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (out / "lade_checklist.md").write_text(render_lade_checklist(pack), encoding="utf-8")
    (out / "playbook_v1.json").write_text(
        json.dumps(build_playbook_v1_dict(pack), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (out / "OPERATOR_SESSION.md").write_text(
        "\n".join(
            [
                "# Operator session sheet",
                "",
                "Use with `lade_checklist.md` during the first LADE session.",
                "",
                "| Field | Value |",
                "|-------|-------|",
                "| Date | |",
                "| Workzone | |",
                "| Attacker host / IP | |",
                "| Target host / IP | |",
                f"| Pack path | `{out}` |",
                f"| Path used | `{pack.scenarios[0].path_id if pack.scenarios else 'n/a'}` |",
                "| Result (ok / partial / fail) | |",
                "| Deviations vs draft | |",
                "",
                "Copy this table into `Rapport/NOTES_RAPPORT_STAGE.md` §15 journal when done.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export a CyberRange scenario pack from a V5 result JSON.",
    )
    parser.add_argument("--from-result", required=True, help="V5 result JSON with ranked_paths")
    parser.add_argument("--output", required=True, help="Output directory for the pack")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--objective", default=None, help="Override attack objective for Infinity stubs / checklist")
    parser.add_argument("--attaquant-ip", default=None, help="Override attacker IP for playbook_v1")
    parser.add_argument(
        "--infra",
        default=None,
        help="Optional V5 infra JSON to read attack_objective / attaquant IP",
    )
    return parser


def _objective_and_attacker_from_infra(infra_path: str | Path) -> tuple[str, str | None]:
    payload = json.loads(Path(infra_path).read_text(encoding="utf-8"))
    objective = ""
    for key in ("attack_objective", "objective", "scenario_objective"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            objective = value.strip()
            break
    att = payload.get("attaquant") or {}
    attacker = None
    if isinstance(att, dict):
        attacker = att.get("ip_machine_ecoute") or att.get("ip")
    return objective, attacker


def export_from_result_file(
    result_path: str | Path,
    output_dir: str | Path,
    *,
    top_k: int = 5,
    attack_objective: str | None = None,
    attaquant_ip: str | None = None,
    infra_path: str | Path | None = None,
) -> CRScenarioPack:
    paths, payload = load_ranked_paths_payload(result_path)
    strategy = str(payload.get("strategy") or "balanced")
    objective = attack_objective or _attack_objective_from_payload(payload)
    attacker = attaquant_ip or _attacker_ip_from_payload(payload)
    if infra_path:
        infra_obj, infra_att = _objective_and_attacker_from_infra(infra_path)
        objective = objective or infra_obj
        attacker = attacker or infra_att
    pack = build_cr_scenario_pack(
        paths,
        top_k=top_k,
        strategy=strategy,
        attack_objective=objective,
        attaquant_ip=attacker,
        source_result=str(result_path),
        meta={"payload_keys": sorted(payload.keys())},
    )
    write_cr_scenario_pack(pack, output_dir)
    return pack


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        pack = export_from_result_file(
            args.from_result,
            args.output,
            top_k=args.top_k,
            attack_objective=args.objective,
            attaquant_ip=args.attaquant_ip,
            infra_path=args.infra,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"cr_pack written to {args.output} "
        f"scenarios={len(pack.scenarios)} objectives={len(pack.infinity_objectives)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
