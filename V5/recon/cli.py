"""Standalone recon CLI: enrich infra from bounded lab scans (no attack-path loop)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from V5.infra_loader import load_v5_infra
from V5.recon.llm_proposer import ReconLLMProposer
from V5.recon.models import ReconBudget, ReconRunConfig
from V5.recon.orchestrator import ReconOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="V5 bounded reconnaissance (plan/execute) producing an enriched infra JSON."
    )
    seed = parser.add_mutually_exclusive_group(required=True)
    seed.add_argument("--infra", help="Existing V5 infrastructure JSON to enrich")
    seed.add_argument("--target-ip", help="Private/lab IP seed (scan-only)")
    parser.add_argument("--objective", default=None, help="Attack objective (required for --target-ip)")
    parser.add_argument("--execute-recon", action="store_true", help="Actually run allowlisted scan commands")
    parser.add_argument("--recon-level", type=int, choices=[0, 1, 2], default=None)
    parser.add_argument("--recon-llm", action="store_true", help="Enable L2 template proposals")
    parser.add_argument("--recon-aggressive", action="store_true", help="Allow deeper allowlisted enums")
    parser.add_argument("--recon-output", help="Write full ReconPhaseResult JSON")
    parser.add_argument("--infra-output", required=True, help="Write enriched V5 infra JSON")
    parser.add_argument("--scan-tools", default="nmap,curl,dirb,wpscan")
    parser.add_argument("--scan-timeout", type=int, default=90)
    parser.add_argument("--recon-max-commands", type=int, default=40)
    parser.add_argument("--recon-max-seconds", type=float, default=600.0)
    parser.add_argument("--enable-llm", action="store_true", help="Use real LLM for L2 proposals")
    parser.add_argument("--llm-provider", default="openai")
    parser.add_argument("--llm-model", default=None)
    parser.add_argument("--json-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.target_ip and not args.objective:
        print("error: --objective is required with --target-ip", file=sys.stderr)
        return 2

    level = args.recon_level
    if level is None:
        if args.recon_llm:
            level = 2
        elif args.execute_recon:
            level = 1
        else:
            level = 0
    if args.recon_llm and level < 2:
        level = 2
    if args.recon_llm and args.enable_llm is False and level >= 2:
        # heuristic proposer still works offline
        pass

    config = ReconRunConfig(
        level=level,  # type: ignore[arg-type]
        execute=bool(args.execute_recon),
        aggressive=bool(args.recon_aggressive),
        scan_tools=tuple(tool.strip() for tool in args.scan_tools.split(",") if tool.strip()),
        scan_timeout_seconds=args.scan_timeout,
        budget=ReconBudget(
            max_commands=args.recon_max_commands,
            max_seconds=args.recon_max_seconds,
        ),
        objective=args.objective
        or "Identify and draft plausible attack scenarios for authorized SOC training.",
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
    )

    proposer = None
    if level >= 2:
        proposer = ReconLLMProposer(
            provider=args.llm_provider,
            model=args.llm_model,
            use_llm=bool(args.enable_llm),
        )
    orchestrator = ReconOrchestrator(proposer=proposer)

    seed_infra = load_v5_infra(args.infra) if args.infra else None
    if seed_infra is not None and args.objective:
        seed_infra.attack_objective = args.objective

    result = orchestrator.run(
        config=config,
        seed_infra=seed_infra,
        target_ip=args.target_ip,
    )

    Path(args.infra_output).write_text(
        json.dumps(result.infra_after.model_dump(mode="json", by_alias=False), ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )
    if args.recon_output:
        Path(args.recon_output).write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    if not args.json_only:
        print(f"recon stop_reason={result.stop_reason} level={config.level} execute={config.execute}")
        print(f"diff: {result.diff.summary}")
        print(f"planned={len(result.commands_planned)} executed={len(result.commands_executed)}")
        print(f"wrote infra -> {args.infra_output}")
    else:
        json.dump(result.trace_payload(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
