"""V5 CLI — optional bounded recon, then iterative LLM path generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from V2.rag_adapter import RAGAdapter
from V5.infra_loader import load_v5_infra, retarget_machines
from V5.llm_path_agent import LLMPathAgent
from V5.path_loop import PathLoopConfig, PathLoopOrchestrator
from V5.recon.llm_proposer import ReconLLMProposer
from V5.recon.models import ReconBudget, ReconRunConfig
from V5.recon.orchestrator import ReconOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="V5 neuro-symbolic path generator with LLM loop.")
    parser.add_argument("--infra", help="Infrastructure JSON path (static or recon seed)")
    parser.add_argument("--target-ip", help="Private/lab IP seed; enables recon instead of --infra")
    parser.add_argument("--objective", help="Attack objective (required with --target-ip)")
    parser.add_argument("--output", help="Optional JSON output path")
    parser.add_argument("--strategy", default="balanced", choices=["success", "stealth", "balanced", "fast", "cheap", "least_destructive"])
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--max-rounds", type=int, default=0, help="Max LLM loop rounds (0 = unlimited; default)")
    parser.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=5,
        help="Stop after N rounds with no accepted path (0 = unlimited)",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.85,
        help="Ordered tool-sequence similarity above this value rejects the path as too_similar (default: 0.85)",
    )
    parser.add_argument(
        "--max-similarity-rejections",
        type=int,
        default=10,
        help="Stop the loop after this many too_similar rejections; +1 per duplicate path (0 = unlimited, default: 10)",
    )
    parser.add_argument(
        "--explore-until-exhausted",
        action="store_true",
        help="Exploration preset: no round/failure caps; stop on llm_exhausted or similarity_exhausted only",
    )
    parser.add_argument(
        "--plausibility-threshold",
        type=float,
        default=0.60,
        help="Accept path if composite plausibility ≥ α (default: 0.60)",
    )
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument(
        "--rag-per-service",
        type=int,
        default=8,
        help="Metasploit modules retrieved per service for the LLM prompt (default: 8)",
    )
    parser.add_argument(
        "--rag-module-limit",
        type=int,
        default=40,
        help="Max distinct Metasploit module paths injected into the LLM prompt (default: 40)",
    )
    parser.add_argument("--enable-llm", action="store_true", help="Use real LLM API (requires key). Default: mock offline paths.")
    parser.add_argument("--llm-provider", default="openai")
    parser.add_argument("--llm-model", default=None, help="Default: gpt-4o-mini (openai) or gemini-flash-lite-latest (google)")
    parser.add_argument("--json-only", action="store_true")

    # Optional recon phase (separate loop; off by default)
    parser.add_argument("--execute-recon", action="store_true", help="Run allowlisted live recon commands")
    parser.add_argument("--recon-level", type=int, choices=[0, 1, 2], default=None, help="0=plan, 1=deterministic, 2=+LLM templates")
    parser.add_argument("--recon-llm", action="store_true", help="Enable L2 recon template proposals")
    parser.add_argument("--recon-aggressive", action="store_true", help="Allow deeper allowlisted recon enums")
    parser.add_argument("--recon-output", help="Write ReconPhaseResult JSON")
    parser.add_argument("--infra-output", help="Write enriched V5 infra JSON after recon")
    parser.add_argument("--scan-tools", default="nmap,curl,dirb,wpscan")
    parser.add_argument("--scan-timeout", type=int, default=90)
    parser.add_argument("--recon-max-commands", type=int, default=40)
    parser.add_argument("--recon-max-seconds", type=float, default=600.0)
    parser.add_argument("--recon-only", action="store_true", help="Stop after recon; skip attack-path loop")

    # Optional HITL path execution (post-FPS; separate from drafting loop)
    parser.add_argument(
        "--execute-paths",
        action="store_true",
        help="After ranking, enter HITL runtime on ranked paths (lab only)",
    )
    parser.add_argument("--runtime-top-k", type=int, default=5)
    parser.add_argument("--runtime-timeout", type=int, default=90)
    parser.add_argument("--runtime-output", help="Write RuntimeSession JSON")
    parser.add_argument(
        "--runtime-noninteractive",
        help="Scripted HITL answers (one per line) for tests/CI",
    )
    parser.add_argument(
        "--auto-execute",
        action="store_true",
        help="Lab-only: run ranked paths without per-step y/n (promotes missing tools automatically)",
    )
    parser.add_argument(
        "--allow-auto-exploits",
        action="store_true",
        help="Lab-only: allow subprocess auto-run of exploit/* / msfconsole templates",
    )
    parser.add_argument(
        "--export-cr-pack",
        help="Write CyberRange scenario pack (LADE/Infinity bridge) to this directory",
    )
    parser.add_argument(
        "--cr-pack-top-k",
        type=int,
        default=5,
        help="Max ranked paths to include in --export-cr-pack (default: 5)",
    )
    return parser


def _resolve_recon_level(args: argparse.Namespace) -> int | None:
    """Return recon level, or None if recon is not requested."""
    wants_recon = bool(
        args.target_ip
        or args.execute_recon
        or args.recon_llm
        or args.recon_level is not None
        or args.recon_only
        or args.recon_output
        or args.infra_output
    )
    if not wants_recon:
        return None
    if args.recon_level is not None:
        level = args.recon_level
    elif args.recon_llm:
        level = 2
    elif args.execute_recon:
        level = 1
    else:
        level = 0
    if args.recon_llm and level < 2:
        level = 2
    return level


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.infra and not args.target_ip:
        print("error: provide --infra or --target-ip", file=sys.stderr)
        return 2
    if args.target_ip and not args.objective and not args.infra:
        print("error: --objective is required with --target-ip", file=sys.stderr)
        return 2

    recon_level = _resolve_recon_level(args)
    if args.target_ip and recon_level is None:
        recon_level = 0

    infra = None
    recon_result = None
    if recon_level is not None:
        if args.recon_llm and not args.enable_llm:
            # Allowed: heuristic L2 proposer without API key.
            pass
        config = ReconRunConfig(
            level=recon_level,  # type: ignore[arg-type]
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
        if recon_level >= 2:
            proposer = ReconLLMProposer(
                provider=args.llm_provider,
                model=args.llm_model,
                use_llm=bool(args.enable_llm),
            )
        seed_infra = None
        recon_target_ip = args.target_ip
        if args.infra:
            seed_infra = load_v5_infra(args.infra)
            if args.objective:
                seed_infra.attack_objective = args.objective
            if args.target_ip:
                seed_infra = retarget_machines(seed_infra, args.target_ip)
                recon_target_ip = None
        recon_result = ReconOrchestrator(proposer=proposer).run(
            config=config,
            seed_infra=seed_infra,
            target_ip=recon_target_ip,
        )
        infra = recon_result.infra_after
        if args.infra_output:
            Path(args.infra_output).write_text(
                json.dumps(infra.model_dump(mode="json", by_alias=False), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if args.recon_output:
            Path(args.recon_output).write_text(
                json.dumps(recon_result.model_dump(mode="json"), ensure_ascii=False, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
        if not args.json_only:
            print(
                f"recon stop_reason={recon_result.stop_reason} "
                f"level={config.level} execute={config.execute} "
                f"diff={recon_result.diff.summary}"
            )
        if args.recon_only:
            if args.json_only and recon_result is not None:
                json.dump(recon_result.trace_payload(), sys.stdout, ensure_ascii=False, indent=2)
                sys.stdout.write("\n")
            return 0
    else:
        infra = load_v5_infra(args.infra)
        if args.target_ip:
            infra = retarget_machines(infra, args.target_ip)
        if args.objective:
            infra.attack_objective = args.objective

    assert infra is not None
    rag = RAGAdapter.from_paths(disabled=args.no_rag)
    llm_agent = None
    if args.enable_llm:
        llm_agent = LLMPathAgent(provider=args.llm_provider, model=args.llm_model, use_llm=True)
    max_rounds = args.max_rounds
    max_consecutive_failures = args.max_consecutive_failures
    max_similarity_rejections = args.max_similarity_rejections
    top_k = args.top_k
    if args.explore_until_exhausted:
        max_rounds = 0
        max_consecutive_failures = 0
        if top_k == 5:
            top_k = 0
        if max_similarity_rejections == 10:
            max_similarity_rejections = 30
    config = PathLoopConfig(
        max_llm_rounds=max_rounds,
        max_consecutive_failures=max_consecutive_failures,
        similarity_threshold=args.similarity_threshold,
        max_similarity_rejections=max_similarity_rejections,
        plausibility_threshold=args.plausibility_threshold,
        strategy=args.strategy,
        top_k=top_k,
        rag_per_service_k=args.rag_per_service,
        rag_module_prompt_limit=args.rag_module_limit,
    )
    orchestrator = PathLoopOrchestrator(llm_agent=llm_agent)
    result = orchestrator.run(infra, rag=rag, config=config)
    result.trace["infra"] = args.infra or f"target-ip:{args.target_ip}"
    if recon_result is not None:
        result.trace["recon"] = recon_result.trace_payload()
    result.trace["loop_config"] = {
        "max_llm_rounds": config.max_llm_rounds,
        "max_consecutive_failures": config.max_consecutive_failures,
        "max_similarity_rejections": config.max_similarity_rejections,
        "similarity_threshold": config.similarity_threshold,
        "plausibility_threshold": config.plausibility_threshold,
        "explore_until_exhausted": args.explore_until_exhausted,
        "top_k": config.top_k,
    }
    if llm_agent:
        result.trace["llm_provider"] = llm_agent.provider
        result.trace["llm_model"] = llm_agent.model

    if not args.json_only:
        print(
            "loop_config: "
            f"α={config.plausibility_threshold} "
            f"similarity≥{config.similarity_threshold} "
            f"max_similar_rejects={config.max_similarity_rejections} "
            f"max_rounds={config.max_llm_rounds}"
        )
        print(f"V5 stop_reason={result.trace.get('stop_reason')}")
        print(f"similarity_rejection_streak={result.trace.get('similarity_rejection_streak', 0)}")
        print(f"accepted={len(result.accepted_paths)} rejected={len(result.rejected_records)} rounds={result.trace.get('rounds')}")
        counters = result.trace.get("rejection_counters") or {}
        if any(counters.values()):
            parts = [f"{key}={value}" for key, value in sorted(counters.items()) if value]
            print(f"rejection_counters: {', '.join(parts)}")
        if result.trace.get("llm_errors"):
            print(f"llm_errors ({len(result.trace['llm_errors'])}):")
            for err in result.trace["llm_errors"][:3]:
                print(f"  - {err[:240]}")
        for index, path in enumerate(result.ranked_paths, start=1):
            tools = " -> ".join(step.tool for step in path.steps)
            print(f"#{index} [{path.strategy}] {tools} score={path.strategy_score:.3f} plausibility={path.plausibility:.3f}")

    payload = result.model_dump_for_export()
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.execute_paths:
        from V5.runtime.hitl import OperatorIO
        from V5.runtime.models import RuntimeConfig
        from V5.runtime.orchestrator import RuntimeOrchestrator

        if args.auto_execute and args.runtime_noninteractive:
            print(
                "warning: --auto-execute ignores --runtime-noninteractive prompts",
                file=sys.stderr,
            )
        io = (
            OperatorIO.from_script_file(args.runtime_noninteractive)
            if args.runtime_noninteractive and not args.auto_execute
            else OperatorIO()
        )
        runtime_session = RuntimeOrchestrator(
            io,
            config=RuntimeConfig(
                top_k=args.runtime_top_k,
                timeout_seconds=args.runtime_timeout,
                lab_ack=True,
                auto_execute=bool(args.auto_execute),
                allow_auto_exploits=bool(args.allow_auto_exploits),
                auto_promote_missing_tools=bool(args.auto_execute),
                adapt=bool(args.auto_execute),
            ),
        ).run(result.ranked_paths)
        result.trace["runtime"] = runtime_session.model_dump(mode="json")
        _merge_observed_runtime(result, runtime_session)
        payload = result.model_dump_for_export()
        if args.runtime_output:
            Path(args.runtime_output).write_text(
                json.dumps(runtime_session.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if args.output:
            Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if not args.json_only:
            executed = (runtime_session.trace or {}).get("executed_chain")
            drafted = (runtime_session.trace or {}).get("drafted_chain")
            if drafted or executed:
                print(f"drafted_chain={drafted}")
                print(f"executed_chain={executed}")
            print(
                f"runtime stop_reason={runtime_session.stop_reason} "
                f"successful_path={runtime_session.successful_path_id} "
                f"auto_execute={args.auto_execute} allow_auto_exploits={args.allow_auto_exploits}"
            )

    if args.export_cr_pack:
        from V5.export.cr_pack import build_cr_scenario_pack, write_cr_scenario_pack

        pack = build_cr_scenario_pack(
            result.ranked_paths,
            top_k=args.cr_pack_top_k,
            strategy=result.strategy,
            attack_objective=infra.attack_objective or "",
            attaquant_ip=(infra.attaquant or {}).get("ip_machine_ecoute")
            or (infra.attaquant or {}).get("ip"),
            source_result=args.output or args.infra or (f"target-ip:{args.target_ip}" if args.target_ip else None),
            meta={"cli": "V5.cli", "strategy": result.strategy},
        )
        write_cr_scenario_pack(pack, args.export_cr_pack)
        if not args.json_only:
            print(
                f"cr_pack written to {args.export_cr_pack} "
                f"scenarios={len(pack.scenarios)} objectives={len(pack.infinity_objectives)}"
            )

    if args.json_only:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0


def _merge_observed_runtime(result: object, runtime_session: object) -> None:
    """Attach the executed chain to the V5 result and merge the observed graph."""
    from V5.models import AttackPath, KnowledgeGraph, V5Result
    from V5.runtime.models import RuntimeSession

    if not isinstance(result, V5Result) or not isinstance(runtime_session, RuntimeSession):
        return
    trace = runtime_session.trace or {}
    if trace.get("executed_chain"):
        result.trace["drafted_chain"] = trace.get("drafted_chain")
        result.trace["executed_chain"] = trace.get("executed_chain")
        result.trace["executed_detail"] = trace.get("executed_detail")
    observed_payload = trace.get("observed_path")
    if observed_payload:
        observed = AttackPath.model_validate(observed_payload)
        result.trace["observed_path_id"] = observed.path_id
        result.ranked_paths = [observed, *[path for path in result.ranked_paths if path.path_id != observed.path_id]]
        result.accepted_paths = [
            observed,
            *[path for path in result.accepted_paths if path.path_id != observed.path_id],
        ]
    graph_payload = trace.get("observed_graph")
    if not graph_payload:
        return
    observed_graph = KnowledgeGraph.model_validate(graph_payload)
    existing = {node.node_id for node in result.graph.nodes}
    for node in observed_graph.nodes:
        if node.node_id not in existing:
            result.graph.nodes.append(node)
            existing.add(node.node_id)
    result.graph.edges.extend(observed_graph.edges)


if __name__ == "__main__":
    raise SystemExit(main())
