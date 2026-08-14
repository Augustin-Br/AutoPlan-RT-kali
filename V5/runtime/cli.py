"""Standalone HITL / auto runtime over a saved V5 result JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from V5.models import AttackPath, V5Result
from V5.runtime.hitl import OperatorIO
from V5.runtime.models import RuntimeConfig
from V5.runtime.orchestrator import RuntimeOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute ranked V5 attack paths (HITL or lab-only auto mode)."
    )
    parser.add_argument("--from-result", required=True, help="V5 result JSON with ranked_paths")
    parser.add_argument("--runtime-output", help="Write RuntimeSession JSON")
    parser.add_argument("--runtime-top-k", type=int, default=5)
    parser.add_argument("--runtime-timeout", type=int, default=90)
    parser.add_argument(
        "--runtime-noninteractive",
        help="Script file (one answer per line, or JSONL {\"answer\":...})",
    )
    parser.add_argument(
        "--i-understand-lab-only",
        action="store_true",
        help="Required: acknowledge authorized isolated-lab use only",
    )
    parser.add_argument(
        "--auto-execute",
        action="store_true",
        help="Run without per-step prompts; auto-promote missing tools",
    )
    parser.add_argument(
        "--allow-auto-exploits",
        action="store_true",
        help="Allow msfconsole / exploit/* templates to auto-run (lab only)",
    )
    return parser


def load_ranked_paths(path: str | Path) -> list[AttackPath]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if "ranked_paths" in payload:
        return [AttackPath.model_validate(item) for item in payload["ranked_paths"]]
    result = V5Result.model_validate(payload)
    return result.ranked_paths


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.i_understand_lab_only:
        print("error: refuse to run without --i-understand-lab-only", file=sys.stderr)
        return 2

    io = (
        OperatorIO.from_script_file(args.runtime_noninteractive)
        if args.runtime_noninteractive and not args.auto_execute
        else OperatorIO()
    )
    config = RuntimeConfig(
        top_k=args.runtime_top_k,
        timeout_seconds=args.runtime_timeout,
        lab_ack=True,
        auto_execute=bool(args.auto_execute),
        allow_auto_exploits=bool(args.allow_auto_exploits),
        auto_promote_missing_tools=bool(args.auto_execute),
    )
    paths = load_ranked_paths(args.from_result)
    session = RuntimeOrchestrator(io, config=config).run(paths)

    if args.runtime_output:
        Path(args.runtime_output).write_text(
            json.dumps(session.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(
        f"runtime stop_reason={session.stop_reason} successful_path={session.successful_path_id} "
        f"auto_execute={args.auto_execute} allow_auto_exploits={args.allow_auto_exploits}"
    )
    print(f"attempts={len(session.attempts)} session_allowlist={session.session_allowlist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
