"""Choose the next lab action: follow the drafted scenario, else adapt."""

from __future__ import annotations

from dataclasses import dataclass

from V5.models import AttackPath, PathStep
from V5.runtime.allowlist import _normalize_tool
from V5.runtime.artifacts import http_url, local_name_for_path, wordlist_paths
from V5.runtime.command_suggest import (
    compile_hydra_command,
    module_needs_login_credentials,
    normalize_target_uri,
)
from V5.runtime.world import WorldState

_PLAN_RECON = frozenset({"nmap", "curl", "dirb", "wpscan"})


@dataclass
class AdaptDecision:
    step: PathStep
    command_override: str | None = None
    note: str = ""
    source: str = "plan"
    consumes_plan: bool = False
    consume_tool: str | None = None
    # Local privesc runs only after has_shell (separate action — never chained).
    followup_module: str | None = None
    skip: bool = False
    skip_wpcheck: bool = False


def scenario_needs_web_creds(plan: list[PathStep]) -> bool:
    tools = {_normalize_tool(step.tool) for step in plan}
    return "hydra" in tools or any(module_needs_login_credentials(tool) for tool in tools)


def path_focus_score(path: AttackPath) -> int:
    """Prefer drafted chains that include WP creds + admin foothold, not ssh/desktop noise."""
    tools = [_normalize_tool(step.tool) for step in path.steps]
    score = 0
    if any(module_needs_login_credentials(tool) for tool in tools):
        score += 4
    if "hydra" in tools:
        score += 3
    if any(is_local_privesc(tool) for tool in tools):
        score += 1
    if "ssh" in tools:
        score -= 2
    if any("desktop_privilege" in tool for tool in tools):
        score -= 2
    if any(module_needs_login_credentials(tool) for tool in tools) and "hydra" not in tools:
        score -= 1
    return score


def select_primary_path(paths: list[AttackPath]) -> AttackPath:
    """Pick the drafted path closest to creds → WP admin, not merely rank #1."""
    if not paths:
        raise ValueError("no ranked paths")
    return max(
        paths,
        key=lambda path: (path_focus_score(path), path.strategy_score, path.plausibility),
    )


def useful_merge_steps(
    world: WorldState,
    remaining: list[PathStep],
    extra_steps: list[PathStep],
) -> list[PathStep]:
    """Keep only fallback tools that can still run and are not already queued."""
    have = {_normalize_tool(step.tool) for step in remaining}
    added: list[PathStep] = []
    for step in extra_steps:
        tool = _normalize_tool(step.tool)
        if tool in have:
            continue
        if _permanently_skip(world, tool):
            continue
        if is_local_privesc(tool) and not world.has_shell:
            continue
        have.add(tool)
        added.append(step)
    return added


def choose_next(
    world: WorldState,
    remaining: list[PathStep],
    *,
    last_error: str | None = None,
) -> AdaptDecision | None:
    """Deterministic next action. None → caller may ask the LLM or stop."""
    del last_error  # world.last_error / last_stdout carry failure context
    if world.has_root:
        return None

    prune_remaining(world, remaining)
    needs_creds = scenario_needs_web_creds(remaining) or bool(world.tried & {"hydra_enum", "hydra_pass"})

    if needs_creds and world.robots_body is None and "robots" not in world.tried:
        world.tried.add("robots")
        return _curl_decision(world, "/robots.txt", note="fetch robots.txt before credential attack")

    if world.robots_paths and not world.wordlist_path and "download_dic" not in world.tried:
        targets = wordlist_paths(world.robots_paths)
        if targets:
            world.tried.add("download_dic")
            path = targets[0]
            dest = local_name_for_path(path)
            url = http_url(world.target_ip, world.port, path)
            return _curl_decision(
                world,
                path,
                note=f"download exposed wordlist {path}",
                extra_flags=f"-o {dest}",
                url=url,
            )

    if needs_creds and not world.valid_users and not world.credentials and "hydra_enum" not in world.tried:
        world.tried.add("hydra_enum")
        return _hydra_decision(world, phase="enum", note="enumerate valid WP users")

    if needs_creds and not world.credentials and "hydra_pass" not in world.tried:
        world.tried.add("hydra_pass")
        return _hydra_decision(world, phase="password", note="brute WP password with lab wordlist")

    runnable = _first_runnable(world, remaining)
    if runnable is None:
        return None

    _index, step = runnable
    tool = _normalize_tool(step.tool)
    if tool == "hydra":
        return AdaptDecision(
            step=step,
            note="drop frozen hydra (adaptive hydra already ran)",
            source="skip",
            consumes_plan=True,
            skip=True,
        )

    if (
        module_needs_login_credentials(step.tool)
        and world.credentials
        and "wp_probe" not in world.tried
    ):
        world.tried.add("wp_probe")
        login_path = f"{normalize_target_uri(world.target_uri).rstrip('/')}/wp-login.php"
        return _curl_decision(
            world,
            login_path,
            note="confirm WordPress login surface before admin exploit",
        )

    return AdaptDecision(
        step=step,
        note="follow scenario",
        source="plan",
        consumes_plan=True,
        consume_tool=step.tool,
        followup_module=None,
    )


def prune_remaining(world: WorldState, remaining: list[PathStep]) -> None:
    remaining[:] = [
        step for step in remaining if not _permanently_skip(world, _normalize_tool(step.tool))
    ]


def _permanently_skip(world: WorldState, tool: str) -> bool:
    """Drop tools that will not become useful later in this run."""
    if f"done:{tool}" in world.tried or f"missing:{tool}" in world.tried:
        return True
    if tool == "ssh":
        return True
    if tool == "hydra" and (world.credentials or "hydra_pass" in world.tried):
        return True
    if "desktop_privilege" in tool:
        return True
    if tool in _PLAN_RECON and (world.credentials or "hydra_pass" in world.tried):
        return True
    return False


def _first_runnable(world: WorldState, remaining: list[PathStep]) -> tuple[int, PathStep] | None:
    for index, step in enumerate(remaining):
        tool = _normalize_tool(step.tool)
        if _permanently_skip(world, tool) and tool != "hydra":
            continue
        if tool == "hydra":
            return index, step
        if module_needs_login_credentials(step.tool) and not world.credentials:
            continue
        if is_local_privesc(tool) and not world.has_shell:
            continue
        if f"missing:{tool}" in world.tried:
            continue
        if f"done:{tool}" in world.tried:
            continue
        return index, step
    return None


def is_local_privesc(tool: str) -> bool:
    lowered = tool.lower()
    return lowered.startswith(("exploit/linux/local/", "exploit/unix/local/")) or "nmap_interactive" in lowered


def _curl_decision(
    world: WorldState,
    path: str,
    *,
    note: str,
    extra_flags: str = "",
    url: str | None = None,
) -> AdaptDecision:
    target = url or http_url(world.target_ip, world.port, path)
    flags = extra_flags.strip()
    command = " ".join(part for part in ("curl", "-sS", "--max-time", "30", flags, target) if part)
    step = PathStep(
        step_index=1,
        tool="curl",
        tool_type="web_client",
        target_ip=world.target_ip,
        port=world.port or 80,
        service="HTTP",
        produces_fact="service_intelligence",
        justification=note,
    )
    return AdaptDecision(step=step, command_override=command, note=note, source="policy")


def _hydra_decision(world: WorldState, *, phase: str, note: str) -> AdaptDecision:
    step = PathStep(
        step_index=2,
        tool="hydra",
        tool_type="bruteforce",
        target_ip=world.target_ip,
        port=world.port or 80,
        service="HTTP",
        produces_fact="credential_access",
        justification=note,
    )
    command = compile_hydra_command(
        step,
        phase=phase,
        users=world.valid_users,
        passwords_file=world.wordlist_path,
    )
    return AdaptDecision(step=step, command_override=command, note=note, source="policy")
