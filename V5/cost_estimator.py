"""Per-edge and per-path cost estimation for V5.

DEFAULT_EDGE_COSTS combine three evidence classes documented in fps2026_v6 §Cost Model:
  (1) empirical recon measurements (MrRobot traces),
  (2) literature priors (CVSS/EPSS/KEV for exploits; attack-graph conventions),
  (3) scenario assumptions (detection ordinals, destructiveness).
Frozen campaign uses tool_type bucket defaults; per-CVE EPSS lookup is future work.
"""

from __future__ import annotations

from V5.models import AttackPath, PathStep
from V5.tool_registry import ToolRegistry

DEFAULT_EDGE_COSTS = {
    "scanner": {"detection": 0.40, "destructiveness": 0.10, "requests": 100, "time_minutes": 0.5},
    "enumeration": {"detection": 0.20, "destructiveness": 0.08, "requests": 5, "time_minutes": 0.1},
    "bruteforce": {"detection": 0.55, "destructiveness": 0.25, "requests": 200, "time_minutes": 2.0},
    "web_client": {"detection": 0.15, "destructiveness": 0.05, "requests": 2, "time_minutes": 0.05},
    "exploit_framework": {"detection": 0.70, "destructiveness": 0.80, "requests": 10, "time_minutes": 0.3},
    "credential": {"detection": 0.25, "destructiveness": 0.15, "requests": 50, "time_minutes": 5.0},
    "shell": {"detection": 0.45, "destructiveness": 0.35, "requests": 3, "time_minutes": 0.1},
    "other": {"detection": 0.30, "destructiveness": 0.20, "requests": 10, "time_minutes": 0.5},
}


def estimate_edge_cost(step: PathStep, *, tool_registry: ToolRegistry) -> dict[str, float]:
    record = tool_registry.lookup(step.tool)
    tool_type = record.tool_type if record else step.tool_type
    base = DEFAULT_EDGE_COSTS.get(tool_type, DEFAULT_EDGE_COSTS["other"]).copy()
    base["destructiveness"] = max(base["destructiveness"], step.estimated_destructiveness)
    if tool_type == "exploit_framework":
        base["success_probability"] = 0.55
    elif tool_type == "scanner":
        base["success_probability"] = 0.90
    else:
        base["success_probability"] = 0.70
    base["attacker_risk"] = round(
        0.35 * base["detection"] + 0.25 * base["destructiveness"] + 0.20 * min(1.0, base["requests"] / 200),
        4,
    )
    return base


def aggregate_path_costs(edge_costs: list[dict[str, float]]) -> dict[str, float]:
    if not edge_costs:
        return {}
    success = 1.0
    remaining_detection = 1.0
    for cost in edge_costs:
        success *= cost.get("success_probability", 0.5)
        remaining_detection *= 1.0 - cost.get("detection", 0.0)
    return {
        "total_success_probability": round(success, 4),
        "total_detection_probability": round(1.0 - remaining_detection, 4),
        "total_destructiveness": round(max(cost.get("destructiveness", 0.0) for cost in edge_costs), 4),
        "total_requests": int(sum(cost.get("requests", 0) for cost in edge_costs)),
        "total_time_minutes": round(sum(cost.get("time_minutes", 0.0) for cost in edge_costs), 4),
        "total_attacker_risk": round(max(cost.get("attacker_risk", 0.0) for cost in edge_costs), 4),
    }


def strategy_weight(total_cost: dict[str, float], *, strategy: str, steps: list | None = None) -> float:
    success_penalty = 1.0 - total_cost.get("total_success_probability", 0.0)
    detection = total_cost.get("total_detection_probability", 0.0)
    destructiveness = total_cost.get("total_destructiveness", 0.0)
    time_penalty = min(1.0, total_cost.get("total_time_minutes", 0.0) / 10.0)
    request_penalty = min(1.0, total_cost.get("total_requests", 0) / 1000.0)
    if strategy == "success":
        return success_penalty * 0.8 + detection * 0.1 + destructiveness * 0.1
    if strategy == "stealth":
        return detection * 0.45 + destructiveness * 0.25 + request_penalty * 0.15 + success_penalty * 0.15
    if strategy == "fast":
        return time_penalty * 0.7 + success_penalty * 0.2 + request_penalty * 0.1
    if strategy == "cheap":
        return request_penalty * 0.45 + time_penalty * 0.25 + detection * 0.15 + success_penalty * 0.15
    if strategy == "least_destructive":
        score = destructiveness * 0.55 + detection * 0.20 + success_penalty * 0.15 + time_penalty * 0.10
    else:
        score = success_penalty * 0.30 + detection * 0.20 + destructiveness * 0.15 + time_penalty * 0.15 + request_penalty * 0.20
    if steps:
        score += _runbook_fidelity_penalty(steps)
    return score


def _runbook_fidelity_penalty(steps: list) -> float:
    """Prefer complete lab runbooks (wp_crop → john → ssh) over symbolic shortcuts."""
    penalty = 0.0
    tools = [(getattr(step, "tool", "") or "").lower() for step in steps]
    has_setuid = any("setuid_nmap" in tool for tool in tools)
    has_john = any(tool in {"john", "hashcat"} for tool in tools)
    has_wp_crop = any("wp_crop" in tool for tool in tools)

    if has_setuid and not has_john:
        penalty += 0.08
    if has_wp_crop and has_john:
        penalty -= 0.07

    for step in steps:
        fact = getattr(step, "produces_fact", None)
        if fact != "shell_access":
            continue
        tool = (getattr(step, "tool", "") or "").lower()
        if tool.startswith(("exploit/", "post/")):
            continue
        penalty += 0.05
    return penalty


def build_attack_path(
    record,
    *,
    tool_registry: ToolRegistry,
    strategy: str,
) -> AttackPath:
    edge_costs = [estimate_edge_cost(step, tool_registry=tool_registry) for step in record.path.steps]
    total_cost = aggregate_path_costs(edge_costs)
    path = AttackPath(
        path_id=record.path.path_id,
        steps=record.path.steps,
        total_cost=total_cost,
        plausibility=record.plausibility.composite,
    )
    path.strategy = strategy
    path.strategy_score = strategy_weight(total_cost, strategy=strategy, steps=record.path.steps)
    return path
