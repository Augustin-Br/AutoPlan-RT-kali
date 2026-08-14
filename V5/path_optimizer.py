"""Search and rank optimal paths among accepted candidates."""

from __future__ import annotations

from V5.cost_estimator import strategy_weight
from V5.models import AttackPath


def rank_paths(paths: list[AttackPath], *, strategy: str, top_k: int = 5) -> list[AttackPath]:
    ranked = sorted(paths, key=lambda path: (path.strategy_score, -path.plausibility))
    for path in ranked:
        path.strategy = strategy
        path.strategy_score = strategy_weight(path.total_cost, strategy=strategy, steps=path.steps)
    ranked = sorted(ranked, key=lambda path: (path.strategy_score, -path.plausibility))
    if top_k <= 0:
        return ranked
    return ranked[:top_k]


def estimate_max_paths(*, machine_count: int, service_count: int, max_depth: int = 6) -> int:
    """Heuristic upper bound for distinct path candidates."""

    branching = max(2, min(5, service_count))
    return min(50, machine_count * (branching ** min(max_depth, 4)))
