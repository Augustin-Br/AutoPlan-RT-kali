"""Attack pattern store — sequential tool/type plausibility."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from V5.tool_registry import ToolRegistry

DEFAULT_PATTERNS = Path(__file__).resolve().parent / "data" / "attack_patterns.json"


@dataclass(frozen=True)
class AttackPattern:
    pattern_id: str
    type_sequence: tuple[str, ...]
    tool_sequence: tuple[str, ...]
    weight: float
    description: str


class PatternStore:
    def __init__(self, patterns: list[AttackPattern]) -> None:
        self._patterns = patterns

    @classmethod
    def load(cls, path: str | Path | None = None) -> "PatternStore":
        payload = json.loads(Path(path or DEFAULT_PATTERNS).read_text(encoding="utf-8"))
        patterns = [
            AttackPattern(
                pattern_id=item["id"],
                type_sequence=tuple(item.get("sequence", [])),
                tool_sequence=tuple(item.get("tool_sequence", [])),
                weight=float(item.get("weight", 0.5)),
                description=item.get("description", ""),
            )
            for item in payload.get("patterns", [])
        ]
        return cls(patterns)

    def pattern_plausibility(
        self,
        steps: list,
        *,
        tool_registry: ToolRegistry,
    ) -> float:
        if len(steps) < 2:
            return 0.6
        tool_types = []
        tool_names = []
        for step in steps:
            record = tool_registry.lookup(step.tool)
            tool_types.append(record.tool_type if record else step.tool_type)
            tool_names.append(step.tool.lower())
        best = 0.35
        for pattern in self._patterns:
            if pattern.type_sequence and _subsequence(pattern.type_sequence, tool_types):
                best = max(best, 0.55 * pattern.weight + 0.35)
            if pattern.tool_sequence and _subsequence(pattern.tool_sequence, tool_names):
                best = max(best, 0.65 * pattern.weight + 0.30)
        return min(1.0, best)


def _subsequence(pattern: tuple[str, ...], observed: list[str]) -> bool:
    if not pattern:
        return False
    idx = 0
    for item in observed:
        if item == pattern[idx] or pattern[idx] in item:
            idx += 1
            if idx == len(pattern):
                return True
    return False
