"""MITRE ATT&CK knowledge base and probabilistic technique scoring."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_KB = Path(__file__).resolve().parent / "data" / "mitre_techniques.json"
FALLBACK_KB = Path(__file__).resolve().parent / "data" / "mitre_techniques_seed.json"


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    requires_prior: tuple[str, ...]
    typical_tools: tuple[str, ...]


class MitreKnowledgeBase:
    def __init__(self, techniques: list[MitreTechnique]) -> None:
        self._techniques = {item.technique_id: item for item in techniques}

    @classmethod
    def load(cls, path: str | Path | None = None) -> "MitreKnowledgeBase":
        if path is None:
            path = DEFAULT_KB if DEFAULT_KB.exists() else FALLBACK_KB
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        techniques = [
            MitreTechnique(
                technique_id=item["id"],
                name=item["name"],
                tactics=tuple(item.get("tactics", [])),
                requires_prior=tuple(item.get("requires_prior", [])),
                typical_tools=tuple(item.get("typical_tools", [])),
            )
            for item in payload.get("techniques", [])
        ]
        return cls(techniques)

    def get(self, technique_id: str | None) -> MitreTechnique | None:
        if not technique_id:
            return None
        return self._techniques.get(technique_id.upper())

    def mitre_plausibility(
        self,
        *,
        technique_id: str | None,
        tool_name: str,
        known_facts: set[str],
        step_index: int,
    ) -> float:
        technique = self.get(technique_id)
        if not technique:
            return 0.25 if step_index == 1 else 0.15
        score = 0.55
        tool_lower = tool_name.lower()
        if any(tool_lower == t or t in tool_lower for t in technique.typical_tools):
            score += 0.25
        if technique.requires_prior:
            if any(req in known_facts for req in technique.requires_prior):
                score += 0.15
            else:
                score -= 0.20
        else:
            score += 0.10
        return max(0.0, min(1.0, score))
