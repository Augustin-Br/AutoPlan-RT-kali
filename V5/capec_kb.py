"""MITRE CAPEC knowledge base — attack pattern plausibility for LLM paths."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_KB = Path(__file__).resolve().parent / "data" / "capec_patterns.json"
FALLBACK_KB = Path(__file__).resolve().parent / "data" / "capec_patterns_seed.json"

PREREQ_PENALTY = 0.18


@dataclass(frozen=True)
class CapecPattern:
    pattern_id: str
    name: str
    related_attack_techniques: tuple[str, ...]
    prerequisite_facts: tuple[str, ...]
    can_precede: tuple[str, ...]


class CapecKnowledgeBase:
    def __init__(
        self,
        patterns: list[CapecPattern],
        *,
        technique_index: dict[str, list[str]],
        tool_hints: dict[str, list[str]],
    ) -> None:
        self._patterns = {item.pattern_id: item for item in patterns}
        self._technique_index = {key.upper(): value for key, value in technique_index.items()}
        self._tool_hints = {key.lower(): value for key, value in tool_hints.items()}

    @classmethod
    def load(cls, path: str | Path | None = None) -> "CapecKnowledgeBase":
        kb_path = Path(path) if path else (DEFAULT_KB if DEFAULT_KB.exists() else FALLBACK_KB)
        payload = json.loads(kb_path.read_text(encoding="utf-8"))
        patterns = [
            CapecPattern(
                pattern_id=item["id"],
                name=item.get("name", item["id"]),
                related_attack_techniques=tuple(item.get("related_attack_techniques", [])),
                prerequisite_facts=tuple(item.get("prerequisite_facts", [])),
                can_precede=tuple(item.get("can_precede", [])),
            )
            for item in payload.get("patterns", [])
        ]
        return cls(
            patterns,
            technique_index=payload.get("technique_index", {}),
            tool_hints=payload.get("tool_hints", {}),
        )

    def get(self, pattern_id: str | None) -> CapecPattern | None:
        if not pattern_id:
            return None
        normalized = pattern_id.upper()
        if normalized.isdigit():
            normalized = f"CAPEC-{normalized}"
        if not normalized.startswith("CAPEC-"):
            normalized = f"CAPEC-{normalized}"
        return self._patterns.get(normalized)

    def resolve_step_capec_ids(self, *, tool_name: str, mitre_technique_id: str | None) -> list[str]:
        candidates: list[str] = []
        tool_lower = tool_name.lower()
        if mitre_technique_id:
            for cid in self._technique_index.get(mitre_technique_id.upper(), []):
                if cid not in candidates:
                    candidates.append(cid)
        for key, capec_ids in self._tool_hints.items():
            if key in tool_lower or tool_lower.endswith("/" + key) or tool_lower == key:
                for cid in capec_ids:
                    if cid not in candidates:
                        candidates.append(cid)
        if tool_lower.startswith(("exploit/", "auxiliary/", "post/")):
            for cid in ("CAPEC-88", "CAPEC-7", "CAPEC-242"):
                if cid not in candidates:
                    candidates.append(cid)
        return candidates[:5]

    def capec_plausibility(
        self,
        steps: list,
        *,
        known_facts: set[str] | None = None,
    ) -> float:
        if not steps:
            return 0.35
        if len(steps) == 1:
            matches = self.resolve_step_capec_ids(
                tool_name=steps[0].tool,
                mitre_technique_id=steps[0].mitre_technique_id,
            )
            return 0.55 if matches else 0.40

        facts = set(known_facts or [])
        step_capec: list[list[str]] = []
        step_scores: list[float] = []

        for index, step in enumerate(sorted(steps, key=lambda item: item.step_index)):
            matches = self.resolve_step_capec_ids(
                tool_name=step.tool,
                mitre_technique_id=step.mitre_technique_id,
            )
            step_capec.append(matches)
            if not matches:
                step_scores.append(0.30)
                continue
            best = 0.50
            for cid in matches:
                pattern = self._patterns.get(cid)
                if not pattern:
                    best = max(best, 0.55)
                    continue
                score = 0.62
                if pattern.related_attack_techniques and step.mitre_technique_id:
                    if step.mitre_technique_id.upper() in {t.upper() for t in pattern.related_attack_techniques}:
                        score += 0.18
                if pattern.prerequisite_facts:
                    if all(req in facts for req in pattern.prerequisite_facts):
                        score += 0.12
                    elif index > 0:
                        score -= PREREQ_PENALTY
                else:
                    score += 0.08
                best = max(best, score)
            step_scores.append(min(1.0, best))
            if step.produces_fact:
                facts.add(step.produces_fact)

        coverage = sum(1 for matches in step_capec if matches) / len(step_capec)
        sequence_bonus = self._sequence_bonus(step_capec)
        step_avg = sum(step_scores) / len(step_scores)
        return min(1.0, 0.40 * coverage + 0.35 * step_avg + 0.25 * sequence_bonus)

    def _sequence_bonus(self, step_capec: list[list[str]]) -> float:
        if len(step_capec) < 2:
            return 0.5
        valid_pairs = 0
        total_pairs = 0
        for left, right in zip(step_capec, step_capec[1:]):
            if not left or not right:
                total_pairs += 1
                continue
            total_pairs += 1
            ok = False
            for lid in left:
                pattern = self._patterns.get(lid)
                if not pattern:
                    continue
                if any(rid in pattern.can_precede for rid in right):
                    ok = True
                    break
                if any(rid in left for rid in right):
                    ok = True
                    break
            if ok:
                valid_pairs += 1
        if total_pairs == 0:
            return 0.5
        ratio = valid_pairs / total_pairs
        if ratio >= 0.5:
            return 0.55 + 0.35 * ratio
        return 0.35 + 0.30 * ratio
