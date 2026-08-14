"""Tool registry — verify LLM-proposed tools against a known database."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REGISTRY = Path(__file__).resolve().parent / "data" / "tools_registry.json"


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str
    aliases: tuple[str, ...]
    tool_type: str
    mitre_techniques: tuple[str, ...]
    description: str


class ToolRegistry:
    def __init__(self, records: list[ToolRecord]) -> None:
        self._records = records
        self._by_id: dict[str, ToolRecord] = {}
        self._alias_index: dict[str, ToolRecord] = {}
        for record in records:
            self._by_id[record.tool_id.lower()] = record
            self._alias_index[record.tool_id.lower()] = record
            for alias in record.aliases:
                self._alias_index[alias.lower()] = record

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ToolRegistry":
        payload = json.loads(Path(path or DEFAULT_REGISTRY).read_text(encoding="utf-8"))
        records = [
            ToolRecord(
                tool_id=item["id"],
                aliases=tuple(item.get("aliases", [])),
                tool_type=item.get("type", "other"),
                mitre_techniques=tuple(item.get("mitre_techniques", [])),
                description=item.get("description", ""),
            )
            for item in payload.get("tools", [])
        ]
        return cls(records)

    def lookup(self, tool_name: str) -> ToolRecord | None:
        normalized = _normalize_tool(tool_name)
        if normalized in self._alias_index:
            return self._alias_index[normalized]
        if _looks_like_msf_module(tool_name):
            return self._by_id.get(normalized)
        for key, record in self._alias_index.items():
            if len(key) < 4:
                continue
            if normalized == key or normalized.endswith("/" + key):
                return record
        return None

    def tool_plausibility(self, tool_name: str) -> tuple[float, str | None]:
        record = self.lookup(tool_name)
        if record:
            return 1.0, record.tool_id
        if _looks_like_msf_module(tool_name):
            return 0.75, tool_name
        if _looks_like_plausible_cli(tool_name):
            return 0.35, None
        return 0.0, None

    def known_tool_ids(self) -> list[str]:
        return sorted(self._by_id.keys())


def _normalize_tool(name: str) -> str:
    return re.sub(r"[^a-z0-9_/\-]+", "", name.strip().lower())


def _looks_like_msf_module(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(("exploit/", "auxiliary/", "payload/", "post/"))


def _looks_like_plausible_cli(name: str) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9_-]{1,30}$", name.lower()))
