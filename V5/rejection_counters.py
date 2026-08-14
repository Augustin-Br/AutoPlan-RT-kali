"""Map validator rejection reason strings to aggregate counter keys."""

from __future__ import annotations

from typing import Any

COUNTER_KEYS = (
    "unknown_tool",
    "too_similar",
    "plausibility_below_threshold",
    "fact_grounding_violation",
    "defense_violation",
    "topology_violation",
    "recon_cannot_grant_root",
    "unknown_evidence",
    "knowledge_alignment",
    "other",
)


def empty_rejection_counters() -> dict[str, int]:
    return {key: 0 for key in COUNTER_KEYS}


def rejection_reason_to_counter(reason: str) -> str:
    if reason == "too_similar_to_existing_path":
        return "too_similar"
    if reason.startswith("plausibility_below_threshold"):
        return "plausibility_below_threshold"
    if reason == "target_ip_not_in_topology":
        return "topology_violation"
    if reason == "defense_policy_violation":
        return "defense_violation"
    if "unknown_target" in reason:
        return "topology_violation"
    if "unknown_tool:" in reason:
        return "unknown_tool"
    if "recon_cannot_grant_root" in reason:
        return "recon_cannot_grant_root"
    if "defense_" in reason:
        return "defense_violation"
    if "unknown_evidence" in reason:
        return "unknown_evidence"
    if "knowledge_level" in reason:
        return "knowledge_alignment"
    if any(
        token in reason
        for token in (
            "fact_ungrounded",
            "fact_evidence_mismatch",
            "fact_prerequisite_missing",
            "privesc_requires",
            "web_client_cannot_grant",
            "scanner_cannot_grant",
            "ssh_requires_local_credentials",
        )
    ):
        return "fact_grounding_violation"
    return "other"


def increment_rejection_counters(trace: dict[str, Any], reasons: list[str]) -> None:
    counters = trace.setdefault("rejection_counters", empty_rejection_counters())
    for reason in reasons:
        key = rejection_reason_to_counter(reason)
        counters[key] = counters.get(key, 0) + 1
