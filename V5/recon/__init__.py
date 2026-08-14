"""Optional bounded reconnaissance phase for V5 (separate from attack-path generation)."""

from V5.recon.adapter import (
    diff_infras,
    empty_seed_infra,
    merge_v5_infras,
    recon_report_to_v5,
    v2_infra_to_v5,
)
from V5.recon.models import (
    InfraDiff,
    ReconBudget,
    ReconPhaseResult,
    ReconRunConfig,
    ScanProposal,
    ScanProposalBatch,
)
from V5.recon.orchestrator import ReconOrchestrator
from V5.recon.policy_catalog import compile_proposal, list_templates

__all__ = [
    "InfraDiff",
    "ReconBudget",
    "ReconOrchestrator",
    "ReconPhaseResult",
    "ReconRunConfig",
    "ScanProposal",
    "ScanProposalBatch",
    "compile_proposal",
    "diff_infras",
    "empty_seed_infra",
    "list_templates",
    "merge_v5_infras",
    "recon_report_to_v5",
    "v2_infra_to_v5",
]
