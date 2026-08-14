"""Export adapters from V5 drafts toward CyberRange / LADE / Infinity packs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from V5.export.cr_pack import build_cr_scenario_pack, write_cr_scenario_pack

__all__ = ["build_cr_scenario_pack", "write_cr_scenario_pack"]


def __getattr__(name: str):
    if name in __all__:
        from V5.export import cr_pack

        return getattr(cr_pack, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
