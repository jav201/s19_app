"""
CDFX (ASAM CDF 2.0) format handler + memory-field change model for s19_app.

This package began (batch-03) as the CDFX format handler: the parameter
change-list model and the CDFX read/write handler. Batch-04 extends it — as a
**peer addition, not a new architectural layer** — with the memory-field
change concern: a raw ``(memory address -> new bytes)`` change model, a unified
change-set composing both change kinds, a JSON file handler, and a selective
export coordinator. The directory keeps the ``cdfx`` name; the package scope is
now "the CDFX format handler **and** the memory-field / unified-change-set
concern", both sitting beside the parsers (``parsers -> engine -> tui``) so all
serialize/parse logic stays out of ``app.py`` (constraint C-7 / LLR-007.5).

The concerns are split one-per-module:

- ``changelist`` — the pure parameter change-list model (batch-03).
- ``resolve``    — parameter resolution against the enriched A2L payload.
- ``display``    — type-driven parameter value display formatting.
- ``writer``     — CDFX writer + the standalone ``W-*`` validator.
- ``reader``     — CDFX reader + read-time ``R-*`` validation + XML-safety.
- ``memory``          — the memory-field change model (batch-04, increment 1).
- ``memory_validate`` — memory-change validation against the loaded image
  ranges (batch-04, increment 2).
- ``memory_display``  — hex / ASCII / decimal display formatting of a
  memory-change entry's stored bytes (batch-04, increment 3).
- ``changeset``       — the unified change-set container composing both the
  parameter ``ChangeList`` and the ``MemoryChangeList`` (batch-04,
  increment 4).
- ``unified_io``      — the unified change-set JSON file handler: the writer
  (batch-04, increment 5) and the reader + ``MF-*`` rule set (increment 6).
- ``export``          — the selective-export coordinator: re-resolves the
  parameter half, calls the unchanged CDFX writer, writes the memory-field
  JSON file, tags per-half issue origin (batch-04, increment 7).

``__init__`` is the package's narrow public import surface: callers do
``from s19_app.tui.cdfx import ChangeList`` and nothing else. The CDFX
read/write entry points (``read_cdfx`` / ``write_cdfx``), the standalone
``W-*`` validator (``validate_w_rules``), the memory-field model
(``MemoryChange`` / ``MemoryChangeList`` / ``MemoryStatus``), the
memory-change validator (``validate_memory_changes``), the memory-change
value formatter (``format_memory_value`` / ``MemoryValueRendering``), the
unified change-set container (``UnifiedChangeSet``), the unified-file
writer / reader (``serialize_unified`` / ``write_unified_to_workarea`` /
``read_unified``) and the selective-export coordinator (``export_unified`` /
``ExportResult`` / ``serialize_memory_field`` /
``write_memory_field_to_workarea``) are all re-exported here so the CDFX
service has one import surface.
"""

from __future__ import annotations

from .changelist import ChangeList, ChangeListEntry, ResolutionStatus
from .changeset import UnifiedChangeSet
from .export import (
    ExportResult,
    export_unified,
    serialize_memory_field,
    write_memory_field_to_workarea,
)
from .memory import MemoryChange, MemoryChangeList, MemoryStatus
from .memory_display import MemoryValueRendering, format_memory_value
from .memory_validate import validate_memory_changes
from .reader import read_cdfx
from .unified_io import read_unified, serialize_unified, write_unified_to_workarea
from .writer import validate_w_rules, write_cdfx, write_cdfx_to_workarea

__all__ = [
    "ChangeList",
    "ChangeListEntry",
    "ExportResult",
    "MemoryChange",
    "MemoryChangeList",
    "MemoryStatus",
    "MemoryValueRendering",
    "ResolutionStatus",
    "UnifiedChangeSet",
    "export_unified",
    "format_memory_value",
    "read_cdfx",
    "read_unified",
    "serialize_memory_field",
    "serialize_unified",
    "validate_memory_changes",
    "validate_w_rules",
    "write_cdfx",
    "write_cdfx_to_workarea",
    "write_memory_field_to_workarea",
    "write_unified_to_workarea",
]
