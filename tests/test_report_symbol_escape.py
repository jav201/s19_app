"""Batch-39 S2 (S-F7) — report ``linkage_symbol`` markdown-table escape.

Coverage map:

- AC-2.1 — ``test_hostile_linkage_symbol_md_escaped``: a change entry whose
  ``linkage_symbol`` carries table-breaking / markup metacharacters (a raw
  ``|``, a backslash, a newline, a control char) is rendered escaped in the
  Modifications table of the generated project report — the pipe becomes
  ``\\|``, the backslash is doubled, the newline/control char is stripped —
  so the file-derived symbol cannot break the markdown row or shift columns.
  The load-bearing counterfactual: RED pre-fix (raw ``|`` breaks the table),
  GREEN post-fix.
- AC-2.1 (benign no-op) — ``test_benign_linkage_symbol_unchanged``: a plain
  identifier symbol round-trips byte-identical (``_md_table_cell`` is a no-op
  on symbols free of ``|`` / ``\\`` / control chars), guarding the goldens.

Confidentiality (F-S-07): every fixture is a synthetic in-memory byte run —
never operator firmware.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from s19_app.tui.changes.model import (
    DISPOSITION_DOMAIN,
    ChangeSummary,
    ChangeSummaryEntry,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.report_service import (
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import (
    VariantExecutionResult,
)

FIXED_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)


def _fixed_clock() -> datetime:
    return FIXED_NOW


def _counts(applied: int = 0) -> dict[str, int]:
    counts = {token: 0 for token in DISPOSITION_DOMAIN}
    counts["applied"] = applied
    return counts


def _applied_entry(
    start: int,
    before: Sequence[int],
    after: Sequence[int],
    linkage: str = "standalone",
    symbol: Optional[str] = None,
) -> ChangeSummaryEntry:
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=start,
        address_end=start + len(after),
        before_bytes=tuple(before),
        after_bytes=tuple(after),
        disposition="applied",
        linkage=linkage,
        linkage_symbol=symbol,
    )


def _summary(entries: Sequence[ChangeSummaryEntry]) -> ChangeSummary:
    applied = sum(1 for entry in entries if entry.disposition == "applied")
    return ChangeSummary(
        source_path=Path("chg.json"),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-06-10T11:00:00+00:00",
        variant_id="a",
        counts=_counts(applied),
        entries=list(entries),
        issues=[],
        saved_path=None,
    )


def _variant_set() -> ProjectVariantSet:
    return ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(variant_id="a", path=Path("a.s19"), file_type="s19"),
        ),
        active_id="a",
    )


def _generate(entry: ChangeSummaryEntry, tmp_path: Path) -> str:
    results = [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            change_summaries=[_summary([entry])],
            check_results=[],
            mem_map={},
        )
    ]
    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(),
        variant_set=_variant_set(),
        now_fn=_fixed_clock,
    )
    return path.read_text(encoding="utf-8")


def _modifications_row(text: str) -> str:
    return next(
        ln for ln in text.splitlines() if ln.startswith("| 0x00001000 |")
    )


def test_hostile_linkage_symbol_md_escaped(tmp_path: Path) -> None:
    """A pipe/backslash/control-char symbol is escaped in the md row (AC-2.1).

    Intent: S-F7 — the ``linkage_symbol`` is the only unescaped file-derived
    field on the Modifications row (``report_service.py:977``). A hostile
    symbol carrying a raw ``|`` would open extra table columns and shift the
    row; a bare ``\\`` and control chars corrupt the cell. After the
    ``_md_table_cell`` fix the pipe is ``\\|``, the backslash is doubled, and
    the control/newline chars are stripped — the row keeps its 6-cell shape.
    RED pre-fix (raw ``|`` present, extra structural pipes); GREEN post-fix.
    """
    evil = "EVIL|SYM\\PATH\x01\nEND"
    text = _generate(
        _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "mac-linked", evil),
        tmp_path,
    )
    row = _modifications_row(text)

    # The pipe is escaped, the backslash doubled, control/newline stripped.
    assert "EVIL\\|SYM\\\\PATHEND" in row
    # No raw table-breaking pipe survives inside the symbol cell.
    assert "EVIL|SYM" not in row
    assert "\x01" not in text
    # Row keeps exactly 6 cells => 7 structural (unescaped) pipes.
    structural = re.findall(r"(?<!\\)\|", row)
    assert len(structural) == 7


def test_benign_linkage_symbol_unchanged(tmp_path: Path) -> None:
    """A plain identifier symbol is byte-identical (no-op) — guards goldens.

    Intent: ``_md_table_cell`` only rewrites ``|`` / ``\\`` / control chars,
    so a benign symbol must render exactly as before the fix — this is why
    the byte-identity report goldens with benign symbols stay unchanged
    (AC-2.2 / C-24).
    """
    text = _generate(
        _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "mac-linked", "SYM_A"),
        tmp_path,
    )
    assert "| 0x00001000 | 2 | 01 02 | AA BB | mac-linked | SYM_A |" in text
