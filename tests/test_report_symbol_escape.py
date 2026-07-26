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
- AC-2.1 (benign) — ``test_benign_linkage_symbol_escapes_invisibly``: a plain
  identifier carries the escape in the SOURCE and renders unchanged to the
  reader. (Was "round-trips byte-identical" until batch-62 measured that claim
  false — ``_`` is escaped, so ``SYM_A`` is ``SYM\\_A`` on disk.)

batch-62 extends this file with the acceptance tests for the escaping batch,
since ``_md_table_cell`` — the helper batch-39 added here — is what it replaces:

- **AT-159** positional cell content survives a pipe-injecting symbol.
- **AT-160** the re-captured golden carries the intended escaped forms.
- **AT-162** Mode-B paths keep byte fidelity and leak no host root (R-1).
- **AT-163** the escape is applied exactly once, asserted at the sink.

Confidentiality (F-S-07): every fixture is a synthetic in-memory byte run —
never operator firmware.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from markdown_it import MarkdownIt

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

    # §6.5 A-03 re-baseline (batch-62): `_md_table_cell` was replaced by
    # `markdown_safety.md_safe`, which is a strict superset on the security axis
    # but NOT byte-identical. Two differences, both deliberate:
    #   BEFORE `EVIL\|SYM\\PATHEND`  — ctl and newline DELETED
    #   AFTER  `EVIL\|SYM\\PATH<FFFD> END` — ctl becomes a VISIBLE loss marker,
    #                                        newline becomes a space
    # Deleting characters from an evidentiary record turns one symbol into a
    # different one silently; the marker keeps the edit legible.
    assert "EVIL\\|SYM\\\\PATH� END" in row
    # No raw table-breaking pipe survives inside the symbol cell.
    assert "EVIL|SYM" not in row
    assert "\x01" not in text
    # Row keeps exactly 6 cells => 7 structural (unescaped) pipes.
    #
    # RETAINED, not replaced (§6.5 A-22 / D-27). Batch-62 initially recorded
    # this guard as "blind to this class" and was measurably wrong: it counts
    # pipes in the RAW SOURCE, so a hostile pipe yields 8 != 7 and goes RED. It
    # is blind to the other 32 fields and to every pipe-free payload, which is
    # what the new token-level ATs cover — so the two are complementary and
    # this one stays.
    structural = re.findall(r"(?<!\\)\|", row)
    assert len(structural) == 7


def test_benign_linkage_symbol_escapes_invisibly(tmp_path: Path) -> None:
    """A plain identifier renders unchanged TO THE READER, not byte-identically.

    §6.5 A-03 re-baseline (batch-62). BEFORE, this asserted the raw bytes
    ``| … | mac-linked | SYM_A |`` on the claim that the escaper is a no-op on
    benign symbols. That claim was measured FALSE — ``_`` is in the escape set,
    so ``SYM_A`` becomes ``SYM\\_A`` on disk.

    The property worth guarding was never byte identity; it is that the escape
    is INVISIBLE once rendered. So the assertion moves down a layer: the source
    carries the escape, and the reader sees the original identifier. That is
    strictly stronger — the old form would have passed on an escaper that
    mangled the displayed text, as long as the bytes happened to match.

    ``mac-linked`` also pins A-43: an interior hyphen is never escaped, only a
    leading one.
    """
    text = _generate(
        _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "mac-linked", "SYM_A"),
        tmp_path,
    )
    assert "| 0x00001000 | 2 | 01 02 | AA BB | mac-linked | SYM\\_A |" in text
    assert _cells_of_row(text, "0x00001000")[-1] == "SYM_A"


# --------------------------------------------------------------------------- #
# batch-62 acceptance tests — AT-159, AT-160, AT-162, AT-163
# --------------------------------------------------------------------------- #


def _walk_tokens(tokens):
    for tok in tokens:
        yield tok
        if tok.children:
            yield from _walk_tokens(tok.children)


def _cells_of_row(text: str, first_cell: str) -> list:
    """Positional cell content of the body row whose first cell is `first_cell`.

    Parses the WHOLE report rather than reconstructing a header, because the
    header width is exactly what the attack manipulates — synthesising one from
    a pipe count reads the escaped pipes too and lands on the wrong width.

    This is the observable a pipe-count or cell-COUNT assertion cannot see:
    markdown-it caps a row at the header width, so injected pipes never grow the
    row — they SHIFT values between columns and drop the overflow, with the cell
    count unchanged.
    """
    rows: list = []
    current: list = []
    in_body = in_cell = False
    for tok in _walk_tokens(MarkdownIt("gfm-like").parse(text)):
        if tok.type == "tbody_open":
            in_body = True
        elif tok.type == "tbody_close":
            in_body = False
        elif tok.type == "tr_open" and in_body:
            current = []
        elif tok.type == "tr_close" and in_body:
            rows.append(current)
        elif tok.type == "td_open" and in_body:
            in_cell = True
        elif tok.type == "inline" and in_cell:
            current.append("".join(
                c.content for c in _walk_tokens([tok]) if c.type == "text"
            ))
            in_cell = False
    for row in rows:
        if row and row[0] == first_cell:
            return row
    return []


def test_at159_hostile_symbol_cannot_shift_table_columns(tmp_path: Path) -> None:
    """AT-159 (US-B62-3) — rows keep POSITIONAL cell content, not just a count.

    Counterfactual measured at `8d3c504`: an unescaped `EVIL|INJECTED|COL`
    turned `['BENIGN','a.s19','s19','yes']` into `['EVIL','INJECTED','COL','a.s19']`
    — the file type and active flag silently destroyed while the cell count
    stayed 4. A count assertion is GREEN on that input, which is why this AT
    asserts the cells verbatim.
    """
    text = _generate(
        _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB),
                       "standalone", "EVIL|INJECTED|COL"),
        tmp_path,
    )
    cells = _cells_of_row(text, "0x00001000")
    assert cells == ["0x00001000", "2", "01 02", "AA BB",
                     "standalone", "EVIL|INJECTED|COL"]


def test_at160_recaptured_golden_carries_the_escaped_forms(tmp_path: Path) -> None:
    """AT-160 — the golden's three drifted lines carry the intended forms.

    Deliberately NOT "the report is byte-identical to the golden": that golden
    was re-captured FROM this code, so byte-identity is true by construction and
    carries no information (the seam test already owns the anti-drift duty). The
    information is in WHICH lines moved and to what — the Inc-2 gate asserted
    the changed-line set is exactly {14, 15, 51}, and this node pins the content
    so a later "cleanup" of the escaping cannot pass silently.
    """
    golden = (Path(__file__).parent / "goldens" / "batch35"
              / "at055b-project-report.md").read_text(encoding="utf-8")
    lines = golden.splitlines()
    assert lines[13] == "| a | a\\.s19 | s19 | yes |"
    assert lines[14] == "| b | b\\.s19 | s19 | no |"
    # Mode B: wrapped in a code span, and NOT escaped — the run-root token has
    # to survive as raw bytes for the canonicaliser to substitute it.
    assert lines[50].startswith("- `<RUN-ROOT>/.s19tool/workarea/proj/chg.json`")
    assert "\\." not in lines[50], "a path took Mode A — CN-6 would break"


def test_at162_paths_render_without_inserted_escapes(tmp_path: Path) -> None:
    """AT-162 (R-1) — Mode-B paths stay byte-faithful and leak no host root.

    The mode-agnostic backstop: whatever mode a future path field picks, the
    emitted document must still contain no drive letter and no home directory.
    Mode A would escape `\\`, `.`, `/` and `_`, destroying both the run-root
    substring the canonicaliser replaces AND the separator normalisation —
    leaking `C:\\Users\\<operator>\\…` into the compared bytes.
    """
    source = tmp_path / "work" / "chg.json"
    source.parent.mkdir(parents=True, exist_ok=True)
    entry = _applied_entry(0x1000, (0x01,), (0xAA,))
    summary = _summary([entry])
    object.__setattr__(summary, "source_path", source)
    results = [
        VariantExecutionResult(
            variant_id="a", status="ok", change_summaries=[summary],
            check_results=[], mem_map={},
        )
    ]
    text = generate_project_report(
        tmp_path, results, ReportOptions(),
        variant_set=_variant_set(), now_fn=_fixed_clock,
    ).read_text(encoding="utf-8")

    bullet = next(ln for ln in text.splitlines() if "chg.json" in ln)
    assert f"`{source}`" in bullet, "the path was altered or lost its code span"
    assert "\\." not in bullet and "\\/" not in bullet, "escapes reached a path"


def test_at163_escaping_is_applied_exactly_once(tmp_path: Path) -> None:
    """AT-163 — over- AND under-application, detected at the SINK.

    `md_safe` is not idempotent (`a.s19` -> `a\\.s19` -> `a\\\\\\.s19`), so
    "apply it exactly once" is a design obligation. Testing the helper's
    non-idempotence documents a property of the helper and cannot see a double
    application in the COMPOSER — the defect class. This asserts on the emitted
    line instead, which catches both directions.
    """
    text = _generate(
        _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "standalone", "SYM_A"),
        tmp_path,
    )
    row = _modifications_row(text)
    assert "SYM\\_A" in row, "under-applied: the escape is missing"
    assert "SYM\\\\\\_A" not in row, "over-applied: escaped twice"
