"""batch-63 D3 (R-TUI-097 / HLR-102) — one document encoder; accounting is an
unchanged upper bound.

The defect: ``_line_bytes`` (``report_service.py:394``) charges one byte per line
while the writers open in TEXT mode, so on a host where ``os.linesep`` is CRLF the
file is larger than the budget accounted for it — by exactly ``N - 2`` bytes
(measured 7/7 in ``.dev-flow/2026-07-26-batch-63/00b-measurements-rescoped.md``).
In ``flow_report_service`` the same allocator *gates emission* (``:310``), so the
undercount decides whether a section is written at all.

Why the gates below are shaped the way they are — three vacuous acceptances were
authored for this defect before these survived (see 00b M-7 and the Phase-2
re-gate):

* An assertion relating ``_line_bytes`` to ``"\\n".join`` cannot fail: both are
  pure functions of ``lines`` and the fix changes neither, so the writer never
  appears in the expression.
* "The written file contains no CR" is GREEN pre-fix on ``ubuntu-latest``, which
  is where the merge gate runs (``.github/workflows/tui-ci.yml:25,:61``) — the
  unpatched writer already emits LF there.
* "``report_bytes`` exists" is a property of the SYMBOL, not of the defect.

What survives is (a) mutating the encoder and observing THE FILE, and (b) a
structural census whose input set is derived from the import graph.
"""

from __future__ import annotations

import ast
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.tui.services import report_service as rs
from s19_app.tui.services.report_service import ReportOptions, generate_project_report

from test_report_service import _fixed_clock, _summary, _applied_entry, _variant_set

FIXED_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
LF = chr(10)
CR = chr(13)

#: Modules that consult the shared ``_ByteBudget`` accounting. DERIVED from the
#: import graph by :func:`_accounting_modules`, never hand-listed (C-31): a
#: hand-listed census survives every code mutation while omitting the one member
#: that would fail it.
_SERVICES = Path(rs.__file__).parent


def _accounting_modules() -> list[Path]:
    """Return every service module that shares ``report_service``'s byte accounting.

    Summary:
        Walk the service package's import graph and select the modules that bind
        ``_ByteBudget`` or ``_line_bytes`` from ``report_service``, plus
        ``report_service`` itself (it defines them).

    Returns:
        list[Path]: The derived module set, sorted by name.

    Data Flow:
        - ``s19_app/tui/services/*.py`` -> AST -> ``ImportFrom`` nodes naming the
          accounting symbols -> the module set the census asserts over.

    Dependencies:
        Used by:
            - test_at193_no_accounting_module_writes_in_text_mode
    """
    wanted = {"_ByteBudget", "_line_bytes"}
    found = [Path(rs.__file__)]
    for path in sorted(_SERVICES.glob("*.py")):
        if path.name == Path(rs.__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "report_service":
                if wanted & {alias.name for alias in node.names}:
                    found.append(path)
                    break
    return sorted(found)


def _write_text_calls(path: Path) -> list[int]:
    """Return the line numbers of every ``.write_text(...)`` call in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "write_text"
    ]


def _one_variant_report(tmp_path: Path) -> Path:
    entries = [_applied_entry(0x1000 + 16 * i, (0x01, 0x02), (0xAA, 0xBB)) for i in range(4)]
    results = [
        rs.VariantExecutionResult(
            variant_id="v0",
            status="ok",
            change_summaries=[_summary(entries, source="chg.json", variant_id="v0")],
        )
    ]
    return generate_project_report(
        tmp_path, results, ReportOptions(),
        variant_set=_variant_set("v0"), now_fn=_fixed_clock,
    )


# --------------------------------------------------------------------------
# AT-172 — the encoder is the single seam, and the FILE follows it
# --------------------------------------------------------------------------


def test_at172_replacing_the_encoder_changes_what_the_project_report_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-172 / TC-470 — mutate the encoder, observe the bytes on disk.

    The file is in the expression, which is precisely what the three refuted
    acceptances lacked. RED pre-fix on every platform INCLUDING CI, because
    before the fix the module exposes no encoder to rebind and
    ``generate_project_report`` reaches ``write_text`` regardless.
    """
    sentinel = b"SENTINEL-ENCODER-OUTPUT"
    monkeypatch.setattr(rs, "document_bytes", lambda text: sentinel)

    path = _one_variant_report(tmp_path)

    assert path.read_bytes() == sentinel, (
        "generate_project_report did not obtain its bytes from document_bytes; "
        "the encoder is not the single seam."
    )


def test_at172b_the_unpatched_report_is_exactly_the_encoder_output(tmp_path: Path) -> None:
    """AT-172 / TC-471 — the file equals ``document_bytes`` of the joined document.

    Platform-independent: it never consults ``os.linesep``. This is the clause
    that fails on a text-mode writer wherever ``os.linesep != LF``.
    """
    path = _one_variant_report(tmp_path)
    raw = path.read_bytes()

    assert raw == rs.document_bytes(raw.decode("utf-8")), (
        "the written bytes are not the encoder's output for their own text — "
        "a newline translation happened at write time."
    )
    assert CR.encode() not in raw or os.linesep == LF


# --------------------------------------------------------------------------
# AT-174 — a PIN on the accounting, explicitly NOT a D3 gate
# --------------------------------------------------------------------------


def test_at174_line_bytes_charges_one_byte_per_line(tmp_path: Path) -> None:
    """AT-174 / TC-473 — PIN, not a gate.

    ``_line_bytes`` has ZERO test references on ``031ca8d`` (C-26 reverse census),
    so its convention can be changed today with a fully green suite. This pins the
    ``+1``-per-line charge. It does NOT verify D3 — AT-172/173/193 do that.
    """
    for lines in ([], [""], ["a"], ["ab", "cde"], ["éá", ""]):
        expected = sum(len(line.encode("utf-8")) for line in lines) + len(lines)
        assert rs._line_bytes(lines) == expected


def test_at174b_line_bytes_is_partition_invariant() -> None:
    """AT-174 / TC-474 — PIN on partition-invariance (LLR-102.2).

    The composer accounts in ~12 separate ``emit()`` batches, so the accounting
    function must be independent of how the document is partitioned. Redefining
    ``_line_bytes`` as ``len(LF.join(batch))`` loses one byte per batch boundary
    and undercounts LINEARLY IN THE VARIANT COUNT — worse than the CRLF defect
    this batch fixes, which is bounded at N-2 and zero on Linux.

    Both halves of this pin are load-bearing and neither implies the other:
    ``+1 -> +2`` IS partition-invariant, so invariance alone would miss it; and a
    single-batch check cannot see the composability loss.
    """
    doc = [f"line {i}" for i in range(24)]
    partitions = ([24], [12, 12], [2] * 12, [1, 5, 3, 7, 8])

    totals = set()
    for sizes in partitions:
        parts, i = [], 0
        for size in sizes:
            parts.append(doc[i:i + size])
            i += size
        totals.add(sum(rs._line_bytes(p) for p in parts))

    assert len(totals) == 1, f"accounting is partition-dependent: {sorted(totals)}"
    assert totals.pop() == rs._line_bytes(doc)


# --------------------------------------------------------------------------
# AT-193 — the structural gate CI can actually run
# --------------------------------------------------------------------------


def test_at193_no_accounting_module_writes_in_text_mode() -> None:
    """AT-193 / TC-476 — derived census: nobody sharing the budget uses ``write_text``.

    RED pre-fix on EVERY platform including ``ubuntu-latest``, which is what makes
    it the load-bearing merge-gate check: CI cannot observe D3's behavioural
    difference at all, because on Linux the pre- and post-fix writers are
    byte-identical.

    The module set is derived from the import graph (C-31) and asserted non-empty:
    a hand-listed census survives every code mutation while omitting the member
    that would fail it.
    """
    modules = _accounting_modules()

    assert len(modules) >= 2, (
        f"the derived accounting-module set is implausibly small: {modules}. "
        "An empty or truncated set makes this census vacuous."
    )
    assert {m.name for m in modules} >= {"report_service.py", "flow_report_service.py"}

    offenders = {m.name: _write_text_calls(m) for m in modules if _write_text_calls(m)}
    assert not offenders, (
        f"these modules share the _ByteBudget accounting but write in text mode, "
        f"so the file can differ from what was charged: {offenders}"
    )


# --------------------------------------------------------------------------
# AT-175 — supplementary, Windows-only, NOT verified by the merge gate
# --------------------------------------------------------------------------


@pytest.mark.skipif(os.linesep == LF, reason="AT-175 can only fail where os.linesep != LF")
def test_at175_written_report_carries_no_cr_on_a_crlf_host(tmp_path: Path) -> None:
    """AT-175 — SUPPLEMENTARY. Explicitly NOT verified by the merge gate.

    ``tui-ci`` and ``snapshot-regen`` both run ``ubuntu-latest``, where the
    UNPATCHED writer already emits LF — so this test is GREEN pre-fix on CI and is
    skipped there. It pins the Windows behaviour for a developer running locally;
    it is recorded so the batch cannot imply CI covers D3.
    """
    assert CR.encode() not in _one_variant_report(tmp_path).read_bytes()
