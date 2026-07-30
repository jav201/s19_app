"""batch-71 — AC-6's byte-golden: an unscoped flow run is unchanged by FB-P2.

`R-TUI-099` claims *"a run left at the default scope shall be unchanged from the
single-image path"*. batch-70 shipped that claim with a **structural** guard only
— ``compose_flow_report`` lives in a different module and is not edited — and
recorded the missing byte-golden as an explicit non-claim. This closes it.

**Why the structural guard was not enough, and why this is not vacuous.**
Measured at batch-71 against the pre-FB-P2 parent ``f1f3987``:

- ``s19_app/tui/services/flow_report_service.py`` → **0 diff lines.** A golden of
  the COMPOSER alone could never fail. That test would have been vacuous.
- ``s19_app/tui/services/flow_execution_service.py`` → **+263 / −5.** Two of the
  five deletions are on the UNSCOPED SOURCE path:
  ``ctx.project_dir, block.image_ref,`` and ``if block.file_type == …``, now
  routed through ``_bound_source_ref``. That function returns the identity when
  ``ctx.variant is None`` — and *that identity is exactly what AC-6 asserts*.

So the golden is taken **end-to-end through ``run_flow``**, over a flow that
exercises every block kind, because that is the code that actually changed.

Golden home ``tests/goldens/batch71/`` (mirrors ``batch35``/``batch64``);
comparison via the shared ``conftest.canonical_report_bytes`` — reused, not
re-derived, so capture and comparison cannot drift apart.

Traceability: `AT-212` (behavioural, artifact-on-disk) · `TC-509` (the fixture's
own coverage guard).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.conftest import canonical_report_bytes

from s19_app.tui.services import flow_report_service
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    FLOW_STATUS_OK,
    WRITE_FMT_S19,
    CheckBlock,
    CrcBlock,
    Flow,
    FlowContext,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)

#: Golden home, mirroring ``tests/goldens/batch35/`` and ``batch64/``.
_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batch71"
_AC6_GOLDEN = _GOLDEN_DIR / "ac6-unscoped-flow-report.md"

#: The environment-pin instant. The flow report stamps this into its body AND
#: derives its filename from it, so without the pin nothing here is comparable.
#: It is the same instant the golden was captured under at ``f1f3987``.
_FIXED_INSTANT = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

#: One data record at 0x1000 = 01 02 03 04 -> ranges [(0x1000, 0x1004)].
_S19_SRC = "S107100001020304DE\nS9030000FC\n"


def _change_doc(entries: list[dict], kind: str = "change") -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": kind,
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _crc_config() -> str:
    return json.dumps(
        {
            "polynomial": "0x04C11DB7",
            "init": "0xFFFFFFFF",
            "reverse": True,
            "final_xor": "0xFFFFFFFF",
            "regions": [
                {"start": "0x1000", "end": "0x1004", "output_address": "0x2000"}
            ],
        }
    )


def _build_fixture(root: Path) -> Path:
    """Materialise the same deterministic project the golden was captured from."""
    project = root / ".s19tool" / "workarea" / "ac6"
    project.mkdir(parents=True, exist_ok=True)
    (project / "prg.s19").write_text(_S19_SRC, encoding="utf-8")
    (project / "patch.json").write_text(
        _change_doc([{"type": "bytes", "address": "0x1000", "bytes": "AA"}]),
        encoding="utf-8",
    )
    (project / "check.json").write_text(
        _change_doc(
            [{"type": "bytes", "address": "0x1000", "bytes": "AA"}], kind="check"
        ),
        encoding="utf-8",
    )
    (project / "crc.json").write_text(_crc_config(), encoding="utf-8")
    return project


def _build_flow() -> Flow:
    """Every block kind, in a realistic order.

    A golden over SOURCE + REPORT alone would leave PATCH/CHECK/CRC/WRITE-OUT
    unobserved — and those are branches of the very function that was rewritten.
    """
    return Flow(
        name="ac6 unscoped golden",
        blocks=[
            SourceBlock("prg.s19", file_type=WRITE_FMT_S19),
            PatchBlock("patch.json"),
            CheckBlock("check.json"),
            CrcBlock("crc.json"),
            WriteOutBlock("out.s19", fmt=WRITE_FMT_S19),
            ReportBlock(),
        ],
    )


@pytest.fixture()
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the report clock — the body timestamp AND the filename derive from it."""
    monkeypatch.setattr(
        flow_report_service, "_default_now", lambda: _FIXED_INSTANT
    )


# ---------------------------------------------------------------------------
# AT-212 — the byte-golden itself (AC-6)
# ---------------------------------------------------------------------------

def test_at212_unscoped_flow_report_is_byte_identical_to_the_pre_fbp2_golden(
    tmp_path: Path, _pinned_clock: None
) -> None:
    """An unscoped run writes byte-for-byte what the pre-FB-P2 tree wrote.

    The golden was captured by driving THIS fixture on ``f1f3987`` — the commit
    immediately before FB-P2 merged (``b457ef8``'s parent, verified). If the
    variant dimension ever leaks into the default path, these bytes move.
    """
    project = _build_fixture(tmp_path)

    result = run_flow(_build_flow(), FlowContext(project_dir=project))

    assert result.status == FLOW_STATUS_OK, (
        "the fixture must run clean, else the golden pins a broken document: "
        f"{[(b.kind, b.status, b.diagnostics) for b in result.block_results]}"
    )
    reports = sorted((project / "reports").glob("*.md"))
    assert len(reports) == 1, f"expected exactly one report, got {len(reports)}"

    produced = canonical_report_bytes(reports[0].read_bytes(), run_root=tmp_path)
    golden = canonical_report_bytes(_AC6_GOLDEN.read_bytes())

    assert produced == golden, (
        "the unscoped flow report drifted from the pre-FB-P2 golden.\n"
        "AC-6 says the new variant dimension is ADDITIVE — if this is an "
        "intended change, AC-6 and R-TUI-099 must be amended and the golden "
        "re-captured from the new baseline, never silently overwritten.\n"
        f"--- produced ---\n{produced.decode('utf-8')}\n"
        f"--- golden ---\n{golden.decode('utf-8')}"
    )


# ---------------------------------------------------------------------------
# TC-509 — the fixture must actually cover the edited surface
# ---------------------------------------------------------------------------

def test_tc509_the_golden_fixture_exercises_every_block_kind() -> None:
    """Guard the guard: a golden that stopped covering the edited branches
    would keep passing while proving progressively less.

    This asserts the FIXTURE's coverage, not the product — if someone trims a
    block from ``_build_flow`` to make a failure go away, this goes red first.
    """
    kinds = [type(block) for block in _build_flow().blocks]

    assert kinds == [
        SourceBlock, PatchBlock, CheckBlock, CrcBlock, WriteOutBlock, ReportBlock
    ], "the golden fixture must exercise every block kind the engine supports"


def test_tc509b_the_golden_is_stored_lf_only_and_non_empty() -> None:
    """The stored blob — not the file handed to git — is what must be LF.

    ``tests/goldens/** text eol=lf`` in ``.gitattributes`` normalises on
    checkout, but a golden is only portable if the bytes on disk really are LF;
    a CRLF golden would compare unequal on one platform and equal on the other.
    """
    raw = _AC6_GOLDEN.read_bytes()

    assert raw, "the golden must not be empty"
    assert b"\r\n" not in raw, "the golden must be LF-only"
    assert raw.startswith(b"# Flow report \xe2\x80\x94"), (
        "the golden must be the SINGLE-IMAGE document, never the fused one"
    )
