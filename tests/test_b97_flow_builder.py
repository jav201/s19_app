"""Batch-97 Flow Builder arms (HLR-146).

Inc-2 arms: the NUL refusal of LLR-146.14 (TC-B97-62, 15 arms plus the
manifest and A2L arms the Code-Wire graph names) and the token half of
LLR-146.6 (TC-B97-18 token arm). Inc-5 arms (the pipeline rail, below the
Inc-2 section): TC-B97-13..20, -47..51, the TCSS mirror and paint arms of
TC-B97-18, the add-form arms of TC-B97-62 (S4-1, LED-…97.23) and AT-B97-06,
-07, -08, -19. Every Inc-5 wait is a bounded poll (``settled`` / ``poll``),
never one fixed ``pilot.pause()`` before an assertion that waits for a render.

Where each NUL check sits (design-proposal I-6, PDR condition PC-17):

* ``dict_to_flow`` — the five single-ref fields and ``a2l_ref`` →
  ``FLOW-UNSAFE-REF`` (before the guard and before the ``output_name`` shape
  check, so a NUL ``output_name`` is ``FLOW-UNSAFE-REF``).
* ``_parse_a2b_entry`` — each binding ``ref`` → ``FLOW-UNSAFE-REF``.
* ``_parse_external_step_entry`` — ``log_ref`` and ``output_path`` →
  ``FLOW-UNSAFE-REF`` (both were accepted on ``main``, not raised).
* ``dict_to_chain_set`` — the template (``_is_plain_template_stem``) and each
  input ref → ``CHAIN-SET-UNSAFE-REF``.
* ``_resolve_manifest_entry`` — every other caller (manifest entries, run-time
  refs, a bound lane input) → ``MANIFEST-PATH-ESCAPE``.
* the ``stat()`` guards of ``load_flow_json`` / ``load_chain_set`` catch
  ``ValueError`` → ``FLOW-JSON-PARSE`` / ``CHAIN-SET-JSON-PARSE``.

Every call is wrapped so a raise is counted, never propagated: on ``main`` the
arms fail at the named ``0 exceptions`` / ``refused`` assertion, not at an
import (PC-11). Each test names the mutation that turns it RED.
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

import pytest

from s19_app.tui import insight_style
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services import variant_execution_service as ves
from s19_app.tui.services.flow_execution_service import (
    ChainSpec,
    run_chain_set,
    run_flow,
)
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    EXTERNAL_MODE_TERMINAL,
    A2BBlock,
    A2BInputBinding,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    FlowContext,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from tests.b97_fixtures import HOSTILE_NUL, nul_flow, nul_set, patch_chain_blocks
from tests.b97_probes import hue_distance

FLOW_UNSAFE_REF = "FLOW-UNSAFE-REF"
CHAIN_SET_UNSAFE_REF = "CHAIN-SET-UNSAFE-REF"
MANIFEST_PATH_ESCAPE = "MANIFEST-PATH-ESCAPE"


def _project(tmp_path: Path) -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    return project_dir


def _call(fn: Callable[..., Any], *args: Any) -> Tuple[Any, Optional[BaseException]]:
    """Run ``fn``; return ``(result, None)`` or ``(None, the exception)``."""
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001 - the arm counts the raise
        return None, exc


def _assert_refused(
    outcome: Tuple[Any, Optional[BaseException]], code: str, field: str
) -> None:
    """0 exceptions, no artifact, exactly one finding of ``code`` naming ``field``."""
    result, exc = outcome
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    artifact, findings = result
    assert artifact is None, f"a NUL in {field} was accepted: {artifact!r}"
    assert len(findings) == 1, [(f.code, f.message) for f in findings]
    assert findings[0].code == code, (findings[0].code, findings[0].message)
    assert field in findings[0].message, findings[0].message


def _arms_flow() -> Flow:
    """One block of every kind that carries a path-bearing field."""
    return Flow(
        name="nul_arms",
        blocks=[
            SourceBlock("prg.s19"),
            PatchBlock("calib_hotfix.json"),
            CheckBlock("baseline.chk.json"),
            CrcBlock("crc.json"),
            A2BBlock(
                image_a=A2BInputBinding("file", "other.s19"),
                image_b=A2BInputBinding("flow", "0"),
            ),
            ExternalStepBlock(
                mode=EXTERNAL_MODE_TERMINAL,
                instruction="python flash.py",
                log_ref="run.log",
                output_path="ext_out.s19",
            ),
            WriteOutBlock("out.s19"),
        ],
    )


def _write_flow(project_dir: Path, payload: dict) -> Path:
    path = project_dir / fps.FLOWS_SUBDIR / "arms.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# (arm id, path into the payload's blocks, the field name the finding names)
# flow_model.py:229, 250, 267, 289, 315, 338, 505, 506 — the eight fields of
# LLR-146.14, in that order.
_FIELD_ARMS: List[Tuple[str, Tuple[Any, ...], str]] = [
    ("image_ref", (0, "image_ref"), "image_ref"),
    ("change_doc_ref", (1, "change_doc_ref"), "change_doc_ref"),
    ("output_name", (6, "output_name"), "output_name"),
    ("check_doc_ref", (2, "check_doc_ref"), "check_doc_ref"),
    ("config_ref", (3, "config_ref"), "config_ref"),
    ("a2b_binding_ref", (4, "image_a", "ref"), "image_a.ref"),
    ("log_ref", (5, "log_ref"), "log_ref"),
    ("output_path", (5, "output_path"), "output_path"),
]


# --------------------------------------------------------------------------- #
# TC-B97-62 — LLR-146.14, a NUL in a ref is refused, never raised
# --------------------------------------------------------------------------- #


def test_tc_b97_62_clean_arms_flow_loads(tmp_path: Path) -> None:
    """Positive control: the envelope every field arm mutates loads clean, so
    a refusal in an arm below is caused by its NUL and nothing else.

    Reddening mutation: none in the source; a fixture edit that makes the
    envelope invalid (e.g. a downstream A2B flow index) turns it RED.
    """
    project_dir = _project(tmp_path)
    path = _write_flow(project_dir, fps.flow_to_dict(_arms_flow()))
    flow, findings = fps.load_flow_json(path, project_dir)
    assert findings == [] and flow is not None


@pytest.mark.parametrize(
    "keys,field", [(keys, field) for _, keys, field in _FIELD_ARMS],
    ids=[arm for arm, _, _ in _FIELD_ARMS],
)
def test_tc_b97_62_nul_in_each_block_field_refuses_the_flow(
    tmp_path: Path, keys: Tuple[Any, ...], field: str
) -> None:
    """One ``load_flow_json`` arm per enumerated block field (8): a NUL in the
    field refuses the whole file with one ``FLOW-UNSAFE-REF`` naming it.

    Reddening mutations: the NUL pre-reject removed from ``dict_to_flow``
    (image_ref / change_doc_ref / output_name / check_doc_ref / config_ref
    are refused under the wrong code — the guard's own NUL arm answers
    ``MANIFEST-PATH-ESCAPE`` — or, for ``output_name``, load), from
    ``_parse_a2b_entry`` (the binding raises) or from
    ``_parse_external_step_entry`` (``log_ref`` / ``output_path`` load).
    """
    project_dir = _project(tmp_path)
    payload = fps.flow_to_dict(_arms_flow())
    target = payload["blocks"]
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = "arm\x00.bin"
    path = _write_flow(project_dir, payload)
    _assert_refused(_call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, field)


def test_tc_b97_62_nul_a2l_ref_refuses_the_flow(tmp_path: Path) -> None:
    """The optional ``a2l_ref`` rides the same grammar as the other read refs,
    so a NUL in it gets the same ``FLOW-UNSAFE-REF``.

    Reddening mutation: the V6b NUL branch removed (the ref is refused under
    the wrong code, the guard's ``MANIFEST-PATH-ESCAPE``).
    """
    project_dir = _project(tmp_path)
    payload = fps.flow_to_dict(_arms_flow())
    payload["blocks"][0]["a2l_ref"] = "demo\x00.a2l"
    path = _write_flow(project_dir, payload)
    _assert_refused(_call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, "a2l_ref")


def test_tc_b97_62_p36_nul_flow_file_refused(tmp_path: Path) -> None:
    """P-36 arm 1: the ``nul_flow`` fixture (``patch_chain`` with
    ``change_doc_ref = HOSTILE_NUL``) is refused by ``load_flow_json``.

    Reddening mutation: the ``dict_to_flow`` NUL pre-reject removed.
    """
    project_dir = _project(tmp_path)
    path = nul_flow(project_dir)
    _assert_refused(
        _call(fps.load_flow_json, path, project_dir), FLOW_UNSAFE_REF, "change_doc_ref"
    )


def test_tc_b97_62_p36_run_flow_over_nul_ref_is_a_block_error(tmp_path: Path) -> None:
    """P-36 arm 2: ``run_flow`` over a flow built in memory with the NUL
    ``change_doc_ref`` records a block error carrying ``MANIFEST-PATH-ESCAPE``
    and never raises.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``
    (its ``resolve()`` raises ``ValueError``).
    """
    project_dir = _project(tmp_path)
    _copy_prg(project_dir)
    flow = Flow(name="nul_mem", blocks=patch_chain_blocks(HOSTILE_NUL))
    result, exc = _call(run_flow, flow, FlowContext(project_dir=project_dir))
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_ERROR, (patch.status, patch.summary)
    assert any(MANIFEST_PATH_ESCAPE in line for line in patch.diagnostics), patch.diagnostics


def test_tc_b97_62_p36_nul_template_refuses_the_set(tmp_path: Path) -> None:
    """P-36 arm 3: the ``nul_set`` fixture (template ``patch\\x00chain``) is
    refused with one ``CHAIN-SET-UNSAFE-REF`` naming the template. On ``main``
    it loads and the later template load raises.

    Reddening mutation: the NUL term removed from ``_is_plain_template_stem``.
    """
    project_dir = _project(tmp_path)
    path = nul_set(project_dir)
    _assert_refused(
        _call(fps.load_chain_set, path, project_dir), CHAIN_SET_UNSAFE_REF, "template"
    )


def test_tc_b97_62_p36_nul_input_ref_refuses_the_set(tmp_path: Path) -> None:
    """P-36 arm 4: a NUL in a chain-set input ref is refused with one
    ``CHAIN-SET-UNSAFE-REF`` naming the inputs ref.

    Reddening mutation: the input-ref NUL branch removed from
    ``dict_to_chain_set`` (the guard's ``resolve()`` raises).
    """
    project_dir = _project(tmp_path)
    entry = fps.ChainSetEntry(chain="lane0", template="patch_chain", inputs=((0, "base\x00.s19"),))
    payload = fps.chain_set_to_dict(fps.ChainSet(name="s", chains=(entry,)))
    path = project_dir / fps.FLOWSETS_SUBDIR / "nul_input.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    _assert_refused(
        _call(fps.load_chain_set, path, project_dir), CHAIN_SET_UNSAFE_REF, "inputs"
    )


def test_tc_b97_62_p36_p50_manifest_guard_refuses_nul_entry(tmp_path: Path) -> None:
    """P-36 arm 5 (also the bound-lane-input path of P-50): the shared guard
    resolves no path for a NUL entry and appends one ``MANIFEST-PATH-ESCAPE``
    naming the context.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path).resolve()
    issues: list = []
    resolved, exc = _call(
        ves._resolve_manifest_entry, project_dir, "base\x00.s19", "SourceBlock.image_ref", issues
    )
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    assert resolved is None
    assert [i.code for i in issues] == [MANIFEST_PATH_ESCAPE], issues
    assert "SourceBlock.image_ref" in issues[0].message


def test_tc_b97_62_p50_bound_lane_input_is_a_block_error(tmp_path: Path) -> None:
    """P-50 at the service: a lane whose SOURCE is bound to ``base\\x00.s19``
    runs to a ``source unresolved`` block error naming ``MANIFEST-PATH-ESCAPE``
    — through ``run_flow`` and the provenance seam ``_chain_inputs`` — and
    never raises. The UI half (``#fx_bind_0_0``) is AT-B97-23, Inc-6.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path)
    _copy_prg(project_dir)
    spec = ChainSpec(
        name="lane0",
        template="patch_chain",
        flow=Flow(name="patch_chain", blocks=patch_chain_blocks()),
        bindings={0: "base\x00.s19"},
    )
    record, exc = _call(run_chain_set, [spec], FlowContext(project_dir=project_dir))
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    source = record.outcomes[0].block_results[0]
    assert source.status == BLOCK_STATUS_ERROR and source.summary == "source unresolved"
    assert any(MANIFEST_PATH_ESCAPE in line for line in source.diagnostics), source.diagnostics


def test_tc_b97_62_manifest_nul_entry_skipped_others_kept(tmp_path: Path) -> None:
    """The Code-Wire ``read_project_manifest`` example: a NUL batch entry is
    skipped with one ``MANIFEST-PATH-ESCAPE``; the other entry is kept.

    Reddening mutation: the NUL branch removed from ``_resolve_manifest_entry``.
    """
    project_dir = _project(tmp_path)
    manifest = {"schema_version": 1, "batch": ["a\x00.s19", "prg.s19"]}
    (project_dir / ves.PROJECT_MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    loaded, exc = _call(ves.read_project_manifest, project_dir)
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    assert [p.name for p in loaded.batch] == ["prg.s19"]
    assert [i.code for i in loaded.issues] == [MANIFEST_PATH_ESCAPE], loaded.issues


@pytest.mark.parametrize(
    "loader,code",
    [(fps.load_flow_json, fps.FLOW_JSON_PARSE), (fps.load_chain_set, fps.CHAIN_SET_JSON_PARSE)],
    ids=["load_flow_json", "load_chain_set"],
)
def test_tc_b97_62_nul_in_the_file_path_is_refused_at_stat(
    tmp_path: Path, loader: Callable[..., Any], code: str
) -> None:
    """A NUL in the file path handed to each ``stat()`` guard (2 arms): the
    ``ValueError`` is caught like an ``OSError`` — no artifact, one finding.

    Reddening mutation: the guard narrowed back to ``except OSError`` (the
    shipped shape, P-36 F).
    """
    project_dir = _project(tmp_path)
    result, exc = _call(loader, project_dir / "flows" / "x\x00.json", project_dir)
    assert exc is None, f"raised {type(exc).__name__}: {exc}"
    artifact, findings = result
    assert artifact is None
    assert [f.code for f in findings] == [code], findings
    assert "ValueError" in findings[0].message


def _copy_prg(project_dir: Path) -> None:
    from tests.b97_fixtures import EXAMPLES_DIR

    (project_dir / "prg.s19").write_bytes((EXAMPLES_DIR / "prg.s19").read_bytes())


# --------------------------------------------------------------------------- #
# TC-B97-18 — LLR-146.6, token arm (the TCSS mirror and the paint: Inc-5)
# --------------------------------------------------------------------------- #


def test_tc_b97_18_waiting_and_crc_tokens_declared_apart() -> None:
    """The two role tokens exist with their decided values (ledger .3,
    operator decision 1) and lie 23.0° apart, at least the 20° the waiting
    role needs (P-40). The in-test control shows the predicate can fail: the
    prototype amber ``#e8a33d`` sits 19.5° from the CRC hue.

    Reddening mutations: ``WAITING_HUMAN = "#e8a33d"`` (19.5°, RED) or either
    token removed / changed.
    """
    assert hasattr(insight_style, "WAITING_HUMAN"), "no WAITING_HUMAN token"
    assert hasattr(insight_style, "CRC_FAMILY"), "no CRC_FAMILY token"
    assert insight_style.WAITING_HUMAN == "#e8ad3d"
    assert insight_style.CRC_FAMILY == "#c9562b"
    distance = hue_distance(insight_style.WAITING_HUMAN, insight_style.CRC_FAMILY)
    assert distance >= 20.0, distance
    assert round(distance, 1) == 23.0, distance
    assert round(hue_distance("#e8a33d", "#c9562b"), 1) == 19.5


# =========================================================================== #
# Inc-5 — the Flow Builder as a pipeline rail (HLR-146, fb_A, decision B)
# =========================================================================== #

from rich.cells import cell_len  # noqa: E402
from textual import events  # noqa: E402
from textual.widgets import Button, Input, Select, Static  # noqa: E402

from s19_app.tui import flow_screens as fs  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.services.flow_model import (  # noqa: E402
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
    FLOW_SCOPE_SINGLE,
)
from tests.b97_fixtures import (  # noqa: E402
    ES_48_9C7BEAF,
    ES_MARKER_RE,
    HOSTILE_C1,
    HOSTILE_CONTENT,
    HOSTILE_NAME,
    PATCHED_OUTPUT,
    REPO_ROOT,
    flow_project,
    hostile_flow_demo,
    load_flow,
    open_flow_builder,
    write_flow,
)
from tests.b97_probes import (  # noqa: E402
    chip_style,
    hue_matches,
    is_displayed,
    painted_rows,
    settle,
    span_colours,
    string_constants,
)

KINDS = [kind for _, kind in fs.FlowBuilderPanel._KIND_OPTIONS]
ADD_INPUTS = (
    "flow_gating", "flow_ref", "flow_ref_a", "flow_ref_b",
    "flow_ext_mode", "flow_ext_instruction", "flow_ext_log", "flow_ext_output",
)
#: LLR-146.3's table: kind -> the add inputs it displays.
KIND_INPUTS = {
    BLOCK_SOURCE: {"flow_ref"},
    BLOCK_PATCH: {"flow_ref"},
    BLOCK_CRC: {"flow_ref"},
    BLOCK_WRITE_OUT: {"flow_ref"},
    BLOCK_CHECK: {"flow_ref", "flow_gating"},
    BLOCK_A2B: {"flow_ref_a", "flow_ref_b"},
    BLOCK_EXTERNAL_STEP: {"flow_ext_mode", "flow_ext_instruction", "flow_ext_log", "flow_ext_output"},
}
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
NUL_TEXT = "x\x00y.s19"


async def poll(pilot, predicate, attempts: int = 60) -> bool:
    """Bounded pump-until that returns the outcome (the assertion stays in the
    test body, so a RED names its own clause)."""
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return True
    return False


def run_builder(tmp_path: Path, size, body, *, project: bool = True):
    """Open the Flow Builder at ``size`` (with the flow project loaded through
    the app's own load when ``project``) and return ``await body(...)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = flow_project(app) if project else None
            panel = await open_flow_builder(app, pilot)
            return await body(app, pilot, panel, project_dir)

    return asyncio.run(_drive())


def need(root, selector: str):
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    return found[0]


def shown(widget) -> bool:
    return is_displayed(widget) and widget.region.width > 0


def displayed_add_inputs(panel) -> set:
    return {wid for wid in ADD_INPUTS if shown(panel.query_one(f"#{wid}"))}


def pipeline_lines(app, panel) -> List[str]:
    """The pipeline as the terminal paints it (one string per row)."""
    return [row.rstrip() for row in painted_rows(app, need(panel, "#flow_pipeline"))]


def card_count(app, panel) -> int:
    """Cards in the emitted pipeline text (C-42: the whole chain, also the
    cards scrolled past the rail's right edge from the 5th card at 118)."""
    lines = need(panel, "#flow_pipeline").render().plain.splitlines()
    return lines[0].count("╭") if lines else 0


async def choose_kind(app, pilot, panel, kind: str) -> None:
    await pilot.click(f"#flow_palette_{kind}")
    await poll(pilot, lambda: str(panel.query_one("#flow_kind", Select).value) == kind)
    await settle(pilot, 2)


async def press(pilot, panel, wid: str, predicate=None) -> None:
    panel.query_one(f"#{wid}", Button).press()
    if predicate is not None:
        await poll(pilot, predicate)
    await settle(pilot, 2)


def result_text(app, panel) -> str:
    return "\n".join(painted_rows(app, panel.query_one("#flow_result")))


def notice_lines(app, panel) -> List[str]:
    notice = panel.query_one("#flow_wiring_notice", Static)
    if not shown(notice):
        return []
    return [r.strip() for r in painted_rows(app, notice) if r.strip()]


# --------------------------------------------------------------------------- #
# TC-B97-13 — LLR-146.1, the pipeline of cards joined by cables
# --------------------------------------------------------------------------- #


def test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas(tmp_path: Path) -> None:
    """TC-B97-13 (LLR-146.1): with ``patch_chain`` loaded at 118x54 the
    numbered list and the grid canvas are not displayed, and the pipeline
    paints 4 cards on one band (all four tops on one row, all four bottoms on
    one row) joined by 3 cables on one row, the kinds in block order. Empty
    arm: with no blocks the pipeline paints one line.

    RED on main (main-observable clause first, PC-11): ``#flow_blocks``
    displayed at (5, 37, 110, 5). Mutation: a cable left out between two cards.
    """

    async def body(app, pilot, panel, project_dir):
        empty = [r for r in pipeline_lines(app, panel) if r.strip()] if panel.query("#flow_pipeline") else None
        await load_flow(app, pilot, "patch_chain")
        await settle(pilot, 2)
        hidden = (not shown(panel.query_one("#flow_blocks")), not shown(panel.query_one("#flow_canvas")))
        assert hidden == (True, True), f"list / canvas displayed: {hidden}"
        return empty, pipeline_lines(app, panel)

    empty, rows = run_builder(tmp_path, (118, 54), body)
    tops = [i for i, r in enumerate(rows) if "╭" in r]
    bottoms = [i for i, r in enumerate(rows) if "╰" in r]
    assert len(tops) == 1 and rows[tops[0]].count("╭") == 4, rows[:2]
    assert len(bottoms) == 1 and rows[bottoms[0]].count("╰") == 4
    cable_rows = [r for r in rows if "▶" in r]
    assert len(cable_rows) == 1 and cable_rows[0].count("▶") == 3, cable_rows
    kind_row = next(r for r in rows if "LOAD" in r)
    positions = [kind_row.find(label) for label in ("LOAD", "PATCH", "CHECK", "WRITE-OUT")]
    assert -1 not in positions and positions == sorted(positions), (kind_row, positions)
    assert empty is not None and len(empty) == 1 and "No blocks yet" in empty[0], empty


# --------------------------------------------------------------------------- #
# TC-B97-14 — LLR-146.2, every placeable kind in the palette
# --------------------------------------------------------------------------- #


def test_tc_b97_14_palette_offers_every_kind_in_order(tmp_path: Path) -> None:
    """TC-B97-14 (LLR-146.2): one ``flow_palette_<kind>`` chip per kind of
    ``_KIND_OPTIONS``, in that order (C-40 limb 2: the expected list is read
    from the panel's own table), and each click sets ``#flow_kind``.

    RED on main (P-13): 4 chips (patch, CRC, A2B, EXT-STEP). Mutation: one
    kind left out of the palette.
    """

    async def body(app, pilot, panel, project_dir):
        chips = [b.id for b in panel.query("#flow_palette Button")]
        assert chips == [f"flow_palette_{k}" for k in KINDS], chips
        got = {}
        for kind in KINDS:
            await pilot.click(f"#flow_palette_{kind}")
            await poll(pilot, lambda: str(panel.query_one("#flow_kind", Select).value) == kind)
            got[kind] = str(panel.query_one("#flow_kind", Select).value)
        return got

    got = run_builder(tmp_path, (118, 54), body, project=False)
    assert len(KINDS) == 7 and KINDS[0] == BLOCK_SOURCE and KINDS[-1] == BLOCK_EXTERNAL_STEP
    assert got == {k: k for k in KINDS}, got


# --------------------------------------------------------------------------- #
# TC-B97-15 — LLR-146.3, the add form shows only the chosen kind's inputs
# --------------------------------------------------------------------------- #


def test_tc_b97_15_add_form_shows_exactly_the_kind_inputs(tmp_path: Path) -> None:
    """TC-B97-15 (LLR-146.3): EXT-STEP shows mode, command, log and output on
    two distinct rows (the gate); every kind shows exactly its table row
    (a regression pin of ``_sync_kind_dependent_visibility``), also after
    switching kinds twice.

    RED on main (P-22): the four EXT-STEP inputs share one row (y 13).
    Mutation: the ext row hidden for EXT-STEP; the gating select shown for
    every kind.
    """

    async def body(app, pilot, panel, project_dir):
        await pilot.click("#flow_palette_external_step")
        await poll(pilot, lambda: shown(panel.query_one("#flow_ext_log")))
        await settle(pilot, 2)
        ext_rows = sorted({panel.query_one(f"#{w}").region.y for w in KIND_INPUTS[BLOCK_EXTERNAL_STEP]})
        assert len(ext_rows) == 2, f"EXT-STEP inputs on {len(ext_rows)} row(s): {ext_rows}"
        seen = {}
        for kind in KINDS + [BLOCK_A2B, BLOCK_CHECK]:
            await choose_kind(app, pilot, panel, kind)
            seen.setdefault(kind, []).append(displayed_add_inputs(panel))
        return seen

    seen = run_builder(tmp_path, (118, 54), body, project=False)
    for kind, readings in seen.items():
        for reading in readings:
            assert reading == KIND_INPUTS[kind], (kind, reading)


# --------------------------------------------------------------------------- #
# TC-B97-16 — LLR-146.4, card text clipped to the card (layer 0)
# --------------------------------------------------------------------------- #

LONG_TITLE = "Calibration hotfix for the release line X"[:40]
LONG_PATH = "C:\\work\\flash\\release\\candidates\\2026\\" + "q" * 3 + "\\fw_app_flashed.s19"
LONG_COMMAND = "./flash.sh --port COM17 --verify --erase-all fw_app_patc.s19"


def test_tc_b97_16_clip_head_and_clip_tail() -> None:
    """TC-B97-16 (LLR-146.4, layer 0): ``clip_head`` keeps the first ``w-1``
    cells and one ``…`` (labels, titles, commands); ``clip_tail`` keeps one
    ``…`` and the last ``w-1`` cells (file names, paths); a text exactly ``w``
    wide is never clipped.

    RED: no ``clip_head`` / ``clip_tail`` on main (the card painter wrote the
    raw text past ``x + w``, P-14). Mutation: the two swapped.
    """
    clip_head = getattr(fs, "clip_head", None)
    clip_tail = getattr(fs, "clip_tail", None)
    assert clip_head is not None and clip_tail is not None
    assert len(LONG_TITLE) == 40 and len(LONG_PATH) == 60 and len(LONG_COMMAND) == 60
    assert clip_head(LONG_TITLE, 21) == LONG_TITLE[:20] + "…"
    assert clip_head(LONG_COMMAND, 21) == LONG_COMMAND[:20] + "…"
    assert clip_tail(LONG_PATH, 21) == "…" + LONG_PATH[-20:]
    assert clip_tail(LONG_PATH, 21).endswith("fw_app_flashed.s19")
    exact = "e" * 21
    assert clip_head(exact, 21) == exact and clip_tail(exact, 21) == exact
    assert cell_len(clip_head(LONG_TITLE, 21)) == 21 == cell_len(clip_tail(LONG_PATH, 21))


def test_tc_b97_16_cards_clip_every_line_to_the_card() -> None:
    """TC-B97-16 (LLR-146.4, card arm): every painted card line is exactly the
    card width; a clipped line holds exactly one ``…``; the command line keeps
    its head (``./flash.sh``), the path lines (source ref, log, output) keep
    their tail (``fw_app_flashed.s19``); a ref exactly the inner width is not
    clipped.

    RED on main (P-14): a 60-cell ref painted past the card. Mutations: a
    tail-keeping command clip (the head clause RED); a head-keeping path clip.
    """
    from s19_app.tui.services.flow_model import (
        EXTERNAL_MODE_TERMINAL,
        ExternalStepBlock,
        SourceBlock,
        WriteOutBlock,
    )

    pipeline_text = getattr(fs, "pipeline_text", None)
    assert pipeline_text is not None
    card_w, cable_w = 24, fs.CABLE_W
    inner = card_w - 4
    exact = "x" * (inner - 4) + ".s19"
    blocks = [
        SourceBlock(LONG_PATH),
        ExternalStepBlock(EXTERNAL_MODE_TERMINAL, LONG_COMMAND, LONG_PATH, LONG_PATH),
        WriteOutBlock(exact),
    ]
    lines = pipeline_text(blocks, card_w).plain.split("\n")
    step = card_w + cable_w
    cards = [[line[i * step: i * step + card_w] for line in lines] for i in range(3)]
    for card in cards:
        for line in card:
            assert cell_len(line) == card_w, repr(line)
    bodies = [[line[2:-2].rstrip() for line in card[1:-1]] for card in cards]
    for body in bodies:
        for text in body:
            assert text.count("…") <= 1, text
    command = [t for t in bodies[1] if t.startswith("./flash.sh")]
    assert command == [LONG_COMMAND[: inner - 1] + "…"], bodies[1]
    paths = [t for card in bodies[:2] for t in card if t.endswith("fw_app_flashed.s19")]
    assert len(paths) == 3, paths  # the source ref, the step's log, the step's output
    assert all(p == "…" + LONG_PATH[-(inner - 1):] for p in paths), paths
    assert exact in bodies[2] and not any("…" in t for t in bodies[2]), bodies[2]


# --------------------------------------------------------------------------- #
# TC-B97-17 — LLR-146.5, the foot row and Run as the one filled action
# --------------------------------------------------------------------------- #


def test_tc_b97_17_run_is_the_one_filled_action_on_one_foot_row(tmp_path: Path) -> None:
    """TC-B97-17 (LLR-146.5): Run, Clear, Save… and Load… share one painted
    row of height 1; with each of the 7 kinds selected the filled list is
    exactly ``['flow_run']``; the selected kind chip's background differs from
    Run's; one press of Run posts one ``RunRequested``.

    RED on main: the four buttons are 3 rows tall. Mutations: a second filled
    chip; the selected kind given the filled class.
    """

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        ids = ("flow_run", "flow_clear", "flow_save", "flow_load")
        geometry = [(panel.query_one(f"#{i}").region.y, panel.query_one(f"#{i}").region.height) for i in ids]
        assert len({y for y, _ in geometry}) == 1 and {h for _, h in geometry} == {1}, geometry
        filled_by_kind, backgrounds = {}, {}
        for kind in KINDS:
            await choose_kind(app, pilot, panel, kind)
            panel.query_one("#flow_pick").focus()
            await settle(pilot, 2)
            filled_by_kind[kind] = [
                w.id for w in panel.query("*")
                if is_displayed(w) and (w.has_class("fill-accent") or (isinstance(w, Button) and w.variant == "primary"))
            ]
            backgrounds[kind] = (
                chip_style(app, panel.query_one(f"#flow_palette_{kind}"))[1],
                chip_style(app, panel.query_one("#flow_run"))[1],
            )
        posted = []
        original = panel.post_message

        def spy(message):
            posted.append(message)
            return original(message)

        panel.post_message = spy
        panel.query_one("#flow_run", Button).press()
        await poll(pilot, lambda: any(isinstance(m, fs.FlowBuilderPanel.RunRequested) for m in posted))
        await settle(pilot, 2)
        runs = [m for m in posted if isinstance(m, fs.FlowBuilderPanel.RunRequested)]
        return filled_by_kind, backgrounds, len(runs)

    filled_by_kind, backgrounds, runs = run_builder(tmp_path, (118, 54), body)
    for kind, filled in filled_by_kind.items():
        assert filled == ["flow_run"], (kind, filled)
    for kind, (chip_bg, run_bg) in backgrounds.items():
        assert chip_bg != run_bg, (kind, chip_bg, run_bg)
    assert runs == 1


# --------------------------------------------------------------------------- #
# TC-B97-18 — LLR-146.6, the CRC card paint (A) and the TCSS mirror (0)
# --------------------------------------------------------------------------- #


def test_tc_b97_18_crc_card_painted_in_the_crc_colour(tmp_path: Path) -> None:
    """TC-B97-18 (LLR-146.6, paint arm, PC-7): with a ``source → patch → crc →
    write_out`` chain at 118x54, the CRC card's kind line, read as painted
    cells (``span_colours`` strip runs), carries a foreground within 4° of
    ``CRC_FAMILY``, and no painted cell of the pipeline lies within 4° of
    ``WAITING_HUMAN`` — hue distance, never hex equality.

    RED: no pipeline on main. Mutations: the CRC card painted with
    ``WAITING_HUMAN``; painted with fb_A's ``#d9a35b`` (17.96° from CRC).
    """

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "crc_chain")
        await settle(pilot, 2)
        return span_colours(app, need(panel, "#flow_pipeline"))

    runs = run_builder(tmp_path, (118, 54), body)
    strips = [r for r in runs if r.source == "strip"]
    crc = [r for r in strips if "CRC" in r.text]
    assert crc, [r.text for r in strips][:20]
    assert any(hue_matches(r.fg, insight_style.CRC_FAMILY) for r in crc), [(r.text, r.fg) for r in crc]
    waiting = [(r.text, r.fg) for r in strips if hue_matches(r.fg, insight_style.WAITING_HUMAN)]
    assert waiting == [], waiting


def test_tc_b97_18_tcss_mirrors_equal_their_tokens() -> None:
    """TC-B97-18 (LLR-146.6, mirror arm, layer 0, LED-…97.22): ``styles.tcss``
    declares ``$crc-family`` and ``$waiting-human`` exactly once each, equal
    (case-folded) to ``insight_style.CRC_FAMILY`` / ``WAITING_HUMAN``, each
    with a ``/* … (insight_style.<NAME>) */`` comment naming its own
    constant, above the first rule line that uses it.

    RED on HEAD ``09e44de``: no mirror declared. Mutations: the two values
    swapped; a mirror removed; the comment naming the other constant.
    """
    lines = (REPO_ROOT / "s19_app" / "tui" / "styles.tcss").read_text(encoding="utf-8").splitlines()
    for variable, name in (("crc-family", "CRC_FAMILY"), ("waiting-human", "WAITING_HUMAN")):
        decl = re.compile(rf"^\${variable}:\s*(#[0-9a-fA-F]{{6}})\s*;\s*/\*.*\(insight_style\.(\w+)\).*\*/\s*$")
        found = [(i, decl.match(line)) for i, line in enumerate(lines) if line.startswith(f"${variable}:")]
        assert len(found) == 1, (variable, found)
        index, match = found[0]
        assert match is not None, lines[index]
        assert match.group(1).lower() == getattr(insight_style, name).lower(), (variable, match.group(1))
        assert match.group(2) == name, (variable, match.group(2))
        uses = [i for i, line in enumerate(lines) if f"${variable}" in line and i != index]
        assert all(i > index for i in uses), (variable, index, uses)


# --------------------------------------------------------------------------- #
# TC-B97-19 — LLR-146.7, the Flow Builder in English
# --------------------------------------------------------------------------- #

FLOW_SCREENS = "s19_app/tui/flow_screens.py"
FROZEN_BUILDER = [value for scope, value in ES_48_9C7BEAF if scope == "FlowBuilderPanel"]


def test_tc_b97_19_builder_reach_guard_on_9c7beaf() -> None:
    """Census (a) over the ``FlowBuilderPanel`` class of ``git show
    9c7beaf:flow_screens.py`` returns exactly the 27 frozen values — so 0 on
    this tree means the census reaches the strings.

    Reddening mutation: a census keyed on line spans instead of the
    ``ClassDef`` node, or one that skips f-string parts.
    """
    try:
        source = subprocess.run(
            ["git", "show", f"9c7beaf:{FLOW_SCREENS}"], cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 9c7beaf unavailable — reach guard cannot run: {exc}")
    found = [v for v in string_constants(source, "FlowBuilderPanel") if ES_MARKER_RE.search(v)]
    assert len(FROZEN_BUILDER) == 27
    assert sorted(found) == sorted(FROZEN_BUILDER), sorted(set(found) ^ set(FROZEN_BUILDER))


def test_tc_b97_19_builder_constants_carry_no_spanish() -> None:
    """TC-B97-19 (LLR-146.7): (a) 0 ``ES_MARKER`` constants in the
    ``FlowBuilderPanel`` class (docstrings excluded) and (b) none of its 27
    frozen values present.

    RED on HEAD: 27 present. Mutation: ``'pegado: '`` left in place (the one
    census (b) catches and the round-2 marker missed).
    """
    constants = string_constants((REPO_ROOT / FLOW_SCREENS).read_text(encoding="utf-8"), "FlowBuilderPanel")
    still_frozen = [v for v in FROZEN_BUILDER if v in constants]
    assert still_frozen == [], still_frozen
    spanish = [v for v in constants if ES_MARKER_RE.search(v)]
    assert spanish == [], spanish


# --------------------------------------------------------------------------- #
# TC-B97-20 — LLR-146.8, file-derived text renders literally (C-17)
# --------------------------------------------------------------------------- #

#: The panel's own foreground colours: every span of the pipeline and the
#: ribbon paints one of these, so a span the payload's markup produced (a
#: ``[red]``, a ``[link=…]``, an ``[@click=…]``) cannot hide among them.
OUR_COLOURS = {
    insight_style.VALUE, insight_style.DGRAY, insight_style.CYAN, insight_style.DEPTH_BORDER,
    insight_style.HILITE, insight_style.GREEN, insight_style.CRC_FAMILY, insight_style.PURPLE,
    insight_style.LBLUE, "#56e0d6",
}


def _span_styles(app, widget) -> List[str]:
    """``fg | style`` of every span of the widget's render (C-37 origin
    check): a span outside the panel's palette, or carrying a link or an
    action, came from the payload."""
    return [
        f"{run.fg} | {span.style}"
        for run, span in zip(
            [r for r in span_colours(app, widget) if r.source == "span"], widget.render().spans
        )
    ]


def _foreign(styles: List[str]) -> List[str]:
    return [
        s for s in styles
        if s.split(" | ")[0] not in OUR_COLOURS or "link" in s or "click" in s or "@" in s
    ]


def test_tc_b97_20_hostile_refs_render_literally(tmp_path: Path) -> None:
    """TC-B97-20 (LLR-146.8): ``hostile_flow`` (file ``HOSTILE_NAME.json``;
    ``change_doc_ref``, ``instruction``, ``log_ref`` = ``HOSTILE_CONTENT +
    HOSTILE_C1``; ``output_path`` = ``HOSTILE_NAME``) loads through
    ``#flow_load`` with 0 ``MarkupError``; on the ribbon and on each of the
    four card fields the brackets paint literally (the clipped value is
    painted as ``clip_*`` of the scrubbed text); every span of the pipeline and
    the ribbon is one of the panel's own styles (0 from the payload); 0
    control characters painted.

    RED: no pipeline on main. Mutation: the card IO line built with
    ``Text.from_markup`` (MarkupError or payload spans).
    """
    safe_text = fs.safe_text  # the panel's own sink (not a new importer, TC-653)

    async def body(app, pilot, panel, project_dir):
        write_flow(project_dir, HOSTILE_NAME, hostile_flow_demo(project_dir))
        await load_flow(app, pilot, HOSTILE_NAME)
        await settle(pilot, 2)
        pipeline = need(panel, "#flow_pipeline")
        ribbon = panel.query_one("#flow_name_strip")
        return (
            pipeline_lines(app, panel),
            list(painted_rows(app, ribbon)),
            _span_styles(app, pipeline) + _span_styles(app, ribbon),
            panel._card_w,
        )

    rows, ribbon, styles, card_w = run_builder(tmp_path, (118, 54), body)
    inner = card_w - 4
    payload = safe_text(HOSTILE_CONTENT + HOSTILE_C1).plain
    painted = "\n".join(rows)
    assert sum(r.count(fs.clip_tail(payload, inner)) for r in rows) == 2  # change_doc_ref, log_ref
    assert fs.clip_head(payload, inner) in painted  # instruction (a command)
    assert fs.clip_tail(HOSTILE_NAME, inner) in painted  # output_path
    assert "[" in fs.clip_tail(payload, inner) and "[" in fs.clip_head(payload, inner)
    assert "[bold]" in "".join(ribbon), ribbon
    assert not CONTROL_CHARS.search(painted + "".join(ribbon))
    assert styles and _foreign(styles) == [], sorted(set(_foreign(styles)))


# --------------------------------------------------------------------------- #
# TC-B97-47 — LLR-146.9, the one-row copy/paste strip
# --------------------------------------------------------------------------- #


def test_tc_b97_47_copy_paste_strip_on_one_row_inside(tmp_path: Path) -> None:
    """TC-B97-47 (LLR-146.9): ``#flow_pick``, ``#flow_copy``, ``#flow_paste``
    and ``#flow_clip_status`` share one painted row, each 1 row tall and inside
    the panel region; copying block 2 and pasting it through the chips adds one
    card.

    RED on main (P-10): ``#flow_clip_status`` overflows the panel. Mutation:
    the status given a fixed width wider than what is left on the row.
    """

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        ids = ("flow_pick", "flow_copy", "flow_paste", "flow_clip_status")
        regions = [panel.query_one(f"#{i}").region for i in ids]
        box = panel.region
        inside = [i for i, r in zip(ids, regions) if r.x >= box.x and r.right <= box.right]
        assert inside == list(ids), f"outside the panel: {set(ids) - set(inside)}"
        assert len({r.y for r in regions}) == 1 and {r.height for r in regions} == {1}, regions
        before = card_count(app, panel)
        panel.query_one("#flow_pick", Input).value = "2"
        await press(pilot, panel, "flow_copy")
        await press(pilot, panel, "flow_paste", lambda: card_count(app, panel) == before + 1)
        return before, card_count(app, panel)

    before, after = run_builder(tmp_path, (118, 54), body)
    assert (before, after) == (4, 5)


# --------------------------------------------------------------------------- #
# TC-B97-48 — LLR-146.10, the Variables (n) chip
# --------------------------------------------------------------------------- #


def test_tc_b97_48_variables_chip_counts_and_toggles(tmp_path: Path) -> None:
    """TC-B97-48 (LLR-146.10): the chip reads ``Variables (0)`` with no
    variable and ``Variables (1)`` after one is added through
    ``#flow_funnel_add``; two presses show then hide the editor.

    RED on main: ``Funnel (0)`` (``flow_screens.py:1243``). Mutation: the
    count left out of the label.
    """

    async def body(app, pilot, panel, project_dir):
        toggle = panel.query_one("#flow_funnel_toggle", Button)
        labels = [str(toggle.label)]
        assert labels[0] == "Variables (0)", labels
        editor = panel.query_one("#flow_funnel_editor")
        displays = []
        await press(pilot, panel, "flow_funnel_toggle", lambda: editor.display)
        displays.append(editor.display)
        panel.query_one("#flow_funnel_name", Input).value = "BOOST"
        panel.query_one("#flow_funnel_value", Input).value = "1.5"
        await press(pilot, panel, "flow_funnel_add", lambda: "1" in str(toggle.label))
        labels.append(str(toggle.label))
        await press(pilot, panel, "flow_funnel_toggle", lambda: not editor.display)
        displays.append(editor.display)
        return labels, displays

    labels, displays = run_builder(tmp_path, (118, 54), body, project=False)
    assert labels == ["Variables (0)", "Variables (1)"]
    assert displays == [True, False]


# --------------------------------------------------------------------------- #
# TC-B97-49 — LLR-146.11, the session directory on the ribbon
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("arm", ["project", "no_project"])
def test_tc_b97_49_session_on_the_ribbon(tmp_path: Path, arm: str) -> None:
    """TC-B97-49 (LLR-146.11): with a project opened through the app's own
    load, the ribbon's painted line ends with the session path's last segment
    and ``#flow_ext_session`` is not displayed; with no project the ribbon
    names the state in English (LLR-148.9).

    RED on main: the session sits in the displayed ``#flow_ext_session``
    (``flow_screens.py:764``). Mutation: the ribbon keeping the path's head.
    """

    async def body(app, pilot, panel, project_dir):
        session = panel.query_one("#flow_ext_session")
        assert not shown(session), "#flow_ext_session is displayed"
        rows = [r.rstrip() for r in painted_rows(app, need(panel, "#flow_ribbon")) if r.strip()]
        return rows, project_dir

    rows, project_dir = run_builder(tmp_path, (118, 54), body, project=arm == "project")
    assert len(rows) == 1, rows
    if arm == "project":
        assert rows[0].endswith(project_dir.name), rows
    else:
        assert rows[0].endswith("(no active project)") and not ES_MARKER_RE.search(rows[0]), rows


# --------------------------------------------------------------------------- #
# TC-B97-49 — LLR-146.11, the ribbon's saved state as a word (gate fold,
# operator decision 3, LED-…97.26; supersedes batch-53's ✓ / ● glyph)
# --------------------------------------------------------------------------- #


def test_tc_b97_49_ribbon_saved_state_is_a_word() -> None:
    """TC-B97-49 (LLR-146.11 as amended by LED-…97.26, layer 0): the ribbon
    reads ``· saved`` in the grey ``DGRAY`` when the flow is saved and
    ``· unsaved`` in the attention ``YELLOW`` when it is dirty; neither
    ``✓`` nor ``●`` is painted on it any more (each kept one meaning only:
    check block, ok).

    Why: on the same screen ``✓`` also meant a CHECK block and ``●`` an ok
    verdict (D6); a word cannot be confused with either. RED on the pre-fold
    tree: ``Flow: demo  ✓``. Mutation: the dirty word painted grey.
    """
    from s19_app.tui.insight_style import DGRAY, YELLOW

    for dirty, word, colour in ((False, "· saved", DGRAY), (True, "· unsaved", YELLOW)):
        text = fs.ribbon_text("demo", dirty, ["source", "patch"], "C:/w/proj1", 108)
        plain = text.plain
        assert word in plain and "✓" not in plain and "●" not in plain, plain
        if not dirty:
            assert "unsaved" not in plain, plain
        start = plain.index(word)
        styles = {str(span.style) for span in text.spans if span.start <= start + 2 < span.end}
        assert any(colour.lower() in style.lower() for style in styles), (word, styles)


def test_tc_b97_49_ribbon_paints_saved_then_unsaved(tmp_path: Path) -> None:
    """TC-B97-49 (LLR-146.11, painted arm): a loaded flow paints ``· saved``
    with no saturated hue (grey); one Add later the ribbon paints ``·
    unsaved`` within 4° of ``YELLOW`` (PC-7: the painted strip, matched by
    hue, never hex equality) and no ``✓`` / ``●`` on either reading.

    RED on the pre-fold tree: the glyphs. Mutation: the dirty word grey.
    """
    from s19_app.tui.insight_style import YELLOW

    def word_runs(app, panel, word):
        return [r for r in span_colours(app, need(panel, "#flow_name_strip"))
                if r.source == "strip" and word in r.text]

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        await poll(pilot, lambda: "saved" in " ".join(painted_rows(app, need(panel, "#flow_name_strip"))))
        saved_row = " ".join(painted_rows(app, need(panel, "#flow_name_strip")))
        saved = word_runs(app, panel, "saved")
        await choose_kind(app, pilot, panel, BLOCK_WRITE_OUT)
        panel.query_one("#flow_ref", Input).value = "more.s19"
        await press(pilot, panel, "flow_add", lambda: "unsaved" in " ".join(painted_rows(app, need(panel, "#flow_name_strip"))))
        dirty_row = " ".join(painted_rows(app, need(panel, "#flow_name_strip")))
        unsaved = word_runs(app, panel, "unsaved")
        return saved_row, saved, dirty_row, unsaved

    saved_row, saved, dirty_row, unsaved = run_builder(tmp_path, (118, 54), body)
    assert "· saved" in saved_row and "unsaved" not in saved_row, saved_row
    assert "· unsaved" in dirty_row, dirty_row
    for row in (saved_row, dirty_row):
        assert "✓" not in row and "●" not in row, row
    assert saved and all(not hue_matches(r.fg, YELLOW) for r in saved), saved
    assert saved and all(r.fg and _saturation(r.fg) < 0.30 for r in saved), saved
    assert unsaved and all(hue_matches(r.fg, YELLOW) for r in unsaved), unsaved


def _saturation(hex_color: str) -> float:
    import colorsys

    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)[1]


# --------------------------------------------------------------------------- #
# LLR-148.9 Builder row, add form · error (gate fold ux M3, LED-…97.28)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "kind,label",
    [(BLOCK_SOURCE, "image file"), (BLOCK_CHECK, "check doc"), (BLOCK_WRITE_OUT, "output file")],
)
def test_tc_b97_58_add_with_an_empty_field_says_what_it_needs(tmp_path: Path, kind, label) -> None:
    """TC-B97-58 (LLR-148.9, Builder add-form error state, LED-…97.28): Add
    with the kind's required field empty adds no block and paints one English
    line in ``#flow_wiring_notice``: ``Add needs <field label> — nothing
    added``; typing the field and pressing Add again appends the card and
    clears the line.

    Why: before the fold the press did nothing and said nothing (ux M3), so
    the user could not tell a refused Add from a missed key. RED on the
    pre-fold tree: no notice line. Mutation: the notice call removed.
    """

    async def body(app, pilot, panel, project_dir):
        await choose_kind(app, pilot, panel, kind)
        panel.query_one("#flow_ref", Input).value = "   "
        before = len(panel._blocks)
        await press(pilot, panel, "flow_add", lambda: bool(notice_lines(app, panel)))
        refused = (len(panel._blocks), notice_lines(app, panel))
        panel.query_one("#flow_ref", Input).value = "given.s19"
        await press(pilot, panel, "flow_add", lambda: len(panel._blocks) == before + 1)
        return before, refused, len(panel._blocks), notice_lines(app, panel)

    before, (after_empty, lines), after_typed, lines_after = run_builder(tmp_path, (118, 54), body)
    assert after_empty == before, f"an empty {label} added a block"
    assert lines == [f"Add needs {label} — nothing added"], lines
    assert after_typed == before + 1 and lines_after == [], (after_typed, lines_after)


@pytest.mark.parametrize("then", ["kind change", "Run"])
def test_tc_b97_58_add_notice_clears_on_kind_change_and_run(tmp_path: Path, then) -> None:
    """TC-B97-58 (LLR-148.9, gate re-read ux L-a): the ``Add needs …`` line
    is about the kind it was raised for, so choosing another kind or pressing
    Run clears it.

    Why: at 118x53 a stale line takes the result area's only spare row and
    pushes the ``wrote …`` line out of view after a good run. Mutation: the
    clear call removed from the palette or Run branch.
    """

    async def body(app, pilot, panel, project_dir):
        await choose_kind(app, pilot, panel, BLOCK_CHECK)
        panel.query_one("#flow_ref", Input).value = ""
        await press(pilot, panel, "flow_add", lambda: bool(notice_lines(app, panel)))
        raised = notice_lines(app, panel)
        if then == "kind change":
            await choose_kind(app, pilot, panel, BLOCK_SOURCE)
        else:
            await press(pilot, panel, "flow_run", lambda: not notice_lines(app, panel))
        return raised, notice_lines(app, panel)

    raised, after = run_builder(tmp_path, (118, 54), body)
    assert raised == ["Add needs check doc — nothing added"], raised
    assert after == [], f"the Add notice survived the {then}: {after}"


# --------------------------------------------------------------------------- #
# TC-B97-50 — LLR-146.12, Run is single-image; no scope selector
# --------------------------------------------------------------------------- #


def test_tc_b97_50_run_requests_the_single_image_scope(tmp_path: Path) -> None:
    """TC-B97-50 (LLR-146.12): no ``#flow_scope`` is composed; with a project
    that declares a 3-variant set, Run posts ``FLOW_SCOPE_SINGLE`` and
    ``#flow_result`` paints the single-image ledger (``NOTICES``), 0
    ``variant(s):`` lines.

    RED on main (P-47): ``#flow_scope`` composed (query length 1). Mutation:
    the scope select re-composed and read by Run.
    """
    import shutil

    from s19_app.tui.workspace import build_variant_set, validate_project_files

    async def body(app, pilot, panel, project_dir):
        assert len(app.query("#flow_scope")) == 0, "a scope selector is composed"
        for name in ("prg_b.s19", "prg_c.s19"):
            shutil.copyfile(project_dir / "prg.s19", project_dir / name)
        data_files, _a2l, _error = validate_project_files(project_dir)
        app._variant_set = build_variant_set(project_dir.name, data_files)
        assert len(app._variant_set.variants) == 3
        await load_flow(app, pilot, "patch_chain")
        posted = []
        original = panel.post_message

        def spy(message):
            posted.append(message)
            return original(message)

        panel.post_message = spy
        panel.query_one("#flow_run", Button).press()
        await poll(pilot, lambda: "NOTICES" in result_text(app, panel))
        scopes = [m.scope for m in posted if isinstance(m, fs.FlowBuilderPanel.RunRequested)]
        return scopes, result_text(app, panel)

    scopes, text = run_builder(tmp_path, (118, 54), body)
    assert scopes == [FLOW_SCOPE_SINGLE], scopes
    assert "NOTICES" in text and "variant(s):" not in text, text[:400]


# --------------------------------------------------------------------------- #
# TC-B97-51 — LLR-146.13, the Flow Builder keyboard order
# --------------------------------------------------------------------------- #

KIND_CHIPS = tuple(f"flow_palette_{k}" for k in KINDS)
#: LLR-146.13's groups, in order, with the EXT-STEP form and the funnel editor open.
KEY_GROUPS = (
    ("open_folder_flows", "window_help_flow"),
    KIND_CHIPS,
    ("flow_ext_mode", "flow_ext_instruction", "flow_ext_log", "flow_ext_output"),
    ("flow_add",),
    ("flow_pick", "flow_copy", "flow_paste"),
    ("flow_funnel_toggle",),
    ("flow_funnel_name", "flow_funnel_value", "flow_funnel_add"),
    ("flow_run", "flow_clear", "flow_save", "flow_load"),
)


def _reference_set(screen) -> set:
    """§4 method (b): every displayed, enabled control by TYPE, independent of
    ``can_focus`` — a control whose ``can_focus`` was turned off is still in
    this set and missing from the chain (P-54)."""
    return {
        w.id for w in screen.query("*")
        if w.id and isinstance(w, (Button, Input, Select)) and shown(w) and not w.disabled
    }


def test_tc_b97_51_keyboard_order_keys_and_chip_states(tmp_path: Path) -> None:
    """TC-B97-51 (LLR-146.13): with the EXT-STEP form and the funnel editor
    open the focus chain runs header chips → kind chips → add inputs → Add →
    copy/paste strip → ``Variables (n)`` → funnel editor → foot row with no
    inversion and no displayed control left out; every kind chip sets its kind
    on ``enter`` and on ``space``; ``enter`` acts on one member of each button
    group (Add, Copy, Variables, Add var, Run); the arrow keys scroll the
    pipeline; a focused chip paints differently from an unfocused one, and a
    kind chip's unfocused, focused and selected styles are pairwise distinct.

    RED on main (P-33): 4 kind chips in the chain and ``flow_scope`` between
    paste and Run. Mutation: ``can_focus = False`` on a kind chip; the
    ``space`` binding removed from the kind-chip class.
    """

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        await choose_kind(app, pilot, panel, BLOCK_EXTERNAL_STEP)
        await press(pilot, panel, "flow_funnel_toggle", lambda: panel.query_one("#flow_funnel_editor").display)
        # The chain is sorted by region: read it once every group member shown
        # by the two toggles is laid out (an unlaid widget sorts first).
        await poll(pilot, lambda: all(
            panel.query_one(f"#{wid}").region.width > 0 for ids in KEY_GROUPS[2:] for wid in ids
        ))
        await settle(pilot, 2)
        screen = app.query_one("#screen_flow")
        chain = [w.id for w in app.screen.focus_chain if w.id]
        chips_in_chain = [c for c in chain if c in KIND_CHIPS]
        assert chips_in_chain == list(KIND_CHIPS), chips_in_chain
        index = {wid: g for g, ids in enumerate(KEY_GROUPS) for wid in ids}
        seq = [index[w] for w in chain if w in index]
        members = [sum(1 for w in chain if w in ids) for ids in KEY_GROUPS]
        missing = sorted(_reference_set(screen) - set(chain))
        keyed = {}
        for chip in KIND_CHIPS:
            for key in ("enter", "space"):
                await choose_kind(app, pilot, panel, BLOCK_SOURCE if chip != "flow_palette_source" else BLOCK_PATCH)
                widget = panel.query_one(f"#{chip}")
                widget.focus()
                # Button ignores a key during its 0.2 s press effect.
                await poll(pilot, lambda: app.focused is widget and not widget.has_class("-active"), 120)
                await pilot.press(key)
                kind = chip.removeprefix("flow_palette_")
                await poll(pilot, lambda: str(panel.query_one("#flow_kind", Select).value) == kind)
                keyed[(chip, key)] = str(panel.query_one("#flow_kind", Select).value) == kind
        enters = {}

        async def enter_on(wid, predicate):
            widget = panel.query_one(f"#{wid}")
            widget.focus()
            await poll(pilot, lambda: app.focused is widget and not widget.has_class("-active"), 120)
            await pilot.press("enter")
            enters[wid] = await poll(pilot, predicate)

        await choose_kind(app, pilot, panel, BLOCK_WRITE_OUT)
        panel.query_one("#flow_ref", Input).value = "keyed.s19"
        await enter_on("flow_add", lambda: card_count(app, panel) == 5)
        await enter_on("flow_copy", lambda: "write_out" in str(panel.query_one("#flow_clip_status").render()))
        await enter_on("flow_funnel_toggle", lambda: not panel.query_one("#flow_funnel_editor").display)
        await press(pilot, panel, "flow_funnel_toggle", lambda: panel.query_one("#flow_funnel_editor").display)
        panel.query_one("#flow_funnel_name", Input).value = "KEYED"
        panel.query_one("#flow_funnel_value", Input).value = "1"
        await enter_on("flow_funnel_add", lambda: "(1)" in str(panel.query_one("#flow_funnel_toggle").label))
        await enter_on("flow_run", lambda: bool(result_text(app, panel).strip()) and "No run yet" not in result_text(app, panel))
        scroller = panel.query_one("#flow_pipeline_scroll")
        scroller.focus()
        await poll(pilot, lambda: app.focused is scroller)
        await settle(pilot, 2)
        for _ in range(12):
            await pilot.press("right")
        await poll(pilot, lambda: scroller.scroll_x > 0)
        enters["arrows"] = scroller.scroll_x > 0
        states = {}
        anchor = panel.query_one("#flow_pick")
        await choose_kind(app, pilot, panel, BLOCK_SOURCE)
        for wid in ("flow_palette_patch", "flow_run", "flow_copy"):
            chip = panel.query_one(f"#{wid}")
            anchor.focus()
            await poll(pilot, lambda: app.focused is anchor)
            await settle(pilot, 2)
            unfocused = chip_style(app, chip)
            chip.focus()
            await poll(pilot, lambda: app.focused is chip)
            await settle(pilot, 2)
            states[wid] = [unfocused, chip_style(app, chip)]
        anchor.focus()
        await poll(pilot, lambda: app.focused is anchor)
        await settle(pilot, 2)
        states["flow_palette_patch"].append(chip_style(app, panel.query_one("#flow_palette_source")))
        return seq, members, missing, keyed, enters, states

    seq, members, missing, keyed, enters, states = run_builder(tmp_path, (118, 54), body)
    assert seq == sorted(seq), f"group order inverted: {seq}"
    assert all(n >= 1 for n in members), members
    assert missing == [], f"displayed controls outside the focus chain: {missing}"
    assert all(keyed.values()) and len(keyed) == 14, {k: v for k, v in keyed.items() if not v}
    assert all(enters.values()), enters
    for wid, readings in states.items():
        assert readings[0] != readings[1], (wid, readings)
    unfocused, focused, selected = states["flow_palette_patch"]
    assert len({unfocused, focused, selected}) == 3, states["flow_palette_patch"]


def test_tc_b97_51_space_presses_every_builder_button_group(tmp_path: Path) -> None:
    """TC-B97-51 (LLR-146.13, re-run at Inc-6 for PC-3 / D13): ``space`` acts
    on one member of each Builder button group — Add, Copy, Variables, Add
    var, Run — as ``enter`` does: every button of the flow screens is a
    ``FlowChip``, which binds ``space``.

    Why: a keyboard user should not have to learn that only the kind chips
    take ``space``. RED on HEAD ``b514b07``: only ``KindChip`` binds
    ``space`` (Button binds ``enter`` alone). Mutation: the ``space``
    binding removed from ``FlowChip``.
    """

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        acted = {}

        async def space_on(wid, predicate):
            widget = panel.query_one(f"#{wid}")
            widget.focus()
            await poll(pilot, lambda: app.focused is widget and not widget.has_class("-active"), 120)
            await pilot.press("space")
            acted[wid] = await poll(pilot, predicate)

        await choose_kind(app, pilot, panel, BLOCK_WRITE_OUT)
        panel.query_one("#flow_ref", Input).value = "spaced.s19"
        await space_on("flow_add", lambda: card_count(app, panel) == 5)
        await space_on("flow_copy", lambda: "write_out" in str(panel.query_one("#flow_clip_status").render()))
        await space_on("flow_funnel_toggle", lambda: panel.query_one("#flow_funnel_editor").display)
        panel.query_one("#flow_funnel_name", Input).value = "SPACED"
        panel.query_one("#flow_funnel_value", Input).value = "1"
        await space_on("flow_funnel_add", lambda: "(1)" in str(panel.query_one("#flow_funnel_toggle").label))
        await space_on("flow_run", lambda: bool(result_text(app, panel).strip()) and "No run yet" not in result_text(app, panel))
        return acted

    acted = run_builder(tmp_path, (118, 54), body)
    assert acted and all(acted.values()), acted
    assert len(acted) == 5


# --------------------------------------------------------------------------- #
# TC-B97-62 — LLR-146.14, the add-form arms (Inc-5, S4-1, LED-…97.23)
# --------------------------------------------------------------------------- #

#: (arm = kind.block field, kind, the input the NUL is pasted into, the
#: line's kind and field as the UI labels them — the chip label and the
#: input's label, gate fold ux L1 / LED-…97.28 — the other inputs)
ADD_FORM_ARMS = [
    ("source.image_ref", BLOCK_SOURCE, "#flow_ref", "LOAD image file", {}),
    ("patch.change_doc_ref", BLOCK_PATCH, "#flow_ref", "PATCH change doc", {}),
    ("check.check_doc_ref", BLOCK_CHECK, "#flow_ref", "CHECK check doc", {}),
    ("crc.config_ref", BLOCK_CRC, "#flow_ref", "CRC CRC template", {}),
    ("write_out.output_name", BLOCK_WRITE_OUT, "#flow_ref", "WRITE-OUT output file", {}),
    ("a2b.image_a.ref", BLOCK_A2B, "#flow_ref_a", "A2B-DIFF image A", {"#flow_ref_b": "#1"}),
    ("a2b.image_b.ref", BLOCK_A2B, "#flow_ref_b", "A2B-DIFF image B", {"#flow_ref_a": "#1"}),
    ("external_step.log_ref", BLOCK_EXTERNAL_STEP, "#flow_ext_log", "EXT-STEP log",
     {"#flow_ext_instruction": "echo hi", "#flow_ext_output": "o.s19"}),
    ("external_step.output_path", BLOCK_EXTERNAL_STEP, "#flow_ext_output", "EXT-STEP output file",
     {"#flow_ext_instruction": "echo hi", "#flow_ext_log": "r.log"}),
]


@pytest.mark.parametrize(
    "kind,target,field,others",
    [arm[1:] for arm in ADD_FORM_ARMS],
    ids=[arm[0] for arm in ADD_FORM_ARMS],
)
def test_tc_b97_62_nul_refusal_helper_names_kind_and_field(kind, target, field, others) -> None:
    """TC-B97-62 (layer 0): ``nul_add_refusal`` returns, for the first
    path-bearing input of the kind holding a NUL, the one English line naming
    ``FLOW-UNSAFE-REF``, the kind and the field by their UI labels — the kind
    chip's label and the input's label, e.g. ``WRITE-OUT output file holds a
    NUL character`` (gate fold ux L1, LED-…97.28; the block field names
    before) — (≤ 93 cells, the value never echoed); a clean set returns
    ``None``; a NUL in a non-path input (the EXT-STEP command) is not its
    concern.

    RED: no helper on HEAD (the add form appended the block, S4-1). Mutation:
    the helper reads ``#flow_ref`` only (the A2B and EXT-STEP arms RED).
    """
    helper = getattr(fs, "nul_add_refusal", None)
    assert helper is not None, "no nul_add_refusal"
    values = {**others, target: NUL_TEXT}
    line = helper(kind, values)
    assert line == f"Add refused: [{fps.FLOW_UNSAFE_REF}] {field} holds a NUL character - not a path"
    assert cell_len(line) <= 93 and "\x00" not in line
    assert helper(kind, {**others, target: "clean.s19"}) is None
    assert helper(BLOCK_EXTERNAL_STEP, {"#flow_ext_instruction": NUL_TEXT, "#flow_ext_log": "a", "#flow_ext_output": "b"}) is None


@pytest.mark.parametrize(
    "kind,target,field,others",
    [arm[1:] for arm in ADD_FORM_ARMS],
    ids=[arm[0] for arm in ADD_FORM_ARMS],
)
def test_tc_b97_62_nul_pasted_into_the_add_form_is_refused(tmp_path: Path, kind, target, field, others) -> None:
    """TC-B97-62 (LLR-146.14 add-form arms, A): with one ``source`` block in
    the chain, a NUL pasted (bracketed paste, ``events.Paste``) into the
    kind's path-bearing input and Add pressed adds no block, keeps the input
    as typed and paints one ``#flow_wiring_notice`` line naming
    ``FLOW-UNSAFE-REF``, the kind and the field; 0 exceptions; then Run over
    the chain left in the panel paints no ``ValueError`` / ``embedded null``.

    RED on HEAD ``09e44de`` (``evidence/pc-before-inc5-2026-10-21/
    s41-add-form-arms.txt``): 9 of 9 Adds append the block. Mutation: the
    helper call removed from the ``flow_add`` branch.
    """

    async def set_kind(pilot, panel, value):
        # White-box driver: the kind select the chips set (mounted on main and
        # on the rail), so a run on HEAD fails at the acceptance clause (PC-11).
        panel.query_one("#flow_kind", Select).value = value
        await poll(pilot, lambda: str(panel.query_one("#flow_kind", Select).value) == value)
        await settle(pilot, 2)

    async def body(app, pilot, panel, project_dir):
        await set_kind(pilot, panel, BLOCK_SOURCE)
        panel.query_one("#flow_ref", Input).value = "prg.s19"
        await press(pilot, panel, "flow_add", lambda: len(panel._blocks) == 1)
        await set_kind(pilot, panel, kind)
        for wid, value in others.items():
            panel.query_one(wid, Input).value = value
        box = panel.query_one(target, Input)
        box.focus()
        await settle(pilot, 2)
        box.post_message(events.Paste(NUL_TEXT))
        pasted = await poll(pilot, lambda: "\x00" in box.value)
        before = len(panel._blocks)
        await press(pilot, panel, "flow_add", lambda: bool(notice_lines(app, panel)) or len(panel._blocks) != before)
        outcome = (pasted, before, len(panel._blocks), notice_lines(app, panel), box.value)
        panel.query_one("#flow_run", Button).press()
        await poll(pilot, lambda: bool(panel.query("#flow_result .flow-banner")))
        return outcome, result_text(app, panel)

    (pasted, before, after, lines, value), text = run_builder(tmp_path, (118, 54), body)
    assert pasted, "the paste did not reach the input"
    assert after == before, f"a NUL {field} was added ({before} -> {after})"
    assert len(lines) == 1 and fps.FLOW_UNSAFE_REF in lines[0], lines
    assert field in lines[0], lines
    assert "\x00" in value
    assert "ValueError" not in text and "embedded null" not in text, text[:400]


# --------------------------------------------------------------------------- #
# AT-B97-06 / -07 / -08 / -19 — HLR-146, black-box through the shipped surface
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53)], ids=["118x54", "118x53"])
def test_at_b97_06_chain_on_screen_and_run_writes_the_image(tmp_path: Path, size) -> None:
    """AT-B97-06 (HLR-146): with no blocks ``#flow_run`` is inside the panel at
    scroll 0; ``patch_chain`` loaded through ``#flow_load`` paints 4 cards and
    3 cables on one band with Run still inside; a click on Run paints
    ``NOTICES`` in ``#flow_result`` and creates ``<project>/fw_app_patched.s19``
    (absent before). 118x53 is the body height 118x54 keeps once the Inc-8
    two-row key bar lands (PC-24).

    RED on main (P-11): ``#flow_run (51, 48, 16, 3)`` past the panel bottom 44.
    """

    def inside(panel, wid) -> bool:
        r, box = panel.query_one(f"#{wid}").region, panel.region
        return box.y <= r.y and r.bottom <= box.bottom and box.x <= r.x and r.right <= box.right

    async def body(app, pilot, panel, project_dir):
        empty_ok = inside(panel, "flow_run")
        await load_flow(app, pilot, "patch_chain")
        await settle(pilot, 2)
        run_ok = inside(panel, "flow_run") and panel.scroll_y == 0
        assert run_ok, f"Run at {panel.query_one('#flow_run').region} outside {panel.region}"
        rows = pipeline_lines(app, panel)
        absent = not (project_dir / PATCHED_OUTPUT).exists()
        await pilot.click("#flow_run")
        await poll(pilot, lambda: "NOTICES" in result_text(app, panel))
        return empty_ok, rows, run_ok, absent, result_text(app, panel), (project_dir / PATCHED_OUTPUT).exists()

    empty_ok, rows, run_ok, absent, text, created = run_builder(tmp_path, size, body)
    assert empty_ok and run_ok
    assert sum(r.count("╭") for r in rows) == 4 and len([r for r in rows if "╭" in r]) == 1
    assert sum(r.count("▶") for r in rows) == 3 and len([r for r in rows if "▶" in r]) == 1
    assert "NOTICES" in text, text[:300]
    assert absent and created


def test_at_b97_07_each_kind_its_inputs_and_an_ext_step_card(tmp_path: Path) -> None:
    """AT-B97-07 (HLR-146): a click on each of the 7 kind chips shows exactly
    LLR-146.3's inputs; with EXT-STEP chosen, typing the command, the log and
    the output and clicking Add appends a 5th card; with the log left empty
    Add paints one English refusal line naming the log and adds nothing.

    RED on main (P-13): 4 palette chips.
    """

    async def type_into(pilot, panel, wid, text):
        panel.query_one(f"#{wid}", Input).focus()
        await settle(pilot, 2)
        await pilot.press(*list(text))
        await poll(pilot, lambda: panel.query_one(f"#{wid}", Input).value == text)

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "patch_chain")
        assert len(panel.query("#flow_palette Button")) == 7, len(panel.query("#flow_palette Button"))
        shown_inputs = {}
        for kind in KINDS:
            await choose_kind(app, pilot, panel, kind)
            shown_inputs[kind] = displayed_add_inputs(panel)
        await type_into(pilot, panel, "flow_ext_instruction", "flash2")
        await type_into(pilot, panel, "flow_ext_output", "out2.s19")
        await pilot.click("#flow_add")
        await poll(pilot, lambda: bool(notice_lines(app, panel)))
        refusal = notice_lines(app, panel)
        refused_cards = card_count(app, panel)
        await type_into(pilot, panel, "flow_ext_log", "log2.txt")
        await pilot.click("#flow_add")
        await poll(pilot, lambda: card_count(app, panel) == 5)
        return shown_inputs, refusal, refused_cards, card_count(app, panel), need(panel, "#flow_pipeline").render().plain

    shown_inputs, refusal, refused_cards, cards, rows = run_builder(tmp_path, (118, 54), body)
    assert shown_inputs == KIND_INPUTS
    assert len(refusal) == 1 and "log" in refusal[0] and not ES_MARKER_RE.search(refusal[0]), refusal
    assert refused_cards == 4 and cards == 5
    assert "EXT-STEP" in rows


def test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject(tmp_path: Path) -> None:
    """AT-B97-08 (HLR-146): ``hostile_flow`` loads with its four payload
    fields painted literally (0 control characters, 0 payload spans, the long
    ref clipped with its tail kept); ``nul_flow`` is refused with exactly one
    painted line naming ``FLOW-UNSAFE-REF`` and the previous chain kept;
    ``x\\x00y.s19`` pasted into ``#flow_ref`` with WRITE-OUT chosen adds no
    card and paints one refusal line naming ``FLOW-UNSAFE-REF`` and the
    field as the UI labels it, ``WRITE-OUT output file`` (gate fold ux L1,
    LED-…97.28); then Run paints no ``ValueError``.

    RED on HEAD ``09e44de``: the pasted NUL ``output_name`` is added and Run
    paints ``ValueError: unlink: embedded null character in path`` (S4-1).
    """
    safe_text = fs.safe_text  # the panel's own sink (not a new importer, TC-653)

    from tests.b97_fixtures import nul_flow

    async def body(app, pilot, panel, project_dir):
        write_flow(project_dir, HOSTILE_NAME, hostile_flow_demo(project_dir))
        nul_flow(project_dir)
        await load_flow(app, pilot, HOSTILE_NAME)
        await settle(pilot, 2)
        hostile_rows = pipeline_lines(app, panel)
        spans = _span_styles(app, need(panel, "#flow_pipeline"))
        inner = panel._card_w - 4
        await load_flow(app, pilot, "nul_flow")
        await poll(pilot, lambda: bool(panel.query("#flow_result .flow-quarantine")))
        await settle(pilot, 2)
        panel_text = "\n".join(painted_rows(app, panel))
        kept_rows = pipeline_lines(app, panel)
        await choose_kind(app, pilot, panel, BLOCK_WRITE_OUT)
        box = panel.query_one("#flow_ref", Input)
        box.focus()
        await settle(pilot, 2)
        box.post_message(events.Paste(NUL_TEXT))
        await poll(pilot, lambda: "\x00" in box.value)
        before = card_count(app, panel)
        await pilot.click("#flow_add")
        await poll(pilot, lambda: bool(notice_lines(app, panel)))
        refusal = notice_lines(app, panel)
        after = card_count(app, panel)
        await pilot.click("#flow_run")
        await poll(pilot, lambda: bool(panel.query("#flow_result .flow-banner")))
        return hostile_rows, spans, inner, panel_text, kept_rows, refusal, before, after, result_text(app, panel)

    hostile_rows, spans, inner, panel_text, kept_rows, refusal, before, after, text = run_builder(
        tmp_path, (118, 54), body
    )
    painted = "\n".join(hostile_rows)
    payload = safe_text(HOSTILE_CONTENT + HOSTILE_C1).plain
    assert fs.clip_tail(payload, inner) in painted and fs.clip_tail(payload, inner).startswith("…")
    assert not CONTROL_CHARS.search(painted)
    assert spans and _foreign(spans) == [], sorted(set(_foreign(spans)))
    named = [line for line in panel_text.split("\n") if fps.FLOW_UNSAFE_REF in line]
    assert len(named) == 1, named
    assert kept_rows == hostile_rows, "the refused load replaced the chain"
    assert after == before and len(refusal) == 1 and fps.FLOW_UNSAFE_REF in refusal[0], (before, after, refusal)
    assert "WRITE-OUT output file holds a NUL character" in refusal[0], refusal
    assert "ValueError" not in text and "embedded null" not in text, text[:400]


def test_at_b97_19_first_task_from_the_keyboard(tmp_path: Path) -> None:
    """AT-B97-19 (HLR-146): keys only, from the header — ``tab`` to the CHECK
    chip and ``enter`` shows exactly ``#flow_ref`` and ``#flow_gating``;
    ``tab`` to the EXT-STEP chip, ``enter``; type the command, the log and the
    output; ``enter`` on Add appends a 5th card to ``flash_chain``; ``tab`` to
    Run, ``enter`` paints the paused banner with 0 ``ES_MARKER`` matches; no
    focused id along the way is ``flow_scope``.

    RED on main (P-56): no ``flow_palette_check``; ``tab`` visits
    ``flow_scope``; banner ``PAUSED - ESPERANDO HUMANO``.
    """

    async def tab_to(app, pilot, wid, visited, bound=60) -> bool:
        for _ in range(bound):
            if app.focused is not None and app.focused.id == wid:
                return True
            await pilot.press("tab")
            await settle(pilot, 1)
            if app.focused is not None and app.focused.id:
                visited.append(app.focused.id)
        return app.focused is not None and app.focused.id == wid

    async def body(app, pilot, panel, project_dir):
        await load_flow(app, pilot, "flash_chain")
        app.query_one("#window_help_flow").focus()
        await settle(pilot, 2)
        visited = []
        reached = await tab_to(app, pilot, "flow_palette_check", visited)
        assert reached, f"the CHECK chip is not reachable by tab: {visited}"
        await pilot.press("enter")
        await poll(pilot, lambda: displayed_add_inputs(panel) == KIND_INPUTS[BLOCK_CHECK])
        check_inputs = displayed_add_inputs(panel)
        assert await tab_to(app, pilot, "flow_palette_external_step", visited)
        await pilot.press("enter")
        await poll(pilot, lambda: shown(panel.query_one("#flow_ext_log")))
        for wid, text in (("flow_ext_instruction", "flash2"), ("flow_ext_log", "log2.txt"), ("flow_ext_output", "out2.s19")):
            assert await tab_to(app, pilot, wid, visited), (wid, visited[-6:])
            await pilot.press(*list(text))
            await poll(pilot, lambda: panel.query_one(f"#{wid}", Input).value == text)
        assert await tab_to(app, pilot, "flow_add", visited)
        await pilot.press("enter")
        await poll(pilot, lambda: card_count(app, panel) == 5)
        cards = card_count(app, panel)
        assert await tab_to(app, pilot, "flow_run", visited)
        await pilot.press("enter")
        await poll(pilot, lambda: "PAUSED" in result_text(app, panel))
        return check_inputs, cards, visited, result_text(app, panel)

    check_inputs, cards, visited, text = run_builder(tmp_path, (118, 54), body)
    assert check_inputs == KIND_INPUTS[BLOCK_CHECK]
    assert cards == 5
    assert "flow_scope" not in visited
    banner = [line for line in text.split("\n") if "PAUSED" in line]
    assert banner and not ES_MARKER_RE.search("\n".join(banner)), banner
    assert not ES_MARKER_RE.search(text), [m.group(0) for m in ES_MARKER_RE.finditer(text)]


# --------------------------------------------------------------------------- #
# CSS guard (design §6.1 Inc-5 item (6), D23): the shared rules stay byte-equal
# to 09e44de and every Builder rule is rooted at #flow_panel / #screen_flow
# --------------------------------------------------------------------------- #

STYLES = REPO_ROOT / "s19_app" / "tui" / "styles.tcss"
#: The shared rules Inc-5 must not touch: the name-strip class (it also paints
#: ``#fx_name_strip``), the five frozen severity classes, the modal hint and
#: the unscoped docked-row rule the Check Editor's rows inherit.
GUARDED_HEADS = (
    ".flow-name-strip {",
    ".sev-ok {", ".sev-error {", ".sev-warning {", ".sev-info {", ".sev-neutral {",
    ".modal-hint {",
    ".patch-docked-row,\n.patch-docked-group {",
)


def _css_rules(text: str) -> list:
    """(selectors, body) per rule — comments stripped, selector lists split."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return [
        ([s.strip() for s in m.group(1).split(",") if s.strip()], m.group(2))
        for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", text)
    ]


def test_tc_b97_flow_css_shared_rules_byte_equal_and_section_scoped() -> None:
    """Design guard (Inc-5 item (6)): ``.flow-name-strip``, the five ``.sev-*``
    rules, ``.modal-hint`` and the unscoped ``.patch-docked-row,
    .patch-docked-group`` rule are byte-equal to ``09e44de``; every selector of
    the ``/* batch-97 flow_builder */`` section starts with ``#flow_panel`` or
    ``#screen_flow``; and no selector anywhere names a ``#flow_`` id without
    that root.

    Why: ``.flow-name-strip`` also paints Flow Execution's ``#fx_name_strip``;
    the others paint every screen. RED by mutation: ``.flow-name-strip {
    margin-bottom: 0; }`` edited in place; an unscoped ``#flow_result`` rule.
    """
    try:
        old = subprocess.run(
            ["git", "show", "09e44de:s19_app/tui/styles.tcss"], cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8").replace("\r\n", "\n")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 09e44de unavailable — the byte-equal arm cannot run: {exc}")
    text = STYLES.read_text(encoding="utf-8").replace("\r\n", "\n")
    for head in GUARDED_HEADS:
        start = old.index("\n" + head) + 1
        block = old[start: old.index("\n}\n", start) + 3]
        assert old.count(block) == 1, head
        assert text.count(block) == 1, f"{head!r} changed or duplicated"
    marker = "/* batch-97 flow_builder"
    assert marker in text, "the scoped Flow Builder section exists"
    section = text.split(marker, 1)[1]
    following = re.search(r"\n/\* batch-97 (?!flow_builder)", section)
    if following:
        section = section[: following.start()]
    selectors = [s for sels, _b in _css_rules("/*" + section) for s in sels]
    assert len(selectors) >= 20, len(selectors)
    rooted = ("#flow_panel", "#screen_flow")
    assert [s for s in selectors if not s.startswith(rooted)] == []
    stray = [s for sels, _b in _css_rules(text) for s in sels if "#flow_" in s and not s.startswith(rooted)]
    assert stray == [], stray
