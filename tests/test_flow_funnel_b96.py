"""Batch-96 — the FUNNEL (B1) and block COPY/PASTE (B2) in the real tree.

TC-1816/TC-1817 (the funnel, spec "funnel de variables"): a funnel is a
flow-level name→value table (``Flow.funnel`` — ordered pairs, NOT a block
kind: it is flow-scoped declaration state like the flow's name, one table
per flow/chain, editable beside the canvas). Persistence is ADDITIVE
grammar: the wire envelope gains an optional ``funnel`` [[name, value], …]
pair list (absent ⇔ empty, so pre-B1 envelopes inter-read); names match the
EXACT placeholder charset [A-Z0-9_], values are non-empty strings, names
are unique. Execution: when a PATCH arm loads its change-doc JSON, the raw
TEXT passes through substitution BEFORE the parse — every exact
``${NAME}`` token with a declared value is replaced; an undeclared name
stays INTACT and adds one named NOTICE to the block result (never a
failure); with NO funnel the doc passes through byte-identical (regression).

TC-1818/TC-1819 (copy/paste): the builder serializes a picked block
(ledger nº, 1-based, empty = last) through the REAL wire serializer into an
in-panel clipboard, and pastes it back through the hardened loader
validated against the current flow's own blocks — a NEW block instance
each paste (never shared state), the ledger numbers it anew, an empty
clipboard is a friendly no-op. A2B ``#<n>`` refs ride a paste VERBATIM
(the builder never silently rewrites operator wiring).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button, Input, Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.flow_screens import FlowBuilderPanel
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    A2BBlock,
    A2BInputBinding,
    BLOCK_STATUS_NOTICES,
    EXTERNAL_MODE_MANUAL,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    ExternalStepBlock,
    Flow,
    FlowContext,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
    substitute_funnel,
)
from s19_app.tui.services.load_service import build_loaded_s19

#: 16-byte CLEAN S19 at 0x1000 (00..0F, checksum-verified) — wide enough to
#: host a substituted byte AND a literal-placeholder string inside the image.
_BASE16 = (
    "S1131000000102030405060708090A0B0C0D0E0F64\n"
    "S9030000FC\n"
)


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _funnel_doc() -> str:
    """A change-doc whose TEXT carries two exact ${NAME} placeholders."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "bytes", "address": "0x1001", "bytes": "${BOOST}"},
                {"type": "string", "address": "0x1005", "value": "${MISSING}"},
            ],
        }
    )


def _out_mem_map(project: Path, name: str) -> dict:
    path = project / name
    return build_loaded_s19(path, S19File(str(path)), None, None).mem_map


def _flow_blocks() -> list:
    return [
        SourceBlock("base.s19"),
        PatchBlock("ch.json"),
        WriteOutBlock("out.s19"),
    ]


# --------------------------------------------------------------------------- #
# TC-1816 — persistence: round-trip + the additive grammar
# --------------------------------------------------------------------------- #


def test_tc1816_funnel_persistence_roundtrip(tmp_path: Path) -> None:
    """TC-1816 (persistence): a flow's funnel table round-trips through the
    real saver/loader as an ordered [[name, value], …] wire list; a flow
    WITHOUT a funnel loads with an empty table (pre-B1 envelopes inter-read);
    the strict grammar refuses a lowercase/empty/duplicate/malformed entry
    with FLOW-BAD-FIELD and drops the whole flow."""
    project = _make_project(tmp_path, {"base.s19": _BASE16})
    funnel = (("BOOST", "AB"), ("REV", "C"), ("CAL_NAME", "torque"))
    flow = Flow(name="funnel_flow", blocks=_flow_blocks(), funnel=funnel)

    path = fps.save_flow_json(flow, "funnel_flow", project)
    assert path is not None
    wire = json.loads(path.read_text(encoding="utf-8"))
    assert wire["funnel"] == [["BOOST", "AB"], ["REV", "C"], ["CAL_NAME", "torque"]]

    loaded, findings = fps.load_flow_json(path, project)
    assert findings == []
    assert loaded is not None
    assert tuple(loaded.funnel) == funnel  # order is the declared order

    # Absent funnel ⇔ empty table (an old envelope is a clean load).
    old_wire = json.loads(path.read_text(encoding="utf-8"))
    del old_wire["funnel"]
    legacy = project / "flows" / "legacy.json"
    legacy.write_text(json.dumps(old_wire), encoding="utf-8")
    loaded_old, findings_old = fps.load_flow_json(legacy, project)
    assert findings_old == []
    assert loaded_old is not None
    assert tuple(loaded_old.funnel) == ()

    # The strict grammar — every malformed table refuses the WHOLE flow.
    refused = {
        "lowercase_name": [["boost", "AB"]],
        "empty_name": [["", "AB"]],
        "empty_value": [["BOOST", "  "]],
        "duplicate_name": [["BOOST", "AB"], ["BOOST", "CD"]],
        "not_pairs": [["BOOST"]],
        "not_a_list": {"BOOST": "AB"},
        "over_cap": [[f"V{i}", "1"] for i in range(33)],
    }
    for case, table in refused.items():
        bad_wire = json.loads(path.read_text(encoding="utf-8"))
        bad_wire["funnel"] = table
        bad_path = project / "flows" / f"bad_{case}.json"
        bad_path.write_text(json.dumps(bad_wire), encoding="utf-8")
        loaded_bad, findings_bad = fps.load_flow_json(bad_path, project)
        assert loaded_bad is None, f"{case}: the whole flow must be refused"
        assert any(
            finding.code == "FLOW-BAD-FIELD" for finding in findings_bad
        ), f"{case}: the refusal names FLOW-BAD-FIELD"


def test_tc1816_substitution_unit_exact_token(tmp_path: Path) -> None:
    """TC-1816 (grammar): substitution replaces ONLY the exact ${NAME}
    token — a near-miss (lowercase, unbraced, partial key) rides verbatim,
    and the missing list names each undeclared variable once."""
    text = '{"a": "${BOOST}", "b": "${boost}", "c": "$BOOST", "d": "${MISSING}"}'
    out, missing = substitute_funnel(text, [("BOOST", "AB")])
    assert out == '{"a": "AB", "b": "${boost}", "c": "$BOOST", "d": "${MISSING}"}'
    assert missing == ["MISSING"]
    # An empty funnel is the identity (the no-funnel regression, unit level).
    assert substitute_funnel(text, []) == (text, ["BOOST", "MISSING"])


# --------------------------------------------------------------------------- #
# TC-1817 — execution: substitution, the named NOTICE, the no-funnel regression
# --------------------------------------------------------------------------- #


def test_tc1817_execution_substitution_and_named_notice(tmp_path: Path) -> None:
    """TC-1817 (execution): a PATCH change-doc whose text carries ${BOOST}
    and ${MISSING} runs against a funnel declaring BOOST only — the applied
    image carries the DECLARED value at 0x1001, the ${MISSING} placeholder
    rides INTO the applied string byte-intact, the PATCH block reports
    ``notices`` with one finding NAMING ${MISSING}, and the flow completes
    WITH ISSUES (never an error). Declaring MISSING too turns the very same
    doc into a CLEAN run."""
    project = _make_project(
        tmp_path, {"base.s19": _BASE16, "ch.json": _funnel_doc()}
    )

    flow = Flow(
        name="partial",
        blocks=_flow_blocks(),
        funnel=(("BOOST", "AB"),),
    )
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_ISSUES
    patch_result = result.block_results[1]
    assert patch_result.status == BLOCK_STATUS_NOTICES
    messages = [finding.message for finding in patch_result.findings]
    assert len(messages) == 1 and "MISSING" in messages[0]

    mem_map = _out_mem_map(project, "out.s19")
    assert mem_map[0x1001] == 0xAB  # ${BOOST} → the declared value
    spelled = "".join(chr(mem_map[0x1005 + i]) for i in range(10))
    assert spelled == "${MISSING}"  # undeclared → intact, never a failure

    # The fully-declared funnel: same doc, same run, CLEAN.
    full = Flow(
        name="full",
        blocks=[
            SourceBlock("base.s19"),
            PatchBlock("ch.json"),
            WriteOutBlock("out2.s19"),
        ],
        funnel=(("BOOST", "AB"), ("MISSING", "OK")),
    )
    result_full = run_flow(full, FlowContext(project_dir=project))
    assert result_full.status == FLOW_STATUS_OK
    assert result_full.block_results[1].status == "ok"
    mem_map_full = _out_mem_map(project, "out2.s19")
    assert mem_map_full[0x1001] == 0xAB
    assert "".join(chr(mem_map_full[0x1005 + i]) for i in range(2)) == "OK"


def _plain_doc() -> str:
    """A change-doc whose placeholders sit in STRING entries — valid with
    or without substitution, so the no-funnel arm proves the text passed
    UNCHANGED (no bytes entry can carry ``${BOOST}`` unsubstituted: it is
    not valid hex, and refusing it would test the reader, not the funnel)."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "string", "address": "0x1005", "value": "${BOOST}"},
            ],
        }
    )


def test_tc1817_no_funnel_doc_passes_unchanged(tmp_path: Path) -> None:
    """TC-1817 (regression): a flow WITHOUT a funnel performs NO
    substitution — a change-doc string entry carrying ${BOOST} applies
    VERBATIM (the painted image spells the placeholder) and the run is
    CLEAN, exactly as before the funnel existed."""
    project = _make_project(
        tmp_path, {"base.s19": _BASE16, "ch.json": _plain_doc()}
    )
    flow = Flow(name="nofunnel", blocks=_flow_blocks())
    assert flow.funnel == ()
    result = run_flow(flow, FlowContext(project_dir=project))
    assert result.status == FLOW_STATUS_OK
    assert result.block_results[1].status == "ok"
    assert result.block_results[1].findings == []
    assert "applied 1 entry" in result.block_results[1].summary
    mem_map = _out_mem_map(project, "out.s19")
    assert mem_map[0x1001] == 0x01  # the base image byte, untouched
    spelled = "".join(chr(mem_map[0x1005 + i]) for i in range(8))
    assert spelled == "${BOOST}"  # the placeholder rode into the image intact


def test_tc1817_builder_funnel_table_edits(tmp_path: Path) -> None:
    """TC-1817 (builder): the funnel editor toggles open beside the canvas,
    declares a variable (name/value row), REFUSES a lowercase name with the
    visible wiring notice, UPDATES a re-declared name (table semantics),
    paints the table line, and the table rides ``current_flow`` → Save →
    Load back into the panel."""
    project = _make_project(tmp_path, {"base.s19": _BASE16})

    async def _drive() -> "tuple[list, str, str, str, tuple]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)

            # Collapsed by default; the toggle opens the editor.
            editor_closed = not app.query_one("#flow_funnel_editor").display
            app.query_one("#flow_funnel_toggle", Button).press()
            await pilot.pause()
            editor_open = app.query_one("#flow_funnel_editor").display

            app.query_one("#flow_funnel_name", Input).value = "BOOST"
            app.query_one("#flow_funnel_value", Input).value = "AB"
            app.query_one("#flow_funnel_add", Button).press()
            await pilot.pause()

            # Refused: lowercase name rides the wiring notice, adds nothing.
            app.query_one("#flow_funnel_name", Input).value = "boost"
            app.query_one("#flow_funnel_value", Input).value = "XX"
            app.query_one("#flow_funnel_add", Button).press()
            await pilot.pause()
            notice = app.query_one("#flow_wiring_notice", Static).render().plain

            # Update semantics: re-declaring BOOST replaces its value.
            app.query_one("#flow_funnel_name", Input).value = "BOOST"
            app.query_one("#flow_funnel_value", Input).value = "CD"
            app.query_one("#flow_funnel_add", Button).press()
            await pilot.pause()
            painted = app.query_one("#flow_funnel_list", Static).render().plain
            toggle_label = str(app.query_one("#flow_funnel_toggle", Button).label)

            # A flow needs ≥1 block to save — place one through Add.
            app.query_one("#flow_kind").value = "source"
            app.query_one("#flow_ref", Input).value = "base.s19"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()

            # Round trip through the REAL Save/Load seam.
            saved = fps.save_flow_json(panel.current_flow, "funnel", project)
            assert saved is not None
            loaded, findings = fps.load_flow_json(saved, project)
            assert findings == [] and loaded is not None
            panel.set_blocks(loaded, "funnel")
            return (
                list(panel._funnel),
                painted,
                toggle_label,
                notice,
                tuple(panel.current_flow.funnel),
            ) if editor_closed and editor_open else ([], "", "", "no-toggle", ())

    funnel, painted, toggle_label, notice, current = asyncio.run(_drive())

    assert funnel == [("BOOST", "CD")]
    assert "${BOOST} = CD" in painted
    # batch-97 Inc-5 (LLR-146.10 / 146.7, named supersession): the chip is
    # `Variables (n)` and the refusal is English.
    assert toggle_label == "Variables (1)"
    assert "refused" in notice and "[A-Z0-9_]" in notice
    assert current == (("BOOST", "CD"),)


# --------------------------------------------------------------------------- #
# TC-1818 — copy/paste: the wire clipboard, distinct instances, all kinds
# --------------------------------------------------------------------------- #


def _seed_blocks(panel: FlowBuilderPanel) -> None:
    """Seed the canvas with one block of every copyable shape (source,
    patch, external-step, A2B) through the panel's OWN Add paths."""
    panel._blocks.extend(
        [
            SourceBlock("base.s19"),
            PatchBlock("ch.json"),
            ExternalStepBlock(
                mode=EXTERNAL_MODE_MANUAL,
                instruction="revisar el binario",
                log_ref="constancia.txt",
                output_path="salida.s19",
            ),
            A2BBlock(
                image_a=A2BInputBinding("flow", "0"),
                image_b=A2BInputBinding("file", "base.s19"),
            ),
        ]
    )
    panel._refresh_blocks()


def test_tc1818_copy_paste_duplicates_config_via_wire(tmp_path: Path) -> None:
    """TC-1818 (copy/paste): copying a block stores the REAL wire projection
    (``flow_to_dict`` of that one block — never the instance), and pasting
    appends a NEW, EQUAL-config block for EVERY kind (PATCH config, the
    EXT-STEP five keys, the A2B bindings VERBATIM) — distinct objects, the
    clipboard survives each paste, and the ledger numbers the copies anew.
    Pasting WITHOUT a project (no session dir, no active project) refuses
    with a friendly wiring notice instead of crashing."""
    project = _make_project(tmp_path, {"base.s19": _BASE16})

    async def _drive() -> "tuple[list, list, str, int, str]" :
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            _seed_blocks(panel)
            kinds_before = [b.kind for b in panel._blocks]

            # Copy each block in turn and paste it: 4 → 8 blocks.
            clipboard_shapes = []
            for ledger_no in range(1, 5):
                app.query_one("#flow_pick", Input).value = str(ledger_no)
                app.query_one("#flow_copy", Button).press()
                await pilot.pause()
                clipboard_shapes.append(dict(panel._clipboard or {}))
                app.query_one("#flow_paste", Button).press()
                await pilot.pause()
            blocks_after = panel._blocks
            identity_flags = [
                blocks_after[i + 4] is blocks_after[i] for i in range(4)
            ]
            equality_flags = [
                blocks_after[i + 4] == blocks_after[i] for i in range(4)
            ]

            # The A2B copy kept its #n binding VERBATIM (no silent rewire).
            a2b_pasted = blocks_after[7]
            a2b_refs = (a2b_pasted.image_a.ref, a2b_pasted.image_b.ref)

            # No-project paste refuses friendly (session dir + app project
            # both cleared on a fresh panel state).
            panel2_blocks_before = len(panel._blocks)
            app.current_project_dir = None
            panel._session_dir = None
            panel._clipboard = {"kind": "patch", "change_doc_ref": "x.json"}
            app.query_one("#flow_paste", Button).press()
            await pilot.pause()
            refused_notice = app.query_one(
                "#flow_wiring_notice", Static
            ).render().plain
            count_after_refusal = len(panel._blocks)
            return (
                kinds_before,
                identity_flags + equality_flags,
                json.dumps(clipboard_shapes[1]),  # the PATCH wire shape
                panel2_blocks_before * 100 + count_after_refusal,
                refused_notice + "|" + json.dumps(list(a2b_refs)),
            )

    kinds, flags, patch_wire, counts, pack = asyncio.run(_drive())
    refused_notice, a2b_refs = pack.rsplit("|", 1)

    assert kinds == ["source", "patch", "external_step", "a2b"]
    # 4 distinct-instance flags (all False) + 4 equal-config flags (all True).
    assert flags == [False] * 4 + [True] * 4
    # The clipboard carried the REAL wire projection of the PATCH block.
    assert json.loads(patch_wire) == {
        "kind": "patch",
        "change_doc_ref": "ch.json",
    }
    assert counts // 100 == 8 and counts % 100 == 8  # paste x4 grew, refusal didn't
    assert "load a project first" in refused_notice  # batch-97 LLR-146.7 (English)
    assert json.loads(a2b_refs) == ["0", "base.s19"]  # VERBATIM, not renumbered


def test_tc1819_paste_empty_clipboard_is_friendly_noop(tmp_path: Path) -> None:
    """TC-1819 (the empty clipboard): pasting with NOTHING copied is a
    friendly no-op — a visible wiring notice, zero blocks added, no crash —
    and an out-of-range copy pick is refused just as friendly."""
    project = _make_project(tmp_path, {"base.s19": _BASE16})

    async def _drive() -> "tuple[str, int, str, int]" :
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)

            app.query_one("#flow_paste", Button).press()
            await pilot.pause()
            noop_notice = app.query_one(
                "#flow_wiring_notice", Static
            ).render().plain
            count_after_noop = len(panel._blocks)

            # A copy pick outside the ledger refuses, copies nothing.
            app.query_one("#flow_pick", Input).value = "7"
            app.query_one("#flow_copy", Button).press()
            await pilot.pause()
            bad_pick_notice = app.query_one(
                "#flow_wiring_notice", Static
            ).render().plain
            return (noop_notice, count_after_noop, bad_pick_notice, panel._clipboard is None)

    noop_notice, count, bad_pick_notice, clipboard_still_empty = asyncio.run(
        _drive()
    )

    # batch-97 Inc-5 (LLR-146.7, named supersession): the notices are English.
    assert "clipboard is empty" in noop_notice
    assert count == 0
    assert "there is no block #7" in bad_pick_notice
    assert clipboard_still_empty is True
