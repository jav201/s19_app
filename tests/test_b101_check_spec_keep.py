"""batch-101 Inc 5 - the Check Editor keeps its picks, names and expected bytes.

Written by independent E4 tester 2 from the approved design only:
``inc-5/01-requirements.md`` (rows, thresholds and Definitions),
``inc-5/02-test-cases.md`` (the cases), ``inc-5/E1-rulings.md`` and
``inc-5/E3-rulings.md`` (the rulings that bind the tests, including the E4
addenda), ``inc-5/codewire/graph-inc5.md`` (examples). No line of the Inc 5
implementation was read to decide what to assert.

Covers the Check Editor cases of the increment (one node per case, the case id
is in each docstring; the node name starts with the id in test spelling):
  - R-CHKED-010/1..3   picks survive a plain return, the same A2L loaded
                       again and the image loaded again.
  - R-CHKED-055/1      a parameter the new A2L no longer lists is dropped.
  - R-CHKED-054/1      Write keeps the field set (F-26 guard).
  - R-CHKED-041.1/1    a spec pick replaces the whole field set.
  - R-CHKED-041.2/1,3  a spec pick names and includes the parameters (F-27);
                       /2 is ``test_b101_symbol_reads.py::
                       test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols``.
  - R-CHKED-041.3/1..6 the entries with no named parameter become unlabelled
                       memory rows (/5 and /6 through the panel seam).
  - R-CHKED-025/1..3   fields included in this session read the image.
  - R-CHKED-026/1..4   fields loaded from a spec keep the spec's bytes (D9-11).
  - R-CHKED-027/1,2    fields outside the image are left out; spec fields stay.
  - R-CHKED-056/1..3   a parameter a new A2L moves, renames or resizes becomes
                       an unlabelled memory row keeping its spec entry.

Oracles are observable: the status log (every ``set_status`` message), the
Check Editor's own painted Fields lines, memory table and ledger marks, the
Validate result rows, and the ``.chk.json`` file the product wrote (read back as
JSON). Expected bytes come from the independent S19 reader over the generated
case 08 image; names, addresses and byte counts come from the generated A2L
text. The planted A2Ls are written by the test from the generated one.
Waits poll with ``tests/support/timing.py::wait_until``; a pause is never the
wait before a state read. The suite's autouse fixtures isolate LOCALAPPDATA;
nothing here touches the OS clipboard.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from tests.support import b100_projects as projects  # noqa: E402
from tests.support.independent_reader import read_s19  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402
from tests.test_b101_symbol_reads import (  # noqa: E402
    attach_a2l,
    attach_image,
    click,
    load_through_dialog,
    pick_by_keys,
    settle,
)

SEED = 20260001
SIZE_MB = 1.0

PILOT = "pilot_fields.chk.json"
EM = "—"
PATCH_BYTE = 0x93

LAYOUT_SIZE = {"RL_U8": 1, "RL_U16": 2, "RL_U32": 4, "RL_S16": 2, "RL_S32": 4, "RL_F32": 4}
LAYOUT_OF_SIZE = {1: "RL_U8", 2: "RL_U16", 4: "RL_U32"}


# ---------------------------------------------------------------------------
# Case 08 facts, taken from the generated files (never typed in)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Param:
    name: str
    address: int
    size: int


@dataclass(frozen=True)
class Facts:
    case: Path
    image: dict  # address -> byte, from the independent S19 reader
    v1: Param
    v2: Param
    v3: Param
    serial: int  # the memory row the pilot adds: last four bytes of the image
    moved: int  # address A of the planted moved A2L

    def image_bytes(self, address: int, size: int) -> bytes:
        return bytes(self.image[address + i] for i in range(size))


_VALUE_BLOCK = re.compile(
    r'/begin CHARACTERISTIC (\S+) "[^"]*"\s*\n\s*VALUE (0x[0-9A-Fa-f]+) (RL_\w+)'
)


def measurements(a2l_text: str) -> dict:
    """``{name: Param}`` of every ``VALUE`` CHARACTERISTIC of the generated A2L
    (the parameters the ledger lists; the byte count follows the record
    layout)."""
    return {
        name: Param(name, int(address, 16), LAYOUT_SIZE[layout])
        for name, address, layout in _VALUE_BLOCK.findall(a2l_text)
    }


@pytest.fixture(scope="module")
def case08(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The release demo case, generated once (seed 20260001, 1.0 MB)."""
    folder = tmp_path_factory.mktemp("b101_inc5_case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


@pytest.fixture(scope="module")
def facts(case08: Path) -> Facts:
    image = read_s19(case08 / "firmware.s19").data
    params = measurements((case08 / "firmware.a2l").read_text(encoding="utf-8"))
    v1, v2, v3 = (params[f"VALUE_000{n}"] for n in (1, 2, 3))
    first_byte = image[v1.address]
    moved = next(a for a in sorted(image) if a >= 0x20 and image[a] != first_byte)
    return Facts(case08, image, v1, v2, v3, max(image) - 3, moved)


# ---------------------------------------------------------------------------
# Planted documents (written by the test)
# ---------------------------------------------------------------------------


def spec_doc(entries: list) -> str:
    """A v2 ``kind=check`` document. ``entries``: ``(address, bytes[, symbol])``."""
    rows = []
    for entry in entries:
        address, data = entry[0], entry[1]
        row = {
            "type": "bytes",
            "address": f"0x{address:X}",
            "bytes": " ".join(f"{b:02X}" for b in data),
        }
        if len(entry) > 2 and entry[2]:
            row["symbol"] = entry[2]
        rows.append(row)
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": rows,
        },
        indent=2,
    )


def pilot_entries(f: Facts) -> list:
    """The pilot spec: VALUE_0001, VALUE_0002 and the memory row, image bytes."""
    return [
        (p.address, f.image_bytes(p.address, p.size)) for p in (f.v1, f.v2)
    ] + [(f.serial, f.image_bytes(f.serial, 4))]


def change_doc(address: int, data: bytes) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {
                    "type": "bytes",
                    "address": f"0x{address:X}",
                    "bytes": " ".join(f"{b:02X}" for b in data),
                }
            ],
        }
    )


_OBJECT_BLOCK = re.compile(
    r"^[ \t]*/begin (MEASUREMENT|CHARACTERISTIC) .*?^[ \t]*/end \1[ \t]*\n",
    re.S | re.M,
)
_MODULE_TAIL = "  /end MODULE\n/end PROJECT\n"


def plant_a2l(case: Path, dest: Path, objects: list) -> Path:
    """The generated A2L with every MEASUREMENT / CHARACTERISTIC block replaced
    by ``objects`` = ``[(name, address, size), ...]`` (``VALUE``
    CHARACTERISTIC blocks, the form of the generated ``VALUE_000n``)."""
    text = _OBJECT_BLOCK.sub("", (case / "firmware.a2l").read_text(encoding="utf-8"))
    assert text.endswith(_MODULE_TAIL), "the generated A2L changed shape"
    blocks = "".join(
        f'    /begin CHARACTERISTIC {name} "planted characteristic"\n'
        f"      VALUE 0x{address:08X} {LAYOUT_OF_SIZE[size]} 0 CM_IDENT 0 255\n"
        "      BYTE_ORDER MSB_FIRST\n"
        "    /end CHARACTERISTIC\n"
        for name, address, size in objects
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text[: -len(_MODULE_TAIL)] + blocks + _MODULE_TAIL, encoding="utf-8")
    return dest


def planted_moved(f: Facts, tmp_path: Path) -> Path:
    return plant_a2l(
        f.case, tmp_path / "planted" / "moved.a2l",
        [(f.v1.name, f.moved, f.v1.size), (f.v2.name, f.v2.address, f.v2.size)],
    )


def planted_renamed(f: Facts, tmp_path: Path) -> Path:
    return plant_a2l(
        f.case, tmp_path / "planted" / "renamed.a2l",
        [("VALUE_0001_R", f.v1.address, f.v1.size), (f.v2.name, f.v2.address, f.v2.size)],
    )


def planted_resized(f: Facts, tmp_path: Path) -> Path:
    return plant_a2l(
        f.case, tmp_path / "planted" / "resized.a2l",
        [(f.v1.name, f.v1.address, 2), (f.v2.name, f.v2.address, f.v2.size)],
    )


def planted_twin(f: Facts, tmp_path: Path) -> Path:
    return plant_a2l(
        f.case, tmp_path / "planted" / "twin.a2l",
        [("ALPHA", 0x14, 2), ("BETA", 0x14, 2)],
    )


# ---------------------------------------------------------------------------
# Session drivers and readers (the Check Editor's own rendering)
# ---------------------------------------------------------------------------


def run(tmp_path: Path, scenario, name: str = "app"):
    base = tmp_path / name
    base.mkdir(parents=True, exist_ok=True)
    return projects.run_app(base, scenario)


def painted(widget) -> str:
    """The text a Static paints (its own rendering)."""
    rendered = widget.render()
    return getattr(rendered, "plain", None) or str(rendered)


def editor(app):
    from s19_app.tui.screens_directionb import CheckEditorPanel

    return app.query_one("#check_editor_panel", CheckEditorPanel)


def fields_lines(app) -> list:
    from textual.widgets import Static

    return painted(app.query_one("#check_fields_lines", Static)).split("\n")


def head(app) -> str:
    return fields_lines(app)[0]


def included(app) -> list:
    return list(editor(app)._picked_params)


def param_lines(app) -> list:
    return [line for line in fields_lines(app) if line.startswith("◆")]


def mem_rows(app) -> list:
    """``[(address cell, label cell, fmt cell), ...]`` of the memory table."""
    from textual.widgets import DataTable

    table = app.query_one("#check_mem_table", DataTable)
    return [
        tuple(str(getattr(cell, "plain", cell)) for cell in table.get_row_at(i))
        for i in range(table.row_count)
    ]


def mark_of(app, name: str) -> str:
    """The ledger's ✓ cell of the row ``name`` (mounted on the current page)."""
    from textual.widgets import DataTable

    panel = editor(app)
    assert name in panel._visible_params, (name, panel._visible_params[:5])
    table = panel.query_one("#check_param_table", DataTable)
    return str(getattr(table.get_row(name)[0], "plain", table.get_row(name)[0]))


def ledger_names(app) -> list:
    return list(editor(app)._visible_params)


async def go_workspace(pilot, app) -> None:
    # Leave no text field focused (a typed 'l' would go into it, not the key
    # that opens the Load dialog).
    app.screen.set_focus(None)
    await pilot.press("1")
    await wait_until(
        pilot,
        lambda: any(b.region.width > 0 for b in app.query("Button.loaded-unload")),
        "timed out waiting for the Workspace Loaded panel after key 1",
    )


async def enter_check_editor(pilot, app, *, ledger: bool = True) -> None:
    """Key ``=`` and wait for the Check Editor (and, when an A2L is loaded, its
    ledger) to be painted."""
    await pilot.press("equals_sign")
    await wait_until(
        pilot,
        lambda: len(app.query("#check_editor_panel")) > 0
        and editor(app).region.width > 0
        and (not ledger or len(editor(app)._param_rows) > 0)
        and (not ledger or len(editor(app)._visible_params) > 0),
        "timed out waiting for the Check Editor after key '='",
    )
    await settle(pilot, 2)


async def open_session(
    pilot,
    app,
    f: Facts,
    *,
    specs: dict | None = None,
    image: bool = True,
    a2l: Path | None | bool = True,
) -> None:
    """Stage ``specs`` (name -> text) in the patches folder, load the image and
    the A2L through the Load dialog, and enter the Check Editor."""
    patches = app._patches_dir()
    patches.mkdir(parents=True, exist_ok=True)
    for name, text in (specs or {}).items():
        (patches / name).write_text(text, encoding="utf-8")
    if image:
        await attach_image(pilot, app, f.case, by_dialog=True)
    if a2l is True:
        await attach_a2l(pilot, app, f.case)
    elif a2l:
        await load_a2l_file(pilot, app, a2l)
    await enter_check_editor(pilot, app, ledger=bool(a2l))


async def load_a2l_file(pilot, app, path: Path) -> None:
    """Load ``path`` as the A2L through the Load dialog; wait for the new parse."""
    generation = app._a2l_view_generation
    await load_through_dialog(
        pilot,
        app,
        path,
        lambda: app.current_a2l_data is not None
        and app._a2l_view_generation > generation,
        f"the load of {path.name}",
    )


async def reload_image(pilot, app, f: Facts) -> None:
    generation = app._image_generation
    await load_through_dialog(
        pilot,
        app,
        f.case / "firmware.s19",
        lambda: app.current_file is not None
        and app._image_generation > generation
        and app.current_file.path.name == "firmware.s19",
        "the image load",
    )


async def return_via_workspace(pilot, app) -> None:
    await go_workspace(pilot, app)
    await enter_check_editor(pilot, app)


async def include_by_space(pilot, app, name: str) -> None:
    """Toggle ``name`` with ``space`` on its ledger row (focus the ledger, move
    the cursor to the row, press space), then wait for the toggle to be handled
    by the panel (its Fields lines repaint)."""
    from textual.widgets import DataTable

    panel = editor(app)
    assert name in panel._visible_params, (name, panel._visible_params[:5])
    table = panel.query_one("#check_param_table", DataTable)
    row = panel._visible_params.index(name)
    was = name in panel._picked_params
    seen = len(param_lines(app))
    table.focus()
    table.move_cursor(row=row)
    await wait_until(
        pilot,
        lambda: app.focused is table and table.cursor_row == row,
        f"timed out moving the ledger cursor to {name}",
    )
    await pilot.press("space")
    await wait_until(
        pilot,
        lambda: (name in panel._picked_params) != was
        and len(param_lines(app)) == seen + (-1 if was else 1),
        f"timed out waiting for the toggle of {name} to be painted",
    )


async def add_memory_row(pilot, app, address: int, label: str, size: int) -> None:
    from textual.widgets import Button, Input

    before = len(mem_rows(app))
    app.query_one("#check_mem_address_input", Input).value = f"0x{address:08X}"
    app.query_one("#check_mem_label_input", Input).value = label
    app.query_one("#check_mem_size_input", Input).value = str(size)
    app.query_one("#check_mem_add_button", Button).press()
    await wait_until(
        pilot,
        lambda: len(mem_rows(app)) == before + 1,
        f"timed out waiting for the memory row {label}",
    )


async def pick_spec(pilot, app, log, name: str) -> list:
    """Pick ``name`` in the Spec dropdown the operator's way; return the status
    lines of the pick."""
    mark = len(log.messages)
    await pick_by_keys(pilot, app, "#check_spec_file_select", name)
    await wait_until(
        pilot,
        lambda: any(
            m.startswith("Check Editor: loaded") or "NOT loaded" in m
            for m in log.since(mark)
        ),
        lambda: f"timed out waiting for the pick of {name}: {log.since(mark)!r}",
    )
    await settle(pilot, 3)
    return log.since(mark)


async def write_spec(pilot, app, log, name: str) -> tuple:
    """Type ``name`` and press Write; return ``(status lines, entries)`` with
    entries = ``[(address, bytes), ...]`` read back from the written file."""
    from textual.widgets import Button, Input

    app.query_one("#check_file_name_input", Input).value = name
    mark = len(log.messages)
    app.query_one("#check_write_button", Button).press()
    await wait_until(
        pilot,
        lambda: any(
            m.startswith("Check Editor: wrote") or m == "Check Editor: spec NOT written."
            for m in log.since(mark)
        ),
        lambda: f"timed out waiting for the write of {name}: {log.since(mark)!r}",
    )
    await settle(pilot, 3)
    document = json.loads((app._patches_dir() / name).read_text(encoding="utf-8"))
    entries = [
        (int(e["address"], 16), bytes.fromhex(e["bytes"].replace(" ", "")))
        for e in document["entries"]
    ]
    return log.since(mark), entries


async def apply_bytes(pilot, app, log, tmp_path: Path, address: int, data: bytes) -> None:
    """Change the session image through the Patch Editor (key 6, the change
    document typed and loaded, Apply pressed); then wait for the apply status."""
    from textual.widgets import Button, Input

    doc = tmp_path / "docs" / f"set_{address:X}.changes.json"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(change_doc(address, data), encoding="utf-8")
    await pilot.press("6")
    await wait_until(
        pilot,
        lambda: len(app.query("#patch_doc_path_input")) > 0
        and app.query_one("#patch_doc_path_input").region.width > 0,
        "timed out waiting for the Patch Editor after key 6",
    )
    app.query_one("#patch_doc_path_input", Input).value = str(doc)
    mark = len(log.messages)
    app.query_one("#patch_doc_load_button", Button).press()
    await wait_until(
        pilot,
        lambda: any(m.startswith("Loaded change:") for m in log.since(mark)),
        lambda: f"timed out waiting for the change load: {log.since(mark)!r}",
    )
    app.query_one("#patch_doc_apply_button", Button).press()
    await wait_until(
        pilot,
        lambda: any(m.startswith("Apply: 1 applied") for m in log.since(mark)),
        lambda: f"timed out waiting for the apply: {log.since(mark)!r}",
    )
    mem = app.current_file.mem_map
    assert bytes(mem[address + i] for i in range(len(data))) == data, "the apply did not write"
    await enter_check_editor(pilot, app)


async def unload_image(pilot, app) -> None:
    """Unload the image from the Workspace Loaded panel's ``[u]`` control."""
    await go_workspace(pilot, app)
    (button,) = [b for b in app.query("Button.loaded-unload") if b.name == "primary"]
    await click(pilot, button, "the Loaded panel's image [u]")
    await wait_until(
        pilot,
        lambda: not (app.current_file is not None and app.current_file.mem_map),
        "timed out waiting for the image unload",
    )
    await enter_check_editor(pilot, app)


async def validate(pilot, app, log) -> tuple:
    """Press Validate; return ``(status lines, result row texts)``."""
    from textual.widgets import Button, Static

    mark = len(log.messages)
    app.query_one("#check_validate_button", Button).press()
    await wait_until(
        pilot,
        lambda: any(m.startswith("Checks:") for m in log.since(mark)),
        lambda: f"timed out waiting for Validate: {log.since(mark)!r}",
    )
    await wait_until(
        pilot,
        lambda: len(app.query("#check_results Static")) > 0,
        "timed out waiting for the Validate result rows",
    )
    rows = [painted(w) for w in app.query("#check_results Static")]
    return log.since(mark), rows


async def picked_session(pilot, app, log, f: Facts, tmp_path: Path):
    """Case 08 loaded, ``VALUE_0001`` and ``VALUE_0002`` included in that order
    by ``space`` on their ledger rows, the memory row ``SERIAL`` added."""
    await open_session(pilot, app, f)
    await include_by_space(pilot, app, f.v1.name)
    await include_by_space(pilot, app, f.v2.name)
    await add_memory_row(pilot, app, f.serial, "SERIAL", 4)
    assert included(app) == [f.v1.name, f.v2.name]
    assert head(app) == "3 fields: 2 params · 1 memory row", head(app)


HEAD_3 = "3 fields: 2 params · 1 memory row"
SERIAL_ROW = lambda f: (f"0x{f.serial:08X}", "SERIAL", "u32")  # noqa: E731
BLANK_SERIAL_ROW = lambda f: (f"0x{f.serial:08X}", EM, "u32")  # noqa: E731


# ---------------------------------------------------------------------------
# US-CHK-KEEP-1 - R-CHKED-010, -054, -055
# ---------------------------------------------------------------------------


def test_r_chked_010_1_plain_return_keeps_picks(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-010/1: case 08 and its A2L loaded, ``VALUE_0001`` and
    ``VALUE_0002`` included by ``space``, the memory row ``SERIAL`` added; key
    ``1`` then key ``=`` -> included exactly ``[VALUE_0001, VALUE_0002]``, both
    ledger rows show ``✓``, head line ``3 fields: 2 params · 1 memory row``.

    Standing guard: holds on the base (batch-102 signature reuse; E1 base
    column "Partly: /1 holds"). Negative control: a return that repopulates the
    ledger and clears the picks -> ``[]`` -> RED."""

    async def scenario(app, pilot, log):
        await picked_session(pilot, app, log, facts, tmp_path)
        await return_via_workspace(pilot, app)
        return (
            included(app), mark_of(app, facts.v1.name), mark_of(app, facts.v2.name), head(app)
        )

    picks, mark1, mark2, line = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert (mark1, mark2) == ("✓", "✓"), (mark1, mark2)
    assert line == HEAD_3, line


def test_r_chked_010_2_same_a2l_reloaded_keeps_picks(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-010/2: as /1; key ``1``, ``firmware.a2l`` loaded again
    through the Load dialog, key ``=`` -> included exactly ``[VALUE_0001,
    VALUE_0002]`` in that order, both ``✓``, head line ``3 fields: 2 params · 1
    memory row``.

    Negative control: the included parameters cleared on a ledger
    repopulation (the base) -> ``[]`` -> RED."""

    async def scenario(app, pilot, log):
        await picked_session(pilot, app, log, facts, tmp_path)
        await go_workspace(pilot, app)
        await load_a2l_file(pilot, app, facts.case / "firmware.a2l")
        await enter_check_editor(pilot, app)
        return (
            included(app), mark_of(app, facts.v1.name), mark_of(app, facts.v2.name), head(app)
        )

    picks, mark1, mark2, line = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert (mark1, mark2) == ("✓", "✓"), (mark1, mark2)
    assert line == HEAD_3, line


def test_r_chked_010_3_image_reloaded_keeps_picks(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-010/3: as /1; key ``1``, ``firmware.s19`` loaded again
    through the Load dialog, key ``=`` -> as /2.

    Negative control: the included parameters cleared on a ledger
    repopulation (the image generation is part of the signature) -> ``[]`` ->
    RED."""

    async def scenario(app, pilot, log):
        await picked_session(pilot, app, log, facts, tmp_path)
        await go_workspace(pilot, app)
        await reload_image(pilot, app, facts)
        await enter_check_editor(pilot, app)
        return (
            included(app), mark_of(app, facts.v1.name), mark_of(app, facts.v2.name), head(app)
        )

    picks, mark1, mark2, line = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert (mark1, mark2) == ("✓", "✓"), (mark1, mark2)
    assert line == HEAD_3, line


def test_r_chked_055_1_unlisted_parameter_dropped(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-055/1: as R-CHKED-010/1; key ``1``, a planted A2L listing
    only ``VALUE_0002`` (same address and size) loaded through the Load dialog,
    key ``=`` -> included exactly ``[VALUE_0002]``; head line ``2 fields: 1
    param · 1 memory row``; no Fields line reads ``unresolved``; Write as
    ``two.chk.json`` writes 2 entries.

    Negative control: every earlier name kept without checking the new ledger
    -> a field with no address (``unresolved``) and ``3 fields: 2 params · 1
    memory row`` -> RED. (On the base every pick is dropped, so the kept
    ``VALUE_0002`` makes it RED too.)"""
    only_v2 = plant_a2l(
        facts.case, tmp_path / "planted" / "only_v2.a2l",
        [(facts.v2.name, facts.v2.address, facts.v2.size)],
    )

    async def scenario(app, pilot, log):
        await picked_session(pilot, app, log, facts, tmp_path)
        await go_workspace(pilot, app)
        await load_a2l_file(pilot, app, only_v2)
        await enter_check_editor(pilot, app)
        state = (included(app), head(app), list(fields_lines(app)))
        _lines, entries = await write_spec(pilot, app, log, "two.chk.json")
        return state, entries

    (picks, line, lines), entries = run(tmp_path, scenario)
    assert picks == [facts.v2.name], picks
    assert line == "2 fields: 1 param · 1 memory row", line
    assert not [ln for ln in lines if "unresolved" in ln], lines
    assert len(entries) == 2, entries
    assert [a for a, _ in entries] == [facts.v2.address, facts.serial], entries


def test_r_chked_054_1_write_keeps_the_field_set(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-054/1 (F-26): as R-CHKED-010/1; Write as
    ``pilot_fields.chk.json`` -> status ``Check Editor: wrote
    pilot_fields.chk.json (3 fields, kind=check).``; afterwards the included
    parameters are exactly ``[VALUE_0001, VALUE_0002]``, the memory table holds
    one row (``SERIAL``, ``u32``) and the head line is the one before the
    Write.

    Standing guard: holds on the base (batch-102's picker; F-26 is not
    reproduced on ``c2cba35``, E1 D-2); it keeps the R-CHKED-010 fix from
    bringing F-26 back. Negative control: the post-Write refresh repopulating
    the ledger with no signature -> ``1 field: 0 params · 1 memory row`` ->
    RED."""

    async def scenario(app, pilot, log):
        await picked_session(pilot, app, log, facts, tmp_path)
        before = head(app)
        lines, _entries = await write_spec(pilot, app, log, PILOT)
        return before, lines, included(app), mem_rows(app), head(app)

    before, lines, picks, rows, after = run(tmp_path, scenario)
    assert f"Check Editor: wrote {PILOT} (3 fields, kind=check)." in lines, lines
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert rows == [SERIAL_ROW(facts)], rows
    assert before == after == HEAD_3, (before, after)


# ---------------------------------------------------------------------------
# US-CHK-SPEC-1 - R-CHKED-041.1, .2, .3
# ---------------------------------------------------------------------------


def test_r_chked_041_1_pick_replaces_the_field_set(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.1/1: case 08 and its A2L loaded, the pilot spec in the
    patches folder, the field set ``VALUE_0003`` included and two memory rows;
    the pilot spec picked in the Spec dropdown (click, arrows, enter) -> 3
    fields (included parameters + memory rows), neither ``VALUE_0003`` nor the
    two earlier rows remain, status ``Check Editor: loaded
    'pilot_fields.chk.json' (3 fields).``

    Standing guard on the count (base: 3 memory rows, E1 base column "Yes");
    it guards "earlier fields kept" (6 fields) and "an entry dropped" (2
    fields). The names that come back are R-CHKED-041.2's."""
    old_rows = [(0x1000, "OLD_A", 2), (0x1010, "OLD_B", 1)]

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await include_by_space(pilot, app, facts.v3.name)
        for address, label, size in old_rows:
            await add_memory_row(pilot, app, address, label, size)
        assert included(app) == [facts.v3.name] and len(mem_rows(app)) == 2
        lines = await pick_spec(pilot, app, log, PILOT)
        return lines, included(app), mem_rows(app), fields_lines(app)

    lines, picks, rows, flines = run(tmp_path, scenario)
    assert lines[-1] == f"Check Editor: loaded '{PILOT}' (3 fields).", lines
    assert len(picks) + len(rows) == 3, (picks, rows)
    assert facts.v3.name not in picks, picks
    for address, label, _size in old_rows:
        assert not [r for r in rows if r[0] == f"0x{address:08X}" or r[1] == label], rows
    assert len(flines) == 1 + 3, flines


def test_r_chked_041_2_1_written_spec_names_come_back(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.2/1 (F-27): case 08 and its A2L loaded, the pilot spec,
    an empty field set; the pilot spec picked -> included exactly
    ``[VALUE_0001, VALUE_0002]``, both ``✓`` in the ledger, Fields lines
    ``◆ 0x00000000 VALUE_0001``, ``◆ 0x00000014 VALUE_0002``, ``▪ 0x00C00FFC
    u32 memory row``, head line ``3 fields: 2 params · 1 memory row``.

    Negative control: resolution removed (the base) -> ``3 fields: 0 params ·
    3 memory rows`` -> RED."""

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await pick_spec(pilot, app, log, PILOT)
        return (
            included(app), mark_of(app, facts.v1.name), mark_of(app, facts.v2.name),
            fields_lines(app),
        )

    picks, mark1, mark2, lines = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert (mark1, mark2) == ("✓", "✓"), (mark1, mark2)
    assert lines == [
        HEAD_3,
        f"◆ 0x{facts.v1.address:08X} {facts.v1.name}",
        f"◆ 0x{facts.v2.address:08X} {facts.v2.name}",
        f"▪ 0x{facts.serial:08X} u32 memory row",
    ], lines


def test_r_chked_041_2_3_symbol_disambiguates(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.2/3: the planted twin A2L (``ALPHA`` and ``BETA``, both
    ``0x14``, 2 bytes) loaded with the case 08 image; a spec of one entry
    ``0x14`` ``A0 BE`` with symbol ``BETA`` picked -> included exactly
    ``[BETA]``, 0 memory rows.

    Negative control: the symbol ignored -> a memory row, or the first match
    taken -> ``ALPHA`` -> RED."""
    twin = planted_twin(facts, tmp_path)
    spec = spec_doc([(0x14, facts.image_bytes(0x14, 2), "BETA")])

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={"beta.chk.json": spec}, a2l=twin)
        await pick_spec(pilot, app, log, "beta.chk.json")
        return included(app), mem_rows(app)

    picks, rows = run(tmp_path, scenario)
    assert picks == ["BETA"], picks
    assert rows == [], rows


def test_r_chked_041_3_1_no_a2l_memory_rows(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/1: case 08 image loaded, no A2L; the pilot spec
    picked -> 0 included, 3 memory rows, each Label cell ``—``, each Fields
    line ends ``memory row``.

    Standing guard: holds on the base (every entry is an unlabelled memory row
    there, E1 base column "Yes"); there is no resolution to prove without an
    A2L. It fails on a build that invents a parameter or a label with no A2L."""

    async def scenario(app, pilot, log):
        await open_session(
            pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))}, a2l=False
        )
        await pick_spec(pilot, app, log, PILOT)
        return included(app), mem_rows(app), fields_lines(app)

    picks, rows, lines = run(tmp_path, scenario)
    assert picks == [], picks
    assert len(rows) == 3, rows
    assert [r[1] for r in rows] == [EM, EM, EM], rows
    assert len(lines) == 1 + 3 and all(ln.endswith("memory row") for ln in lines[1:]), lines


def test_r_chked_041_3_2_unmatched_address_memory_row(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/2: case 08 and its A2L loaded; the pilot spec picked
    -> the ``0x00C00FFC`` entry (no parameter has that address) is a memory row
    whose Label cell is ``—`` (the ``SERIAL`` label is not restored: the wire
    form carries none); the other two entries are included parameters, so that
    this memory row is the one unmatched entry.

    Negative control: a made-up label for the unmatched entry -> RED; no
    resolution at all (the base) -> 3 memory rows, 0 included -> RED."""

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await pick_spec(pilot, app, log, PILOT)
        return included(app), mem_rows(app)

    picks, rows = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert rows == [BLANK_SERIAL_ROW(facts)], rows


def test_r_chked_041_3_3_size_mismatch_memory_row(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/3: case 08 and its A2L loaded; a spec of one entry at
    ``VALUE_0002``'s address with 1 byte picked -> 0 included, 1 memory row at
    that address (``u8``). Control in the same session: the pilot spec then
    picked includes ``VALUE_0001`` and ``VALUE_0002``, so the mismatch result
    is not a resolution that never runs.

    Negative control: the size ignored -> ``VALUE_0002`` included -> RED; no
    resolution at all (the base) -> the control pick includes nothing -> RED."""
    one_byte = spec_doc([(facts.v2.address, facts.image_bytes(facts.v2.address, 1))])

    async def scenario(app, pilot, log):
        await open_session(
            pilot, app, facts,
            specs={"short.chk.json": one_byte, PILOT: spec_doc(pilot_entries(facts))},
        )
        await pick_spec(pilot, app, log, "short.chk.json")
        first = (included(app), mem_rows(app))
        await pick_spec(pilot, app, log, PILOT)
        return first, included(app)

    (picks, rows), control = run(tmp_path, scenario)
    assert picks == [], picks
    assert rows == [(f"0x{facts.v2.address:08X}", EM, "u8")], rows
    assert control == [facts.v1.name, facts.v2.name], control


def test_r_chked_041_3_4_ambiguous_memory_row(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/4: the planted twin A2L loaded; a spec of one entry
    ``0x14`` ``A0 BE`` with no symbol picked -> 0 included (neither ``ALPHA``
    nor ``BETA``), 1 memory row ``0x00000014``. Control in the same session: a
    spec naming ``BETA`` then picked includes ``BETA``.

    Negative control: first match taken on an ambiguity -> ``ALPHA`` included
    -> RED; no resolution at all (the base) -> the control pick includes
    nothing -> RED."""
    twin = planted_twin(facts, tmp_path)
    data = facts.image_bytes(0x14, 2)
    specs = {
        "plain.chk.json": spec_doc([(0x14, data)]),
        "beta.chk.json": spec_doc([(0x14, data, "BETA")]),
    }

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs=specs, a2l=twin)
        await pick_spec(pilot, app, log, "plain.chk.json")
        first = (included(app), mem_rows(app))
        await pick_spec(pilot, app, log, "beta.chk.json")
        return first, included(app)

    (picks, rows), control = run(tmp_path, scenario)
    assert picks == [], picks
    assert rows == [("0x00000014", EM, "u16")], rows
    assert control == ["BETA"], control


def test_r_chked_041_3_5_duplicate_memory_row(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/5 (partial: a pick cannot reach it - E3 round 2 NOTE -
    so the two items go through the panel seam ``CheckEditorPanel.load_spec``):
    case 08 and its A2L loaded; a spec of two entries at ``VALUE_0001``'s
    address and size -> ``VALUE_0001`` included once and one memory row
    ``0x00000000``; head line ``2 fields: 1 param · 1 memory row``.

    Negative control: a duplicate included twice or dropped -> not 2 fields ->
    RED; no resolution at all (the base) -> 2 memory rows, 0 included -> RED."""
    v1 = facts.v1
    data = tuple(facts.image_bytes(v1.address, v1.size))
    item = {"address": v1.address, "size": v1.size, "expected": data, "symbol": None}

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts)
        editor(app).load_spec([dict(item), dict(item)], "dup.chk.json")
        await wait_until(
            pilot,
            lambda: head(app).startswith("2 fields"),
            lambda: f"timed out waiting for the seam load: {head(app)!r}",
        )
        return included(app), mem_rows(app), head(app)

    picks, rows, line = run(tmp_path, scenario)
    assert picks == [v1.name], picks
    assert rows == [(f"0x{v1.address:08X}", EM, "u8")], rows
    assert line == "2 fields: 1 param · 1 memory row", line


def test_r_chked_041_3_6_symbol_range_mismatch_memory_row(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-041.3/6 (partial: Inc 4's reader drops such an entry when
    the tag carries a length, so the item goes through the panel seam): a
    ledger of ``ALPHA`` (``0x14``, 2 bytes) and ``GAMMA`` (``0x14``, 1 byte)
    set through ``set_a2l_parameters``; one spec-load item ``{address 0x14,
    size 1, expected (0xA0,), symbol "ALPHA"}`` handed to ``load_spec`` -> 0
    included (neither ``ALPHA`` nor ``GAMMA``), 1 memory row ``0x00000014``,
    Label ``—``, Fmt ``u8``. Control in the same session: an item of size 2
    with symbol ``ALPHA`` includes ``ALPHA``.

    Negative control: a symbol naming a listed parameter at another range
    falling back to the address rule -> ``GAMMA`` included -> RED; no
    resolution at all (the base) -> the control item includes nothing -> RED."""
    rows_in = [
        {"name": "ALPHA", "address": 0x14, "byte_size": 2},
        {"name": "GAMMA", "address": 0x14, "byte_size": 1},
    ]

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, image=False, a2l=False)
        panel = editor(app)
        panel.set_a2l_parameters(rows_in)
        await wait_until(
            pilot, lambda: len(panel._visible_params) == 2, "timed out waiting for the ledger"
        )
        panel.load_spec(
            [{"address": 0x14, "size": 1, "expected": (0xA0,), "symbol": "ALPHA"}],
            "mismatch.chk.json",
        )
        await wait_until(
            pilot, lambda: head(app).startswith("1 field:"), "timed out waiting for the seam load"
        )
        first = (included(app), mem_rows(app))
        panel.load_spec(
            [{"address": 0x14, "size": 2, "expected": (0xA0, 0xBE), "symbol": "ALPHA"}],
            "exact.chk.json",
        )
        await settle(pilot, 4)  # load_spec is synchronous; let the repaint flush
        return first, included(app)

    (picks, rows), control = run(tmp_path, scenario)
    assert picks == [], picks
    assert rows == [("0x00000014", EM, "u8")], rows
    assert control == ["ALPHA"], control


# ---------------------------------------------------------------------------
# US-CHK-SPEC-1 - R-CHKED-025, -026, -027
# ---------------------------------------------------------------------------


def test_r_chked_025_1_session_field_reads_the_image(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-025/1: case 08 and its A2L loaded, the pilot spec picked;
    ``VALUE_0003`` included by ``space``; Write as ``plus.chk.json`` -> the
    entry at ``VALUE_0003``'s address holds the image bytes of its range.

    Standing guard: holds on the base (every field reads the image there; E1
    base column "Yes"); it catches a build that gives a session field a spec's
    bytes or none."""

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await pick_spec(pilot, app, log, PILOT)
        await include_by_space(pilot, app, facts.v3.name)
        _lines, entries = await write_spec(pilot, app, log, "plus.chk.json")
        return entries

    entries = run(tmp_path, scenario)
    v3 = facts.v3
    assert [e for e in entries if e[0] == v3.address] == [
        (v3.address, facts.image_bytes(v3.address, v3.size))
    ], entries


def test_r_chked_025_2_exclude_include_rebaselines(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-025/2: case 08 and its A2L loaded; a Patch Editor apply set
    the image byte at ``0x0`` to ``93``; the pilot spec picked; ``space`` on
    ``VALUE_0001`` (excluded), the toggle awaited, ``space`` again (included);
    Write as ``rebased.chk.json`` -> included ``[VALUE_0002, VALUE_0001]``, the
    entries ``0x14`` ``A0 BE``, ``0x0`` ``93`` (re-baselined from the image),
    ``0xC00FFC`` ``FF FF FF FF``.

    Negative control: every field taking the spec's bytes when a spec was
    loaded -> ``0x0`` ``6C`` -> RED; the base clears the picks on the pick, so
    the toggles end with ``VALUE_0001`` excluded -> RED."""
    assert facts.image[facts.v1.address] != PATCH_BYTE

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await apply_bytes(pilot, app, log, tmp_path, facts.v1.address, bytes([PATCH_BYTE]))
        await pick_spec(pilot, app, log, PILOT)
        await include_by_space(pilot, app, facts.v1.name)  # excluded
        await include_by_space(pilot, app, facts.v1.name)  # included again
        _lines, entries = await write_spec(pilot, app, log, "rebased.chk.json")
        return included(app), entries

    picks, entries = run(tmp_path, scenario)
    assert picks == [facts.v2.name, facts.v1.name], picks
    assert entries == [
        (facts.v2.address, facts.image_bytes(facts.v2.address, facts.v2.size)),
        (facts.v1.address, bytes([PATCH_BYTE])),
        (facts.serial, facts.image_bytes(facts.serial, 4)),
    ], entries


def test_r_chked_025_3_reincluded_after_move_reads_the_image(
    tmp_path: Path, facts: Facts
) -> None:
    """Case R-CHKED-025/3 (E3 A-1, SEC5-1): as R-CHKED-056/1 after the return
    (included ``[VALUE_0002]``, memory rows ``0x00C00FFC``, ``0x00000000``);
    ``space`` on ``VALUE_0001``'s ledger row (now at *A*); Write as
    ``moved_plus.chk.json`` -> 4 entries in this order: ``0x14`` ``A0 BE``, *A*
    = the image byte at *A* (not ``6C``), ``0xC00FFC`` ``FF FF FF FF``, ``0x0``
    ``6C``.

    Negative control: the spec's bytes kept under the parameter's name after
    the move -> *A* ``6C`` -> RED."""
    moved = planted_moved(facts, tmp_path)
    a = facts.moved
    assert facts.image[a] != facts.image[facts.v1.address]

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await pick_spec(pilot, app, log, PILOT)
        await go_workspace(pilot, app)
        await load_a2l_file(pilot, app, moved)
        await enter_check_editor(pilot, app)
        assert included(app) == [facts.v2.name], included(app)
        await include_by_space(pilot, app, facts.v1.name)
        _lines, entries = await write_spec(pilot, app, log, "moved_plus.chk.json")
        return entries

    entries = run(tmp_path, scenario)
    assert entries == [
        (facts.v2.address, facts.image_bytes(facts.v2.address, facts.v2.size)),
        (a, bytes([facts.image[a]])),
        (facts.serial, facts.image_bytes(facts.serial, 4)),
        (facts.v1.address, facts.image_bytes(facts.v1.address, facts.v1.size)),
    ], entries
    assert entries[1][1] != facts.image_bytes(facts.v1.address, 1), entries


async def patched_pick(pilot, app, log, f: Facts, tmp_path: Path, address: int, data: bytes):
    """Case 08 and its A2L loaded, the pilot spec staged; a Patch Editor apply
    writes ``data`` at ``address``; the pilot spec is picked."""
    await open_session(pilot, app, f, specs={PILOT: spec_doc(pilot_entries(f))})
    await apply_bytes(pilot, app, log, tmp_path, address, data)
    await pick_spec(pilot, app, log, PILOT)


def test_r_chked_026_1_write_keeps_spec_bytes(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-026/1 (D9-11): case 08 and its A2L loaded; a Patch Editor
    apply set ``0x0`` to ``93``; the pilot spec picked; Write as
    ``rewritten.chk.json`` -> entries ``0x0`` ``6C``, ``0x14`` ``A0 BE``,
    ``0xC00FFC`` ``FF FF FF FF`` (the spec's bytes, not the image's).

    Negative control: the expected bytes re-read from the image (the base) ->
    ``0x0`` ``93`` -> RED."""

    async def scenario(app, pilot, log):
        await patched_pick(pilot, app, log, facts, tmp_path, facts.v1.address, bytes([PATCH_BYTE]))
        _lines, entries = await write_spec(pilot, app, log, "rewritten.chk.json")
        return entries

    entries = run(tmp_path, scenario)
    assert entries == pilot_entries(facts), entries


def test_r_chked_026_2_validate_reports_the_drift(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-026/2: as /1; Validate pressed -> status ``Checks: 2
    passed, 1 failed, 0 uncheckable`` and the result row ``0x0-0x0 expected
    [6C] actual [93] -> fail``.

    Negative control: the expected bytes re-read from the image (the base) ->
    ``Checks: 3 passed, 0 failed, 0 uncheckable`` -> RED."""
    original = facts.image[facts.v1.address]

    async def scenario(app, pilot, log):
        await patched_pick(pilot, app, log, facts, tmp_path, facts.v1.address, bytes([PATCH_BYTE]))
        return await validate(pilot, app, log)

    lines, rows = run(tmp_path, scenario)
    assert "Checks: 2 passed, 1 failed, 0 uncheckable" in lines, lines
    expected_row = (
        f"0x{facts.v1.address:X}-0x{facts.v1.address:X} expected [{original:02X}] "
        f"actual [{PATCH_BYTE:02X}] -> fail"
    )
    assert expected_row in rows, rows


def test_r_chked_026_3_memory_row_keeps_spec_bytes(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-026/3: case 08 and its A2L loaded; a Patch Editor apply set
    the image bytes at ``0xC00FFC``-``0xC00FFF`` to ``00 00 00 00``; the pilot
    spec picked; Write as ``mem.chk.json`` -> entry ``0xC00FFC`` ``FF FF FF
    FF``.

    Negative control: the memory row's bytes re-read from the image (the base)
    -> ``00 00 00 00`` -> RED."""

    async def scenario(app, pilot, log):
        await patched_pick(pilot, app, log, facts, tmp_path, facts.serial, bytes(4))
        _lines, entries = await write_spec(pilot, app, log, "mem.chk.json")
        return entries

    entries = run(tmp_path, scenario)
    assert facts.image_bytes(facts.serial, 4) != bytes(4), "the spec's bytes must differ from the patch"
    assert [e for e in entries if e[0] == facts.serial] == [
        (facts.serial, facts.image_bytes(facts.serial, 4))
    ], entries


def test_r_chked_026_4_spec_bytes_survive_same_range_reload(
    tmp_path: Path, facts: Facts
) -> None:
    """Case R-CHKED-026/4 (E3 SEC5-1: the key is name, address and size): as
    /1 (``0x0`` set to ``93``, the pilot spec picked); key ``1``;
    ``firmware.a2l`` loaded again through the Load dialog; key ``=``; Write as
    ``reloaded.chk.json`` -> included ``[VALUE_0001, VALUE_0002]``; entries
    ``0x0`` ``6C``, ``0x14`` ``A0 BE``, ``0xC00FFC`` ``FF FF FF FF``.

    Negative control: the spec's bytes dropped on every repopulation -> ``0x0``
    ``93`` -> RED."""

    async def scenario(app, pilot, log):
        await patched_pick(pilot, app, log, facts, tmp_path, facts.v1.address, bytes([PATCH_BYTE]))
        await go_workspace(pilot, app)
        await load_a2l_file(pilot, app, facts.case / "firmware.a2l")
        await enter_check_editor(pilot, app)
        picks = included(app)
        _lines, entries = await write_spec(pilot, app, log, "reloaded.chk.json")
        return picks, entries

    picks, entries = run(tmp_path, scenario)
    assert picks == [facts.v1.name, facts.v2.name], picks
    assert entries == pilot_entries(facts), entries


def test_r_chked_027_1_session_field_outside_left_out(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-027/1: case 08 loaded; a memory row ``0x0F000000`` size 4
    (outside the image) and, as a control, one inside the image (``SERIAL``)
    added; Write as ``out.chk.json`` -> the file holds no entry at
    ``0xF000000`` and one entry at the inside row; status ``Check Editor: 1
    field(s) outside the loaded image — not declared.``

    Standing guard: holds on the base (E1 base column "Yes")."""
    assert 0x0F000000 not in facts.image

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, a2l=False)
        await add_memory_row(pilot, app, 0x0F000000, "OUTSIDE", 4)
        await add_memory_row(pilot, app, facts.serial, "SERIAL", 4)
        return await write_spec(pilot, app, log, "out.chk.json")

    lines, entries = run(tmp_path, scenario)
    assert "Check Editor: 1 field(s) outside the loaded image — not declared." in lines, lines
    assert entries == [(facts.serial, facts.image_bytes(facts.serial, 4))], entries


def test_r_chked_027_2_loaded_fields_kept_without_image(tmp_path: Path, facts: Facts) -> None:
    """Case R-CHKED-027/2: case 08's A2L loaded, the image unloaded (Workspace
    ``[u]``); the pilot spec picked; Write as ``noimage.chk.json`` -> the file
    holds the 3 pilot-spec entries with the spec's bytes and no status mentions
    ``outside the loaded image``.

    Negative control: a field loaded from a spec left out when the image lacks
    its range (the base) -> an empty spec and ``Check Editor: 3 field(s)
    outside the loaded image — not declared.`` -> RED."""

    async def scenario(app, pilot, log):
        await open_session(pilot, app, facts, specs={PILOT: spec_doc(pilot_entries(facts))})
        await unload_image(pilot, app)
        await pick_spec(pilot, app, log, PILOT)
        return await write_spec(pilot, app, log, "noimage.chk.json")

    lines, entries = run(tmp_path, scenario)
    assert not [ln for ln in lines if "outside the loaded image" in ln], lines
    assert entries == pilot_entries(facts), entries


# ---------------------------------------------------------------------------
# US-CHK-SPEC-1 - R-CHKED-056 (E3 SEC5-1 = A-1)
# ---------------------------------------------------------------------------


async def relayout_and_write(pilot, app, log, f: Facts, tmp_path: Path, planted: Path):
    """Case 08 and its A2L loaded, the pilot spec picked; key ``1``; the
    planted A2L loaded through the Load dialog; key ``=``; Write as
    ``kept.chk.json``. Returns the state the cases read."""
    await open_session(pilot, app, f, specs={PILOT: spec_doc(pilot_entries(f))})
    await pick_spec(pilot, app, log, PILOT)
    await go_workspace(pilot, app)
    await load_a2l_file(pilot, app, planted)
    await enter_check_editor(pilot, app)
    state = (included(app), mem_rows(app), head(app))
    lines, entries = await write_spec(pilot, app, log, "kept.chk.json")
    return state, lines, entries


def assert_declared_entry_kept(f: Facts, state, lines, entries) -> None:
    picks, rows, line = state
    assert picks == [f.v2.name], picks
    assert rows == [BLANK_SERIAL_ROW(f), (f"0x{f.v1.address:08X}", EM, "u8")], rows
    assert line == "3 fields: 1 param · 2 memory rows", line
    assert "Check Editor: wrote kept.chk.json (3 fields, kind=check)." in lines, lines
    assert entries == [
        (f.v2.address, f.image_bytes(f.v2.address, f.v2.size)),
        (f.serial, f.image_bytes(f.serial, 4)),
        (f.v1.address, f.image_bytes(f.v1.address, f.v1.size)),
    ], entries


def test_r_chked_056_1_moved_parameter_keeps_the_declared_entry(
    tmp_path: Path, facts: Facts
) -> None:
    """Case R-CHKED-056/1: case 08 and its A2L loaded, the pilot spec picked;
    the planted moved A2L (``VALUE_0001`` at *A*, 1 byte) loaded through the
    Load dialog; key ``=``; Write as ``kept.chk.json`` -> included exactly
    ``[VALUE_0002]``; memory rows ``0x00C00FFC`` ``—`` ``u32``, then
    ``0x00000000`` ``—`` ``u8``; head line ``3 fields: 1 param · 2 memory
    rows``; status ``Check Editor: wrote kept.chk.json (3 fields,
    kind=check).``; the file holds exactly ``0x14`` ``A0 BE``, ``0xC00FFC``
    ``FF FF FF FF``, ``0x0`` ``6C`` in that order and none at *A*.

    Negative control: the spec's bytes keyed by name only (the E1 design) ->
    an entry at *A* ``6C`` and none at ``0x0`` -> RED."""
    planted = planted_moved(facts, tmp_path)

    async def scenario(app, pilot, log):
        return await relayout_and_write(pilot, app, log, facts, tmp_path, planted)

    state, lines, entries = run(tmp_path, scenario)
    assert_declared_entry_kept(facts, state, lines, entries)
    assert facts.moved not in [a for a, _ in entries], entries


def test_r_chked_056_2_renamed_parameter_keeps_the_declared_entry(
    tmp_path: Path, facts: Facts
) -> None:
    """Case R-CHKED-056/2: as /1 with the planted renamed A2L (``VALUE_0001_R``
    at ``0x00000000``, 1 byte) -> included exactly ``[VALUE_0002]`` (``VALUE_0001_R``
    not included); the memory rows, head line, status and entries of /1.

    Negative control: R-CHKED-055's drop applied to a field loaded from a spec
    -> 2 entries, none at ``0x0`` -> RED."""
    planted = planted_renamed(facts, tmp_path)

    async def scenario(app, pilot, log):
        return await relayout_and_write(pilot, app, log, facts, tmp_path, planted)

    state, lines, entries = run(tmp_path, scenario)
    assert "VALUE_0001_R" not in state[0], state
    assert_declared_entry_kept(facts, state, lines, entries)


def test_r_chked_056_3_resized_parameter_keeps_the_declared_entry(
    tmp_path: Path, facts: Facts
) -> None:
    """Case R-CHKED-056/3: as /1 with the planted resized A2L (``VALUE_0001`` at
    ``0x00000000``, 2 bytes) -> as /1; the entry at ``0x0`` is the 1 byte
    ``6C`` and no 2-byte entry is written at ``0x0``.

    Negative control: the byte count left out of the key -> a 2-byte entry at
    ``0x0`` read from the image -> RED."""
    planted = planted_resized(facts, tmp_path)

    async def scenario(app, pilot, log):
        return await relayout_and_write(pilot, app, log, facts, tmp_path, planted)

    state, lines, entries = run(tmp_path, scenario)
    assert_declared_entry_kept(facts, state, lines, entries)
    assert [e for e in entries if e[0] == facts.v1.address] == [
        (facts.v1.address, facts.image_bytes(facts.v1.address, 1))
    ], entries
