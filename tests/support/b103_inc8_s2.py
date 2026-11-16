"""Batch-103 Inc 8 E4, group S2: shared builders for the StagingSheet widget tests.

The sheet is mounted alone in a minimal ``App`` (the full Patch Editor wiring is group P's).
Expected values come from the committed requirement texts, from I-2 itself (bytes are
encoded with ``encode_definition``, never retyped) and from the header line the sheet
paints (columns are sliced where their header words start, never counted by hand).

Nothing here touches the operator's clipboard: ``no_os_clipboard`` stands in at the three
module-level entry points and fails the test that reaches one.
"""
from __future__ import annotations

import dataclasses
import subprocess
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from textual.app import App
from textual.binding import Binding
from textual.widgets import Input, Static

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = REPO_ROOT / "examples" / "case_00_public"
V171_ASCII = "ASAM.C.ASCII.UBYTE.NUMBER_42"
HEADERS = ("Parameter", "Kind", "Current", "New", "Unit", "Limits", "Δ")
#: The page the DEFC tests show, in this order (names of the committed `definitions` case).
DEFC_NAMES = ("DISPLAY_0001", "ENUM_0001", "MASK_FIELD_0001", "MASK_BIT_0001")


@dataclass
class Case:
    """One parsed A2L with its definitions, its image and where it came from."""

    a2l: dict
    image: dict
    defs: dict
    path: Path


def _parse(path):
    from s19_app.tui.a2l_parse import parse_a2l_file

    return parse_a2l_file(path)


def build_defc(dest: Path) -> Case:
    """The committed `definitions` case (seed of the generator), parsed and described."""
    from s19_app.core import S19File
    from s19_app.tui.a2l_definition import describe_definitions

    subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "tools" / "synth" / "make_release_case.py"),
         "--case", "definitions", "--out", str(dest)],
        check=True, cwd=REPO_ROOT, capture_output=True,
    )
    a2l = _parse(dest / "definitions.a2l")
    image = dict(S19File(str(dest / "definitions.s19")).get_memory_map())
    return Case(a2l, image, describe_definitions(list(DEFC_NAMES), a2l), dest / "definitions.a2l")


def variant(case: Case, dest: Path, *replacements: tuple[str, str]) -> Case:
    """The same A2L with exact text replacements (each `old` must be present), re-parsed."""
    from s19_app.tui.a2l_definition import describe_definitions

    text = case.path.read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / "variant.a2l"
    path.write_text(text, encoding="utf-8")
    a2l = _parse(path)
    return Case(a2l, case.image, describe_definitions(list(DEFC_NAMES), a2l), path)


def build_v171() -> Case:
    """The public V171 demo: the 42-byte ASCII object over `Hello ASAM` + 32 NULs, and one number row."""
    from s19_app.tui.a2l_definition import describe_definition, describe_definitions

    a2l = _parse(EXAMPLES / "ASAP2_Demo_V171.a2l")
    text_def = describe_definition(V171_ASCII, a2l)
    other = None
    for tag in a2l["tags"]:
        name = tag.get("name")
        if name == V171_ASCII or not isinstance(tag.get("address"), int):
            continue
        definition = describe_definition(name, a2l)
        if definition.kind == "number" and definition.bit_mask is None and definition.refusal is None:
            other = name
            break
    assert other is not None
    image = {text_def.address + i: b for i, b in enumerate(b"Hello ASAM" + bytes(32))}
    other_def = describe_definition(other, a2l)
    for i in range(other_def.byte_length or 1):
        image[other_def.address + i] = 0
    return Case(a2l, image, describe_definitions([V171_ASCII, other], a2l), EXAMPLES / "ASAP2_Demo_V171.a2l")


def overlay_entries(case: Case, name: str, text: str) -> list:
    """(address, bytes) of the I-2 encode of `text` for `name`: how the tests stage a value."""
    from s19_app.tui.a2l_definition import Encoded, encode_definition

    result = encode_definition(case.defs[name], case.a2l, text, case.image)
    assert isinstance(result, Encoded), result
    return [(result.address, tuple(result.data))]


class SheetApp(App):
    """The smallest host of one StagingSheet; records what bubbles to the app."""

    CSS = """
    StagingSheet { height: 1fr; width: 1fr; }
    """
    BINDINGS = [Binding("escape", "back", "back")]

    def __init__(self) -> None:
        super().__init__()
        self.backs = 0
        self.staged: list = []
        self.selections: list = []
        self.current_a2l_data = None

    def compose(self):
        from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

        yield StagingSheet(id="patch_sheet")

    def action_back(self) -> None:
        self.backs += 1

    def on_staging_sheet_stage_requested(self, event) -> None:
        self.staged.append((event.name, event.text))

    def on_staging_sheet_selection_changed(self, event) -> None:
        self.selections.append(event.name)


def make_app(body_height: int | None = None) -> SheetApp:
    if body_height is None:
        return SheetApp()
    css = SheetApp.CSS + f"\n#patch_sheet_body {{ height: {body_height}; }}\n"
    return type("SheetAppFixed", (SheetApp,), {"CSS": css})()


@asynccontextmanager
async def sheet_ctx(size=(160, 40), body_height: int | None = None):
    """Mount the sheet alone: yields (app, pilot, sheet)."""
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    app = make_app(body_height)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        yield app, pilot, app.query_one(StagingSheet)


async def show(pilot, sheet, case: Case, names=None, entries=(), image="case") -> None:
    """One page: `show_page` then `set_document` (no describe: the page's definitions are passed)."""
    names = tuple(case.defs) if names is None else names
    img = case.image if image == "case" else image
    sheet.show_page(list(names), {n: case.defs[n] for n in names}, case.a2l, img)
    sheet.set_document(list(entries), img)
    await pilot.pause()
    await pilot.pause()


def plain(content) -> str:
    return content.plain if hasattr(content, "plain") else str(content)


def body_lines(sheet) -> list:
    return plain(sheet.query_one("#patch_sheet_body", Static).content).splitlines()


def body_text(sheet) -> str:
    return "\n".join(body_lines(sheet))


def _starts(header: str) -> list:
    found = sorted((header.index(h), h) for h in HEADERS if h in header)
    return found


def row_line(sheet, name: str) -> str:
    """The painted line of the row named `name` (matched on the name's start in the Parameter column)."""
    lines = body_lines(sheet)
    col = lines[0].index("Parameter")
    hits = [ln for ln in lines[1:] if ln[col:col + 12].rstrip() == name[:12]]
    assert len(hits) == 1, (name, lines)
    return hits[0]


def cells(sheet, name: str) -> dict:
    """The cell text of one row by column word, cut where the header words start."""
    lines = body_lines(sheet)
    header = lines[0]
    line = row_line(sheet, name)
    starts = _starts(header)
    out = {}
    for i, (pos, word) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(line)
        text = line[pos:end].strip()
        # Inc 8b (R-PE-DEF.90): a `│` gutter closes every column, so it is not part of the cell.
        out[word] = text[:-1].rstrip() if text.endswith("│") else text
    out["mark"] = line[:2]
    return out


def bar_statics(sheet) -> list:
    body = sheet.query_one("#patch_sheet_body")
    seen, out = set(), []
    for widget in sheet.query(Static):
        if widget is body or id(widget) in seen:
            continue
        seen.add(id(widget))
        out.append(widget)
    assert len(out) >= 3, out
    return out


def bar_name(sheet) -> str:
    return plain(bar_statics(sheet)[0].content)


def bar_label(sheet) -> str:
    return plain(bar_statics(sheet)[1].content).strip()


def bar_tail(sheet) -> str:
    return plain(bar_statics(sheet)[-1].content)


def formula_input(sheet) -> Input:
    return sheet.query_one("#patch_sheet_input", Input)


async def select(pilot, sheet, name: str) -> None:
    """Down-arrow to the row (the body holds the focus), never by poking `selected`."""
    sheet.query_one("#patch_sheet_body").focus()
    await pilot.pause()
    for key in ("down", "up"):
        for _ in range(400):
            if sheet.selected_name == name:
                return
            before = sheet.selected_name
            await pilot.press(key)
            if sheet.selected_name == before:
                break  # the end of the rows in this direction
    raise AssertionError(f"could not select {name!r}; at {sheet.selected_name!r}")


async def fill(pilot, sheet, text: str) -> None:
    """Put `text` in the formula input as typed text (one insert at the cursor)."""
    inp = formula_input(sheet)
    inp.focus()
    await pilot.pause()
    inp.insert_text_at_cursor(text)
    await pilot.pause()
    await pilot.pause()


async def type_keys(pilot, sheet, text: str) -> None:
    formula_input(sheet).focus()
    await pilot.pause()
    for ch in text:
        await pilot.press(ch)
    await pilot.pause()


@pytest.fixture(autouse=True)
def no_os_clipboard(monkeypatch):
    """Rule 4: the operator's clipboard is never touched; any OS-boundary call fails the test."""
    from s19_app.tui import os_clipboard_input as mod

    def _refuse(*_args, **_kwargs):
        raise AssertionError("a test reached the OS clipboard")

    async def _arefuse(*_args, **_kwargs):
        raise AssertionError("a test reached the OS clipboard")

    monkeypatch.setattr(mod, "read_os_clipboard", _refuse)
    monkeypatch.setattr(mod, "write_os_clipboard", _refuse)
    monkeypatch.setattr(mod, "_mirror_and_write_os_clipboard", _arefuse)


@pytest.fixture(scope="session")
def defc(tmp_path_factory) -> Case:
    return build_defc(tmp_path_factory.mktemp("s2_defc"))


@pytest.fixture(scope="session")
def v171() -> Case:
    return build_v171()


@pytest.fixture(scope="session")
def softa_page():
    from s19_app.tui.a2l_definition import describe_definitions
    from s19_app.tui.a2l_parse import parse_a2l_file

    a2l = parse_a2l_file(EXAMPLES / "software_a.a2l")
    names = list(dict.fromkeys(t["name"] for t in a2l["tags"] if isinstance(t.get("address"), int)))[:200]
    defs = describe_definitions(names, a2l)
    image = {}
    for definition in defs.values():
        if isinstance(definition.address, int):
            for i in range(min(definition.byte_length or 1, 1 << 16)):
                image[definition.address + i] = 0
    return a2l, names, defs, image


def widened(definition, size: int):
    """A copy of a text definition widened to `size` bytes (the E3R1 hostile spans)."""
    return dataclasses.replace(definition, byte_length=size)
