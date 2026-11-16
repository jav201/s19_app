"""Batch-103 Inc 10, E4 tester T10 - shared drivers for the ``test_b103_inc10_*`` files.

Everything drives the shipped chain: the real ``S19TuiApp`` under Textual Pilot, the Load dialog, the Patch
Editor's own boxes and buttons, and the files the save-back writes into the work area.  Expected values are
never typed from the implementation: they come from the case rows of ``inc-10/02-test-cases.md``, from the
committed x64u data (``tests/fixtures/b103_inc10``) and from ``tests/support/independent_reader.py``.
Fixtures are synthetic and public (``examples/``, plus images built here by the system's own writers).
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from textual.widgets import Button, Label

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_intel_hex_from_mem_map, emit_s19_from_mem_map
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR
from tests.b97_probes import is_displayed, painted_rows
from tests.support.b100_load_dialog import is_load_dialog

ROOT = Path(__file__).resolve().parents[2]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"
CASE00 = ROOT / "examples" / "case_00_public" / "s19_sample.s19"
X64U_DIR = ROOT / "tests" / "fixtures" / "b103_inc10"

SIZE = (118, 54)
WIDE = (220, 60)
SIZES = (SIZE, WIDE)
PATCH_ADDRESS = "0x8000007C"
PATCH_BYTES = "DE AD BE EF"
PATCH_RUN = (0xDE, 0xAD, 0xBE, 0xEF)
APPLY_LINE_1 = "Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it"
TABS = ("patch_tab_script", "patch_tab_inspector", "patch_tab_json", "patch_tab_checks")
TAB_PANES = {"patch_tab_script": "patch_win_script", "patch_tab_inspector": "patch_pane_inspector",
             "patch_tab_json": "patch_win_json", "patch_tab_checks": "patch_win_checks"}
PROMPT_IDS = ("patch_saveback_name_input", "patch_saveback_format_button", "patch_saveback_width_button",
              "patch_saveback_confirm_button", "patch_saveback_decline_button")


# ---------------------------------------------------------------- sources


def ranges_of(keys) -> list:
    """Contiguous half-open ranges of a set of addresses."""
    out, start, prev = [], None, None
    for key in sorted(keys):
        if start is None:
            start = prev = key
        elif key == prev + 1:
            prev = key
        else:
            out.append((start, prev + 1))
            start = prev = key
    if start is not None:
        out.append((start, prev + 1))
    return out


def load_image(path: Path):
    """The system's own loader result for an S19 or Intel HEX file."""
    if path.suffix.lower() == ".hex":
        return build_loaded_hex(path, IntelHexFile(path), None, None)
    return build_loaded_s19(path, S19File(str(path)), None, None)


def conversion_sources(folder: Path) -> list:
    """The 8 conversion sources (census sources and their Intel HEX twins), written under ``folder``."""
    folder.mkdir(parents=True, exist_ok=True)
    s2_map = {a: (a * 7) & 0xFF for a in list(range(0x012340, 0x012368)) + list(range(0x020000, 0x020011))}
    s2 = folder / "s2_source.s19"
    s2.write_text(emit_s19_from_mem_map(dict(s2_map), ranges_of(s2_map), 16, b"S2SRC"), newline="\n")
    x64_map = {a: a & 0xFF for a in range(0x0000FFF0, 0x00010014)}
    x64 = folder / "cross64k.s19"
    x64.write_text(emit_s19_from_mem_map(dict(x64_map), ranges_of(x64_map), 32, b"X64"), newline="\n")
    out = []
    for source in (CASE00, s2, CASE01, x64):
        local = folder / source.name
        if source != local:
            shutil.copy2(source, local)
        twin = folder / (source.stem + ".hex")
        loaded = load_image(local)
        twin.write_text(emit_intel_hex_from_mem_map(dict(loaded.mem_map), list(loaded.ranges)), newline="\n")
        out += [local, twin]
    return out


def copy_source(tmp_path: Path, name: str) -> Path:
    """A scratch copy of one conversion source (``firmware.s19``, ``firmware.hex`` ...) under ``tmp/sources``."""
    return next(p for p in conversion_sources(tmp_path / "sources") if p.name == name)


# ---------------------------------------------------------------- app driving


def run_scene(tmp_path: Path, size, body, *, notifications: bool = False):
    """Run ``body(app, pilot)`` in a fresh app (isolated ``base_dir``) at ``size``.

    ``app.status_history`` collects every status message the app sets, in order."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path / "app")
        app.status_history = []
        real = app.set_status

        def _capture(message, *args, **kwargs):
            app.status_history.append(str(message))
            return real(message, *args, **kwargs)

        app.set_status = _capture
        async with app.run_test(size=size, notifications=notifications) as pilot:
            await pilot.pause()
            return await body(app, pilot)

    return asyncio.run(_drive())


async def wait_for(pilot, predicate, description: str, attempts: int = 200) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def settle(pilot, rounds: int = 6) -> None:
    for _ in range(rounds):
        await pilot.pause()


def status_text(app) -> str:
    """The painted last line of the log strip (the status the operator reads)."""
    return str(app.query_one("#log_line_4", Label).render())


def painted_log(app) -> str:
    """The four painted log-strip lines, oldest first."""
    return "\n".join(str(app.query_one(f"#log_line_{i}", Label).render()) for i in (1, 2, 3, 4))


def panel_of(app):
    return app.query_one("#patch_editor_panel")


def need(root, selector: str):
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    return found[0]


async def load_via_dialog(pilot, app, src: Path) -> None:
    """Load ``src`` through the Load dialog (``l``, the path typed, ``#load_ok``)."""
    await pilot.press("l")
    await wait_for(pilot, lambda: is_load_dialog(app.screen), "the Load dialog")
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await wait_for(
        pilot,
        lambda: not is_load_dialog(app.screen) and status_text(app).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


async def click_inner(pilot, selector: str) -> None:
    """Click a control of the landing pane's tab content, scrolling that 9-row pane to it if needed."""
    if await pilot.click(selector):
        return
    pilot.app.screen.query_one(selector).scroll_visible(animate=False)
    await settle(pilot, 3)
    assert await pilot.click(selector), f"click missed {selector}"


async def load_fast(pilot, app, src: Path) -> None:
    """Load ``src`` through the app's own loader (``load_from_path``), as Inc 8's drivers do; the Load dialog
    route is ``load_via_dialog`` (used by the acceptance cases and R-CHG-003.1/1, /5: typing a path key by
    key costs ~10 s a scene)."""
    app.load_from_path(src)
    await wait_for(pilot, lambda: app.current_file is not None and app.current_file.path.name == src.name,
                   f"the load of {src.name}")
    await settle(pilot, 4)


#: "value": a box is filled by assigning its value (fast; the click and key route is exercised by the
#: acceptance cases, which set "keys"); "keys": click, clear, one key press per character.
TYPING = {"mode": "value"}


async def type_into(pilot, selector: str, text: str) -> None:
    """Fill a box: by assignment (default) or by clicking it and pressing keys (``TYPING["mode"] == "keys"``)."""
    if TYPING["mode"] == "value":
        box = pilot.app.screen.query_one(selector)
        box.value = text
        await settle(pilot, 1)
        return
    await click_inner(pilot, selector)
    await pilot.press("ctrl+a", "delete")
    if text:
        await pilot.press(*text)


async def open_patch_editor(pilot, app) -> None:
    app.action_show_screen("patch")
    await wait_for(pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor")
    await settle(pilot)


async def entry_boxes(pilot, address: str, run: str) -> None:
    await type_into(pilot, "#patch_entry_address_input", address)
    await type_into(pilot, "#patch_entry_bytes_input", run)


async def press_entry(pilot, app, button: str, after: str, address: str, run: str = "") -> None:
    """Type the entry boxes and click Add / Edit / Remove; wait for the status ``after``."""
    await entry_boxes(pilot, address, run)
    seen = len(app.status_history)
    await click_inner(pilot, f"#patch_entry_{button}_button")
    await wait_for(pilot, lambda: after in " ".join(app.status_history[seen:]), f"status {after!r}")
    await settle(pilot, 3)


async def add_entry(pilot, app, address: str = PATCH_ADDRESS, run: str = PATCH_BYTES) -> None:
    await press_entry(pilot, app, "add", "Patch Editor: entry added.", address, run)


async def click_tab(pilot, tab: str) -> None:
    assert await pilot.click(f"#{tab}"), f"click missed #{tab}"
    await settle(pilot, 3)


async def press_apply(pilot, app) -> str:
    """Click ``Apply loaded changes``; return the status that Apply set."""
    seen = len(app.status_history)
    app.notices_at_apply = len(app._notifications)
    assert await pilot.click("#patch_doc_apply_button"), "click missed #patch_doc_apply_button"
    await wait_for(pilot, lambda: any(s.startswith("Apply:") for s in app.status_history[seen:]), "an Apply status")
    await settle(pilot, 4)
    return next(s for s in app.status_history[seen:] if s.startswith("Apply:"))


async def applied_scene(pilot, app, source: Path, tab: str = "patch_tab_inspector", dialog: bool = False) -> None:
    """Applied case: ``source`` loaded (``dialog``: through the Load dialog), the PATCH entry added, tab ``tab``
    clicked, Apply pressed."""
    await (load_via_dialog if dialog else load_fast)(pilot, app, source)
    await open_patch_editor(pilot, app)
    await click_tab(pilot, "patch_tab_inspector")  # the entry boxes live in the Inspector pane
    await add_entry(pilot, app)
    await click_tab(pilot, tab)
    await press_apply(pilot, app)


async def press_button(pilot, selector: str, rounds: int = 4) -> None:
    assert await pilot.click(selector), f"click missed {selector}"
    await settle(pilot, rounds)


async def write_file(pilot, app) -> str:
    """Click ``Write file``; wait for the save status; return it."""
    seen = len(app.status_history)
    assert not at_its_place(app, need(app.screen, "#patch_saveback_confirm_button")), "Write file is not at its place"
    assert await pilot.click("#patch_saveback_confirm_button"), "click missed Write file"
    await wait_for(
        pilot,
        lambda: any(s.startswith(("Saved", "Verify", "Patch Editor:")) for s in app.status_history[seen:]),
        "the save-back status",
    )
    await settle(pilot, 6)
    return next(s for s in app.status_history[seen:] if s.startswith(("Saved", "Verify", "Patch Editor:")))


# ---------------------------------------------------------------- what the operator sees


def shown(widget) -> bool:
    """A shown widget: displayed with every holder, not invisible, a non-empty region."""
    return (
        is_displayed(widget)
        and widget.styles.visibility != "hidden"
        and widget.region.width > 0
        and widget.region.height > 0
    )


def at_its_place(app, widget) -> list:
    """Reasons the widget is NOT shown at its place (empty list = shown at its place)."""
    if not shown(widget):
        return [f"{widget.id}: not a shown widget (region {widget.region})"]
    region = widget.region
    if not app.screen.region.contains_region(region):
        return [f"{widget.id}: region {region} leaves the screen {app.screen.region}"]
    hit, _ = app.get_widget_at(*region.center)
    return [] if hit is widget else [f"{widget.id}: the widget at its centre is {hit!r}"]


def row_at_its_place(app, row) -> list:
    """``at_its_place`` for a container (the prompt row): its centre is painted by the row or by one of its own
    children, never by a widget outside it (a container's centre is a child's by construction)."""
    reasons = at_its_place(app, row)
    if reasons and reasons[0].startswith(f"{row.id}: the widget at its centre is "):
        hit, _ = app.get_widget_at(*row.region.center)
        return [] if row in hit.ancestors_with_self else reasons
    return reasons


def need_shown(app, selector: str):
    widget = need(app.screen, selector)
    assert not at_its_place(app, widget), at_its_place(app, widget)
    return widget


def painted(app, widget) -> str:
    """The painted text of a widget, rows joined, whitespace collapsed."""
    return " ".join(" ".join(painted_rows(app, widget)).split())


def prompt_widgets(app) -> dict:
    return {wid: need(app.screen, f"#{wid}") for wid in PROMPT_IDS}


def prompt_is_shown(app) -> bool:
    return shown(need(app.screen, "#patch_saveback_row"))


def prompt_offered(app) -> bool:
    """The prompt row does not carry the ``hidden`` class (the app has offered it, wherever it is painted)."""
    return not need(app.screen, "#patch_saveback_row").has_class("hidden")


def prompt_hidden(app) -> bool:
    """The prompt is withdrawn: the ``hidden`` class is set AND it is not a shown widget (both, so a prompt
    that was never painted cannot pass for one the app hid)."""
    row = need(app.screen, "#patch_saveback_row")
    return row.has_class("hidden") and not shown(row)


def scroll_offsets(panel) -> list:
    """Every non-zero scroll offset of the panel and of the widgets it holds, except the ones inside the
    landing pane's own tab content (``#patch_tab_switcher``: the 9-row pane scrolls itself, R-PE-DEF.1.1)."""
    inner = set(panel.query("#patch_tab_switcher, #patch_tab_switcher *"))
    return [(w.id or type(w).__name__, w.scroll_x, w.scroll_y) for w in [panel, *panel.query("*")]
            if w not in inner and (getattr(w, "scroll_y", 0) or getattr(w, "scroll_x", 0))]


def regions(app, ids) -> dict:
    return {i: need(app.screen, f"#{i}").region for i in ids}


def top_rows(app, ids) -> list:
    return [need(app.screen, f"#{i}").region.y for i in ids]


def notices(app) -> list:
    """(title, message, severity) of every notification raised so far."""
    return [(n.title, n.message, n.severity) for n in app._notifications]


def workarea(app) -> Path:
    return Path(app.workarea)


def work_files(app) -> list:
    base = app.base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    return sorted(p.name for p in base.iterdir() if p.is_file()) if base.is_dir() else []


def written(app, name: str) -> Path:
    path = app.base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR / name
    assert path.is_file(), f"{name} was not written; work area holds {work_files(app)}"
    return path


def first_line(path: Path) -> str:
    return path.read_text(encoding="ascii").splitlines()[0]


def format_label(button: Button) -> str:
    return str(button.label)


def width_label(app) -> str:
    return str(need(app.screen, "#patch_saveback_width_button").label)


def name_value(app) -> str:
    return need(app.screen, "#patch_saveback_name_input").value


# ---------------------------------------------------------------- record readers (text, not the system's reader)


def hex_records(path: Path) -> list:
    """(type, offset, length) of each Intel HEX line, parsed from the text."""
    out = []
    for line in path.read_text(encoding="ascii").splitlines():
        assert line.startswith(":"), f"not an Intel HEX line: {line!r}"
        out.append((int(line[7:9], 16), int(line[3:7], 16), int(line[1:3], 16)))
    return out


def s19_data_lengths(path: Path) -> list:
    """Data bytes of each S1/S2/S3 record, parsed from the text."""
    widths = {"S1": 2, "S2": 3, "S3": 4}
    return [int(l[2:4], 16) - widths[l[:2]] - 1 for l in path.read_text(encoding="ascii").splitlines()
            if l[:2] in widths]


def s0_data(path: Path) -> bytes:
    line = first_line(path)
    assert line.startswith("S0"), line
    count = int(line[2:4], 16)
    return bytes.fromhex(line[8:8 + 2 * (count - 3)])


def last_tag(path: Path) -> str:
    return path.read_text(encoding="ascii").splitlines()[-1][:2]


def current_pane(app) -> str:
    """The pane the landing pane's content switcher shows."""
    return need(app.screen, "#patch_tab_switcher").current


# ---------------------------------------------------------------- whole scenes


def run_applied(tmp_path: Path, size, source: str, tab: str, body, *, dialog: bool = False, **kw):
    """Applied case: ``source`` loaded, the entry added, ``tab`` clicked, Apply pressed; then ``body``."""
    path = copy_source(tmp_path, source)

    async def scene(app, pilot):
        await applied_scene(pilot, app, path, tab, dialog)
        return await body(app, pilot)

    return run_scene(tmp_path, size, scene, **kw)


def run_loaded(tmp_path: Path, size, source, body, *, dialog: bool = False, **kw):
    """``source`` (a conversion-source name, or None for no image) loaded and the Patch Editor open; ``body``."""
    path = copy_source(tmp_path, source) if source else None

    async def scene(app, pilot):
        if path is not None:
            await (load_via_dialog if dialog else load_fast)(pilot, app, path)
        await open_patch_editor(pilot, app)
        await click_tab(pilot, "patch_tab_inspector")
        return await body(app, pilot)

    return run_scene(tmp_path, size, scene, **kw)


async def show_prompt_again(app, pilot, *, fmt: str = "s19", name: str = "firmware-patched.s19") -> None:
    """Re-show the prompt through I-10.1 (the shown-prompt precondition of R-PE-EXPORT.3's cases)."""
    panel_of(app).show_save_prompt(name, output_format=fmt, apply_line=APPLY_LINE_1)
    await settle(pilot, 4)
    assert prompt_is_shown(app), "the prompt is not a shown widget after show_save_prompt"


async def post_decision(app, pilot, name, fmt, width: int = 32) -> list:
    """The panel's confirm message, as the Write file chip posts it, for handler cases that need no prompt
    (the app's own ``on_patch_editor_panel_save_back_decision`` runs).  Returns the new status lines."""
    panel = panel_of(app)
    seen = len(app.status_history)
    panel.post_message(type(panel).SaveBackDecision(name, bytes_per_line=width, output_format=fmt))
    await wait_for(pilot, lambda: any(s.startswith(("Saved", "Verify", "Patch Editor:", "Save"))
                                      for s in app.status_history[seen:]), "the save-back status")
    await settle(pilot, 6)
    return app.status_history[seen:]
