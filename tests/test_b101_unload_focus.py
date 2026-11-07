"""Batch-101 increment 10a - unload state and focus landing (group F).

Written by the independent tester (E4) from the approved design only
(``inc-10/01-requirements.md``, ``02-test-cases.md``, ``E1-slice.md``,
``E1-rulings.md``, ``E3-rulings.md``, ``E3-security.md`` and
``codewire/graph-inc10.md``). No line of the Inc 10a implementation was read.
The nodes whose docstring says "written at E4 integration" (or "added at E4
integration") were added by the integrator, who had read it
(``inc-10/E4-integration-notes.md``).

Requirements observed (the case id is in each node's docstring):

- R-WS-LOADED.18 / .14 / .16 / .19 / .20 - the file status after an unload,
  ``U`` with nothing loaded, the primary's diagnostics, and a saved project and
  a load question after a primary unload;
- R-TUI-012L.8 and R-SHELL-STATUS.7 - the load status and the project-load line
  carry no character of category Cc, Cf, Zl or Zp;
- R-SHELL-FOCUS.2 / .3 / .4 / .5 - the focus after a rail key, an unload and an
  empty-state window;
- R-SEG-OPEN.6 and R-SEG-OPEN.7 - the hidden Split / Join window holds no focus
  and runs no key action or button.

Every node drives the shipped controls (keys, the Loaded panel's ``[u]``
buttons, the Load and Save project dialogs) and reads what is painted or
written to disk. Waits go through ``tests/support/timing.py::wait_until`` and
every negative assertion follows a positive wait in the same node. Windows are
switched with the keys or ``action_show_screen``, never ``action_view_*``.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import sys
import unicodedata
from pathlib import Path

import pytest
from textual.widgets import Button, Input, Label, Static, TextArea

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.screens import ConfirmQuestionScreen  # noqa: E402
from s19_app.tui.screens_directionb import (  # noqa: E402
    LoadedArtifactsPanel,
    PatchEditorPanel,
)
from tests.support import b100_load_dialog as ld  # noqa: E402
from tests.support import b100_projects as projects  # noqa: E402
from tests.support import b100_save_dialog as sd  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

SEED = 20260001
SIZE_MB = 1.0
SIZE = (120, 56)  # measured 118 x 54, the regime of the guide
FOCUS_WAIT_S = 10.0
MESSAGE_WAIT_S = 20.0
LOAD_WAIT_S = 30.0

BAD_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")
RLO = "\u202e"  # right-to-left override (Cf)
ZWSP = "\u200b"  # zero-width space (Cf)

#: The CTX-SHELL focus target of each rail window, written here from the
#: requirement (not read from the product): key, window, target id. The A2L
#: entry is the window's switch landing of E4-R4 (graph I-4): the ``?`` chip,
#: because the tag table's own PgDn would shadow R-TUI-020.1's paging
#: (changed at E4, E4-R4).
RAIL_TARGETS = (
    ("1", "workspace", "files_list"),
    ("2", "a2l", "window_help_a2l"),
    ("3", "mac", "mac_records_list"),
    ("4", "map", "memory_map_panel"),
    ("5", "issues", "validation_issues_groups"),
    ("6", "patch", "patch_editor_panel"),
    ("equals_sign", "check_editor", "check_editor_panel"),
    ("7", "diff", "diff_compare_button"),
    ("8", "flow", "flow_panel"),
    ("right_square_bracket", "flow_execution", "fx_panel"),
    ("9", "checks", "checks_grouped"),
    ("0", "crc_designer", "crc_designer_panel"),
)


# ---------------------------------------------------------------------------
# Fixtures and files
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def case08(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Case 08 (seed 20260001, 1.0 MB), generated once."""
    folder = tmp_path_factory.mktemp("b101_i10f_case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


def s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_three_ranges(path: Path, terminator: bool = True) -> Path:
    """Fixture three: 0x8000 (00..07), 0x8010 (eight FF), 0x8020 (20..27)."""
    lines = [
        "S0030000FC",
        s1(0x8000, bytes(range(8))),
        s1(0x8010, b"\xff" * 8),
        s1(0x8020, bytes(range(0x20, 0x28))),
    ]
    if terminator:
        lines.append("S9030000FC")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def write_bad_checksum(path: Path) -> Path:
    """An S19 with one bad-checksum line (one loader diagnostic)."""
    good = s1(0x8000, bytes(range(8)))
    bad = good[:-2] + ("00" if good[-2:] != "00" else "01")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(["S0030000FC", good, bad, "S9030000FC"]) + "\n", encoding="ascii")
    return path


def copy_to(source: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    return dest


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def painted_name(name: str) -> str:
    """The name without any character of Cc, Cf, Zl, Zp (written here)."""
    return "".join(ch for ch in name if unicodedata.category(ch) not in BAD_CATEGORIES)


def bad_chars(text: str) -> list:
    return [f"U+{ord(ch):04X}" for ch in text if unicodedata.category(ch) in BAD_CATEGORIES]


def change_doc(folder: Path, name: str, address: int, value: int) -> Path:
    import json

    folder.mkdir(parents=True, exist_ok=True)
    doc = folder / name
    doc.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {"type": "bytes", "address": f"0x{address:X}", "bytes": f"{value:02X}"}
                ],
            }
        ),
        encoding="utf-8",
    )
    return doc


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------
def plain_of(widget) -> str:
    content = getattr(widget, "content", None)
    if content is None:
        content = widget.render()
    return str(getattr(content, "plain", content))


def status_text(app) -> str:
    """The painted durable file-status line."""
    return plain_of(app.query_one("#status_text", Label))


def newest_message(app) -> str:
    """The painted newest message line."""
    return plain_of(app.query_one("#log_line_4", Label))


def ws_stats(app) -> str:
    return plain_of(app.query_one("#ws_stats", Static))


def loader_error_count(app) -> int:
    match = re.search(r"Loader (\d+) err", ws_stats(app))
    return -1 if match is None else int(match.group(1))


def slot_texts(app) -> list:
    """The three Loaded-panel slot readouts: primary, MAC, A2L."""
    panel = app.query_one("#loaded_panel", LoadedArtifactsPanel)
    return [plain_of(cell) for cell in panel.query(".loaded-detail")]


def focus_of(app):
    return app.default_screen.focused


def focus_report(app) -> str:
    widget = focus_of(app)
    if widget is None:
        return "no widget focused"
    return f"{type(widget).__name__}#{widget.id} (region area {widget.region.area})"


def inside(widget, container_id: str) -> bool:
    if widget is None:
        return False
    return any(node.id == container_id for node in widget.ancestors_with_self)


def split_join_hidden(app) -> bool:
    return app.query_one("#screen_split_join").has_class("hidden")


def export_files(app) -> list:
    """Every file under the Split / Join export destination (no project)."""
    root = Path(app.workarea) / "splits"
    if not root.exists():
        return []
    return sorted(path.name for path in root.rglob("*") if path.is_file())


def exported_messages(log, mark: int) -> list:
    return [m for m in log.since(mark) if m.startswith(("Exported", "nothing selected"))]


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
async def settle(pilot, count: int = 8) -> None:
    for _ in range(count):
        await pilot.pause()


async def wait_message(pilot, log, mark: int, text: str, timeout: float = MESSAGE_WAIT_S) -> None:
    await wait_until(
        pilot,
        lambda: text in log.since(mark),
        lambda: f"timed out waiting for the message {text!r}; got {log.since(mark)!r}",
        timeout=timeout,
    )


async def wait_focus(pilot, app, widget_id: str, timeout: float = FOCUS_WAIT_S) -> None:
    """Poll until the focus is on ``widget_id`` and it paints a region."""

    def landed() -> bool:
        widget = focus_of(app)
        return widget is not None and widget.id == widget_id and widget.region.area > 0

    await wait_until(
        pilot,
        landed,
        lambda: f"the focus never landed on #{widget_id}; it is {focus_report(app)}",
        timeout=timeout,
    )


async def wait_screen(pilot, app, key: str, timeout: float = FOCUS_WAIT_S) -> None:
    await wait_until(
        pilot,
        lambda: app._active_screen_key == key,
        lambda: f"the shown window is {app._active_screen_key!r}, not {key!r}",
        timeout=timeout,
    )


async def put_focus(pilot, app, widget_id: str) -> None:
    """Set the focus on ``widget_id`` and wait for it (emulated precondition)."""
    app.default_screen.set_focus(app.query_one(f"#{widget_id}"))
    await wait_until(
        pilot,
        lambda: focus_of(app) is not None and focus_of(app).id == widget_id,
        lambda: f"the precondition focus on #{widget_id} did not hold: {focus_report(app)}",
        timeout=FOCUS_WAIT_S,
    )


async def load_image(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None
        and app.current_file.path.name == path.name
        and status_text(app).startswith("Loaded "),
        lambda: f"the load of {path.name!r} did not finish; status {status_text(app)!r}",
        timeout=LOAD_WAIT_S,
    )
    await settle_workers(pilot)
    await settle(pilot, 8)


async def load_mac(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.mac_path is not None,
        lambda: f"the MAC load of {path.name!r} did not finish; status {status_text(app)!r}",
        timeout=LOAD_WAIT_S,
    )
    await settle_workers(pilot)
    await settle(pilot, 8)


async def load_a2l(pilot, app, path: Path) -> None:
    app.load_a2l_from_path(path)
    await wait_until(
        pilot,
        lambda: app.current_a2l_data is not None,
        "the A2L load did not finish",
        timeout=LOAD_WAIT_S,
    )
    await settle_workers(pilot)
    await settle(pilot, 8)


async def case_session(pilot, app, case: Path, *, mac: bool = True, a2l: bool = False) -> None:
    """Case 08 image, optionally with its A2L and its MAC, and the focus on
    ``files_list`` (the Workspace target)."""
    await load_image(pilot, app, case / "firmware.s19")
    if a2l:
        await load_a2l(pilot, app, case / "firmware.a2l")
    if mac:
        await load_mac(pilot, app, case / "firmware.mac")
    await put_focus(pilot, app, "files_list")


def unload_button(app, kind: str):
    panel = app.query_one("#loaded_panel", LoadedArtifactsPanel)
    for button in panel.query(Button):
        if button.name == kind:
            return button
    return None


async def wait_unload_button(pilot, app, kind: str) -> Button:
    await wait_until(
        pilot,
        lambda: unload_button(app, kind) is not None,
        lambda: f"no [u] button for {kind!r}; slots {slot_texts(app)!r}",
        timeout=FOCUS_WAIT_S,
    )
    return unload_button(app, kind)


async def press_unload(pilot, app, kind: str) -> None:
    """A press of the slot's ``[u]`` button; the focus is left where it is."""
    button = await wait_unload_button(pilot, app, kind)
    button.press()
    await settle(pilot, 2)


def run(base: Path, scenario):
    return projects.run_app(base, scenario, size=SIZE)


# ---------------------------------------------------------------------------
# R-WS-LOADED.18 - the unload status is the file status
# ---------------------------------------------------------------------------
def test_r_ws_loaded_18_1_unload_mac_slot_sets_file_status(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.18 case /1: ``[u]`` on the MAC slot makes ``#status_text``
    ``Unloaded MAC.`` (base: ``Loaded firmware.mac (S19+MAC)`` stays)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        assert status_text(app) == "Loaded firmware.mac (S19+MAC)", status_text(app)
        mark = len(log.messages)
        await press_unload(pilot, app, "mac")
        await wait_message(pilot, log, mark, "Unloaded MAC.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded MAC."
        assert status_text(app) == "Unloaded MAC."

    run(tmp_path, scenario)


def test_r_ws_loaded_18_2_unload_all_sets_file_status(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.18 case /2: ``U`` makes ``#status_text`` ``Unloaded all
    artifacts.``"""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        assert status_text(app) == "Loaded firmware.mac (S19+MAC)", status_text(app)
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded all artifacts."
        assert status_text(app) == "Unloaded all artifacts."

    run(tmp_path, scenario)


def test_r_ws_loaded_18_3_unload_primary_slot_sets_file_status(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.18 case /3: ``[u]`` on the primary slot makes ``#status_text``
    ``Unloaded primary image.``"""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        assert status_text(app) == "Loaded firmware.mac (S19+MAC)", status_text(app)
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded primary image."
        assert status_text(app) == "Unloaded primary image."

    run(tmp_path, scenario)


def test_r_ws_loaded_18_4_unload_a2l_slot_sets_file_status(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.18 case /4: ``[u]`` on the A2L slot makes ``#status_text``
    ``Unloaded A2L.``"""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=False, a2l=True)
        assert status_text(app).startswith("Loaded "), status_text(app)
        mark = len(log.messages)
        await press_unload(pilot, app, "a2l")
        await wait_message(pilot, log, mark, "Unloaded A2L.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded A2L."
        assert status_text(app) == "Unloaded A2L."

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-WS-LOADED.13 - the unload messages (regression)
# ---------------------------------------------------------------------------
def test_r_ws_loaded_13_1_unload_messages_are_unchanged(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.13 case /1 (regression, written at E4 integration): ``[u]``
    on the MAC slot, then ``U``: the newest message line is ``Unloaded MAC.``,
    then ``Unloaded all artifacts.``, each painted once (the file-status write
    of R-WS-LOADED.18 adds no message line). Fails if a message is removed,
    changed or painted twice."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        mark = len(log.messages)
        await press_unload(pilot, app, "mac")
        await wait_message(pilot, log, mark, "Unloaded MAC.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded MAC.", newest_message(app)
        assert list(app.log_lines).count("Unloaded MAC.") == 1, list(app.log_lines)
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded all artifacts.", newest_message(app)
        lines = list(app.log_lines)
        assert (lines.count("Unloaded MAC."), lines.count("Unloaded all artifacts.")) == (1, 1), lines

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-WS-LOADED.14 - U with nothing loaded
# ---------------------------------------------------------------------------
def test_r_ws_loaded_14_1_unload_all_with_nothing_loaded(tmp_path: Path) -> None:
    """R-WS-LOADED.14 case /1: ``U`` on a fresh app says ``Nothing to unload.``
    and leaves the file status ``Ready.`` (base: ``Unloaded all artifacts.``)."""

    async def scenario(app, pilot, log):
        assert status_text(app) == "Ready.", status_text(app)
        assert app.current_file is None and app.current_a2l_path is None
        mark = len(log.messages)
        await pilot.press("U")
        await wait_until(
            pilot,
            lambda: len(log.since(mark)) > 0,
            "U painted no message",
            timeout=MESSAGE_WAIT_S,
        )
        await settle(pilot, 4)
        assert newest_message(app) == "Nothing to unload."
        assert status_text(app) == "Ready."

    run(tmp_path, scenario)


def test_r_ws_loaded_14_2_unload_all_in_an_a2l_only_session(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.14 case /2 (standing guard): in an A2L-only session ``U``
    still unloads the A2L (the new early return must not catch it). Passes on
    base, where ``all`` always proceeds; it fails if the early return ignores
    ``current_a2l_path``."""

    async def scenario(app, pilot, log):
        await load_a2l(pilot, app, case08 / "firmware.a2l")
        assert app.current_file is None, "setup: an image is loaded"
        assert slot_texts(app)[2].startswith("firmware.a2l"), slot_texts(app)
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await settle(pilot, 4)
        assert newest_message(app) == "Unloaded all artifacts."
        assert slot_texts(app)[2] == "(none)", slot_texts(app)
        assert app.current_a2l_path is None

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-WS-LOADED.16 - the primary's diagnostics go with it
# ---------------------------------------------------------------------------
def test_r_ws_loaded_16_1_primary_diagnostics_go_with_it(tmp_path: Path, case08: Path) -> None:
    """R-WS-LOADED.16 case /1: a bad-checksum S19 plus the case 08 MAC; after
    ``[u]`` on the primary the loader-facts line reads 0 errors and no
    ``integrity notices`` text is painted (base: ``Loader 1 err``)."""
    bad = write_bad_checksum(tmp_path / "src" / "bad.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, bad)
        await load_mac(pilot, app, case08 / "firmware.mac")
        await wait_until(
            pilot,
            lambda: loader_error_count(app) == 1,
            lambda: f"setup: the loader facts read {ws_stats(app)!r}",
            timeout=FOCUS_WAIT_S,
        )
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        assert loader_error_count(app) in (0, -1), ws_stats(app)
        assert "bad.s19" not in " ".join(slot_texts(app)), slot_texts(app)
        assert "integrity notices" not in status_text(app)
        assert "integrity notices" not in newest_message(app)

    run(tmp_path, scenario)


def test_r_ws_loaded_16_2_primary_unload_without_mac_clears_the_session(tmp_path: Path) -> None:
    """R-WS-LOADED.16 case /2 (regression, written at E4 integration): the
    bad-checksum S19 with no MAC; after ``[u]`` on the primary no file is
    loaded and the three hex views paint ``No file loaded.``"""
    bad = write_bad_checksum(tmp_path / "src" / "bad.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, bad)
        assert app.current_file is not None and app.current_file.mac_path is None
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        assert app.current_file is None
        painted = {
            view_id: plain_of(app.query_one(view_id, Static))
            for view_id in ("#hex_view", "#alt_hex_view", "#mac_hex_view")
        }
        assert set(painted.values()) == {"No file loaded."}, painted

    run(tmp_path, scenario)


def test_r_ws_loaded_16_3_mac_diagnostics_stay_after_a_primary_unload(
    tmp_path: Path, case08: Path
) -> None:
    """R-WS-LOADED.16 case /3: with ``firmware_issues.mac`` (2 parse
    diagnostics) the loader facts after ``[u]`` on the primary equal those of a
    MAC-only load of the same file: 2 errors, none of the primary's (base: 1,
    the primary's)."""
    bad = write_bad_checksum(tmp_path / "src" / "bad.s19")
    mac = case08 / "firmware_issues.mac"

    async def reference(app, pilot, log):
        await load_mac(pilot, app, mac)
        await wait_until(
            pilot,
            lambda: loader_error_count(app) >= 0,
            lambda: f"reference: the loader facts read {ws_stats(app)!r}",
            timeout=FOCUS_WAIT_S,
        )
        return loader_error_count(app)

    expected = run(tmp_path / "reference", reference)
    assert expected == 2, f"the MAC-only reference shows {expected} errors, not 2"

    async def scenario(app, pilot, log):
        await load_image(pilot, app, bad)
        await load_mac(pilot, app, mac)
        await wait_until(
            pilot,
            lambda: loader_error_count(app) >= 1,
            lambda: f"setup: the loader facts read {ws_stats(app)!r}",
            timeout=FOCUS_WAIT_S,
        )
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        assert loader_error_count(app) == expected, ws_stats(app)

    run(tmp_path / "session", scenario)


# ---------------------------------------------------------------------------
# R-WS-LOADED.19 / .20 - a saved project and a question after a primary unload
# ---------------------------------------------------------------------------
def project_files(app, name: str) -> dict:
    root = Path(app.workarea) / name
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


async def save_and_wait(pilot, app, log, name: str) -> list:
    mark = len(log.messages)
    await sd.save_through_dialog(pilot, app, name)
    await wait_until(
        pilot,
        lambda: any(
            outcome in message for message in log.since(mark) for outcome in projects.SAVE_OUTCOMES
        ),
        lambda: f"no Save project outcome for {name!r}: {log.since(mark)!r}",
        timeout=LOAD_WAIT_S,
    )
    await settle_workers(pilot)
    await settle(pilot, 6)
    return log.since(mark)


def test_r_ws_loaded_19_1_save_after_primary_unload_writes_no_image(
    tmp_path: Path, case08: Path
) -> None:
    """R-WS-LOADED.19 case /1: fixture three as ``unloaded_primary.s19`` plus the
    case 08 MAC; ``[u]`` on the primary; Save project ``P6`` writes no ``.s19`` or
    ``.hex`` file, no file with the image's SHA-256, and names no
    ``unloaded_primary`` in its status (base: ``P6/unloaded_primary.s19``)."""
    image = write_three_ranges(tmp_path / "src" / "unloaded_primary.s19")
    mac = copy_to(case08 / "firmware.mac", tmp_path / "src" / "firmware.mac")
    image_digest = sha256(image)

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await load_mac(pilot, app, mac)
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        messages = await save_and_wait(pilot, app, log, "P6")
        assert any(m.startswith("Saved project to") for m in messages), messages
        files = project_files(app, "P6")
        assert "firmware.mac" in files, f"the MAC is not in P6: {sorted(files)}"
        images = [n for n in files if n.lower().endswith((".s19", ".hex"))]
        assert images == [], f"P6 holds image files: {images}"
        assert image_digest not in files.values(), f"P6 holds the image's bytes: {sorted(files)}"
        assert not any("unloaded_primary" in m for m in messages), messages

    run(tmp_path, scenario)


def test_r_ws_loaded_19_2_save_without_unload_writes_the_image(
    tmp_path: Path, case08: Path
) -> None:
    """R-WS-LOADED.19 case /2 (control): the same session without the unload;
    Save project ``P7`` holds ``unloaded_primary.s19`` with the image's SHA-256,
    so the /1 oracle can fail."""
    image = write_three_ranges(tmp_path / "src" / "unloaded_primary.s19")
    mac = copy_to(case08 / "firmware.mac", tmp_path / "src" / "firmware.mac")
    image_digest = sha256(image)

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await load_mac(pilot, app, mac)
        messages = await save_and_wait(pilot, app, log, "P7")
        assert any(m.startswith("Saved project to") for m in messages), messages
        files = project_files(app, "P7")
        assert files.get("unloaded_primary.s19") == image_digest, sorted(files)

    run(tmp_path, scenario)


def test_r_ws_loaded_20_1_load_question_names_the_mac_after_a_primary_unload(
    tmp_path: Path, case08: Path
) -> None:
    """R-WS-LOADED.20 case /1: after the primary unload, with no project open and
    one Patch Editor entry unsaved, a project load asks ``Replace
    firmware.mac?`` and names no ``unloaded_primary`` (base: ``Replace
    unloaded_primary.s19?``)."""
    image = write_three_ranges(tmp_path / "src" / "unloaded_primary.s19")
    mac = copy_to(case08 / "firmware.mac", tmp_path / "src" / "firmware.mac")

    async def scenario(app, pilot, log):
        folder = Path(app.workarea) / "PQ"
        copy_to(image, folder / "firmware.s19")
        await load_image(pilot, app, image)
        await load_mac(pilot, app, mac)
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.request_action("add_entry")
        await wait_until(
            pilot,
            lambda: panel.is_dirty,
            "setup: the Patch Editor entry did not make the panel unsaved",
            timeout=FOCUS_WAIT_S,
        )
        mark = len(log.messages)
        await press_unload(pilot, app, "primary")
        await wait_message(pilot, log, mark, "Unloaded primary image.")
        await settle(pilot, 4)
        assert panel.is_dirty, "setup: the unload dropped the unsaved entry"
        assert app.current_project is None
        # The `p` key must reach the app: put the focus on the Workspace target
        # (on base the unload leaves it on the hidden window's table).
        await put_focus(pilot, app, "files_list")
        await ld.open_project_through_dialog(pilot, app, "PQ", confirm="enter")
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, ConfirmQuestionScreen),
            lambda: f"no load question; screen {type(app.screen).__name__}",
            timeout=FOCUS_WAIT_S,
        )
        await settle(pilot, 4)
        title = plain_of(app.screen.query_one("#confirm_title"))
        body = plain_of(app.screen.query_one("#confirm_body"))
        await pilot.press("n")
        assert title == "Replace firmware.mac?", title
        assert "unloaded_primary" not in title + body, (title, body)

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-012L.8 - the load status paints names without format characters
# ---------------------------------------------------------------------------
def test_r_tui_012l_8_1_load_status_drops_a_cf_character(tmp_path: Path) -> None:
    """R-TUI-012L.8 case /1: ``fw`` U+202E ``gpj.s19`` loads as ``Loaded
    fwgpj.s19 (S19 only)`` in ``#status_text`` and in the newest message, with
    0 characters of Cc, Cf, Zl, Zp (base: U+202E kept)."""
    image = write_three_ranges(tmp_path / "src" / f"fw{RLO}gpj.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        # The load line reaches the message lines directly (not through
        # ``set_status``), so the wait reads every painted line, never the
        # newest alone (R-TST-050 / QC-OR; fixed at E4 integration, I-D8).
        await wait_until(
            pilot,
            lambda: any(line.startswith("Loaded ") for line in app.log_lines),
            lambda: f"no load message; painted lines {ascii(list(app.log_lines)[-4:])}",
            timeout=MESSAGE_WAIT_S,
        )
        await settle(pilot, 4)
        expected = "Loaded fwgpj.s19 (S19 only)"
        assert status_text(app) == expected, ascii(status_text(app))
        assert newest_message(app) == expected, ascii(newest_message(app))
        assert bad_chars(status_text(app) + newest_message(app)) == []

    run(tmp_path, scenario)


def test_r_tui_012l_8_2_mac_name_of_the_plus_mac_arm_is_painted(
    tmp_path: Path, case08: Path
) -> None:
    """R-TUI-012L.8 case /2: with a MAC named ``m`` U+200B ``x.mac`` and fixture
    three both loaded, the load status of the arm that names the MAC ends
    ``+MAC: mx.mac)`` with 0 Cc, Cf, Zl, Zp characters (base: U+200B kept). The
    arm is reached by loading the MAC first and the image second: loading the
    MAC onto an image paints ``(S19+MAC)`` without the MAC name."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")
    mac = copy_to(case08 / "firmware.mac", tmp_path / "src" / f"m{ZWSP}x.mac")

    async def scenario(app, pilot, log):
        await load_mac(pilot, app, mac)
        await load_image(pilot, app, image)
        await wait_until(
            pilot,
            lambda: "mx.mac" in status_text(app).replace(ZWSP, "") and "+MAC:" in status_text(app),
            lambda: f"the MAC load status never painted: {ascii(status_text(app))}",
            timeout=MESSAGE_WAIT_S,
        )
        await settle(pilot, 4)
        text = status_text(app)
        assert text.endswith("+MAC: mx.mac)"), ascii(text)
        assert bad_chars(text + newest_message(app)) == []

    run(tmp_path, scenario)


def test_r_tui_012l_8_3_integrity_notice_arm_paints_the_name(tmp_path: Path) -> None:
    """R-TUI-012L.8 case /3: an S19 with a notice code (no terminator) and U+202E
    in its name loads as ``Loaded <painted name> with integrity notices: `` and
    carries no Cc, Cf, Zl, Zp character (base: U+202E kept)."""
    raw = f"fw{RLO}gpj.s19"
    image = write_three_ranges(tmp_path / "src" / raw, terminator=False)

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await settle(pilot, 4)
        prefix = f"Loaded {painted_name(raw)} with integrity notices: "
        text = status_text(app)
        assert "integrity notices" in text, f"setup: no notice arm: {ascii(text)}"
        assert text.startswith(prefix), ascii(text)
        assert bad_chars(text + newest_message(app)) == []

    run(tmp_path, scenario)


def test_r_tui_012l_8_4_plain_name_is_unchanged(tmp_path: Path, case08: Path) -> None:
    """R-TUI-012L.8 case /4 (regression, written at E4 integration): case 08's
    ``firmware.s19`` loads as ``Loaded firmware.s19 (S19 only)`` in
    ``#status_text`` and in the message lines: the scrub leaves a plain name
    alone. The load line is written to the message lines directly (not
    through ``set_status``), so the painted lines are read."""

    async def scenario(app, pilot, log):
        await load_image(pilot, app, case08 / "firmware.s19")
        await settle(pilot, 4)
        expected = "Loaded firmware.s19 (S19 only)"
        assert status_text(app) == expected, status_text(app)
        assert expected in list(app.log_lines), list(app.log_lines)

    run(tmp_path, scenario)


def test_r_tui_012l_8_5_a_long_name_is_clipped_to_120(tmp_path: Path) -> None:
    """R-TUI-012L.8 case /5 (added at E4 integration: the threshold's E3 A10-06
    arm had no case): a 130-character file name loads as ``Loaded`` + its
    first 119 characters + ``...`` (U+2026) + `` (S19 only)`` in
    ``#status_text`` (base: the whole name)."""
    raw = "n" * 126 + ".s19"
    image = write_three_ranges(tmp_path / "src" / raw)

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await settle(pilot, 4)
        expected = f"Loaded {raw[:119]}… (S19 only)"
        assert status_text(app) == expected, status_text(app)

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SHELL-STATUS.7 - the project-load line
# ---------------------------------------------------------------------------
async def save_unload_reload(pilot, app, log, name: str) -> str:
    """Save project ``name``, ``U``, load it through the Load dialog and return
    the painted file status once the project line is there."""
    await save_and_wait(pilot, app, log, name)
    mark = len(log.messages)
    await pilot.press("U")
    await wait_message(pilot, log, mark, "Unloaded all artifacts.")
    await settle(pilot, 4)
    # The `p` key must reach the app: put the focus on the Workspace target
    # (on base the unload leaves it on the hidden window's table).
    await put_focus(pilot, app, "files_list")
    await ld.open_project_through_dialog(pilot, app, name, confirm="enter")
    prefix = f"Loaded project '{name}'"
    await wait_until(
        pilot,
        lambda: status_text(app).startswith(prefix),
        lambda: f"the project line never painted: {ascii(status_text(app))}",
        timeout=LOAD_WAIT_S,
    )
    await settle_workers(pilot)
    await settle(pilot, 6)
    return status_text(app)


def test_r_shell_status_7_1_project_load_line_has_no_format_character(tmp_path: Path) -> None:
    """R-SHELL-STATUS.7 case /1: fixture three saved as ``fw`` U+202E ``gpj.s19``
    in project ``PB``; ``U``; the project load paints ``Loaded project 'PB' ->
    fwgpj.s19`` with 0 Cc, Cf, Zl, Zp characters (base: U+202E kept)."""
    image = write_three_ranges(tmp_path / "src" / f"fw{RLO}gpj.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        text = await save_unload_reload(pilot, app, log, "PB")
        assert text == "Loaded project 'PB' -> fwgpj.s19", ascii(text)
        assert bad_chars(text) == []

    run(tmp_path, scenario)


def test_r_shell_status_7_2_project_load_line_scrubs_the_mac_name(
    tmp_path: Path, case08: Path
) -> None:
    """R-SHELL-STATUS.7 case /2: as /1 with a MAC ``m`` U+200B ``x.mac`` in ``PB``
    paints ``Loaded project 'PB' -> fwgpj.s19 + mx.mac`` (base: U+202E and
    U+200B kept)."""
    image = write_three_ranges(tmp_path / "src" / f"fw{RLO}gpj.s19")
    mac = copy_to(case08 / "firmware.mac", tmp_path / "src" / f"m{ZWSP}x.mac")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await load_mac(pilot, app, mac)
        text = await save_unload_reload(pilot, app, log, "PB")
        assert text == "Loaded project 'PB' -> fwgpj.s19 + mx.mac", ascii(text)
        assert bad_chars(text) == []

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SHELL-FOCUS.2 - the focus after a rail key
# ---------------------------------------------------------------------------
def test_r_shell_focus_2_1_key_2_lands_on_the_a2l_window_help_chip(tmp_path: Path, case08: Path) -> None:
    """R-SHELL-FOCUS.2 case /1 (changed at E4, E4-R4): with the image and A2L
    loaded and ``files_list`` focused, ``2`` lands the focus on the A2L
    window's switch landing ``window_help_a2l`` (graph I-4), inside the shown
    window and not on the tag table, whose own PgDn would scroll it instead of
    paging the explorer (R-TUI-020.1; base: ``ws_load_project_button``, in the
    hidden Workspace, area 0; the Inc 10a tree before E4-R4: ``a2l_tags_list``)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=False, a2l=True)
        await pilot.press("2")
        await wait_screen(pilot, app, "a2l")
        await wait_focus(pilot, app, "window_help_a2l")
        assert inside(focus_of(app), "screen_a2l"), focus_report(app)
        await settle(pilot, 6)
        assert focus_of(app) is not None and focus_of(app).id == "window_help_a2l", focus_report(app)

    run(tmp_path, scenario)


async def open_split_join(pilot, app) -> None:
    """Open Split / Join through the palette entry's action and wait for
    ``#sje_table`` to hold the focus with a region: R-SEG-OPEN.1 case /1 (the
    open path still focuses the table), checked by every node that opens the
    window (E4 integration, I-D9)."""
    app.action_open_split_join_export()
    await wait_focus(pilot, app, "sje_table")
    assert not split_join_hidden(app), "setup: Split / Join is not shown"
    assert app._active_screen_key == "split_join"


def test_r_shell_focus_2_2_esc_in_split_join_focuses_the_workspace_target(
    tmp_path: Path, case08: Path
) -> None:
    """R-SHELL-FOCUS.2 case /2: Esc in Split / Join shows the Workspace with
    ``files_list`` focused (base: nothing focused)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        await open_split_join(pilot, app)
        await pilot.press("escape")
        await wait_screen(pilot, app, "workspace")
        await wait_focus(pilot, app, "files_list")

    run(tmp_path, scenario)


def test_r_shell_focus_2_3_rail_key_in_split_join_focuses_that_window(
    tmp_path: Path, case08: Path
) -> None:
    """R-SHELL-FOCUS.2 case /3: ``3`` in Split / Join shows the MAC View with
    ``mac_records_list`` focused (base: nothing focused)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        await open_split_join(pilot, app)
        await pilot.press("3")
        await wait_screen(pilot, app, "mac")
        await wait_focus(pilot, app, "mac_records_list")

    run(tmp_path, scenario)


def target_is_shown(app, target_id: str) -> bool:
    return app.query_one(f"#{target_id}").region.area > 0


def focus_matches_target(app, target_id: str) -> bool:
    widget = focus_of(app)
    if widget is None or widget.region.area <= 0:
        return False
    return widget.id == target_id or inside(widget, target_id)


def window_fallback_id(app, container_id: str, rail_id: str) -> str:
    """R-SHELL-FOCUS.5's landing when the window's target is not shown: the
    first shown focusable widget of the window that is not a text box, else
    the window's rail item (written from the requirement, as in /5/1)."""
    shown = [
        widget
        for widget in app.query_one(f"#{container_id}").query("*")
        if widget.can_focus
        and widget.focusable
        and widget.region.area > 0
        and not isinstance(widget, (Input, TextArea))
    ]
    return shown[0].id if shown else rail_id


async def wait_empty_workspace_landing(pilot, app) -> str:
    """After ``U`` the empty state hides the Workspace panes (LLR-002.3), so
    ``files_list`` is not shown and R-SHELL-FOCUS.3 / .5 land the focus on the
    Workspace's fallback; wait for it and return its id."""
    await wait_until(
        pilot,
        lambda: app.query_one("#files_list").region.area == 0,
        "setup: files_list is still shown after U",
        timeout=FOCUS_WAIT_S,
    )
    expected = window_fallback_id(app, "screen_workspace", "rail_item_workspace")
    await wait_focus(pilot, app, expected)
    return expected


@pytest.mark.parametrize(
    "key,window,target_id", RAIL_TARGETS, ids=[row[1] for row in RAIL_TARGETS]
)
def test_r_shell_focus_2_5_every_rail_key_lands_on_its_target(
    tmp_path: Path, case08: Path, key: str, window: str, target_id: str
) -> None:
    """R-SHELL-FOCUS.2 case /5: with the image, A2L and MAC loaded, each rail key
    lands the focus on its window's CTX-SHELL target, or (target not shown) on
    the first shown focusable non-text widget of the window, else its rail item
    (base: the focus stays in the window just left)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=True, a2l=True)
        if window == "workspace":
            await pilot.press("3")
            await wait_screen(pilot, app, "mac")
            await settle(pilot, 8)
        await pilot.press(key)
        await wait_screen(pilot, app, window)
        await wait_until(
            pilot,
            lambda: focus_matches_target(app, target_id),
            lambda: f"after {key!r} the focus is {focus_report(app)}, not #{target_id}",
            timeout=FOCUS_WAIT_S,
        )
        assert target_is_shown(app, target_id), f"#{target_id} paints no region"

    run(tmp_path, scenario)


def test_r_shell_focus_2_6_synchronous_clear_decides_and_enter_runs_nothing(
    tmp_path: Path,
) -> None:
    """R-SHELL-FOCUS.2 case /6: with a Patch Editor button focused, running ``1``'s
    action clears the focus before any await, an Enter pressed at once runs no
    Patch Editor control (no ``Validate:`` message), and the focus lands on
    ``files_list`` (base: the button keeps the focus and Enter paints
    ``Validate: 1 entry, 0 error(s), 0 warning(s)``)."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await pilot.press("6")
        await wait_screen(pilot, app, "patch")
        await settle(pilot, 6)
        doc = change_doc(app._patches_dir(), "i10f.changes.json", 0x8013, 0xAA)
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        mark = len(log.messages)
        panel.post_message(PatchEditorPanel.ActionRequested("load_doc", path_text=str(doc)))
        await wait_until(
            pilot,
            lambda: any(m.startswith("Loaded change") for m in log.since(mark)),
            lambda: f"setup: the document did not load: {log.since(mark)!r}",
            timeout=MESSAGE_WAIT_S,
        )
        await put_focus(pilot, app, "patch_doc_validate_button")
        assert not any(m.startswith("Validate:") for m in log.since(mark)), "setup"
        mark = len(log.messages)
        app.action_show_screen("workspace")
        # No await since the action returned: the clear is synchronous.
        assert focus_of(app) is None, (
            f"the focus was not cleared synchronously: {focus_report(app)}"
        )
        await pilot.press("enter")
        await wait_screen(pilot, app, "workspace")
        await wait_focus(pilot, app, "files_list")
        await settle(pilot, 4)
        validated = [m for m in log.since(mark) if m.startswith("Validate:")]
        assert validated == [], validated

    run(tmp_path, scenario)


def test_r_shell_focus_2_7_the_later_of_two_rail_keys_wins(tmp_path: Path, case08: Path) -> None:
    """R-SHELL-FOCUS.2 case /7: two rail actions (``2``, then ``3``) with no await
    between them land the focus on ``mac_records_list`` once laid out; the
    stale ``2`` landing does not move it (base: nothing lands)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=True, a2l=True)
        app.action_show_screen("a2l")
        app.action_show_screen("mac")
        await wait_screen(pilot, app, "mac")
        await wait_focus(pilot, app, "mac_records_list")
        await settle(pilot, 8)
        assert focus_of(app) is not None and focus_of(app).id == "mac_records_list", focus_report(app)

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SHELL-FOCUS.3 / .4 - the focus after an unload
# ---------------------------------------------------------------------------
def test_r_shell_focus_3_1_unload_that_removes_the_focused_button_rehomes_focus(
    tmp_path: Path, case08: Path
) -> None:
    """R-SHELL-FOCUS.3 case /1: the MAC slot's ``[u]`` focused and pressed with
    Enter; the unload removes the button and the focus lands on ``files_list``,
    polled until laid out (base: not on ``files_list``)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        button = await wait_unload_button(pilot, app, "mac")
        app.default_screen.set_focus(button)
        await wait_until(
            pilot,
            lambda: focus_of(app) is button,
            lambda: f"setup: the [u] button is not focused: {focus_report(app)}",
            timeout=FOCUS_WAIT_S,
        )
        mark = len(log.messages)
        await pilot.press("enter")
        await wait_message(pilot, log, mark, "Unloaded MAC.")
        await wait_focus(pilot, app, "files_list")

    run(tmp_path, scenario)


def test_r_shell_focus_3_2_unload_with_nothing_focused_lands_on_the_target(tmp_path: Path) -> None:
    """R-SHELL-FOCUS.3 case /2: the Workspace with no focus; ``U`` lands the focus
    on the shown window's landing (base: ``sje_table``, hidden). After ``U``
    the empty state hides the Workspace panes and ``files_list`` with them
    (LLR-002.3), so the landing is R-SHELL-FOCUS.5's fallback of the Workspace
    (corrected at E4 integration, I-D6: the node expected ``files_list``)."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        app.default_screen.set_focus(None)
        await wait_until(
            pilot, lambda: focus_of(app) is None, "setup: the focus was not cleared", timeout=FOCUS_WAIT_S
        )
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await wait_empty_workspace_landing(pilot, app)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_shell_focus_4_1_mac_unload_keeps_a_healthy_list_focus(tmp_path: Path, case08: Path) -> None:
    """R-SHELL-FOCUS.4 case /1 (changed at E4, E4-R2): case 08 S19 + MAC,
    ``files_list`` focused, ``[u]`` on the MAC slot keeps the focus on
    ``files_list`` — the image stays, so ``files_list`` stays shown. The arm
    was ``U``, whose empty state hides ``files_list`` (LLR-002.3; I-D7). Base:
    ``sje_table`` (the unload's ``refresh_window`` focused the hidden table)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        mark = len(log.messages)
        await press_unload(pilot, app, "mac")
        await wait_message(pilot, log, mark, "Unloaded MAC.")
        await settle(pilot, 10)
        await wait_focus(pilot, app, "files_list")
        await settle(pilot, 6)
        assert focus_of(app) is not None and focus_of(app).id == "files_list", focus_report(app)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_shell_focus_4_2_unload_all_keeps_a_rail_items_focus(tmp_path: Path) -> None:
    """R-SHELL-FOCUS.4 case /2: ``rail_item_workspace`` focused, ``U`` keeps it
    (base: the unload refresh moves the focus to ``sje_table``)."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await put_focus(pilot, app, "rail_item_workspace")
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await settle(pilot, 10)
        await wait_focus(pilot, app, "rail_item_workspace")

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SHELL-FOCUS.5 - a target that is not shown
# ---------------------------------------------------------------------------
def test_r_shell_focus_5_1_empty_state_window_uses_the_fallback(tmp_path: Path) -> None:
    """R-SHELL-FOCUS.5 case /1: nothing loaded, ``5`` (the Issues empty state,
    chosen from the empty-state window whose target paints no region): the focus
    is the first shown focusable non-text widget of Issues, else its rail item
    (base: the focus stays on the Workspace rail item)."""

    async def scenario(app, pilot, log):
        target = app.query_one("#validation_issues_groups")
        await pilot.press("5")
        await wait_screen(pilot, app, "issues")
        await settle(pilot, 8)
        assert target.region.area == 0, "setup: the Issues target is shown"
        shown = [
            widget
            for widget in app.query_one("#screen_issues").query("*")
            if widget.can_focus
            and widget.focusable
            and widget.region.area > 0
            and not isinstance(widget, (Input, TextArea))
        ]
        expected = shown[0].id if shown else "rail_item_issues"
        await wait_focus(pilot, app, expected)

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SEG-OPEN.6 - the hidden Split / Join window holds no focus
# ---------------------------------------------------------------------------
def test_r_seg_open_6_1_unload_keeps_the_focus_out_of_the_hidden_window(tmp_path: Path) -> None:
    """R-SEG-OPEN.6 case /1: ``files_list`` focused, ``U``; once the focus has
    landed no focused widget has ``#screen_split_join`` as an ancestor (base:
    ``sje_table``). The positive wait is the landing on the empty Workspace's
    fallback (corrected at E4 integration, I-D6: it waited for ``files_list``,
    which the empty state hides after ``U``, LLR-002.3)."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await put_focus(pilot, app, "files_list")
        assert split_join_hidden(app)
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await wait_empty_workspace_landing(pilot, app)
        await settle(pilot, 6)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_seg_open_6_2_load_keeps_the_focus_out_of_the_hidden_window(tmp_path: Path) -> None:
    """R-SEG-OPEN.6 case /2 (written at E4 integration): fixture three loaded
    (so the Workspace panes are shown), ``files_list`` focused and Split / Join
    hidden; a second load of fixture three puts the focus inside
    ``#screen_split_join`` at no point: every focus the screen takes during the
    load is recorded, none sits in the window, and the focus ends on
    ``files_list``. Base: the load's ``refresh_window`` focuses the hidden
    ``#sje_table`` and the load tail's re-home moves it back, so the end state
    alone could not fail. (With nothing loaded the empty state hides the
    panes, LLR-002.3, so ``files_list`` is focused after a first load.)"""
    image = write_three_ranges(tmp_path / "src" / "three.s19")
    again = write_three_ranges(tmp_path / "src" / "three_again.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await put_focus(pilot, app, "files_list")
        await wait_focus(pilot, app, "files_list")
        assert split_join_hidden(app)
        screen = app.default_screen
        taken = []
        original = screen.set_focus

        def record(widget, *args, **kwargs):
            taken.append(widget)
            return original(widget, *args, **kwargs)

        screen.set_focus = record
        try:
            await load_image(pilot, app, again)
            await wait_focus(pilot, app, "files_list")
            await settle(pilot, 6)
        finally:
            del screen.set_focus
        leaked = [widget.id for widget in taken if inside(widget, "screen_split_join")]
        assert leaked == [], f"the load focused {leaked} inside the hidden window"
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_seg_open_6_3_in_place_write_keeps_the_focus_out_of_the_hidden_window(
    tmp_path: Path,
) -> None:
    """R-SEG-OPEN.6 case /3 (standing guard on base): a one-entry document applied
    in the Patch Editor while Split / Join is hidden leaves no focus inside it.
    Passes on base, where the write hook calls no ``refresh_window``; it fails
    if a later change makes the write refresh the window and take its table
    focus (re-run at Inc 10b's E5)."""
    image = write_three_ranges(tmp_path / "src" / "three.s19")

    async def scenario(app, pilot, log):
        await load_image(pilot, app, image)
        await pilot.press("6")
        await wait_screen(pilot, app, "patch")
        await settle(pilot, 6)
        assert split_join_hidden(app)
        doc = change_doc(app._patches_dir(), "i10f_write.changes.json", 0x8013, 0xAA)
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        mark = len(log.messages)
        panel.post_message(PatchEditorPanel.ActionRequested("load_doc", path_text=str(doc)))
        await wait_until(
            pilot,
            lambda: any(m.startswith("Loaded change") for m in log.since(mark)),
            lambda: f"setup: the document did not load: {log.since(mark)!r}",
            timeout=MESSAGE_WAIT_S,
        )
        panel.post_message(PatchEditorPanel.ActionRequested("apply_doc"))
        await wait_until(
            pilot,
            lambda: any(m.startswith("Apply:") for m in log.since(mark)),
            lambda: f"the write did not run: {log.since(mark)!r}",
            timeout=MESSAGE_WAIT_S,
        )
        assert app.current_file.mem_map[0x8013] == 0xAA, "setup: the image was not written"
        await settle(pilot, 10)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_seg_open_6_4_esc_leaves_no_focus_in_the_closed_window(
    tmp_path: Path, case08: Path
) -> None:
    """R-SEG-OPEN.6 case /4 (standing guard on base, where nothing is focused
    after Esc): after Esc closes Split / Join no focused widget sits inside it.
    It fails if the close leaves the table focused."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        await open_split_join(pilot, app)
        await pilot.press("escape")
        await wait_screen(pilot, app, "workspace")
        await wait_until(
            pilot, lambda: split_join_hidden(app), "Split / Join was not hidden", timeout=FOCUS_WAIT_S
        )
        await settle(pilot, 10)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


def test_r_seg_open_6_5_rail_key_leaves_no_focus_in_the_closed_window(
    tmp_path: Path, case08: Path
) -> None:
    """R-SEG-OPEN.6 case /5 (standing guard on base, where nothing is focused
    after the rail key): after ``3`` closes Split / Join no focused widget sits
    inside it. It fails if the switch leaves the table focused."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        await open_split_join(pilot, app)
        await pilot.press("3")
        await wait_screen(pilot, app, "mac")
        await wait_until(
            pilot, lambda: split_join_hidden(app), "Split / Join was not hidden", timeout=FOCUS_WAIT_S
        )
        await settle(pilot, 10)
        assert not inside(focus_of(app), "screen_split_join"), focus_report(app)

    run(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SEG-OPEN.7 - the hidden window's keys and button run nothing
# ---------------------------------------------------------------------------
async def keys_a_e_then_sentinel(pilot, app) -> None:
    """``a`` then ``e``, then ``2`` as a sentinel: key events are handled in
    order, so once the A2L window is shown both earlier keys have run."""
    await pilot.press("a", "e")
    await pilot.press("2")
    await wait_screen(pilot, app, "a2l")
    await settle(pilot, 4)


def test_r_seg_open_7_1_keys_after_a_mac_unload_export_nothing(tmp_path: Path, case08: Path) -> None:
    """R-SEG-OPEN.7 case /1: case 08 S19 + MAC, ``files_list`` focused, ``[u]`` on
    the MAC slot; ``a`` then ``e`` write 0 files and paint no ``Exported`` (base:
    4 files)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        assert export_files(app) == []
        mark = len(log.messages)
        await press_unload(pilot, app, "mac")
        await wait_message(pilot, log, mark, "Unloaded MAC.")
        await settle(pilot, 10)
        await keys_a_e_then_sentinel(pilot, app)
        assert export_files(app) == [], export_files(app)
        assert exported_messages(log, mark) == [], exported_messages(log, mark)

    run(tmp_path, scenario)


def test_r_seg_open_7_2_keys_after_unload_all_export_nothing(tmp_path: Path, case08: Path) -> None:
    """R-SEG-OPEN.7 case /2: as /1 after ``U``. On base 0 files are written (``U``
    leaves no image to export), but the hidden window's ``e`` runs and paints
    ``nothing selected``; that message is the RED reason here."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08)
        mark = len(log.messages)
        await pilot.press("U")
        await wait_message(pilot, log, mark, "Unloaded all artifacts.")
        await settle(pilot, 10)
        await keys_a_e_then_sentinel(pilot, app)
        assert export_files(app) == [], export_files(app)
        assert exported_messages(log, mark) == [], exported_messages(log, mark)

    run(tmp_path, scenario)


def test_r_seg_open_7_3_keys_stay_inert_while_hidden_even_with_focus_inside(
    tmp_path: Path, case08: Path
) -> None:
    """R-SEG-OPEN.7 case /3: Split / Join opened and closed with Esc, the focus
    then put on ``#sje_table`` (the base's leak shape); ``a`` then ``e`` write 0
    files and paint no ``Exported`` (base: 4 files)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=False)
        await open_split_join(pilot, app)
        await pilot.press("escape")
        await wait_screen(pilot, app, "workspace")
        await wait_until(
            pilot, lambda: split_join_hidden(app), "Split / Join was not hidden", timeout=FOCUS_WAIT_S
        )
        await settle(pilot, 10)
        mark = len(log.messages)
        await put_focus(pilot, app, "sje_table")
        assert split_join_hidden(app)
        await keys_a_e_then_sentinel(pilot, app)
        assert export_files(app) == [], export_files(app)
        assert exported_messages(log, mark) == [], exported_messages(log, mark)

    run(tmp_path, scenario)


def test_r_seg_open_7_4_export_button_writes_nothing_while_hidden(tmp_path: Path, case08: Path) -> None:
    """R-SEG-OPEN.7 case /4: Split / Join opened and every row ticked with ``a``
    (asserted before the trigger), closed with Esc, the focus put on
    ``#sje_export``; Enter writes 0 files, paints no ``Exported`` and no
    ``nothing selected`` (base: the button runs the export)."""

    async def scenario(app, pilot, log):
        await case_session(pilot, app, case08, mac=False)
        await open_split_join(pilot, app)
        await pilot.press("a")
        await wait_until(
            pilot,
            lambda: "nothing selected" not in plain_of(app.query_one("#sje_stats", Static)),
            lambda: f"setup: no row ticked: {plain_of(app.query_one('#sje_stats', Static))!r}",
            timeout=FOCUS_WAIT_S,
        )
        await pilot.press("escape")
        await wait_screen(pilot, app, "workspace")
        await wait_until(
            pilot, lambda: split_join_hidden(app), "Split / Join was not hidden", timeout=FOCUS_WAIT_S
        )
        await settle(pilot, 10)
        await put_focus(pilot, app, "sje_export")
        assert split_join_hidden(app)
        assert export_files(app) == []
        mark = len(log.messages)
        await pilot.press("enter")
        await pilot.press("2")
        await wait_screen(pilot, app, "a2l")
        await settle(pilot, 4)
        assert export_files(app) == [], export_files(app)
        assert exported_messages(log, mark) == [], exported_messages(log, mark)

    run(tmp_path, scenario)
