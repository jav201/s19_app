"""Batch-101 Inc 14 -- help, legend and README describe the shipped app.

Independent tests of the approved design (``inc-14/01-requirements.md``,
``02-test-cases.md``): the six rewritten help sections and six Flow Builder
steps against the approved copy, the claims those sections make against the
running app, the Memory Map legend sheet, and the documents (README,
SECURITY.md, CHANGELOG.md, the user guide and its findings table).

Groups:

- help sections (data): the copy is true, plain text, free of stale claims
  and of references the operator cannot open;
- help claims (app): each claim a rewritten step makes is observed through
  the shipped surface (keys, dialogs, files written);
- legend: the Memory Map key line and the region-row field line;
- documents: README, CHANGELOG.md, user guide, findings table;
- SECURITY.md group (one hold-out unit, ruling N-2): every test named
  ``test_r_doc_security_*``. If the repository setting that the policy names
  is still off at merge, the file, these tests and the README link to it are
  held out together and re-checked at the batch end.

Every check that scans text is also run against a deliberately broken copy
(its negative control), so the check shows that it can fail.
"""
from __future__ import annotations

import asyncio
import copy
import json
import re
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from rich.cells import cell_len
from textual.widgets import Button, DataTable, Input, Label, Select, Static, TextArea

from s19_app.core import S19File
from s19_app.tui import legend as L
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens import LegendScreen, ReportViewerScreen
from s19_app.tui.segment_split_view import SplitJoinWindow
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.report_service import REPORT_FILENAME_REGEX
from s19_app.tui.window_help import WINDOW_HELP_SECTIONS
from tests.support import help_copy_i14 as COPY
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until

ROOT = Path(__file__).resolve().parents[1]
IMAGE_F = ROOT / "examples" / "case_07_stress_smoke" / "firmware.s19"
A2L_F = ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l"

#: The twelve help sections (R-WHELP.7 pins their keys).
SECTION_KEYS = (
    "patch",
    "checks",
    "crc_designer",
    "reports",
    "map",
    "flow",
    "a2l",
    "workspace",
    "split_join_export",
    "flow_execution",
    "check_editor",
    "changes_file_notation",
)


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #


def _flat(text: str) -> str:
    """Whitespace-normalised text (Markdown wraps lines)."""
    return re.sub(r"\s+", " ", text).strip()


def _doc(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"{rel} does not exist in the repository"
    return path.read_text(encoding="utf-8")


def _steps(key: str) -> Tuple[str, ...]:
    return tuple(WINDOW_HELP_SECTIONS[key]["steps"])


def _all_step_texts(sections: Optional[dict] = None) -> List[Tuple[str, int, str]]:
    sections = WINDOW_HELP_SECTIONS if sections is None else sections
    return [
        (key, n, step)
        for key, section in sections.items()
        for n, step in enumerate(section["steps"], start=1)
    ]


def _with_step_appended(key: str, extra: str) -> dict:
    """A deep copy of the sections with ``extra`` added to the end of the
    first step of ``key`` (used by the negative controls)."""
    broken = copy.deepcopy(dict(WINDOW_HELP_SECTIONS))
    steps = list(broken[key]["steps"])
    steps[0] = steps[0] + " " + extra
    broken[key] = {**broken[key], "steps": tuple(steps)}
    return broken


async def _pause(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause()


# --------------------------------------------------------------------------- #
# R-WHELP.12/1 -- every key a step quotes acts on its window
# --------------------------------------------------------------------------- #

_KEY_DISPLAY = {
    "escape": "esc",
    "slash": "/",
    "comma": ",",
    "period": ".",
    "plus": "+",
    "minus": "-",
    "question_mark": "?",
    "equals_sign": "=",
    "right_square_bracket": "]",
    "pagedown": "pgdn",
    "pageup": "pgup",
}

#: Help section -> the window whose keys act while its help is read.
#: ``None``: no window of its own (a modal or a copy-only section): the
#: application keys only.
_SECTION_WINDOW = {
    "patch": "patch",
    "checks": "checks",
    "crc_designer": "crc_designer",
    "reports": None,
    "map": "map",
    "flow": "flow",
    "a2l": "a2l",
    "workspace": "workspace",
    "split_join_export": "split_join",
    "flow_execution": "flow_execution",
    "check_editor": "check_editor",
    "changes_file_notation": None,
}


def _display(key: str) -> str:
    if key in _KEY_DISPLAY:
        return _KEY_DISPLAY[key]
    if key.startswith("ctrl+"):
        return "^" + key[5:].upper()
    return key


def _keys_acting_on(window: Optional[str]) -> set:
    """K(w): the keys whose binding is active while ``window`` is shown, as
    the key bar writes them (E3 A-4, N-1)."""
    keys = set(S19TuiApp._merged_bindings.key_to_bindings)
    if S19TuiApp.ENABLE_COMMAND_PALETTE:
        keys.add(S19TuiApp.COMMAND_PALETTE_BINDING)
    # check_action: paging and confirm keys act on their windows only
    if window not in ("a2l", "mac"):
        keys -= {"plus", "minus"}
    if window != "workspace":
        keys -= {"comma", "period"}
    if window != "flow_execution":
        keys -= {"c"}
    # self-guarded actions bound to another window
    if window != "a2l":
        keys -= {"d"}
    if window != "patch":
        keys -= {"ctrl+z", "ctrl+y"}
    # N-1: find / go-to and paging act only where the window has the target
    if window not in ("workspace", "a2l", "mac"):
        keys -= {"slash", "g"}
    if window not in ("a2l", "mac", "issues"):
        keys -= {"pagedown", "pageup"}
    shown = {_display(k) for k in keys}
    if window == "split_join":
        for binding in SplitJoinWindow.BINDINGS:
            key = binding.key if hasattr(binding, "key") else binding[0]
            shown.add(_display(str(key)))
    return shown


_SPECIAL_TOKENS = {"esc", "space", "enter", "pgup", "pgdn"}


def _key_tokens(step: str) -> List[str]:
    """Key tokens: code spans holding one printable character, ``^`` and a
    letter, or one of the named keys."""
    out = []
    for span in re.findall(r"`([^`]+)`", step):
        if (
            (len(span) == 1 and span.isprintable() and not span.isspace())
            or re.fullmatch(r"\^[A-Za-z]", span)
            or span in _SPECIAL_TOKENS
        ):
            out.append(span)
    return out


def _key_defects(sections: dict) -> List[Tuple[str, int, str]]:
    defects = []
    for key, n, step in _all_step_texts(sections):
        acting = _keys_acting_on(_SECTION_WINDOW[key])
        for token in _key_tokens(step):
            if token not in acting:
                defects.append((key, n, token))
    return defects


def test_r_whelp_12_1_quoted_keys_act_on_the_window() -> None:
    assert _key_defects(WINDOW_HELP_SECTIONS) == []
    # the check reads tokens: the sections with tokens are the ones named
    with_tokens = {
        key for key, _n, step in _all_step_texts() if _key_tokens(step)
    }
    assert {
        "patch", "reports", "map", "a2l", "workspace", "crc_designer",
        "split_join_export", "changes_file_notation",
    } <= with_tokens, with_tokens
    # negative controls: a key that is bound nowhere, and two keys that are
    # bound but inert on this window, are each reported
    assert _key_defects(_with_step_appended("checks", "Press `h`.")) != []
    assert _key_defects(_with_step_appended("checks", "Press `,`.")) != []
    assert _key_defects(_with_step_appended("checks", "Press `d`.")) != []
    # and a key that does act is not reported
    assert _key_defects(_with_step_appended("workspace", "Press `,`.")) == []


# --------------------------------------------------------------------------- #
# R-WHELP.12/2 -- every control the rewritten sections name exists
# --------------------------------------------------------------------------- #

_CONTROLS = {
    "a2l": (
        "Filter tags", "All", "Invalid", "In-Memory", "Find in tag table",
        "Find next", "Page Prev", "Page Next", "Search ASCII text",
        "Find Next", "Goto 0xADDR", "Goto", "Region",
    ),
    "checks": ("Hex Peek",),
    "patch": ("Run checks",),
    "crc_designer": (
        "Ranges", "Intra gap", "Join gaps", "Pad byte", "On conflict",
        "Store placement", "Address", "Bytes", "Store endianness", "Save",
        "Load", "Load path", "Open templates/", "CRC-32/ISO-HDLC",
    ),
    "reports": (
        "Filter", "filter path", "Declared regions", "Context bytes",
        "Generate new report", "Open reports/",
    ),
    "split_join": ("NAMING", "coverage", "EXPORT"),
    "workspace": ("Loaded",),
}


def _painted_strings(root) -> set:
    """Every label, placeholder, border title, column label and text a
    window paints."""
    out: set = set()

    def add(value) -> None:
        if value is None:
            return
        text = str(value).strip()
        if text:
            out.add(text)

    for widget in root.query("*"):
        add(getattr(widget, "border_title", None))
        add(getattr(widget, "border_subtitle", None))
        if isinstance(widget, Button):
            add(widget.label)
        if isinstance(widget, Input):
            add(widget.placeholder)
        if isinstance(widget, TextArea):
            add(getattr(widget, "placeholder", None))
        if isinstance(widget, Select):
            add(getattr(widget, "prompt", None))
            for option in getattr(widget, "_options", []):
                add(option[0] if isinstance(option, tuple) else option)
        if isinstance(widget, DataTable):
            for column in widget.columns.values():
                add(column.label)
        if isinstance(widget, (Static, Label)):
            try:
                add(widget.render())
            except Exception:  # a widget that cannot render yet paints nothing
                pass
        add(getattr(widget, "label", None) if not isinstance(widget, Button) else None)
        add(getattr(widget, "tooltip", None))
    return out


def _control_found(control: str, painted: set) -> bool:
    """A control is painted when a label, placeholder, title or column label
    is the control's name (a leading icon, a trailing colon or a trailing
    parenthesis aside)."""
    if control == "coverage":
        # the coverage column of the ranges table: a mark and a byte count
        return any(re.search(r"[✓✗!]\s*\d+ [KMG]?i?B", text) for text in painted)
    for text in painted:
        for line in text.splitlines():
            t = re.sub(r"^[^\w]+", "", line.strip())
            if t == control or t.rstrip(":") == control:
                return True
            if t.startswith(control + ":") or t.startswith(control + " "):
                return True
    return False


def test_r_whelp_12_2_named_controls_exist(tmp_path: Path) -> None:
    from tests.test_tui_report_seam import _flush, _make_report_project

    async def _drive() -> Dict[str, set]:
        app = S19TuiApp(base_dir=tmp_path)
        painted: Dict[str, set] = {}
        _make_report_project(app, "proj")
        async with app.run_test(size=(220, 60)) as pilot:
            await _pause(pilot)
            app.load_selected_file(IMAGE_F)
            await wait_until(
                pilot,
                lambda: app.current_file is not None,
                "the load of the image",
            )
            await settle_workers(pilot)
            app.load_a2l_from_path(A2L_F)
            await wait_until(
                pilot,
                lambda: app.current_a2l_path is not None,
                "the load of the A2L",
            )
            await settle_workers(pilot)
            for window, screen in (
                ("a2l", "a2l"),
                ("checks", "checks"),
                ("patch", "patch"),
                ("crc_designer", "crc_designer"),
                ("workspace", "workspace"),
            ):
                app.action_show_screen(screen)
                await _pause(pilot)
                painted[window] = _painted_strings(app.screen)
            app.action_open_split_join_export()
            await _pause(pilot)
            window = app.query_one("#screen_split_join", SplitJoinWindow)
            painted["split_join"] = _painted_strings(window)
            window.action_close_window()
            await _pause(pilot)
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            app.action_view_reports()
            await _flush(pilot)
            assert isinstance(app.screen_stack[-1], ReportViewerScreen)
            painted["reports"] = _painted_strings(app.screen_stack[-1])
        return painted

    painted = asyncio.run(_drive())
    missing = [
        (window, control)
        for window, controls in _CONTROLS.items()
        for control in controls
        if not _control_found(control, painted[window])
    ]
    assert sum(len(c) for c in _CONTROLS.values()) == 39
    assert missing == [], f"named controls not painted by their window: {missing}"
    # negative control: a control no window paints is reported
    assert not _control_found("Section tree", painted["a2l"])


# --------------------------------------------------------------------------- #
# R-WHELP.12/3 -- no stale claim
# --------------------------------------------------------------------------- #

_STALE_PHRASES = (
    "section tree",
    "jump to a name",
    "the tree highlights",
    "the same table the Split / Join / Export window offers",
    "the table lists every entry",
    "Grouped view clusters failures by reason",
    "should not be exported",
    "the image's real ranges",
    "(skip / concat)",
    "preview-only until an image is loaded",
    "reload by name",
    "CRC-32/ISO-HDC)",
    "pre-fills from the loaded A2L",
    "`*.md` + `*.html` pair",
    "or browse to one",
    "and the naming pattern",
    "configurable pad byte",
    "today's emitters",
)


def _stale_hits(sections: dict) -> List[Tuple[str, str]]:
    texts = {key: " ".join(section["steps"]) for key, section in sections.items()}
    return [
        (key, phrase)
        for key, text in texts.items()
        for phrase in _STALE_PHRASES
        if phrase in text
    ]


def test_r_whelp_12_3_no_stale_claim() -> None:
    assert len(_STALE_PHRASES) == 18
    assert _stale_hits(WINDOW_HELP_SECTIONS) == []
    # negative control: restoring one stale phrase is found
    broken = _with_step_appended("a2l", "Use the section tree to browse.")
    assert ("a2l", "section tree") in _stale_hits(broken)


# --------------------------------------------------------------------------- #
# R-WHELP.13 -- references the operator can open
# --------------------------------------------------------------------------- #

_REFERENCE_PATTERNS = (
    re.compile(r"folders\.html", re.I),
    re.compile(r"change 1", re.I),
    re.compile(r"change 2", re.I),
    re.compile(r"\b(?:LLR|HLR)-\d"),
    re.compile(r"\bR-[A-Z][A-Z0-9]*-"),
    re.compile(r"E3 ruling", re.I),
    re.compile(r"\binc-?\d", re.I),
)


def _reference_hits(sections: dict) -> List[Tuple[str, int, str]]:
    return [
        (key, n, pattern.pattern)
        for key, n, step in _all_step_texts(sections)
        for pattern in _REFERENCE_PATTERNS
        if pattern.search(step)
    ]


def test_r_whelp_13_1_no_reference_to_unopenable_things() -> None:
    assert _reference_hits(WINDOW_HELP_SECTIONS) == []
    # negative controls
    assert _reference_hits(_with_step_appended("flow", "(LLR-003.7)")) != []
    assert _reference_hits(_with_step_appended("workspace", "see folders.html")) != []
    assert _reference_hits(_with_step_appended("reports", "(Change 2)")) != []


def _folder_constants() -> Dict[str, str]:
    from s19_app.tui import app as app_module
    from s19_app.tui import workspace
    from s19_app.tui.segment_split_view import SPLITS_DIR
    from s19_app.tui.services.project_gather_service import PROJECT_TEMPLATES_DIR
    from s19_app.tui.services.report_service import REPORTS_DIR_NAME

    return {
        "WORKAREA_TEMP": workspace.WORKAREA_TEMP,
        "WORKAREA_DIRNAME": workspace.WORKAREA_DIRNAME,
        "WORKAREA_SUBDIR": workspace.WORKAREA_SUBDIR,
        "WORKAREA_PATCHES": workspace.WORKAREA_PATCHES,
        "SPLITS_DIR": SPLITS_DIR,
        "PROJECT_TEMPLATES_DIR": PROJECT_TEMPLATES_DIR,
        "WORKAREA_TEMPLATES": workspace.WORKAREA_TEMPLATES,
        "REPORTS_DIR_NAME": REPORTS_DIR_NAME,
        "REPORT_FILTERS_DIR_NAME": app_module.REPORT_FILTERS_DIR_NAME,
    }


_REWRITTEN = ("a2l", "workspace", "checks", "crc_designer", "reports", "split_join_export")

#: The eight folder tokens the rewritten sections name (R-WHELP.13/2).
_FOLDER_TOKENS = (
    "temp\\",
    ".s19tool\\workarea\\",
    "patches\\",
    "splits\\",
    "templates\\",
    ".s19tool\\templates\\",
    "reports\\",
    "filters\\",
)


def _folder_parts(sections: dict) -> List[Tuple[str, int, str]]:
    """Every directory part of every code span that holds a backslash path,
    in the rewritten sections, as ``(section, step, part)``."""
    parts = []
    for key, n, step in _all_step_texts({k: sections[k] for k in _REWRITTEN}):
        for span in re.findall(r"`([^`]+)`", step):
            if "\\" not in span:
                continue
            pieces = span.split("\\")
            directories = pieces[:-1]  # the last piece is a file name or empty
            parts.extend((key, n, p) for p in directories if p)
    return parts


def test_r_whelp_13_2_named_folders_are_the_apps() -> None:
    constants = _folder_constants()
    known = set(constants.values())
    unknown = [
        (key, n, part)
        for key, n, part in _folder_parts(WINDOW_HELP_SECTIONS)
        if part not in known
    ]
    assert unknown == [], f"folders no app constant names: {unknown}"
    # the constants carry the values the text writes
    assert constants["WORKAREA_DIRNAME"] == ".s19tool"
    assert constants["WORKAREA_SUBDIR"] == "workarea"
    # all eight folders are named by the rewritten sections
    text = "\n".join(
        step for _k, _n, step in _all_step_texts({k: WINDOW_HELP_SECTIONS[k] for k in _REWRITTEN})
    )
    missing = [token for token in _FOLDER_TOKENS if token not in text]
    assert missing == [], f"folders not named: {missing}"
    # negative control: a folder the app has no constant for is reported
    broken = _with_step_appended("workspace", "Files go to `boards\\` first.")
    assert any(part == "boards" for _k, _n, part in _folder_parts(broken))


# --------------------------------------------------------------------------- #
# R-WHELP.14 -- no Markdown marks
# --------------------------------------------------------------------------- #

_FENCE = re.compile(r"```.*?```", re.S)
_CODE_SPAN = re.compile(r"`[^`]*`")
_MARKS = (
    re.compile(r"\*\*"),
    re.compile(r"__"),
    re.compile(r"(?<![\w*])\*[^\s*][^*]*\*(?![\w*])"),
    re.compile(r"(?<!\w)_[^\s_][^_]*_(?!\w)"),
)


def _mark_hits(sections: dict) -> List[Tuple[str, int, str]]:
    hits = []
    for key, n, step in _all_step_texts(sections):
        text = _CODE_SPAN.sub("", _FENCE.sub("", step))
        for mark in _MARKS:
            if mark.search(text):
                hits.append((key, n, mark.pattern))
    return hits


def test_r_whelp_14_1_no_markdown_marks() -> None:
    assert _mark_hits(WINDOW_HELP_SECTIONS) == []
    # negative controls: bold, italic, underscore pair
    assert _mark_hits(_with_step_appended("checks", "**Pass / Fail / Uncheck**")) != []
    assert _mark_hits(_with_step_appended("checks", "*why* it failed")) != []
    assert _mark_hits(_with_step_appended("checks", "_why_ it failed")) != []
    # a code span is not a mark
    assert _mark_hits(_with_step_appended("checks", "Press `*why*`.")) == []


# --------------------------------------------------------------------------- #
# the approved copy, step by step (one test per case /1)
# --------------------------------------------------------------------------- #


def _equals_copy(section: str, number: int) -> None:
    assert _steps(section)[number - 1] == COPY.REWRITTEN_SECTIONS[section][1][number - 1]


def test_r_whelp_18_1_reports_step_names_one_markdown_file() -> None:
    _equals_copy("reports", 6)
    assert "*.md` + `*.html" not in _steps("reports")[5]


def test_r_whelp_19_1_reports_step_names_saved_regions() -> None:
    _equals_copy("reports", 4)
    assert "pre-fills from the loaded A2L" not in _steps("reports")[3]


def test_r_whelp_20_1_a2l_step_names_the_ascii_search() -> None:
    _equals_copy("a2l", 3)


def test_r_whelp_21_1_split_step_names_the_loaded_image() -> None:
    _equals_copy("split_join_export", 1)


def test_r_whelp_22_1_split_step_names_the_file_names() -> None:
    _equals_copy("split_join_export", 7)


def test_r_whelp_23_1_checks_step_names_outcome_groups() -> None:
    _equals_copy("checks", 2)


def test_r_whelp_24_1_crc_step_names_typed_ranges() -> None:
    _equals_copy("crc_designer", 3)


def test_r_whelp_25_1_crc_template_line_names_a_crc_config() -> None:
    assert _steps("flow")[11] == COPY.FLOW_STEPS[12]
    assert sum(1 for s in _steps("flow") if s.startswith("CRC template — ")) == 1


def test_r_whelp_26_1_flow_help_says_designer_template_refused() -> None:
    assert (
        "a template the CRC Designer saves is not a CRC config and is refused"
        in _steps("flow")[11]
    )


# --------------------------------------------------------------------------- #
# help claims observed through the app
# --------------------------------------------------------------------------- #


def _image_f() -> LoadedFile:
    return build_loaded_s19(IMAGE_F, S19File(str(IMAGE_F)), None, None)


async def _load_image_f(app: S19TuiApp, pilot) -> None:
    app.load_selected_file(IMAGE_F)
    await wait_until(
        pilot,
        lambda: app.current_file is not None
        and app.current_file.path.name == IMAGE_F.name,
        "the load of the image",
    )
    await settle_workers(pilot)


def test_r_whelp_18_2_generate_writes_markdown_only(tmp_path: Path) -> None:
    from tests.test_tui_report_seam import _flush, _make_report_project

    async def _drive() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_report_project(app, "proj")
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await pilot.press("t")
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen), "t must open Reports"
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return sorted(p.name for p in (project_dir / "reports").iterdir())

    names = asyncio.run(_drive())
    assert len(names) == 1, names
    assert REPORT_FILENAME_REGEX.match(names[0]), names
    assert not [n for n in names if n.lower().endswith(".html")], names


def _regions_json(regions: Sequence[Tuple[str, int, int]]) -> list:
    return [{"name": n, "start": s, "end": e} for n, s, e in regions]


def _project_with_regions(app: S19TuiApp, name: str, regions) -> Path:
    from tests.test_tui_report_seam import _make_report_project

    project_dir = _make_report_project(app, name)
    manifest = project_dir / "project.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if regions:
        data["declared_regions"] = _regions_json(regions)
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return project_dir


async def _open_reports_with_t(app: S19TuiApp, pilot) -> ReportViewerScreen:
    from tests.test_tui_report_seam import _flush

    await pilot.press("t")
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen), "t must open Reports"
    return screen


def _regions_text(screen: ReportViewerScreen) -> str:
    return screen.query_one("#report_declared_regions", TextArea).text


def test_r_whelp_19_2_declared_regions_come_from_the_project(tmp_path: Path) -> None:
    from tests.test_tui_report_seam import _flush

    regions = [("cal", 0x00800000, 0x0080FFFF), ("cfg", 0x00C00000, 0x00C00FFF)]

    async def _open(base: Path, with_regions: bool) -> str:
        app = S19TuiApp(base_dir=base)
        _project_with_regions(app, "proj", regions if with_regions else [])
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            if not with_regions:
                app.load_a2l_from_path(A2L_F)
                await wait_until(
                    pilot,
                    lambda: app.current_a2l_path is not None,
                    "the load of the A2L",
                )
                await settle_workers(pilot)
            screen = await _open_reports_with_t(app, pilot)
            return _regions_text(screen)

    with_regions = asyncio.run(_open(tmp_path / "p", True))
    assert with_regions == "cal,8388608,8454143\ncfg,12582912,12587007"
    without = asyncio.run(_open(tmp_path / "p0", False))
    assert without == ""


def test_r_whelp_19_3_declared_regions_keep_the_last_generate(tmp_path: Path) -> None:
    from tests.test_tui_report_seam import _flush

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        _project_with_regions(app, "proj", [])
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            screen = await _open_reports_with_t(app, pilot)
            screen.query_one("#report_declared_regions", TextArea).text = (
                "cal,0x00800000,0x0080FFFF"
            )
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            reopened = await _open_reports_with_t(app, pilot)
            return _regions_text(reopened)

    assert asyncio.run(_drive()) == "cal,8388608,8454143"


def test_r_whelp_20_2_slash_focuses_ascii_search(tmp_path: Path) -> None:
    async def _drive() -> Tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await _load_image_f(app, pilot)
            app.load_a2l_from_path(A2L_F)
            await wait_until(
                pilot, lambda: app.current_a2l_path is not None, "the load of the A2L"
            )
            await settle_workers(pilot)
            await pilot.press("2")
            await _pause(pilot)
            app.set_focus(None)
            await pilot.press("slash")
            await _pause(pilot)
            focused = app.focused
            assert focused is not None, "/ must focus a widget on the A2L Explorer"
            return str(focused.id), str(getattr(focused, "placeholder", ""))

    focused_id, placeholder = asyncio.run(_drive())
    assert focused_id == "alt_search_input"
    assert placeholder == "Search ASCII text"


def test_r_whelp_21_2_ranges_come_from_the_loaded_image(tmp_path: Path) -> None:
    async def _drive() -> Tuple[list, list]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await _load_image_f(app, pilot)
            app.action_open_split_join_export()
            await _pause(pilot)
            window = app.query_one("#screen_split_join", SplitJoinWindow)
            rows = [(r.name, r.base, r.size) for r in window._rows()]
            ranges = list(app.current_file.ranges)
            return rows, ranges

    rows, ranges = asyncio.run(_drive())
    assert len(ranges) == 4
    assert rows == [
        (f"range_{i:02d}", start, end - start) for i, (start, end) in enumerate(ranges)
    ]


def test_r_whelp_22_2_naming_line_split_and_join(tmp_path: Path) -> None:
    async def _drive() -> Tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            await _load_image_f(app, pilot)
            app.action_open_split_join_export()
            await _pause(pilot)
            await pilot.press("space")  # tick the highlighted row, range_00
            await _pause(pilot)
            split_line = str(app.query_one("#sje_naming").render())
            await pilot.press("m")  # split -> join
            await _pause(pilot)
            join_line = str(app.query_one("#sje_naming").render())
            return split_line, join_line

    split_line, join_line = asyncio.run(_drive())
    assert split_line.rstrip().endswith("firmware_range_00.s19"), split_line
    assert join_line.rstrip().endswith("firmware_joined.s19"), join_line


def test_r_whelp_23_2_checks_group_order() -> None:
    from tests.test_tui_checks_view import _ChecksHarness, _entry, _service_with
    from s19_app.tui.checks_view import CheckGroupHeader, GroupedChecksPanel

    rows = _service_with(
        [_entry("pass", 0x200), _entry("fail", 0x100), _entry("uncheckable", 0x300, reason="no image")]
    ).check_display_rows()

    async def _drive() -> List[str]:
        app = _ChecksHarness()
        async with app.run_test() as pilot:
            panel = app.query_one(GroupedChecksPanel)
            panel.render_groups(rows)
            await pilot.pause()
            return [
                child.result_label
                for child in panel.children
                if isinstance(child, CheckGroupHeader)
            ]

    assert asyncio.run(_drive()) == ["FAILED", "UNCHECKABLE", "PASSED"]


def test_r_whelp_24_2_coverage_reads_typed_ranges(tmp_path: Path) -> None:
    from tests.test_crc_designer_view import _coverage_preview

    mem = {0x8000 + i: ord(c) for i, c in enumerate("123456789ABCDEF0")}
    expected = zlib.crc32(b"12345678")
    whole = zlib.crc32(b"123456789ABCDEF0")
    assert expected != whole
    text = asyncio.run(
        _coverage_preview(tmp_path, mem, "0x00008000-0x00008008", join="concat")
    )
    assert f"0x{expected:08X}" in text, text
    assert f"0x{whole:08X}" not in text, text


# --------------------------------------------------------------------------- #
# legend: the Memory Map key line and region-row field line
# --------------------------------------------------------------------------- #

_MAP_KEYS = "↑↓ move · click / ↵ inspect · double-click open hex · Esc close"
_FIELD_LINE = "glyph · start · size · size vs largest · A2L sym · band · ↵ inspect"


async def _open_map_legend(app: S19TuiApp, pilot) -> LegendScreen:
    app.action_show_screen("map")
    await pilot.pause()
    app.action_show_legend()
    await pilot.pause()
    assert isinstance(app.screen, LegendScreen), f"legend did not open: {app.screen}"
    return app.screen


def _box_lines(legend: LegendScreen, title: str) -> List[str]:
    for box in legend.query(".legend-sheet-box"):
        if box.border_title == title:
            return [str(s.render()) for s in box.query(Static)]
    raise AssertionError(f"no legend box titled {title!r}")


def test_r_tui_062_10_1_1_map_key_line_text(tmp_path: Path) -> None:
    assert L.MAP_KEYS_LINE == _MAP_KEYS == COPY.MAP_KEYS_LINE

    async def _drive() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            return _box_lines(legend, "Map keys")

    assert asyncio.run(_drive()) == [_MAP_KEYS]
    for stale in ("j k", "select", "↵ open hex"):
        assert stale not in L.MAP_KEYS_LINE


def test_r_tui_062_10_1_2_named_actions_are_the_handled_ones(tmp_path: Path) -> None:
    from s19_app.tui.screens_directionb import RegionRow
    from tests.test_map_click_chain import _capture_nav, _map_ready

    loaded = _image_f()

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        out: dict = {}
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            navs: List[int] = []
            _capture_nav(panel, navs)
            rows = list(app.query(RegionRow))
            assert len(rows) >= 2, "the image has four regions"
            chains: List[int] = []
            for row in rows:
                original = row.post_message

                def _spy(message, _orig=original):
                    if isinstance(message, RegionRow.Activated):
                        chains.append(message.chain)
                    return _orig(message)

                row.post_message = _spy  # type: ignore[method-assign]

            def detail() -> str:
                return str(app.query_one("#map_detail_body").render())

            rows[0].focus()
            await _pause(pilot)
            before = detail()
            await pilot.press("down")
            await _pause(pilot)
            out["down_focus"] = app.focused is rows[1]
            out["down_detail_same"] = detail() == before
            await pilot.press("up")
            await _pause(pilot)
            out["up_focus"] = app.focused is rows[0]
            out["up_detail_same"] = detail() == before
            # Enter inspects
            await pilot.press("down")
            await _pause(pilot)
            await pilot.press("enter")
            await _pause(pilot)
            out["enter_chains"] = list(chains)
            out["enter_detail"] = f"0x{rows[1].region_start:08X}" in detail()
            out["enter_navs"] = list(navs)
            out["enter_screen_is_map"] = app._active_screen_key == "map"
            # a single click inspects
            chains.clear()
            panel_scroll = app.query_one(".map-region-scroll")
            panel_scroll.scroll_to_widget(rows[2], animate=False, top=True)
            for _ in range(8):
                await pilot.pause()
                cx, cy = rows[2].region.center
                widget, _ = app.get_widget_at(int(cx), int(cy))
                if isinstance(widget, RegionRow) and widget.region_start == rows[2].region_start:
                    break
            await pilot.click(rows[2])
            await _pause(pilot)
            out["click_chains"] = list(chains)
            out["click_detail"] = f"0x{rows[2].region_start:08X}" in detail()
            out["click_navs"] = list(navs)
            # a double click opens the Workspace at the region start
            chains.clear()
            await pilot.double_click(rows[2])
            await _pause(pilot)
            out["double_navs"] = list(navs)
            out["double_start"] = rows[2].region_start
            out["double_screen"] = app._active_screen_key
        return out

    out = asyncio.run(_drive())
    assert out["down_focus"] and out["down_detail_same"], out
    assert out["up_focus"] and out["up_detail_same"], out
    assert out["enter_chains"] == [1], out
    assert out["enter_detail"] and out["enter_navs"] == [], out
    assert out["enter_screen_is_map"], out
    assert out["click_chains"] == [1] and out["click_detail"], out
    assert out["click_navs"] == [], out
    assert out["double_navs"] == [out["double_start"]], out
    assert out["double_screen"] == "workspace", out


def test_r_legend_011_1_region_row_field_line(tmp_path: Path) -> None:
    assert L.MAP_REGION_ROW_FIELD_KEY == _FIELD_LINE == COPY.MAP_REGION_ROW_FIELD_KEY

    async def _drive() -> Tuple[List[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await _load_image_f(app, pilot)
            await pilot.press("4")
            await _pause(pilot)
            await pilot.press("k")
            await _pause(pilot)
            legend = app.screen
            assert isinstance(legend, LegendScreen)
            lines = _box_lines(legend, "Region row")
            sheet = "\n".join(
                str(s.render()) for s in legend.query(".legend-sheet-box Static")
            )
            return lines, sheet

    lines, sheet = asyncio.run(_drive())
    assert lines[1] == _FIELD_LINE, lines
    assert "opens hex" not in sheet


def test_r_legend_011_2_changed_lines_fit_the_floor(tmp_path: Path) -> None:
    assert cell_len(_MAP_KEYS) == 63 and cell_len(_FIELD_LINE) == 67
    assert cell_len(L.MAP_KEYS_LINE) <= 72
    assert cell_len(L.MAP_REGION_ROW_FIELD_KEY) <= 72

    async def _drive() -> List[Tuple[str, int, int, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen = []
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _load_image_f(app, pilot)
            await pilot.press("4")
            await _pause(pilot)
            await pilot.press("k")
            await _pause(pilot)
            legend = app.screen
            assert isinstance(legend, LegendScreen)
            for line in legend.query(".legend-sheet-box Static"):
                plain = str(line.render())
                if plain in (_MAP_KEYS, _FIELD_LINE):
                    seen.append(
                        (plain, cell_len(plain), line.region.width, line.region.height)
                    )
        return seen

    seen = asyncio.run(_drive())
    assert sorted(s[0] for s in seen) == sorted([_MAP_KEYS, _FIELD_LINE]), seen
    for plain, cells, width, height in seen:
        assert cells <= 72 and cells <= width and height == 1, (plain, cells, width, height)


# --------------------------------------------------------------------------- #
# README
# --------------------------------------------------------------------------- #

_WINDOWS = (
    "Workspace", "A2L Explorer", "MAC View", "Memory Map", "Issues Report",
    "Patch Editor", "Check Editor", "A2B Diff", "Flow Builder",
    "Flow Execution", "Checks", "CRC Designer", "Split / Join / Export",
)
_RAIL = (
    ("1", "Workspace"), ("2", "A2L Explorer"), ("3", "MAC View"),
    ("4", "Memory Map"), ("5", "Issues Report"), ("6", "Patch Editor"),
    ("=", "Check Editor"), ("7", "A2B Diff"), ("8", "Flow Builder"),
    ("]", "Flow Execution"), ("9", "Checks"), ("0", "CRC Designer"),
)


def _readme() -> str:
    return _doc("README.md")


def _sections(text: str, level: str = "### ") -> Dict[str, str]:
    """Body text of every ``level`` heading, up to the next heading of the
    same or a higher level."""
    depth = len(level.strip())
    out: Dict[str, str] = {}
    current = None
    for line in text.splitlines():
        match = re.match(r"(#+) ", line)
        if match and len(match.group(1)) <= depth:
            if line.startswith(level):
                current = line[len(level):].strip()
                out[current] = ""
            else:
                current = None
        elif current is not None:
            out[current] += line + "\n"
    return out


def _table_rows(text: str) -> List[List[str]]:
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c) for c in cells if c):
            continue
        rows.append(cells)
    return rows


def test_r_doc_readme_2_1_one_section_per_window() -> None:
    sections = _sections(_readme())
    missing = [w for w in _WINDOWS if w not in sections]
    assert missing == [], f"README has no section for: {missing}"
    empty = [w for w in _WINDOWS if not sections[w].strip()]
    assert empty == [], f"README sections with no text: {empty}"
    assert len(_WINDOWS) == 13


def test_r_doc_readme_2_2_rail_table() -> None:
    text = _readme()
    rows = [
        r for r in _table_rows(text)
        if len(r) >= 2 and re.fullmatch(r"`[^`]+`", r[0]) and r[0].strip("`") in dict(_RAIL)
    ]
    got = [(r[0].strip("`"), r[1]) for r in rows]
    assert [k for k, _ in got] == [k for k, _ in _RAIL], got
    for (key, label), (_k, cell) in zip(_RAIL, got):
        assert cell.startswith(label), (key, cell)
    # the paragraph above the table says where Split / Join / Export opens from
    first = text.index("| `1`")
    above = _flat(text[max(0, first - 900):first])
    assert "Split / Join / Export" in above and "palette" in above, above


_CTX_KEYS: Tuple[Tuple[str, ...], ...] = (
    ("Ctrl+K",), ("Ctrl+D",), ("Ctrl+L", "l"), ("Ctrl+S", "s"), ("/",), ("g",),
    ("q", "Ctrl+Q"), ("?",), tuple(k for k, _ in _RAIL), ("U",), ("r",), ("o",),
    ("p",), ("v",), ("j",), ("d",), ("t",), ("x",), ("k",), ("b",), ("+", "-"),
    (",", "."), ("PgDn", "PgUp"), ("Ctrl+Z", "Ctrl+Y"), ("c",), ("Ctrl+P",),
)


def _token_norm(token: str) -> str:
    return token.lower() if token.lower().startswith("ctrl+") else token


def _key_cell_tokens(cell: str) -> set:
    return {_token_norm(t) for t in re.findall(r"`([^`]+)`", cell)}


def _ctx_key_rows_found(rows: List[List[str]]) -> List[Tuple[str, ...]]:
    found = []
    for keys in _CTX_KEYS:
        want = {_token_norm(k) for k in keys}
        if len(keys) == 12:  # the rail keys: one row per window in the window table
            ok = all(
                any(want_one in _key_cell_tokens(r[0]) and r[1] for r in rows if len(r) >= 2)
                for want_one in want
            )
        else:
            ok = any(
                want <= _key_cell_tokens(r[0]) and len(r) >= 2 and r[1].strip()
                for r in rows
                if r
            )
        if ok:
            found.append(keys)
    return found


def test_r_doc_readme_3_1_every_ctx_key_listed() -> None:
    assert len(_CTX_KEYS) == 26
    rows = _table_rows(_readme())
    found = _ctx_key_rows_found(rows)
    missing = [k for k in _CTX_KEYS if k not in found]
    assert missing == [], f"keys with no README table row and action: {missing}"
    # negative control: a table without the `c` row misses exactly that row
    trimmed = [r for r in rows if "`c`" not in r[0]]
    assert ("c",) not in _ctx_key_rows_found(trimmed)


_STALE_README = (
    "ten single-context screens",
    "`1`–`0`",
    "the footer stays uncrowded",
    "`flow.json`",
    "Markdown or self-contained HTML",
    "and executes the selected one",
    "`project.toml` at the repo root",
    "or over every variant of a project",
    "(`SOURCE`",
    "**Save patched**",
    "Flows and change-set runs can execute variant-scoped",
)
_CHECK_EDITOR_PHRASE = (
    "writes the spec into the common `.s19tool/workarea/patches/` folder, "
    "with or without a project"
)


def test_r_doc_readme_4_1_no_stale_claim() -> None:
    text = _flat(_readme())
    assert len(_STALE_README) == 11
    present = [phrase for phrase in _STALE_README if _flat(phrase) in text]
    assert present == [], f"stale README claims still present: {present}"
    section = _flat(_sections(_readme()).get("Check Editor", ""))
    assert _CHECK_EDITOR_PHRASE in section, "Check Editor section lacks the present phrase"


def _link_targets(text: str) -> List[str]:
    targets = []
    for target in re.findall(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text):
        if re.match(r"[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("#"):
            continue
        targets.append(target.split("#")[0])
    return [t for t in targets if t]


def test_r_doc_readme_4_2_linked_documents_exist() -> None:
    targets = _link_targets(_readme())
    assert "CHANGELOG.md" in targets, "the README does not link CHANGELOG.md"
    missing = [t for t in targets if not (ROOT / t).exists()]
    assert missing == [], f"README links to files the tree does not hold: {missing}"


def test_r_doc_readme_4_3_operations_names_placeholders(tmp_path: Path) -> None:
    from s19_app.tui.operations import get_operation
    from s19_app.tui.operations.model import OperationInput

    sections = _sections(_readme())
    heading = next((h for h in sections if h.startswith("Operations")), None)
    assert heading is not None, "README has no Operations section"
    text = _flat(sections[heading])
    for name in ("crc", "extract", "split_by_segment"):
        assert f"`{name}`" in text, f"Operations section does not name {name}"
    assert "not implemented" in text.lower(), text
    assert "executes the selected one" not in text
    # the claim holds: extract only leaves a placeholder note
    result = get_operation("extract").execute(OperationInput.from_loaded(_image_f()))
    assert result.notes == ["placeholder: extract not yet implemented"]


# --------------------------------------------------------------------------- #
# SECURITY.md group (hold-out unit, ruling N-2)
# --------------------------------------------------------------------------- #


def test_r_doc_security_1_1_policy_names_private_path() -> None:
    text = _flat(_doc("SECURITY.md"))
    assert "Security tab" in text
    assert "Report a vulnerability" in text
    assert re.search(r"(?i)\b(do not|don't|never)\b[^.]{0,80}public (github )?issue", text), text


def _status_cell(cells: List[str]) -> str:
    return " ".join(cells[1:]).lower()


_YES = re.compile(r"(?i)\byes\b|supported|receiv|:white_check_mark:|:heavy_check_mark:|✅|✔|✓")
_NO = re.compile(r"(?i)\bno\b|not supported|unsupported|:x:|❌|✗|✘|none|end of life")


def test_r_doc_security_2_1_supported_versions() -> None:
    rows = _table_rows(_doc("SECURITY.md"))
    current = [r for r in rows if "1.0.x" in r[0]]
    assert current, "no table row for 1.0.x"
    assert _YES.search(_status_cell(current[0])), current[0]
    assert not _NO.search(_status_cell(current[0])), current[0]
    earlier = [
        r
        for r in rows
        if ("0.x" in r[0] and "1.0.x" not in r[0])
        or re.search(r"(?i)\brc|release candidate", r[0])
    ]
    assert any("0.x" in r[0] and "1.0.x" not in r[0] for r in earlier), "no row for 0.x"
    assert any(
        re.search(r"(?i)\brc|release candidate", r[0]) for r in earlier
    ), "no row for the 1.0.0 release candidates"
    for row in earlier:
        assert _NO.search(_status_cell(row)), row
        assert not _YES.search(_status_cell(row).replace("not supported", "")), row


def test_r_doc_security_1_3_readme_links_the_policy() -> None:
    targets = _link_targets(_readme())
    assert "SECURITY.md" in targets, "the README does not link SECURITY.md"
    assert (ROOT / "SECURITY.md").is_file()


# --------------------------------------------------------------------------- #
# CHANGELOG.md -- the 1.0.0 release notes
# --------------------------------------------------------------------------- #


def _release() -> str:
    text = _doc("CHANGELOG.md")
    headings = [m for m in re.finditer(r"(?m)^## .*$", text)]
    assert headings, "CHANGELOG.md has no `## ` section"
    assert headings[0].group(0).strip() == "## 1.0.0", headings[0].group(0)
    end = headings[1].start() if len(headings) > 1 else len(text)
    return text[headings[0].start():end]


def _subsection(release: str, name: str) -> str:
    parts = re.split(r"(?m)^### ", release)
    for part in parts[1:]:
        if part.splitlines()[0].strip() == name:
            return part
    raise AssertionError(f"the 1.0.0 section has no `### {name}` subsection")


def _holds(text: str, *phrases: str) -> None:
    flat = _flat(text)
    missing = [p for p in phrases if _flat(p) not in flat]
    assert missing == [], f"missing from the release notes: {missing}"


def _absent(text: str, *phrases: str) -> None:
    flat = _flat(text)
    present = [p for p in phrases if _flat(p) in flat]
    assert present == [], f"stale text in the release notes: {present}"


_CRC_KAT = b"123456789"


def test_r_doc_relnote_1_1_crc_change_stated() -> None:
    _holds(
        _release(),
        "the register starts at `init` exactly as written",
        'Am I affected?',
        '"reverse": true',
        "not bit-symmetric",
        "0x18026B2A",
        "0x0F8B7431",
    )


def test_r_doc_relnote_1_2_stated_value_is_the_engines() -> None:
    from s19_app.tui.operations.crc import crc32_stream

    value = crc32_stream(
        _CRC_KAT, polynomial=0x04C11DB7, init=0x12345678, reverse=True, final_xor=0xFFFFFFFF
    )
    assert value == 0x0F8B7431
    assert value != 0x18026B2A


def test_r_doc_relnote_2_1_remedy_stated() -> None:
    _holds(_release(), "How to keep the earlier value", "0x12345678", "0x1E6A2C48")


def test_r_doc_relnote_2_2_remedy_restores_old_value() -> None:
    from s19_app.tui.operations.crc import crc32_stream

    reversed_init = int(f"{0x12345678:032b}"[::-1], 2)
    assert reversed_init == 0x1E6A2C48
    restored = crc32_stream(
        _CRC_KAT, polynomial=0x04C11DB7, init=reversed_init, reverse=True, final_xor=0xFFFFFFFF
    )
    assert restored == 0x18026B2A


def test_r_doc_relnote_3_1_before_after_report_stated() -> None:
    _holds(_release(), "Before/after report", "a2l=used", "Symbols", "from the loaded A2L and MAC")


def test_r_doc_relnote_4_1_external_copy_stated() -> None:
    _holds(_release(), "this run's copy", " · read <copy file name> in place of <ref>")


def test_r_doc_relnote_5_1_markdown_escaping_stated() -> None:
    release = _release()
    _holds(release, "backslash", "`CAL\\_A`", "paths stay as written", "plain-text search")
    _absent(release, "names and paths carry a backslash")


def test_r_doc_relnote_6_1_whole_hex_windows_stated() -> None:
    release = _release()
    _holds(release, "every hex window whole", "each Markdown window", "512 rows")
    _absent(release, "cut each window at 512 rows")


def test_r_doc_relnote_7_1_deleted_project_folder_stated() -> None:
    from s19_app.tui import app as app_module

    _holds(_subsection(_release(), "Projects"), "no longer re-creates", "Project sync NOT done")
    reason, step = app_module._TYPED_REFUSAL_TOKENS["unreadable"]
    assert (reason, step) == (
        "could not be read",
        "check that the folder can be opened, then load again",
    )


def test_r_doc_relnote_8_1_climbing_path_refusal_stated() -> None:
    _holds(
        _subsection(_release(), "Flows"),
        "climbs above the project folder",
        "external step refused",
        "give an absolute path for a file outside the project",
    )


def test_r_doc_relnote_9_1_relative_output_under_project_stated() -> None:
    _holds(
        _subsection(_release(), "Flows"),
        "relative output path is read under the project folder",
        "against the working directory",
    )


def test_r_doc_relnote_10_1_reports_name_the_copy_stated() -> None:
    _holds(
        _subsection(_release(), "Flows"),
        "flow report and the chain-set report",
        "copy's file name in place of the ref",
    )


def test_r_doc_relnote_11_1_crc_config_reasons_stated() -> None:
    source = (ROOT / "s19_app" / "tui" / "operations" / "crc_config.py").read_text(encoding="utf-8")
    for written in (
        "CRC config is structurally invalid: ",
        "field '{key}' is missing",
        "is not a number: ",
        "a CRC Designer template is not a CRC config - it has no regions or groups",
    ):
        assert written in source, written
    _holds(
        _release(),
        "CRC config is structurally invalid: ",
        "field '<name>' is missing",
        "field '<name>' is not a number: <value>",
        "a CRC Designer template is not a CRC config - it has no regions or groups",
    )


def test_r_doc_relnote_12_1_failed_write_leaves_nothing_stated() -> None:
    _holds(
        _subsection(_release(), "Reports"),
        "no partial report file",
        "no Markdown file without its HTML file",
    )


def test_r_doc_relnote_13_1_visible_replacements_stated() -> None:
    from s19_app.tui.services.diff_report_service import _strip_ctl

    assert _strip_ctl("a\x00b") == "a�b"
    assert _strip_ctl("a‮b") == "a�b"
    assert _strip_ctl("a\tb\r\nc") == "a b  c"
    _holds(_subsection(_release(), "Reports"), "direction-override", "�", "one space")


def test_r_doc_relnote_14_1_part_file_safe_to_delete_stated() -> None:
    reports = _subsection(_release(), "Reports")
    _holds(reports, "<file name>.<hex>.part", "safe to delete")
    assert "random" not in reports.lower()


# --------------------------------------------------------------------------- #
# user guide and findings table
# --------------------------------------------------------------------------- #

_BEFORE = "(capture taken before 1.0.0)"

#: (file, absent phrases, present phrases) per passage, in the order of the cases.
_GUIDE_PASSAGES = (
    ("ch06-memory-map.md",
     ('The "Map keys" line says `j k` select',),
     ("↑↓ move · click / ↵ inspect · double-click open hex", _BEFORE)),
    ("ch16-reports.md",
     ("The in-app help says it pre-fills from the loaded A2L",),
     ("regions saved with the project",)),
    ("ch16-reports.md",
     ("although the window's help says",),
     ("It writes Markdown only",)),
    ("ch17-flow-builder.md",
     ("crc error — CRC config is structurally invalid: 'reverse'",),
     ("a CRC Designer template is not a CRC config - it has no regions or groups", _BEFORE)),
    ("ch17-flow-builder.md",
     ("but the later block still reads the first copy",),
     ("reads this run's copy",)),
    ("ch18-flow-execution.md",
     ("To use a new output, delete or rename the old copy",),
     ("in place of step_patch.changes.json",)),
    ("ch19-help-palettes-settings.md",
     ("Some steps do not match the app yet",),
     (_BEFORE,)),
    ("ch21-html-reports.md",
     ('The page is titled "Diff report" although',),
     ('titled "Before/after report"', _BEFORE)),
    ("ch21-html-reports.md",
     ("column stays `-` in this report",),
     ("a2l=used", "from the loaded A2L and MAC")),
    ("ch21-html-reports.md",
     ("(findings F-41 and F-44)", "Markdown only (finding F-41)"),
     ("(finding F-44)",)),
    ("ch21-html-reports.md",
     ("names and paths carry a backslash",),
     ("`CAL\\_A`", "paths stay as written", "a plain-text search")),
)


@pytest.mark.parametrize(
    "number", range(1, len(_GUIDE_PASSAGES) + 1), ids=lambda n: f"passage-{n}"
)
def test_r_doc_guide_1_passages_describe_1_0_0(number: int) -> None:
    name, absent, present = _GUIDE_PASSAGES[number - 1]
    text = _flat(_doc(f"docs/user-guide/{name}"))
    stale = [p for p in absent if _flat(p) in text]
    missing = [p for p in present if _flat(p) not in text]
    assert stale == [], f"{name}: stale text still present: {stale}"
    assert missing == [], f"{name}: 1.0.0 text missing: {missing}"


_FIXED = ("F-16", "F-28", "F-30", "F-37", "F-38", "F-41", "F-42", "F-49")


def _findings_rows() -> Dict[str, str]:
    text = _doc("docs/user-guide/DOSSIER.md")
    start = text.index("## 5. Findings for the release fix")
    nxt = re.search(r"(?m)^## ", text[start + 5:])
    section = text[start: start + 5 + nxt.start()] if nxt else text[start:]
    rows = {}
    for match in re.finditer(r"(?m)^\| (F-\d+) \| ([^|]*) \|", section):
        rows[match.group(1)] = match.group(2).strip()
    return rows


def test_r_doc_guide_2_1_fixed_rows_marked() -> None:
    rows = _findings_rows()
    assert len(_FIXED) == 8
    unmarked = [f for f in _FIXED if not rows.get(f, "").endswith("fixed in 1.0.0")]
    assert unmarked == [], f"rows without the fixed mark: {unmarked}"


def test_r_doc_guide_2_2_no_other_row_marked() -> None:
    rows = _findings_rows()
    marked = sorted(f for f, kind in rows.items() if "fixed in 1.0.0" in kind)
    assert marked == sorted(_FIXED), f"marked set is not the pinned set: {marked}"
    limits = [f for f, kind in rows.items() if kind.startswith("limitation") and "fixed in 1.0.0" in kind]
    assert limits == []
    assert rows.get("F-43", "").startswith("limitation")
    assert rows.get("F-44", "").startswith("limitation")
