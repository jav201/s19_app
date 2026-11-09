"""TC-B102-FILE-01..07 — batch-102 Inc 7 — Flow Builder: orígenes y selección
de archivos por bloque (tester E4).

Pins the Inc-7 slice designed in
``.dev-flow/2026-11-03-batch-102/inc-7/{01-requirements.md,02-test-cases.md,codewire-graph.md,prototype.md}``
plus the mandatory Inc-7 addenda of
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc7.md``:

* TC-B102-FILE-01 — every file-bearing block card paints its ref's resolution
  source (R-B102-FILE-001, 5/5 states). Painted-card arms cover
  ``project`` / ``temp`` / ``external`` / ``missing`` through the shipped
  pipeline; the ``loaded`` state plus the precedence
  (``external`` > ``project`` > ``temp`` > ``loaded``) and the textual
  rejection of absolute / drive-relative / ``..`` / NUL refs are pinned on
  the pure classifier ``flow_screens.resolve_flow_ref_source`` (the codewire
  seam — a real app load always copies the image through the workarea temp
  folder, so a loaded image's name also lands in the temp listing and the
  painted ``loaded`` state is not reachable through the shipped loader; the
  chooser arm of TC-02 pins that loaded artifacts are listed and pickable).
  The kind matrix pins ruling 6: SOURCE / PATCH / CHECK / CRC cards and A2B
  FILE bindings carry the annotation; WRITE_OUT, EXT-STEP, REPORT and A2B
  ``#n`` bindings never do (WRITE_OUT is not painted ``missing``).
* TC-B102-FILE-02 — Browse (``#flow_browse`` beside ``#flow_ref``, the
  default SOURCE kind) posts ``FlowBuilderPanel.BrowseRequested`` (E3 ruling
  2: the panel never pushes the modal) and the app tops
  ``FileRefChooserScreen`` listing ``Project`` / ``Temp / workarea`` /
  ``Loaded artifacts`` + the ``#flow_external_path_input`` row with
  Import/Cancel (R-B102-FILE-002, 3/3 sources). A2B fields carry their own
  ``#flow_ref_a_browse`` / ``#flow_ref_b_browse``. Addendum: links (a live
  symlink and a dangling one) planted in the project dir never appear in the
  chooser, while a regular project file does (ruling 4's link-safe listing).
* TC-B102-FILE-03 — picking a candidate dismisses the chooser and writes ONLY
  the host field; no block is added or replaced (R-B102-FILE-003). Addendum
  (ruling 1): a temp candidate that does not resolve inside the project is
  imported through the safe path into ``<project>/external/`` and the field
  gets the executable ``external/<name>``; a loaded artifact already inside
  the project (every shipped load syncs into the project, LLR-163.5) gets its
  relative ref directly. The Edit modal arm pins ruling-2 host routing:
  Browse inside ``FlowBlockEditScreen`` fills ``#flow_edit_ref`` and Save —
  not the pick — applies the change.
* TC-B102-FILE-04 — submitting an external path copies the file into
  ``<project>/external/``, writes ``external/<name>`` into the field, keeps
  the original, reports ``imported as external/<name>`` and never
  overwrites: a same-named file with different content lands on
  ``external/<name>-1`` (R-B102-FILE-004 + rulings 1/4). Service layer:
  ``workspace.import_external_ref`` returns ``(dest, ref)``; a repeated
  import of IDENTICAL bytes still suffixes (content reuse is disabled for
  this flow); refusals raise ``ValueError`` carrying the exact pinned
  messages; link/dangling sources are refused without copying.
* TC-B102-FILE-05 — with no active project the import refusal paints the
  exact ``Load or create a project before importing an external file.`` for
  both an external path and a temp-candidate pick; nothing is copied and the
  field stays unchanged (R-B102-FILE-005 + ruling 1).
* TC-B102-FILE-06 — an unreadable external path paints the exact
  ``External file not readable: <name>`` (the name, never the full path),
  copies nothing and leaves the field unchanged (R-B102-FILE-006 + ruling 8).
* TC-B102-FILE-07 — hostile candidate names render as literal text in the
  chooser and the card annotations: the safe_text payload paints, zero
  markup spans, zero control bytes (R-B102-FILE-007). Addendum (ruling 8
  logs arm): across the root logger and the app logger during
  Browse/annotate/import, no record carries the full external path or the
  file name.

RED-phase discipline: every new symbol (``#flow_browse`` /
``#flow_ref_a_browse`` / ``#flow_ref_b_browse`` / ``#flow_edit_browse``,
``FileRefChooserScreen``, ``resolve_flow_ref_source``,
``import_external_ref``) is reached lazily — a ``need()`` assertion, a
bounded screen poll or ``getattr`` — so this module still COLLECTS on the
pre-increment tree and each test fails on its own behavioural reason.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path

import pytest
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
)

from s19_app.tui import flow_screens as fs
from s19_app.tui import workspace as ws
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.flow_model import (
    A2B_INPUT_FILE,
    A2B_INPUT_FLOW,
    A2BBlock,
    BLOCK_A2B,
    A2BInputBinding,
    EXTERNAL_MODE_TERMINAL,
    CheckBlock,
    CrcBlock,
    ExternalStepBlock,
    Flow,
    PatchBlock,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.utils import safe_text
from tests.b97_fixtures import (
    EXAMPLES_DIR,
    HOSTILE_C1,
    HOSTILE_NAME,
    flow_project,
    open_flow_builder,
)
from tests.b97_probes import painted_rows, painted_style, record_statuses, settle, span_colours

SIZE = (118, 54)

#: The chooser modal of the codewire graph (module ``s19_app/tui/screens.py``)
#: — compared by class-name string so this module collects on the pre-Inc-7
#: tree, where the class does not exist.
CHOOSER = "FileRefChooserScreen"

#: The three chooser section headers (codewire example, TC-B102-FILE-02).
SECTIONS = ("Project", "Temp / workarea", "Loaded artifacts")

#: The chooser's external-path input (codewire example, TC-B102-FILE-02).
EXTERNAL_INPUT = "#flow_external_path_input"

#: The exact no-project refusal of R-B102-FILE-005 / ruling 1.
NO_PROJECT_REFUSAL = "Load or create a project before importing an external file."


def _unreadable(name: str) -> str:
    """The exact unreadable-external refusal of R-B102-FILE-006."""
    return f"External file not readable: {name}"


#: Span-style tokens that prove Rich markup was applied instead of literal
#: text (the batch-102 Inc-4 hostile oracle, reused by Inc 6).
MARKUP_SPAN_RE = re.compile(r"link|click|bold|^red$")

#: C0/C1 control bytes that must never be painted (R-B102-FILE-007).
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------- #
# Drivers and readers (Layer B — the shipped chain under Textual Pilot).
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, body, *, project: bool = True, size=SIZE):
    """Open the Flow Builder at ``size`` (with the flow project loaded through
    the app's own load when ``project``) and return ``await body(...)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = await flow_project(app) if project else None
            panel = await open_flow_builder(app, pilot)
            return await body(app, pilot, panel, project_dir)

    return asyncio.run(_drive())


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure (PC-11)."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), f"{selector}: expected {kind.__name__}, got {type(widget).__name__}"
    return widget


def _plain(widget) -> str:
    """The widget's text as plain str (Button label / Static / Label render)."""
    if isinstance(widget, Button):
        return str(widget.label)
    rendered = widget.render()
    return rendered.plain if hasattr(rendered, "plain") else str(rendered)


def _labeled_button(root, label_prefix: str) -> Button:
    """The one Button whose label starts with ``label_prefix`` (RED-safe)."""
    prefix = label_prefix.lower()
    matches = [
        b for b in root.query(Button)
        if str(b.label).strip().lower().startswith(prefix)
    ]
    assert len(matches) == 1, f"{label_prefix!r}: expected exactly 1 button, found {len(matches)}"
    return matches[0]


def _seed(panel, blocks) -> None:
    """Load ``blocks`` through the panel's public seam."""
    panel.set_blocks(Flow(name="file_case", blocks=list(blocks)))
    return list(blocks)


def _pipeline_plain(panel) -> str:
    """The pipeline Static's full text (cards, borders and annotations)."""
    return need(panel, "#flow_pipeline", Static).render().plain


def _plant_temp(base_dir: Path, name: str, source: Path = None) -> Path:
    """Copy ``source`` (default ``prg.s19``) into the workarea temp folder."""
    temp_dir = base_dir / ws.WORKAREA_DIRNAME / ws.WORKAREA_SUBDIR / ws.WORKAREA_TEMP
    temp_dir.mkdir(parents=True, exist_ok=True)
    dest = temp_dir / name
    shutil.copyfile(source or (EXAMPLES_DIR / "prg.s19"), dest)
    return dest


def _workarea_project(tmp_path: Path) -> Path:
    """A project dir inside the workarea, as the placement guards require."""
    root = tmp_path / ws.WORKAREA_DIRNAME / ws.WORKAREA_SUBDIR / "proj1"
    root.mkdir(parents=True)
    return root


async def _wait_modal(app, pilot, class_name: str, attempts: int = 150):
    """Pump until a screen of ``class_name`` tops (bounded, named on failure)."""
    for _ in range(attempts):
        await pilot.pause()
        if type(app.screen).__name__ == class_name:
            return app.screen
    raise AssertionError(f"{class_name} never topped")


async def _wait_modal_closed(app, pilot, class_name: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        await pilot.pause()
        if type(app.screen).__name__ != class_name:
            return
    raise AssertionError(f"{class_name} never dismissed")


async def _open_chooser(app, pilot, panel):
    """Press the add-form Browse chip and wait for the chooser to top."""
    need(panel, "#flow_browse", Button).press()
    await settle(pilot, 2)
    return await _wait_modal(app, pilot, CHOOSER)


def _header_widgets(modal) -> list:
    """The chooser's section-header widgets (Static/Label matching a section)."""
    headers = [
        w for w in list(modal.query(Static)) + list(modal.query(Label))
        if _plain(w).strip() in SECTIONS
    ]
    return sorted(headers, key=lambda w: (w.region.y, w.region.x))


async def _pick_in_chooser(pilot, modal, section: str, name: str) -> None:
    """Pick the candidate ``name`` inside chooser ``section`` (RED-safe).

    The candidate may compose as a Button, a ListItem or a DataTable row; the
    section band is delimited by the section header widgets' rows.
    """
    headers = _header_widgets(modal)
    tops = [w.region.y for w in headers if _plain(w).strip() == section]
    assert len(tops) == 1, f"{section!r}: expected exactly 1 section header, found {len(tops)}"
    top = tops[0]
    lower = [w.region.y for w in headers if w.region.y > top]
    bottom = min(lower) if lower else top + 10 ** 6

    def in_band(w) -> bool:
        return bool(w.display) and top < w.region.y < bottom and name in _plain(w)

    buttons = [w for w in modal.query(Button) if in_band(w)]
    items = [w for w in modal.query(ListItem) if in_band(w)]
    assert len(buttons) + len(items) == 1, (
        f"{section}/{name!r}: expected exactly 1 candidate, "
        f"found {len(buttons)} button(s) + {len(items)} item(s)"
    )
    if buttons:
        buttons[0].press()
    else:
        view = items[0].parent
        while view is not None and not isinstance(view, ListView):
            view = view.parent
        assert isinstance(view, ListView), f"{name!r}: the candidate is not inside a ListView"
        view.index = list(view.query(ListItem)).index(items[0])
        view.focus()
        await settle(pilot, 2)
        await pilot.press("enter")
    await settle(pilot, 3)


async def _import_via_chooser(pilot, modal, path: Path) -> None:
    """Type an external path into the chooser and press Import."""
    need(modal, EXTERNAL_INPUT, Input).value = str(path)
    _labeled_button(modal, "import").press()
    await settle(pilot, 3)


def _painted_text(app, root) -> str:
    """Everything ``root`` paints right now, one row per line."""
    return "\n".join(painted_rows(app, root))


def _refusal_texts(app, statuses) -> str:
    """The union of every status line and the topped screen's painted rows —
    where an import refusal may lawfully paint."""
    return "\n".join(list(statuses) + painted_rows(app, app.screen))


def _resolve_classifier():
    """The new pure classifier, or a named assertion (collects on base)."""
    resolve = getattr(fs, "resolve_flow_ref_source", None)
    assert resolve is not None, "no flow_screens.resolve_flow_ref_source"
    return resolve


def _import_service():
    """The new external-import helper, or a named assertion (collects on base)."""
    helper = getattr(ws, "import_external_ref", None)
    assert helper is not None, "no workspace.import_external_ref"
    return helper


# --------------------------------------------------------------------------- #
# TC-B102-FILE-01 — card origin annotations (R-B102-FILE-001, 5/5 states)
# --------------------------------------------------------------------------- #

STATE_ARMS = [
    # (arm, ref, planted before seeding, expected annotation line)
    ("project", "prg.s19", None, "↳ project: prg.s19"),
    ("temp", "trial.s19", "temp", "↳ temp: trial.s19"),
    ("external", "external/exp.json", "external", "↳ external: external/exp.json"),
    ("missing", "ghost.json", None, "missing: ghost.json"),
]


@pytest.mark.parametrize("arm,ref,plant,expected", STATE_ARMS, ids=[a[0] for a in STATE_ARMS])
def test_tc_b102_file_01_card_origin_annotation(tmp_path: Path, arm, ref, plant, expected) -> None:
    """TC-B102-FILE-01 (R-B102-FILE-001): a file-bearing card paints the
    prototype's annotation grammar — ``↳ <source>: <ref>`` for a resolved
    source, ``missing: <ref>`` for an unresolved one — with the ref verbatim.

    RED on base: no annotation row exists (the pipeline paints only the raw
    ref). Mutant: the origin omitted, or ``missing`` painted as ``project``.
    """

    async def body(app, pilot, panel, project_dir):
        if plant == "temp":
            _plant_temp(app.base_dir, "trial.s19")
        elif plant == "external":
            ext = project_dir / "external"
            ext.mkdir(parents=True, exist_ok=True)
            (ext / "exp.json").write_text("{}", encoding="utf-8")
        _seed(panel, [SourceBlock(ref)])
        await settle(pilot, 2)
        return _pipeline_plain(panel)

    painted = run(tmp_path, body)
    assert expected in painted, f"{expected!r} not painted:\n{painted}"


def test_tc_b102_file_01_missing_paints_in_the_alert_colour(tmp_path: Path) -> None:
    """TC-B102-FILE-01 (design note): the ``missing`` annotation uses the
    reserved alert colour — the painted style of the ``missing:`` token
    differs from the dim ``↳ project`` token on the same chain.

    Mutant: ``missing`` painted exactly like the other origins (design:
    "los demás origen permanecen en dim"; missing uses the alert colour).
    """

    def _style_tuple(style):
        if style is None:
            return None
        return (
            str(style.color.triplet) if style.color and style.color.triplet else str(style.color),
            str(style.bgcolor.triplet) if style.bgcolor and style.bgcolor.triplet else str(style.bgcolor),
            bool(style.bold),
        )

    async def body(app, pilot, panel, project_dir):
        _seed(panel, [SourceBlock("prg.s19"), SourceBlock("ghost.json")])
        await settle(pilot, 2)
        pipeline = need(panel, "#flow_pipeline", Static)
        styles = {}
        for y, row in enumerate(painted_rows(app, pipeline)):
            for token in ("↳ project", "missing:"):
                if token in row and token not in styles:
                    x = pipeline.region.x + row.index(token)
                    styles[token] = _style_tuple(painted_style(app, x, pipeline.region.y + y))
        return styles

    styles = run(tmp_path, body)
    assert styles.get("↳ project"), f"no ↳ project token painted: {styles}"
    assert styles.get("missing:"), f"no missing: token painted: {styles}"
    assert styles["↳ project"] != styles["missing:"], styles


CLASSIFIER_ARMS = [
    # (ref, project files, temp_files, loaded_names, project_root mode, expected)
    ("calib.json", ("calib.json",), (), (), "dir", "project"),
    ("trial.a2l", (), ("trial.a2l",), (), "dir", "temp"),
    ("demo.a2l", (), (), ("demo.a2l",), "dir", "loaded"),
    ("ghost.bin", (), (), (), "dir", "missing"),
    ("external/exp.json", ("external/exp.json",), (), (), "dir", "external"),
    ("both.json", ("both.json",), ("both.json",), (), "dir", "project"),
    ("mix.json", (), ("mix.json",), ("mix.json",), "dir", "temp"),
    ("trial.a2l", (), ("trial.a2l",), (), "none", "temp"),
    ("demo.a2l", (), (), ("demo.a2l",), "none", "loaded"),
    ("ghost.bin", (), (), (), "none", "missing"),
]


@pytest.mark.parametrize(
    "ref,project_files,temp_files,loaded_names,root_mode,expected",
    CLASSIFIER_ARMS,
    ids=[f"{a[4]}-{a[0]}-{a[5]}" for a in CLASSIFIER_ARMS],
)
def test_tc_b102_file_01_classifier_states_and_precedence(
    tmp_path: Path, ref, project_files, temp_files, loaded_names, root_mode, expected
) -> None:
    """TC-B102-FILE-01 (R-B102-FILE-001, full 5/5 + rulings 5/6):
    ``resolve_flow_ref_source`` classifies a ref as ``project`` / ``temp`` /
    ``loaded`` / ``external`` / ``missing`` with precedence
    ``external`` > ``project`` > ``temp`` > ``loaded``; a ``None`` project
    root still classifies against temp/loaded; the project listing is read,
    never mutated.

    RED on base: no classifier. Mutant: precedence flattened, or the
    project listing written, or ``None`` root crashing.
    """
    root = _workarea_project(tmp_path)
    for name in project_files:
        planted = root / name
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text("{}", encoding="utf-8")
    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    resolve = _resolve_classifier()
    project_root = root if root_mode == "dir" else None
    got = resolve(ref, project_root, list(temp_files), list(loaded_names))
    assert got == expected, f"resolve_flow_ref_source({ref!r}) = {got!r}, expected {expected!r}"
    after = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    assert after == before, "the classifier mutated the project listing"


def test_tc_b102_file_01_classifier_textual_absolute_dotdot_nul(tmp_path: Path) -> None:
    """TC-B102-FILE-01 addendum (ruling 5): the classifier is textual —
    absolute, drive-relative, ``..``-bearing, NUL-bearing and empty refs are
    ``missing`` even when the very file exists on disk, and no path is ever
    joined (the ``sub/..`` form would escape any textual base).
    """
    root = _workarea_project(tmp_path)
    (root / "calib.json").write_text("{}", encoding="utf-8")
    resolve = _resolve_classifier()
    cases = [
        (str(root / "calib.json"), "missing"),  # absolute — the file EXISTS
        (str(tmp_path / ".s19tool" / "workarea" / "calib.json"), "missing"),
        (os.path.join(str(tmp_path), "calib.json"), "missing"),
        ("..\\up.json", "missing"),
        ("../up.json", "missing"),
        ("sub\\..\\up.json", "missing"),
        ("C:calib.json", "missing"),  # drive-relative
        ("cal\x00ib.json", "missing"),
        ("", "missing"),
        ("calib.json", "project"),  # control arm: the plain name classifies
    ]
    for ref, expected in cases:
        got = resolve(ref, root, ["trial.a2l"], ["demo.a2l"])
        assert got == expected, f"resolve_flow_ref_source({ref!r}) = {got!r}, expected {expected!r}"


ANNOTATION_MATRIX = [
    # (arm, block factory, annotated?) — every file-ish ref names "ghost.json",
    # absent everywhere, so an annotated card must read "missing: ghost.json".
    ("source", lambda: SourceBlock("ghost.json"), True),
    ("patch", lambda: PatchBlock("ghost.json"), True),
    ("check", lambda: CheckBlock("ghost.json"), True),
    ("crc", lambda: CrcBlock("ghost.json"), True),
    ("write_out", lambda: WriteOutBlock("ghost.json"), False),
    (
        "external_step",
        lambda: ExternalStepBlock(
            mode=EXTERNAL_MODE_TERMINAL, instruction="echo hi",
            log_ref="ghost.json", output_path="ghost.json",
        ),
        False,
    ),
    ("report", lambda: ReportBlock(), False),
    (
        "a2b_flow_bindings",
        lambda: A2BBlock(
            image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
            image_b=A2BInputBinding(A2B_INPUT_FLOW, "0"),
        ),
        False,
    ),
    (
        "a2b_file_binding",
        lambda: A2BBlock(
            image_a=A2BInputBinding(A2B_INPUT_FLOW, "0"),
            image_b=A2BInputBinding(A2B_INPUT_FILE, "ghost.json"),
        ),
        True,
    ),
]


@pytest.mark.parametrize("arm,factory,annotated", ANNOTATION_MATRIX, ids=[a[0] for a in ANNOTATION_MATRIX])
def test_tc_b102_file_01_annotation_matrix_by_kind(tmp_path: Path, arm, factory, annotated) -> None:
    """TC-B102-FILE-01 addendum (ruling 6, read-only annotation matrix): a
    missing file annotates SOURCE / PATCH / CHECK / CRC cards and A2B FILE
    bindings only; WRITE_OUT, EXT-STEP, REPORT and A2B ``#n`` bindings carry
    NO file annotation — WRITE_OUT is never painted ``missing``.

    RED on base: no annotation row at all (the annotated arms fail). Mutant:
    every card annotated (WRITE_OUT painted ``missing``), or file-bearing
    cards skipped.
    """
    block = factory()

    async def body(app, pilot, panel, project_dir):
        _seed(panel, [block])
        await settle(pilot, 2)
        return _pipeline_plain(panel)

    painted = run(tmp_path, body)
    count = painted.count("missing:")
    if annotated:
        assert count == 1, f"{arm}: expected exactly 1 missing annotation, got {count}:\n{painted}"
        assert "ghost.json" in painted, f"{arm}: the card stopped painting its ref:\n{painted}"
    else:
        assert count == 0, f"{arm}: a file annotation must not paint:\n{painted}"
        assert "↳" not in painted, f"{arm}: an origin annotation must not paint:\n{painted}"


# --------------------------------------------------------------------------- #
# TC-B102-FILE-02 — Browse lists all sources (R-B102-FILE-002, 3/3)
# --------------------------------------------------------------------------- #


def test_tc_b102_file_02_browse_posts_request_and_chooser_lists_all_sources(tmp_path: Path) -> None:
    """TC-B102-FILE-02 (R-B102-FILE-002 + ruling 2): pressing ``#flow_browse``
    beside ``#flow_ref`` posts exactly one ``BrowseRequested('#flow_ref')``
    (the panel never pushes the modal itself) and the app tops
    ``FileRefChooserScreen`` painting the ``Project`` / ``Temp / workarea`` /
    ``Loaded artifacts`` headers, the project/temp/loaded candidates and the
    ``#flow_external_path_input`` row with Import + Cancel.

    RED on base: ``#flow_browse`` does not ship (``need()`` finds 0). Mutant:
    the panel pushes its own modal (no ``BrowseRequested``), or a source
    section omitted, or manual-only input.
    """

    async def body(app, pilot, panel, project_dir):
        _plant_temp(app.base_dir, "trial.s19")
        image = app.base_dir / "loaded_img.s19"
        shutil.copyfile(EXAMPLES_DIR / "prg.s19", image)
        app.load_from_path(image)
        for _ in range(150):
            if app.current_file is not None:
                break
            await pilot.pause(0.05)
        assert app.current_file is not None, "the image did not load"
        await settle(pilot, 2)
        browse = need(panel, "#flow_browse", Button)
        assert str(browse.label).strip() == "Browse"
        posted = []
        original = panel.post_message

        def spy(message):
            posted.append(message)
            return original(message)

        panel.post_message = spy
        chooser = await _open_chooser(app, pilot, panel)
        browses = [m for m in posted if type(m).__name__ == "BrowseRequested"]
        assert len(browses) == 1 and getattr(browses[0], "input_id", None) == "#flow_ref", browses
        painted = _painted_text(app, chooser)
        for header in SECTIONS:
            assert header in painted, f"{header!r} header not painted:\n{painted}"
        need(chooser, EXTERNAL_INPUT, Input)
        _labeled_button(chooser, "import")
        _labeled_button(chooser, "cancel")
        for name in ("prg.s19", "trial.s19", "loaded_img.s19"):
            assert any(name in _plain(w) for w in chooser.query("*")), (
                f"{name!r} not listed by the chooser:\n{painted}"
            )
        _labeled_button(chooser, "cancel").press()
        await _wait_modal_closed(app, pilot, CHOOSER)
        return project_dir

    project_dir = run(tmp_path, body)
    assert not list(project_dir.glob("external/*")), "cancel must not import anything"


def test_tc_b102_file_02_browse_beside_every_ref_field(tmp_path: Path) -> None:
    """TC-B102-FILE-02 (R-B102-FILE-002, every ref field): the add form
    carries ``#flow_browse`` beside ``#flow_ref`` for the single-ref kinds
    and ``#flow_ref_a_browse`` / ``#flow_ref_b_browse`` beside the A2B
    bindings; Browse on an A2B binding routes through the same chooser and a
    temp pick imports it (ruling 1).

    RED on base: the buttons do not ship. Mutant: Browse wired to a single
    hard-coded field (the A2B pick writes the wrong host).
    """

    async def body(app, pilot, panel, project_dir):
        _plant_temp(app.base_dir, "trial.s19")
        results = {}
        single = need(panel, "#flow_browse", Button)
        results["single_label"] = str(single.label).strip()
        need(panel, f"#flow_palette_{BLOCK_A2B}", Button).press()
        for _ in range(60):
            await pilot.pause()
            if need(panel, "#flow_ref_a", Input).display:
                break
        assert need(panel, "#flow_ref_a", Input).display, "the A2B form did not open"
        need(panel, "#flow_ref_a_browse", Button)
        need(panel, "#flow_ref_b_browse", Button)
        need(panel, "#flow_ref_a_browse", Button).press()
        await settle(pilot, 2)
        chooser = await _wait_modal(app, pilot, CHOOSER)
        await _pick_in_chooser(pilot, chooser, "Temp / workarea", "trial.s19")
        await _wait_modal_closed(app, pilot, CHOOSER)
        results["ref_a"] = need(panel, "#flow_ref_a", Input).value
        results["blocks"] = len(panel._blocks)
        return results, project_dir

    results, project_dir = run(tmp_path, body)
    assert results["single_label"] == "Browse"
    assert results["ref_a"] == "external/trial.s19", results
    assert results["blocks"] == 0, results
    imported = project_dir / "external" / "trial.s19"
    assert imported.is_file(), "the temp pick was not imported into the project"
    assert imported.read_bytes() == (EXAMPLES_DIR / "prg.s19").read_bytes()


def test_tc_b102_file_02_project_links_omitted_from_chooser(tmp_path: Path) -> None:
    """TC-B102-FILE-02 addendum (ruling 4's link-safe listing): a symlink
    planted in the project dir — live or dangling — never appears among the
    chooser's Project candidates, while a regular project file does.

    RED on base: ``#flow_browse`` does not ship. Mutant: candidates built
    from a bare ``os.listdir`` (the link guard bypassed).
    """
    import sys

    async def body(app, pilot, panel, project_dir):
        target = app.base_dir / "real_target.s19"
        shutil.copyfile(EXAMPLES_DIR / "prg.s19", target)
        shutil.copyfile(EXAMPLES_DIR / "prg.s19", project_dir / "plain.s19")
        try:
            os.symlink(target, project_dir / "linked.s19")
            os.symlink(app.base_dir / "missing_target.s19", project_dir / "dangling.s19")
        except OSError as exc:  # pragma: no cover - symlinks need privileges
            if sys.platform.startswith("win"):
                pytest.skip(f"symlinks unavailable on this Windows host: {exc}")
            raise
        chooser = await _open_chooser(app, pilot, panel)
        painted = _painted_text(app, chooser)
        _labeled_button(chooser, "cancel").press()
        await _wait_modal_closed(app, pilot, CHOOSER)
        return painted

    painted = run(tmp_path, body)
    assert "plain.s19" in painted, f"the regular project file is not listed:\n{painted}"
    assert "linked.s19" not in painted, f"the live symlink leaked into the chooser:\n{painted}"
    assert "dangling.s19" not in painted, f"the dangling symlink leaked into the chooser:\n{painted}"


# --------------------------------------------------------------------------- #
# TC-B102-FILE-03 — picking fills the field only (R-B102-FILE-003)
# --------------------------------------------------------------------------- #


def test_tc_b102_file_03_project_pick_fills_field_only(tmp_path: Path) -> None:
    """TC-B102-FILE-03 (R-B102-FILE-003, project source): picking the project
    candidate ``prg.s19`` dismisses the chooser, writes ``prg.s19`` into
    ``#flow_ref`` and adds/replaces nothing; no import happens for a
    project-resident pick (ruling 1).

    Mutant: the pick adds/replaces the block, or imports a project-resident
    file again.
    """

    async def body(app, pilot, panel, project_dir):
        chooser = await _open_chooser(app, pilot, panel)
        await _pick_in_chooser(pilot, chooser, "Project", "prg.s19")
        await _wait_modal_closed(app, pilot, CHOOSER)
        field = need(panel, "#flow_ref", Input).value
        return field, list(panel._blocks), project_dir

    field, blocks, project_dir = run(tmp_path, body)
    assert field == "prg.s19", field
    assert blocks == [], blocks
    assert not list(project_dir.glob("external/*")), "a project pick must not import"


def test_tc_b102_file_03_temp_pick_imports_executable_ref(tmp_path: Path) -> None:
    """TC-B102-FILE-03 addendum (ruling 1, executability): picking the temp
    candidate ``trial.s19`` — not resolvable inside the project — imports it
    through the safe path into ``<project>/external/`` and the field gets the
    executable ``external/trial.s19``; the chain stays untouched until Add.

    Mutant: the field keeps the temp name (``run_flow`` cannot resolve it),
    or no copy happens.
    """

    async def body(app, pilot, panel, project_dir):
        _plant_temp(app.base_dir, "trial.s19")
        chooser = await _open_chooser(app, pilot, panel)
        await _pick_in_chooser(pilot, chooser, "Temp / workarea", "trial.s19")
        await _wait_modal_closed(app, pilot, CHOOSER)
        return need(panel, "#flow_ref", Input).value, list(panel._blocks)

    field, blocks = run(tmp_path, body)
    assert field == "external/trial.s19", field
    assert blocks == [], blocks


def test_tc_b102_file_03_loaded_pick_inside_project_writes_relative_ref(tmp_path: Path) -> None:
    """TC-B102-FILE-03 addendum (ruling 1, loaded arm): the loaded image is
    synced into the active project by the shipped load (LLR-163.5), so
    picking it from the ``Loaded artifacts`` section writes its relative ref
    directly — no second copy into ``external/``.

    Mutant: the loaded pick re-imports an in-project artifact, or writes a
    display label instead of the wire ref.
    """

    async def body(app, pilot, panel, project_dir):
        image = app.base_dir / "loaded_img.s19"
        shutil.copyfile(EXAMPLES_DIR / "prg.s19", image)
        app.load_from_path(image)
        for _ in range(150):
            if app.current_file is not None:
                break
            await pilot.pause(0.05)
        assert app.current_file is not None, "the image did not load"
        in_project = project_dir / "loaded_img.s19"
        for _ in range(150):
            if in_project.exists():
                break
            await pilot.pause(0.05)
        assert in_project.exists(), "the shipped load did not sync the image into the project"
        chooser = await _open_chooser(app, pilot, panel)
        await _pick_in_chooser(pilot, chooser, "Loaded artifacts", "loaded_img.s19")
        await _wait_modal_closed(app, pilot, CHOOSER)
        return need(panel, "#flow_ref", Input).value, list(panel._blocks), project_dir

    field, blocks, project_dir = run(tmp_path, body)
    assert field == "loaded_img.s19", field
    assert blocks == [], blocks
    assert not list(project_dir.glob("external/*")), "an in-project pick must not import"


def test_tc_b102_file_03_edit_modal_browse_routes_back_to_the_host(tmp_path: Path) -> None:
    """TC-B102-FILE-03 (ruling 2, the Edit-modal host): Browse inside
    ``FlowBlockEditScreen`` tops the same chooser, the pick fills
    ``#flow_edit_ref`` while the modal stays open, and nothing changes until
    Save — Save then applies the browsed ref to exactly the picked block.

    RED on base: ``#flow_edit_browse`` does not ship. Mutant: the pick
    applies immediately (bypassing Save), or writes the panel's add field.
    """

    async def body(app, pilot, panel, project_dir):
        _seed(panel, [SourceBlock("old.s19"), WriteOutBlock("out.s19")])
        await settle(pilot, 2)
        need(panel, "#flow_pick", Input).value = "1"
        need(panel, "#flow_edit", Button).press()
        await settle(pilot, 2)
        modal = await _wait_modal(app, pilot, "FlowBlockEditScreen")
        await settle(pilot, 2)
        need(modal, "#flow_edit_browse", Button).press()
        await settle(pilot, 2)
        chooser = await _wait_modal(app, pilot, CHOOSER)
        await _pick_in_chooser(pilot, chooser, "Project", "prg.s19")
        await _wait_modal_closed(app, pilot, CHOOSER)
        assert type(app.screen).__name__ == "FlowBlockEditScreen", (
            "the pick must return to the edit modal, not apply it"
        )
        field = need(app.screen, "#flow_edit_ref", Input).value
        untouched = [b.image_ref for b in panel._blocks if isinstance(b, SourceBlock)]
        _labeled_button(app.screen, "save").press()
        await _wait_modal_closed(app, pilot, "FlowBlockEditScreen")
        applied = [b.image_ref for b in panel._blocks if isinstance(b, SourceBlock)]
        return field, untouched, applied, len(panel._blocks)

    field, untouched, applied, count = run(tmp_path, body)
    assert field == "prg.s19", field
    assert untouched == ["old.s19"], untouched
    assert applied == ["prg.s19"], applied
    assert count == 2, count


# --------------------------------------------------------------------------- #
# TC-B102-FILE-04 — external import (R-B102-FILE-004 + ruling 4)
# --------------------------------------------------------------------------- #


def test_tc_b102_file_04_external_import_via_chooser(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-FILE-04 (R-B102-FILE-004, 2/2): submitting ``calib.json``
    through the chooser's external row copies it into
    ``<project>/external/``, writes ``external/calib.json`` into ``#flow_ref``,
    keeps the original, reports ``imported as external/calib.json`` and closes
    the chooser; importing a same-named file with DIFFERENT content lands on
    ``external/calib-1.json`` — the first copy is never overwritten (ruling 4).

    RED on base: no Browse/chooser. Mutant: the absolute path stored, or the
    destination overwritten, or the original moved.
    """
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        outside = app.base_dir / "outside"
        outside.mkdir()
        first = outside / "calib.json"
        first.write_bytes(b'{"version": 1}')
        chooser = await _open_chooser(app, pilot, panel)
        await _import_via_chooser(pilot, chooser, first)
        await _wait_modal_closed(app, pilot, CHOOSER)
        field1 = need(panel, "#flow_ref", Input).value
        copied1 = (project_dir / "external" / "calib.json").read_bytes()
        # Collision with different content: suffix, never overwrite.
        second_dir = app.base_dir / "outside2"
        second_dir.mkdir()
        second = second_dir / "calib.json"
        second.write_bytes(b'{"version": 2}')
        chooser = await _open_chooser(app, pilot, panel)
        await _import_via_chooser(pilot, chooser, second)
        await _wait_modal_closed(app, pilot, CHOOSER)
        field2 = need(panel, "#flow_ref", Input).value
        reported = "\n".join(list(statuses) + painted_rows(app, app.screen))
        return field1, copied1, field2, first, second, project_dir, reported

    field1, copied1, field2, first, second, project_dir, reported = run(tmp_path, body)
    assert field1 == "external/calib.json", field1
    assert copied1 == b'{"version": 1}', copied1
    assert field2 == "external/calib-1.json", field2
    assert first.read_bytes() == b'{"version": 1}', "the original was mutated"
    assert second.read_bytes() == b'{"version": 2}', "the original was mutated"
    assert (project_dir / "external" / "calib.json").read_bytes() == b'{"version": 1}'
    assert (project_dir / "external" / "calib-1.json").read_bytes() == b'{"version": 2}'
    assert "imported as external/calib.json" in reported, (
        f"the import report not painted on any surface: {list(statuses)[-6:]!r}"
    )


def test_tc_b102_file_04_import_external_ref_service(tmp_path: Path) -> None:
    """TC-B102-FILE-04 service layer (``workspace.import_external_ref``):
    success returns ``(dest, "external/<name>")`` with the bytes copied and
    the original intact; a repeated import of IDENTICAL bytes still suffixes
    (``calib-1.json`` — content reuse is disabled for this flow, ruling 4);
    every destination stays inside ``<project>/external/``.

    RED on base: no helper. Mutant: byte-identical reuse returning the
    existing name, or a destination outside ``external/``.
    """
    helper = _import_service()
    root = _workarea_project(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    source = outside / "calib.json"
    source.write_bytes(b'{"version": 1}')

    dest, ref = helper(source, root)
    assert ref == "external/calib.json", ref
    assert Path(dest) == root / "external" / "calib.json", dest
    assert Path(dest).read_bytes() == b'{"version": 1}'
    assert source.read_bytes() == b'{"version": 1}', "the original was mutated"

    dest2, ref2 = helper(source, root)  # identical bytes — still a suffix
    assert ref2 == "external/calib-1.json", ref2
    assert Path(dest2) == root / "external" / "calib-1.json", dest2
    assert Path(dest2).read_bytes() == b'{"version": 1}'
    assert Path(dest).read_bytes() == b'{"version": 1}', "the first copy was overwritten"


def test_tc_b102_file_04_import_external_ref_refusals(tmp_path: Path) -> None:
    """TC-B102-FILE-04/05/06 service refusals: no project raises ``ValueError``
    carrying the exact ``Load or create a project before importing an
    external file.`` — checked BEFORE the file's existence, so a missing file
    with no project still names the project refusal; an unreadable file
    raises ``ValueError`` with the exact ``External file not readable:
    <name>`` (the name, never the path). Every refusal copies nothing.
    """
    helper = _import_service()
    root = _workarea_project(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    missing = outside / "dead.json"

    with pytest.raises(ValueError) as no_project:
        helper(missing, None)
    assert str(no_project.value) == NO_PROJECT_REFUSAL, str(no_project.value)

    with pytest.raises(ValueError) as unreadable:
        helper(missing, root)
    assert str(unreadable.value) == _unreadable("dead.json"), str(unreadable.value)
    assert str(missing) not in str(unreadable.value), "the full path leaked into the refusal"

    assert not (root / "external").exists(), "a refusal must not create the destination"


def test_tc_b102_file_04_import_external_ref_link_sources(tmp_path: Path) -> None:
    """TC-B102-FILE-04 addendum (ruling 4, hardened placement): a symlinked
    source — live or dangling — is refused (``ValueError`` family) and
    nothing is copied: the link is never followed into the workarea.
    """
    helper = _import_service()
    root = _workarea_project(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "real.json"
    target.write_bytes(b"{}")
    live = outside / "linked.json"
    dangling = outside / "dangling.json"
    os.symlink(target, live)
    os.symlink(outside / "nowhere.json", dangling)

    for link in (live, dangling):
        with pytest.raises(ValueError):
            helper(link, root)
    assert not (root / "external").exists(), "a link source must not be copied"


# --------------------------------------------------------------------------- #
# TC-B102-FILE-05 — no-project refusal (R-B102-FILE-005)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("attempt", ["external_path", "temp_candidate"])
def test_tc_b102_file_05_no_project_refusal(tmp_path: Path, monkeypatch, attempt: str) -> None:
    """TC-B102-FILE-05 (R-B102-FILE-005 + ruling 1): with no active project,
    both an external-path submit and a temp-candidate pick refuse with the
    exact ``Load or create a project before importing an external file.``,
    copy nothing at all and leave the field unchanged.

    RED on base: ``#flow_browse`` does not ship. Mutant: the copy happens
    outside a workarea, or the refusal text drifts, or the field is cleared.
    """
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        assert project_dir is None
        outside = app.base_dir / "outside"
        outside.mkdir()
        if attempt == "external_path":
            (outside / "calib.json").write_bytes(b"{}")
        _plant_temp(app.base_dir, "trial.s19")
        snapshot = sorted(p.relative_to(app.base_dir).as_posix() for p in app.base_dir.rglob("*"))
        before_field = need(panel, "#flow_ref", Input).value
        chooser = await _open_chooser(app, pilot, panel)
        if attempt == "external_path":
            await _import_via_chooser(pilot, chooser, outside / "calib.json")
        else:
            await _pick_in_chooser(pilot, chooser, "Temp / workarea", "trial.s19")
        await settle(pilot, 3)
        texts = _refusal_texts(app, statuses)
        after = sorted(p.relative_to(app.base_dir).as_posix() for p in app.base_dir.rglob("*"))
        field = need(panel, "#flow_ref", Input).value
        return texts, snapshot, after, before_field, field

    texts, snapshot, after, before_field, field = run(tmp_path, body, project=False)
    assert NO_PROJECT_REFUSAL in texts, f"refusal not painted:\n{texts[-800:]}"
    assert after == snapshot, "the refusal copied something"
    assert field == before_field == "", field


# --------------------------------------------------------------------------- #
# TC-B102-FILE-06 — unreadable external (R-B102-FILE-006)
# --------------------------------------------------------------------------- #


def test_tc_b102_file_06_unreadable_external_refusal(tmp_path: Path, monkeypatch) -> None:
    """TC-B102-FILE-06 (R-B102-FILE-006): an external path pointing at a
    missing file paints the exact ``External file not readable: dead.json``
    — the NAME, never the full path (ruling 8) — copies nothing and leaves
    the field unchanged.

    RED on base: no Browse/chooser. Mutant: the field cleared, the invalid
    path written, or the refusal naming the full path.
    """
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        dead = app.base_dir / "outside" / "dead.json"
        chooser = await _open_chooser(app, pilot, panel)
        await _import_via_chooser(pilot, chooser, dead)
        await settle(pilot, 3)
        texts = _refusal_texts(app, statuses)
        field = need(panel, "#flow_ref", Input).value
        return texts, field, project_dir, dead

    texts, field, project_dir, dead = run(tmp_path, body)
    assert _unreadable("dead.json") in texts, f"refusal not painted:\n{texts[-800:]}"
    assert str(dead) not in texts, "the full path leaked into a painted surface"
    assert field == "", field
    assert not (project_dir / "external").exists(), "the refusal copied something"


# --------------------------------------------------------------------------- #
# TC-B102-FILE-07 — hostile names render literally (R-B102-FILE-007)
# --------------------------------------------------------------------------- #


def test_tc_b102_file_07_hostile_names_render_literally(tmp_path: Path) -> None:
    """TC-B102-FILE-07 (R-B102-FILE-007): a candidate filename carrying every
    markup token family paints as literal text in the chooser and in the
    card annotation — the safe_text payload verbatim, zero markup spans,
    zero control bytes.

    RED on base: no chooser/annotation. Mutant: markup parsed into spans, or
    control bytes painted.
    """

    def _foreign(spans) -> list:
        return [r for r in spans if r.fg is not None and MARKUP_SPAN_RE.search(str(r.fg))]

    hostile = f"{HOSTILE_NAME}.s19"
    scrubbed = safe_text(hostile).plain
    # A middle slice survives a head- or tail-clip of a long candidate label.
    core = hostile[8:26]

    async def body(app, pilot, panel, project_dir):
        _plant_temp(app.base_dir, hostile)
        _seed(panel, [SourceBlock(hostile)])
        await settle(pilot, 2)
        pipeline = need(panel, "#flow_pipeline", Static)
        painted = _pipeline_plain(panel)
        spans = [r for r in span_colours(app, pipeline) if r.source == "span"]
        chooser = await _open_chooser(app, pilot, panel)
        chooser_text = _painted_text(app, chooser)
        chooser_spans = [
            r for w in chooser.query(Static)
            for r in span_colours(app, w) if r.source == "span"
        ]
        _labeled_button(chooser, "cancel").press()
        await _wait_modal_closed(app, pilot, CHOOSER)
        return painted, spans, chooser_text, chooser_spans

    painted, spans, chooser_text, chooser_spans = run(tmp_path, body)
    assert scrubbed in painted, f"the card dropped the hostile name:\n{painted}"
    assert CONTROL_CHARS_RE.search(painted) is None, "control bytes painted on the card"
    assert _foreign(spans) == [], f"markup spans painted on the card: {sorted(set(map(str, spans)))[:6]}"
    assert core in chooser_text, f"the chooser dropped the hostile candidate:\n{chooser_text}"
    assert CONTROL_CHARS_RE.search(chooser_text) is None, "control bytes painted in the chooser"
    assert _foreign(chooser_spans) == [], "markup spans painted in the chooser"


def test_tc_b102_file_07_logs_carry_no_paths(tmp_path: Path) -> None:
    """TC-B102-FILE-07 addendum (ruling 8, logs arm): across the root logger
    and the app logger, opening the chooser, annotating a hostile card and
    importing a hostile-named external file leave no record carrying the
    full external path — and no record carrying the file name at all.

    Mutant: a debug/info line logging the submitted path or the picked name.
    """
    hostile = f"{HOSTILE_NAME}.json"
    log_records: list = []
    root_logger = logging.getLogger()
    handler = logging.Handler(level=logging.DEBUG)
    handler.emit = lambda record: log_records.append(record.getMessage())
    old_level = root_logger.level
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG)
    try:
        app_log, external, project_dir = _run_with_app_log_capture(tmp_path, hostile)
    finally:
        root_logger.removeHandler(handler)
        root_logger.setLevel(old_level)
    log_records.extend(app_log)
    blob = "\n".join(log_records)
    assert str(external) not in blob, "the full external path was logged"
    assert hostile not in blob, "the file name was logged"
    assert (project_dir / "external" / hostile).is_file(), "the import did not land"


def _run_with_app_log_capture(tmp_path: Path, hostile: str):
    """Drive Browse + annotate + a hostile-named external import while
    recording every line the app's own logger writes."""

    async def body(app, pilot, panel, project_dir):
        app_log: list = []
        for meth in ("info", "warning", "error", "debug", "critical", "exception"):
            original = getattr(app.logger, meth, None)
            if original is None:
                continue

            def make(o):
                def wrapped(*args, **kwargs):
                    app_log.append(" ".join(str(a) for a in args))
                    return o(*args, **kwargs)
                return wrapped

            setattr(app.logger, meth, make(original))
        outside = app.base_dir / "outside"
        outside.mkdir()
        external = outside / hostile
        external.write_bytes(b"{}")
        _seed(panel, [SourceBlock(hostile)])
        await settle(pilot, 2)
        chooser = await _open_chooser(app, pilot, panel)
        await _import_via_chooser(pilot, chooser, external)
        await _wait_modal_closed(app, pilot, CHOOSER)
        return app_log, external, project_dir

    return run(tmp_path, body)
