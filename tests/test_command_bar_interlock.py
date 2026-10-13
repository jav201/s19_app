"""batch-93 increment 003 — the command-bar interlock arm (HLR-133 / LLR-133.1).

The do-not-resurrect law: the Memory Map screen shall neither compose nor
reference ``#command_bar_row`` nor the bar's find/goto inputs (``#find_input``
/ ``#cmdbar_goto_input`` — the pair batch-79 HLR-118 deleted with the row).
Premise P-2 measured the shipped tree: those ids survive ONLY in comments and
docstrings (``command_bar.py:10,130,143``, ``styles.tcss:61,74-76,79``,
``app.py:6274-6276``), so the arm masks exactly those two zones and flags
everything else — a planted live reference in any scanned file reddens it
(the negative control HLR-133 asks for).

The arm has two limbs:

- **the scan** — every ``*.py`` under ``s19_app/tui`` is tokenized; an
  occurrence counts only when it is NOT inside a COMMENT token and NOT inside
  a docstring (an ast-located ``Expr(Constant(str))`` first statement of a
  module/class/function). ``styles.tcss`` is scanned after ``/* */`` comment
  stripping. The bar's ids match as whole id tokens — ``a2l_tag_find_input``
  and the surviving ``#search_input`` / ``#goto_input`` hex controls must NOT
  trip the arm.
- **the DOM** — the live map screen is queryable: zero ``#command_bar_row``
  widgets anywhere in the app DOM, no ``#find_input`` / ``#cmdbar_goto_input``
  widgets, and no ``CommandBar`` widget composed inside ``#screen_map``.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path
from typing import List, Tuple

import s19_app
from s19_app.tui.app import S19TuiApp

#: The interlocked ids (HLR-133 / LLR-133.1) — matched as WHOLE id tokens so
#: the surviving lookalikes (`a2l_tag_find_input`, `mac_goto_input`) never
#: trip the arm. ``command_bar_row`` and ``cmdbar_goto_input`` are unique
#: enough as plain substrings; the lookbehind/lookahead set is applied to all
#: three uniformly.
_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:command_bar_row|cmdbar_goto_input|find_input)"
    r"(?![A-Za-z0-9_-])"
)

#: Files the arm scans: the whole shipped tui package (source) + its
#: stylesheet. Tests are deliberately out of scope — the arm's own plant
#: strings live there.
_TUI_DIR = Path(s19_app.__file__).resolve().parent / "tui"


def _docstring_lines(source: str) -> set:
    """Line numbers occupied by docstrings (module/class/function first
    statements), so a mention inside one is not a live reference."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    lines = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not (isinstance(body, list) and body):
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            end = first.value.end_lineno or first.value.lineno
            lines.update(range(first.value.lineno, end + 1))
    return lines


def _allowed_spans(source: str) -> List[Tuple[int, int]]:
    """Char spans where an id mention is ALLOWED: comment tokens and
    docstring literals (P-2's surviving zones), as (start, end) offsets."""
    line_starts = [0]
    for index, ch in enumerate(source):
        if ch == "\n":
            line_starts.append(index + 1)

    def _offset(row: int, col: int) -> int:
        return line_starts[row - 1] + col

    doc_lines = _docstring_lines(source)
    spans: List[Tuple[int, int]] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            spans.append((_offset(*tok.start), _offset(*tok.end)))
        elif tok.type == tokenize.STRING and tok.start[0] in doc_lines:
            spans.append((_offset(*tok.start), _offset(*tok.end)))
    return spans


def scan_python(source: str, label: str) -> List[Tuple[str, int, str]]:
    """Live (non-comment, non-docstring) interlocked-id hits in one Python
    source. Returns ``(label, line, matched_id)`` per hit."""
    allowed = _allowed_spans(source)
    hits = []
    for match in _ID_RE.finditer(source):
        if any(start <= match.start() and match.end() <= end for start, end in allowed):
            continue
        line = source.count("\n", 0, match.start()) + 1
        hits.append((label, line, match.group(0)))
    return hits


def scan_tcss(source: str, label: str) -> List[Tuple[str, int, str]]:
    """Live interlocked-id hits in a Textual stylesheet (comments stripped —
    P-2's surviving mentions in ``styles.tcss`` are all inside ``/* */``)."""
    cleaned = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    hits = []
    for match in _ID_RE.finditer(cleaned):
        line = cleaned.count("\n", 0, match.start()) + 1
        hits.append((label, line, match.group(0)))
    return hits


def scan_files(paths: List[Path]) -> List[Tuple[str, int, str]]:
    """The arm over a file set: every live hit, in scan order."""
    hits: List[Tuple[str, int, str]] = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        label = str(path)
        if path.suffix == ".tcss":
            hits.extend(scan_tcss(source, label))
        else:
            hits.extend(scan_python(source, label))
    return hits


def _shipped_surface_files() -> List[Path]:
    return sorted(_TUI_DIR.rglob("*.py")) + [_TUI_DIR / "styles.tcss"]


# ---------------------------------------------------------------------------
# TC-678 — the arm over the shipped surface: 0 live references.
# ---------------------------------------------------------------------------
def test_tc678_interlock_arm_shipped_surface_is_clean() -> None:
    """HLR-133 — the shipped tui tree carries NO live ``#command_bar_row`` /
    bar find/goto input reference; the P-2 comment/docstring mentions are the
    only survivors and the arm masks exactly those zones."""
    hits = scan_files(_shipped_surface_files())
    assert hits == [], (
        "the command-bar interlock is breached — a live reference to the "
        f"deleted bar ids appeared: {hits}"
    )


# ---------------------------------------------------------------------------
# TC-679 — the plant: a live reference in a scanned file reddens the arm.
# ---------------------------------------------------------------------------
def test_tc679_interlock_arm_plant_reddens(tmp_path) -> None:
    """The arm must be able to FAIL (C-43): a planted widget id / CSS rule /
    query string in a scanned file is flagged, and the lookalike ids
    (``a2l_tag_find_input``) stay clean."""
    planted_py = tmp_path / "planted_screen.py"
    planted_py.write_text(
        "class PlantedRow:\n"
        "    def compose(self):\n"
        '        yield Static(id="command_bar_row")\n'
        "\n"
        "    def lookup(self, app):\n"
        '        return app.query_one("#cmdbar_goto_input")\n'
        "\n",
        encoding="utf-8",
    )
    planted_tcss = tmp_path / "planted.tcss"
    planted_tcss.write_text(
        "/* a comment mentioning #command_bar_row is allowed */\n"
        "#command_bar_row {\n"
        "    height: 1;\n"
        "}\n",
        encoding="utf-8",
    )
    clean_py = tmp_path / "clean_lookalike.py"
    clean_py.write_text(
        'A2L_FIND = "a2l_tag_find_input"  # a lookalike, never the bar id\n'
        'HEX_GOTO = "goto_input"  # the surviving hex control\n',
        encoding="utf-8",
    )
    hits = scan_files([planted_py, planted_tcss, clean_py])
    flagged = {(Path(label).name, line) for label, line, _match in hits}
    assert ("planted_screen.py", 3) in flagged, f"the planted row id was not flagged: {hits}"
    assert ("planted_screen.py", 6) in flagged, f"the planted query id was not flagged: {hits}"
    assert ("planted.tcss", 2) in flagged, f"the planted CSS rule was not flagged: {hits}"
    assert all("clean_lookalike" not in label for label, _line, _match in hits), (
        f"the arm tripped on the surviving lookalike ids: {hits}"
    )


# ---------------------------------------------------------------------------
# AT-295 — the live map screen composes no command-bar widget.
# ---------------------------------------------------------------------------
def test_at295_map_screen_composes_no_command_bar(tmp_path) -> None:
    """HLR-133 — with the map screen live, the DOM carries zero
    ``#command_bar_row`` widgets, zero bar find/goto inputs, and ``#screen_map``
    composes no ``CommandBar`` (the surviving palette host mounts in the app
    chrome, outside the map screen)."""
    import asyncio

    from s19_app.tui.command_bar import CommandBar

    async def _drive() -> Tuple[int, int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            await pilot.pause()
            map_screen = app.query_one("#screen_map")
            return (
                len(app.query("#command_bar_row")),
                len(app.query("#find_input")),
                len(app.query("#cmdbar_goto_input")),
                len(map_screen.query(CommandBar)),
            )

    n_row, n_find, n_goto, n_bar = asyncio.run(_drive())
    assert n_row == 0, f"#command_bar_row resurrected in the DOM ({n_row})"
    assert n_find == 0, f"the bar's #find_input resurrected in the DOM ({n_find})"
    assert n_goto == 0, f"the bar's #cmdbar_goto_input resurrected ({n_goto})"
    assert n_bar == 0, f"the map screen composes a CommandBar ({n_bar})"
