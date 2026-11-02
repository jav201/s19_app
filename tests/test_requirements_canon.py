"""
Requirements-canon guard -- ``REQUIREMENTS.md`` and the files that stand behind it.

``REQUIREMENTS.md`` is one table per section, one row per requirement, one strict
EARS sentence per row (S0.3, CTX-CANON). A canon that is not enforced drifts: a row
gets a second sentence, an id is reused, a module moves, the replaced canon is
edited "just once", a rationale file cites a test that was renamed. This module is
the enforcement -- one test per row ``R-DOC-CANON.1`` ... ``.11``, in that order,
all reading one shared parser (``canon_text`` -> ``parse_canon`` -> ``OPENING``).

Every test names its offenders with their locus (id, line, file) rather than
asserting a bare count, and every test refuses to pass on a parser that sees
nothing: a guard that checks 0 rows is green and worthless, so each per-row test
carries a floor (``MIN_ROWS``; ``.8`` and ``.10`` carry their own).

Plain pytest, standard library only. Paths are relative to the repository root, so
the module runs unchanged in a worktree, a mirror or a CI checkout. No marker: it
reads the canon, the history file, the review files and the test sources (text only,
about 2 s) and runs in the PR lane, because PRs are where requirements change.

``MIN_ROWS`` is the size of the canon when it was built, a floor and not an exact
count: it stops a parser that reads nothing from passing, and a change that retires
rows below it must lower it in the same change. It cannot catch a row dropped while
others are added.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[1]
CANON = ROOT / "REQUIREMENTS.md"
HISTORY = ROOT / "docs" / "requirements" / "history" / "REQUIREMENTS-legacy-e273181.md"
REVIEW_DIR = ROOT / "docs" / "requirements" / "review"
TESTS_DIR = ROOT / "tests"

# sha256 of the blob of REQUIREMENTS.md at e273181 (LF bytes). R-DOC-CANON.7.
HISTORY_SHA256 = "4411f41b9a8d87ca6fb57e3740e6ac32fd6c8bbb320674404d0fd2e2b41b2899"

# Floors that keep a blind parser from passing (see the module docstring).
MIN_ROWS = 2623  # rows of the canon when it was built (2612 product rows + 11 here)
MIN_S0_CITATIONS = 473  # R-DOC-CANON.8: ids checked in the absorbing cells of S0.2
MIN_TEST_NAMES = 1000  # R-DOC-CANON.10: distinct test names cited in the review files (1 109 when built)

MODULES = [f"S{n}" for n in range(18)]
FORMS = ("U", "When", "While", "If", "Where")
CANON_HEADER = "| Id | Form | Requirement |"
SHOWN = 15  # offenders printed per failure; the count is always printed in full

# N3 -- the opening words of each form (CTX-CANON).
OPENING: Dict[str, "re.Pattern[str]"] = {
    "U": re.compile(r"The system shall "),
    "When": re.compile(r"When .+?, the system shall "),
    "While": re.compile(r"While .+?, the system shall "),
    "If": re.compile(r"If .+?, then the system shall "),
    "Where": re.compile(r"Where .+?, the system shall "),
}

ID_RE = re.compile(r"R-[A-Za-z0-9.-]+")
MODULE_HEADING_RE = re.compile(r"^## (S\d+) · ")  # "## S3 · name"
SEPARATOR_RE = re.compile(r"^\|[\s:|-]+$")
UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")
CODE_SPAN_RE = re.compile(r"`[^`]*`")


class Row(NamedTuple):
    id: str
    form: str
    sentence: str
    module: Optional[str]
    line: int
    cells: int


class Canon(NamedTuple):
    rows: Tuple[Row, ...]
    modules: Tuple[Tuple[str, int], ...]  # (module id, line), in file order


# ---------------------------------------------------------------------------
# N1 .. N3 -- the shared parser.
# ---------------------------------------------------------------------------


def _read_utf8(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def canon_text() -> str:
    """N1 -- ``REQUIREMENTS.md`` at the repo root, UTF-8, ``\\r\\n`` read as ``\\n``."""
    if not CANON.is_file():
        pytest.fail(f"{CANON} is missing: the requirements live in one file at the repository root")
    return _read_utf8(CANON)


def _cells(line: str) -> List[str]:
    """Cells of one table line: split on a pipe that is not escaped, edges dropped."""
    parts = UNESCAPED_PIPE_RE.split(line.strip())
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return [p.strip() for p in parts]


def parse_canon(text: str) -> Canon:
    """N2 -- rows of every table headed exactly ``| Id | Form | Requirement |``.

    A table with any other header (for example ``| Id | Where it lives now | Note |``)
    is not a canon table. A module starts at ``^## S<n> · ``; each row carries the
    module it sits under.
    """
    rows: List[Row] = []
    modules: List[Tuple[str, int]] = []
    module: Optional[str] = None
    in_table = False
    for number, line in enumerate(text.split("\n"), start=1):
        heading = MODULE_HEADING_RE.match(line)
        if heading:
            module = heading.group(1)
            modules.append((module, number))
            in_table = False
            continue
        if line.rstrip() == CANON_HEADER:
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        if SEPARATOR_RE.match(line):
            continue
        cells = _cells(line)
        rows.append(
            Row(
                id=cells[0] if len(cells) > 0 else "",
                form=cells[1] if len(cells) > 1 else "",
                sentence=cells[2] if len(cells) > 2 else "",
                module=module,
                line=number,
                cells=len(cells),
            )
        )
    return Canon(rows=tuple(rows), modules=tuple(modules))


@lru_cache(maxsize=None)
def _canon() -> Canon:
    return parse_canon(canon_text())


def _rows() -> Tuple[Row, ...]:
    """Every canon row, refusing a parser that sees fewer than the canon holds."""
    rows = _canon().rows
    if len(rows) < MIN_ROWS:
        pytest.fail(
            f"the parser found {len(rows)} canon rows in {CANON}, below the floor of {MIN_ROWS}: "
            "rows were lost, or the tables no longer carry the header '| Id | Form | Requirement |'"
        )
    return rows


def _report(rule: str, offenders: List[str], checked: int) -> None:
    if not offenders:
        return
    shown = "\n  ".join(offenders[:SHOWN])
    more = f"\n  ... and {len(offenders) - SHOWN} more" if len(offenders) > SHOWN else ""
    pytest.fail(f"{rule}: {len(offenders)} offending ({checked} checked)\n  {shown}{more}")


# ---------------------------------------------------------------------------
# R-DOC-CANON.1 .. .6 -- the shape of the canon.
# ---------------------------------------------------------------------------


def test_canon_is_one_file_with_rows() -> None:
    """R-DOC-CANON.1 -- the requirements live in one file at the root, and it has rows.

    Why: a reader, ``trace_check`` and every later increment look for exactly one
    file; a canon that moved or went empty would leave them tracing against nothing.
    """
    assert CANON.is_file(), f"{CANON} is missing: the requirements live in one file at the repository root"
    rows = _canon().rows
    assert len(rows) >= 1, f"{CANON} holds no canon row (no table headed '{CANON_HEADER}')"


def test_canon_rows_have_id_form_sentence() -> None:
    """R-DOC-CANON.2 -- every row is exactly an id, a form and a sentence.

    Why: a row is the unit a test case and a trace link to. A fourth cell, a form
    outside the five, or an id with a space cannot be keyed, so the registry and the
    case records that come later would have to guess.
    """
    rows = _rows()
    offenders: List[str] = []
    for r in rows:
        problems = []
        if r.cells != 3:
            problems.append(f"{r.cells} cells (want 3)")
        if not ID_RE.fullmatch(r.id):
            problems.append(f"id {r.id!r} does not match ^R-[A-Za-z0-9.-]+$")
        if r.form not in FORMS:
            problems.append(f"form {r.form!r} is not one of {', '.join(FORMS)}")
        if not r.sentence.endswith((".", ".`", ".)")):
            problems.append(f"sentence ends {r.sentence[-12:]!r}, not with '.', '.`' or '.)'")
        if problems:
            offenders.append(f"line {r.line} {r.id or '(no id)'}: " + "; ".join(problems))
    _report("R-DOC-CANON.2 a row lacks a well-formed id, form or sentence", offenders, len(rows))


def test_canon_rows_open_with_their_form() -> None:
    """R-DOC-CANON.3 -- each sentence opens with the words of the form its row names.

    Why: the form is how a reader knows what kind of case the row needs (a state, an
    event, an unwanted condition). A row filed under ``When`` that opens "The system
    shall" claims a trigger it does not have.
    """
    rows = _rows()
    offenders: List[str] = []
    for r in rows:
        opening = OPENING.get(r.form)
        if opening is None:  # an unknown form is test .2's finding, not this one's
            continue
        if not opening.match(r.sentence):
            offenders.append(f"line {r.line} {r.id}: form {r.form} but the sentence opens {r.sentence[:60]!r}")
    _report("R-DOC-CANON.3 a sentence does not open with the words of its form", offenders, len(rows))


def test_canon_rows_hold_the_obligation_word_once() -> None:
    """R-DOC-CANON.4 -- each sentence holds ``shall`` exactly once.

    Why: one ``shall`` is one obligation is one test case. Two make a row that can be
    half met; none makes a statement that obliges nothing.
    """
    rows = _rows()
    offenders: List[str] = []
    for r in rows:
        n = len(re.findall(r"\bshall\b", r.sentence))
        if n != 1:
            offenders.append(f"line {r.line} {r.id}: 'shall' appears {n} times")
    _report("R-DOC-CANON.4 the obligation word is not used exactly once", offenders, len(rows))


def test_canon_row_ids_are_unique() -> None:
    """R-DOC-CANON.5 -- no id is used by two rows.

    Why: an id is the join key to tests and registry records; a reused id makes two
    requirements indistinguishable and silently merges their coverage.
    """
    rows = _rows()
    first: Dict[str, int] = {}
    offenders: List[str] = []
    for r in rows:
        if r.id in first:
            offenders.append(f"{r.id}: lines {first[r.id]} and {r.line}")
        else:
            first[r.id] = r.line
    _report("R-DOC-CANON.5 an id is used by more than one row", offenders, len(rows))


def test_canon_modules_are_s0_to_s17_in_order() -> None:
    """R-DOC-CANON.6 -- the rows sit under the modules S0 ... S17, in that order.

    Why: the module is the delegation boundary (an agent is given one module) and the
    order is how the module table, the review files and the S0 pointers agree. A module
    that is missing, doubled, swapped or empty breaks all three.
    """
    canon = _canon()
    found = [m for m, _ in canon.modules]
    assert found == MODULES, (
        f"the '## S<n> · ' headings of {CANON} read {found}, want {MODULES} "
        f"(lines {[n for _, n in canon.modules]})"
    )
    orphans = [f"{r.id} (line {r.line})" for r in canon.rows if r.module is None]
    assert not orphans, f"rows outside any '## S<n> · ' module: {orphans[:SHOWN]}"
    per_module = Counter(r.module for r in canon.rows)
    empty = [m for m in MODULES if per_module[m] < 1]
    assert not empty, f"modules with no requirement row: {empty}"


# ---------------------------------------------------------------------------
# R-DOC-CANON.7 -- the replaced canon is kept untouched.
# ---------------------------------------------------------------------------


def test_canon_history_is_the_committed_blob() -> None:
    """R-DOC-CANON.7 -- the replaced canon is kept byte for byte as committed at e273181.

    Why: the strict canon states some figures only as behaviour; the earlier text
    that carried them is the record, and code comments still cite its sections. One
    edited byte, or a CRLF checkout, turns the record into a copy nobody can vouch for.
    Raw bytes, no newline normalisation: ``.gitattributes`` marks the folder ``-text``.
    """
    assert HISTORY.is_file(), f"{HISTORY} is missing: the replaced canon is kept in docs/requirements/history/"
    raw = HISTORY.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    hint = ""
    if digest != HISTORY_SHA256 and hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == HISTORY_SHA256:
        hint = " (the bytes are the committed ones with CRLF line endings: check .gitattributes 'docs/requirements/history/** -text')"
    assert digest == HISTORY_SHA256, (
        f"{HISTORY.name} has sha256 {digest}, want {HISTORY_SHA256}, the blob of REQUIREMENTS.md at e273181{hint}"
    )


# ---------------------------------------------------------------------------
# R-DOC-CANON.8 -- S0's pointers resolve.
# ---------------------------------------------------------------------------

_FULL_ID = r"R-[A-Za-z0-9-]+(?:\.[0-9]+[a-z]?)*"
_ABBREVIATION = r"(?:(?<=[,…])|(?<=[,…]\s))\.[0-9]+[a-z]?"
_TOKEN_RE = re.compile(rf"(?P<full>{_FULL_ID})|(?P<abbr>{_ABBREVIATION})")
_DOTTED_TAIL_RE = re.compile(r"^(.+?)(?:\.[0-9]+[a-z]?)$")


def s0_citations(text: str) -> List[Tuple[int, str]]:
    """N11 -- ``(line, id)`` for every id cited in the second cell of an S0.2 ``| HLR-`` line.

    A full id sets the current stem (the id without its last ``.n``); an abbreviation
    ``.n`` right after a comma or ``...`` expands to ``<stem>.n``. Cells do not share a stem.
    """
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if re.match(r"^#+ S0\.2\b", l)), None)
    stop = next((i for i, l in enumerate(lines) if re.match(r"^#+ S0\.3\b", l)), None)
    if start is None or stop is None or stop <= start:
        pytest.fail("S0.2 (the heading '^#+ S0.2') or S0.3 is missing from the canon: the table of retired ids is gone")
    cited: List[Tuple[int, str]] = []
    for i in range(start, stop):
        line = lines[i]
        if not line.startswith("| HLR-"):
            continue
        cells = _cells(line)
        if len(cells) < 2:
            continue
        stem: Optional[str] = None
        for m in _TOKEN_RE.finditer(cells[1]):
            if m.group("full"):
                token = m.group("full")
                tail = _DOTTED_TAIL_RE.match(token)
                stem = tail.group(1) if tail else token
                cited.append((i + 1, token))
            else:
                if stem is None:
                    cited.append((i + 1, f"{m.group('abbr')} (abbreviation with no full id before it)"))
                else:
                    cited.append((i + 1, f"{stem}{m.group('abbr')}"))
    return cited


def test_canon_s0_table_cites_existing_rows() -> None:
    """R-DOC-CANON.8 -- every id cited in an absorbing cell of S0.2 is a row of the canon.

    Why: S0.2 is how a retired batch id (HLR-/LLR-) is traced to the rows that absorbed
    it. A pointer to a row that was renamed or never written sends the trace to nothing,
    and nothing else in the flow would notice. The bound keeps a parser that finds no
    ids from passing for lack of anything to check.
    """
    text = canon_text()
    known: Set[str] = {r.id for r in parse_canon(text).rows}
    cited = s0_citations(text)
    offenders = [f"line {n}: {token}" for n, token in cited if token not in known]
    problems = []
    if offenders:
        problems.append(f"{len(offenders)} of {len(cited)} cited ids are not rows of the canon:\n  " + "\n  ".join(offenders[:SHOWN]))
    if len(cited) < MIN_S0_CITATIONS:
        problems.append(f"only {len(cited)} ids were checked, below the bound of {MIN_S0_CITATIONS}: the S0.2 table is not being read")
    if problems:
        pytest.fail("R-DOC-CANON.8 " + "\n".join(problems))


# ---------------------------------------------------------------------------
# R-DOC-CANON.9, .10 -- the rationale files.
# ---------------------------------------------------------------------------

_REVIEW_LINK_RE = re.compile(r"\]\((docs/requirements/review/[^)\s#]+)\)")
_DECISIONS_HEADING_RE = re.compile(r"^#{1,6} .*\bDecisions\b", re.MULTILINE)


def test_review_files_hold_the_decisions() -> None:
    """R-DOC-CANON.9 -- each module has its review file, with decisions, linked from the canon.

    Why: the strict rows state what the system does and not why; the reason for each
    wording lives in the module's review file. A module without its file, a file
    without a Decisions heading, or a module-table link that points nowhere leaves a
    row whose wording nobody can defend.
    """
    links = set(_REVIEW_LINK_RE.findall(canon_text()))
    offenders: List[str] = []
    for module in MODULES:
        rel = f"docs/requirements/review/{module}-ears-strict.md"
        path = ROOT / rel
        if not path.is_file():
            offenders.append(f"{rel}: the file does not exist")
        elif not _DECISIONS_HEADING_RE.search(_read_utf8(path)):
            offenders.append(f"{rel}: no heading names 'Decisions'")
        if rel not in links:
            offenders.append(f"{module}: the canon holds no link ']({rel})'")
    for link in sorted(links):
        if not (ROOT / link).is_file():
            offenders.append(f"{link}: linked from REQUIREMENTS.md but the file does not exist")
    _report("R-DOC-CANON.9 a module's decisions are not kept where the canon says", offenders, len(MODULES))


_TEST_NAME_SPAN_RE = re.compile(r"`(?:[\w/.-]+\.py::)?(test_\w*[A-Za-z0-9])`")
_DEF_RE = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(test_\w+)", re.MULTILINE)
_CLASS_RE = re.compile(r"^[ \t]*class[ \t]+(Test\w*)", re.MULTILINE)


def _defined_test_names() -> Set[str]:
    names: Set[str] = set()
    for path in TESTS_DIR.rglob("*.py"):
        source = path.read_text(encoding="utf-8", errors="replace")
        names.update(_DEF_RE.findall(source))
        names.update(_CLASS_RE.findall(source))
    return names


def test_review_files_name_only_existing_tests() -> None:
    """R-DOC-CANON.10 -- every test the review files name is defined under ``tests/``.

    Why: a rationale that cites ``test_x`` as the proof of a decision is a promise. A
    renamed or deleted test turns the promise into a phantom that reads as coverage.
    Whole code spans only (``test_y`` or ``tests/x.py::test_y``): a file
    (``test_x.py``) or a prefix (``test_b100_``) names no single test and is skipped.
    """
    files = sorted(REVIEW_DIR.glob("*.md"))
    defined = _defined_test_names()
    cited: Dict[str, str] = {}  # test name -> first place it is cited
    for path in files:
        text = _read_utf8(path)
        for number, line in enumerate(text.split("\n"), start=1):
            for name in _TEST_NAME_SPAN_RE.findall(line):
                cited.setdefault(name, f"{path.name}:{number}")
    checked = len(cited)
    offenders = [f"{where}: `{name}` is not a def test_ or class Test under tests/" for name, where in cited.items() if name not in defined]
    problems = []
    if offenders:
        problems.append(f"{len(offenders)} of {checked} cited test names are not defined:\n  " + "\n  ".join(offenders[:SHOWN]))
    if checked < MIN_TEST_NAMES:
        problems.append(
            f"only {checked} test names were checked in {len(files)} files of {REVIEW_DIR}, below the bound of {MIN_TEST_NAMES}: "
            "the review files are missing or are not being read"
        )
    if problems:
        pytest.fail("R-DOC-CANON.10 " + "\n".join(problems))


# ---------------------------------------------------------------------------
# R-DOC-CANON.11 -- one sentence per row.
# ---------------------------------------------------------------------------


def test_canon_rows_are_one_sentence() -> None:
    """R-DOC-CANON.11 -- a requirement is one sentence.

    Why: a second sentence is where a second obligation, an exception or a hidden
    condition goes in, and it is what a one-line test case cannot carry. The check is
    the break signature (a full stop, a space, a capital letter) outside code spans,
    where file names and messages may legitimately hold one.
    """
    rows = _rows()
    offenders: List[str] = []
    for r in rows:
        plain = CODE_SPAN_RE.sub("", r.sentence)
        m = re.search(r"\. [A-Z]", plain)
        if m:
            offenders.append(f"line {r.line} {r.id}: a second sentence starts after {plain[max(0, m.start() - 20):m.end() + 12]!r}")
    _report("R-DOC-CANON.11 a sentence holds a second sentence", offenders, len(rows))
