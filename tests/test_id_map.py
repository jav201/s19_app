"""Old->new id map and rename tool (increment I0, batch 2026-11-20-cleanup).

Every test imports ``tools.id_map`` / ``tools.id_rename`` inside its own body, so
this module collects on a tree that does not have them yet and each test is RED
there with ImportError. Fixtures use synthetic families only (ZZT, ZZX, ZZP, ZZQ,
ZZY); fixture trees are real git repositories built in ``tmp_path``.
"""

from __future__ import annotations

import builtins
import hashlib
import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REAL_MAP = ROOT / "docs" / "requirements" / "id-map.tsv"
MAP_REL = "docs/requirements/id-map.tsv"
HEADER = "old_id\tnew_id\tchange\torigin"
L_REN = "R-ZZT-011\tR-ZZT.11\trename\tREQUIREMENTS.md:10@ef5ab17c"
L_FOLD = (
    "2026-07-01-batch-22/HLR-9\tR-ZZT.12\tfold\t"
    ".dev-flow/2026-07-01-batch-22/01-requirements.md:5@ef5ab17c"
)
L_RET = "R-ZZT-013\t-\tretire\tN6 = A (P-308)"
L_Q = "R-ZZQ-7\tR-ZZQ.7\trename\tREQUIREMENTS.md:11@ef5ab17c"
M_OK = (L_REN, L_FOLD, L_RET)
M_Q = M_OK + (L_Q,)
HYGIENE_REL = "tests/test_suite_hygiene.py"
HYGIENE = (
    b"import pytest\n"
    b'RULES = {"R-ZZT-011": 1}\n'
    b'@pytest.mark.parametrize("rule_id", ["R-ZZT-011"])\n'
    b"def test_r(rule_id):\n"
    b'    if rule_id == "R-ZZT-011":\n'
    b'        assert RULES[rule_id] == 1  # R-ZZT-011\n'
)
REGISTRY_NAME = "AT" + "-" + "TC" + "-REGISTRY.jsonl"
T1_FILES = {
    "a.md": b"see R-ZZT-011 and R-ZZT-011.1\n",
    "b.txt": b"R-ZZT-011\r\n",
    "c.py": b"x = 1\n",
    "c2.py": b"# R-ZZT-011\n",
    "s.md": b"R-ZZT-011/012 and R-ZZT-011-g/h\n",
    "f.md": b"see HLR-9\n",
    "q.md": b"R-ZZQ-7 and R-ZZQ-70\n",
    "docs/requirements/history/h.md": b"R-ZZT-011\n",
    ".dev-flow/x.md": b"R-ZZT-011\n",
    REGISTRY_NAME: b"R-ZZT-011\n",
    "tools/seed_id_registry.py": b"R-ZZT-011\n",
    HYGIENE_REL: HYGIENE,
}
T1_LIVE = ["a.md", "b.txt", "c.py", "c2.py", "f.md", "q.md", "s.md", HYGIENE_REL]
HYG_OFFENDERS = [f"{HYGIENE_REL}:{n}: `R-ZZT-011`" for n in (2, 3, 5, 6)]


# ---------------------------------------------------------------- helpers
def _load(name):
    return importlib.import_module(name)


def _exc(name):
    for mod in ("tools.id_map", "tools.id_rename"):
        found = getattr(_load(mod), name, None)
        if found is not None:
            return found
    raise AssertionError(f"{name} is defined in neither tools.id_map nor tools.id_rename")


def _mapbytes(*lines):
    return ("\n".join((HEADER,) + tuple(lines)) + "\n").encode("utf-8")


def _entries(*lines):
    entries, errors = _load("tools.id_map").parse_map(_mapbytes(*lines))
    assert errors == [], errors
    return entries


def _git(repo, *args):
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=True, env=env,
    )


def _write_files(repo, files):
    for rel, data in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _make_repo(tmp_path, files, name="repo"):
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    for key, val in (("user.name", "t"), ("user.email", "t@example.invalid"),
                     ("core.autocrlf", "false"), ("commit.gpgsign", "false")):
        _git(repo, "config", key, val)
    _write_files(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture")
    return repo


def _t1(tmp_path, map_lines=M_OK):
    files = dict(T1_FILES)
    files[MAP_REL] = _mapbytes(*map_lines)
    repo = _make_repo(tmp_path, files)
    (repo / "u.md").write_bytes(b"R-ZZT-011\n")  # untracked on purpose
    return repo


def _tree(repo):
    out = {}
    for path in repo.rglob("*"):
        rel = path.relative_to(repo)
        if path.is_file() and ".git" not in rel.parts:
            out[rel.as_posix()] = path.read_bytes()
    return out


def _digest(repo):
    h = hashlib.sha256()
    for rel, data in sorted(_tree(repo).items()):
        h.update(rel.encode("utf-8") + b"\0" + data + b"\0")
    return h.hexdigest()


def _cli(*args):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-m", "tools.id_rename", *[str(a) for a in args]],
        cwd=str(ROOT), stdin=subprocess.DEVNULL, capture_output=True,
        text=True, encoding="utf-8", timeout=60, env=env,
    )


def _skip_has(skips, path, line, cls, ident=None):
    want = f"{path}:{line}\t{cls}\t{ident}" if line is not None else f"{path}\t{cls}"
    for item in skips:
        if isinstance(item, str):
            if item == want:
                return True
            continue
        text = repr(item)
        if cls in text and (ident is None or ident in text):
            if line is None or getattr(item, "line", line) == line:
                return True
    return False


def _canon_doc(rows, pointer=(), module="S0"):
    lines = ["# Requirements", "", f"## {module} \u00b7 Fixture module", "",
             "### Requirements", "", "filler line", "filler line", "",
             "| Id | Form | Requirement |", "|---|---|---|"]
    for row in rows:
        ident, sentence = row if isinstance(row, tuple) else (row, "The system shall act.")
        lines.append(f"| {ident} | U | {sentence} |")
    if pointer:
        lines += ["", "| Id | Where it lives now | Note |", "|---|---|---|"]
        lines += [f"| {ident} | S0.2 | retired |" for ident in pointer]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _rw(path, data, lines):
    entries = _entries(*lines)
    mapping = {e.old_id: e.new_id for e in entries if e.change == "rename"}
    old_ids = {e.old_id for e in entries if e.old_id.startswith("R-")}
    return _load("tools.id_rename").rewrite_file(path, data, mapping, old_ids)


def _fail_reads(monkeypatch, suffix):
    def guard(target):
        if isinstance(target, (str, os.PathLike)) and \
                str(target).replace("\\", "/").endswith(suffix):
            raise PermissionError(13, "synthetic read failure", str(target))

    real_open, real_os_open = builtins.open, os.open
    real_rb, real_po = Path.read_bytes, Path.open

    def f_open(file, *a, **k):
        guard(file)
        return real_open(file, *a, **k)

    def f_os_open(file, *a, **k):
        guard(file)
        return real_os_open(file, *a, **k)

    def f_rb(self):
        guard(self)
        return real_rb(self)

    def f_po(self, *a, **k):
        guard(self)
        return real_po(self, *a, **k)

    monkeypatch.setattr(builtins, "open", f_open)
    monkeypatch.setattr(os, "open", f_os_open)
    monkeypatch.setattr(Path, "read_bytes", f_rb)
    monkeypatch.setattr(Path, "open", f_po)


def _write_exclusion(tmp_path, text):
    path = tmp_path / "ex.txt"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


# ------------------------------------------------------------ parse_map
def test_parse_map_valid_four_entries_no_errors():
    """A valid map must parse whole: readers (law, F2, F4) rely on zero false errors. R-DOC-IDMAP.1/1"""
    id_map = _load("tools.id_map")
    entries, errors = id_map.parse_map(_mapbytes(*M_Q))
    assert (len(entries), errors) == (4, [])


def test_map_entry_carries_line_and_fields():
    """Each entry keeps its 1-based file line so every offender can name its line. R-DOC-IDMAP.1/5"""
    id_map = _load("tools.id_map")
    entry = id_map.parse_map(_mapbytes(*M_OK))[0][0]
    assert (entry.line, entry.old_id, entry.new_id, entry.change) == (
        2, "R-ZZT-011", "R-ZZT.11", "rename")


def test_parse_map_swapped_header_is_one_error():
    """A reader of the wrong column order would swap old and new ids silently. R-DOC-IDMAP.1/2"""
    id_map = _load("tools.id_map")
    data = ("new_id\told_id\tchange\torigin\n" + "\n".join(M_OK) + "\n").encode()
    assert id_map.parse_map(data)[1] == ["line 1: bad header"]


def test_parse_map_five_fields_is_one_error():
    """An extra field means a corrupted or hand-edited line; it must be named, not tolerated. R-DOC-IDMAP.1/4"""
    id_map = _load("tools.id_map")
    data = _mapbytes(L_REN + "\tx")
    assert id_map.parse_map(data)[1] == ["line 2: 5 fields, expected 4"]


def test_parse_map_header_only_has_no_entries():
    """The I0 map is header-only and must read as an empty, valid map. R-DOC-IDMAP.1/3"""
    id_map = _load("tools.id_map")
    assert id_map.parse_map(_mapbytes()) == ([], [])


def test_parse_map_seven_invalid_forms_exact():
    """Each field form is a separate guard: a map accepting any of the seven breaks renames later. R-DOC-IDMAP.2/1"""
    id_map = _load("tools.id_map")
    bad = (
        "R-ZZT-011\tR-ZZT.11\tmerge\tREQUIREMENTS.md:10@ef5ab17c",
        "R-ZZT-012\tR-ZZT.011\trename\tREQUIREMENTS.md:10@ef5ab17c",
        "R-ZZT-013\tR-ZZT.14\tretire\tN6 = A (P-308)",
        "R-ZZT-014\tR-ZZT.15\trename\t",
        "R-ZZT-015\tR-ZZT.16\trename\tREQUIREMENTS.md@ef5ab17c",
        "R-ZZT-016\t-\tretire\tby hand",
        "HLR-9\tR-ZZT.17\tfold\t.dev-flow/2026-07-01-batch-22/01-requirements.md:5@ef5ab17c",
    )
    errors = id_map.parse_map(_mapbytes(*bad))[1]
    assert errors == [
        "line 2: unknown change `merge`",
        "line 3: bad new id `R-ZZT.011`",
        "line 4: retire needs new id `-`",
        "line 5: empty origin",
        "line 6: bad origin `REQUIREMENTS.md@ef5ab17c`",
        "line 7: retire origin names no decision id",
        "line 8: fold needs a qualified old id `HLR-9`",
    ]


def test_parse_map_valid_fold_and_unpadded_rename():
    """The qualified fold and the unpadded rename are valid forms and must not be rejected. R-DOC-IDMAP.2/2"""
    id_map = _load("tools.id_map")
    entries, errors = id_map.parse_map(_mapbytes(L_FOLD, L_Q))
    assert (len(entries), errors) == (2, [])


def test_parse_map_control_character_rejected():
    """A BEL in a field would corrupt terminal output of messages; it must be named. R-DOC-IDMAP.15/5"""
    id_map = _load("tools.id_map")
    errors = id_map.parse_map(_mapbytes(L_REN + "\x07"))[1]
    assert "line 2: control character" in errors


def test_parse_map_oversize_rejected():
    """An oversized map must be refused with line 0 so hostile input is bounded. R-DOC-IDMAP.15/6"""
    id_map = _load("tools.id_map")
    errors = id_map.parse_map(b"x" * 1048577)[1]
    assert "line 0: map larger than 1048576 bytes" in errors


def test_parse_map_size_cap_boundary_accepted():
    """Exactly 1,048,576 bytes is within the cap; an off-by-one refuses a legal map. R-DOC-IDMAP.15/B"""
    id_map = _load("tools.id_map")
    base = len(_mapbytes("R-ZZT-011\tR-ZZT.11\trename\t:1@ef5ab17c"))
    pad = "a" * (1048576 - base)
    data = _mapbytes(f"R-ZZT-011\tR-ZZT.11\trename\t{pad}:1@ef5ab17c")
    assert len(data) == 1048576
    assert id_map.parse_map(data)[1] == []


# --------------------------------------------------------- map_offenders
def test_map_offenders_clean_map_has_none():
    """The clean map is the control: a check that flags it is noise. R-DOC-IDMAP.3/2"""
    id_map = _load("tools.id_map")
    assert id_map.map_offenders(_entries(*M_OK)) == []


def test_map_offenders_duplicate_old_id():
    """Two entries for one old id make resolution ambiguous. R-DOC-IDMAP.3/1"""
    id_map = _load("tools.id_map")
    dup = "R-ZZT-011\tR-ZZT.20\trename\tREQUIREMENTS.md:14@ef5ab17c"
    assert id_map.map_offenders(_entries(*M_OK, dup)) == [
        "line 5: duplicate old id `R-ZZT-011`"]


def test_map_offenders_two_batches_same_batch_id():
    """A batch id is reused across batches; only the qualified id is unique. R-DOC-IDMAP.3/3"""
    id_map = _load("tools.id_map")
    other = ("2026-07-10-batch-35/HLR-9\tR-ZZT.14\tfold\t"
             ".dev-flow/2026-07-10-batch-35/01-requirements.md:7@ef5ab17c")
    assert id_map.map_offenders(_entries(*M_OK, other)) == []


def test_map_offenders_reused_new_id():
    """Two old ids onto one new id would merge requirements silently. R-DOC-IDMAP.4/1"""
    id_map = _load("tools.id_map")
    reuse = "R-ZZT-020\tR-ZZT.11\trename\tREQUIREMENTS.md:12@ef5ab17c"
    assert id_map.map_offenders(_entries(*M_OK, reuse)) == [
        "line 5: new id `R-ZZT.11` reused"]


# -------------------------------------------------------------- read_map
@pytest.mark.parametrize(
    "extra,message",
    [
        pytest.param((L_REN, "R-ZZT-013\t-\tretire"),
                     "id-map: line 3: 3 fields, expected 4", id="15-1"),
        pytest.param((L_REN, L_FOLD, "R-ZZT-011\tR-ZZT.20\trename\tREQUIREMENTS.md:14@ef5ab17c"),
                     "id-map: line 4: duplicate old id `R-ZZT-011`", id="15-2"),
        pytest.param(M_OK + ("R-ZZT-020\tR-ZZT.11\trename\tREQUIREMENTS.md:12@ef5ab17c",),
                     "id-map: line 5: new id `R-ZZT.11` reused", id="15-7"),
        pytest.param(M_OK + ("R-ZZT-021\tR-ZZT-013\trename\tREQUIREMENTS.md:13@ef5ab17c",),
                     "id-map: line 5: bad new id `R-ZZT-013`", id="15-8"),
        pytest.param(M_OK + ("R-ZZT-022\tR-ZZT.21\trename\tREQUIREMENTS.md@ef5ab17c",),
                     "id-map: line 5: bad origin `REQUIREMENTS.md@ef5ab17c`", id="15-9"),
    ],
)
def test_read_map_raises_map_error_with_first_error(tmp_path, extra, message):
    """Every reader stops on the first bad line with the exact message; cases R-DOC-IDMAP.15/1, 15/2, 15/7, 15/8, 15/9."""
    id_map = _load("tools.id_map")
    path = tmp_path / "m.tsv"
    path.write_bytes(_mapbytes(*extra))
    with pytest.raises(_exc("MapError")) as info:
        id_map.read_map(path)
    assert str(info.value) == message


def test_read_map_valid_file_returns_entries(tmp_path):
    """A reader that always raises is useless; the valid map must come back whole. R-DOC-IDMAP.15/V"""
    id_map = _load("tools.id_map")
    path = tmp_path / "m.tsv"
    path.write_bytes(_mapbytes(*M_Q))
    assert [e.old_id for e in id_map.read_map(path)] == [
        "R-ZZT-011", "2026-07-01-batch-22/HLR-9", "R-ZZT-013", "R-ZZQ-7"]


# ------------------------------------------------------------ canon ids
def test_canon_row_ids_ignores_sentence_citations():
    """A new id only cited in a sentence is not a defined row. R-DOC-IDMAP.6/2"""
    id_map = _load("tools.id_map")
    doc = _canon_doc([("R-ZZT.11", "The system shall cite R-ZZT.12.")]).decode()
    assert id_map.canon_row_ids(doc) == ["R-ZZT.11"]


def test_canon_row_ids_ignores_pointer_table():
    """Pointer-table first cells are resolved by S0.2 and are not canon rows. R-DOC-IDMAP.7/2"""
    id_map = _load("tools.id_map")
    doc = ("| Id | Where it lives now | Note |\n|---|---|---|\n"
           "| R-ZZT-013 | S0.2 | retired |\n")
    assert id_map.canon_row_ids(doc) == []


def test_pointer_ids_lists_first_cells():
    """The law needs the S0.2 ids to keep them out of the map. R-DOC-IDMAP.21/1"""
    id_map = _load("tools.id_map")
    doc = _canon_doc(["R-ZZT.1"], pointer=["R-ZZT-011", "R-ZZT-030"]).decode()
    assert id_map.pointer_ids(doc) == ["R-ZZT-011", "R-ZZT-030"]


def test_canon_offenders_missing_new_row():
    """A map entry whose new id has no canon row leaves a dangling id. R-DOC-IDMAP.6/1"""
    id_map = _load("tools.id_map")
    doc = _canon_doc([("R-ZZT.11", "The system shall cite R-ZZT.12.")]).decode()
    out = id_map.canon_offenders(_entries(*M_OK), id_map.canon_row_ids(doc), [])
    assert out == ["missing row `R-ZZT.12` (line 3)"]


def test_canon_offenders_old_row_still_defined():
    """A surviving old row means the rename was not carried through the canon. R-DOC-IDMAP.7/1"""
    id_map = _load("tools.id_map")
    doc = _canon_doc(["R-ZZT.11", "R-ZZT.12", "R-ZZT-013"]).decode()
    out = id_map.canon_offenders(_entries(*M_OK), id_map.canon_row_ids(doc), [])
    assert out == ["old row `R-ZZT-013` still defined (line 4)"]


def test_canon_offenders_pointer_only_old_id_is_not_a_row():
    """An old id only in a pointer table is not a canon row, but it must not be in the map. R-DOC-IDMAP.7/3"""
    id_map = _load("tools.id_map")
    doc = _canon_doc(["R-ZZT.11", "R-ZZT.12"], pointer=["R-ZZT-013"]).decode()
    out = id_map.canon_offenders(
        _entries(*M_OK), id_map.canon_row_ids(doc), id_map.pointer_ids(doc))
    assert out == ["old id `R-ZZT-013` resolved by S0.2 (line 4)"]


def test_canon_offenders_old_id_resolved_by_pointer_table():
    """S0.2 is the resolver of earlier retirements; the map must not shadow it. R-DOC-IDMAP.21/2"""
    id_map = _load("tools.id_map")
    doc = _canon_doc(["R-ZZT.11", "R-ZZT.12"], pointer=["R-ZZT-011"]).decode()
    out = id_map.canon_offenders(
        _entries(*M_OK), id_map.canon_row_ids(doc), id_map.pointer_ids(doc))
    assert out == ["old id `R-ZZT-011` resolved by S0.2 (line 2)"]


# --------------------------------------------------------- plan_new_ids
def test_plan_new_ids_free_number_keeps_value():
    """The old number is kept when free so the new id stays recognisable. R-DOC-IDMAP.9/1"""
    rename = _load("tools.id_rename")
    assert rename.plan_new_ids(["R-ZZT-011"], [], []) == {"R-ZZT-011": "R-ZZT.11"}


def test_plan_new_ids_taken_number_goes_to_highest_plus_one():
    """A taken number must not be reused; the family continues after its highest. R-DOC-IDMAP.9/2"""
    rename = _load("tools.id_rename")
    got = rename.plan_new_ids(["R-ZZX-003"], ["R-ZZX.3", "R-ZZX.7"], [])
    assert got == {"R-ZZX-003": "R-ZZX.8"}


def test_plan_new_ids_same_integer_in_one_run_gets_distinct_numbers():
    """Padded and unpadded forms of one integer must not collide in a run. R-DOC-IDMAP.9/3"""
    rename = _load("tools.id_rename")
    got = rename.plan_new_ids(["R-ZZY-002", "R-ZZY-02"], [], [])
    assert got == {"R-ZZY-002": "R-ZZY.2", "R-ZZY-02": "R-ZZY.3"}


def test_plan_new_ids_unpadded_old_id():
    """Old ids without padding are legal and plan like padded ones. R-DOC-IDMAP.9/5"""
    rename = _load("tools.id_rename")
    assert rename.plan_new_ids(["R-ZZQ-7"], [], []) == {"R-ZZQ-7": "R-ZZQ.7"}


def test_plan_new_ids_respects_map_new_ids():
    """Numbers already given as new ids in the map are not free; highest includes them. R-DOC-IDMAP.9/E1"""
    rename = _load("tools.id_rename")
    entries = _entries(*M_OK)  # new ids R-ZZT.11 and R-ZZT.12
    assert rename.plan_new_ids(["R-ZZT-012"], [], entries) == {"R-ZZT-012": "R-ZZT.13"}
    assert rename.plan_new_ids(["R-ZZT-099"], [], entries) == {"R-ZZT-099": "R-ZZT.99"}


def test_plan_new_ids_letter_suffix_after_plain_ids():
    """Letter-suffixed ids take fresh numbers after the plain ones, in canon order. R-DOC-IDMAP.10/1"""
    rename = _load("tools.id_rename")
    old = ["R-ZZP-001", "R-ZZP-001b", "R-ZZP-002", "R-ZZP-002a"]
    assert rename.plan_new_ids(old, [], []) == {
        "R-ZZP-001": "R-ZZP.1", "R-ZZP-001b": "R-ZZP.3",
        "R-ZZP-002": "R-ZZP.2", "R-ZZP-002a": "R-ZZP.4"}


def test_plan_new_ids_letter_suffix_with_free_number_still_takes_highest_plus_one():
    """A letter suffix never keeps its own number, even when that number is free. R-DOC-IDMAP.10/b"""
    rename = _load("tools.id_rename")
    got = rename.plan_new_ids(["R-ZZP-005a"], ["R-ZZP.2"], [])
    assert got == {"R-ZZP-005a": "R-ZZP.3"}


def test_plan_new_ids_highest_counts_deferred_old_form_rows():
    """A deferred old row still holds its number; reusing it would alias two requirements. R-DOC-IDMAP.10/c"""
    rename = _load("tools.id_rename")
    rows = ["R-ZZT-001", "R-ZZT-103", "R-ZZT-103a", "R-ZZT-103.1"]
    assert rename.plan_new_ids(["R-ZZT-103a"], rows, []) == {"R-ZZT-103a": "R-ZZT.104"}


def test_plan_new_ids_highest_counts_dotted_stems():
    """A dotted old row R-FAM-049.1 holds 49; a letter id must land after it. R-DOC-IDMAP.10/d"""
    rename = _load("tools.id_rename")
    rows = ["R-ZZT-010", "R-ZZT-049.1", "R-ZZT-020a"]
    got = rename.plan_new_ids(["R-ZZT-010", "R-ZZT-020a"], rows, [])
    assert got == {"R-ZZT-010": "R-ZZT.10", "R-ZZT-020a": "R-ZZT.50"}


def test_plan_new_ids_map_numbers_count_and_plain_ids_keep_their_own():
    """Counting old stems must not push plain ids off their own free number (R-DOC-IDMAP.9). R-DOC-IDMAP.10/e"""
    rename = _load("tools.id_rename")
    entries = _entries("R-ZZT-099\tR-ZZT.120\trename\tREQUIREMENTS.md:10@ef5ab17c")
    got = rename.plan_new_ids(
        ["R-ZZT-005", "R-ZZT-006a"], ["R-ZZT-005", "R-ZZT-006a"], entries)
    assert got == {"R-ZZT-005": "R-ZZT.5", "R-ZZT-006a": "R-ZZT.121"}


def test_plan_new_ids_highest_accepts_upper_case_letter_stem():
    """A stem letter in either case is still the same family number; ignoring it reuses numbers. R-DOC-IDMAP.10/f"""
    rename = _load("tools.id_rename")
    rows = ["R-ZZT-103B.4", "R-ZZT-001a"]
    assert rename.plan_new_ids(["R-ZZT-001a"], rows, []) == {"R-ZZT-001a": "R-ZZT.104"}


# -------------------------------------------------------------- scan_ids
def test_scan_ids_boundaries_keep_only_the_true_token():
    """Dotted, prefixed, hyphen-suffixed and longer ids are other ids; only the plain token is a citation. R-DOC-IDMAP.8/2"""
    id_map = _load("tools.id_map")
    text = "see R-ZZT-011 and R-ZZT-011.1, xR-ZZT-011, R-ZZT-011-2, R-ZZT-0111"
    cits = id_map.scan_ids(text, {"R-ZZT-011"})
    assert len(cits) == 1
    assert (cits[0][1], cits[0][3], cits[0][4]) == (4, "R-ZZT-011", "token")


@pytest.mark.parametrize("text", ["(R-ZZT-011).", "`R-ZZT-011`,"])
def test_scan_ids_punctuation_around_token(text):
    """Brackets, backticks and trailing punctuation still delimit a token. R-DOC-IDMAP.8/3"""
    id_map = _load("tools.id_map")
    cits = id_map.scan_ids(text, {"R-ZZT-011"})
    assert [(c[3], c[4]) for c in cits] == [("R-ZZT-011", "token")]


def test_scan_ids_fold_ids_are_never_matched():
    """Batch ids are not R-form old ids; text mentioning them must stay untouched. R-DOC-IDMAP.8/5"""
    id_map = _load("tools.id_map")
    assert id_map.scan_ids("see HLR-9", {"R-ZZT-011", "R-ZZT-013"}) == []


def test_scan_ids_longer_number_is_another_id():
    """R-ZZQ-7 must not match inside R-ZZQ-70. R-DOC-IDMAP.11/4"""
    id_map = _load("tools.id_map")
    cits = id_map.scan_ids("R-ZZQ-7 and R-ZZQ-70", {"R-ZZQ-7"})
    assert len(cits) == 1
    assert (cits[0][1], cits[0][3], cits[0][4]) == (0, "R-ZZQ-7", "token")


def test_scan_ids_seven_shorthand_forms():
    """Ranges and lists cite ids the tool cannot rewrite safely; they must be flagged. R-DOC-IDMAP.18/1"""
    id_map = _load("tools.id_map")
    text = ("R-ZZT-011/012, R-ZZT-011 .. 014, R-ZZT-011, 012, R-ZZT-011\u2013013, "
            "R-ZZT-011 \u2026 011b, R-ZZT-011-g/h, R-ZZT-011*")
    cits = id_map.scan_ids(text, {"R-ZZT-011"})
    assert len(cits) == 7
    assert {c[4] for c in cits} == {"shorthand"}


def test_scan_ids_test_case_suffix_is_a_plain_token():
    """A one-digit suffix names a test case, not a range; the head is a real token. R-DOC-IDMAP.18/2"""
    id_map = _load("tools.id_map")
    cits = id_map.scan_ids("R-ZZT-011/5", {"R-ZZT-011"})
    assert [(c[3], c[4]) for c in cits] == [("R-ZZT-011", "token")]


# -------------------------------------------------------- git_live_files
def test_git_live_files_plain_folder_is_not_a_work_tree(tmp_path):
    """A folder with no repository must stop the tool before any path is read. R-DOC-IDMAP.17/1"""
    id_map = _load("tools.id_map")
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(_exc("RepoError")) as info:
        id_map.git_live_files(plain, plain / "m.tsv")
    assert str(info.value) == f"id-map: not a git work tree: {plain}"


def test_git_live_files_subfolder_is_not_the_top_level(tmp_path):
    """A sub-folder of a work tree would scope the tool silently to part of the repo. R-DOC-IDMAP.17/2"""
    id_map = _load("tools.id_map")
    repo = _t1(tmp_path)
    with pytest.raises(_exc("RepoError")) as info:
        id_map.git_live_files(repo / "tests", repo / MAP_REL)
    assert str(info.value) == f"id-map: not a git work tree: {repo / 'tests'}"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="mixed-case paths name the same folder only on Windows")
def test_git_live_files_top_level_in_other_case_is_accepted(tmp_path):
    """Windows paths are case-insensitive and git prints C:/...; the comparison must normalise. R-DOC-IDMAP.17/4"""
    id_map = _load("tools.id_map")
    repo = _t1(tmp_path)
    shouting = Path(str(repo).upper().replace("\\", "/"))
    paths, _ = id_map.git_live_files(shouting, repo / MAP_REL)
    assert sorted(paths) == T1_LIVE


def test_git_live_files_lists_only_live_tracked_files(tmp_path):
    """Records, registry, seed, the map and untracked files are not live; walking the disk would include them. R-DOC-IDMAP.8/7"""
    id_map = _load("tools.id_map")
    repo = _t1(tmp_path)
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert sorted(paths) == T1_LIVE
    assert skips == []


def test_git_live_files_skips_symlink_and_gitlink_modes(tmp_path):
    """Index modes 120000 and 160000 are not readable files; reading them would follow a link or fail. R-DOC-IDMAP.23/1"""
    id_map = _load("tools.id_map")
    repo = _make_repo(tmp_path, {"a.md": b"x\n", MAP_REL: _mapbytes()})
    blob = tmp_path / "blob.txt"
    blob.write_bytes(b"a.md")
    sha = _git(repo, "hash-object", "-w", "--", str(blob)).stdout.decode().strip()
    head = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{sha},l.md")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},sub")
    (repo / "l.md").write_bytes(b"R-ZZT-011\n")  # a plain file stands in for the link
    (repo / "sub").mkdir()
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert sorted(skips) == ["l.md\tnot-a-file", "sub\tnot-a-file"]
    assert "l.md" not in paths and "sub" not in paths


def test_git_live_files_skips_path_missing_from_work_tree(tmp_path):
    """A committed file deleted on disk must be listed, not crash the run. R-DOC-IDMAP.24/1"""
    id_map = _load("tools.id_map")
    repo = _make_repo(tmp_path, {"a.md": b"x\n", "d.md": b"y\n", MAP_REL: _mapbytes()})
    (repo / "d.md").unlink()
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert skips == ["d.md\tmissing"]
    assert "d.md" not in paths


# ------------------------------------------------------- load_exclusions
def test_load_exclusions_skips_comments_and_blank_lines(tmp_path):
    """Comments and blanks must not become globs that match nothing or everything. R-DOC-IDMAP.14/1"""
    rename = _load("tools.id_rename")
    path = _write_exclusion(
        tmp_path, "# p279\n\ns19_app/a2l_definition.py\ntests/test_alp_*.py\n")
    assert rename.load_exclusions(path) == [
        "s19_app/a2l_definition.py", "tests/test_alp_*.py"]


# ----------------------------------------------------------- rewrite_file
def test_rewrite_file_replaces_token_not_dotted_id():
    """The plain id is renamed, the dotted current-form id is another id. R-DOC-IDMAP.11/1"""
    new, hits, _ = _rw("a.md", T1_FILES["a.md"], M_OK)
    assert new == b"see R-ZZT.11 and R-ZZT-011.1\n"
    assert len(hits) == 1


def test_rewrite_file_keeps_crlf_bytes():
    """CRLF files must keep their line ends: the diff must be the id and nothing else. R-DOC-IDMAP.11/2"""
    new, _, _ = _rw("b.txt", T1_FILES["b.txt"], M_OK)
    assert new == b"R-ZZT.11\r\n"
    assert new.count(b"\r") == 1


def test_rewrite_file_without_hit_is_identical():
    """A file with no old id must come back byte for byte. R-DOC-IDMAP.11/3"""
    new, hits, skips = _rw("c.py", T1_FILES["c.py"], M_OK)
    assert (new, hits) == (T1_FILES["c.py"], [])


def test_rewrite_file_longer_number_is_kept():
    """R-ZZQ-70 is another id; replacing inside it would corrupt it. R-DOC-IDMAP.11/5"""
    new, hits, _ = _rw("q.md", T1_FILES["q.md"], M_Q)
    assert new == b"R-ZZQ.7 and R-ZZQ-70\n"
    assert len(hits) == 1


def test_rewrite_file_fold_ids_are_not_rewritten_in_text():
    """Fold ids resolve through the map only; rewriting HLR text would damage records. R-DOC-IDMAP.11/6"""
    new, hits, _ = _rw("f.md", T1_FILES["f.md"], M_OK)
    assert (new, hits) == (T1_FILES["f.md"], [])


def test_rewrite_file_runtime_read_file_lists_four_skips():
    """Ids a test collector reads as data must not be renamed under it; they are listed. R-DOC-IDMAP.13/1"""
    new, hits, skips = _rw(HYGIENE_REL, HYGIENE, M_OK)
    assert (new, hits, len(skips)) == (HYGIENE, [], 4)
    for line in (2, 3, 5, 6):
        assert _skip_has(skips, HYGIENE_REL, line, "runtime-read", "R-ZZT-011")


def test_rewrite_file_comment_in_unlisted_file_is_replaced():
    """The runtime-read rule is per listed file, not per comment; other files rename. R-DOC-IDMAP.13/2"""
    new, hits, _ = _rw("c2.py", T1_FILES["c2.py"], M_OK)
    assert new == b"# R-ZZT.11\n"
    assert len(hits) == 1


def test_rewrite_file_shorthand_heads_are_skipped_not_replaced():
    """A shorthand head renamed alone would leave a wrong range; it is listed for hand repair. R-DOC-IDMAP.18/3"""
    new, hits, skips = _rw("s.md", T1_FILES["s.md"], M_OK)
    assert (new, hits, len(skips)) == (T1_FILES["s.md"], [], 2)
    assert all(_skip_has([s], "s.md", 1, "shorthand", "R-ZZT-011") for s in skips)


def test_rewrite_file_seven_shorthand_forms_unchanged():
    """All seven shorthand forms are listed and the line stays byte-identical. R-DOC-IDMAP.18/R1"""
    text = ("R-ZZT-011/012, R-ZZT-011 .. 014, R-ZZT-011, 012, R-ZZT-011\u2013013, "
            "R-ZZT-011 \u2026 011b, R-ZZT-011-g/h, R-ZZT-011*\n").encode("utf-8")
    new, hits, skips = _rw("s2.md", text, M_OK)
    assert (new, hits, len(skips)) == (text, [], 7)


def test_rewrite_file_test_case_suffix_head_is_replaced():
    """A one-digit suffix names a test case; its head is a plain token to rename. R-DOC-IDMAP.18/R2"""
    new, hits, skips = _rw("t.md", b"R-ZZT-011/5\n", M_OK)
    assert (new, len(hits), skips) == (b"R-ZZT.11/5\n", 1, [])


_L10 = "R-ZZT-010\tR-ZZT.10\trename\tREQUIREMENTS.md:10@ef5ab17c"
_L31 = "R-ZZT-031\tR-ZZT.31\trename\tREQUIREMENTS.md:11@ef5ab17c"


def test_rewrite_file_dash_tail_lists_are_shorthand_and_unchanged():
    """Renaming only the head of `R-ZZT-010, -011` strands the tail on a dead id. R-DOC-IDMAP.18/4"""
    text = b"R-ZZT-010, -011\nR-ZZT-031 / -034 / -040\n"
    new, hits, skips = _rw("t.md", text, (_L10, _L31))
    assert (new, hits, len(skips)) == (text, [], 2)
    assert _skip_has(skips, "t.md", 1, "shorthand", "R-ZZT-010")
    assert _skip_has(skips, "t.md", 2, "shorthand", "R-ZZT-031")


def test_rewrite_file_dash_tail_needs_a_separator():
    """A bare ` -011` is prose, not a list; over-matching would leave real ids unrenamed. R-DOC-IDMAP.18/5"""
    text = b"R-ZZT-010-g/h\nR-ZZT-010 -011\n"
    new, hits, skips = _rw("t.md", text, (_L10,))
    assert new == b"R-ZZT-010-g/h\nR-ZZT.10 -011\n"
    assert len(hits) == 1
    assert len(skips) == 1 and _skip_has(skips, "t.md", 1, "shorthand", "R-ZZT-010")


_L9 = "R-ZZT-009\tR-ZZT.9\trename\tREQUIREMENTS.md:9@ef5ab17c"


@pytest.mark.parametrize(
    "line",
    [
        "R-ZZT-009 \u2026 -012\n",
        "R-ZZT-009 .. -012\n",
        "R-ZZT-009 \u2013 -012\n",
    ],
    ids=["ellipsis", "two-dots", "en-dash"],
)
def test_rewrite_file_dash_tail_after_any_shorthand_separator(line):
    """Every shorthand separator may carry a dash tail; renaming only the head strands it. R-DOC-IDMAP.18/6"""
    text = line.encode("utf-8")
    new, hits, skips = _rw("t.md", text, (_L9,))
    assert (new, hits) == (text, [])
    assert skips == ["t.md:1\tshorthand\tR-ZZT-009"]


def test_rewrite_file_separator_without_number_keeps_the_token():
    """A separator with no number after it is prose; the head is a plain token to rename. R-DOC-IDMAP.18/7"""
    new, hits, skips = _rw("t.md", b"R-ZZT-009 \xe2\x80\xa6 (see below)\n", (_L9,))
    assert new == "R-ZZT.9 \u2026 (see below)\n".encode("utf-8")
    assert (len(hits), skips) == (1, [])


def test_rewrite_file_non_utf8_is_binary_skip():
    """Decoding with replacement and writing back would corrupt a binary file. R-DOC-IDMAP.16/1"""
    data = b"\xff\xfe R-ZZT-011"
    new, hits, skips = _rw("bin.dat", data, M_OK)
    assert (new, hits, len(skips)) == (data, [], 1)
    assert _skip_has(skips, "bin.dat", None, "binary")


def test_rewrite_file_over_cap_is_too_large_skip():
    """A file over 8,388,608 bytes is data, not text to rewrite; it is listed. R-DOC-IDMAP.16/2"""
    data = b"R-ZZT-011\n" + b"a" * (8388609 - 10)
    new, hits, skips = _rw("big.md", data, M_OK)
    assert (new, hits, len(skips)) == (data, [], 1)
    assert _skip_has(skips, "big.md", None, "too-large")


def test_rewrite_file_exactly_at_cap_is_processed():
    """The cap is 'more than' 8,388,608; an off-by-one would skip a legal file. R-DOC-IDMAP.16/B"""
    data = b"R-ZZT-011\n" + b"a" * (8388608 - 10)
    new, hits, skips = _rw("edge.md", data, M_OK)
    assert len(hits) == 1 and new.startswith(b"R-ZZT.11\n")
    assert not _skip_has(skips, "edge.md", None, "too-large")


# ------------------------------------------------ live_citation_offenders
def test_live_citation_offenders_nine_before_apply_six_after(tmp_path):
    """The law must see every live citation (shorthand and runtime-read included) and shrink only by what apply fixes. R-DOC-IDMAP.8/1"""
    id_map = _load("tools.id_map")
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    entries = id_map.read_map(repo / MAP_REL)
    before = id_map.live_citation_offenders(repo, entries)
    assert sorted(before) == sorted([
        "a.md:1: `R-ZZT-011`", "b.txt:1: `R-ZZT-011`", "c2.py:1: `R-ZZT-011`",
        "s.md:1: `R-ZZT-011`", "s.md:1: `R-ZZT-011`", *HYG_OFFENDERS])
    rename.run(repo, repo / MAP_REL, exclude=None, apply=True)
    after = id_map.live_citation_offenders(repo, entries)
    assert sorted(after) == sorted(["s.md:1: `R-ZZT-011`"] * 2 + HYG_OFFENDERS)


# ------------------------------------------------------------------- run
def test_run_dry_run_reports_three_files_and_writes_nothing(tmp_path):
    """A dry run is a preview: exact report lines and an unchanged tree. R-DOC-IDMAP.12/1"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    before = _digest(repo)
    report, _ = rename.run(repo, repo / MAP_REL, exclude=None, apply=False)
    assert sorted(report) == ["a.md\t1", "b.txt\t1", "c2.py\t1"]
    assert _digest(repo) == before


def test_run_dry_run_lists_runtime_read_and_shorthand_skips(tmp_path):
    """The skip report is how the operator finds what needs a hand fix. R-DOC-IDMAP.13/3"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    _, skips = rename.run(repo, repo / MAP_REL, exclude=None, apply=False)
    assert skips.count("s.md:1\tshorthand\tR-ZZT-011") == 2
    for line in (2, 3, 5, 6):
        assert f"{HYGIENE_REL}:{line}\truntime-read\tR-ZZT-011" in skips


def test_run_apply_rewrites_exactly_the_tokens_in_binary_mode(tmp_path):
    """Apply must change the tokens and not one other byte: LF stays LF, CRLF stays CRLF, map and records untouched. R-DOC-IDMAP.11/7"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path, M_Q)
    before = _tree(repo)
    report, _ = rename.run(repo, repo / MAP_REL, exclude=None, apply=True)
    expect = dict(before)
    expect["a.md"] = b"see R-ZZT.11 and R-ZZT-011.1\n"
    expect["b.txt"] = b"R-ZZT.11\r\n"
    expect["c2.py"] = b"# R-ZZT.11\n"
    expect["q.md"] = b"R-ZZQ.7 and R-ZZQ-70\n"
    assert _tree(repo) == expect
    assert sorted(report) == ["a.md\t1", "b.txt\t1", "c2.py\t1", "q.md\t1"]


@pytest.mark.parametrize("pattern", ["c*.py", "c2.py"], ids=["glob-14-2", "path-14-4"])
def test_run_apply_with_excluded_citation_stops_before_writing(tmp_path, pattern):
    """A cited file on the exclusion list must stop the apply with nothing changed; cases R-DOC-IDMAP.14/2 (glob) and 14/4 (path)."""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    before = _digest(repo)
    ex = _write_exclusion(tmp_path, pattern + "\n")
    with pytest.raises(_exc("ExcludedError")) as info:
        rename.run(repo, repo / MAP_REL, exclude=ex, apply=True)
    assert str(info.value) == "id-map: excluded file c2.py holds R-ZZT-011"
    assert _digest(repo) == before


def test_run_dry_run_lists_excluded_citation_without_reporting_it(tmp_path):
    """A dry run must preview an exclusion, not stop and not count the file. R-DOC-IDMAP.20/1"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    before = _digest(repo)
    ex = _write_exclusion(tmp_path, "c2.py\n")
    report, skips = rename.run(repo, repo / MAP_REL, exclude=ex, apply=False)
    assert "c2.py:1\texcluded\tR-ZZT-011" in skips
    assert sorted(report) == ["a.md\t1", "b.txt\t1"]
    assert _digest(repo) == before


def test_run_apply_writes_nothing_when_a_later_read_fails(tmp_path, monkeypatch):
    """New contents are computed for every file before the first write; one failed read must leave a.md and b.txt intact. R-DOC-IDMAP.25/1"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    before = _digest(repo)
    _fail_reads(monkeypatch, HYGIENE_REL)
    with pytest.raises(OSError):
        rename.run(repo, repo / MAP_REL, exclude=None, apply=True)
    monkeypatch.undo()
    assert _digest(repo) == before


def test_run_with_bad_map_raises_before_any_write(tmp_path):
    """A hostile map must stop the run before a valid line is applied. R-DOC-IDMAP.15/3"""
    rename = _load("tools.id_rename")
    bad = ("R-ZZT-011\tR-ZZT.11\tmerge\tREQUIREMENTS.md:10@ef5ab17c", L_FOLD)
    repo = _t1(tmp_path, bad)
    before = _digest(repo)
    with pytest.raises(_exc("MapError")) as info:
        rename.run(repo, repo / MAP_REL, exclude=None, apply=True)
    assert str(info.value) == "id-map: line 2: unknown change `merge`"
    assert _digest(repo) == before


def test_run_apply_never_reads_or_writes_symlink_mode_paths(tmp_path):
    """A tracked link entry must not be followed or rewritten even if the path holds an old id. R-DOC-IDMAP.23/R"""
    rename = _load("tools.id_rename")
    repo = _make_repo(tmp_path, {"a.md": b"R-ZZT-011\n", MAP_REL: _mapbytes(*M_OK)})
    blob = tmp_path / "blob.txt"
    blob.write_bytes(b"a.md")
    sha = _git(repo, "hash-object", "-w", "--", str(blob)).stdout.decode().strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"120000,{sha},l.md")
    (repo / "l.md").write_bytes(b"R-ZZT-011\n")
    report, skips = rename.run(repo, repo / MAP_REL, exclude=None, apply=True)
    assert (repo / "l.md").read_bytes() == b"R-ZZT-011\n"
    assert report == ["a.md\t1"]
    assert "l.md\tnot-a-file" in skips


# ---------------------------------------------------------- plan_command
def _plan_repo(tmp_path, canon, extra=None):
    files = {"REQUIREMENTS.md": canon, MAP_REL: _mapbytes()}
    files.update(extra or {})
    return _make_repo(tmp_path, files)


def _sha_of(repo):
    full = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    return full


def _check_entry(line, old, new, row, full_sha):
    match = re.fullmatch(rf"{old}\t{new}\trename\tREQUIREMENTS\.md:{row}@([0-9a-f]{{7,40}})", line)
    assert match, line
    assert full_sha.startswith(match.group(1))


def test_plan_command_proposes_rename_with_row_line_and_head(tmp_path):
    """The plan is I1's input: new id, canon line and head sha must be exact. R-DOC-IDMAP.9/4"""
    rename = _load("tools.id_rename")
    repo = _plan_repo(tmp_path, _canon_doc(["R-ZZT-011", "R-ZZT.1"]))
    lines = rename.plan_command(repo, ["S0"], [])
    assert len(lines) == 1
    _check_entry(lines[0], "R-ZZT-011", "R-ZZT.11", 12, _sha_of(repo))


def test_plan_command_defers_ids_cited_in_excluded_files(tmp_path):
    """Ids cited in files that wait for another merge must be deferred, not planned. R-DOC-IDMAP.19/1"""
    rename = _load("tools.id_rename")
    canon = _canon_doc(["R-ZZT-011", "R-ZZT-020"])
    repo = _plan_repo(tmp_path, canon, {"x.py": b"# R-ZZT-020\n"})
    lines = rename.plan_command(repo, ["S0"], ["x.py"])
    assert len(lines) == 2
    _check_entry(lines[0], "R-ZZT-011", "R-ZZT.11", 12, _sha_of(repo))
    assert lines[1] == "# deferred: R-ZZT-020 cited in x.py"


def test_plan_command_never_plans_pointer_table_ids(tmp_path):
    """S0.2 already resolves pointer ids; planning them would re-enter retired ids. R-DOC-IDMAP.21/3"""
    rename = _load("tools.id_rename")
    repo = _plan_repo(tmp_path, _canon_doc(["R-ZZT.1"], pointer=["R-ZZT-030"]))
    assert rename.plan_command(repo, ["S0"], []) == []


# ------------------------------------------------------------------ main
def _lines_before_skipped(stdout):
    lines = stdout.splitlines()
    assert "# skipped" in lines, stdout
    return lines[: lines.index("# skipped")]


def test_cli_hostile_map_exits_2_with_message(tmp_path):
    """The operator sees the first map error on stderr and nothing is changed. R-DOC-IDMAP.15/4"""
    repo = _t1(tmp_path)
    bad = tmp_path / "bad.tsv"
    bad.write_bytes(_mapbytes(L_REN, "R-ZZT-013\t-\tretire"))
    before = _digest(repo)
    proc = _cli("rename", "--repo", repo, "--map", bad)
    assert proc.stderr.strip() == "id-map: line 3: 3 fields, expected 4"
    assert proc.returncode == 2
    assert _digest(repo) == before


def test_cli_plain_folder_exits_2_with_message(tmp_path):
    """A non-repo folder is refused up front with the exact message. R-DOC-IDMAP.17/3"""
    plain = tmp_path / "plain"
    plain.mkdir()
    good = tmp_path / "m.tsv"
    good.write_bytes(_mapbytes(*M_OK))
    proc = _cli("rename", "--repo", plain, "--map", good)
    assert proc.stderr.strip() == f"id-map: not a git work tree: {plain}"
    assert proc.returncode == 2


def test_cli_subfolder_exits_2_with_message(tmp_path):
    """A sub-folder is not the top level and must be refused too. R-DOC-IDMAP.17/R"""
    repo = _t1(tmp_path)
    good = tmp_path / "m.tsv"
    good.write_bytes(_mapbytes(*M_OK))
    sub = repo / "tests"
    proc = _cli("rename", "--repo", sub, "--map", good)
    assert proc.stderr.strip() == f"id-map: not a git work tree: {sub}"
    assert proc.returncode == 2


@pytest.mark.skipif(sys.platform != "win32",
                    reason="mixed-case paths name the same folder only on Windows")
def test_cli_top_level_in_other_case_exits_0(tmp_path):
    """The Windows top level written in other case with slashes must be accepted. R-DOC-IDMAP.17/5"""
    repo = _t1(tmp_path)
    good = tmp_path / "m.tsv"
    good.write_bytes(_mapbytes(*M_OK))
    shouting = str(repo).upper().replace("\\", "/")
    proc = _cli("rename", "--repo", shouting, "--map", good)
    assert proc.returncode == 0, proc.stderr


def test_cli_apply_with_excluded_citation_exits_2_and_writes_nothing(tmp_path):
    """The exclusion list stops --apply with the exact message and an untouched tree. R-DOC-IDMAP.14/3"""
    repo = _t1(tmp_path)
    ex = _write_exclusion(tmp_path, "c2.py\n")
    before = _digest(repo)
    proc = _cli("rename", "--apply", "--exclude", ex, "--repo", repo)
    assert proc.stderr.strip() == "id-map: excluded file c2.py holds R-ZZT-011"
    assert proc.returncode == 2
    assert _digest(repo) == before


def test_cli_apply_with_unrelated_exclusion_exits_0_and_rewrites(tmp_path):
    """An exclusion that matches no citing file must not block the apply. R-DOC-IDMAP.14/5"""
    repo = _t1(tmp_path)
    ex = _write_exclusion(tmp_path, "zz.md\n")
    proc = _cli("rename", "--apply", "--exclude", ex, "--repo", repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / "a.md").read_bytes() == b"see R-ZZT.11 and R-ZZT-011.1\n"


def test_cli_apply_failed_read_exits_2_and_writes_nothing(tmp_path, monkeypatch, capsys):
    """The last file's read failure must stop the apply with the cannot-read message and no write (in-process: a failed read cannot be forced portably in a child). R-DOC-IDMAP.25/2"""
    rename = _load("tools.id_rename")
    repo = _t1(tmp_path)
    before = _digest(repo)
    _fail_reads(monkeypatch, HYGIENE_REL)
    status = rename.main(["rename", "--apply", "--repo", str(repo)])
    monkeypatch.undo()
    err = capsys.readouterr().err
    assert status == 2
    assert err.startswith(f"id-map: cannot read {HYGIENE_REL}")
    assert _digest(repo) == before


def test_cli_dry_run_exits_0_with_three_report_lines(tmp_path):
    """The default command previews: status 0, three report lines before the skip marker. R-DOC-IDMAP.12/2"""
    repo = _t1(tmp_path)
    before = _digest(repo)
    proc = _cli("rename", "--repo", repo)
    assert proc.returncode == 0, proc.stderr
    assert sorted(_lines_before_skipped(proc.stdout)) == ["a.md\t1", "b.txt\t1", "c2.py\t1"]
    assert _digest(repo) == before


def test_cli_missing_file_exits_0_and_other_files_still_rewritten(tmp_path):
    """One deleted tracked file must not stop the run or block the other rewrites. R-DOC-IDMAP.24/R"""
    files = {"a.md": b"R-ZZT-011\n", "d.md": b"y\n", MAP_REL: _mapbytes(*M_OK)}
    repo = _make_repo(tmp_path, files)
    (repo / "d.md").unlink()
    proc = _cli("rename", "--apply", "--repo", repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / "a.md").read_bytes() == b"R-ZZT.11\n"
    assert "d.md\tmissing" in proc.stdout.splitlines()


# ------------------------------------------------------- E5 review arms
def _add_commit(repo, files):
    _write_files(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "more")


def _symlink_or_skip(target, link, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation not permitted here: {exc}")


def test_run_never_rewrites_the_tracked_permanent_map_via_other_map_arg(tmp_path):
    """A draft map given by --map must never rewrite the tracked permanent resolver. R-DOC-IDMAP.8/F2"""
    id_map = _load("tools.id_map")
    repo = _t1(tmp_path)
    other = tmp_path / "other.tsv"
    other.write_bytes(_mapbytes(*M_OK))
    paths, _ = id_map.git_live_files(repo, other)
    assert MAP_REL not in paths
    tracked = (repo / MAP_REL).read_bytes()
    proc = _cli("rename", "--apply", "--repo", repo, "--map", other)
    assert proc.returncode == 0, proc.stderr
    assert (repo / MAP_REL).read_bytes() == tracked
    assert (repo / "a.md").read_bytes() == b"see R-ZZT.11 and R-ZZT-011.1\n"


def test_cli_plan_on_plain_folder_exits_2_with_message(tmp_path):
    """plan must run the same top-level check as rename, not read a non-repo. R-DOC-IDMAP.17/F3"""
    plain = tmp_path / "plain"
    plain.mkdir()
    good = tmp_path / "m.tsv"
    good.write_bytes(_mapbytes(*M_OK))
    proc = _cli("plan", "--module", "S0", "--repo", plain, "--map", good)
    assert proc.stderr.strip() == f"id-map: not a git work tree: {plain}"
    assert proc.returncode == 2


def test_cli_plan_reads_the_map_it_is_given(tmp_path):
    """plan must honour --map: a bad map named there stops it with the map error. R-DOC-IDMAP.17/F3b"""
    repo = _plan_repo(tmp_path, _canon_doc(["R-ZZT-011", "R-ZZT.1"]))
    bad = tmp_path / "bad.tsv"
    bad.write_bytes(_mapbytes(L_REN, "R-ZZT-013\t-\tretire"))
    proc = _cli("plan", "--module", "S0", "--repo", repo, "--map", bad)
    assert proc.stderr.strip() == "id-map: line 3: 3 fields, expected 4"
    assert proc.returncode == 2


@pytest.mark.parametrize(
    "entry,shown",
    [pytest.param("./c2.py", "c2.py", id="dot-slash"),
     pytest.param("sub\\c3.py", "sub/c3.py", id="backslash")],
)
def test_cli_exclusion_path_forms_still_match(tmp_path, entry, shown):
    """A leading ./ or a backslash must not let a P-313 file slip past the exclusion list. R-DOC-IDMAP.14/F5a"""
    repo = _t1(tmp_path)
    _add_commit(repo, {"sub/c3.py": b"# R-ZZT-011\n"})
    ex = _write_exclusion(tmp_path, entry + "\n")
    before = _digest(repo)
    proc = _cli("rename", "--apply", "--exclude", ex, "--repo", repo)
    assert proc.stderr.strip() == f"id-map: excluded file {shown} holds R-ZZT-011"
    assert proc.returncode == 2
    assert _digest(repo) == before


@pytest.mark.parametrize(
    "data",
    [pytest.param(b"c2.py\n\xff\n", id="non-utf8-26-1"),
     pytest.param(b"x" * 1048577, id="oversize-26-2")],
)
def test_cli_bad_exclusion_list_exits_2_and_writes_nothing(tmp_path, data):
    """The exclusion list is the P-313 safety control; a list that cannot be read whole must fail loud. R-DOC-IDMAP.26/1, 26/2"""
    repo = _t1(tmp_path)
    ex = tmp_path / "ex.txt"
    ex.write_bytes(data)
    before = _digest(repo)
    proc = _cli("rename", "--apply", "--exclude", ex, "--repo", repo)
    assert proc.stderr.startswith("id-map: bad exclusion list ")
    assert proc.returncode == 2
    assert _digest(repo) == before


@pytest.mark.skipif(sys.platform == "win32",
                    reason="symlink creation needs privileges on Windows; skipped there")
def test_symlinked_file_is_not_a_file_and_outside_target_untouched(tmp_path):
    """A tracked file turned into a link must never be followed out of the tree. R-DOC-IDMAP.23/F6a"""
    id_map = _load("tools.id_map")
    repo = _make_repo(tmp_path, {"a.md": b"x\n", "b.md": b"R-ZZT-011\n", MAP_REL: _mapbytes(*M_OK)})
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"R-ZZT-011\n")
    (repo / "a.md").unlink()
    _symlink_or_skip(outside, repo / "a.md")
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert "a.md\tnot-a-file" in skips and "a.md" not in paths
    proc = _cli("rename", "--apply", "--repo", repo)
    assert proc.returncode == 0, proc.stderr
    assert outside.read_bytes() == b"R-ZZT-011\n"
    assert (repo / "b.md").read_bytes() == b"R-ZZT.11\n"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="symlink creation needs privileges on Windows; skipped there")
def test_file_under_symlinked_folder_is_not_a_file_and_outside_untouched(tmp_path):
    """A tracked folder turned into a link must not let a write land outside the tree. R-DOC-IDMAP.23/F6b"""
    import shutil
    id_map = _load("tools.id_map")
    repo = _make_repo(tmp_path, {"sub/f.md": b"x\n", "b.md": b"R-ZZT-011\n", MAP_REL: _mapbytes(*M_OK)})
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    (outdir / "f.md").write_bytes(b"R-ZZT-011\n")
    shutil.rmtree(repo / "sub")
    _symlink_or_skip(outdir, repo / "sub", directory=True)
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert "sub/f.md\tnot-a-file" in skips and "sub/f.md" not in paths
    proc = _cli("rename", "--apply", "--repo", repo)
    assert proc.returncode == 0, proc.stderr
    assert (outdir / "f.md").read_bytes() == b"R-ZZT-011\n"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="symlink creation needs privileges on Windows; skipped there")
def test_symlink_to_in_tree_file_is_not_a_file(tmp_path):
    """A link that stays inside the tree is still a link: it must not be read as a second copy of its target. R-DOC-IDMAP.23/F6c"""
    id_map = _load("tools.id_map")
    repo = _make_repo(
        tmp_path, {"a.md": b"R-ZZT-011\n", "l.md": b"x\n", MAP_REL: _mapbytes(*M_OK)})
    (repo / "l.md").unlink()
    _symlink_or_skip(repo / "a.md", repo / "l.md")
    paths, skips = id_map.git_live_files(repo, repo / MAP_REL)
    assert "l.md\tnot-a-file" in skips and "l.md" not in paths


# ------------------------------------------------------------ real tree
def test_real_map_file_bytes_are_well_formed():
    """The shipped map is the resolver for history; its bytes must be UTF-8, LF only, four fields per line. R-DOC-IDMAP.1/R"""
    data = REAL_MAP.read_bytes()
    text = data.decode("utf-8")
    assert b"\r" not in data
    lines = text.split("\n")
    assert lines[0] == HEADER
    assert all(len(line.split("\t")) == 4 for line in lines[1:] if line)


def test_real_map_reads_clean_and_has_no_map_offenders():
    """The shipped map must satisfy the form and cross-entry laws. R-DOC-IDMAP.2/R, 3/R, 4/R"""
    id_map = _load("tools.id_map")
    entries, errors = id_map.parse_map(REAL_MAP.read_bytes())
    assert errors == []
    assert id_map.map_offenders(entries) == []
    assert id_map.read_map(REAL_MAP) == entries


def test_real_map_agrees_with_requirements_canon():
    """Every new id has a canon row, no old row survives, no pointer-table id is in the map. R-DOC-IDMAP.6/R, 7/R, 21/R"""
    id_map = _load("tools.id_map")
    text = (ROOT / "REQUIREMENTS.md").read_text(encoding="utf-8")
    out = id_map.canon_offenders(
        id_map.read_map(REAL_MAP), id_map.canon_row_ids(text), id_map.pointer_ids(text))
    assert out == []


def test_real_tree_cites_no_old_id_of_the_map():
    """Live files must hold no R-form old id once the map names it. R-DOC-IDMAP.8/6"""
    id_map = _load("tools.id_map")
    assert id_map.live_citation_offenders(ROOT, id_map.read_map(REAL_MAP)) == []


def test_real_tree_dry_run_finds_no_replacement_and_no_shorthand():
    """The shorthand forms in the tree were fixed by hand; the tool must find no stranded citation left. R-DOC-IDMAP.18/R3"""
    rename = _load("tools.id_rename")
    report, skips = rename.run(ROOT, REAL_MAP, exclude=None, apply=False)
    assert report == []
    assert [s for s in skips if "\tshorthand\t" in s] == []


def test_real_gitattributes_pins_map_to_lf():
    """CRLF in the map would break every reader on a Windows checkout. R-DOC-IDMAP.22/1"""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--eol", "docs/requirements/id-map.tsv"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=True,
    ).stdout
    assert "attr/text eol=lf" in out
