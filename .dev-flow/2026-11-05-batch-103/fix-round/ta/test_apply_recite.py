"""Tests for apply_recite.py (U1-recite), against a synthetic tmp repo.

Each test names the rule it guards and why: a test that cannot go RED when the
rule breaks would be vacuous.  Never imports s19_app; drives the script as a
subprocess so exit codes and "nothing written" are observable.
"""
import subprocess
import sys
from pathlib import Path

import pytest

APPLY = Path(__file__).resolve().parent / "apply_recite.py"
FILE = "tests/test_f.py"
HEADER = "seq\tclass\tfile\ttest\told_id\tnew_ids\taction\told_where\tedit_at\tsource_row\tnote\tline_excerpt"

REQ = """#### S0.1
#### S0.2 · x
| R-OLD-1 | **retired** | x |
#### S1 · x
| R-NEW-1 | U | x |
| R-NEW-2 | U | x |
"""

TEST_F = '''"""Module docstring citing HLR-9 for the file level."""
import os


def test_replace_doc() -> None:
    """Cites LLR-001.2 inside its own docstring."""
    pass


def test_replace_comment() -> None:
    # LLR-001.3 lives in a body comment.
    pass


def test_add_case_a() -> None:
    """Case A docstring with closing quotes on their own line.

    Some body text here.
    """
    pass


def test_add_case_b() -> None:
    """Case B docstring whose closing quotes end the last text line.

    More text."""
    pass


def test_add_case_c() -> None:
    """Case C one-line docstring."""
    pass


def test_add_case_d() -> None:
    pass


def test_string_literal() -> None:
    value = "LLR-009.9 appears in a string literal, not a docstring"
    return value


def test_case_id() -> None:
    """Cites LLR-1.1/1 as a case id."""
    pass
'''


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "tests").mkdir(parents=True)
    (r / "REQUIREMENTS.md").write_text(REQ, encoding="utf-8")
    (r / FILE).write_text(TEST_F, encoding="utf-8")
    return r


def mrow(seq, test, old_id, new_ids, action, old_where, line_no, excerpt=""):
    return "\t".join([
        str(seq), "X", FILE, test, old_id, new_ids, action, old_where,
        f"{FILE}:{line_no}", "src", "", excerpt,
    ])


def line_of(repo, needle):
    for i, l in enumerate((repo / FILE).read_text(encoding="utf-8").splitlines(), 1):
        if needle in l:
            return i
    raise AssertionError(f"needle not found: {needle}")


def run_apply(repo, rows, apply):
    (repo / "map.tsv").write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    cmd = [sys.executable, "-I", "-B", str(APPLY), "--repo", str(repo),
           "--map", str(repo / "map.tsv"), "--result", str(repo / "result.tsv")]
    if apply:
        cmd.append("--apply")
    return subprocess.run(cmd, capture_output=True, text=True)


def test_t1_replace_doc_and_comment(repo):
    """P3 REPLACE: an old id token in the test's own docstring and one in a body
    comment are each swapped for the joined new ids; a broken token/drift check
    would leave the row unapplied, so this fails if either rewrite is skipped."""
    ln_doc = line_of(repo, "Cites LLR-001.2")
    ln_com = line_of(repo, "LLR-001.3 lives")
    rows = [
        mrow(1, "test_replace_doc", "LLR-001.2", "R-NEW-1;R-NEW-2",
             "REPLACE", "doc", ln_doc, '"""Cites LLR-001.2 inside its own docstring."""'),
        mrow(2, "test_replace_comment", "LLR-001.3", "R-NEW-2",
             "REPLACE", "comment", ln_com, "# LLR-001.3 lives in a body comment."),
    ]
    proc = run_apply(repo, rows, apply=True)
    assert proc.returncode == 0, proc.stderr
    text = (repo / FILE).read_text(encoding="utf-8")
    assert "Cites R-NEW-1, R-NEW-2 inside its own docstring" in text
    assert "# R-NEW-2 lives in a body comment." in text
    assert "LLR-001.2" not in text and "LLR-001.3" not in text


def test_t2_add_case_a_closing_quotes_alone(repo):
    """P4 ADD case (a): a blank line then the Traces line are inserted just
    before a closing-quote line that sits alone, and the closing quote stays."""
    ln = line_of(repo, "Case A docstring")
    proc = run_apply(repo, [mrow(1, "test_add_case_a", "LLR-001.4", "R-NEW-1",
                                 "ADD", "doc", ln)], apply=True)
    assert proc.returncode == 0, proc.stderr
    lines = (repo / FILE).read_text(encoding="utf-8").splitlines()
    i = next(j for j, l in enumerate(lines) if l.strip() == "Traces: R-NEW-1.")
    assert lines[i - 1].strip() == ""
    assert lines[i + 1].strip() == '"""'


def test_t3_add_case_b_closing_quotes_on_text(repo):
    """P4 ADD case (b): closing quotes ending a text line move to their own
    line, the text stays, and Traces lands between them."""
    ln = line_of(repo, "Case B docstring")
    proc = run_apply(repo, [mrow(1, "test_add_case_b", "LLR-001.5", "R-NEW-2",
                                 "ADD", "doc", ln)], apply=True)
    assert proc.returncode == 0, proc.stderr
    lines = (repo / FILE).read_text(encoding="utf-8").splitlines()
    i = next(j for j, l in enumerate(lines) if l.strip() == "Traces: R-NEW-2.")
    assert lines[i - 2].strip() == "More text."
    assert lines[i - 1].strip() == ""
    assert lines[i + 1].strip() == '"""'


def test_t4_add_case_c_one_line_docstring(repo):
    """P4 ADD case (c): a one-line docstring keeps opening quotes and text,
    then blank, Traces, and a fresh closing quote."""
    ln = line_of(repo, "Case C one-line")
    proc = run_apply(repo, [mrow(1, "test_add_case_c", "LLR-001.6", "R-NEW-1",
                                 "ADD", "doc", ln)], apply=True)
    assert proc.returncode == 0, proc.stderr
    lines = (repo / FILE).read_text(encoding="utf-8").splitlines()
    i = next(j for j, l in enumerate(lines) if l.strip() == "Traces: R-NEW-1.")
    assert lines[i - 2].strip() == '"""Case C one-line docstring.'
    assert lines[i - 1].strip() == ""
    assert lines[i + 1].strip() == '"""'


def test_t5_add_case_d_no_docstring(repo):
    """P4 ADD case (d): a test with no docstring gains a one-line Traces
    docstring at the first body statement's indentation."""
    ln = line_of(repo, "def test_add_case_d")
    proc = run_apply(repo, [mrow(1, "test_add_case_d", "LLR-001.7", "R-NEW-1",
                                 "ADD", "doc", ln)], apply=True)
    assert proc.returncode == 0, proc.stderr
    text = (repo / FILE).read_text(encoding="utf-8")
    assert '    """Traces: R-NEW-1."""\n    pass' in text


def test_t6_preflight_rejects_non_canon_new_ids(repo):
    """P1 canon preflight: a retired S0.2 pointer and an unknown id both exit 2
    before any byte is written, so a preflight hole would still apply the row."""
    ln = line_of(repo, "Cites LLR-001.2")
    before = (repo / FILE).read_bytes()
    rows = [
        mrow(1, "test_replace_doc", "LLR-001.2", "R-OLD-1", "REPLACE", "doc", ln),
        mrow(2, "test_replace_doc", "LLR-001.2", "R-NOPE-1", "REPLACE", "doc", ln),
    ]
    proc = run_apply(repo, rows, apply=True)
    assert proc.returncode == 2
    assert "R-OLD-1" in proc.stderr and "R-NOPE-1" in proc.stderr
    assert (repo / FILE).read_bytes() == before


def test_t7_excerpt_mismatch_exits(repo):
    """P3 drift check: an edit_at line not starting with the recorded excerpt
    exits 2 rather than rewriting the wrong line."""
    ln = line_of(repo, "Cites LLR-001.2")
    before = (repo / FILE).read_bytes()
    proc = run_apply(repo, [mrow(1, "test_replace_doc", "LLR-001.2", "R-NEW-1",
                                 "REPLACE", "doc", ln, '"""WRONG excerpt"""')], apply=True)
    assert proc.returncode == 2
    assert (repo / FILE).read_bytes() == before


def test_t8_case_id_refused(repo):
    """P3 case-id guard: an id immediately followed by '/' is a case id, never
    a replaceable token, so the row exits 2 and the file is untouched."""
    ln = line_of(repo, "Cites LLR-1.1/1")
    before = (repo / FILE).read_bytes()
    proc = run_apply(repo, [mrow(1, "test_case_id", "LLR-1.1", "R-NEW-1",
                                 "REPLACE", "doc", ln, '"""Cites LLR-1.1/1 as a case id."""')],
                    apply=True)
    assert proc.returncode == 2
    assert (repo / FILE).read_bytes() == before


def test_t9_non_docstring_string_literal_refused(repo):
    """P3 location guard: a row whose line is a plain string literal (not the
    test's docstring) fails non-zero and writes nothing."""
    ln = line_of(repo, "LLR-009.9 appears")
    before = (repo / FILE).read_bytes()
    proc = run_apply(repo, [mrow(1, "test_string_literal", "LLR-009.9", "R-NEW-1",
                                 "REPLACE", "doc", ln,
                                 'value = "LLR-009.9 appears in a string literal, not a docstring"')],
                    apply=True)
    assert proc.returncode != 0
    assert (repo / FILE).read_bytes() == before


def test_t10_second_run_all_already(repo):
    """P8 idempotence: a second --apply over an applied tree reports 'already'
    for every row and keeps the file bytes identical."""
    ln = line_of(repo, "Cites LLR-001.2")
    ln_a = line_of(repo, "Case A docstring")
    rows = [
        mrow(1, "test_replace_doc", "LLR-001.2", "R-NEW-1", "REPLACE", "doc", ln,
             '"""Cites LLR-001.2 inside its own docstring."""'),
        mrow(2, "test_add_case_a", "LLR-001.4", "R-NEW-1", "ADD", "doc", ln_a),
    ]
    first = run_apply(repo, rows, apply=True)
    assert first.returncode == 0, first.stderr
    res = (repo / "result.tsv").read_text(encoding="utf-8").splitlines()
    assert len(res) == 3 and all("\tapplied\t" in l for l in res[1:])
    after_first = (repo / FILE).read_bytes()
    second = run_apply(repo, rows, apply=True)
    assert second.returncode == 0, second.stderr
    res2 = (repo / "result.tsv").read_text(encoding="utf-8").splitlines()
    assert all("\talready\t" in l for l in res2[1:])
    assert (repo / FILE).read_bytes() == after_first


def test_t11_dry_run_writes_nothing(repo):
    """P8 dry-run: without --apply every check runs but neither the test file
    nor the result TSV is written."""
    ln = line_of(repo, "Cites LLR-001.2")
    before = (repo / FILE).read_bytes()
    proc = run_apply(repo, [mrow(1, "test_replace_doc", "LLR-001.2", "R-NEW-1",
                                 "REPLACE", "doc", ln,
                                 '"""Cites LLR-001.2 inside its own docstring."""')],
                    apply=False)
    assert proc.returncode == 0, proc.stderr
    assert (repo / FILE).read_bytes() == before
    assert not (repo / "result.tsv").exists()
