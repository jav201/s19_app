"""Inc-11 E5 mutants-A runner (Linux canonical).

One mutation at a time: apply, run the smallest discriminating test node(s),
restore the pristine bytes, verify the hash. Every verdict is read from the
pytest summary *and* the assertion text in the transcript, never from the
process exit code alone. A zero-application arm is BAD, not SURVIVED.

Works only on <tree>/s19_app/tui/a2l.py and <out>/; no git checkout/stash/
commit, no real-worktree edits.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

OUT = Path("/tmp/b103-e5-11-mutA-laptop/out")
TREE = Path("/tmp/b103-e5-11-mutA-laptop/tree")
TARGET = TREE / "s19_app" / "tui" / "a2l.py"
PRISTINE = OUT / ".pristine-a2l.py"
TRANSCRIPTS = OUT / "mutants-A"

PY = "/data/miniconda3/envs/s19ci/bin/python"
ISO = Path("/tmp/b103-e5-11-mutA-laptop/zq_iso_user")

DRIVER = OUT / "driver.py"

# Mutant-A anchors rebuilt against this tree (f1397097 -> current tree copy).
# Every anchor occurs exactly once; the runner asserts that.
ARMS = [
    {
        "id": "M1",
        "req": "R-A2L-READ.7",
        "anchor": '_SLOW_WORD_RE = re.compile(r\'(?:[^ \\t\\x0b\\x0c"/\\r\\n]|/(?![/*]))+\')',
        "mutation": '_SLOW_WORD_RE = re.compile(r\'(?:[^ \\t\\x0b\\x0c"/\\r\\n]|/)+\')',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_7_comment_between_digits_splits"],
    },
    {
        "id": "M2",
        "req": "R-A2L-READ.9",
        "anchor": (
            '            if ch == "/" and i + 1 < n and body[i + 1] == "/":\n'
            "                i += 2\n"
            '                while i < n and body[i] != "\\r" and body[i] != "\\n":\n'
            "                    i += 1\n"
            "                continue"
        ),
        "mutation": (
            '            if ch == "/" and i + 1 < n and body[i + 1] == "/":\n'
            "                in_comment = True\n"
            "                comment_line = line\n"
            "                i += 2\n"
            "                continue"
        ),
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_9_line_comment_ends_at_line_end"],
    },
    {
        "id": "M3",
        "req": "R-A2L-READ.10",
        "anchor": '        errors.append(f"Line {comment_line}: comment not closed")',
        "mutation": "        pass",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_10_comment_not_closed"],
    },
    {
        "id": "M4",
        "req": "R-A2L-READ.11",
        "anchor": '    if "*/" in word:',
        "mutation": "    if False:",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_11_stray_close"],
    },
    {
        "id": "M5",
        "req": "R-A2L-READ.8",
        "anchor": '                j = body.find("*/", i)',
        "mutation": '                j = body.rfind("*/", i)',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_8_comments_do_not_nest"],
    },
    {
        "id": "M6",
        "req": "R-A2L-001.3.2",
        "anchor": "        if backslashes % 2 == 0:\n            return j",
        "mutation": "        if True:\n            return j",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_001_3_2_escapes"],
    },
    {
        "id": "M7",
        "req": "R-A2L-READ.15",
        "anchor": '        errors.append(f"Line {string_line}: quoted string not closed")',
        "mutation": "        pass",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_15_quoted_string_not_closed"],
    },
    {
        "id": "M8",
        "req": "R-A2L-001.3.1",
        "anchor": "    return _WORD_SPLIT_RE.findall(text)",
        "mutation": '    return text.split(" ") if text else []',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_001_3_1_quoted_string_one_word"],
    },
    {
        "id": "M9",
        "req": "R-A2L-READ.16",
        "anchor": '_SLOW_WORD_RE = re.compile(r\'(?:[^ \\t\\x0b\\x0c"/\\r\\n]|/(?![/*]))+\')',
        "mutation": '_SLOW_WORD_RE = re.compile(r\'(?:[^ \\t\\x0b\\x0c/\\r\\n]|/(?![/*]))+\')',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_16_quote_ends_word"],
    },
    {
        "id": "M10",
        "req": "R-A2L-READ.1",
        "anchor": '                if ch == "\\r" and i + 1 < n and body[i + 1] == "\\n":',
        "mutation": '                if ch == "\\r" and False:',
        "tests": [
            "tests/test_b103_a2l_reader.py::test_r_a2l_read_1_cr_cr_lf_counts_two_ends",
            "tests/test_b103_a2l_reader.py::test_r_a2l_read_1_crlf_cr_mixed_read_as_lf",
        ],
    },
    {
        "id": "M11",
        "req": "R-A2L-READ.5",
        "anchor": '    utf8_bom = head[:3] == b"\\xef\\xbb\\xbf"',
        "mutation": "    utf8_bom = False",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_5_bom_before_project_dropped"],
    },
    {
        "id": "M12",
        "req": "R-A2L-READ.6",
        "anchor": '    if head[:2] in (b"\\xff\\xfe", b"\\xfe\\xff"):',
        "mutation": "    if False:",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_6_utf16_refusal"],
    },
    {
        "id": "M13",
        "req": "R-A2L-READ.55",
        "anchor": '        if "\\x00" in body:',
        "mutation": "        if False:",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_55_nul_after_address_refused"],
    },
    {
        "id": "M14",
        "req": "R-A2L-001.1",
        "anchor": '            or "/" in text',
        "mutation": '            or text.startswith("/")',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_001_1_begin_end_words"],
    },
    {
        "id": "M15",
        "req": "R-A2L-READ.64",
        "anchor": "_MAX_NESTING = 32",
        "mutation": "_MAX_NESTING = 10000",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_64_nesting_cap"],
    },
    {
        "id": "M16",
        "req": "R-A2L-READ.22",
        "anchor": '            if low == "/include":',
        "mutation": "            if False:",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_22_include_error"],
    },
    {
        "id": "M17",
        "req": "R-A2L-READ.56",
        "anchor": "        if len(self._texts) < self._cap:",
        "mutation": "        if True:",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_56_cap_at_edge"],
    },
    {
        "id": "M18",
        "req": "R-A2L-READ.19",
        "anchor": '            if low == "/begin":',
        "mutation": '            if low.startswith("/begin"):',
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_19_glued_begin_end"],
    },
    {
        "id": "M19",
        "req": "R-A2L-001.5",
        "anchor": '                    matched = top["name"] == word',
        "mutation": "                    matched = True",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_001_5_end_name_mismatch"],
    },
    {
        "id": "M20",
        "req": "R-A2L-001.4",
        "anchor": '                    errors.append(f"Line {pending_end_line}: /end without /begin")',
        "mutation": "                    pass",
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_001_4_stray_end"],
    },
    {
        "id": "M-BAD",
        "req": "control",
        "anchor": "def _no_such_anchor_xyz_mutant_control():",
        "mutation": None,
        "tests": ["tests/test_b103_a2l_reader.py::test_r_a2l_read_7_comment_between_digits_splits"],
        "control": True,
    },
]


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def iso_env() -> dict:
    env = os.environ.copy()
    env["HOME"] = str(ISO / "home")
    env["XDG_CACHE_HOME"] = str(ISO / "xdg_cache")
    env["XDG_CONFIG_HOME"] = str(ISO / "xdg_config")
    env["XDG_DATA_HOME"] = str(ISO / "xdg_data")
    env["LOCALAPPDATA"] = str(ISO / "localappdata")
    env["TMPDIR"] = str(ISO / "tmp")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_tests(node_ids: list[str], out_path: Path) -> tuple[int, str]:
    cmd = [PY, "-I", "-B", str(DRIVER), "-p", "no:cacheprovider", "-q", *node_ids]
    proc = subprocess.run(
        cmd,
        cwd=str(TREE),
        env=iso_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out_path.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode, proc.stdout


def main() -> int:
    pristine_hash = sha256(PRISTINE)
    target_hash = sha256(TARGET)
    if pristine_hash != target_hash:
        print(f"ABORT: pristine {pristine_hash} != target {target_hash}", flush=True)
        return 2
    print(f"pristine==target {pristine_hash}", flush=True)

    results: list[str] = []
    for arm in ARMS:
        arm_id = arm["id"]
        anchor = arm["anchor"]
        mutation = arm["mutation"]
        control = arm.get("control", False)

        text = TARGET.read_text(encoding="utf-8")
        applied = text.count(anchor)

        header = f"=== {arm_id} ({arm['req']}) ===\n"
        header += f"anchor: {anchor!r}\n"
        header += f"mutation: {mutation!r}\n"
        header += f"applied count: {applied}\n"

        if control or applied == 0:
            # known-bad control: the anchor is absent -> BAD, never SURVIVED
            rc, out = run_tests(arm["tests"], TRANSCRIPTS / f"{arm_id}.txt")
            (TRANSCRIPTS / f"{arm_id}.txt").write_text(
                header + "\n" + out, encoding="utf-8"
            )
            results.append(f"{arm_id}: applied={applied} BAD (control) rc={rc}")
            print(results[-1], flush=True)
            continue

        if applied != 1:
            # unexpected multiplicity -> BAD (mutation not uniquely applied)
            rc, out = run_tests(arm["tests"], TRANSCRIPTS / f"{arm_id}.txt")
            (TRANSCRIPTS / f"{arm_id}.txt").write_text(
                header + f"UNEXPECTED applied={applied}\n" + out, encoding="utf-8"
            )
            results.append(f"{arm_id}: applied={applied} BAD (multiplicity) rc={rc}")
            print(results[-1], flush=True)
            continue

        # apply exactly one mutation
        mutated = text.replace(anchor, mutation, 1)
        assert mutated != text, f"{arm_id}: mutation produced no change"
        TARGET.write_text(mutated, encoding="utf-8")
        mut_hash = sha256(TARGET)
        assert mut_hash != pristine_hash, f"{arm_id}: mutation did not change bytes"

        rc, out = run_tests(arm["tests"], TRANSCRIPTS / f"{arm_id}.txt")

        # restore pristine bytes and verify hash
        TARGET.write_bytes(PRISTINE.read_bytes())
        restored_hash = sha256(TARGET)
        assert restored_hash == pristine_hash, f"{arm_id}: restore hash mismatch"

        (TRANSCRIPTS / f"{arm_id}.txt").write_text(
            header + f"mutated hash: {mut_hash}\nrestored hash: {restored_hash}\n\n" + out,
            encoding="utf-8",
        )

        results.append(f"{arm_id}: applied={applied} rc={rc}")
        print(results[-1], flush=True)

    # final: restore and prove the copied tree green (baseline = 331 tests)
    TARGET.write_bytes(PRISTINE.read_bytes())
    assert sha256(TARGET) == pristine_hash, "final restore hash mismatch"
    final_nodes = [
        "tests/test_b103_a2l_reader.py",
        "tests/test_b103_a2l_reader_coverage.py",
        "tests/test_b103_a2l_reader_e5.py",
    ]
    rc, out = run_tests(final_nodes, TRANSCRIPTS / "final-baseline-green.txt")
    print(f"final baseline rc={rc}", flush=True)

    (OUT / "runner-summary.txt").write_text("\n".join(results) + f"\nfinal baseline rc={rc}\n", encoding="utf-8")
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
