"""Inc 12 E5 mutant runner (batch-103, DeepSeek v4 Pro).

One textual mutation at a time, on an ISOLATED copy of the integrated
checkout. The runner takes a checkout and an output directory, copies the
tree to a fresh directory, verifies the green baseline with the selected
test nodes, then for each arm applies exactly one mutation, runs the
narrowest discriminating node(s), restores and hash-verifies the pristine
source bytes, and classifies the arm from the pytest report — not from the
exit code alone.

Rules enforced here:

* every anchor must match exactly once on its reachable product file —
  zero matches or multiple matches is BAD, never SURVIVED;
* a verdict is read from the pytest JUnit report, not the raw exit code:
  a ``rc=1`` is KILLED only when at least one selected node failed in the
  **call** phase (a real assertion failure); setup/teardown errors and
  collection errors are BAD and never kill. ``--self-test`` proves this
  mechanism, including a fixture-error case;
* the selected nodes must actually be collected, run and passed — a
  collect-only or typo'd node id is BAD, never SURVIVED. ``PYTEST_ADDOPTS``
  and ``PYTEST_PLUGINS`` are stripped from the environment so a leaked
  ``--collect-only`` or plugin cannot poison the run;
* every pytest invocation is bounded by a per-invocation timeout; a
  timed-out or signal-killed run (negative return code) is CRASH;
* source and clone commit ids are recorded and verified equal, and an
  unexpected dirty ``s19_app/``/``tests/`` tree is rejected before any run;
  the test modules are hashed alongside the mutated product files;
* evidence fields are paths relative to the ``transcripts/`` directory and
  are verified to resolve; the baseline is included as evidence too;
* publication summaries tokenize the checkout/tree/python paths; transcripts
  keep the required absolute ``s19_app.__file__`` only in the raw private
  copies, with a redacted publication copy emitted alongside;
* CONTROL-KILL is kept out of the product arm results and counts.

The remaining contract is unchanged: pytest runs under ``python -I -B`` with
the mutant checkout inserted at ``sys.path[0]``, ``s19_app.__file__`` printed,
stdin closed, ``PYTHONDONTWRITEBYTECODE=1`` and HOME/XDG/LOCALAPPDATA isolated
under ``zq_iso_user``; the real worktree is never mutated — only
``<out>/tree`` is touched; one transcript per arm plus a machine-readable
``summary.json``.

Usage (Linux orchestrator):

    python mutation_runner.py <checkout> <outdir> [--python /path/to/python]
                                 [--timeout 60] [--self-test]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

#: The two reachable product files the arms mutate, as repo-relative paths.
APP = "s19_app/tui/app.py"
UTILS = "s19_app/utils.py"

#: Narrowest discriminating node prefixes.
TT = "tests/test_b103_inc12_tag_table.py::"
DT = "tests/test_tui_a2l_detail.py::"

#: The two test modules that host every discriminating node (hashed + verified).
TEST_FILES = ["tests/test_b103_inc12_tag_table.py", "tests/test_tui_a2l_detail.py"]

#: The minimum table from the E5 handoff has exactly this many product arms.
EXPECTED_PRODUCT_ARMS = 20

#: Publication tokens that stand in for absolute filesystem paths.
TOKENS = ("<CHECKOUT>", "<TREE>", "<PYTHON>", "<OUTDIR>", "<ISO>")

#: Default per-invocation pytest timeout in seconds (configurable).
DEFAULT_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Arms — minimum table. ``anchor`` must occur exactly once in ``file``; the
# runner asserts that before applying. ``req`` is the requirement/case the arm
# makes wrong; ``tests`` are the narrowest discriminating node ids.
# ---------------------------------------------------------------------------

ARMS = [
    {
        "id": "M1",
        "req": "R-TUI-042a.2/1,/2 — one blank column between adjacent cells",
        "file": APP,
        "anchor": "                cell_padding=1,",
        "mutation": "                cell_padding=0,",
        "tests": [
            TT + "test_r_tui_042a_2_1_gap_at_220_and_160",
            TT + "test_r_tui_042a_2_2_gap_at_118_100_80",
        ],
    },
    {
        "id": "M2",
        "req": "R-TUI-042a.4/2 — Address and Length stay whole under horizontal scroll",
        "file": APP,
        "anchor": "                fixed_columns=2,",
        "mutation": "                fixed_columns=0,",
        "tests": [TT + "test_r_tui_042a_4_2_address_length_whole_scrolled"],
    },
    {
        "id": "M3",
        "req": "R-TUI-042a.5/1,/3,/5 — Tag cell sized from the measured width left, not a fixed 34",
        "file": APP,
        "anchor": "        cap = 34 if name_width is None else min(34, name_width)",
        "mutation": "        cap = 34",
        "tests": [
            TT + "test_r_tui_042a_5_1_width_left_on_a_32_bit_page",
            TT + "test_r_tui_042a_5_3_64_bit_page",
            TT + "test_r_tui_042a_5_5_narrowest_width",
        ],
    },
    {
        "id": "M4",
        "req": "R-TUI-042a.3/1,/2,/3 — the 34-cell Tag cap (no cap -> glued/cut values)",
        "file": APP,
        "anchor": '        tag_text = f"{glyph} {_shorten_tag_name(name_text, cap)}"',
        "mutation": '        tag_text = f"{glyph} {name_text}"',
        "tests": [
            TT + "test_r_tui_042a_3_1_tag_cap_at_118",
            TT + "test_r_tui_042a_3_2_tag_cap_at_220",
            TT + "test_r_tui_042a_3_3_cap_edge",
        ],
    },
    {
        "id": "M5",
        "req": "R-TUI-042a.5/8,/9 — the page build re-fits the Tag cell after the refresh",
        "file": APP,
        "anchor": "        self.call_after_refresh(self._fit_a2l_tag_cells)",
        "mutation": "        pass  # E5 mutant: post-page-build fit removed",
        "tests": [
            TT + "test_r_tui_042a_5_8_page_build_widens_the_address_column",
            TT + "test_r_tui_042a_5_9_page_build_drops_the_vertical_scrollbar",
        ],
    },
    {
        "id": "M6",
        "req": "R-TUI-042a.5/6 — the table's own resize re-fits the Tag cells",
        "file": APP,
        "anchor": "        self.post_message(self.Measured())",
        "mutation": "        pass  # E5 mutant: Measured resize fit removed",
        "tests": [TT + "test_r_tui_042a_5_6_resize_resizes_the_tag_cell"],
    },
    {
        "id": "M7",
        "req": "R-TUI-042a.5/7 — the Save-project repaint keeps the measured w form (E3A-18)",
        "file": APP,
        "anchor": (
            "            cells = self._build_a2l_table_cells(\n"
            "                tag, self._a2l_tag_name_width(table)\n"
            "            )"
        ),
        "mutation": "            cells = self._build_a2l_table_cells(tag)",
        "tests": [TT + "test_r_tui_042a_5_7_save_project_commit_keeps_the_w_form"],
    },
    {
        "id": "M8",
        "req": "R-TUI-042a.6/3 — a trailing space projects to U+FFFD, not stripped",
        "file": APP,
        "anchor": '        name_text = str(tag.get("name") or "UNKNOWN")',
        "mutation": r'        name_text = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()',
        "tests": [TT + "test_r_tui_042a_6_3_plain_ascii_unchanged"],
    },
    {
        "id": "M9",
        "req": "R-TUI-042a.6/1 — O(w) projection, not the E2 quadratic cell-length loop",
        "file": APP,
        "anchor": (
            '    if width < 1:\n'
            '        width = 1\n'
            '\n'
            '    def _project(slice_: str) -> str:\n'
            '        return "".join(\n'
            r'            ch if "\u0021" <= ch <= "\u007E" else "\uFFFD" for ch in slice_' + "\n"
            '        )\n'
            '\n'
            '    if len(name) <= width:\n'
            '        return _project(name)\n'
            '    head = (width - 1) // 2\n'
            '    tail = width - 1 - head\n'
            '    return _project(name[:head]) + "…" + _project(name[len(name) - tail:])'
        ),
        "mutation": (
            '    if cell_len(name) <= width:\n'
            '        return name\n'
            '    width = max(1, width)\n'
            '    head = (width - 1) // 2\n'
            '    tail = width - 1 - head\n'
            '    suffix = ""\n'
            '    for char in reversed(name):\n'
            '        if cell_len(char + suffix) > tail:\n'
            '            break\n'
            '        suffix = char + suffix\n'
            '    return set_cell_size(name, head) + "…" + " " * (tail - cell_len(suffix)) + suffix'
        ),
        "tests": [TT + "test_r_tui_042a_6_1_zero_width_tail"],
    },
    {
        "id": "M10",
        "req": "R-TUI-042a.7.1/1,/2 — the card header value renders through _card_value_text",
        "file": APP,
        "anchor": '    text.append(_card_value_text(display_id or name or "UNKNOWN", style=VALUE))',
        "mutation": '    text.append(str(display_id or name or "UNKNOWN"), style=VALUE)',
        "tests": [
            TT + "test_r_tui_042a_7_1_1_name_without_display_identifier",
            TT + "test_r_tui_042a_7_1_2_display_identifier",
        ],
    },
    {
        "id": "M11",
        "req": "R-TUI-042a.7.1/3,/7 — card field values scrubbed via _card_value_text",
        "file": APP,
        "anchor": "    text.append(_card_value_text(value, style=VALUE))",
        "mutation": "    text.append(str(value), style=VALUE)",
        "tests": [
            TT + "test_r_tui_042a_7_1_3_description",
            TT + "test_r_tui_042a_7_1_7_name_on_the_name_line",
        ],
    },
    {
        "id": "M12",
        "req": "R-TUI-042a.7.1/4 — the unit scrubbed via _card_value_text",
        "file": APP,
        "anchor": "            text.append(_card_value_text(unit, style=VALUE))",
        "mutation": "            text.append(str(unit), style=VALUE)",
        "tests": [TT + "test_r_tui_042a_7_1_4_unit"],
    },
    {
        "id": "M13",
        "req": "R-TUI-042a.7.1/5 — the conversion scrubbed via _card_value_text",
        "file": APP,
        "anchor": "            text.append(_card_value_text(conversion, style=VALUE))",
        "mutation": "            text.append(str(conversion), style=VALUE)",
        "tests": [TT + "test_r_tui_042a_7_1_5_conversion"],
    },
    {
        "id": "M14",
        "req": "R-TUI-042a.7.1/6 — lower/upper limits scrubbed via _card_value_text",
        "file": APP,
        "anchor": (
            '        text.append(_card_value_text(lower if lower is not None else ""))\n'
            '        text.append("..", style=VALUE)\n'
            '        text.append(_card_value_text(upper if upper is not None else ""))'
        ),
        "mutation": (
            '        text.append(str(lower if lower is not None else ""))\n'
            '        text.append("..", style=VALUE)\n'
            '        text.append(str(upper if upper is not None else ""))'
        ),
        "tests": [TT + "test_r_tui_042a_7_1_6_limits"],
    },
    {
        "id": "M15",
        "req": "R-TUI-042a.7.1/7 — the Name line built through _card_value_text",
        "file": APP,
        "anchor": '        _card_field(text, "name", name)',
        "mutation": (
            '        text.append("\\n")\n'
            '        text.append("name ", style=LABEL)\n'
            '        text.append(str(name), style=VALUE)'
        ),
        "tests": [TT + "test_r_tui_042a_7_1_7_name_on_the_name_line"],
    },
    {
        "id": "M16",
        "req": "R-TUI-042a.7.2/1,/2 — each maximal run of break chars maps to one space",
        "file": APP,
        "anchor": (
            r'    scrubbed = re.sub(r"[\t\n\r]+", " ", str(value))' + "\n"
            '    return safe_text(scrubbed, style=style)'
        ),
        "mutation": "    return safe_text(str(value), style=style)",
        "tests": [
            TT + "test_r_tui_042a_7_2_1_description_break_run",
            TT + "test_r_tui_042a_7_2_2_unit_break_run",
        ],
    },
    {
        "id": "M17",
        "req": "R-TUI-042a.8/1 — the Name line shown under a display identifier",
        "file": APP,
        "anchor": (
            '    if display_id:\n'
            '        _card_field(text, "name", name)\n'
            '    _card_field(text, "desc", tag.get("description"))'
        ),
        "mutation": '    _card_field(text, "desc", tag.get("description"))',
        "tests": [TT + "test_r_tui_042a_8_1_name_line_with_a_display_identifier"],
    },
    {
        "id": "M18",
        "req": "AT-069c — the hostile tag NAME renders verbatim, never markup-parsed",
        "file": APP,
        "anchor": "            safe_text(tag_text, style=VALUE),",
        "mutation": "            Text.from_markup(tag_text, style=VALUE),",
        "tests": [DT + "test_at069c_c17_table_name"],
    },
    {
        "id": "M19",
        "req": "R-TUI-042a.7.1 — U+009D/U+0090 scrubbed, not only ESC and U+009B",
        "file": UTILS,
        "anchor": "_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x7F, 0xA0)))",
        "mutation": "_CONTROL_SCRUB = dict.fromkeys((0x1B, 0x9B))",
        "tests": [TT + "test_r_tui_042a_7_1_1_name_without_display_identifier"],
    },
    {
        "id": "M20",
        "req": "R-TUI-042a.7.1 — DEL (U+007F) scrubbed",
        "file": UTILS,
        "anchor": "_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x7F, 0xA0)))",
        "mutation": "_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x80, 0xA0)))",
        "tests": [TT + "test_r_tui_042a_7_1_1_name_without_display_identifier"],
    },
]

#: A known-bad arm: it must be KILLED, or the runner's PASS results are not
#: believed (a green baseline alone is not proof). It is not part of the
#: minimum table and is never counted in ``EXPECTED_PRODUCT_ARMS`` or the
#: product arm results/counts.
CONTROL = {
    "id": "CONTROL-KILL",
    "req": "CONTROL — address must render (known-bad; must be KILLED)",
    "file": APP,
    "anchor": '        addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"',
    "mutation": '        addr_text = "n/a"',
    "tests": [TT + "test_r_tui_042a_4_1_address_length_whole_unscrolled"],
}

#: Fixture self-test body: one passing node, one call-phase assertion failure,
#: and one fixture (setup) error — the three report shapes the classifier must
#: tell apart.
SELF_TEST_PYTEST_SRC = """\
import pytest


def test_pass():
    assert True


def test_assert_fail():
    assert False, "mutant caught in call phase"


@pytest.fixture
def broken_fixture():
    raise RuntimeError("fixture setup boom")
    yield


def test_fixture_error(broken_fixture):
    assert True
"""


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def redact(text: str, mappings: list[tuple[str, str]]) -> str:
    """Replace absolute paths with publication tokens, longest first."""
    for src, token in sorted(mappings, key=lambda kv: len(kv[0]), reverse=True):
        text = text.replace(src, token)
    return text


def _mangle_node_id(address: str) -> tuple[str, str]:
    """Reproduce pytest's junit ``mangle_test_address`` -> (classname, name)."""
    path, possible_open_bracket, params = address.partition("[")
    names = path.split("::")
    names[0] = names[0].replace("/", ".")
    names[0] = re.sub(r"\.py$", "", names[0])
    names[-1] += possible_open_bracket + params
    return ".".join(names[:-1]), names[-1]


def parse_junit(xml_path: Path, node_ids: list[str]) -> tuple[dict[str, str] | None, int]:
    """Map each requested node id to a per-node report status.

    Statuses: ``passed``, ``failed`` (call-phase assertion), ``error``
    (setup/teardown), ``skipped``, or ``missing`` (not collected). Returns
    ``(None, collection_errors)`` when the report is absent or unreadable.
    """
    try:
        root = ET.parse(str(xml_path)).getroot()
    except (ET.ParseError, OSError):
        return None, 0

    statuses: dict[str, str] = {nid: "missing" for nid in node_ids}
    wanted = {nid: _mangle_node_id(nid) for nid in node_ids}
    rank = {"missing": -1, "passed": 0, "skipped": 1, "error": 2, "failed": 3}
    collection_errors = 0

    for tc in root.iter("testcase"):
        classname = tc.get("classname", "")
        name = tc.get("name", "")
        matched_nid = None
        for nid, (exp_cls, exp_name) in wanted.items():
            if classname == exp_cls and (
                name == exp_name or name.startswith(exp_name + "[")
            ):
                matched_nid = nid
                break
        if matched_nid is None:
            # A non-test testcase: flag collection failures explicitly.
            if any(e.get("message") == "collection failure" for e in tc.iter("error")):
                collection_errors += 1
            continue

        if any(True for _ in tc.iter("failure")):
            status = "failed"
        elif any(True for _ in tc.iter("error")):
            status = "error"
        elif any(True for _ in tc.iter("skipped")):
            status = "skipped"
        else:
            status = "passed"
        if rank[status] > rank[statuses[matched_nid]]:
            statuses[matched_nid] = status

    return statuses, collection_errors


def classify_arm(
    rc: int | None,
    statuses: dict[str, str] | None,
    timed_out: bool,
    collection_errors: int = 0,
) -> str:
    """Classify an arm from the pytest exit code plus the parsed report.

    ``rc=1`` is KILLED only on a call-phase ``failed`` node; setup/teardown
    errors and collection errors are BAD. Timed-out or signal-killed runs are
    CRASH.
    """
    if timed_out or (rc is not None and rc < 0) or rc == 3:
        return "CRASH"
    if collection_errors > 0:
        return "BAD"
    if statuses is None:
        return "BAD"
    if rc == 0:
        if statuses and all(s == "passed" for s in statuses.values()):
            return "SURVIVED"
        return "BAD"
    if rc == 1:
        if any(s == "failed" for s in statuses.values()):
            return "KILLED"
        return "BAD"
    return "BAD"


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Best-effort kill of the process group, then the direct child."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def run_subprocess(
    cmd: list[str], cwd: Path, env: dict, timeout: float
) -> tuple[int | None, str, bool]:
    """Run a command bounded by ``timeout``; return (rc, stdout, timed_out).

    A negative return code means the process was killed by a signal.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return -1, f"failed to start subprocess: {exc}\n", False
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out, False
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        out, _ = proc.communicate()
        return proc.returncode, out, True


def copy_tree(checkout: Path, tree: Path, source_commit: str | None) -> str:
    """Copy the integrated checkout into a fresh isolated directory.

    Prefer ``git clone --no-hardlinks`` when ``checkout`` is a repository so
    tracked-file tests that shell out to ``git ls-files`` keep working; fall
    back to a plain filesystem copy otherwise. The clone is pinned to the
    source commit (a detached-HEAD source must not clone a different branch
    tip).
    """
    if tree.exists():
        shutil.rmtree(tree)
    if (checkout / ".git").exists():
        subprocess.run(
            ["git", "clone", "--quiet", "--no-hardlinks", str(checkout), str(tree)],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if source_commit:
            clone_head = git_head(tree)
            if clone_head != source_commit:
                subprocess.run(
                    ["git", "-C", str(tree), "checkout", "--quiet", "--detach", source_commit],
                    check=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
        return "git-clone"
    shutil.copytree(checkout, tree)
    return "copytree"


def git_head(repo: Path) -> str | None:
    """Return ``HEAD`` of ``repo``, or ``None`` when it is not a repository."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def git_dirty_product_tests(repo: Path) -> list[str]:
    """List unexpected uncommitted changes under ``s19_app/`` and ``tests/``."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--", "s19_app", "tests"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def write_driver(tree: Path, driver_path: Path) -> None:
    """Write the pytest wrapper that inserts the mutant tree at ``sys.path[0]``."""
    driver_path.write_text(
        "import sys\n"
        "\n"
        f"TREE = {json.dumps(str(tree))}\n"
        "\n"
        "sys.path.insert(0, TREE)\n"
        "\n"
        "import s19_app  # noqa: E402\n"
        "\n"
        'print("s19_app.__file__ =", s19_app.__file__, flush=True)\n'
        "\n"
        "import pytest  # noqa: E402\n"
        "\n"
        "raise SystemExit(pytest.main(sys.argv[1:]))\n",
        encoding="utf-8",
    )


def sanitized_env(env: dict) -> dict:
    """Strip pytest-affecting vars so a leaked option/plugin cannot poison a run."""
    clean = dict(env)
    clean.pop("PYTEST_ADDOPTS", None)
    clean.pop("PYTEST_PLUGINS", None)
    return clean


def iso_env(iso: Path) -> dict:
    """Isolated environment: HOME/XDG/LOCALAPPDATA under ``zq_iso_user``."""
    env = sanitized_env(os.environ)
    env["HOME"] = str(iso / "home")
    env["XDG_CACHE_HOME"] = str(iso / "xdg_cache")
    env["XDG_CONFIG_HOME"] = str(iso / "xdg_config")
    env["XDG_DATA_HOME"] = str(iso / "xdg_data")
    env["LOCALAPPDATA"] = str(iso / "localappdata")
    env["TMPDIR"] = str(iso / "tmp")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_tests(
    py: str,
    driver: Path,
    tree: Path,
    iso: Path,
    node_ids: list[str],
    transcript_path: Path,
    junit_path: Path,
    timeout: float,
) -> tuple[int | None, str, bool]:
    """Run the given nodes under ``python -I -B`` and return (rc, stdout, timed_out).

    The JUnit report is the machine-readable verdict source; the stdout is
    written verbatim to ``transcript_path``.
    """
    cmd = [
        py,
        "-I",
        "-B",
        str(driver),
        "-p",
        "no:cacheprovider",
        "-q",
        "--junitxml",
        str(junit_path),
        *node_ids,
    ]
    rc, out, timed_out = run_subprocess(cmd, cwd=tree, env=iso_env(iso), timeout=timeout)
    transcript_path.write_text(out, encoding="utf-8")
    return rc, out, timed_out


def run_self_test(py: str, timeout: float) -> int:
    """Exercise the report->verdict mechanism on a fixture-error case and friends.

    Proves: call-phase assertion -> KILLED; fixture (setup) error -> BAD;
    all-pass -> SURVIVED; collect-only -> BAD (nodes never ran).
    """
    tmp = Path(tempfile.mkdtemp(prefix="s19-mut-selftest-"))
    try:
        test_file = tmp / "test_selftest_mechanism.py"
        test_file.write_text(SELF_TEST_PYTEST_SRC, encoding="utf-8")
        junit_dir = tmp / "junit"
        junit_dir.mkdir()
        env = sanitized_env(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        cases = [
            ("pass", ["test_selftest_mechanism.py::test_pass"], "SURVIVED", False),
            ("assert-fail", ["test_selftest_mechanism.py::test_assert_fail"], "KILLED", False),
            ("fixture-error", ["test_selftest_mechanism.py::test_fixture_error"], "BAD", False),
            ("collect-only", ["test_selftest_mechanism.py::test_pass"], "BAD", True),
        ]

        failures: list[str] = []
        for label, node_ids, expected, collect_only in cases:
            junit = junit_dir / f"{label}.xml"
            args = [
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-q",
                "--junitxml",
                str(junit),
            ]
            if collect_only:
                args.append("--collect-only")
            args.extend(node_ids)
            rc, _out, timed_out = run_subprocess(
                [py, "-I", "-B", *args], cwd=tmp, env=env, timeout=timeout
            )
            statuses, collection_errors = parse_junit(junit, node_ids)
            verdict = classify_arm(rc, statuses, timed_out, collection_errors)
            ok = verdict == expected
            print(
                f"self-test {label}: rc={rc} verdict={verdict} "
                f"expected={expected} {'OK' if ok else 'FAIL'}",
                flush=True,
            )
            if not ok:
                failures.append(label)
        if failures:
            print("SELF-TEST FAILED:", failures, flush=True)
            return 1
        print("SELF-TEST PASSED", flush=True)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inc 12 E5 mutation runner")
    parser.add_argument(
        "checkout", type=Path, nargs="?", help="integrated checkout (read-only)"
    )
    parser.add_argument("outdir", type=Path, nargs="?", help="output directory (fresh)")
    parser.add_argument(
        "--python",
        type=str,
        default=os.environ.get("S19CI_PYTHON", sys.executable),
        help="Python interpreter used for pytest (default: S19CI_PYTHON or sys.executable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-invocation pytest timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the verdict-mechanism self-test (fixture-error case) and exit",
    )
    parser.add_argument(
        "--only",
        action="append",
        help="run only the named arm id, with baseline and control (repeatable)",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test(args.python, args.timeout)
    if args.checkout is None or args.outdir is None:
        parser.error("checkout and outdir are required unless --self-test is given")

    checkout = args.checkout.resolve()
    outdir = args.outdir.resolve()
    tree = outdir / "tree"
    iso = outdir / "zq_iso_user"
    transcripts = outdir / "transcripts"
    public_transcripts = outdir / "transcripts-public"
    junit_dir = outdir / "junit"
    transcripts.mkdir(parents=True, exist_ok=True)
    public_transcripts.mkdir(parents=True, exist_ok=True)
    junit_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("home", "xdg_cache", "xdg_config", "xdg_data", "localappdata", "tmp"):
        (iso / sub).mkdir(parents=True, exist_ok=True)

    # The minimum table must be complete before any run starts.
    product_ids = [arm["id"] for arm in ARMS]
    assert len(ARMS) == EXPECTED_PRODUCT_ARMS, (
        f"expected {EXPECTED_PRODUCT_ARMS} product arms, got {len(ARMS)}"
    )
    assert len(set(product_ids)) == len(product_ids), "duplicate arm ids"
    selected_arms = [arm for arm in ARMS if not args.only or arm["id"] in args.only]
    if not selected_arms:
        print(f"ABORT: no product arms selected by --only={args.only}", flush=True)
        return 2

    # Source identity: record HEAD and reject unexpected dirty product/tests.
    source_commit = git_head(checkout)
    dirty = git_dirty_product_tests(checkout)
    if dirty:
        print(
            "ABORT: checkout has unexpected dirty product/tests (refusing to run):",
            flush=True,
        )
        for line in dirty:
            print(f"  {line}", flush=True)
        return 2

    method = copy_tree(checkout, tree, source_commit)
    print(f"tree copy method: {method}", flush=True)
    print(f"tree: {tree}", flush=True)

    clone_commit = git_head(tree)
    if source_commit is not None and clone_commit != source_commit:
        print(
            f"ABORT: clone HEAD {clone_commit} != source HEAD {source_commit}",
            flush=True,
        )
        return 2
    print(f"source commit: {source_commit}", flush=True)
    print(f"clone commit:  {clone_commit}", flush=True)

    driver = outdir / "driver.py"
    write_driver(tree, driver)

    # Redaction map for publication copies (absolute paths only).
    redact_map: list[tuple[str, str]] = []
    for token, path in (
        ("<CHECKOUT>", checkout),
        ("<TREE>", tree),
        ("<OUTDIR>", outdir),
        ("<ISO>", iso),
    ):
        redact_map.append((str(path), token))
    py_path = Path(args.python)
    if py_path.is_absolute():
        redact_map.append((str(py_path), "<PYTHON>"))

    # Pristine bytes of every mutated file, captured once from the copy.
    mutated_files = sorted({arm["file"] for arm in ARMS} | {CONTROL["file"]})
    pristine: dict[str, bytes] = {}
    for rel in mutated_files:
        path = tree / rel
        if not path.is_file():
            print(f"ABORT: reachable product file missing in tree: {rel}", flush=True)
            return 2
        pristine[rel] = path.read_bytes()

    # Test modules must exist and are hashed so verdicts bind to test bytes.
    test_hashes: dict[str, str] = {}
    for rel in TEST_FILES:
        path = tree / rel
        if not path.is_file():
            print(f"ABORT: discriminating test module missing in tree: {rel}", flush=True)
            return 2
        test_hashes[rel] = sha256_bytes(path.read_bytes())

    def write_pristine(rel: str) -> None:
        (tree / rel).write_bytes(pristine[rel])

    def verify_pristine(rel: str, context: str) -> bool:
        ok = (tree / rel).read_bytes() == pristine[rel]
        if not ok:
            print(f"ABORT: {context}: {rel} does not match pristine bytes", flush=True)
        return ok

    all_nodes: list[str] = []
    for arm in selected_arms:
        all_nodes.extend(arm["tests"])
    all_nodes.extend(CONTROL["tests"])
    all_nodes = sorted(set(all_nodes))

    def write_transcript(evidence: str, text: str) -> None:
        """Write the raw private transcript and a redacted publication copy."""
        (transcripts / evidence).write_text(text, encoding="utf-8")
        (public_transcripts / evidence).write_text(
            redact(text, redact_map), encoding="utf-8"
        )

    # Baseline: the selected nodes must be collected, run and passed.
    print("== baseline ==", flush=True)
    base_junit = junit_dir / "baseline.xml"
    base_rc, _base_out, base_timed_out = run_tests(
        args.python,
        driver,
        tree,
        iso,
        all_nodes,
        transcripts / "baseline.txt",
        base_junit,
        args.timeout,
    )
    base_statuses, base_collection_errors = parse_junit(base_junit, all_nodes)
    base_verdict = classify_arm(
        base_rc, base_statuses, base_timed_out, base_collection_errors
    )
    print(
        f"baseline rc={base_rc} ({base_verdict}) "
        f"nodes={len(all_nodes)}",
        flush=True,
    )
    if base_verdict != "SURVIVED":
        print("ABORT: baseline not green; cannot trust any mutant verdict", flush=True)
        return 2
    # Redacted publication copy of the baseline transcript (raw keeps __file__).
    (public_transcripts / "baseline.txt").write_text(
        redact((transcripts / "baseline.txt").read_text(encoding="utf-8"), redact_map),
        encoding="utf-8",
    )
    baseline = {
        "rc": base_rc,
        "verdict": "GREEN",
        "evidence": "baseline.txt",
        "nodes": len(all_nodes),
    }

    results: list[dict] = []

    def run_arm(arm: dict) -> dict:
        arm_id = arm["id"]
        rel = arm["file"]
        anchor = arm["anchor"]
        mutation = arm["mutation"]
        text = (tree / rel).read_text(encoding="utf-8")
        applied = text.count(anchor)

        header = (
            f"=== {arm_id} ({arm['req']}) ===\n"
            f"file: {rel}\n"
            f"anchor: {anchor!r}\n"
            f"mutation: {mutation!r}\n"
            f"applied count: {applied} (expected 1)\n"
        )
        evidence = f"{arm_id}.txt"

        if applied != 1:
            # Zero or multiple matches = BAD, never SURVIVED. Run the nodes on
            # the pristine copy so the transcript still shows the anchor issue.
            rc, out, timed_out = run_tests(
                args.python,
                driver,
                tree,
                iso,
                arm["tests"],
                transcripts / evidence,
                junit_dir / f"{arm_id}.xml",
                args.timeout,
            )
            write_transcript(
                evidence,
                header + f"verdict: BAD (applied={applied})\n\n" + out,
            )
            record = {
                "id": arm_id,
                "req": arm["req"],
                "file": rel,
                "applied": applied,
                "rc": rc,
                "verdict": "BAD",
                "tests": arm["tests"],
                "evidence": evidence,
            }
            print(
                f"{arm_id}: applied={applied} BAD (anchor not unique) rc={rc}",
                flush=True,
            )
            return record

        mutated = text.replace(anchor, mutation, 1)
        assert mutated != text, f"{arm_id}: mutation produced no change"
        (tree / rel).write_text(mutated, encoding="utf-8")
        mut_hash = sha256_bytes((tree / rel).read_bytes())
        assert mut_hash != sha256_bytes(pristine[rel]), f"{arm_id}: bytes unchanged"

        rc, out, timed_out = run_tests(
            args.python,
            driver,
            tree,
            iso,
            arm["tests"],
            transcripts / evidence,
            junit_dir / f"{arm_id}.xml",
            args.timeout,
        )
        statuses, collection_errors = parse_junit(junit_dir / f"{arm_id}.xml", arm["tests"])

        write_pristine(rel)
        restored_hash = sha256_bytes((tree / rel).read_bytes())
        assert restored_hash == sha256_bytes(pristine[rel]), f"{arm_id}: restore mismatch"

        verdict = classify_arm(rc, statuses, timed_out, collection_errors)
        if timed_out:
            note = f"TIMEOUT after {args.timeout}s\n\n"
        else:
            note = ""
        write_transcript(
            evidence,
            header
            + f"mutated hash: {mut_hash}\n"
            + f"restored hash: {restored_hash}\n"
            + f"verdict: {verdict} (rc={rc})\n\n"
            + note
            + out,
        )
        record = {
            "id": arm_id,
            "req": arm["req"],
            "file": rel,
            "applied": applied,
            "rc": rc,
            "verdict": verdict,
            "tests": arm["tests"],
            "evidence": evidence,
        }
        print(f"{arm_id}: applied={applied} rc={rc} {verdict}", flush=True)
        return record

    # Control first: a green baseline alone is not proof. The control verdict
    # is recorded separately and is never part of product arms or counts.
    print("== control ==", flush=True)
    control_record = run_arm(CONTROL)
    if control_record["verdict"] != "KILLED":
        print(
            "ABORT: known-bad control arm was not KILLED; PASS results are not believed",
            flush=True,
        )
        return 2

    print("== arms ==", flush=True)
    for arm in selected_arms:
        results.append(run_arm(arm))

    # Final: restore both files and prove the copied tree is byte-identical.
    for rel in mutated_files:
        write_pristine(rel)
        if not verify_pristine(rel, "final restore"):
            return 2

    # Every evidence field must be a transcript-relative path that resolves.
    for rec in results + [baseline, control_record]:
        evidence = rec["evidence"]
        if not (transcripts / evidence).is_file():
            print(f"ABORT: evidence does not resolve: {evidence}", flush=True)
            return 2

    counts: dict[str, int] = {}
    for rec in results:
        counts[rec["verdict"]] = counts.get(rec["verdict"], 0) + 1

    summary = {
        "checkout": "<CHECKOUT>",
        "tree": "<TREE>",
        "python": "<PYTHON>",
        "copy_method": method,
        "source_commit": source_commit,
        "clone_commit": clone_commit,
        "expected_product_arms": EXPECTED_PRODUCT_ARMS,
        "evidence_base": "transcripts",
        "baseline": baseline,
        "control": control_record,
        "arms": results,
        "counts": counts,
        "pristine_sha256": {rel: sha256_bytes(pristine[rel]) for rel in mutated_files},
        "test_sha256": test_hashes,
    }
    (outdir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )

    lines = [f"{r['id']}: applied={r['applied']} rc={r['rc']} {r['verdict']}" for r in results]
    lines.append(f"baseline rc={base_rc}")
    lines.append(f"counts: {counts}")
    (outdir / "runner-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("== summary ==", flush=True)
    print("\n".join(lines), flush=True)
    print(f"summary.json written to {outdir / 'summary.json'}", flush=True)
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
