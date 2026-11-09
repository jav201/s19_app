"""Inc 12 E5 mutant runner (batch-103, DeepSeek v4 Pro).

One textual mutation at a time, on an ISOLATED copy of the integrated
checkout. The runner takes a checkout and an output directory, copies the
tree to a fresh directory, verifies the green baseline with the selected
test nodes, then for each arm applies exactly one mutation, runs the
narrowest discriminating node(s), restores and hash-verifies the pristine
source bytes, and classifies the arm from the pytest exit code.

Rules enforced here:

* every anchor must match exactly once on its reachable product file —
  zero matches or multiple matches is BAD, never SURVIVED;
* pytest runs under ``python -I -B`` with the mutant checkout inserted at
  ``sys.path[0]``, ``s19_app.__file__`` printed, stdin closed,
  ``PYTHONDONTWRITEBYTECODE=1`` and HOME/XDG/LOCALAPPDATA isolated under
  ``zq_iso_user``;
* the real worktree is never mutated — only ``<out>/tree`` is touched;
* one transcript per arm plus a machine-readable ``summary.json``.

Usage (Linux orchestrator):

    python mutation_runner.py <checkout> <outdir> [--python /path/to/python]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

#: The two reachable product files the arms mutate, as repo-relative paths.
APP = "s19_app/tui/app.py"
UTILS = "s19_app/utils.py"

#: Narrowest discriminating node prefixes.
TT = "tests/test_b103_inc12_tag_table.py::"
DT = "tests/test_tui_a2l_detail.py::"

#: The minimum table from the E5 handoff has exactly this many product arms.
EXPECTED_PRODUCT_ARMS = 20


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
#: minimum table and is not counted in ``EXPECTED_PRODUCT_ARMS``.
CONTROL = {
    "id": "CONTROL-KILL",
    "req": "CONTROL — address must render (known-bad; must be KILLED)",
    "file": APP,
    "anchor": '        addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"',
    "mutation": '        addr_text = "n/a"',
    "tests": [TT + "test_r_tui_042a_4_1_address_length_whole_unscrolled"],
}


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def classify(rc: int) -> str:
    """Map a pytest exit code to KILLED / SURVIVED / CRASH / BAD."""
    return {0: "SURVIVED", 1: "KILLED", 2: "BAD", 3: "CRASH", 4: "BAD", 5: "BAD"}.get(
        rc, "BAD"
    )


def copy_tree(checkout: Path, tree: Path) -> str:
    """Copy the integrated checkout into a fresh isolated directory.

    Prefer ``git clone --no-hardlinks`` when ``checkout`` is a repository so
    tracked-file tests that shell out to ``git ls-files`` keep working; fall
    back to a plain filesystem copy otherwise. The copy is a separate inode
    tree, so mutations never touch the real worktree.
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
        return "git-clone"
    shutil.copytree(checkout, tree)
    return "copytree"


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


def iso_env(iso: Path) -> dict:
    """Isolated environment: HOME/XDG/LOCALAPPDATA under ``zq_iso_user``."""
    env = os.environ.copy()
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
    out_path: Path,
) -> tuple[int, str]:
    """Run the given nodes under ``python -I -B`` and return (rc, stdout)."""
    cmd = [py, "-I", "-B", str(driver), "-p", "no:cacheprovider", "-q", *node_ids]
    proc = subprocess.run(
        cmd,
        cwd=str(tree),
        env=iso_env(iso),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out_path.write_text(proc.stdout, encoding="utf-8")
    return proc.returncode, proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description="Inc 12 E5 mutation runner")
    parser.add_argument("checkout", type=Path, help="integrated checkout (read-only)")
    parser.add_argument("outdir", type=Path, help="output directory (fresh)")
    parser.add_argument(
        "--python",
        type=str,
        default=os.environ.get("S19CI_PYTHON", sys.executable),
        help="Python interpreter used for pytest (default: S19CI_PYTHON or sys.executable)",
    )
    args = parser.parse_args()

    checkout = args.checkout.resolve()
    outdir = args.outdir.resolve()
    tree = outdir / "tree"
    iso = outdir / "zq_iso_user"
    transcripts = outdir / "transcripts"
    transcripts.mkdir(parents=True, exist_ok=True)

    # The minimum table must be complete before any run starts.
    product_ids = [arm["id"] for arm in ARMS]
    assert len(ARMS) == EXPECTED_PRODUCT_ARMS, (
        f"expected {EXPECTED_PRODUCT_ARMS} product arms, got {len(ARMS)}"
    )
    assert len(set(product_ids)) == len(product_ids), "duplicate arm ids"

    method = copy_tree(checkout, tree)
    print(f"tree copy method: {method}", flush=True)
    print(f"tree: {tree}", flush=True)

    driver = outdir / "driver.py"
    write_driver(tree, driver)

    # Pristine bytes of every mutated file, captured once from the copy.
    mutated_files = sorted({arm["file"] for arm in ARMS} | {CONTROL["file"]})
    pristine: dict[str, bytes] = {}
    for rel in mutated_files:
        path = tree / rel
        if not path.is_file():
            print(f"ABORT: reachable product file missing in tree: {rel}", flush=True)
            return 2
        pristine[rel] = path.read_bytes()

    def write_pristine(rel: str) -> None:
        (tree / rel).write_bytes(pristine[rel])

    def verify_pristine(rel: str, context: str) -> bool:
        ok = (tree / rel).read_bytes() == pristine[rel]
        if not ok:
            print(f"ABORT: {context}: {rel} does not match pristine bytes", flush=True)
        return ok

    all_nodes: list[str] = []
    for arm in ARMS:
        all_nodes.extend(arm["tests"])
    all_nodes.extend(CONTROL["tests"])
    all_nodes = sorted(set(all_nodes))

    # Baseline: the selected nodes must be green on the pristine copy.
    print("== baseline ==", flush=True)
    base_rc, _base_out = run_tests(
        args.python, driver, tree, iso, all_nodes, transcripts / "baseline.txt"
    )
    print(f"baseline rc={base_rc} ({classify(base_rc)})", flush=True)
    if base_rc != 0:
        print("ABORT: baseline not green; cannot trust any mutant verdict", flush=True)
        return 2

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
            rc, out = run_tests(
                args.python, driver, tree, iso, arm["tests"], transcripts / evidence
            )
            (transcripts / evidence).write_text(
                header + f"verdict: BAD (applied={applied})\n\n" + out, encoding="utf-8"
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
            results.append(record)
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

        rc, out = run_tests(
            args.python, driver, tree, iso, arm["tests"], transcripts / evidence
        )

        write_pristine(rel)
        restored_hash = sha256_bytes((tree / rel).read_bytes())
        assert restored_hash == sha256_bytes(pristine[rel]), f"{arm_id}: restore mismatch"

        verdict = classify(rc)
        (transcripts / evidence).write_text(
            header
            + f"mutated hash: {mut_hash}\n"
            + f"restored hash: {restored_hash}\n"
            + f"verdict: {verdict} (rc={rc})\n\n"
            + out,
            encoding="utf-8",
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
        results.append(record)
        print(f"{arm_id}: applied={applied} rc={rc} {verdict}", flush=True)
        return record

    # Control first: a green baseline alone is not proof.
    print("== control ==", flush=True)
    control_record = run_arm(CONTROL)
    if control_record["verdict"] != "KILLED":
        print(
            "ABORT: known-bad control arm was not KILLED; PASS results are not believed",
            flush=True,
        )
        return 2

    print("== arms ==", flush=True)
    for arm in ARMS:
        run_arm(arm)

    # Final: restore both files and prove the copied tree is byte-identical.
    for rel in mutated_files:
        write_pristine(rel)
        if not verify_pristine(rel, "final restore"):
            return 2

    counts: dict[str, int] = {}
    for rec in results:
        counts[rec["verdict"]] = counts.get(rec["verdict"], 0) + 1

    summary = {
        "checkout": str(checkout),
        "tree": str(tree),
        "copy_method": method,
        "python": args.python,
        "expected_product_arms": EXPECTED_PRODUCT_ARMS,
        "baseline": {"rc": base_rc, "verdict": classify(base_rc)},
        "control": control_record,
        "arms": results,
        "counts": counts,
        "pristine_sha256": {rel: sha256_bytes(pristine[rel]) for rel in mutated_files},
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
