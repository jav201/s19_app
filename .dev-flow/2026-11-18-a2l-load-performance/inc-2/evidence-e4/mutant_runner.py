"""Mutant runner for INC 2 E4 — every planned negative control as a real
source mutant in a copy of the tree; records KILLED / SURVIVED. Generated
evidence: output goes to mutant-run.txt beside this script. A replacement
whose anchor is missing is ANCHOR-MISSING and never a verdict.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SCRATCH = Path(sys.argv[1]) if len(sys.argv) > 1 else (
    Path(__import__("tempfile").gettempdir()) / "inc2-mutants"
)
TREE = SCRATCH / "tree"
PY = sys.executable
OUT = REPO / ".dev-flow/2026-11-18-a2l-load-performance/inc-2/evidence-e4/mutant-run.txt"

ATTACH = "tests/test_alp_inc2_a2l_attach.py"

FL = "s19_app/tui/app/file_load.py"
PICK = "s19_app/tui/a2l_parameter_picker.py"

# (name, file, [(old, new), ...], pytest -k expr)
MUTANTS = [
    # R-A2L-REFRESH.029/.033 negative: move one preparation call back to the
    # UI thread — the worker returns preparation=None and _on_a2l_attached
    # computes it on the UI thread.
    ("029-prep-on-ui", FL, [
        (
            "                preparation = self._prepare_a2l_attach_snapshot(\n"
            "                    a2l_path=path,\n"
            "                    a2l_data=entry[1],\n"
            "                    image_mem_map=request.image_mem_map,\n"
            "                    expected_a2l_generation=request.expected_a2l_generation,\n"
            "                    expected_image_generation=request.expected_image_generation,\n"
            "                )",
            "                preparation = None",
        ),
        (
            "        self.call_after_refresh(self._install_attached_a2l, result)",
            "        if result.preparation is None:\n"
            "            req = result.request\n"
            "            preparation = self._prepare_a2l_attach_snapshot(\n"
            "                a2l_path=result.path,\n"
            "                a2l_data=result.entry[1],\n"
            "                image_mem_map=req.image_mem_map,\n"
            "                expected_a2l_generation=req.expected_a2l_generation,\n"
            "                expected_image_generation=req.expected_image_generation,\n"
            "            )\n"
            "            result = A2LAttachResult(\n"
            "                req, result.path, result.entry, result.parse_seconds,\n"
            "                preparation=preparation,\n"
            "            )\n"
            "        self.call_after_refresh(self._install_attached_a2l, result)",
        ),
    ], "029 and typed"),
    # R-A2L-REFRESH.033 negative: the same UI-thread preparation mutant
    # against the key-latency arm (held enrichment no longer runs off UI).
    ("033-prep-on-ui", FL, [
        (
            "                preparation = self._prepare_a2l_attach_snapshot(\n"
            "                    a2l_path=path,\n"
            "                    a2l_data=entry[1],\n"
            "                    image_mem_map=request.image_mem_map,\n"
            "                    expected_a2l_generation=request.expected_a2l_generation,\n"
            "                    expected_image_generation=request.expected_image_generation,\n"
            "                )",
            "                preparation = None",
        ),
        (
            "        self.call_after_refresh(self._install_attached_a2l, result)",
            "        if result.preparation is None:\n"
            "            req = result.request\n"
            "            preparation = self._prepare_a2l_attach_snapshot(\n"
            "                a2l_path=result.path,\n"
            "                a2l_data=result.entry[1],\n"
            "                image_mem_map=req.image_mem_map,\n"
            "                expected_a2l_generation=req.expected_a2l_generation,\n"
            "                expected_image_generation=req.expected_image_generation,\n"
            "            )\n"
            "            result = A2LAttachResult(\n"
            "                req, result.path, result.entry, result.parse_seconds,\n"
            "                preparation=preparation,\n"
            "            )\n"
            "        self.call_after_refresh(self._install_attached_a2l, result)",
        ),
    ], "033_key_latency and enrichment"),
    # R-A2L-REFRESH.030 negative: a forbidden session read in the worker/helper
    # (the census arm must list it).
    ("030-forbidden-read", FL, [
        (
            "        enriched, summary_lines = enrich_tags_and_render(\n"
            "            a2l_data,\n"
            "            image_mem_map,\n"
            "            max_tag_lines=500,\n"
            "        )",
            "        _ = self.current_a2l_data  # mutant: forbidden session read\n"
            "        enriched, summary_lines = enrich_tags_and_render(\n"
            "            a2l_data,\n"
            "            image_mem_map,\n"
            "            max_tag_lines=500,\n"
            "        )",
        ),
    ], "030_worker_input_census"),
    # R-A2L-REFRESH.030 negative (writable snapshot): drop the read-only
    # wrapper so container writes succeed.
    ("030-writable-mapping", FL, [
        (
            "                image_mem_map = MappingProxyType(dict(current_file.mem_map))",
            "                image_mem_map = dict(current_file.mem_map)",
        ),
    ], "030_request_isolation"),
    # R-A2L-REFRESH.031 negative: install only part of the snapshot.
    ("031-partial-install", FL, [
        (
            "            if preparation is not None:\n"
            "                self._a2l_enriched_key = preparation.enrichment_key\n"
            "                self._a2l_enriched_tags = list(preparation.enriched_tags)\n"
            "                self._a2l_summary_lines = list(preparation.summary_lines)\n"
            "                self._a2l_summary_start = 0\n"
            "                self._accepted_a2l_picker_snapshots = preparation.picker_snapshots",
            "            if preparation is not None:\n"
            "                self._a2l_summary_start = 0\n"
            "                self._accepted_a2l_picker_snapshots = preparation.picker_snapshots",
        ),
    ], "031_matching_snapshot_installs"),
    # R-A2L-REFRESH.032 negative: accept the stale result (preflight disabled).
    ("032-accept-stale", FL, [
        (
            "            if preparation is not None and (",
            "            if False and preparation is not None and (",
        ),
    ], "032_stale_direct_attach"),
    # R-A2L-REFRESH.034 negative: clear the progress line during the held
    # phase (end_busy dispatched from the worker before preparation).
    ("034-clear-progress", FL, [
        (
            "        gc.disable()\n"
            "        try:\n"
            "            try:\n"
            "                started = time.perf_counter()",
            "        gc.disable()\n"
            "        self.call_from_thread(self.end_busy, \"a2l_load\", request.gen, \"interrupted\")\n"
            "        try:\n"
            "            try:\n"
            "                started = time.perf_counter()",
        ),
    ], "034_progress_throughout and enrichment"),
    # R-A2L-REFRESH.035 negative: omit the common refresh.
    ("035-omit-refresh", FL, [
        (
            "            self._refresh_a2l_dependent_views()\n"
            "            view_elapsed = time.perf_counter() - view_started",
            "            # mutant: common refresh omitted\n"
            "            view_elapsed = time.perf_counter() - view_started",
        ),
    ], "035_refresh_before_success"),
    # R-A2L-REFRESH.036 negative: drop the installed cache before the
    # refresh so enrich_tags_and_render recomputes on main.
    ("036-drop-cache", FL, [
        (
            "                self._accepted_a2l_picker_snapshots = preparation.picker_snapshots\n"
            "            view_started = time.perf_counter()",
            "                self._accepted_a2l_picker_snapshots = preparation.picker_snapshots\n"
            "            self._a2l_enriched_key = None  # mutant: cache dropped pre-refresh\n"
            "            view_started = time.perf_counter()",
        ),
    ], "036_refresh_reuses_snapshot"),
    # R-A2L-REFRESH.037 negative: describe per population instead of
    # consuming the prepared map.
    ("037-always-describe", PICK, [
        (
            "        if prepared_definitions is not None:\n"
            "            definitions: Mapping[str, Definition] = prepared_definitions",
            "        if False and prepared_definitions is not None:\n"
            "            definitions: Mapping[str, Definition] = prepared_definitions",
        ),
    ], "037_picker_snapshot_reuse and initial"),
    # R-A2L-REFRESH.037 negative: share one describe between both pickers.
    ("037-shared-describe", FL, [
        (
            "        patch_definitions = describe_definitions(names, a2l_data)",
            "        patch_definitions = check_definitions  # mutant: shared",
        ),
    ], "037_picker_snapshot_reuse and initial"),
    # R-A2L-REFRESH.038 negative: install a partial snapshot by swallowing the
    # enrichment failure instead of routing to the existing failure outcome.
    ("038-swallow-enrich-failure", FL, [
        (
            "        enriched, summary_lines = enrich_tags_and_render(\n"
            "            a2l_data,\n"
            "            image_mem_map,\n"
            "            max_tag_lines=500,\n"
            "        )",
            "        try:\n"
            "            enriched, summary_lines = enrich_tags_and_render(\n"
            "                a2l_data,\n"
            "                image_mem_map,\n"
            "                max_tag_lines=500,\n"
            "            )\n"
            "        except ValueError:\n"
            "            enriched, summary_lines = [], []",
        ),
    ], "038_preparation_failure and enrichment"),
    # R-A2L-REFRESH.038 negative: suppress the existing Workarea Files refresh.
    ("038-suppress-workarea-refresh", FL, [
        (
            "        if request.copy:\n"
            "            self.refresh_files()\n"
            "        self._quit_pending = False",
            "        if request.copy:\n"
            "            pass  # mutant: Workarea Files refresh suppressed\n"
            "        self._quit_pending = False",
        ),
    ], "038_preparation_failure"),
]


def prepare_tree() -> None:
    if TREE.exists():
        shutil.rmtree(TREE)
    TREE.mkdir(parents=True)
    for name in ("s19_app", "tests", "examples"):
        shutil.copytree(
            REPO / name, TREE / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    shutil.copy2(REPO / "pyproject.toml", TREE / "pyproject.toml")


def run_pytest(k: str, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(
        [PY, "-m", "pytest", "-p", "no:cacheprovider", "-q", ATTACH, "-k", k],
        cwd=TREE, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    tail = "\n".join(proc.stdout.strip().splitlines()[-3:])
    return proc.returncode, tail


def main() -> int:
    prepare_tree()
    pristine = {}
    for rel in (FL, PICK):
        pristine[rel] = (TREE / rel).read_text(encoding="utf-8")
    lines: list[str] = [
        "mutant-run: Inc 2 negative controls as source mutants; python "
        f"{sys.version.split()[0]}",
        "",
    ]
    for name, target, replacements, k in MUTANTS:
        text = pristine[target]
        missing = []
        for old, new in replacements:
            if old not in text:
                missing.append(old[:70])
                continue
            text = text.replace(old, new, 1)
        if missing:
            lines.append(f"{name}: ANCHOR-MISSING {missing}")
            continue
        (TREE / target).write_text(text, encoding="utf-8")
        try:
            code, tail = run_pytest(k)
        except subprocess.TimeoutExpired:
            lines.append(f"{name}: TIMEOUT (needs ruling)")
            continue
        verdict = "KILLED" if code != 0 else "SURVIVED"
        lines.append(f"{name}: {verdict} (exit {code}) target -k {k}")
        for tail_line in tail.splitlines():
            lines.append(f"    {tail_line}")
        lines.append("")
        (TREE / target).write_text(pristine[target], encoding="utf-8")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"TRANSCRIPT {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
