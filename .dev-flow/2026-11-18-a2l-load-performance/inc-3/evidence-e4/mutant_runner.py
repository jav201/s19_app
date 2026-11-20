"""Mutant runner for INC 3 E4 — the planned negative controls as real
source mutants in a tree copy; records KILLED / SURVIVED. Generated
evidence: mutant-run.txt beside this script.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SCRATCH = Path(sys.argv[1]) if len(sys.argv) > 1 else (
    Path(__import__("tempfile").gettempdir()) / "inc3-mutants"
)
TREE = SCRATCH / "tree"
PY = sys.executable
OUT = REPO / ".dev-flow/2026-11-18-a2l-load-performance/inc-3/evidence-e4/mutant-run.txt"

PARITY = "tests/test_alp_inc3_snapshot_parity.py"
PERF = "tests/test_alp_inc3_load_responsiveness.py"

FL = "s19_app/tui/app/file_load.py"
PL = "s19_app/tui/app/project_load.py"
LS = "s19_app/tui/app/loaded_state.py"

MUTANTS = [
    # R-A2L-REFRESH.039 negative: bypass the producer and enrich directly.
    ("039-bypass-producer", FL, [
        (
            "            preparation = self._prepare_a2l_attach_snapshot(\n"
            "                a2l_path=loaded.a2l_path or loaded.path,\n"
            "                a2l_data=a2l_data,\n"
            "                image_mem_map=loaded.mem_map,\n"
            "                expected_a2l_generation=a2l_view_generation,\n"
            "                expected_image_generation=image_generation,\n"
            "            )",
            "            a2l_preparation = None\n"
            "            enriched_tags, summary_lines = enrich_tags_and_render(\n"
            "                a2l_data,\n"
            "                loaded.mem_map,\n"
            "                max_tag_lines=500,\n"
            "            )\n"
            "            a2l_enriched_tags = list(enriched_tags)\n"
            "            a2l_summary_lines = list(summary_lines)\n"
            "            a2l_enriched_key = (\n"
            "                a2l_view_generation,\n"
            "                image_generation,\n"
            "                len(loaded.mem_map) if loaded.mem_map is not None else -1,\n"
            "            )",
        ),
        (
            "            a2l_preparation = preparation\n"
            "            a2l_enriched_tags = list(preparation.enriched_tags)\n"
            "            a2l_enriched_key = preparation.enrichment_key\n"
            "            a2l_summary_lines = list(preparation.summary_lines)",
            "            pass  # mutant: direct enrichment already installed",
        ),
    ], "039"),
    # R-A2L-REFRESH.040/.042 negative: preparation leaves the worker (bare
    # bundle; no producer call) — the timer/phase assertions go RED.
    ("040-prep-on-ui", FL, [
        (
            "                try:\n"
            "                    prepared = self._prepare_load_payload(\n"
            "                        loaded,\n"
            "                        a2l_view_generation=context.expected_a2l_generation,\n"
            "                        image_generation=context.expected_image_generation,\n"
            "                    )",
            "                try:\n"
            "                    prepared = PreparedLoad(loaded=loaded)",
        ),
    ], "040_image_post_parse_responsive"),
    # R-A2L-REFRESH.040/.042 negative: a responsive 105 s worker hold must
    # exceed the individual total-run bound.
    ("040-hold-105s", FL, [
        (
            "            prepare_started = time.perf_counter()",
            "            prepare_started = time.perf_counter()\n"
            "            import time as _time\n"
            "            _time.sleep(105.0)  # mutant: responsive worker hold",
        ),
    ], "040_image_post_parse_responsive"),
    # R-A2L-REFRESH.041 negative: leave bundles non-precomputed.
    ("041-non-precomputed", PL, [
        (
            "        if captured_a is not None and captured_i is not None:",
            "        if False and captured_a is not None and captured_i is not None:",
        ),
    ], "041_project_pair_post_parse_responsive"),
    # R-A2L-REFRESH.043 negative: restore the minimal PreparedLoad fallback.
    ("043-minimal-fallback", FL, [
        (
            "                except Exception as exc:\n"
            "                    if not gc.isenabled():\n"
            "                        gc.enable()\n"
            "                    self.logger.exception(\n"
            "                        \"Prepare load payload failed: %s\", exc\n"
            "                    )\n"
            "                    self.call_from_thread(\n"
            "                        self._handle_load_error, path, exc, gen\n"
            "                    )\n"
            "                    return",
            "                except Exception as exc:\n"
            "                    self.logger.exception(\n"
            "                        \"Prepare load payload failed; falling back: %s\", exc\n"
            "                    )\n"
            "                    prepared = PreparedLoad(loaded=loaded)",
        ),
    ], "043_preparation_failure"),
    # R-A2L-REFRESH.044 negative: publish a second time on the image route.
    ("044-publish-twice", LS, [
        (
            "        if publish_a2l:\n"
            "            self._refresh_a2l_dependent_views()",
            "        if publish_a2l:\n"
            "            self._refresh_a2l_dependent_views()\n"
            "            self._refresh_a2l_dependent_views()  # mutant: second publication",
        ),
    ], "044_image_final_publication"),
    # R-A2L-REFRESH.045 negative: publish on reset.
    ("045-publish-on-reset", PL, [
        (
            "        try:\n"
            "            self._reset_project_session()",
            "        try:\n"
            "            self._reset_project_session()\n"
            "            self._refresh_a2l_dependent_views()  # mutant: reset publication",
        ),
    ], "045_project_final_publication"),
    # R-A2L-REFRESH.046 negative: skip the prepared A2L-only installation.
    ("046-skip-a2l-only-install", PL, [
        (
            "                if a2l_only is not None:\n"
            "                    # Inc 3 (I-ALP-2.3 / R-A2L-REFRESH.046): install the",
            "                if False and a2l_only is not None:\n"
            "                    # Inc 3 (I-ALP-2.3 / R-A2L-REFRESH.046): install the",
        ),
    ], "046_a2l_only_final_publication"),
    # R-A2L-REFRESH.047 negative: key preparation by path alone.
    ("047-path-keyed-reuse", FL, [
        (
            "class FileLoadMixin:",
            "_PATH_KEYED_A2L: dict = {}\n\n\nclass FileLoadMixin:",
        ),
        (
            "            a2l_path = context.a2l_files[0] if context.a2l_files else context.a2l_path\n"
            "            if a2l_path is not None:\n"
            "                entry = deps.parse_a2l_cached(a2l_path, context.a2l_cache)",
            "            a2l_path = context.a2l_files[0] if context.a2l_files else context.a2l_path\n"
            "            if a2l_path is not None and str(a2l_path) in _PATH_KEYED_A2L:\n"
            "                entry = _PATH_KEYED_A2L[str(a2l_path)]\n"
            "            elif a2l_path is not None:\n"
            "                entry = deps.parse_a2l_cached(a2l_path, context.a2l_cache)\n"
            "                _PATH_KEYED_A2L[str(a2l_path)] = entry",
        ),
    ], "047_same_path_changed_content and 047/1"),
    # R-A2L-REFRESH.048 negative: accept stale (preflight comparison
    # disabled for bundles and the A2L-only snapshot).
    ("048-accept-stale", PL, [
        (
            "            if actual != required:",
            "            if False and actual != required:",
        ),
        (
            "        if a2l_only is not None and (",
            "        if False and a2l_only is not None and (",
        ),
    ], "048_stale_snapshot_discard"),
    # R-A2L-REFRESH.048 negative: disable the L1 bundle preflight too (the
    # image-route arms reject there — both the agreement guard and the live
    # comparison).
    ("048-l1-accept-stale", LS, [
        (
            "            if preparation is not None and legacy_a2l is not None and (",
            "            if False and preparation is not None and legacy_a2l is not None and (",
        ),
        (
            "            if actual != expected:",
            "            if False and actual != expected:",
        ),
    ], "048_stale_snapshot_discard"),
    # R-A2L-REFRESH.048 negative: use captured rather than live counters.
    ("048-captured-not-live", PL, [
        (
            "        current_a = self._a2l_view_generation\n"
            "        current_i = self._image_generation",
            "        current_a = request.captured_a2l_generation  # mutant: captured\n"
            "        current_i = request.captured_image_generation",
        ),
    ], "048_stale_snapshot_discard and 048/9"),
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


def run_pytest(testfile: str, k: str, timeout: int = 1500) -> tuple[int, str]:
    proc = subprocess.run(
        [PY, "-m", "pytest", "-p", "no:cacheprovider", "-q", testfile, "-k", k],
        cwd=TREE, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    tail = "\n".join(proc.stdout.strip().splitlines()[-3:])
    return proc.returncode, tail


def main() -> int:
    prepare_tree()
    pristine = {}
    for rel in (FL, PL, LS):
        pristine[rel] = (TREE / rel).read_text(encoding="utf-8")
    lines: list[str] = [
        "mutant-run: Inc 3 negative controls as source mutants; python "
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
        testfile = PERF if k.startswith("04") and "post_parse" in k else PARITY
        try:
            code, tail = run_pytest(testfile, k)
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
