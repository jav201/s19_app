"""Batch-95 counterfactual mutation runner (evidence/mutations-batch95).

Produces the RED mutation evidence for increments inc-002, inc-003b and
inc-003c of batch-95, in the spirit of ``tools/mutation_harness.py``:

* every anchor must match the target file EXACTLY once (0- or 2-match is a
  hard abort, never a red);
* the baseline is the FIXED tree: the targeted tests must be green BEFORE
  the mutation, RED under it, and green again after a byte-exact restore
  verified by SHA-256 (never ``git checkout`` — no git at all);
* matching is newline-agnostic (``core.autocrlf=true``) but the file is
  never rewritten into a different convention, so the byte-exact restore
  holds on both LF and CRLF working copies;
* pytest runs through ``subprocess`` with ``encoding="utf-8",
  errors="replace"`` — without it, cp1252 on this Windows host explodes on
  the emoji tooltips.

Usage::

    C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
        evidence/mutations-batch95/run_mutations.py
    ... --only INC002-M1            # run a single mutation
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent.parent
OUT_DIR = Path(__file__).resolve().parent
PY = r"C:/Users/jjgh8/anaconda3/envs/s19env/python.exe"


@dataclass(frozen=True)
class Mutation:
    """One byte-level substitution claimed to redden the targeted tests."""

    label: str
    increment: str
    finding: str
    path: str  # repo-relative
    anchor: str
    replacement: str
    targets: Tuple[str, ...]  # pytest selectors
    claim: str


_GATHER_SVC = "s19_app/tui/services/project_gather_service.py"
_FOLDER_SVC = "s19_app/tui/services/folder_open_service.py"
_WINDOW_HELP = "s19_app/tui/window_help.py"

MUTATIONS: Tuple[Mutation, ...] = (
    # ------------------------------------------------------------------ inc-002
    Mutation(
        label="INC002-M1",
        increment="inc-002 (4d6db31)",
        finding="LLR-138.4 snapshot refresh",
        path=_GATHER_SVC,
        anchor="            if destination.read_bytes() == source.read_bytes():",
        replacement="            if destination.read_bytes() != source.read_bytes():",
        targets=(
            "tests/test_project_gather.py::test_tc702_resave_refreshes_stale_copies",
        ),
        claim=(
            "inverting the drift compare makes a drifted destination SKIP the "
            "refresh (the stale bytes are kept and copy2 never runs) — "
            "TC-702's refreshed-bytes assertion must redden"
        ),
    ),
    Mutation(
        label="INC002-M2",
        increment="inc-002 (4d6db31)",
        finding="LLR-138.2 kind→home classification",
        path=_GATHER_SVC,
        anchor='    return PROJECT_CHECKS_DIR if kind == "check" else PROJECT_PATCHES_DIR',
        replacement='    return PROJECT_CHECKS_DIR if kind != "check" else PROJECT_PATCHES_DIR',
        targets=(
            "tests/test_project_gather.py::test_tc700_check_document_gathers_into_project_checks",
        ),
        claim=(
            "inverting the kind discriminator gathers a check document into "
            "patches/ — TC-700's checks-home census must redden"
        ),
    ),
    # ----------------------------------------------------------------- inc-003b
    Mutation(
        label="INC003B-M1",
        increment="inc-003b (59ee033)",
        finding="LLR-139.3 per-platform opener",
        path=_FOLDER_SVC,
        anchor='    if platform == "darwin":\n        return "open"',
        replacement='    if platform == "darwin":\n        return "explorer"',
        targets=(
            "tests/test_open_folder_chips.py::test_tc705_seam_popen_argv_list_per_platform_arm",
        ),
        claim=(
            "pointing the darwin arm at the Windows opener breaks the "
            "platform→opener table — TC-705's darwin arm must redden"
        ),
    ),
    Mutation(
        label="INC003B-M2",
        increment="inc-003b (59ee033)",
        finding="LLR-139.1 checks-family COMMON home",
        path=_FOLDER_SVC,
        anchor="        return _FAMILY_SUBDIR[family], workarea / WORKAREA_PATCHES",
        replacement='        return _FAMILY_SUBDIR[family], workarea / "checks"',
        targets=(
            "tests/test_open_folder_chips.py::test_tc703_checks_chip_resolves_check_artifact_home_both_modes",
        ),
        claim=(
            "a no-project Checks chip pointed at a (nonexistent) COMMON "
            "checks/ home instead of the contracted workarea/patches — "
            "TC-703's no-project arm must redden"
        ),
    ),
    # ----------------------------------------------------------------- inc-003c
    Mutation(
        label="INC003C-M1",
        increment="inc-003c (e460ffb)",
        finding="LLR-140.2 generated N. numbering",
        path=_WINDOW_HELP,
        anchor='        f"{number}. {step}" for number, step in enumerate(steps, start=1)',
        replacement='        f"{number}) {step}" for number, step in enumerate(steps, start=1)',
        targets=(
            "tests/test_window_usage_help.py::test_tc707_numbering_generated_sequential",
            "tests/test_window_usage_help.py::test_tc707_boundary_no_orphan_seats_no_blank_modal",
        ),
        claim=(
            "rendering the generated numbering with ')' instead of '. ' "
            "breaks the numbered-steps voice — TC-707's sequential-numbering "
            "assertion (and the '1. ' boundary) must redden"
        ),
    ),
    Mutation(
        label="INC003C-M2",
        increment="inc-003c (e460ffb)",
        finding="LLR-140.1 markup=False verbatim render",
        path=_WINDOW_HELP,
        anchor="                markup=False,",
        replacement="                markup=True,",
        targets=(
            "tests/test_window_usage_help.py::test_tc706_affordance_opens_window_section_modal",
        ),
        claim=(
            "turning Rich markup parsing ON lets **/backtick metacharacters "
            "in the operator copy be interpreted — TC-706's markup_off "
            "assertion (8/8 windows) must redden"
        ),
    ),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _encode_for(source: bytes, text: str) -> bytes:
    """Newline-agnostic anchor encoding (mutation_harness.py idiom)."""
    encoded = text.encode("utf-8")
    if b"\r\n" in source and b"\r\n" not in encoded:
        return encoded.replace(b"\n", b"\r\n")
    return encoded


def _run_pytest(targets: Sequence[str]) -> Tuple[int, str]:
    """Run the targeted tests; UTF-8 with replacement (cp1252 safety)."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        [PY, "-m", "pytest", *targets, "-q", "-p", "no:cacheprovider"],
        cwd=REPO,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=600,
    )
    return proc.returncode, proc.stdout + ("\n--- stderr ---\n" + proc.stderr if proc.stderr else "")


def _substitute(target: Path, anchor: str, replacement: str) -> bytes:
    source = target.read_bytes()
    encoded = _encode_for(source, anchor)
    count = source.count(encoded)
    if count != 1:
        raise SystemExit(
            f"ABORT: anchor matched {count} time(s) in {target.name}, "
            f"expected exactly 1.\nanchor: {anchor!r}"
        )
    target.write_bytes(source.replace(encoded, _encode_for(source, replacement)))
    return source


def run_mutation(mutation: Mutation) -> dict:
    target = REPO / mutation.path
    report = {
        "label": mutation.label,
        "increment": mutation.increment,
        "finding": mutation.finding,
        "file": mutation.path,
        "anchor": mutation.anchor,
        "replacement": mutation.replacement,
        "claim": mutation.claim,
        "command": (
            f"PYTHONUTF8=1 {PY} -m pytest {' '.join(mutation.targets)} "
            "-q -p no:cacheprovider"
        ),
    }

    # 0. Baseline on the fixed tree — a red baseline proves nothing.
    code, out = _run_pytest(mutation.targets)
    report["baseline"] = {"rc": code, "green": code == 0}
    if code != 0:
        report["verdict"] = "ABORT (baseline not green)"
        report["baseline_transcript"] = out
        return report

    # 1. Mutate (byte-level, anchor unique), capture the RED transcript.
    before_hash = _sha256(target)
    original = _substitute(target, mutation.anchor, mutation.replacement)
    report["sha256_before"] = before_hash
    try:
        red_code, red_out = _run_pytest(mutation.targets)
    finally:
        # 2. Restore immediately and verify byte-exactness by SHA-256.
        target.write_bytes(original)
        after_hash = _sha256(target)
    report["sha256_after_restore"] = after_hash
    report["restore_verified"] = after_hash == before_hash
    report["red_transcript"] = red_out
    report["red_rc"] = red_code
    report["red"] = red_code != 0

    # 3. Re-run on the restored tree — must be green again.
    green_code, green_out = _run_pytest(mutation.targets)
    report["green_rc"] = green_code
    report["green_transcript"] = green_out
    report["green_after_restore"] = green_code == 0

    if not report["restore_verified"]:
        report["verdict"] = "ABORT (restore failed — SHA mismatch)"
    elif not report["red"]:
        report["verdict"] = "INERT (mutant left every targeted test green)"
    elif not report["green_after_restore"]:
        report["verdict"] = "ABORT (not green after restore)"
    else:
        report["verdict"] = "RED (counterfactual confirmed)"
    return report


def _write_transcript(report: dict) -> Path:
    path = OUT_DIR / f"{report['label'].lower().replace('-', '_')}.txt"
    lines: List[str] = []
    lines.append(f"# Mutation {report['label']} — {report['increment']}")
    lines.append(f"# Finding: {report['finding']}")
    lines.append(f"# File: {report['file']}")
    lines.append("# Anchor (must match exactly once):")
    lines.append(report["anchor"])
    lines.append("# Replacement:")
    lines.append(report["replacement"])
    lines.append(f"# Claim: {report['claim']}")
    lines.append(f"# Command: {report['command']}")
    lines.append(f"# sha256 before mutation: {report['sha256_before']}")
    lines.append(f"# sha256 after restore:   {report.get('sha256_after_restore', 'n/a')}")
    lines.append(f"# restore verified: {report.get('restore_verified', 'n/a')}")
    lines.append(f"# VERDICT: {report['verdict']}")
    lines.append("")
    lines.append("=" * 78)
    lines.append("BASELINE (fixed tree) transcript:")
    lines.append("=" * 78)
    lines.append(report.get("baseline_transcript", "(green — see summary)"))
    lines.append("")
    lines.append("=" * 78)
    lines.append("MUTATED (RED expected) transcript:")
    lines.append("=" * 78)
    lines.append(report.get("red_transcript", "(not run)"))
    lines.append("")
    lines.append("=" * 78)
    lines.append("RESTORED (green expected) transcript:")
    lines.append("=" * 78)
    lines.append(report.get("green_transcript", "(not run)"))
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default=None, help="run one mutation by label")
    args = parser.parse_args()

    selected = [m for m in MUTATIONS if args.only in (None, m.label)]
    if not selected:
        raise SystemExit(f"no mutation labelled {args.only!r}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ok = True
    for mutation in selected:
        print(f"\n=== {mutation.label} · {mutation.path} ===")
        report = run_mutation(mutation)
        transcript = _write_transcript(report)
        print(f"  verdict: {report['verdict']}")
        print(f"  transcript: {transcript}")
        ok &= report["verdict"].startswith("RED")
    print("\n" + ("ALL MUTANTS RED" if ok else "SOME MUTANTS NOT RED — see transcripts"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
