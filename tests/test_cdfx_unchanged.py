"""
Engine / data-processing-unchanged inspection check — s19_app batch-04, increment 9.

Implements TC-027 — the §5.6 inspection checklist as an **executable** test.
Batch-04 (the memory-field change kind + the unified change-set + selective
export) is contractually a *peer addition* inside ``s19_app/tui/cdfx/``: it
consumes the parsing / range / validation engine and the batch-03 CDFX writer
and resolver **read-only** and may not edit them (constraints C-1, C-2, C-3).
TC-027 is the inspection that proves the constraint held.

The checklist has two arms, each an executable assertion rather than a manual
read-through:

  1. **Engine / data-processing modules unchanged vs ``main``.** The parsing
     layer (``core.py``, ``hexfile.py``, ``tui/a2l.py``, ``tui/mac.py``), the
     range primitive (``range_index.py``) and the validation engine
     (``validation/``) all exist on the ``main`` baseline. This arm runs
     ``git diff --name-only main -- <those paths>`` and asserts the output is
     empty — batch-04 changed none of them. ``git diff`` is line-ending and
     ``__pycache__`` aware, so the verdict is robust to checkout noise.

  2. **The batch-03 ``cdfx/writer.py`` and ``cdfx/resolve.py`` are byte-unchanged
     vs their batch-03 state.** These two modules do **not** exist on the
     ``main`` baseline — they are batch-03 additions carried on this branch — so
     a ``git diff main`` cannot express "unchanged since batch-03". Instead this
     arm pins the SHA-256 of each module's source content to its batch-03 state.
     ``writer.py``'s pin is the exact hash the increment-7 packet recorded
     (``_WRITER_PY_SHA256`` in ``test_unified_export.py``); this test re-pins it
     so the byte-unchanged guard survives even if the increment-7 test is later
     refactored. The hash is over file *content*, so ``__pycache__`` noise
     cannot perturb it.

If a future batch genuinely needs to change one of these modules, the relevant
assertion fails **loud** and names the new hash — the change is never silent.
This is the corroborating inspection for LLR-004.2 (``UnifiedChangeSet``
composes, does not subclass) and LLR-009.2 (the UI holds no model / JSON logic):
those are verified at runtime by TC-026 / TC-032..034; TC-027 closes the
"the engine was not touched to make it work" half of the checklist.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

import s19_app


# ---------------------------------------------------------------------------
# Repo-root / git helpers.
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    """
    Summary:
        Resolve the repository root — the directory holding ``pyproject.toml``
        and the ``.git`` directory — by walking up from the installed
        ``s19_app`` package.

    Returns:
        Path: The absolute repository-root path.

    Raises:
        RuntimeError: If no ancestor of the ``s19_app`` package carries both a
            ``.git`` entry and a ``pyproject.toml`` — i.e. the test is running
            from an installed wheel detached from its source checkout.

    Data Flow:
        - Starts at ``s19_app.__file__``'s parent and walks upward until an
          ancestor has both ``.git`` and ``pyproject.toml``.

    Dependencies:
        Used by:
            - _git_diff_name_only
            - the byte-unchanged hash-pin test.
    """
    here = Path(s19_app.__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists() and (
            candidate / "pyproject.toml"
        ).exists():
            return candidate
    raise RuntimeError(
        "could not locate the repository root from the s19_app package — "
        "TC-027 needs the source checkout, not an installed wheel"
    )


def _git_diff_name_only(repo_root: Path, paths: list[str]) -> list[str]:
    """
    Summary:
        Run ``git diff --name-only main -- <paths>`` in the repo and return the
        list of changed files — the engine-unchanged check of TC-027.

    Args:
        repo_root (Path): The repository root the ``git`` command runs in.
        paths (list[str]): The repo-relative paths to diff against ``main``.

    Returns:
        list[str]: The repo-relative paths ``git`` reports as changed vs
        ``main`` — empty when none of ``paths`` differ from the baseline.

    Raises:
        None: A non-zero ``git`` exit (no ``main`` ref, not a checkout) is
            surfaced by the calling test as a skip, not an error — see
            :func:`test_tc027_engine_modules_unchanged_vs_main`.

    Data Flow:
        - Invokes ``git diff --name-only main -- <paths>`` via ``subprocess``
          with ``cwd=repo_root`` and splits the captured stdout into lines.

    Dependencies:
        Uses:
            - subprocess.run
        Used by:
            - test_tc027_engine_modules_unchanged_vs_main
    """
    completed = subprocess.run(
        ["git", "diff", "--name-only", "main", "--", *paths],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The engine / data-processing module set — the paths that must be unchanged
# vs ``main`` (constraints C-2 / C-3 / the increment-9 TC-027 specification).
# ---------------------------------------------------------------------------

_ENGINE_PATHS: list[str] = [
    "s19_app/core.py",
    "s19_app/hexfile.py",
    "s19_app/range_index.py",
    "s19_app/validation",
    "s19_app/tui/a2l.py",
    "s19_app/tui/mac.py",
]


# ---------------------------------------------------------------------------
# The batch-03 CDFX modules — byte-unchanged vs their batch-03 state. Pinned by
# content SHA-256: these two files do not exist on ``main`` (they are batch-03
# additions on this branch), so a ``git diff main`` cannot express "unchanged
# since batch-03". The writer hash is the increment-7 packet's pinned baseline.
# If a future batch deliberately changes one of these, update its hash here —
# the test fails loud and prints the new value, so the change is never silent.
# ---------------------------------------------------------------------------

_BATCH03_CDFX_HASHES: dict[str, str] = {
    "s19_app/tui/cdfx/writer.py": (
        "82d527c0d89e18e32c02b55a9132b1b31ec482b29f869229807dae77c9afe4ac"
    ),
    "s19_app/tui/cdfx/resolve.py": (
        "81db0237dee9d4d5960e6529bb077d0ec9b4df1087eaf2e1de9d41db0b0112b9"
    ),
}


# ---------------------------------------------------------------------------
# TC-027 — engine / data-processing modules unchanged vs ``main``
# ---------------------------------------------------------------------------


def test_tc027_engine_modules_unchanged_vs_main() -> None:
    """TC-027 — the parsing / range / validation engine is unchanged vs ``main``.

    Constraints C-2 / C-3 forbid batch-04 from editing the parsing layer
    (``core.py`` / ``hexfile.py`` / ``tui/a2l.py`` / ``tui/mac.py``), the range
    primitive (``range_index.py``) or the validation engine (``validation/``):
    batch-04 *consumes* them read-only. This runs ``git diff --name-only main``
    over exactly those paths and asserts the result is empty — so a single
    accidental edit to any engine module is caught at the increment boundary,
    not discovered later. ``git diff`` is line-ending / ``__pycache__`` aware,
    so the verdict is robust to checkout noise.
    """
    repo_root = _repo_root()
    try:
        changed = _git_diff_name_only(repo_root, _ENGINE_PATHS)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(
            "git is unavailable or the 'main' ref is missing in this "
            f"environment — TC-027's engine-unchanged arm cannot run: {exc}"
        )

    assert changed == [], (
        "batch-04 must not edit the parsing / range / validation engine "
        f"(constraints C-2 / C-3) — git reports these changed vs main: "
        f"{changed}"
    )


# ---------------------------------------------------------------------------
# TC-027 — the batch-03 CDFX writer / resolver are byte-unchanged
# ---------------------------------------------------------------------------


def test_tc027_batch03_cdfx_modules_are_byte_unchanged() -> None:
    """TC-027 — ``cdfx/writer.py`` and ``cdfx/resolve.py`` are byte-unchanged.

    Constraint C-1 forbids batch-04 from re-implementing, forking or editing the
    batch-03 CDFX writer or resolver — selective export must *reuse* them. These
    two modules are not on the ``main`` baseline, so a ``git diff main`` cannot
    express the constraint; instead this hashes each module's source content and
    asserts it matches the pinned batch-03 baseline. ``writer.py``'s pin is the
    exact hash the increment-7 packet recorded. Any accidental edit to either
    file is caught here; a *deliberate* future change must update the pin in
    ``_BATCH03_CDFX_HASHES`` — the test fails loud and prints the new hash, so
    the change is never silent.
    """
    repo_root = _repo_root()
    for rel_path, expected_hash in _BATCH03_CDFX_HASHES.items():
        module_path = repo_root / rel_path
        assert module_path.exists(), (
            f"{rel_path} is missing — TC-027 cannot verify it is unchanged"
        )
        actual_hash = hashlib.sha256(module_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        assert actual_hash == expected_hash, (
            f"{rel_path} changed since its batch-03 baseline — constraint C-1 "
            f"forbids editing the batch-03 CDFX writer / resolver. If the "
            f"change was deliberate, update _BATCH03_CDFX_HASHES["
            f"{rel_path!r}] to {actual_hash!r}."
        )
