"""
Engine / data-processing-unchanged inspection check — relocated at batch-07 E3b.

Implements TC-027's surviving arm as an **executable** test. The parsing /
range / validation engine is contractually consumed **read-only** by every
TUI-side batch (batch-04 constraints C-2 / C-3, re-affirmed by batch-07 §1.2:
"parser internals and the validation engine's rules are out of scope,
consumed read-only"). This test is the inspection that proves the constraint
held: it runs ``git diff --name-only main -- <engine paths>`` and asserts the
output is empty — the current branch changed none of them. ``git diff`` is
line-ending and ``__pycache__`` aware, so the verdict is robust to checkout
noise.

Relocated from ``tests/test_cdfx_unchanged.py`` (batch-04, increment 9) when
the ``cdfx/`` package retired at batch-07 E3b — the engine-untouched guard
outlives the cdfx flow it was written alongside (§6.6 disposition: SURVIVES;
batch acceptance §5.3 names this test as the standing engine read-only guard).
The sibling SHA-256 pin of ``cdfx/writer.py`` / ``cdfx/resolve.py`` retired
with those modules: the C-1 reuse constraint it guarded dissolved with the
retirement decision.

If a future batch genuinely needs to change an engine module, the assertion
fails **loud** and names the changed files — the change is never silent.
"""

from __future__ import annotations

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
            - test_tc027_engine_modules_unchanged_vs_main
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
# vs ``main`` (read-only-engine constraint, every TUI-side batch).
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
# TC-027 — engine / data-processing modules unchanged vs ``main``
# ---------------------------------------------------------------------------


def test_tc027_engine_modules_unchanged_vs_main() -> None:
    """TC-027 — the parsing / range / validation engine is unchanged vs ``main``.

    The read-only-engine constraint forbids TUI-side batches from editing the
    parsing layer (``core.py`` / ``hexfile.py`` / ``tui/a2l.py`` /
    ``tui/mac.py``), the range primitive (``range_index.py``) or the validation
    engine (``validation/``): they are *consumed* read-only. This runs
    ``git diff --name-only main`` over exactly those paths and asserts the
    result is empty — so a single accidental edit to any engine module is
    caught at the increment boundary, not discovered later. ``git diff`` is
    line-ending / ``__pycache__`` aware, so the verdict is robust to checkout
    noise.
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
        "TUI-side batches must not edit the parsing / range / validation "
        f"engine (read-only constraint) — git reports these changed vs main: "
        f"{changed}"
    )
