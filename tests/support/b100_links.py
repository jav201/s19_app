"""Junction helpers for batch-100 placement tests (enabler E1).

Windows directory junctions are created with ``_winapi.CreateJunction``,
which needs no elevated privilege (unlike symbolic links).  On every other
platform the helpers raise :class:`JunctionUnavailable`, and the tests that
need a junction skip with that named reason (PDR C-QA-6) — the skip itself
is counted in the increment packet.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import pytest


class JunctionUnavailable(Exception):
    """Raised when junction creation is requested off Windows."""


def junctions_available() -> bool:
    """True when this platform can create directory junctions."""
    return sys.platform == "win32"


def require_junctions() -> None:
    """Skip the calling test with a named reason when junctions are unavailable."""
    if not junctions_available():
        pytest.skip("directory junctions are a Windows-only test arm (PDR C-QA-6)")


def enable_case_sensitive(folder: Path) -> None:
    """Make the empty ``folder`` case-sensitive (``fsutil file
    setCaseSensitiveInfo``), so ``sub`` and ``SUB`` are two objects in it
    (Inc 7 corrective pass 2, SEC7-R2-1). Skips the calling test with a
    named reason when the flag cannot be set: off Windows, or where the
    Windows feature is unavailable."""
    if not junctions_available():
        pytest.skip("case-sensitive folders are a Windows-only test arm (PDR C-QA-6)")
    import subprocess

    result = subprocess.run(
        ["fsutil", "file", "setCaseSensitiveInfo", str(folder), "enable"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        pytest.skip(
            "fsutil setCaseSensitiveInfo is unavailable here: "
            + (result.stdout.strip() or result.stderr.strip())
        )


def create_junction(link: Path, target: Path) -> Path:
    """Create a directory junction at ``link`` pointing at ``target``.

    Summary:
        Thin wrapper over ``_winapi.CreateJunction`` so tests build the
        junction arms of TC-B100-62 without privilege elevation.  (The
        Windows API takes the arguments target-first; this helper keeps the
        conventional link-first order for the tests.)

    Args:
        link (Path): The junction path to create; must not exist.
        target (Path): An existing directory the junction resolves to.

    Returns:
        Path: ``link``, for chaining.

    Raises:
        JunctionUnavailable: On non-Windows platforms.
        OSError: When the Windows API rejects the creation.
    """
    if not junctions_available():
        raise JunctionUnavailable(
            f"cannot create junction {link} -> {target} off Windows"
        )
    import _winapi

    _winapi.CreateJunction(str(target), str(link))
    return link


def short_path_name(path: Path) -> Optional[Path]:
    """Return the 8.3 short-name spelling of ``path``, or None when the
    volume does not provide one (8.3 names disabled).

    Summary:
        Thin wrapper over ``GetShortPathNameW`` for the F8 short-name
        fallback arms: builds a destination whose ``.s19tool`` /
        ``workarea`` anchor survives only in a non-canonical spelling, a
        form the old resolve-first code accepted (review finding N4).

    Args:
        path (Path): An existing path on a volume that may carry 8.3 names.

    Returns:
        Optional[Path]: The short spelling when it differs from the given
            spelling and every component resolved; None otherwise (the
            caller then skips with this named reason).

    Raises:
        None.
    """
    if not junctions_available():
        return None
    import ctypes

    buffer = ctypes.create_unicode_buffer(512)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 512)
    if length == 0 or length >= 512:
        return None
    short = Path(buffer.value)
    if short == path:
        return None
    return short
