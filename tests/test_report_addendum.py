"""Batch-19 — DeclaredRegion model (US-020c, LLR-024.1). TC-024.3.

Covers: inclusive ``[start,end]`` membership (distinct from CrcRegion's
half-open convention — architect-M1); per-field ValueError validation
(empty name / start<0 / start>end); and the security-F1 fold — the operator
``name`` is scrubbed (control/ANSI stripped) + length-capped at construction
via the shared ``_scrub_issue_message`` primitive.
"""

from __future__ import annotations

import pytest

from s19_app.tui.services.report_addendum import (
    DECLARED_REGION_NAME_MAX,
    DeclaredRegion,
)


def test_membership_is_inclusive_at_both_bounds() -> None:
    r = DeclaredRegion("cal", 0x1000, 0x10FF)
    assert r.contains(0x1000)  # inclusive start
    assert r.contains(0x10FF)  # inclusive end
    assert not r.contains(0x0FFF)
    assert not r.contains(0x1100)


def test_rejects_bad_bounds() -> None:
    with pytest.raises(ValueError):
        DeclaredRegion("x", 0x20, 0x10)  # start > end
    with pytest.raises(ValueError):
        DeclaredRegion("x", -1, 0x10)  # start < 0


def test_rejects_empty_or_control_only_name() -> None:
    with pytest.raises(ValueError):
        DeclaredRegion("", 0, 0x10)
    with pytest.raises(ValueError):
        # newline + ANSI only → scrubbed to "" → rejected
        DeclaredRegion("\n\t\x1b[31m", 0, 0x10)


def test_name_is_scrubbed_of_control_and_ansi() -> None:
    r = DeclaredRegion("cal\nMAP\x1b[31m!", 0, 0x10)
    assert "\n" not in r.name
    assert "\x1b" not in r.name
    assert "cal" in r.name and "MAP" in r.name


def test_name_is_length_capped() -> None:
    r = DeclaredRegion("A" * 200, 0, 0x10)
    assert len(r.name) <= DECLARED_REGION_NAME_MAX
