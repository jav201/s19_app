"""Flow Builder model tests — batch-51 Inc-1 keel (R-TUI-085/086/087).

Pure-data unit checks over ``flow_model`` for the new status tokens, the
``Finding`` advisory type, and the ``CheckBlock`` + gating vocabulary. No
Textual, no execution — the run-engine behaviour lives in
``test_flow_execution_service.py``.
"""

from __future__ import annotations

from s19_app.tui.services.flow_model import (
    BLOCK_CHECK,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    CHECK_GATING_ADVISORY,
    CHECK_GATING_BLOCK_OWN,
    FINDING_WARN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    BlockResult,
    CheckBlock,
    Finding,
)


# ===========================================================================
# TC-085.1 — Finding type + `notices` block status token (LLR-085.1)
# ===========================================================================


def test_tc085_1_finding_and_notices_token() -> None:
    """LLR-085.1: ``BLOCK_STATUS_NOTICES``/``Finding``/``FINDING_WARN`` exist,
    a ``Finding`` round-trips its fields, and ``BlockResult.findings`` defaults
    to an empty list without disturbing the existing invariant.

    Intent: the advisory WARN channel is a distinct, additive carrier — a
    notices token separate from ``ok``, and findings that default empty so a
    legacy ``BlockResult`` construction is unaffected.
    """
    assert BLOCK_STATUS_NOTICES == "notices"
    assert BLOCK_STATUS_NOTICES != BLOCK_STATUS_OK

    finding = Finding(FINDING_WARN, "bad checksum on line 2")
    assert finding.severity == FINDING_WARN
    assert finding.message == "bad checksum on line 2"

    # findings defaults empty (additive — legacy positional construction still works).
    result = BlockResult(0, "source", BLOCK_STATUS_OK)
    assert result.findings == []
    result.findings.append(finding)
    assert result.findings == [finding]


# ===========================================================================
# TC-086.1 — CheckBlock dataclass + gating vocabulary (LLR-086.1)
# ===========================================================================


def test_tc086_1_check_block_and_gating_vocab() -> None:
    """LLR-086.1: ``CheckBlock`` is a frozen block with a ``check_doc_ref``,
    an ``advisory``-default gating flag, and the ``check`` kind discriminator;
    both gating tokens are importable and distinct.

    Intent: the gating flag is a first-class per-block field (default
    advisory) so a flow author opts into ``block-own-op`` explicitly; the
    ``check`` kind is the batch-53 JSON-persistence tag.
    """
    assert BLOCK_CHECK == "check"
    assert CHECK_GATING_ADVISORY == "advisory"
    assert CHECK_GATING_BLOCK_OWN == "block-own-op"
    assert CHECK_GATING_ADVISORY != CHECK_GATING_BLOCK_OWN

    default = CheckBlock("checks.json")
    assert default.check_doc_ref == "checks.json"
    assert default.gating == CHECK_GATING_ADVISORY
    assert default.kind == BLOCK_CHECK

    gated = CheckBlock("checks.json", gating=CHECK_GATING_BLOCK_OWN)
    assert gated.gating == CHECK_GATING_BLOCK_OWN
    assert gated.kind == "check"


def test_tc086_1_check_block_is_frozen() -> None:
    """LLR-086.1: ``CheckBlock`` is frozen (immutable) — mirrors the other
    blocks so a persisted flow cannot be mutated in place."""
    import dataclasses

    block = CheckBlock("checks.json")
    try:
        block.gating = CHECK_GATING_BLOCK_OWN  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:  # pragma: no cover - a mutable block would fail the immutability contract
        raise AssertionError("CheckBlock must be frozen")


# ===========================================================================
# TC-087.1 — completed-with-issues flow-status token (LLR-087.1)
# ===========================================================================


def test_tc087_1_flow_status_issues_token() -> None:
    """LLR-087.1: ``FLOW_STATUS_ISSUES`` is exactly ``"completed-with-issues"``
    and is distinct from both the clean and failed tokens.

    Intent: the amber outcome is a third, non-colliding status the roll-up and
    banner key on — ``"shipped with warnings"`` must never alias ``ok`` or
    ``error``.
    """
    assert FLOW_STATUS_ISSUES == "completed-with-issues"
    assert FLOW_STATUS_ISSUES != FLOW_STATUS_OK
    assert FLOW_STATUS_ISSUES != FLOW_STATUS_ERROR
