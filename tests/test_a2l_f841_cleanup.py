"""F841 cleanup — the dead ``header`` local is removed and the parse is unchanged.

Batch-50 (US-F841 / R-A2L-010). ``extract_a2l_tags`` previously bound
``header = header_meas or header_char`` and never read it (the walk uses
``header_meas`` / ``header_char`` directly, ``a2l.py`` :975/:981/:1055/:1058).
``ruff --select F841`` flagged exactly that line. Removing a dead store cannot
change behaviour, so this module pins BOTH halves of the requirement:

- **TC-094 (analysis):** ``ruff --select F841 s19_app/tui/a2l.py`` reports zero
  findings — the lint debt is actually gone, not merely moved.
- **AT-094 (behavioral parity):** parsing the real demo A2L still yields the same
  tag output through the exact code path around the deleted line — the
  ``header_meas``/``header_char`` propagation into MEASUREMENT/CHARACTERISTIC
  fields is intact. If the deletion had caught a live line, these diverge.

This file is a NON-frozen sibling on purpose: ``tests/test_tui_a2l.py`` is frozen
by TC-032 / C-27, so the batch's new test must not land there.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from s19_app.tui.a2l import parse_a2l_file

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO_A2L = _REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"


# ---------------------------------------------------------------------------
# TC-094 — the F841 debt is gone (analysis method, direct requirement check).
# ---------------------------------------------------------------------------


def test_tc094_no_f841_finding_in_a2l() -> None:
    """``ruff --select F841`` reports zero findings on ``a2l.py``.

    Intent: R-A2L-010's numeric threshold is ``0 errors`` (pre-state: 1). This
    runs ruff over the whole module — so it catches BOTH the removed ``header``
    store and any accidental new dead store the edit might introduce — and
    asserts a clean exit. It **skips** (does not fail) when ruff is not
    importable, so a runtime-only environment (e.g. the CI ``tui-ci`` job, which
    installs no dev tooling) reports honest non-execution rather than a spurious
    failure — ruff is exercised in dev / pre-commit where it is installed.
    """
    import importlib.util

    import pytest

    if importlib.util.find_spec("ruff") is None:
        pytest.skip("ruff is not installed in this environment (runtime-only)")

    completed = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--select", "F841",
         str(_REPO_ROOT / "s19_app" / "tui" / "a2l.py")],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, (
        "ruff --select F841 must report zero findings on a2l.py after the "
        f"dead-store removal; got:\n{completed.stdout}\n{completed.stderr}"
    )


# ---------------------------------------------------------------------------
# AT-094 — the dead-store removal is behaviour-preserving (through the surface).
# ---------------------------------------------------------------------------


def test_at094_demo_parse_stable_after_dead_store_removal() -> None:
    """Parsing the demo A2L is unchanged by removing the dead ``header`` local.

    Intent: the deleted line sat between the ``header_meas``/``header_char``
    binding and their direct use in the tag build. This drives the shipped
    ``parse_a2l_file`` over the real demo fixture and pins invariants that flow
    through exactly that neighbourhood — the total tag count, MEASUREMENT header
    propagation (datatype + derived length), and CHARACTERISTIC parsing. A live
    line caught by the delete would perturb at least one of these.

    Batch-54 update: the old comment here claimed the demo "should parse only one
    CHARACTERISTIC" (the pre-batch-54 multi-line-header limitation). That is now
    FALSE — multi-line header assembly lands all 50 CHARACTERISTICs. The
    structural counts below (75 tags, 25 MEAS, 50 CHAR) are unchanged; the
    ``ASAM.C.VIRTUAL.ASCII`` char_type/length pins survive but are now a *genuine*
    parse (pre-batch-54 they were a ``ASCII /* … */`` comment-token artifact —
    char_type ASCII by luck, deposit garbage; now deposit resolves correctly).
    The 1→50 delta assertion lives in ``tests/test_a2l_multiline_headers.py``.
    These remain regression sentinels for the dead-store removal.
    """
    data = parse_a2l_file(_DEMO_A2L)
    tags = data["tags"]

    # Structural sentinel — the walk still emits every tag it did before.
    assert len(tags) == 75

    measurements = [t for t in tags if t.get("section") == "MEASUREMENT"]
    characteristics = [t for t in tags if t.get("section") == "CHARACTERISTIC"]
    assert len(measurements) == 25
    assert len(characteristics) == 50

    # header_meas propagation intact: MEASUREMENT length derivation still fires.
    meas_with_length = [t for t in measurements if t.get("length") is not None]
    assert len(meas_with_length) == 24
    assert all(t.get("datatype") for t in meas_with_length)

    # header_char propagation intact: ASAM.C.VIRTUAL.ASCII keeps its char_type +
    # derived length. Post-batch-54 this is a genuine multi-line parse (its
    # deposit now resolves to RL.FNC.UBYTE.ROW_DIR instead of the pre-batch
    # comment-token garbage), while char_type/length are unchanged.
    ascii_char = next(t for t in characteristics if t.get("name") == "ASAM.C.VIRTUAL.ASCII")
    assert ascii_char.get("char_type") == "ASCII"
    assert ascii_char.get("length") == 100
    assert ascii_char.get("deposit") == "RL.FNC.UBYTE.ROW_DIR"
