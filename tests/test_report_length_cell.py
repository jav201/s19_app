"""batch-76 Inc-2 — ``HLR-109``: an oversized ``Length`` does not deny the report.

⚠ **REACHABILITY, STATED PLAINLY AND NOT DRESSED UP.** This is **hardening, not a
live defect** (spec P-14, re-triaged to P3 on 2026-07-31). Both construction
sites take ``entry.addressed_range``, and ``ChangeEntry.addressed_range`` is
``(address, address + len(encoded_bytes))``, so ``end - start ==
len(encoded_bytes)`` **always**, bounded by ``MF_RUN_LENGTH_CEILING =
1 048 576`` -> **7 decimal digits against a 4 300 limit**. The backlog's original
headline ("a schema-legal ADDRESS denies the report") was FALSE — a huge address
renders in 45 characters — and the real raise is on ``Length``'s DECIMAL digits.

**The negative arm is constructor-only too** (``len(encoded_bytes) >= 0``), so
nothing in this file is a live wire arm. What IS reachable is the constructor
domain: both entry classes hold INDEPENDENT endpoints and have no
``__post_init__`` validation. The acceptances therefore drive
``generate_project_report`` — a shipped API that writes a real file — with
CONSTRUCTED results, and **no test here claims a change-document route**.

**Why the base tree is not the falsifier.** There these cases *error*, and an
error is not an assertion failure. Falsifiability is mutation on a copy of the
FIXED tree, recording the substituted expression — never "drop the 0x", which
names three different mutants and cost batch-73 a false blocker.
"""

from __future__ import annotations

import ast
import inspect
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence

import pytest

from s19_app.tui.changes.model import (
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunEntry,
    CheckRunResult,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services import report_service
from s19_app.tui.services.markdown_safety import MD_ESCAPE
from s19_app.tui.services.report_service import (
    REPORT_ADDRESS_TRUNCATION_CUE_FMT,
    REPORT_LENGTH_HEX_DIGITS,
    ReportOptions,
    _decimal_width_upper_bound,
    _format_length,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult

_INSTANT = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# The ORACLE. Derived independently of the product, by a different method.
# ---------------------------------------------------------------------------


def _expected_token(value: int) -> str:
    """Derive the expected shortened token WITHOUT calling product code.

    The product obtains its kept digits by an arithmetic SHIFT; this derives
    them by rendering the full hex string and SLICING it. Two different methods
    reaching the same token is what makes this an oracle rather than a mirror.

    Hex conversion is used deliberately: ``sys.get_int_max_str_digits()`` limits
    DECIMAL conversion only, so ``f"{n:X}"`` is safe at any magnitude and the
    oracle needs no limit juggling to compute it.
    """
    magnitude = -value if value < 0 else value
    sign = "-" if value < 0 else ""
    digits = f"{magnitude:X}"
    if len(digits) <= REPORT_LENGTH_HEX_DIGITS:
        return f"{sign}0x{digits.zfill(REPORT_LENGTH_HEX_DIGITS)}"
    kept = digits[:REPORT_LENGTH_HEX_DIGITS]
    dropped = len(digits) - REPORT_LENGTH_HEX_DIGITS
    return f"{sign}0x{kept}" + REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(dropped=dropped)


# ---------------------------------------------------------------------------
# Fixtures — CONSTRUCTOR domain, which is the only place these values live.
# ---------------------------------------------------------------------------


def _mod_result(vid: str, start: int, end: int) -> VariantExecutionResult:
    entry = ChangeSummaryEntry(
        entry_type="bytes",
        address_start=start,
        address_end=end,
        before_bytes=(0x10,),
        after_bytes=(0xA0,),
        disposition="applied",
        linkage="standalone",
        linkage_symbol=None,
    )
    summary = ChangeSummary(
        source_path=Path("chg.json"),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=vid,
        counts={"applied": 1},
        entries=[entry],
        issues=[],
    )
    return VariantExecutionResult(
        variant_id=vid, status="ok", change_summaries=[summary], check_results=[]
    )


def _check_result(vid: str, start: int, end: int) -> VariantExecutionResult:
    entry = CheckRunEntry(
        entry_type="bytes",
        address_start=start,
        address_end=end,
        expected_bytes=(0x20,),
        actual_bytes=(0x20,),
        result="pass",
        linkage="standalone",
        linkage_symbol=None,
        reason_code=None,
        reason=None,
    )
    check = CheckRunResult(
        source_path=Path("chk.json"),
        timestamp_utc="2026-07-31T11:00:00+00:00",
        variant_id=vid,
        aggregates={"passed": 1, "failed": 0, "uncheckable": 0},
        entries=[entry],
        issues=[],
    )
    # change_summaries asserted EMPTY, so the Modifications site cannot be the
    # one that produced the token this node observes.
    return VariantExecutionResult(
        variant_id=vid, status="ok", change_summaries=[], check_results=[check]
    )


def _render(tmp_path: Path, results: Sequence[VariantExecutionResult]) -> str:
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)
    variant_set = ProjectVariantSet(
        project_name="proj",
        variants=tuple(
            VariantDescriptor(
                variant_id=r.variant_id, path=Path(f"{r.variant_id}.s19"), file_type="s19"
            )
            for r in results
        ),
        active_id=results[0].variant_id,
    )
    path = generate_project_report(
        root,
        list(results),
        ReportOptions(),
        variant_set=variant_set,
        now_fn=lambda: _INSTANT,
    )
    return path.read_text(encoding="utf-8")


#: A length whose DECIMAL width is far past any admissible limit, but whose hex
#: form is cheap to derive. 2**16000 is ~4 816 decimal digits vs a 4 300 limit.
_HUGE = 2 ** 16000


# ---------------------------------------------------------------------------
# AT-257 / AT-258 — the two emission sites, accepted SEPARATELY (P-7).
# ---------------------------------------------------------------------------


def test_at257_modifications_length_cell_renders_and_is_unique(tmp_path: Path) -> None:
    """AT-257 — the Modifications ``Length`` cell equals the independent oracle.

    Also asserts the token occurs EXACTLY ONCE and that the Checklists section
    carries no Length row, so this node cannot be satisfied by the other site.

    Mutations: ``f"0x{leading:0{kept}X}"`` -> ``f"{leading:0{kept}X}"`` ·
    ``_format_length`` -> ``lambda v: "0"``.
    """
    text = _render(tmp_path, [_mod_result("v0", 0, _HUGE)])
    expected = _expected_token(_HUGE)

    assert expected in text, f"the Modifications Length cell is not {expected!r}"
    assert text.count(expected) == 1, (
        f"the token appears {text.count(expected)} times; it must be emitted once"
    )
    checklists = text.split("### Checklists")[1] if "### Checklists" in text else ""
    assert expected not in checklists, (
        "the token also appears under Checklists, so this node does not isolate "
        "the Modifications site"
    )


def test_at258_checklist_length_cell_renders_and_is_unique(tmp_path: Path) -> None:
    """AT-258 — the same, at the Checklists site, with ``change_summaries`` EMPTY.

    Emptying change_summaries is what makes the two sites independently
    accepted (P-7): the Modifications producer cannot have emitted this token.
    """
    result = _check_result("v0", 0, _HUGE)
    assert result.change_summaries == [], "the fixture does not isolate the Checklists site"
    text = _render(tmp_path, [result])
    expected = _expected_token(_HUGE)

    assert expected in text, f"the Checklists Length cell is not {expected!r}"
    assert text.count(expected) == 1


def test_at259_negative_length_renders_with_its_sign(tmp_path: Path) -> None:
    """AT-259 — a huge NEGATIVE length keeps its sign.

    Mutation: ``f"-0x{abs(value):X}"`` -> ``f"0x{abs(value):X}"`` (i.e. dropping
    ``sign`` from the shortened return).

    ⚠ Constructor-only, like the rest of this story: ``len(encoded_bytes) >= 0``
    on every shipped path, so a negative Length is not reachable through
    ingestion. Stated rather than implied.
    """
    text = _render(tmp_path, [_mod_result("v0", 0, -_HUGE)])
    expected = _expected_token(-_HUGE)

    assert expected.startswith("-0x"), "the oracle itself lost the sign"
    assert f"| {expected} |" in text, "the negative Length rendered without its sign"
    # A positive rendering of the same magnitude must NOT appear. Compared as a
    # CELL, not as a bare token: "-0xFFF..." CONTAINS "0xFFF...", so a plain
    # substring check is satisfied by the correct output and discriminates
    # nothing -- it would false-pass, which is worse than false-failing.
    assert f"| {_expected_token(_HUGE)} |" not in text, (
        "a positive rendering of the same magnitude is present — the sign was "
        "dropped somewhere"
    )


# ---------------------------------------------------------------------------
# TC-562 / TC-563 — the call-site census and its positive control.
# ---------------------------------------------------------------------------


def _inline_length_fstrings(source: str) -> List[int]:
    """Line numbers of any f-string still computing a Length inline."""
    tree = ast.parse(source)
    found: List[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FormattedValue):
            continue
        expr = node.value
        if (
            isinstance(expr, ast.BinOp)
            and isinstance(expr.op, ast.Sub)
            and isinstance(expr.left, ast.Attribute)
            and expr.left.attr == "address_end"
            and isinstance(expr.right, ast.Attribute)
            and expr.right.attr == "address_start"
        ):
            found.append(node.lineno)
    return found


def test_tc562_no_inline_length_arithmetic_survives_in_an_fstring() -> None:
    """TC-562 — LLR-109.5: both producers route through the formatter.

    The census asserts an ABSENCE, which is why TC-563 exists: a walk that finds
    nothing because it is broken passes an emptiness check silently.
    """
    source = inspect.getsource(report_service)
    assert _inline_length_fstrings(source) == [], (
        "an inline `address_end - address_start` f-string survives; it will "
        "raise on a constructor-domain value"
    )
    # ...and the formatter really is called at BOTH sites, not just once.
    assert source.count("_format_length(entry.address_end - entry.address_start)") == 2


def test_tc563_the_inline_census_walk_finds_a_planted_fstring() -> None:
    """TC-563 — positive control for TC-562 (Phase-2 M-3)."""
    planted = 'x = f"| {entry.address_end - entry.address_start} |"\n'
    assert _inline_length_fstrings(planted), (
        "the census walk is broken — it cannot see a planted inline Length"
    )


# ---------------------------------------------------------------------------
# TC-564 — the C-39 node. The boundary is EXECUTED, never typed.
# ---------------------------------------------------------------------------


@pytest.fixture()
def narrowed_limit():
    """Shrink the interpreter's decimal limit, restoring it in ``finally``.

    ⚠ Process-global: this must not run in parallel with anything that renders a
    wide integer.
    """
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(1000)
    try:
        yield 1000
    finally:
        sys.set_int_max_str_digits(original)


def test_tc564_the_shortening_boundary_tracks_the_live_limit(narrowed_limit) -> None:
    """TC-564 — the boundary follows ``sys.get_int_max_str_digits()``, not a literal.

    Under a limit of 1 000: a 1 001-digit value shortens and a 999-digit value
    does not. An implementation with a TYPED 4300 (or 3572) stays decimal in
    both arms and reddens here.
    """
    assert sys.get_int_max_str_digits() == 1000

    wide = 10 ** 1000       # 1 001 digits
    narrow = 10 ** 998      # 999 digits

    assert _format_length(wide).startswith("0x"), (
        "a 1 001-digit value did not shorten under a 1 000 limit — the boundary "
        "is not reading the live limit"
    )
    assert _format_length(narrow) == str(narrow), (
        "a 999-digit value shortened under a 1 000 limit — the bound is too tight"
    )


def test_tc576_a_disabled_limit_means_always_in_domain() -> None:
    """TC-576 — ``0`` disables the limit, so nothing shortens."""
    original = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        assert _format_length(10 ** 6000) == str(10 ** 6000)
    finally:
        sys.set_int_max_str_digits(original)


# ---------------------------------------------------------------------------
# TC-565 / TC-566 / TC-567 — the oracle, in-domain identity, and forgery.
# ---------------------------------------------------------------------------


def test_tc565_the_oracle_discriminates() -> None:
    """TC-565 — the oracle is not a mirror of the product.

    Its discriminating arm: two implementations the product could plausibly have
    (bare hex, and a constant) must NOT satisfy it.
    """
    expected = _expected_token(_HUGE)
    assert _format_length(_HUGE) == expected

    assert expected != f"{_HUGE:X}", "the oracle is satisfied by a bare hex rendering"
    assert expected != "0", "the oracle is satisfied by a constant"
    # regex membership is refused on purpose: ^-?0x[0-9A-F]+$ is satisfied by a
    # sign-dropping implementation, which is why AT-259 asserts equality.
    assert not expected.replace(" ", "").isalnum(), (
        "the token carries no cue, so a shortened cell is indistinguishable "
        "from a complete one"
    )


@pytest.mark.parametrize("value", [0, 1, -1, 4, -4, 1_048_576, -1_048_576])
def test_tc566_in_domain_values_render_decimally_and_keep_their_sign(value: int) -> None:
    """TC-566 — in-domain identity, including the in-domain NEGATIVE arm.

    ⚠ The negative half is UNFALSIFIABLE by mutation and that is recorded rather
    than hidden: an f-string preserves the sign unconditionally, so no
    substituted expression reddens it (Phase-2 m-3). It is kept as a PIN.

    The wire-reachable maximum, ``MF_RUN_LENGTH_CEILING = 1 048 576``, is in the
    set — this is the arm that actually ships.
    """
    assert _format_length(value) == str(value)
    assert _format_length(value) != f"0x{abs(value):X}", (
        "an in-domain value rendered as hex — every Length cell in the "
        "repository would drift, and AT-256 pins them"
    )


def test_tc567_a_shortened_token_cannot_be_read_as_a_complete_decimal() -> None:
    """TC-567 — the forgery counterexample, recorded with its value.

    For ``n = int('9' * L, 16)`` the kept digits are all ``9``s, so a bare hex
    rendering would be indistinguishable from a decimal number. The cue and the
    ``0x`` are what break that shape.
    """
    # ⚠ Sized to CROSS the limit, not merely to be wide. A first draft used
    # REPORT_LENGTH_HEX_DIGITS + 40 hex digits = ~67 DECIMAL digits, which is
    # far inside the 4 300 limit, so it rendered decimally and this node never
    # reached the branch it claims to test. 4 000 hex digits is ~4 818 decimal.
    length = 4000
    n = int("9" * length, 16)
    assert _decimal_width_upper_bound(n) > sys.get_int_max_str_digits(), (
        "the forgery fixture does not cross the limit — it cannot exercise the "
        "shortened branch"
    )
    token = _format_length(n)

    assert not token.lstrip("-").isdigit(), (
        f"the token {token!r} is all digits and forges a complete decimal value"
    )
    assert token.startswith("0x")
    assert "more hex digits" in token, "the token does not state what was elided"


def test_tc568_the_formatter_does_not_raise_where_str_would() -> None:
    """TC-568 — the whole point: no raise on a value ``str()`` refuses.

    A format-then-slice implementation still raises here, because the int->str
    conversion precedes the slice. That is the measured reason ``LLR-109.2``
    forbids capping the rendered width.
    """
    limit = sys.get_int_max_str_digits()
    hostile = 10 ** (limit + 5)

    with pytest.raises(ValueError):
        str(hostile)  # the defect being closed, shown live

    token = _format_length(hostile)  # must not raise
    assert token.startswith("0x")
    assert _format_length(-hostile).startswith("-0x")


def test_tc569_every_character_of_the_token_is_markdown_inert() -> None:
    """TC-569 — LLR-109.6: the WHOLE token, against the real ``MD_ESCAPE`` tuple.

    Revision 1 constrained only the cue, and separately named ``|`` — which is
    already ``MD_ESCAPE[2]``. Executed against the real tuple rather than a
    hand-maintained whitelist that could drift away from it.
    """
    assert MD_ESCAPE, "MD_ESCAPE is empty — this check would be vacuous"
    for value in (_HUGE, -_HUGE, int("9" * 64, 16)):
        token = _format_length(value)
        offenders = sorted({ch for ch in token if ch in MD_ESCAPE})
        assert not offenders, (
            f"{token!r} carries markdown-active characters {offenders} and is "
            f"emitted UNESCAPED into a table cell"
        )


def test_tc577_the_decimal_width_bound_never_understates() -> None:
    """TC-577 — the bound must OVER-estimate; an understatement admits the raise.

    Swept across magnitudes rather than spot-checked, because the failure mode
    is a single magnitude where the rational approximation rounds the wrong way.
    """
    for exponent in range(0, 2000, 37):
        value = 10 ** exponent
        actual = len(str(value))
        assert _decimal_width_upper_bound(value) >= actual, (
            f"bound understates at 10**{exponent}: "
            f"{_decimal_width_upper_bound(value)} < {actual}"
        )
