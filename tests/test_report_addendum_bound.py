"""batch-64 Inc-1 — acceptance + test nodes for R-TUI-098 / HLR-103 / LLR-103.x.

The declared-region report addendum (``report_service._addendum_lines``) is an
UNBOUNDED producer today: it materialises one fully-formatted string per
matching *(region x variant x entry/issue)* before any output exists, so no
output-side byte budget can reach it, and it re-reads the whole candidate set
once per declared region. Backlog item **D1**.

This module is authored at **Increment 1**, BEFORE the producer is touched
(C-12): the byte-identity golden is captured from the SHIPPED producer so it
cannot later certify the rewrite against itself.

Expected verdicts at Inc-1 (spec ``01-requirements.md`` §11.1) — 13 RED, 12
GREEN regression guards, 4 ``xfail(strict=True)``:

- **RED** (the asserted behaviour does not exist yet): ``AT-194``, ``AT-197``,
  ``AT-198[K_plus_1]``, ``AT-199``, ``AT-201``, ``AT-202``, ``AT-203``,
  ``TC-480``, ``TC-483``, ``TC-488``, ``TC-489``, ``TC-493`` here, plus
  ``AT-200`` in ``tests/test_tui_report_seam.py``.
- **GREEN regression guards** (the shipped producer already satisfies the
  predicate; their falsifiability is carried by the Inc-2 mutant arms named in
  §11.1): ``AT-196``, ``AT-198[le_K]``, ``AT-198[interior]``, ``TC-481``,
  ``TC-482``, ``TC-484``, ``TC-485``, ``TC-486``, ``TC-487``, ``TC-491``,
  ``TC-494``, ``TC-499``.
- **``xfail(strict=True)``** (subject does not exist on the base tree, so there
  is nothing to assert against): ``TC-490``, ``TC-492``, ``TC-495``, ``TC-498``.

Two mechanisms this module is required to use, both decided in the spec rather
than left to the author:

1. **No module-level import of the four new constants** (§11.1 note 4). They do
   not exist on the base tree, so a module-level import is a pytest COLLECTION
   error — which ``xfail`` does not cover and which would take down every node
   here, including the ones whose RED is meaningful. A RED produced by an
   ``ImportError`` is a vacuous RED. Every node reads its constants inside the
   test body through :func:`_const`. **Inc-2's gate deletes the fallbacks**
   (``rg -n "_const\\(" tests/test_report_addendum_bound.py`` -> 0 hits), so
   "an AT quotes the constant, never its value" holds from Inc-2 onward.
2. **Notice counting is ADDENDUM-SCOPED, and an empty scope FAILS** (§3
   US-B64-2, spec revision 3). The report carries three pre-existing
   ``> TRUNCATED:`` emitters (``report_service.py:1134`` / ``:1383`` /
   ``:1403``), so a report-wide grep is not an oracle. The addendum runs from
   its ``## Addendum: declared regions`` heading to the next ``^## `` **or
   END-OF-FILE** — it is the LAST ``## `` section on an ordinary report — and
   :func:`_addendum_scope` RAISES when the heading is missing or the scope is
   empty, so "no notice" can never be confused with "no scope".

Confidentiality (F-S-07): every fixture below is a synthetic in-memory object
graph written under ``tmp_path`` — never operator firmware, never a repo write.
"""

from __future__ import annotations

import inspect
import re
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

import pytest

from s19_app.tui.changes.model import (
    CHECK_AGGREGATE_KEYS,
    DISPOSITION_DOMAIN,
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunResult,
)
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services import report_service
from s19_app.tui.services.markdown_safety import md_safe
from s19_app.tui.services.report_addendum import (
    DECLARED_REGION_NAME_MAX,
    DeclaredRegion,
)
from s19_app.tui.services.report_service import (
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult
from s19_app.validation.model import ValidationIssue, ValidationSeverity

from conftest import canonical_report_bytes

# ---------------------------------------------------------------------------
# LLR-103.6 constants — read through _const, NEVER imported at module level
# ---------------------------------------------------------------------------

#: ``MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION`` fallback (§8.1). DELETED at Inc-2.
_K_FALLBACK = 200
#: ``ADDENDUM_CLASS_LABELS`` fallback, indexed by class ordinal. DELETED at Inc-2.
_LABELS_FALLBACK: Tuple[str, str, str] = (
    "modification",
    "change-file issue",
    "check-file issue",
)
#: ``ADDENDUM_NOTICE_VARIANTS_MAX`` fallback (§8.1). DELETED at Inc-2.
_VARIANTS_MAX_FALLBACK = 8
#: ``ADDENDUM_TRUNCATION_NOTICE_FMT`` fallback (§8.1). DELETED at Inc-2.
_NOTICE_FMT_FALLBACK = (
    "> TRUNCATED: {label} hits in this region were capped at {cap}; "
    "{dropped} more not listed (variants affected: {variants})."
)

#: Class ordinals (§8.1): the addendum's three hit classes, in producer order.
_CLASS_MODIFICATION = 0
_CLASS_CHANGE_ISSUE = 1
_CLASS_CHECK_ISSUE = 2

#: The named region-op seam ``TC-498`` reads (LLR-103.1, "The seam"). Inc-2
#: picks the module-level-int form; this name IS the pinned choice.
_REGION_OPS_SEAM = "_LAST_ADDENDUM_REGION_OPS"

#: The addendum's own ``## `` heading — the scope anchor (§3 US-B64-2).
_ADDENDUM_HEADING = "## Addendum: declared regions"

#: Fixed report clock, so a generated document is a deterministic artefact.
_FIXED_INSTANT = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)


def _const(name: str, fallback: object) -> object:
    """
    Summary:
        Read an ``LLR-103.6`` constant off the ``report_service`` MODULE
        OBJECT, falling back to the spec's pinned value while the constant
        does not exist (§11.1 note 4).

    Args:
        name (str): The constant's attribute name on ``report_service``.
        fallback (object): The §8.1 value used while the attribute is absent.

    Returns:
        object: The module constant when defined, else ``fallback``.

    Data Flow:
        - Every ``K``-derived or format-derived fixture in this module reads its
          constant through here, INSIDE the test body — never at import time,
          because a module-level import of a not-yet-existing name is a pytest
          collection error that ``xfail`` cannot cover.

    Dependencies:
        Uses:
            - s19_app.tui.services.report_service (the module object)
        Used by:
            - every ``K``-derived / notice-format node in this module

    Example:
        >>> _const("MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", 200)
        200
    """
    return getattr(report_service, name, fallback)


def _cap() -> int:
    """Return ``MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION`` (``K``)."""
    return int(_const("MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", _K_FALLBACK))


def _class_labels() -> Tuple[str, ...]:
    """Return ``ADDENDUM_CLASS_LABELS``, indexed by class ordinal."""
    return tuple(_const("ADDENDUM_CLASS_LABELS", _LABELS_FALLBACK))


def _variants_max() -> int:
    """Return ``ADDENDUM_NOTICE_VARIANTS_MAX``."""
    return int(_const("ADDENDUM_NOTICE_VARIANTS_MAX", _VARIANTS_MAX_FALLBACK))


def _notice_fmt() -> str:
    """Return ``ADDENDUM_TRUNCATION_NOTICE_FMT``."""
    return str(_const("ADDENDUM_TRUNCATION_NOTICE_FMT", _NOTICE_FMT_FALLBACK))


# ---------------------------------------------------------------------------
# Fixture builders — synthetic object graphs, never a parsed file
# ---------------------------------------------------------------------------


def _counts(applied: int = 0) -> Dict[str, int]:
    """Build a ``ChangeSummary.counts`` mapping over the disposition domain."""
    counts = {token: 0 for token in DISPOSITION_DOMAIN}
    counts["applied"] = applied
    return counts


def _aggregates() -> Dict[str, int]:
    """Build an all-zero ``CheckRunResult.aggregates`` mapping."""
    return {key: 0 for key in CHECK_AGGREGATE_KEYS}


def _entry(start: int) -> ChangeSummaryEntry:
    """Build one applied 1-byte ``ChangeSummaryEntry`` at ``start``."""
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=start,
        address_end=start + 1,
        before_bytes=(0x01,),
        after_bytes=(0xAA,),
        disposition="applied",
        linkage="standalone",
        linkage_symbol=None,
    )


def _issue(
    code: str,
    address: Optional[int],
    severity: ValidationSeverity = ValidationSeverity.ERROR,
) -> ValidationIssue:
    """Build one addressed ``ValidationIssue`` (``address=None`` is allowed)."""
    return ValidationIssue(
        code=code,
        severity=severity,
        message=f"{code} synthetic message",
        artifact="changes",
        address=address,
    )


def _summary(
    entries: Sequence[ChangeSummaryEntry] = (),
    issues: Sequence[ValidationIssue] = (),
    *,
    variant_id: Optional[str] = None,
    source: str = "chg.json",
) -> ChangeSummary:
    """Build a ``ChangeSummary`` carrying ``entries`` and ``issues``."""
    return ChangeSummary(
        source_path=Path(source),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-07-27T11:00:00+00:00",
        variant_id=variant_id,
        counts=_counts(len(entries)),
        entries=list(entries),
        issues=list(issues),
        saved_path=None,
    )


def _check(
    issues: Sequence[ValidationIssue] = (), *, source: str = "chk.json"
) -> CheckRunResult:
    """Build a ``CheckRunResult`` carrying ``issues`` and no entries."""
    return CheckRunResult(
        source_path=Path(source),
        timestamp_utc="2026-07-27T11:00:00+00:00",
        variant_id=None,
        aggregates=_aggregates(),
        entries=[],
        issues=list(issues),
    )


def _result(
    variant_id: str,
    summaries: Sequence[ChangeSummary] = (),
    checks: Sequence[CheckRunResult] = (),
) -> VariantExecutionResult:
    """Build one ``VariantExecutionResult`` for ``variant_id``."""
    return VariantExecutionResult(
        variant_id=variant_id,
        status="ok",
        change_summaries=list(summaries),
        check_results=list(checks),
    )


def _variant_set(*variant_ids: str) -> ProjectVariantSet:
    """Build the report's ``ProjectVariantSet`` inventory over ``variant_ids``."""
    descriptors = tuple(
        VariantDescriptor(
            variant_id=vid, path=Path(f"{vid}.s19"), file_type="s19"
        )
        for vid in variant_ids
    )
    return ProjectVariantSet(
        project_name="proj", variants=descriptors, active_id=variant_ids[0]
    )


# ---------------------------------------------------------------------------
# The A2/A3 attack fixture (§7 T-5) — one variant floods a class, two others
# each contribute one ERROR that the flood evicts
# ---------------------------------------------------------------------------

#: The single declared region every ``K``-boundary fixture uses.
_ATTACK_REGION = DeclaredRegion("calzone", 0x1000, 0x1FFF)

#: How many UNCUT ``modification``-class hits ``v1`` also contributes — the
#: class ``AT-201`` proves is never named.
_ATTACK_UNCUT_MODS = 3


def _attack_results(class_total: int) -> List[VariantExecutionResult]:
    """
    Summary:
        Build the batch-63 A2/A3 attack fixture at an EXACT ``change-file
        issue`` class total inside :data:`_ATTACK_REGION`: ``v1`` floods
        ``class_total - 2`` WARNING ``CHG-ADDRESS-SYNTAX`` issues, then ``v2``
        and ``v3`` each contribute one ERROR ``CHG-COLLISION``. ``v1`` also
        contributes :data:`_ATTACK_UNCUT_MODS` modification-class hits, which
        no cap touches.

    Args:
        class_total (int): The exact number of ``change-file issue`` candidates
            inside the region. Must be ``>= 2``.

    Returns:
        List[VariantExecutionResult]: ``[v1, v2, v3]`` in producer order — the
        order that decides which candidates are admitted first.

    Raises:
        ValueError: When ``class_total < 2`` (the two collisions would not fit).

    Data Flow:
        - The predicate under test keys on the CLASS TOTAL, never on the flood
          size (§7 T-5's executed trap: a flood of ``K-1`` still truncates once
          another variant contributes to the same class).
        - v1 is FIRST, so at ``class_total = K + n`` the first ``K`` admitted
          candidates are all v1's and the dropped ones are v2's and v3's.

    Dependencies:
        Uses:
            - _result / _summary / _issue / _entry
        Used by:
            - AT-197, AT-198, AT-199, AT-201, AT-202, TC-480..TC-483

    Example:
        >>> len(_attack_results(202))
        3
    """
    if class_total < 2:
        raise ValueError("class_total must leave room for the two collisions")
    flood = class_total - 2
    last = 0x1100 + flood - 1
    assert _ATTACK_REGION.contains(last), (
        f"_attack_results({class_total}): the flood overruns the declared region "
        f"at 0x{last:X} > 0x{_ATTACK_REGION.end:X}, so the builder would deliver "
        f"fewer candidates than it reports. A predicate must test what its label "
        f"claims: widen _ATTACK_REGION or lower class_total."
    )
    v1 = _result(
        "v1",
        [
            _summary(
                entries=[_entry(0x1000 + i) for i in range(_ATTACK_UNCUT_MODS)],
                issues=[
                    _issue(
                        "CHG-ADDRESS-SYNTAX",
                        0x1100 + i,
                        ValidationSeverity.WARNING,
                    )
                    for i in range(flood)
                ],
                variant_id="v1",
            )
        ],
    )
    v2 = _result(
        "v2", [_summary(issues=[_issue("CHG-COLLISION", 0x1500)], variant_id="v2")]
    )
    v3 = _result(
        "v3", [_summary(issues=[_issue("CHG-COLLISION", 0x1501)], variant_id="v3")]
    )
    return [v1, v2, v3]


def _class_candidates(
    results: Sequence[VariantExecutionResult],
    region: DeclaredRegion,
    hit_class: int,
) -> List[Tuple[str, int]]:
    """
    Summary:
        Replay the shipped traversal order and return ``(variant_id, address)``
        for every candidate of ``hit_class`` that falls inside ``region``.

    Args:
        results (Sequence[VariantExecutionResult]): The fixture, in producer
            order.
        region (DeclaredRegion): The region whose membership is tested.
        hit_class (int): Class ordinal — 0 modification, 1 change-file issue,
            2 check-file issue.

    Returns:
        List[Tuple[str, int]]: Candidates in the order the producer meets them.

    Data Flow:
        - This is the test's OWN derivation of what the notice must say. It is
          computed from the FIXTURE, never parsed out of the report, so a
          producer that names the wrong variants cannot also define the
          expectation (the ``AT-165`` failure mode).

    Dependencies:
        Uses:
            - DeclaredRegion.contains
        Used by:
            - _expected_cut

    Example:
        >>> _class_candidates([], DeclaredRegion("z", 0, 1), 0)
        []
    """
    found: List[Tuple[str, int]] = []
    for result in results:
        for summary in result.change_summaries:
            if hit_class == _CLASS_MODIFICATION:
                for entry in summary.entries:
                    if region.contains(entry.address_start):
                        found.append((result.variant_id, entry.address_start))
            elif hit_class == _CLASS_CHANGE_ISSUE:
                for issue in summary.issues:
                    if issue.address is not None and region.contains(issue.address):
                        found.append((result.variant_id, issue.address))
        if hit_class == _CLASS_CHECK_ISSUE:
            for check in result.check_results:
                for issue in check.issues:
                    if issue.address is not None and region.contains(issue.address):
                        found.append((result.variant_id, issue.address))
    return found


def _expected_cut(
    results: Sequence[VariantExecutionResult],
    region: DeclaredRegion,
    hit_class: int,
    cap: int,
) -> Tuple[int, int, List[str]]:
    """
    Summary:
        Derive, from the fixture alone, what a correct producer must disclose
        for one ``(region, class)``: the class total, the dropped count, and
        the sorted set of variants that lost AT LEAST ONE hit.

    Args:
        results (Sequence[VariantExecutionResult]): The fixture.
        region (DeclaredRegion): The region.
        hit_class (int): Class ordinal.
        cap (int): ``MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION``.

    Returns:
        Tuple[int, int, List[str]]: ``(class_total, dropped, dropped_variants)``.

    Data Flow:
        - first-``cap`` admission in traversal order -> the tail is dropped ->
          the dropped tail's distinct variant ids are exactly the set the
          notice may name. A variant that contributed and lost nothing is
          absent by construction, which is the ``AT-202`` predicate.

    Dependencies:
        Uses:
            - _class_candidates
        Used by:
            - AT-197, AT-201, AT-202, TC-490

    Example:
        >>> _expected_cut([], DeclaredRegion("z", 0, 1), 0, 200)
        (0, 0, [])
    """
    candidates = _class_candidates(results, region, hit_class)
    dropped = candidates[cap:]
    return len(candidates), len(dropped), sorted({vid for vid, _ in dropped})


# ---------------------------------------------------------------------------
# Addendum scope + notice parsing (§3 US-B64-2) — the oracle, not a grep
# ---------------------------------------------------------------------------


def _addendum_scope(text: str) -> str:
    """
    Summary:
        Return the addendum section of ``text`` — from its
        ``## Addendum: declared regions`` heading to the next ``^## `` heading
        **or END-OF-FILE, whichever comes first** — and FAIL when the heading
        is absent or the scope carries no content.

    Args:
        text (str): A whole report document (or the joined output of
            ``_addendum_lines``).

    Returns:
        str: The addendum section INCLUDING its heading line.

    Raises:
        AssertionError: When the heading is missing, or the scope holds nothing
            but blank lines. A predicate that cannot distinguish "no notice"
            from "no scope" is not an oracle (§3 US-B64-2, revision 3): the
            ``or EOF`` arm is load-bearing because the addendum is the LAST
            ``## `` section on an ordinary report, so a heading-to-next-``## ``
            reading finds NO scope and reads 0 notices on every report.

    Data Flow:
        - report text -> addendum span -> every notice/hit predicate in this
          module. Nothing here counts a line outside that span, so the three
          pre-existing ``> TRUNCATED:`` emitters (``report_service.py:1134`` /
          ``:1383`` / ``:1403``) cannot be mistaken for the addendum's notice.

    Dependencies:
        Uses:
            - _ADDENDUM_HEADING
        Used by:
            - every notice-counting and hit-counting node in this module

    Example:
        >>> _addendum_scope("## Addendum: declared regions\\n\\n### z\\nNone.\\n")
        '## Addendum: declared regions\\n\\n### z\\nNone.\\n'
    """
    start = text.find(_ADDENDUM_HEADING)
    assert start >= 0, (
        f"addendum scope: {_ADDENDUM_HEADING!r} not found — the document has no "
        f"addendum, so no notice predicate over it can mean anything"
    )
    body = text[start + len(_ADDENDUM_HEADING) :]
    following = re.search(r"^## ", body, re.M)
    scope = body if following is None else body[: following.start()]
    assert scope.strip(), (
        "addendum scope: the span from the addendum heading to the next '## ' "
        "or EOF is EMPTY — an empty scope must FAIL, never read as zero notices"
    )
    return _ADDENDUM_HEADING + scope


def _notice_prefix_re() -> "re.Pattern[str]":
    """
    Summary:
        Build the addendum-notice line matcher from
        ``ADDENDUM_TRUNCATION_NOTICE_FMT`` and ``ADDENDUM_CLASS_LABELS`` —
        never from a literal notice text.

    Args:
        None.

    Returns:
        re.Pattern[str]: A multiline pattern anchored at the start of a line,
        matching the notice's fixed prefix up to (not including) the cap value.

    Data Flow:
        - the two constants -> the pattern §3 US-B64-2 pins:
          ``^> TRUNCATED: (?:modification|change-file issue|check-file issue)
          hits in this region were capped at``.

    Dependencies:
        Uses:
            - _notice_fmt / _class_labels
        Used by:
            - _addendum_notices

    Example:
        >>> bool(_notice_prefix_re())
        True
    """
    fmt = _notice_fmt()
    head = fmt.split("{cap}")[0]
    before, _, after = head.partition("{label}")
    alternation = "|".join(re.escape(label) for label in _class_labels())
    return re.compile(
        "^" + re.escape(before) + f"(?:{alternation})" + re.escape(after.rstrip()),
        re.M,
    )


def _notice_full_re() -> "re.Pattern[str]":
    """
    Summary:
        Build the FULL notice matcher, with named groups for the class label,
        the cap, the dropped count, and the variant field — again derived from
        ``ADDENDUM_TRUNCATION_NOTICE_FMT``, never from a literal.

    Args:
        None.

    Returns:
        re.Pattern[str]: A multiline pattern with groups ``label`` / ``cap`` /
        ``dropped`` / ``variants``.

    Data Flow:
        - the format constant -> a regex whose placeholders are the only free
          text, so a producer that changes the prose without changing the
          constant is caught rather than accommodated.

    Dependencies:
        Uses:
            - _notice_fmt / _class_labels
        Used by:
            - _parsed_notices

    Example:
        >>> _notice_full_re().groupindex["dropped"] > 0
        True
    """
    pattern = re.escape(_notice_fmt())
    alternation = "|".join(re.escape(label) for label in _class_labels())
    pattern = pattern.replace(
        re.escape("{label}"), f"(?P<label>{alternation})"
    )
    pattern = pattern.replace(re.escape("{cap}"), r"(?P<cap>\d+)")
    pattern = pattern.replace(re.escape("{dropped}"), r"(?P<dropped>\d+)")
    pattern = pattern.replace(re.escape("{variants}"), r"(?P<variants>.*?)")
    return re.compile("^" + pattern + r"[ \t]*$", re.M)


def _addendum_notices(text: str) -> List[str]:
    """Return every addendum-scoped truncation-notice LINE in ``text``."""
    scope = _addendum_scope(text)
    prefix = _notice_prefix_re()
    return [line for line in scope.splitlines() if prefix.match(line)]


def _parsed_notices(text: str) -> List[Tuple[str, int, int, List[str]]]:
    """
    Summary:
        Parse every addendum-scoped notice into
        ``(label, cap, dropped, variants)``.

    Args:
        text (str): A whole report document.

    Returns:
        List[Tuple[str, int, int, List[str]]]: One tuple per notice, in
        document order. ``variants`` is the comma-separated field split and
        stripped — including a trailing ``+N more`` token when present.

    Data Flow:
        - addendum scope -> full-format regex -> the tuple ``AT-197`` /
          ``AT-201`` / ``AT-202`` assert on.

    Dependencies:
        Uses:
            - _addendum_scope / _notice_full_re
        Used by:
            - AT-197, AT-201, AT-202, AT-203, TC-490

    Example:
        >>> _parsed_notices("## Addendum: declared regions\\n\\nNone.\\n")
        []
    """
    scope = _addendum_scope(text)
    parsed: List[Tuple[str, int, int, List[str]]] = []
    for match in _notice_full_re().finditer(scope):
        field = match.group("variants")
        variants = [token.strip() for token in field.split(",") if token.strip()]
        parsed.append(
            (
                match.group("label"),
                int(match.group("cap")),
                int(match.group("dropped")),
                variants,
            )
        )
    return parsed


def _hit_lines(text: str) -> List[str]:
    """Return every addendum-scoped hit line (``- modification`` / ``- issue``)."""
    scope = _addendum_scope(text)
    return [line for line in scope.splitlines() if line.startswith("- ")]


def _issue_hit_lines(text: str) -> List[str]:
    """Return the addendum-scoped ``- issue [...]`` hit lines only."""
    return [line for line in _hit_lines(text) if line.startswith("- issue ")]


def _modification_hit_lines(text: str) -> List[str]:
    """Return the addendum-scoped ``- modification`` hit lines only."""
    return [line for line in _hit_lines(text) if line.startswith("- modification")]


def _region_heading(region: DeclaredRegion) -> str:
    """
    Summary:
        Render a region's ``### `` sub-heading exactly as ``_addendum_lines``
        does — through ``md_safe`` at ``DECLARED_REGION_NAME_MAX``.

    Args:
        region (DeclaredRegion): The declared region.

    Returns:
        str: The full sub-heading line.

    Data Flow:
        - A test that splits the addendum on the RAW region name finds no
          sub-section, and an "absent from every other region" half then passes
          VACUOUSLY (§3 ``QA-NEW-7``, executed: ``B_quiet`` renders
          ``### B\\_quiet``). Deriving the heading through ``md_safe`` is one of
          the two forms the spec permits; it is the one that survives a hostile
          region name.

    Dependencies:
        Uses:
            - md_safe / DECLARED_REGION_NAME_MAX
        Used by:
            - _region_subsection

    Example:
        >>> _region_heading(DeclaredRegion("zone a", 0x10, 0x1F))
        '### zone a (0x10-0x1F)'
    """
    name = md_safe(region.name, limit=DECLARED_REGION_NAME_MAX)
    return f"### {name} (0x{region.start:X}-0x{region.end:X})"


def _region_subsection(text: str, region: DeclaredRegion) -> str:
    """
    Summary:
        Return one region's ``### `` sub-section of the addendum, and FAIL when
        that sub-section is not found.

    Args:
        text (str): A whole report document.
        region (DeclaredRegion): The region whose sub-section is wanted.

    Returns:
        str: The sub-section text, from its ``### `` heading to the next
        ``^### `` or the end of the addendum scope.

    Raises:
        AssertionError: When the sub-heading is absent — asserted BEFORE any
        claim about the sub-section's contents (§3 ``QA-NEW-7``).

    Data Flow:
        - addendum scope -> md_safe-derived ``### `` heading -> the span
          ``AT-203`` reads for region attribution.

    Dependencies:
        Uses:
            - _addendum_scope / _region_heading
        Used by:
            - AT-203, TC-480

    Example:
        >>> _region_subsection(
        ...     "## Addendum: declared regions\\n\\n### z (0x0-0x1)\\nNone.\\n",
        ...     DeclaredRegion("z", 0, 1),
        ... ).startswith("### z")
        True
    """
    scope = _addendum_scope(text)
    heading = _region_heading(region)
    start = scope.find(heading)
    assert start >= 0, (
        f"region sub-section {heading!r} NOT FOUND in the addendum — assert the "
        f"sub-section exists before asserting anything about its contents"
    )
    body = scope[start + len(heading) :]
    following = re.search(r"^### ", body, re.M)
    return heading + (body if following is None else body[: following.start()])


# ---------------------------------------------------------------------------
# Report driving
# ---------------------------------------------------------------------------


def _write_report(
    root: Path,
    results: Sequence[VariantExecutionResult],
    regions: Sequence[DeclaredRegion],
    variant_ids: Sequence[str],
) -> Tuple[Path, str]:
    """
    Summary:
        Drive the shipped surface — ``generate_project_report`` with a
        non-empty ``options.declared_regions`` — under the fixed clock and
        return the written file and its text.

    Args:
        root (Path): The project work area (per-test ``tmp_path`` subdirectory).
        results (Sequence[VariantExecutionResult]): The fixture.
        regions (Sequence[DeclaredRegion]): The declared regions, in caller
            order (which is the addendum's sub-section order).
        variant_ids (Sequence[str]): The inventory ids, in order.

    Returns:
        Tuple[Path, str]: The written report path and its decoded text.

    Raises:
        AssertionError: When the report file does not exist or is empty — §3's
        Deliverable clause: "An AT that produced no file fails".

    Data Flow:
        - fixture -> real generate_project_report -> report file on disk ->
          text every Layer-B node reads. No Layer-B node in this module
          inspects a private symbol.

    Dependencies:
        Uses:
            - generate_project_report / ReportOptions / _variant_set
        Used by:
            - AT-194, AT-196..AT-199, AT-201..AT-203, TC-480, TC-485, TC-491,
              TC-499

    Example:
        >>> callable(_write_report)
        True
    """
    root.mkdir(parents=True, exist_ok=True)
    path = generate_project_report(
        root,
        results,
        ReportOptions(declared_regions=tuple(regions)),
        variant_set=_variant_set(*variant_ids),
        now_fn=lambda: _FIXED_INSTANT,
    )
    assert path.is_file(), f"no report file was produced at {path}"
    text = path.read_text(encoding="utf-8")
    assert text.strip(), "the produced report file is empty"
    return path, text


def _addendum_text(
    regions: Sequence[DeclaredRegion],
    results: Sequence[VariantExecutionResult],
) -> str:
    """Call the producer directly and join its lines (Layer-A nodes only)."""
    return "\n".join(report_service._addendum_lines(list(regions), list(results)))


# ---------------------------------------------------------------------------
# The Inc-1 byte-identity golden (C-12) — captured from the SHIPPED producer
# ---------------------------------------------------------------------------

#: Golden home, mirroring ``tests/goldens/batch35/`` (§11.1 "Golden path").
_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batch64"
_GOLDEN = _GOLDEN_DIR / "addendum-below-bound.md"

#: One file holds every below-bound shape, one document per shape, so the
#: increment stays at the three files §11 allocates it. The delimiter is a
#: markdown comment that no report body can produce.
_GOLDEN_DELIM = "<!-- s19tool-golden-shape: {name} -->"
_GOLDEN_DELIM_RE = re.compile(r"^<!-- s19tool-golden-shape: (?P<name>[\w.-]+) -->$", re.M)


def _shape_regions(count: int) -> List[DeclaredRegion]:
    """Build ``count`` nested regions that all contain the shape's hits."""
    return [
        DeclaredRegion(f"zone {index}", 0x1000, 0x2000 + 0x1000 * index)
        for index in range(count)
    ]


def _shape_results(variants: int, per_class: int) -> List[VariantExecutionResult]:
    """
    Summary:
        Build one of the architect lane's ``(R, V, E)`` golden shapes: ``V``
        variants, each with ONE change summary carrying ``per_class``
        modifications and ``per_class`` change-file issues, plus one check
        result carrying ``per_class`` check-file issues.

    Args:
        variants (int): ``V`` — the variant count.
        per_class (int): ``E`` — the per-variant, per-class candidate count.

    Returns:
        List[VariantExecutionResult]: The fixture, in producer order.

    Data Flow:
        - Every shape stays BELOW the bound on every ``(region, class)``:
          the per-region class total is ``V x E``, and the five shapes are
          ``1x1``, ``2x5``, ``3x66 = 198``, ``1x0`` and ``1x200 = K``.
          ``LLR-103.4`` only promises byte identity while no cap has fired, so
          a golden shape that exceeds ``K`` would make the golden UNSATISFIABLE
          for a correct Inc-2 implementation.
        - ``E`` is a LITERAL, never ``K``-derived (``LLR-103.4``, architect
          M-1): with ``E := K`` the ``TC-492`` ``K -> 37`` mutation would change
          the document the golden was captured from.

    Dependencies:
        Uses:
            - _result / _summary / _check / _entry / _issue
        Used by:
            - _golden_shapes

    Example:
        >>> len(_shape_results(2, 1))
        2
    """
    results: List[VariantExecutionResult] = []
    for index in range(variants):
        vid = f"v{index}"
        results.append(
            _result(
                vid,
                [
                    _summary(
                        entries=[_entry(0x1000 + 4 * i) for i in range(per_class)],
                        issues=[
                            _issue("CHG-SYNTAX", 0x1001 + 4 * i)
                            for i in range(per_class)
                        ],
                        variant_id=vid,
                        source=f"chg_{vid}.json",
                    )
                ],
                [
                    _check(
                        issues=[
                            _issue("CHK-MISMATCH", 0x1002 + 4 * i)
                            for i in range(per_class)
                        ],
                        source=f"chk_{vid}.json",
                    )
                ],
            )
        )
    return results


def _fix_gold_shape() -> Tuple[
    List[DeclaredRegion], List[VariantExecutionResult], List[str]
]:
    """
    Summary:
        Build the qa lane's hostile below-bound ``FIX-GOLD`` shape: overlapping
        + nested + inclusive-edge + empty regions, TWO variants whose ids carry
        markdown-escapable characters, ``S = 2`` change summaries each, and
        check results.

    Args:
        None.

    Returns:
        Tuple[List[DeclaredRegion], List[VariantExecutionResult], List[str]]:
        ``(regions, results, variant_ids)``.

    Data Flow:
        - ``S >= 2`` is a fixture PRECONDITION, not a preference
          (``LLR-103.4``, architect m-1): at ``S = V = 1`` the shipped emission
          order is class-grouped, so a per-class-bucket mutant (``FIX-B``) is
          GREEN and the order arm is vacuous. With ``S = 2`` the shipped order
          interleaves, and ``FIX-B`` is RED at Inc-2.
        - The variant ids ``variant_a`` and ``v-2.1`` both carry ``MD_ESCAPE``
          characters, so the golden pins the ESCAPED hit-line rendering — the
          side ``TC-495``'s notice-vs-hit-line equality is compared against.

    Dependencies:
        Uses:
            - _result / _summary / _check / _entry / _issue / DeclaredRegion
        Used by:
            - _golden_shapes

    Example:
        >>> len(_fix_gold_shape()[0])
        4
    """
    regions = [
        DeclaredRegion("outer zone", 0x1000, 0x9000),
        DeclaredRegion("inner zone", 0x2000, 0x2010),
        DeclaredRegion("edge zone", 0x3000, 0x3000),
        DeclaredRegion("empty zone", 0xF000, 0xF0FF),
    ]
    variant_ids = ["variant_a", "v-2.1"]
    results: List[VariantExecutionResult] = []
    for index, vid in enumerate(variant_ids):
        base = 0x2000 + index
        results.append(
            _result(
                vid,
                [
                    _summary(
                        entries=[_entry(base), _entry(0x3000)],
                        issues=[
                            _issue("CHG-COLLISION", 0x2010),
                            _issue("CHG > TRUNCATED", 0x2011),
                            _issue("CHG-NULL", None),
                        ],
                        variant_id=vid,
                        source=f"chg_{index}_0.json",
                    ),
                    _summary(
                        entries=[_entry(0x5000 + index)],
                        issues=[_issue("CHG-SYNTAX", 0x1800)],
                        variant_id=vid,
                        source=f"chg_{index}_1.json",
                    ),
                ],
                [
                    _check(
                        issues=[_issue("CHK-FAIL", 0x2000)],
                        source=f"chk_{index}.json",
                    )
                ],
            )
        )
    return regions, results, variant_ids


def _golden_shapes() -> Dict[
    str, Tuple[List[DeclaredRegion], List[VariantExecutionResult], List[str]]
]:
    """
    Summary:
        Return every below-bound golden shape by name — the architect lane's
        five ``(R, V, E)`` shapes plus the qa lane's hostile ``FIX-GOLD``
        (§5.1 row 1: both fixture sets ship).

    Args:
        None.

    Returns:
        Dict[str, Tuple[...]]: ``{name: (regions, results, variant_ids)}``.

    Data Flow:
        - the shape table -> the capture procedure AND the comparison nodes, so
          a golden document and the fixture that reproduces it can never drift
          apart.

    Dependencies:
        Uses:
            - _shape_regions / _shape_results / _fix_gold_shape
        Used by:
            - _capture_golden, AT-196, TC-491

    Example:
        >>> sorted(_golden_shapes())[0]
        'R1V1E0'
    """
    shapes: Dict[str, Tuple[List[DeclaredRegion], List[VariantExecutionResult], List[str]]] = {}
    for name, (regions, variants, per_class) in {
        "R1V1E1": (1, 1, 1),
        "R3V2E5": (3, 2, 5),
        "R2V3E66": (2, 3, 66),
        "R1V1E0": (1, 1, 0),
        "R1V1E200": (1, 1, 200),
    }.items():
        shapes[name] = (
            _shape_regions(regions),
            _shape_results(variants, per_class),
            [f"v{i}" for i in range(variants)],
        )
    shapes["FIXGOLD"] = _fix_gold_shape()
    return shapes


def _canonical_shape_bytes(root: Path, name: str) -> bytes:
    """Generate one golden shape under ``root`` and return its canonical bytes."""
    regions, results, variant_ids = _golden_shapes()[name]
    shape_root = root / name
    path, _ = _write_report(shape_root, results, regions, variant_ids)
    return canonical_report_bytes(path.read_bytes(), shape_root)


def _golden_documents() -> Dict[str, bytes]:
    """
    Summary:
        Split the committed golden file into ``{shape name: canonical bytes}``.

    Args:
        None.

    Returns:
        Dict[str, bytes]: One entry per captured shape.

    Raises:
        AssertionError: When the golden file is missing or carries no shape
        delimiter — a golden that cannot be parsed must fail loudly rather than
        compare as an empty set.

    Data Flow:
        - committed golden -> per-shape canonical bytes -> the byte-equality
          gate of ``AT-196`` / ``TC-491``.

    Dependencies:
        Uses:
            - _GOLDEN / _GOLDEN_DELIM_RE
        Used by:
            - AT-196, TC-491

    Example:
        >>> isinstance(_golden_documents(), dict)
        True
    """
    assert _GOLDEN.is_file(), (
        f"byte-identity golden missing: {_GOLDEN} — captured in batch-64 "
        f"increment-001 from the SHIPPED producer at base revision 082ada9"
    )
    raw = _GOLDEN.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    marks = list(_GOLDEN_DELIM_RE.finditer(raw))
    assert marks, f"golden {_GOLDEN.name} carries no shape delimiter"
    documents: Dict[str, bytes] = {}
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(raw)
        body = raw[mark.end() : end]
        # The delimiter is a whole line, so exactly one newline separates it
        # from the document it introduces. Strip that one and nothing else —
        # the document's own leading/trailing blank lines are golden bytes.
        if body.startswith("\n"):
            body = body[1:]
        documents[mark.group("name")] = body.encode("utf-8")
    return documents


def _capture_golden(root: Path) -> Path:
    """
    Summary:
        Capture the Inc-1 byte-identity golden by driving the SHIPPED producer
        over every shape and writing one delimited document per shape.

    Args:
        root (Path): A scratch directory the capture runs under.

    Returns:
        Path: The written golden file.

    Data Flow:
        - shipped ``generate_project_report`` -> canonical bytes per shape ->
          one committed file. C-12: the output is produced by the code under
          test BEFORE that code is rewritten, so the golden cannot certify the
          rewrite against itself. Both Phase-1 lanes flagged this sequencing
          independently.

    Dependencies:
        Uses:
            - _golden_shapes / _canonical_shape_bytes
        Used by:
            - the batch-64 increment-001 capture procedure:
              ``python -c "import sys; sys.path.insert(0, 'tests'); from
              test_report_addendum_bound import _capture_golden; from pathlib
              import Path; _capture_golden(Path('<scratch>'))"``

    Example:
        >>> callable(_capture_golden)
        True
    """
    _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    parts: List[str] = [
        "<!-- batch-64 Inc-1 byte-identity golden (LLR-103.4 / AT-196 / TC-491).\n"
        "     Captured from the SHIPPED _addendum_lines at base revision 082ada9,\n"
        "     BEFORE the producer was touched (C-12). Every shape is BELOW the\n"
        "     per-(region, class) bound, which is the only regime in which\n"
        "     LLR-103.4 promises byte identity. Regenerate ONLY by re-running\n"
        "     tests/test_report_addendum_bound.py::_capture_golden against the\n"
        "     pre-batch-64 producer — never after the rewrite. -->\n\n"
    ]
    for name in _golden_shapes():
        document = _canonical_shape_bytes(root, name).decode("utf-8")
        assert document.endswith("\n"), (
            f"golden shape {name} does not end with a newline, so the next "
            f"delimiter would not start its own line"
        )
        parts.append(_GOLDEN_DELIM.format(name=name) + "\n")
        parts.append(document)
    _GOLDEN.write_bytes("".join(parts).encode("utf-8"))
    return _GOLDEN


# ---------------------------------------------------------------------------
# The re-iterable counting sequence (inherited finding #4/#5)
# ---------------------------------------------------------------------------


class _CountingList(list):
    """
    Summary:
        A ``list`` subclass that counts every element it YIELDS, and that stays
        RE-ITERABLE so a region loop can consume it more than once.

    Args:
        items (Sequence[object]): The elements.
        box (List[int]): A one-element mutable counter shared across every
            substituted sequence in one measurement.

    Returns:
        None: Constructor.

    Data Flow:
        - Bounding OUTPUT does not bound TRAVERSAL: cap-and-break and
          cap-and-continue are indistinguishable by peak memory (19019/19019)
          and by wall time (1.00 vs 1.04) — inherited finding #4. The ONLY
          falsifiable oracle for candidate consumption is an injected counting
          iterable.
        - It must be RE-ITERABLE (inherited finding #5): the shipped producer
          re-reads every leaf once per region, so a one-shot generator would
          break the measurement at ``R >= 2`` instead of measuring it.

    Dependencies:
        Uses:
            - list
        Used by:
            - TC-488, TC-489

    Example:
        >>> box = [0]
        >>> seq = _CountingList([1, 2], box)
        >>> list(seq), list(seq), box
        ([1, 2], [1, 2], [4])
    """

    def __init__(self, items: Sequence[object], box: List[int]) -> None:
        super().__init__(items)
        self._box = box

    def __iter__(self) -> Iterator[object]:  # type: ignore[override]
        for item in list.__iter__(self):
            self._box[0] += 1
            yield item


def _consumption_fixture(
    box: List[int], per_leaf: int
) -> List[VariantExecutionResult]:
    """Build a one-variant fixture whose three leaf sequences count their yields."""
    result = _result(
        "a",
        [_summary(variant_id="a")],
        [_check()],
    )
    result.change_summaries[0].entries = _CountingList(
        [_entry(0x1000 + i) for i in range(per_leaf)], box
    )
    result.change_summaries[0].issues = _CountingList(
        [_issue("CHG-X", 0x1000 + i) for i in range(per_leaf)], box
    )
    result.check_results[0].issues = _CountingList(
        [_issue("CHK-X", 0x1000 + i) for i in range(per_leaf)], box
    )
    return [result]


def _overlapping_regions(count: int) -> List[DeclaredRegion]:
    """``count`` regions that all cover the same span (``TC-488`` geometry)."""
    return [DeclaredRegion(f"r{i}", 0x1000, 0x1FFF) for i in range(count)]


def _disjoint_regions(count: int) -> List[DeclaredRegion]:
    """``count`` regions each covering ``1/count`` of the span (``TC-489``)."""
    span = 0x1000 // count
    return [
        DeclaredRegion(f"r{i}", 0x1000 + i * span, 0x1000 + (i + 1) * span - 1)
        for i in range(count)
    ]


def _huge_tiny_regions(count: int) -> List[DeclaredRegion]:
    """
    Summary:
        Build the ``huge+tiny`` geometry (``TC-498``): one enclosing region
        spanning the image plus ``count - 1`` narrow regions BELOW the probe
        address — the natural "whole calibration area + named sub-blocks"
        operator declaration.

    Args:
        count (int): ``R``.

    Returns:
        List[DeclaredRegion]: The enclosing region first, then the narrow ones.

    Data Flow:
        - Exactly ONE region matches at every ``R``, so the OUTPUT is
          R-independent and any growth in region ops is pure cost, not work the
          output justifies (§7 T-9).
        - The equality ``A == R x N`` is a law ONLY because every region's
          ``start`` lies below the probe address, so the prefix-max walk visits
          all ``R`` entries. Without that precondition the equality is fixture
          luck (``LLR-103.1``).

    Dependencies:
        Uses:
            - DeclaredRegion
        Used by:
            - TC-498

    Example:
        >>> len(_huge_tiny_regions(4))
        4
    """
    regions = [DeclaredRegion("whole image", 0x0000, 0xFFFF)]
    for index in range(count - 1):
        start = 0x0100 + index
        regions.append(DeclaredRegion(f"block {index}", start, start))
    return regions


# ===========================================================================
# AT-194 — US-B64-1: the addendum's MARGINAL resident cost stops tracking V x E
# ===========================================================================


def test_at194_addendum_marginal_resident_cost_flat_in_candidate_count(
    tmp_path: Path,
) -> None:
    """AT-194 / HLR-103 / US-B64-1 — the additional memory attributable to the
    declared-region addendum stops growing with the candidate count.

    Fixture ``at194-marginal-delta``: one variant, one summary, ``E``
    modifications inside one declared region; ``delta(E)`` is
    ``peak(with regions) - peak(no regions)`` over the SAME fixture, and the
    acceptance is ``delta(4000) / delta(2000) <= 1.30``.

    Intent: the observable is the addendum's MARGINAL cost, by difference —
    NOT the whole report's peak. With no addendum at all the report's baseline
    peak still doubles per E-doubling (§10.2), so a whole-report bound is
    unsatisfiable and this batch must not claim it (risk R-1).

    Threshold family: ratio-valued (§6.3) — RED strictly above 1.30 with a
    >= 25 % margin on this node's own named fixture. The lanes' figures
    (2.27 / 2.265 / 2.000) are NOT reproduction targets: the marginal delta is
    fixture-specific.

    Expected at Inc-1: **RED** — the shipped producer's marginal cost grows
    with E. Expected at Inc-2: GREEN.

    Every fixture is built BEFORE ``tracemalloc.start()`` (inherited finding
    #7: a fixture built inside the traced window can never go green), and a
    warm-up generation precedes the measurement so module-level lazy state is
    not charged to the first sample.
    """
    threshold = 1.30
    region = DeclaredRegion("calzone", 0x1000, 0x9FFF)

    def _fixture(count: int) -> List[VariantExecutionResult]:
        return [
            _result(
                "a",
                [
                    _summary(
                        entries=[_entry(0x1000 + i) for i in range(count)],
                        variant_id="a",
                    )
                ],
            )
        ]

    def _peak(
        root: Path,
        results: Sequence[VariantExecutionResult],
        regions: Sequence[DeclaredRegion],
    ) -> int:
        root.mkdir(parents=True, exist_ok=True)
        options = ReportOptions(declared_regions=tuple(regions))
        variant_set = _variant_set("a")
        tracemalloc.start()
        try:
            generate_project_report(
                root,
                results,
                options,
                variant_set=variant_set,
                now_fn=lambda: _FIXED_INSTANT,
            )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return peak

    warm = _fixture(64)
    _peak(tmp_path / "warm", warm, (region,))

    deltas: Dict[int, int] = {}
    for count in (2000, 4000):
        results = _fixture(count)  # built BEFORE tracemalloc.start()
        without = _peak(tmp_path / f"e{count}-none", results, ())
        with_regions = _peak(tmp_path / f"e{count}-regions", results, (region,))
        deltas[count] = with_regions - without

    # §3 Deliverable: an AT that produced no file fails.
    path, text = _write_report(tmp_path / "deliverable", _fixture(4), [region], ["a"])
    assert path.is_file() and text.strip()
    assert _ADDENDUM_HEADING in text
    assert _region_heading(region) in _addendum_scope(text)

    assert deltas[2000] > 0, (
        f"AT-194 fixture precondition: the addendum must cost something to "
        f"measure; delta(2000)={deltas[2000]}"
    )
    ratio = deltas[4000] / deltas[2000]
    assert ratio <= threshold, (
        f"AT-194: the addendum's marginal resident cost still tracks the "
        f"candidate count — delta(E=2000)={deltas[2000]} "
        f"delta(E=4000)={deltas[4000]} ratio={ratio:.3f} > {threshold}"
    )


# ===========================================================================
# AT-196 / TC-491 — US-B64-1: byte identity below the bound (LLR-103.4)
# ===========================================================================


def test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden(
    tmp_path: Path,
) -> None:
    """AT-196 / LLR-103.4 / US-B64-1 — while no admission cap has fired, the
    report the shipped surface writes is byte-identical, under
    ``canonical_report_bytes``, to the golden captured at Inc-1.

    Six shapes ship: the architect lane's ``(R,V,E)`` = ``(1,1,1)``,
    ``(3,2,5)``, ``(2,3,66)``, ``(1,1,0)``, ``(1,1,200)`` plus the qa lane's
    hostile ``FIX-GOLD`` (overlapping + nested + inclusive-edge + empty
    regions, escapable variant ids, ``S = 2``, check results).

    Intent: ``_addendum_lines`` has ZERO direct tests today (inherited finding
    #9) and ``tests/goldens/batch35/at055b-project-report.md`` contains **0**
    addendum bytes, so nothing protects a structural rewrite from silent
    drift. This is the arm batch-63 dropped (its D-2) and the one both of its
    Phase-1 lanes independently converged on.

    Expected at Inc-1: **GREEN — a regression guard, by construction.** The
    golden is captured FROM the code under test, so it cannot be RED here
    without manufacturing one. Its detection power is carried by the Inc-2
    mutant arms the spec requires reproduced against the IMPLEMENTED producer:
    ``FIX-B`` (per-class bucket concatenation), ``FIX-E`` (raw ``range_index``
    membership without coalescing), ``FIX-G`` (a spurious notice below the
    bound) — all three executed RED on ``FIX-GOLD``.
    """
    documents = _golden_documents()
    shapes = _golden_shapes()
    assert set(documents) == set(shapes), (
        f"AT-196: golden shapes {sorted(documents)} do not match the fixture "
        f"shapes {sorted(shapes)}"
    )
    for name in shapes:
        observed = _canonical_shape_bytes(tmp_path, name)
        assert observed == documents[name], (
            f"AT-196: shape {name} drifted from the Inc-1 golden "
            f"{_GOLDEN.name} (LLR-103.4 byte identity, canonical form); "
            f"observed {len(observed)} bytes vs golden "
            f"{len(documents[name])} bytes"
        )


def test_tc491_golden_capture_harness_is_deterministic(tmp_path: Path) -> None:
    """TC-491 / LLR-103.4 — the byte-identity harness itself is sound: the same
    producer over the same input, written under two DIFFERENT run roots,
    canonicalizes to identical bytes, and those bytes are the golden's.

    Intent: ``AT-196``'s equality is only meaningful if a difference in the
    per-run temporary root cannot by itself flip it. This node proves the
    canonical form removes run-root variance (and, through
    ``canonical_report_bytes``'s ``_assert_no_host_path_residue``, that no
    operator path was baked into the committed golden).

    Expected at Inc-1: **GREEN — a regression guard, by construction** (same
    producer, same input). Carried with ``AT-196``.
    """
    documents = _golden_documents()
    for name in _golden_shapes():
        first = _canonical_shape_bytes(tmp_path / "run-a", name)
        second = _canonical_shape_bytes(tmp_path / "run-b", name)
        assert first == second, (
            f"TC-491: shape {name} is not reproducible across run roots — the "
            f"canonical form does not remove per-run variance"
        )
        assert first == documents[name], (
            f"TC-491: shape {name} does not match the committed golden"
        )


# ===========================================================================
# AT-197 — US-B64-2: the notice names the cut class, the count, the variants
# ===========================================================================


def test_at197_notice_names_cut_class_dropped_count_and_exact_variant_set(
    tmp_path: Path,
) -> None:
    """AT-197 / LLR-103.5 / US-B64-2 — under the A2/A3 attack at a
    ``change-file issue`` class total of ``K + 2``, the written report carries
    exactly ONE addendum notice for that class, whose dropped count and whose
    variant set the test derives INDEPENDENTLY from its own fixture.

    The variant field is asserted by SET EQUALITY against *the variants with at
    least one DROPPED hit*, never by containment. Revision 1's ``{variants} ⊇
    {v2, v3}`` is a REPRESENTATION check — structurally batch-63's vacuous
    ``AT-165`` with ``variant`` substituted for ``class`` — and ``FIX-H``
    passes it while naming ``v1``, the attacker whose flood caused the eviction
    and every one of whose hits was admitted.

    Expected at Inc-1: **RED** — the shipped producer emits no notice at all,
    so the asserted object does not exist. Expected at Inc-2: GREEN, with RED
    arms ``FIX-C`` (``(variants ?)``), ``FIX-F`` (no variant list), ``FIX-H``
    (over-naming), ``FIX-A2`` (no notice).
    """
    cap = _cap()
    results = _attack_results(cap + 2)
    _, text = _write_report(
        tmp_path, results, [_ATTACK_REGION], ["v1", "v2", "v3"]
    )

    total, dropped, dropped_variants = _expected_cut(
        results, _ATTACK_REGION, _CLASS_CHANGE_ISSUE, cap
    )
    assert (total, dropped, dropped_variants) == (cap + 2, 2, ["v2", "v3"]), (
        f"AT-197 fixture precondition: expected the class total to be K+2 with "
        f"v2 and v3 evicted; derived total={total} dropped={dropped} "
        f"variants={dropped_variants}"
    )

    label = _class_labels()[_CLASS_CHANGE_ISSUE]
    notices = [row for row in _parsed_notices(text) if row[0] == label]
    assert len(notices) == 1, (
        f"AT-197: expected exactly 1 addendum notice for {label!r}; observed "
        f"{len(notices)} — all addendum notices: {_addendum_notices(text)}"
    )
    _, observed_cap, observed_dropped, observed_variants = notices[0]
    assert observed_cap == cap
    assert observed_dropped == dropped, (
        f"AT-197: notice claims {observed_dropped} dropped, fixture says {dropped}"
    )
    assert set(observed_variants) == set(dropped_variants), (
        f"AT-197: notice names {sorted(observed_variants)}; the variants that "
        f"actually lost a hit are {dropped_variants} (set EQUALITY, not ⊇ — "
        f"over-naming inverts US-B64-2 for the named variants)"
    )


# ===========================================================================
# AT-198 — US-B64-2: no notice when nothing was cut, exactly one when something was
# ===========================================================================


@pytest.mark.parametrize("arm", ["le_K", "interior", "K_plus_1"])
def test_at198_notice_presence_keys_on_the_class_total(
    tmp_path: Path, arm: str
) -> None:
    """AT-198 / LLR-103.5 / US-B64-2 — a class total ``<= K`` produces **0**
    addendum notice lines anywhere; a class total of ``K + 1`` produces
    **exactly 1**.

    Three arms, three collected nodes, because one collected pytest node
    reports one verdict and the arms have different Inc-1 verdicts:
    ``le_K`` (total ``K-1``, GREEN by vacuity), ``interior`` (total exactly
    ``K``: 0 notices AND ``K`` rendered hit lines, GREEN by vacuity),
    ``K_plus_1`` (total ``K+1``: exactly 1 notice, **RED**).

    Intent: the predicate keys on the class TOTAL, never on the flood size.
    Executed trap (§7 T-5): a flood of ``K-1`` still truncates once another
    variant contributes to the same class, because ``199 flood + 1 collision``
    fills the cap and the second collision is the ``K+1``-th candidate.

    Threshold family: boundary-valued (§6.3) — **no margin**; the gate is the
    adjacent pair, the ``K`` fixture GREEN and the ``K+1`` fixture RED, with
    ``E`` derived from the constant.

    Arms 1-2 expected GREEN at Inc-1 by vacuity (they assert ABSENCE and the
    shipped producer emits none); their detection power is carried by the Inc-2
    mutant arm ``FIX-G`` (a spurious notice below the bound).
    """
    cap = _cap()
    totals = {"le_K": cap - 1, "interior": cap, "K_plus_1": cap + 1}
    total = totals[arm]
    results = _attack_results(total)
    _, text = _write_report(
        tmp_path, results, [_ATTACK_REGION], ["v1", "v2", "v3"]
    )

    derived_total, _, _ = _expected_cut(
        results, _ATTACK_REGION, _CLASS_CHANGE_ISSUE, cap
    )
    assert derived_total == total, (
        f"AT-198[{arm}] fixture precondition: class total is {derived_total}, "
        f"expected {total}"
    )

    notices = _addendum_notices(text)
    if arm == "K_plus_1":
        assert len(notices) == 1, (
            f"AT-198[{arm}]: class total {total} == K+1 must produce EXACTLY 1 "
            f"addendum notice line; observed {len(notices)}: {notices}"
        )
        return

    assert notices == [], (
        f"AT-198[{arm}]: class total {total} <= K must produce NO addendum "
        f"notice line anywhere; observed {notices}"
    )
    if arm == "interior":
        rendered = _issue_hit_lines(text)
        assert len(rendered) == cap, (
            f"AT-198[{arm}]: at a class total of exactly K the producer must "
            f"render all {cap} hits and cut nothing; observed {len(rendered)}"
        )


# ===========================================================================
# AT-199 — US-B64-2: a notice cannot be forged from document-derived text
# ===========================================================================


def test_at199_document_derived_text_cannot_forge_a_notice(tmp_path: Path) -> None:
    """AT-199 / LLR-103.5 / US-B64-2 — a variant id whose text IS a notice
    line, and an issue code carrying ``> TRUNCATED`` and ``\\r\\n\\t``, render
    escaped and cannot add a notice-shaped line to the addendum.

    Intent: the notice is a NEW markdown sink (§2.7). Every file-derived value
    in it goes through ``md_safe`` with an explicit limit, exactly as the hit
    lines do; ``MD_ESCAPE`` contains ``>`` and ``#`` and ``_normalise``
    collapses ``\\r\\n\\t`` BEFORE any mode-specific step, so an injected
    ``> TRUNCATED`` reaches the document as ``\\>`` and never at column 0.

    Expected at Inc-1: **RED**, and the RED is the notice-count assertion, not
    the escaping one — the escaping arms below are asserted FIRST and are GREEN
    on the shipped tree, so this node's RED is the specced one (no notice
    exists to count) rather than an accident of the hostile fixture.
    """
    cap = _cap()
    forged = _notice_fmt().format(
        label=_class_labels()[_CLASS_CHANGE_ISSUE],
        cap=cap,
        dropped=99,
        variants="v9",
    )
    hostile_id = f"{forged}\r\n\tTAIL"
    results = _attack_results(cap + 1)
    results[0] = _result(
        hostile_id,
        [
            _summary(
                entries=[_entry(0x1000)],
                issues=[
                    _issue("CHG-ADDRESS-SYNTAX", 0x1100 + i, ValidationSeverity.WARNING)
                    for i in range(cap - 1)
                ],
                variant_id=hostile_id,
            )
        ],
    )
    _, text = _write_report(
        tmp_path, results, [_ATTACK_REGION], [hostile_id, "v2", "v3"]
    )
    scope = _addendum_scope(text)

    assert "\r" not in scope and "\t" not in scope, (
        "AT-199: a carriage return or tab survived into the addendum — "
        "_normalise must collapse them before any mode-specific step"
    )
    forged_at_column_0 = [
        line for line in scope.splitlines() if line.startswith("> TRUNCATED")
    ]
    injected_escaped = [
        line for line in scope.splitlines() if "\\> TRUNCATED" in line
    ]
    assert injected_escaped, (
        "AT-199 fixture precondition: the injected notice text must reach the "
        "addendum in ESCAPED form, otherwise the forgery arm proves nothing"
    )
    assert len(forged_at_column_0) == len(_addendum_notices(text)), (
        f"AT-199: a document-derived value reached column 0 as a notice-shaped "
        f"line; column-0 lines={forged_at_column_0!r} vs recognised notices="
        f"{_addendum_notices(text)!r}"
    )

    assert len(_addendum_notices(text)) == 1, (
        f"AT-199: at a class total of K+1 the addendum must carry exactly ONE "
        f"genuine notice; observed {_addendum_notices(text)}"
    )


# ===========================================================================
# AT-201 / AT-202 — US-B64-2: the false-positive controls (class and variant)
# ===========================================================================


def test_at201_a_class_that_lost_nothing_is_never_named(tmp_path: Path) -> None:
    """AT-201 / LLR-103.5 / US-B64-2 — the set of classes the notices name
    equals the set of classes that were actually cut.

    Fixture: the A2/A3 attack at class total ``K + 2``, where ``v1`` also
    contributes three UNCUT ``modification``-class hits in the same region.

    Intent: the P-6 class-level positive control. ``FIX-G`` — which always
    names all three classes — is GREEN on six of the nine other observables in
    this batch, so nothing else catches it. It is RED here and RED on
    ``AT-198`` arm 1, for two DIFFERENT reasons, which is why this is its own
    collected node rather than a third arm of ``AT-198``.

    Expected at Inc-1: **RED** (no notice exists). Expected at Inc-2: GREEN,
    RED arm ``FIX-G``.
    """
    cap = _cap()
    results = _attack_results(cap + 2)
    _, text = _write_report(
        tmp_path, results, [_ATTACK_REGION], ["v1", "v2", "v3"]
    )

    labels = _class_labels()
    expected_cut = {
        labels[hit_class]
        for hit_class in (_CLASS_MODIFICATION, _CLASS_CHANGE_ISSUE, _CLASS_CHECK_ISSUE)
        if _expected_cut(results, _ATTACK_REGION, hit_class, cap)[1] > 0
    }
    assert expected_cut == {labels[_CLASS_CHANGE_ISSUE]}, (
        f"AT-201 fixture precondition: exactly one class must be cut; derived "
        f"{sorted(expected_cut)}"
    )
    present_uncut = _expected_cut(
        results, _ATTACK_REGION, _CLASS_MODIFICATION, cap
    )
    assert present_uncut[0] == _ATTACK_UNCUT_MODS and present_uncut[1] == 0, (
        f"AT-201 fixture precondition: the modification class must be PRESENT "
        f"and UNCUT in the same region; derived {present_uncut}"
    )

    named = {row[0] for row in _parsed_notices(text)}
    assert named == expected_cut, (
        f"AT-201: the notices name {sorted(named)}; the classes actually cut "
        f"are {sorted(expected_cut)} — a class that lost nothing must never be "
        f"named (all notices: {_addendum_notices(text)})"
    )


def test_at202_a_variant_that_lost_nothing_is_never_named(tmp_path: Path) -> None:
    """AT-202 / LLR-103.5 / US-B64-2 — the set of variants the notice names
    equals the set of variants that lost at least one hit; a variant that
    contributed to the cut class and lost NOTHING is absent.

    Intent: the P-6 VARIANT-level positive control, and the one the class-axis
    control does not cover. Executed: ``FIX-G`` is GREEN here, and ``AT-196``'s
    byte identity is GREEN on ``FIX-H`` (its defect lives in the notice's
    variant list, which is invisible below the bound). Without this node,
    ``FIX-H`` passes the ENTIRE revision-1 acceptance set while telling the
    operator that ``v1`` — the attacker whose flood caused the eviction, every
    one of whose hits was admitted — lost evidence.

    Expected at Inc-1: **RED** (no notice exists). Expected at Inc-2: GREEN,
    RED arm ``FIX-H``.
    """
    cap = _cap()
    results = _attack_results(cap + 2)
    _, text = _write_report(
        tmp_path, results, [_ATTACK_REGION], ["v1", "v2", "v3"]
    )

    candidates = _class_candidates(results, _ATTACK_REGION, _CLASS_CHANGE_ISSUE)
    contributors = {vid for vid, _ in candidates}
    _, dropped, dropped_variants = _expected_cut(
        results, _ATTACK_REGION, _CLASS_CHANGE_ISSUE, cap
    )
    uncut_contributors = contributors - set(dropped_variants)
    assert dropped > 0 and uncut_contributors == {"v1"}, (
        f"AT-202 fixture precondition: v1 must contribute to the cut class and "
        f"lose nothing; contributors={sorted(contributors)} "
        f"dropped_variants={dropped_variants}"
    )

    notices = _parsed_notices(text)
    assert len(notices) == 1, (
        f"AT-202: expected exactly one addendum notice to read the variant "
        f"field from; observed {_addendum_notices(text)}"
    )
    named = set(notices[0][3])
    assert named == set(dropped_variants), (
        f"AT-202: the notice names {sorted(named)}; only {dropped_variants} "
        f"lost a hit — naming {sorted(named & uncut_contributors)} inverts "
        f"US-B64-2 for a variant that lost nothing"
    )


# ===========================================================================
# AT-203 — US-B64-2: the notice tells the operator WHICH region lost evidence
# ===========================================================================


def test_at203_notice_sits_under_the_flooded_regions_subsection(
    tmp_path: Path,
) -> None:
    """AT-203 / LLR-103.5 / US-B64-2 — with two disjoint declared regions, the
    quiet one declared FIRST and the flooded one second, the notice appears
    inside the FLOODED region's ``### `` sub-section and is absent from the
    quiet region's.

    Intent: every notice fixture in revision 1 was ``R = 1`` or below-bound, so
    no acceptance ever had a cap fire with ``R > 1``. Arm ``FIX-I`` (every
    notice re-emitted under the FIRST region's sub-section) passes every other
    acceptance in this batch while telling the operator that the quiet region
    lost evidence and the flooded one lost none.

    Both sub-sections are asserted FOUND before anything is claimed about
    their contents, and the split keys on the ``md_safe``-ESCAPED heading
    (``QA-NEW-7``): a test that splits on the raw region name finds no
    sub-section, and the "absent from every other region" half then passes
    VACUOUSLY.

    Expected at Inc-1: **RED** (no notice exists). Expected at Inc-2: GREEN,
    RED arm ``FIX-I``.
    """
    cap = _cap()
    quiet = DeclaredRegion("quiet zone", 0x1000, 0x1FFF)
    flooded = DeclaredRegion("flood zone", 0x4000, 0x4FFF)
    results = [
        _result(
            "v1",
            [
                _summary(
                    issues=[
                        _issue("CHG-ADDRESS-SYNTAX", 0x4000, ValidationSeverity.WARNING)
                        for _ in range(cap + 1)
                    ],
                    variant_id="v1",
                )
            ],
        ),
        _result(
            "v2",
            [_summary(entries=[_entry(0x1000)], variant_id="v2")],
        ),
    ]
    _, text = _write_report(tmp_path, results, [quiet, flooded], ["v1", "v2"])

    quiet_section = _region_subsection(text, quiet)
    flooded_section = _region_subsection(text, flooded)
    assert quiet_section.startswith(_region_heading(quiet))
    assert flooded_section.startswith(_region_heading(flooded))
    assert _expected_cut(results, flooded, _CLASS_CHANGE_ISSUE, cap)[1] == 1, (
        "AT-203 fixture precondition: exactly one hit must be dropped in the "
        "flooded region"
    )
    assert _expected_cut(results, quiet, _CLASS_CHANGE_ISSUE, cap)[1] == 0, (
        "AT-203 fixture precondition: the quiet region must lose nothing"
    )

    prefix = _notice_prefix_re()
    in_quiet = [line for line in quiet_section.splitlines() if prefix.match(line)]
    in_flooded = [line for line in flooded_section.splitlines() if prefix.match(line)]
    assert in_quiet == [], (
        f"AT-203: a region that lost nothing carries a notice: {in_quiet}"
    )
    assert len(in_flooded) == 1, (
        f"AT-203: the flooded region's sub-section must carry exactly the one "
        f"notice for its cut class; observed {in_flooded}"
    )


# ===========================================================================
# TC-480 — HLR-103: the end-to-end addendum shape
# ===========================================================================


def test_tc480_addendum_end_to_end_shape_at_the_boundary(tmp_path: Path) -> None:
    """TC-480 / HLR-103 — at a class total of ``K + 1`` the written report
    carries the addendum heading, one ``### `` sub-heading per declared region,
    at most ``K`` rendered hit lines of the cut class, and at least one
    addendum notice.

    Intent: the integration-level shape assertion the HLR needs — heading,
    sub-headings, bounded hits, disclosure — over the shipped surface rather
    than over the producer's return value.

    Expected at Inc-1: **RED** — the shipped producer renders 201 hit lines
    (``> K``) and 0 notices. Expected at Inc-2: GREEN.
    """
    cap = _cap()
    regions = [_ATTACK_REGION, DeclaredRegion("quiet zone", 0x8000, 0x8FFF)]
    results = _attack_results(cap + 1)
    _, text = _write_report(tmp_path, results, regions, ["v1", "v2", "v3"])

    assert _ADDENDUM_HEADING in text
    for region in regions:
        assert _region_subsection(text, region).startswith(_region_heading(region))

    section = _region_subsection(text, _ATTACK_REGION)
    rendered = [line for line in section.splitlines() if line.startswith("- issue ")]
    notices = [
        line for line in section.splitlines() if _notice_prefix_re().match(line)
    ]
    assert len(rendered) <= cap, (
        f"TC-480: the region renders {len(rendered)} hit lines of the cut class, "
        f"above the bound {cap}"
    )
    assert len(notices) >= 1, (
        f"TC-480: a class total of {cap + 1} was cut but the region discloses "
        f"nothing; notices={notices}"
    )


# ===========================================================================
# TC-481 / TC-482 / TC-483 — LLR-103.3: the K-1 / K / K+1 boundary family
# ===========================================================================


def test_tc481_below_the_bound_renders_every_hit_and_no_notice() -> None:
    """TC-481 / LLR-103.3 — at a class total of ``K - 1`` the producer renders
    every hit (``<= K``) and emits no notice.

    Threshold family: boundary-valued — no margin; the gate is the adjacent
    pair with ``TC-482`` / ``TC-483``, ``E`` derived from the constant.

    Expected at Inc-1: **GREEN by vacuity** — the shipped producer emits 199
    hit lines (``<= 200``) and has no notice concept at all. Its detection
    power is carried by the Inc-2 mutant arms ``FIX-C`` (``hits[:CAP]`` — which
    bounds the OUTPUT, not the producer) and ``FIX-G`` (a spurious notice below
    the bound).
    """
    cap = _cap()
    text = _addendum_text([_ATTACK_REGION], _attack_results(cap - 1))
    rendered = _issue_hit_lines(text)
    assert len(rendered) == cap - 1, (
        f"TC-481: expected all {cap - 1} hits rendered; observed {len(rendered)}"
    )
    assert len(rendered) <= cap
    assert _addendum_notices(text) == [], (
        f"TC-481: nothing was cut, so no notice may appear; observed "
        f"{_addendum_notices(text)}"
    )


def test_tc482_exactly_at_the_bound_renders_k_hits_and_no_notice() -> None:
    """TC-482 / LLR-103.3 — at a class total of exactly ``K`` the producer
    renders exactly ``K`` hits and still emits no notice: the cap fires when a
    candidate is REJECTED, which first happens at ``K + 1``.

    Expected at Inc-1: **GREEN by vacuity** (200 <= 200, 0 notices). Inc-2 RED
    arm: ``FIX-G``.
    """
    cap = _cap()
    text = _addendum_text([_ATTACK_REGION], _attack_results(cap))
    rendered = _issue_hit_lines(text)
    assert len(rendered) == cap, (
        f"TC-482: expected exactly {cap} hits rendered; observed {len(rendered)}"
    )
    assert _addendum_notices(text) == [], (
        f"TC-482: at exactly K nothing is rejected, so no notice may appear; "
        f"observed {_addendum_notices(text)}"
    )


def test_tc483_above_the_bound_is_capped_and_line_count_is_bounded() -> None:
    """TC-483 / LLR-103.3 — at a class total of ``K + 1``, and again far above
    it, the producer renders at most ``K`` hits of the cut class and its whole
    emitted line count stays under ``2 + R x (1 + 3K + 3 + 1)``.

    Threshold family: boundary-valued — **no margin**. A boundary node's RED is
    ``threshold + 1`` BY CONSTRUCTION (201 vs 200 = 0.5 % over), so a
    ratio-margin gate would kill the one genuinely-correct RED in this family
    or force the author to abandon the boundary fixture for a far-above one.
    Both fixtures are asserted here: the ``K + 1`` boundary and ``E = 4000``.

    Expected at Inc-1: **RED** — the shipped producer renders 201 at ``K + 1``
    and 4000 at ``E = 4000``. Expected at Inc-2: GREEN.
    """
    cap = _cap()
    regions = [_ATTACK_REGION]
    bound = 2 + len(regions) * (1 + 3 * cap + 3 + 1)

    boundary = _addendum_text(regions, _attack_results(cap + 1))
    boundary_hits = _issue_hit_lines(boundary)

    far_above = _addendum_text(regions, _attack_results(3000))
    far_hits = _issue_hit_lines(far_above)
    far_lines = len(_addendum_scope(far_above).splitlines())

    assert len(boundary_hits) <= cap, (
        f"TC-483: class total {cap + 1} renders {len(boundary_hits)} hit lines, "
        f"above the bound {cap}"
    )
    assert len(far_hits) <= cap, (
        f"TC-483: class total 3000 renders {len(far_hits)} hit lines, above the "
        f"bound {cap}"
    )
    assert far_lines <= bound, (
        f"TC-483: the addendum emits {far_lines} lines at E=4000, above the "
        f"line-count bound {bound} = 2 + R x (1 + 3K + 3 + 1)"
    )


# ===========================================================================
# TC-484 / TC-485 — LLR-103.3: the negative / empty / error domain
# ===========================================================================


def test_tc484_empty_and_negative_domain_renders_none_without_notice() -> None:
    """TC-484 / LLR-103.3 — the four empty/negative sub-cases: no variants at
    all, an ``issue.address is None``, every candidate outside the region, and
    a 1-byte-wide region. Each renders an explicit ``None.`` (or exactly its
    one in-region hit) and never a notice.

    Intent: ``None.`` is the addendum's explicit empty rendering, and an issue
    with no address must be SKIPPED rather than treated as address 0.

    Expected at Inc-1: **GREEN by construction** — §3's boundary catalog
    already records all four executed against the SHIPPED function. Its
    detection power is carried by the Inc-2 mutant arm ``FIX-NONE`` (drops the
    ``None.`` branch and stops skipping ``issue.address is None``).
    """
    empty_region = DeclaredRegion("nowhere", 0x9000, 0x90FF)

    no_variants = _addendum_text([empty_region], [])
    address_none = _addendum_text(
        [empty_region],
        [_result("a", [_summary(issues=[_issue("CHG-NULL", None)], variant_id="a")])],
    )
    all_outside = _addendum_text(
        [empty_region],
        [_result("a", [_summary(entries=[_entry(0x1000)], variant_id="a")])],
    )
    for name, rendered in (
        ("no variants", no_variants),
        ("issue.address is None", address_none),
        ("every candidate outside", all_outside),
    ):
        assert "None." in _addendum_scope(rendered), (
            f"TC-484 [{name}]: an empty region must render an explicit 'None.'"
        )
        assert _hit_lines(rendered) == [], (
            f"TC-484 [{name}]: an empty region rendered hit lines: "
            f"{_hit_lines(rendered)}"
        )
        assert _addendum_notices(rendered) == [], (
            f"TC-484 [{name}]: nothing was cut, so no notice may appear"
        )

    one_byte = DeclaredRegion("one byte", 0x1000, 0x1000)
    tight = _addendum_text(
        [one_byte],
        [
            _result(
                "a",
                [
                    _summary(
                        entries=[_entry(0x1000), _entry(0x1001)], variant_id="a"
                    )
                ],
            )
        ],
    )
    assert len(_hit_lines(tight)) == 1, (
        f"TC-484 [1-byte region]: inclusive [start, end] with start == end must "
        f"admit exactly the one candidate at that address; observed "
        f"{_hit_lines(tight)}"
    )
    assert _addendum_notices(tight) == []


def test_tc485_addendum_is_guarded_by_a_non_empty_declared_region_set(
    tmp_path: Path,
) -> None:
    """TC-485 / LLR-103.3 — ``R = 0`` never reaches ``_addendum_lines``: the
    caller guards it, and a report generated with no declared regions carries
    no addendum at all.

    Intent: the error-domain row is asserted as a GUARD, not exercised as an
    addendum case — ``_addendum_lines`` is simply not called. Both halves are
    asserted: the guard exists in the caller's source, and the behaviour it
    produces is observable in the written file.

    Expected at Inc-1: **GREEN by construction** — it asserts a guard on
    UNCHANGED code. This is a pure regression guard over unchanged behaviour
    and carries **no** Inc-2 mutant arm; the spec says so in writing rather
    than inventing one.
    """
    source = inspect.getsource(report_service.generate_project_report)
    guards = [
        line.strip()
        for line in source.splitlines()
        if "options.declared_regions" in line and line.strip().startswith("if ")
    ]
    assert guards == ["if options.declared_regions:"], (
        f"TC-485: the declared-region guard in generate_project_report changed "
        f"shape; observed {guards}"
    )

    tmp_path.mkdir(parents=True, exist_ok=True)
    path = generate_project_report(
        tmp_path,
        [_result("a", [_summary(entries=[_entry(0x1000)], variant_id="a")])],
        ReportOptions(declared_regions=()),
        variant_set=_variant_set("a"),
        now_fn=lambda: _FIXED_INSTANT,
    )
    text = path.read_text(encoding="utf-8")
    assert _ADDENDUM_HEADING not in text, (
        "TC-485: R = 0 produced an addendum section"
    )


# ===========================================================================
# TC-486 / TC-487 — LLR-103.2: sound membership over overlapping regions
# ===========================================================================


def test_tc486_membership_is_sound_over_nested_overlapping_regions() -> None:
    """TC-486 / LLR-103.2 — a candidate that lies inside an OUTER declared
    region beyond an inner region's end is still reported, and a candidate
    inside both is reported under both.

    Intent: this guards a hazard the NEW implementation introduces. The
    ``range_index`` primitive is boolean-only and is INCORRECT on a raw
    overlapping range set — executed pre-state:
    ``address_in_sorted_ranges(0x5000, [(0x1000,0x9000),(0x2000,0x2010)])`` is
    ``False`` while ground truth is ``True``. ``LLR-103.2`` therefore requires
    a COALESCED cover, and coalescing is a CORRECTNESS precondition, not an
    optimisation. The shipped producer uses ``DeclaredRegion.contains`` and is
    already correct here.

    Expected at Inc-1: **GREEN by construction** — the RED belongs to a
    different subject (the primitive, not the addendum). Its detection power is
    carried by the Inc-2 mutant arm ``FIX-E`` (raw ``range_index`` membership
    with no coalescing), executed RED on ``FIX-GOLD``: it drops two hits and
    adds none.
    """
    outer = DeclaredRegion("outer zone", 0x1000, 0x9000)
    inner = DeclaredRegion("inner zone", 0x2000, 0x2010)
    beyond = _addendum_text(
        [outer, inner],
        [_result("v0", [_summary(entries=[_entry(0x5000)], variant_id="v0")])],
    )
    assert len(_hit_lines(beyond)) == 1, (
        f"TC-486: a candidate at 0x5000 lies inside the outer region beyond the "
        f"inner region's end and must be reported exactly once; observed "
        f"{_hit_lines(beyond)}"
    )

    section = _addendum_text(
        [outer, inner],
        [
            _result("v0", [_summary(issues=[_issue("S1I", 0x1800)], variant_id="v0")]),
            _result("v1", [_summary(issues=[_issue("S3I", 0x2000)], variant_id="v1")]),
        ],
    )
    hits = _hit_lines(section)
    assert any("0x1800" in line for line in hits), (
        f"TC-486: the 0x1800 hit (inside the outer region only) is missing: {hits}"
    )
    assert sum("0x2000" in line for line in hits) == 2, (
        f"TC-486: the 0x2000 hit lies inside BOTH regions and must be emitted "
        f"once per matching region; observed {hits}"
    )


def test_tc487_duplicate_and_equal_start_nested_regions_each_emit() -> None:
    """TC-487 / LLR-103.2 — duplicate, exactly-duplicated and equal-start
    nested regions each get their own sub-section and each emit the candidate.

    Intent: ``LLR-103.2`` promises to REPRODUCE today's behaviour in which a
    candidate inside ``M`` overlapping regions is emitted ``M`` times. A
    coalescing step used for anything other than a reject pre-filter would
    silently collapse these.

    Expected at Inc-1: **GREEN by construction** (shipped emits 3 and 2 on the
    two sub-fixtures). Inc-2 RED arm: ``FIX-E``.
    """
    results = [
        _result("v0", [_summary(entries=[_entry(0x1500)], variant_id="v0")])
    ]
    duplicated = [DeclaredRegion("dup zone", 0x1000, 0x1FFF)] * 3
    assert len(_hit_lines(_addendum_text(duplicated, results))) == 3, (
        "TC-487: three identical declared regions must each emit the candidate"
    )

    nested = [
        DeclaredRegion("outer zone", 0x1000, 0x9000),
        DeclaredRegion("inner zone", 0x1000, 0x2000),
    ]
    assert len(_hit_lines(_addendum_text(nested, results))) == 2, (
        "TC-487: equal-start nested regions must each emit the candidate"
    )


# ===========================================================================
# TC-488 / TC-489 — LLR-103.1: candidate consumption independent of R
# ===========================================================================


def _consumed(regions: Sequence[DeclaredRegion], per_leaf: int) -> Tuple[int, int]:
    """Run the producer over a counting fixture; return ``(consumed, N)``."""
    box = [0]
    results = _consumption_fixture(box, per_leaf)
    report_service._addendum_lines(list(regions), results)
    return box[0], per_leaf * 3


def test_tc488_candidate_consumption_is_r_independent_overlapping() -> None:
    """TC-488 / LLR-103.1 — under OVERLAPPING geometry (all ``R`` regions cover
    one span) the producer consumes each candidate exactly once: ``consumed ==
    N`` at ``R`` in ``{1, 8, 64}``.

    Instrument: a re-iterable ``list`` subclass substituted for each of the
    three leaf sequences, counting every element it yields. Peak memory and
    wall time must NOT be used for this LLR — batch-63 measured cap-and-break
    against cap-and-continue at 19019/19019 peak and 1.00 vs 1.04 time; only
    the counting iterable separates them.

    This node also carries the stealth-early-exit control: a per-class early
    exit (``FIX-A2``) reads ``201/201/201`` here — RED at EVERY ``R`` — whereas
    under disjoint geometry it cannot fire until ``N > R x K`` and two thirds
    of the control is dead at this fixture scale.

    Threshold family: exact-equality — RED means observed != required, with
    both values and the per-arm ratio pasted. The ``R = 1`` arm reads
    ``consumed == N`` because the shipped producer IS correct at ``R = 1``;
    this node's RED comes from ``R = 8`` and ``R = 64``.

    Expected at Inc-1: **RED**. Expected at Inc-2: GREEN.
    """
    observed = {
        count: _consumed(_overlapping_regions(count), 100) for count in (1, 8, 64)
    }
    failures = {
        count: (consumed, total)
        for count, (consumed, total) in observed.items()
        if consumed != total
    }
    assert not failures, (
        f"TC-488: the candidate set is re-read once per declared region — "
        f"overlapping geometry, consumed vs N per R: "
        f"{ {count: f'{c}/{n} = x{c / n:.0f}' for count, (c, n) in observed.items()} }"
    )


def test_tc489_candidate_consumption_is_r_independent_disjoint() -> None:
    """TC-489 / LLR-103.1 — under DISJOINT geometry (each region covers
    ``1/R`` of the span) the producer still consumes each candidate exactly
    once: ``consumed == N`` at ``R`` in ``{1, 8, 64}``.

    Stated purpose, in writing: this is a control that the candidate-
    consumption property is not GEOMETRY-dependent. It is NOT a stealth-early-
    exit control — executed refutation: a real per-class early exit cannot fire
    under disjoint geometry until ``N > R x K``, so at this fixture scale two
    thirds of that claim is dead. That claim lives on ``TC-488``. This node has
    ZERO detection power for the §10.7 region-ops residual: under disjoint
    geometry the prefix-max prunes immediately and region ops read ``N`` at
    every ``R`` for a correct AND an ``O(R)`` implementation alike.

    The instrument's re-iterability is asserted here as a positive control: a
    one-shot generator would break the measurement at ``R >= 2`` rather than
    measure it (inherited finding #5).

    Expected at Inc-1: **RED**. Expected at Inc-2: GREEN.
    """
    box = [0]
    reusable = _CountingList([1, 2, 3], box)
    assert list(reusable) == list(reusable) == [1, 2, 3] and box[0] == 6, (
        "TC-489: the counting instrument must be RE-ITERABLE, otherwise the "
        "region loop measures a broken fixture instead of the producer"
    )

    observed = {
        count: _consumed(_disjoint_regions(count), 100) for count in (1, 8, 64)
    }
    failures = {
        count: (consumed, total)
        for count, (consumed, total) in observed.items()
        if consumed != total
    }
    assert not failures, (
        f"TC-489: the candidate set is re-read once per declared region — "
        f"disjoint geometry, consumed vs N per R: "
        f"{ {count: f'{c}/{n} = x{c / n:.0f}' for count, (c, n) in observed.items()} }"
    )


# ===========================================================================
# TC-490 — LLR-103.5: the +N more remainder (NOT EXECUTABLE PRE-FIX)
# ===========================================================================


@pytest.mark.xfail(
    strict=True,
    reason=(
        "NOT EXECUTABLE PRE-FIX (§6.2): ADDENDUM_NOTICE_VARIANTS_MAX and the "
        "notice it caps do not exist on the base tree. First real verdict at "
        "Inc-2, where the xfail marker is removed."
    ),
)
def test_tc490_notice_caps_the_variant_list_with_a_plus_n_more_remainder(
    tmp_path: Path,
) -> None:
    """TC-490 / LLR-103.5 — with more affected variants than
    ``ADDENDUM_NOTICE_VARIANTS_MAX``, the notice names that many and appends
    ``+N more`` carrying the count of the DISTINCT unnamed affected variants —
    it does not grow with ``V``.

    Fixture precondition: at least one variant contributes cut hits
    NON-CONTIGUOUSLY in traversal order. That is the architect lane's sentinel
    invariant: the remainder is counted with an ``O(1)`` per-(region, class)
    last-seen sentinel rather than an ``O(V)`` membership set, and an ``O(V)``
    set would put ``V`` straight back into the very bound ``LLR-103.3``
    establishes. An implementer reorganising loops breaks it silently.

    Expected at Inc-1: ``xfail(strict=True)`` — the constant and the notice do
    not exist. Expected at Inc-2: GREEN with the marker removed.
    """
    cap = _cap()
    limit = _variants_max()
    assert hasattr(report_service, "ADDENDUM_NOTICE_VARIANTS_MAX"), (
        "TC-490: ADDENDUM_NOTICE_VARIANTS_MAX is not defined on report_service"
    )

    affected = limit + 12
    summaries = [
        _summary(
            issues=[
                _issue("CHG-FLOOD", 0x1100 + i, ValidationSeverity.WARNING)
                for i in range(cap)
            ],
            variant_id="v0",
        )
    ]
    results = [_result("v0", summaries)]
    # Each later variant contributes TWO cut hits separated by another
    # variant's hit, so no variant's dropped hits are contiguous.
    for index in range(affected):
        results.append(
            _result(
                f"a{index}",
                [
                    _summary(
                        issues=[_issue("CHG-LATE", 0x1200 + index)],
                        variant_id=f"a{index}",
                    )
                ],
            )
        )
    for index in range(affected):
        results.append(
            _result(
                f"a{index}b",
                [
                    _summary(
                        issues=[_issue("CHG-LATE", 0x1300 + index)],
                        variant_id=f"a{index}",
                    )
                ],
            )
        )
    ids = ["v0"] + [f"a{i}" for i in range(affected)] + [f"a{i}b" for i in range(affected)]
    _, text = _write_report(tmp_path, results, [_ATTACK_REGION], ids)

    notices = _parsed_notices(text)
    assert len(notices) == 1, f"TC-490: expected one notice; got {notices}"
    variants = notices[0][3]
    named = [token for token in variants if not token.startswith("+")]
    remainder = [token for token in variants if token.startswith("+")]
    _, _, dropped_variants = _expected_cut(
        results, _ATTACK_REGION, _CLASS_CHANGE_ISSUE, cap
    )
    assert len(named) == limit, (
        f"TC-490: the notice names {len(named)} variants, cap is {limit}"
    )
    assert remainder == [f"+{len(dropped_variants) - limit} more"], (
        f"TC-490: expected a +N more remainder naming "
        f"{len(dropped_variants) - limit} distinct unnamed affected variants; "
        f"observed {remainder}"
    )


# ===========================================================================
# TC-492 — LLR-103.6: the constants (NOT EXECUTABLE PRE-FIX)
# ===========================================================================


@pytest.mark.xfail(
    strict=True,
    reason=(
        "NOT EXECUTABLE PRE-FIX (§6.2 / LLR-103.6): the four constants do not "
        "exist on the base tree — executed pre-state, rg over s19_app/ and "
        "tests/ -> 0 hits. First real verdict at Inc-2."
    ),
)
def test_tc492_cap_labels_and_notice_format_are_module_constants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-492 / LLR-103.6 — the cap, the class labels, the variant-list cap and
    the notice format are module-level constants of ``report_service``;
    ``_addendum_lines``'s body carries no bare ``200``; and re-valuing the cap
    to 37 keeps the ``K``-derived nodes green.

    Scope correction: the ``K -> 37`` mutation applies to the ``K``-derived
    nodes only (``TC-481`` / ``TC-482`` / ``TC-483``, ``AT-197``, ``AT-198``,
    ``AT-201``, ``AT-202``) — **not** to "the suite". ``TC-491`` / ``AT-196``'s
    golden shapes use LITERAL ``E`` by ``LLR-103.4``'s pin and are excluded by
    construction; applying the mutation to them would false-fail a correct
    implementation.

    Expected at Inc-1: ``xfail(strict=True)`` — its subject is the EXISTENCE of
    the constants. Expected at Inc-2: GREEN with the marker removed.
    """
    missing = [
        name
        for name in (
            "MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION",
            "ADDENDUM_CLASS_LABELS",
            "ADDENDUM_NOTICE_VARIANTS_MAX",
            "ADDENDUM_TRUNCATION_NOTICE_FMT",
        )
        if not hasattr(report_service, name)
    ]
    assert not missing, f"TC-492: constants not defined on report_service: {missing}"

    body = inspect.getsource(report_service._addendum_lines)
    body = body.split('"""')[-1]
    assert not re.search(r"(?<![\w.])200(?![\w.])", body), (
        "TC-492: _addendum_lines's body still carries a bare literal 200"
    )

    monkeypatch.setattr(report_service, "MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION", 37)
    mutated = _cap()
    assert mutated == 37
    at_cap = _addendum_text([_ATTACK_REGION], _attack_results(mutated))
    above = _addendum_text([_ATTACK_REGION], _attack_results(mutated + 1))
    assert len(_issue_hit_lines(at_cap)) == mutated
    assert _addendum_notices(at_cap) == []
    assert len(_issue_hit_lines(above)) == mutated
    assert len(_addendum_notices(above)) == 1


# ===========================================================================
# TC-493 — LLR-103.3: the producer's own peak, E-axis
# ===========================================================================


def test_tc493_addendum_producer_peak_is_flat_in_the_candidate_count() -> None:
    """TC-493 / LLR-103.3 — ``_addendum_lines``'s OWN traced peak, measured
    directly at ``R = 1, V = 1``, grows by at most 1.25x per ``E``-doubling.

    Intent: this is the white-box counterpart of ``AT-194`` and the node that
    separates bounding the PRODUCER from bounding the OUTPUT. ``FIX-C``
    (``hits[:CAP]``) is GREEN on byte identity and RED here — the entire cost
    is paid before any output exists, so a row cap or a byte budget is
    structurally blind to it.

    Threshold family: ratio-valued — RED strictly above 1.25 with a >= 25 %
    margin on this node's own fixture. Union GREEN max across three lanes was
    1.02 and union RED min 1.96, so the admissible gap is (1.02, 1.96) and 1.25
    sits inside it. Anti-widening rule: if Inc-2 measures GREEN > 1.10 the
    threshold returns to Phase 1 rather than being widened at the gate.

    Expected at Inc-1: **RED**. Expected at Inc-2: GREEN.
    """
    threshold = 1.25
    region = DeclaredRegion("calzone", 0x1000, 0x9FFF)

    def _peak(count: int) -> int:
        results = [
            _result(
                "a",
                [
                    _summary(
                        entries=[_entry(0x1000 + i) for i in range(count)],
                        variant_id="a",
                    )
                ],
            )
        ]  # built BEFORE tracemalloc.start()
        tracemalloc.start()
        try:
            report_service._addendum_lines([region], results)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return peak

    _peak(64)
    low = _peak(1000)
    high = _peak(2000)
    ratio = high / low
    assert ratio <= threshold, (
        f"TC-493: the producer's resident peak still tracks the candidate count "
        f"— peak(E=1000)={low} peak(E=2000)={high} ratio={ratio:.3f} > "
        f"{threshold}"
    )


# ===========================================================================
# TC-494 — LLR-103.4: the explicit emission sequence
# ===========================================================================


def test_tc494_emission_order_is_result_summary_interleaved() -> None:
    """TC-494 / LLR-103.4 — within one region the emitted hit sequence is
    ``for result -> for summary -> (that summary's entry hits, then that
    summary's issue hits) -> after all of that result's summaries, that
    result's check-result issue hits``.

    Fixture precondition ``S >= 2``: the interleaving this node exists to pin
    holds only for ``S >= 2`` or ``V >= 2``. At ``S = V = 1`` the shipped order
    is class-GROUPED (all entries, then all issues), so a ``TC-494`` written on
    an ``S = 1`` fixture is GREEN on ``FIX-B`` — the per-class-bucket mutant it
    exists to kill — and is therefore vacuous.

    The failure report names the POSITION rather than an opaque byte offset,
    which is why the order needs its own node beside ``AT-196``'s byte
    identity.

    Expected at Inc-1: **GREEN by construction** — the expected sequence IS the
    shipped sequence; ``LLR-103.4`` is a PRESERVATION requirement. Inc-2 RED
    arm: ``FIX-B`` (per-class bucket concatenation), executed RED at §7 T-4.
    """
    summaries = [
        _summary(
            entries=[_entry(0x1000)],
            issues=[_issue("I1", 0x1001)],
            variant_id="v0",
            source="chg_0.json",
        ),
        _summary(
            entries=[_entry(0x1002)],
            issues=[_issue("I2", 0x1003)],
            variant_id="v0",
            source="chg_1.json",
        ),
    ]
    assert len(summaries) >= 2, "TC-494 fixture precondition: S >= 2"
    results = [
        _result("v0", summaries, [_check(issues=[_issue("C1", 0x1004)])])
    ]
    text = _addendum_text([_ATTACK_REGION], results)
    observed = [
        "modification" if line.startswith("- modification") else "issue"
        for line in _hit_lines(text)
    ]
    expected = ["modification", "issue", "modification", "issue", "issue"]
    assert observed == expected, (
        f"TC-494: emission order drifted — expected {expected} "
        f"(summary-interleaved, check-result issues last), observed {observed}; "
        f"first difference at position "
        f"{next((i for i, (o, e) in enumerate(zip(observed, expected)) if o != e), min(len(observed), len(expected)))}"
    )


# ===========================================================================
# TC-495 — LLR-103.5: the notice escapes exactly as a hit line does
# ===========================================================================


@pytest.mark.xfail(
    strict=True,
    reason=(
        "NOT EXECUTABLE PRE-FIX (§6.2 / LLR-103.6): there is no notice to "
        "compare a hit line against on the base tree. First real verdict at "
        "Inc-2."
    ),
)
def test_tc495_notice_renders_a_variant_id_exactly_as_a_hit_line_does(
    tmp_path: Path,
) -> None:
    """TC-495 / LLR-103.5 — for the SAME variant id, the notice's rendering
    equals the neighbouring hit line's rendering, byte for byte, over an id set
    spanning ``[A-Za-z0-9-]``, ``_``, ``.``, and a hostile markdown string.

    Intent: revision 1 required "a benign variant id renders with 0 escape
    artefacts". That is executed-FALSE for a correct implementation — ``_`` and
    ``.`` are in ``MD_ESCAPE``, so ``md_safe('variant_a')`` is ``variant\\_a``
    and the threshold's verdict depended entirely on the unpinned choice of
    "benign" id. The invariant that cannot false-fail is the EQUALITY: hostile
    ids escape in both, benign ids escape in both, and neither side is
    privileged.

    This is one third of the escaping story and says so: the equality is also
    satisfied by an implementation that escapes NEITHER side. What forbids that
    is the pair ``AT-199`` (a hostile id cannot forge a notice line) plus
    ``AT-196``'s byte identity, which pins the hit-line side to the shipped
    escaped form.

    Expected at Inc-1: ``xfail(strict=True)``. Expected at Inc-2: GREEN.
    """
    cap = _cap()
    assert hasattr(report_service, "ADDENDUM_TRUNCATION_NOTICE_FMT"), (
        "TC-495: there is no notice format on report_service to compare against"
    )
    for variant_id in ("v1", "cal zone", "variant_a", "v-2.1", "*_[x](http://e.example)~~z~~"):
        results = [
            _result(
                "flooder",
                [
                    _summary(
                        issues=[
                            _issue("CHG-FLOOD", 0x1100 + i, ValidationSeverity.WARNING)
                            for i in range(cap)
                        ],
                        variant_id="flooder",
                    )
                ],
            ),
            _result(
                variant_id,
                [
                    _summary(
                        entries=[_entry(0x1000)],
                        issues=[_issue("CHG-LATE", 0x1500)],
                        variant_id=variant_id,
                    )
                ],
            ),
        ]
        _, text = _write_report(
            tmp_path / re.sub(r"\W+", "_", variant_id),
            results,
            [_ATTACK_REGION],
            ["flooder", variant_id],
        )
        notices = _parsed_notices(text)
        assert len(notices) == 1, f"TC-495 [{variant_id!r}]: {notices}"
        named = notices[0][3]
        hit_rendering = md_safe(variant_id, limit=report_service.REPORT_CELL_CHARS)
        assert named == [hit_rendering], (
            f"TC-495 [{variant_id!r}]: the notice renders {named}, the hit line "
            f"renders {hit_rendering!r} — the two must be byte-identical"
        )
        assert any(
            f"(variant {hit_rendering})" in line for line in _hit_lines(text)
        ), (
            f"TC-495 [{variant_id!r}]: no hit line carries the escaped id, so "
            f"the equality has nothing to compare against"
        )


# ===========================================================================
# TC-498 — LLR-103.1: the region-ops disclosure counter (NOT EXECUTABLE PRE-FIX)
# ===========================================================================


@pytest.mark.xfail(
    strict=True,
    reason=(
        "NOT EXECUTABLE PRE-FIX (§6.2 / §7 T-9, revision 3): the instrument is "
        "the attribution walk's OWN region-op counter, and the walk does not "
        "exist on the base tree. Under the only AVAILABLE pre-fix seam "
        "(counting DeclaredRegion.contains) the shipped producer reads exactly "
        "R x N, so the equality would be GREEN today for the wrong reason. "
        "First real verdict at Inc-2."
    ),
)
def test_tc498_region_ops_equal_r_times_n_under_huge_tiny_geometry() -> None:
    """TC-498 / LLR-103.1 / §10.7 — under ``huge+tiny`` geometry the producer's
    region-op count ``A`` equals ``R x N`` at ``R`` in ``{1, 8, 64, 256}``.

    This is a **disclosure counter with a recorded value, not a pass/fail
    bound**. The bound form ``A <= c x (N + total_hits)`` was CONSIDERED AND
    REJECTED: under ``huge+tiny`` exactly one region matches at every ``R``, so
    the output is R-independent while ``A = R x N`` grows without bound in
    ``R`` and no constant ``c`` exists. A gate that cannot pass is the same
    defect class as one that cannot fail. What this node buys instead: §10.7's
    number cannot go stale silently, and a later batch that swaps in an
    output-sensitive structure fails here LOUDLY and must re-read and rewrite
    the residual rather than leave it over-claiming.

    The counted quantity is pinned: **one region op = one ``ends[i] >= addr``
    comparison in the downward walk**. The ``pmax[i] >= addr`` loop guard, the
    attribution ``bisect_right(starts, addr)`` and the coalesced-cover reject
    pre-filter's bisect are EXCLUDED — executed, only the ends-only convention
    satisfies the equality, and it is the only one invariant under the
    spec-sanctioned choice to drop the reject pre-filter.

    The seam is pinned too: ``report_service._LAST_ADDENDUM_REGION_OPS``, an
    ``int`` reset at ``_addendum_lines`` entry and written at exit. An
    exact-equality gate on an unpinned counter is satisfied by tuning the
    counter until it prints ``R x N``.

    Fixture precondition the equality rests on: EVERY declared region's
    ``start`` lies below the probe address, so the downward walk visits all
    ``R`` entries. Without it, ``A == R x N`` is fixture luck, not a law.

    Expected at Inc-1: ``xfail(strict=True)``. Expected at Inc-2: GREEN,
    recording ``A == R x N`` — the §10.7 disclosure.
    """
    probe = 0x5000
    per_leaf = 100
    assert hasattr(report_service, _REGION_OPS_SEAM), (
        f"TC-498: the named region-op seam report_service.{_REGION_OPS_SEAM} "
        f"does not exist — the attribution walk it counts has not been written"
    )
    for count in (1, 8, 64, 256):
        regions = _huge_tiny_regions(count)
        assert all(region.start <= probe for region in regions), (
            "TC-498 fixture precondition: every region start must lie below the "
            "probe address, else the downward walk short-circuits and A == R x N "
            "is fixture luck"
        )
        results = [
            _result(
                "a",
                [
                    _summary(
                        entries=[_entry(probe) for _ in range(per_leaf)],
                        issues=[_issue("I", probe) for _ in range(per_leaf)],
                        variant_id="a",
                    )
                ],
                [_check(issues=[_issue("C", probe) for _ in range(per_leaf)])],
            )
        ]
        report_service._addendum_lines(regions, results)
        observed = getattr(report_service, _REGION_OPS_SEAM)
        candidates = per_leaf * 3
        assert observed == count * candidates, (
            f"TC-498: region ops at R={count} read {observed}, the disclosed "
            f"residual is R x N = {count * candidates}"
        )


# ===========================================================================
# TC-499 — LLR-103.5: the addendum-scoped counting positive control
# ===========================================================================


def test_tc499_report_wide_truncation_is_not_an_addendum_notice(
    tmp_path: Path,
) -> None:
    """TC-499 / LLR-103.5 — a report in which the PRE-EXISTING declaration-error
    cap fires, while no addendum cap fires, reads **0** addendum notices and at
    least one report-wide ``> TRUNCATED:`` line.

    Intent: this is the positive control that proves the notice predicate is
    ADDENDUM-SCOPED rather than a report-wide grep. The report carries three
    pre-existing ``> TRUNCATED:`` emitters (``report_service.py:1134``,
    ``:1383``, ``:1403``); §7 T-5's own ``flood = 400`` row produces TWO
    ``> TRUNCATED:`` lines, only one of which is the addendum's.

    Expected at Inc-1: **GREEN by vacuity** — the predicate reads 0 on a
    producer with no notice concept at all. Inc-2 RED arm: ``FIX-SCOPE``
    (counting ``> TRUNCATED:`` report-wide instead of addendum-scoped) — the
    arm that proves the scope predicate is scoped.
    """
    over_cap = report_service.MAX_REPORT_ISSUES_PER_VARIANT + 1
    results = [
        _result(
            "v1",
            [
                _summary(
                    entries=[_entry(0x1000)],
                    issues=[
                        # OUTSIDE the declared region, so the addendum's own
                        # per-(region, class) counter never reaches its cap.
                        _issue("CHG-OUT", 0x8000 + i)
                        for i in range(over_cap)
                    ],
                    variant_id="v1",
                )
            ],
        )
    ]
    _, text = _write_report(tmp_path, results, [_ATTACK_REGION], ["v1"])

    cap = _cap()
    for hit_class in (_CLASS_MODIFICATION, _CLASS_CHANGE_ISSUE, _CLASS_CHECK_ISSUE):
        assert _expected_cut(results, _ATTACK_REGION, hit_class, cap)[1] == 0, (
            "TC-499 fixture precondition: no addendum cap may fire, otherwise "
            "the control cannot distinguish scoped from report-wide counting"
        )

    scope = _addendum_scope(text)
    report_wide = [
        line for line in text.splitlines() if line.startswith("> TRUNCATED:")
    ]
    outside = [line for line in report_wide if line not in scope.splitlines()]
    assert outside, (
        "TC-499 fixture precondition: the pre-existing declaration-error cap "
        "must fire OUTSIDE the addendum, otherwise a report-wide grep and an "
        "addendum-scoped count are indistinguishable on this fixture"
    )
    assert _addendum_notices(text) == [], (
        f"TC-499: a report-wide '> TRUNCATED:' line was counted as an addendum "
        f"notice; addendum-scoped notices={_addendum_notices(text)} "
        f"report-wide={report_wide}"
    )
