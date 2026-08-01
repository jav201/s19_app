"""
Markdown project-report generator — batch-07 E7 (HLR-007).

Headless service: :func:`generate_project_report` writes one Markdown
report to ``<project>/reports/<UTC timestamp>-report.md`` from exactly the
LLR-007.8 input set — the per-variant C-6 producer objects
(``ChangeSummary`` / ``CheckRunResult`` riding ``VariantExecutionResult``),
each variant's POST-CHANGE memory map (``VariantExecutionResult.mem_map``,
captured by the E6 execution layer on request), the ``ProjectVariantSet``
inventory, :class:`ReportOptions`, and the tool version. Before-values
always come from ``ChangeSummaryEntry.before_bytes`` — this module never
re-parses an image (no parser import) and never imports Textual code
(LLR-007.1).

Hexdumps reuse the plain-string ``hexview.render_hex_view`` renderer —
never the Rich renderer (LLR-007.3). Each modified region expands to the
row-aligned window
``[max(0, align16(start - context_bytes)),
min(align16_up(end + context_bytes), align16_up(image_top)))``
(LLR-007.2 + F-Q-06, upper bound clamped at the aligned image top so no
all-gap rows are dumped past the highest mapped address); windows whose row
ranges overlap or touch MERGE into one block; addresses inside a window
that are absent from the memory map render through the renderer's existing
gap convention (blank hex cell, ``.`` in the ASCII gutter).

Size discipline (LLR-007.6): at most ``REPORT_MAX_REGIONS_PER_VARIANT``
regions are dumped per variant and the whole document is budgeted against
``REPORT_MAX_TOTAL_BYTES`` at hexdump-block granularity — a cap firing
always writes an explicit in-document ``TRUNCATED`` marker stating the
omitted count plus a truncation-appendix entry, never a silent cut.

Confidentiality (F-S-07): reports carry raw memory bytes. They are written
ONLY under the gitignored ``.s19tool/`` tree (``reports/`` inside the
project work area), this module performs NO logging at all — so report
body content can never reach the rotating log — and its tests use
synthetic in-memory fixtures / public example data exclusively.
"""

from __future__ import annotations

import bisect
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ...range_index import (
    RangeIndex,
    address_in_sorted_ranges,
    build_sorted_range_index,
)
from ...version import __version__
from ..changes import DISPOSITION_APPLIED
from ..changes.io import READ_SIZE_CAP_BYTES
from ..hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view
from ..legend import LEGEND_TABLE
from .entropy_service import ENTROPY_BANDS, compute_entropy
from .markdown_safety import md_code, md_safe
from .report_addendum import DECLARED_REGION_NAME_MAX, DeclaredRegion
from .report_filter import ReportFilterMatcher, _merge_ranges
from ..models import ProjectVariantSet
from .variant_execution_service import (
    SCOPE_ACTIVE,
    SCOPE_ALL,
    SCOPE_ASSIGNMENTS,
    VariantExecutionResult,
)

#: Default ± surrounding-byte count of every modified-region hexdump
#: (LLR-007.2; US-004 "±64, adjustable").
REPORT_CONTEXT_BYTES_DEFAULT = 64

#: Upper bound of the ``context_bytes`` domain (F-S-05). 4096 bytes of
#: context per region keeps the worst-case window at 512+ rows, the
#: per-region ``MAX_HEX_ROWS`` ceiling — measured against the
#: ``make_large_s19`` fixture in the E7 verification run
#: (``assumed — verify per-regime`` in the spec; measurement recorded in
#: the E7 review packet).
REPORT_CONTEXT_BYTES_MAX = 4096

#: Maximum modified regions dumped per variant (LLR-007.6;
#: ``assumed — verify per-regime``, measured at E7 — see review packet).
REPORT_MAX_REGIONS_PER_VARIANT = 128

#: Per-variant declaration-error cap (batch-62 D-20, closing security F7).
#:
#: ``_ByteBudget`` is consumed at hexdump-block granularity only, so the
#: declaration-error section sits OUTSIDE the whole-document accounting — and a
#: corrupt image can mint one issue per parse fault with no bound of its own.
#: batch-62 made that worse before it made it better: raising ``issue.message``'s
#: escape limit from 240 to 500 roughly doubled the section's per-issue cost.
#:
#: 200 mirrors ``flow_report_service.MAX_REPORT_FINDINGS_PER_BLOCK`` deliberately
#: — the two sections have the same unbounded-input shape, so a reader comparing
#: the two report kinds should not have to learn two numbers.
MAX_REPORT_ISSUES_PER_VARIANT = 200

#: Per-variant admitted-row cap for the Modifications table (batch-74,
#: LLR-105.1; the Checklists table joins it at Inc-2, LLR-105.2).
#:
#: Both producers used to emit one row per entry with NO cap, after first
#: flattening the whole population into a list — so the cost was paid before any
#: output existed and no output-side budget could reach it. The wire ceiling is
#: ``MF_ENTRY_COUNT_CEILING = 100_000`` entries per change file at ``≈ 92 + 6·L``
#: bytes per rendered entry, which puts one variant's table far past the whole
#: document's :data:`REPORT_MAX_TOTAL_BYTES` budget.
#:
#: 200 mirrors :data:`MAX_REPORT_ISSUES_PER_VARIANT` and
#: :data:`MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION` deliberately — this module
#: states its one-number policy twice already, and a reader comparing three caps
#: in one document should not have to learn three numbers.
#:
#: ⚠ **The zero-drift property is EXACTLY spent at this value.** The largest
#: single ``(document, variant)`` Modifications table in
#: ``tests/goldens/batch64/addendum-below-bound.md`` is **exactly 200 rows**
#: (document 5, variant ``v0``), and the cap admits ``<= 200``, so it fires
#: nowhere and drifts 0 goldens — but with no margin at all. Editing that golden
#: to carry a 201st row, or lowering this constant by one, re-baselines it and
#: trips the batch-64 golden pin at ``tests/test_report_addendum_bound.py:793``.
MAX_REPORT_ROWS_PER_VARIANT = 200

#: Per-(declared region, hit class) admission cap for the report addendum
#: (batch-64, LLR-103.3/LLR-103.6).
#:
#: The addendum's cost used to be paid entirely BEFORE any output existed — one
#: fully formatted string per matching (region, candidate) pair accumulated in a
#: local list — so no output-side budget could reach it. This cap bounds the
#: producer's OWN resident allocation at ``len(regions) x 3 x K`` hit lines,
#: independently of the variant count and of the per-variant candidate count.
#:
#: 200 mirrors :data:`MAX_REPORT_ISSUES_PER_VARIANT` deliberately, for the same
#: reason that constant mirrors ``flow_report_service`` — a reader comparing two
#: caps in one document should not have to learn two numbers. The in-domain
#: maximum is 2 hits per region, so the margin is ~100x.
MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION = 200

#: The addendum's three hit classes, INDEXED BY CLASS ORDINAL (batch-64, §8.1):
#: ``0`` change-summary entries, ``1`` change-summary issues, ``2`` check-result
#: issues. Consumed positionally by :func:`_addendum_truncation_notice` and by
#: the acceptance suite — a mapping would break both.
ADDENDUM_CLASS_LABELS: Tuple[str, str, str] = (
    "modification",
    "change-file issue",
    "check-file issue",
)

#: Maximum variant identifiers NAMED in one truncation notice; beyond it the
#: notice states how many further distinct variants were affected, not which.
#:
#: The cap is required, not cosmetic: an uncapped list is ``O(V)`` resident and
#: would put the variant count straight back into the bound
#: :data:`MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION` exists to establish.
ADDENDUM_NOTICE_VARIANTS_MAX = 8

#: The addendum truncation notice (batch-64, LLR-103.5). A bound that silently
#: drops evidence turns an evidentiary document into a misleading one, so every
#: (region, hit class) whose cap fires discloses the class, the cap, the dropped
#: count and the affected variants.
#:
#: ⚠ The literal ``> `` prefix is load-bearing twice over. It renders as a
#: call-out rather than as one more ``- `` hit line, AND it is what keeps the
#: notice's escaped values off column 0.
#:
#: That second job is GUARDED, as of batch-64 Inc-3:
#: ``test_no_escaped_field_is_emitted_at_the_head_of_its_line``
#: (``tests/test_report_field_census.py``) walked ``ast.JoinedStr`` only and was
#: structurally blind to a ``.format()``-built template, so an earlier revision
#: of this comment merely DOCUMENTED the hole. The guard now also walks
#: ``NAME.format()`` over module-level string constants and rejects any template
#: line that begins with a substitution field — so deleting the ``> `` here
#: fails that test rather than silently removing the only protection.
ADDENDUM_TRUNCATION_NOTICE_FMT = (
    "> TRUNCATED: {label} hits in this region were capped at {cap}; "
    "{dropped} more not listed (variants affected: {variants})."
)

#: Report-wide Mode-A character cap (batch-62 A-18). THIS module's cap, not the
#: flow report's 240 — each consumer owns its own, because the leaf escaper takes
#: a REQUIRED ``limit`` precisely so no cap policy is inherited by accident.
#:
#: 512 is chosen against the fields, not by taste: ``descriptor.path.name`` and
#: ``entry.linkage_symbol`` have NO upstream cap, and a filesystem basename
#: reaches 255 characters. Adopting the flow report's 240 would have introduced
#: SILENT data loss into an evidentiary document at ~20 sites while claiming to
#: protect it. 512 holds any OS-bounded name verbatim and still bounds the
#: pathological case **per cell**.
#:
#: ⚠ It does NOT bound the document, and an earlier version of this comment
#: claimed it did — "the modifications table is separately capped at
#: ``REPORT_MAX_REGIONS_PER_VARIANT`` rows, so the worst case stays far inside
#: ``REPORT_MAX_TOTAL_BYTES``". That is **false**, and measured so:
#: :data:`REPORT_MAX_REGIONS_PER_VARIANT` is consumed by ``_hexdump_section``
#: ONLY, so ``_modifications_lines`` and ``_checklist_lines`` emit one row per
#: entry with no cap (5 000 entries → 5 000 rows; ~100 000 rows → ~208 MB, ~99×
#: the 2 MiB budget). The unbounded row count is pre-existing, but escaping
#: raised per-cell cost ~1.4–2×, so this batch amplified it. Capping those two
#: tables — mirroring :data:`MAX_REPORT_ISSUES_PER_VARIANT` — is a carried
#: follow-up; the comment is corrected now so the constant is not read as a
#: guarantee it never provided.
REPORT_CELL_CHARS = 512

#: Byte-VALUE cap for one byte-run cell (batch-74, LLR-105.3) — **derived from**
#: :data:`REPORT_CELL_CHARS`, never chosen. A run of ``n`` values renders as
#: ``3n - 1`` characters, so ``3n - 1 <= REPORT_CELL_CHARS`` iff
#: ``n <= (REPORT_CELL_CHARS + 1) // 3``. Keeping it derived leaves
#: :data:`REPORT_CELL_CHARS` the single per-cell policy number rather than
#: introducing a fourth one that could drift away from it.
#:
#: The bound is consumed at the SOURCE — ``_format_bytes`` stops consuming the
#: iterable here — because the fully rendered string IS the allocation being
#: bounded, and slicing it after the fact would pay the ``MF_RUN_LENGTH_CEILING
#: = 1_048_576`` bytes-per-run cost in full before cutting anything.
REPORT_BYTES_PER_CELL = (REPORT_CELL_CHARS + 1) // 3

#: In-cell cue appended to a byte run cut at :data:`REPORT_BYTES_PER_CELL`
#: (batch-74, LLR-105.5): ``01 AB … (+837 more bytes)``.
#:
#: It STATES A COUNT rather than merely marking a cut. A silently shortened byte
#: run in an evidentiary document is a correctness defect, not a cosmetic one —
#: a reader must never take a truncated run for the complete one.
#:
#: Deliberately distinct from ``markdown_safety.TRUNCATION_MARKER``
#: (``"… (truncated)"``), which marks a Mode-A *escaped* value; a byte cell is
#: emitted UNESCAPED, so the two must not be confusable. Every character here is
#: outside ``markdown_safety.MD_ESCAPE`` and none is ``|``, which is what keeps
#: the cell inert and the table row intact without an escaping pass.
REPORT_BYTES_TRUNCATION_CUE_FMT = " … (+{dropped} more bytes)"

#: The characters :data:`REPORT_BYTES_TRUNCATION_CUE_FMT` introduces beyond the
#: uppercase hex alphabet and the space (batch-74, LLR-105.7).
#:
#: ``_format_bytes`` output satisfies ``set(out) ⊆ HEX ∪ {" "} ∪ CUE_ALPHABET``.
#: ``tests/test_report_field_census.py::test_f17`` pins that closed alphabet —
#: WIDENED to this constant, never relaxed to a blacklist. The closed whitelist
#: is what makes "byte cells need no escaping" a structural fact rather than an
#: argument, so replacing it with reasoning would be a security-relevant
#: weakening (batch-62 F-17).
CUE_ALPHABET = "…(+)bemorsty"

#: Hex-digit cap for one ``Address`` cell (batch-74, LLR-106.1). **This is the
#: policy number**; :data:`REPORT_ADDRESS_CHARS` is its consequence, never the
#: other way round.
#:
#: The threat is wire-reachable and was in nobody's charter until it was
#: measured: ``changes.io._ADDRESS_RE`` is ``^0x[0-9A-Fa-f]+$`` with **no digit
#: limit**, and ``int(raw, 16)`` parses without limit — CPython's
#: ``int_max_str_digits`` guard does **not** apply to base-16 parsing. A
#: wire-legal ``'0x' + 'F'*100000`` therefore renders a 100 000-character cell,
#: and the only real ceiling is :data:`READ_SIZE_CAP_BYTES` (268 MB).
#:
#: 16 is a 64-bit address space — the widest any target in this domain uses.
#: Every in-domain address renders to 8 digits (the widest ``Address`` cell in
#: any golden is ``0x00000000``, 10 characters, executed census), so the bound
#: carries 2x margin and fires only on values no target could have produced.
#:
#: ⚠ It must NOT be derived downwards from that census. Choosing 8 (or a cell
#: width near 10) makes the *cap itself* fire on ordinary addresses; the census
#: bounds what is REACHED, never what is ALLOWED.
REPORT_ADDRESS_HEX_DIGITS = 16

#: In-cell cue appended to an ``Address`` cut at
#: :data:`REPORT_ADDRESS_HEX_DIGITS` (batch-74, LLR-106.2/106.4).
#:
#: ⚠ **The cue is what makes the bound honest, not decoration.** A hex address
#: truncated to ``0xFFFF…`` is still a well-formed numeral, so a shortened cell
#: is INDISTINGUISHABLE from a complete one — measured understatement ``2**12248``
#: on a 3572-digit address. The cue's job is to break that shape: a truncated
#: cell must FAIL ``^-?0x[0-9A-F]+$`` and must STATE how many digits are gone.
#:
#: Inertness (LLR-106.4): the ``Address`` cell is emitted UNESCAPED, and
#: :data:`CUE_ALPHABET` covers ``_format_bytes`` only. The natural first spelling
#: ``… (+99988 more hex digits.)`` would carry ``.``, which **is** in
#: ``markdown_safety.MD_ESCAPE``. Every character here is outside ``MD_ESCAPE``
#: and none is ``|`` — executed by ``TC-551`` against the real ``MD_ESCAPE``
#: rather than against a hand-maintained whitelist that could drift away from it.
#: ``…`` (U+2026) is precedented by ``markdown_safety.TRUNCATION_MARKER``.
REPORT_ADDRESS_TRUNCATION_CUE_FMT = " … (+{dropped} more hex digits)"

#: Hex digits kept in a shortened ``Length`` cell (batch-76, LLR-109.4).
#:
#: **REUSED from :data:`REPORT_ADDRESS_HEX_DIGITS`, never a fourth policy
#: number.** The two cells sit side by side in the same row and are read
#: together; independent widths would make one look truncated relative to the
#: other for reasons that have nothing to do with the data.
REPORT_LENGTH_HEX_DIGITS = REPORT_ADDRESS_HEX_DIGITS

#: Integer-safe rational over-approximation of ``log10(2)`` (batch-76,
#: LLR-109.2), used to bound a value's DECIMAL width from ``bit_length()``
#: without ever rendering it.
#:
#: ⚠ **It must over-estimate, never under-estimate.** The bound decides whether
#: ``str(value)`` is safe to evaluate at all, so an under-estimate would admit
#: the very ``ValueError`` this exists to prevent. ``30103/100000`` is
#: ``log10(2) = 0.301029995…`` rounded UP at the fifth decimal, and the ``+ 1``
#: in :func:`_decimal_width_upper_bound` absorbs the truncating floor division.
_LOG10_2_NUMERATOR = 30103
_LOG10_2_DENOMINATOR = 100_000

#: The largest elided-digit count the cue can ever state — the widest the cue's
#: decimal field can grow (batch-74, LLR-106.3).
#:
#: Derived from the wire ceiling, not chosen: an address token lives inside a
#: change file, so it cannot carry more hex digits than
#: :data:`READ_SIZE_CAP_BYTES` bytes of text.
#:
#: ⚠ **The units are deliberately mixed, and naming that is the point.** This
#: subtracts a DIGIT count from a BYTE count. It is sound only because one hex
#: digit occupies at least one byte of file text, so the byte cap is a valid
#: *upper bound* on the digit count — it is **not** an equality and must not be
#: read as one. Nothing downstream needs it to be tight: the only consumer is
#: :data:`REPORT_ADDRESS_CHARS`, which needs the WIDTH of the cue's decimal
#: field, and that width is flat across eight orders of magnitude
#: (``len(str(n))`` is 9 for every ``n`` in ``[1e8, 1e9)``).
REPORT_ADDRESS_MAX_ELIDED_DIGITS = READ_SIZE_CAP_BYTES - REPORT_ADDRESS_HEX_DIGITS

#: Character cap for one rendered ``Address`` cell (batch-74, LLR-106.3) —
#: **derived top-down** from :data:`REPORT_ADDRESS_HEX_DIGITS`, never chosen, and
#: never derived upwards from the golden census.
#:
#: The derivation is the definition: ``"0x"`` + the kept digits + the cue at its
#: widest. ``TC-550`` executes this equality, so the constant cannot drift from
#: its own statement.
REPORT_ADDRESS_CHARS = (
    len("0x")
    + REPORT_ADDRESS_HEX_DIGITS
    + len(
        REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(
            dropped=REPORT_ADDRESS_MAX_ELIDED_DIGITS
        )
    )
)

#: The per-section row-cap notice (batch-74, LLR-105.5). Names the section, the
#: governing constant AND its value, the dropped count and the total, so a
#: reader can change the policy without reading the producer.
#:
#: ⚠ The literal ``> `` prefix is load-bearing for the same two reasons it is on
#: :data:`ADDENDUM_TRUNCATION_NOTICE_FMT`: it renders as a call-out rather than
#: as one more table row, and it keeps the template's first substitution field
#: off column 0 — guarded by
#: ``test_no_escaped_field_is_emitted_at_the_head_of_its_line``.
ROW_TRUNCATION_NOTICE_FMT = (
    "> TRUNCATED: {section}: {dropped} of {total} rows omitted "
    "(cap: MAX_REPORT_ROWS_PER_VARIANT = {cap} rows per variant)."
)

#: Whole-document byte budget (LLR-007.6). Enforced at hexdump-block
#: granularity: a block that would push the document past the budget is
#: omitted with an explicit marker (the marker itself, like the bounded
#: header/table content, is allowed past the budget — explicit beats
#: silent).
REPORT_MAX_TOTAL_BYTES = 2_097_152

#: Closed set of section kinds a refusal is attributed to (batch-76, LLR-108.6).
#:
#: ⚠ **Closedness is the bound.** The aggregated disclosure block emits at most one
#: row per member, so the block's line count is the cardinality of THIS tuple and
#: nothing else — it cannot grow with the variant count ``V`` or the check-file
#: count ``F``. That is the whole reason revision 2 replaced revision 1's
#: per-refusal disclosure line, which was ``O(V)``: at ``V=100`` it measured ~558
#: lines against a ~1 kB allowance, so a CORRECT implementation would have
#: reddened the batch's own ceiling acceptance.
REPORT_SECTION_KINDS: Tuple[str, ...] = (
    "preamble",
    "modified-files",
    "modifications",
    "declaration-errors",
    "checklists",
    "memory-regions",
    "entropy",
    "addendum",
)

#: How many variant indices one disclosure row names before ``+N more``
#: (batch-76, LLR-108.6). Precedent: :data:`ADDENDUM_NOTICE_VARIANTS_MAX`, which
#: solves the same problem for the addendum notice; reused rather than minting a
#: second policy number.
#:
#: Only the integer INDEX of a variant in ``variant_results`` reaches a
#: disclosure — never an operator-derived string. Revision 1 banned even that,
#: which bought anonymity at the price of a disclosure an auditor could not
#: reconcile to a variant, and was stricter than the shipped appendix (which
#: already interpolates ``md_safe(variant_id, …)``).
REPORT_DISCLOSURE_VARIANTS_MAX = ADDENDUM_NOTICE_VARIANTS_MAX

#: The per-variant byte reservation's floor (batch-76, LLR-108.4).
#:
#: **DERIVED, never chosen.** A reservation of ``REPORT_MAX_TOTAL_BYTES // V``
#: shrinks without limit as ``V`` grows; below this floor a variant could not
#: even carry its own structural skeleton, so its section would be a heading with
#: nothing under it. The floor is that skeleton's cost: the variant heading at its
#: widest (a ``REPORT_CELL_CHARS``-bounded id) plus every fixed section heading
#: and the blank line each carries.
#:
#: Executed check at the batch base: one variant's MINIMAL audit record measured
#: **394 B** (a 2-variant report at 2 752 B minus a 1-variant report at 2 358 B).
#: This derivation sits comfortably above that, and ``TC-556`` asserts the
#: relation rather than the number — a hard-coded 394 would go stale the moment a
#: section heading is renamed.
_VARIANT_SKELETON_HEADINGS: Tuple[str, ...] = (
    "### Modified files",
    "### Modifications",
    "### Declaration errors",
    "### Checklists",
    "### Memory regions",
)
REPORT_VARIANT_RESERVATION_FLOOR_BYTES = (
    # "## Variant: " + the widest admissible id, and its newline
    len("## Variant: ") + REPORT_CELL_CHARS + 1
    # each fixed section heading, its newline, and the blank line after it
    + sum(len(heading) + 2 for heading in _VARIANT_SKELETON_HEADINGS)
)

#: The widest EMITTED-UTF-8-BYTE cost of a rendered ``variant_id`` (batch-76
#: merge gate, ``LLR-108.7``).
#:
#: **This exists because ``REPORT_CELL_CHARS`` is a CHARACTER cap and was being
#: charged as a BYTE bound.** ``md_safe(value, limit=N)`` truncates its INPUT at
#: ``N`` characters and only then escapes, so its output can exceed ``N`` bytes
#: several times over: measured, ``limit=512`` emits **1 039 B** for escaped
#: ASCII (2.03x) and **2 063 B** for unescaped non-BMP code points (4.03x).
#: Deriving an allowance term from ``REPORT_CELL_CHARS`` therefore understates it
#: — the per-variant heading term allocated 524 B for a cell that can emit
#: 2 063 B, and the stated ceiling was measurably violated at
#: ``variant_id = chr(0x1F600) * 600``: **+3 757 B at V=50**, **+54 209 B at
#: V=100**, growing ~1 009 B per variant without bound. ``TC-611`` pins the
#: expansion so this can never be re-derived from the character cap.
#:
#: **DERIVED from the shipped surface, never chosen.** ``variant_id`` is a
#: filename component (``workspace.py:485`` — ``item.name`` or ``item.stem``), so
#: it is bounded at 255 UTF-16 code units. A code point costing 4 UTF-8 bytes is
#: non-BMP and therefore costs 2 units, so only 127 of those fit; the
#: byte-maximising choice within the cap is a 3-byte BMP character at 1 unit
#: each. The supremum is thus ``3 * 255``, and escaping cannot beat it because
#: every ``MD_ESCAPE`` member is ASCII and reaches only 2 bytes escaped.
#: Measured: 255 x U+4E00 renders a 777 B heading, against 522 B for 255 escaped
#: backticks and 520 B for 127 emoji.
#:
#: **The precondition is load-bearing and is stated in ``REQUIREMENTS.md``'s
#: non-claims.** A ``variant_id`` constructed longer than the filesystem permits
#: is outside this domain, exactly as ``US-B75-2``'s ``Length`` cell is. What this
#: constant buys is that each allowance term is now sound *by construction*
#: rather than by compensation: before it, the under-derived heading and note
#: terms were covered only by slack in the ``TRUNCATED``-marker terms, so an edit
#: to the markers would have silently falsified the ceiling. ``TC-555``'s slope
#: floor is the guard that now catches that.
_MAX_FILENAME_UTF16_UNITS = 255
_MAX_UTF8_BYTES_PER_UTF16_UNIT = 3
REPORT_VARIANT_ID_MAX_BYTES = (
    _MAX_FILENAME_UTF16_UNITS * _MAX_UTF8_BYTES_PER_UTF16_UNIT
)

#: Cap on itemised truncation-appendix notes (batch-76, LLR-108.9).
#:
#: **DERIVED from the disclosure budget, never chosen.** Without a cap the
#: appendix is ``O(V·F)`` — one note per variant per fired cap — which is the
#: second unbounded term in the document.
#:
#: Executed against the batch base: **no byte-identity golden contains a
#: truncation appendix at all** (``grep -rln '## Truncation appendix'
#: tests/goldens/`` returns nothing), and the three assertions that reference one
#: each exercise a SINGLE note. So any cap at or above 4 is inert against the
#: current suite — P-17, measured, not assumed.
REPORT_MAX_TRUNCATION_NOTES = 64

#: ``ReportOptions.execution_mode`` domain (LLR-007.4 (a) / F-A-17).
REPORT_MODE_BATCH = "batch"
REPORT_MODE_PER_ASSIGNMENT = "per-assignment"
REPORT_MODE_ACTIVE = "active-only"
REPORT_EXECUTION_MODES: tuple[str, ...] = (
    REPORT_MODE_BATCH,
    REPORT_MODE_PER_ASSIGNMENT,
    REPORT_MODE_ACTIVE,
)

#: ``ReportOptions.assignment_source`` domain — whether the executed
#: variant→file mapping came from ``project.json`` or from the LLR-006.1
#: manifest-absent default (recorded in the header per LLR-007.4 (a)).
REPORT_SOURCE_MANIFEST = "manifest"
REPORT_SOURCE_DEFAULT = "default"
REPORT_ASSIGNMENT_SOURCES: tuple[str, ...] = (
    REPORT_SOURCE_MANIFEST,
    REPORT_SOURCE_DEFAULT,
)

#: Report filename timestamp format — UTC, lexicographic == chronological
#: across seconds (LLR-007.5).
REPORT_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%SZ"

#: The single authoritative report-filename regex (LLR-007.5 / F-Q-05).
REPORT_FILENAME_REGEX = re.compile(r"^\d{8}T\d{6}Z(-\d{2})?-report\.md$")

#: Reports subdirectory inside a project work area, created on demand
#: (LLR-007.7).
REPORTS_DIR_NAME = "reports"

#: E6 execution-scope token → report ``execution_mode`` token (F-A-17),
#: so the E8 trigger records HOW the reported run was scoped without any
#: report vocabulary leaking into ``app.py`` (LLR-008.5).
EXECUTION_SCOPE_TO_REPORT_MODE: dict[str, str] = {
    SCOPE_ACTIVE: REPORT_MODE_ACTIVE,
    SCOPE_ALL: REPORT_MODE_BATCH,
    SCOPE_ASSIGNMENTS: REPORT_MODE_PER_ASSIGNMENT,
}

#: Injectable UTC clock type (LLR-007.5 ``now_fn``, the B-4 pattern).
NowFn = Callable[[], datetime]


def _default_now() -> datetime:
    """
    Summary:
        Return the current UTC time — the default ``now_fn`` clock.

    Returns:
        datetime: Timezone-aware ``datetime.now(timezone.utc)``.

    Dependencies:
        Used by:
            - generate_project_report
    """
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ReportOptions:
    """
    Summary:
        Per-invocation report knobs (LLR-007.2): the hexdump context size,
        the execution mode recorded in the header (F-A-17), and the
        manifest-or-default assignment source. NOT persisted anywhere —
        every report generation supplies its own options.

    Args:
        context_bytes (int): ± surrounding bytes per modified-region
            hexdump. Domain ``0 <= context_bytes <=
            REPORT_CONTEXT_BYTES_MAX`` — an out-of-domain value raises ONE
            explicit ``ValueError`` at construction, never a silent clamp
            (F-S-05).
        execution_mode (str): One token of :data:`REPORT_EXECUTION_MODES`
            — how the reported run was scoped (LLR-007.4 (a)).
        assignment_source (str): One token of
            :data:`REPORT_ASSIGNMENT_SOURCES` — whether the variant→file
            mapping came from ``project.json`` or the manifest-absent
            default.
        include_legend (bool): When ``True`` (default), the report emits the
            classification-legend section (LLR-022.2) from
            :data:`s19_app.tui.legend.LEGEND_TABLE`. ``False`` omits it.
        declared_regions (Tuple[DeclaredRegion, ...]): Operator-declared memory
            regions (LLR-024.2). When non-empty, the report emits an addendum
            listing each region and the modifications/issues whose address
            falls inside it. Each entry must be a :class:`DeclaredRegion`.
        report_filter (Optional[ReportFilterMatcher]): The RESOLVED report
            filter (LLR-055.1, batch-35 B-07) restricting the Modifications
            rows, Checklists rows, and Memory-regions hexdump windows to
            matching items (LLR-055.2) under an audit header. ``None`` (the
            default) means no filtering — the output stays byte-identical
            to the pre-batch report (LLR-055.3). Must already be resolved
            on the UI thread (D-9); a non-matcher value raises ONE explicit
            ``ValueError`` at construction.

    Returns:
        None: Frozen dataclass container.

    Raises:
        ValueError: When ``context_bytes`` is not an ``int`` inside the
            F-S-05 domain, ``execution_mode`` / ``assignment_source`` is
            not a domain token, or ``report_filter`` is neither ``None``
            nor a :class:`ReportFilterMatcher`.

    Data Flow:
        - Built by the TUI report dialog (E8) or a headless caller.
        - Consumed by :func:`generate_project_report` (header lines,
          window math).

    Dependencies:
        Used by:
            - generate_project_report
            - tests/test_report_service.py

    Example:
        >>> ReportOptions().context_bytes
        64
    """

    context_bytes: int = REPORT_CONTEXT_BYTES_DEFAULT
    execution_mode: str = REPORT_MODE_BATCH
    assignment_source: str = REPORT_SOURCE_DEFAULT
    include_legend: bool = True
    include_entropy: bool = True
    declared_regions: Tuple[DeclaredRegion, ...] = ()
    report_filter: Optional[ReportFilterMatcher] = None

    def __post_init__(self) -> None:
        """
        Summary:
            Validate every field against its domain — one explicit
            ``ValueError`` per F-S-05, never a silent clamp.

        Raises:
            ValueError: On any out-of-domain field value.
        """
        if (
            not isinstance(self.context_bytes, int)
            or self.context_bytes < 0
            or self.context_bytes > REPORT_CONTEXT_BYTES_MAX
        ):
            raise ValueError(
                f"context_bytes must be an integer in "
                f"0..{REPORT_CONTEXT_BYTES_MAX}, got "
                f"{self.context_bytes!r} - the value is rejected, not "
                f"clamped"
            )
        if self.execution_mode not in REPORT_EXECUTION_MODES:
            raise ValueError(
                f"execution_mode must be one of {REPORT_EXECUTION_MODES}, "
                f"got {self.execution_mode!r}"
            )
        if self.assignment_source not in REPORT_ASSIGNMENT_SOURCES:
            raise ValueError(
                f"assignment_source must be one of "
                f"{REPORT_ASSIGNMENT_SOURCES}, got "
                f"{self.assignment_source!r}"
            )
        if not isinstance(self.include_legend, bool):
            raise ValueError(
                f"include_legend must be a bool, got "
                f"{self.include_legend!r}"
            )
        if not isinstance(self.include_entropy, bool):
            raise ValueError(
                f"include_entropy must be a bool, got "
                f"{self.include_entropy!r} - the value is rejected, not "
                f"coerced"
            )
        for region in self.declared_regions:
            if not isinstance(region, DeclaredRegion):
                raise ValueError(
                    f"declared_regions entries must be DeclaredRegion, got "
                    f"{region!r}"
                )
        if self.report_filter is not None and not isinstance(
            self.report_filter, ReportFilterMatcher
        ):
            raise ValueError(
                f"report_filter must be a ReportFilterMatcher or None, got "
                f"{self.report_filter!r} - the value is rejected, not "
                f"coerced"
            )


def _align16(value: int) -> int:
    """Round ``value`` DOWN to a 16-byte (``HEX_WIDTH``) boundary."""
    return (value // HEX_WIDTH) * HEX_WIDTH


def _align16_up(value: int) -> int:
    """Round ``value`` UP to a 16-byte (``HEX_WIDTH``) boundary."""
    return ((value + HEX_WIDTH - 1) // HEX_WIDTH) * HEX_WIDTH


def compute_hexdump_windows(
    regions: Sequence[Tuple[int, int]],
    context_bytes: int,
    image_top: int,
    merge_gap_bytes: int = 0,
) -> List[Tuple[int, int]]:
    """
    Summary:
        Expand each modified region to its row-aligned hexdump window and
        MERGE windows whose row ranges overlap or touch (LLR-007.2 +
        F-Q-06) so every row is dumped at most once.

    Args:
        regions (Sequence[Tuple[int, int]]): Half-open ``(start, end)``
            modified byte ranges (the ``applied`` summary entries), in
            document order.
        context_bytes (int): ± surrounding bytes per region (already
            domain-validated by :class:`ReportOptions`).
        image_top (int): EXCLUSIVE top of the mapped image — highest
            mapped address + 1 — so a top byte sitting exactly on a row
            boundary still gets its full row.
        merge_gap_bytes (int): Additional bridge for the merge fold
            (batch-34 B-08): windows separated by at most this many bytes
            merge into one. ``0`` (the default) preserves the original
            overlap-or-touch behavior byte-identically for every existing
            caller; the diff report passes ``5 * HEX_WIDTH`` so changes
            within five hex rows share one window (the operator's
            "+5 lines" limit).

    Returns:
        List[Tuple[int, int]]: Merged half-open windows, ascending, each
        bound a multiple of ``HEX_WIDTH``:
        ``[max(0, align16(start - c)), min(align16_up(end + c),
        align16_up(image_top)))`` per region before merging. The lower
        bound clamps at address 0 (no underflow); the upper bound clamps
        at the aligned image top.

    Data Flow:
        - Per region: align the context-padded bounds, clamp at 0 and at
          ``align16_up(image_top)``, drop empty windows.
        - Sort, then fold: a window starting at or before the previous
          window's end extends it (adjacency merges too — both bounds are
          row-aligned, so touching windows share no gap row).

    Dependencies:
        Uses:
            - _align16 / _align16_up
        Used by:
            - generate_project_report (via _hexdump_section)
            - tests/test_report_service.py (window-math edge fixtures)

    Example:
        >>> compute_hexdump_windows([(0x100, 0x104), (0x114, 0x118)], 0, 0x200)
        [(256, 288)]
    """
    top_aligned = _align16_up(image_top)
    windows: List[Tuple[int, int]] = []
    for start, end in regions:
        low = max(0, _align16(start - context_bytes))
        high = min(_align16_up(end + context_bytes), top_aligned)
        if high > low:
            windows.append((low, high))
    windows.sort()
    merged: List[List[int]] = []
    for low, high in windows:
        if merged and low <= merged[-1][1] + merge_gap_bytes:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return [(low, high) for low, high in merged]


def _line_bytes(lines: Sequence[str]) -> int:
    """Return the UTF-8 byte cost of ``lines`` joined with ``\\n``.

    The ``+ 1`` per line is deliberate and **must not** be re-derived from
    :func:`document_bytes` (LLR-102.2). Sections are accounted in ~12 separate
    ``emit()`` batches, so the accounting function has to be *partition
    invariant*: this form charges the same total under every partition, whereas
    ``len("\\n".join(batch))`` loses one byte per batch boundary and would
    undercount linearly in the variant count. The whole document is therefore
    over-accounted by exactly one byte — the conservative direction.
    """
    return sum(len(line.encode("utf-8")) + 1 for line in lines)


def document_bytes(text: str) -> bytes:
    """
    Summary:
        Encode a composed report document to the exact bytes written to disk
        (LLR-102.1) — the single seam for every report writer **that consults a**
        :class:`_ByteBudget`. Takes the already-composed text rather than a line
        sequence so that both callers can use it: :func:`generate_project_report`
        joins lines, while ``flow_report_service.compose_flow_report`` returns a
        ``str``. ``diff_report_service`` is deliberately outside this seam — it
        documents "no run cap, no byte budget", so it has no accounting that a
        newline expansion could contradict.

    Args:
        text (str): The composed document.

    Returns:
        bytes: ``text`` encoded UTF-8, with ``\\n`` preserved verbatim.

    Data Flow:
        - composed text -> bytes -> ``Path.write_bytes``. Writing bytes is what
          makes the file platform-independent: ``Path.write_text`` opens in text
          mode, so a host whose ``os.linesep`` is CRLF silently expands every
          ``\\n`` and the file ends up larger than :func:`_line_bytes` charged
          for it — by ``N - 2`` bytes, which matters because
          ``flow_report_service`` gates section *emission* on that budget.

    Dependencies:
        Used by:
            - generate_project_report
            - flow_report_service.write_flow_report

    Example:
        >>> document_bytes("a\\nb")
        b'a\\nb'
    """
    return text.encode("utf-8")


@dataclass(slots=True)
class _ByteBudget:
    """
    Summary:
        Running whole-document byte budget (LLR-007.6) — consumed as
        sections are emitted, queried before each hexdump block.

    Args:
        limit (int): The document budget
            (:data:`REPORT_MAX_TOTAL_BYTES`, read at call time so tests
            can shrink it).
        used (int): Bytes accounted so far.

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - generate_project_report / _hexdump_section
    """

    limit: int
    used: int = 0

    def fits(self, extra: int) -> bool:
        """Report whether ``extra`` more bytes stay within the budget."""
        return self.used + extra <= self.limit

    def consume(self, extra: int) -> None:
        """Account ``extra`` emitted bytes."""
        self.used += extra

    def remaining(self) -> int:
        """Bytes still admissible; never negative."""
        return max(0, self.limit - self.used)


def _disclosure_allowance(variant_count: int) -> int:
    """
    Summary:
        The byte allowance the document may spend ABOVE
        :data:`REPORT_MAX_TOTAL_BYTES` on content that is emitted
        unconditionally (batch-76, LLR-108.7): the ``O(1)`` header, the
        per-variant headings, the ``TRUNCATED`` markers, the capped truncation
        appendix, and the single aggregated disclosure block.

    Args:
        variant_count (int): ``len(variant_results)`` — the only ``O(V)`` term,
            and it is named rather than emergent (non-claim (j)).

    Returns:
        int: The allowance in bytes.

    Data Flow:
        - The integer field width is read from ``sys.maxsize`` AT CALL TIME
          rather than typed as a literal, so the derivation has a fixed point on
          any host instead of encoding this one's word size.
        - Every term is an UPPER bound: the widest row the closed label set can
          produce, times the cardinality of that set. Because
          :data:`REPORT_SECTION_KINDS` is closed, this is ``O(1)`` in both ``V``
          and ``F`` — the property that makes the ceiling invariant.

    Dependencies:
        Uses:
            - REPORT_SECTION_KINDS / REPORT_DISCLOSURE_VARIANTS_MAX
            - REPORT_MAX_TRUNCATION_NOTES / REPORT_CELL_CHARS
        Used by:
            - generate_project_report / the AT-250..AT-252 ceiling acceptances

    Example:
        >>> _disclosure_allowance(0) > 0
        True
    """
    # Widest decimal field this host can render, read rather than typed.
    width = len(str(sys.maxsize))
    # One disclosure row at its widest: a label, three counts, and a bounded
    # list of integer variant indices followed by "+N more".
    widest_label = max(len(kind) for kind in REPORT_SECTION_KINDS)
    row = (
        len("- : sections , lines , bytes  (variants )")
        + widest_label
        + 3 * width
        + REPORT_DISCLOSURE_VARIANTS_MAX * (width + 2)
        + len(" +N more") + width
    )
    block = (
        len("## Omitted content") + 2
        + len(REPORT_SECTION_KINDS) * (row + 1)
        + 2
    )
    # The capped appendix: each note names a variant (id bounded by
    # REPORT_VARIANT_ID_MAX_BYTES) and a cap sentence.
    note = len("- Variant '': ") + REPORT_VARIANT_ID_MAX_BYTES + 160
    appendix = len("## Truncation appendix") + 2 + REPORT_MAX_TRUNCATION_NOTES * (note + 1)
    # The one deliberate O(V) term (LLR-108.5): every variant's heading is
    # emitted whatever its reservation, so no variant can vanish — plus the at
    # most two unconditional ``> TRUNCATED:`` markers a variant's hexdump
    # section can carry. Markers are unconditional for the same standing
    # "explicit beats silent" reason recorded on REPORT_MAX_TOTAL_BYTES, so the
    # ceiling has to account for them here or the bound would be understated.
    marker = len("> TRUNCATED: .") + 256
    headings = variant_count * (
        len("## Variant: ") + REPORT_VARIANT_ID_MAX_BYTES + 2 + 2 * (marker + 1)
    )
    # The O(1) header, exempted by P-16: measured flat at 181 B from V=1 to
    # V=20 000, so exempting it does not weaken V-invariance the way exempting
    # the O(V) inventory/overview would have.
    header = 1024
    return block + appendix + headings + header


@dataclass(slots=True)
class _Refusals:
    """
    Summary:
        The ``O(1)`` refusal accumulator (batch-76, LLR-108.6). Keyed by a
        CLOSED tuple of section-kind literals, so the disclosure it produces has
        at most ``len(REPORT_SECTION_KINDS)`` rows however many batches are
        refused.

    Returns:
        None: Dataclass container.

    Data Flow:
        - ``sections`` / ``lines`` / ``bytes`` are counted per kind. The BYTE
          total is the one that matters: revision 1 disclosed "3 sections
          omitted", which is satisfiable while telling an auditor nothing about
          how much of their document is missing.
        - ``variants`` holds integer INDICES only — never a variant id string.

    Dependencies:
        Used by:
            - _EmissionGate / generate_project_report
    """

    sections: Dict[str, int] = field(default_factory=dict)
    lines: Dict[str, int] = field(default_factory=dict)
    byte_count: Dict[str, int] = field(default_factory=dict)
    variants: Dict[str, List[int]] = field(default_factory=dict)

    def record(self, kind: str, batch: Sequence[str], cost: int, variant: Optional[int]) -> None:
        """Record one refused batch against ``kind``."""
        self.sections[kind] = self.sections.get(kind, 0) + 1
        self.lines[kind] = self.lines.get(kind, 0) + len(batch)
        self.byte_count[kind] = self.byte_count.get(kind, 0) + cost
        if variant is not None:
            seen = self.variants.setdefault(kind, [])
            if variant not in seen:
                seen.append(variant)

    def any(self) -> bool:
        """Whether anything at all was refused."""
        return bool(self.sections)

    def total_bytes(self) -> int:
        """Total refused bytes across every kind."""
        return sum(self.byte_count.values())


class _EmissionGate:
    """
    Summary:
        The single admission seam for the whole document (batch-76, HLR-108).
        Every line that reaches the file passes through :meth:`emit` or
        :meth:`emit_unconditional` — there is no third way in, which is what
        ``TC-553``'s AST census asserts.

    Data Flow:
        - **Two budgets, and BOTH must admit.** ``_budget`` is the document's;
          ``_reservation`` is the current variant's share. Gating on the
          reservation ALONE would break the ceiling: a FLOORED reservation
          over-subscribes the document (``Σ = V · max(CAP//V, floor)``, measured
          at **48.8× CAP** for ``V=100 000``, floor 1 024), so a large-`V` report
          would blow the very bound this class exists to enforce. That is P-27,
          found by executing the floor rather than by reading the clause.
        - **Refusal is per-call and does not latch** (LLR-108.2): a batch too
          large to fit is refused whole, and a later smaller batch is still
          admitted. Latching would make the document's contents depend on
          emission ORDER, which is attacker-controlled.
        - **Unconditional emissions bypass both budgets** and are covered by
          :func:`_disclosure_allowance`: the ``O(1)`` header (P-16) and each
          variant's heading (LLR-108.5). They are what keep a budget-exhausted
          report readable and keep every variant present.

    Dependencies:
        Used by:
            - generate_project_report / _hexdump_section
    """

    __slots__ = ("lines", "_budget", "_reservation", "_refusals", "_variant")

    def __init__(self, limit: int) -> None:
        self.lines: List[str] = []
        self._budget = _ByteBudget(limit=limit)
        self._reservation: Optional[_ByteBudget] = None
        self._refusals = _Refusals()
        self._variant: Optional[int] = None

    def begin_variant(self, index: int, reservation: int) -> None:
        """Open a variant's own reservation; closes any previous one."""
        self._variant = index
        self._reservation = _ByteBudget(limit=reservation)

    def end_variants(self) -> None:
        """Leave per-variant scope; later batches are document-scoped again."""
        self._variant = None
        self._reservation = None

    def fits(self, cost: int) -> bool:
        """Whether ``cost`` bytes are admissible under BOTH active budgets."""
        if not self._budget.fits(cost):
            return False
        if self._reservation is not None and not self._reservation.fits(cost):
            return False
        return True

    def emit(self, batch: Sequence[str], kind: str) -> bool:
        """Admit ``batch`` if it fits; otherwise refuse it WHOLE and record it.

        Returns ``True`` when admitted. The batch is never partially admitted —
        half a table is not a smaller table, it is a corrupt one.
        """
        if not batch:
            return True
        cost = _line_bytes(batch)
        if not self.fits(cost):
            self._refusals.record(kind, batch, cost, self._variant)
            return False
        self.lines.extend(batch)
        self._budget.consume(cost)
        if self._reservation is not None:
            self._reservation.consume(cost)
        return True

    def emit_unconditional(self, batch: Sequence[str]) -> None:
        """Admit ``batch`` past both budgets; charged to the allowance.

        Reserved for the ``O(1)`` header and the per-variant headings. Every use
        widens the ceiling by a term that :func:`_disclosure_allowance` must
        account for, so this method is deliberately awkward to reach for.
        """
        if not batch:
            return
        self.lines.extend(batch)

    @property
    def refusals(self) -> _Refusals:
        """The refusal accumulator, for the tail disclosure block."""
        return self._refusals

    @property
    def budget(self) -> _ByteBudget:
        """The document budget — read-only accounting for the hexdump seam."""
        return self._budget


def _disclosure_lines(refusals: _Refusals) -> List[str]:
    """
    Summary:
        Render the single aggregated disclosure block (batch-76, LLR-108.6) —
        emitted ONCE at the document tail, never per refusal.

    Args:
        refusals (_Refusals): The ``O(1)`` accumulator.

    Returns:
        List[str]: The block, or ``[]`` when nothing was refused.

    Data Flow:
        - One row per REFUSED member of the closed :data:`REPORT_SECTION_KINDS`
          tuple, so the block's line count is bounded by that cardinality and is
          invariant in ``V`` and ``F``.
        - The BYTE total is stated, not just a section count: an auditor needs
          to know how much of the document is missing, and "3 sections omitted"
          does not say.
        - Only integer variant INDICES appear, capped at
          :data:`REPORT_DISCLOSURE_VARIANTS_MAX` with a ``+N more`` tail, so no
          operator-derived string reaches the block.

    Dependencies:
        Used by:
            - generate_project_report
    """
    if not refusals.any():
        return []
    out = ["## Omitted content", ""]
    for kind in REPORT_SECTION_KINDS:
        sections = refusals.sections.get(kind, 0)
        if not sections:
            continue
        indices = refusals.variants.get(kind, [])
        shown = indices[:REPORT_DISCLOSURE_VARIANTS_MAX]
        listed = ", ".join(str(index) for index in shown)
        if len(indices) > len(shown):
            listed += f" +{len(indices) - len(shown)} more"
        suffix = f" (variants {listed})" if listed else ""
        out.append(
            f"- {kind}: sections {sections}, "
            f"lines {refusals.lines.get(kind, 0)}, "
            f"bytes {refusals.byte_count.get(kind, 0)}{suffix}"
        )
    out.append("")
    return out


def _select_notes(notes: Sequence[Tuple[int, str]], cap: int) -> Tuple[List[str], int, int]:
    """
    Summary:
        Choose which truncation-appendix notes to itemise (batch-76, LLR-108.9)
        — **round-robin by variant**, at most one note per variant before any
        variant's second.

    Args:
        notes (Sequence[Tuple[int, str]]): ``(variant_index, note_text)`` in
            generation order.
        cap (int): :data:`REPORT_MAX_TRUNCATION_NOTES`.

    Returns:
        Tuple[List[str], int, int]: the itemised notes, the count NOT itemised,
        and the number of DISTINCT variants with an un-itemised note.

    Data Flow:
        - ``notes[:cap]`` — the obvious implementation — retains the EARLIEST,
          which is attacker-choosable: flood with cheap region-cap notes from
          variants named to sort ahead and the note naming the real target is
          evicted. Round-robin makes eviction depend on how many notes a variant
          produced, not on where it sits in the ordering.
        - ``itemised + not_itemised == len(notes)`` is an invariant ``TC-559``
          asserts, so a selection that silently drops a note cannot pass.

    Dependencies:
        Used by:
            - generate_project_report
    """
    by_variant: Dict[int, List[str]] = {}
    order: List[int] = []
    for index, text in notes:
        if index not in by_variant:
            by_variant[index] = []
            order.append(index)
        by_variant[index].append(text)
    selected: List[str] = []
    chosen: Dict[int, int] = {index: 0 for index in order}
    round_index = 0
    while len(selected) < cap:
        progressed = False
        for index in order:
            if len(selected) >= cap:
                break
            bucket = by_variant[index]
            if round_index < len(bucket):
                selected.append(bucket[round_index])
                chosen[index] += 1
                progressed = True
        if not progressed:
            break
        round_index += 1
    not_itemised = len(notes) - len(selected)
    distinct = sum(
        1 for index in order if chosen[index] < len(by_variant[index])
    )
    return selected, not_itemised, distinct


def _format_bytes(values: Optional[Iterable[int]], *, max_bytes: int) -> str:
    """
    Summary:
        Format a byte run as space-separated two-hex-digit tokens, consuming
        at most ``max_bytes`` values; ``None`` (no value captured) renders as
        ``-``. A run cut short carries
        :data:`REPORT_BYTES_TRUNCATION_CUE_FMT` stating how many byte values
        were NOT rendered (batch-74, LLR-105.3/105.5).

    Args:
        values (Optional[Iterable[int]]): Byte values 0-255, or ``None``.
        max_bytes (int): Byte-VALUE cap — required and keyword-only, matching
            ``md_safe``'s required ``limit`` so no cap policy is ever inherited
            by accident. Callers pass :data:`REPORT_BYTES_PER_CELL`.

    Returns:
        str: e.g. ``"01 AB FF"``, ``"01 AB … (+837 more bytes)"``, or ``"-"``.
        A run of ``max_bytes`` or fewer values is byte-identical to the
        un-capped rendering.

    Data Flow:
        - The cap is applied to the ITERABLE, not to a rendered string: the
          fully rendered string is the allocation being bounded, so building it
          and slicing would pay the whole ``MF_RUN_LENGTH_CEILING`` cost first.
        - The elided count comes from ``len(values)`` when the run is sized
          (every production call site passes a tuple, so this is ``O(1)``) and
          otherwise from draining the exhausted iterator, which counts without
          retaining.

    Dependencies:
        Uses:
            - REPORT_BYTES_TRUNCATION_CUE_FMT
        Used by:
            - _modifications_lines / _checklist_lines

    Example:
        >>> _format_bytes((0x01, 0xAB), max_bytes=1)
        '01 … (+1 more bytes)'
    """
    if values is None:
        return "-"
    try:
        total: Optional[int] = len(values)  # type: ignore[arg-type]
    except TypeError:
        total = None
    iterator = iter(values)
    rendered = " ".join(
        f"{value:02X}" for value in islice(iterator, max_bytes)
    )
    dropped = (
        max(0, total - max_bytes)
        if total is not None
        else sum(1 for _ in iterator)
    )
    if not dropped:
        return rendered
    return rendered + REPORT_BYTES_TRUNCATION_CUE_FMT.format(dropped=dropped)


def _format_address(value: int) -> str:
    """
    Summary:
        Render one ``Address`` cell, bounded at
        :data:`REPORT_ADDRESS_HEX_DIGITS` hex digits (batch-74, LLR-106.1/106.2).
        A value inside the bound is byte-identical to the shipped
        ``f"0x{value:08X}"``; a value past it renders its leading digits plus
        :data:`REPORT_ADDRESS_TRUNCATION_CUE_FMT`.

    Args:
        value (int): The entry's address. Unbounded by construction —
            ``changes.io._ADDRESS_RE`` carries no digit limit and ``int(raw, 16)``
            parses without one, so a wire-legal file can reach 100 000 digits.

    Returns:
        str: e.g. ``"0x80040000"``, or
        ``"0xFFFFFFFFFFFFFFFF … (+99984 more hex digits)"``.

    Data Flow:
        - The kept digits are derived ARITHMETICALLY — ``magnitude >> 4·(total −
          kept)`` — never by formatting the value and slicing the result. The
          full rendering IS the allocation being bounded, so producing it first
          would pay the whole cost this function exists to avoid. Measured at
          10**6 hex digits: shift+format **0.000002 s**, full format **0.0014 s**.
        - ``bit_length()`` is O(1) (a limb count, not a scan) and the shift
          allocates only the result's limbs, so residency is independent of the
          value's size — the property ``AT-249`` gates.
        - The elided count is the digit count OF THE VALUE, ``(bit_length()+3)//4
          − kept``, never ``len(raw) − 2``: ``int('0x0FF…', 16)`` discards the
          wire's leading zeros, so the two differ and a raw-string count misfires.

    Dependencies:
        Uses:
            - REPORT_ADDRESS_HEX_DIGITS / REPORT_ADDRESS_TRUNCATION_CUE_FMT
        Used by:
            - _modifications_lines / _checklist_lines

    Example:
        >>> _format_address(0x80040000)
        '0x80040000'
    """
    total = (value.bit_length() + 3) // 4
    kept = REPORT_ADDRESS_HEX_DIGITS
    if total <= kept:
        return f"0x{value:08X}"
    # Negative addresses are out of the wire domain (``_ADDRESS_RE`` admits no
    # sign) but are constructor-reachable; carry the sign rather than silently
    # rendering a positive token for a negative value.
    magnitude = -value if value < 0 else value
    sign = "-" if value < 0 else ""
    leading = magnitude >> (4 * (total - kept))
    return (
        f"{sign}0x{leading:0{kept}X}"
        + REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(dropped=total - kept)
    )


def _decimal_width_upper_bound(value: int) -> int:
    """
    Summary:
        An UPPER bound on ``len(str(value))``'s digit count, computed from
        ``bit_length()`` alone (batch-76, LLR-109.2) — never by rendering the
        value.

    Args:
        value (int): Any integer, of any width. The sign is ignored; the bound
            covers digits only.

    Returns:
        int: A digit count that is never smaller than the true one.

    Data Flow:
        - ``bit_length()`` is O(1) (a limb count, not a scan), so this is cheap
          at every magnitude — which is the point: the check has to be safe to
          run on a value that ``str()`` would refuse to render.
        - The bound is deliberately loose. A tight bound would need the decimal
          expansion, and producing that expansion is exactly the operation being
          guarded.

    Dependencies:
        Used by:
            - _format_length

    Example:
        >>> _decimal_width_upper_bound(999)
        4
    """
    bits = value.bit_length()
    if bits == 0:
        return 1
    return (bits * _LOG10_2_NUMERATOR) // _LOG10_2_DENOMINATOR + 1


def _format_length(value: int) -> str:
    """
    Summary:
        Render one ``Length`` cell (batch-76, HLR-109 / LLR-109.1-109.3). A
        value CPython can render decimally is emitted unchanged; one it cannot
        is emitted as a bounded hex token carrying its sign and stating how many
        hex digits were elided.

    Args:
        value (int): ``address_end - address_start``. Unbounded in the
            CONSTRUCTOR domain — ``ChangeSummaryEntry`` / ``CheckRunEntry`` hold
            independent endpoints and have no ``__post_init__`` validation.

    Returns:
        str: e.g. ``"4"``, ``"-12"``, or
        ``"0xFFFFFFFFFFFFFFFF … (+1284 more hex digits)"``.

    Data Flow:
        - **In-domain renders DECIMAL, byte-identically to the shipped cell.**
          This is not a style choice: ``AT-256`` pins the whole under-cap
          document against a golden captured from the shipped producer, and that
          golden carries ``| 1 |``, ``| 2 |``. Rendering hex in-domain — the way
          :func:`_format_address` does, because ADDRESSES are hex in the shipped
          output — would drift every Length cell in the repository.
        - The domain test is an arithmetic upper bound vs
          ``sys.get_int_max_str_digits()`` read **at call time**, so a host or a
          test that moves the limit moves this with it. ``0`` means the limit is
          disabled, hence always in-domain.
        - ``str(value)`` is **never evaluated on the untested path** — that call
          IS the ``ValueError``. Capping the rendered width instead ("format
          then slice") does not help: the int->str conversion happens before the
          slice, so it raises first. Measured, and it is why ``TC-568`` exists.
        - The kept digits come from a SHIFT, never from formatting and slicing,
          so residency stays independent of the value's size — the same
          arithmetic :func:`_format_address` uses.

    Dependencies:
        Uses:
            - REPORT_LENGTH_HEX_DIGITS / REPORT_ADDRESS_TRUNCATION_CUE_FMT
            - _decimal_width_upper_bound
        Used by:
            - _modifications_lines / _checklist_lines

    Example:
        >>> _format_length(4)
        '4'
    """
    limit = sys.get_int_max_str_digits()
    if limit == 0 or _decimal_width_upper_bound(value) <= limit:
        return str(value)
    # Past here the decimal form is unrenderable, so nothing below may touch it.
    magnitude = -value if value < 0 else value
    sign = "-" if value < 0 else ""
    total = (magnitude.bit_length() + 3) // 4
    kept = REPORT_LENGTH_HEX_DIGITS
    if total <= kept:
        return f"{sign}0x{magnitude:0{kept}X}"
    leading = magnitude >> (4 * (total - kept))
    return (
        f"{sign}0x{leading:0{kept}X}"
        + REPORT_ADDRESS_TRUNCATION_CUE_FMT.format(dropped=total - kept)
    )


def _report_filename(reports_dir: Path, timestamp: datetime) -> str:
    """
    Summary:
        Build the report filename for ``timestamp``, resolving a
        same-second collision with a zero-padded two-digit counter
        (LLR-007.5: ``<ts>-report.md``, then ``<ts>-01-report.md`` ..
        ``<ts>-99-report.md``).

    Args:
        reports_dir (Path): The project's ``reports/`` directory.
        timestamp (datetime): The (UTC) generation instant from the
            injectable clock.

    Returns:
        str: A filename matching :data:`REPORT_FILENAME_REGEX` that does
        not yet exist inside ``reports_dir``.

    Raises:
        FileExistsError: When the base name and all 99 counter slots for
            this second are taken — never a silent overwrite.

    Data Flow:
        - Format the UTC timestamp, probe the un-suffixed base name, then
          ``-01`` .. ``-99`` in order; first free slot wins.

    Dependencies:
        Used by:
            - generate_project_report
    """
    base = timestamp.strftime(REPORT_TIMESTAMP_FORMAT)
    candidate = f"{base}-report.md"
    if not (reports_dir / candidate).exists():
        return candidate
    for counter in range(1, 100):
        candidate = f"{base}-{counter:02d}-report.md"
        if not (reports_dir / candidate).exists():
            return candidate
    raise FileExistsError(
        f"100 reports already exist for second {base} - refusing to "
        f"overwrite an existing report"
    )


def list_project_reports(project_dir: Path) -> List[Path]:
    """
    Summary:
        List the project's ``reports/*.md`` newest-first (LLR-008.3): files
        matching :data:`REPORT_FILENAME_REGEX` sort by the parsed key
        ``(timestamp, NN)`` descending, with a missing ``-NN`` counter
        sorting as ``00``; non-matching ``.md`` files list LAST,
        unsorted-as-found.

    Args:
        project_dir (Path): The project work area
            (``.s19tool/workarea/<project>/``).

    Returns:
        List[Path]: Report paths, newest first, foreign ``.md`` files at
        the end. Empty when ``reports/`` does not exist or holds no
        ``.md`` file.

    Data Flow:
        - The parsed sort key is REQUIRED inside a same-second collision
          group (F-Q-05): raw filename-descending would put the
          un-suffixed base AFTER its ``-NN`` siblings, but the base is the
          group's FIRST (oldest) report — ``NN=00`` keys it correctly, so
          descending order reads ``-02``, ``-01``, base.
        - Non-``.md`` directory entries are ignored entirely (the listing
          contract is ``reports/*.md``).

    Dependencies:
        Uses:
            - REPORT_FILENAME_REGEX / REPORTS_DIR_NAME
        Used by:
            - s19_app.tui.app.S19TuiApp.action_view_reports (E8)
            - tests/test_tui_report_view.py

    Example:
        >>> list_project_reports(Path("missing"))
        []
    """
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    if not reports_dir.is_dir():
        return []
    timestamp_length = len("00000000T000000Z")
    keyed: List[Tuple[Tuple[str, int], Path]] = []
    foreign: List[Path] = []
    for path in reports_dir.iterdir():
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        match = REPORT_FILENAME_REGEX.match(path.name)
        if match is None:
            foreign.append(path)
            continue
        counter = int(match.group(1)[1:]) if match.group(1) else 0
        keyed.append(((path.name[:timestamp_length], counter), path))
    keyed.sort(key=lambda item: item[0], reverse=True)
    return [path for _key, path in keyed] + foreign


def _filter_display_name(report_filter: ReportFilterMatcher) -> str:
    """
    Summary:
        The filter file name the audit header renders (LLR-054.3), read
        from the declared ``ReportFilterMatcher.source_name`` field (the
        Inc-3 promotion of the Inc-2 duck-typed attribute). RAW text —
        the caller sanitizes (``markdown_safety.md_safe``).

    Args:
        report_filter (ReportFilterMatcher): The resolved matcher.

    Returns:
        str: The attached display name, or ``(unnamed filter)`` when the
        field is ``None`` or not a non-empty string.

    Data Flow:
        - Field read + type/emptiness guard; no I/O.

    Dependencies:
        Used by:
            - generate_project_report
    """
    name = report_filter.source_name
    return name if isinstance(name, str) and name else "(unnamed filter)"


def _zero_match_notice(total: int) -> str:
    """
    Summary:
        The LLR-054.3 zero-match notice replacing a filtered section's
        body. Wording identical to the diff report's notice and
        deliberately sharing no prefix token with the LLR-053.5 refusal
        wordings (Q-12): "valid filter, matched nothing" is never
        confusable with "filter invalid".

    Args:
        total (int): The section's PRE-FILTER item count.

    Returns:
        str: ``filter matched 0 of {total} items``.

    Data Flow:
        - Pure formatting; no I/O.

    Dependencies:
        Used by:
            - _modifications_lines
            - _checklist_lines
            - _hexdump_section
    """
    return f"filter matched 0 of {total} items"


def _matches_entry(matcher: ReportFilterMatcher, entry: object) -> bool:
    """
    Summary:
        Classify one report row object against the resolved filter — the
        LLR-053.4 item semantics via ``matches_item`` on the row's
        ``linkage_symbol`` and half-open ``[address_start, address_end)``
        range. Shared by the Modifications, Checklists (F-02: check
        entries CARRY ``linkage_symbol``), and applied-regions surfaces so
        all three sections obey ONE match rule (LLR-055.2).

    Args:
        matcher (ReportFilterMatcher): The resolved filter.
        entry (object): A ``ChangeSummaryEntry`` or ``CheckRunEntry`` —
            any object with ``linkage_symbol`` / ``address_start`` /
            ``address_end`` attributes.

    Returns:
        bool: True when the row matches the filter. Never raises
        (``matches_item`` honours the S-F4 never-raise contract).

    Data Flow:
        - Attribute reads → ``ReportFilterMatcher.matches_item``.

    Dependencies:
        Uses:
            - ReportFilterMatcher.matches_item
        Used by:
            - _modifications_lines / _checklist_lines / _applied_regions
            - _filter_section_counts
    """
    return matcher.matches_item(
        getattr(entry, "linkage_symbol", None),
        getattr(entry, "address_start", None),
        getattr(entry, "address_end", None),
    )


def _filter_section_counts(
    variant_results: Sequence[VariantExecutionResult],
    matcher: ReportFilterMatcher,
) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    Summary:
        Aggregate the audit header's per-section ``(shown, total)`` pairs
        (LLR-054.3 / F-07: the project report counts PER SECTION) across
        every variant: Modifications rows, Checklists rows, and applied
        regions — the same populations the section renderers filter, so
        shown + hidden always equals the pre-filter count.

    Args:
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            execution outcomes, the report's row sources.
        matcher (ReportFilterMatcher): The resolved filter.

    Returns:
        Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
        ``((mods_shown, mods_total), (checks_shown, checks_total),
        (regions_shown, regions_total))``.

    Data Flow:
        - Walk the same entry populations ``_modifications_lines`` /
          ``_checklist_lines`` / ``_applied_regions`` render; classify via
          :func:`_matches_entry`.

    Dependencies:
        Uses:
            - _matches_entry / _applied_regions
        Used by:
            - generate_project_report
    """
    mods_shown = mods_total = checks_shown = checks_total = 0
    regions_shown = regions_total = 0
    for result in variant_results:
        for summary in result.change_summaries:
            for entry in summary.entries:
                mods_total += 1
                if _matches_entry(matcher, entry):
                    mods_shown += 1
        for check in result.check_results:
            for entry in check.entries:
                checks_total += 1
                if _matches_entry(matcher, entry):
                    checks_shown += 1
        regions_total += len(_applied_regions(result))
        regions_shown += len(_applied_regions(result, matcher))
    return (
        (mods_shown, mods_total),
        (checks_shown, checks_total),
        (regions_shown, regions_total),
    )


def _audit_header_lines(
    filter_name: str,
    modification_counts: Tuple[int, int],
    checklist_counts: Tuple[int, int],
    region_counts: Tuple[int, int],
) -> List[str]:
    """
    Summary:
        Build the Markdown audit header block (LLR-054.3) — the FIRST
        block after the report title in every FILTERED report (S-F6),
        same fixed format family as the diff report's audit header: the
        applied filter file name plus the per-section shown/hidden counts
        (F-07: the project report counts Modifications rows, Checklists
        rows, and applied regions), closed by the F-03 informative
        merged-context note. The name passes :func:`markdown_safety.md_safe`
        (LLR-055.4 non-cell minimum).

    Args:
        filter_name (str): The filter display name (raw; ctl-stripped
            here).
        modification_counts (Tuple[int, int]): ``(shown, total)`` for the
            Modifications rows.
        checklist_counts (Tuple[int, int]): ``(shown, total)`` for the
            Checklists rows.
        region_counts (Tuple[int, int]): ``(shown, total)`` for the
            applied regions feeding the hexdump windows.

    Returns:
        List[str]: Markdown lines, trailing blank included; shown +
        hidden equals the pre-filter count per section.

    Data Flow:
        - Pure formatting of the pre-computed counts; no re-scan.

    Dependencies:
        Uses:
            - markdown_safety.md_safe
        Used by:
            - generate_project_report
    """
    lines = [
        "## Report filter applied",
        "",
        f"- Filter file: {md_safe(filter_name, limit=REPORT_CELL_CHARS)}",
    ]
    for label, (shown, total) in (
        ("Modifications rows", modification_counts),
        ("Checklist rows", checklist_counts),
        ("Applied regions", region_counts),
    ):
        lines.append(
            f"- {label}: shown {shown} of {total} (hidden {total - shown})"
        )
    lines.append(
        "- Note: windows seeded by matched regions may include excluded "
        "addresses as merged context."
    )
    lines.append("")
    return lines


def _header_lines(
    project_name: str, generated_at: datetime, options: ReportOptions
) -> List[str]:
    """
    Summary:
        Build the (a) header section: project, UTC timestamp, tool
        version, context setting, execution mode, and the
        manifest-or-default assignment source (LLR-007.4 (a) / F-A-17).

    Args:
        project_name (str): The reported project's name.
        generated_at (datetime): The clock's generation instant.
        options (ReportOptions): The invocation knobs echoed for audit.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    return [
        f"# Project report: {md_safe(project_name, limit=REPORT_CELL_CHARS)}",
        "",
        f"- Project: {md_safe(project_name, limit=REPORT_CELL_CHARS)}",
        f"- Generated (UTC): {generated_at.isoformat()}",
        f"- Tool version: {__version__}",
        f"- Context bytes: {options.context_bytes}",
        f"- Execution mode: {options.execution_mode}",
        f"- Assignment source: {options.assignment_source}",
        "",
    ]


def _inventory_lines(variant_set: ProjectVariantSet) -> List[str]:
    """
    Summary:
        Build the (b) variant-inventory table from the
        ``ProjectVariantSet`` descriptors (LLR-007.4 (b)).

    Args:
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = [
        "## Variant inventory",
        "",
        "| Variant | File | Type | Active |",
        "|---|---|---|---|",
    ]
    for descriptor in variant_set.variants:
        active = "yes" if descriptor.variant_id == variant_set.active_id else "no"
        lines.append(
            f"| {md_safe(descriptor.variant_id, limit=REPORT_CELL_CHARS)} "
            f"| {md_safe(descriptor.path.name, limit=REPORT_CELL_CHARS)} "
            f"| {md_safe(descriptor.file_type, limit=REPORT_CELL_CHARS)} | {active} |"
        )
    lines.append("")
    return lines


def _overview_lines(
    variant_results: Sequence[VariantExecutionResult],
) -> List[str]:
    """
    Summary:
        Build the (c) consolidated overview: one row per variant with its
        execution status, applied-change count, and aggregate check
        results (LLR-007.4 (c)).

    Args:
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            execution outcomes in execution order.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - Applied count sums ``ChangeSummary.counts["applied"]`` across
          the variant's change summaries; check columns sum the
          ``CheckRunResult.aggregates`` keys.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = [
        "## Consolidated overview",
        "",
        "| Variant | Status | Changes applied | Checks passed "
        "| Checks failed | Checks uncheckable |",
        "|---|---|---|---|---|---|",
    ]
    for result in variant_results:
        applied = sum(
            summary.counts.get(DISPOSITION_APPLIED, 0)
            for summary in result.change_summaries
        )
        passed = sum(
            check.aggregates.get("passed", 0) for check in result.check_results
        )
        failed = sum(
            check.aggregates.get("failed", 0) for check in result.check_results
        )
        uncheckable = sum(
            check.aggregates.get("uncheckable", 0)
            for check in result.check_results
        )
        lines.append(
            f"| {md_safe(result.variant_id, limit=REPORT_CELL_CHARS)} "
            f"| {md_safe(result.status, limit=REPORT_CELL_CHARS)} | {applied} "
            f"| {passed} | {failed} | {uncheckable} |"
        )
    lines.append("")
    return lines


def _modified_files_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant modified-files list: every change file that
        applied at least one entry, including the ``saved_path`` of the
        persisted patched image when present (LLR-007.4 (d) / LLR-002.7).

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = ["### Modified files", ""]
    bullets: List[str] = []
    for summary in result.change_summaries:
        if summary.counts.get(DISPOSITION_APPLIED, 0) <= 0:
            continue
        source = (
            f"`{md_code(summary.source_path)}`"
            if summary.source_path is not None
            else "(in-memory document)"
        )
        bullet = (
            f"- {source} (applied entries: "
            f"{summary.counts[DISPOSITION_APPLIED]})"
        )
        if summary.saved_path is not None:
            bullet += f" - saved as `{md_code(summary.saved_path)}`"
        bullets.append(bullet)
    if bullets:
        lines.extend(bullets)
    else:
        lines.append("No files were modified for this variant.")
    lines.append("")
    return lines


def _modifications_lines(
    result: VariantExecutionResult,
    report_filter: Optional[ReportFilterMatcher] = None,
) -> List[str]:
    """
    Summary:
        Build the per-variant per-modification table — address, length,
        before, after, linkage, symbol per entry (LLR-007.4 (d)), entries
        in document order across the variant's change summaries. With a
        ``report_filter`` (LLR-055.2 (a)), only rows matching the
        LLR-053.4 item semantics render; a non-empty section whose rows
        ALL filter out renders the loud zero-match notice instead
        (LLR-054.3 / D-3).

        At most :data:`MAX_REPORT_ROWS_PER_VARIANT` rows are admitted, counted
        at admission, and no full-population list is materialised (batch-74,
        LLR-105.1): a wire-legal change file carries up to
        ``MF_ENTRY_COUNT_CEILING = 100_000`` entries, whose rendering cost used
        to be paid in full before any output existed.

    Args:
        result (VariantExecutionResult): One variant's execution outcome.
        report_filter (Optional[ReportFilterMatcher]): The resolved
            filter; ``None`` (the default) renders every row —
            byte-identical to the pre-batch output (LLR-055.3).

    Returns:
        List[str]: Markdown lines, trailing blank included. Ends with one
        :data:`ROW_TRUNCATION_NOTICE_FMT` call-out when the cap fired.

    Data Flow:
        - ``before_bytes`` is ``None`` for every non-applied disposition
          (LLR-002.5) and renders as ``-`` — values come from the summary
          objects only, never from re-reading memory (LLR-007.8).
        - Filtered rows are classified via :func:`_matches_entry`
          (``matches_item`` on ``linkage_symbol`` + range).
        - ONE pass over ``change_summaries → entries`` fuses the former
          flattening comprehension and filter list. ``total`` counts the
          pre-filter population (the zero-match notice's number) and ``kept``
          counts the rows that WOULD have rendered under the active filter —
          the truncation notice's number (LLR-105.4′). Reporting
          ``total - cap`` instead would overstate the drop by exactly the
          filtered-out rows, and a reader could not detect it.

    Dependencies:
        Uses:
            - _format_address / _format_bytes / _matches_entry
            - _zero_match_notice
            - MAX_REPORT_ROWS_PER_VARIANT / ROW_TRUNCATION_NOTICE_FMT
            - markdown_safety.md_safe (symbol + linkage cells; replaced
              ``diff_report_service._md_table_cell``, which escaped table SHAPE
              only — batch-62 D-5)
        Used by:
            - generate_project_report
    """
    lines = ["### Modifications", ""]
    rows: List[str] = []
    total = 0
    kept = 0
    for summary in result.change_summaries:
        for entry in summary.entries:
            total += 1
            if report_filter is not None and not _matches_entry(
                report_filter, entry
            ):
                continue
            kept += 1
            if kept > MAX_REPORT_ROWS_PER_VARIANT:
                continue
            # The empty guard stays: ``md_safe("")`` would render "(empty)", but
            # a linkage with no symbol is not an empty symbol — it is a
            # standalone entry, and the golden's "-" says so.
            symbol_cell = (
                md_safe(entry.linkage_symbol, limit=REPORT_CELL_CHARS)
                if entry.linkage_symbol
                else "-"
            )
            rows.append(
                f"| {_format_address(entry.address_start)} "
                f"| {_format_length(entry.address_end - entry.address_start)} "
                f"| {_format_bytes(entry.before_bytes, max_bytes=REPORT_BYTES_PER_CELL)} "
                f"| {_format_bytes(entry.after_bytes, max_bytes=REPORT_BYTES_PER_CELL)} "
                f"| {md_safe(entry.linkage, limit=REPORT_CELL_CHARS)} "
                f"| {symbol_cell} |"
            )
    if not total:
        lines.extend(["No change entries were executed for this variant.", ""])
        return lines
    if report_filter is not None and not kept:
        lines.extend([_zero_match_notice(total), ""])
        return lines
    lines.extend(
        [
            "| Address | Length | Before | After | Linkage | Symbol |",
            "|---|---|---|---|---|---|",
        ]
    )
    lines.extend(rows)
    if kept > MAX_REPORT_ROWS_PER_VARIANT:
        # Explicit beats silent, matching the declaration-error and addendum
        # caps: above the cap this table is no longer a COMPLETE record of the
        # variant's modifications, and the document has to say so.
        lines.append(
            ROW_TRUNCATION_NOTICE_FMT.format(
                section="Modifications",
                dropped=kept - MAX_REPORT_ROWS_PER_VARIANT,
                total=kept,
                cap=MAX_REPORT_ROWS_PER_VARIANT,
            )
        )
    lines.append("")
    return lines


def _declaration_error_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Build the per-variant declaration-error subsection: every
        ``ValidationIssue`` collected on the variant's change summaries
        and check results (LLR-007.4 (d) declaration-error subsection,
        per LLR-002.8 + B-2 — operator decision 2026-06-10).

        Capped at :data:`MAX_REPORT_ISSUES_PER_VARIANT`, with the omitted count
        stated in the document. This section is outside ``_ByteBudget``'s
        hexdump-granularity accounting, so without a cap of its own a corrupt
        image composes an unbounded report (batch-62 D-20).

    Args:
        result (VariantExecutionResult): One variant's execution outcome.

    Returns:
        List[str]: Markdown lines, trailing blank included; ``None.`` when
        no declaration fault was collected.

    Dependencies:
        Used by:
            - generate_project_report
    """
    lines = ["### Declaration errors", ""]
    issues = [
        issue
        for summary in result.change_summaries
        for issue in summary.issues
    ]
    issues.extend(
        issue for check in result.check_results for issue in check.issues
    )
    if not issues:
        lines.extend(["None.", ""])
        return lines
    omitted = 0
    if len(issues) > MAX_REPORT_ISSUES_PER_VARIANT:
        omitted = len(issues) - MAX_REPORT_ISSUES_PER_VARIANT
        issues = issues[:MAX_REPORT_ISSUES_PER_VARIANT]
    for issue in issues:
        # D-11 REVERTED at Inc-8 (operator ruling). `issue.message` is escaped
        # but NOT path-redacted: three revisions of a shape-inference redactor
        # produced three integrity defects, the last of which made the report
        # contradict itself about a symbol's identity, because every
        # `ValidationIssue` template embeds a file-derived symbol in quotes and a
        # path-shaped symbol is indistinguishable from a path. Host-path exposure
        # is carried as a named MAJOR, to be solved by substituting KNOWN roots
        # rather than inferring extent from punctuation.
        #
        # The 500 limit stays: it matches `_scrub_issue_message`'s own cap, which
        # the report-wide cap would have truncated.
        line = (
            f"- [{md_safe(issue.code, limit=REPORT_CELL_CHARS)}] "
            f"{issue.severity.value}: "
            f"{md_safe(issue.message, limit=500)}"
        )
        if issue.address is not None:
            line += f" @ 0x{issue.address:X}"
        if issue.symbol:
            line += f" symbol={md_safe(issue.symbol, limit=REPORT_CELL_CHARS)}"
        if issue.related_artifacts:
            # Escaped PER ELEMENT, joined after, so each element gets its own
            # `limit` and its own empty-value handling.
            #
            # (An earlier version of this comment said escaping the joined string
            # "would escape the separator too and fuse the list into one token".
            # That is false — `,` is not in `MD_ESCAPE` — and a comment stating a
            # wrong reason is how the next reader builds a wrong model. The
            # per-element form is still the better choice, for the reason above.)
            related = ",".join(
                md_safe(name, limit=REPORT_CELL_CHARS)
                for name in issue.related_artifacts
            )
            line += f" related={related}"
        lines.append(line)
    if omitted:
        # Explicit beats silent, matching the region and hexdump caps: the cut
        # is stated in the document rather than leaving a reader to wonder
        # whether 200 issues is all there was.
        lines.append(
            f"> TRUNCATED: {omitted} of {omitted + MAX_REPORT_ISSUES_PER_VARIANT} "
            f"declaration errors omitted (cap: {MAX_REPORT_ISSUES_PER_VARIANT} "
            f"issues per variant)."
        )
    lines.append("")
    return lines


def _checklist_lines(
    result: VariantExecutionResult,
    report_filter: Optional[ReportFilterMatcher] = None,
) -> List[str]:
    """
    Summary:
        Build the per-variant checklist tables — one table per executed
        check file with expected/actual/result per entry plus the
        aggregate counts line (LLR-007.4 (d)). With a ``report_filter``
        (LLR-055.2 (b)), rows match via the FULL LLR-053.4 branch set —
        ``CheckRunEntry.linkage_symbol`` OR range intersection (F-02:
        check entries CARRY ``linkage_symbol``) — and a section whose
        rows ALL filter out renders the zero-match notice; the per-file
        aggregates line keeps the PRE-FILTER counts (the audit header
        discloses the hidden row count).

        At most :data:`MAX_REPORT_ROWS_PER_VARIANT` rows are admitted **summed
        across all of the variant's check files** (batch-74, LLR-105.2). The
        sum is what makes the bound a bound: the check-file count ``F`` has no
        cap anywhere, so a per-table cap would leave ``F x CAP`` unbounded. A
        check file that arrives already saturated renders its heading and
        aggregates followed by its own ``> TRUNCATED:`` line, and **omits the
        table header and rule** — an empty table with no local explanation is
        worse than no table.

    Args:
        result (VariantExecutionResult): One variant's execution outcome.
        report_filter (Optional[ReportFilterMatcher]): The resolved
            filter; ``None`` (the default) renders every row —
            byte-identical to the pre-batch output (LLR-055.3).

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - Filtered rows are classified via :func:`_matches_entry`; the
          zero-match test spans the variant's WHOLE checklist row
          population (all check files).
        - ``admitted`` carries the variant-wide admission budget ACROSS files;
          ``file_kept`` counts the rows that WOULD have rendered from THIS file
          under the active filter (LLR-105.4′), so each file's notice states its
          own dropped count and its own total. A variant-wide count repeated
          under three headings would read as three separate drops.
        - Only a cap-bounded ``rows`` buffer is resident per file; no
          full-population list is built.

    Dependencies:
        Uses:
            - _format_address / _format_bytes / _matches_entry
            - _zero_match_notice
            - MAX_REPORT_ROWS_PER_VARIANT / ROW_TRUNCATION_NOTICE_FMT
        Used by:
            - generate_project_report
    """
    lines = ["### Checklists", ""]
    if not result.check_results:
        lines.extend(["No checklists were executed for this variant.", ""])
        return lines
    if report_filter is not None:
        total = sum(len(check.entries) for check in result.check_results)
        kept = sum(
            1
            for check in result.check_results
            for entry in check.entries
            if _matches_entry(report_filter, entry)
        )
        if total and not kept:
            lines.extend([_zero_match_notice(total), ""])
            return lines
    admitted = 0
    for check in result.check_results:
        source = (
            f"`{md_code(check.source_path)}`"
            if check.source_path is not None
            else "(in-memory document)"
        )
        lines.extend(
            [
                f"#### Checklist: {source}",
                "",
                f"Passed: {check.aggregates.get('passed', 0)} - "
                f"Failed: {check.aggregates.get('failed', 0)} - "
                f"Uncheckable: {check.aggregates.get('uncheckable', 0)}",
                "",
            ]
        )
        # Saturation is read BEFORE this file admits anything, because it is
        # what decides whether this file gets a table at all.
        saturated = admitted >= MAX_REPORT_ROWS_PER_VARIANT
        rows: List[str] = []
        file_kept = 0
        for entry in check.entries:
            if report_filter is not None and not _matches_entry(
                report_filter, entry
            ):
                continue
            file_kept += 1
            if admitted >= MAX_REPORT_ROWS_PER_VARIANT:
                continue
            admitted += 1
            rows.append(
                f"| {_format_address(entry.address_start)} "
                f"| {_format_length(entry.address_end - entry.address_start)} "
                f"| {_format_bytes(entry.expected_bytes, max_bytes=REPORT_BYTES_PER_CELL)} "
                f"| {_format_bytes(entry.actual_bytes, max_bytes=REPORT_BYTES_PER_CELL)} "
                f"| {md_safe(entry.result, limit=REPORT_CELL_CHARS)} |"
            )
        # A file that arrives already saturated AND had rows to show renders no
        # table header and no rule (LLR-105.2): a reader of check file 3 must
        # meet a stated reason, not an empty table. A file that arrives
        # saturated with nothing to show is unaffected by the cap, so it keeps
        # today's empty-table rendering rather than acquiring a false notice.
        if not (saturated and file_kept):
            lines.extend(
                [
                    "| Address | Length | Expected | Actual | Result |",
                    "|---|---|---|---|---|",
                ]
            )
            lines.extend(rows)
        file_dropped = file_kept - len(rows)
        if file_dropped:
            # PER CHECK FILE, stating this file's own numbers. The cap is a
            # per-variant budget, so a variant-wide count repeated under three
            # headings would read as three separate drops; the per-file count is
            # locally verifiable and sums to the variant's drop.
            lines.append(
                ROW_TRUNCATION_NOTICE_FMT.format(
                    section=f"Checklist: {source}",
                    dropped=file_dropped,
                    total=file_kept,
                    cap=MAX_REPORT_ROWS_PER_VARIANT,
                )
            )
        lines.append("")
    return lines


def _applied_regions(
    result: VariantExecutionResult,
    report_filter: Optional[ReportFilterMatcher] = None,
) -> List[Tuple[int, int]]:
    """
    Summary:
        Collect the variant's modified regions — the half-open ranges of
        every ``applied`` summary entry, in document order across change
        summaries. With a ``report_filter`` (LLR-055.2 (c)), only entries
        matching the LLR-053.4 item semantics contribute — the filter
        applies to the ENTRY (symbol OR range), BEFORE any window math.

    Args:
        result (VariantExecutionResult): One variant's execution outcome.
        report_filter (Optional[ReportFilterMatcher]): The resolved
            filter; ``None`` (the default) keeps every applied entry —
            byte-identical to the pre-batch output (LLR-055.3).

    Returns:
        List[Tuple[int, int]]: ``(address_start, address_end)`` per
        (matching) applied entry.

    Data Flow:
        - Disposition gate first (unchanged), then the optional
          :func:`_matches_entry` classification (D-5 filter-then-window).

    Dependencies:
        Uses:
            - _matches_entry
        Used by:
            - _hexdump_section
            - _filter_section_counts
    """
    return [
        (entry.address_start, entry.address_end)
        for summary in result.change_summaries
        for entry in summary.entries
        if entry.disposition == DISPOSITION_APPLIED
        and (
            report_filter is None or _matches_entry(report_filter, entry)
        )
    ]


def _hexdump_block(
    mem_map: dict[int, int], low: int, high: int
) -> List[str]:
    """
    Summary:
        Render one merged window as a fenced hexdump block through the
        plain-string ``render_hex_view`` (LLR-007.3) — explicit row bases
        cover the whole window, so unmapped addresses render via the gap
        convention.

    Args:
        mem_map (dict[int, int]): The variant's post-change memory map.
        low (int): Window start (16-byte aligned, inclusive).
        high (int): Window end (16-byte aligned, exclusive).

    Returns:
        List[str]: Markdown lines, trailing blank included. ``MAX_HEX_ROWS``
        bounds the rendered rows per block (per-region cap, LLR-007.3).

    Dependencies:
        Uses:
            - hexview.render_hex_view
        Used by:
            - _hexdump_section
    """
    row_bases = list(range(low, high, HEX_WIDTH))
    rendered = render_hex_view(mem_map, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
    return [
        f"Window 0x{low:08X}-0x{high:08X}:",
        "",
        "```text",
        *rendered.splitlines(),
        "```",
        "",
    ]


def _hexdump_section(
    result: VariantExecutionResult,
    options: ReportOptions,
    gate: _EmissionGate,
) -> List[str]:
    """
    Summary:
        Build the per-variant hexdump section: one merged-window block per
        modified-region cluster, enforcing both LLR-007.6 caps with
        explicit in-document ``TRUNCATED`` markers stating the exact
        omitted counts — never a silent cut.

    Args:
        result (VariantExecutionResult): One variant's execution outcome;
            ``result.mem_map`` is the post-change hexdump source
            (LLR-007.8) — when it was not captured the section states so
            and dumps nothing.
        options (ReportOptions): Supplies ``context_bytes`` and the
            optional ``report_filter`` (LLR-055.2 (c)).
        gate (_EmissionGate): The document's single admission seam (batch-76,
            LLR-108.3). Every line this section emits is offered to it and may
            be REFUSED; a refusal is recorded for the aggregated disclosure
            rather than silently dropped. The section no longer returns its
            lines — it emits them — so there is exactly one way into the
            document, which is what ``TC-553``'s census asserts.

    Returns:
        List[str]: The truncation-appendix notes this section produced (empty
        when no cap fired).

    Data Flow:
        - With ``options.report_filter`` set (LLR-055.2 (c)), the applied
          regions are filtered to matching entries BEFORE any window math
          (D-5 filter-then-window); a non-empty region set whose entries
          ALL filter out renders the zero-match notice (LLR-054.3).
        - Regions over :data:`REPORT_MAX_REGIONS_PER_VARIANT` → keep the
          first cap-many in document order, emit the region marker.
        - ``compute_hexdump_windows`` merges the kept regions' windows
          against ``image_top = max(mem_map) + 1``.
        - Each block is emitted only when the byte budget still fits it;
          omitted blocks end in the size marker.

    Dependencies:
        Uses:
            - _applied_regions / compute_hexdump_windows / _hexdump_block
            - _zero_match_notice
        Used by:
            - generate_project_report
    """
    notes: List[str] = []
    kind = "memory-regions"

    def put(batch: Sequence[str]) -> bool:
        """Admit through the document gate (batch-76, LLR-108.3).

        Revision 1 EXEMPTED this seam on the premise that it already gated. It
        did not: ``put`` called ``budget.consume`` unconditionally and only the
        block loop below ever consulted ``fits``, so five of its six call sites
        emitted past an exhausted budget. That premise (P-24) was written by the
        batch that was chartered to fix this defect, and executing it is what
        found the exemption was covering the bug.
        """
        return gate.emit(batch, kind)

    put(["### Memory regions", ""])
    regions = _applied_regions(result)
    if not regions:
        put(["No modified regions.", ""])
        return notes
    if options.report_filter is not None:
        kept = _applied_regions(result, options.report_filter)
        if not kept:
            put([_zero_match_notice(len(regions)), ""])
            return notes
        regions = kept
    if not result.mem_map:
        put(["Post-change memory map unavailable - hexdumps omitted.", ""])
        return notes
    total_regions = len(regions)
    if total_regions > REPORT_MAX_REGIONS_PER_VARIANT:
        omitted = total_regions - REPORT_MAX_REGIONS_PER_VARIANT
        regions = regions[:REPORT_MAX_REGIONS_PER_VARIANT]
        text = (
            f"{omitted} of {total_regions} modified regions omitted "
            f"(cap: {REPORT_MAX_REGIONS_PER_VARIANT} regions per variant)"
        )
        # The MARKER is unconditional and charged to the allowance, not to the
        # budget: an omission the document does not admit to is worse than the
        # omission. That is the standing "explicit beats silent" policy already
        # recorded on REPORT_MAX_TOTAL_BYTES.
        gate.emit_unconditional([f"> TRUNCATED: {text}.", ""])
        notes.append(
            f"Variant '{md_safe(result.variant_id, limit=REPORT_CELL_CHARS)}': "
            f"{text}."
        )
    image_top = max(result.mem_map) + 1
    omitted_blocks = 0
    for low, high in compute_hexdump_windows(
        regions, options.context_bytes, image_top
    ):
        block = _hexdump_block(result.mem_map, low, high)
        if not gate.emit(block, kind):
            omitted_blocks += 1
    if omitted_blocks:
        text = (
            f"{omitted_blocks} hexdump block(s) omitted "
            f"(report size cap: {REPORT_MAX_TOTAL_BYTES} bytes)"
        )
        gate.emit_unconditional([f"> TRUNCATED: {text}.", ""])
        notes.append(
            f"Variant '{md_safe(result.variant_id, limit=REPORT_CELL_CHARS)}': "
            f"{text}."
        )
    return notes


def _legend_lines() -> List[str]:
    """
    Summary:
        Render :data:`s19_app.tui.legend.LEGEND_TABLE` as a Markdown legend
        section (LLR-022.2) — one sub-heading per artifact, one bullet per
        classification giving its colour and documented meaning. Static text
        (no run data feeds it), so it is identical across every report.

    Returns:
        List[str]: Markdown lines beginning with the ``## Legend`` heading;
        each row is ``- **<classification>**[ (<colour>)] — <meaning>`` with
        the parenthetical colour shown only when it differs from the
        classification label (i.e. the Issues categories).

    Data Flow:
        - Reads the shared ``LEGEND_TABLE`` (single source with the in-app
          ``LegendScreen`` modal — no duplicated literal here).
        - Emitted by :func:`generate_project_report` when
          ``options.include_legend`` is ``True``.

    Dependencies:
        Uses:
            - s19_app.tui.legend.LEGEND_TABLE
        Used by:
            - generate_project_report
            - tests/test_report_service.py
    """
    lines: List[str] = ["## Legend", ""]
    for artifact, rows in LEGEND_TABLE.items():
        lines.append(f"### {artifact}")
        for classification, (colour, meaning) in rows.items():
            suffix = "" if classification == colour else f" ({colour})"
            lines.append(f"- **{classification}**{suffix} — {meaning}")
        lines.append("")
    return lines


def _entropy_lines(result: VariantExecutionResult) -> List[str]:
    """
    Summary:
        Render a per-variant entropy/classification section (LLR-037.2) — a
        band SUMMARY (count per band, low-confidence windows flagged) computed
        from :func:`entropy_service.compute_entropy` over the variant's
        post-change ``result.mem_map``. Band-summary only (O(bands), not
        O(windows)) — no raw byte dump — so the section stays bounded against
        the report byte budget (R-2) and adds no memory-value confidentiality
        surface beyond what the hexdump already emits.

    Args:
        result (VariantExecutionResult): The variant whose ``mem_map`` (the
            same source :func:`_hexdump_section` reads, populated when the E6
            execution layer runs with ``capture_mem_maps=True``) is classified.
            An empty or ``None`` ``mem_map`` yields a heading plus a single
            "no data" line rather than crashing.

    Returns:
        List[str]: Markdown lines beginning with the ``### Entropy`` heading;
        for a populated map, one bullet per :data:`entropy_service.ENTROPY_BANDS`
        band that has ≥1 window (``- **<band>**: <n> window(s)``, with a
        ``(<k> low-confidence)`` suffix when any of that band's windows are
        low-confidence). A map with no mapped bytes returns the heading plus
        ``No mapped bytes - entropy not computed.``.

    Data Flow:
        - ``result.mem_map`` → :func:`entropy_service.compute_entropy` →
          count windows per band label (in ``ENTROPY_BANDS`` order) →
          Markdown bullets.
        - Emitted by :func:`generate_project_report` through the budget-charged
          ``emit`` helper when ``options.include_entropy`` is ``True``, inside
          the per-variant loop immediately after the hexdump section.

    Dependencies:
        Uses:
            - entropy_service.compute_entropy / entropy_service.ENTROPY_BANDS
        Used by:
            - generate_project_report
            - tests/test_report_service.py
    """
    lines: List[str] = ["### Entropy", ""]
    mem_map = result.mem_map
    if not mem_map:
        lines.append("No mapped bytes - entropy not computed.")
        lines.append("")
        return lines
    windows = compute_entropy(mem_map)
    counts: dict[str, int] = {label: 0 for label, _lo, _hi in ENTROPY_BANDS}
    low_conf: dict[str, int] = {label: 0 for label, _lo, _hi in ENTROPY_BANDS}
    for window in windows:
        counts[window.band] += 1
        if window.low_confidence:
            low_conf[window.band] += 1
    for label, _lo, _hi in ENTROPY_BANDS:
        count = counts[label]
        if not count:
            continue
        suffix = (
            f" ({low_conf[label]} low-confidence)" if low_conf[label] else ""
        )
        lines.append(f"- **{label}**: {count} window(s){suffix}")
    lines.append("")
    return lines


@dataclass(frozen=True, slots=True)
class _AddendumRegionIndex:
    """
    Summary:
        The per-call address-membership structure the addendum resolves every
        candidate against: a COALESCED half-open reject cover plus a
        start-sorted view of the ORIGINAL regions with a prefix-maximum-of-ends
        array for overlap-safe identity recovery.

    Args:
        cover (RangeIndex): ``build_sorted_range_index`` over the coalesced,
            half-open ``(start, end + 1)`` cover. Sound REJECT pre-filter only.
        starts (List[int]): Region starts, ascending.
        ends (List[int]): The matching INCLUSIVE region ends, in ``starts``
            order.
        pmax (List[int]): ``pmax[i] = max(ends[0..i])`` — the downward walk's
            prune.
        order (List[int]): ``order[i]`` is the CALLER's index of the region at
            sorted position ``i``, so hits land in the caller's region order.

    Returns:
        None: Frozen container.

    Data Flow:
        - Built once per :func:`_addendum_lines` call in ``O(R log R)``, then
          read once per candidate.

    Dependencies:
        Uses:
            - range_index.build_sorted_range_index
        Used by:
            - _build_addendum_region_index / _addendum_regions_for

    Example:
        >>> _build_addendum_region_index([]).order
        []
    """

    cover: RangeIndex
    starts: List[int]
    ends: List[int]
    pmax: List[int]
    order: List[int]


def _build_addendum_region_index(
    regions: Sequence[DeclaredRegion],
) -> _AddendumRegionIndex:
    """
    Summary:
        Build the addendum's per-call region index (LLR-103.2): the coalesced
        half-open reject cover and the start-sorted starts/ends/prefix-max
        vectors that recover WHICH regions contain an address.

    Args:
        regions (Sequence[DeclaredRegion]): The operator-declared regions, in
            caller order. May overlap, nest, or repeat.

    Returns:
        _AddendumRegionIndex: The structure :func:`_addendum_regions_for` reads.

    Data Flow:
        - ``DeclaredRegion`` is INCLUSIVE ``[start, end]`` and ``range_index``
          is HALF-OPEN, so the cover is built from ``(start, end + 1)``.
          Without the ``+ 1`` the end address of every declared region is a
          false negative.
        - The cover is COALESCED because ``address_in_sorted_ranges`` inspects a
          single ``bisect_right(starts, addr) - 1`` candidate and is therefore
          unsound over overlapping ranges — coalescing is a CORRECTNESS
          precondition here, not an optimisation.
        - ``report_filter._merge_ranges`` is REUSED rather than mirrored: it is
          the same coalescing already applied to freely-overlapping A2L+MAC
          spans at ``report_filter.py``'s ``build_sorted_range_index`` call, and
          a second coalescer would be a second place for the ``+ 1`` convention
          to drift.
        - The cover cannot name a region (it returns ``bool`` and its ranges are
          merged), so identity is recovered from the LOCAL vectors below.

    Dependencies:
        Uses:
            - report_filter._merge_ranges
            - range_index.build_sorted_range_index
        Used by:
            - _addendum_lines

    Example:
        >>> _build_addendum_region_index([DeclaredRegion("z", 0x10, 0x1F)]).ends
        [31]
    """
    order = sorted(range(len(regions)), key=lambda i: regions[i].start)
    starts = [regions[i].start for i in order]
    ends = [regions[i].end for i in order]
    pmax: List[int] = []
    running = -1
    for end in ends:
        running = end if end > running else running
        pmax.append(running)
    cover = build_sorted_range_index(
        _merge_ranges([(region.start, region.end + 1) for region in regions])
    )
    return _AddendumRegionIndex(
        cover=cover, starts=starts, ends=ends, pmax=pmax, order=order
    )


def _addendum_regions_for(
    address: int, index: _AddendumRegionIndex
) -> Tuple[List[int], int]:
    """
    Summary:
        Return the CALLER indices of every declared region containing
        ``address``, plus the number of region ops the resolution cost
        (LLR-103.1 / LLR-103.2).

    Args:
        address (int): The candidate address.
        index (_AddendumRegionIndex): Output of
            :func:`_build_addendum_region_index`.

    Returns:
        Tuple[List[int], int]: ``(matching caller indices, region ops)``. A
        candidate inside ``M`` overlapping regions yields ``M`` indices, which
        is what makes the addendum emit it once per matching region exactly as
        the pre-batch-64 producer did.

    Data Flow:
        - The coalesced cover rejects non-members in ``O(log R)`` and is used
          for NOTHING else — it is boolean and merged, so it can never name a
          region.
        - Identity comes from ``bisect_right(starts, address) - 1`` walked
          DOWNWARD while ``pmax[i] >= address``, collecting every ``i`` whose
          ``ends[i] >= address``. Every visited ``i`` has ``starts[i] <=
          address`` by sortedness, so ``ends[i] >= address`` IS inclusive
          containment.
        - The returned op count is the disclosure counter of §10.7, and it
          counts exactly ONE thing: ``ends[i] >= address`` comparisons in the
          downward walk. The ``pmax`` guard and both bisects are EXCLUDED —
          only that convention is invariant under dropping the reject
          pre-filter, and an exact-equality gate on a counter that moves with a
          sanctioned implementation choice is no gate.

    Dependencies:
        Uses:
            - range_index.address_in_sorted_ranges
            - bisect.bisect_right
        Used by:
            - _addendum_lines

    Example:
        >>> idx = _build_addendum_region_index([DeclaredRegion("z", 0x10, 0x1F)])
        >>> _addendum_regions_for(0x1F, idx)
        ([0], 1)
    """
    if not address_in_sorted_ranges(address, index.cover):
        return [], 0
    starts = index.starts
    ends = index.ends
    pmax = index.pmax
    order = index.order
    matched: List[int] = []
    ops = 0
    position = bisect.bisect_right(starts, address) - 1
    while position >= 0 and pmax[position] >= address:
        ops += 1
        if ends[position] >= address:
            matched.append(order[position])
        position -= 1
    return matched, ops


@dataclass(slots=True)
class _AddendumRegionHits:
    """
    Summary:
        One declared region's ORDERED hit list plus its three per-class
        admission counters and the ``O(1)`` state the truncation notice needs
        (LLR-103.3).

    Args:
        lines (List[str]): Admitted hit lines, in traversal order.
        admitted (List[int]): Admitted count per class ordinal.
        dropped (List[int]): Rejected count per class ordinal.
        named (List[List[str]]): Up to
            :data:`ADDENDUM_NOTICE_VARIANTS_MAX` already-escaped variant ids per
            class, in first-drop order.
        distinct (List[int]): Distinct affected variants per class.
        last_cut (List[Optional[str]]): Per class, the RAW variant id of the
            most recent drop.

    Returns:
        None: Mutable per-region accumulator.

    Data Flow:
        - ONE ordered list, not three per-class lists: the pre-batch-64
          emission order INTERLEAVES ``mod, issue, mod, issue`` per summary, so
          three concatenated per-class lists would emit ``mod, mod, issue,
          issue`` and break byte identity below the bound. With counters, the
          admitted sequence is a SUBSEQUENCE of the shipped one by construction.
        - ``distinct`` is counted with the ``last_cut`` sentinel rather than a
          membership set. That is ``O(1)`` ONLY because ``variant_results`` is
          the outermost loop, so one variant's drops are contiguous; an
          ``O(V)`` set would put the variant count back into the very bound
          this class establishes. PRECONDITION, stated because it is load-bearing
          and not enforced here: each ``variant_id`` must occupy ONE contiguous
          run of ``variant_results``. A repeated id breaks the sentinel — it is
          named twice in the notice and ``distinct`` overcounts. Not reachable
          through ``ProjectVariantSet`` today, which is why this is a documented
          precondition rather than a guard.

    Dependencies:
        Used by:
            - _addendum_lines

    Example:
        >>> _AddendumRegionHits.empty().dropped
        [0, 0, 0]
    """

    lines: List[str]
    admitted: List[int]
    dropped: List[int]
    named: List[List[str]]
    distinct: List[int]
    last_cut: List[Optional[str]]

    @classmethod
    def empty(cls) -> "_AddendumRegionHits":
        """Return a zeroed accumulator for one region."""
        return cls(
            lines=[],
            admitted=[0, 0, 0],
            dropped=[0, 0, 0],
            named=[[], [], []],
            distinct=[0, 0, 0],
            last_cut=[None, None, None],
        )

    def admit(
        self, hit_class: int, line: str, variant_id: str, safe_variant_id: str
    ) -> None:
        """
        Summary:
            Admit ``line`` while this class is under
            :data:`MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION`; otherwise record the
            drop against the notice.

        Args:
            hit_class (int): Class ordinal into
                :data:`ADDENDUM_CLASS_LABELS`.
            line (str): The formatted hit line.
            variant_id (str): The RAW producing variant id — the sentinel key.
            safe_variant_id (str): The same id already escaped for the document.

        Returns:
            None: Mutates this accumulator.

        Data Flow:
            - Traversal never stops on saturation: the dropped count and the
              affected-variant set are exactly what a run that stopped looking
              could not report.

        Dependencies:
            Used by:
                - _addendum_lines
        """
        if self.admitted[hit_class] < MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION:
            self.admitted[hit_class] += 1
            self.lines.append(line)
            return
        self.dropped[hit_class] += 1
        if self.last_cut[hit_class] == variant_id:
            return
        self.last_cut[hit_class] = variant_id
        self.distinct[hit_class] += 1
        if len(self.named[hit_class]) < ADDENDUM_NOTICE_VARIANTS_MAX:
            self.named[hit_class].append(safe_variant_id)


def _addendum_truncation_notice(
    hit_class: int, region_hits: _AddendumRegionHits
) -> str:
    """
    Summary:
        Format one ``(region, cut class)`` truncation notice from
        :data:`ADDENDUM_TRUNCATION_NOTICE_FMT` (LLR-103.5).

    Args:
        hit_class (int): Class ordinal whose cap fired.
        region_hits (_AddendumRegionHits): That region's accumulator.

    Returns:
        str: The notice line, naming the class, the cap, the dropped count and
        the affected variants — at most
        :data:`ADDENDUM_NOTICE_VARIANTS_MAX` of them, then ``+N more``.

    Data Flow:
        - The variant ids are ALREADY escaped: they were escaped at the
          recording site inside the traversal, by the same
          ``md_safe(result.variant_id, limit=REPORT_CELL_CHARS)`` expression the
          hit lines use, so the notice renders a given id byte-identically to
          its neighbouring hit line.
        - ``+N more`` names the count of unnamed DISTINCT affected variants, so
          the notice's own size is bounded independently of the variant count.

    Dependencies:
        Uses:
            - ADDENDUM_TRUNCATION_NOTICE_FMT / ADDENDUM_CLASS_LABELS
        Used by:
            - _addendum_lines

    Example:
        >>> hits = _AddendumRegionHits.empty()
        >>> hits.dropped[1], hits.distinct[1] = 2, 0
        >>> "change-file issue" in _addendum_truncation_notice(1, hits)
        True
    """
    named = list(region_hits.named[hit_class])
    remainder = region_hits.distinct[hit_class] - len(named)
    if remainder > 0:
        named.append(f"+{remainder} more")
    return ADDENDUM_TRUNCATION_NOTICE_FMT.format(
        label=ADDENDUM_CLASS_LABELS[hit_class],
        cap=MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION,
        dropped=region_hits.dropped[hit_class],
        variants=", ".join(named),
    )


def _addendum_lines(
    regions: Sequence[DeclaredRegion],
    variant_results: Sequence[VariantExecutionResult],
    *,
    ops_counter: Optional[List[int]] = None,
) -> List[str]:
    """
    Summary:
        Render the declared-region addendum (LLR-024.2, bounded by
        R-TUI-098/HLR-103): one sub-section per region listing the
        modifications and validation issues whose address falls within the
        region's inclusive ``[start, end]`` range, aggregated across all
        variants. A region with no hits renders an explicit "None."; a
        ``(region, hit class)`` whose admission cap fires renders one
        truncation notice naming what was dropped.

    Args:
        regions (Sequence[DeclaredRegion]): The operator-declared regions, in
            the order their sub-sections appear.
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            outcomes — the same objects the per-variant report sections walk.
        ops_counter (Optional[List[int]]): Test-only seam (LLR-103.1). A
            one-element accumulator; ``ops_counter[0]`` is incremented by the
            region ops this call performed. THE SEAM IS THIS PARAMETER, not a
            module-level counter: ``report_service`` has no module-level mutable
            state, and this function is shared by the TUI report worker and the
            CLI, so a module global would be a cross-call race dressed up as an
            instrument.

    Returns:
        List[str]: Markdown lines beginning with the
        ``## Addendum: declared regions`` heading.

    Data Flow:
        - Reads each variant's change-summary entries (``address_start``) and
          the issues on its change summaries + check results
          (``ValidationIssue.address``) — the SAME address the issue renderer
          (``_declaration_error_lines``) reads (single source, TC-S3).
        - SINGLE PASS: the declared-region loop is OUT of the candidate
          traversal, so each leaf sequence is iterated exactly once per call
          regardless of ``len(regions)``. The pre-batch-64 shape re-read every
          leaf once per region and paid the whole cost — one fully formatted
          string per matching (region, candidate) pair — before any output
          existed, which is why no output budget could reach it.
        - ``variant_results`` stays the OUTERMOST loop. That is load-bearing,
          not incidental: it is what makes each variant's drops contiguous and
          the ``+N more`` remainder countable with an ``O(1)`` sentinel instead
          of an ``O(V)`` membership set.
        - Traversal is NOT terminated on saturation. A run that stopped looking
          could not report the dropped count or the affected variants, which is
          the whole content of the notice.
        - Aggregates across ALL variants regardless of ``result.status`` —
          deliberately consistent with the per-variant report sections, which
          also emit for every variant; each hit line is tagged
          ``(variant <id>)`` for traceability.
        - Emitted by :func:`generate_project_report` when
          ``options.declared_regions`` is non-empty.

    Dependencies:
        Uses:
            - _build_addendum_region_index / _addendum_regions_for
            - _AddendumRegionHits / _addendum_truncation_notice
            - md_safe
        Used by:
            - generate_project_report
            - tests/test_report_service.py
            - tests/test_report_addendum_bound.py

    Example:
        >>> _addendum_lines([], [])
        ['## Addendum: declared regions', '']
    """
    index = _build_addendum_region_index(regions)
    per_region = [_AddendumRegionHits.empty() for _ in regions]
    ops = 0

    def _admit_issue_hits(
        issues: Iterable[object],
        hit_class: int,
        variant_id: str,
        safe_variant: str,
    ) -> int:
        """
        Summary:
            Admit one hit class of address-bearing issues, returning the
            attribution cost so the caller can accumulate it. Extracted because
            the change-summary and check-result arms are identical but for the
            iterable and the class ordinal; the hit line is still built AFTER
            the membership test, so a candidate that matches no region is never
            formatted (the whole point of the batch).

        Args:
            issues (Iterable[object]): ``ValidationIssue`` objects; those with
                ``address is None`` are skipped.
            hit_class (int): The admission-counter ordinal — ``1`` for
                change-summary issues, ``2`` for check-result issues.
            variant_id (str): The raw variant id, used for de-duplication.
            safe_variant (str): The once-escaped id rendered into the line.

        Returns:
            int: Region comparisons performed, for the ``ops_counter`` seam.

        Data Flow:
            - Reads ``index`` and mutates ``per_region``, both closed over.

        Dependencies:
            Uses:
                - _addendum_regions_for / md_safe / _AddendumRegionHits.admit
            Used by:
                - _addendum_lines

        Example:
            >>> _addendum_lines([], [])
            ['## Addendum: declared regions', '']
        """
        cost_total = 0
        for issue in issues:
            if issue.address is None:
                continue
            matched, cost = _addendum_regions_for(issue.address, index)
            cost_total += cost
            if not matched:
                continue
            line = (
                f"- issue [{md_safe(issue.code, limit=REPORT_CELL_CHARS)}] "
                f"@ 0x{issue.address:X} "
                f"(variant {safe_variant})"
            )
            for region_id in matched:
                per_region[region_id].admit(
                    hit_class, line, variant_id, safe_variant
                )
        return cost_total

    for result in variant_results:
        # Escaped ONCE per variant, at the recording site, and shared by the hit
        # lines and the notice — which is what makes a given id render
        # byte-identically in both.
        safe_variant = md_safe(result.variant_id, limit=REPORT_CELL_CHARS)
        for summary in result.change_summaries:
            for entry in summary.entries:
                matched, cost = _addendum_regions_for(entry.address_start, index)
                ops += cost
                if not matched:
                    continue
                line = (
                    f"- modification @ 0x{entry.address_start:X} "
                    f"(variant {safe_variant})"
                )
                for region_id in matched:
                    per_region[region_id].admit(
                        0, line, result.variant_id, safe_variant
                    )
            ops += _admit_issue_hits(
                summary.issues, 1, result.variant_id, safe_variant
            )
        for check in result.check_results:
            ops += _admit_issue_hits(
                check.issues, 2, result.variant_id, safe_variant
            )

    if ops_counter is not None:
        ops_counter[0] += ops
    return _render_addendum(regions, per_region)


def _render_addendum(
    regions: Sequence[DeclaredRegion],
    per_region: Sequence[_AddendumRegionHits],
) -> List[str]:
    """
    Summary:
        Emit the addendum's Markdown from the per-region accumulators: heading,
        then one sub-section per region carrying its hit list (or "None.") and
        one truncation notice per hit class whose cap fired.

    Args:
        regions (Sequence[DeclaredRegion]): The declared regions, in caller
            order.
        per_region (Sequence[_AddendumRegionHits]): One accumulator per region,
            index-aligned with ``regions``.

    Returns:
        List[str]: The addendum's lines.

    Data Flow:
        - Each notice sits INSIDE its own region's sub-section, after that
          region's hit list and before the region's trailing blank line, so the
          document says WHICH region lost evidence.
        - A region whose counters never fired emits no notice, and a report in
          which nothing was cut emits none at all — which is what keeps the
          below-bound document byte-identical to the pre-batch-64 one.

    Dependencies:
        Uses:
            - md_safe / _addendum_truncation_notice
        Used by:
            - _addendum_lines

    Example:
        >>> _render_addendum([], [])
        ['## Addendum: declared regions', '']
    """
    lines: List[str] = ["## Addendum: declared regions", ""]
    for region, hits in zip(regions, per_region):
        # The limit is the field's OWN upstream cap, not the report's: a name is
        # already scrubbed to 80, so a wider cap here could never fire and a
        # narrower one would truncate a legitimately-accepted name.
        name = md_safe(region.name, limit=DECLARED_REGION_NAME_MAX)
        lines.append(f"### {name} (0x{region.start:X}-0x{region.end:X})")
        lines.extend(hits.lines if hits.lines else ["None."])
        for hit_class in range(len(ADDENDUM_CLASS_LABELS)):
            if hits.dropped[hit_class]:
                lines.append(_addendum_truncation_notice(hit_class, hits))
        lines.append("")
    return lines


def generate_project_report(
    project_dir: Path,
    variant_results: Sequence[VariantExecutionResult],
    options: ReportOptions,
    *,
    variant_set: ProjectVariantSet,
    now_fn: Optional[NowFn] = None,
) -> Path:
    """
    Summary:
        Generate one Markdown project report under
        ``<project_dir>/reports/`` (HLR-007) and return its path. Fully
        headless: derivable exclusively from the LLR-007.8 input set —
        the C-6 objects and post-change memory maps riding
        ``variant_results``, the ``variant_set`` inventory, ``options``,
        and the tool version — no image is ever re-parsed.

    Args:
        project_dir (Path): The project work area
            (``.s19tool/workarea/<project>/``) — the gitignored
            destination root (F-S-07).
        variant_results (Sequence[VariantExecutionResult]): Per-variant E6
            execution outcomes in execution order; ``mem_map`` must have
            been captured (``capture_mem_maps=True``) for hexdumps to
            appear.
        options (ReportOptions): Domain-validated invocation knobs
            (context bytes, execution mode, assignment source).
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory — the LLR-007.4 (b) table source. Keyword-only: it
            is the one LLR-007.8 input that does not ride
            ``variant_results``.
        now_fn (Optional[NowFn]): Injectable UTC clock (LLR-007.5 /
            B-4); ``None`` resolves to ``datetime.now(timezone.utc)``.

    Returns:
        Path: The written report file —
        ``reports/<UTC %Y%m%dT%H%M%SZ>-report.md``, with a zero-padded
        ``-NN`` counter on a same-second collision (LLR-007.5).

    Raises:
        ValueError: Never for in-domain options (``ReportOptions``
            validates at construction).
        FileExistsError: When 100 reports already exist for the same
            second — never a silent overwrite (LLR-007.5).

    Data Flow:
        - ``reports/`` is created on demand (LLR-007.7).
        - Sections emit in the LLR-007.4 order: (a) header, (b) variant
          inventory, (c) consolidated overview, (c2) the classification
          legend when ``options.include_legend`` (LLR-022.2), (d) one
          section per variant (modified files → modifications table →
          declaration errors → checklists → memory-region hexdumps), (d2)
          the declared-region addendum when ``options.declared_regions``
          (LLR-024.2), (e) the truncation appendix when any cap fired.
        - With ``options.report_filter`` set (LLR-055.2, batch-35 B-07)
          the audit header block (:func:`_audit_header_lines`) is spliced
          in as the FIRST block after the title (S-F6) and the
          Modifications / Checklists / Memory-regions surfaces render
          matching items only; header, inventory, overview, legend,
          modified-files, declaration-errors, entropy, and addendum
          sections stay complete (D-2). ``report_filter=None`` takes the
          pre-batch code path unchanged (LLR-055.3 byte-identity).
        - The whole document is budgeted against
          :data:`REPORT_MAX_TOTAL_BYTES` at hexdump-block granularity.

    Dependencies:
        Uses:
            - _header_lines / _inventory_lines / _overview_lines
            - _legend_lines / _addendum_lines
            - _modified_files_lines / _modifications_lines
            - _declaration_error_lines / _checklist_lines
            - _hexdump_section / _report_filename
            - _audit_header_lines / _filter_section_counts
            - _filter_display_name
        Used by:
            - The E8 report TUI action (later increment)
            - tests/test_report_service.py

    Example:
        >>> path = generate_project_report(
        ...     project_dir, results, ReportOptions(),
        ...     variant_set=variant_set,
        ... )  # doctest: +SKIP
    """
    clock = now_fn if now_fn is not None else _default_now
    generated_at = clock()
    reports_dir = Path(project_dir) / REPORTS_DIR_NAME
    reports_dir.mkdir(parents=True, exist_ok=True)
    filename = _report_filename(reports_dir, generated_at)

    gate = _EmissionGate(limit=REPORT_MAX_TOTAL_BYTES)
    notes: List[Tuple[int, str]] = []

    header = _header_lines(variant_set.project_name, generated_at, options)
    # P-16, EXECUTED: the header is O(1) — measured flat at 181 B from V=1 to
    # V=20 000 — while the inventory and overview below are O(V) (62.0 then
    # 65.0 B/variant; the slopes disagree, so the growth is O(V log V) as the
    # id column widens). Uniform gating would therefore refuse the document's
    # own TITLE at large V, contradicting AT-255. Exempting the WHOLE preamble
    # instead — the reading the spec first sketched — would put an unbounded
    # term inside the allowance and make HLR-108's V-invariance false while
    # still stating it. So only the O(1) header is exempt; inventory and
    # overview stay gated, refusable and disclosed.
    if options.report_filter is None:
        gate.emit_unconditional(header)
    else:
        mod_counts, check_counts, region_counts = _filter_section_counts(
            variant_results, options.report_filter
        )
        gate.emit_unconditional(header[:2])  # title + blank — audit header follows (S-F6)
        gate.emit(
            _audit_header_lines(
                _filter_display_name(options.report_filter),
                mod_counts,
                check_counts,
                region_counts,
            ),
            "preamble",
        )
        gate.emit_unconditional(header[2:])
    gate.emit(_inventory_lines(variant_set), "preamble")
    gate.emit(_overview_lines(variant_results), "preamble")
    if options.include_legend:
        gate.emit(_legend_lines(), "preamble")

    # LLR-108.4 — the per-variant reservation. Floored, because a share of
    # CAP//V shrinks without limit; and applied ALONGSIDE the document budget,
    # never instead of it (P-27: a floored reservation over-subscribes the
    # document — Σ = V·max(CAP//V, floor), measured 48.8x CAP at V=100 000 —
    # so reservation-only gating would break the very ceiling AT-250/251/252
    # assert).
    # Shares are cut from what is ACTUALLY LEFT, not from the whole cap: the
    # preamble has already been charged by this point, so dividing
    # REPORT_MAX_TOTAL_BYTES hands out shares that together exceed the remaining
    # budget and lets the earlier variants spend the later ones'. Measured: at a
    # 4 000 B limit the preamble takes ~2 000, so six shares of CAP//6 = 666
    # promise 3 996 B against 2 000 B actually available.
    reservation = max(
        gate.budget.remaining() // max(len(variant_results), 1),
        REPORT_VARIANT_RESERVATION_FLOOR_BYTES,
    )
    for index, result in enumerate(variant_results):
        gate.begin_variant(index, reservation)
        # LLR-108.5 — the heading is emitted whatever the reservation holds, so
        # no variant can vanish from the audit record. This is the one
        # deliberate O(V) term and it is named, not emergent (non-claim (j)).
        gate.emit_unconditional(
            [f"## Variant: {md_safe(result.variant_id, limit=REPORT_CELL_CHARS)}", ""]
        )
        gate.emit(_modified_files_lines(result), "modified-files")
        gate.emit(_modifications_lines(result, options.report_filter), "modifications")
        gate.emit(_declaration_error_lines(result), "declaration-errors")
        gate.emit(_checklist_lines(result, options.report_filter), "checklists")
        notes.extend(
            (index, note) for note in _hexdump_section(result, options, gate)
        )
        if options.include_entropy:
            gate.emit(_entropy_lines(result), "entropy")
    gate.end_variants()

    if options.declared_regions:
        gate.emit(
            _addendum_lines(options.declared_regions, variant_results), "addendum"
        )
    if notes:
        # LLR-108.9 — round-robin by variant. notes[:CAP] retains the EARLIEST,
        # which lets a flood of cheap notes from variants ordered ahead evict
        # the note naming the real target.
        itemised, not_itemised, distinct = _select_notes(
            notes, REPORT_MAX_TRUNCATION_NOTES
        )
        block = ["## Truncation appendix", ""] + [f"- {note}" for note in itemised]
        if not_itemised:
            block.append(
                f"- {not_itemised} further note(s) across {distinct} variant(s) "
                f"not itemised (cap: {REPORT_MAX_TRUNCATION_NOTES} notes)."
            )
        block.append("")
        gate.emit_unconditional(block)
    # LLR-108.6 — ONE aggregated disclosure block, at the tail, keyed by the
    # closed section-kind tuple, so its line count is O(1) in V and F.
    gate.emit_unconditional(_disclosure_lines(gate.refusals))

    target = reports_dir / filename
    target.write_bytes(document_bytes("\n".join(gate.lines)))
    return target
