# 04 — Validation (Phase 4) — batch-62

> Tree: `f8ce5b6` (Phase 3 closed). Base `8d3c504`. Language: English.
> Evidence run: the Inc-4 full-suite run, executed on this exact tree with nothing changed since the
> commit — **2195 passed, 2 skipped, 3 xfailed** (34:19), 29 snapshots passed, ruff clean on every
> touched file, frozen guards `tc027` + `tc031`×3 green. Re-running 34 minutes over identical bytes
> would add no information, and saying so is more honest than presenting a second run as new evidence.

## VERDICT: **FAIL → return to Phase 3 for one closing increment (Inc-5).**

The **AT layer is complete**: all seven ATs exist as exactly one named on-disk node each, all pass,
and each was shown RED before its fix. **The TC layer is not**, and one finding is worse than a
coverage gap — a normative ruling from the refined spec **was never implemented**.

| Layer | Result |
|---|---|
| AT-157…163 | **7/7 realized, one node each, all green** |
| TC-376…398 | **17 covered · 5 gaps · 1 superseded** |
| Normative rulings D-1…D-27, A-01…A-43 | **1 NOT IMPLEMENTED (D-20/A-27)** |
| Requirements R-TUI-077 / R-TUI-078 | written, traced, `Automated` |
| Regressions | 0 |

---

## 1. Blockers

### B-1 — **D-20 / A-27 was never implemented.** `MAX_REPORT_ISSUES_PER_VARIANT` does not exist.

Measured: `grep -rn 'MAX_REPORT_ISSUES_PER_VARIANT' s19_app/ tests/` returns **nothing**, and
`_declaration_error_lines` still emits one line per issue with no cap.

The refined spec states it as `shall` (D-20, closing security finding F7): the declaration-error
section is the one section outside `_ByteBudget`'s hexdump-granularity accounting, and **this batch
doubled its per-issue cost** by raising `issue.message`'s escape limit from 240 to 500. The section
the batch grew is the section nothing bounds.

It appears in no increment's file list. Inc-3a and Inc-3b both touched the exact function and neither
carried it — the ruling was made at the fold, recorded in §6.5, and then silently dropped on the way
into the increment cut. That is the same failure mode this batch exists to punish, committed by me at
a later stage.

### B-2 — `REPORT_CELL_CHARS` (512) is unpinned, so TC-396 is unrealized at the composer.

`REPORT_CELL_CHARS` appears in `tests/` **only as an argument** (`test_tui_report_filter_surface.py:1388`),
never with a boundary pair. The flow report's 240 cap is pinned
(`test_flow_report_service.py:269-270`) but that is a **different constant for a different consumer**
— the whole point of A-39.

Deleting `limit=REPORT_CELL_CHARS` from any of the ~20 Mode-A sites, or changing 512, currently turns
**no test red**. That is precisely the batch-60 defect the spec quoted at itself: a cap whose fixture
never crosses it.

---

## 2. AT traceability — 7/7, one node each (C-18)

| AT | Node | Story | RED counterfactual, measured |
|---|---|---|---|
| **AT-157** | `test_report_field_census.py::test_at157_no_planted_field_produces_markup_in_the_app_viewer` | US-B62-1 | escaper neutralised at the composer → RED (13/19 census cases) |
| **AT-158** | `…::test_at158_exported_file_is_inert_under_a_default_reader` | US-B62-2 | same |
| **AT-159** | `test_report_symbol_escape.py::test_at159_hostile_symbol_cannot_shift_table_columns` | US-B62-3 | measured at `8d3c504`: `['EVIL','INJECTED','COL','a.s19']` — `file_type` and the active flag destroyed at an unchanged cell count |
| **AT-160** | `…::test_at160_recaptured_golden_carries_the_escaped_forms` | US-B62-2 | golden gate: changed-line set **{14, 15, 51}**, no unpredicted line |
| **AT-161** | `test_report_field_census.py::test_at161_an_all_backtick_image_cannot_close_the_hexdump_fence` | US-B62-1/2 | carries its own anti-vacuity assertion (backticks provably present) |
| **AT-162** | `test_report_symbol_escape.py::test_at162_paths_render_without_inserted_escapes` | R-1 | Mode A leaks the drive letter; Mode B does not (executed at Phase 1) |
| **AT-163** | `…::test_at163_escaping_is_applied_exactly_once` | R-3 | `SYM\_A` required, `SYM\\\_A` forbidden — catches over- AND under-application |

---

## 3. TC traceability — the honest table

**No TC id appears on any node.** The nodes are consolidated batteries, so traceability is recorded
here rather than in test names. That is a finding in its own right (§5 m-1), not a convention.

| TC | Covered by | Status |
|---|---|---|
| TC-376 payload-set completeness | `test_g1…g5_*` | ✅ |
| TC-377 per-payload neutralisation | `test_mode_a/b_neutralises_and_preserves` (parametrised, 35 each) | ✅ |
| TC-378 never double-escapes | `test_backslash_is_escaped_first_and_ampersand_second` + AT-163 | ✅ |
| TC-379 ctl/newline handling | `test_deceptive_characters_*`, `test_collapse_*` | ✅ *(semantics amended by A-26: control chars become a VISIBLE marker, not deleted)* |
| **TC-380** ⭐ collapse is load-bearing | `test_collapse_defuses_block_starters_pushed_onto_a_new_line` (9 starters) | ✅ |
| TC-381 empty / null / whitespace | `test_both_modes_render_the_empty_marker`, `test_a_value_of_only_format_characters_is_not_empty` | ⚠ **partial** — `None` is not exercised |
| TC-382 Unicode boundary | `test_deceptive_characters_*`, `test_u2028_*` | ❌ **GAP** — no astral char, NBSP, combining mark, and no large-string case (A-38 required raising it above 10 000) |
| **TC-383** ⭐ field-site census | `test_census_every_planted_field_renders_verbatim` (14 fields) | ✅ |
| TC-384 census cannot shrink | `test_census_covers_every_reachable_file_derived_field` | ✅ |
| TC-385 heading sites | census plants all three heading values | ⚠ **partial** — the heading LEVEL is not asserted; `live_tokens` is a type SET, so a `##`→`#` promotion would not show |
| **TC-386** ⭐ code-span site | AT-162 + the census `saved_path` field | ✅ |
| TC-387 declaration-error compound line | census plants code + message + symbol + related simultaneously | ✅ |
| TC-388 filter header upgraded | `test_tc318_*`, `test_tc314_*` (re-baselined) | ✅ |
| TC-389 truncation-appendix path | — | ❌ **GAP** — the region cap is never forced with a hostile `variant_id`; the escaping is in place but untested |
| **TC-390** ⭐ positional cell integrity | AT-159 | ✅ |
| TC-391 cell count == header width | `test_every_table_row_keeps_its_header_width` | ✅ |
| TC-392 backslash + ctl in a cell | `test_hostile_linkage_symbol_md_escaped` | ✅ |
| TC-393 batch-39 regression | both arms re-baselined with §6.5 records (A-03) | ✅ |
| **TC-394** ⭐ benign round-trip | the golden + its two consumers | ✅ *(the golden IS the main-vs-branch comparison; the literal two-tree form was unnecessary)* |
| TC-395 benign shapes untouched | `test_interior_hyphen_is_never_escaped`, AT-162 | 🔄 **superseded** — "character-identical **source**" is false by design under Mode A (`a.s19` → `a\.s19`); the property that survives is character-identical **rendered** text, which every fidelity clause asserts |
| **TC-396** ⭐ any cap pinned | flow-report 240 only | ❌ **GAP → B-2** |
| **TC-397** byte budget | — | ❌ **GAP → B-1** |
| TC-398 truncate before escape | `test_mode_a_truncation_boundary_pair` | ⚠ **partial** — order holds by construction; "truncation never orphans a `\`" is not asserted |

---

## 4. Requirements traceability

`US-B62-1/2/3` → `HLR-095…099` → 16 LLR → `AT-157…163` + `TC-376…398`. Both chains present; HLR-099's
missing US parent was repaired at the fold (A-09). `REQUIREMENTS.md` carries **R-TUI-077** (composer
escaping, two-mode truth table, two pinned scope exclusions) and **R-TUI-078** (host-path redaction),
both `Automated`, both naming their residual risk (RR-1 reader extensions, RR-2 Mode-B host paths).

## 5. Minors

- **m-1** — no TC id is traceable to a node. The registry reads as satisfied while nothing consumes
  it; this is the *reverse-index* control the backlog has carried as an open candidate since
  batch-48 (item 1c). Cheapest honest fix: name the TC ids in the docstrings of the nodes that cover
  them, which also makes §3's table checkable instead of curated.
- **m-2** — `ruff check s19_app/` is red on `main` (verified with this branch's changes stashed).
  Pre-existing, untouched, and worth naming because "ruff clean" in this batch's packets means *the
  touched files*, not the package.
- **m-3** — the batch added 27 tests and ~4 minutes of wall clock to the report suites; the full run
  is now ~25–34 min locally. Not a defect, but the trend is worth a note before the next batch adds
  to the same files.

## 6. What Inc-5 must do

Two blockers, both small, plus the three cheap TC gaps. Estimated 3 files:

1. `report_service.py` — `MAX_REPORT_ISSUES_PER_VARIANT = 200` mirroring
   `MAX_REPORT_FINDINGS_PER_BLOCK`, applied in `_declaration_error_lines` with an explicit
   in-document marker (never a silent cut, per the module's existing size discipline).
2. `tests/test_report_field_census.py` — TC-397 (fixture driving the **uncapped** section past the
   cap, with the fixture's multiple stated in the docstring), TC-396 (a boundary pair on
   `REPORT_CELL_CHARS` at a composer site with **no** upstream cap — `descriptor.path.name` —
   so deleting the `limit=` argument goes RED), TC-389 (force the region cap with a hostile
   `variant_id`), TC-385's heading-level clause.
3. `tests/test_report_markup_safety.py` — TC-382's missing Unicode classes and a large-string case;
   TC-381's `None`; TC-398's orphaned-backslash clause.

Then re-run Phase 4.
