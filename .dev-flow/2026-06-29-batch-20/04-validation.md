# 04 — Validation — batch-20 (D-1 + D-2)

> Phase 4. Two-layer validation executed on the final A+B+C tree. **VERDICT: PASS.** 2 US / 3 HLR / 10 LLR covered BOTH layers; 0 blocker fails. All provisional AT/TC ids reconciled to real on-disk nodes (V-5). Frozen-engine diff 0; ruff clean.

## V-5 reconciliation — provisional id → real collected node (all in `tests/test_tui_report_seam.py`)

| Provisional | Real node | Layer | Result |
|---|---|---|---|
| AT-027a | `::test_save_persists_declared_regions` | B | PASS |
| AT-027b | `::test_typed_but_not_generated_not_saved` | B (boundary) | PASS |
| AT-027c | `::test_save_without_regions_byte_identical` | B (negative/back-compat) | PASS |
| TC-027.1 | `::test_save_threads_declared_regions_to_writer` | A | PASS |
| TC-027.2 | `::test_write_and_verify_manifest_accepts_declared_regions_default` | A | PASS |
| TC-027.3 | `::test_empty_regions_omits_key` | A | PASS |
| AT-028a (C-12 GATE) | `::test_load_prefills_declared_regions` | B | PASS |
| AT-028b (guard) | `::test_load_seed_guard` | B | PASS |
| TC-028.1 | `::test_load_sets_declared_regions_state` | A | PASS |
| TC-028.2 | `::test_seed_format_is_parser_inverse` | A | PASS |
| AT-029a | `::test_skipped_malformed_line_counted` | B | PASS |
| AT-029b | `::test_skipped_invalid_line_counted` | B | PASS |
| AT-029c | `::test_skipped_count_excludes_blank` | B (boundary) | PASS |
| AT-029d | `::test_all_valid_no_skip_message` | B (negative) | PASS |
| TC-029.1 | `::test_parse_returns_skip_count` | A | PASS |
| TC-029.2 | `::test_zero_skip_suppresses_notify` | A | PASS |
| TC-024.5 (batch-19, rewritten LLR-029.4) | `::test_parse_declared_regions_handles_hex_dec_and_skips_malformed` | A | PASS |

Carried-forward batch-19 nodes still green on this tree: `test_declared_region_in_dialog_reaches_report_addendum` (addendum content), `test_report_dialog_with_region_input_fits_80_and_120_cols` (C-13 geometry), `test_report_seam_writes_real_file_on_disk` + 2 others. **Seam file: 22 passed.**

## Layer A — functional (white-box) · TC ↔ LLR/HLR
- **HLR-027:** TC-027.1 (regions reach `write_project_manifest`), TC-027.2 (defaulted signature, existing caller valid), TC-027.3 (empty ⇒ key omitted) — all PASS.
- **HLR-028:** TC-028.1 (`_handle_load_project` sets `self._declared_regions`), TC-028.2 (seed format = exact inverse of `_parse_declared_regions`, round-trip idempotent) — PASS.
- **HLR-029:** TC-029.1 (`(regions, skipped)` count: malformed/invalid counted, blank excluded, all-valid=0), TC-029.2 (zero-suppression guard) — PASS. Rewritten TC-024.5 asserts the new contract (`skipped == 3`).

## Layer B — behavioral (black-box) · AT ↔ US, through the shipped surface
- **US-024 (D-1):** AT-028a is the C-12 GATE — ONE chain: type → real `#report_generate` → real `_handle_save_dialog` → FRESH app `_handle_load_project` → `action_view_reports` → assert `#report_declared_regions` `.text` == literal `"bootblk,4096,4351\ncal,32768,33023"`. AT-027a observes the on-disk `project.json` via `read_project_manifest` (exact 2-tuple). Boundary AT-027b (typed-not-generated ⇒ `()`), negative/back-compat AT-027c (key omitted + legacy load), guard AT-028b (hand-written project.json, kept IN ADDITION — not the gate). **Representative + boundary + negative all present; deliverable observed.**
- **US-025 (D-2):** AT-029a/b drive the surface (dialog → Generate) and observe the `app.notify` channel (via ported `_notices`), asserting the standalone count token. AT-029c boundary (mixed=2, blank excluded, negative `not \b3\b`), AT-029d negative (all-valid + empty ⇒ absence of any skip message). **Deliverable (notify count) observed through the handler.**

## Bidirectional surface-reachability matrix
| Dimension | Direction | Through handler? | Observed by |
|---|---|---|---|
| Typed regions (dialog TextArea) | input | yes — `#report_generate` → `GenerateRequested` capture | AT-027a, AT-028a |
| Malformed line (wrong arity) | input | yes — Generate path | AT-029a |
| Invalid line (`start>end` ValueError) | input | yes — Generate path | AT-029b |
| Blank line | input | yes — Generate path | AT-029c (excluded from count) |
| `project.json` declared_regions (write) | output | yes — `_handle_save_dialog` → real save | AT-027a (oracle `read_project_manifest`) |
| `project.json` key omission (empty) | output | yes — real save | AT-027c (raw-JSON key absence) |
| Seeded TextArea `.text` (load) | output | yes — `_handle_load_project` → `action_view_reports` | AT-028a (literal), AT-028b (guard) |
| Notify count (skip feedback) | output | yes — `on_button_pressed` → `self.notify` | AT-029a/b/c, AT-029d (absence) |

Both input dimensions AND output/deliverables are exercised THROUGH the handler (not the service API). Complete.

## Counterfactual evidence (QC-2 — captured at implement time, one+ per increment)
| Increment | Counterfactual revert | Captured RED |
|---|---|---|
| A | drop `declared_regions=` forward to `write_project_manifest` | AT-027a: oracle `()` ≠ expected 2-tuple |
| B | seed → `TextArea("")` | AT-028a: `'' != 'bootblk,4096,4351\ncal,32768,33023'` |
| C | guard `if skipped >= 0` | AT-029d + TC-029.2: spurious `'0 region line(s) skipped'` |
Each value-discriminating (not a non-empty check). Each AT can FAIL.

## Test-count ledger (collected non-slow)
`958 (base) − 0 + 16 = 974`. Inc A +6 · Inc B +4 · Inc C +6; batch-19 TC-024.5 rewritten-in-place (net 0). **Full non-slow run (confirmed on final tree): 942 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed in 409.92s** (974 collected = 942+29+3). Reconciles exactly.

## Quality gates
- ruff: **All checks passed!** (app.py, screens.py, test_tui_report_seam.py).
- Frozen-engine diff vs `main`: **empty** (0 files). Changed set = `app.py`, `screens.py`, `tests/test_tui_report_seam.py` only.
- No SVG snapshot regen needed (the report dialog is not in the snapshot matrix; geometry covered by the carried C-13 fit test, still green).

## Blocker check
- US-024: black-box deliverable observed (AT-028a TextArea + AT-027a on-disk). ✓
- US-025: black-box deliverable observed (AT-029a/b notify count). ✓
- **No story validated by white-box only.** 0 blockers.

## Gaps / carries
- **Comma-in-name** (§6.3 F-A1): scoped OUT this batch (no escaping); now surfaces as a visible D-2 skip-count. → BACKLOG if it recurs.
- **LOW cosmetic** "region line(s)" plural-agnostic (Inc-C reviewer F1): left as-is (deliberate).
- **D-1 fully closed:** the batch-19 deferred UI auto-wire (save/load) is now shipped end-to-end — the BACKLOG D-1 item closes with this batch.
- No pre-existing lint introduced; ruff clean on all touched files.

**VERDICT: PASS.** No `iterate-to-fix` / `iterate-to-refine` — black-box and white-box both green, no blocker. No §6.5 amendment (C-13 measured/N-A held; no spec change during implementation).
