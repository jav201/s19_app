# Increment I3 — Markdown diff-report generator (HLR-004)

Batch 2026-06-11-batch-09 · Phase 3 · software-dev · branch `claude/batch-09`

Implements **HLR-004** and LLR-004.1..004.6 — the headless Markdown diff-report
generator. Build-on: I1 `s19_app/compare.py` (ComparisonResult/DiffRun/DiffStats),
I2 `s19_app/tui/services/compare_service.py` (ArtifactNote/ArtifactUsage on
`ComparisonResult.notes`). No TUI wiring (that is I4).

---

## 1. What changed

Added a new headless service `diff_report_service.py` that renders a completed
`ComparisonResult` (plus the two diffed memory maps) into one Markdown diff
report and writes it with the batch-07 no-silent-overwrite collision discipline.
The report body is Header → Statistics table → Run table (with best-effort
symbol annotation) → per-run bounded hex windows for image A and B, with
explicit `TRUNCATED` markers for both the per-report run-dump cap and the
whole-document byte budget. The module owns its own listing scheme
(`DIFF_REPORT_FILENAME_REGEX` + `list_diff_reports`) so the shared
`report_service.REPORT_FILENAME_REGEX` / `list_project_reports` are not touched
(G-4). Destination resolution implements the G-8/M-4/M-5 security decisions
exactly: project-active → `<project>/reports/` inside `.s19tool/`; no-project →
operator-supplied directory, normalized via `expanduser().resolve()` and
required to be an existing dir, with NO implicit default and no overwrite.
The module does no logging (F-S-07).

## 2. Files modified

| File | LOC | Purpose |
|---|---|---|
| `s19_app/tui/services/diff_report_service.py` | 746 | NEW. `generate_diff_report`, `DiffReportResult`, `DIFF_REPORT_FILENAME_REGEX`, `list_diff_reports`, `_resolve_destination` (G-8/M-4 validator), `_diff_report_filename` (M-5 counter), section builders, best-effort `_annotate_run` (G-2). No Textual, no logging. |
| `tests/test_diff_report_service.py` | 497 | NEW. 17 tests (16 functions; `test_no_project_empty_path_refused` parametrized ×2) covering TC-016..TC-020 + TC-025. Docstring maps test→TC→LLR. |

Reused READ-ONLY by import (not edited): `report_service.REPORTS_DIR_NAME`,
`REPORT_TIMESTAMP_FORMAT`, `REPORT_MAX_TOTAL_BYTES`, `REPORT_CONTEXT_BYTES_DEFAULT`,
`compute_hexdump_windows`; `hexview.HEX_WIDTH/MAX_HEX_ROWS/render_hex_view`;
`range_index.build_sorted_range_index/address_in_sorted_ranges`; `version.__version__`.
`git status` confirms only the 2 NEW files; `git diff --stat report_service.py` empty.

## 3. How to test

```
python -m pytest -q tests/test_diff_report_service.py
python -m pytest -q tests/test_compare_engine.py tests/test_compare_service.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only        # last line
rg -n "^\s*(from|import)\s+textual" s19_app/tui/services/diff_report_service.py   # expect 0
rg -n "getLogger|import logging" s19_app/tui/services/diff_report_service.py       # expect 0
rg -n "REPORT_FILENAME_REGEX" s19_app/tui/services/report_service.py               # unchanged at :106
```

## 4. Test results (actual)

1. `pytest -q tests/test_diff_report_service.py` → **17 passed in 0.46s**.
2. `pytest -q tests/test_compare_engine.py tests/test_compare_service.py` → **23 passed in 1.90s** (I1+I2 regression intact).
3. `pytest -q -m "not slow"` → **720 passed, 29 skipped, 21 deselected, 3 xfailed in 200.07s** — **0 failures**. (Pre-state 703 passed; 703 + 17 new = 720.)
4. `pytest -q --collect-only` last line → **773 tests collected** (pre-state 756 + 17 new).
5. Probes — textual import: **0 hits**; `getLogger|import logging`: **0 hits** (F-S-07); `REPORT_FILENAME_REGEX` in report_service: **unchanged** (`-report\.md$` at `:106`, G-4 NON-edit). `sanitize_project_name` not in `_resolve_destination` source (TC-025 `test_no_sanitize_project_name_in_validator` green, M-4).

Ledger: **756 → 773** (collection). Lean **703 → 720** passed.

## 5. Security-decision implementation points

- **G-8 (no Downloads default):** `_resolve_destination` no-project branch refuses an empty/blank input and any non-existing directory; there is NO `Path.home()/"Downloads"` branch anywhere in the module (`rg "Downloads"` would return 0). Covered by `test_no_project_empty_path_refused` (×2) + `test_no_project_nonexistent_dir_refused`.
- **M-4 (path validation):** validation is `Path(operator_input).expanduser().resolve()` → `dest.is_dir()`. `sanitize_project_name` is NOT used (proved by source probe on the validator function). A relative operator path resolves against the app cwd (resolve default), matching the read-side `resolve_input_path` idiom; `find_repo_root` is NOT used as base.
- **M-5 (no silent overwrite):** `_diff_report_filename` applies the zero-padded `-NN` counter + `FileExistsError` after 99 in the resolved dir for BOTH branches. `test_collision_never_overwrites_existing_file` (project) and `test_no_project_collision_no_overwrite` (no-project) plant a target and assert the original is byte-identical + a `-01` sibling is produced.
- **G-2 (annotation non-gating):** `_annotate_run` returns `-` when a run intersects no symbol or no context exists; never alters run extraction. `test_symbol_annotation_only_intersecting_run` + `test_annotation_absent_without_context`.
- **G-4 (self-contained listing):** own regex + `list_diff_reports`; `report_service` untouched (`git diff --stat` empty; `test_report_service_regex_unedited`).
- **F-S-07 (no logging):** `test_module_performs_no_logging`.

## 6. A-3 reconciliation (provisional TC names vs actual node ids)

Spec provisional TCs for HLR-004: TC-016 (filename+collision), TC-017 (listing),
TC-018 (content+caps), TC-019 (annotation), TC-020 (confidentiality), TC-025
(no-project destination). Actual pytest node ids created:

| Node id | TC | LLR |
|---|---|---|
| `test_filename_scheme_and_same_second_collision` | TC-016 | LLR-004.1 |
| `test_collision_never_overwrites_existing_file` | TC-016 | LLR-004.1 (M-5) |
| `test_self_contained_listing_newest_first` | TC-017 | LLR-004.2 (G-4) |
| `test_report_service_regex_unedited` | TC-017 | LLR-004.2 (NON-edit) |
| `test_report_sections_present_in_order` | TC-018 | LLR-004.3 |
| `test_run_dump_cap_emits_truncated_marker` | TC-018 | LLR-004.3 (caps) |
| `test_byte_budget_emits_truncated_marker` | TC-018 | LLR-004.3 (caps) |
| `test_generation_is_deterministic_fixed_clock` | TC-018 | LLR-004.3 (determinism) |
| `test_symbol_annotation_only_intersecting_run` | TC-019 | LLR-004.4 (G-2) |
| `test_annotation_absent_without_context` | TC-019 | LLR-004.4 (non-gating) |
| `test_module_performs_no_logging` | TC-020 | LLR-004.5 (F-S-07) |
| `test_no_project_valid_directory_writes_one_file` | TC-025 | LLR-004.6 (G-8 valid) |
| `test_no_project_empty_path_refused[]` / `[   ]` | TC-025 | LLR-004.6 (G-8 refuse) |
| `test_no_project_nonexistent_dir_refused` | TC-025 | LLR-004.6 (G-8 refuse) |
| `test_no_project_collision_no_overwrite` | TC-025 | LLR-004.6 (M-5) |
| `test_no_sanitize_project_name_in_validator` | TC-025 | LLR-004.6 (M-4) |

**Drift:** each provisional TC fans out to multiple node ids (distinct
properties given their own function, the m-4 per-property idiom). 16 functions →
17 collected (one parametrized). No TC is missing; no provisional TC was dropped.

## 7. Risks

- `DIFF_REPORT_MAX_RUN_DUMPS = 128` chosen by the `REPORT_MAX_REGIONS_PER_VARIANT=128`
  precedent (spec flagged `assumed — verify in Phase 3`); not yet measured against
  the byte budget on a large fixture (no slow test this increment — HLR-004 has no
  slow TC). Sizing holds because the budget cap independently bounds total output.
- The run TABLE lists every run uncapped; a pathological diff with millions of
  runs makes a large table. The spec caps only hex windows, not the table — matches
  the precedent (project report tables are also uncapped). Acceptable per LLR-004.3.
- Determinism test compares two bodies under a fixed clock; it does not pin exact
  bytes against a golden file. Sufficient for the LLR-004.3 determinism threshold.

## 8. Pending items (I4–I5)

- **I4:** TUI wiring — inline image-pair selection in `AbDiffPanel`
  (`screens_directionb.py:849`), service-only routing (LLR-005.1), placeholder
  replacement (LLR-005.2), failure surfacing (LLR-005.3), report-trigger feedback
  calling `generate_diff_report` and surfacing `DiffReportResult.path` /
  diagnostics (LLR-005.4). The operator destination PROMPT for the no-project
  branch lives here.
- **I5:** Phase-4 validation, REQUIREMENTS.md R-* traceability updates, batch-07
  LLR-012.3/012.4 supersession recording, slow-suite CI-regime confirmation
  (LLR-001.5).

## 9. Suggested next task

I4 — wire `AbDiffPanel` to `compare_service.compare_images` and
`diff_report_service.generate_diff_report`, including the no-project destination
prompt that feeds `dest_input`. Start by reading `_compose_screen_diff`
(`app.py:1868`) and the `AbDiffPanel` block (`screens_directionb.py:849-939`).

---

## REDO (I3 gate, 2026-06-13) — G-9 amendment: complete files + ```diff cue + HTML export

### R.1 What changed

The I3 spec was iterated at the gate (G-9, BINDING). Three changes to the two
I3 files only (`diff_report_service.py`, `tests/test_diff_report_service.py`):

1. **Complete Markdown file (LLR-004.3 amended).** REMOVED all file-level
   truncation machinery: the `REPORT_MAX_TOTAL_BYTES` import, the
   `DIFF_REPORT_MAX_RUN_DUMPS` constant, the `run_dump_cap` / `budget_limit`
   parameters of `generate_diff_report`, and every `TRUNCATED` marker. The
   written Markdown file now dumps EVERY run's hex windows, uncapped — the
   batch-07 caps are relocated to the TUI display path (I4 / LLR-005.2), not
   this file. `_hex_windows_lines` lost its budget bookkeeping.
2. **```diff cue (LLR-004.3 amended).** Each `changed` run now additionally
   emits a fenced ```` ```diff ```` block (`_diff_block_lines`): image A's
   window rows as `-`-prefixed lines, image B's as `+`-prefixed lines, so the
   block renders red/green on GitHub/VS Code/Obsidian and degrades to plain
   text elsewhere. Plain ```` ```text ```` per-image windows are still emitted
   for both A and B.
3. **Self-contained HTML export (LLR-004.7 NEW).** Added sibling
   `generate_diff_report_html(...)` + `DIFF_REPORT_HTML_FILENAME_REGEX` + the
   `<UTC>(-NN)?-diff-report.html` scheme. Same `ComparisonResult` content
   (identities, usage notes, stats, run table w/ best-effort annotation, per-run
   hex windows for A and B). Inline `<style>` ONLY; the three run kinds carry
   distinct inline-CSS colours (`#b58900` changed / `#dc322f` only-A / `#268bd2`
   only-B). Every embedded value is `html.escape`d via `_esc`. NO `<script>`, no
   external resource/font/CDN/network, no `<link>`. COMPLETE (no cap / byte
   budget / TRUNCATED). Reuses the SAME `_resolve_destination` (G-8 solo-prompt
   / M-4 resolve()+is_dir-else-refuse) and the SAME collision counter
   (`_diff_report_filename`, now parameterised by suffix `.md` / `.html`, M-5).
   No logging (F-S-07).

**Public API shape chosen:** a SIBLING function `generate_diff_report_html(...)`
mirroring `generate_diff_report(...)`'s signature (minus the removed cap
params), returning the same `DiffReportResult`. Rationale: the spec wording is
`generate_diff_report` *or a sibling renderer*; a sibling keeps each renderer
focused, leaves the existing Markdown call sites/imports intact, and avoids a
format-discriminating branch inside one function. The shared destination /
collision / escape helpers are factored once and consumed by both.

### R.2 Verification (exact numbers, 2026-06-13)

1. `pytest -q tests/test_diff_report_service.py` → **20 passed in 0.56s**.
2. `pytest -q tests/test_compare_engine.py tests/test_compare_service.py` →
   **23 passed in 1.62s** (I1+I2 regression intact).
3. Lean `pytest -q -m "not slow"` → **723 passed, 29 skipped, 21 deselected,
   3 xfailed in 186.39s — 0 failures**. Ledger delta vs pre-redo 720: **+3**
   (removed 2 file-truncation tests `test_run_dump_cap_emits_truncated_marker`
   + `test_byte_budget_emits_truncated_marker`; added 5 new functions →
   net +3, one parametrised).
4. `pytest -q --collect-only` last line → **776 tests collected** (pre-redo 773
   + net 3).
5. **LIVE HTML-safety spot-check** — generated an HTML report to a temp dir with
   payload `<script>alert("x")</script> & xss path` in `ImageRef.label`/`.path`
   and a `<`/`&` diagnostic, then probed the actual `.html`:
   - `rg -c "<script" <file>` → **0** (exit 1, no match).
   - `rg -c -e "<script|https?://|@import|src=|url\(" <file>` → **0** (exit 1,
     no match) — combined P-19 external-resource pattern.
   - escaped payload PRESENT: `rg -c "&lt;script&gt;"` → 1; `&amp;` → 1;
     `&quot;` → 1. Raw `rg -c "<script>alert"` → **0** (exit 1). The `<`/`&`/`"`
     payload appears ONLY in `html.escape` form, never raw.
   - Generated filename `20260613T063050Z-diff-report.html` — purely UTC
     timestamp + fixed suffix; the payload lived in image fields, **0 operator
     bytes reached the filename**.
6. Probes:
   - `rg -n "^\s*(from|import)\s+textual" diff_report_service.py` → **0**.
   - `rg -n "getLogger|import logging" diff_report_service.py` → **0** (F-S-07).
   - `rg -c "REPORT_MAX_TOTAL_BYTES|TRUNCATED|DIFF_REPORT_MAX_RUN_DUMPS|run_dump_cap|budget_limit|Downloads"`
     → 8 hits, ALL docstring prose explaining the relocated caps / no-Downloads
     decision; **0** in executable code (no import, no marker, no branch).
   - `git diff --stat HEAD -- report_service.py` → **empty** (G-4: shared
     `REPORT_FILENAME_REGEX` / `list_project_reports` byte-for-byte untouched).
   - No operator string in the filename component (both branches): confirmed by
     the live check + `test_no_project_valid_directory_writes_one_file` /
     `test_html_filename_scheme_and_collision`.

### R.3 A-3 reconciliation (post-redo node ids vs provisional TC names)

| Node id | TC | LLR | redo status |
|---|---|---|---|
| `test_filename_scheme_and_same_second_collision` | TC-016 | LLR-004.1 | unchanged |
| `test_collision_never_overwrites_existing_file` | TC-016 | LLR-004.1 (M-5) | unchanged |
| `test_self_contained_listing_newest_first` | TC-017 | LLR-004.2 (G-4) | unchanged |
| `test_report_service_regex_unedited` | TC-017 | LLR-004.2 (NON-edit) | unchanged |
| `test_report_sections_present_in_order` | TC-018 | LLR-004.3 | EDITED — asserts `TRUNCATED not in text` (was: no-caps-fired); sections + exact rows kept |
| `test_generation_is_deterministic_fixed_clock` | TC-018 | LLR-004.3 (determinism) | unchanged |
| `test_markdown_file_is_complete_no_truncation` | **TC-026** | LLR-004.3 (G-9) | **NEW** — 200-run planted diff, 0 TRUNCATED, all runs + all 200 table rows present |
| `test_changed_run_emits_diff_fenced_block` | **TC-027** | LLR-004.3 (```diff) | **NEW** — ```diff fence with ≥1 `-` (AA) and ≥1 `+` (BB) line |
| `test_symbol_annotation_only_intersecting_run` | TC-019 | LLR-004.4 (G-2) | unchanged |
| `test_annotation_absent_without_context` | TC-019 | LLR-004.4 | unchanged |
| `test_module_performs_no_logging` | TC-020 | LLR-004.5 (F-S-07) | unchanged |
| `test_no_project_valid_directory_writes_one_file` | TC-025 | LLR-004.6 (G-8) | unchanged |
| `test_no_project_empty_path_refused[]` / `[   ]` | TC-025 | LLR-004.6 (G-8) | unchanged (parametrised ×2) |
| `test_no_project_nonexistent_dir_refused` | TC-025 | LLR-004.6 (G-8) | unchanged |
| `test_no_project_collision_no_overwrite` | TC-025 | LLR-004.6 (M-5) | unchanged |
| `test_no_sanitize_project_name_in_validator` | TC-025 | LLR-004.6 (M-4) | unchanged |
| `test_html_export_complete_and_safe` | **TC-028** | LLR-004.7 | **NEW** — 122-run mixed-kind HTML: 0 TRUNCATED, all runs, 0 `<script`, 0 external-resource, 3 colour cues, ends `</html>`, regex match |
| `test_html_escapes_embedded_payload` | **TC-028** | LLR-004.7 (escape) | **NEW** — `<script>`/`&`/`"` payload round-trips as `&lt;`/`&amp;`/`&quot;`, raw absent |
| `test_html_filename_scheme_and_collision` | **TC-028** | LLR-004.7 (M-5/regex) | **NEW** — base + `-01` `.html` siblings, own regex matches, Markdown regex does not |

**REMOVED (file-truncation assertions inverted into TC-026's completeness):**
`test_run_dump_cap_emits_truncated_marker`, `test_byte_budget_emits_truncated_marker`.
**Drift:** TC-026/027 fan out under LLR-004.3 (the m-4 per-property idiom);
TC-028 fans out to 3 node ids (complete+safe / escape / filename). No
provisional TC dropped; the 2 removed tests are subsumed by the inverted
completeness assertion. Net function delta: 16 → 19 functions (20 collected
with the one parametrisation).

### R.4 Coverage-claim discipline

Every node id in the R.3 table exists on disk in
`tests/test_diff_report_service.py` and was executed green in R.2 step 1
(20 passed). The module docstring test→TC→LLR map was updated to match.

### R.5 Deviations / notes

- The HTML colour-cue assertion checks for the three literal hex colours; these
  are NEW constants `_HTML_KIND_COLOUR` in the module (`assumed — verify in
  Phase 3` per the spec's "inline-CSS colour" wording, no specific palette
  mandated). Self-contained named-ish hex colours only; no external font.
- `body{font-family:monospace}` is a generic CSS family keyword, NOT an
  external/CDN font — it matches none of the P-19 external-resource patterns
  (verified: combined probe → 0).
- No new dependencies; `html` is stdlib. No file count breach (2 files).
