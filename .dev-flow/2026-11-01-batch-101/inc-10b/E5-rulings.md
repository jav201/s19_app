# Inc 10b — E5 rulings (orchestrator, 2026-11-07)

Inputs: `E5-review.md` (code + security) **FAIL, BLOCK-UNTIL R-1** (R-1 MAJOR; R-2 … R-6 MINOR); `E5-coverage-audit.md` **PASS-WITH-NOTES** (QA-1 MAJOR: run thresholds; QA-2 MINOR; QA-3 … QA-8 NIT). The mutant table (DeepSeek) is running on the pre-corrective tree. Rulings:

| Finding | Ruling | Why |
|---|---|---|
| R-1 (MAJOR) | **Measure first, on the large case:** re-point QC-TM-10b-1 to `examples/case_06_large_nested_a2l` (about 220,000 objects) on the serial lane, bound 1 s with ≥ 20 % margin, and return early when no image is loaded. If the full refresh exceeds the bound, **recompute only the tags whose address range intersects the bytes the write changed** (in `_refresh_a2l_values_after_write` / `_repaint_a2l_tag_cells`, within `app.py`); keep I-7 (no clear / cursor / scroll). Record the before/after figures. If a partial recompute cannot be built inside the slice, stop and report (the D-10b-6 fallback is then the orchestrator's call). | A write must not freeze the UI on a large A2L the repo ships; E3 A10-12 already asked for the large case. |
| R-2 | Accept: on an `id()` re-point miss, fall back to a re-filter (no KeyError); run the Split/Join notice first, so a failure later in the hook cannot skip the disarm. Add the node if a route reaches the miss; else record it as defensive. | A display refresh must never exit the app. |
| R-3 | **Backlog BL-I10b-1** (flagged for the batch-end review page): the Issues and Checks "Hex Peek" panes keep pre-write bytes after an in-place write until the row is re-selected. Not folded: `_update_issues_hex_pane` is changed by Inc 12 (in flight); fold it into Inc 12 only if its integrator can do so without touching another file — otherwise next batch. | Visible but minor; avoids a cross-increment conflict before 1.0.0. |
| R-4 | Accept: one A2L node on page 2 (the shown page's cells match `tags[start + i]`), with a mutant `tags[i]`. | Page 1 masks an index bug. |
| R-5 | Backlog BL-I10b-2: share the bounds / styling / summary of the tag repaint with `update_a2l_tags_view`. | Refactor, not a defect. |
| R-6 | Accept: the hook docstring matches the code; the new notices guard a missing panel as the old ones did. | — |
| QA-1 | The corrective's final runs on the final tree: the W file **three times**, R-SEG-OPEN.6/3 three times, the serial lane once with the new QC-TM figure. | Thresholds say 3/3 on the final tree. |
| QA-2 | Accept: case R-A2L-048/4 (the R2-7 widening example) with a node that reads the painted line; mutant `update_width=False` must turn it RED. | The width widening had no failing evidence. |
| QA-3 | Record the A10-08 arm as an equivalent mutant (no shipped route reaches it). | — |
| QA-4 | Accept: mutant M-B2 and the pinned scroll (`(10, 40)` main / `(0, 40)` A2L, MAC); amend R-TUI-004.8's threshold text to what the panes can reach, marked "(changed at E5, QA-4)". | Threshold text and node must agree. |
| QA-5 | The corrective runs the mutants QA-5 lists that the DeepSeek table does not cover (re-render removed with the cache kept; `_bump` → `_sync` with the hidden branch as `pass`; the hook call removed per caller), as `mut-c-NN`. | Base RED is not mutant evidence. |
| QA-6 … QA-8 | QA-6 optional: skip, record. QA-7, QA-8: record fixes (executors and trees in Result cells; R-SEG-PREV.22/1's base RED re-run on base if cheap, else say inferred). | Record hygiene. |
