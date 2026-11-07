# Inc 12 — E5 rulings (orchestrator, 2026-11-07)

Inputs: `E5-review.md` (code + security) **PASS-WITH-NOTES** (R-1 MEDIUM, R-2 … R-7 LOW); `E5-coverage-audit.md` **PASS-WITH-NOTES** (QA-1, QA-2 MINOR; QA-3 … QA-8 NIT); `E5-mutants.md` (DeepSeek) **17/17 killed**, M14 (focus dropped before the dismiss) included — so QA-1 stays MINOR. No product defect. Rulings:

| Finding | Ruling | Why |
|---|---|---|
| R-1 | Accept: mark D3-7, D6-12, D7-10, D9-8 done in `docs/requirements/review/CODE-CHANGES.md`, and move Reports to D7-20's done list (7 of 18 dialogs still missing Escape → BL-I12-5 already holds them). | E1-rulings §5 owes these marks. |
| R-2, R-3, R-6 | Accept: the compose docstring names the removed id; TC-011's dead `hasattr` arm and "Either path" comment dropped; `test_validation_issue_filtering_and_format` renamed to what it checks (with the registry entry if it names the node); the "three tests below" comment fixed. | Docs and names describe the code. |
| R-4, R-5, QA-7 | Accept: I-5 in the graph lists the census seed names the test uses (`compute_*`, `key_*`, `render`, `render_line`, `check_action`, `@on`) and states the extra limit (a toolkit-named handler counts as reached even on a class nothing mounts; no instance today). | Spec and test must agree. |
| R-7 | **Backlog BL-I12-6** (pre-existing, toolkit-wide): a dismissing handler should return early when its screen is no longer active (a Generate press in flight when Escape lands, or a double click on Generate, raises `ScreenStackError` after writing the report). | Pre-existing; outside the four findings. |
| QA-1 | Accept: R-DLG.2/1 and AT-I12-1 move the focus to a non-input widget other than the first focusable one before `t`, and assert the focus returns to that widget (so a fallback to the first focusable cannot pass). | The oracle must distinguish restore from fallback. |
| QA-2 | Done by the mutant table (M8 … M17 ran, 17/17); M2, M3, M5 alone: rerun each alone only if the table ran them together. | Evidence per mutant. |
| QA-3, QA-4, QA-5 | Accept: AT-I12-1 asserts `down` moved the highlight to `f1.json`; R-DLG.2/11 checks the file count and the status line through `record_statuses`; R-DLG.2/12 re-checks the top screen after one settle. | Exact oracles. |
| QA-6 | Record only (the active window key and `pane.render()` are the product's own state; acceptable). | — |
| QA-8 | Result cells name the executor and the run; the Windows column reads **n/a (no Windows-only arm in this increment)**. | No Windows-only behaviour changed. |
