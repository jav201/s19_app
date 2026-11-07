# Inc 12b — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-review.md` (code + security) **PASS-WITH-NOTES** (R-1 MEDIUM, R-2 … R-5 LOW); `E5-coverage-audit.md` **PASS-WITH-NOTES** (QA-1 … QA-3 MINOR, QA-4 … QA-9 NIT); `evidence/inc-12b/win-01.txt` (Windows: `test_b100_project_homes.py` with every Windows-only arm of int-01, and the new file — 95 passed, 0 skipped). The mutant table (DeepSeek) is still running. No product defect; every ruling is a test, docstring or record fix.

| Finding | Ruling | Why |
|---|---|---|
| R-1 = QA-3 | Accept: AT-B94-15 and TC-B94-20 bound each line by the rail's `scrollable_content_region.width` (measure first; state the measured width) — show the bound RED with a line one cell too wide. | `#flow_pipeline` is `width: auto`; the current bound cannot fail. |
| R-2 = QA-2 | Accept: AT-B94-18 anchors on the A2B card's `in · B` row, as I-D5 did for AT-088b. | Its kill must not depend on the origin note clipping. |
| R-3 = QA-5 | Accept: the span clause also asserts the covering span's style is the value style, at the three sites. | I-D4 claimed it; the test must do it. |
| R-4 = QA-9 | Accept: AT-006 asserts `"≡ REPORT"`. | The bare word is also painted by the fallback title. |
| R-5, QA-4 | Accept: reword the docstrings and comments that still name the removed dropdown, canvas, ledger or grid (`flow_screens.py` four sites; TC-B97-13 / TC-B97-49 docstrings; the b96 module docstring). | Docs describe the code. |
| QA-1 | Accept: the walks collect over the whole window (`#screen_flow`, `#screen_flow_execution`), as the rows say; re-measure the populations and update the pinned counts. | Row text and walk must agree. |
| QA-6 | Accept: AT-I12b-1 asserts the ribbon text after `session` ends with the project folder's name, if the painted ribbon shows it at the node's size (the integrator saw `…/workarea/proj1`); else keep I-D6 and say so. | The tail is the observable the case names. |
| QA-7 | Accept: the walks key on widget identity, not id; the fixture states the definition of "shown" it uses. | A collapsed id must not hide a widget. |
| QA-8 | Accept: `02-test-cases.md` header line, executors in the Result cells, the Windows column from `win-01`. | Record hygiene. |

Corrective: one pass (Opus), tests, docstrings and records only — no behaviour change in `flow_screens.py` (comments/docstrings only). Re-review: the orchestrator checks the diff; a new finding of MEDIUM or above goes back to the reviewer.
