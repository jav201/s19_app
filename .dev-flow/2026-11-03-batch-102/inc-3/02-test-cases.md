# E1 test cases — Inc 3 — shared A2L picker / Check Editor performance

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-SEL-01 | Verify that populating the picker mounts at most one page of rows. | normal | Parameter sets of 0, 199 and 10 000 rows. | Call `set_a2l_parameters` for each set. | Table row count is `0`, `199` and `200`; no call adds more than 200 rows. | R-B102-SEL-001, full | Restore the full `_rebuild_ledger` loop. | verified |
| TC-B102-SEL-02 | Verify that filter edits are debounced and report truncated results. | normal | 10 000 parameters whose names contain `P`; filter input focused. | Type `P` and wait for the debounce. | One rebuild occurs after 150 ms; count line is `200 of 10000 shown — refine filter.` | R-B102-SEL-002, full | Rebuild synchronously on every `Input.Changed`. | verified |
| TC-B102-SEL-03 | Verify that repeated includes update only marks and preview. | normal | 199 parameters mounted; spies on ledger rebuild and preview refresh. | Toggle three highlighted rows. | Picked count increases 0→1→2→1; ledger rebuild count remains 0 after mount. | R-B102-SEL-003, full | Make `_toggle_highlighted` call `_rebuild_ledger`. | verified |
| TC-B102-SEL-04 | Verify that re-entering Check Editor with the same signature preserves state. | normal | Filter/page and two picks are set; app signature unchanged. | Leave and re-enter the Check Editor twice. | Filter text, page, picked names and table rows are unchanged; no repopulation call occurs. | R-B102-SEL-004, full | Clear picks in `set_a2l_parameters` unconditionally. | verified |
| TC-B102-SEL-05 | Verify pagination boundaries. | normal | 250 filtered parameters; page size 200. | Activate next, previous, next, then next at the last page. | Pages are 1, 2, 1, 2; previous disabled on page 1 and next disabled on page 2. | R-B102-SEL-005, full | Remove clamping or disable logic. | verified |
| TC-B102-SEL-06 | Verify the two empty states. | normal | No A2L; then A2L with filter `missing`. | Populate empty picker; then apply non-matching filter. | First message is exactly `No A2L parameters — load an A2L (^L) to list them.`; second is exactly `No parameter matches the filter.` | R-B102-SEL-006, full | Paint a blank/full-table state. | verified |
| TC-B102-SEL-07 | Verify hostile parameter names remain literal. | robustness | A parameter name carries Rich markup and control bytes. | Populate and render the picker. | Plain text keeps the sentinel; render has zero markup spans and zero control bytes. | R-B102-SEL-007, full | Build the cell with a markup string. | verified |

## Notas de ejecución

- RED: TC-B102-SEL-01/.02/.03/.04/.05 deben fallar en base por montaje completo, ausencia de debounce/paginación y reset en cada entrada. TC-06/.07 fijan comportamiento existente y deben permanecer verdes.
- GREEN: ejecutar los mismos casos tras integrar el componente en la rama batch-102.
