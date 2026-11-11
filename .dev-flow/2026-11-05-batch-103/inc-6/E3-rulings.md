# Inc 6 — E3 round-1 rulings

Date 2026-11-10; orchestrator Kimi. Reviews: `E3-architect.md`, `E3-security.md`. No product/test code is authorized by these rulings.

| Finding | Decision | Required targeted correction |
|---|---|---|
| E3A-01 + E3S-02 | **Accept fix.** Unknown datatype remains exactly `?`; the long-value case uses UWORD with a 400-cell hostile unit. | Update `.017/3`, N2/N4 examples and coverage. Assert both ledger and full-name clipping at 80 and 118. |
| E3A-02 | **Accept explicit oracle.** | `.018/3` asserts both calls return `True` and seeded filter/page/picks reset after each call; no A2L-data-free vacuous describe assertion. |
| E3A-03 | **Accept wording only.** Node totals unchanged. | Slice header: two new Patch host groups (three functions). |
| E3S-01 | **Decline third-file expansion; narrow scope.** The carry-over concerns I-2 strings, while modal first-missing is operator input. Existing R-B102-BULK-006 already requires literal, control-free modal text. | `.017` covers only picker-owned A2L/I-2 surfaces, threshold 3/3. Remove `.017/4`; shared modal remains unchanged and its existing control deletion is not redefined. Update all totals: 20 requirements, 75 cases, 56 normal, 19 robustness. No `screens.py` edit. |
| E3S-03 | **Accept explicit full-name budget.** | N4 clips format/unit to the remaining full-name cell budget with visible ellipsis before fitting the name. `.017/3` asserts ledger and full-name at 80/118. Update slice and graph. |

## Correction-pass boundaries

One correction agent edits only `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E1-slice.md`, `codewire/graph-inc6.md`, and `steps.log`. No product, tests, stubs, extractor marks, PLAN or canon edits. Every count/claim touched by the case removal must be reconciled (C-14/C-65), and Code-Wire lint plus the independent case counter must run afterward.

## Re-review scope

Architect: E3A-01…03 and downstream consistency. Security: E3S-01…03, especially the explicit modal boundary and full-name budget. A PASS or PASS-WITH-NOTES from both is required before E4.

## E3 closure

Both independent round-2 re-reviews returned **PASS**. No MAJOR, HIGH or other blocking finding remains open. Final design: 20 requirements, 75 cases (56 normal, 19 robustness), 11 implementation + 8 context = 19 nodes, exactly two product files. E4 is authorized against this corrected graph; no earlier version is approved.

## E5 design-gap addendum

E5 code review found a remaining Check action fallback outside the approved rows. R-PICKER-CORRECT.021 and N12 now require an exact Validate/Write refusal before any ActionRequested/image read/document write. This is a design-gap correction, not a third-file change: the guard lives in Check's existing button route. E1 records and graph now total 21 requirements, 77 cases and 20 nodes. Independent architecture/security re-review of the addendum and compact-layout corrections is required before final E5 closure.

## E5 addendum re-review — PASS

Architecture and security independently returned PASS on the corrected integration worktree. `.021` closes the Check missing-length fallback with exact zero-action evidence. The compact layout preserves header and hint, and cap+1 is fully visible in three wrapped rows at 80 and 118. Final contract: 21 requirements, 77 cases, 20 graph nodes, exactly two product files.
