# Code-Wire graph — Inc 15: not applicable

Stage E2 of the design-first flow (`dev-flow-v3-beta`) was not run for Inc 15. This note records the skip and its reason (E3 round 1, finding F10, `../E3-rulings.md`).

- **Reason.** Inc 15 is tests-only. 0 files under `s19_app/` change, and no product function, contract or constant changes (`../E1-rulings.md` §2, `../E1-slice.md` §1). A Code-Wire graph prototypes product functions and their contracts, so this increment gives it nothing to model.
- **Where the examples live instead.** The design's examples are the wait sites and their signals: table D in `../01-requirements.md` (site, trigger, description), the per-function change tables in `../E1-slice.md` §2 (predicate and product signal per wait), and the thresholds and negative controls of R-TST-150 … R-TST-163 with their cases in `../02-test-cases.md`.
- **Product behaviour the waits read (unchanged).** These are cited at their base lines in the Definitions of `../01-requirements.md`: the change document's source path (load, paste, dropdown pick), the save-back prompt row's `hidden` class (apply, decline, confirm), and the Flow Execution bind step (`FlowExecutionPanel._rebind`).
