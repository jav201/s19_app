# Inc 16 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` (single reviewer, security lens included) — **FAIL**, 6 MAJOR, 10 MINOR, no BLOCKER/HIGH. Rulings under the operator's standing commission:

| Finding | Ruling | Why |
|---|---|---|
| A16-1 | Accept. The path grammar drops a `::<name>` suffix; the base count is re-measured (25) and cited. | A guard whose base count is wrong cannot fail for the right reason. |
| A16-2 | Accept. The guard's own probe strings and exempt keys are built from parts at runtime; no file-level exemption. | A file-level exemption would also hide a real stale reference added to the guard file. |
| A16-3 | Accept. DEV.12 gets an exact predicate (the stated screen count and key range, matched by a fixed pattern) that `architecture.md:28` satisfies. | "near" is not verifiable. |
| A16-4 | **Remove, don't guard.** The architecture doc stops restating the batch-94 import rule; ARCH.4 keeps only facts that hold on the tree. No new AST import guard. The direct call `flow_screens.py:119` → `flow_persistence_service` is a backlog row routed to Inc 9 (owns `flow_screens.py`), as a docstring/record fix or a ruling there. | A doc must not claim a rule the code breaks; a new AST guard widens this docs increment into a code-law change. |
| A16-5 | Accept. ARCH.5 archives only batch declarations that are superseded or never landed; every landed contract (B100-I*, batch-97/99 contracts that define saved-file shapes such as `project.json` and `derived_from`) stays in `docs/architecture.md`. | The interface map must not understate what fires trigger A3. |
| A16-6 | Accept. Add a row and a test: the archived files under `.dev-flow/design/archive/` hold no home path, drive-letter user path, account/host name or LAN address (the D-8 redaction is checked, not assumed). | The repository is public; `test_r_tst_070_2` does not scan that folder. |
| A16-7 … A16-16 (MINOR) | Fold in the same correction pass where each is a one-line edit; any that is not goes to E4 as an addendum in `E1-rulings.md`. | Skill rule: minors do not force another round. |

Correction: one design-correction agent, targeted edits only (no file rewrite). Round 2: the architect re-checks only A16-1 … A16-6.
