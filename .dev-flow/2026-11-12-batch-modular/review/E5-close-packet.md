# batch-modular — close packet (E5)

Date 2026-11-13. Work branch `batch-modular-apply` (backup, not pushed). Deliverable: local branch `batch-modular-squash` = `main` + batch-103 Inc 1b (cherry-pick of `b103-inc1b`) + one squashed batch commit. Not pushed: waits for the operator.

## 1. What changed
- `s19_app/tui/app.py` (23,488 lines) is now the package `s19_app/tui/app/` (23 files: `core`, 18 mixins, `shared`, `shared_io`, `deps`, `__init__`). `s19_app/tui/screens_directionb.py` (9,296 lines) is a 9-file package. Code was moved, not rewritten: every unit sits once with an identical body, no import cycles, all re-exports bound.
- Test seam: each package has a `deps` module. Product code reads seam names as `deps.X` and tests patch `<package>.deps`. The permanent law `tests/test_deps_seam_law.py` guards it.
- Tools in `tools/modularize/`: census, map planner, mover, identity verifier, test retargeter, suite comparator.
- Canon: R-MOD.6.1 and R-MOD.6.3 promoted to `REQUIREMENTS.md` S6.9, with decision D6-47 in `docs/requirements/review/S6-ears-strict.md`. The other 40 R-MOD rows stay in the batch record (operator verdict 2026-11-13). R-MOD.1.x, 5.2/5.3, 8.x and 9.x enter the canon in P3 with their law tests.

## 2. Files modified
216 files against `b103-inc1b`: 32 package files and 2 deleted monoliths, `tools/modularize/*`, retargeted tests (151 seam sites), `tests/support/package_source.py`, `tests/test_package_source_helper.py`, `tests/test_deps_seam_law.py`, `tests/test_id_registry.py` (bound), `docs/architecture.md`, `CLAUDE.md`, `REQUIREMENTS.md`, `docs/requirements/review/S6-ears-strict.md`, plus the batch records `.dev-flow/2026-11-12-batch-modular/`.

## 3. How to test
- Identity: `python tools/modularize/verify.py ...` (see `evidence/p2-reapply/apply3.sh`) gives `VERIFY OK`.
- Suite equality: `tools/modularize/run_suite.sh` on base and tree, then `compare_outcomes.py` with `--flaky evidence/p2-after3/flaky4.txt` (command in `evidence/p2-after3/cmp.sh`).
- Laws: `pytest tests/test_deps_seam_law.py tests/test_package_source_helper.py tests/test_no_private_tokens.py` on Linux.

## 4. Test results
- `04-validation.md`: PASS 63 (3 scoped: TC-60, TC-63, TC-MOD-7G1), FAIL 1 accepted (TC-37), NO-EVIDENCE 0, PENDING 0.
- Full suite after3 (rtx, `-n 12`): `78 failed, 8126 passed, 285 skipped, 4 xfailed`. Against base: 0 missing ids; 8 new ids (the batch's helper tests). 0 passed->failed after excusing 6 load flakes, each with a serial 3x2 record. The other 14 diffs all move toward passing. 0 collection errors.
- Comparator controls on the final tool: NC-CMP-1 (B1), NC-CMP-2 (B2) and the B4 family drop are RED. NC-CMP-3 (mutant `set_status`) is RED: 238 passed->failed, 233 of which pass on the unmutated tree.
- `trace_check`:
  - SLICE, US and CASE: 0.
  - EVID: 24 lines, all from the tool not resolving the `B/` prefix; every path is tracked.
  - CANON: 40, the rows deferred by the operator.
  - TEST: 42, structural (the evidence is tool transcripts).
- Squash checks on rtx: see `steps.log` (the squash lines).

## 5. Risks
- Modules are still large: 29 of 32 are over 300 lines and 257 functions are over 40. Splitting further (P3) is deferred until an impact analysis.
- TC-37: the mover would accept moving a core-pinned member that has no `@on` or `super()`; the verifier rejects the output (V9). NC-VF-25: the verifier misses `@on` on a mixin method (the mover refuses it). NC-MV-10: losing `TYPE_CHECKING` names passes both tools. All three are in the MINOR backlog; the tools are one-shot.
- The squash is stacked on batch-103 Inc 1b, whose WinCI run 43438310100 is red (4 new Inc 1b tests plus the artifact scanner). batch-modular merges after Inc 1b is settled.
- Pre-existing failures that this batch does not cause: canon "shall" twice (3 rows), `test_r_tst_070_2` flagging the isolated HOME basename, and the `id_registry` count off by one on `main`.

## 6. Pending items
- Operator OK to push `batch-modular-squash`, and the order of merging after `b103-inc1b`.
- MINOR backlog (in `steps.log`):
  - E5 F3–F9; the 2 dead seam-name imports.
  - `_test_violations` is 47 lines; the `CLAUDE.md` TUI bullet still names `app.py::S19TuiApp`.
  - The TC-37 / NC-VF-25 / NC-MV-10 tool gaps.
  - Wrong [V] labels in the P1c hazard table.
- P3 impact analysis.

## 7. Suggested next task
Settle batch-103 Inc 1b WinCI (4 failing tests and the artifact scanner). Then push and merge `b103-inc1b` and `batch-modular-squash` in that order. Then b103 Inc 10 E4.
