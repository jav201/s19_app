# Inc 8 — E4 integration notes

Batch 2026-11-01-batch-101, increment 8, stage E4 (integration step). Model: Opus.
Inputs: the Kimi K2.8 implementation and the Kimi K2.8 independent tests, committed as found (`499d15d`), then `origin/main` (`f11b3f4`, batch-102 hot-fixes and Inc 1's canon) merged in with no conflict.
Records read: `01-requirements.md`, `E1-rulings.md`, `E3-rulings.md` (rounds 1 and 2, addenda N-1 … N-4), `E4-impl-notes.md`, `E4-tester-notes.md`, `02-test-cases.md`, `codewire/graph-inc8.md`.

## 1. Verdict

**GREEN on the tree, RED on the base for behavioural reasons.** The implementation followed the approved graph: **no source line changed at integration.** All 22 first-run failures were in the tests (8) or in design examples that contradict canon rows Inc 8 does not change (14). Every fix is in `tests/test_b101_*.py`; no assertion was weakened (each one now pins the product's real value, often more exactly than before).

## 2. Failures met (first run of the two new files on the tree, `int-01-new-tests-first.txt`)

22 failed, 60 passed. The same 22 failed on the pre-merge commit `499d15d`, so none came from the merge. The tester ran its tests only RED on base and never GREEN against the implementation; the integration found all 22 here.

| # | Test (case) | Cause | Who was wrong | Fix |
|---|---|---|---|---|
| 1 | `test_r_crc_engine_001_1_7…` (001.1/7) | the flow has no PATCH, so canon R-FLOW-CRC.7 ends the CRC block `notices` (CRC before PATCH) | design (case says "CRC block ok") | SR-1: assert `notices`, the one exact finding, the run `completed-with-issues`, and the model bytes — `tests/test_b101_crc_model_and_reasons.py:181` |
| 2 | 9/1 | `in_place_reads` entries read as objects (`.block_index`) | test (I-6 fixes a 4-tuple) | assert the exact I-6 tuple `(2, "PatchBlock.change_doc_ref", "step.changes.json", <proj>/step.changes_1.json)` |
| 3–8 | 9/1, 9/5, 9/6, 9/8, 9/9, 9/10 | run 2's image differs from `out.s19`, so WRITE-OUT places it as `out_1.s19` (canon R-TUI-006.2); the tests read `out.s19` (run 1's image) | design (examples say "`out.s19` holds …" for a second run) | SR-2: helper `_written_image` (`tests/test_b101_flow_ext_copy.py:177`) reads the file named by the run's own WRITE-OUT summary |
| 9 | 9/5 (run 1) | as 1 (CRC before PATCH is `notices`) | design | SR-1 |
| 10 | 9/9 | `FlowChangeRecord.after_bytes` is a tuple; compared with a list | test | compare with tuples |
| 11 | 9/11 (AT, keys) | `c` pressed before the attention dwell (`CONFIRM_DWELL_S`, LLR-147.13) is ignored by design; then `terminal_out.s19` read after run 2 (SR-2) | test (harness; its RED on base was this same harness failure, not behaviour) | `_confirm_key` (`tests/test_b101_flow_ext_copy.py:580`) waits for the dwell like `test_b97_flow_execution.py` does; the image is read from the lane's `last_outputs` (the confirm re-run's outcome) |
| 12–14 | 9/12, 10/4, 10/5 | a symbol entry whose declared address differs from the A2L's is refused (CHG-SYMBOL-VALUE drift, existing); the fixture kept `0x1000` against the v2 A2L at `0x1002` | design (case fixture under-specified) | SR-3: `_symbol_doc(address)` (`:961`); the project's change document follows the v2 A2L in run 2 (declares `0x1002`); base reads the stale A2L and refuses → RED |
| 15 | 9/15 (b) | the manifest guard does not refuse a junction that points back into the project (it walks the resolved path) — true on base and tree | design (premise "the junction ref is refused") | SR-4: junction to a folder outside the project (`:814`), which the guard refuses; gap sent to E5 |
| 16 | 12/10 | as 15 | design | SR-4 (`:1249`) |
| 17–18 | 10/1, 10/2 | report cells escape the copy name (`step\.changes\_1\.json`, shipped `md_safe`, Mode A); the tests expected an unescaped `_` | test | SR-5: exact escaped text |
| 19–20 | 13/1, 13/2 | the provenance line escapes ref and copy (`md_safe`, TC-B94-30 form); expected lines were unescaped | test | SR-5: expected line built with the shipped escaper |
| 21 | 12/2, 12/3, 12/6 | the numbered copy name is stem + `_1` + last suffix (`step.chk_1.json`, `step.crc_1.json`, R-TUI-006.2), as 9/1's `step.changes_1.json` | design (graph examples 12/3, 12/6 write `step_1.crc.json`) | SR-6 (`:1066`, `:1080`, `:1152`) |
| 22 | 12/7 | the confirmations were keyed 1 and 3; the two EXT blocks are at indices 0 and 2 (run 1 paused); run 1 also lacked the bench document | test | keys 0 and 2 (`:1181`, `:1192`); the bench document written before run 1 |
| — | 11/2 | as SR-2: the folder also holds run 2's `out_1.s19` | design | SR-2: the exact set includes `out_1.s19` (`:1446`) |

(Rows 3–8 and 21 count several tests; the 22 are listed in `int-01-new-tests-first.txt`.)

## 3. Seam rulings (design silent or self-contradicting; smallest fix)

- **SR-1** — A case's "CRC block ok" in a flow with no PATCH before the CRC block reads as "the block injects"; R-FLOW-CRC.7 (canon, unchanged) makes it `notices`. Tests assert `notices` + the exact finding.
- **SR-2** — "`out.s19` holds …" for a run after the first means **the image that run's WRITE-OUT wrote** (R-TUI-006.2: a differing image takes the lowest free numbered name). R-FLOW-EXT.11's "no other new file" means no other file *from the copy*; run 2's own WRITE-OUT image is expected. Consequence: 11/2 is now RED on base too (base reads the stale document, writes the same image, and reuses `out.s19`), where the tester had it as a holds-on-base control.
- **SR-3** — A symbol-entry case that moves the symbol in the A2L also updates the change document's declared address (the operator's document follows its A2L). The drift refusal is unchanged.
- **SR-4** — "A refused ref stays refused" is tested with refs the guard does refuse: the absolute ref (a) and a junction whose target is outside the project (b, and 12/10). A junction back into the project is **not** refused by `_resolve_manifest_entry` on base or tree; on the tree such a ref then names the output file and reads the copy in place, **with** the read suffix (visible, no escape). This guard behaviour is outside the slice → E5 (§6).
- **SR-5** — Report cells and provenance lines carry the copy name through the shipped `md_safe`; records (`FlowChangeRecord.change_doc_ref`, `a2l_ref`, `ChainRunOutcome.inputs`) carry it raw. Tests assert both forms exactly.
- **SR-6** — The copy's numbered name is the R-TUI-006.2 form (`<stem>_<n><last suffix>`).

## 4. The tester's six ambiguities, resolved

1. **N-1 vs case 001.11/7(a)** — E3 round-2 ruling N-1 is binding and later than the row text; the test (`z` × 1 000 000) is right. The case row still says `a` → records correction (§6).
2. **12/9, 12/10 without rows** — ordered by rulings N-4 and N-2; both tests pass (12/10 after SR-4). Two rows to add to `02-test-cases.md` → records correction (§6).
3. **R-FLOW-EXT.12 text vs N-2(c)** — N-2 says the row's text states the placement; it does not yet. The ruling governs; `_apply_block_read_suffixes` implements it and 12/10 pins it. Row text → §6.
4. **The cause carrier** — the last `diagnostics` line, per `_record_error` and UX-C2; confirmed by the existing holds-on-base pin R-FLOW-CRC.3/1 and by all cause tests passing.
5. **Escaping in report cells** — SR-5.
6. **`EXPECTED_SCANNED_TEST_FILES`** — measured, not incremented: main reports 246, the guard on the merged tree reports **248** (TC-607 = 248; `tests/test_id_registry.py:172`).

## 5. Runs and counts

All runs: Windows (win32), interpreter `s19env`, pinned env, `s19_app.__file__` printed first (the worktree's or the detached base's), `--basetemp` under a temp folder, `LOCALAPPDATA` redirected. Transcripts (redacted) in `.dev-flow/2026-11-01-batch-101/evidence/inc-8/`.

| Run | Tree | Result | Transcript |
|---|---|---|---|
| New files, as delivered | merged tree | 22 failed, 60 passed | `int-01-new-tests-first.txt` |
| New files, as delivered | pre-merge `499d15d` (detached) | the same 22 failed, 60 passed | `int-02-new-tests-premerge.txt` |
| New files, corrected — RED on base | `origin/main` `f11b3f4` (detached, only the 2 files added) | **64 failed, 18 passed**; all behavioural except 12/8 and 13/2 (`AttributeError` on the new fields `in_place_reads` / `in_place_inputs`, structural; their behavioural clauses are pinned by 12/1 and 13/1) | `int-03-red-on-main.txt` |
| Touched modules + flow/CRC/operations/report neighbours + guards + new files, one file at a time (51 files) | merged tree | **1218 passed, 1 skipped, 0 failed** (new files: 38 + 44 passed) | `int-04-tree-touched-and-neighbours.txt` |

- **Pre-existing failures on main:** none to record — no file of the set failed on the tree, so no comparison run on `origin/main` was owed.
- **The 18 passes on base** are the design's holds-on-base controls: 001.1/3, /4, the 6 Designer catalogue checks, 001.16/4, EXT.2/1, 9/2, 9/3, 9/14, **9/15** (now a true control after SR-4), 10/3, 11/1, FLOW-CRC.3/1, FLOW-CRC.4/3. **11/2 moved from pass to RED on base** (SR-2).
- **TC-607:** `EXPECTED_SCANNED_TEST_FILES` = **248** (main 246 + the 2 new files), measured by the guard on the merged tree (`test_id_registry.py`: 12 passed).
- `02-test-cases.md`: Result cell of all 82 cases set to `verified (win32, int-04)` (the new tests and, for the covered rows R-FLOW-CRC.1/1, R-FLOW-EXT.2/3, R-FLOW-EXT.13/2, the named existing tests, all in INT-04). No other column was touched.
- No source file changed at integration. Changed: `tests/test_b101_crc_model_and_reasons.py`, `tests/test_b101_flow_ext_copy.py` (the fixes above), `tests/test_id_registry.py` (TC-607 count and its docstring line).
- Housekeeping: the merge of `origin/main` had no conflict. The redaction of one home path in `E3-r2.md` (a probe path) is folded in. The real `%LOCALAPPDATA%\s19_app` exists on this machine and was written during this session by another process (its recent-sources list names the main checkout and `prototypes/b103`); no run of this step used it (`LOCALAPPDATA` was redirected on every run).

## 6. Left for E5

**Records corrections** (the integration changed only Result cells; these are the requirements/graph session's):
1. Case 001.11/7(a): `a` × 1 000 000 → `z` × 1 000 000, oracle `"` + 63 × `z` + `…` (N-1).
2. Add rows R-FLOW-EXT.12/9 (N-4) and 12/10 (N-2) to `02-test-cases.md` (tests exist and pass); recount (the "Count" note still says 82 `not_run`).
3. R-FLOW-EXT.12 row text: state the N-2(c) placement (the suffix goes before a trailing `unresolved`).
4. SR-1: case 001.1/7 expected result → CRC block `notices` (R-FLOW-CRC.7) with the model bytes.
5. SR-2: cases 9/1, 9/5, 9/6, 9/8 (implied), 9/9, 9/10, 9/11 and graph examples 9/1, 11/1 → "the image the run's WRITE-OUT wrote" (`out_1.s19`, `terminal_out_1.s19` for a second run); case 11/2's folder set gains `out_1.s19`.
6. SR-3: cases 9/12, 10/4, 10/5 → the change document declares the v2 address in run 2.
7. SR-4: case 9/15(b) and 12/10 → a junction whose target is outside the project.
8. SR-6: graph examples 12/3, 12/6 → `step.crc_1.json`; case 12/2's copy name `step.chk_1.json`.

**Findings for the reviewers:**
- **Security (pre-existing, out of slice):** `variant_execution_service._resolve_manifest_entry` (default mode) does not refuse a junction or symlink that points back inside the project: it checks the *resolved* path for reparse points, and `resolve()` has already removed the junction. Its docstring says a path traversing a link below the project root is refused. Inc 8 does not widen it (the rebind still runs the guard first and re-checks the copy), and the read is named by the suffix. D15-18 family; for the E5 security reviewer to rule (backlog or a later increment).
- **Evidence quality (tester):** the header of `red-01-tester-base.txt` lists 9/15 among the base passes, but its body shows 9/15 failed on base (`'ok' == 'error'`, the guard premise of SR-4). 9/11's base RED was a harness failure (the dwell), not behaviour. The tests were never run GREEN on the implementation before integration. The E5 coverage audit should re-check the `full`/`partial` marks with this in mind.
- **Mutant table:** unchanged from E1/E3 (the negative controls of `01-requirements.md`); E4 adds none. The 9/15 negative control ("rebind lookup before the guard") is killed by arm (a) (the absolute ref), not by arm (b).
- **Not run here:** the full suite (batch end), the mutant table (E5, in a copy of the tree), `trace_check.py`, real captures.
