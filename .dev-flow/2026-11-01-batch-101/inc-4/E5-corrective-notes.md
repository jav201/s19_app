# Inc 4 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 4, branch `b101-inc4` (head `149e3bf` + this pass). Corrective agent: Opus. Input: `E5-rulings.md` (C-1 … C-8 and the Routed list), with `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md` and `E5-mutants.md`.

## 1. Verdict

**All eight rulings done; GREEN on the LAN Linux host.** No product code changed: every strengthened test passed on the Inc 4 code, so no test exposed a deviation from the design. Files changed: `tests/test_b101_symbol_reads.py` (tests only, no function renamed or deleted, no assertion weakened), `02-test-cases.md`, `E4-tester-notes.md`, `.dev-flow/BACKLOG-CODE.md`, `steps.log`, and the evidence below. Source files in this pass: 0.

## 2. Ruling → change

| Ruling | Change | Proof |
|---|---|---|
| C-1 | R-CHG-SYM.13/2 gains a third arm: `demo_patch` read with `a2l_context=None` calls `_symbol_name_index` exactly once and gives 2 R-CHG-SYM.2 findings. | Mutant M-16 (the lazy gate reverted to `symbol_index is None`, `io.py:904`): RED, "a read with no declared A2L called the index builder 2 time(s), expected exactly 1" (`e5c-mut16.txt`, restore checked by sha256). |
| C-2 | R-CHG-SYM.11/3: the overview's applied count is pinned `== 7` (the entry count of `demo_patch`); the Modifications table must hold 7 rows and no row whose Before cell is `-` (the report's rendering of a non-applied entry), so 0 entries are `blocked`. The Reports screen opens through its key `t`; Generate is clicked. The report carries no disposition column, so "0 blocked" is read from those two observables. | `e5c-01` (passed). |
| C-3 | R-CHG-SYM.12/2: the last painted line must be `Execute: scope 'all' finished - 1 variant(s), 0 error(s)` before the "no patched file" premise. | `e5c-01`. |
| C-4 | 9/4: a second confirm of row 2 with every byte changed (XOR 0x5A, length kept) must replace the document: entry 2 then holds the new bytes, same address, symbol kept, 7 entries. 11/2: scope and Execute are clicked, and the finished line must be `lines[-1]`. 13/1: all 1 000 symbols are compared with the tag spellings. | Mutant M-17 (the per-entry confirm returns without reading or replacing, `app.py:5529`): the first confirm's assertions all hold, the second fails at `replaced == …` (`(164,) != (254,)`, `e5c-mut17.txt`). |
| C-5 | `02-test-cases.md`: the 7 expected results corrected (10/3 lists the two findings; 10/4 lists the R-TUI-058.9 line and "document unchanged"; 058.9/3 lists the rejection line in both arms; 058.9/1 says "document unchanged (7 entries equal)" and cites the `[entry-json]` node too; 9/1, 9/5 and 12/2 drive labels now match the gesture drives). The Coverage column uses `covered`, and every Tests node carries `(full)` (with any precondition stand-in named). The new row R-CHG-SYM.13/3 is added and its node is no longer listed under 13/1; 13/1's inputs say "entry k at tag 220·k's address". `E4-tester-notes.md` §2 carries the `…_of_1000_entries…` names. | Records. |
| C-6 | The audit's six clauses with no asserting test: 9 alt. 4 "document replaced" (C-4); 9 alt. 5: the Check Editor collector row of the symbol entry shows that entry's address. The Check Editor keeps only address and size, so **the tag's spelling is ruled not-testable on that surface**; alternatives 1, 2, 3, 4 and 6 assert it. 10 "1 for each check document": the Check Editor arm now also picks `demo_check_fails` and pins its finding. 11 "0 blocked" (C-2); 11 "ends" (C-4); 058.9 "document unchanged" (058.9/1 compares all 7 entries). The 8 owed black-box drives are now gestures: dropdowns are clicked open and picked with the arrow keys and enter (BB-1, BB-5, BB-6); pastes go through the app's paste event after a click and `f7` (BB-2); the draft of 9/3, 9/4, 10/3, 10/4 and 058.9/1–/3 is a real paste plus a Parse paste click (BB-3, BB-4); the ledger row is chosen with a click and the arrow keys; Edit JSON, per-entry Edit JSON and both Confirms are clicked, and popup replacements are pasted (BB-4); the A2L is unloaded with key `1` and a click on the Loaded panel's A2L `[u]` (BB-4, BB-7); scope and Execute are clicked (BB-7); the report opens with `t` and Generate is clicked (BB-8). No drive is left partial. | `e5c-01`. |
| C-7 | R-CHG-SYM.13/3 takes 5 samples per run (plain, then symbolic, after one discarded warm-up), each asserted against `timing_bound(1.0)` through `report_margin`; the transcript prints every sample and the max. | `e5c-05` (quiet host, section 4). |
| C-8 | F5: the R-CHG-SYM.10/4 arm pins `lines[2:] == [PLAIN]`. F4 (the `CODE-CHANGES.md` Totals line) is left to the requirements session, as forwarded. | `e5c-01`. |

Remaining stand-ins (preconditions, not the surface under test): the image is attached through `app.load_selected_file` in the cases not marked black-box; R-CHG-SYM.13/3 plants the session A2L and calls the confirm callback directly (accepted for a measurement, audit C-12); R-CHG-SYM.12/2 removes the A2L copy the attach places in the project folder (OR-1); 11/1 and 12/1 are service-level by design.

Test-support changes in the file: `install_draft` now pastes through the UI. Its `a2l_context` argument has become an assertion that it is the session's A2L, so 058.9/3 passes `app.current_a2l_data`. The local `run()` attaches the status log to the app (`_test_status_log`) for that helper. A Select hit is checked by ancestry, because `pilot.click` reports a hit only for the exact widget under the mouse, which can be a child of the dropdown face.

## 3. Runs (LAN Linux host, `s19ci` Python 3.11)

Remote worktree: a detached worktree of `origin/main` `f9f3cb09` (no difference from `b7b77c4` under `s19_app/`, `tests/` or `tools/`), with `git diff --full-index b7b77c4` of the local worktree applied. Each transcript prints the tree fingerprint (sha256 prefix of that diff) at start and end, plus `s19_app.__file__` (the worktree). Every final run shows fingerprint `7f5b5b48049d1725`, the same as the local diff. Transcripts are redacted (`<HOME>`, `<USER>`, `<LAN-HOST>`, `<CONDA>`) and live in `.dev-flow/2026-11-01-batch-101/evidence/inc-4/`.

| Transcript | What | Result |
|---|---|---|
| `e5c-01.txt` | `tests/test_b101_symbol_reads.py`, `-n 4 -m "not serial_timing"` | 22 passed |
| `e5c-02.txt` | its serial lane (`-m serial_timing`, `-s`), host load 3.6 at start | 2 passed (kept as a record; superseded by e5c-05) |
| `e5c-03-00` … `e5c-03-11.txt` | every test file that imports `changes.io`, `change_service` or `variant_execution_service` (90 files, grep at the fingerprint; 12 chunks of 8), `-n 4 -m "not serial_timing"` | 2 737 passed, 1 failed, 97 skipped, 1 xfailed (2 836 nodes). The failure is `test_changes_file_notation_help::test_tc1802_…` (E-1, environment: an untracked, excluded prototype file; fails on base too; routed) |
| `e5c-03-aborted-3chunk.txt` | the first attempt in 3 chunks of 30 files: too slow on the shared host (another session at load 8), killed by its own 2400 s timeout. No result is drawn from it | — |
| `e5c-04.txt` | `test_id_registry`, `test_suite_hygiene`, `test_engine_unchanged`, `test_requirements_canon` (the law guards of the repo's `CLAUDE.md`: engine-frozen, canon, registry), `test_tui_patch_editor_v2`, `test_checks_engine`, `test_tui_directionb`, `test_changes_schema`; `-n 4 -m "not serial_timing"` | 379 passed |
| `e5c-05.txt` | serial lane of the new file on a quiet host (load 1.34, no other pytest) | 2 passed |
| `e5c-06.txt` | serial lane (`-m serial_timing`) over the 90 importer files plus `test_suite_hygiene`, `test_id_registry` | 53 passed, 2 skipped; QC-TM 80 bounds, 0 under 20 % margin |
| `e5c-mut16.txt`, `e5c-mut17.txt` | the C-1 and C-4 mutants, each restored and checked by sha256 (`RESTORE_OK`) | both KILLED |

Development runs during the pass (not evidence): three runs of the new file while the gesture helpers were fixed. Two Select-click helper bugs were found (the hit check), and the product was not involved.

## 4. Measured times (LAN Linux host, quiet, `e5c-05`)

| Row | Samples | Bound | Result |
|---|---|---|---|
| R-CHG-SYM.13/1: `parse_change_document`, 1 000 symbol entries × 220 040 tags | 0.173, 0.176, 0.178, 0.178, 0.181 s; index built 1× per run | 1.0 s | 5/5, margin ≥ 81.9 % |
| R-CHG-SYM.13/3: added cost of symbol resolution to the whole-document confirm, 1 000 entries × 220 040 tags | additions 0.422, 0.290, 0.021, 0.008, 0.351 s (plain 1.015–1.218 s, symbolic 1.222–1.437 s) | 1.0 s (OR-2: min(2 × 0.622, 1.0)) | 5/5, **max 0.422 s**, margin ≥ 57.8 % |

The addition is a difference of two ~1 s confirms, so the plain arm's own spread (about 0.2 s) shows up as the 0.008–0.422 s spread. The bound covers the max. The record run `e5c-02` (load 3.6) gave 0.180–0.188 s and a max addition of 0.430 s.

## 5. Counts and coverage

- Cases: **23** (22 + R-CHG-SYM.13/3). Coverage **23 covered**, 0 partial, 0 gap. One clause is ruled not-testable on one surface (the tag's spelling in the Check Editor, alternative 5), and the other five alternatives cover it.
- Nodes of the new file: 24 collected (18 functions; no function added, renamed or deleted). All 24 pass: 22 in `e5c-01` and 2 in `e5c-05`.
- Mutants: 15/15 killed at E5 (DeepSeek, `E5-mutants.md`), plus M-16 and M-17 killed here, **17/17**.
- Black-box cases (every step a gesture or dialog): R-CHG-SYM.9/1, /5, R-CHG-SYM.11/2, /3, R-CHG-SYM.12/2. The other session-read cases drive the surface under test by gestures.

## 6. Routed to `BACKLOG-CODE.md` (appended, batch-101 bullet style, CRLF)

S4-1 / E5S4-1 (link or reparse point as the project's A2L, to Inc 9 with S8-1/S8-2); E5S4-3 (O(n²) collision check, sort-and-sweep); T-02 open after Inc 4 (needs `check.py`), T-03 closed (a `Closed:` line added under the T-03 row as well); the stale `check.py:278` docstring; `tc1802` on clean clones and the b100 save waits under load. A grep before the append found none of them on the branch.

## 7. Evidence checklist

- ✓ Tests pass: `e5c-01`, `e5c-03-*`, `e5c-04`, `e5c-05`, `e5c-06`. The one failure is the routed environment failure `tc1802`.
- ✓ No secrets. Transcripts are redacted, and a grep for the account, host and LAN address over `evidence/inc-4/e5c-*` returns nothing.
- ✓ No destructive command outside the agent's own remote worktree. Remote resets and cleans touched only `~/work/s19_c4`, and that worktree is removed at the end.
- ✓ File count: 0 source files, 1 test file, records.
- ✓ No test, probe or product code ran on the Windows PC. Only git, the file edits (small editing scripts), one Python syntax parse of the test file, and the transcript redaction ran there.
