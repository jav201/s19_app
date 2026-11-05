# Inc 3 -- E5 coverage audit

Batch 2026-11-01-batch-101, increment 3. Mode: **validation** (an audit of the case records against the tests and the runs). Auditor: qa-reviewer, independent of the case author, the tester and the integrator. Tree: worktree head `6355565`. Rules applied: TCP-MAP-1, TCP-MAP-5, TCP-MAP-6, TCP-MAP-7 (`s19w/test-cases/TC-PROFILE.md`). Inputs: `02-test-cases.md` (26 cases), `01-requirements.md`, `E4-tester-notes.md`, `E4-integration-notes.md` (OR-1 to OR-5), `evidence/inc-3/int-*.txt` and `red-01-tester-base.txt`, `git diff main...HEAD -- tests`.

Execution: **I ran no test.** The only command I ran is `pytest --collect-only` over the 23 cited node ids (section 6). Every pass or fail named below was executed by the E4 integrator (Opus, transcripts `int-*`) or the E4 tester (`red-01-tester-base.txt`), and I read it from those transcripts. `lan-01-lane1.txt` (untracked, another E5 lane) was not read.

## 1. Verdict

**26/26 covered, 0 `gap`; 4 case rows need a change (15 %), plus a platform note on the Result of 18 more (22/26 = 85 % of the rows touched in all).**
- One rating goes up: R-PROJ-GATHER.12/2, partial → full.
- One Result goes down: R-PROJ-GATHER.12/3, verified → not_run. Its Windows run cannot tell the fold apart.
- Two partial reasons are rewritten: R-PROJ-GATHER.12/1 and R-PROJ-001.13/1.

The R-TST mutant evidence proves R-TST-110, R-TST-111 and R-TST-113. For R-TST-112 the equality assert has not been shown failing on the final file (section 3).

## 2. Changes to `02-test-cases.md` (for the record's owner; I did not edit it)

| Case | Column | Old → new | Reason |
|---|---|---|---|
| R-PROJ-GATHER.12/2 | Tests | partial → **full** | OR-2 checked the code: the product's only project-folder check is `in_project.is_file()` on a `Path` (`project_gather_service.py`, composition limb). The spy counts that call and passes it through, so the count of 1 is the product's own (TCP-MAP-5 (a) does not apply: no stand-in text is asserted). The inputs (empty `Q`, empty library) and the expected result (1 check, `GATHER-SOURCE-MISSING` naming `'gone.json'`) match the node exactly. |
| R-PROJ-GATHER.12/1 | Tests (partial reason) | "counter spies two seams" → "**input is not the T2 composition**: 1 000 flat top-level names `n0000.json`, not 1 000 names at the end of the 31-folder chain; the seam concern is closed by OR-2" | Stays partial. The precondition ("1 000 real files under the chain") and the R-PROJ-GATHER.12 threshold ("T2 composition") pin an input the node does not use. The once-per-name rule does not depend on depth, so the gap is small. Fix: either change the case's precondition to the flat set or seed the chain. |
| R-PROJ-GATHER.12/3 | Tests (partial reason) | add: "**the spy records `os.path.normpath` text, so 'checked on `<project>/x.json`' holds whether or not the product folded the name**; only `gathered == {}` / 0 issues discriminate, and only on POSIX" | The `calls == [expected_check]` assertion cannot see the fold on any platform. On POSIX an unfolded `missing/../x.json` fails `is_file` (ENOENT on `missing`), the empty library gives a `GATHER-SOURCE-MISSING`, and the node fails. On Windows the OS folds `..` itself. |
| R-PROJ-GATHER.12/3 | Result | verified (Windows) → **not_run** (Windows run executed by the integrator, non-discriminating by construction; LAN POSIX run owed) | The case's own note says it "passes on base by construction" on Windows. A Windows pass verifies nothing about the fold that the case names. |
| R-PROJ-001.13/1 | Tests (partial reason) | add: "the node pins `'manifest verified' in outcomes[0]` (a substring of the first writer outcome), not the exact line `Project saved + manifest verified`; `timing_bound(1.0)` loosens under `CI`" | A different pinned value (TCP-MAP-1): any first outcome line that holds `manifest verified` passes. Stays partial. Result stays not_run (section 5). |
| 18 rows (section 5, list B) | Result | `verified (Windows, …)` → `verified on Windows; LAN not_run` | The record's header sets the platform to "Windows and the LAN Linux host unless the case says otherwise". These 18 rows do not say otherwise and have no Linux run, so `verified` alone claims more than the runs show. |

Unchanged after re-check (TCP-MAP-1/5/6/7): GATHER.13/1 and /2 full (`gathered == {"patches": ["patches/x.json"]}`, no raise); ROLLBACK.9/1 and .2/1 full (exact refusal ×1, 0 unexpected, 0 verified, alive, `runs == []`, both `lexists` False); 002.12/1–/6, 002.13/1–/2 and 002.14/1–/4 full (exact line ×1, exact last line, app alive, no run; the 002.13 faults are injected preconditions, and the lines are the product's); R-TST-110/1 (rule full, sites partial); R-TST-111/1–/3, R-TST-112/1 and R-TST-113/1 full. TCP-MAP-7: every entry point the scenes call has a product caller. `_handle_save_dialog` is the `SaveProjectScreen` dismiss callback (`app.py:8367`); `load_from_path` (`:9107`, `:15309`) and `load_a2l_from_path` (`:15287`) are called by the Load router.

## 3. R-TST-110…113: does RED by mutant prove them?

The subject of these rows is the test suite, not the product. So the right negative control reverts the **test** code to base inside the head file, and an unchanged product passing on base is expected. M-5 (`max(pressed, install)`), M-6 and M-7 (clock stopped when the wait notices) are exactly the base behaviour of each clause. That is a valid RED in kind.

| Row | Proven? | Evidence and gap |
|---|---|---|
| R-TST-110 | **Yes** | M-5 RED (12.0 vs 10.0), deterministic, `red-01-tester-base.txt` (tester). The call-site half is a source check. Behaviour at the 3 sites rests on the R-TST-111 verifier: a site that started at the click would differ from the observer's install stamp by the load time. |
| R-TST-111 | **Yes, with one caveat** | M-6 RED on all 3 parameters by 0.5–0.6 s against a 1 ms tolerance (tester, pre-integration file, tolerance 0.005). The integrator's re-run on the final file is "not kept as a transcript", so the RED on `6355565` cannot be traced → E5-mutants. Caveat (common mode): the arm and the observer share `_summary_laid_out` and the same `screen_layout_refresh_signal`. The verifier proves "arm = observer", and only inspection backs "observer = the panel paint stamp definition" (E1-profile §2.2, 8/8). |
| R-TST-112 | **Not yet** | M-7: in every recorded run the arm's own 1 s bound tripped before the equality assert. That happened in the tester's default run (1.17 s) and in the integrator's final-file run (1.073 s, no transcript). The equality failed only in the tester's `CI=1` run on the pre-OR-1 file (1.119 vs 0.714 s). Owed: M-7 on `6355565` with the bound loosened (`CI=1`) so that the equality assert stops the run, and a transcript (E5-mutants). |
| R-TST-113 | **Yes** | M-8 RED (`red-01`), and a planted `timing_bound(1.5)` negative control runs inside the node on every run. Residual: the check pins the text of the third argument. It does not check that the caller still compares against the returned bound (`report_margin` never asserts, `tests/support/timing.py:72`). |

Test-file defect (no case change): the docstring of `test_r_tst_110_panel_clock_starts_at_the_install_stamp` says "at the install stamp, whichever came later: the click or the install". That is the old `max` rule. Its second assert, `(install 12.0, click 10.0) → 12.0`, holds under both rules and does not discriminate.

## 4. Requirement clauses with no case, and owed black-box ATs

Clauses with no case:
1. **R-PROJ-ROLLBACK.2 threshold:** "`<P>/patches/` does not exist **unless it existed before the save**". No case pre-seeds `patches/` and checks that the rollback keeps the folder while removing `x.json`. Proposed R-PROJ-ROLLBACK.2/2. Mutant to pair with it: a rollback that removes the pre-existing folder.
2. **R-TST-111 F4 clause** (row count at the stamp = final `rows`, 3/3 per arm): the arms assert it inside, but only case /1 states it. Add it to /2 and /3.
3. **R-PROJ-GATHER.13** "by its last part": both cases use `x.json` at the top level, where the last part equals the whole name, so the "last part" lookup is not discriminated. The threshold pins only the top level, so this is not a gap against the threshold. It is noted in case the canon row is read as a requirement for nested names.

Owed black-box ATs, through keys and dialogs (Layer B). Every product case drives a handler directly:
- **AT-a (ROLLBACK.9/.2):** `ctrl+s` → `SaveProjectScreen` → confirm into P with the junction loop present. Expect the project.json refusal painted once in the status bar and no `patches/` left. Windows.
- **AT-b (002.12/002.14):** `ctrl+l` → Load dialog → type `<outside>/other.s19` → answer the replace question (`_confirm_then_load`) with the P2 folder deleted. Expect the `Project sync NOT done …` line once, last line `Loaded other.s19`, and no `P2` path. The direct `load_from_path` call skips `_confirm_then_load` and its replace modal.
- **AT-c (002.13/2):** a typed `.a2l` through the Load dialog (the `attach` route). Expect the `A2L sync NOT done …` line.
- R-PROJ-001.13's interval is defined from the `_handle_save_dialog` call, so AT-a is evidence of the shipped surface, not of the timing bound. The panel arms already open P through the dialog (`_open_panel_through_the_dialog`).

## 5. Results owed to the Linux (LAN) runs

- **A, deterministic POSIX catches:** R-PROJ-GATHER.13/2 (self-symlink; it ran on Windows with symlinks creatable and was RED on base there too) and R-PROJ-GATHER.12/3 (the only discriminating platform).
- **B, platform matrix of the header (18 rows):** R-PROJ-GATHER.12/1, /2; R-PROJ-002.12/1–/6; R-PROJ-002.13/1–/2; R-PROJ-002.14/1–/4; R-TST-110/1, R-TST-111/1–/3, R-TST-112/1, R-TST-113/1. R-TST-110 and R-TST-113 are platform-independent by nature, but the header still asks for the run.
- **C, timing:** R-PROJ-001.13/1 needs 5/5 under 1.0 s and QC-TM ≥ 20 % (≤ 0.8 s) on the LAN host, plus 3 more Windows runs. Windows has 2 of 5: 0.694 s (`int-03`, line 89) and 0.561 s (`int-06`, line 26), both serial-lane runs by the integrator. R-TST-111/112 needs 3/3 on the LAN host. Read a red `[scene]` for which assert stopped it: it inherits the `sec6_5 load` flake (1.001 s in `int-03`, OR-4).
- **Skips on Linux, expected (not owed there):** R-PROJ-GATHER.13/1, R-PROJ-ROLLBACK.9/1 and R-PROJ-ROLLBACK.2/1 (Windows junctions, `require_junctions`).

## 6. Node ids and run traceability

- `pytest --collect-only` (s19env, Python 3.11, `PYTHONPATH=.`, isolated `LOCALAPPDATA`) on `6355565`: **23/23 cited node ids collected**, 0 errors. These are the 3 gather nodes, 2 active-variant nodes, 13 workers ids (with all 10 parameters), and 5 project-check ids (with the 3 verifier parameters).
- The Windows runs ran on "`b2b3c05` + uncommitted edits". The per-file `--stat` of the tests in each transcript (12/58/1/5/10) equals `git diff b2b3c05 6355565 -- tests`. The tree is traceable by diffstat only, with no content hash.
- `int-02` runs in `-q` mode: no per-node pass list. Each case's pass is inferred from "248 passed, 1 xfailed, 0 failed, 0 skipped" over the four files. The one xfail is `test_tc_b100_53_a_source_that_vanished_under_the_dialog…` (`test_b100_workers.py:2290`, pre-existing), not an Inc 3 node.
- No case has `gap` with a passing full test (no case is `gap`).

## 7. Evidence checklist

- [x] Mode declared: validation (top).
- [x] Every case carries a result state; executors named: E4 integrator (int-*), E4 tester (red-01); auditor ran collect-only only.
- [x] Each full/partial re-judged against the node's assertions (section 2), with file:line where it matters.
- [x] Requirement clauses without a case named (section 4).
- [x] Layer B: owed black-box ATs named per surface (section 4).
- [x] Linux-owed results listed (section 5).
- [x] Every cited node id collects (section 6).
- [x] No names, home paths, hosts, credentials or PII written.
- [ ] R-TST-112 negative control on the final tree: **open**, owed to E5-mutants.
