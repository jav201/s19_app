# Inc 9 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 9, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation** (an audit of marks, oracles and results; no test was run). Auditor: the QA reviewer agent, which wrote no case, no node and no run. Worktree `C:/Users/jjgh8/Github/s19_app-b101-inc9`, branch `b101-inc9`, head `b204c7d`. Inputs: `01-requirements.md` (12 active rows), `02-test-cases.md` (34 active cases), `E4-integration-notes.md` (runs int-01 … int-09, I-D1 … I-D11, the mutant table), `E4-rulings.md`, `E4-tester1-notes.md`, `E4-tester2-notes.md`, the transcripts in `../evidence/inc-9/`, `tests/test_b101_flow_saves.py` (**S**, G-T1), `tests/test_b101_flow_names_ui.py` (**U**, G-T2), the edited `tests/test_b99_staging.py`, `tests/test_b101_help_legend_docs.py`, `tests/test_id_registry.py`, the fixtures the nodes call (`tests/b97_fixtures.py`), and the product code they enter (`flow_persistence_service.py` `_create_new_json`, `save_flow_json`, `save_chain_set`; `app.py` the three handlers). `02-test-cases.md` is not edited; the marks below are this audit's proposal for it.

## 1. Verdict

**PASS-WITH-NOTES.** No HIGH or MAJOR finding among the coverage findings. Four MINOR findings, five NITs, and one finding closed during the audit (QA-5) (§6). This verdict is about coverage only. It does not rule on the Windows bypasses the security probe reports (§5, last bullet). Those belong to the security review, and they may add cases.

- **Coverage: 33 `full`, 1 `partial`, 0 `gap`.** All 35 nodes the cases name exist (cross-checked: 35 named, 35 defined, none extra). The one partial is R-FLOW-CHAIN.20/2 (QA-2). It is an oracle that the row's threshold demands and the case leaves out. Marks changed: 1 of 34 (3 %).
- **Row thresholds: 11 of 12 met on Linux.** R-FLOW-CHAIN.20 is met except one clause of its sequential arm (QA-2). R-FLOW-FILE.11 and R-FLOW-SET.7 meet their "plain home saves 1 file" control only through G-T2 nodes. The case table does not name those nodes (§4).
- **Results.** Every node was executed and passed on Linux.
  - The **G-T1 file** ran on the commit's own tree, so its 24 cases should cite **int-09**, not int-01.
  - The **10 G-T2 cases**, the 3 ATs among them, last ran on Linux on the integration tree `7e6ba8ff…` (int-07). That tree predates E4-R3. Their only run on the commit's product is the Windows run win-01 (QA-1).
- **Windows: 32 cases `verified (windows, win-01)`, 2 skipped by design.** win-01 appeared in `../evidence/inc-9/` during this audit; this audit did not run it. It ran all 36 nodes at head `b204c7d4`: `34 passed, 2 skipped`, every node named. The three I-D8 gaps:
  - The junction arms are now executed (QA-5, closed by win-01).
  - The file-link and emulation nodes passed on this account, which therefore holds the symlink privilege. They still lack the house skip for an account without it (QA-6).
  - The dangling-junction arm still has no node. The security probe's P5 measured its behaviour once (QA-7).
- **S-3's failure arms need one node** (QA-4). E3 ruled the behaviour, the census allowlists its `os.unlink`, and no node executes it.
- **Negative controls: `pending mutants`** on every row except two groups:
  - R-FLOW-FILE.11/x and R-FLOW-SET.7/x: int-06, service nodes only.
  - R-FLOW-FILE.14/6 and R-FLOW-SET.8/5: int-09.

  M14 is not an equivalent mutant (QA-3).

## 2. Evidence checks made by this audit

- **The trees are the commits.** I recomputed them with git plumbing only: a scratch index and a scratch object directory, the repository's objects as alternates, nothing written to the worktree, and no `s19_app` import. `e07fb00` + `git diff --binary e07fb00 9120d91 -- s19_app tests docs README.md` = **`7e6ba8ff…`**, the tree of int-07 (11 files). `e07fb00` + the same diff to `b204c7d` = **`d1b3f7dd…`**, the tree of int-09 (11 files). So int-09 ran this commit's product and test files byte for byte. int-01 … int-05 (`e222dd27…`) and int-07 ran the product **before** E4-R3, which added the claim's `0o666` mode argument, and without node 14/6.
- **What ran on the commit's tree (int-09):** `test_b101_flow_saves.py` (all 26 nodes), `test_b99_staging.py`, `test_address_census.py`, `test_suite_hygiene.py` and `test_id_registry.py`. The summary reads `158 passed`, with no failure, skip or deselection. **Not run on `d1b3f7dd`:** `test_b101_flow_names_ui.py`, `test_b101_help_legend_docs.py`, `test_engine_unchanged.py`, `test_docs_canon.py`, `test_b101_doc_hygiene.py`, the QC-BC set (int-02) and the importers (int-03).
- **Per-node results come from whole-file totals.** Every transcript is `-q`, with no per-node line. int-01 reads `134 passed`, int-07 `283 passed` and int-09 `158 passed`: no failure, no skip, no `deselected`. Every collected node of those files therefore passed. int-09 prints no command line, and for its negative control only `git diff --stat` (QA-1).
- **Base RED.** `red-01-tester1-base.txt` reads `20 failed, 4 passed`: the 4 passes are /14/2, /8/2 and the two loader controls. `red-01-tester2-base.txt` reads `9 failed, 1 passed`: the pass is 19/1. Both print base `e07fb00f` and an `s19_app.__file__` in the tester's worktree. The five home rows failed on base by `TypeError`. int-06 shows their behavioural failure: `DID NOT RAISE`, with each file at its link's target.
- **Executors.**
  - int-01 … int-08: the E4 integrator (Opus) on LAN Linux host 2.
  - int-09: the orchestrator's E4-R3 follow-up.
  - red-01: testers G-T1 and G-T2 (Sonnet).

  This audit executed none of them.
- **Product routes read, not run.**
  - `save_flow_json` and `save_chain_set` always call `_guarded_destination(home, workarea_root)`. With `workarea_root=None`, the guard derives the root from the textual path.
  - `_create_new_json` builds every candidate from the **unresolved** home (`home / f"{clean}.json"`). The Create spy's `taken` path and `_windows_follow`'s `candidate.parent == home` therefore compare in the same form as the product's calls, so /14/3 and /8/3 cannot pass vacuously.
  - The only product callers are the two app handlers, and both pass `workarea_root=self.workarea` (`app.py:4017`, `:4580`). The G-T1 name and claim nodes use the derived-root arm. On the fixture layout it yields the same resolved home, so the arm does not change any verdict.
  - The Builder save runs synchronously in the `push_screen` callback `_do_save` (`app.py:4013-4030`). G-T2's `target.exists` wait therefore cannot observe a claimed but still-empty file.
- **win-01** (`../evidence/inc-9/win-01.txt`; it appeared during this audit, which did not run it; the transcript does not name its executor). What it prints:
  - the Windows PC, the worktree head `b204c7d4`, and an `s19_app.__file__` in the worktree;
  - `LOCALAPPDATA` isolated, the OS clipboard unused;
  - Python 3.11.15 and `collected 36 items`;
  - one `PASSED`/`SKIPPED` line per node id, and `34 passed, 2 skipped`, the skip reason being the POSIX permission bits.

  It prints no command line and no tree hash. The worktree differs from the commit only by `steps.log` and untracked evidence files (`git status`), so the product and test files it ran are the commit's. It ran the whole two files, not only the Windows-only arms. The file-link nodes passed, so this account holds the symlink privilege.
- **Security probe** (`../evidence/inc-9/e5s-probe.txt`, source `e5s-probe.py.txt`; another E5 agent's, read only). It execs the AST-extracted source of `_create_new_json` and of the guard helpers on real Windows links, with no `s19_app` import. Its findings are the security review's to rule. §5 lists only the arms that bear on coverage.
- **trace_check** (`python -I …/dev-flow-v3-beta/trace_check.py --req …/inc-9/01-requirements.md --base e07fb00 --src s19_app`; it reads text and git only): `3 US, 12 active requirements (1 withdrawn), 1 gap`. The gap is `EVID` (no `04-validation.md`), which is expected before the validation record.

## 3. Per case

S = `tests/test_b101_flow_saves.py`, U = `tests/test_b101_flow_names_ui.py`; node names drop the `test_r_` prefix. "Std guard" means the node passes on base. Windows states are in §5.

| # | Case | Node | Stimulus route ok | Oracle exact | Evidence | Verdict |
|---|---|---|---|---|---|---|
| 1 | R-FLOW-CHAIN.19/1 | U `flow_chain_19_1_confirm_writes_one_lane_report` | yes: Import… (buttons), mode switch by `enter`, Run, `#fx_confirm_1` pressed once visible and enabled. The wait is on the action's own sign: report count + 1, `re-run` in the run log, Run enabled | yes: exactly 1 new report, the line `- **Chains:** 1`, ledger `== ["flash_chain"]` | int-01, int-07 (`7e6ba8ff`); std guard on base; M3 pending | full · verified (linux, int-07); commit tree on Windows only (win-01) (QA-1) |
| 2 | R-FLOW-CHAIN.20/1 | U `flow_chain_20_1_parallel_confirm_mode_line` | yes, as #1 | yes: `confirm re-run` line present, 0 `sequential` lines, the Run's report `parallel` | int-01, int-07; base RED (`sequential`) | full · as #1 |
| 3 Δ | R-FLOW-CHAIN.20/2 | U `flow_chain_20_2_sequential_confirm_mode_line` | yes, as #1 (default `sequential`) | matches the case, which is short of the row: the threshold's "0 lines `- **Mode:** sequential`" in this arm's confirm report is asserted by neither the case nor the node | int-01, int-07; base RED | full → **partial** (QA-2) |
| 4 | R-FLOW-FILE.12/1 | U `flow_file_12_1_save_after_clear_holds_own_name` | yes: Load… picker, `#flow_clear`, palette chip + `#flow_ref` + Add, Save… dialog (name by value), Save. The wait is on the file | yes: `"name" == "tune_b"` | int-01, int-07; base RED (`patch_chain`) | full · as #1 |
| 5 | R-FLOW-FILE.12/2 | S `flow_file_12_2_clash_file_holds_its_stem` | yes: service call as the Input names it | yes | int-01, int-07, **int-09**; base RED | full · verified (linux, int-09) |
| 6 | R-FLOW-FILE.12/3 | S `flow_file_12_3_cleaned_name_is_written` | yes | yes (path and name) | int-09; base RED | full · int-09 |
| 7 | R-FLOW-FILE.12/4 | S `flow_file_12_4_stem_of_64_is_whole` | yes | yes (+ 0 load findings) | int-09; base RED | full · int-09 |
| 8 | R-FLOW-FILE.12/5 | U `flow_file_12_5_lane_report_reads_the_saved_name` | yes: Load…, Save…, Import…, Run (`run_lanes` waits for the run record and Run enabled), then the new flow report | yes: name, exactly 1 flow report, first line `== # Flow report — rep\_b` | int-01, int-07; base RED at the name (the title is shown RED by AT-I9-2) | full · as #1 |
| 9 | R-FLOW-FILE.13/1 | S `flow_file_13_1_long_stem_is_cut_to_64` (+ `…_control_whole_65_name_is_refused_by_loader`) | yes | yes. The control proves the 0-findings clause can fail (std guard) | int-09; base RED | full · int-09 |
| 10 | R-FLOW-FILE.13/2 | S `flow_file_13_2_clash_suffix_is_cut` | yes | yes | int-09; base RED | full · int-09 |
| 11 | R-FLOW-SET.9/1 | S `flow_set_9_1_cleaned_name_is_written` | yes | yes (+ `loaded.name`) | int-09; base RED | full · int-09 |
| 12 | R-FLOW-SET.9/2 | S `flow_set_9_2_clash_file_holds_its_stem` | yes | yes | int-09; base RED | full · int-09 |
| 13 | R-FLOW-SET.10/1 | S `flow_set_10_1_long_stem_is_cut_to_64` (+ control) | yes | yes | int-09; base RED | full · int-09 |
| 14 | R-FLOW-FILE.11/1 | S `flow_file_11_1_home_linked_outside_saves_nothing` | yes: `workarea_root=R`, the app's form; `make_junction` | yes: raises; `O/flows` empty | int-09; base RED (`TypeError`), behavioural RED in int-06 | full · int-09 |
| 15 | R-FLOW-FILE.11/2 | S `flow_file_11_2_home_linked_inside_saves_nothing` | yes | yes | int-09; int-06 | full · int-09 |
| 16 | R-FLOW-FILE.11/3 | S `flow_file_11_3_linked_project_folder_saves_nothing` | yes. The link is `R/pl` → `R/q`, not `R/p`, because the fixture's `p` is real; same shape | yes: raises; no `R/q/flows`; `R/q` unchanged | int-09; int-06 | full · int-09 |
| 17 | R-FLOW-SET.7/1 | S `flow_set_7_1_home_linked_outside_saves_nothing` | yes | yes | int-09; int-06 | full · int-09 |
| 18 | R-FLOW-SET.7/2 | S `flow_set_7_2_home_linked_inside_saves_nothing` | yes | yes | int-09; int-06 | full · int-09 |
| 19 | R-FLOW-FILE.14/1 | S `flow_file_14_1_dangling_link_gets_no_file` | yes (derived-root guard arm, §2) | yes. "The link unchanged" is read as `is_symlink()` (NIT, QA-8) | int-09; base RED (target created). M10 may leave it GREEN on Linux | full · int-09 |
| 20 | R-FLOW-FILE.14/2 | S `flow_file_14_2_link_to_file_is_not_written` | yes | yes for the case's two clauses. Not asserted: the link kept, the parent `flows/` (QA-8) | int-09; std guard; no isolating mutant on Linux (QA-9) | full · int-09 |
| 21 | R-FLOW-FILE.14/3 | S `flow_file_14_3_no_create_on_a_taken_name` | yes: Create spy; the path forms match (§2) | yes: 0 calls on `z.json`, exactly 1 on the returned path | int-09; base RED; M10 pending | full · int-09 |
| 22 | R-FLOW-FILE.14/4 | S `flow_file_14_4_followed_create_gets_no_byte` | yes: emulated Windows follow | yes: raises; `followed.json == b""`; the link kept; `flows/ == ["z.json"]` | int-09; base RED; M11 pending | full · int-09 |
| 23 | R-FLOW-FILE.14/5 | S `flow_file_14_5_swapped_home_gets_no_byte` | yes: home swap at the first `os.open` | yes: raises; at most an empty `O/z.json`; nothing else in O | int-09 (I-D7 docstring included); base RED; M11–M13 pending | full · int-09 |
| 24 | R-FLOW-FILE.14/6 | S `flow_file_14_6_saved_file_mode_matches_write_text[flow]` | yes | yes. Mode equal to a `write_text` sibling and no execute bit; robust to the host umask | int-09 + negative control RED (int-09 run 2) | full · int-09 |
| 25 | R-FLOW-SET.8/1 | S `flow_set_8_1_dangling_link_gets_no_file` | yes | yes for the case. The row's "link unchanged" is not asserted (QA-8) | int-09; base RED | full · int-09 |
| 26 | R-FLOW-SET.8/2 | S `flow_set_8_2_link_to_file_is_not_written` | yes | as #20 | int-09; std guard | full · int-09 |
| 27 | R-FLOW-SET.8/3 | S `flow_set_8_3_no_create_on_a_taken_name` | yes | yes | int-09; base RED; M10 pending | full · int-09 |
| 28 | R-FLOW-SET.8/4 | S `flow_set_8_4_followed_create_gets_no_byte` | yes | yes | int-09; base RED; M11 pending | full · int-09 |
| 29 | R-FLOW-SET.8/5 | S `flow_file_14_6_…[set]` | yes | yes | int-09 + negative control RED | full · int-09 (the node name traces to R-FLOW-FILE.14 only; NIT, QA-10) |
| 30 | R-FB-SAVE.8/1 | U `fb_save_8_1_refused_home_status` | yes: Save… dialog, Save. The wait is on the exact text in the status log | yes: painted `#log_line_4` `==` the text; `O/flows` empty; no `saved flows/` | int-01, int-07; base RED | full · as #1 |
| 31 | R-FX-SET.15/1 | U `fx_set_15_1_refused_home_status` | yes: `#fx_set_name` by value, Save Set | yes (+ ribbon still `unsaved`) | int-01, int-07; base RED | full · as #1 |
| 32 | AT-I9-1 | U `at_i9_1_confirm_report_says_confirm_rerun` | yes: keys (`enter`/`down`/`tab`/`enter` per import, `enter`, `enter`, `c` after the panel's own dwell). The focus is placed by `.focus()` and the screen by `action_show_screen`; both are preconditions the Input does not name as keys | yes: 2 new reports, `parallel` + `Chains: 3`, `confirm re-run` + `Chains: 1` + ledger `flash_chain`, none `sequential` | int-01, int-07; base RED | full · as #1 |
| 33 | AT-I9-2 | U `at_i9_2_resaved_flow_and_long_set_keep_own_names` | yes: dialogs and buttons. The names are set by value (I-D6: `#fx_set_name` has no `max_length`). "Pick the saved set" is the app's own prefill, waited as `select.value == set_name` | yes on every clause. `lanes == ["rep_b"]` already holds before Load Set; the `1 chain(s) restored` notice carries that clause (QA-8) | int-01, int-07; base RED on 4 clauses | full · as #1 |
| 34 | AT-I9-3 | U `at_i9_3_linked_homes_refuse_saves` | yes: both dialogs, Save and Save Set | yes: both texts exact, both outside folders empty | int-01, int-07; base RED | full · as #1 |

## 4. Per row: thresholds (Linux)

| Row | Threshold | Cases | Met | Note |
|---|---|---|---|---|
| R-FLOW-CHAIN.19 | 1/1 | 19/1, AT-I9-1 | yes | |
| R-FLOW-CHAIN.20 | 2/2 + 1/1 | 20/1, 20/2, AT-I9-1 | **no, one clause short** | The sequential arm's "0 lines `- **Mode:** sequential`" is unasserted. In that arm the base value and the dispatch value are the same word (QA-2) |
| R-FLOW-FILE.12 | 5/5 | 12/1 … 12/5, AT-I9-2 | yes | |
| R-FLOW-FILE.13 | 2/2 | 13/1, 13/2 | yes | |
| R-FLOW-SET.9 | 2/2 | 9/1, 9/2; consumed by AT-I9-2 | yes | |
| R-FLOW-SET.10 | 1/1 | 10/1, AT-I9-2 | yes | |
| R-FLOW-FILE.11 | 3/3 + control | 11/1 … 11/3, AT-I9-3 | yes | The control "a plain `flows/` saves 1 file" through the guard with `workarea_root` is carried by 12/1, 12/5 and AT-I9-2 (the app passes `self.workarea`). No case names them as the control (QA-10) |
| R-FLOW-SET.7 | 2/2 + control | 7/1, 7/2, AT-I9-3 | yes | The control is carried by AT-I9-2's Save Set |
| R-FLOW-FILE.14 | 4/4 | /1 … /4 (+ /5, /6) | yes | The link clauses of the check after the claim are never isolated (QA-3). The failure arms have no node (QA-4) |
| R-FLOW-SET.8 | 4/4 | /1 … /4 (+ /5) | yes | No set analogue of /14/5. The helper is shared, and the set's `resolved_home` comes from its own guard call (read). Acceptable |
| R-FB-SAVE.8 | 1/1 | FB-SAVE.8/1, AT-I9-3 | yes | |
| R-FX-SET.15 | 1/1 | FX-SET.15/1, AT-I9-3 | yes | |

## 5. Gaps the integration notes list: rulings

- **S-3: render-before-claim and the write-failure arm (plus R2-2's `lstat`-failure arm, which the notes do not list). Needs a node (QA-4).** E3 accepted S-3 as a design obligation (`E3-rulings.md` S-3), and the code carries it in `_create_new_json` steps (b) and (e). These are the paths that run the census-allowlisted `os.unlink`. TC-B99-13's third stated fact, "unlinks only its own same-stat claim on a failure path", has no executing node. The 0-byte file under a claimed name is a defect class that E3 S-3 calls new with this claim-then-write design: it shows in the Load list and loads as `FLOW-JSON-PARSE`. All three arms run on Linux with monkeypatch. Not acceptable as "no row": E4-R3 already set the precedent of filing a property of the claim under the claim rows.
- **I-D8 (a): the folder-link nodes run on Windows with junctions. No node is needed; the run was owed and win-01 executed it (QA-5, closed).** The eight nodes are R-FLOW-FILE.11/1–/3, R-FLOW-SET.7/1–/2, R-FB-SAVE.8/1, R-FX-SET.15/1 and AT-I9-3. They create links only through `make_junction`, which on Windows is `_winapi.CreateJunction` and needs no privilege. The guard refuses them through `_is_reparse_point`'s reparse-attribute branch, not `is_symlink`. All eight `PASSED` in win-01, each named by node id. The security probe's P7 and P8 show the same guard refusal on junctions.
- **I-D8 (b): the file-link nodes need the symlink privilege. Acceptable on this PC; the house skip is still owed for any other Windows account (QA-6).** The nine nodes (/14/1–/14/5, /8/1–/8/4) passed in win-01, so this account holds the privilege. On an account without it they would not "error". They would **fail**:
  - In /14/1–/14/3 and /8/1–/8/3, `os.symlink` raises in the test body.
  - In /14/4, /8/4 and /14/5, it raises inside the patched `os.open`, that is, inside the product's own call, and reads as a product failure.
- **I-D8 (c): the dangling-junction arm has no node. Its behaviour is measured; a node is optional (QA-7).** The security probe's P5 (a dangling junction at `z.json` before the save) gives `z_2.json`, with the junction kept. That measures the arm on Windows from the extracted source text, but it is not a regression node. Since /14/1 and /8/1 ran on Windows with real file links (win-01), the two cases do have a Windows arm. The junction node stays the only privilege-free one. The base was not measured, so no base RED is claimed for it.
- **Probe arms that may add cases (not ruled here; security review).**
  - P3 (the home swapped out before the create, and back before the check) and P4 (the real S-F1 follow, then a hard link put at the name) each end with the flow's content outside the work area (`outside/z.json`, `outside/t.json`, 44 B), and the save returns a path.
  - P9 and P10 test the cleanup `os.unlink` after the home is re-pointed. In P10 the probe ended in its own `rmdir` error.

  No node of this catalogue drives a swap back, a hard link or a re-point before the cleanup: every link case uses a symbolic link or a junction, and no node reads `st_nlink`. `E5-security.md` (it landed during this audit) rules these as **SE5-1** (P3, P4) and **SE5-2** (P9), both LOW `design-gap`, and gives each fix its own node. If those fixes are folded into Inc 9, each owes a case under R-FLOW-FILE.14 / R-FLOW-SET.8:
  - P3's double swap, as an `os.open` / `os.lstat` wrapper;
  - P4's hard link, the `st_nlink == 1` clause;
  - P9's re-point before the cleanup.

  Each case needs its mutant expected RED. If the fixes go to the backlog, the backlog row carries the cases. SE5-3 also records that a junction at the free name is never followed on Windows (P1), which lowers QA-7's stake.

## 6. Findings

| Id | Severity | Finding | Fix |
|---|---|---|---|
| QA-1 | MINOR | **Results cite a tree that is not the commit's.** Every Result cell cites int-01 (`e222dd27`). The commit's tree is `d1b3f7dd` (recomputed, §2). The G-T1 file ran on it in int-09. On Linux, the 10 G-T2 cases, `test_b101_help_legend_docs.py` and the law guards `test_engine_unchanged`, `test_docs_canon` and `test_b101_doc_hygiene` did not run on it. Their last Linux run (int-07, `7e6ba8ff`) lacks E4-R3's mode argument in `_create_new_json`, which every G-T2 save goes through. The G-T2 nodes did pass on the commit's product on Windows (win-01). Also, int-09 prints no command line, and for its negative control only `git diff --stat`; win-01 prints no command line and no tree | Re-cite the 24 G-T1 cases to int-09, and the G-T2 cases to `int-07; win-01 (commit, windows)`. In E5's own gate run (which the stage owes), run the 4 int-01 files and the 7 law guards on `d1b3f7dd` on the Linux host. Print `CMD:` and the tree, then re-cite. Re-record int-09 with its two commands and the mutation's diff body. Add the command to win-01. Executor: the orchestrator |
| QA-2 | MINOR | **R-FLOW-CHAIN.20/2 is short of its row.** The threshold reads "the confirm's report in a parallel set **and in a sequential set** each hold `- **Mode:** confirm re-run` and 0 lines `- **Mode:** sequential`". The case Expected and the node assert only the positive line for the sequential arm, the one arm where the defect's value and the dispatch value are the same word | Add `assert "- **Mode:** sequential" not in new[0].splitlines()` to `test_r_flow_chain_20_2_…`, and that clause to the case's Expected. Show it GREEN on the tree and RED on base. Mark → `full` |
| QA-3 | MINOR | **M14 is not an equivalent mutant.** Every link target in the catalogue lies outside the home, so the real-parent clause of step (d) masks its link clauses (`S_ISREG`/`samestat`, the reparse test) on every case. A save that wrote through a link at the free name into a sibling **inside** the home would break R-FLOW-FILE.14 / R-FLOW-SET.8 ("no byte through that link"), and no node would go RED | Add cases R-FLOW-FILE.14/7 and R-FLOW-SET.8/6 (one node, `[flow, set]`). Use `_windows_follow` with its target at a missing `flows/other.json` (`flowsets/other.json`) inside the home. Assert a raise, `other.json` holding 0 bytes, the link kept, and no other new entry. Add mutant **M14b** (`owned := True` and the reparse clause dropped), expected RED on both. Record M14 alone as "survives: `samestat` has no isolating row", not "equivalent" |
| QA-4 | MINOR | **S-3 and R2-2's failure arms have no node** (§5). The arms: a serialiser raise before the claim, a write `OSError` after the check, and an `lstat` failure inside the check | One parametrised S node, `[flow, set] × [render raises, write OSError, lstat OSError]`, filed as cases under R-FLOW-FILE.14 / R-FLOW-SET.8 (as E4-R3 did). Monkeypatch `json.dumps`, the handle `os.fdopen` returns, and `os.lstat` on its first call after the claim. Not before the claim: `os.path.lexists` calls `os.lstat` and would read the error as a free name. Expected: (render) 0 `os.open` calls and the home with no new entry; (write) the error re-raised and the claimed file gone; (lstat) `WorkareaContainmentError` and the claim gone. Add mutants: render moved after the claim; the unlink dropped from (e) |
| QA-5 | MINOR → **closed** | **The Windows junction arms were owed a run** (§5, I-D8 a). win-01 executed all 8 (`PASSED`, named by node id) at head `b204c7d4` | Cite `windows: verified (win-01)` on the 8 junction rows, and on the other 24 rows that passed there. Name win-01's executor in the record. 14/6 and 8/5: `windows: skipped by design (win-01)` |
| QA-6 | NIT | **Without the privilege, 9 file-link and emulation nodes would fail instead of skipping** (§5, I-D8 b). They passed on this PC (win-01). On an account without the privilege, the `OSError` would surface in 3 of them from inside the product's `os.open` call. This breaks the house pattern (Inc 6 I-D5; `test_b101_document_homes.py:131-136`) | Before any link or monkeypatch: probe `os.symlink` once in `tmp_path`. On `OSError`, call `pytest.skip("a file symbolic link needs a privilege this platform does not grant here")`. Correct I-D8's "error" to "fail" |
| QA-7 | NIT | **The dangling-junction Windows arm of /14/1 and /8/1 has no node** (§5, I-D8 c). Its behaviour is measured once by the security probe's P5, from extracted source and not as a test node. /14/1 and /8/1 ran on Windows with real file links (win-01). The Windows create does not follow a junction (P1, SE5-3) | Optional regression node: Windows-only, `[flow, set]`, skipping elsewhere with a named reason (`tests/support/b100_links.require_junctions`). Steps: `make_junction(flows/z.json, O/dangling)`, then remove `O/dangling`, then save `z`. Assert: `O/dangling` not created, `z.json` still a junction, a plain `z_<N>.json` returned, and 0 Create-spy calls on `z.json`. No base RED is claimed until base is measured (E3A-08). Otherwise, strike the arm from the fixtures note and cite P5 |
| QA-8 | NIT | **Oracle relaxations, kept `full`.** No plausible defect passes them: the code always returns `home / candidate`, and a removed link would yield `z.json`, not `z_…`. The relaxations: /14/1 reads "the link unchanged" as `is_symlink()`; /14/2, /8/1 and /8/2 do not assert the link at all, and /14/2 and /8/2 not the parent folder; `z_<N>.json` is `startswith("z_")`; AT-I9-2's `lanes == ["rep_b"]` already holds before Load Set | When the files are next touched: `os.readlink(link) == target`; `re.fullmatch(r"z_\d+\.json", saved.name)` and `saved.parent == home`; in AT-I9-2, remove the lane before Load Set or compare the lane widgets' identity |
| QA-9 | NIT | **Mutant coverage.** No row has a full E5 mutant run yet. int-06 ran M8 and M9 together on the 5 service nodes only; the UI nodes the table lists for M8 and M9 (`fb_save_8_1`, `fx_set_15_1`, `at_i9_3`) were not in it. /14/1, /14/2, /8/1 and /8/2 have no isolating mutant on Linux, because `lexists` and `O_EXCL` both defend them; their only failing evidence is base RED, and /14/2 and /8/2 have not even that. /14/3 and /8/3 do isolate `lexists` | `E5-mutants.md`: run M8 and M9 one at a time with the U nodes they name. Add M14b (QA-3) and the QA-4 mutants. Record /14/2 and /8/2 as double-defended standing guards |
| QA-10 | NIT | **Record hygiene in `02-test-cases.md`:** <ul><li>The footer counts 32 cases; there are 34 after E4-R3.</li><li>The footer says Windows is `not_run` everywhere, while /14/6 and /8/5 read "skipped by design".</li><li>R-FLOW-SET.8/5's node name traces to R-FLOW-FILE.14 only.</li><li>The R-FLOW-FILE.11 / R-FLOW-SET.7 controls are not named.</li><li>The Result cells name no executor.</li></ul> | Correct the footer counts. Name the controls (12/1 and 12/5 for the flows home, AT-I9-2 for the sets home). Optionally rename the parametrised node, or add an `id` naming `R-FLOW-SET.8/5`. Name the executor of each cited run (§2) |

## 7. Not run by this audit

No test was run, and nothing that imports `s19_app` ran on the Windows PC. The only commands were:

- file reads and greps;
- git plumbing in a scratch index and object directory (the tree recomputation, §2);
- `trace_check.py` under `python -I`, which reads text and git only.

The results above are:

- the E4 runs on LAN Linux host 2 (int-01 … int-09);
- the testers' base runs (red-01);
- win-01 and the security probe, both of which appeared during this audit and were not executed by it.

**Scratch incident.** I did the git plumbing in the session scratch folder `…/scratchpad/i9e5` and then removed that folder with `rm -rf`. The same folder also held the security probe's script (`i9e5_probe.py`) and its run folders. The script's source and output survive as `../evidence/inc-9/e5s-probe.py.txt` and `e5s-probe.txt`; the run folders do not. If the security review needs to re-run the probe, it must rebuild the folder from `e5s-probe.py.txt`.

## 8. Totals

| | Before | After |
|---|---|---|
| Active cases | 34 (footer says 32) | 34 |
| Coverage `full` / `partial` / `gap` | 34 / 0 / 0 | 33 / 1 / 0 |
| Marks changed | — | 1 (3 %) |
| Row thresholds met (Linux) | 12 claimed | 11 of 12 (R-FLOW-CHAIN.20 one clause short) |
| Result `verified` (linux) | 34, all citing int-01 | 34. G-T1: 24 citing int-09 (commit tree). G-T2: 10 citing int-07; not run on the commit tree on Linux (QA-1) |
| Windows | `not_run` 32, skipped by design 2 | `verified (win-01)` 32, skipped by design 2 (QA-5 closed). 9 nodes lack the privilege skip (QA-6); 1 arm has no node, measured by probe P5 (QA-7) |
| Negative controls | — | Pending on all rows except 11/x and 7/x (int-06) and 14/6 and 8/5 (int-09) |
| Cases or nodes to add | — | QA-3: 2 cases / 1 node; QA-4: 1 node (6 arms); QA-7: optional, 1 node (2 arms). Probe P3 and P4: pending the security review |
