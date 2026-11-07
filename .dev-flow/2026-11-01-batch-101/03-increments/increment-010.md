# Increment 010 — Inc 10a · R-TUI-018.1…4, R-TUI-040.4/.8/.11/.12, R-TUI-007.3/.5/.8/.9, R-WS-LOADED.13/.14/.16/.18…20, R-TUI-012L.8, R-SHELL-STATUS.7, R-SHELL-FOCUS.2…5, R-SEG-OPEN.1/.6/.7 · A jump shows its target near the top; the status line describes what is loaded; the keys reach the window I see

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-10/`: `01-requirements.md` (US-HEXNAV-1, US-UNLOAD-1, US-FOCUS-2; 27 active rows), `02-test-cases.md` (92 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E4-impl-notes-app.md`, `E4-impl-notes-split.md`, `E4-impl-notes-render.md`, `E4-tester-f-notes.md`, `E4-tester-h-notes.md`, `E4-integration-notes.md`, `E4-rulings.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc10.md`, the pilot under `evidence-e1/` and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-10/`. Branch `b101-inc10` from `main` (base `09b4808`), head `079696d4` plus the uncommitted E5 records, this packet and `04-validation.md`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1–E3 (requirements, rulings, both code-free design reviews, the E3 correction and the Inc 12 D-2 addendum), the three E4 integration steps, the E5 code and security reviews, the coverage audit (as the `qa-reviewer`), the E5 corrective, and the E5 re-review; **DeepSeek v4 Pro** — the E3 correction round 2, the E4 implementers (3 units: G1 `app.py`, G2 `segment_split_view.py`, G3 `render/hexview.py`), the E5 mutant battery (M1…M38), and this record; **Sonnet** — the E4 testers ×2 (H `hex_jump`, F `unload_focus`) and the E5 rr-fixes pass.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `010` |
| Lane (if the batch forked) | none — single lane (10a of the E3 split; 10b is `../inc-10b/`, a later increment, its records not part of this packet) |
| Requirement(s) | R-TUI-018.1, .2, .3, .4 · R-TUI-040.4, .8, .11, .12 · R-TUI-007.3, .5, .8, .9 · R-WS-LOADED.13, .14, .16, .18, .19, .20 · R-TUI-012L.8 · R-SHELL-STATUS.7 · R-SHELL-FOCUS.2, .3, .4, .5 · R-SEG-OPEN.1, .6, .7 (stories US-HEXNAV-1, US-UNLOAD-1, US-FOCUS-2) |
| Acceptance | the 92 cases of `02-test-cases.md`; black-box through the shipped controls (the go-to / search boxes, section / Memory-Map / MAC-record / tag-find jumps, the rail keys, the Loaded panel `[u]` / `U`, the Save / Load dialogs, the Split / Join palette) · unit: the changed units of `E1-slice.md` §1 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-07 |

---

## 1 · What changed

A hex jump (a go-to, search hit, section, A2L tag find, MAC record or Memory Map cell) now shows the target row as the second hex row — or the first, when the target is the first view row — with the pane scrolled to its top-left; MAC rows added outside the image (R-TUI-004.3) count in the view rows and in the pages; an A2L or MAC jump to an absent target snaps to the next present row. A failed go-to re-renders keeping the window and removes the `> ` marker (also on an empty box or an invalid address); paging, a new search, a new target and a load clear the marker; a load shows the first hex page. An unload paints `Unloaded primary image.` / `Unloaded MAC.` / `Unloaded A2L.` / `Unloaded all artifacts.` as the file status (and `Nothing to unload.` when nothing is loaded), drops the unloaded image's diagnostics, scrubs Cc / Cf / Zl / Zp from every painted file name (the load line clips names at 120 characters, ending `…`), and `_plan_project_save` drops the open project's top-level S19 / HEX files on a save as when no image is loaded — so a saved project never writes the unloaded image back — while the load question names the MAC. After a rail key, a window switch or an unload the focus lands on the shown window's focus target (the A2L `?` chip, the MAC Page Prev button) once the window is laid out, a hidden Split / Join window runs none of its keys and exports nothing, and the deferred load steps do nothing once the app is exiting. `segment_split_view.py` changes its module guards only; `render/hexview.py` extracts the row list.

## 2 · Files modified

Committed: `git diff --stat 09b4808 HEAD -- s19_app tests docs README.md` (10 files, +3 791 / −123). Uncommitted: the E5 record edits, this packet and `04-validation.md`. **SOURCE files: 3 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | US-HEXNAV-1 · US-UNLOAD-1 · US-FOCUS-2 | `update_hex_view` / `update_alt_hex_view` / `update_mac_hex_view` start the window one view row above the target (min 0) with one `[0, len(rows)−1]` clamp and `scroll_home`; `action_hex_page_next` pages in view rows; `_handle_goto` / `_handle_goto_alt` / `_handle_goto_mac` clear the marker and keep the window on a failure (one `_clear_goto_marker_keeping_window` helper, `bisect` once); `_hex_view_rows` (memoised, declared and reset per CR-1); `_row_start_for_near_top_focus` snaps on present rows; `_unload_primary` rebuilds a MAC-only spine; `_apply_unload` writes the unload status and schedules a stamped landing; `set_file_status` scrubs Cc / Cf / Zl / Zp; `_format_coexistence_status` paints names and clips at 120; `action_show_screen` + `_land_focus` + `_rehome_placeholder_focus_after_load` + `_note_focus_landing` + `_fallback_focus_target` (the landing, `_SWITCH_LANDING_TARGETS`); `_apply_prepared_load` resets the window on an image install and guards the four deferred steps with `_load_tree_gone`; `_plan_project_save` drops top-level S19 / HEX on a save as with no image; `_reset_project_session` resets the view-row memo |
| `s19_app/tui/segment_split_view.py` | source | US-FOCUS-2 | `refresh_window` focuses `#sje_table` only while shown; `check_action` (new) refuses while hidden (docstring names the two inputs it does not refuse); `action_export` returns while hidden |
| `s19_app/render/hexview.py` | source | US-HEXNAV-1 | `hex_row_bases` (new) extracts the row list; `_collect_hex_rows` uses it (output unchanged) |
| `tests/test_b101_hex_jump.py` | test | US-HEXNAV-1 | new file, H: 45 nodes + the 80 × 24 main arm skipped by name — the jump / marker / paging cases |
| `tests/test_b101_unload_focus.py` | test | US-UNLOAD-1 · US-FOCUS-2 | new file, F: 57 nodes — the unload status, save-as, focus landing and hidden-window cases |
| `tests/test_b100_focus.py` | test | US-FOCUS-2 | the 10 I-D14 nodes kept, the E4-R3 re-home node added (HLR-166) |
| `tests/test_b100_session_reset.py` | test | US-HEXNAV-1 · US-FOCUS-2 | `_SESSION_SNAPSHOT_NAMES` census: `_hex_view_rows_cache`, `_focus_landing_fallback` re-frozen |
| `tests/test_b97_flow_execution.py` | test | US-FOCUS-2 | TC-B97-64 named supersession: `]` lands on `fx_panel`; `c` still confirms 1 |
| `tests/test_id_registry.py` | test | US-HEXNAV-1 · US-UNLOAD-1 · US-FOCUS-2 | `EXPECTED_SCANNED_TEST_FILES` 270 → 272 (the two new test modules, measured) |
| `tests/test_tui_commandbar.py` | test | US-FOCUS-2 | TC-008: the sweep waits for the landing, then `/` keeps or moves the focus per screen |
| `tests/test_b101_inplace_views.py` | test | US-FRESH-3 | Inc 10b file (its packet `increment-010b.md` is outside V59's `increment-\d+.md` packet read): new file, 21 non-serial nodes + the QC-TM-10b-1 `serial_timing` node — the value/table/hex/preview/disarm, repaint sign, R-A2L-048/4 and /5, RR-1/RR-4 cases |
| `.dev-flow/2026-11-01-batch-101/inc-10/*.md` | doc |  | the E1–E5 records, the codewire graph, `04-validation.md` and `steps.log` (uncommitted records listed here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-10/*.txt` | generated | US-HEXNAV-1 · US-UNLOAD-1 · US-FOCUS-2 | 144 transcripts and probes (int-01 … int-23, e5c-01 … e5c-16, e5c-rr-01 … e5c-rr-05, e5s-probe, mut-01 … mut-38, mut-c-01 … mut-c-23, red-01 ×2) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 7 (2 new, 5 changed; uncapped) |
| Doc files | 0 product docs + the `.dev-flow` records (outside the count) |
| Generated | 146 (144 committed transcripts / probes under `evidence/inc-10/` + the pilot script and transcript under `inc-10/evidence-e1/`) |

- ⚠ **At 3 source files:** `app.py` owns the jump / landing / unload / status logic; `segment_split_view.py` owns the hidden-window guards; `hexview.py` owns the row-list extraction. The E5 corrective and the re-review changed the same `app.py` and `segment_split_view.py` sites only.

## 3 · How to test

```bash
# the two new files and the edited nodes (LAN Linux laptop, Python 3.11)
python -m pytest -q -n 6 --dist load -m "not serial_timing" -rA tests/test_b101_hex_jump.py tests/test_b101_unload_focus.py \
  tests/test_b97_flow_execution.py tests/test_b100_focus.py tests/test_b100_session_reset.py tests/test_tui_commandbar.py \
  tests/test_tui_goto_marker.py tests/test_tui_app.py::test_hex_page_actions_only_work_in_main_view
# the law guards
python -m pytest -q -n 6 --dist load tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py
# the serial-timing lane over the touched files
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_hex_jump.py tests/test_b101_unload_focus.py
# the HLR-177c quit nodes, serial, three times
python -m pytest -q -m serial_timing -p no:xdist tests/test_b100_workers.py -k "confirmed_quit"
```

All of these ran on the LAN Linux laptop only (operator rule); the Windows PC ran only the security probe (`e5s-probe`, stdlib, no `s19_app` import). The transcripts are `evidence/inc-10/int-01.txt` … `int-23.txt`, `e5c-01-setup.txt` … `e5c-16.txt`, `e5c-rr-01-setup.txt` … `e5c-rr-05.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | H (45 + the 80 × 24 skip) + F (57) + TC-B97-64 (2) + the edited nodes | **120 passed, 1 skipped** ×3 (e5c-11/12/13, the gate set); 92 cases, 90 covered / 2 partial / 0 gap |
| **A · neighbours** | the edited files + the 7 law guards + the serial lane | **492 passed, 1 failed** (known `at_b78_03`, e5c-15) · **219 passed** (e5c-rr-05) · serial **6 passed** (e5c-16) |
| **B · black-box** (keys and dialogs) | the go-to / search boxes, section / map / MAC-record / tag-find jumps, the rail keys, `[u]` / `U`, the Save / Load dialogs, the Split / Join palette | passed in int-21 / e5c-11..13; no Windows-only arm |

Details: `inc-10/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base (before the fix) and each corrective mutant removes the guard it pins |
| Instrument | project code: the testers' own nodes; the corrective's staged-tree copies; restore checked by the transcript's tree fingerprint |
| Where it ran | the LAN Linux laptop (testers, integration, corrective, re-review) |
| Transcript | `red-01-tester-h-base.txt` (36 failed / 4 standing / 1 skip), `red-01-tester-f-base.txt` (41 failed / 5 standing), `int-09.txt` / `int-09b.txt` (8 RED, 3 standing guards), `int-18a–d.txt` (the E4-R1/R3/R4/R5 mutants RED), `int-20.txt` (the E4-R6 nodes RED 4/4), `mut-c-01.txt` … `mut-c-23.txt` (each corrective mutant RED on its target, M-L excepted) |
| Restore proven by | each mutant copy restored byte-exact and deleted; `git worktree list` clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 92 nodes, every node named in the transcripts' PASSED / FAILED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the declared standing guards (4 H, 5 F) — each named in `E4-tester-h-notes.md` / `E4-tester-f-notes.md` |

| Field | Value |
|---|---|
| **RED counterfactual** | The new + edited nodes were RED on base for behavioural reasons (testers: 36 + 41 failed); the corrective mutants each turned their target nodes RED (mut-c-01 … mut-c-23, M-L excepted). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 38 mutants on the pre-corrective tree: **35 KILLED**; survivors M23 (equivalent, killed by /2/8), M-L (layout wait, equivalent on every reachable route by probe), M28 (coverage gap, killed by the strengthened /7/3). The corrective's 20 mutations are RED on their targets except M-L. Transcripts `evidence/inc-10/mut-01.txt` … `mut-38.txt`, `mut-c-01.txt` … `mut-c-23.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test files on base (36 + 41 failed, `red-01-*`); the E4-ruling mutants (int-18a–d, int-20); the corrective mutants (mut-c-01 … mut-c-23); the coverage audit (first pass found R-TUI-040.11 5/9 arms, R-TUI-012L.8 two arms short, 3/3 runs unmet) — `E5-coverage-audit.md` §3, §7. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 5 emitted forms asserted exactly: the unload statuses (`Unloaded primary image.` / `Unloaded MAC.` / `Unloaded A2L.` / `Unloaded all artifacts.`, `Nothing to unload.`) and the file status painted from the same text (F); the scrubbed names in the load line and the project-load line (F); the failed-go-to marker removal (0 lines starting `> `, H); the second-row window (the two hex rows and the `... showing from` line, H); the save-as project files on disk (no top-level `.s19` / `.hex`, no image SHA-256, F). All passed in e5c-11/12/13 and e5c-rr-03/rr-04. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-07. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-10/` and the pilot in `inc-10/evidence-e1/`. Each transcript prints the base commit, the staged tree, `s19_app.__file__` and (the corrective) the exact command line; home paths and account names are redacted.

| Evidence artifact | Path — under .dev-flow/2026-11-01-batch-101/ | SHA-256 |
|---|---|---|
| e5c-01-setup.txt | evidence/inc-10/e5c-01-setup.txt | 2ac2cd003ee723f80ae6b16a3c256f1cf8c0d4c8d898e0218df109fc2c19df46 |
| e5c-02.txt | evidence/inc-10/e5c-02.txt | 1e1f217404aaee8bcc860054e21b68845818a68f0e0b0312417c05e71d69b053 |
| e5c-03.txt | evidence/inc-10/e5c-03.txt | a5ab03a9f3755d0498eb559b4ab155ad0a64c51eed05a4dd50e609a7b384d5f2 |
| e5c-04-setup.txt | evidence/inc-10/e5c-04-setup.txt | 7a613ca3c34c3e32a26708b1f51f3615e7b6ad3dd54a815195358b1e659a9381 |
| e5c-04.txt | evidence/inc-10/e5c-04.txt | e2edb65a7f427b60a6b90d1b0ccac6aca7d919d6500e144cb8f12f08e7315427 |
| e5c-05-setup.txt | evidence/inc-10/e5c-05-setup.txt | 660128a9d2d9bbdf3373f011e4d49295f2d9f9363c8b93dd0b71e70da4410f3f |
| e5c-05.txt | evidence/inc-10/e5c-05.txt | 9d35b64d303ba998c828a21fff4134f824c91b94606b7379d8da958a00e95ab0 |
| e5c-06-probe.py.txt | evidence/inc-10/e5c-06-probe.py.txt | 1d4cf7942ef60994d9ea57b26c27d219119688d725ea3b07eade862e64f2417a |
| e5c-06.txt | evidence/inc-10/e5c-06.txt | a9a7032edf42cda8048fa4ed0ad698f1a5b9f37c6fd0881b6109912e5ea0c8eb |
| e5c-07-setup.txt | evidence/inc-10/e5c-07-setup.txt | 82166718ce9f8422aa87d0d843c083e4fe35acd9612af954a47c5ca5b56ca11f |
| e5c-07.txt | evidence/inc-10/e5c-07.txt | fe382f48bef7522fda6ac07e67722e11f9c20478e1dbb347e80d4d95d474267a |
| e5c-08-probe.py.txt | evidence/inc-10/e5c-08-probe.py.txt | 1350089746b94491fafedb96ceab256da35bcac4c17667d8e8095d814aadf5de |
| e5c-08-setup.txt | evidence/inc-10/e5c-08-setup.txt | 660128a9d2d9bbdf3373f011e4d49295f2d9f9363c8b93dd0b71e70da4410f3f |
| e5c-08.txt | evidence/inc-10/e5c-08.txt | ef646ff716caf384ae125e15b56b1eccee235c450f42ea70f37c097522d7619f |
| e5c-09-probe.py.txt | evidence/inc-10/e5c-09-probe.py.txt | 6617492fc6fd36278bc49ee3e9d43476911712343f97c89ac392bf7c8f401f4b |
| e5c-09.txt | evidence/inc-10/e5c-09.txt | a341e96d7ec04921f473c45416ec09f3ac54080f1a35ce8631ac719b988a91bc |
| e5c-10-probe.py.txt | evidence/inc-10/e5c-10-probe.py.txt | bf829cb190f03e16ba7b50e7f699d336724f8b92e9485cdcfda26cb0a931c7c8 |
| e5c-10.txt | evidence/inc-10/e5c-10.txt | 1e75b4ad90e520dbed2967c3f9179a5ccd0ffd34b473ee9f19cee5de311d12a1 |
| e5c-11.txt | evidence/inc-10/e5c-11.txt | a4d9bd7578c51f0a625e2fe80c0e4212a965c54374a456dd0d42ae138b9da73d |
| e5c-12.txt | evidence/inc-10/e5c-12.txt | 98562e87605093280ee1009a0d3c7690058c9816c2f60a1acf1943bb5b3c9892 |
| e5c-13.txt | evidence/inc-10/e5c-13.txt | f3d8a90b5f4175877fffc7ba4f630af6be4c407c4343ce578aa354fb934744f2 |
| e5c-14a.txt | evidence/inc-10/e5c-14a.txt | b130d9cd6d6353ebe25cd46d32d0942c933bc16cdc8b3e0df30f3147fd24a598 |
| e5c-14b.txt | evidence/inc-10/e5c-14b.txt | e2b377bc1aa69930450e68016796763ef5eaa934ac1eca5d0e0d710462a60b8a |
| e5c-14c.txt | evidence/inc-10/e5c-14c.txt | 1050f8341d0ee09e7124ce5b8e11def329fedf2540b467a583fb61818ac33370 |
| e5c-15.txt | evidence/inc-10/e5c-15.txt | 72df5eb3394b6704ab882e9eb6ab40dedcaa58768272ebaf24ab7617b4f9f608 |
| e5c-16.txt | evidence/inc-10/e5c-16.txt | 9bf291ff748de0115eb208aafda543a9ccb9b7344f6606b365017fa7a21490b3 |
| e5c-rr-01-setup.txt | evidence/inc-10/e5c-rr-01-setup.txt | bd1559b444ba3f4522a82f5e45ac48c8750030235053b11502e03a00296ff9f3 |
| e5c-rr-02.txt | evidence/inc-10/e5c-rr-02.txt | 85a04866ade2c36d6319f672ccbb8e2a978f0629472fcaf7d3a0fdaaba899db0 |
| e5c-rr-03.txt | evidence/inc-10/e5c-rr-03.txt | f46dcaf00573bb8f88d038342daa73bb056973b128cbc354e205cff1bc736545 |
| e5c-rr-04.txt | evidence/inc-10/e5c-rr-04.txt | 2d7e00ac58a2f51aa538bae84581af0026d323e57dd985cd4083b5b2771d7ee3 |
| e5c-rr-05.txt | evidence/inc-10/e5c-rr-05.txt | 12957c6da1c15a06a26421f85485728df7281b4359764d30ee06006325255889 |
| e5s-probe.py.txt | evidence/inc-10/e5s-probe.py.txt | 4ad6d9c2be2262be8c7f5e069593997cd50b01c0293607a588c6f1c7fd511398 |
| e5s-probe.txt | evidence/inc-10/e5s-probe.txt | 6ee4d75b97dd9bb90ee323249eb5fdcb5d1cba54707e5e92895c6e842f0f7c93 |
| int-01.txt | evidence/inc-10/int-01.txt | 3948e141a44eac7829b772add63d91fd985c15e0a4c33e1bd8b1de614d70f3a6 |
| int-01a-prefix.txt | evidence/inc-10/int-01a-prefix.txt | 0e791cc88b74cc2a7d5c2bdf827aca790eb2da93eade0907043f2a4ac1494b95 |
| int-02.txt | evidence/inc-10/int-02.txt | 21521cf6ae4661ff236dc3075d6edf9f1b5a77bddcb1dd6d47215a3e2528f91c |
| int-02b-freeze.txt | evidence/inc-10/int-02b-freeze.txt | 44bec11a3a9a9b6c311e57e687154d2db1eb712940b01cf61b4697d6392cf958 |
| int-02c-workers-serial.txt | evidence/inc-10/int-02c-workers-serial.txt | a4aa5e0b174dfa8479800a83ad2affce8ae00f372c94f3d61889e43a5a45210a |
| int-02d.txt | evidence/inc-10/int-02d.txt | 3a3ee764a1d5bac782f83903a8046b15b4da1660bfcdd89e5530217720242198 |
| int-03.txt | evidence/inc-10/int-03.txt | 02a144496c4aed5852019fe9d6fb7fac79deea78c7ca5ad55174f4f50b7e9fbc |
| int-04.txt | evidence/inc-10/int-04.txt | 7f4b8ec10d3d3ba677e73a0eb6243fa95a9cecaba48250b7289d4f2b904803c5 |
| int-04a-r-tst-050.txt | evidence/inc-10/int-04a-r-tst-050.txt | 78cd25fed1f72f8fe128d033009ec9046f549a67b5da8a56770454c8e6b6b57f |
| int-04b-7d9218d3.txt | evidence/inc-10/int-04b-7d9218d3.txt | f0333d915a984048ec5630a1ee4c048735918fb55d4114d97ba60f34eddc0705 |
| int-05.txt | evidence/inc-10/int-05.txt | 871a3782ae1671c5bb5aaee6d716ac17027b68e63879cff5f46af8864a576e8d |
| int-06.txt | evidence/inc-10/int-06.txt | d2a7006d8f9c88cfa86a4879dd85ec0645d2b1cde154cac6a103c2fbc0ebb403 |
| int-07.txt | evidence/inc-10/int-07.txt | 09276f99c2c166ff6ee9a0840b27be2ef567035d2d7ed823921b4b83d8ce07af |
| int-08.txt | evidence/inc-10/int-08.txt | 529b316ef702de513b51631a861377ce015fdb5e103c8de98de152b7af26cf22 |
| int-08b.txt | evidence/inc-10/int-08b.txt | f3bb7ea9b22843036e4b161c0f58f95787f95c32249779ea2d9bbb76271d063d |
| int-09.txt | evidence/inc-10/int-09.txt | 2a5b23dc6c78e1727ef79b2d8b4e303600890260b1401e6b248f2046f1b49152 |
| int-09b.txt | evidence/inc-10/int-09b.txt | 30db82f7ada7babf39e288fdf63e604ef6ffbde44aee6509f92e6260a16558d7 |
| int-10.txt | evidence/inc-10/int-10.txt | 352c19af7a5992c340d42fe6a980a270a47e8fd3a59888d6345b4366637178c1 |
| int-11.txt | evidence/inc-10/int-11.txt | e130da2a698917d9cbecee7a54f29bc033b07dbfd0537c7537bf4624bc45cdbc |
| int-12.txt | evidence/inc-10/int-12.txt | aafdbf8421f42ba3fb59d2c6d43859b7ed9592fdb6ed68bd740570ba35bdf7a1 |
| int-12a.txt | evidence/inc-10/int-12a.txt | ca52f49c8cbc820bb61dea5f7f0ed5b3dd3b36b9d39f3f537f999ce3bd94da3d |
| int-13a.txt | evidence/inc-10/int-13a.txt | 87d167bc72df3986ecd5023cfe0c9b994b587ab356548566fa27c0e4d908ef87 |
| int-13b.txt | evidence/inc-10/int-13b.txt | 09db0e06b21e464c2d3debb5c139c949c1ce751b76a427085ff88b82fb829c7f |
| int-13c.txt | evidence/inc-10/int-13c.txt | 00a347509d084681988b7e8b9842eb23603bf23dd0474a97e26402c3dd1eee65 |
| int-14.txt | evidence/inc-10/int-14.txt | f3ed9006318eb8ce3ad2bc4a9394cc47b7284be7ceba60d457a12fe5d3f1eb46 |
| int-15.txt | evidence/inc-10/int-15.txt | 66cd868e8297f785009cca56e1e4576b4d86d96f8772c0d7e807662dda4ca03a |
| int-16.txt | evidence/inc-10/int-16.txt | f291f7c9b4da83f938debf2e5b3d64094c953612e04d5ed2405dc7875eca3987 |
| int-17.txt | evidence/inc-10/int-17.txt | 25d0d2ab54b3b195abc5d0ec0693f0314140ef1b574120c8d1d6404d239e29e3 |
| int-18a.txt | evidence/inc-10/int-18a.txt | c49cc086ec45a81bfaec2a4b9e9efa75233c79356f8b97bdd69a63bf4a30173b |
| int-18b.txt | evidence/inc-10/int-18b.txt | 207f056b6bd3df81d04460bc70b79cae36978c26752c17ce3964c5d3fd5245e5 |
| int-18c.txt | evidence/inc-10/int-18c.txt | 64a75d3b8b1234d249c7506fd88a1d886a891f72a6a6d9a70875d946264a8f05 |
| int-18d.txt | evidence/inc-10/int-18d.txt | fa8ec3f1967671472a2cd9ad50d0a78e61ab539f091c256b0a7d1f68ee7f43b1 |
| int-19a.txt | evidence/inc-10/int-19a.txt | 9fc4097852aa68e1e1207620df37be768932778a67fb1f67684e8b54e531b8d1 |
| int-19b.txt | evidence/inc-10/int-19b.txt | 5ebe927b0a6553bf256945c721912202eb3b0bddf5efc465fa69ed6461ba8a17 |
| int-19c.txt | evidence/inc-10/int-19c.txt | 7f49d3ffdac08895a38e2dc1a315a27cf01215a61afe2a57f4951a2bdb02cfa6 |
| int-20-setup.txt | evidence/inc-10/int-20-setup.txt | e8e7afa63c97a18e4de3c286f438c299b28ab52e72c41ee74679d38c0ecfbd93 |
| int-20.txt | evidence/inc-10/int-20.txt | b1b67ea2bb6bfc6daec3c84805b3400a6243f5a7953f35b778d5b7ef4b2506d8 |
| int-20c.txt | evidence/inc-10/int-20c.txt | c6dfa97dadc371daae180353d0cd0304a48146f51bd3835945e800433465eaeb |
| int-20d.txt | evidence/inc-10/int-20d.txt | 29a6505b977cfc3e4dea0f5cbf83ea3a53b2ce9d2dc09438cc9d4d367dd33672 |
| int-20e.txt | evidence/inc-10/int-20e.txt | 692335b7152e56b1c5ee9dfbd9fbdf05f86c52ddccba1c5729610daf01db1f73 |
| int-21.txt | evidence/inc-10/int-21.txt | 5509e85fec3262847e1224c12a8151c8be9b260d0f5bb162cfa7ef590c97f059 |
| int-22.txt | evidence/inc-10/int-22.txt | 035432640e5cfa99885f392d32019dc06b35a9961c27759e9165746864843256 |
| int-23.txt | evidence/inc-10/int-23.txt | 501dd3287f99f9b8f96d5adfca7fc79b515bddf815b535e5e4e8c8fb5dade9d0 |
| int-base-01.txt | evidence/inc-10/int-base-01.txt | ea9be3aac7d205ffb391a93788a962fc03e84666c14c0ffbf51e66e08661567f |
| int-base-02.txt | evidence/inc-10/int-base-02.txt | ea027647d3efacbe5c10190ca2bdbe9958f06d9d94242906105a6514433a20c8 |
| mut-01.txt | evidence/inc-10/mut-01.txt | e2390f11f13ec19eef8783158cad55a7d7514e6719a7d04baa240e476464c481 |
| mut-02.txt | evidence/inc-10/mut-02.txt | 4927c157c7f5faad58c87f47e669cd63481fe9fce91a5a373ad50a1aea984a85 |
| mut-03.txt | evidence/inc-10/mut-03.txt | 145914e3d4eb0041ceb08cb9c39c9a85153ab0f7648d65044efeb3d2ca08082b |
| mut-04.txt | evidence/inc-10/mut-04.txt | 2833784f28ad27847c96e7a6c6f0345297ccc0eeb878b2e15073052dfb17f75c |
| mut-05.txt | evidence/inc-10/mut-05.txt | 8127d6ab9112faee471a29daced79b184dfcfaa7c387d80dd9b2b33d0a5e38ba |
| mut-06.txt | evidence/inc-10/mut-06.txt | 08673031b1396ef36a0b3fff0d65363d954945dffc8075d75b077fabb85b17f0 |
| mut-07.txt | evidence/inc-10/mut-07.txt | 674aec517b389f6a5d570f0693278b5b6d804d3536b5023ece20c5ca608cfb27 |
| mut-08.txt | evidence/inc-10/mut-08.txt | 4189ca7d6a61582e0f55ac4455df3fd25807c3936bf97e04e713d7af1d4a87a5 |
| mut-09.txt | evidence/inc-10/mut-09.txt | bb0b6ebb0ce9bcfc14c0b1cf3cbf469e42c638e97b009ea2a31a87e2a17999e7 |
| mut-10.txt | evidence/inc-10/mut-10.txt | e06cc45a71f20524fea3bde5540ea4f417bb5b325c3cd62182bbc1f4331469cc |
| mut-11.txt | evidence/inc-10/mut-11.txt | 7579609754688463cb8afaf03796661729b3e5d9a0e7c78ffc70ef6f18d677a0 |
| mut-12.txt | evidence/inc-10/mut-12.txt | 9e44ea9fc57aff694da6d373213d57320397def77f10c298559bd5da69e6b57f |
| mut-13.txt | evidence/inc-10/mut-13.txt | e5fbc440135cc5391ecdb5ff2188e1de3caf73030a464a0768ea573e7633451b |
| mut-14.txt | evidence/inc-10/mut-14.txt | c04ab8a45427ad6bc6c45d3b3fa1eccd9fe2c9d1990861f3ac2ce425e3c054aa |
| mut-15.txt | evidence/inc-10/mut-15.txt | b989bed3d76f34e77c618ae85d35043ba1e57233bad2b4175a07b68131ca4c09 |
| mut-16.txt | evidence/inc-10/mut-16.txt | 232d744240819e021cb51a034039c7bab321fcef23cb86156ef9b9bd1e1ef319 |
| mut-17.txt | evidence/inc-10/mut-17.txt | 8eada47d75d6b80871a6923451b36620301fa18a3ee9c1673a08102d4a1d4d75 |
| mut-18.txt | evidence/inc-10/mut-18.txt | e959b6bb307d8aec16969b5fd8b1be7cb95a258fda5b28c51e221b8af0f6437a |
| mut-19.txt | evidence/inc-10/mut-19.txt | da4f8cc10361d55389f37cb40f77d1b3ef399aa300618d22d19d15b032efd444 |
| mut-20.txt | evidence/inc-10/mut-20.txt | 6dae327dd5211fd14126603c634aaf65e895dd34509dcdac15f9f8db2fe50fd7 |
| mut-21.txt | evidence/inc-10/mut-21.txt | 01a363f3776717589daa7959f5742a567445d07f5b6f98eff80e1b68199e0f6e |
| mut-22.txt | evidence/inc-10/mut-22.txt | 822556b86eb357845a61a5ec7366487933ac21b8edfd7990ebe17b2a2c658ef1 |
| mut-23.txt | evidence/inc-10/mut-23.txt | 955c931da2c6430bb80f918db712aae4339067e6f23fb78286fd5eb0d01a904a |
| mut-24.txt | evidence/inc-10/mut-24.txt | 6a0ff24987251f298c3f5d1a1f9da9012b39cc76536e07cba3fda2155050659d |
| mut-25.txt | evidence/inc-10/mut-25.txt | b62743792313d90b51d451136fee020981f416fc51c71a48a33c8942085737a5 |
| mut-26.txt | evidence/inc-10/mut-26.txt | 6623aaf14c781e3d53481bcfcbbfd81198aecf15d5d726b93452a2980126458a |
| mut-27.txt | evidence/inc-10/mut-27.txt | c010a533e56c09c2c76b7dc97b0f7cc4899ff85b27a6b883208ce816f74a068a |
| mut-28.txt | evidence/inc-10/mut-28.txt | 47da55e6c35e19e0dbd425051f75c05512ba51534c08ccc658e9777d81e2c085 |
| mut-29.txt | evidence/inc-10/mut-29.txt | 71d2bff6b871e5b49ea70345b05151c34da6f48b2f822c88bd8d1e3286152034 |
| mut-30.txt | evidence/inc-10/mut-30.txt | 29b2f891d3e75b5e19edf34a7d7e14710c1e8b576c69688f6d7d585ba0df2930 |
| mut-31.txt | evidence/inc-10/mut-31.txt | 0aa59e618da25469179689ef2f45b4f038681763804a2c96bdff141374c977f0 |
| mut-32.txt | evidence/inc-10/mut-32.txt | 5136a633eb36525decd768ddc7a37574b086c97ad9599f56de1e8b5e1bf81d4b |
| mut-33.txt | evidence/inc-10/mut-33.txt | ffafbc4d87854ea8c5575cc63432ff5998c444e06693defddedd8c641c852aa7 |
| mut-34.txt | evidence/inc-10/mut-34.txt | 3300af40b750ef08227ae5ebcb49264b3b7c23b398190b59fda2727316f4f3a9 |
| mut-35.txt | evidence/inc-10/mut-35.txt | 504ef846c1959065c1a90ea3135b38a24a35b121383465f4f6bfe2f77482abd4 |
| mut-36.txt | evidence/inc-10/mut-36.txt | 9620d7c71a094a385958cea68ade37f6eda67ef3ee34d706f680699674cbb689 |
| mut-37.txt | evidence/inc-10/mut-37.txt | ccd6b5cfcc4ce87a08726e6d30e8d1cca79af575231f99942a635b68860cf20f |
| mut-38.txt | evidence/inc-10/mut-38.txt | 007b86d350896b59f61f9831a5b495a7571d5c21e6f5637d417bde8b08dedb71 |
| mut-c-01.txt | evidence/inc-10/mut-c-01.txt | 5e3d920b3baf8edb9b74e3b40e67aa008f2b3208410e35a83e2524e6258495f3 |
| mut-c-02.txt | evidence/inc-10/mut-c-02.txt | 7bf8611ff74defb6704e708a15d71a8ca6d74f8b1904ea985e0e9ee4bd5336a0 |
| mut-c-03.txt | evidence/inc-10/mut-c-03.txt | 48ab35223ec1110f1b2865b3a116e03c964f621970a8e059e1f5d0784965817f |
| mut-c-04.txt | evidence/inc-10/mut-c-04.txt | 78a816943a4dd4bdcbdc8d18e7c4c90cb9e35efa45a158fb6c32b4b34d84d06b |
| mut-c-05.txt | evidence/inc-10/mut-c-05.txt | 2f59ba229e6d1714fd58a0227c3703a35c3c6e474354e599973a044134bfb1cb |
| mut-c-06.txt | evidence/inc-10/mut-c-06.txt | 4933f5bef12437d32a1bec94e527c822245fe699776d6c3d99bcf688e26f2cae |
| mut-c-07.txt | evidence/inc-10/mut-c-07.txt | 05908eda25bafc677eb1b9bb51bd64a07630647aa7f4f318ab1154553bbe85d3 |
| mut-c-08.txt | evidence/inc-10/mut-c-08.txt | 9a1b426d973d920c8298ee5dae2181f8a6993bef31b7cad0beef408beaace16c |
| mut-c-09.txt | evidence/inc-10/mut-c-09.txt | 8313eca1ce7ea607ecd47b551eff2cfc9263478088e94cf1b8f180d6d05ff3ba |
| mut-c-10.txt | evidence/inc-10/mut-c-10.txt | 97d1dc8ed55a0b16894ea5e0c0b87b85cc70a4977cf32b8191a504244867b573 |
| mut-c-11.txt | evidence/inc-10/mut-c-11.txt | 1d4979d2ea6a6eba6f85dc050619d2beae09b50badd6a141673dbc653501ab69 |
| mut-c-12.txt | evidence/inc-10/mut-c-12.txt | 6eb672d0c39db845742ef609088c8428a10976d6798043bc8fe0d0f18846d2fa |
| mut-c-13.txt | evidence/inc-10/mut-c-13.txt | 6320759498f59df7b3b03e0a25d0e935d6e6291cf506dfe43d010193dc397c4b |
| mut-c-14.txt | evidence/inc-10/mut-c-14.txt | e3aefa1b243450798ea227520a5c8c2ee340b0e53894e18d78822b95cd9fa9e0 |
| mut-c-14b.txt | evidence/inc-10/mut-c-14b.txt | d0cefd16f94661c9379f87915f5f1c80d5bcc937ce796b9f685db902678a2c74 |
| mut-c-14c.txt | evidence/inc-10/mut-c-14c.txt | e7982f6f766c73ec24766b6c484fcb5126f39ae85652e7f5fe4ca640157e6cfa |
| mut-c-15.txt | evidence/inc-10/mut-c-15.txt | eb385f47747a0a08a7763c8bb0c19e59fab74f555c5fc31e018b52b4440bad52 |
| mut-c-16.txt | evidence/inc-10/mut-c-16.txt | f97fec95faaa718768df2b97d123ba0661328fe3060a38c0e570dd7d8d0aa12e |
| mut-c-17.txt | evidence/inc-10/mut-c-17.txt | 5e3ce832c41baa26f7dd2445691812d71acb15165d329832290ad24f557784ad |
| mut-c-18.txt | evidence/inc-10/mut-c-18.txt | 516c8fc11976cb4dcbf449ec1510fb72bd186a57b9e6edb2df760cd8e01464b6 |
| mut-c-19.txt | evidence/inc-10/mut-c-19.txt | 5037893b97d8b59e141fe15818d0e53dc6f26e4fa3e08453ff3f0a3e670c6e76 |
| mut-c-20.txt | evidence/inc-10/mut-c-20.txt | d7f0dda6c2f50cf7857294b448505eb4015268827ac5230a6344bfb9c639e781 |
| mut-c-21.txt | evidence/inc-10/mut-c-21.txt | dc44dd247dfdb4ce7d1f5113f3d01fd8066631cd8f9d1a9bf598139ee5ad55dc |
| mut-c-22.txt | evidence/inc-10/mut-c-22.txt | dd013139edc23034e7f094435bf6a55026aa490cc1c7472aa530b6121a4a8f17 |
| mut-c-23.txt | evidence/inc-10/mut-c-23.txt | 56ba793b1332879df39690e12a6ce8fa50392342420b9163b9626d0e3bd37366 |
| mut-c-mutations.py.txt | evidence/inc-10/mut-c-mutations.py.txt | 748cce240a6559cc0674a246ec262b92c0daa375d51314ead60d02641b0fb06d |
| red-01-tester-f-base.txt | evidence/inc-10/red-01-tester-f-base.txt | d4df65dbf9df11291d3708c8167178f29280a4fd300f0c90cd79b8534a09a58f |
| red-01-tester-h-base.txt | evidence/inc-10/red-01-tester-h-base.txt | 2963702a735f9828b77ca5801ac165165aeccbbf5e298921aa70c71f0d546e08 |
| i10e1-pilot-transcript.txt | inc-10/evidence-e1/i10e1-pilot-transcript.txt | 9844ccd6067df44c40337571b291dfc7fbeae9f75259ddc628af610acd7139b1 |
| i10e1-pilot.py | inc-10/evidence-e1/i10e1-pilot.py | 89d3fe073e5e85ab88b6c91a7cc8d4284069a8cafb271903404b40a0cbba3630 |

| Field | Value |
|---|---|
| **Evidence files** | 146 committed transcripts, probes and scripts at the declared home, each printing the base commit and the staged tree; the pilot script and transcript sit under `inc-10/evidence-e1/`. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no key acts on a hidden Split / Join window" (R-SEG-OPEN.7) and "no saved project holds the unloaded image" (R-WS-LOADED.19) |
| If the result is an ABSENCE, what made the search wide enough | `git diff 09b4808 HEAD -- s19_app` shows only the 3 slice files; the A10-11 census enumerated 69 test files calling `action_show_screen` (17 reading the focus after a switch); the engine-frozen guards (`test_engine_unchanged`, `test_tui_directionb`) confirm no frozen parser / engine module moved |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `check_action` / `action_export` hidden guards (R-SEG-OPEN.7: no key, no export from a hidden window); the save-as filter in `_plan_project_save` (R-WS-LOADED.19: no unloaded image written back) |
| Conjunctive criteria: one mutation per conjunct | the landing's move conditions are each isolated (M21 no landing, M22 no synchronous clear, M23 stale return, M24 no unload landing, M25 move unconditionally); the hidden-window guards (M28 `check_action`, M29 `action_export`); the save-as filter (mut-c-01); the exit guard (mut-c-03) |
| Synthetic instance of the absent case | the forced-focus hidden table (R-SEG-OPEN.7/3, /4), the A2L-only save-as after a primary unload (R-WS-LOADED.19/5), the switch-made-while-a-dialog-is-current probe (e5c-06, e5c-09) |
| **Positive control for every probe that returned an ABSENCE** | M28 (check_action removed) turns /7/3 RED, M29 (export guard removed) turns /7/4 RED, mut-c-01 (filter off) turns /19/3 RED, mut-c-03 (exit guard removed) turns /3/3 RED — the same probe reads the painted absence and fails when a defence is removed |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the A10-11 census + the QC-BC set (int-16) + the importers + the 7 law guards | int-16 3442 passed (187 skipped, 2 xfailed, 2 known failures); int-22 218 passed; the 69 test files re-run at E4 integration |
| B2 file moved on disk | no file moved; the three sources changed in place | 0 readers of a moved path |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the three changed sources | no golden captures `app.py`, `segment_split_view.py` or `render/hexview.py` |
| B4 artifact produced here is consumed elsewhere | the saved project (top-level image files filtered), the file status line, the focus landing | consumed by the project load, the status painter and the rail-key / unload landings (asserted in H and F) |
| A3 interface consumed by another module changed | `hex_row_bases` (new), `update_alt_hex_view` / `update_mac_hex_view` gain `start_row`, `_clear_goto_marker_keeping_window` (new) | the one keyword is passed by both call sites; `_collect_hex_rows` reuses `hex_row_bases`; Inc 10b relies on I-5 (unchanged) |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it; B2 no moved file; B3 no golden hit; B4 the project-load / status / landing consumers; A3 the `start_row` keyword and the `hex_row_bases` extraction with Inc 10b's interface (I-5) unchanged. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result / control no longer matches its node | the coverage audit's row-by-row read (`E5-coverage-audit.md` §3, QA-1 … QA-10), then the corrective's per-ruling edits (SE5-1, SE5-2, SE5-5, CR-1 … CR-9, QA-3, QA-4, QA-5 … QA-10), then the re-review (RR-1, RR-2, RR-3) | 8 cases added (R-TUI-040.11/6 … /9, R-WS-LOADED.19/3, /4, R-SHELL-FOCUS.2/8, R-SHELL-FOCUS.3/3) + 1 at the re-review (R-WS-LOADED.19/5); marks changed (R-TUI-012L.8/2, /3 partial → full; R-TUI-007.3/2 partial) | all, by the E5 corrective, the rr-fixes and this close unit | none; re-audit: 90 full, 2 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (QA-1 … QA-10) before the corrective edited its first site: the 8 + 1 added cases, the mark changes and the record-only Result / executor / entry-point re-citations. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `272 = 270 − 0 + 2` (`tests/test_id_registry.py`, measured; two new modules). Cases `92 = 83 + 8 + 1` (E4 83, corrective +8, re-review +1). No test node deleted, no function renamed, no assertion weakened (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §6–§7).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; CR-1, CR-2 MEDIUM — the `_hex_view_rows` memo contract and the six duplicated failed-go-to blocks; CR-3 … CR-9 LOW) — `inc-10/E5-code-review.md`. Re-review of the corrective: **FAIL** (0 HIGH; RR-1 MEDIUM the SE5-1 filter covers the MAC remainder only, RR-2 LOW top-level wording, RR-3 LOW nine doc items) → fixed by the rr-fixes, GREEN — `inc-10/E5-code-review.md` "Re-review of the corrective". `security-reviewer` · **FAIL** (0 HIGH; SE5-1 MEDIUM the save as after a primary unload writes the unloaded image; SE5-2 LOW no node pins I-6; SE5-3 … SE5-6 INFO) — `inc-10/E5-security.md`. `qa-reviewer` · coverage audit (R-TUI-040.11 5/9 → 9/9 arms, R-TUI-012L.8 two arms short → full, 3/3 runs unmet → met; QA-1 … QA-10) — `inc-10/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **FAIL** (1 HIGH, 3 MAJOR, 10 MINOR) → rounds 2–3 **PASS-WITH-NOTES** · `security-reviewer` **FAIL — BLOCK-UNTIL S-1, S-2, S-3** (3 HIGH, 2 MAJOR, 3 MINOR) → **closed** — `inc-10/E3-architect.md`, `inc-10/E3-security.md`, `inc-10/E3-rulings.md`. The independent `testers` (E4, Sonnet ×2) wrote the 92 nodes from the design records only and ran them RED on base — `inc-10/E4-tester-h-notes.md`, `inc-10/E4-tester-f-notes.md`. |

## 5 · Risks

- **The MAC switch landing's Enter pages back** (I-D23, CR-4): Enter right after `3` presses Page Prev — page 1: nothing; a later page: back one page. Read-only, nothing writes (SE5-4); named in CTX-SHELL's MAC line for the canon fold.
- **The `check_action` guard is not the whole story** (BL-I10-3, SE5-3): the hidden window's table binds up / down / `k` / `j` itself, so a forced focus on it still moves the hidden cursor. Nothing is written (the export sink is guarded), and no product route puts the focus there.
- **A MAC-only spine's record jump still centres** (BL-I10-4, CR-8): with no present rows a MAC record jump centres with 64 context rows; R-TUI-018.1's second row and R-TUI-018.3's target are undefined without present rows.
- **A MAC load or unload can still shift the window** (BL-I10-1): MAC rows outside the image shift the stored index; the load half is fixed (R-TUI-007.9), the MAC re-anchor half stays.
- **The 80 × 24 main pane is one line** (BL-I10-2): no jump target can be the second row in the main pane at the floor size; R-TUI-018.1/13's main arm runs at 100 × 30.

## 6 · Pending

- **Merge verification** — per the operator's order (2026-11-06), no full suite runs per increment: each increment ran partial sets (its slice, the edited files, the two HLR-177c nodes, the law guards, the serial lane) on the merged tree; the full suite runs once at batch end, when the batch's increments are all on `main`.
- **Canon ids to forward to the requirements session** — the 6 new rows (R-TUI-018.4, R-WS-LOADED.18, R-WS-LOADED.19, R-WS-LOADED.20, R-SEG-OPEN.7, R-SHELL-STATUS.7), the 5 changed rows (R-TUI-018.1, R-TUI-018.2, R-TUI-040.4, R-SHELL-FOCUS.3, R-SHELL-FOCUS.4), the 16 canon rows used with text unchanged (R-TUI-018.3, R-TUI-040.8, R-TUI-040.11, R-TUI-040.12, R-TUI-007.3, R-TUI-007.5, R-TUI-007.8, R-TUI-007.9, R-WS-LOADED.13, R-WS-LOADED.14, R-WS-LOADED.16, R-TUI-012L.8, R-SHELL-FOCUS.2, R-SHELL-FOCUS.5, R-SEG-OPEN.6, R-SEG-OPEN.1), the 3 cases withdrawn by id (R-TUI-018.1/5, R-TUI-018.3/1, R-TUI-040.12/2, Inc 12 D-2), and the context-note changes (CTX-HEX jump / second row / view rows / first view row / next hex page / last page shown; CTX-SHELL file status / focus target) go into `REQUIREMENTS.md` at the batch-end requirements session.
- **Requirement-text changes to forward** — R-SHELL-FOCUS.4's frame-widget arm ("a frame widget the operator chose", E4-R3); CTX-SHELL's focus target of the A2L Explorer (tag table after a load / unload, `window_help_a2l` after a switch, E4-R4) and of the MAC View (record table after a load / unload, `mac_page_prev_button` after a switch, E4-R6, with I-D23 accepted as is at E5 CR-4); R-WS-LOADED.19 widened to "when no S19 or HEX image is loaded" and narrowed to top-level files (E5 RR-1, RR-2); R-TUI-007.9 brought in unchanged (E4-R1); R-WS-LOADED.16's threshold drops "the Issues Report" (QA-7).
- **Backlog** — BL-I10-1 … BL-I10-4 and S-6 (with its SE5-6 addition) carried into the batch backlog, each named in `04-validation.md` §Owed.
- **Uncommitted records** — this packet, `04-validation.md` and the E5 record edits are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 10a; run the full suite once at batch end (the QC-BC set and the other importers included); forward the 6 new / 5 changed / 9 canon-used ids, the 3 withdrawn cases, the requirement-text changes and the context notes to the requirements session; carry BL-I10-1 … BL-I10-4 and S-6 into the backlog; open Inc 10b (the in-place-write views) on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 / 4 — `app.py`, `segment_split_view.py`, `hexview.py`; reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_hex_jump.py` (45 + the 80 × 24 skip), `tests/test_b101_unload_focus.py` (57) + 5 edited files |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the slice units traced node-for-node in `codewire/graph-inc10.md`; e5c-11/12/13 120 passed ×3 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 36 + 41 failed, int-18a–d / int-20 mutants RED, mut-c-01 … mut-c-23 RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES, 0 HIGH (re-review FAIL → fixed, GREEN) |
| 7 | No file from another lane touched | all | ✓ | single lane; the 3 slice files are Inc 10a's own |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the 3 slice files are outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-15 / int-22 / e5c-rr-05) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 90 full, 2 partial, 0 gap — `E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the forced-focus hidden table, the A2L-only save-as, the switch-under-a-dialog probe |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 35/38 killed, M23/M28 killed by the corrective, M-L equivalent |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 1 correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — 5 emitted forms |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer, security-reviewer, qa-reviewer, architect, security-reviewer, testers ×2 |
| 16 | **Evidence files** declared | all | ✓ | §4 — 146 committed transcripts / probes / scripts at the declared home |
