# PLAN draft — s19_app batch-101 (release hardening for v1.0.0) — P0 / ARQ

- **Author and status:** architect, P0/ARQ, 2026-11-01. Draft; nothing is committed.
- **Tree:** worktree `b101-p0` = `main` `e273181` plus the untracked `p0/` triage.
- **Rulings applied** (operator, 2026-11-01, relayed by the orchestrator):
  1. The 37 "UI change = yes" rows leave scope. They are known failed checks in `p0/known-failed.md`, carried as 8 grouped backlog rows `KF-101-*`.
  2. No prototype round runs in batch-101.
  3. Help or README text that describes absent features is fixed by changing the text.
  4. The strict-EARS canon from the requirements re-write session (`C:/Users/jjgh8/Github/s19w/review/S<n>-ears-strict.md`, 2612 rows) **replaces** the canon. It lands as batch-101's **first** increment, together with the 29119-3 test-case records.
  5. Every later defect increment cites the **new** canon's row ids and adds or modifies EARS rows there.
- **Read first:** §b, the increment table; §e, what starts now.

## (a) Triage verification

Kimi K2.8's triage holds **78 rows** (51 F, 20 UX-I, 7 backlog); the brief said 79.

- **Coverage:** at least one row per triage file, plus every row marked `plausible` or `could not locate`.
- **Method:** grep, then a read of the cited lines on `e273181`. No tests were run.

| Row | File | What was checked (command / lines read) | Held? |
|---|---|---|---|
| F-01 | A | `grep "service.load(path_text\|read_change_document(str(candidate)" app.py` → `:6800`, `:7106`, **`:7432`**. `io.py:331-336` accepts `a2l_context`. Then a census of every `read_change_document(` call in `s19_app/` | **Partly.** The two cited sites are right, but a **third** editor site was missed: `app.py:7432` `on_ab_diff_panel_check_file_selected` (the A2B Diff check spec). Two service sites share the same root: `change_service.py:3224` and `variant_execution_service.py:2557`. They are the open backlog rows T-03 and T-04. Inc 4 takes all five |
| F-26 | A | `screens_directionb.py:7088-7096`: `set_a2l_parameters` resets `_param_rows = {}` and `_picked_params = []` | yes |
| F-47 | A (plausible) | `grep "No applied change summary"` → only `before_after_service.py:265`. Triggers: `app.py:2683` (binding `b`) and `:4808` (panel control) | yes, as stated. The trigger is still unidentified |
| F-51 | A | `screens.py:2328-2330`: `ReportViewerScreen.BINDINGS` holds `question_mark` only | yes |
| F-28 | B | `flow_execution_service.py:810` calls `parse_crc_config`. `crc_config.py:487` reads `data["reverse"]`. `crc_designer_model.py:799-807`: `emit_template` writes a nested `algorithm{poly, init, refin, …}` | yes |
| F-45 | B | `flow_execution_service.py:1873` calls `write_chain_set_report` unconditionally | yes |
| F-46 | B | `flow_screens.py:2037-2049`: `flow_clear` clears `_blocks` and `_funnel`, never `_flow_name` | yes |
| F-12 | C | `styles.tcss:283-290`: `width-narrow` gives `#loaded_slots { height: 2 }` | yes (known failed) |
| F-29 | C | `a2l.py:960-970`: fixed `parts[3]` / `parts[4]`, `ValueError` swallowed. Kimi's fixture probe was not re-run | yes (mechanism) |
| F-15 | C (partly plausible) | `MemoryMapPanel` (`screens_directionb.py:2221`) has **no** `on_show`. The only ones are `PatchEditorPanel:5380` and `CheckEditorPanel:7409`. `call_after_refresh(self._resize_band_segments)` at `:2619` | Mechanism yes. The blank-until-key trigger is not reproduced (known failed) |
| F-23 | C | `crc_designer_view.py:999-1000` and `:1079-1080` call `compute_target_crc` **4×** per recompute. `segment_split_view.py:344` loops per byte. Pin claim: `grep -rl conflict_mark tests` → **0 files** | **Partly.** The cost mechanism holds. The claim that "`test_segment_ops.py` sibling pins `_conflict_marks` equivalence" **does not**: no test names the function, and the claim lives only in a docstring (`segment_split_view.py:327-328`). Inc 13 writes that pin first and shows it can fail (mutant) before optimising |
| F-03 | D | `app.py:16008-16014`: the filter uses raw engine severity | yes |
| F-19 | D | `app.py:9769-9774` is open-only. `_toggle_settings_menu` (`:19437`) has no caller | yes (known failed) |
| F-39 | D (could not locate) | `issues_view.py:657` iterates `SEVERITY_ORDER = (ERROR, WARNING, INFO)` within each page. `app.py:16280-16307` pages the raw-order list. Guide `ch07-issues.md:31` states the symptom | Kimi's reading holds: no code path paints INFO before WARNING inside one page. The live symptom stays unexplained, so Inc 11 adds a verification arm on the demo case |
| UX-I-13 | E | `app.py:8553-8573` recomputes `choose_install_set` from disk | yes (known failed) |
| UX-I-17 | E | `screens.py:1499-1501`: `AUTO_FOCUS="#confirm_no"`, `PRIMARY_BUTTON="confirm_yes"`. `app.py:450`: the quit question overrides to `confirm_no` | yes (known failed) |
| UX-I-15 | E (plausible) | `styles.tcss:1797-1804`: `#load_panes.stacked` sets only `layout` and `width` | **No, as cited.** The "equal 1fr heights" are not in these lines (known failed) |
| R1-P1 | E | `app.py:11542` `_save_project_files`, `:11523` `_save_project_worker` | yes (located). The timing is the backlog's evidence, not re-measured |
| OBS-F2-1 | E | `app.py:14614-14615`: `mkdir(parents=True, exist_ok=True)` inside the SE5-12b-2 `try` | yes |
| R2-CI | E | `tui-ci.yml:28`: `actions/checkout@v4` with no `fetch-depth`. Lines 45 and 49 show CI runs `pytest -q` **serially** | yes. Consequence: G-015's parallel-only failures cannot appear on CI, only on the LAN `-n 8` gate |
| G-015 | E (plausible) | `pyproject.toml:111-114`: markers are `slow` and `snapshot` only, so no serial marker exists. `evidence/batch-end/linux-gate-f72eef1-timing-serial.txt` exists | yes |
| SR12b-7 | E (plausible) | `evidence/fix-2/SR12b-7-census.txt` exists | yes (record; not re-counted) |
| SR12b-7b | E (plausible) | `2026-10-26-batch-100/fix-round-3.md` exists | yes (record; not reproduced) |
| CI deferral | E | `gh run view 41372953464` → `status: in_progress`, `tui-ci` conclusion empty, `snapshot` = **success**, headSha `f72eef1` | Still open. The advisory snapshot job passed |

**Rows that did not hold:**
- **F-01:** incomplete; one editor site and two service sites were missed.
- **F-23:** the claimed equivalence pin does not exist.
- **UX-I-15:** the cited lines do not contain the cause.
- **Row count:** 78, not 79.

## (b) Increments

**Common rules for every increment:**
- **Pipeline:** E1 (strict EARS / 29148 rows **in the new canon**) → E2 (Code-Wire graph) → E3 (code-free design review) → E4 (build ∥ independent tester) → E5 (change validation).
- **Workers:** Kimi K2.8 implements E4 and runs mutants and mechanical records. Opus designs, reviews and integrates.
- **Source files:** at most 4 under `s19_app/`. Tests are uncapped.
- **Class:** every defect increment is class `a`: the code does not do what its canon row, help text or contract says. None builds new UI.
- **Canon rows:** the column gives the new canon ids that `review/CODE-CHANGES.md` already maps. "new" means E1 adds the row in the named group.

| Inc | Title | Findings (+ CODE-CHANGES items) | Canon rows (new canon) | Source files (≤4) | UI / prototype | Size | Depends on | Parallel-safe with |
|---|---|---|---|---|---|---|---|---|
| 1 | Canon swap and test-case records | Requirements re-write session's delivery: `REQUIREMENTS.md` = strict EARS rows; old canon → `docs/requirements/history/`; decisions → `docs/requirements/review/`; 29119-3 TC records (key `<R-id>/<n>`, status from junit, `s19w/test-cases/TC-PROFILE.md`); **D0-8** (registry guard exempt headings + scan count, AT-B100/TC-B100 ids) | all 18 groups | **0** (delivered on its own branch by that session; merged by the orchestrator) | none | L (docs) | — | 2 (disjoint files; merge after 1) |
| 2 | Test hygiene, timing arms and CI | G-015, SR12b-7 (shared helpers), SR12b-7b (named arms), QC-TM, QC-OR, QC-BC, R2-CI, CI deferral, CI dwell flake `test_tc_b97_64` (marked `serial_timing`; clock injected only if test-only) | new (S0, process rows) | **0** (`pyproject.toml`, `tui-ci.yml`, `tests/conftest.py`, `tests/*`) | none | M | merges after 1 | 1, 11, 14 |
| 3 | Save project margin; a vanished project folder | R1-P1 (profile first), OBS-F2-1 (+ **D11-72**) | R-PROJ-002.12, .13; new S11 row for the Save bound | `tui/app.py` | none (reuses `Project sync NOT done …`) | M | 1, 2 | 7, 8, 11, 13, 14 |
| 4 | Change and check documents resolve symbols through the loaded A2L | F-01 (`app.py:6800`, `:7106`, `:7432`), T-03 (`change_service.py:3224`), T-04 (`variant_execution_service.py:2557`), T-12 if E1's census puts it in these files | new (S8, S9) | `tui/app.py`, `tui/services/change_service.py`, `tui/services/variant_execution_service.py` | none | M | 3 (`app.py` chain) | 7, 11, 13, 14 |
| 5 | Check Editor write and reload keep picks, names and expected bytes | F-26 (= **D9-12**), F-27 (names re-resolved from the loaded A2L by address; **no** wire-grammar change), **D9-11** (co-located in `load_spec`) | R-CHKED-010, R-CHKED-025, -026; new S9 row for names | `tui/app.py`, `tui/screens_directionb.py` | none | M | 4 | 7, 8, 11, 13, 14 |
| 6 | Patch Editor document lifecycle | F-06 (= **D10-25**, **D9-15**), F-40 (= **D9-10**; **D10-30** co-located in the load tail), F-05 (= **D14-14**), F-47 (reproduce with the ch17/18 driver; fix only a reproduced cause) | R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-031, -040, R-CHK-PE-008…012, R-CHKS-001/004/009, R-TUI-049.3, R-BEFORE-AFTER-REPORT-001.1, .11 | `tui/app.py`, `tui/services/change_service.py`, `tui/screens_directionb.py` (Checks tab no-run state) | none | M | 5 | 7, 8, 11, 14 |
| 7 | Before/after report names itself and its inputs; written reports carry whole hex windows | F-42 (= **D14-15**; the title part gets a new row), **F6-1** (BACKLOG-CODE HIGH, co-located: the written diff report cuts hex windows at 512 rows, against R-CMP-004) | R-BEFORE-AFTER-REPORT-001.24, R-CMP-004; new S14 row (title) | `tui/services/diff_report_service.py`, `tui/services/before_after_service.py` | none (report file; B3 goldens re-pinned) | M | 1 | 3–6, 8, 10–14 |
| 8 | Flow CRC block reads designer templates; external outputs stay current | F-28 (+ **D13-23** co-located), F-49 (+ **D15-17** co-located). E3 rules "overwrite" vs "rotate" for F-49; the recommendation is rotate | R-CRC-CONFIG-001.10, .11, R-FLOW-EXT.2; new S15 rows (template input, newest copy) | `tui/services/flow_execution_service.py`, `tui/operations/crc_config.py` (or `crc_designer_model.py`), `tui/workspace.py`, `tui/services/variant_execution_service.py` (only if the ref seam needs it) | none | M | 1; 4 if `variant_execution_service.py` is touched | 3, 5, 6, 7, 11, 13, 14 |
| 9 | Confirm re-run writes no stray report; a saved flow keeps its own name | F-45, F-46 | new (S15, S16) | `tui/app.py`, `tui/services/flow_execution_service.py`, `tui/flow_screens.py`, `tui/services/flow_persistence_service.py` | none | S–M | 6 (`app.py`), 8 | 7, 11, 13, 14 |
| 10 | Hex navigation, unload state, Split/Join focus | F-07 (= **D4-2**; **D4-6** co-located), F-13 (= **D5-17**; **D5-19**, **D5-27** co-located in `_apply_unload`), F-14 (= **D17-38**, **D6-21**), F-18, **SE5-12a-2** (BACKLOG-CODE, co-located in `_format_coexistence_status`) | R-TUI-018.1, .2, R-TUI-040.4, .11, .12, R-WS-LOADED.13, .14, .16, R-SEG-OPEN.6, R-SHELL-FOCUS.2; new S17 row for F-18 | `tui/app.py`, `tui/segment_split_view.py` | none | M | 9 (`app.py`), 13 (`segment_split_view.py`) | 7, 11, 14 |
| 11 | A2L validation and parsing | F-02 (= **D3-12**), F-03, F-39 (verification arm), F-21, F-29 | R-VAL-032; new S2/S3 rows (CURVE note, segment record shape, filter) | `validation/rules.py`, `tui/issues_view.py`, `tui/a2l.py` | none | M | 1 (unfreezes and re-freezes `rules.py` / `a2l.py`, TC-B94-18) | 2–10, 12–14 |
| 12 | Unreachable code; Reports viewer `esc` | F-33 (= **D7-10**), F-34 (= **D6-12**, first half), F-35 (= **D9-8**; **D16-6** co-located), F-51 | new S7 row (viewer `esc`) | `tui/screens.py`, `tui/app.py`, `tui/screens_directionb.py`, `tui/flow_screens.py` | none (only hidden widgets go) | S–M | 5, 6, 9, 10 | 7, 11, 13, 14 |
| 13 | CRC Designer and Split/Join stay responsive with a 10 MB image | F-23 (profile first), F-24 | new (S13, S17) | `tui/crc_designer_view.py`, `tui/segment_split_view.py` | none (no worker, no busy paint) | M–L | 1, 2 | 3–9, 11, 14 |
| 14 | Help, legend and README describe the shipped app | F-16 (≈ **D3-19**, the map-keys line only), F-37 (= **D7-26**), F-30, F-41, F-38 (= **D0-9**, **D0-10**, **D0-11** partly) | R-LEGEND-011, R-WHELP.12, .13, .14, R-DOC-README.2, .3, .4 | `tui/window_help.py`, `tui/legend.py` (plus `README.md` and `prototypes/cambios_10_12_2026/help_sections.md`, outside `s19_app/`) | none (text) | M | 1 | all except 1 |

**F-23 and R1-P1 targets.** Each timing arm is marked `serial_timing` and reports its margin (QC-TM).

| Target | Arm kind | Pass |
|---|---|---|
| CRC Designer template load → coverage recomputes | deterministic count | exactly **1** (today about 10) |
| Field-edit burst inside 150 ms → recomputes | deterministic (injected timer) | exactly **1** |
| CRC Designer recompute on the 10 MB demo image | serial timing, LAN host | ≤ **3 s** (today ≈ 10 s). A floor shown by the profile re-rules the target, with the profile cited |
| Split/Join join-fill preview on the 10 MB demo image | serial timing | ≤ **2.5 s** (today ≈ 25 s). Marks identical to the pinned per-byte result |
| Save project at the TC-B100-20 composition | serial timing | ≤ **0.8 s** run alone (≥ 20 % margin under 1 s). Otherwise the bound is re-ruled with the profile cited |

## (c) Prototype rounds

**None** (operator ruling). Every UI row is a known failed check in `p0/known-failed.md`, carried under `KF-101-*` for the next iteration.

## (d) Where each finding lands (each id exactly once)

| Finding | Lands in |
|---|---|
| Canon swap, TC records, D0-8 | Inc 1 |
| G-015, SR12b-7, SR12b-7b, R2-CI, CI deferral, QC-TM, QC-OR, QC-BC | Inc 2. QC-BC is also a standing E5 step; see Conventions |
| R1-P1, OBS-F2-1 | Inc 3 |
| F-01, T-03, T-04, T-12 | Inc 4. T-12 only if its site is in Inc 4's files; otherwise it stays in the backlog |
| F-26, F-27 | Inc 5 |
| F-05, F-06, F-40, F-47 | Inc 6 |
| F-42, F6-1 | Inc 7 |
| F-28, F-49 | Inc 8 |
| F-45, F-46 | Inc 9 |
| F-07, F-13, F-14, F-18, SE5-12a-2 | Inc 10 |
| CI dwell flake `test_tc_b97_64` | Inc 2 |
| F-02, F-03, F-21, F-29, F-39 | Inc 11 |
| F-33, F-34, F-35, F-51 | Inc 12 |
| F-23, F-24 | Inc 13 |
| F-16, F-30, F-37, F-38, F-41 | Inc 14. The text is fixed to match the app; F-30's A2L prefill and F-41's HTML twin are not built |
| F-04, F-08–F-12, F-15, F-17, F-19, F-20, F-22, F-25, F-31, F-32, F-36, F-48, F-50, UX-I-01 … UX-I-20 (37) | **Known failed → backlog** (`p0/known-failed.md`, rows KF-101-L/S/Q/V/M/P/F/K). Operator ruling |
| F-43 | **Deferred past v1.0.0.** A limitation: the Checks addendum lists the declared fields correctly; verdict columns would be a new report feature. Guide ch21.6 states it, and Inc 14 removes any help claim beyond it |
| F-44 | **Deferred past v1.0.0.** A limitation, L-sized: three composers plus goldens. Guide ch21.11 states it. Inc 14 corrects any help line that promises HTML for these reports |
| F-15 (perf half) | Deferred with the UI rows. Its target is written in `known-failed.md` |

**CODE-CHANGES.md items that coincide with UI rows** stay with those rows in the backlog. Each is a new-canon row, which the next review should read:

| Item | Canon row | Known-failed row |
|---|---|---|
| D6-26 | R-SHELL-SETTINGS.5 | F-19 |
| D6-12, second half (`_toggle_settings_menu`) | — | F-19 |
| D13-13 | R-OPS-002.1 | F-31 |
| D10-40 (needs prototype) | — | F-04 |
| D7-30 (needs prototype) | — | F-11 (title row) |
| D16-14 | — | F-46-adjacent Clear question, UI |

**All other CODE-CHANGES.md items** (317 items in total) are **out of scope** for batch-101, because they are not in the batch objective and not co-located with an in-scope fix. They stay `open` in that file. The orchestrator may want to rule on two of them early:
- **D13-20:** the CRC engine takes `init` reflected when `reverse` is true. That is a **wrong result** for a non-symmetric init (R-CRC-ENGINE-001.1).
- **D14-10:** the Markdown diff report does not escape labels, paths or symbol names (R-CMP-004.9).

**Not done in batch-101, with reason:**
- F-50's Terminal-mode command execution is a new capability with an external-process security surface (C3). It stays with F-50 in KF-101-F.
- F-27's wire-grammar extension would be a one-way door for `.chk.json` files. Inc 5 re-resolves names instead, which can be undone.
- D0-11's "Operations runs `crc` only" depends on D13-13, which is out of scope. Inc 14's README therefore says the two other operations are listed but not implemented.

## (e) Order of work

| Wave | Increments | Notes |
|---|---|---|
| **Now** | **Inc 1** (the re-write session's branch) ∥ **Inc 2** (E1–E4) | Disjoint files. Inc 2 merges after Inc 1. Inc 2 first reads run 41372953464's FAILED set against the 5 known failures (still `in_progress` at P0; `snapshot` = success) and records it at `evidence/ci/41372953464.txt` |
| Once Inc 1's row ids are frozen | E1 of **Inc 11** and **Inc 14** may start | They cite canon ids. Code merges only after Inc 1 is on `main` |
| After Inc 1 + Inc 2 merge | **Inc 3** (head of the `app.py` chain) ∥ **Inc 7** ∥ **Inc 8** ∥ **Inc 11** ∥ **Inc 13** ∥ **Inc 14** | Disjoint sources. At most 3 Kimi E4 lanes in flight. If Inc 8 needs `variant_execution_service.py`, it waits for Inc 4 |
| `app.py` chain, serial | **3 → 4 → 5 → 6 → 9 → 10 → 12** | One `app.py` writer at a time. Inc 9 also waits for Inc 8. Inc 10 waits for Inc 13 |
| Close | Batch-end battery on the LAN host; CI on push; P4 re-checks batch-100's gaps G-005, G-007, G-008, G-013 | — |

**Merge gate per increment:**
- The full suite on the LAN Linux host: `pytest -n 8 -m "not serial_timing"`, then `-m serial_timing` serially. About 1 h.
- Then push, and compare CI's FAILED set with the previous run.
- TC records are regenerated from the junit of that run (Inc 1's generator).

## (f) Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| The canon swap changes the id space under the flow's validator and the registry guard (V-rules, `tests/test_id_registry.py`, `AT-TC-REGISTRY.jsonl`) | high | D0-8 is in Inc 1. Run `devflow-validate --brief` right after Inc 1 merges, and add no defect increment until it shows no new BLOCK |
| `app.py` is in 7 of 14 increments (about 20,500 lines). Batch-100's postmortem asks for an ADR on splitting it before a batch that touches ≥ 4 `app.py` areas | certain | **Decision: the ADR is deferred to before batch-102.** A split inside release hardening is a large refactor. Edits stay local, one `app.py` writer at a time, QC-BC at each E5 |
| Inc 11 unfreezes `rules.py` / `a2l.py` (TC-B94-18); engine output changes for every A2L | medium | A planned unfreeze, re-frozen at Inc 11's close. B1 census: `RECOGNIZED_A2L_BLOCKS`, `test_synth_release_case.py`, the issues triage tests |
| Inc 7 changes the before/after goldens (B3: `tests/goldens/batch35/at054b-before-after-report.{md,html}`) | certain | The golden re-pin is named in E1. Diff-report goldens stay byte-identical (default title unchanged) |
| F-49's fix changes what the project folder holds (backlog A-01: writers bypass the manifest writer) | medium | E3 rules rotate vs overwrite against A-01, through the existing placement API |
| F-23 / R1-P1 targets may need a worker, which would be UI | medium | Profile first. A floor above the target re-rules it with the profile cited; the worker variant goes to the KF review. A bound is never raised blind |
| Kimi K2.8 is the only worker (DeepSeek paused) | medium | At most 3 E4 lanes. Opus reviews every E4. Kimi records stay drafts until the orchestrator's V-check |
| The operator wants a UI-row fix in v1.0.0 after all (flags: F-15, F-25, F-36, UX-I-13, UX-I-10, UX-I-12, UX-I-03) | operator decision | Flagged in the P0 reply. The plan changes only on a ruling |
| F-47 cannot be reproduced | medium | No product change without a reproduced cause; carry it with the driver evidence |
| The P0 validator run already shows 4 BLOCKs: V20, the derived `_derived/ATLAS-*.md` files differ from the corpus | certain | The orchestrator regenerates with `--atlas --write` before the P0 gate, or rules on them |
