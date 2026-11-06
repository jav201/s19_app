# Inc 9 — E1 rulings: scope, canon changes, decisions

Base `98d94d7`. Rows: `01-requirements.md`. Slice: `E1-slice.md`. Evidence of the reproductions: `evidence-e1/i9e1-pilot-transcript.txt` (script `evidence-e1/i9e1-pilot.py`; Linux, Python 3.11, worktree at `98d94d7`, home, XDG and LOCALAPPDATA folders isolated under the run folder, no clipboard use).

## 1. Scope

**In:**
- **F-45** — a confirm re-run in Flow Execution writes a chain-set report that records `Mode: sequential`, `Chains: 1`. Reproduced (B): after a parallel Run of 3 lanes and a Confirm of the waiting lane, `reports/` holds 2 chain-set reports: `Mode: parallel`, `Chains: 3` (3 ledger rows) and `Mode: sequential`, `Chains: 1` (1 ledger row). Cause: `app.py:4514-4519` re-runs the one lane through `run_chain_set(..., mode="sequential")`, and `run_chain_set` writes the report with the dispatch mode (`flow_execution_service.py:2089-2090`, `compose_chain_set_report` `:2145`).
- **F-46** — a flow saved after Clear holds the previous flow's name. Reproduced (B): load `patch_chain`, Clear (the ribbon still reads `Flow: patch_chain`; Save… opens with `patch_chain`), add a LOAD, Save as `tune_b` → `flows/tune_b.json` holds `"name": "patch_chain"`. Causes: `save_flow_json` serializes the display name (`flow_persistence_service.py:1032`), and Clear keeps `_flow_name` (`flow_screens.py:2555-2566`). The name is not only cosmetic: a Flow Execution lane runs the loaded `Flow` with its embedded name, so a REPORT block in that lane writes `# Flow report — tune\_a` for a lane loaded from `tune_b.json` (B); the clash file `tune_b_2.json` also holds the old name (B); the load question names the stale flow (`flow <flow name>`, S5 CTX-LOADQ; R).
- **D15-18** — a `flows/` or `flowsets/` link lets a save land outside the work area. Reproduced (B): with `flows/` and `flowsets/` symlinked to folders outside the work area, `save_flow_json` and `save_chain_set` each write their file there. The shared destination guard `_guarded_destination` refuses both homes (B), and the flow Import already refuses the linked `flows/` through `copy_into_workarea` (B). A second shape found at E1 (B): a plain `flows/` holding a link `z.json` whose target is missing outside the work area — `save_flow_json(…, "z")` creates the target, while the guard on the home passes (D-6).
- **A16-4** (BACKLOG-CODE, routed by Inc 16) — the `flow_screens.py` module docstring (`:5-10`, `:32-33`) says the module calls no service and imports only the flow-model data types; the module imports `services/flow_persistence_service` (`:119`) and calls it at `:824`, `:2235`, `:2267`, `:2273` (AST census at `98d94d7`: `.services.flow_persistence_service`, `.services.flow_model`, `.changes.model`, `.workspace`, `..validation`, `..utils`, `.insight_style`, `.os_clipboard_input`; no `flow_execution_service`).

**Out (with reason):**
- D15-15 (lowest free `_<N>` from 1; the code starts at 2) — co-located in `save_flow_json` / `save_chain_set`, not in the plan row, and it renames saved files (D-9). The new tests compare `name` with the file stem, never with `_2`.
- D16-14 (ask `Discard unsaved flow edits?` before Clear) — a UI row of the known-failed backlog (KF-101).
- D16-16, D16-18 (Run's set name, the report path in the run log) — not in the plan row; R-FX-RUN.14 and .13 keep their status.
- Help text `window_help.py:310` ("Clear — empties the chain, its variables and the clipboard.") stays true and is not edited: a fifth source file.

## 2. Changes to existing canon rows and notes

| Row or note | Change | Reason |
|---|---|---|
| R-FLOW-FILE.11 | `If the flows home resolves to a folder outside the work area, …` → `If the flows home passes through a link or resolves to a folder outside the work area, …` | The guard D15-18 names (the manifest write's, S11 R-MAN-WRITE-001.5, `_guarded_destination`) refuses every link between the work area and the home, also one that stays inside the project; Inc 6's E3 ruling S-3 made that the one rule for picks and writes. The row states what the guard does, so a test of a link that stays inside can be judged. |
| R-FLOW-SET.7 | as R-FLOW-FILE.11, for the flowsets home | as R-FLOW-FILE.11 |
| CTX-FLOWREPORT, chain-set report | the `Mode` line lists its values: `sequential` or `parallel` for a run of the set, `confirm re-run` for a confirm re-run | R-FLOW-CHAIN.20 gives the confirm re-run its own mode; the note listed no values |
| CTX-CHAIN | new term "confirm re-run" | R-FLOW-CHAIN.19, .20 cite it |
| CTX-FLOWFILE | new terms "file stem", "link", "passes through a link", "exists"; the two status texts | R-FLOW-FILE.11 … .14, R-FLOW-SET.7, .8, R-FB-SAVE.8, R-FX-SET.15 cite them |

No other canon row changes. Cited and unchanged: R-FLOW-CHAIN.9, .11, .14, .18, R-FX-RUN.14 (the confirm re-run's report uses the typed set name — true today and kept), R-FLOW-FILE.1, .2, .10, R-FLOW-SET.1, .3, R-FB-RUN.6, R-FB-SAVE.4, .5, .6, R-FX-SET.4, R-MAN-WRITE-001.5.

## 3. Decisions (each with the recommendation the rows follow)

| # | Question | Options | Recommendation and reason | Orchestrator? |
|---|---|---|---|---|
| D-1 | What does a confirm re-run write to `reports/`? | **A** no chain-set report (the plan title's literal reading); **B** a report of the whole set, the other lanes' last outcomes merged in; **C** a report of that lane alone that records `- **Mode:** confirm re-run` | **C.** A drops the only report that records a confirmed lane's completion: a new Run clears every confirmation (`render_run`, `flow_screens.py:4013`), so a lane with an external step could never reach a chain-set report again, and S16 R-FX-RUN.14 (approved canon) names "the report of … a confirm re-run". B mixes the outcomes of two runs (elapsed values, lanes imported or rebound after the Run) and needs the panel's last record in the app. C is one mode token: 0 existing assertions change (TC-B97-55 counts 1 new report and keeps it). Under A, `test_tc_b97_55_confirm_rerun_is_one_run_at_a_time` changes its assertion (`new == 1` → `0`) and R-FX-RUN.14 loses its second half. | **yes** |
| D-2 | Does Clear reset the flow name (R-FB-RUN.8)? | reset to `flow`; keep the name | **Reset.** The file is fixed by R-FLOW-FILE.12 either way, but after Clear the ribbon, the Save dialog's suggestion and the load question still name the old flow, and accepting the suggestion saves `patch_chain_2.json` for a new chain. `flow` is the name the Builder starts with (`flow_screens.py:1535`). Visible change: the ribbon text after Clear (the defect becoming correct); no layout, widget or key changes. | **yes** (a screen text changes) |
| D-3 | A file stem longer than 64 characters (the file format's name limit) | cut the `name` to 64 (R-FLOW-FILE.13); refuse the save with a new status | **Cut.** Identity is the file name (`flow_persistence_service.py:407`); the cut keeps the file loadable and adds no message. Today the same file is already unloadable when a long stem was loaded and saved again (B: `FLOW-BAD-FIELD`). | no |
| D-4 | Flow files saved before Inc 9 with a stale `name` | leave them; or run a lane under its template's stem | **Leave**, backlog row BL-I9-1: a lane's flow report title still reads the embedded name of an old file. Repairing it changes the run path (`run_chain_set._run_one`) for every lane. | no |
| D-5 | The chain-set file's `name` (the raw typed text, `app.py:4552`) | leave; write the file stem | **Leave**, backlog row BL-I9-2: no reader uses it (the load uses the stem, `app.py:4604`); not in the plan row. | no |
| D-6 | A link in the home named like the file to write (found at E1) | include R-FLOW-FILE.14, R-FLOW-SET.8; leave to the backlog | **Include.** Same actor and outcome as D15-18 (a write lands outside through a link); the home guard does not see it (B). The fix is the house claim: a name is taken when any entry of that name exists (`os.path.lexists`), and the file is created exclusively (`open(…, "x")`), a lost race moving on to the next name. It needs no new message. | **yes** (scope beyond the D15-18 text) |
| D-7 | Reading through a linked `flows/` or `flowsets/` (the Load list, Load, Import… list, Load Set) | refuse; leave | **Leave**, backlog row BL-I9-3: D15-18 is about saves; loads are fail-closed and re-check every ref. | no |
| D-8 | A16-4: the `flow_screens.py` docstring | rewrite the two sentences to the measured imports; or a ruling only | **Rewrite** (the smallest true statement), no requirement row: a docstring is not behaviour. `flow_screens.py` is in the slice for R-FB-RUN.8, so it costs no file. E5 check: 0 occurrences in `flow_screens.py` of `services never called directly`, `the one declared data edge` and `No engine code is imported beyond`; the new text names `flow_model` and `flow_persistence_service` and states that the module never calls the executor. | no |
| D-9 | D15-15 (numbering from 1) | take; leave | **Leave**: not in the plan row, it renames saved files; tests do not pin `_2`. | no |
| D-10 | How a save reports a refused home | the save functions raise `WorkareaContainmentError` (the guard's own error, as `import_flow_file` already does) and the two app handlers show the status; or return `None` | **Raise.** `None` already means "empty name" (R-FB-SAVE.6, R-FX-SET.4); one value for two causes would give the wrong status. | no |

## 4. Reproductions (numbers)

| Finding | Reproduced? | Numbers (B) |
|---|---|---|
| F-45 | yes | 1 report from Run (`Mode: parallel`, `Chains: 3`, 3 ledger rows); +1 from the confirm (`Mode: sequential`, `Chains: 1`, 1 ledger row); lane statuses after the confirm `completed-with-issues`, `ok`, `completed-with-issues` |
| F-46 | yes | ribbon after Clear `Flow: patch_chain`; Save dialog prefill `patch_chain`; `flows/tune_b.json` `name` = `patch_chain`; clash file `tune_b_2.json` `name` = `tune_a`; a lane of `tune_b.json` (`name` `tune_a`) with a REPORT block writes `# Flow report — tune\_a`; a 70-character `name` loads with `FLOW-BAD-FIELD` |
| D15-18 | yes | linked `flows/`: `x.json` lands outside (True); linked `flowsets/`: `s.json` lands outside (True); `_guarded_destination` refuses both homes; Import through the linked `flows/` refused; a dangling link `flows/z.json`: the save creates the outside target (True) while the guard on the plain home passes |

## 5. Interfaces with other increments

- **Inc 6** (in flight, `b101-inc6`, E4; merges first). Its `app.py` functions (`_resolve_listed_file`, `_patch_editor_load`, `_check_home`, `_spec_homes`, … 30 by an AST map of its diff, `E1-slice.md` §4) and Inc 9's three (`on_flow_builder_panel_save_requested`, `on_flow_execution_panel_external_step_confirmed`, `on_flow_execution_panel_save_requested`) are disjoint; Inc 9 makes no module-level change in `app.py` (`WorkareaContainmentError` is already imported, `:289`). Inc 6's E3 ruling S-3 names Inc 9: Inc 9 reuses the Write guard `workspace._guarded_destination` (which walks `_path_traverses_reparse_point` / `_is_reparse_point` from the work area down) as it is, and changes no helper of `workspace.py`. Inc 6 also edits `docs/user-guide/DOSSIER.md` (rows F-05, F-06, F-40, F-47); Inc 9's rows F-45, F-46 follow the marker Inc 6 lands.
- **Inc 8** (merged): `run_chain_set` and `compose_chain_set_report` keep `ChainRunOutcome.in_place_inputs` and `FlowRunResult.in_place_reads` (its I-6); only the accepted mode tokens change.
- **Inc 12** (later; `flow_screens.py`): the module docstring after Inc 9 states the measured imports; a change of imports there updates it.
- **Inc 15** (merged): `_rebind`, the `settled` helper and the bind observable of `tests/test_tui_flow_execution_b94.py` are not touched; no node is affected.
- **Inc 16** (merged): `docs/architecture.md` §10 reads `not declared` for `flow_screens.py` imports; the new docstring cites no section, so no guard of Inc 16 is involved (its E5 ruling C-5).
- **Docs (not source, written at E4):** `docs/user-guide/ch18-flow-execution.md:111-113` (the confirm's report records `confirm re-run`; drop "(finding F-45)"); `docs/user-guide/ch17-*.md:150` may add that Clear also resets the name to `flow`; `docs/user-guide/DOSSIER.md:754-755`.

## 6. Backlog rows proposed (for the batch end)

- **BL-I9-1** (D-4): flow files saved before Inc 9 may hold another flow's `name`; a Flow Execution lane's flow report is titled with it.
- **BL-I9-2** (D-5): a chain-set file's `name` is the raw typed text (not the stem; over 64 characters it makes the file unloadable, `flow_persistence_service.py:1302`).
- **BL-I9-3** (D-7): the Load, Import… and Load Set lists and loads read through a linked `flows/` or `flowsets/`.
- **BL-I9-4**: between the home guard and the exclusive create a link can still be swapped in for the home (the TOCTOU residual every guarded write of the app has; Inc 8b backlog).

## Orchestrator rulings on E1 decisions (2026-11-06)

Taken under the operator's standing commission (decide with a recorded reason).

- **D-1 → C.** The confirm re-run keeps its chain-set report and records `- **Mode:** confirm re-run`. Why: option A (no report) leaves a lane that passed an external step out of every chain-set report and cuts half of R-FX-RUN.14; C removes the defect (a report that misstates mode and chains) without losing evidence, and TC-B97-55's assertion stays.
- **D-2 → no.** Clear does not reset the ribbon name in this increment; the file fix (the saved `name` is the file's stem) stands without it. The stale ribbon text after Clear is a backlog row with the UI rows (KF-101 family). Why: it changes visible text, and the operator's P0 ruling keeps UI changes out of batch-101; the saved-file defect is fixed either way.
- **D-6 → yes.** Add R-FLOW-FILE.14 and R-FLOW-SET.8: no write through a link that carries the file's own name (a dangling link included); the save claims the name with an exclusive create. Why: the E1 pilot showed a dangling `flows/z.json` link makes the save create a file outside the work area, which the folder guard misses; Inc 6 uses the same free-name claim (`lstat` + `O_EXCL`).
