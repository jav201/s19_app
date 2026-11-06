# Code-Wire graph — Inc 9 (confirm re-run report, saved flow names, flow and chain-set saves inside the work area), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `98d94d7`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (the Code-Wire repository's `docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md` and `../../inc-8/codewire/graph-inc8.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because a changed node calls them, or because their examples are the oracle of a row.
- Example sources are the case ids of `02-test-cases.md`; `B` = the E1 pilot on the base tree (`../evidence-e1/i9e1-pilot-transcript.txt`). Every example states the Inc 9 target unless it says "holds on base".
- `<W>` = `<tmp>/.s19tool/workarea/p` (Project W), `R` = `<tmp>/.s19tool/workarea`, `<O>` = `<tmp>/outside` (Folder O). `F1` = `Flow(name="a", blocks=[SourceBlock("prg.s19")])`. `C1` = the one-lane chain set of `02-test-cases.md`.
- The graph follows the recommended options of `../E1-rulings.md` §3: D-1 C, D-2 reset, D-3 cut, D-6 include, D-8 rewrite, D-10 raise. If the orchestrator rules otherwise, the nodes marked with that decision change and nothing else.

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 services | `s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/services/flow_persistence_service.py`; tests `tests/test_b101_flow_saves.py` (tester G-T1) | `[Data: CHAIN_RUN_CONFIRM_RERUN]`, `run_chain_set`, `save_flow_json`, `save_chain_set` |
| G2 app and Builder | `s19_app/tui/app.py`, `s19_app/tui/flow_screens.py`; tests `tests/test_b101_flow_names_ui.py` (tester G-T2, also the three ATs) | `S19TuiApp.on_flow_execution_panel_external_step_confirmed`, `S19TuiApp.on_flow_builder_panel_save_requested`, `S19TuiApp.on_flow_execution_panel_save_requested`, `FlowBuilderPanel.on_button_pressed`, `[Doc: flow_screens module docstring]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 confirm mode token | `flow_execution_service.CHAIN_RUN_CONFIRM_RERUN = "confirm re-run"`; `run_chain_set(chains, ctx, mode=CHAIN_RUN_CONFIRM_RERUN, set_name=…)` runs the lanes in order and returns `record.mode == "confirm re-run"`; `CHAIN_RUN_MODES` stays `("sequential", "parallel")`; any other token raises `ValueError` as today | G1 → G2 (the confirm handler) |
| I-2 save calls | `save_flow_json(flow, raw_name, project_dir, *, workarea_root: Optional[Path] = None) -> Optional[Path]` and `save_chain_set(chain_set, raw_name, project_dir, *, workarea_root: Optional[Path] = None) -> Optional[Path]`: `None` = nothing to save (empty name; for a set also no lane), unchanged; **raises `WorkareaContainmentError`** when the home is refused, before any folder or file is created (D-10); otherwise returns the plain file it created | G1 → G2 (the two save handlers), tests |
| I-3 refusal statuses | `Flow not saved - the project's flows folder is a link or is outside the work area.` · `Chain set not saved - the project's flowsets folder is a link or is outside the work area.` — through `S19TuiApp.set_status`, nothing else painted | G2 |
| I-4 start name | `"flow"`: the name `FlowBuilderPanel.__init__` gives (`flow_screens.py:1535`) and Clear gives (R-FB-RUN.8) | G2 |
| I-5 the shared guard | `workspace._guarded_destination(destination, workarea_root=None) -> (resolved_destination, resolved_root)`, unchanged; raises `WorkareaContainmentError`. The same helpers (`_path_traverses_reparse_point`, `_is_reparse_point`) serve Inc 6's pick guard and Write guard (Inc 6 E3 ruling S-3); Inc 9 changes none | `workspace.py` (not edited) → G1 |
| I-6 Inc 8 fields | `ChainRunOutcome.in_place_inputs`, `FlowRunResult.in_place_reads` (Inc 8's I-6) kept as they are | `run_chain_set` (G1) |

Order inside E4: G1 and G2 in parallel; G2's app cases need G1's I-1 and I-2 at integration.

## Nodes

run_chain_set
req: R-FLOW-CHAIN.19, R-FLOW-CHAIN.20
in: Sequence[ChainSpec] chains; FlowContext ctx; str mode = "sequential"; str set_name = "chain-set"; Callable? run_one = None; Callable? clock = None
out: ChainSetRunRecord record
func: changed. was: `mode` not in `CHAIN_RUN_MODES` raises `ValueError`; an empty set returns the record with `no chains in set - nothing was executed`; a WRITE-OUT name clash refuses the set; `parallel` runs every lane in a thread pool, any other mode in lane order; then `write_chain_set_report(record, set_name, ctx.project_dir)` (a failure recorded as `chain-set report write failed: …`). / now: the same, except that the check also accepts `CHAIN_RUN_CONFIRM_RERUN`, which runs the lanes in order like `sequential` and stays in `record.mode`, so the report records it (D-1 C).
module: s19_app/tui/services/flow_execution_service.py
examples: (R-FLOW-CHAIN.20/1, service half) chains [flash_chain spec], ctx with block 2 confirmed, mode "confirm re-run", set_name "fx" → record.mode "confirm re-run", 1 outcome, record.report_path names a report holding `- **Mode:** confirm re-run`
examples: (R-FLOW-CHAIN.19/1, holds on base) the same call with mode "sequential" (the base handler) → 1 outcome, 1 report with `- **Chains:** 1` (B)
examples: (R-FLOW-CHAIN.20/1 neg) mutant: the token mapped to "sequential" before it reaches the record → the report holds `- **Mode:** sequential` → RED
examples: (holds on base) mode "diagonal" → raises ValueError("unknown chain-run mode 'diagonal'")
examples: (R-FLOW-CHAIN.14, holds on base) 3 chains, mode "parallel" → record.mode "parallel", report `- **Mode:** parallel`, `- **Chains:** 3` (B)

compose_chain_set_report
req: R-FLOW-CHAIN.20
in: ChainSetRunRecord record; str set_name; datetime generated_at
out: str markdown
func: unchanged. Header lines `# Chain-set report — <set name>`, `- **Generated:** …`, `- **Mode:** <record.mode>` (`:2145`), `- **Chains:** <len(record.outcomes)>`, then the Chain ledger and the sections of CTX-FLOWREPORT. The oracle of the Mode line: it prints `record.mode` verbatim.
module: s19_app/tui/services/flow_execution_service.py
examples: (R-FLOW-CHAIN.20/1) record.mode "confirm re-run", 1 outcome `flash_chain` → lines `- **Mode:** confirm re-run`, `- **Chains:** 1`, one ledger row `| 1 | flash\_chain | flash\_chain | ✓ ok | 4 | <elapsed>s |` (the Chain and Template cells through `md_safe`)
examples: (R-FLOW-CHAIN.19/1, holds on base) record.mode "sequential", 1 outcome → `- **Mode:** sequential`, `- **Chains:** 1` (B)

S19TuiApp.on_flow_execution_panel_external_step_confirmed
req: R-FLOW-CHAIN.19, R-FLOW-CHAIN.20
in: FlowExecutionPanel.ExternalStepConfirmed event
out: None
func: changed. was: no project → `render_confirm_error`; a lane that no longer waits there → the refused line; else one `ChainSpec` of that lane, one `ExternalStepConfirmation` per confirmed block, `run_chain_set(chains, ctx, mode="sequential", set_name=<typed #fx_set_name>)` (`app.py:4514-4519`); a raise → `render_confirm_error(lane, fx_run_error_line(exc))`; else `apply_confirmed_run`. / now: the same, with `mode=CHAIN_RUN_CONFIRM_RERUN` (I-1), imported in the handler beside `ChainSpec` and `run_chain_set`.
module: s19_app/tui/app.py
examples: (R-FLOW-CHAIN.19/1) Set P after Run, lane 1 waits at block 3, Evidence written; press `#fx_confirm_1` → exactly 1 new `*-chain-set-report.md`, with `- **Chains:** 1` and 1 ledger row `flash_chain`
examples: (R-FLOW-CHAIN.20/1) the same → the new report holds `- **Mode:** confirm re-run`, 0 lines `- **Mode:** sequential`; the Run's report keeps `- **Mode:** parallel` (base: `- **Mode:** sequential`, B)
examples: (R-FLOW-CHAIN.20/2) Set S after Run, lane 1 waits; press `#fx_confirm_1` → new report `- **Mode:** confirm re-run`; the Run's report `- **Mode:** sequential`
examples: (AT-I9-1) keys only: `enter` on the mode switch to `parallel`, `enter` on Run, Evidence, `c` after the dwell → 2 new reports, modes `parallel` (Chains 3) and `confirm re-run` (Chains 1)
examples: (TC-B97-55, holds) a second Confirm and a Run pressed during the re-run → 1 post, 1 `run_chain_set` call, 1 new report

S19TuiApp.on_flow_execution_panel_run_requested
req: R-FLOW-CHAIN.20
in: FlowExecutionPanel.RunRequested event
out: None
func: unchanged. Runs the lanes with the switch's mode (`app.py:4415-4420`), so a set run's report keeps `sequential` or `parallel`.
module: s19_app/tui/app.py
examples: (R-FLOW-CHAIN.20/1, holds on base) Set P → one report `- **Mode:** parallel`, `- **Chains:** 3` (B)

FlowExecutionPanel.apply_confirmed_run
req: R-FLOW-CHAIN.19
in: int lane_index; ChainSetRunRecord record
out: str? failed
func: unchanged. Reads `record.outcomes[0]` into the lane and appends the re-run's log lines; never reads `record.mode` or `record.report_path`.
module: s19_app/tui/flow_screens.py
examples: (R-FLOW-CHAIN.19/1, holds on base) the confirm's record → lane 1 status `ok`, log line `… · re-run after confirming the external step (block 3/4)` (B: lane statuses `completed-with-issues`, `ok`, `completed-with-issues`)

save_flow_json
req: R-FLOW-FILE.11, R-FLOW-FILE.12, R-FLOW-FILE.13, R-FLOW-FILE.14
in: Flow flow; str raw_name; Path project_dir; Path? workarea_root = None
out: Path? written
func: changed. was: `clean = sanitize_project_name(raw_name)`, `None` → return `None`; `flows_dir.mkdir(parents=True, exist_ok=True)`; target `<clean>.json`, while `target.exists()` (follows links) try `<clean>_2.json`, `_3`, …; `target.write_text(json.dumps(flow_to_dict(flow), indent=2), encoding="utf-8")`. / now: `clean` as before (`None` → `None`, nothing created); then `_guarded_destination(flows_dir, workarea_root)` (I-5) before the `mkdir` — a refusal propagates as `WorkareaContainmentError` (D-10); a candidate (`<clean>.json`, `<clean>_2.json`, …) is taken when `os.path.lexists(candidate)` (a file, a folder or a link, also a dangling one); the free candidate is created with `open(candidate, "x", encoding="utf-8")` (exclusive; a `FileExistsError` from a lost race moves on to the next candidate) and receives `json.dumps(flow_to_dict(replace(flow, name=candidate.stem[:FLOW_MAX_NAME_LEN])), indent=2)` — text mode, so the same bytes as `write_text` for the same payload. No new writer function: the TC-B99-13 census pins write sites to this function.
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-FILE.12/2) <W> holding flows/tune_b.json; flow `Flow(name="tune_a", …)`, raw_name "tune_b" → written flows/tune_b_2.json with `"name": "tune_b_2"` (base: `"tune_a"`, B)
examples: (R-FLOW-FILE.12/3) F1, "Nightly Release!  " → flows/NightlyRelease.json, `"name": "NightlyRelease"` (base: `"a"`)
examples: (R-FLOW-FILE.12/4) F1, "A" × 64 → `"name"` = "A" × 64; `load_flow_json` → 0 findings
examples: (R-FLOW-FILE.13/1) F1, "B" × 65 → flows/<"B"×65>.json, `"name"` = "B" × 64; `load_flow_json` → 0 findings
examples: (R-FLOW-FILE.13/2) <W> holding flows/<"C"×64>.json; F1, "C" × 64 → flows/<"C"×64>_2.json, `"name"` = "C" × 64; 0 findings
examples: (R-FLOW-FILE.13/1 neg) mutant: `name=candidate.stem` uncut → `load_flow_json` → [FLOW-BAD-FIELD `flow name exceeds 64 characters`] → RED
examples: (R-FLOW-FILE.11/1) <W>/flows = Link(→ <O>/flows); F1, "x", workarea_root R → raises WorkareaContainmentError; <O>/flows holds 0 files (base: x.json there, B)
examples: (R-FLOW-FILE.11/2) <W>/flows = Link(→ <W>/patches) → raises WorkareaContainmentError; <W>/patches unchanged
examples: (R-FLOW-FILE.14/1) plain <W>/flows holding the link z.json → <O>/dangling/z.json (missing); F1, "z" → <O>/dangling/z.json still missing; flows/z.json still the link; written flows/z_2.json, a plain file, `"name": "z_2"` (base: <O>/dangling/z.json created, B)
examples: (R-FLOW-FILE.14/2) the link z.json → <O>/z.json (bytes K) → <O>/z.json still K; written flows/z_2.json (holds on base: `exists()` follows the link to the file)
examples: (R-FLOW-FILE.3, holds on base) F1, "!!!" → `None`; flows/ not created
examples: (R-FLOW-FILE.12/1 neg) mutant: `flow_to_dict(flow)` (the base payload) → /2 gives `"tune_a"` → RED
examples: (R-FLOW-FILE.11/1 neg) mutant: the guard call removed → x.json lands in <O>/flows → RED

save_chain_set
req: R-FLOW-SET.7, R-FLOW-SET.8
in: ChainSet chain_set; str raw_name; Path project_dir; Path? workarea_root = None
out: Path? written
func: changed. was: no lane → `None`; `clean` `None` → `None`; `flowsets_dir.mkdir(...)`; `exists()` dedup from `_2`; `write_text(json.dumps(chain_set_to_dict(chain_set), indent=2), …)`. / now: the same checks; `_guarded_destination(flowsets_dir, workarea_root)` before the `mkdir`; `os.path.lexists` for a taken name; exclusive create as `save_flow_json`. The payload is unchanged (`chain_set_to_dict`; its `name` stays the typed text, D-5).
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-SET.7/1) <W>/flowsets = Link(→ <O>/flowsets); C1, "s", workarea_root R → raises WorkareaContainmentError; <O>/flowsets holds 0 files (base: s.json there, B)
examples: (R-FLOW-SET.7/2) <W>/flowsets = Link(→ <W>/patches) → raises WorkareaContainmentError
examples: (R-FLOW-SET.8/1) plain <W>/flowsets holding the link s.json → <O>/dangling/s.json (missing); C1, "s" → <O>/dangling/s.json still missing; written flowsets/s_2.json, a plain file
examples: (R-FLOW-SET.8/2) the link s.json → <O>/s.json (bytes K) → <O>/s.json still K; written flowsets/s_2.json (holds on base)
examples: (R-FLOW-SET.2, holds on base) a set with no lane → `None`; flowsets/ not created

_guarded_destination
req: R-FLOW-FILE.11, R-FLOW-SET.7
in: Path destination; Path? workarea_root = None
out: tuple(Path resolved_destination, Path resolved_root)
func: unchanged (I-5). Finds the outermost `.s19tool/workarea` anchor on the textual path (or takes `workarea_root`), walks every folder from the destination up to the anchor's parent for a link (`_path_traverses_reparse_point`, `stop_at=root.parent`) and checks `.s19tool` itself, then resolves both and requires containment. A missing destination passes the walk.
module: s19_app/tui/workspace.py
examples: (R-FLOW-FILE.11/1, holds on base) <W>/flows a link → raises (`Refusing to place: destination traverses a symbolic link or reparse point: …`) (B)
examples: (R-FLOW-SET.7/1, holds on base) <W>/flowsets a link → raises (B)
examples: (R-FLOW-FILE.14/1, holds on base) plain <W>/flows holding a file link → passes (B: the guard checks the folder chain, not the file)
examples: (R-FLOW-FILE.12/3, holds on base) <W>/flows missing → passes (returns the resolved pair)

flow_to_dict
req: R-FLOW-FILE.12
in: Flow flow
out: dict envelope
func: unchanged. `{"schema_version", "name": flow.name, "blocks", ["funnel"]}`. Also the serializer of the Builder's copy and paste (`flow_screens.py:2235`, `:2267`), which is why the name fix sits in `save_flow_json`, not here.
module: s19_app/tui/services/flow_persistence_service.py
examples: (holds on base) F1 → {"schema_version": 1, "name": "a", "blocks": [{"kind": "source", "image_ref": "prg.s19", "file_type": "s19"}]}

dict_to_flow
req: R-FLOW-FILE.13
in: dict payload; Path project_dir
out: tuple(Flow? flow, list[ValidationIssue] findings)
func: unchanged. Its V3 rule: `name` a non-empty string of at most 64 characters (`FLOW_MAX_NAME_LEN`), else `FLOW-BAD-FIELD`. The oracle of R-FLOW-FILE.13.
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-FILE.13/1 neg, holds on base) a `name` of 70 characters → [FLOW-BAD-FIELD `flow name exceeds 64 characters`] (B)
examples: (R-FLOW-FILE.13/1) a `name` of 64 characters → 0 findings

S19TuiApp.on_flow_builder_panel_save_requested
req: R-FLOW-FILE.11, R-FB-SAVE.8
in: FlowBuilderPanel.SaveRequested event
out: None
func: changed. was: no project → the FAILED card; else `SaveFlowScreen(event.flow.name, existing)`; `_do_save`: `None` → return; `saved = save_flow_json(event.flow, raw_name, project_dir)`; `None` → status `Flow name is empty after sanitising - not saved.`; else `panel.mark_saved(saved.stem)`. / now: `_do_save` calls `save_flow_json(event.flow, raw_name, project_dir, workarea_root=self.workarea)` inside `try`; `except WorkareaContainmentError` → `self.set_status("Flow not saved - the project's flows folder is a link or is outside the work area.")` and return, without `mark_saved` (I-2, I-3). The rest is unchanged.
module: s19_app/tui/app.py
examples: (R-FB-SAVE.8/1) Builder project; flows/ replaced by Link(→ <O>/flows); a LOAD added; Save…, `x`, Save → status line `Flow not saved - the project's flows folder is a link or is outside the work area.`; <O>/flows holds 0 files; the result area shows no `✓ saved` line
examples: (R-FLOW-FILE.12/1) Builder project, Clear, LOAD `prg.s19` added; Save…, `tune_b`, Save → flows/tune_b.json `"name": "tune_b"`; `mark_saved("tune_b")` (base: `"patch_chain"`, B)
examples: (R-FB-SAVE.6, holds on base) Save…, `!!!`, Save → status `Flow name is empty after sanitising - not saved.`
examples: (R-FB-SAVE.8/1 neg) mutant: the `except` shows the R-FB-SAVE.6 text → RED; mutant: no `except` → the refusal escapes the callback → RED

S19TuiApp.on_flow_execution_panel_save_requested
req: R-FLOW-SET.7, R-FX-SET.15
in: FlowExecutionPanel.SaveRequested event
out: None
func: changed. was: no project → status `No project loaded - load or save a project first.`; build `ChainSet(name=raw_name.strip() or "chain-set", chains=…)`; `saved = save_chain_set(chain_set, event.raw_name, project_dir)`; `None` → status `Chain set not saved - the set is empty or the name sanitised away.`; else `panel.mark_saved(saved.stem)` and `_prefill_flow_execution_sets()`. / now: `save_chain_set(…, workarea_root=self.workarea)` inside `try`; `except WorkareaContainmentError` → `self.set_status("Chain set not saved - the project's flowsets folder is a link or is outside the work area.")` and return, without `mark_saved` and without the list refresh.
module: s19_app/tui/app.py
examples: (R-FX-SET.15/1) FX project, lane `patch_chain`; flowsets/ = Link(→ <O>/flowsets); set name `s`, Save Set → status `Chain set not saved - the project's flowsets folder is a link or is outside the work area.`; <O>/flowsets holds 0 files; the ribbon keeps `· unsaved`
examples: (R-FX-SET.4, holds on base) no lane, Save Set → status `Chain set not saved - the set is empty or the name sanitised away.`
examples: (AT-I9-3) both refusals through the dialogs → the two status texts, 0 files in <O>

FlowBuilderPanel.on_button_pressed
req: R-FB-RUN.8
in: Button.Pressed event
out: None
func: changed (branch `flow_clear` only, `flow_screens.py:2555-2566`). was: empties `_blocks`, `_funnel`, `_clipboard`, the clip status, the notice, the pipeline frame's subtitle and the result; `_mark_dirty()` when the chain had blocks; `_flow_name` kept. / now: the same, and `self._flow_name = "flow"` (I-4) followed by `self._refresh_name_strip()` (so the ribbon shows it also when the chain was empty). The other branches are unchanged.
module: s19_app/tui/flow_screens.py
examples: (R-FB-RUN.8/1) `patch_chain` loaded; Clear → painted ribbon starts `Flow: flow` (base: `Flow: patch_chain`, B)
examples: (R-FB-RUN.8/2) then a LOAD added; Save… → `#flow_save_name` holds `flow` (base: `patch_chain`, B)
examples: (R-FB-RUN.6, holds on base) Clear → 0 blocks, 0 variables, clipboard empty, the empty result
examples: (R-FB-RUN.8/1 neg) mutant: the reset removed → `Flow: patch_chain` → RED

FlowBuilderPanel.current_flow
req: R-FB-RUN.8, R-FLOW-FILE.12
in:
out: Flow
func: unchanged. `Flow(name=self._flow_name, blocks=list(self._blocks), funnel=tuple(self._funnel))`; its name feeds the Save dialog's suggestion (`app.py:4021`), the Builder's Run and the load question's flow item (`app.py:8657`). After Inc 9 the saved file's `name` no longer depends on it.
module: s19_app/tui/flow_screens.py
examples: (R-FB-RUN.8/2) after Clear → name "flow"

run_flow
req: R-FLOW-FILE.12
in: Flow flow; FlowContext ctx
out: FlowRunResult
func: unchanged. A REPORT block writes `# Flow report — <flow.name>` (`flow_execution_service.py:1257`); a Flow Execution lane runs the loaded `Flow`, so its title is the file's `name`. Context for why R-FLOW-FILE.12 matters beyond the file (and for BL-I9-1: older files keep a stale `name`).
module: s19_app/tui/services/flow_execution_service.py
examples: (holds on base) a lane loaded from flows/tune_b.json holding `"name": "tune_a"`, blocks LOAD + REPORT → `# Flow report — tune\_a` (B)
examples: (R-FLOW-FILE.12/1) after Inc 9, a lane of a file saved as `tune_b` → `# Flow report — tune\_b`

## Entities

[Data: CHAIN_RUN_CONFIRM_RERUN]
in: str
desc: new module constant of `flow_execution_service.py`, beside `CHAIN_RUN_SEQUENTIAL`, `CHAIN_RUN_PARALLEL`, `CHAIN_RUN_MODES` (`:1743-1745`): `"confirm re-run"`. The mode of a confirm re-run (CTX-CHAIN). Not a mode of the switch, so not in `CHAIN_RUN_MODES`.

[Doc: flow_screens module docstring]
desc: `flow_screens.py:1-42` (no requirement row, `../E1-rulings.md` D-8). was: "messages out, services never called directly; the one declared data edge `flow_screens → services/flow_model` is read-only constants/dataclasses per `docs/architecture.md` §10" (`:7-10`) and "No engine code is imported beyond the read-only flow-model data types" (`:32-33`), while `:35-42` already names a second edge. now: one statement of the measured edges — the panels post messages and never call the executor (`services/flow_execution_service`); the module reads `services/flow_model` (block and flow data types and constants) and `services/flow_persistence_service` (the wire serializer and the loader, for copy and paste, and the unsafe-ref finding code); no section of `docs/architecture.md` is cited for an import rule (§10 reads `not declared`). E5 check: 0 occurrences of `services never called directly`, `the one declared data edge` and `No engine code is imported beyond`.

[I/O: reports/ chain-set reports]
desc: `<project>/reports/<ts>-chain-set-report.md` (a same-second clash: `<ts>-<NN>-chain-set-report.md`). After a parallel Run and one confirm: two files, `- **Mode:** parallel` / `- **Chains:** 3` and `- **Mode:** confirm re-run` / `- **Chains:** 1`.

[I/O: flows home]
desc: `<project>/flows/`. Saved files: `<stem>.json` with `"name"` = the stem cut to 64. Refused when it, or a folder between it and the work area, is a link, or when it resolves outside the work area. A link inside it with a candidate's name is a taken name, never written through.

[I/O: flowsets home]
desc: `<project>/flowsets/`; the same rules as the flows home; the file's `"name"` is unchanged (the typed text).

[I/O: outside folder]
desc: any folder not under this work area (`<O>` in the cases). After Inc 9 no flow or chain-set save creates or changes a file there.

[Interface: status line]
desc: `#log_line_4` through `S19TuiApp.set_status`; carries the two refusal texts of I-3.

[Interface: Builder ribbon]
desc: `#flow_name_strip`: `Flow: <name>  · saved|· unsaved  …`; after Clear `<name>` is `flow`.

## Edges

S19TuiApp.on_flow_execution_panel_external_step_confirmed ──▶ run_chain_set
when: a waiting lane is confirmed (Confirm or `c`); mode = [Data: CHAIN_RUN_CONFIRM_RERUN]
[Data: CHAIN_RUN_CONFIRM_RERUN] ──▶ run_chain_set
run_chain_set ──▶ compose_chain_set_report
compose_chain_set_report ──▶ [I/O: reports/ chain-set reports]
run_chain_set ──▶ S19TuiApp.on_flow_execution_panel_external_step_confirmed
when: the record returns; then FlowExecutionPanel.apply_confirmed_run
S19TuiApp.on_flow_execution_panel_run_requested ──▶ run_chain_set
when: Run; mode = the switch's
S19TuiApp.on_flow_builder_panel_save_requested ──▶ save_flow_json
S19TuiApp.on_flow_execution_panel_save_requested ──▶ save_chain_set
save_flow_json ──▶ _guarded_destination
save_chain_set ──▶ _guarded_destination
save_flow_json ──▶ [I/O: flows home]
save_chain_set ──▶ [I/O: flowsets home]
save_flow_json ──▶ S19TuiApp.on_flow_builder_panel_save_requested
when: raises WorkareaContainmentError; then [Interface: status line]
save_chain_set ──▶ S19TuiApp.on_flow_execution_panel_save_requested
when: raises WorkareaContainmentError; then [Interface: status line]
FlowBuilderPanel.on_button_pressed ──▶ [Interface: Builder ribbon]
when: Clear
FlowBuilderPanel.current_flow ──▶ S19TuiApp.on_flow_builder_panel_save_requested
when: Save… (the dialog's suggestion)

## Findings

> E2-1 (for E3, D-1). The confirm re-run keeps a report and labels it. The alternative A (no report) would also satisfy the plan title, at the cost of the only chain-set record of a confirmed lane's completion and of half of R-FX-RUN.14; B (a merged whole-set report) mixes two runs. The graph changes one token and one check; under A, `run_chain_set` would instead gain a `write_report=False` keyword and TC-B97-55's assertion would change.
> E2-2 (for E3, D-6). `_guarded_destination` checks the folder chain only (B: it passes a plain `flows/` holding a file link). R-FLOW-FILE.14 / R-FLOW-SET.8 close the file name with `os.path.lexists` and an exclusive create; the race between the home guard and the create (a home swapped for a link) stays, as for every guarded write (BL-I9-4).
> E2-3 (for E3, D-10). The save functions raise the guard's own `WorkareaContainmentError` (as `import_flow_file` does through `copy_into_workarea`); `None` keeps its one meaning (nothing to save). Other `OSError`s of a save are not handled today and are not changed (out of scope).
> E2-4 (for E3, D-2). R-FB-RUN.8 changes a screen text (the ribbon after Clear, the Save dialog's suggestion, the load question's flow item); layout, widgets and keys are unchanged. Dropping it leaves the file fix intact.
> E2-5. Coverage of the requirement → node map: R-FLOW-CHAIN.19: `run_chain_set`, `S19TuiApp.on_flow_execution_panel_external_step_confirmed`, `compose_chain_set_report`, `FlowExecutionPanel.apply_confirmed_run`; R-FLOW-CHAIN.20: `[Data: CHAIN_RUN_CONFIRM_RERUN]`, `run_chain_set`, `compose_chain_set_report`, the confirm handler, `S19TuiApp.on_flow_execution_panel_run_requested`; R-FLOW-FILE.12: `save_flow_json`, `S19TuiApp.on_flow_builder_panel_save_requested`, `flow_to_dict`, `run_flow`; R-FLOW-FILE.13: `save_flow_json`, `dict_to_flow`; R-FB-RUN.8: `FlowBuilderPanel.on_button_pressed`, `FlowBuilderPanel.current_flow`; R-FLOW-FILE.11: `save_flow_json`, `_guarded_destination`, the Builder save handler; R-FLOW-SET.7: `save_chain_set`, `_guarded_destination`, the FX save handler; R-FLOW-FILE.14: `save_flow_json`; R-FLOW-SET.8: `save_chain_set`; R-FB-SAVE.8: the Builder save handler; R-FX-SET.15: the FX save handler. Every row has at least one concrete example.
