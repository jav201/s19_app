# Code-Wire graph — Inc 9 (confirm re-run report, saved flow names, flow and chain-set saves inside the work area), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `98d94d7`. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (the Code-Wire repository's `docs/Notation-Grammar.md`), as in `../../inc-2/codewire/graph-inc2.md` and `../../inc-8/codewire/graph-inc8.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because a changed node calls them, or because their examples are the oracle of a row.
- Example sources are the case ids of `02-test-cases.md`; `B` = the E1 pilot on the base tree (`../evidence-e1/i9e1-pilot-transcript.txt`). Every example states the Inc 9 target unless it says "holds on base".
- `<W>` = `<tmp>/.s19tool/workarea/p` (Project W), `R` = `<tmp>/.s19tool/workarea`, `<O>` = `<tmp>/outside` (Folder O). `F1` = `Flow(name="a", blocks=[SourceBlock("prg.s19")])`. `C1` = the one-lane chain set of `02-test-cases.md`.
- The graph follows the orchestrator's rulings (`../E1-rulings.md`, end; `../E3-rulings.md`): D-1 C, D-2 no (R-FB-RUN.8 withdrawn; Clear keeps the name), D-3 cut, D-5 the file stem (E3A-04), D-6 include with the check after the claim (E3 S-1, S-3), D-8 rewrite, D-10 raise.
- Numbering (E3A-05): `_<N>` is the next free name. Where an example writes `_2`, that is the base numbering (`_2` first, D-9), kept as one concrete example; tests compare `name` with the returned stem, never with `_2`.

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G1 services | `s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/services/flow_persistence_service.py`; tests `tests/test_b101_flow_saves.py` (tester G-T1) | `[Data: CHAIN_RUN_CONFIRM_RERUN]`, `run_chain_set`, `save_flow_json`, `save_chain_set`, `_create_new_json`; the TC-B99-13 census lists (`tests/test_b99_staging.py`, E3A-09) |
| G2 app and Builder | `s19_app/tui/app.py`, `s19_app/tui/flow_screens.py`; tests `tests/test_b101_flow_names_ui.py` (tester G-T2, also the three ATs) | `S19TuiApp.on_flow_execution_panel_external_step_confirmed`, `S19TuiApp.on_flow_builder_panel_save_requested`, `S19TuiApp.on_flow_execution_panel_save_requested`, `[Doc: flow_screens module docstring]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 confirm mode token | `flow_execution_service.CHAIN_RUN_CONFIRM_RERUN = "confirm re-run"`; `run_chain_set(chains, ctx, mode=CHAIN_RUN_CONFIRM_RERUN, set_name=…)` runs the lanes in order and returns `record.mode == "confirm re-run"`; `CHAIN_RUN_MODES` stays `("sequential", "parallel")`; any other token raises `ValueError` as today | G1 → G2 (the confirm handler) |
| I-2 save calls | `save_flow_json(flow, raw_name, project_dir, *, workarea_root: Optional[Path] = None) -> Optional[Path]` and `save_chain_set(chain_set, raw_name, project_dir, *, workarea_root: Optional[Path] = None) -> Optional[Path]`: `None` = nothing to save (empty name; for a set also no lane), unchanged; **raises `WorkareaContainmentError`** when the home is refused, before any folder or file is created (D-10), and also when the entry at the claimed name fails the check after the claim (E3 S-1; no byte written); otherwise returns the plain file it created | G1 → G2 (the two save handlers), tests |
| I-3 refusal statuses | `Flow not saved - the project's flows folder is a link or is outside the work area.` · `Chain set not saved - the project's flowsets folder is a link or is outside the work area.` — through `S19TuiApp.set_status`, nothing else painted; the same text for either cause of the raise in I-2 (E3 S-1: I-3 does not change) | G2 |
| I-4 start name | **withdrawn** with R-FB-RUN.8 (D-2 = no, E3A-01): Clear keeps the name; `"flow"` stays only the name `FlowBuilderPanel.__init__` gives (`flow_screens.py:1535`), unchanged | — |
| I-5 the shared guard | `workspace._guarded_destination(destination, workarea_root=None) -> (resolved_destination, resolved_root)`, unchanged; raises `WorkareaContainmentError`. The same helpers (`_path_traverses_reparse_point`, `_is_reparse_point`) serve Inc 6's pick guard and Write guard (Inc 6 E3 ruling S-3); Inc 9 changes none | `workspace.py` (not edited) → G1 |
| I-6 Inc 8 fields | `ChainRunOutcome.in_place_inputs`, `FlowRunResult.in_place_reads` (Inc 8's I-6) kept as they are | `run_chain_set` (G1) |
| I-7 the claim primitive | `_create_new_json(home: Path, resolved_home: Path, clean: str, render: Callable[[str], str]) -> Path` claims with `os.open(candidate, O_CREAT\|O_EXCL\|O_WRONLY\|O_BINARY)` (`O_BINARY` where the platform has it) **with mode `0o666`** (E4-R3: `write_text`'s mode; the umask applies) and fills the claim through that descriptor; the cases' Create spy and Windows follow wrap this `os.open` (E3 S-2). **E5 corrective:** the check after the claim also requires `st_nlink == 1` (SE5-1: no hard link to a followed target), and every read of the check (`fstat`, `lstat`, the reparse test, `realpath`) sits inside one `try` — a failed read is a failed check (CR-07). Every cleanup unlink goes through `_unlink_own_claim(candidate, claim, resolved_home)`: the entry at the name is unlinked only when its `lstat` succeeds, it is `samestat` with `claim` (the descriptor's `fstat`, taken before the close) and its real parent equals `resolved_home`; otherwise nothing is unlinked (SE5-2) | G1 → tests (G-T1) |

Order inside E4: G1 and G2 in parallel; G2's app cases need G1's I-1 and I-2 at integration.

## Nodes

run_chain_set
req: R-FLOW-CHAIN.19, R-FLOW-CHAIN.20
in: Sequence[ChainSpec] chains; FlowContext ctx; str mode = "sequential"; str set_name = "chain-set"; Callable? run_one = None; Callable? clock = None
out: ChainSetRunRecord record
func: changed. was: `mode` not in `CHAIN_RUN_MODES` raises `ValueError`; an empty set returns the record with `no chains in set - nothing was executed`; a WRITE-OUT name clash refuses the set; `parallel` runs every lane in a thread pool, any other mode in lane order; then `write_chain_set_report(record, set_name, ctx.project_dir)` (a failure recorded as `chain-set report write failed: …`). / now: the same, except that the check also accepts `CHAIN_RUN_CONFIRM_RERUN`, which runs the lanes in order like `sequential` and stays in `record.mode`, so the report records it (D-1 C). Three docstrings name the new token beside the two modes (E3A-07; E5 checks them): `ChainSetRunRecord.mode` (`:1840`, was "The dispatched mode — sequential or parallel"), the Args entry `mode` of `run_chain_set` (`:1966`) and its Raises entry (`:1982`).
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
func: changed. was: `clean = sanitize_project_name(raw_name)`, `None` → return `None`; `flows_dir.mkdir(parents=True, exist_ok=True)`; target `<clean>.json`, while `target.exists()` (follows links) try `<clean>_2.json`, `_3`, …; `target.write_text(json.dumps(flow_to_dict(flow), indent=2), encoding="utf-8")`. / now: `clean` as before (`None` → `None`, nothing created); then `resolved_home, _ = _guarded_destination(flows_dir, workarea_root)` (I-5) before the `mkdir` — a refusal propagates as `WorkareaContainmentError` (D-10); then the `mkdir` and `_create_new_json(flows_dir, resolved_home, clean, render)` (I-7) with `render(stem) = json.dumps(flow_to_dict(replace(flow, name=stem[:FLOW_MAX_NAME_LEN])), indent=2)`, which returns the plain file it created or raises. The `exists()` loop and `write_text` go, so this function calls no TC-B99-13 primitive and leaves the census's declared exceptions (E3A-09).
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-FILE.12/2) <W> holding flows/tune_b.json; flow `Flow(name="tune_a", …)`, raw_name "tune_b" → written flows/tune_b_2.json with `"name": "tune_b_2"` (base: `"tune_a"`, B). `_2` is the base numbering; the test asserts only that the stem is not `tune_b` and that `name` equals the stem
examples: (R-FLOW-FILE.12/3) F1, "Nightly Release!  " → flows/NightlyRelease.json, `"name": "NightlyRelease"` (base: `"a"`)
examples: (R-FLOW-FILE.12/4) F1, "A" × 64 → `"name"` = "A" × 64; `load_flow_json` → 0 findings
examples: (R-FLOW-FILE.13/1) F1, "B" × 65 → flows/<"B"×65>.json, `"name"` = "B" × 64; `load_flow_json` → 0 findings
examples: (R-FLOW-FILE.13/2) <W> holding flows/<"C"×64>.json; F1, "C" × 64 → flows/<"C"×64>_<N>.json (the next free name), `"name"` = "C" × 64; 0 findings
examples: (R-FLOW-FILE.13/1 neg) mutant: `name=candidate.stem` uncut → `load_flow_json` → [FLOW-BAD-FIELD `flow name exceeds 64 characters`] → RED
examples: (R-FLOW-FILE.11/1) <W>/flows = Link(→ <O>/flows); F1, "x", workarea_root R → raises WorkareaContainmentError; <O>/flows holds 0 files (base: x.json there, B)
examples: (R-FLOW-FILE.11/2) <W>/flows = Link(→ <W>/patches) → raises WorkareaContainmentError; <W>/patches unchanged
examples: (R-FLOW-FILE.11/3) R/q a project folder; R/p = Link(→ R/q); F1, "x", project_dir R/p, workarea_root R → raises WorkareaContainmentError (the walk finds R/p); R/q/flows not created (base: R/q/flows/x.json written)
examples: (R-FLOW-FILE.14/1) plain <W>/flows holding the link z.json → <O>/dangling/z.json (missing); F1, "z" → <O>/dangling/z.json still missing; flows/z.json still the link; written flows/z_<N>.json, a plain file, `"name"` = its stem (base: <O>/dangling/z.json created, B)
examples: (R-FLOW-FILE.14/2) the link z.json → <O>/z.json (bytes K) → <O>/z.json still K; written flows/z_<N>.json (holds on base: `exists()` follows the link to the file)
examples: (R-FLOW-FILE.3, holds on base) F1, "!!!" → `None`; flows/ not created
examples: (R-FLOW-FILE.12/1 neg) mutant: `flow_to_dict(flow)` (the base payload) → /2 gives `"tune_a"` → RED
examples: (R-FLOW-FILE.11/1 neg) mutant: the guard call removed → x.json lands in <O>/flows → RED

_create_new_json
req: R-FLOW-FILE.14, R-FLOW-SET.8, R-FLOW-FILE.12, R-FLOW-FILE.13, R-FLOW-SET.9, R-FLOW-SET.10
in: Path home; Path resolved_home; str clean; Callable[[str], str] render
out: Path created
func: new (E3 S-1, S-3; I-7). The house claim of `place_into_workarea` (`workspace.py:1243-1316`, house finding S-F1), once for both saves. For each candidate `<clean>.json`, `<clean>_2.json`, … in `home`: (a) `os.path.lexists(candidate)` → the name is taken, next; (b) `text = render(candidate.stem)` — the payload is built before the claim, so a serialiser raise leaves no file (S-3); (c) `fd = os.open(candidate, O_CREAT|O_EXCL|O_WRONLY|O_BINARY)`; `FileExistsError` → next; any other `OSError` → next when `lexists(candidate)` now holds (a racing directory raises `PermissionError` on Windows, house F1), else re-raise; (d) before any byte is written, inside one `try` (E5 CR-07: a failed read is a failed check): `claim = os.fstat(fd)`, `st = os.lstat(candidate)` is a regular file (`stat.S_ISREG`) with `st.st_nlink == 1` (E5 SE5-1), `os.path.samestat(claim, st)`, `_is_reparse_point(candidate)` is false, and `Path(os.path.realpath(candidate)).parent == resolved_home` (E4 ruling E4-R1: the claim's real parent equals the home the guard already resolved, never resolved again; was `contained_in_workarea(…, resolved_home)`, which re-resolves the home and passes a home swapped for a link) — otherwise close `fd`, call `_unlink_own_claim(candidate, claim, resolved_home)` (E5 SE5-2: the entry is re-read and unlinked only when it is provably the claim), and raise `WorkareaContainmentError` (E3 R2-2: a read failure is the same refusal); (e) write `text` through `os.fdopen(fd, "w", encoding="utf-8")` — `O_BINARY` leaves the newline handling to the text wrapper alone, so the bytes are those `write_text` writes (R, read; the Windows arm at E5 compares them); an `OSError` while writing → the `with` closes, `_unlink_own_claim(…)`, re-raise (S-3); (f) return `candidate`. The candidate walk is one generator (`<clean>.json`, then `_2`, `_3`, …; E5 CR-08, numbering unchanged). It calls no TC-B99-13 primitive itself since E5: the own-claim `os.unlink` sits in `_unlink_own_claim`, which is the allow-listed function (E3A-09, moved at E5). Residual (BL-I9-4, E5 SE5-3): never an overwrite; with no concurrent writer nothing outside; a file link put in at the free name on Windows (privilege needed; a junction at the free name is never followed, probe P1/P5) → an empty file at its target; one home swap → an empty file at the link's target, left there (its name resolves outside), or an empty `flows/` / `flowsets/` folder when the project folder is swapped between the guard and the `mkdir` (CR-10); content outside only under a double swap, and a cleanup that deletes another file only under a swap inside the last window between its re-read and its unlink (BL-I9-10).
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-FILE.14/3) plain <W>/flows holding the dangling link z.json; Create spy; clean "z" → the spy records 0 calls on flows/z.json and 1 on the returned flows/z_<N>.json
examples: (R-FLOW-FILE.14/3 neg) mutant: `candidate.exists()` in (a) → `exists()` is False for the dangling link → a call on flows/z.json is recorded (on Linux `O_EXCL` then refuses the link and the loop moves on, so only the spy sees the mutant) → RED
examples: (R-FLOW-FILE.14/4) plain, empty <W>/flows; Windows follow (emulated): the call for flows/z.json creates <O>/followed.json, puts a symlink to it at flows/z.json and returns its descriptor → (d) finds a link, not a regular file → `fd` closed, flows/z.json left as it is (not ours), raises WorkareaContainmentError; <O>/followed.json holds 0 bytes; flows/ holds no other entry
examples: (R-FLOW-FILE.14/4 neg) mutant: (d) removed → the flow's JSON is written through `fd` into <O>/followed.json → RED
examples: (R-FLOW-SET.8/3) plain <W>/flowsets holding the dangling link s.json; Create spy; clean "s" → 0 calls on flowsets/s.json, 1 on the returned flowsets/s_<N>.json
examples: (R-FLOW-SET.8/4) Windows follow (emulated) on flowsets/s.json → raises WorkareaContainmentError; <O>/followed.json holds 0 bytes; flowsets/s.json still the link
examples: (S-3, no row: design robustness) `render` raises → no `os.open` call, nothing created; a write `OSError` after (d) → the claimed file is removed and the error re-raised, the home holds no new entry
examples: (house F1) a directory that wins the race at the free name: `os.open` raises `PermissionError` (Windows), `lexists` then holds → the next candidate is claimed
examples: (R-FLOW-FILE.14/7, R-FLOW-SET.8/6; E5 QA-3) the emulated follow to a sibling `<home>/other.json` inside the home → the real-path clause passes, the link clauses refuse → raises; `other.json` 0 bytes; the link kept (neg: M14b, the check reduced to its one-link and real-path clauses → the payload lands in `other.json` → RED)
examples: (R-FLOW-FILE.14/8; E5 CR-03) render raises → 0 `os.open` calls in the home, no file (neg M26); the write fails with `ENOSPC` → re-raised, the claim removed (neg M27); the check's `lstat` fails → `WorkareaContainmentError`, the claim removed (neg M28); `PermissionError` with a folder now at the name → `z_2.json` (neg M29)
examples: (R-FLOW-FILE.14/9, R-FLOW-SET.8/7; E5 SE5-2) the home swapped for a link to `<O>` at the create, then re-pointed at `<V>` (holding `z.json`) after the close → raises; `<V>/z.json` keeps its bytes; the empty claim stays in `<O>` (neg M24, the cleanup unlinks by name without the re-read → `<V>/z.json` deleted → RED)
examples: (R-FLOW-FILE.14/10, R-FLOW-SET.8/8; E5 CR-02) a followed create, then a regular file planted at the name → only `samestat` refuses → raises; `followed.json` 0 bytes; the planted file unchanged (neg M22, the same-file clause dropped → RED)
examples: (R-FLOW-FILE.14/11, R-FLOW-SET.8/9; E5 SE5-1) a followed create, then a hard link to the followed target at the name → only `st_nlink == 1` refuses → raises; `followed.json` 0 bytes; the hard-link name removed (ours) (neg M23, the one-link clause dropped → RED)

_unlink_own_claim
req: R-FLOW-FILE.14, R-FLOW-SET.8
in: Path candidate; os.stat_result? claim; Path resolved_home
out: None
func: new (E5 rulings CR-07, SE5-2). The cleanup of `_create_new_json`: `claim is None` → nothing; else, best-effort (`OSError` swallowed): `os.unlink(candidate)` only when `os.path.samestat(claim, os.lstat(candidate))` and `Path(os.path.realpath(candidate)).parent == resolved_home` — a name that now leads to another file or outside the approved home is never unlinked. The one TC-B99-13 `os.unlink` of the two saves; it is the function `_FINAL_NAME_ALLOWLIST` names for this module.
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-FILE.14/5) the claim made through a swapped home, `realpath` parent `<O>` → not unlinked; `<O>` holds exactly the empty claim (neg M25, the real-parent clause dropped → removed → RED)
examples: (R-FLOW-FILE.14/9) the home re-pointed at `<V>` after the close → the entry at the name is `<V>/z.json`, not `samestat` with the claim → not unlinked

save_chain_set
req: R-FLOW-SET.7, R-FLOW-SET.8, R-FLOW-SET.9, R-FLOW-SET.10
in: ChainSet chain_set; str raw_name; Path project_dir; Path? workarea_root = None
out: Path? written
func: changed. was: no lane → `None`; `clean` `None` → `None`; `flowsets_dir.mkdir(...)`; `exists()` dedup from `_2`; `write_text(json.dumps(chain_set_to_dict(chain_set), indent=2), …)`. / now: the same checks; `resolved_home, _ = _guarded_destination(flowsets_dir, workarea_root)` before the `mkdir`; then `_create_new_json(flowsets_dir, resolved_home, clean, render)` (I-7) with `render(stem) = json.dumps(chain_set_to_dict(replace(chain_set, name=stem[:CHAIN_SET_MAX_NAME_LEN])), indent=2)`: the set file's `name` is its file stem cut to 64 (E3A-04; was the typed text, D-5).
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-SET.7/1) <W>/flowsets = Link(→ <O>/flowsets); C1, "s", workarea_root R → raises WorkareaContainmentError; <O>/flowsets holds 0 files (base: s.json there, B)
examples: (R-FLOW-SET.7/2) <W>/flowsets = Link(→ <W>/patches) → raises WorkareaContainmentError
examples: (R-FLOW-SET.8/1) plain <W>/flowsets holding the link s.json → <O>/dangling/s.json (missing); C1, "s" → <O>/dangling/s.json still missing; written flowsets/s_<N>.json, a plain file
examples: (R-FLOW-SET.8/2) the link s.json → <O>/s.json (bytes K) → <O>/s.json still K; written flowsets/s_<N>.json (holds on base)
examples: (R-FLOW-SET.9/1) `replace(C1, name="Nightly Set!")`, "Nightly Set!  " → flowsets/NightlySet.json, `"name": "NightlySet"`; `load_chain_set` → the set, 0 findings (base: `"Nightly Set!"`)
examples: (R-FLOW-SET.9/2) <W> holding flowsets/s.json; C1, "s" → written flowsets/s_<N>.json whose `"name"` equals its stem (base: `"s"`)
examples: (R-FLOW-SET.10/1) `replace(C1, name="D" × 65)`, "D" × 65 → flowsets/<"D"×65>.json, `"name"` = "D" × 64; `load_chain_set` → the set, 0 findings
examples: (R-FLOW-SET.10/1 neg) mutant: `name=stem` uncut → `load_chain_set` → (None, [CHAIN-SET-BAD-FIELD `chain-set name exceeds 64 characters`]) → RED
examples: (R-FLOW-SET.9/1 neg) mutant: `chain_set_to_dict(chain_set)` (the base payload) → `"Nightly Set!"` → RED
examples: (R-FLOW-SET.2, holds on base) a set with no lane → `None`; flowsets/ not created

load_chain_set
req: R-FLOW-SET.10
in: Path set_path; Path project_dir
out: tuple(ChainSet? chain_set, list[ValidationIssue] findings)
func: unchanged. Its name rule (`flow_persistence_service.py:1297-1309`): `name` a non-blank string of at most 64 characters (`CHAIN_SET_MAX_NAME_LEN`), else `CHAIN-SET-BAD-FIELD` and the set is refused. The oracle of R-FLOW-SET.10.
module: s19_app/tui/services/flow_persistence_service.py
examples: (R-FLOW-SET.10/1 neg, holds on base) a set file whose `name` has 65 characters → (None, [CHAIN-SET-BAD-FIELD `chain-set name exceeds 64 characters`])
examples: (R-FLOW-SET.10/1) a `name` of 64 characters → the set, 0 findings

S19TuiApp.on_flow_execution_panel_load_set_requested
req: R-FLOW-SET.10
in: FlowExecutionPanel.LoadSetRequested event
out: None
func: unchanged. Loads `flowsets/<event.stem>.json` through `load_chain_set` (`app.py:4574-4609`); a refusal paints `render_set_refusal` and the status `Chain set load refused: <first finding>`; otherwise the lanes are restored from their templates by stem.
module: s19_app/tui/app.py
examples: (AT-I9-2, set arm) after Save Set with the typed name "S" × 70 → Load Set of that stem mounts the one lane `rep_b`; the status line does not start `Chain set load refused`
examples: (AT-I9-2, holds on base as the defect) the same file written by the base (`name` = the 70 typed characters) → status `Chain set load refused: chain-set name exceeds 64 characters`, 0 lanes change (R)

_guarded_destination
req: R-FLOW-FILE.11, R-FLOW-SET.7
in: Path destination; Path? workarea_root = None
out: tuple(Path resolved_destination, Path resolved_root)
func: unchanged (I-5). Finds the outermost `.s19tool/workarea` anchor on the textual path (or takes `workarea_root`), walks every folder from the destination up to and including the work-area folder for a link (`_path_traverses_reparse_point`, `stop_at=root.parent`, exclusive) and checks `.s19tool` itself, then resolves both and requires containment. A missing destination passes the walk. Its first result is the `resolved_home` that `_create_new_json` checks the claim against.
module: s19_app/tui/workspace.py
examples: (R-FLOW-FILE.11/1, holds on base) <W>/flows a link → raises (`Refusing to place: destination traverses a symbolic link or reparse point: …`) (B)
examples: (R-FLOW-SET.7/1, holds on base) <W>/flowsets a link → raises (B)
examples: (R-FLOW-FILE.11/3, holds on base) R/p a link to R/q, destination R/p/flows (missing) → the walk reaches R/p → raises (R)
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
examples: (R-FLOW-FILE.12/1) Builder project, Clear, LOAD `prg.s19` added; Save… (suggests `patch_chain`: Clear keeps the name, D-2 = no), `tune_b`, Save → flows/tune_b.json `"name": "tune_b"`; `mark_saved("tune_b")` (base: `"patch_chain"`, B)
examples: (R-FLOW-FILE.12/5) Builder project plus Flow rep_a; Load… `rep_a`; Save…, `rep_b`, Save → flows/rep_b.json `"name": "rep_b"` (base: `"rep_a"`)
examples: (E3 S-1) the claim fails its check after the claim → the same raise → the same status as R-FB-SAVE.8/1 (I-3); no `mark_saved`
examples: (R-FB-SAVE.6, holds on base) Save…, `!!!`, Save → status `Flow name is empty after sanitising - not saved.`
examples: (R-FB-SAVE.8/1 neg) mutant: the `except` shows the R-FB-SAVE.6 text → RED; mutant: no `except` → the refusal escapes the callback → RED

S19TuiApp.on_flow_execution_panel_save_requested
req: R-FLOW-SET.7, R-FX-SET.15
in: FlowExecutionPanel.SaveRequested event
out: None
func: changed. was: no project → status `No project loaded - load or save a project first.`; build `ChainSet(name=raw_name.strip() or "chain-set", chains=…)`; `saved = save_chain_set(chain_set, event.raw_name, project_dir)`; `None` → status `Chain set not saved - the set is empty or the name sanitised away.`; else `panel.mark_saved(saved.stem)` and `_prefill_flow_execution_sets()`. / now: `save_chain_set(…, workarea_root=self.workarea)` inside `try`; `except WorkareaContainmentError` → `self.set_status("Chain set not saved - the project's flowsets folder is a link or is outside the work area.")` and return, without `mark_saved` and without the list refresh. The `ChainSet` is still built with the typed text; the service writes the file stem as its `name` (E3A-04).
module: s19_app/tui/app.py
examples: (R-FX-SET.15/1) FX project, lane `patch_chain`; flowsets/ = Link(→ <O>/flowsets); set name `s`, Save Set → status `Chain set not saved - the project's flowsets folder is a link or is outside the work area.`; <O>/flowsets holds 0 files; the ribbon keeps `· unsaved`
examples: (R-FX-SET.4, holds on base) no lane, Save Set → status `Chain set not saved - the set is empty or the name sanitised away.`
examples: (AT-I9-3) both refusals through the dialogs → the two status texts, 0 files in <O>
examples: (AT-I9-2, set arm) lane `rep_b` after its Run; set name "S" × 70, Save Set → flowsets/<"S"×70>.json with `"name"` = "S" × 64; `mark_saved` with that stem (base: `"name"` = the 70 typed characters, R)

FlowBuilderPanel.on_button_pressed
req: R-FLOW-FILE.12
in: Button.Pressed event
out: None
func: unchanged (E3A-01: the Clear change is withdrawn with R-FB-RUN.8, D-2 = no). Branch `flow_clear` (`flow_screens.py:2555-2566`) empties `_blocks`, `_funnel`, `_clipboard`, the clip status, the notice, the pipeline frame's subtitle and the result; `_mark_dirty()` when the chain had blocks; `_flow_name` kept. Context only: because Clear keeps the name, R-FLOW-FILE.12 fixes the file in the save (BL-I9-5 holds the stale ribbon text).
module: s19_app/tui/flow_screens.py
examples: (R-FLOW-FILE.12/1 precondition, holds on base) `patch_chain` loaded; Clear → the ribbon still starts `Flow: patch_chain` (B)
examples: (R-FB-RUN.6, holds on base) Clear → 0 blocks, 0 variables, clipboard empty, the empty result

FlowBuilderPanel.current_flow
req: R-FLOW-FILE.12
in:
out: Flow
func: unchanged. `Flow(name=self._flow_name, blocks=list(self._blocks), funnel=tuple(self._funnel))`; its name feeds the Save dialog's suggestion (`app.py:4021`), the Builder's Run and the load question's flow item (`app.py:8657`). After Inc 9 the saved file's `name` no longer depends on it.
module: s19_app/tui/flow_screens.py
examples: (R-FLOW-FILE.12/1, holds on base) after Clear of the loaded `patch_chain` → name "patch_chain"; the file saved as `tune_b` still holds `"name": "tune_b"` (the save writes the stem)

run_flow
req: R-FLOW-FILE.12
in: Flow flow; FlowContext ctx
out: FlowRunResult
func: unchanged. A REPORT block writes `# Flow report — <flow.name>` (`flow_execution_service.py:1257`, through `md_safe`, `flow_report_service.py:425`) into `reports/<ts>-report.md`; a Flow Execution lane runs `Flow(name=spec.flow.name, …)` (`:2028-2029`), the loaded file's `name`. The one reader of the saved `name` (E3A-02; BL-I9-1: older, renamed or hand-written files keep their embedded `name`).
module: s19_app/tui/services/flow_execution_service.py
examples: (holds on base) a lane loaded from flows/tune_b.json holding `"name": "tune_a"`, blocks LOAD + REPORT → `# Flow report — tune\_a` (B)
examples: (R-FLOW-FILE.12/5, AT-I9-2) Flow rep_a (LOAD + REPORT) loaded in the Builder, saved as `rep_b`, imported as a lane and Run → exactly 1 new `reports/<ts>-report.md`, first line `# Flow report — rep\_b` (base: `# Flow report — rep\_a`)
examples: (R-FLOW-FILE.12/5 neg) mutant: `flow_to_dict(flow)` in the save → `# Flow report — rep\_a` → RED

## Entities

[Data: CHAIN_RUN_CONFIRM_RERUN]
in: str
desc: new module constant of `flow_execution_service.py`, beside `CHAIN_RUN_SEQUENTIAL`, `CHAIN_RUN_PARALLEL`, `CHAIN_RUN_MODES` (`:1743-1745`): `"confirm re-run"`. The mode of a confirm re-run (CTX-CHAIN). Not a mode of the switch, so not in `CHAIN_RUN_MODES`.

[Doc: flow_screens module docstring]
desc: `flow_screens.py:1-42` (no requirement row, `../E1-rulings.md` D-8). was: "messages out, services never called directly; the one declared data edge `flow_screens → services/flow_model` is read-only constants/dataclasses per `docs/architecture.md` §10" (`:7-10`) and "No engine code is imported beyond the read-only flow-model data types" (`:32-33`), while `:35-42` already names a second edge. now: one statement of the measured edges — the panels post messages and never call the executor (`services/flow_execution_service`); the module reads `services/flow_model` (block and flow data types and constants) and `services/flow_persistence_service` (the wire serializer and the loader, for copy and paste, and the unsafe-ref finding code); no section of `docs/architecture.md` is cited for an import rule (§10 reads `not declared`). E5 check: 0 occurrences of `services never called directly`, `the one declared data edge` and `No engine code is imported beyond`.

[I/O: reports/ chain-set reports]
desc: `<project>/reports/<ts>-chain-set-report.md` (a same-second clash: `<ts>-<NN>-chain-set-report.md`). After a parallel Run and one confirm: two files, `- **Mode:** parallel` / `- **Chains:** 3` and `- **Mode:** confirm re-run` / `- **Chains:** 1`.

[I/O: flows home]
desc: `<project>/flows/`. Saved files: `<stem>.json` with `"name"` = the stem cut to 64. Refused when it, any folder up to and including the work area, or `.s19tool` is a link, or when it resolves outside the work area. A link inside it with a candidate's name is a taken name, never written through; a link put in at the claimed name after the name check gets no byte (the check after the claim).

[I/O: flowsets home]
desc: `<project>/flowsets/`; the same rules as the flows home; the file's `"name"` is the stem cut to 64 (E3A-04; was the typed text).

[I/O: outside folder]
desc: any folder not under this work area (`<O>` in the cases). After Inc 9 no flow or chain-set save writes a byte there, and none creates a file there through a link that exists before the save. Under a concurrent writer (BL-I9-4, E5 SE5-3): a file link put in at the free name on Windows (privilege needed; a junction is never followed) or one home swap can leave an empty file there, and a project folder swapped between the guard and the `mkdir` an empty `flows/` / `flowsets/` folder (CR-10); content, or the cleanup deleting a file there, only under a double swap or a swap inside the cleanup's last window (BL-I9-10). Never an overwrite.

[Interface: status line]
desc: `#log_line_4` through `S19TuiApp.set_status`; carries the two refusal texts of I-3.

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
save_flow_json ──▶ _create_new_json
save_chain_set ──▶ _create_new_json
_create_new_json ──▶ [I/O: flows home]
when: called by save_flow_json
_create_new_json ──▶ [I/O: flowsets home]
when: called by save_chain_set
_create_new_json ──▶ [I/O: outside folder]
when: no byte with no concurrent writer; under one (a file link at the free name on Windows, one home swap) an empty file, or an empty `flows/` / `flowsets/` folder; content only under a double swap (BL-I9-4, BL-I9-10, E5 SE5-3)
_create_new_json ──▶ _unlink_own_claim
when: the check after the claim fails, or the write fails
run_chain_set ──▶ run_flow
when: each lane runs `Flow(name=spec.flow.name, …)` (`:2028`); a REPORT block titles its report with that name
S19TuiApp.on_flow_execution_panel_load_set_requested ──▶ load_chain_set
save_flow_json ──▶ S19TuiApp.on_flow_builder_panel_save_requested
when: raises WorkareaContainmentError; then [Interface: status line]
save_chain_set ──▶ S19TuiApp.on_flow_execution_panel_save_requested
when: raises WorkareaContainmentError; then [Interface: status line]
FlowBuilderPanel.current_flow ──▶ S19TuiApp.on_flow_builder_panel_save_requested
when: Save… (the dialog's suggestion)

## Findings

> E2-1 (for E3, D-1). The confirm re-run keeps a report and labels it. The alternative A (no report) would also satisfy the plan title, at the cost of the only chain-set record of a confirmed lane's completion and of half of R-FX-RUN.14; B (a merged whole-set report) mixes two runs. The graph changes one token and one check; under A, `run_chain_set` would instead gain a `write_report=False` keyword and TC-B97-55's assertion would change.
> E2-2 (for E3, D-6; corrected by E3 S-1). `_guarded_destination` checks the folder chain only (B: it passes a plain `flows/` holding a file link). R-FLOW-FILE.14 / R-FLOW-SET.8 close the file name in `_create_new_json`: `os.path.lexists`, then an exclusive create, then the check after the claim before any byte. On Linux `O_EXCL` never follows a link; on Windows it follows a dangling one (house finding S-F1), so there the check after the claim is what keeps the content out. Residual (BL-I9-4): in a race, a link put in at the free name (Windows) or a home swapped for a link (any platform: `O_EXCL` follows a link in the folder part) can still receive an empty file from the create; never content (E3 R2-1; the home-swap arm is pinned by R-FLOW-FILE.14/5).
> E2-3 (for E3, D-10). The save functions raise the guard's own `WorkareaContainmentError` (as `import_flow_file` does through `copy_into_workarea`); `None` keeps its one meaning (nothing to save). Other `OSError`s of a save are not handled today and are not changed (out of scope).
> E2-4 (for E3, D-2) — resolved: the orchestrator ruled D-2 = no; R-FB-RUN.8 and I-4 are withdrawn, `FlowBuilderPanel.on_button_pressed` is unchanged context, and the stale name after Clear is BL-I9-5 (E3A-01). The file fix stands without it.
> E2-5. Coverage of the requirement → node map: R-FLOW-CHAIN.19: `run_chain_set`, `S19TuiApp.on_flow_execution_panel_external_step_confirmed`, `compose_chain_set_report`, `FlowExecutionPanel.apply_confirmed_run`; R-FLOW-CHAIN.20: `[Data: CHAIN_RUN_CONFIRM_RERUN]`, `run_chain_set`, `compose_chain_set_report`, the confirm handler, `S19TuiApp.on_flow_execution_panel_run_requested`; R-FLOW-FILE.12: `save_flow_json`, `S19TuiApp.on_flow_builder_panel_save_requested`, `flow_to_dict`, `run_flow` (the reader, E3A-02), `FlowBuilderPanel.current_flow`, `FlowBuilderPanel.on_button_pressed` (context); R-FLOW-FILE.13: `save_flow_json`, `dict_to_flow`; R-FLOW-SET.9: `save_chain_set`, `_create_new_json`, the FX save handler; R-FLOW-SET.10: `save_chain_set`, `load_chain_set`, `S19TuiApp.on_flow_execution_panel_load_set_requested`; R-FLOW-FILE.11: `save_flow_json`, `_guarded_destination`, the Builder save handler; R-FLOW-SET.7: `save_chain_set`, `_guarded_destination`, the FX save handler; R-FLOW-FILE.14: `save_flow_json`, `_create_new_json`; R-FLOW-SET.8: `save_chain_set`, `_create_new_json`; R-FB-SAVE.8: the Builder save handler; R-FX-SET.15: the FX save handler. R-FB-RUN.8: withdrawn, no node. Every active row and every new case (R-FLOW-FILE.11/3, .12/5, .14/3, .14/4, R-FLOW-SET.8/3, .8/4, .9/1, .9/2, .10/1, AT-I9-2) has at least one concrete example.
> E3-1 (E3 round 1, `../E3-rulings.md`). Changed by the corrections: I-2 (a second cause of the raise), I-4 (withdrawn), I-7 (new); nodes `_create_new_json`, `load_chain_set`, `S19TuiApp.on_flow_execution_panel_load_set_requested` (added), `save_flow_json`, `save_chain_set`, `run_chain_set` (docstrings), `FlowBuilderPanel.on_button_pressed` (back to unchanged context); entity `[Interface: Builder ribbon]` and its Clear edge removed. Nodes now 18 (6 changed, 1 new helper, 11 context); one design choice beyond the reviewers' texts: the claim lives in one helper `_create_new_json` for both saves, so the census can drop the two saves from its exceptions (E3A-09) while the helper's own-claim `os.unlink` is allow-listed.
> E5-1 (E5 corrective, `../E5-rulings.md`, `../E5-corrective-notes.md`). Changed: I-7 (the one-link clause, every read of the check inside the `try`, the cleanup's ownership rule); node `_create_new_json` (func, examples), new node `_unlink_own_claim` and its edge; entity `[I/O: outside folder]` and its edge (the residual, SE5-3, CR-10). Nodes now 19 (6 changed, 2 new helpers, 11 context). The census allow-list moves from `_create_new_json` to `_unlink_own_claim`, the only function of the module that unlinks.
