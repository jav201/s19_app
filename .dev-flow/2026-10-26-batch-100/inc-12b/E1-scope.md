# E1 — Inc 12b requirements scope and E2 slice

**Run.** Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 12b (PLAN.md row 12b: "project load, Save project, A2L parse on workers — N5, O-7 — app (+ flow_screens) — gate P-D"; prototype verdict P-D A, `pd_A`: spinner, step `n/m` and elapsed time in `#status_text`, the bar kept working).

**Source.** The replacement text is `E1-requirements-draft.md` in this folder; nothing has been merged into `01-requirements.md`. Requirement and code reads were taken on the main checkout `<HOME>/Github/s19_app` at `8947666` (Inc 9a merged; Inc 9b, 10, 11 not implemented; `git status`: only the untracked `prototypes/load_projects/`). Code is cited by symbol, with `app.py` lines where a line carries the argument. Hooks follow the later increments' E1 drafts: the 9b router `_handle_load_dialog` and `_load_workarea_file` (`inc-9b-design/codewire/interfaces-9b.md`), the Inc 10 load guard `_confirm_then_load(kind, target, go)` and its question modal (`inc-10-design/E1-scope.md` S-a, S-b), the Inc 11 preparation / commit split of Save project (`inc-11-design/E1-scope.md` N1, S-c), and Inc 12a's indicator seam and rulings (`inc-12a-design/E1-scope.md` S-a … S-f, `E1-rulings.md` Q1 … Q10, ruled 15:17 while this E1 ran; the draft was aligned to them).

**Premises in scope.** P-29 (24 `set_progress` sites in 12 functions), P-33 (the case_06 A2L is 37 742 888 bytes), plus the rulings routed here: Inc 11 Q2 (the save on a worker: the worker half), Inc 10's note on LLR-174.4 (the worker refusal in the load guard), Inc 10 LLR-174.2a's quit arm (the modal takes the quit texts), and Inc 12a Q1 (LLR-176.3, LLR-176.4, TC-B100-52, TC-B100-73, AT-B100-18, AT-B100-17's parse half moved here), Q2 (the R12 backlog row moved here without its cancel), Q3 (overlapping long actions, newest shown), Q5 (no "copied, read" promise; Save placements by files left to 12b), Q8 (app survival of a raising worker is 12b's), and 12a's two observations for 12b (the work-area image pick, the typed load's copy).

**Counts.**
- **Before:** 5 requirements in scope (HLR-177, LLR-177.1, LLR-177.2, and LLR-176.3, LLR-176.4 moved from 12a), holding 18 "shall"s (HLR-177: 7; LLR-177.1: 7; LLR-177.2: 1 over three actions; LLR-176.3: 1; LLR-176.4: 2, plus a re-freeze sentence). 0 BACKLOG-CODE rows name 12b; 1 row (the R12 save-as row, targeting 12a) is moved here by 12a ruling Q2.
- **After E1:** 39 single-"shall" requirements, all owed new at 12b:
  - 4 HLRs (HLR-177, HLR-177a, HLR-177b, HLR-177c);
  - 31 LLRs under HLR-177 … HLR-177c (LLR-177.1 … LLR-177.1k: 12; LLR-177.2 … LLR-177.2b: 3; LLR-177.3 … LLR-177.3h: 9; LLR-177.4 … LLR-177.4d: 5; LLR-177.5, LLR-177.5a: 2);
  - 4 LLRs under HLR-176 (LLR-176.3, LLR-176.4, LLR-176.4a, LLR-176.4b).
- **Outside the count:** LLR-165.1 (its caller clause changes, draft §C.1), and these extended with their text unchanged: LLR-164.4 (TC-B100-07 worker arms), LLR-165.2 (TC-B100-09), LLR-174.4 (TC-B100-72), LLR-176.1l and LLR-176.1q (TC-B100-50, the three new worker bodies), LLR-176.2, LLR-176.2c, LLR-176.2d (TC-B100-51 re-derived), LLR-178.3 (the panel after the install), LLR-173.7 (TC-B100-66).

**Per EARS form (39 in scope):** event (E) 15 · ubiquitous (U) 13 · unwanted (UW) 10 · state (S) 1 · optional 0. Checked by script (`work/check_shall.py`, output `work/check_shall.out.txt`): every Statement holds exactly 1 "shall", and no other field of a requirement block holds the word.

**Base probes (executed, all under `work/`, read-only against the repo; `LOCALAPPDATA` and `base_dir` in `work/`).**

| Probe | What | Result |
|---|---|---|
| P12b-1 (`probe_textual.py`) | Textual 8.2.8, minimal app: a second worker in the same exclusive group | the first `Worker` is `CANCELLED`, its thread keeps running, and its `call_from_thread` callback still lands: `landed: [('second', …), ('first', …)]` |
| P12b-2 (same) | an exception escaping a `@work(thread=True)` body (default `exit_on_error=True`) | `app running after worker raise: False | return_code: 1`; `run_test raised: WorkerFailed` |
| P12b-3 (same) | `App.exit()` while a thread worker sleeps | after exit the worker's `call_from_thread` callback still runs: `landed: [('late', …)] | errors: [] | app running: False` |
| P12b-4 (`probe_base.py`) | base: `load_a2l_from_path(case_06 firmware.a2l)` with a 0.1 s interval timer | `wall 8.76 s; ticks during the call 0; … ran on main thread True` |
| P12b-5 (same) | base: `_handle_load_project('P')`, P = case_06 `firmware.s19` + `.mac` + `.a2l`, no `project.json` | `wall 5.81 s; ticks during the call 0; … ran on main thread True` |
| P12b-6 (same) | base: `_handle_save_dialog('Q')` right after P12b-5 | `wall 0.12 s; ticks during the call 0; … ran on main thread True`; Q = `firmware.a2l, firmware.mac, firmware.s19, project.json` |
| P12b-7 (`probe_parse.py`) | base: `parse_a2l_file(case_06)` alone | `5.01 s`, the worker-eligible share of P12b-4's 8.76 s; the rest is the copy and the main-thread tag-table build (HLR-176's declared freeze) |

**P12b-3 production semantics (E3 S12b-07).** P12b-3 measured `run_test`, not production: in a real `App.run()`, after `exit()` a worker's `call_from_thread` raises `RuntimeError('App is not running')`, and `run()` returns only after the thread ends. The Save's shutdown safety rests on that — an exit that is not ours makes the next step or tick post raise **inside** the rollback `try`, so the save is rolled back or already complete, never half-written. Hence the design rule "after `mkdir`, every cross-thread call in the Save worker sits inside the rollback `try`".

Consequences: Save project of the case_06 project is faster than one elapsed-time tick, so every "during a Save project" arm uses a **forced slow step** (a test double blocked on a `threading.Event`); AT-B100-18's black-box quit-confirm arm uses a slow save-as (8b measured 14.0 s for 2 000 files). Code reads on the base cover the rest; LLR-177.1f's base-digest arm is `planned` for the E2 baseline.

## 1 · Scope list

| Id | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-177 | Project-load reads, Save writes, A2L copy + parse on worker threads | U | case_06 project: elapsed changes ≥ 1 before the install ends; 3 of 3 steps off main | P12b-5 executed |
| HLR-177a | A request that changes image / document / project while a session action runs → busy line | UW | 8 requests during a held save → 8 busy lines, digest and stack unchanged | code read (no busy state); P12b-6 |
| HLR-177b | Quit while a session action runs asks first | E | `q` during a held save → 1 question, focus Stay; idle `q` → exit | code read: no `action_quit` override |
| HLR-177c | Confirmed quit exits only after the action finished or rolled back | E | held save + `y` → running; released → complete or absent; raising → absent | exit-at-once mutant; P12b-3 |
| LLR-177.1 | Project load reads and parses on a worker | U | 5 of 5 reader spies off main; 4 cheap refusals in the request frame | P12b-5 executed |
| LLR-177.1a | Save creates, places, emits, writes `project.json` on a worker | U | 4 of 4 spies off main; 10 preparation refusals before any worker | P12b-6 executed |
| LLR-177.1b | Every A2L attach copies and parses on a worker | U | 4 routes parse off main; 3 copying routes copy off main | P12b-4 executed |
| LLR-177.1c | Timers keep running during a worker step | S | ≥ 10 ticks of a 0.1 s timer in each of 3 arms | P12b-4, P12b-5 (0 ticks) |
| LLR-177.1d | Session written only on the main thread | U | `__setattr__` + service probe, 6 runs → 0 off-main writes | code read: `_a2l_cache_*`, `_last_manifest_verify_result` |
| LLR-177.1e | A worker reads only its immutable request | U | AST: 0 session reads in 3 workers and their callees; 3 frozen requests | code read: `_parse_loaded_file` reads `current_file` |
| LLR-177.1f | A project loaded on a worker equals a cold load | E | P2-over-P1 vs cold P2 → 0 names; cold digest = base | live-`current_file` MAC-merge mutant; base digest `planned` |
| LLR-177.1g | Reset after the worker read, before the first install | E | order 3 of 3; 0 resets on failure | reset-before-worker mutant |
| LLR-177.1h | Load-result panel opens after the install | E | 0 while held, 1 after; typed route 1; direct call 0 | post-return identity-check mutant (base shape) |
| LLR-177.1i | Save re-derives and renders on main before the worker | U | 2 calls on main, both before the worker start | re-derive-in-worker mutant |
| LLR-177.1j | Save adopts the re-derived image on main after the commit | E | 1 adopt after `project.json`; manifest failure → 0 adopts | adopt-before mutant (the old text) |
| LLR-177.1k | A work-area data pick parses on the file-load worker, in place | E | 2 surfaces × 4 (thread, ≥ 10 ticks, 0 copies, digest = base) | code read `_load_from_item` → `load_selected_file`; 12a P12a-3 (2.38 s) |
| LLR-177.2 | Project-load worker raises → `could not be read`, session and app kept | UW | 2 forced raises × 4 checks | P12b-2 executed |
| LLR-177.2a | Save worker raises (non-`OSError`) → rolled back, `could not save`, app running | UW | 6 of 6 | code read: SEC-7 re-raise; P12b-2 |
| LLR-177.2b | A2L worker raises → `could not be read`, session and app kept | UW | 2 × 3 | P12b-2 executed |
| LLR-177.3 | Open Load while busy → busy line, no dialog | UW | 6 triggers → 6 lines, 0 dialogs | code read `action_load_file` |
| LLR-177.3a | The load guard refuses before it asks | UW | 2 routes with unsaved work → 2 lines, 0 questions | check-after-question mutant |
| LLR-177.3b | Variant selector while busy → busy line | UW | 2 of 2 | code read `action_select_variant` |
| LLR-177.3c | Unload while busy → busy line | UW | 2 of 2 | code read `action_unload_all` |
| LLR-177.3d | Save project while busy → busy line | UW | 4 of 4 | code read `action_save_project` |
| LLR-177.3e | Patch Editor change while busy → busy line, image and document unchanged | UW | 12 + 2 | old-list mutant (silent loss) |
| LLR-177.3f | Busy line wording | U | 3 of 3; `[b]P` literal; 0 decision ids | fixed-text mutant |
| LLR-177.3g | A refusal changes nothing | U | digest, focus, stack per refusal | focus-move mutant |
| LLR-177.3h | Refusals stop when the action ends | E | 3 exits → `l` opens the dialog | state-left-set mutant |
| LLR-177.4 | Quit while busy → quit question, focus Stay | E | 3 triggers × 3 | code read: Textual `action_quit` |
| LLR-177.4a | Quit question texts | U | 6 of 6 | load-question-text mutant |
| LLR-177.4b | Stay keeps running | E | 3 of 3 | exit-on-any-answer mutant |
| LLR-177.4c | Quit exits after the end handler | E | 4 of 4, 0 partial folders | exit-at-once mutant; P12b-3 |
| LLR-177.4d | Idle quit exits at once | E | 2 + 1 | always-ask mutant |
| LLR-177.5 | A2L parse bytes reach the step from the worker | E | ≥ 2 bar increases in the parse step, 2 of 2 | no-callback mutant |
| LLR-177.5a | The Save worker advances the bar per file placed | E | ≥ 4 for 4 files; ≥ 10 for 2 000 files | end-only mutant; 12a P12a-1 (no save step) |
| LLR-176.3 | A main-thread step paints its name before its work | E | 2 equalities (tag-table build, project install) + 1 | work-before-refresh mutant |
| LLR-176.4 | The parser reports bytes consumed to an optional callback | U | ≥ 2 calls, non-decreasing, last = size; small A2L ≥ 1 | once-at-end mutant; code read `parse_a2l_file(path)` |
| LLR-176.4a | Same parse result with and without the callback | U | case_06 and case_01: identical | field-changing mutant |
| LLR-176.4b | `a2l.py` listed in the frozen-engine guard | U | 1 assertion; TC-027 after the merge | code read: commented out since batch-95 |

| AT / TC | Owner | 12b share |
|---|---|---|
| AT-B100-18 | HLR-177 (worker half), HLR-177a (refusal half), HLR-177b (quit half), HLR-177c (quit-confirm half) | written at 12b: load the case_06 project (elapsed advances, the log names the project); during a slow save `l` → `busy` naming Save project; `q` asks; `y` waits, 0 partial folders |
| AT-B100-17 | HLR-176 (12a half written at 12a) | parse half written at 12b (12a ruling Q1): the case_06 A2L by keys, the bar rises ≥ 2 times and the elapsed time advances during the parse (LLR-177.5, LLR-176.4) |
| TC-B100-53 | LLR-177.1 … LLR-177.1k, LLR-177.3, LLR-177.3b … LLR-177.3h, LLR-177.4 … LLR-177.4d, LLR-177.5, LLR-177.5a | full |
| TC-B100-54 | LLR-177.2, LLR-177.2a, LLR-177.2b | full |
| TC-B100-52 | LLR-176.3 | full (moved from 12a) |
| TC-B100-73 | LLR-176.4, LLR-176.4a, LLR-176.4b | full (moved from 12a); the TC-027 run after the merge |
| TC-B100-72 | LLR-174.4 + LLR-177.3a | extended (the refusal before the question) |
| TC-B100-50 | LLR-176.1l, LLR-176.1q | extended (the three new worker bodies) |
| TC-B100-51 | LLR-176.2, LLR-176.2c, LLR-176.2d | extended (re-derived over the worker bodies) |
| TC-B100-07 | LLR-164.4 | extended (worker census, 5 stage failures on the worker) |
| TC-B100-08 | LLR-165.1 | re-pinned (the call site moves to the install handler) |
| TC-B100-09 | LLR-165.2 | extended (new names; P2-over-P1 on the worker) |
| TC-B100-66 | LLR-173.7 | extended (busy line, quit question) |

**29148 check.** Every requirement above is singular (1 "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace (LLR-176.4b names a test file's list, which is its subject).

Declared exceptions:
- **Shared response, several triggers.** These hold OR triggers with one identical response; each threshold tests each trigger: LLR-177.3 (`l`, `ctrl+l`, `p`, the button, two palette entries), LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e (12 + 2 messages), LLR-177.4 (`q`, `ctrl+q`, palette), LLR-177.1k (two surfaces).
- **RED only as a mutation.** On the base no worker exists, so these hold trivially there and each RED is a mutation: LLR-177.1d's "0 off-main writes" for project load and Save project (the base's off-main writes are in the file-load worker; the code-read control names them), LLR-177.1g, LLR-177.1i, LLR-177.1j (the base adopts after the commit), LLR-177.3g, LLR-177.4d (the base exits at once on idle `q`), LLR-176.4a.
- **Planned control.** LLR-177.1f's base-digest arm is recorded at the E2 baseline.
- **Owed after the merge.** LLR-176.4b's TC-027 run compares against `main`, where `a2l.py` differs until the increment merges.
- **Timing-dependent arms.** LLR-177.1c, LLR-177.1k and HLR-177's elapsed arm depend on the measured step taking more than 1 s on the host (5.01 s parse, P12b-7; 2.38 s for the 8 MiB-data S19, 12a P12a-3); every "during" arm that needs a long Save uses a forced slow step instead of the host's speed.
- **Seam-dependent wording.** LLR-177.3f and LLR-177.4a paint `<label>`, the running session action's label from 12a's action table (12a S-c); the label strings are 12a's.

## 2 · Defects fixed in place (old → new)

| Defect | Old | New |
|---|---|---|
| HLR-177 compound | 1 statement, 7 "shall"s, 1 AT | HLR-177, HLR-177a, HLR-177b, HLR-177c; AT-B100-18 split into four halves under one id |
| LLR-177.1 compound | 7 "shall"s (workers, main-thread writes, re-derive, worker copy, refusal, quit question, quit wait) | 25 requirements: LLR-177.1 … LLR-177.1j (11), LLR-177.3 … LLR-177.3h (9), LLR-177.4 … LLR-177.4d (5) |
| LLR-177.2 over three actions | 1 "shall" for project load, Save project and the A2L parse | LLR-177.2, LLR-177.2a, LLR-177.2b, each with its token pair |
| LLR-176.3 mechanism in the statement | "`step_busy` shall paint the step's name … through the `call_after_refresh` idiom" | event "a main-thread step paints its name before its work"; the idiom in the trace |
| LLR-176.4 compound | callback + identical result + re-freeze sentence | LLR-176.4, LLR-176.4a, LLR-176.4b |
| Conflict (rule 7) | "run `rederive_for_save` and apply the result on the main thread before its worker starts" vs LLR-167.2 / review F4 (adopt only after `project.json` is on disk) and LLR-177.2 (session as before) | re-derive before (LLR-177.1i), adopt after the commit (LLR-177.1j) — Q1 |
| Conflict | SEC-7 "roll back, then let it surface" (re-raise) vs LLR-177.2 "the app keeps running"; a worker raise ends the app (P12b-2) | report + logged traceback, app running (LLR-177.2a) — Q4 |
| Ambiguous trigger | "while one of these actions runs" vs 12a's overlapping runs (12a Q3) and the existing file-load worker | "while a session action runs": `file_load`, `a2l_load`, `project_load`, `save_project` — Q2 |
| Mechanism, not behaviour | "Every write of `current_file`, … shall run on the main thread through `call_from_thread`" (5 names) | "write the session only on the main thread", over the LLR-165.2 census (LLR-177.1d); the base already writes `_a2l_cache_*` on the file-load worker and `_last_manifest_verify_result` in the save |
| Unverifiable | "the worker shall write from a copy" | "each worker reads only an immutable request built on the main thread", by an AST census (LLR-177.1e) |
| Missing failure path (correctness) | nothing stops the project worker from parsing against the live session | LLR-177.1e + LLR-177.1f: the base's `_parse_loaded_file` merges a MAC into the live `current_file`; a worker that runs before the reset would merge into the previous project's image |
| Infeasible comparison | "the same final snapshot as a main-thread load" (no main-thread load remains after 12b) | equality with a cold load on the worker, plus the base digest recorded at E2 (LLR-177.1f) |
| Missing requirement (ordering) | the reset's place under a worker was undefined; LLR-165.1 pins it inside `_handle_load_project` before `load_selected_file` | LLR-177.1g; LLR-165.1's caller clause edited (draft §C.1) |
| Missing requirement (route) | `_route_load_project` opens the panel after a synchronous return | LLR-177.1h (after the install) |
| Incomplete refused set | "a load on any route, an unload, `v`, a save-back, Save project, a Patch apply or undo" | + redo and every Patch Editor change (LLR-177.3e, Q3); the approved items keep their own requirements |
| Unverifiable wording | "refused with the `busy` token naming the running action" | the exact line `busy: <label> is running — wait for it to finish.` (LLR-177.3f), in the status log, never in `#status_text` |
| Missing requirement | refusals after the action ends | LLR-177.3h (all three exits) |
| Missing control | overriding `action_quit` could break idle quit | LLR-177.4d |
| Feasibility note (Textual 8.2.8) | "Quit … confirmed, it shall wait for the worker" (how undefined) | LLR-177.4c: exit from the end handler (a flag); a main-thread wait would deadlock with `call_from_thread` (`future.result()`); exiting at once runs the worker's callbacks on a stopped app (P12b-3) |
| Missing requirement | the event loop staying free was only observable through 12a's elapsed text | LLR-177.1c (a timer oracle independent of 12a's format) |
| Open from 12a | the work-area image pick and the typed load's copy on the main thread | LLR-177.1k (the pick on the file-load worker); the copy stays, declared — Q5 |
| Stale scope | PLAN row "app (+ flow_screens)" | `app.py` + `a2l.py` (Q7) |

## 3 · Slice for E2

Names come from the requirements and the base. **(guess)** marks a node the requirements imply but do not name; it may end up inline. Sources: `s19_app/tui/app.py` and `s19_app/tui/a2l.py` (2 files; Q7). Tests (not capped): `tests/test_b100_workers.py` (new: TC-B100-53, TC-B100-54, AT-B100-17's parse half, AT-B100-18), `tests/test_b100_busy.py` (TC-B100-52, TC-B100-73; TC-B100-50, TC-B100-51 extended), `tests/test_engine_unchanged.py` (`_ENGINE_PATHS`), `tests/support/` (one wait helper), the re-pins of Q6, and the extended arms in `test_b100_save_guards.py` (TC-B100-07), `test_b100_session_reset.py` (TC-B100-08, TC-B100-09), `test_b100_confirm.py` (TC-B100-72).

### `app.py` — project load (group G-A)

| # | Node | What changes | Requirement |
|---|---|---|---|
| A1 | `_handle_load_project` | keeps every main-thread refusal (link, outside, not found, not listed, unreadable listing, validation, A2L link / cap, no data or A2L); then builds the request, `begin_busy`, starts A2; no install inline | 177.1, .1g |
| A2 | project-load worker (NEW, `@work(thread=True, exit_on_error=False)`) | variant set, manifest, digest check, A2L parse (byte callback), image parse with the next-valid fallback, MAC parse merged with its own image, document read; returns `PreparedProjectLoad` | 177.1, .1e, .5 |
| A3 | project-load install handler (NEW, main) | tag-table / install step painted first (176.3); reset; install image, MAC, A2L; reopen the document into the service and panel; `current_project`, variant set; announcement; `end_busy(final_line)`; panel when routed; the quit flag | 177.1d, .1f, .1g, .1h; 176.3 |
| A4 | project-load failure handler (NEW, main) | `could not be read` line, `end_busy` with the failure, the quit flag | 177.2 |
| A5 | `_route_load_project` | no post-call announcement check; the request carries `routed=True` | 177.1h |
| A6 | `_install_project_image` | parse half → A2; apply half → A3 (may dissolve) | 177.1, .1d |
| A7 | `_reopen_active_document` | `recorded_document_state` → A2; service and panel install → A3 | 177.1, .1d |
| A8 | `_parse_loaded_file` (guess: a pure sibling for the worker) | explicit A2L data and primary to merge; no `self.current_*` read | 177.1e, .1f |
| A9 | `_load_a2l_data_with_cache` | pure parse on the worker; the cache write on the main thread | 177.1d |
| D1 | `PreparedProjectLoad`, `ProjectLoadRequest` (NEW, frozen dataclasses) | seam S-b | 177.1e |

### `app.py` — Save project (group G-B)

| # | Node | What changes | Requirement |
|---|---|---|---|
| B1 | `_handle_save_dialog` (after Inc 11: the commit half) | main: `record_save_entries`, request from the prepared plan and image step, `begin_busy`, start B2; the post-commit statements move to B3 | 177.1a, .1i |
| B2 | Save worker (NEW, `@work(thread=True, exit_on_error=False)`) | `mkdir` … verified `project.json`; LLR-164.4's `OSError` handler and the rollback inside the worker; non-`OSError` → rollback, then a failure outcome; a step report per file placed | 177.1a, .1e, .2a, .5a; 164.4 |
| B3 | Save commit / failure handler (NEW, main) | `adopt_rederived`, `mark_saved`, status lines, panel flag, variant set, `current_project`, `refresh_files`, flow session dir, `end_busy`; or the failure lines; the quit flag | 177.1d, .1j, .2a |
| B4 | `_write_and_verify_manifest` | returns its verify result instead of assigning `_last_manifest_verify_result`; `_rewrite_project_manifest` (main-thread caller) assigns it | 177.1d |
| B5 | `_abort_save` | the session-restore half (`_variant_set`, `_report_filter_path`, `current_project`, `current_project_dir`) is removed, because the worker never writes the session; the file rollback stays | 177.1d |
| D2 | `SaveRequest`, `SaveOutcome` (NEW, frozen dataclasses) | seam S-b | 177.1e |

### `app.py` — A2L attach, work-area pick, refusal and quit (group G-C)

| # | Node | What changes | Requirement |
|---|---|---|---|
| C1 | `load_a2l_from_path` | main checks (resolve, suffix, project already has an A2L); request, `begin_busy`, start C2 | 177.1b |
| C2 | A2L worker (NEW) | copy into the work area (unless in place), parse with the byte callback | 177.1b, .5 |
| C3 | A2L install / failure handler (NEW, main) | tag-table step painted first (176.3); `current_a2l_*`, `current_file.a2l_*`, recent record, `refresh_files`, tag-table build, labels, status, focus, sync to project, `end_busy`; or `could not be read` | 177.1d, .2b; 176.3 |
| C4 | `_load_workarea_file` (9b G1) | A2L arm → C2 with `copy=False`; data arm → `_start_load_worker` in place (no `load_selected_file`) | 177.1b, .1k |
| C5 | busy check (NEW, for example `_refuse_if_busy() -> bool`) | reads 12a's run state; the newest session action's label; paints the busy line | 177.3f, .3g, .3h |
| C6 | busy-check calls (17 entry points) | `action_load_file`, `action_load_project`, `_confirm_then_load` (Inc 10), `action_select_variant`, `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, `action_save_project`; Patch Editor: `on_patch_editor_panel_action_requested`, `…_save_back_decision`, `…_undo_requested`, `…_redo_requested`, `action_patch_undo`, `action_patch_redo`, `…_edit_json_requested`, `…_entry_edit_json_requested`, `…_change_file_selected`, `…_dirty_load_requested` | 177.3 … .3e |
| C7 | `action_quit` (NEW override) | busy → the Inc 10 modal with the quit texts; idle → `exit()` | 177.4, .4a, .4d |
| C8 | quit-answer handler (NEW) | Stay → nothing; Quit → set the quit flag | 177.4b, .4c |
| C9 | shared end tail (guess, for example `_finish_session_action`) | `end_busy`, then `exit()` when the quit flag is set; called by A3, A4, B3, C3 and the file-load end | 177.3h, .4c |
| D3 | `A2LAttachRequest`, `A2LAttachResult` (NEW, frozen dataclasses) | seam S-b | 177.1e |

### `a2l.py` — the named crossing (group G-D)

| # | Node | What changes | Requirement |
|---|---|---|---|
| E1 | `parse_a2l_file(path, progress=None)` | passes the callback to the tree build; the result is unchanged | 176.4, .4a |
| E2 | `build_section_tree` | reports `(bytes_consumed, total_bytes)` from its read loop, at most once per chunk | 176.4 |
| T1 | `tests/test_engine_unchanged.py::_ENGINE_PATHS` (test file) | `s19_app/tui/a2l.py` uncommented | 176.4b |

**Callers checked (base; later increments noted).**
- `_handle_load_project` ← `_route_load_project` only in `src` (after 9b: from `_handle_load_dialog`'s `project` kind and the typed route; after Inc 10: inside `_confirm_then_load`'s continuation). Tests: 20 files, 181 call sites.
- `_route_load_project` ← the 9b router, `_load_path_from_user_input` (`project` kind). Tests: 1 file, 6.
- `_handle_save_dialog` ← `action_save_project`'s dismiss callback (Inc 11: after the dialog's confirm). Tests: 10 files, 101.
- `load_a2l_from_path` ← `_load_path_from_user_input` (typed, recent, the start-up `load_path`); after 9b no longer from `_load_workarea_file`. Tests: 9 files, 52.
- `_load_workarea_file` ← `_load_from_item` (`#files_list`), the 9b router (`workarea`). Tests: `_load_from_item` 3 calls in 5 files that reference `#files_list`.
- `_load_a2l_data_with_cache` ← `_handle_load_project` (`:11858`), `load_a2l_from_path` (`:13145`), `_load_mac_file` (`:14217`), `_parse_loaded_file` (`:15151`, `:15170`; reached from the file-load worker).
- `_parse_loaded_file` ← `_install_project_image` (`:12078`), `load_selected_file` (`:15080`), `_start_load_worker` (`:15743`).
- `_write_and_verify_manifest` ← `_handle_save_dialog` (`:10323`), `_rewrite_project_manifest` (`:12495`).
- `_abort_save` ← `_handle_save_dialog` only (11 sites).
- `_reopen_active_document`, `_install_project_image`, `_reset_project_session` ← `_handle_load_project` only.
- `action_quit` ← `q` (`BINDINGS` tuple `("q", "quit", "Quit")`), `ctrl+q` (Textual `App.BINDINGS`, priority), the palette (built 1:1 from `BINDINGS`).
- `parse_a2l_file` ← `_load_a2l_data_with_cache` (via `a2l_parse` re-export), `tests/test_tui_a2l.py`; P12b-7's probe.

**Unchanged context:** `_start_load_worker` and `load_from_path` (the file load is already a worker; its key `file_load` makes it a session action, Q2), `load_selected_file` (88 direct test calls; no longer reached by the work-area pick), the typed load's copy in `load_from_path` (stays on the main thread, Q5), `choose_install_set`, `compose_load_announcement`, `check_project_files` (`manifest_writer.py`, moves by step), `place_into_workarea`, `ChangeService.emit_and_verify` (writes files, assigns no service state), `_prepare_project_save` (Inc 11), the Inc 10 question modal, `LoadResultScreen`, 12a's seam and table, report / diff-report / before-after workers (not session actions), flow runs (O-7).

**Node count:**
- **Firm:** G-A 9 (A1 … A7, A9, D1), G-B 6 (B1 … B5, D2), G-C 9 (C1 … C8, D3; C6 counted as one census node of 17 one-line sites), G-D 2 (E1, E2) = 26 nodes; with the guesses A8 and C9, 28.
- That is far above ~8, so E2 runs by group. G-A, G-B and G-C all edit `app.py`, so they run in order: G-C1 first (C5, C7, C8, C9: the shared busy check and end tail), then G-D (the parser callback, independent file), G-A, G-B, G-C2 (C1 … C4, C6).
- **Source files:** 2 (`app.py`, `a2l.py`), under the cap of 4 (Q7).

**Seams to fix before E2:** S-a … S-f in `E1-rulings-proposed.md` (the busy check over 12a's run state, the request values, the quit flag, the worker options, the 9b / 10 / 11 hooks, the parser callback).

## 4 · Open questions

Recommendations and the alternatives are in `E1-rulings-proposed.md` (Q1 … Q7); a "settled before this E1" list there records what 12a's rulings already decided. The draft follows each recommendation; a different ruling changes the ids named there. One line each:
- Q1: re-derive before the Save worker, adopt after the commit (F4 wins over "apply before").
- Q2: the busy refusal is triggered by the four session-writing runs (file load, A2L attach, project load, Save project); reports overlap.
- Q3: refuse every Patch Editor change during a session action, not only apply and undo.
- Q4: a non-`OSError` in the Save worker is reported after the rollback, not raised (SEC-7 vs LLR-177.2).
- Q5: the work-area image pick moves onto the existing file-load worker; the typed load's copy stays on the main thread.
- Q6: test re-pin strategy — workers everywhere, success paths wait through one helper (`wait_for_complete()` + 2 pauses); the W class is re-taken by a **poll on a condition**, not by a helper's name (E3 A12b-01) (census: 26 files, 184 direct sites, 1 no-app test).
- Q7: 12b touches `app.py` and `a2l.py`; drop "(+ flow_screens)".

## 5 · Observations

- **Test census (Q6 detail; corrected by E3 A12b-01 / DF-13).** 184 direct call sites in 26 files, 1 no-app test (`test_tui_app.py:85`), plus the 4 sync helpers. The W class is a **poll on a condition**, not a helper's name: in the 7 files whose `_flush` is a fixed loop of `pilot.pause()` calls (`test_b100_announce.py:106`, `test_b100_save_guards.py:158`, `test_b100_session_reset.py:131`, `test_tui_manifest_save.py:58`, `test_tui_patch_variant.py:104`, `test_tui_variants.py:70` (also imported by `test_tui_commandbar.py:1127`), `test_tui_evidence_packs.py:76`), `_flush` becomes the one Q6 helper (`wait_for_complete()` + 2 pauses) — 7 one-line edits, no call-site change. Only `test_tc_b100_30_…under_one_second` becomes vacuous. `tests/support/b100_projects.py` helpers poll (`wait_for`, 400 attempts) and survive, except where a second action follows at once: `:383` loads a project, pauses once, then calls `load_from_path`; under the refusal that call is refused (loud, deterministic).
- **A refusal rule breaks chained tests loudly, not flakily.** A test that starts a second load or save before the first ends now gets a busy line; the failure names the cause.
- **The handler's wall time stops meaning anything.** `tests/support/b100_projects.load_project` returns `_handle_load_project`'s wall time, which `test_b100_document.py:1069` bounds (the SEC8a-2 reopen margin). After 12b the call returns at once, so the bound passes vacuously unless re-pinned to "request → end of install" (Q6). The backlog row SEC8a-2 is about main-thread time, which after 12b is the install only.
- **A residual freeze stays.** The A2L tag-table build (about 3.5 s of the case_06 attach, P12b-4 minus P12b-7) stays on the main thread under HLR-176's declared freeze; LLR-176.3 paints its step name first.
- **Flow runs and reports are not refused.** O-7 keeps flow runs on the main thread, Inc 10 Q8 put flow sets out of scope, and Q2 leaves reports overlapping. A flow WRITE-OUT or a report written into the project folder during a Save worker's save-as is possible; propose a backlog row at the 12b close.
- **Closing the terminal window** ends the process without the quit question (not a key the app receives); a save in flight is then cut. Declared in Risks; it is the part of the R12 row that stays open.
- **Quit pressed again while a confirmed quit waits** opens the question again (harmless); no requirement asks otherwise.
- **The typed load's copy** (up to the 256 MiB cap, about 1 s) stays on the main thread (Q5); 12a's "Observations for Inc 12b's E1" asked for a decision, recorded here.
- **Pre-existing off-main write.** The file-load worker writes `_a2l_cache_key` / `_a2l_cache_data` (`_parse_loaded_file` → `_load_a2l_data_with_cache`, `app.py:15151`, `:15851-15852`). A9 moves the cache write to the main thread for every caller of that function, so the file-load worker's write goes too.
- **Parser progress frequency.** `call_from_thread` blocks the worker until the main thread runs the callback, so the byte reports must be bounded (seam S-f: at most once per chunk) or the parse slows down by the round trips.
- **Backlog.** No BACKLOG-CODE row names 12b. The R12 save-as row is moved here by 12a ruling Q2 and closes at 12b (LLR-177.1a, LLR-177.5a, LLR-177.4c), minus the cancel (VS-PD-2) and the terminal-window close (declared). New row added by E3 DF-7: `load_selected_file` (88 direct test calls; after 12b it has no product caller — the project MAC install moves to the worker and the work-area pick to P-2's file-load start; the re-pin is outside 12b's slice). The rows that target "Inc 12a" for the backlog sweep (CR9-2, CR9-5, CR9-7, CR9-8, SEC9-2, CR9-9, C7) are not worker items and stay with 12a.
