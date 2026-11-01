# Inc 12b E1 — replacement requirement blocks (draft, not merged)

Stage E1 of the design-first pipeline (`dev-flow-v3-beta` skill) for Inc 12b, "project load, Save project, A2L parse on workers" (PLAN.md row 12b: "N5, O-7 — app (+ flow_screens) — gate P-D"; prototype verdict P-D A).

**How to merge.**
1. §A replaces the `### HLR-177 — Project load, Save project and the A2L parse run off the main thread` block in `01-requirements.md` (§3), and inserts the new HLR-177a, HLR-177b and HLR-177c blocks right after it.
2. §B replaces the blocks `### LLR-177.1` and `### LLR-177.2` (§4) with the blocks below, in the order given.
3. §B2 replaces the blocks `### LLR-176.3` and `### LLR-176.4` (moved from 12a with their text unchanged, 12a ruling Q1) with LLR-176.3, LLR-176.4, LLR-176.4a and LLR-176.4b.
4. §C lists the edits to requirements owned by earlier increments that 12b changes (LLR-165.1's caller clause; LLR-164.4, LLR-165.2, LLR-174.4, LLR-176.1l, LLR-176.1q, LLR-176.2, LLR-176.2c, LLR-176.2d, LLR-178.3, LLR-173.7 extended).
5. §D holds the TC-index rows (§5.3), the AT-table edits, the token-table edits (§3 preface) and the reverse-census rows (§5.4).
6. §E is the ledger entry, numbered `LED .NN`. Every `LED-2026-10-26-batch-100.NN` below takes the number assigned at merge.

**Conventions.**
- Every Statement holds exactly one "shall". No other field uses the word.
- Function names appear only in the trace.
- "The base" is the main checkout at `8947666` (Inc 9a merged). Inc 9b, 10 and 11 are designed, not implemented; this draft hooks into the routes as their E1 drafts and fixed interfaces leave them: the 9b router `_handle_load_dialog` and `_load_workarea_file` (`inc-9b-design/codewire/interfaces-9b.md`), the Inc 10 load guard `_confirm_then_load(kind, target, go)` and its question modal (`inc-10-design/E1-scope.md` seams S-a, S-b), and the Inc 11 split of Save project into a main-thread preparation and the commit half (`inc-11-design/E1-scope.md` node N1, S-c).
- **Inc 12a's seam** is fixed (`inc-12a-design/E1-scope.md` S-a … S-c, rulings Q1 … Q10): `begin_busy(key, label, steps) -> int` (a generation), `step_busy(key, gen, n, done=None, total=None)`, `end_busy(key, gen, outcome, final_line=None)`, all main-thread only and reached from workers through `call_from_thread`; the run state is an ordered mapping key → run, the newest shown (12a Q3); the action table `_BUSY_ACTIONS` has the keys `file_load`, `a2l_load`, `project_load`, `save_project`, `report`, `diff_report`, `before_after`, each with a label template.
- **Session action** means a run in 12a's run state whose key is `file_load`, `a2l_load`, `project_load` or `save_project`: the four actions that write the session (ruling Q2). Report, diff-report and before/after runs are not session actions; they may overlap, as 12a ruling Q3 shows them. **The three 12b actions** are project load, Save project and the A2L attach.
- **Worker step** means the part of a 12b action that runs on its worker thread: for project load, reading and parsing the project's files; for Save project, the writes from the folder's creation to the verified `project.json`; for the A2L attach, the copy into the work area and the parse.
- **Session** means every attribute the `S19TuiApp` source assigns (the LLR-165.2 census domain) plus the change service's state. **Session digest** means the tuple (`current_file.path`, SHA-256 of the installed image bytes, `current_project`, `current_a2l_path`, the MAC path, the change document's entry count), read before and after an action.
- **The busy line** is the status-log line `busy: <label> is running — wait for it to finish.` (LLR-177.3f), where `<label>` is the newest running session action's label from 12a's action table. **The quit question** is the Inc 10 question modal built with the quit texts of LLR-177.4a.
- **Forced slow step** means a test double that blocks the named step on a `threading.Event` until the test releases it, so a "during" arm is deterministic.
- Painted strings are English. The busy line is painted in the status log (`set_status`); `#status_text` stays with 12a's progress line while a long action runs (HLR-176d).

---

## §A — HLR blocks (replace HLR-177; insert HLR-177a, HLR-177b, HLR-177c after it)

### HLR-177 — Project load, Save project and the A2L parse do their heavy work on worker threads
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.2, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall run the reading and parsing of a project load, the writing of Save project and the copy and parse of an A2L attach on worker threads.
- **Decomposition:**
  - LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1k, LLR-177.1c: the three worker steps, the work-area image pick on the existing file-load worker, and the event loop staying free.
  - LLR-177.1d, LLR-177.1e: the session is written only on the main thread, and a worker reads only its request.
  - LLR-177.1f, LLR-177.1g, LLR-177.1h: the project load's result, reset and Load-result panel after the worker.
  - LLR-177.1i, LLR-177.1j: the Save project re-derive before the worker and the adopt after it.
  - LLR-177.2, LLR-177.2a, LLR-177.2b: a worker that raises.
  - LLR-177.5, LLR-177.5a, LLR-176.3, LLR-176.4, LLR-176.4a, LLR-176.4b: the 12b actions on 12a's indicator (the parse's byte reports, the save's files placed, the main-thread step painted first, the parser callback and the `a2l.py` re-freeze).
  - The compound HLR-177 (7 obligations: workers, main-thread installs, re-derive, copy, elapsed time, refusal, quit) is split here into HLR-177, HLR-177a, HLR-177b and HLR-177c (LED .NN). "Flow runs stay on the main thread" is a scope note (O-7), kept in the Rationale.
- **Variant slots (filled by the P-D verdict A, LED-2026-10-26-batch-100.2):** VS-PD-3 = a second request is refused with a status naming the running action (HLR-177a).
- **Rationale (informative):**
  - These three block the main thread today (ARQ §7). Executed on the base (P12b-4 … P12b-6): the case_06 A2L attach blocks the event loop for 8.76 s, the case_06 project load for 5.81 s, a 0.1 s interval timer ticks 0 times during either; Save project of that project takes 0.12 s.
  - R-PD makes 12b unconditional. O-7 leaves flow runs on the main thread. A-17 keeps the worker off the live image. UX-34 lists the refused set and the quit rule.
  - A thread worker, not an async one: Textual 8.2.8 runs an async worker's coroutine on the event loop (`Worker._run_async` awaits it there), so CPU-bound parsing would still block it.
  - The tag-table build of an attached A2L stays on the main thread; HLR-176 declares that freeze (12a, LLR-176.3). P12b-7 measures the worker share: `parse_a2l_file` takes 5.01 s of the attach's 8.76 s.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or tc_b100_54 or at_b100_18"`
- **Numeric pass threshold:**
  - A project holding the case_06 A2L, data and MAC files, loaded from the Load dialog → the indicator's elapsed text changes ≥ 1 time before the install ends, and the status log then names the project loaded (2 of 2).
  - Each of the three worker steps → the thread that runs it is not the main thread (thread-id probe, 3 of 3).
- **Negative control:** executed on the base (P12b-5): `_handle_load_project('P'): wall 5.81 s; ticks during the call 0; … ran on main thread True` → the elapsed text cannot change during the load → AT-B100-18's worker half RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, worker half) the engineer loads a project holding the case_06 A2L: the elapsed time advances during the load, and the status log then names the project loaded.
  - **Shipped surface:** Load (`p`, `#load_list`, `enter`), `#status_text`, the status log.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☒ error
    - boundary: a project whose worker step ends inside one timer tick (shown and cleared, the result installed);
    - error: a worker that raises (the app keeps running, the indicator ends, the session unchanged; LLR-177.2 … LLR-177.2b).
    - empty / invalid: N/A — the inputs are the existing load and save inputs, whose classes earlier HLRs own.
  - **Negative control:** executed on the base (P12b-5, above) → AT-B100-18 RED.

### HLR-177a — A second request is refused while a session action runs
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks for an action that replaces or changes the image, the change document or the project while a session action runs, then the system shall refuse it with the busy line naming the running action.
- **Decomposition:** LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h.
- **Variant slots:** VS-PD-3 = refuse (P-D verdict A; Q-6 at round 1).
- **Rationale (informative):**
  - Two writers of the session at once are the defect class this removes. An exclusive worker group does not prevent it: Textual 8.2.8 cancels the older `Worker` object, but its thread keeps running and its `call_from_thread` install still lands (P12b-1: `first worker state: CANCELLED | landed: [('second', …), ('first', …)]`). So the refusal is a state check before the action starts.
  - "Changes the change document" widens the approved list (apply, undo) to every Patch Editor change (ruling Q3). Only the four session actions trigger the refusal; reports, diff reports and before/after runs may overlap, as 12a ruling Q3 shows them (ruling Q2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `l`, a Workarea Files pick, `v`, `U`, a save-back, a Patch apply, a Patch undo and `ctrl+s` → 8 busy lines naming Save project, the session digest unchanged after each, the screen stack depth unchanged (8 of 8).
- **Negative control:** code read, base: no busy state exists (`grep -n "begin_busy\|busy" s19_app/tui/app.py` finds no refusal), and Save project runs synchronously (P12b-6), so no key reaches the app during it → AT-B100-18's refusal half RED. Mutation: omitting `v` from the refused set → the image changes during the save → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, refusal half) during a Save project, after the worker step is painted, the engineer presses `l`: the status log paints `busy` naming Save project, and no Load dialog opens.
  - **Shipped surface:** `l`, `ctrl+s`, `v`, `U`, the Workarea Files list, the Patch Editor, the status log.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary ☒ invalid
    - boundary: a request in the frame after the session action ends (accepted, LLR-177.3h); a report running alone (no refusal);
    - invalid: each refused request kind (load, variant, unload, save, Patch Editor change).
  - **Negative control:** as above → AT-B100-18 RED.

### HLR-177b — Quit asks first while a session action runs
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks to quit while a session action runs, the system shall ask the quit question before exiting.
- **Decomposition:** LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4d.
- **Rationale (informative):** UX-34. The question reuses the Inc 10 modal with its own texts (C-UX-4, ARCH-PDR-4); the modal starts on its No button (LLR-174.2b).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** `q` during a Save project held at a forced slow step → 1 quit question, the focus on `#confirm_no`, the app running (3 of 3); `q` with no session action → the app exits with 0 questions.
- **Negative control:** code read, base: `S19TuiApp` defines no `action_quit`, so `q` and `ctrl+q` run Textual's `App.action_quit` (`self.exit()`, `textual/app.py:4460`) → 0 questions → RED.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, quit half) during a Save project the engineer presses `q`: a question asks first, with the focus on Stay.
  - **Shipped surface:** `q`, `ctrl+q`, the quit question (`#confirm_yes`, `#confirm_no`).
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary — `q` and `ctrl+q`; no session action running.
  - **Negative control:** as above → AT-B100-18 RED.

### HLR-177c — A confirmed quit leaves no partial save
- **Traceability:** US-167
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer confirms the quit question, the system shall exit only after the running session action has finished or rolled back.
- **Decomposition:** LLR-177.4c.
- **Rationale (informative):** UX-34; backlog row "the 2 000-file save-as runs on the main thread … closing the app mid-copy leaves a partial Q", moved to 12b without its cancel by 12a ruling Q2 (R12's "rollback on close"). Exiting at once is unsafe: after `App.exit()` a thread worker's later `call_from_thread` still runs its callback, on an app that is no longer running (P12b-3: `landed: [('late', …)] | … app running: False`).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_b100_workers.py -k "tc_b100_53 or at_b100_18"`
- **Numeric pass threshold:** a Save project held at a forced slow step, `q`, `y` → the app still running while the step is held (1 check); the step released → the app exits, and the target folder is either complete (its `project.json` verifies) or absent (0 partial folders); the same with the held step forced to raise → the app **keeps running**, the folder is absent, the failure line is `log_lines[-1]` and the failure toast is shown, and the entries are kept (2 of 2).
- **Negative control:** a mutation that exits at once on `y` → the app stops while the step is held → RED. Executed P12b-3 shows why the arm is needed (the worker's callback runs on a stopped app).
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** (AT-B100-18, quit-confirm half) during a slow save-as the engineer presses `q`, then `y`: the app stays until the save ends, then exits, and the work area holds no partial project folder.
  - **Shipped surface:** `q`, the quit question, the work area on disk.
  - **Acceptance test(s):** AT-B100-18
  - **Boundary catalog (QC-3):** ☒ boundary ☒ error
    - boundary: the action ends in the frame `y` is pressed;
    - error: the worker step raises after `y` (rolled back; the app keeps running, the failure line is `log_lines[-1]` and the failure toast is shown, and the entries are kept).
  - **Negative control:** as above → AT-B100-18 RED.

---

## §B — LLR blocks (replace LLR-177.1 and LLR-177.2)

### LLR-177.1 — The project load reads and parses on a worker
- **Traceability:** HLR-177 · trace: `_handle_load_project` (changed), the project-load worker (NEW, `@work(thread=True)`), `check_project_files`, `read_project_manifest`, `build_variant_set`, `parse_a2l_file`, `_parse_loaded_file`, `recorded_document_state` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.1, LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.19, LED-2026-10-26-batch-100.38, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall read and parse a project's files for a project load on a worker thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project with data, MAC, A2L and a recorded change document, loaded from the Load dialog → the calls that read the files (the digest check, the manifest read, the A2L parse, each image parse, the document read) each record a thread id other than the main thread's (spies, 5 of 5). The refusals that need no file content (a link, outside, not listed, no data or A2L file) still paint in the frame of the request, before any worker starts (4 of 4).
- **Negative control:** executed on the base (P12b-5): `ran on main thread True`, 0 timer ticks in 5.81 s → RED. Mutation: calling the A2L parse in the main-thread install → that spy records the main thread → RED.
- **Boundary catalog:** ☒ boundary — an A2L-only project; a project whose recorded variant is unreadable (the next valid one is parsed on the same worker).

### LLR-177.1a — Save project writes on a worker
- **Traceability:** HLR-177 · trace: `_handle_save_dialog` (changed: the commit half), the Save worker (NEW, `@work(thread=True)`), `_save_project_files`, `save_patched_image`, `verify_written_image`, `_write_manifest_for_save`, `_abort_save` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall create the project folder, place the files, write the emitted image and write and verify `project.json` for Save project on a worker thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a patched session saved as a new project → the folder creation, each placement, the image emit and the manifest write record a thread id other than the main thread's (spies, 4 of 4). Every refusal of the Inc 11 preparation (empty, device, reserved, too long, path, clash, link, missing source, plan, free space) paints before any worker starts and creates 0 folders (10 of 10).
- **Negative control:** executed on the base (P12b-6): `_handle_save_dialog('Q') … ran on main thread True` → RED.
- **Boundary catalog:** ☒ boundary — a copy-only save and an emitting save; a save into the open project (merge).

### LLR-177.1b — Every A2L attach copies and parses on a worker
- **Traceability:** HLR-177 · trace: `load_a2l_from_path` (changed), `_load_workarea_file` (9b G1, its A2L arm), the A2L worker (NEW, `@work(thread=True)`), `copy_into_workarea`, `parse_a2l_cached` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall copy an attached A2L file into the work area and parse it on a worker thread, on every A2L attach route.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a typed `.a2l` path, a recent `.a2l` entry, a Workarea Files pick of an `.a2l` file (in place, parse only) and the start-up `load_path` of an `.a2l` → the parse records a thread id other than the main thread's (4 of 4); the three copying routes → the copy records a non-main thread id (3 of 3).
- **Negative control:** executed on the base (P12b-4): `load_a2l_from_path(case_06 A2L): wall 8.76 s; ticks during the call 0; … ran on main thread True` → RED.
- **Boundary catalog:** ☒ boundary — each route; an A2L smaller than one progress chunk.

### LLR-177.1c — The event loop keeps running during a worker step
- **Traceability:** HLR-177 · trace: the three workers (NEW); Textual `set_interval` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS state):** While a worker step of the three 12b actions runs, the system shall keep running the main thread's timers.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a 0.1 s interval timer started before the request → ≥ 10 ticks between the worker's start and the install for the case_06 project load, and ≥ 10 ticks during the case_06 A2L attach's worker step; a Save project held at a forced slow step for 1.5 s → ≥ 10 ticks (3 of 3).
- **Negative control:** executed on the base (P12b-4, P12b-5): 0 ticks during 8.76 s and during 5.81 s → RED.
- **Boundary catalog:** ☒ boundary — the measured step on the development host; a worker step shorter than one tick (0 ticks required, the result installed).

### LLR-177.1d — The session is written only on the main thread
- **Traceability:** HLR-177 · trace: the three workers and their main-thread install handlers (NEW); `call_from_thread`; `parse_a2l_cached` / `_store_a2l_cache` (the cache write), `_write_manifest_for_save` / `_write_and_verify_manifest` (the `_last_manifest_verify_result` write), `_abort_save` (its session restore), `ChangeService.record_save_entries` / `adopt_rederived` / `mark_saved` (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall write the session only on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a probe that records the thread of every attribute write on the app object (a test subclass overriding `__setattr__`) and of every `ChangeService` method that changes its state, during a project load, a Save project (emitting), an A2L attach and one forced failure of each → 0 writes from a thread other than the main thread (6 runs, 0 off-main writes).
- **Negative control:** code read, base: `_start_load_worker` → `_parse_loaded_file` → `_load_a2l_data_with_cache` assigns `_a2l_cache_key` and `_a2l_cache_data` on the load worker (`app.py:15151`, `:15851-15852`), and `_write_and_verify_manifest` assigns `_last_manifest_verify_result` (`:11260`, `:11311`); moved into a worker unchanged, each records an off-main write → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the success and the failure path of each action.

### LLR-177.1e — A worker reads only its request
- **Traceability:** HLR-177 · trace: the three workers (NEW); their request values (NEW, frozen dataclasses) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall give each worker of the three 12b actions everything it reads from the session in an immutable request built on the main thread before the worker starts.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53` (an AST census)
- **Numeric pass threshold:** AST census of `s19_app/tui/app.py`: the body of each worker function, and of every `app.py` method it calls, holds 0 reads of `self.current_file`, `self.current_project`, `self.current_project_dir`, `self.current_a2l_path`, `self.current_a2l_data`, `self._variant_set` and `self._change_service` (3 workers, 0 reads); each worker takes one request argument whose class is a frozen dataclass (3 of 3).
- **Negative control:** code read, base: `_parse_loaded_file` reads `self.current_file` and `self.current_a2l_*` to merge a MAC with the loaded primary (`app.py:15098-15226`), and the save's emit reads `self.current_file.ranges` (`:10006-10019`) → moved into a worker unchanged, the census names them → RED.
- **Boundary catalog:** none — a structural census; its set is every function the workers reach in `app.py`.

### LLR-177.1f — A project loaded on a worker equals a cold load
- **Traceability:** HLR-177 · trace: the project-load worker and its install handler (NEW); `_session_snapshot` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project load's worker step completes, the system shall install a session equal to a cold load of that project.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-09 (its P2-over-P1 arm, on the worker path)
- **Numeric pass threshold:**
  - P2 holds a data file, a MAC file and an A2L file. P2 loaded over P1 (an image loaded, a patch applied) → `_session_snapshot()` equals that of a cold load of P2, 0 differing names outside LLR-165.2's allow-list.
  - The cold P2 session digest equals the digest the base produces for the same fixture (recorded at the E2 baseline).
  - After the install, `current_file.variant_id` equals the opened variant's id (1 assertion; the snapshot normalises `current_file` to type, path and image digest, so it does not see a lost variant id).
  - 3 of 3.
- **Negative control:** a mutation in which the worker parses P2's MAC against the live `current_file` (the base's `_merge_mac_with_existing_primary` path) → the MAC merges into P1's image → 1 differing name (`current_file`) → RED. The base-digest arm is a `planned` control, recorded at the E2 baseline.
- **Boundary catalog:** ☒ boundary — a MAC beside a data file; an A2L-only project.

### LLR-177.1g — The project session resets after the worker read, before the first install
- **Traceability:** HLR-177 · trace: `_reset_project_session` (caller moves), the project-load install handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project load's worker step completes, the system shall reset the project session on the main thread before the first install.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-08 (its one-call-site census, re-pinned to the install handler)
- **Numeric pass threshold:** call-order spy on a project load → worker step end, then 1 reset on the main thread, then the first install (order 3 of 3); a forced worker failure → 0 resets.
- **Negative control:** a mutation that resets before the worker starts → the forced-failure arm leaves an empty session → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a successful load; a worker failure.

### LLR-177.1h — The Load-result panel opens after the install
- **Traceability:** HLR-177, HLR-178 · trace: `_route_load_project` (changed), the project-load install handler (NEW), `LoadResultScreen` (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a project load started from a load route completes its install, the system shall open the Load-result panel.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project row of the Load dialog, `enter` → 0 `LoadResultScreen` while the worker step is held, 1 after the install (2 of 2); a typed absolute project path → 1 panel after the install; a direct `_handle_load_project` call → 0 panels (LLR-174.3b).
- **Negative control:** a mutation that keeps the base's identity check after `_handle_load_project` returns (`_route_load_project`, `app.py:7478-7482`) → the announcement is not yet composed when the call returns → 0 panels → RED.
- **Boundary catalog:** ☒ boundary — the dialog route, the typed-path route, a direct call; a load that stops before composing (0 panels).

### LLR-177.1i — Save project re-derives the image on the main thread before its worker
- **Traceability:** HLR-177 · trace: `_decide_project_image`, `ChangeService.rederive_for_save`, `render_patched_image` (Inc 11: called by `_prepare_project_save` / the per-open session inputs) (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall re-derive and render the image Save project emits on the main thread before the Save worker starts.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** an emitting save → `rederive_for_save` and `render_patched_image` each record the main thread's id, and both calls precede the worker start (order spy, 2 + 2).
- **Negative control:** a mutation that re-derives inside the worker → the thread-id arm RED, and LLR-177.1e's census names `self._change_service` → RED.
- **Boundary catalog:** ☒ boundary — an emitting save; a copy-only save (no re-derive, 0 calls).

### LLR-177.1j — Save project adopts the re-derived image after the save commits
- **Traceability:** HLR-177 · trace: the Save commit handler (NEW), `ChangeService.adopt_rederived` / `mark_saved` (`app.py`, `change_service.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save worker reports a committed save, the system shall adopt the re-derived image on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; `pytest tests/test_b100_save_image.py -k "failed_manifest_write_adopts_nothing"` (re-pinned to wait for the worker)
- **Numeric pass threshold:** an emitting save that commits → 1 `adopt_rederived` call on the main thread, after `project.json` is on disk; a forced manifest-write failure → 0 adopt calls and the session map still holds the source bytes at the entry (review F4) (3 of 3).
- **Negative control:** a mutation that adopts before the worker starts (the old LLR-177.1 reading "apply the result … before its worker starts") → the forced-failure arm shows the re-derived image although no file holds it → RED.
- **Boundary catalog:** ☒ boundary ☒ error — a committed save; a manifest-write failure.

### LLR-177.1k — A data file picked from the work area is parsed on a worker
- **Traceability:** HLR-177 · trace: `_load_workarea_file` (9b G1; its data arm), `_start_load_worker` (existing, key `file_load`), `load_selected_file` (no longer called by the pick) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer picks a data file from the work area, the system shall parse it on the file-load worker, in place.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a Workarea Files pick and a Load dialog `workarea` row of a generated S19 holding 8 MiB of data → the parse records a thread id other than the main thread's, ≥ 10 ticks of a 0.1 s timer pass during it, 0 `copy_into_workarea` calls (spy), and the session digest equals that of the base's synchronous pick on a twin fixture (4 of 4 per surface).
- **Negative control:** code read, base: `_load_from_item` → `load_selected_file` parses on the main thread (`app.py:13325-13335`, `:15047`); 12a P12a-3 measured the 8 MiB-data S19 parse at 2.38 s → 0 ticks → RED.
- **Boundary catalog:** ☒ boundary — both surfaces; a MAC file (attached, same worker); a file deleted after the list was painted (0 loads, as today).
- **Note (informative):** 12a's E1 left this pick and the typed load's copy to 12b's E1 (`inc-12a-design/E1-rulings-proposed.md`, "Observations for Inc 12b's E1"); ruling Q5 decides it. The typed load's copy (`copy_into_workarea` before `_start_load_worker`) stays on the main thread.

### LLR-177.2 — A project load whose worker raises keeps the session
- **Traceability:** HLR-177 · trace: the project-load worker and its failure handler (NEW); `end_busy` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If a project load's worker step raises, then the system shall paint the `could not be read` line for that project and keep the session and the app as they were before the load.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** a `PermissionError` and a `ValueError` forced into the worker's manifest read → each: 1 status line holding `could not be read` and `check that the folder can be opened, then load again`, the session digest unchanged, 0 resets, the app running, the indicator ended with the failure (2 × 4 checks).
- **Negative control:** executed on a minimal Textual 8.2.8 app (P12b-2): an exception escaping a `@work(thread=True)` body ends the app (`WorkerFailed`, return code 1) → RED. Mutation: no catch in the worker → the same.
- **Boundary catalog:** ☒ error — an `OSError` and a non-`OSError`.

### LLR-177.2a — A Save project whose worker raises rolls back and reports
- **Traceability:** HLR-177, HLR-164 · trace: the Save worker (NEW), `_abort_save`, `_remove_created_project_dir`, the Save failure handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the Save worker raises an exception that is not an `OSError`, then the system shall remove what this save created, paint the `could not save` line and keep the app running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`; `pytest tests/test_b100_save_image.py -k non_os_error_after_the_emit` (re-pinned: reported, not raised)
- **Numeric pass threshold:** a `ValueError` forced into the image verify after the emit → the target folder absent, the work-area tree digest unchanged, 1 status line holding `could not save` and `check the folder`, 1 logged traceback, the app running, the session digest unchanged (6 of 6).
- **Negative control:** code read, base: the handler re-raises after the rollback (`app.py:10413-10425`, SEC-7 "then let it surface"); on a worker that raise ends the app (P12b-2) → RED.
- **Boundary catalog:** ☒ error — a non-`OSError` after the emit; before the emit.
- **Note (informative):** an `OSError` keeps LLR-164.4's handler (extended at 12b, §C).

### LLR-177.2b — An A2L attach whose worker raises keeps the session
- **Traceability:** HLR-177 · trace: the A2L worker and its failure handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If an A2L attach's worker step raises, then the system shall paint the `could not be read` line for that A2L file and keep the session and the app as they were before the attach.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-54 — `pytest tests/test_b100_workers.py -k tc_b100_54`
- **Numeric pass threshold:** a `ValueError` forced into the parse and a `PermissionError` forced into the copy → each: 1 status line holding `could not be read` and `check that the file can be opened, then load again`, `current_a2l_path` and `current_a2l_data` unchanged, the app running (2 × 3 checks).
- **Negative control:** executed P12b-2 (an escaping exception ends the app) → RED.
- **Boundary catalog:** ☒ error — the copy and the parse.
- **Note (informative):** a failed A2L attach records nothing in the recents — recording moves to the install handler (E2 ruling P2-9); the base recorded the source before the parse.

### LLR-177.3 — Load requests are refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_load_file`, `action_load_project`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks to open Load while a session action runs, then the system shall paint the busy line and open no Load dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a project load held at a forced slow step: `l`, `ctrl+l`, `p`, a click on `#ws_load_project_button` and the palette entries `load_file` and `load_project` → 6 busy lines, 0 `LoadDialog` on the stack (6 of 6).
- **Negative control:** code read, base: `action_load_file` pushes the dialog unconditionally (`app.py:7329`) → RED.
- **Boundary catalog:** ☒ invalid — each of the six triggers.

### LLR-177.3a — The load guard refuses before it asks
- **Traceability:** HLR-177a, HLR-174 · trace: `_confirm_then_load` (Inc 10, B100-I20), the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If an image-replacing route reaches the load guard while a session action runs, then the system shall paint the busy line without asking the load question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-72 — `pytest tests/test_b100_confirm.py -k tc_b100_72`
- **Numeric pass threshold:** with an unsaved patch and an A2L attach held at a forced slow step: a Workarea Files pick of `x.s19` and the variant selector's pick → 2 busy lines, 0 load questions, the session digest unchanged (2 of 2).
- **Negative control:** a mutation that runs the busy check after the guard's question → 1 question before the refusal → RED.
- **Boundary catalog:** ☒ boundary — a route with unsaved work (the question would have been asked); one without.

### LLR-177.3b — The variant selector is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_select_variant`, `_handle_load_result`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks for the variant selector while a session action runs, then the system shall paint the busy line and open no variant selector.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `v` and the palette entry `select_variant` → 2 busy lines, 0 `SelectVariantScreen` (2 of 2).
- **Negative control:** code read, base: `action_select_variant` pushes the selector with no state check (`app.py:7509`) → RED.
- **Boundary catalog:** ☒ invalid — `v`, the palette entry.

### LLR-177.3c — An unload is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_unload_all`, `on_loaded_artifacts_panel_unload_requested`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks to unload while a session action runs, then the system shall paint the busy line and unload nothing.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `U` and a Loaded panel `[u]` on the A2L slot → 2 busy lines, the session digest unchanged (2 of 2).
- **Negative control:** code read, base: `action_unload_all` (`app.py:14668`) has no state check → RED.
- **Boundary catalog:** ☒ invalid — unload all; one artifact.

### LLR-177.3d — Save project is refused while a session action runs
- **Traceability:** HLR-177a · trace: `action_save_project`, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks for Save project while a session action runs, then the system shall paint the busy line and open no Save project dialog.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a project load held at a forced slow step: `ctrl+s`, `s` and the palette entry `save_project` → 3 busy lines, 0 `SaveProjectScreen`; during a Save project, `ctrl+s` → 1 busy line (4 of 4).
- **Negative control:** code read, base: `action_save_project` (`app.py:7355`) has no state check → RED.
- **Boundary catalog:** ☒ invalid — each trigger; a second save during a save.

### LLR-177.3e — Patch Editor changes are refused while a session action runs
- **Traceability:** HLR-177a · trace: `on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`, `on_patch_editor_panel_undo_requested`, `on_patch_editor_panel_redo_requested`, `action_patch_undo`, `action_patch_redo`, `on_patch_editor_panel_edit_json_requested`, `on_patch_editor_panel_entry_edit_json_requested`, `on_patch_editor_panel_change_file_selected`, `on_patch_editor_panel_dirty_load_requested`, `_apply_changeset_json_edit`, `_apply_entry_json_edit`, the two `LoadGuardScreen` accept arms, the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS unwanted):** If the engineer asks the Patch Editor for an action that changes the image or the change document while a session action runs, then the system shall paint the busy line and leave the image and the document unchanged.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: the 11 dispatcher actions `apply_doc`, `add_entry`, `edit_entry`, `remove_entry`, `load_doc`, `parse_paste`, `refresh_doc`, `validate_doc`, `run_checks`, `save_doc`, `execute_scope`; the `UndoRequested` and `RedoRequested` handlers; a save-back decision; an edit-JSON request and an entry edit-JSON request → 16 busy lines; the image SHA-256 and the document's serialised entries unchanged after each (16 of 16). The four continuations — the `ChangeSetJsonScreen` result, the `EntryJsonScreen` result, and the accept arm of the two `LoadGuardScreen` paths — also refuse, dropping the JSON the user typed, with the busy line (4 of 4).
- **Negative control:** a mutation that refuses only `apply_doc` and undo (the old list) → the `add_entry` arm adds an entry that the save's commit then marks saved (`panel.mark_saved()`, `app.py:10558-10572`) although no file holds it → RED.
- **Boundary catalog:** ☒ invalid — every message the Patch Editor sends that reaches the change service.

### LLR-177.3f — The busy line names the running action
- **Traceability:** HLR-177a · trace: the busy check (NEW); 12a's run state and action-table label (12a S-b, S-c) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall word each busy refusal as `busy: <label> is running — wait for it to finish.`, where `<label>` is the running action's label.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-66 (no decision id)
- **Numeric pass threshold:** a refusal during each of the three 12b actions → 1 status-log line each, holding `busy`, that action's label and `wait for it to finish` (3 of 3); a project named `[b]P` → the label paints `[b]P` with 0 markup spans; 0 decision ids (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`) in the line.
- **Negative control:** a mutation that paints a fixed `busy` with no label → the label arm RED.
- **Boundary catalog:** ☒ boundary ☒ invalid — each action; a hostile project name.

### LLR-177.3g — A refusal changes nothing
- **Traceability:** HLR-177a · trace: the busy check (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall leave the session, the focus and the screen stack unchanged when it refuses a request as busy.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** for each refusal of LLR-177.3 … LLR-177.3e → the session digest, `app.focused` and the screen-stack depth equal their values before the request (3 checks per refusal).
- **Negative control:** a mutation that moves the focus to the status log before refusing → the focus arm RED.
- **Boundary catalog:** ☒ boundary — the focus on a list, on an input, on the rail.

### LLR-177.3h — Refusals stop when the session action ends
- **Traceability:** HLR-177a · trace: the busy check (NEW); `end_busy` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a session action ends by success, failure or exception, the system shall accept the requests it refused while that action ran.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a project load ending by success, by a reported failure and by a forced exception → after each, `l` opens the Load dialog (3 of 3).
- **Negative control:** a mutation that leaves the running state set on the exception exit → `l` paints the busy line after the failure → RED.
- **Boundary catalog:** ☒ boundary ☒ error — the three exits.

### LLR-177.4 — Quit during a session action opens the quit question
- **Traceability:** HLR-177b · trace: `action_quit` (NEW override), the question modal (Inc 10) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks to quit while a session action runs, the system shall open the quit question with the focus on its Stay button.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** during a Save project held at a forced slow step: `q`, `ctrl+q` and the palette entry `quit` → 1 quit question each, `focused.id == "confirm_no"`, the app running (3 × 3).
- **Negative control:** code read, base: no `action_quit` in `S19TuiApp`; Textual's `App.action_quit` calls `self.exit()` (`textual/app.py:4460-4462`) → RED.
- **Boundary catalog:** ☒ boundary — `q`, `ctrl+q`, the palette.

### LLR-177.4a — The quit question names the running action
- **Traceability:** HLR-177b · trace: the quit question texts (NEW), the question modal `__init__(title, body, yes_label, no_label)` (Inc 10, LLR-174.2a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall build the quit question with the title `Quit?`, the text `still working: <label> — wait, or quit after it finishes` and the button labels `Quit (y)` and `Stay (n)`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; TC-B100-66 (no decision id)
- **Numeric pass threshold:** the question during a Save project of `P1` → the 4 strings painted, the label naming Save project; 0 painted `Replace`; 0 decision ids (6 of 6).
- **Negative control:** a mutation that opens the Inc 10 load question texts → `Replace …?` painted → RED.
- **Boundary catalog:** ☒ boundary — each of the three 12b actions as the running one.

### LLR-177.4b — Stay keeps the session action running
- **Traceability:** HLR-177b · trace: the quit-answer handler (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer answers the quit question with Stay, the system shall keep the app and the session action running.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** `n`, `escape` and an immediate `enter` → the question closed, the app running, and after the held step is released the save completes and its success line paints (3 of 3).
- **Negative control:** a mutation that exits on any answer → the `n` arm stops the app → RED.
- **Boundary catalog:** ☒ boundary — the three cancel answers (LLR-174.2d, LLR-174.2e).

### LLR-177.4c — Confirmed quit waits for the session action's end
- **Traceability:** HLR-177c · trace: the quit-answer handler (NEW), the end handlers of the three actions (NEW) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer answers the quit question with Quit, the system shall exit after the running session action's end handler has run on the main thread.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:**
  - A Save project held at a forced slow step, `y` → the app running while held; released → the app exits, and the target folder's `project.json` verifies.
  - The held step forced to raise after `y` → the app keeps running, the folder is absent, the failure line is `log_lines[-1]` and the failure toast is shown (the failure arm clears `_quit_pending`).
  - A project load held at its worker step, `y` → the app exits after the install, with 0 exceptions logged.
  - 0 partial folders over the three arms (4 of 4).
- **Negative control:** a mutation that exits on `y` → the app stops while the step is held → RED. Executed P12b-3: after `App.exit()` the worker's `call_from_thread` callback runs with `app running: False`, so the end handler's status and rollback reporting would run on a stopped app.
- **Boundary catalog:** ☒ boundary ☒ error — a save, a load, a failing save.
- **Note (informative):** the wait is a flag read by the end handler, never a main-thread wait on the worker: a main-thread wait would deadlock with the worker's own `call_from_thread`, which blocks until the main thread runs its callback (Textual 8.2.8 `call_from_thread` returns `future.result()`).

### LLR-177.4d — Quit with no session action exits at once
- **Traceability:** HLR-177b · trace: `action_quit` (NEW override) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the engineer asks to quit while no session action runs, the system shall exit without a question.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** idle `q` and idle `ctrl+q` → the app exits, 0 questions (2 of 2); `q` while the Inc 10 load question is open and idle → the question keeps the key (LLR-174.2g), 0 exits.
- **Negative control:** a mutation that always asks → the idle arm opens a question → RED.
- **Boundary catalog:** ☒ boundary — idle; idle under a modal.

### LLR-177.5 — The A2L parse step reports its bytes from the worker
- **Traceability:** HLR-177, HLR-176 · trace: the A2L worker and the project-load worker (NEW); the parser's progress callback (LLR-176.4, moved to 12b by 12a ruling Q1) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When an A2L parse runs on a worker, the system shall pass the parser's consumed-byte reports to the indicator's current step.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`; AT-B100-17
- **Numeric pass threshold:** the case_06 A2L attach and the case_06 project load → `#progress_bar`'s value increases ≥ 2 times within the parse step, read on the main thread (2 of 2).
- **Negative control:** a mutation that passes no callback → the bar moves by step only → 0 increases within the step → RED.
- **Boundary catalog:** ☒ boundary — an attach and a project load; an A2L smaller than one progress chunk (≥ 1 report).
- **Note (informative):** the bar reaches the end of the parse step after the A2L text is read (about 1 s of 6.6 s for case_06) and holds there while the tags are extracted; the spinner and the elapsed time keep moving during the tag-table build (E2 ruling P2-8).

### LLR-177.5a — The Save worker advances the bar per file placed
- **Traceability:** HLR-177, HLR-176 · trace: the Save worker (NEW), its placement loop over the plan rows; `step_busy(key, gen, n, done, total)` (12a) (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When the Save worker finishes placing one file of the save plan, the system shall advance the indicator's bar within the placement step.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-53 — `pytest tests/test_b100_workers.py -k tc_b100_53`
- **Numeric pass threshold:** a Save project placing 4 files → `#progress_bar`'s value increases ≥ 4 times within the placement step, read on the main thread; a save-as placing 2 000 files → the value increases ≥ 10 times within that step (2 of 2).
- **Negative control:** a mutation that reports only at the step's end → 1 increase per step → RED. On the base no save step is reported at all (12a P12a-1) → RED.
- **Boundary catalog:** ☒ boundary — 1 file (1 increase); 4 files; 2 000 files.
- **Note (informative):** 12a ruling Q5 removed "copied, read" from the within-step promise because the byte callbacks would live in `workspace.py`; it kept "Save project's copy by files placed" open if 12b finds it countable in `app.py`. The placement loop is in `app.py`, so it is counted by files, not bytes. The project load's digest check (`check_project_files`, `manifest_writer.py`) has no per-file hook in `app.py` and moves by step.

---

## §B2 — LLR-176.3 and LLR-176.4, moved from 12a (12a ruling Q1), split here

### LLR-176.3 — A main-thread step paints its name before its work
- **Traceability:** HLR-176 · trace: `step_busy` (12a), the `call_after_refresh` idiom (`app.py:8708`); the A2L tag-table build (`update_a2l_view`) and the install steps of the four session actions (`app.py`)
- **Ledger:** LED-2026-10-26-batch-100.11, LED-2026-10-26-batch-100.NN
- **Statement (EARS event):** When a long action reaches a step that runs on the main thread, the system shall paint that step's name before the step's work starts.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B100-52 — `pytest tests/test_b100_busy.py -k tc_b100_52`
- **Numeric pass threshold:** the case_06 A2L attach's tag-table step and the case_06 project load's install step → the step text read in a `call_after_refresh` callback scheduled before each step starts equals that step's name (2 equalities); a step on a 1-byte image → 1 equality.
- **Negative control:** a mutation that starts the tag-table build before the refresh → the callback reads the previous step's name → RED.
- **Boundary catalog:** ☒ boundary — a step on a 1-byte image; the tag-table build of the 37.7 MB A2L.
- **Note (informative):** after 12b the main-thread steps are the installs and the tag-table build; during the tag-table build the indicator stays frozen, as HLR-176 declares (about 3.5 s for case_06: P12b-4 minus P12b-7).

### LLR-176.4 — The A2L parser reports the bytes it has consumed
- **Traceability:** HLR-176 · trace: `parse_a2l_file`, `build_section_tree` (`s19_app/tui/a2l.py`; a named frozen-engine crossing, `docs/ARCHITECTURE.md` §7, chosen by the operator at the PDR gate, C-UX-1 / C-QA-1)
- **Ledger:** LED-2026-10-26-batch-100.35, LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall report, to an optional progress callback of the A2L parse entry point, the bytes consumed and the total bytes as the parser consumes its input.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_busy.py -k tc_b100_73`
- **Numeric pass threshold:** the case_06 A2L → ≥ 2 calls, the consumed values non-decreasing, the last equal to the file size (3 of 3); an A2L smaller than one progress chunk → ≥ 1 call, the last equal to the size.
- **Negative control:** a mutation that calls the callback only once at the end → fewer than 2 calls → RED. Code read, base: `parse_a2l_file(path)` takes no callback (`a2l.py:2627`) → RED.
- **Boundary catalog:** ☒ empty ☒ boundary — no callback; an A2L smaller than one chunk.

### LLR-176.4a — The parse result does not depend on the callback
- **Traceability:** HLR-176 · trace: `parse_a2l_file` (`s19_app/tui/a2l.py`)
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall parse an A2L file to the same result with a progress callback as without one.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_busy.py -k tc_b100_73`
- **Numeric pass threshold:** the case_06 A2L parsed with and without a callback → identical results: tag count and every parsed field equal (1 comparison); the same for `examples/case_01_basic_valid/firmware.a2l`.
- **Negative control:** a mutation that changes a parsed field when a callback is given → the comparison RED.
- **Boundary catalog:** ☒ boundary — a large and a small A2L.

### LLR-176.4b — `a2l.py` is frozen again after the increment
- **Traceability:** HLR-176 · trace: `tests/test_engine_unchanged.py::_ENGINE_PATHS`, TC-027
- **Ledger:** LED-2026-10-26-batch-100.NN
- **Statement (EARS ubiquitous):** The system shall list `s19_app/tui/a2l.py` in the frozen-engine guard's paths.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B100-73 — `pytest tests/test_b100_busy.py -k tc_b100_73`; `pytest tests/test_engine_unchanged.py` after the increment merges
- **Numeric pass threshold:** `_ENGINE_PATHS` contains `s19_app/tui/a2l.py` (1 assertion); after the merge, TC-027 reports 0 changed engine paths against `main`.
- **Negative control:** code read, base: the entry is commented out since batch-95 (`tests/test_engine_unchanged.py:125-133`) → RED.
- **Boundary catalog:** none — one list entry.
- **Note (informative):** on the increment branch TC-027 compares against `main`, where `a2l.py` differs until the merge, so its full run is owed after the merge (declared).

---

## Retired

None.

---

## §C — Edits to requirements owned by earlier increments

### C.1 — LLR-165.1 (Inc 3): the reset's caller clause
- Old clause: "`_handle_load_project` (`app.py:8444`) shall call it once per load, after `validate_project_files` succeeds (`:8453-8461`) and before `load_selected_file` (`:8510`). No other caller shall call it."
- New clause: "The project load's main-thread install step (Inc 12b, LLR-177.1g) shall call it once per load, after the worker step succeeds and before the first install. No other caller shall call it."
- TC-B100-08's one-call-site census is re-pinned from `_handle_load_project` to the install handler. Add `LED-2026-10-26-batch-100.NN` to LLR-165.1's Ledger line.

### C.2 — Extended at 12b, statement unchanged
- **LLR-164.4** — its statement already names "the Save worker body (LLR-177.1)". 12b writes the worker arms of TC-B100-07: the AST census over the worker body's returns and exception exits, and the forced `OSError` at each of 5 stages on the worker (0 folders left, 0 raises, the app running).
- **LLR-165.2** — TC-B100-09: every attribute name 12b adds to `S19TuiApp` (the quit flag, the request handles) is classified in the snapshot domain or in the exclusion list with a reason (0 unclassified); its P2-over-P1 arm runs on the worker path (LLR-177.1f).
- **LLR-174.4** — TC-B100-72: the busy refusal in the load guard (LLR-177.3a), as Inc 10's informative note routes it.
- **LLR-176.1l** (12a) — the exception exit now also covers the three new worker bodies: a worker-step failure ends its run through its failure handler (the end is the handler's last statement); `_busy_fail` is posted only after a main-thread handler raises, before the worker re-raises (TC-B100-50 arm per worker).
- **LLR-176.1q** (12a) — "progress widgets written only on the main thread": its thread-id probe widens from the 4 worker actions to 7 (TC-B100-50).
- **LLR-176.2, LLR-176.2c, LLR-176.2d** (12a) — TC-B100-51 re-derived over the moved code: the census sites now sit in the worker bodies and their main-thread handlers; every exit, the worker failures included, still ends its run; the Save project phases are reported from the Save worker.
- **LLR-178.3** — the panel opens from the project route after the install (LLR-177.1h).
- **LLR-173.7** — TC-B100-66: the busy line and the quit question (LLR-177.3f, LLR-177.4a).

---

## §D — Index, AT, token and census rows

### D.1 — §5.3 TC index: new rows

| TC arm | Written at | Extended at |
|---|---|---|
| TC-B100-53 (LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1c, LLR-177.1d, LLR-177.1e, LLR-177.1f, LLR-177.1g, LLR-177.1h, LLR-177.1i, LLR-177.1j, LLR-177.1k, LLR-177.3, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h, LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4c, LLR-177.4d, LLR-177.5, LLR-177.5a) | Inc 12b: the three worker steps and the work-area pick off the main thread, timers during them, main-thread session writes, the request census, a cold-load equal result, the reset order, the panel after the install, the Save re-derive before and adopt after, the busy refusals and their wording, quit (ask, stay, wait, idle), the parse's byte reports and the save's files placed (LED .NN) | — |
| TC-B100-54 (LLR-177.2, LLR-177.2a, LLR-177.2b) | Inc 12b: one forced raise per action, the session kept, the save rolled back, the app running (LED .NN) | — |
| TC-B100-52 (LLR-176.3) | Inc 12b (moved from 12a, 12a ruling Q1): a main-thread step's name painted before its work (LED .NN) | — |
| TC-B100-73 (LLR-176.4, LLR-176.4a, LLR-176.4b) | Inc 12b (moved from 12a): the parser's byte callback, the identical result, the `a2l.py` re-freeze (LED .NN) | — |
| TC-B100-07 (LLR-164.4, worker arm) | — | Inc 12b: the census over the Save worker body, 5 forced stage failures on the worker |
| TC-B100-08 (LLR-165.1) | — | Inc 12b: the one call site moves to the project-load install handler |
| TC-B100-09 (LLR-165.2) | — | Inc 12b: the new attribute names classified; the P2-over-P1 arm on the worker |
| TC-B100-50 (LLR-176.1l, LLR-176.1q) | — | Inc 12b: the three new worker bodies |
| TC-B100-51 (LLR-176.2, LLR-176.2c, LLR-176.2d) | — | Inc 12b: re-derived over the worker bodies and their handlers |
| TC-B100-72 (LLR-174.4, LLR-177.3a) | — | Inc 12b: the busy refusal before the question |
| TC-B100-66 (LLR-173.7) | — | Inc 12b: the busy line and the quit question |

### D.2 — §5.2 AT table

- AT-B100-18, "Written at": `Inc 12a+12b` → `Inc 12b (four halves: worker, refusal, quit, quit-confirm; HLR-177, HLR-177a, HLR-177b, HLR-177c)`.
- AT-B100-17, "Written at": as 12a's E1 splits it (12a ruling Q1), its parse half is written at 12b: the engineer loads the case_06 A2L by keys, and the bar rises ≥ 2 times and the elapsed time advances during the parse (LLR-177.5, LLR-176.4).

### D.3 — §3 preface token table

- Row `an image-replacing or project action while a worker runs | busy + the running action's label | wait for it to finish` → `a request that changes the image, the change document or the project while a file load, A2L attach, project load or Save project runs (Inc 12b, LLR-177.3 … LLR-177.3f) | busy + the running action's label | wait for it to finish`.
- Row `quit while a worker runs | still working + the running action's label | wait, or quit after it finishes`: add `(Inc 12b, LLR-177.4a; the quit question's text, title Quit?, buttons Quit (y) / Stay (n))`.
- Row `Load or Save target: the project folder cannot be inspected …`: add `a project load whose worker step raises (Inc 12b, LLR-177.2)`.
- Row `folder cannot be created or written | could not save | check the folder`: add `a Save worker that raises any exception (Inc 12b, LLR-177.2a)`.
- New row: `an A2L attach whose copy or parse raises (Inc 12b, LLR-177.2b) | could not be read + the A2L file | check that the file can be opened, then load again`.

### D.4 — §5.4 reverse census (taken on the base `8947666`; `work/census.out.txt`, `work/census2.out.txt`)

- New row: `_handle_load_project`, `_route_load_project`, `_handle_save_dialog`, `load_a2l_from_path` direct callers (Inc 12b) | 26 test files; 184 direct call sites; 1 no-app test (`test_tui_app.py:85`); the W class is taken by a **poll on a condition**, not by a helper's name (E3 A12b-01), and only `test_tc_b100_30_…under_one_second` becomes vacuous | refusal paths stay synchronous; success paths re-pinned by ruling Q6 and the one Q6 wait helper (`wait_for_complete()` + 2 pauses).
- Row `_handle_load_project direct callers (Inc 3, Inc 7)`, Disposition: add `Inc 12b: the success path finishes on a worker; a caller waits for the install (ruling Q6).`
- Row `set_progress / #progress_bar (Inc 12a+12b)`: add `Inc 12b: the three 12b actions' step and end calls move into worker bodies, through call_from_thread (LLR-176.2, re-derived).`

---

## §E — Ledger entry (number assigned at merge)

### LED-2026-10-26-batch-100.NN — Inc 12b E1 — requirements to strict EARS / ISO 29148
- **Requirement:** HLR-177, HLR-177a, HLR-177b, HLR-177c, LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1c, LLR-177.1d, LLR-177.1e, LLR-177.1f, LLR-177.1g, LLR-177.1h, LLR-177.1i, LLR-177.1j, LLR-177.1k, LLR-177.2, LLR-177.2a, LLR-177.2b, LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e, LLR-177.3f, LLR-177.3g, LLR-177.3h, LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4c, LLR-177.4d, LLR-177.5, LLR-177.5a, LLR-176.3, LLR-176.4, LLR-176.4a, LLR-176.4b, LLR-165.1. New in this entry: HLR-177a, HLR-177b, HLR-177c, LLR-176.4a, LLR-176.4b, and every suffixed LLR-177 id above. Also: §3 token table (1 row changed, 3 rows annotated, 1 row added); §5.2 AT table (2 rows changed); §5.3 TC index (4 rows added, 7 rows extended); §5.4 reverse census (1 row added, 2 rows annotated).
- **Pairing note:** a requirement split here lists on its Ledger line only this entry. The history before the split stays on its parent's Ledger line: HLR-177 (.1, .2, .11, .19, .38), LLR-177.1 (.1, .11, .19, .38), LLR-177.2 (none), LLR-176.3 (.11), LLR-176.4 (.35).
- **Date:** 2026-10-31
- **What changed:** each Inc 12b requirement was rewritten to the operator's strict standard, as in LED .76 and .82: one EARS sentence in one of the five forms, one "shall", every failure path its own unwanted-behaviour requirement, a numeric pass threshold and a negative control each, checked against ISO/IEC/IEEE 29148. Function names moved from the statements to the trace. Existing ids are kept; a split keeps the id for the first part and adds a suffix; nothing is renumbered or deleted. Negative controls are executed probes where one exists (P12b-1, P12b-2, P12b-3, P12b-4, P12b-5, P12b-6, P12b-7, in `inc-12b-design/work/`), code reads on the base otherwise, each named. Per id:
  - **HLR-177:** 7 "shall"s → ubiquitous "run the reading and parsing of a project load, the writing of Save project and the copy and parse of an A2L attach on worker threads". "Install their results on the main thread only" moved to LLR-177.1d; the re-derive and the copy to LLR-177.1i, LLR-177.1j and LLR-177.1e; the refusal to HLR-177a; quit to HLR-177b and HLR-177c. "Flow runs stay on the main thread" is a scope note (O-7). AT-B100-18's worker half.
  - **HLR-177a (new, split from HLR-177):** unwanted "a request that changes the image, the change document or the project, while a session action runs, is refused with the busy line". The approved list (a load on any route, an unload, `v`, a save-back, Save project, a Patch apply or undo) is widened to every Patch Editor change (ruling Q3). "While one of these actions runs" becomes "while a session action runs": the three 12b actions plus the existing file load, which also writes the session (ruling Q2); report runs overlap as 12a ruling Q3 shows them. AT-B100-18's refusal half.
  - **HLR-177b (new, split from HLR-177):** event "quit while a session action runs asks first". AT-B100-18's quit half.
  - **HLR-177c (new, split from HLR-177):** event "a confirmed quit exits only after the running action finished or rolled back". AT-B100-18's quit-confirm half.
  - **LLR-177.1:** 7 "shall"s → ubiquitous "read and parse a project's files for a project load on a worker thread". The cheap refusals stay in the frame of the request.
  - **LLR-177.1a, LLR-177.1b (new):** one ubiquitous requirement per other action (Save project writes; every A2L attach route, the 9b in-place work-area attach included).
  - **LLR-177.1c (new):** state "the main thread's timers keep running during a worker step" — the oracle is the event loop, measured by a timer, so it does not depend on 12a's elapsed-text format. Base: 0 ticks in 8.76 s and 5.81 s (P12b-4, P12b-5).
  - **LLR-177.1d (new):** ubiquitous "write the session only on the main thread" (was "every write of `current_file` … through `call_from_thread`", a mechanism). The list is widened to the whole session census, because the base already writes `_a2l_cache_*` on the file-load worker and `_last_manifest_verify_result` inside the save.
  - **LLR-177.1e (new):** ubiquitous "a worker reads only its immutable request" (was "the worker shall write from a copy"). The base's `_parse_loaded_file` reads the live `current_file` to merge a MAC, which on a worker that runs before the reset would merge into the previous project's image.
  - **LLR-177.1f (new):** event "a project loaded on a worker equals a cold load" (was "the same final snapshot as a main-thread load", which has no main-thread load left to compare with after 12b) → cold-load equality plus the base digest recorded at E2.
  - **LLR-177.1g (new):** event "reset after the worker read, before the first install". A worker failure must leave the session as it was (LLR-177.2), so the reset cannot run before the worker. Changes LLR-165.1's caller clause (§C.1).
  - **LLR-177.1h (new):** event "the Load-result panel opens after the install". The base opens it after `_handle_load_project` returns, which a worker breaks.
  - **LLR-177.1i (new):** ubiquitous "re-derive and render the emitted image on the main thread before the Save worker starts".
  - **LLR-177.1j (new):** event "adopt the re-derived image on the main thread after the save commits". The old LLR-177.1 said "apply the result on the main thread before its worker starts"; that contradicts review F4 (LLR-167.2, `test_tc_b100_17_failed_manifest_write_adopts_nothing`: adopting before `project.json` is on disk shows an image no file holds) and LLR-177.2 (the session as it was). The tested rule wins (rule 7; ruling Q1).
  - **LLR-177.2:** 1 "shall" over three actions (end the indicator, report, keep the app and the session) → three unwanted requirements, one per action: LLR-177.2 (project load, `could not be read`), LLR-177.2a (Save project, non-`OSError`: rolled back, `could not save`), LLR-177.2b (A2L attach, `could not be read`). LLR-177.2a resolves the conflict with SEC-7's "then let it surface": on a worker a raise ends the app (P12b-2), so "surface" becomes a status line plus a logged traceback (ruling Q4).
  - **LLR-177.3, LLR-177.3a, LLR-177.3b, LLR-177.3c, LLR-177.3d, LLR-177.3e (new):** one unwanted requirement per refused request kind (open Load, the load guard, the variant selector, unload, Save project, Patch Editor changes).
  - **LLR-177.3f (new):** ubiquitous "the busy line's wording".
  - **LLR-177.3g (new):** ubiquitous "a refusal leaves the session, the focus and the screen stack unchanged".
  - **LLR-177.3h (new):** event "refusals stop when the action ends", on all three exits.
  - **LLR-177.1k (new, ruling Q5):** event "a data file picked from the work area is parsed on the file-load worker, in place" — 12a's E1 left the pick to 12b; the typed load's copy stays on the main thread.
  - **LLR-177.4, LLR-177.4a, LLR-177.4b, LLR-177.4c (new):** quit opens the question with the focus on Stay; its texts; Stay keeps running; Quit exits after the end handler. LLR-177.4c's note: the wait is a flag, never a main-thread wait (deadlock with `call_from_thread`).
  - **LLR-177.4d (new):** event "quit while idle exits at once" — the control for the new `action_quit` override.
  - **LLR-177.5, LLR-177.5a (new):** the 12b actions on 12a's indicator: the A2L parse's byte reports from the worker (AT-B100-17's parse half); the save's files placed, counted in `app.py` (12a ruling Q5 left it open). 12a's table, steps and ends (LLR-176.2b, LLR-176.2c, LLR-176.2d) are not restated here.
  - **LLR-176.3 (moved from 12a, rewritten):** 1 "shall" with the mechanism in the statement ("`step_busy` … through the `call_after_refresh` idiom") → event "a main-thread step paints its name before its work"; the idiom moves to the trace.
  - **LLR-176.4 (moved from 12a, split):** 2 "shall"s plus the re-freeze sentence → LLR-176.4 (the byte callback), LLR-176.4a (same result with and without it), LLR-176.4b (`a2l.py` back in `_ENGINE_PATHS`). The crossing's naming stays in the trace.
  - **LLR-165.1:** the caller clause moves to the project load's install step (§C.1).
- **Rulings applied:** the text follows Inc 12a's E1 rulings (Q1, Q2, Q3, Q5) and the recommendations of `inc-12b-design/E1-rulings-proposed.md` Q1 to Q7. A different ruling changes the ids each question names.
