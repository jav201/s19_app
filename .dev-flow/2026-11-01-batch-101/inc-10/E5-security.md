# Inc 10a — E5 security review (implemented code)

Batch 2026-11-01-batch-101, increment 10a, branch `b101-inc10`, head `54a0eb2`. Scope: `git diff 09b4808 -- s19_app tests`, which covers 3 source files (`tui/app.py`, `tui/segment_split_view.py`, `render/hexview.py`) and 7 test files (2 of them new). Reviewer: security-reviewer (Opus), independent of the implementers, the testers and the integrators. I also reviewed this lens at E3 (`E3-security.md`, rounds 1–3).

Records read:
- `E3-security.md` and `E3-rulings.md` (with SR2-1 and R3-1).
- `E4-rulings.md` (E4-R1 … R6).
- `E4-integration-notes.md`: §2, §3 (I-D6, I-D14, I-D16, I-D17), §6 (I-D20 … I-D22), §7 (I-D23) and the mutant table.
- `01-requirements.md` rows R-WS-LOADED.19 and .20, plus the R-SEG-OPEN.7 cases and nodes.

Model: `inc-9/E5-security.md`. No product or test file was edited, and nothing was committed.

**Lens:**
- No key acts on a hidden window.
- No saved project holds the unloaded image.
- The deferred load steps do nothing after exit.
- Where a focus landing can put the focus, and what one Enter does there.
- Format characters and markup in the status texts.

**Severity:** HIGH / MEDIUM / LOW / INFO. On the flow's scale, MEDIUM = MAJOR, LOW = MINOR and INFO = note. **Tags:** `design-gap`, `test`, `records`.

## Verdict

**FAIL**, on one MEDIUM (SE5-1). This gate is not `BLOCK-UNTIL`, because no HIGH is open. Count: HIGH 0, MEDIUM 1, LOW 1, INFO 4.

- **Five of the six items hold as built.** These are: no key acts on a hidden Split / Join window; the deferred load steps after exit; the focus re-home; the format characters in the file-state line; markup in the status texts. Evidence: reading, plus the E4 runs another reviewer executed (cited, not mine). No writing or destructive action is one Enter away after a switch, a load or an unload (SE5-4).
- **SE5-1: a save as can still write the unloaded image.** The case is a save as (Save project to a new name while a project is open) after a primary unload. The save-as copy list carries the open project's top-level S19 and HEX files. The image row no longer names the S19, because D-7 makes it the MAC. So the old image is carried into the new project, and loading that project installs it as the primary.
  - This breaks R-WS-LOADED.19 on a path its cases do not reach: /19/1 runs with no project open.
  - The helper's rule is executed (probe below). The chain around it comes from reading.
  - It closes in one of two ways. Either the fix plus case R-WS-LOADED.19/3, RED then GREEN. Or a ruling that narrows R-WS-LOADED.19; this lens is then PASS-WITH-NOTES.
- **SE5-2 (LOW): no node pins I-6 on its own.** Since SR2-1, the export sink refuses every hidden-window export. So the R-SEG-OPEN.7 nodes stay GREEN with `SplitJoinWindow.check_action` removed, and mutant M28 will survive.
- This clearance covers the security lens of the E5 gate only. It authorises neither the merge nor the push.

## How it was checked

- **Reading.**
  - The full diff, and the callers and callees named in the tables below.
  - Textual 8.2.8 (the pinned floor), read only from a local install:
    - `app.py`: `:3966-3988` (`_check_bindings`), `:4223-4248` (`run_action` asks the namespace's `check_action`), `:954-956` (`default_screen` is the composed screen), `:1283` (`exit` sets `_exit`).
    - `message_pump.py:270-281`: `is_attached` is False once `_exit` is set or the parent is gone.
    - `widget.py`: `:2368-2375` (`focusable` ignores `display`), `:4579-4598` (`focus()` is queued with `call_later`).
    - `dom.py:939-954` (`visible`).
    - `screen.py`: `:408-446` (the binding chain starts at the focused widget), `:772-817` (the focus chain holds displayed children only).
    - `widgets/_button.py`: `:297` (Enter → `press`), `:429` (`press` checks only the button's own `display`).
- **Probe (Windows PC, executed).**
  - Script: `../evidence/inc-10/e5s-probe.py.txt`. Python 3.11.15, run with `-I` from a folder outside the repository.
  - It extracts by AST the source text of `_plan_copies` and of the dataclasses it reads (`services/project_gather_service.py`), plus the two extension sets (`workspace.py`). It execs that text in one namespace and calls `_plan_copies` twice: with the rows planned before the unload, and with the rows planned after it.
  - Nothing from `s19_app` was imported; the transcript prints this. Transcript: `../evidence/inc-10/e5s-probe.txt`.
  - This is evidence for the helper's rule, not for a product node.
- **Tree checked.** The worktree's product blobs equal HEAD (`git hash-object`: `app.py` `aba486d4`, `segment_split_view.py` `108cf014`, `project_gather_service.py` `78981ac8`). The other E5 reviewers' files in `inc-10/` were left untouched.
- **Cited, not mine.** `int-12` … `int-23` (`E4-integration-notes.md` §6–§7, LAN Linux laptop).
- **Not run by me.** Any `pytest` run; any mutant (M17 … M30, M-R*); any LAN run. Nothing that imports `s19_app` ran on this PC.

## The brief's items — state as built

### 1. No key acts on a hidden window

**State:** `executed` · `approved` (read). One test gap: I-6 is not pinned by any node on its own (SE5-2).

**Code:**
- **`check_action`.** `SplitJoinWindow.check_action` (`segment_split_view.py:1752-1770`) returns `False` while the window has `hidden`.
  - It covers every binding in the window's namespace: the 15 at `:1500-1515` and `WindowSection`'s `?`.
  - The window has no priority binding. The app's four `ctrl+` priority keys act on the session from any window, by design.
- **Textual's dispatch.** Textual asks `check_action` of the namespace that owns the binding. A refused key then falls through to the screen and the app.
  - At app level, `a`, `e`, `n`, `m`, `f` and `space` are unbound.
  - `j`, `k`, `d`, `t`, `p`, `g` and Esc act on the session, as they do from any window (E3 round 2).
- **The sink.** `action_export` returns before the export body while the window is hidden (`:2081-2087`). `write_split_join_export` has one caller (`:2139`). Every route reaches the sink:
  - the `e` key: I-6 first, then the sink;
  - Enter or a click on `#sje_export`: `on_button_pressed` (`:2077-2079`), then the sink;
  - the key bar's own `e` token: `run_token` → `widget.run_action` (`window_help.py:1250-1256`), which asks `check_action`, then the sink;
  - the command palette: it has no export entry, and its Split / Join entry un-hides the window first (`app.py:10255-10258`).
- **The focus layer.**
  - `refresh_window` focuses the table only while the window is shown (`:1746`).
  - `action_show_screen` clears at once a focus left in a window it just hid (`app.py:10123-10136`). The clear works for any window in `_WINDOW_CONTAINER_IDS`.
  - Tab and Shift+Tab skip `display: none` nodes (the focus chain).

**Evidence:**
- R-SEG-OPEN.7/1–/4 are GREEN (int-21, cited).
- The /4 oracle also refuses `nothing selected`, through `exported_messages` (`tests/test_b101_unload_focus.py:241-242`), and its precondition asserts the ticks. So R3-1 is applied as built.

### 2. Save project after an unload never writes the unloaded image

**State:** `executed` (read) for a save with no project open. **Not met** for a save as from an open project (SE5-1).

**Code:**
- `_unload_primary` (`app.py:1882-1900`) sets `path = mac_path` and builds `errors` from `mac_diagnostics`. That is the shape a fresh MAC-only load builds (`:17636`).
- The plan's image row is therefore the MAC (`:13766-13773`), and the MAC row is skipped (`:13774-13780`). A change document on a MAC spine is refused (E3 round 2, item 2).
- The load question names the MAC (R-WS-LOADED.20).
- `_unload_mac` on a MAC-only spine returns `None` (`:1794-1834`), because `_has_primary` is False there.

**Evidence:**
- /19/1, /19/2 and /20/1 are GREEN (cited).
- M17 was not run by me.
- The save-as gap: SE5-1.

### 3. The deferred load steps cannot act after exit (E4-R5)

**State:** `executed` · `approved` (read).

**Code:**
- **The test.** `_load_tree_gone` (`app.py:10763-10773`) is `not default_screen.is_attached`.
  - `default_screen` is the composed screen, never a modal.
  - `is_attached` is False once `App.exit` has set `_exit`, or once the screen has lost its parent.
- **The steps.** `_step_sections`, `_step_hex`, `_step_a2l` and `_step_finalize` each return at their first line (`:18973`, `:18988`, `:19002`, `:19017`). Each schedules the next step only inside its own body, so the chain ends. E4-R3's re-check returns too (`:10732`).
- **No write is skipped.** No step writes a file. The project sync (`_sync_loaded_file_to_project`, a write) is dispatched by the worker outside this chain (`:19367`), and it is unchanged. A confirmed quit waits for the load to end (Inc 12b).

**Evidence:**
- int-13a–c pass 3 of 3, and M-R5 is RED (int-18d), both cited.
- Residual: SE5-5.

### 4. The focus re-home (E4-R3) cannot reach a hidden window

**State:** `approved` (read).

**Code:**
- **What it moves.** `_rehome_placeholder_focus_after_load` (`:10695-10761`) moves only a focus that sits on a `RailItem` or on the recorded landing.
- **Where it lands.** The target is `_FOCUS_TARGETS` for the active window, set only when it is `focusable` and `region.area > 0`.
  - Textual's `focusable` ignores `display: none`, so the area test is what keeps the focus out of hidden widgets.
  - The target belongs to the shown window. A widget that was just hidden never is the target.
- **`_land_focus`** (`:10775-10877`) waits for the shown window's region before it tests anything (I-D3), so every region it reads comes from after the swap.
  - The switch landing needs area > 0 (`:10861-10868`).
  - `_resolve_focus_target` and `_fallback_focus_target` take only a widget with area > 0, or the rail's active item.

**Enter after a landing:** see SE5-4. No write or destructive action is one Enter away.

### 5. Bidi and control characters in the file-state line (SE5-12a-2)

**State:** `executed` · `approved` (read).

**Code:**
- **The scrub.** `set_file_status` (`:21681-21705`) runs `painted_names([text], limit=1, clip=len(text))` before `safe_text`.
  - It removes Cc, Cf, Zl and Zp, and turns Cs into U+FFFD.
  - It clips nothing, because the scrub only removes characters.
- **One writer, one painter.** `set_file_status` is the only writer of `_busy.file_state` (`:21703`). `_paint_status_text` is the only painter of `#status_text`, a Label with `markup=False` (`:3437`).
- **The load line.** `_format_coexistence_status` (`:19044-19088`) paints both names through `painted_names`, clipped at 120. So the activity log's load line is now scrubbed as well.

**Evidence:**
- R-SHELL-STATUS.7/1–/2 and R-TUI-012L.8/1–/5 are GREEN (cited).
- M18–M20 were not run by me.
- Scope note: SE5-6.

### 6. Status texts paint no unescaped markup from file names

**State:** `executed` · `approved` (read).

**Code:**
- **The new texts.** Every new status text in Inc 10a is either fixed or passes its names through `painted_names`.
  - Fixed: `Nothing to unload.`; `Unloaded {label}.`, where the label comes from a fixed set; the go-to lines.
- **The sinks.** These texts reach `#status_text` (markup off) and the log labels (markup off at construction; `_append_log_line`, `:21707-21730`). Inc 10a adds no `notify` call.
- **The MAC-only spine's errors.** Its `errors` are those of a fresh MAC-only load (`:17636`), so no new painter is added.

## Findings

### SE5-1 — MEDIUM · `design-gap`: a save as after a primary unload still writes the unloaded image

**Where:**
- `app.py:13766-13780`: the image row is the MAC, and no `mac` row is planned.
- `services/project_gather_service.py:1484-1500`: `_plan_copies`.
- `app.py:15115-15126`: `_save_as_source_for`.
- `app.py:12187-12205`: a `.mac` image row sets no active variant.
- `app.py:2012-2066`: `choose_install_set`.

**Scenario:**
1. Project P holds `unloaded_primary.s19` and `firmware.mac` from an earlier save. The operator loads P.
2. The operator presses `[u]` on the primary.
3. The operator saves the project as P9. P9 does not exist yet, so this is a save as.
4. The plan's image row is the MAC (`firmware.mac`), so `_plan_copies` leaves out that one name only. Every top-level `.s19` and `.hex` file of P is carried. MAC and A2L files are left out by suffix only when a `mac` or `a2l` row is planned.
5. **Probe (executed):** carried `[]` with the rows planned before the unload, and `['unloaded_primary.s19']` with the rows planned after it.
6. P9 then holds the unloaded image's bytes. Its manifest names no active variant, so loading P9 installs `unloaded_primary.s19` as the primary (the first variant).

**Consequence:** a save as followed by a load undoes the unload. This is S-2's harm, on a path that R-WS-LOADED.19/1 does not reach: /19/1 runs with no project open.

**Related, not covered by the row (no write):** saving to P itself leaves its variants in place, and loading P again installs the first one.

**Fix (a ruling):**
- **(a) Apply the row as written.** In `_plan_project_save`, for a save as from a session that holds no S19 or HEX image (`loaded.file_type not in {"s19", "hex"}`), remove every top-level name with a `PROJECT_PRIMARY_DATA_EXTENSIONS` suffix from `walked.top_level` before `plan_project_save`. The edit stays in `app.py`, so the increment stays at 3 source files. Cost: this drops all of P's variants, not only the unloaded one. After D-7 the session no longer knows which file was unloaded.
- **(b) Narrow R-WS-LOADED.19** to a save with no project open, or to the open project. Then record that a save as copies the open project's variants, the unloaded one included, and that the next load installs the first variant.

**Cases for (a):**
- **R-WS-LOADED.19/3.** Save fixture three as `unloaded_primary.s19` plus case 08's MAC as project `PS`. Load `PS`, press `[u]` on the primary, then Save project `P9`. Expected: P9 holds no `.s19` or `.hex` file and no file with the image's SHA-256. On base the S-2 path makes it RED. On the current tree the carry makes it RED (read; the helper's rule is executed).
- **/19/4 (control).** The same steps with no unload. Expected: P9 holds the image, so /19/3 can fail.

**State:** `planned`.

### SE5-2 — LOW · `test`: no node pins I-6 on its own (M28 will survive)

**Where:** `tests/test_b101_unload_focus.py:1484-1508` (R-SEG-OPEN.7/3), and the mutant table row M28.

**Scenario:**
- Since SR2-1, the sink refuses every export from a hidden window, and the R-SEG-OPEN.7 nodes observe only the export: files written, `Exported` and `nothing selected`.
- Under M28 (`check_action` removed, sink kept), /7/3 goes like this:
  1. `a` ticks every row of the hidden window.
  2. `e` reaches the sink, which returns.
  3. The result is 0 files and no message, so the node is GREEN.
- The table's "expected RED: /7/3" for M28 will therefore not hold.

**What I-6 alone guards:** the window's other state while it is hidden: ticks, tab, mode, gap, format, pad, destination, Esc and `?`. None of these writes. But a tick made while hidden carries into the next export from the shown window, because the selection resets only on a new image (`segment_split_view.py:1730-1736`).

**Fix:**
- In /7/3, after the keys, reopen Split / Join and assert that `#sje_stats` still reads `nothing selected`. Pressing `d` while hidden and asserting the destination chip is unchanged would also work. M28 then turns /7/3 RED.
- Correct M28's row in the table.

**State:** `not-run` (read).

### SE5-3 — INFO · `records`: the `check_action` docstring overstates its reach

**Where:** `segment_split_view.py:1753-1758`.

**Scenario:** the docstring says Textual asks `check_action` "for every binding of the window (… the arrows)". Two inputs escape it:
- With the focus on `#sje_table`, `up`, `down`, `k` and `j` are the table's own bindings (`:1238-1243`). Textual asks `_SegTable` (default True), and the table forwards them straight to `SplitJoinWindow.action_move` (`:1245-1249`).
- Text typed into `#sje_manual` is consumed by the TextArea; no binding is involved.

Neither writes anything. Both need the focus inside the hidden window, which the focus layer prevents.

**Fix:** name these two exceptions in the docstring, or give `_SegTable` the window's hidden test. Not required.

### SE5-4 — INFO: landing census (I-D23's question)

**After a window switch**, the focus lands on one of these:
- **A2L:** `window_help_a2l`. Enter opens the help modal.
- **MAC:** `mac_page_prev_button`. Enter goes back one page; read-only.
- **Every other window:** its `_FOCUS_TARGETS` entry (`app.py:9935-9949`):
  - **Containers with no Enter binding:** the Map, Patch Editor, Check Editor, Flow Builder, Flow Execution, Checks and CRC Designer panels.
  - **Navigation tables:** the A2L tag table, the MAC record table and the Issues groups. Their region and check rows post `Activated` / `Selected`.
  - **Diff:** `diff_compare_button`. It runs an in-memory compare and writes nothing. The `Report` button, which writes, is not a target.
  - **Split / Join:** `sje_table`, which has no Enter binding.

**Fallbacks (empty states):** the window's `?` chip or the rail item. EmptyStatePanel is a `Static`. A fallback is never an `Input` or a `TextArea`.

**Load and unload landings** use the same targets.

**Conclusion:** no write or destructive action is one Enter away.

**A pre-existing note:** Enter on the Workspace's `files_list` loads the highlighted work-area file (`app.py:16681-16774`).
- The image arm goes through the replace question, whose focus starts on Cancel (`screens.py:2340`). It loads with `sync_project=False`.
- The A2L arm loads with `copy=False`. The A2L load tail then copies the file into an open project that has no A2L yet (`app.py:16497-16498`, `:15872-15915`). That copy is guarded by `place_into_workarea` and never overwrites.
- Base already landed every load there (HLR-166). After `1`, the focus now lands there too (R-SHELL-FOCUS.2, approved).

Flow Execution's `c` is an app binding; it is unchanged and works this way by design.

### SE5-5 — INFO: `_land_focus` has no exit guard

E4-R5's guard does not cover `_land_focus`, which a switch or an unload schedules after the refresh.
- It only moves the focus and writes nothing.
- Its `_fallback_focus_target` calls `self.query_one(Rail)` outside a `try` (`:10570`). A landing that runs after teardown could therefore raise at exit, the crash class of I-D17.
- This is not a security issue. It is for the code review.

### SE5-6 — INFO: the scrub's scope and S-6's backlog

- **The scrub removes Cc, Cf, Zl and Zp only.** Strong right-to-left letters stay: they reorder text but carry no override. Invisible letters such as U+3164 stay too. Both are outside SE5-12a-2.
- **S-6's backlog still stands:** the Loaded panel slot rows, the Save project `(variant '…')` line and the log.
- **One addition for that backlog:** the Split / Join export status and toast. They paint names built from the loaded file's stem (`segment_split_view.py:1652-1656`) through `set_status`, which scrubs C0 and C1 only.

## Evidence states

| Item | State | Basis |
|---|---|---|
| Items 1 and 3–6 | `approved` | Reading, plus E4 runs cited (int-13, int-18d, int-21), not mine |
| Item 2, no project open | `approved` | Reading, plus /19/1, /19/2 and /20/1 cited |
| SE5-1 | `executed` · `planned` | The helper's rule is `executed` (probe). The save-as chain and the reload are `not-run` (read). The fix is `planned`, pending a ruling |
| SE5-2 | `not-run` · `planned` | Read. M28 is to be run in the E5 mutant pass. The fix is `planned` |
| SE5-3 … SE5-6 | `not-run` | Read |
| Mutants | `not-run` | None run by me: M17 … M30, M-R* |

## Evidence checklist

- [x] **What, where, why and a fix for every finding:** each finding above has a Where, a Scenario and a Fix (or a conclusion).
- [x] **A severity for every finding:** MEDIUM SE5-1; LOW SE5-2; INFO SE5-3 … SE5-6.
- [x] **No secret values:** no secrets were read; this report holds paths and code citations only. The probe script and transcript hold no home path or account name.
- [x] **Explicit verdict:** FAIL on SE5-1. No HIGH is open, so this gate is not `BLOCK-UNTIL`. Every ruled mitigation of E3 and E4 in this lens is `executed` in the code. SE5-1 and SE5-2 stay `planned`.
- [x] **No new tool or integration:** none (n/a). The write surfaces re-checked are the Split / Join export (every route), Save project with save as, the project A2L sync behind `files_list` and the load chain after exit.
