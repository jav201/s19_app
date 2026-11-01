# E1 — Inc 12a requirements scope and E2 slice

**Run.** Stage E1 of the design-first pipeline (skill `dev-flow-v3-beta`) for Inc 12a. PLAN.md row 12a: "progress indicator (begin/step/end, elapsed) — N5 — app, styles (+ screens) — gate P-D". Prototype verdict: P-D variant A (`veredicto-load-projects.json`; `prototypes/load_projects/variants/pd_A.py`).

**Source.** The replacement text is `E1-requirements-draft.md` in this folder; nothing has been merged into `01-requirements.md`. Requirement line numbers refer to `01-requirements.md` on main `8947666` (Inc 9a merged). Code is cited by symbol, with `app.py` line numbers on `8947666`. Inc 9b, 10 and 11 run before 12a and change `app.py`. This E1 designs against their fixed interfaces: `interfaces-9b.md` (`LoadDialog`, `_handle_load_dialog`, `_load_workarea_file`, `_TYPED_REFUSAL_TOKENS`, `_load_dialog_verdict`, `check_action`) and the Inc 10 and 11 E1 rulings (`check_action` widened by their two screens; `_prepare_project_save`).

**In scope.**
- US-166, HLR-176, LLR-176.1 … LLR-176.4.
- AT-B100-17 and AT-B100-18 ("Inc 12a+12b"); TC-B100-50, -51, -52, -73; TC-B100-66's "Inc 12a: the busy indicator" extension.
- Routed here: 9b ruling Q8 (labels "Load" / "Projects", LLR-173.2m, and their snapshots); Inc 11 ruling Q2 (Save project on a worker with real progress, split between 12a and 12b).
- BACKLOG-CODE rows naming Inc 12a or its sweep: R12 (Inc 8b save-as copy), CR9-2, CR9-5 / SEC9-8, CR9-7, CR9-8, SEC9-2, SEC9-5, the `os.name` addendum (CR9-9), OBS-9a-1, OBS-9a-2, C7. Also the two rows Inc 10 will open (its Q7, Q8).

**Counts.**
- **Before:** 5 requirements (HLR-176; LLR-176.1, LLR-176.2, LLR-176.3, LLR-176.4), holding 14 obligation clauses and about 30 behaviours. HLR-176 alone had 8 clauses; LLR-176.1 had 1 clause over about 10 behaviours. Plus 1 requirement routed back (LLR-173.2m, removed from 9b) and 12 backlog rows.
- **After E1:** 38 single-"shall" requirements owed at 12a:
  - 5 HLRs (HLR-176, HLR-176a … HLR-176d);
  - 20 LLRs for the seam (LLR-176.1, LLR-176.1a … LLR-176.1s);
  - 5 LLRs for the action table (LLR-176.2, LLR-176.2a … LLR-176.2d);
  - 1 restored label LLR (LLR-173.2m);
  - 7 backlog-sweep LLRs (LLR-172.4e, LLR-172.4f, LLR-172.5i, LLR-172.5j, LLR-172.5k, LLR-172.6b, LLR-172.6c).
- **Moved to Inc 12b, text unchanged:** LLR-176.3 and LLR-176.4 (2), with TC-B100-52, TC-B100-73, AT-B100-18 and AT-B100-17's parse half (ruling Q1). 12b's E1 splits them.
- **Outside the count, extended at 12a with text unchanged:** LLR-173.7 (TC-B100-66: the 7 progress labels and the 2 new token pairs); LLR-178.2 (TC-B100-56: the project and file line as the project load's file state).
- **Backlog rows decided without a requirement:** 7 (B1, B2, B6, B8, B9, B11, B12 in `E1-rulings-proposed.md`).

**Per EARS form (38 in scope):** event (E) 13 · state (S) 4 · ubiquitous (U) 11 · unwanted (UW) 10 · optional 0. Checked by script (`work/check_shall.py`, output `work/check_shall.out.txt`): every Statement holds exactly 1 "shall", no other field of a requirement block holds the word, and every block has a threshold and a negative control.

**Base probes.** Executed on `8947666` with `s19env` and `LOCALAPPDATA` under `work/`; nothing was written into the tree (`git status` unchanged):
- P12a-1 (`work/p1_progress_census.py`): `set_progress` is called 24 times in 12 functions (P-29 holds); `set_file_status` is called in 2 functions; there is 1 `#status_text` query site.
- P12a-2 (`work/p2_base_load.py`): across a file load, `#status_text` takes only `Ready.` and `Loaded firmware.s19 (S19 only)`. The second is painted while the bar is at 50. The bar ends at 100. `set_interval(` occurs 0 times. The idle and busy bar heights are 1 / 1, and `#log_line_1` is at y 47 / 47.
- P12a-3 (`work/p3_s19_parse_time.py`): a generated S19 parses in `S19File` in 0.29 s (1 MiB of data), 1.16 s (4 MiB) and 2.38 s (8 MiB).
- P12a-4 (`work/p4_sweep_base.py`):
  - `_typed_load_route(Path('fw\x00.s19'))` raises `ValueError`;
  - 2 functions hold the project match (`_handle_load_project`, `_typed_load_route`);
  - the `os.name == "nt"` gate is present in `list_projects`;
  - the loadable suffixes are `.hex .ihex .mac .s19 .srec` plus `.a2l`.
- Snapshot census (`work/snap_loadfile.txt`, `work/snap_loadproject.txt`): 29 pinned SVG files hold `Load file` and 6 of them also hold `Load project`. The `tests/_artifacts/` matches are untracked.

Code reads only, with the executed probe owed at E2: LLR-172.6b arms (a) and (b), LLR-172.5k's painting-site count, LLR-176.2c's per-action failure arms, and B9 (OBS-9a-2).

## 1 · Scope list

| Id | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-176 | A long action begins → one progress line (glyph, label, `step n/m` + name, elapsed) | E | 4 of 4 worker actions match the line pattern | P12a-2 executed (no line) |
| HLR-176a | While a worker runs: glyph and elapsed advance | S | 8 MiB S19: elapsed ≥ 1 change, ≥ 5 glyphs; synthetic 1.2 s: same | P12a-2 executed (0 timers) |
| HLR-176b | A step reports done of total → the bar moves within the step | E | 50, 62, 75, 87, rising 4 times | P12a-1 executed (constants only); index-only mutant |
| HLR-176c | End (success, failure, exception) → indicator replaced by outcome | E | 7 actions × 2 exits: no glyph, bar cleared, log = outcome, 0 timers | P12a-2 executed (bar 100) |
| HLR-176d | While running: `#status_text` kept for the progress line | S | 0 non-progress values between begin and end; file state after | P12a-2 executed (file state at bar 50) |
| LLR-176.1 | Begin paints `⠋ <label>  ·  step 1/<m> <name>  ·  00:00` | E | 1 equality | P12a-2 |
| LLR-176.1a | Begin sets the bar to 0 of 100 | E | 40 → 0 | untouched-bar mutant; base starts at 10 (P12a-1) |
| LLR-176.1b | Step without amount: `step n/m`, bar `floor(100(n−1)/m)` | E | 0, 25, 50, 75 | bar-untouched mutant |
| LLR-176.1c | Step with amount: bar `floor(100(n−1+done/total)/m)` | E | 62, 75, 87, 100 | amount-ignored mutant |
| LLR-176.1d | Out-of-range step data clamped, no raise | UW | 6 of 6 arms | no-clamp mutant (`ZeroDivisionError`) |
| LLR-176.1e | One 0.1 s timer while ≥ 1 action runs | S | ≥ 5 glyphs, `00:00` → `00:01`; overlap → 1 timer | P12a-2 (0 timers); timer-per-begin mutant |
| LLR-176.1f | Last end stops the timer | E | 0 timers; text unchanged 0.5 s later | never-stop mutant |
| LLR-176.1g | Elapsed is `mm:ss`, minutes past 59 | U | 5 of 5 (`75:03`) | `%M:%S` mutant |
| LLR-176.1h | File state written while running is stored, not painted | S | 2 writes → 0 changes, last stored | P12a-2 executed |
| LLR-176.1i | End with outcome → 1 status-log line | E | 2 arms | outcome-dropped mutant |
| LLR-176.1j | Last end paints the stored file state | E | 2 of 2 | final_line-over-file_state mutant; TC-B100-56 arm |
| LLR-176.1k | Last end clears the bar | E | 0 of 100; render = start-up | P12a-2 executed (100) |
| LLR-176.1l | A raise ends the progress with a failure outcome first | UW | 7 of 7 (spy) | end-dropped-on-exception mutant |
| LLR-176.1m | Unknown/replaced step or end: indicator unchanged; the outcome still logged | UW | 3 of 3 | key-only mutant |
| LLR-176.1n | A begin while another runs → the newer is shown | UW | 3 assertions | first-stays mutant |
| LLR-176.1o | A non-last end → the newest still running is shown | E | 4 assertions | hand-back-on-any-end mutant |
| LLR-176.1p | A begin under a running key restarts it | UW | 2 assertions | two-entries mutant |
| LLR-176.1q | Progress widgets written only on the main thread | U | 0 off-main writes, 4 actions | direct-call-from-worker mutant |
| LLR-176.1r | Names in a line through the one scrub + `safe_text`, markup off; `begin_busy` only in `_busy_begin_action` | U | 4 of 4 | raw-name mutant; `begin_busy`-call-site AST |
| LLR-176.1s | Bar row and log position the same idle or busy | U | 2 sizes × 2 | hide-when-idle mutant (base passes, declared) |
| LLR-176.2 | Each baseline `set_progress` site maps to one begin, step or end | U | 24 of 24 (re-derived) | P12a-1 executed (no table) |
| LLR-176.2a | Only the seam sets the bar | U | 0 outside calls; 0 outside queries | P12a-1 executed (24) |
| LLR-176.2b | Action table: 7 entries, label + ≥ 1 step | U | 7 of 7; 0 decision ids | code read (no table) |
| LLR-176.2c | Every success and failure exit ends the progress | U | 14 of 14 | `_handle_load_error` end-dropped mutant |
| LLR-176.2d | Save project reports its phases as steps (Inc 11 Q2 half) | E | phases in order, 1 end; refused → 0 begins | P12a-1 executed (no call in the save) |
| LLR-173.2m | Key bar and palette say "Load" / "Projects" | U | 6 assertions; key-bar pins; 29 SVG files | code read `app.py:2122`, `:2127`, `:2135` |
| LLR-172.4e | Dot/space-ending folder not listed on any OS | UW | 2 platform arms | P12a-4 executed (gate present) |
| LLR-172.4f | Workarea Files list: loadable suffixes only | UW | 4 of 6 rows; 1 shared predicate | code read (C7) |
| LLR-172.5i | Path the OS refuses (EACCES / ENAMETOOLONG) → refused with tokens; NUL arms regression | UW | 4 of 4 | base catch too narrow (ValueError/RuntimeError) |
| LLR-172.5j | One project-match function | U | 1 function (AST) | P12a-4 executed (2) |
| LLR-172.5k | Shared refusals worded from one table | U | 1 definition, 0 stray literals | P12a-4 raw count; E2 sites |
| LLR-172.6b | Pick re-checks the entry: not regular → nothing loads | UW | 6 arms (2 routes × 3) | SEC9-2 code read; E2 executes (a), (b) |
| LLR-172.6c | Pick over the copy cap → nothing loads | UW | cap / cap + 1 | code read (no size check) |

| AT / TC | Owner | 12a share |
|---|---|---|
| AT-B100-17 | HLR-176, HLR-176a, HLR-176c, HLR-176d | 12a half: worker load of a generated 8 MiB-data S19 by keys (the line, the elapsed time advancing, the outcome, the cleared bar). The parse half (bar ≥ 2 rises) is 12b's. |
| AT-B100-18 | HLR-177 | none (moved to 12b) |
| TC-B100-50 | LLR-176.1, LLR-176.1a … LLR-176.1s | full |
| TC-B100-51 | LLR-176.2, LLR-176.2a … LLR-176.2d | full |
| TC-B100-52 | LLR-176.3 | none (moved to 12b) |
| TC-B100-73 | LLR-176.4 | none (moved to 12b) |
| TC-B100-41 | LLR-173.2m | the labels arm |
| TC-B100-66 | LLR-173.7 | extended: progress labels, step names, 2 token pairs |
| TC-B100-56 | LLR-178.2 | extended: the file state through the hand-back |
| TC-B100-37 | LLR-172.4e, LLR-172.4f | new arms |
| TC-B100-38 | LLR-172.5i, LLR-172.5j, LLR-172.5k | new arms |
| TC-B100-39 | LLR-172.6b, LLR-172.6c | new arms |

**29148 check.** Every requirement above is singular (1 "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace, threshold or control.

Declared exceptions:
- **RED only as a mutation.** LLR-176.1s holds on base (P12a-2: the bar never hides). LLR-172.5j and LLR-172.5k are structural (an AST census); their base RED is the census count, not a behaviour.
- **Platform-dependent arms.** These are reported not run, never passed, when the platform cannot make the fixture: LLR-172.6b arm (c), a file symbolic link, which needs the privilege; LLR-172.4e's Windows arm (`\\?\` names) on Linux, and its Linux arm on Windows.
- **Declared invisibility.** At 12a, the A2L load, project load and Save project run on the main thread, so their line is painted and cleared without a frame between. HLR-176a's threshold uses only worker actions. Inc 12b removes the limit (HLR-177).
- **Shared response, several parts.** HLR-176 ("one progress line that holds …") and HLR-176c ("replace its progress indicator with the action's outcome") each state one response with parts; their thresholds test each part, as 9b did for HLR-173.
- **Planned controls.** LLR-176.2c's per-action failure arms and LLR-172.6b arms (a) and (b) are executed on the E2 baseline; their E1 controls are code reads.

## 2 · Defects fixed in place (old → new)

| Defect | Old | New |
|---|---|---|
| HLR-176 compound | 1 statement, 8 obligation clauses, about 14 behaviours | HLR-176 … HLR-176d, one "shall" each |
| LLR-176.1 compound | 1 "shall widen" carrying about 10 behaviours (ownership, bar, timer, threads, end order, idle row) | LLR-176.1 … LLR-176.1s, one behaviour each |
| LLR-176.2 compound | 2 clauses (table; census) | LLR-176.2 (census), LLR-176.2a (only the seam), LLR-176.2b (the table), LLR-176.2c (every exit) |
| Contradictory end order | "one final writer … paint[s], in this order, the outcome, then the project and file line, then the file state" on a one-row label; HLR-176's threshold and LLR-178.2 need the project and file line to stay | the outcome to the status log (LLR-176.1i); one stored `file_state` painted at the last end (LLR-176.1j); a file state written during the action stored, not painted (LLR-176.1h) (Q4, A12a-06) |
| Infeasible in the file set | "the bar shall advance within a step wherever progress is measurable (bytes copied, read or parsed)"; copy and read live in `workspace.py` and the frozen engine, outside the 12a+12b files | "copied, read" removed; the seam keeps `done` / `total`; the A2L parse is the shipped reporter (12b) (Q5) |
| Infeasible at 12a | LLR-176.3 "step_busy shall paint the step's name once before the work starts, through the `call_after_refresh` idiom", with a threshold read in a `call_after_refresh` callback, which passes only if the work is deferred | moved to 12b, where the only main-thread step left is the tag-table build (Q1) |
| No consumer at 12a | LLR-176.4's parse callback while the parse still blocks the main thread | moved to 12b with the `a2l.py` re-freeze (Q1) |
| Missing failure paths | no rule for overlapping actions, or for a late end from a replaced `exclusive=True` worker run | LLR-176.1m, LLR-176.1n, LLR-176.1o, LLR-176.1p (Q3) |
| Missing failure path | out-of-range step data (`total = 0`) | LLR-176.1d |
| Missing failure path | a raising action (the old text said "an exception included" without a threshold the 12a app can meet) | LLR-176.1l, spy-measured; app survival stays LLR-177.2 at 12b (Q8) |
| Unverifiable | "begin_busy takes ownership of `#status_text` (no other writer … paints it)" — what happens to the blocked write was not stated | LLR-176.1h: stored as the one file state and painted at the last end |
| Ambiguous term | "the bar shall be cleared" | "cleared bar" defined: progress 0 of total 100, the start-up state (LLR-176.1k) |
| Stale reference | LLR-176.2 "`app.py:4951`, `:6210`, `:8769`, `:8841`" (lines at `1d677ba`; `app.py` is 17 956 lines at `8947666`) | the census is re-derived at the 12a baseline and stored as a fixture list (LLR-176.2) |
| Existing pin of the defect | `test_report_progress.py::test_report_generation_drives_progress_bar_to_100` ("a completed report must leave #progress_bar at 100") encodes the stale 100 % | named for re-pin in §D.3 (LLR-176.1k) |
| Routed requirement (9b Q8) | LLR-173.2m removed from 9b; the 35-cell rebaseline deferred | restored at 12a with the 29 files named (§D.4) and the CI-environment constraint |
| Split decision (Inc 11 Q2) | "the save then runs on a worker under the status line with real progress" had no owner | 12a: LLR-176.2d (table entry, phases, end); 12b: the worker, refusal, quit (Q2) |
| Backlog sweep | 12 rows targeted at Inc 12a or its sweep, no requirement | 5 fixes as 7 LLRs; 7 rows declared, moved or closed (B1 … B12) |

## 3 · Slice for E2

Names come from the requirements, the tree at `8947666` and the 9b/10/11 interfaces. **(guess)** marks a node the requirements imply but do not name. Sources: `app.py` and at most one rule in `styles.tcss`, so **1–2 source files** (the PLAN row's "+ screens" is not needed: no 12a requirement touches `screens.py`).

Tests (not capped):
- `tests/test_b100_busy.py` (new: TC-B100-50, TC-B100-51, AT-B100-17 12a half);
- `tests/test_b97_key_bar.py` (`GLOBAL_TEXTS`, `GLOBAL_TEXTS_80`, the bindings table at `:1037`);
- `tests/test_report_progress.py` (re-pin `:49`);
- `tests/test_b100_load_dialog.py` (TC-B100-41 labels arm, TC-B100-66 extension);
- `tests/test_b100_announce.py` (TC-B100-56 extension);
- `tests/test_b100_recents.py` (TC-B100-37, -38, -39 arms);
- the 29 SVG files of draft §D.4.

### `app.py` — G-A (indicator): 16 changed + 5 new

| # | Node | What | Requirement |
|---|---|---|---|
| N1 | `begin_busy(key, label, steps) -> int` (NEW) | add or restart the run (new generation), remember the text before the first begin, paint the line, bar 0, start the one timer | 176.1, .1a, .1n, .1p, .1r |
| N2 | `step_busy(key, gen, n, done=None, total=None)` (NEW) | clamp; update the run; paint and set the bar only if the run is the shown one; ignore unknown or replaced runs | 176.1b, .1c, .1d, .1m |
| N3 | `end_busy(key, gen, outcome)` (NEW) | write the outcome to the log, then ignore unknown or replaced runs; drop the run; show the newest remaining or paint the stored file state, clear the bar, stop the timer | 176.1f, .1i, .1j, .1k, .1m, .1o |
| N4 | `_busy_tick` (NEW) | advance the glyph and repaint the elapsed time of the shown run | 176.1e, .1g |
| N5 | `_BUSY_ACTIONS` (NEW, data) | 7 keys → label template + step names | 176.2b |
| G1 | `_busy_line(run) -> str` (guess) | the `pd_A` text, names through `painted_names` | 176.1, .1g, .1r |
| C1 | `set_progress` | unchanged signature; called only by N1–N3 | 176.2a |
| C2 | `set_file_status` | always store `file_state`; paint only while no run exists | 176.1h |
| C3 | `load_from_path` | begin `file_load` (replaces `set_progress(10, …)`); copy and parse steps; refusals after the begin end it | 176.2, .2c |
| C4 | `_start_load_worker` | step and end through `call_from_thread`; try / finally end on a raise | 176.1l, .1q, .2 |
| C5 | `_handle_load_error` | end with `Load failed` (replaces `set_progress(100, "Load failed")`) | 176.2c |
| C6 | `load_a2l_from_path` | begin `a2l_load`; 3 steps; end (5 sites today) | 176.2, .2c |
| C7 | `action_before_after_report` | begin `before_after` | 176.2 |
| C8 | `_start_before_after_worker` | steps and end via `call_from_thread` (4 sites) | 176.2, .1q |
| C9 | `_trigger_generate_report` | begin `report` | 176.2 |
| C10 | `_start_generate_report_worker` | steps via `call_from_thread` (2 sites) | 176.2 |
| C11 | `_finish_generate_report` | end on success | 176.2c |
| C12 | `report_failed` | end on failure | 176.2c |
| C13 | `on_ab_diff_panel_report_requested` | begin `diff_report` | 176.2 |
| C14 | `_start_diff_report_worker` | steps and ends via `call_from_thread` (6 sites) | 176.2, .2c |
| C15 | `_handle_load_project` | begin / end `project_load`; the project and file line stored as the file state (its `set_file_status` stores it) | 176.2b, .1j; TC-B100-56 |
| C16 | `_handle_save_dialog` / `_prepare_project_save` (Inc 11) | begin `save_project` after the dialog accepts; one step per phase; end on every exit | 176.2d, .2c |

### `app.py` — G-B (labels and sweep): 7 changed + 1 new (+1 guess)

| # | Node | What | Requirement |
|---|---|---|---|
| B1 | `BINDINGS` (data) | `"Load"` for both `load_file` bindings; `"Projects"` for `load_project` | 173.2m |
| B2 | `list_projects` | drop `os.name == "nt"` from the trailing-dot skip | 172.4e |
| B3 | `refresh_files` | keep loadable suffixes only, through the predicate 9b's `_load_dialog_rows` uses | 172.4f |
| B4 | `_typed_load_route` | catch `(OSError, ValueError, RuntimeError)` from the one `resolve_input_path` call → `("refuse", "not found")`; use B6 | 172.5i, .5j |
| B5 | `_load_path_from_user_input` / `_handle_load_project` | refusal lines from one table (9b's `_TYPED_REFUSAL_TOKENS` or its successor); `_handle_load_project` uses B6 | 172.5j, .5k |
| B6 | `_listed_project_name(name) -> Optional[str]` (NEW) | the one `list_projects()` + `normcase` match | 172.5j |
| B7 | `_load_workarea_file` (9b G1) | `os.lstat` at pick time: not `S_ISREG` or a reparse point → `not a regular file`; size over `DEFAULT_COPY_SIZE_CAP_BYTES` (read at call time) → `too large to open` | 172.6b, .6c |
| G2 | `_loadable_suffix(name)` (guess) | the shared suffix predicate, if 9b left it inline | 172.4f |

### `styles.tcss` — 0 or 1 rule (guess)

| # | Selector | What | Requirement |
|---|---|---|---|
| S1 | a `#status_text` component or class for the glyph and elapsed accent (guess) | only if E2 keeps `pd_A`'s colours; the 6-token palette is closed, so the rule uses `$accent-calm` | 176.1 (look, Q9) |

**Node count.**
- **Firm:** G-A 21 (16 changed + 5 new); G-B 8 (7 changed + 1 new).
- **With the guesses:** up to 31 code nodes plus 1 CSS rule. That is far above ~8, so E2 runs by group (Q7): G-A (one prototype for the seam and the 4 worker actions, then the 3 main-thread actions) and G-B (labels + sweep). If G-A must split again: G-A1 = N1 … N5, G1, C1, C2 (the seam); G-A2 = C3 … C16 (the callers).
- **Source files:** 1 (`app.py`), or 2 with S1, against the cap of 4.

**Callers checked (`8947666`):**
- `set_progress` ← the 12 functions of P-29 (P12a-1 lists every line).
- `set_file_status` ← `_handle_load_project` (`:11942`), `_apply_prepared_load` (`:15464`).
- `_start_load_worker` ← `load_from_path` only (`:13071`). `load_selected_file` is synchronous and is reached from `_handle_load_project` (`:11920`) and `_load_from_item` (`:13335`).
- `list_projects` ← `action_load_project`, `_handle_load_project`, `_typed_load_route`, 9b's `_load_dialog_rows`, and 7 test files (9b scope).
- `refresh_files` ← `on_mount` (`:7195`), `action_refresh_files` (`:7327`), `_handle_save_dialog` (`:10601`), `load_from_path` (via `call_later`, `:13075`), `load_a2l_from_path` (`:13134`).
- `_load_workarea_file` ← `_load_from_item` and the 9b router's `workarea` choice (`interfaces-9b.md`).
- `BINDINGS` ← `_build_palette_entries`, the key bar (`window_help.py`), the help overlay.

**Unchanged context:** `compose` (`#status_line`, `#progress_bar` at `app.py:2819`, `:2825`), `_apply_prepared_load` (its `set_file_status` stores `file_state` through C2), `set_status` / `_append_log_line`, `painted_names` (`project_gather_service.py`), `check_action` (9b + Inc 10 + Inc 11 guard; 12a adds no modal), `copy_into_workarea` / `place_into_workarea` (`workspace.py`, Q5), `parse_a2l_file` (`a2l.py`, 12b).

**Seams to fix before E2 (in one file, by the orchestrator):**
- S-a The seam's signatures: `begin_busy(key: str, label: str, steps: Sequence[str]) -> int` (returns the run's generation); `step_busy(key, gen, n, done=None, total=None)`; `end_busy(key, gen, outcome: str)`. All three are main-thread only, and workers reach them through `call_from_thread`.
- S-b Run state: an ordered mapping key → run (generation, label, steps, `n`, fraction, start time); the one stored file-state line; one timer handle. The shown run is the most recently begun.
- S-c `_BUSY_ACTIONS` shape: key → (label template with an optional `{name}`, tuple of step names). Keys: `file_load`, `a2l_load`, `project_load`, `save_project`, `report`, `diff_report`, `before_after`.
- S-d The stored `file_state` hand-back (LLR-176.1j) and the "cleared bar" value (0 of 100).
- S-e The exception rule: each action body holds begin … end in a try / finally; a worker's finally posts the end through `call_from_thread`.
- S-f The loadable-suffix predicate: one function or constant, shared by `refresh_files` and 9b's `_load_dialog_rows`. G-B confirms the name 9b ships.

## 4 · Open questions

Recommendations and alternatives are in `E1-rulings-proposed.md` (Q1 … Q10, and the backlog dispositions B1 … B12). The draft text follows each recommendation; a different ruling changes only the ids named there.

## 5 · Observations

- **The cap.** It does not bind at 12a: every recommended fix is in `app.py`. Only the alternatives that fix B2, B6 or B7 in `workspace.py`, or keep LLR-176.4 at 12a (`a2l.py`), add a file, and the worst case is 4.
- **12a is invisible for three actions.** The A2L load, project load and Save project paint their line and clear it within one blocked call at 12a. This is declared in HLR-176a; the user-visible gain at 12a is on file loads, reports, diff reports and before/after runs. 12a and 12b land together (R-PD), so the operator never sees the half state in a release.
- **Test blast radius of the ownership rule.** A test that reads `#status_text` after an action ends sees the same text as today (the stored file state is painted at the end). A test that reads it while a worker action still runs now sees the progress line. E2 owes the census of such tests among the 25 `#status_text` consumers listed in the `busy_status_line` component.
- **`test_report_progress.py`** pins the bar at 100 after a report (AC-2/3). That pin encodes the stale-100 defect HLR-176c removes, so it is re-pinned, not kept green.
- **Snapshot drift.** Inc 9b, 10 and 11 may rebaseline some of the 29 files first. E2 re-runs the census on the 12a baseline. The regeneration itself runs only through `.github/workflows/snapshot-regen.yml` (draft §D.4).
- **The work-area image pick and the typed-load copy stay on the main thread after 12b** (`load_selected_file` from `_load_from_item`; `copy_into_workarea` in `load_from_path`). Neither is in HLR-177's list. Recorded for 12b's E1 in the rulings file.
- **OBS-9a-2** comes from the E13 seed (`tools/e13/run.py` writes `project.json` without `files`), not from app code (code read; B9).
