# Increment 006 — HLR-147 (+ the Execution arms of HLR-148 / HLR-149) · `Flow Execution: one pipeline per lane (fx_A), headers closed`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-006.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `006` |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-147 / LLR-147.1–147.13` (147.5 panel scope; 147.7 over the four panels) · closes `LLR-148.4, 148.5, 148.6` (`flow_execution` key), `148.7, 148.9, 148.10` · Execution arms of `LLR-149.1–149.6` · operator decisions at the Inc-6 pre-work gate: `LED-2026-10-19-batch-97.30` (two-external-step fix lands here), `.31` (Q-B97-6a: no start mark) · implementation finding `.32` (two A.5 fixtures re-cut) |
| Acceptance | AT-B97-09, -10, -11, -20, -22 (HLR-147) · AT-B97-12, -13, -14, -23 (HLR-148, four screens) · TC-B97-21..26, -52..56, -63, -64 · TC-B97-29..33, -58, -65 (Execution arms) · TC-B97-34..38, -59 (Execution arms) · TC-B97-51 (Builder `space` arm, PC-3) |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-22` |
| Design refs | `PDR-2026-10-19-batch-97#D6`, `#D7` (a)–(e), `#D10` (amended), `#D12`, `#D13`, `#D14`, `#D15`, `#D21`, `#D23`, `#D24`, `#D25`; I-4, I-7 (a)–(e), I-9, I-11; PC-2, PC-3, PC-4, PC-10, PC-11, PC-13, PC-15, PC-16, PC-21, PC-24 (owed here) |

---

## 1 · What changed

Flow Execution is fx_A: lanes are stacked. Each lane is a head line, its pending lines while it waits, and one row of block cards. The cards are joined by cables, and each cable carries its block's run status from the retained record. The waiting lane's card and Confirm are brought into view, `c` confirms it after a 0.5 s dwell, and a lane with two external steps now reaches its end.

- **Ribbon + set row (LLR-147.4).** `#fx_ribbon` holds `#fx_name_strip` and `#fx_run_row` (Import…, the mode toggle, Run). The name strip reads `Set: <name>  · saved | · unsaved`, with `session <path tail>` right-aligned (the Builder's `ribbon_text`, which gained a `prefix=` keyword; the Builder output is unchanged). The set row holds `set name` + input, Save Set, `saved sets` + a compact select, and Load Set. Everything is one row each, and Save Set / Load Set lie inside the panel at every size.
- **Mode toggle (D13, PC-3).** `ModeToggle(FlowChip)` `#fx_mode` paints `sequential · parallel` (23 cells). A click selects the word under it and never toggles; `enter` / `space` toggle; it posts no `Button.Pressed`. `FlowExecutionPanel.mode` feeds `RunRequested.mode`.
- **`FlowChip` (D13, PC-3).** `FlowChip(Button)` binds `space`. Every `Button(` in `flow_screens.py` is now a `FlowChip(` (Builder: Add, Copy, Paste, Variables, Add var, Run, Clear, Save…, Load…; Execution: Import…, Run, Save Set, Load Set, Bind, Confirm). `KindChip` is a `FlowChip`. An AST census pins 0 `Button(` constructors.
- **Lanes (LLR-147.1, 147.2, 147.12; D24, PC-4).** `#fx_lanes_scroll` is the hero (`height: 1fr`, both axes, stable 1-cell gutter, title `lanes · N chains`). `#fx_lanes` is a `Vertical`. Each `#fx_lane_<i>` holds:
  - `#fx_lane_<i>_head`: the worst-status mark (`✗ □ ◇ ▓ ░`), chain, status word, elapsed, block count and `wrote …`;
  - `#fx_lane_<i>_pending`: red `▪` lines while waiting, plus a reload's `▪ '<ref>' missing - re-bind`;
  - `#fx_lane_<i>_row`: cards `#fx_card_<i>_<j>`, cables `#fx_cable_<i>_<j>` and `#fx_confirm_<i>`.
  A card is a bordered `Vertical` whose border title is the kind glyph + label in the kind colour. It holds two io lines (clipped at `card_w − 4`, refs tail-kept, commands head-kept) and one status line. The SOURCE card holds `#fx_lane_<i>_edit_<j>` (the `#fx_in_<i>_<j>` input + `#fx_bind_<i>_<j>`). Cards measure **5 rows** (design §3 assumed 7). `lane_layout(viewport_w, n_max) = pipeline_layout(viewport_w − CONFIRM_RESERVE, n_max)` applies once to every lane. Card *k* starts at the same x in every lane, and the reserve is taken whether or not a lane waits. `#fx_lane_<i>_paint` is not mounted any more. `lane_paint_plain(i)` returns the head, pending lines and card rows.
- **Cables (LLR-147.1).** `cable_glyph(status, next)`: `□` into a waiting block; otherwise `▓` ok, `◇` notices, `✗` error, `░` skipped / waiting / no record. A cable paints `─<mark>─▶` on the card's output row, and the cable into the waiting card paints in `$waiting-human`.
- **The waiting lane (LLR-147.3, 147.7, 147.9).** The waiting card's border, the cable into it, the lane's status word, the Confirm and the REQUIRED line all paint in the waiting colour. Confirm is a 1-row `FlowChip` `Confirm` (`variant="primary"`, so it counts as filled), placed 1 gap after the lane's last card on the output row. The attention Confirm (`.fx-attention`) is filled `$waiting-human` with bold `$bg-base` text; another waiting Confirm is filled `$waiting-human 40%`; Run keeps `fill-accent`. `#fx_required` reads `log + output file: REQUIRED for <chain> · press c to confirm`.
- **Attention state (I-7 (b)–(c), PC-21).** The panel alone owns `_attention`, `_attention_block` and `_attention_since`; `_rearm_attention()` is their only writer. The dwell base is stamped by `call_after_refresh(_stamp_attention, …)` through the `_fx_clock` seam. The scroll step brings the waiting card + Confirm into view on both axes, clamped so that a focused widget inside the lanes stays visible. The focus never moves.
- **`c` (D10 amended, PC-13; LLR-147.13; D15).** `S19TuiApp.BINDINGS` gains `Binding("c", "confirm_attention", "Confirm", show=False)`. `check_action` is new, with one arm: `confirm_attention` runs only when `_active_screen_key == "flow_execution"`. `action_confirm_attention` writes `panel.confirm_attention()` to the status line, which is one of the three I-9 lines.
- **One run at a time (D14, PC-15; LLR-147.10).** Run and every displayed Confirm are disabled before `RunRequested` / `ExternalStepConfirmed` is posted. **Implementation note:** the flag is set without Textual's `disabled` watcher, because that watcher blurs a focused button and hands the focus (and any queued `enter`) to its neighbour, Import… or the mode switch. The focus stays put, and a queued key reaches a disabled button. The Run and confirm handlers each wrap `run_chain_set` in `try/except Exception` and paint `fx_run_error_line(exc)` (`run failed - <Type>: <first line>`, ≤ 160 cells, never a traceback). Every exit of the confirm handler ends in `apply_confirmed_run` or `render_confirm_error`, and all four painters re-enable through `call_after_refresh`. A failed re-run leaves the step unconfirmed.
- **Two external steps (HIGH, operator decision 1, LED-…97.30; I-7 (d)).**
  - Each lane keeps `confirmed: tuple[int, ...]`, exposed by `confirmed_blocks(i)`.
  - The app sends one `ExternalStepConfirmation` per confirmed block. The message type is unchanged.
  - `apply_confirmed_run` derives `paused_block` exactly as `render_run` does and re-arms the attention.
  - `flash2_chain` and `two_wait` end `ok`. The panel probe on HEAD shows the shipped lane stuck: after one confirm it is still `paused`, with Confirm hidden. The service shows the bounce-back (`{2}` → waits at block 1 again). Mutation M27 (the re-run carries only the current block) reproduces the bounce on the Inc-6 tree.
- **Run log (LLR-147.8, 147.5, I-7 (e); Q-B97-6a, LED-…97.31).** One composer serves the set run and the re-run. Stamps are measured from the set's run start. A start line reads `<stamp> <chain> · started` (no mark). Terminal lines read `▓ … · done`, `◇ … · done with notices`, `✗ … · block i/n KIND — … · chain halted` and `□ … · WAITING FOR A HUMAN — external step (block i/n) · log '<ref>' pending`. A re-run reads `· re-run after confirming the external step (block i/n)`. The log paints at most 8 lines: a log longer than that shows `… k earlier lines — the full log is in the run report` and then the newest 7. Before a run it shows `No run yet — Run executes every lane.`; Run with no lanes shows `No chains to run — Import… adds a lane first.`
- **Refusals (LLR-148.9).** Import / set-load notices now lead with the loader's code (`[FLOW-UNSAFE-REF] …`, `[CHAIN-SET-UNSAFE-REF] …`) and stay on one row. A bound ref refused at run (`nul_bind`) names `[MANIFEST-PATH-ESCAPE]` (it used to name the template's own `prg.s19`). A missing SOURCE file names the bound ref.
- **English (LLR-147.5).** The 9 Spanish panel constants are gone: `Confirm`, `session`, `(no active project)`, `▪ log '<ref>' pending`, `▪ output file not confirmed — waiting for a human`, `waiting for a human`, the WAITING log line, and the re-run line.
- **Glyphs (D7 (a)–(e)).** `FX_CABLE_GLYPHS = {▓ ok, ░ not run, ✗ error, ◇ notices, □ waiting for a human}`, `FX_PENDING_GLYPH = "▪"`, and `_FX_STATUS_STYLE` re-keyed on the cable vocabulary. 0 `⚠ ✖ ✔ ☑ ⏸` are painted. The legend `#fx_legend` (one row) is generated from those.
- **app.py.** `#screen_flow_execution` is a plain `WindowSection("flow_execution", titled_header("Flow Execution", OpenFolderChip("session"), help_button=WindowHelpChip("flow_execution")), …)`. The session chip is silent at mount (Inc-5's `_resolved_once`; `open_folder_chip.py` is untouched).
- **styles.tcss.** One appended section `/* batch-97 flow_execution */`, every selector rooted at `#fx_panel`. Everything shipped at `b514b07` is a byte-equal prefix of the new sheet (test-pinned).
- **window_help.py.** `flow_execution` is written code-authored (D25), with one `label — effect` line per chip, field, key and glyph, plus the key line `c — Confirm: …`. `SHIPPED_WINDOW_KEYS` gains `flow_execution`. The Builder's `space` line now says it presses every chip.
- **docs/architecture.md §11.** The I-7 row is amended to the as-built surface, and the I-11 row is added.

**Visible deltas vs fx_A** (`prototypes/b94_polish/png/fx_A*.png` vs `evidence/inc-6/png/impl.flow-execution*.png`) — **for the operator:**
1. **Confirm is a 1-row chip** after the lane's last card on the output row, not fx_A's 10x6 amber slab (D24/I-9 sizing).
2. **The ^K palette gains a `Confirm` entry** (LLR-003.2 makes every app binding a palette entry). It is inert off Flow Execution through `check_action`.
3. **The run log is capped at 8 lines**, with `… k earlier lines — the full log is in the run report`.
4. **`· saved` / `· unsaved`** replaces fx_A's `●`, as on the Builder ribbon (LED-…97.26 reasoning).
5. Cards are 5 rows: border title, 2 io lines, status. fx_A's title row sits on the border, and its separate `in1` label is gone; the SOURCE card's first row is the input itself.
6. The session folder moved from each lane head to the ribbon (design tree). fx_A's ghost row `+ Import… adds another lane` is not there; the empty lanes area says it.
7. **New, not decided:** a waiting lane past the viewport scrolls the lanes sideways (LLR-147.3), so **that lane's head and pending lines scroll out of view** (capture `impl.flow-execution-two-wait-done*` before the fix showed it; a single scroller is D24's choice). **The view also stays scrolled after the lane finishes** (`impl.flow-execution-two-wait-done.png`: the LOAD card is cut). See §6 item 1.

### 1b · Gate fold

Gate fold (2026-10-22). Both reviews came in at the Inc-6 gate: `code-reviewer` (OK to advance, 0 HIGH) and `ux-reviewer` (approve with conditions). The fold stays inside the same **four source files**, and no fifth file was needed. The orchestrator relayed one operator decision, asked at the Inc-6 gate on 2026-10-22, recorded as LED-…97.33. The review folds that change a literal are LED-…97.34.

| Finding | What changed | Pinned by |
|---|---|---|
| **ux M1** (option b) | When no lane waits, `_rearm_attention`'s `target is None` branch schedules `_scroll_lanes_home`, which scrolls `#fx_lanes_scroll` to `x 0` with `animate=False`. The retained-focus rule still holds: a focused widget inside the lanes stays in view. The WT captures `impl.flow-execution-two-wait-done*.png` were re-captured: the finished lane reads in full from `▓ two_step · done`, and its LOAD card is whole | `test_tc_b97_23_lanes_return_home_when_no_lane_waits` (NEW, RED on the pre-fold source: `scroll_x` 14); M47 |
| **ux M2** + **code F5** (LED-…97.34) | The confirm line reads `Confirmed <chain> — re-running from block i/n.` A failed re-run now writes `<chain> failed at block i/n — <reason>; Run re-runs the set.` (`apply_confirmed_run` returns the line, and the app writes it). `c` during a run writes `c: a run is in progress — wait for it to finish.` I-9's third line is superseded by name in `test_tc_b97_64_c_after_the_dwell_confirms_the_attention_lane`. **Flagged for the operator:** PC-2 decision 2 froze the old wording. Asked at the gate (2026-10-22), the operator kept the new wording | that node (rewritten) plus `test_tc_b97_64_a_failed_rerun_says_so_on_the_status_line` and `test_tc_b97_55_c_during_a_run_says_a_run_is_in_progress` (NEW), all RED on the pre-fold source; M48, M49, M50 |
| ux L1 | The legend words became `▓ done` and `░ not run / skipped`, the cards' words. The help body's `▓` and `░` lines match | `test_tc_b97_33_flow_execution_glyphs_closed_and_in_the_legend` (+ word clause, RED pre-fold); M52 |
| ux L2 | The lane head's time is the log's clock — `mm:ss.mmm` since the set run began (`_FxLane.last_finished`) — and no longer the lane's own duration | `test_tc_b97_63_lane_head_time_is_on_the_set_clock` (NEW, RED pre-fold: `0.016s` vs `00:00.016`); M51 |
| ux L3 | `#fx_lanes_scroll`'s scrollbars are dimmed: a DGRAY thumb on `$bg-panel`, as the Patch Editor's (Inc-4). They sit inside the scoped section | visual — WT captures; the CSS scope arm stays green |
| ux L4, L5 | accepted (L4 is covered by M2) | — |
| **code F1** | `_rearm_attention(restart: bool = False)`. `render_run` calls it with `restart=True`, and its two direct writes to `_attention` / `_attention_block` are deleted. `_rearm_attention` is again the only writer. The restart arm is mutation-checked | `test_tc_b97_64_a_new_set_run_restarts_the_dwell` (NEW). It is GREEN on the pre-fold source (a refactor) and RED by M46 |
| code F3 | Before each `pause(0.6)` in the dwell arms (11 sites in `test_b97_flow_execution.py`), `await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)` is added. The `is None` half lets the no-waiting arm skip the wait | the dwell arms, green |
| code F4 | The modal arm of `test_tc_b97_64_c_confirms_nothing_out_of_scope` gains a positive control: with the modal closed, the same `c` confirms once | that node |
| code F2 (PC-10 harness race) | Not fixed here, as instructed. Owed to Inc-7 before the regen (§6 item 10) | — |
| **Operator, ux M3** (LED-…97.33) | The cut of the waiting lane's head and `▪` lines under horizontal scroll is **accepted for now**. A next-batch prototype round is in `BACKLOG-CODE.md` (batch-97, operator-requested: pinned heads via an offset-x spike, or a D24 re-cut). The silent no-op patch at `0x00020000` was already back-logged (P2) | backlog |

**Fold RED** on the pre-fold Inc-6 source (worktree `prefold6`, digests `a2afd60a…` / `6f32fbae…` / `f91bd869…` / `303be19e…`): **6 failed / 2 passed** over the fold's 8 new or changed arms (`red-fold.txt`). The 2 GREEN are F1's restart arm (a refactor: same behaviour; RED by M46) and F4's modal positive control (it passes by design; the 0-confirm clause above it is the arm).
**Fold GREEN** on the gate set (34 files, guard host `tests/test_tui_directionb.py` included): **1014 passed, 29 xfailed, 2 failed** in 1:09:11 (`green-fold.txt`). The two failures:
- `AT-B78-03` is the baseline failure, with the `Confirm` palette row.
- `test_at_b94_17_template_save_listing_import_and_dedup` is not in the baseline. It failed 1 of 5 runs isolated on the folded tree, and also 1 of 5 on the pre-fold tree (`rerun-nonbaseline-fold.txt`), so it is a pre-existing flake of the Builder template listing.

`test_at073b` passed this time.

**Fold mutations**: **11 mutants, 14 arms: 13 KILLED / 1 SURVIVED / 0 BAD** (`mutations-fold.txt`). These were the new M46–M52, plus M4, M7, M22 and M23 re-run because F1 and F3 touch the attention path. The survivor is **M22** (no dwell) on the `flash2_chain` arm, which it killed before the fold. The burst's second `c` now arrives while the first re-run is still in flight, and F5's in-flight arm (D14's guard) refuses it before the dwell is read. Two independent guards each suffice there. M22 is still KILLED by the `two_wait` burst arm.
**Neighbour frames** after the fold: identical to `b514b07` (`frames-fold.txt` = `675f95e1…`, `frames-diff-fold.txt` empty).
**PC-10** after the fold: 1 of 29 cells differs from HEAD (`diff-comfortable-120x30`), and only in the status-bar A2L column (`(none)` vs `snap.a2l`). That is the same harness race as before (F2), not Inc-6 content.

Final fold source digests: `flow_screens.py 2e46f312…`, `app.py a0be1dd7…`, `styles.tcss 7a5bef81…`, `window_help.py a488a0bc…`. GREEN, the mutation battery and the captures ran on these.

### 1c · Close (orchestrator, 2026-10-22)

| Item | What changed | Pinned by |
|---|---|---|
| **code-reviewer F6** (MEDIUM, gate re-read) | `_rearm_attention` returned on `target == current` even after `restart` had cleared the attention, so a new run with no lane waiting left the REQUIRED line, `fx-attention` and the scroll stale. The early return now reads `target == current and not restart` | `test_tc_b97_64_a_restart_with_no_lane_waiting_clears_the_attention` (NEW); the F6 mutant (the old guard) is RED, restored GREEN (`mutation-f6.txt`) |
| code-reviewer F7 (LOW) | The docstring names `_stamp_attention` as the scheduled writer of `_attention_since` | — |
| **Full-suite finding** (LED-…97.35) | The full suite failed both `tests/test_tui_theme.py::test_tc_012_*` nodes: design D12 named a sixth `sev-*` class (`sev-waiting`) against LLR-005.2's frozen five. The class is renamed `fx-waiting` (2 sites in `flow_screens.py`, 1 rule in `styles.tcss`); D12 is amended. The gate set did not carry `test_tui_theme.py`, which is why the gate GREEN missed it | `test_tui_theme.py` (GREEN in `green-post-suite.txt`) |

**Full suite** (`suite-full.txt`, 2:00:13, on the fold tree before 1c): **12 failed, 3542 passed, 3 skipped, 32 xfailed**. Against the baseline's 10: 5 baseline nodes passed this time, 7 are not in the baseline.
- `test_tc_012_five_sev_rules_present_and_unchanged` and `test_tc_012_severity_class_names_match_color_policy` are real (above), fixed in 1c.
- `test_tc_b97_55_input_queued_during_a_run_starts_no_second_run` is new in Inc-6; it passed 6 of 6 isolated on the final tree (`rerun-nonbaseline-suite.txt` and the isolated re-run), so it is a load flake in the 2-hour run — **recorded, not fixed.**
- `test_at_061a_…`, `test_at194_…` (a resident-cost bound), `test_tc081_3_sites` and `test_ac2_1_…` (a known flake) passed isolated.

**Post-suite GREEN** on the final source digests (`green-post-suite.txt`): `test_tui_theme.py`, `test_b97_flow_execution.py`, `test_tui_flow_execution_b94.py`, `test_b97_width.py` and `test_flow_external_step_b96.py` — **262 passed**. The full suite was not re-run after 1c (3 lines of class rename plus the F6 guard; the affected modules were re-run).

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/flow_screens.py` | source | HLR-147, LLR-147.1–147.13, LLR-148.7, 148.9, 149.1, 149.4, 149.5; D13 (Builder chips, LLR-146.13) | `FlowChip`, `ModeToggle`, `FX_MODES`; `FX_CABLE_GLYPHS`, `FX_PENDING_GLYPH`, `CONFIRM_DWELL_S`, `CONFIRM_RESERVE`, `FX_LOG_MAX_ROWS`, `_fx_clock`, `cable_glyph`, `LaneLayout` / `lane_layout`, `fx_run_error_line`, `fx_legend_text`, `_coded`; `FlowExecutionPanel` re-composed (attention state, D14 disable, confirmed blocks, log composer, layout pass); Builder `Button(` → `FlowChip(`; `ribbon_text(prefix=)` |
| `s19_app/tui/app.py` | source | LLR-147.10, 147.13, 148.5; D10, D14, I-7 (d), I-11 | `WindowSection` header with the session + help chips; `c` binding; `check_action`; `action_confirm_attention`; the Run handler's `except`; the confirm handler rewritten (every confirmed block, guards → `render_confirm_error`, `except`) |
| `s19_app/tui/styles.tcss` | source | LLR-147.3, 147.4, 147.7, 147.8, 147.9, 149.2, 149.4, 149.5 | one appended `/* batch-97 flow_execution */` section |
| `s19_app/tui/window_help.py` | source | LLR-148.6, 147.13 | `flow_execution` section; `SHIPPED_WINDOW_KEYS`; Builder `space` line |
| `docs/architecture.md` | doc | I-7, I-11 | §11 rows |
| `tests/test_b97_flow_execution.py` | test | HLR-147, LLR-147.1–147.13, 149.1 (layer 0) | +58 nodes (TC-21..26, 52..56, 63, 64, layer-0 arms, CSS scope, chip census, AT-09/10/11/20/22) |
| `tests/test_b97_chips_help.py` | test | HLR-148, LLR-148.3–148.10 | +30 nodes (TC-29, 30, 31, 32, 33 ×2, 58 ×6, 65 ×2, AT-12 ×5, AT-13, AT-14 ×4, AT-23 ×6); `WT_NARROW_GLYPHS` + `▓ ░ ◇` |
| `tests/test_b97_width.py` | test | HLR-149, LLR-149.1–149.6 | +42 Execution nodes |
| `tests/test_b97_flow_builder.py` | test | LLR-146.13 (PC-3) | +1 node (`space` per Builder button group) |
| `tests/b97_fixtures.py` | fixture | HLR-147 (A.5) | `err_chain_demo`, `crc_wait_chain_demo`, `six_ok_demo`, `six_wait_demo`, `flash2_chain_demo`, `flip_one_data_byte`, `fx_project`, `flash_evidence`, `hostile_flow_file`, `hostile_set_file`, `open_flow_execution`, `import_flow`, `import_lanes`, `run_lanes` |
| `tests/test_tui_flow_execution_b94.py` | test | LLR-147.1, 147.2, 147.4, LED-…97.31 | named supersession: AT-B94-19 (`:345-348`), TC-B94-26 (`:451-454`), TC-B94-27 (`in1 base.s19` → `base.s19`), AT-B94-20 (`✓` → `▓`), AT-B94-21 / -22 (`#fx_mode` read as the toggle), AT-B94-22 / -23, TC-B94-29 (start mark and `✓`) |
| `tests/test_flow_external_step_b96.py` | test | LLR-147.5 | TC-1804: `lane_paint_plain`; Spanish pins → English |
| `tests/test_window_usage_help.py` · `tests/test_changes_file_notation_help.py` | test | LLR-148.6 (I-4) | `flow_execution` joins the code-authored keys |
| `tests/test_tui_patch_history_strip.py` | test | LLR-147.13 (D10 / PC-13) | TC-081.4: marker `confirm_attention` sanctioned (named supersession) |
| `prototypes/b94_polish/run_real.py` | doc | | untracked harness: scenarios `flow-execution-idle`, `flow-execution-two-wait-done`; drive errors logged to a file |
| `.dev-flow/…/01-requirements-ledger.md`, `design/design-proposal.md` (D7 (e), I-7 (e)), `.dev-flow/BACKLOG-CODE.md` | doc | LED-…97.30–.32 | records |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** — `flow_screens.py`, `app.py`, `styles.tcss`, `window_help.py` (`open_folder_chip.py` untouched) |
| Test files | 9 (4 b97 modules, the fixture module, 4 superseded modules) |
| Doc files | `docs/architecture.md`, this packet, ledger / design / backlog records, evidence, one untracked harness |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8; unset NO_COLOR
python -m pytest $(cat .dev-flow/2026-10-19-batch-97/evidence/inc-6/gate-files.txt) -q -rfE -p no:cacheprovider
python .dev-flow/2026-10-19-batch-97/evidence/inc-6/mutate.py              # 45 mutants / 67 arms
python .dev-flow/2026-10-19-batch-97/evidence/inc-6/measure_budget.py .    # PC-24 budget
python .dev-flow/2026-10-19-batch-97/evidence/inc-6/frames.py <tree>       # Check / Patch / Builder frames
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/snapshot_cells.py <tree>   # PC-10
python .dev-flow/2026-10-19-batch-97/evidence/inc-6/probe_two_ext.py <tree>    # the two-step lane
powershell -File prototypes/b94_polish/capture.ps1 -Scenario flow-execution-idle|-paused|-two-wait-done -RealTree -OutPng <png> [-Rows 53 | -Cols 220 -Rows 60]
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `cable_glyph` ×8, `lane_layout`, `fx_run_error_line`, the `Button(` census, CSS scope, panel Spanish census (+ reach guard on `9c7beaf`), WT width arm | passed (in `green.txt`) |
| **A · white-box** | `core` · `full` | gate set (`gate-files.txt`, 34 files incl. guard host `tests/test_tui_directionb.py`, the snapshot module, the Check / Patch / Builder b97 modules) | **1009 passed, 29 xfailed, 2 failed** in 1:09:43 (`green.txt`, on the final source digests). `test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` is a **baseline failure** (`baseline-pytest-51ee191.txt`); its unexpected set now names `confirm_attention` beside `a2l_describe_tag` — the new `Confirm` palette row, as design §6.1 Inc-6 (2) said it would. `test_at073b_glance_geometry_fits_and_reflows` is not in the baseline: **5/5 passed isolated on the Inc-6 tree, 2/5 failed on a clean `b514b07` worktree** (`rerun-nonbaseline.txt`) — a pre-existing flake |
| **Full suite** | `full` | — | **not-run** (the orchestrator runs it; ~1h30, memory-tight host) |
| **B · black-box** | `core` · `full` | AT-B97-09, -10 ×2, -11, -20, -22, -12 ×5, -13, -14 ×4, -23 ×6 | passed (same run) |

**PC-24, the 118x53 arms:** these all pass at 118x53 too: TC-B97-23 (both fixtures), TC-B97-24, TC-B97-53, TC-B97-36 (Execution, 7 samples), TC-B97-38 (height, before / after run) and AT-B97-10. **Budget measured on the real tree** (`budget.txt`). Every row the cards lose against the design's 7-row assumption goes to the lanes frame:

| Size | H | Frame | Viewport | Log · REQUIRED | Card h | 3-lane content | Empty rows under the last lane (before run / after the paused run) | `lane_layout` 4 blocks / 6 blocks |
|---|---|---|---|---|---|---|---|---|
| 118x54 | 40 | 36 → 30 | 107 × 34 → 28 | 1 → 6 · 1 | 5 | 18 → 20 | **16 / 8** (wait_third_6: 7) | (21, 1) / (21, 0), lanes scroll 49 cells |
| 118x53 | 39 | 35 → 29 | 107 × 33 → 27 | 1 → 6 · 1 | 5 | 18 → 20 | **15 / 7** (wait_third_6: 6) | (21, 1) / (21, 0) |
| 220x60 | 46 | 42 → 36 | 191 × 40 → 34 | 1 → 6 · 1 | 5 | 18 → 20 | **22 / 14** | (42, 1) / (26, 5) |
| 220x59 | 45 | 41 → 35 | 191 × 39 → 33 | 1 → 6 · 1 | 5 | 18 → 20 | **21 / 13** | (42, 1) / (26, 5) |

The design's D24 readings hold: viewport 107 / 191; 4 blocks → card 21 spare 1 at 118, and 42 spare 1 at 220; 6 blocks → 21 at 118 (the lanes scroll) and 26 at 220.

**PC-10 — prediction 0 of 29; verified: 0 of 29 differ by Inc-6 content, with one timing artifact recorded.**
- Three full runs of `inc-3/snapshot_cells.py` on HEAD all give the same digest `8bc937d1…`, equal to Inc-5's `cells-head.txt`.
- On the Inc-6 tree each run differs from HEAD in 1, 3 and 1 cells (`cells-diff.txt`, `cells-diff-rerun.txt`, `cells-diff-settled.txt`). It is always one row: the status bar's A2L column reads `(none)` instead of `snap.a2l`, and in a different cell each run (a2l-compact-120x30; map/patch/diff; mac-compact-120x30).
- Isolated, the same cell reads `snap.a2l` 8 of 8 times on both trees (`context-race.txt`).
- The A2L column is not Inc-6 content, so the panel prediction holds. It is a load-timing race in the instrument's single-pause capture, seen only on the Inc-6 tree in long runs, possibly from the heavier Flow Execution compose. It is recorded as a risk (§5) for the Inc-7 regen, not as a pass.

| Cell | Predicted | Verified |
|---|---|---|
| the 29 cells (`workspace`, `a2l`, `mac`, `issues`, `map`, `patch`, `diff` × densities × sizes) | 0 changed — no cell renders `#screen_flow_execution`; `c` is `show=False`; `check_action` falls through for every other action; the session chip is silent at mount | 28–29 of 29 byte-identical per run. The 1–3 differing cells per run differ only in the status-bar A2L column (`(none)` vs `snap.a2l`), a different cell each run; isolated 8/8 equal → timing, not content |

**Neighbour screens (design item (11)).** The painted frames of the Check Editor, the Patch Editor and the Flow Builder (patch_chain loaded and run) at 118x54 and 220x60 are **identical** to `b514b07` (`frames-diff.txt` empty; both digests `675f95e1…`). The Builder frame is also the guard of the `FlowChip` swap: 0 rows change.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new and changed tests ran on a detached worktree of `b514b07` (digests in the transcript header equal HEAD's; `s19_app` imported from the worktree) |
| Transcript | `red.txt` — b97 Execution module **57 failed / 11 passed** (the 11 are Inc-2/Inc-5 nodes); chips_help Inc-6 selection **26 failed / 8 passed** (the 8 are pre-existing nodes the `-k` also matched); width Execution **41 failed / 1 passed**; Builder `space` + superseded **10 failed / 6 passed** |
| Instrument | pytest, one run per selection line; then `red-rerun.txt` (20 failed / 0 passed) and `red-rerun2.txt` (2 failed) after the PC-11 reorders |
| Where it ran | `scratchpad/head_b514b07` (git worktree, detached at `b514b07`) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 134 RED over the four selections (red.txt) |
| Verdict granularity | per node (`-rfE --tb=line`) |
| Arms that stayed GREEN | 1: `test_tc_b97_34_execution_card_width_holds_when_a_lane_starts_waiting` passed **vacuously** on HEAD (no cards, so `{}` == `{}`). A guard was added (`card columns painted`), and the node is now RED on HEAD at the guard and GREEN on Inc-6; M29 still kills it (`red-rerun3.txt`) |

| Field | Value |
|---|---|
| **RED counterfactual** | 134 RED on the unchanged `b514b07` source (`red.txt`); 20 re-checked after the PC-11 reorders (`red-rerun.txt`), 2 more (`red-rerun2.txt`) and the guarded TC-34 arm (`red-rerun3.txt`); 0 restores needed (no source edit) |

**PC-11 classification.**
- **RED at the named, main-observable clause:**
  - TC-21 `cable_glyph` ×8 and the 3-lane arm (`◇` absent, after the reorder);
  - TC-23 three-lane (`REQUIRED` absent);
  - TC-24 ×3 (`#fx_mode` 80 cells);
  - TC-25 ×2 (9 Spanish constants; the re-run line);
  - TC-26 (picker spans `bold`, `red`, `link=e`, `@click`, after the reorder);
  - TC-52 (no waiting-colour cell, after the reorder);
  - TC-53 ×5 (`[5, 13, 42]` blank rows, empty lane line Spanish-free but different) and the log cap (10 lines);
  - TC-55 ×2 error arms (the raise escaped);
  - TC-56 ((0, 0) header chips);
  - TC-63 ×2 (`max_scroll_x` 77, `┌` heads);
  - TC-64 ×8 (`c` unbound), and two-ext `(0, 2, True, False)`;
  - the layer-0 arms, the census and the CSS section;
  - AT-09 (Spanish log), AT-10 ×2 (`fx_save`, `fx_set_select`, `fx_load` outside), AT-20 (`c` unbound), AT-22 (mode 80);
  - chips TC-29 / 30 / 31 / 32 / 33 ×2 / 58 ×6 / 65 ×2, AT-12 ×5, AT-13, AT-14 ×4, AT-23 ×2;
  - width TC-35 ×10 (`fx_save` … overflow), TC-36 ×7, TC-37 ×6 (no category), TC-38 height ×6 (after the reorder), TC-59 ×3 (after the reorder);
  - the Builder `space` arm; the superseded nodes (their old literals).
- **Not RED at a clause (NoMatches / AttributeError), RED by mutation instead:**
  - TC-22 (M3);
  - TC-23 two-waiting / past-viewport ×4 / focus-in-lanes (M7, M4, M6);
  - TC-52 CRC (M13);
  - TC-55 in-flight and confirm arms (M17, M18);
  - TC-54 (M16);
  - AT-11 (M41);
  - width TC-34 ×3 (M28, M29, M30), TC-38 width ×5 (M33).

### Mutation verdicts

| Field | Value |
|---|---|
| **Mutation verdicts** | **45 mutants, 67 arms: 66 KILLED / 1 SURVIVED / 0 BAD**, every restore SHA-256-proven (`mutations.txt`, `mutate.py`). The sources after the battery equal the GREEN digests. Survivor **M31** (`overflow: hidden` on `#fx_panel`) on TC-59: at 80x24 / 100x40 / 220x40 the Execution panel holds no row below its fold — the lanes frame is the `1fr` hero and shrinks, and every other row is one terminal row — so hiding the panel's overflow hides nothing reachable. It is equivalent on this tree; TC-59 is a pin here. **Killed:** the waiting row ordered after the status rows; the cable read from the next block; the rebind pair displaced out of its card; the scroll step removed; Confirm auto-focused (×2); the scroll ignoring the focus; the attention class on every Confirm; a click that toggles; `space` unbound on `FlowChip` (×4, the Builder included); the re-run line in Spanish (×2); the chain name through markup; notices in the waiting colour; CRC in the waiting colour (×2); a blank row under the ribbon (×2) and between lanes; a primary Import; the Run disable dropped (×2); Confirm enabled during its re-run; either handler without its `except`; the error painter keeping the block confirmed; no dwell (×2); the dwell base from an earlier event (×2); `c` reaching only a focus inside the screen (the sealed D10, arrival arms); the `check_action` arm removed; the re-run forgetting the next wait; the re-run carrying the current block only (**the HIGH bounce-back**); card width per lane; the reserve only while waiting; the layout triggers removed (×2); the log at 20 cells and wrapping; cards fixed at 21 (×2); the lanes frame not `1fr` (×2); `⚠` back (×3); a help line without its effect; the session chip removed (×2); an unscoped shared rule; a `Button(` put back; the empty lanes line removed (×2); a refusal without its code (×2); a bound-NUL detail without its code; the REQUIRED line not cleared (×2); a head without its mark (×2); the log cap raised |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the new Inc-6 nodes | the unchanged `b514b07` source | 134 failed (`red.txt`) |
| `mutate.py` | 45 one-edit mutants | 66 RED arms (each anchor asserted once, the edit asserted applied) |
| `span_colours` / `hue_matches` (TC-52, TC-23) | notices / CRC painted in the waiting colour; the attention class on every Confirm (M12, M13, M7) | RED each time |
| `frames.py` | — | its frames come from Inc-5's `frames.py`, whose positive control (`.flow-name-strip margin-bottom: 0` → 4 rows) is recorded at Inc-5; M38 shows the CSS scope arm catching the same edit |
| `snapshot_cells.py` | the two trees | it reported cells differing (the A2L column), so it does see a status-pane change |
| `probe_two_ext.py` | HEAD `b514b07` | `AFTER_CONFIRM_1 (None, False, 'paused')` — the stuck lane (`red-rerun2.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 6 instruments, each shown failing on a known-bad input |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | Cables are read off the compositor strips (`cable_marks`; emitted content only for cables scrolled past the viewport, C-42). Colours are read off the strips (`span_colours`): Confirm vs Confirm vs Run, the waiting colour, the CRC title, the red pending lines. Head marks, pending lines, REQUIRED, log and legend rows are painted rows. The re-run's `external_confirmations` keys are read on a `run_chain_set` spy (`[(), (2,), (2, 3)]`). Reports are read from disk (`- **Mode:** parallel`); `fw_b.s19` ≠ `fw_app_patched.s19` on disk |

### Evidence files

All paths are under `.dev-flow/2026-10-19-batch-97/evidence/`.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED selection | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red-selection.txt` | `04d821688c5e39b5b8fe78100f504272fa117972121b4cf7d2faedb729f8e741` |
| RED (57+26+41+10 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red.txt` | `2dd1a2bc78533fb7a86e19bb9cd1b48b5d33846bdbe9c37d834750b843b819f1` |
| RED re-run (20 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red-rerun.txt` | `186eadfd46ef7bb099d174ba6b25f07745d027e3b3addddbf6b8c978e3b4d798` |
| RED re-run 2 (2 failed) + the HEAD probe | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red-rerun2.txt` | `90485268aa94e5a0cc5b059495d8edae5c4a55ab98f7213965ed9f6b0185f47f` |
| RED re-run 3 (the vacuous TC-34 arm guarded: GREEN Inc-6, RED HEAD, M29 RED) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red-rerun3.txt` | `173f5d4850277fab67968c67c802454aa103280ee306d721117a4ecc0a664b45` |
| Gate file list | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/gate-files.txt` | `3b34c53a1d226b0f383767482c0c9283852ec18cd101be6483192015d9b81fbb` |
| GREEN gate (1009 passed / 29 xf / 2 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/green.txt` | `a9f594ebacba8806788621a2302268e070ee167d5c3f35bb70ecff45200fd811` |
| Non-baseline re-runs (at073b 5/5 Inc-6, 2/5 fail HEAD; AT-B78-03 row) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/rerun-nonbaseline.txt` | `ea62dfbe8d84e4b8d81094bc288660a0e145cd6ae8a60d1f92b69601849f777b` |
| Mutations (66 / 1 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutations.txt` | `138d856ae110f1a532a755260ab20dda8072fe3b1e797d7fa4daff604f51689c` |
| Mutation script (first run; the fold appended M46–M52 to `mutate.py`, so these bytes are kept as) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutate.pre-fold.py` | `a90173ac6b7582908e598cff52a3ac4a806a4829e51e47c4948363948ea75960` |
| Two-step probe, Inc-6 tree (waits at 2, then `ok`) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/probe-two-ext.txt` | `e502537fb37c3ed629c0256a7d7f07a1825fd100453e8e6c9aa75fded52404ae` |
| Probe script | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/probe_two_ext.py` | `88e0d710688acaede66c4b3207dad9d17c2288c430abba964c8e40463e667d64` |
| Budget | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/budget.txt` | `a25f8ec6fcbca6d4790d2f26daf57b84c17d4122c495cd012cc757d9b536ea42` |
| Budget script | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/measure_budget.py` | `48bfb2729d8c6ce5ba2d1be9e05e78fbdb31f223137c7959c5799e8b11310957` |
| Frames HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames-b514b07.txt` | `675f95e16d8d0ef4915bbc7b0753946384658915dd3d5bd7276d735f38303ac7` |
| Frames Inc-6 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames-inc6.txt` | `675f95e16d8d0ef4915bbc7b0753946384658915dd3d5bd7276d735f38303ac7` |
| Frames diff (empty) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames-diff.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Frames script | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames.py` | `d7d22e01a35a6b66985b3c2a006c5190f3e2af35130e1a9165eb7308fb5af847` |
| Cells HEAD (×3 runs, same digest) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-head.txt` | `8bc937d17414f7f03b5525ee114c01c9fc58aa2c655b1e522c95314bfcdba9dd` |
| Cells Inc-6 run 1 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-inc6.txt` | `274404fd78801291a51c19770bf0e60afeef24a9b3527e7bc562e59ab31124a1` |
| Cells diff run 1 (1 cell, A2L column) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-diff.txt` | `582032439df57a2f31839024610a012abb397753ff2617c9d903e8341ca0c1af` |
| Cells Inc-6 run 2 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-inc6-rerun.txt` | `1596d3311166b1f6906b0e05f462a95cfb3520204e14f8f10df8a06a1e9943cd` |
| Cells diff run 2 (3 cells, A2L column) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-diff-rerun.txt` | `9c874d8b6af5c327e2d02616a605e3df62855339d9b0ef44945e90c0f432b515` |
| Cells HEAD run 2 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-head-rerun.txt` | `8bc937d17414f7f03b5525ee114c01c9fc58aa2c655b1e522c95314bfcdba9dd` |
| Cells settled, HEAD | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-head-settled.txt` | `8bc937d17414f7f03b5525ee114c01c9fc58aa2c655b1e522c95314bfcdba9dd` |
| Cells settled, Inc-6 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-inc6-settled.txt` | `6202ee56eef1d16ced1335d5abf518d1920298c7421e033304e9b680e078f058` |
| Cells diff settled (1 cell, A2L column) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-diff-settled.txt` | `013e422d892f2f348c057732d32d0ca274f40d8e437b51ce907a3fdeb14cb060` |
| Settled instrument | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/snapshot_cells_settled.py` | `7be6ac8b678df427396d3e885b143741ca3446b8e0dc52e5c188bf34272eeb68` |
| A2L-column race, isolated 8/8 both trees | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/context-race.txt` | `5ef60a7e0ce4756763f8cb09d6558e44baa05f607ac7977a7960c96a3ae5be56` |
| Race probe | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/context_race_probe.py` | `ac289752bc45d925b45326caeee6d53e4fe034cf2866a9e9e256ad09cf873765` |
| Pre-Inc-6 probe: second confirm (service) | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/probe-second-confirm.txt` | `2723a3c6f34fa5b5b47ba1bd8e3f208d3de9083dfe1862b14fdf8966c8313397` |
| Script | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/probe_second_confirm.py` | `04763470bf18db34fc947f1a56d268b12af090c4de387b95283f951acbd75dc1` |
| Pre-Inc-6 probe: `c` scope | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/c-scope-probe.txt` | `2ae292db27bd66908f1d149c166c59d3b8356107ce1c261f068a034c2b25011f` |
| Script | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/c_scope_probe.py` | `7f0303ff84e64e9cd64898fe6dc619d8b630a1bb36bca6f1db9385ec7df1db72` |
| Pre-Inc-6 probe: fx regions | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/fx-regions.txt` | `28a869d051297d9d11bd278437d2e22b2f3ef77a171d38ea9336e232ff50a0ff` |
| Script | `.dev-flow/2026-10-19-batch-97/evidence/pc-before-inc6-2026-10-22/fx_regions.py` | `bfe0499b075e1b27e8484b30423c70e08e908aab0db04d24a22dcae7be2f40de` |
| WT idle 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-idle.png` | `b80f125639ec4111b5787fa67f63f2fd072dc274a46089da431f64b2017f53b4` |
| WT idle 118x53 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-idle.118x53.png` | `6eb15cffaf8d42ffa677bdcd9dac94759a8e56666281096988e4e6ecc54847c3` |
| WT idle 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-idle.220.png` | `dbd75bcc95937cde7e7fc80e7620ee21ef1bdad34a69432f44c93464ea2dd1ab` |
| WT paused 118x53 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-paused.118x53.png` | `7f1c0819729bdda1368ff00cd132d8e4a826a3895d0aff5615b2c5a09207c7e2` |
| WT paused 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-paused.220.png` | `cc17b6f7dcbbee42c53037d026f2172499bff2a3285054ced8a7bc86a7786400` |
| Full suite (12 failed / 3542 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/suite-full.txt` | `56339b6517afb75baef6f8c61727a365dfb57c2a76b8ff1ca1e405fed5ecdf83` |
| Post-suite GREEN (262 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/green-post-suite.txt` | `35a9a8fd97f2cc1ea0fecd6c9dd932feef1f6af100efd77c849c531ab082c8a7` |
| F6 mutation (RED / restored GREEN) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutation-f6.txt` | `1e43ca653b00c4305170de6d82ead3dd3cb3031656b421d03290ceaeaa9ed9b6` |
| Suite non-baseline re-run (5/5 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/rerun-nonbaseline-suite.txt` | `7520b1702dabe15347f34f3f9f2855e8285d5b5aaae971ab828d2c7ce838e2f7` |

| Field | Value |
|---|---|
| **Evidence files** | 40 first-run artifacts and 13 gate-fold artifacts above, each with its SHA-256. Four first-run PNGs (paused 118x54; two-step done at 3 sizes) were overwritten by the fold's re-captures. Their first-run digests are not kept, and only the fold rows cite them |

**Gate-fold evidence** (repo-relative, SHA-256):

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| Fold RED (6 failed / 2 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/red-fold.txt` | `f6494b3830f91176dd12ccf15aba770647c71491522128901ba532425901c326` |
| Fold GREEN (1014 passed / 29 xf / 2 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/green-fold.txt` | `8f3822cee9eeba32d5b4a290c16c910a351a0b96eae8311bfdf0d5bd5b01b54d` |
| AT-B94-17 1/5 fold, 1/5 pre-fold | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/rerun-nonbaseline-fold.txt` | `d7007b613c2058101cb00fa927813842654f3122d64f8e66e7c3ba2d461ca652` |
| Fold mutations (13 / 1 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutations-fold.txt` | `270865d5afd997d84308007d1173d55eed8b78527fc0486441bb4bcdb28b5b34` |
| Mutation script (after the fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/mutate.py` | `2810607a4367bfbd89ea5d2b6b977de0252738e1a806c0ec2313d989eef8eb41` |
| Frames fold (= HEAD) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames-fold.txt` | `675f95e16d8d0ef4915bbc7b0753946384658915dd3d5bd7276d735f38303ac7` |
| Frames diff fold (empty) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/frames-diff-fold.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Cells fold | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-fold.txt` | `f0f5f246732bb703947f8d6449c206cef74623feef38749f011ed8a3a86182da` |
| Cells diff fold (1 cell, A2L column) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/cells-diff-fold.txt` | `0b9abcfa6ed8656960123034b0300d29b0bafa15993d9db1b40e071cd2db1748` |
| WT two-step lane done 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-two-wait-done.png` | `cece1732a15bc503389350a6016048f1060dae368e624ab6714153fa661104b4` |
| WT two-step lane done 118x53 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-two-wait-done.118x53.png` | `a9ea62f6f0135ced249dcce556a781537d9db8aefc4060b4b3fbffff1c9b08f6` |
| WT two-step lane done 220x60 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-two-wait-done.220.png` | `482ab9759834fcef6ed0a4b160d0e6ed848914009568312593630267c85159c9` |
| WT paused 118x54 (fold) | `.dev-flow/2026-10-19-batch-97/evidence/inc-6/png/impl.flow-execution-paused.png` | `29df53d603c8631552ff68113965d8f5fde3890dc7bbf87ee8d5ae57b8ab77d0` |

First-run source digests: `flow_screens.py a2afd60a…`, `app.py 6f32fbae…`, `styles.tcss f91bd869…`, `window_help.py 303be19e…`. These are the digests GREEN ran on, and the digests the mutation battery restored to.

**"Running" capture: n/a.** A set run is synchronous, so the terminal paints no frame while it is in flight. The disabled Run / Confirm state is pinned headless (TC-B97-55 reads `disabled` inside the run).

**WT glyph check** (captures, legend, cables, heads, pending, log). `▓ ░ ✗ ◇ □ ▪ ◉ ▣ ✓ » ▼ ⏚ ─ ▶ ·` each paint one cell, with no glyph glued to its neighbour; the legend's spacing is even at 118 and at 220. `⊕` (CRC) and `≡` do not appear in these captures; their width rests on the Inc-5 ruler.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes, in eight places: 0 `Button(` constructors in `flow_screens.py`; 0 Spanish panel constants; 0 blank rows outside the lanes frame / between lanes; 0 waiting-colour cells outside a waiting-human element; 0 accents within 20° of the waiting hue; 0 h-overflowing descendants; 0 unscoped selectors in the section; 0 differing neighbour-frame rows |
| What made the search wide enough | AST over the whole module (calls by name); the `ClassDef` census with the `9c7beaf` reach guard; full-width painted panel rows; strip runs over the whole panel and the three other screens; every displayed descendant (guard ≥ 10); the CSS section parsed into selectors plus the HEAD sheet as a byte-equal prefix |
| Positive control | M39 (a `Button(` back), M10, M14 / M15, M12, M38 — each RED |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a: tests reaching Execution ids / symbols (`git grep` of the design's B1 pattern plus `fx_`, `FlowChip`, `KindChip`, `ribbon_text`, `SHIPPED_WINDOW_KEYS`, the palette) | 43 files; the UI ones are in the gate set (34). Red before the rewrites: 12 nodes in 5 modules (b94 ×8, b96 TC-1804, TC-707, TC-1802, TC-081.4). Each was rewritten by named supersession (§2). Added to the gate after the census: `test_tui_commandbar.py` (TC-007 green; AT-B78-03 baseline), `test_discoverability.py`, `test_segment_split_window.py`, `test_universal_paste.py`, `test_flow_a2b_b94.py` |
| B1b: removed symbols | `_FX_LANE_W`, `_FX_BAR_*`, `_fx_progress_bar`, `_lane_paint`, `#fx_lane_<i>_paint`, `_MODE_OPTIONS`: 0 references left in `s19_app/` or `tests/` |
| B1c: hex sweep | no new hex literal in Python; the TCSS reuses tokens and the DGRAY literal already claimed |
| B1d: TC-081.4 | one `Binding(` line in the `app.py` diff (`confirm_attention`), sanctioned by name |
| B2 · B3 | no file moved; no golden captures Flow Execution |
| A3 | I-7 landed as amended 2026-10-22 (no further change); message types unchanged (`RunRequested`, `ExternalStepConfirmed`); I-1 consumed unchanged; I-11's first arm; `ribbon_text` gained a keyword with the Builder default (no Builder frame change) |

| Field | Value |
|---|---|
| **Reverse census** | B1a 43 files, 12 red nodes rewritten by name; B1b–B1d clean; B2–B3 none; A3 none |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | `FlowExecutionPanel` Spanish: 9 frozen values (`ES_48_9C7BEAF`), enumerated by the AST census with the `9c7beaf` reach guard; **9 gone**, 0 left (TC-25). Spanish test pins: TC-1804 (5 asserts). `▶` start-mark pins: 3 nodes (AT-B94-22, -23, TC-B94-29). `✓` terminal-mark pins: 4 nodes. `#fx_mode`-as-`Select` reads: 2 nodes |

### Signed-balance test ledger

`post = base − 0 deleted + 131 added`: +58 (`test_b97_flow_execution.py`), +30 (`test_b97_chips_help.py`), +42 (`test_b97_width.py`), +1 (`test_b97_flow_builder.py`). Rewritten in place: 8 (b94), 1 (b96), 2 help modules, 1 TC-081.4. D18: no new scanned module, so the registry stays 197 (`test_id_registry.py` is in the gate set, green).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · OK to advance on re-read of the gate fold (2026-10-22; 0 HIGH): F1 verified — `_rearm_attention(restart=True)` is the only writer of `_attention`/`_attention_block` (flow_screens.py:3419, :3553-3579); F3, F4, F5 verified on the diff (15 dwell polls; modal positive control `== [(1, 2)]`; in-flight line :3660); F2 stays owed to Inc-7 (§6 item 10); the M22 survivor on flash2_chain is explained (the in-flight guard refuses first; the two-wait burst arm still kills it, mutations-fold.txt:12); new F6 MEDIUM (a restart with no lane waiting returned early and left the REQUIRED line, `fx-attention` and the scroll stale) and F7 LOW (docstring scope) — both applied by the orchestrator, see §1b. `ux-reviewer` · approve on re-read (2026-10-22): M1 lanes return to x 0 when no lane waits (`_scroll_lanes_home`; two-wait-done capture reads from `▓ two_step`, LOAD card whole); M2 `Confirmed <chain> — re-running from block i/n.` / `<chain> failed at block i/n — <reason>; Run re-runs the set.` verbatim in code and pinned by tests, not painted in any WT capture (inspected, not exercised); supersedes the PC-2 I-9 phrase — the operator kept the new wording when asked at the gate (LED-…97.34); L1 legend `▓ done` / `░ not run / skipped`; L2 head time on the set clock; L3 dimmed scrollbar seen in capture; M3 head cut accepted by the operator (LED-…97.33, next-batch prototype in backlog); evaluation with users not performed — one-person team |

## 5 · Risks

- **The waiting lane's head and pending lines scroll out of view** when its card lies past the viewport. This is accepted for now (LED-…97.33), with a next-batch prototype. After the wait ends, the lanes return to `x 0` (gate fold M1).
- **PC-10 timing artifact.** The status-bar A2L column sometimes paints `(none)` in a long 29-cell run on the Inc-6 tree (1–3 cells per run, a different cell each time; never on HEAD in 3 runs; 8/8 fine isolated). The Inc-7 regen could capture it. The cells are inside the batch-94 `xfail(strict=False)` envelope.
- **Focus is held on a disabled button during a run** (D14 implementation note). Textual's `disabled` watcher is bypassed with `set_reactive` + `update_node_styles`, a public API used deliberately. A Textual bump that changes key dispatch to disabled focused widgets must re-run TC-B97-55.
- **The harness posts `RunRequested` directly**, so the WT captures do not go through Run's disable. It is the same code path otherwise.
- **The attention dwell restarts on every new set run** (`render_run` → `_rearm_attention(restart=True)`, gate fold F1). This is stricter than I-7's "nothing changes" for an unchanged `(lane, block)`, and chosen so that a `c` typed during a run cannot confirm the instant the run ends. See §6 item 4.
- **Card clipping is by `len`, not cell width** (as in Inc-5): a CJK or emoji ref could misalign a card border.
- **Pre-existing flake** `test_at073b` (2/5 on clean HEAD).

## 6 · Pending items / spec deviations

1. **Decided at the gate (LED-…97.33).** (b) is folded: the lanes return to `scroll_x 0` when no lane waits. The head / `▪` cut while a lane waits past the viewport is **accepted for now**, with a next-batch prototype round in the backlog (operator-requested). The earlier text of this item asked when the lanes stay scrolled after a wait:
   - (a) keep as is;
   - (b) scroll back to `scroll_x 0` when no lane waits (a few lines in `_rearm_attention`);
   - (c) pin the lane heads and pending lines outside the horizontal scroll (a re-cut of D24's one-scroller tree).
   The backlog P3 entry for (b) is closed.
2. **Deviation — A.5 fixtures (LED-…97.32).** `err_chain` errs on a missing change doc. On this tree an entry at `0x00020000` reports `ok`, `applied 0 entries` — **a silent no-op patch, routed to the backlog as P2**. TC-B97-23's both-axes guard adds a five-lane `deep` set, because the cards are 5 rows and `wait_third_6` fits vertically.
3. **Deviation — design §3 card height.** The cards measure 5 rows, not the illustrative 7. The lanes frame takes the difference (`budget.txt`), and the §3 table should be restated with these readings.
4. **Interpretation — the dwell after a new set run.** `render_run` calls `_rearm_attention(restart=True)` (gate fold F1; it used to reset the two fields itself), so the dwell restarts after every run, even when the same lane waits at the same block. With the in-flight guard in `_post_confirm` and its own status line (F5), a `c` typed during a run confirms nothing.
5. **Interpretation — the waiting Confirm counts as filled through `variant="primary"`** (the §1.3 definition), not `fill-accent`, so `fill-accent` keeps one meaning (Run).
6. **Not captured: "running".** The run is synchronous (§4).
7. **The mode toggle's active word** paints accent colour + bold but no selection background (Button's label paint drops the span background). Routed to the backlog as P3.
8. Full suite: run by the orchestrator (§1c): 12 failed, 2 real (fixed in §1c), 5 non-baseline passed isolated, 5 baseline. Not re-run after §1c.
9. The HEAD worktree `scratchpad/head_b514b07` (`git worktree`) is removed after this packet. Its outputs are the RED transcripts above.
10. **Owed to Inc-7, before the regen (code-reviewer F2, the PC-10 harness race).** `tests/test_tui_snapshot.py`'s `_build_loaded_triple` never calls `update_project_labels()`, so the status bar's A2L column depends on timing in a long run (`(none)` vs `snap.a2l`). The fix: `run_before` calls `app.update_project_labels()`, or polls for `snap.a2l` before the capture. It is not fixed here.

## 7 · Suggested next task

Inc-8 (two-row key bar): the `c Confirm` token for Flow Execution (I-10 row, no owner), `check_action`'s D28 arms in the method Inc-6 created, and deleting the hand-typed `c — Confirm` help line for the generated keys block. Before it: the operator's answers to §6 items 1–3.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | 4 / 4 (§2); `open_folder_chip.py` untouched |
| 2 | Tests written in this same increment | all | ✓ | 131 new nodes + 12 rewritten by name; fold: +5 nodes, 2 rewritten (I-9 line, F4), 11 F3 polls |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | `cable_glyph`, `lane_layout`, `fx_run_error_line`, censuses, CSS scope |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 134; `red-rerun.txt` 20; `red-rerun2.txt` 2 + the HEAD probe; `red-rerun3.txt` 1; fold `red-fold.txt` 6 |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4 reverse census |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b, re-read of the gate fold, 0 HIGH |
| 7 | No file from another lane touched | all | ✓ | one lane |
| 8 | Frozen interfaces untouched | all | ✓ | I-7 as amended 2026-10-22; message types unchanged; I-1 unchanged; I-11 first arm as designed |
| 9 | Coverage claims verified on disk | all | ✓ | `green.txt`, `green-fold.txt` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 67 arms: 66 killed / 1 survived (M31, explained) / 0 bad; fold 14 arms: 13 / 1 (M22 on flash2, explained) / 0 |
| 12 | Instrument RED-proof | all | ✓ | 6 instruments |
| 13 | Correction population | all | ✓ | 9 + 5 + 3 + 4 + 2 |
| 14 | Emitted-form assertion | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | `code-reviewer`, `ux-reviewer` (Inc-6 gate, 2026-10-22) |
| 16 | Evidence files with digests | all | ✓ | §4, 40 + 13 fold artifacts |
