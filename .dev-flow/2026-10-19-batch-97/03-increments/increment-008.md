# Increment 008 — HLR-150 · `Two-row key bar on every window`

> **Field guide:** `templates/guides/increment-template.md`. Template: `templates/increment-template.md` (level `full`).
> **Where this lives:** `.dev-flow/2026-10-19-batch-97/03-increments/increment-008.md` (repo, not synced).

| Field | Value |
|---|---|
| Batch | `2026-10-19-batch-97` |
| Increment | `008` (executed after Inc-6 and before Inc-7, D29) |
| Lane (if the batch forked) | `none — one lane (design-proposal §8)` |
| Requirement(s) | `HLR-150 / LLR-150.1–150.7` · the key-binding half of `LLR-148.6` (the generated keys block replaces the hand-typed key lines) · ledger `LED-2026-10-19-batch-97.9`, `.10`, `.36` (new) |
| Acceptance | AT-B97-25, AT-B97-26 · TC-B97-66..72 · layer 0: `pack_key_row` arms of TC-B97-70 |
| Agent | `software-dev` (spawned sub-agent) |
| Date | `2026-10-22` |
| Design refs | `PDR-2026-10-19-batch-97#D26`, `#D27`, `#D28`, `#D29`; I-10, I-11 (amended 2026-10-22, PC-13); PC-22, PC-23, PC-24, PC-25, PC-26; operator verdict on the bar: variant **A** (`evidence/operator-keybar-verdict-2026-10-20.json`); key-bar QA H-1 (a click runs the binding's action) |

---

## 1 · What changed

Every window now ends in a two-row key bar instead of Textual's one-row `Footer`.
- **Row 1** shows the global keys on every window, whatever holds the focus, and always includes `? Help`.
- **Row 2** shows the window's name in the title colours, then the keys that act on that window, then its go keys.
- A key that cannot act right now is dimmed.
- A row never cuts a token: when it is too long, it ends with `? more`.
- A click on a token runs that binding's action, and nothing is typed into the focused widget.
- `+ - , .` no longer page a hidden view on windows that do not handle them.

Each window loses exactly one row (42 → 41 at 118x54, 48 → 47 at 220x60). The bodies are unchanged at the same body height (§4, neighbour frames).

- **`window_help.py` — the window-key table (I-10, D27).** `KeyEntry(key, when, owner)`, `GLOBAL_KEYS`, `WINDOW_KEYS` / `WINDOW_GO_KEYS` over the 13 windows, `HELP_KEY_WINDOW`.
  - The table stores keys only. Every label is the description of the binding the key resolves to, read when the bar mounts.
  - An unbound key raises `KeyError`, and an empty description raises `ValueError`.
  - The only label literals are `more` and `palette` (pinned by an AST test).
  - The five rendered rows are the frozen I-10 rows. The eight other rows are derived from each action's own guard (§*For the operator*).
- **`window_help.py` — the key bar (I-11, D26).** `KeyBar(Vertical)` `#key_bar` holds two `KeyRow(Static)` rows, `#key_bar_global` and `#key_bar_window`.
  - Each row is packed on every paint by the pure `pack_key_row`. It reserves the mandatory parts (`? Help`; the tag and the `? more` tail), then keeps the longest display-order prefix of the rest. It never skips greedily and never crops.
  - Colours come from the component classes `key-bar--key` / `--description` / `--tag` / `--separator`, read with `get_component_rich_style`. There is no hex in Python.
  - A click maps `event.x` to a hit range and runs the token's action in its own namespace: `app.run_action(action)` for an app key (which honours `check_action`), or `owner_widget.run_action(action)` for an owned key (`space` on `#check_param_table`; the Diff panel's and Split / Join / Export's own keys). It never uses `simulate_key`.
  - A click on a dimmed token rings the bell. A click on the tag, a separator or the padding runs nothing.
  - The bar repaints on `Screen.bindings_updated_signal`. There is no timer.
- **`window_help.py` — help.** The help modal shows `#window_help_keys` (generated `key — label` lines) beneath the steps for every section that maps to a window with keys. `section_body_text` is still the steps alone, so TC-707 is unchanged. The hand-typed key lines the block now carries are deleted: Patch `ctrl+z —` / `ctrl+y —`, Check Editor `space —`, Flow Execution `c — Confirm`.
- **`app.py`.**
  - `KeyBar(id="key_bar")` replaces `Footer()`.
  - `Binding("period", "hex_page_next", "Hex+", key_display=".")` (D28).
  - `check_action` gains D28's arms in the method Inc-6 created: `page_next_context` / `page_prev_context` run only on A2L / MAC, and `hex_page_prev` / `hex_page_next` only on Workspace.
  - `key_condition(when)` evaluates `has_image` / `patch_history` / `has_variants`.
  - **PC-23:** `refresh_bindings()` at the end of `action_show_screen` and `action_open_split_join_export`, in `watch_current_file`, and in `_patch_document_view` (the one builder passed at all four `refresh_entries` sites). `_variant_set` became a property whose setter refreshes, which covers its four writers.
- **`styles.tcss`.** One appended section, `/* batch-97 key bar */`. Every selector is rooted at `#key_bar`. It uses `$footer-*`, `$accent-calm` and `$bg-base` only. The shipped sheet is a byte-equal prefix.
- **`screens_directionb.py` (gate fold, the fourth SOURCE file).** `_DIFF_MIN_H` 28 → 29. The bar's extra chrome row made 120x28 declare the Diff deliverable while it painted 0 hex rows (LLR-125.2, TC-B78-54 RED). Re-measured: 28 → 0, 29 → 1, 30 → 1. One constant and its comment.
- **`docs/architecture.md` §11.** The I-10 row is added (as built), and the I-11 row is amended to the as-built surface.
- **Harness (untracked, not source).** `prototypes/keybar/run_keybar.py` and `capture.ps1` are re-pointed at the real tree (13 `win-<window>` scenarios). The round's originals are kept as `*.prototype-round.*`. `capture.ps1` now calls `SetProcessDPIAware()`: on this display a DPI-unaware `PrintWindow` cropped the window to its top-left two thirds.

### For the operator

**What you will see** (`evidence/inc-8/png/`, real Windows Terminal, truecolor, 118x54 unless noted). Row 1 is identical on every window: `^k Palette  ^d Density  ^l Load file  ^s Save project  x Operations  ? Help  q Quit  ^p palette` (gate fold, LED-…97.38). **Since the gate fold, an owned token (Check Editor `space`, the Diff panel's keys, Split / Join / Export's keys) is dimmed while the focus is outside its window or its owner refuses the action, and every dimmed token is one grey colour, key and description alike.**

| Window | Row 2 as painted at 118x54 | Source of each entry (`file:line`) | Capture |
|---|---|---|---|
| Workspace | `Workspace  / Find  g Go-to  , Hex-  . Hex+  k Legend  p Load project  o Open workarea  r Refresh workarea  ? more` (`U Unload all` behind `? more`; shown at 220) | frozen I-10 row (prototype round) — `window_help.py:756` | `impl.keybar.workspace.png`, `impl.keybar.workspace.220.png` |
| A2L Explorer | `A2L Explorer  / Find  g Go-to  + Page+  - Page-  d Describe tag  k Legend` | `/` `g`: `app.py:6850` (`_FIND_GOTO_INPUTS["a2l"]`) · `+` `-`: `app.py:7658`, `:7685` (`page_*_context` → A2L pages) · `d`: `app.py:6774` (`a2l_describe_tag` guard) · `k`: `app.py:6886` (legend section `A2L`) | `impl.keybar.a2l.png` |
| MAC View | `MAC View  / Find  g Go-to  + Page+  - Page-  k Legend` | `app.py:6851`, `:7660`, `:7687`, `:6887` | `impl.keybar.mac.png` |
| Memory Map | `Memory Map  k Legend` (gate fold: at 120x30 the region list shows one row and scrolls, `map.120x30`) | `app.py:6889` (`"map": ()` + `view_key="map"` → the entropy band key) | `impl.keybar.map.png` |
| Issues Report | `Issues Report  pgdn Page+  pgup Page-  k Legend` | `app.py:7717`, `:7748` (`page_down/up_context` → the Issues panel), `:6888` | `impl.keybar.issues.png` |
| Patch Editor | `Patch Editor  ^z Undo  ^y Redo  v Select variant  k Legend  · go = Check Editor  9 Checks` (`^z ^y` dimmed: the file-backed `calib_hotfix.json`; `v` dimmed: no variant set) | frozen I-10 row — `window_help.py:772` | `impl.keybar.patch.png`, `impl.keybar.patch.220.png` |
| Check Editor | `Check Editor  space Include  · go 6 Patch Editor  9 Checks` — **visible delta vs the round:** `space Include` (the key Inc-3 created) | frozen I-10 row — `window_help.py:776`; owner `#check_param_table` (`screens_directionb.py:6905`) | `impl.keybar.check_editor.png` |
| A2B Diff | `A2B Diff  k Legend  f Run list  esc Close the run list  ] Window page +  [ Window page -` | `k`: `app.py:6891` · the panel's own keys: `screens_directionb.py:7905-7908` (owner `#ab_diff_panel`) | `impl.keybar.diff.png` |
| Flow Builder | `Flow Builder  go ] Flow Execution  6 Patch Editor  = Check Editor` | frozen I-10 row — `window_help.py:784` | `impl.keybar.flow.png` |
| Flow Execution | `Flow Execution  c Confirm  · go 8 Flow Builder  t View reports` — **visible delta vs the round:** `c Confirm` (the key Inc-6 created; an app key, no owner) | frozen I-10 row — `window_help.py:785` | `impl.keybar.flow_execution.png`, `impl.keybar.flow_execution.220.png` |
| Checks | `Checks  k Legend` | `app.py:6892` | `impl.keybar.checks.png` |
| CRC Designer | `CRC Designer` (tag alone — the empty-window arm of AT-B97-25) | no guard admits it: `app.py:6860` (`"crc_designer": None`, no find / go-to input); not in `_SCREEN_LEGEND_SECTIONS` (the legend falls back to the full table, the same rule that leaves `k` off Check / Flow / Flow Execution) | `impl.keybar.crc_designer.png` |
| Split / Join / Export | `Split / Join / Export  space Tick  a All  n None  t Source  m Mode  g Gap  f Format  p Pad  d Dest  ? more` (`e Export`, `esc Close` behind `? more`; shown at 220) | `segment_split_view.py:1033-1043` (`SplitJoinWindow.BINDINGS`, owner `#screen_split_join`) | `impl.keybar.split_join.png`, `impl.keybar.split_join.220.png` |

**Derivation rule used for the eight derived rows (PC-26).** A key belongs to window *w* when its action's own guard names *w* (or the panel that owns the binding sits in *w*) and the key is not global. The rows have no go keys. The test `DERIVED_GUARDS` holds every `file:line` above and asserts that each guard still sits there.
- **Left out by the rule:**
  - `j` Dump A2L JSON (no window guard: `app.py:6731` `if not self.current_a2l_data`);
  - `b` Before/After report, and `t` / `p` / `o` / `r` / `U` / `l` / `s` (app-wide; on Workspace and Flow Execution only through the frozen rows);
  - `v` (no window guard; on Patch only through its frozen row);
  - PgDn / PgUp on A2L / MAC: they reach `+` / `-`'s action only through the Issues fallback (`app.py:7719`), so they are synonyms;
  - the Split / Join cursor keys `up down k j` and `_SegTable`'s keys (arrow synonyms; `_SegTable`'s bindings have no description);
  - `k` on CRC Designer and Split / Join (full-table legend).

**Label and key collisions — your decision; nothing was relabelled.**

1. **The two Saves (and Loads).** Row 1's `^s Save` is `save_project`: it saves the project folder. On the same windows, buttons a user can confuse with it:
   - **Patch Editor** `Save` (writes the change-set file) and `Write file` (writes the patched image);
   - **Flow Builder** `Save…` (the flow);
   - **Flow Execution** `Save Set` (the chain-set);
   - **Check Editor** `Write .chk.json`;
   - **CRC Designer** `Save` (a template).

   The same pattern holds for `^l Load` (`load_file`, the S19/HEX/A2L/MAC picker) against Patch `Load`, Flow Builder `Load…`, Flow Execution `Load Set`, CRC Designer `Load`, and the Workspace row's `p Load project`. Options:
   - **(a)** Give `^s` and `^l` the descriptions their sibling bindings already carry, `Save project` (`s`) and `Load file` (`l`). No new label is invented. Row 1 grows 84 → 97 cells (fits 118; at 80x24 `q Quit` would drop behind `^p palette`, i.e. 6 tokens instead of 7). This is a `Binding(` edit in `app.py` (TC-081.4 marker) plus the LLR-150.2 token list.
   - **(b)** Keep `^s Save` / `^l Load` and rename the window buttons (`Save change-set`, `Save flow`…). That touches four screens' layouts and their pinned labels (Inc-4..6 tests).
   - **(c)** Keep everything, and add one line to each affected help: "`^s` saves the project; this window's Save writes …".

   **Recommendation: (a).** One place, existing words, and every window is disambiguated at once.
2. **The same word for two key pairs: `Page+` / `Page-`.** `+ -` page the A2L / MAC tables, while `pgdn pgup` page the Issues groups (and also page A2L / MAC, not painted there). Options:
   - **(a)** keep;
   - **(b)** also paint `pgdn pgup` on A2L / MAC (a faithful reading of the guard, 2 more tokens each);
   - **(c)** drop `+ -` from A2L / MAC in favour of `pgdn pgup`.

   **Recommendation: (a)** — different windows, one meaning each.
3. **A key whose meaning depends on the focus (shadowing).** While the focus is inside Split / Join / Export, `t` is Source, `g` Gap, `p` Pad and `d` Dest. Outside it they are the app's `t` View reports, `g` Go-to, `p` Load project and `d` Describe tag. On the Diff panel, `]` is Window page + inside the panel and the Flow Execution rail key outside it. Row 2 always paints the window's meaning, and a **click** is always right (it runs in the owner's namespace). A **keypress** with the focus elsewhere (for example, after a click on the rail) runs the app's meaning. Options:
   - **(a)** keep (each window focuses its own table on entry);
   - **(b)** dim the owned tokens while the focus is outside their window (a new `when`, which changes the frozen I-10 condition set);
   - **(c)** rebind the window keys to unshadowed letters (changes the batch-95 / batch-78 contracts).

   **Recommendation: (a).**
4. **Split / Join / Export paints `EXPORT ^E` in its own panel, but the binding is plain `e`.** The bar says `e Export` (at 220; behind `? more` at 118). This was there before Inc-8. Options:
   - **(a)** make the panel say `e` (`segment_split_view.py`, outside Inc-8's files);
   - **(b)** also bind `ctrl+e`;
   - **(c)** leave it.

   **Recommendation: (a)**, routed to Inc-7 or the backlog.
5. **The Memory Map help still claims `+ -` / `, .` page memory there, and `g` jumps.** No guard admits any of them on Map, and D28 now disables `+ - , .` there. The help was stale before Inc-8. Options:
   - **(a)** rewrite the two Map help steps (`window_help.py`, Inc-7 may fix there);
   - **(b)** leave it.

   **Recommendation: (a).**
6. **`j` on A2L.** The A2L help names `j`, but the rule leaves it out (no window guard). Options:
   - **(a)** keep the rule;
   - **(b)** add `j Dump A2L JSON` to the A2L row as an editorial exception (a table edit).

   **Recommendation: (a)**, unless you want it.

7. **Memory Map at 120x30 loses its second region row, and it cannot be reached** (AT-074 RED; GREEN on 9793fcd). The bar's row comes out of `#map_body`. `.map-region-scroll` keeps its 2-row floor (`min-height: 2`, batch-93 HLR-126), so its second row lies under `#map_grid`'s bottom padding row and the list reports nothing to scroll. Options:
   - **(a)** `.map-region-scroll { min-height: 1 }` in `styles.tcss`: the list shows 1 row at 120x30 and scrolls to the second (AT-074 green). This breaks batch-93's "2-row floor" note;
   - **(b)** give the Map its row back inside the pane (drop `#map_grid`'s blank bottom row): a Map layout change on every size;
   - **(c)** accept it for 120x30 and re-pin AT-074 at a taller size.

   **Recommendation: (a)** — the smallest change that keeps every region reachable. Not done here, because it decides a batch-93 budget.
8. **Flow Builder at 118x53 with the bar** (body 38 rows, below the PC-5 budget's lowest column of 39) scrolls its run result by one row after a run (TC-B97-38 `after_run`, 118x53 arm). It holds at 118x54. The 118x53 arms were PC-24's stand-in for "118x54 with the bar". Options:
   - **(a)** retire the 118x53 hedge parameters now that the bar is real (named supersession; Inc-7 sweeps the real layout);
   - **(b)** keep them as a one-row-short guard and give the Builder its row (a Flow Builder layout change, outside Inc-8's files);
   - **(c)** keep them and accept the scroll at 118x53.

   **Recommendation: (a).**
9. **Patch Editor at 118x54:** with a 64-byte entry, the entry chips sit **2** rows below the inspector's fold at scroll 0 (it was 1). That is the reading you accepted at the Inc-4 gate for 118x53, which has the same body height (PC-24's purpose). TC-B97-40 is re-pinned to 2 / 3 (118x53). Shown for confirmation, no decision expected.
10. **The Diff screen's floor moved from 28 to 29 rows** (the fold above), and at 120x30 the Diff shows 1 hex row where R-1 accepted 2.

**Also for you (finding, not new in Inc-8):** the Patch Editor, Flow Execution, Check Editor and Flow Builder help modals are taller than the terminal and do not scroll. At 118x54 the Patch dialog is 105 rows, with its top at row −11. Their keys block (and their last steps) cannot be read. This was already true of the hand-typed key lines on 9793fcd. Owed to Inc-7 (`window_help.py` is in its fix set) or the backlog (§6 item 3).

### 1b · Gate fold (2026-10-23)

The reviews came in at the Inc-8 gate: `code-reviewer` was BLOCK-UNTIL F1 (HIGH: AT-074, Memory Map at 120x30), and `ux-reviewer` approved with conditions. The orchestrator relayed the operator's decisions, asked at the Inc-8 gate on 2026-10-23. The fold stays inside the same **four SOURCE files**. Records: LED-…97.37–.41.

| Finding / decision | What changed | Pinned by |
|---|---|---|
| **code F1 (HIGH), operator item 7** | `.map-region-scroll { min-height: 1 }` (was 2), comment rewritten. At 120x30 the Map paints one region row and scrolls to the rest (capture `map.120x30`: 14 regions, scrollbar). This is a named supersession of batch-93's "2-row floor" note (LED-…97.37) | AT-074 GREEN (RED pre-fold, `red-fold.txt`); M28 |
| **operator item 1** (the two Saves / Loads) | `ctrl+l` → `Load file` and `ctrl+s` → `Save project` (the sibling `l` / `s` descriptions). Row 1 grows 84 → 97 cells. **At 80x24 row 1 paints 6 tokens: `^k Palette ^d Density ^l Load file ^s Save project x Operations ? Help`.** `q Quit` and `^p palette` drop whole. Row 1 never paints `? more` (LLR-150.2): `? Help` is mandatory and lists every binding. TC-081.4 sanctions both lines; LLR-150.2's list is amended (LED-…97.38) | TC-B97-67 ×3, AT-B97-25 (RED pre-fold); M29, M26 |
| **operator item 3 + code F5** (named I-10 change) | An owned token is lit only while the focus is inside its **window** and the owner's own `check_action` allows the action; otherwise it is dimmed and not clickable. It repaints on the focus change (the bindings signal). "Window", not "owner widget": the owner-widget reading would dim Check Editor `space` with the focus on a tab chip, where LLR-150.7 requires the click to work (LED-…97.39). **ux F1 (Diff keys dimmed when they cannot act) is covered by the owner clause:** `AbDiffPanel.check_action` (`screens_directionb.py:8225`) gates `esc` (run list open), `f` (fallback regime) and `] [` (not the notice regime). The test reads `f` and `esc` dimmed and `] [` lit at 220x60, and `f` lit at 118x54 | `test_tc_b97_69_owned_keys_dim_outside_their_window` (NEW, RED pre-fold); M30, M31, M33; captures `split_join` / `split_join.rail` |
| **operator item 8** | The `(118, 53)` arms of the four TC-B97-38 height tests retire (named supersession, LED-…97.40). Every other PC-24 118x53 arm still passes and is kept | `tests/test_b97_width.py` |
| **package — ux F2** | A disabled token paints whole, key **and** description, in one colour: `key-bar--dim` → `$foreground-disabled`, painted `#6a7177`. It used to be Rich `dim` on each half (`#b47d2f` / `#6b80ae`) | `test_tc_b97_69_a_dimmed_token_paints_whole_in_one_colour` (NEW, painted strips, RED pre-fold), TC-B97-70 layer 0 (rewritten); M32, M35 |
| **package — Map help** | The Map help is code-authored and leaves the md census (TC-707 / TC-1802 sets updated by name). Its steps quote only `^L`; the keys block reads `k — Legend` (LED-…97.41) | `test_tc_b97_66_map_help_names_only_keys_that_act_on_the_map` (NEW, RED pre-fold: `+ , - . g`); M34 |
| package — accepted | `Page±` unchanged; `j` stays off A2L; **the Diff shows 1 hex row at 120x30** (R-1 accepted 2), recorded (LED-…97.41) | — |
| **code F3 (MEDIUM)** | `DERIVED_GUARDS` names the function or class attribute that holds each guard (`S19TuiApp.action_page_next_context`, `AbDiffPanel.BINDINGS`…). The test locates the guard text inside that node with `ast`, with no fixed line. The bare row comparison is now backed by a reach check: an app key's binding action names the guard node directly or through ≤ 2 `self.<method>(` hops, and an owned key is bound in the guard's class `BINDINGS` | `test_tc_b97_69_derived_rows_follow_their_guards` (GREEN pre-fold: a refactor of the instrument); M22 |
| code F4 (LOW) | `refresh_bindings()` left the `_patch_document_view` builder for its four `refresh_entries` callers | TC-B97-69 dims; M13 (4 sites) |
| code F6 (LOW) | recorded in §5 | — |
| Owed to Inc-7 (not here) | Split / Join's `EXPORT ^E` label against its `e` binding (`segment_split_view.py`, a fifth file); scrollable help modals (ux F3) | §6 |

**Fold RED** on the pre-fold tree (`scratchpad/prefold8` = 9793fcd + the Inc-8 tree as first reported): **14 failed, 1 passed** over the fold's arms (`red-fold.txt`). The passing one is the F3 guard arm, a refactor.
**Fold mutations:** **10 mutants, 12 arms: 11 KILLED / 1 SURVIVED / 0 BAD** (`mutations-fold2.txt`). The survivor is M13 on AT-B97-26, the same as before: a keypress on Parse moves the focus and repaints the bar; TC-B97-69 kills M13.
**Fold GREEN** (`green-fold2.txt`, the 64-file gate set on the folded digests): **1605 passed, 29 xfailed, 4 failed** in 1:32:14. 3 are baseline nodes (AT-B78-03, AT-B78-32, AT-056e). 1 is not in the baseline: `tests/test_tui_map_big.py::test_tc_b77_22_b77_select_single_run_is_selected_and_marked[size1]`. It failed once in the long run; it passes 8 of 8 isolated (16 of 16 parametrized runs), and the whole `test_tui_map_big.py` module passes (107 passed) on the fold tree (`rerun-nonbaseline-fold2.txt`). It is a load flake, recorded and not fixed. AT-074 and every other node of the first gate's 16 is GREEN; the TC-B97-38 118x53 arms are retired.
**Re-captures** (real WT, truecolor, one window at a time, each closed): `workspace` (the new row-1 labels), `patch` (the whole-token dim of `^z ^y v`), `split_join` (focus inside: lit) and `split_join.rail` (focus on the rail: owned tokens dim), `map` at 118x54 and `map.120x30` (one row and a scrollbar), `diff` (owned keys dimmed with the focus on the rail).

Fold source digests: `app.py b09bb8ce…`, `window_help.py 7212592d…`, `styles.tcss 4b894b97…`, `screens_directionb.py edfe50de…` (the fold GREEN, the fold mutants and the re-captures ran on these).

---

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/window_help.py` | source | HLR-150, LLR-150.1, 150.2, 150.3, 150.5, 150.7, LLR-148.6 | the I-10 table, `KeyToken`, `PackedRow`, `pack_key_row`, `resolve_window_tokens`, `global_tokens`, `more_token`, `window_tag`, `window_keys_text`, `owner_widget`, `KeyRow`, `KeyBar`; `WindowHelpScreen` shows `#window_help_keys`; 4 hand-typed key lines deleted (patch ×2, check_editor, flow_execution) |
| `s19_app/tui/app.py` | source | LLR-150.4, 150.6, PC-23 | `KeyBar` replaces `Footer`; `period` `key_display="."`; D28 arms in `check_action`; `key_condition`; `refresh_bindings()` in `action_show_screen`, `action_open_split_join_export`, `watch_current_file`, `_patch_document_view`; `_variant_set` property |
| `s19_app/tui/styles.tcss` | source | LLR-150.2, 150.3, 150.6 | one appended `/* batch-97 key bar */` section |
| `s19_app/tui/screens_directionb.py` | source | LLR-150.6 (via LLR-125.2) | gate fold: `_DIFF_MIN_H` 28 → 29, re-measured with the bar |
| `docs/architecture.md` | doc | | §11: the I-10 row; the I-11 row as built |
| `tests/test_b97_key_bar.py` | test | HLR-150, LLR-150.1–150.7 | NEW, 30 nodes: TC-B97-66 ×5, -67 ×3, -68 ×3, -69 ×5, -70 ×6 (3 layer 0), -71 ×2, -72 ×4, AT-B97-25, AT-B97-26 |
| `tests/test_tui_directionb.py` | test | HLR-150 (supersedes LLR-013.2) | the four `test_tc030_*` nodes read the painted key bar (named supersession, PC-25, LED-…97.10) |
| `tests/test_tui_diff_screen.py` | test | HLR-150 | AT-B78-28 clause 3 and TC-B78-38: the chip set is the painted bar on the diff window (`_B97_DIFF_BAR_KEYS`, set equality); AT-B78-32 untouched (LED-…97.36) |
| `tests/test_tui_patch_history_strip.py` | test | LLR-150.5 (D28) | TC-081.4: marker `key_display="."` sanctioned with its comment |
| `tests/test_b97_chips_help.py` | test | LLR-148.6 (I-10) | TC-B97-32 Check / Patch / Execution arms parse the steps + the generated keys block (`^z`/`^y` read in the bar's display form) |
| `tests/test_b97_width.py` | test | LLR-149.5 | gate fold: the TC-B97-38 118x53 arms retire (LED-…97.40) |
| `tests/test_window_usage_help.py`, `tests/test_changes_file_notation_help.py` | test | LLR-148.6 | gate fold: `map` leaves the md census (code-authored) |
| `tests/test_id_registry.py` | test | HLR-150 (D18) | `EXPECTED_SCANNED_TEST_FILES` 197 → 198, measured |
| `tests/test_b97_flow_execution.py` | test | LLR-148.6 (D27) | gate fold: TC-B97-64 reads `c — Confirm` in the keys block; the CSS scope arm ends at the next batch-97 section |
| `tests/test_b97_patch_editor.py` | test | LLR-150.6 | gate fold: TC-B97-40's chips-below-fold 2 @118x54 / 3 @118x53 (measured, flagged) |
| `tests/test_tui_flow_builder_b94.py`, `tests/test_tui_flow_execution_b94.py` | test | LLR-150.6 | gate fold: screen box 96x17 / 136x27 |
| `prototypes/keybar/run_keybar.py`, `capture.ps1` | doc | | untracked throwaway harness re-pointed at the real tree; round originals kept as `*.prototype-round.*` |
| `.dev-flow/…/01-requirements-ledger.md`, `01-requirements.md` | doc | LED-…97.36 | new ledger entry; LLR-150.1/.4/.6/.7 `Ledger:` fields point back to it (V26) |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** — `window_help.py`, `app.py`, `styles.tcss` (the design's three) + **`screens_directionb.py`** (gate fold: one constant, `_DIFF_MIN_H`; it could not be cut smaller, because the Diff floor is defined in that module and the bar moved it) |
| Test files | 10 (1 new; 9 rewritten by name: directionb, diff_screen, patch_history_strip, chips_help, id_registry, b97_flow_execution, b97_patch_editor, flow_builder_b94, flow_execution_b94) |
| Doc files | `docs/architecture.md`, ledger + requirements back-pointers, evidence, this packet, the untracked harness |

## 3 · How to test

```bash
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8; unset NO_COLOR
python -m pytest tests/test_b97_key_bar.py -q -rfE -p no:cacheprovider
python -m pytest $(cat .dev-flow/2026-10-19-batch-97/evidence/inc-8/gate-files.txt) -q -rfE -p no:cacheprovider
python .dev-flow/2026-10-19-batch-97/evidence/inc-8/mutate.py <tree>                         # 27 mutants
python .dev-flow/2026-10-19-batch-97/evidence/inc-8/frames.py . 118x54 220x60                 # vs <head> 118x53 220x59
python .dev-flow/2026-10-19-batch-97/evidence/inc-3/snapshot_cells.py <tree>                  # PC-10
powershell -File prototypes/keybar/capture.ps1 -Scenario win-<window> -OutPng <png> [-Cols 220 -Rows 60]
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `pack_key_row` ×3 (prefix over widths 20..240 on two lists, dim / no-hit, exact fit); the AST arms (no label, no hex) | passed (`green.txt`) |
| **A · white-box** | `core` · `full` | the gate set (`gate-files.txt`, **64 files**: Inc-6's 34 + the B1 census of this increment, incl. `test_tui_theme.py`, every module that parses `styles.tcss`, the guard host `tests/test_tui_directionb.py`, `test_tui_snapshot.py`, all `test_b97_*`) | **first run: 1593 passed, 29 xfailed, 19 failed** in 1:25:22 (`green.txt`, on `app.py ae33ceea…`, `window_help.py 3d0db1b1…`, `styles.tcss 957a0ec7…`). Against the baseline (`baseline-pytest-51ee191.txt`): **3 baseline nodes** (AT-B78-03 with the `Confirm` palette row, AT-B78-32 rows `c` / `d`, AT-056e) and **16 not in the baseline** — see the fold table below |
| **A · gate fold** | `core` · `full` | the 16 nodes + every module the fold touched (`test_id_registry.py`, `test_tui_diff_screen.py` whole, both b94 flow modules whole, `test_tui_snapshot.py`, `test_b97_key_bar.py` whole, `test_docs_canon.py`) | **128 passed, 29 xfailed, 5 failed** in 12:25 (`green-fold.txt`, with `screens_directionb.py edfe50de…`): AT-B78-32 (baseline); `test_tc024_report_trigger_invalid_dest_refused` (pre-existing flake, below); `test_tc_b97_69_derived_rows_follow_their_guards` (**the guard arm doing its job**: the `_DIFF_MIN_H` comment moved the Diff panel's bindings 4 lines; `DERIVED_GUARDS` updated to `:7909-7912`, 1 passed, `rerun-nonbaseline.txt`); **AT-074** and **TC-B97-38 Builder `after_run` @118x53** (not folded, owed to a decision — §*For the operator* items 7, 8) |
| **Full suite** | `full` | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/suite-full.txt` | **8 failed, 3574 passed, 3 skipped, 32 xfailed** (1:55:46, orchestrator, fold tree). Against the baseline: 6 are baseline nodes; the 2 others (`test_tc_b94_27_lane_binding_isolation_and_noop`, `test_save_back_prompt`) passed isolated (2 passed) and in their full modules (62 passed; the 1 failure there, `test_at031b_two_saves_are_distinct_no_clobber`, is a baseline node) — `rerun-nonbaseline-suite.txt`. Load flakes, not Inc-8. |
| **B · black-box** | `core` · `full` | AT-B97-25, AT-B97-26 | passed (`green.txt`; AT-26 again in `green-fold.txt`) |

**The 16 non-baseline nodes of the first gate run, and their fold:**

| Node(s) | Cause | Fold |
|---|---|---|
| `test_id_registry.py` ×4, `test_tui_commandbar.py::test_at_b78_14_no_live_registry_row_names_a_missing_node` | the scanned-module bound (197 → 198) and the TC-030 registry row naming the helper `_shown_footer_keys` (renamed by the first tc030 rewrite) | bound measured at 198; the helper keeps its registered name — GREEN |
| `test_b97_flow_execution.py::test_tc_b97_flow_execution_css_section_is_scoped` | the arm read "from the marker to the end of the sheet", so it swallowed the appended key-bar section | the section ends at the next `/* batch-97 ` marker (named supersession) — GREEN |
| `test_b97_flow_execution.py::test_tc_b97_64_c_after_the_dwell…` | pinned the hand-typed `c — Confirm` step D27 deletes | reads the generated keys block, and asserts the line is no longer a step — GREEN |
| `test_tui_flow_builder_b94.py::test_at_b94_15_fb_a_surface_and_wired_patch_run`, `test_tui_flow_execution_b94.py::test_at_b94_19_import_mounts_lanes_side_by_side`, `::test_tc_b94_26` | the measured screen box 96x18 / 136x28 at 120x30 / 160x40 | 96x17 / 136x27 (the bar's one row, named) — GREEN |
| `test_b97_patch_editor.py::test_tc_b97_40_…` ×2 | the operator-accepted "chips below the fold" counts (1 at 118x54, 2 at 118x53) | 2 at 118x54 (the accepted 118x53 reading, at the same body height), 3 at 118x53, measured — GREEN; **flagged** (item 9) |
| `test_tui_diff_screen.py::test_tc_b78_54_the_height_floor_delivers_a_hex_row` | **a real defect from the bar:** at 120x28 the Diff declared the terminal deliverable and painted a header and 0 hex rows (LLR-125.2) | **`_DIFF_MIN_H` 28 → 29** in `screens_directionb.py` (the fourth SOURCE file, §2), re-measured 28 → 0, 29 → 1, 30 → 1 hex rows — GREEN |
| `test_tui_diff_screen.py::test_tc024_report_trigger_surfaces_paths` | a pre-existing flake: 1 of 5 isolated runs fail on 9793fcd, 3 of 5 on Inc-8 (`rerun-nonbaseline.txt`; its sibling `…invalid_dest_refused` flakes the same way) | recorded, not fixed (the report worker's timing; its idiom is batch-78's) |
| `test_tui_directionb.py::test_at074_single_click_repositions_hex` | **a real consequence of the bar on another screen:** at 120x30 the Memory Map's region list shows 1 of 2 rows, the second row lies under `#map_grid`'s bottom padding row, and `.map-region-scroll` (`min-height: 2`) reports no scroll, so the second region cannot be reached (deterministic; GREEN on 9793fcd) | **not folded** — a Map budget decision (item 7) |
| `test_b97_width.py::test_tc_b97_38_builder_height_goes_to_the_result[after_run-size1]` | at 118x53 **with the bar** (Builder body 38 rows, below the PC-5 budget's lowest column) the result area scrolls by 1 row; it holds at 118x54 | **not folded** — the 118x53 hedge arm now measures a height the design never budgeted (item 8) |

**PC-24 (the 118x53 arms of Inc-3..6, now at 118x54 with the bar).** They run in the gate set: `tests/test_b97_check_editor.py`, `test_b97_patch_editor.py`, `test_b97_flow_builder.py`, `test_b97_flow_execution.py` and `test_b97_width.py`. They carry their 118x54 and 118x53 arms; 118x54 with the bar now has 118x53's body height. **Neighbour frames:** the painted frames of the Check Editor, Patch Editor, Flow Builder and Flow Execution containers on the Inc-8 tree at 118x54 / 220x60 are **byte-identical** to 9793fcd at 118x53 / 220x59 (the same container height, 41 / 47). Both digests are `b8664a6a…`, and `frames-diff.txt` is empty. So the bar takes one row, and nothing else in those four screens moves. Positive control: 9793fcd at the same size (118x54 / 220x60) against Inc-8 differs in 14 rows (`frames-diff-control.txt`). No fix was needed in any of the three files.

**PC-10 — predicted: all 29 snapshot cells drift (the bottom two rows of every window). Verified: 29 of 29 cell digests differ** between 9793fcd and the Inc-8 tree (`cells-9793fcd.txt`, `cells-inc8.txt`, `cells-diff.txt`). The cells sit inside the batch-94 `xfail(strict=False)` envelope until Inc-7's regen reconciles them.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | none to the source: the new and rewritten tests ran in a detached worktree of `9793fcd` (`app.py a0be1dd7…`, `window_help.py a488a0bc…`, `styles.tcss 4c790e6e…`, the Inc-6 close digests; `s19_app` imported from the worktree, printed in the transcript header) |
| Transcript | `red.txt` — **38 failed / 2 passed** over the 30 new nodes + 10 rewritten ones; the 2 passed are TC-081.4 (a guard: the worktree's diff is empty) and nothing else of the new module |
| Instrument | pytest `-rfE --tb=line`, one run; then `red-rerun.txt` (7 failed) after the PC-11 reorders |
| Where it ran | `scratchpad/head_9793fcd` (git worktree, detached at `9793fcd`, removed after this packet) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider` |
| Arms resolved at baseline | 38 RED (`red.txt`), 7 re-checked RED at their clause (`red-rerun.txt`) |
| Verdict granularity | per node |
| Arms that stayed GREEN | TC-081.4 (by design: it diffs `app.py` against its base; GREEN on base, GREEN on Inc-8 with the sanctioned marker) |

| Field | Value |
|---|---|
| **RED counterfactual** | 38 RED on the unchanged `9793fcd` source (`red.txt`), 7 re-checked at their clause after the PC-11 reorders (`red-rerun.txt`); the fold's TC-B78-54 RED on the pre-fold Inc-8 tree (`green.txt`) and GREEN after `_DIFF_MIN_H` 29 (`green-fold.txt`); 0 restores needed (no source edit in the RED runs) |

**PC-11 classification.**
- **RED at the main-observable clause:**
  - TC-67 ×2 (row 1 is the Footer row: `/ Find`, `g Go-to`… and no `? Help` with the focus in a window) and TC-67 80x24;
  - TC-68 ×2 (one row);
  - TC-69 page keys (`.` on Map advanced the hidden hex view 0 → 200; `,` / `.` on Issues, CRC, Split / Join…), TC-69 pin ×2 (`+ Pa▏`, `+ Page+` painted on Workspace…), TC-69 dims (one row);
  - TC-70 integration 118x54 / 220x60 (`perio▏` / `period Hex+`);
  - TC-71 ×2 (containers 42 / 48);
  - AT-25 (`+ Pa▏^p palette`, no `? Help`), AT-26 (no `? Help` with the focus inside the Patch Editor);
  - the 4 `tc030` rewrites (one row), AT-B78-28 / TC-B78-38 (no painted bar).
- **RED structurally (the symbol does not exist on main, the main-observable fact of P-62), and RED by mutation as well:** TC-66 ×5 (no table: M16–M20); TC-69 derived (M22); TC-70 layer 0 ×3 (M3, M4, M5); TC-70 80x24 (M3, M5); TC-72 ×4 (no row 2 / no hits: M6, M7, M8, M23); TC-68 hex (M21); the 3 TC-B97-32 rewrites (ImportError of the keys block; their old arms were GREEN on main through the hand-typed lines).

### Mutation verdicts

| Field | Value |
|---|---|
| **Mutation verdicts** | **First run: 27 mutants, 34 arms — 30 KILLED / 4 SURVIVED / 0 BAD** (`mutations.txt`). **After the test fold: the 4 survivor arms re-run — 5 of 6 KILLED, 1 SURVIVED** (`mutations-fold.txt`). Every restore was SHA-256-checked against the GREEN digests (`window_help.py 3d0db1b1…`, `app.py ae33ceea…`, `styles.tcss 957a0ec7…`). **Fixed by the fold:** M1 on AT-B97-26 (the AT read the hex view's header row, not its first address; it now reads the first `0x…` row); M2 (the `+ -` arm is behaviourally a no-op, because `page_next_context` routes only A2L / MAC; TC-69 now also asserts that each disabled key is absent from `app.active_bindings`, the "not live" clause); M12 (loading an image refreshes the bar through another path; an **unload** does not, so TC-69 gained the unload arm); M13 on TC-69 (the paste arm now waits for the document, then allows only 3 pauses for the repaint). **Survivor M13 on AT-B97-26:** pressing Parse pasted by key moves the focus, and the focus move repaints the bar anyway. TC-B97-69 (`press()`, no focus move) is the arm that kills it. **Killed:** no `, .` arm (×2); no `+ -` arm; a cropping packer (×2); a greedy packer; no `? more` (×2); a click by `simulate_key` (×3: the palette input typed into, `space` presses the focused tab chip, `c` typed into `#fx_in_0_0`); hit ranges offset (×2); dimmed tokens clickable; the tag in the description pair; a bar of height 3; no refresh in `action_show_screen`; no refresh on unload / document / variant set; `.` displayed `period`; a keys block with another label; an unbound key or an empty description accepted (×2); the hand-typed `c — Confirm` back; a label in the table; a hex literal in the painter; a derived key with no guard; an owned key run on the focused widget; row-2 descriptions in the row-1 colour; the go separator always ` · go`; row 1 out of order; the Footer kept beside the bar |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the new and rewritten nodes | the unchanged `9793fcd` source | 38 failed (`red.txt`), 7 at their clause after the reorders (`red-rerun.txt`) |
| `mutate.py` | 27 one-edit mutants | 35 RED arms of 40 (each anchor asserted once, the edit asserted applied, every restore digest-checked) |
| `bar_rows` / `pieces` (painted-row tokeniser) | the Footer row on main | `+ Pa▏^p palette` and `period Hex+` reported as partial / unknown tokens (TC-70, AT-25 RED) |
| `_dim` (colour-based dim reader) | M12 / M13 / M14 (a writer without its refresh) | the stale lit colour `#ffa62b` reported where `#b47d2f` was due (TC-69 RED) |
| `click_bar` | M6 (`simulate_key`), M7 (offset hits) | input typed into, the wrong token run (TC-72 RED) |
| `frames.py` | 9793fcd at 118x54 against Inc-8 at 118x54 | 14 differing rows (`frames-diff-control.txt`) |
| `snapshot_cells.py` | the two trees | 29 of 29 cells differ (it sees a bottom-row change) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 7 instruments, each shown failing on a known-bad input |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | Every key-bar claim reads the compositor strips: the row texts are tokenised from painted rows (`painted_rows` over each `KeyRow` region), and the colours are painted cell styles (`painted_style`): the tag `#0a0e1b` on `#91abec` and bold, the descriptions `#91abec`, the key glyphs `footer-key-foreground`, the row background `footer-background`, no reserved colour in any bar cell. Dimming is the painted blended colour (`#b47d2f`), since the strips carry no `dim` attribute. Behaviour is read on app state: `_hex_window_start`, `_a2l_window_start`, `_mac_window_start`, `_active_screen_key`, the document's `source_path` / entry count, the include count, `ContentSwitcher.current`, the input's `value`, `ExternalStepConfirmed` posts, an `action_quit` spy and a bell spy. Each click's hit range is checked against the painted cells it covers |

### Evidence files

All paths are under `.dev-flow/2026-10-19-batch-97/evidence/inc-8/`.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED (38 failed / 2 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/red.txt` | `a1f419a071609894069c124f3ba9b62059552d6c0b5622590b4c7135c218b3fb` |
| RED re-run after the PC-11 reorders (7 failed at their clause) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/red-rerun.txt` | `23049c4df594ef038061d85690eb7352e5be659a42ddc91645fa01427a235d70` |
| Gate file list (64) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/gate-files.txt` | `0ad7f46b9ada4446968cc97c519bd25f43d6a827f4669f01c0ff82a03751ac06` |
| GREEN gate (1593 passed / 29 xf / 19 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/green.txt` | `9d781e8263a4c5566eec995e2ea0c5a79a435b1c9744878191215d5bea274a1c` |
| Gate fold (128 passed / 29 xf / 5 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/green-fold.txt` | `89199631664b8bd31b14c2fefa48e595f93ed5168fb770911e575334c7f78700` |
| Non-baseline re-runs (tc024 ×5 on both trees; the guard arm after its line update) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/rerun-nonbaseline.txt` | `88efde2f9d5c883413eb4e5081a8231f0030b7762dcd620c86174400ababc6ba` |
| Mutations (27 mutants, 34 arms: 30 / 4 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/mutations.txt` | `dd6b1f5d6547768a621d09c27fe4f18cd6b9c3681f78d737ec73bf7feb39421b` |
| Mutations after the test fold (6 arms: 5 / 1 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/mutations-fold.txt` | `9e9071b20e025a7d8b48952d286e1c7ce0dbf792049278a9ec2f8e009f275ed0` |
| Mutation script | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/mutate.py` | `be2902a90766eceda7f130686d4954c8d78f77c38856f85baf9035713ac84d6b` |
| Frames script | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames.py` | `c29b39f04d3ce3a86bcdbea69f89fa1f9f9b7ee3dbd3e6dafb6037a4f627e34b` |
| Frames Inc-8 @118x54 / 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames-inc8.txt` | `b8664a6ab7beb24fbe1d0da1a51dfc1a1db50b00a7ed86483b91a949e0f3dd9f` |
| Frames 9793fcd @118x53 / 220x59 (= Inc-8) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames-9793fcd.txt` | `b8664a6ab7beb24fbe1d0da1a51dfc1a1db50b00a7ed86483b91a949e0f3dd9f` |
| Frames diff (empty) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames-diff.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Frames 9793fcd @118x54 / 220x60 (control) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames-9793fcd-same-size.txt` | `c3d4a76d79bc66b384c6dd6d1a6f3957d7f281a7bb71c2c9158b1ab05dd4b385` |
| Frames control diff (14 rows) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/frames-diff-control.txt` | `79cc0cd7be6ee5e4899523245743d5ebd658d9bae5a34d05dfeeeea4f20bcdbf` |
| Snapshot cells Inc-8 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/cells-inc8.txt` | `b2658ff133437186a1561da4f964fc508241781c70393763d56a3d39f2e242a6` |
| Snapshot cells 9793fcd | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/cells-9793fcd.txt` | `4db98ec843e6165205c833d881c92284bf29ec3d183027021441684771b7ca2a` |
| Snapshot cells diff (29 / 29) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/cells-diff.txt` | `6ef52809c45f2bb205079b24db72ee4881393114ac1ca4b3458686b2d1af3598` |
| WT Workspace 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.workspace.png` | `8663bbece6d0efdb211d944227c8aa4b845f80e5b22759a301563eeea461784f` |
| WT Workspace 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.workspace.220.png` | `759ee4b3c20aeffde6c108ac5f7344cffb2878b3dfc9d434a16457405aad018e` |
| WT A2L Explorer | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.a2l.png` | `5c4bdfbfc932f89388f5afa3cdac0d777d9ef30aea28dad8709a396cbcc23950` |
| WT MAC View | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.mac.png` | `f1c341c61cf2f0a081c40a275cb404e34b34f9b72737bc8b758fb92869f1d3c6` |
| WT Memory Map | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.map.png` | `88103a5314e050c5e78fc9da694d9614f394843f6d72c43c778b4fac767e3b6f` |
| WT Issues Report | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.issues.png` | `66c1b7cdd5f3268a4e7ffe50f1c7e4828104f49164ef69d38d139b44d5f85357` |
| WT Patch Editor 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.patch.png` | `d3fdce91aba3b4614c834d9589156d9ddc0f246bd89e33169c3be128af11f05d` |
| WT Patch Editor 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.patch.220.png` | `23e11aa9f445ba6228c5ac9f1c50f0f593c24860ce19bef390eb5cd5f188dfcf` |
| WT Check Editor | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.check_editor.png` | `79224ec164a3a03b2ac91556de6fe6e3dcb38077e0d4731834c4acba35381497` |
| WT A2B Diff | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.diff.png` | `fb2e1de64e2552e6f5457ef35baff44a5b75568f1d3a3f1f6c97e689f3e67d7a` |
| WT Flow Builder | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.flow.png` | `0e5474cac8223748877ffe8240861c873e67e9936268ec18755ee019258e5fee` |
| WT Flow Execution 118x54 (paused) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.flow_execution.png` | `85a5266b9ccc787d07a5963e40d7b6f07b481c7d1448e8df9d0d8d44606935fd` |
| WT Flow Execution 220x60 (paused) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.flow_execution.220.png` | `8a98dff265e9fc189d119d9fd3e2f36b32e04f7e6cbd35cf37ed06829f4041e7` |
| WT Checks | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.checks.png` | `1538c3217b36c45d3a42e3bfe46d8166a9cb4e8a6692a8bc8d61abff40e2a2e5` |
| WT CRC Designer | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.crc_designer.png` | `96ac3ce9f3b2b0481971a309b67cd0da03df76987523e56519e5ae3e897e26e5` |
| WT Split / Join / Export 118x54 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.split_join.png` | `54ab4fca7981c3b68f10ee859a389f806a0a32b4b21f8663e4bd8e0df255cc06` |
| WT Split / Join / Export 220x60 | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.split_join.220.png` | `83fe1ed1d748ea47f3927e4095bb6b5411760af089f57ff141aeb0335b778b47` |
| Fold RED (14 failed / 1 passed, pre-fold tree) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/red-fold.txt` | `ff264b49f14f43cdfe8c16146243d056638b40bbe2d5052b73115c2bcddbe8fd` |
| Fold GREEN, 64-file gate set (1605 passed / 29 xf / 4 failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/green-fold2.txt` | `3b413b39ccd94c2a9e59e6fc0b70424977934a55c52a8d05f28d9372a1af0b3f` |
| Full suite (8 failed / 3574 passed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/suite-full.txt` | `c5fb6cd492ad9d0aadb9b8de2aa8817af8dafce6d1cf21a48f17b259c28413e0` |
| Full-suite non-baseline re-run (2 passed; modules 62 passed / 1 baseline failed) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/rerun-nonbaseline-suite.txt` | `92938aa12d5a31b5a0120de63eaafa7e09e4563f0abbbc27c2244dbc153109e9` |
| Fold mutations (12 arms: 11 / 1 / 0) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/mutations-fold2.txt` | `adb1803eb07dec982155525d2ab00dc17ca33d060b4a55af0ba225e209bd4057` |
| Fold non-baseline re-runs (tc_b77_22 ×8, map_big module) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/rerun-nonbaseline-fold2.txt` | `b0cb50b9eee38c62bb4248cdceea0705a33c85ec2b0a0998d621822a052e13f4` |
| WT Split / Join / Export, focus on the rail (owned tokens dim) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.split_join.rail.png` | `bd9c2158ec7481f3361f4f2ecc10cde51ae54c6f82255687eb2a8a034a6ccf5c` |
| WT Memory Map 120x30 (one row + scrollbar) | `.dev-flow/2026-10-19-batch-97/evidence/inc-8/png/impl.keybar.map.120x30.png` | `13355d33892da6282c17999d3f39eff3d43fbb1be283ddde0dd72b959736f8c4` |

| Field | Value |
|---|---|
| **Evidence files** | 22 transcripts / scripts and 19 WT captures above. Five captures (workspace, patch, split_join, map, diff) were re-taken on the fold tree and carry their new digests; the first-run digests of those five are not kept (the validator brief, `evidence/inc-8/validate-brief.txt`, is regenerated on every run and so carries no digest), each with its SHA-256. The captures were taken on the pre-fold tree. The fold's only source change (`_DIFF_MIN_H`) acts below 29 rows, and every capture is at 54 or 60 rows |

Final source digests: `app.py ae33ceea…`, `window_help.py 3d0db1b1…`, `styles.tcss 957a0ec7…` (GREEN, the mutation battery and the captures ran on these), `screens_directionb.py edfe50de…` (the gate fold).

**WT glyph check:** the bar paints only ASCII, `·` and `^`, all one cell in the captures. No glyph from the 2-cell list (`⚠ ✖ ✔ ☑ ⏸`) is used.

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | Yes, in six places: 0 hex literals in `window_help.py`; 0 strings in the table that are not key names / selectors / conditions; 0 label literals but `more` / `palette`; 0 painted tokens outside a window's allowed set; 0 `perio` / partial tokens; 0 differing frame rows at equal body height |
| What made the search wide enough | an AST walk over the whole module (every `Constant`; every `label=` keyword); every row of every window at three sizes; the four batch-97 containers whole |
| Positive control | M21, M20, M26 / M3, M15, `frames-diff-control.txt` — each RED |

### Reverse census — trigger family B, and A3

| Probe | Result |
|---|---|
| B1a: tests reaching `Footer`, `active_bindings`, `key_display`, `show_help_panel`, `window_help`, `refresh_bindings`, `check_action`, `_variant_set`, `styles.tcss` | 48 files (`grep -l`); all are in the gate set (64 files with Inc-6's 34). Red before the rewrites: the 4 `tc030`, AT-B78-28, **TC-B78-38** (not named in PC-25; the same chip-set clause, rewritten by name, LED-…97.36), TC-081.4, the 3 TC-B97-32 arms. AT-B78-32: its projection carries no `key_display`, so it is untouched, and its baseline failure (rows `c`, `d`) is unchanged |
| B1b: removed symbols | `Footer` import and `yield Footer()` in `app.py`: 0 left in `s19_app/` |
| B1c: hex sweep | no hex in Python (TC-68 AST arm); the TCSS section uses only variables |
| B1d: TC-081.4 | one `Binding(` line added to the `app.py` diff (`period` with `key_display="."`), sanctioned by name |
| B2 · B3 | no file moved; the snapshot goldens drift 29 / 29 (PC-10), reconciled by Inc-7's regen |
| A3 | I-10 landed as frozen, with two additive extensions recorded (`styles=` keyword, `PackedRow.dimmed`); I-11 as amended; `section_body_text` unchanged (TC-707 GREEN) |

| Field | Value |
|---|---|
| **Reverse census** | B1a 48 files, 10 red nodes rewritten by name; B1b–B1d clean; B2 none moved, B3 29 cells predicted and verified; A3 two additive extensions (LED-…97.36) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | Hand-typed key lines the generated block now carries: **4** (patch `ctrl+z —`, `ctrl+y —`; check_editor `space —`; flow_execution `c — Confirm`), enumerated by the "described twice" clause of TC-B97-66 over every section; **4 deleted**, 0 left. Footer-encoded test nodes: 6 (4 `tc030`, AT-B78-28 cl. 3, TC-B78-38), all rewritten |

### Signed-balance test ledger

`post = base − 0 deleted + 30 added` (`tests/test_b97_key_bar.py`). Rewritten in place, by name: 4 (`tc030`), 2 (AT-B78-28 clause 3, TC-B78-38), 1 (TC-081.4 marker), 3 (TC-B97-32 helpers). D18: one new scanned module, so the registry goes 197 → 198, measured (`test_id_registry.py`).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — OK to advance · F1 HIGH resolved (styles.tcss:954 min-height 1; AT-074 unchanged, GREEN, re-run by reviewer with test_b97_key_bar.py: 34 passed); F2–F5 applied and verified, F6 recorded §5; LOW notes L1–L3 (lit-by-window ≠ key fires; possible stale dim on height-only resize; substring _reaches) · ux-reviewer — approve with conditions (first read) · F1–F5 folded in §1b; the fold's re-captures (map 120x30, split_join rail, workspace, patch, diff) were checked by the orchestrator, no second ux read |

## 5 · Risks

- **Help modals taller than the terminal.** Patch, Flow Execution, Check Editor and Flow Builder: the keys block and the last steps cannot be reached at 118x54 or 220x60. This was already true on 9793fcd (§6 item 3).
- **Focus-dependent shadowing.** On Split / Join / Export and the Diff panel, a keypress with the focus outside the window runs the app's meaning of the same key (§*For the operator* item 3). A click is always right.
- **Pilot geometry.** Textual's pilot refuses clicks on the bottom content row (Screen padding). The tests post the same event sequence without the check (`click_bar`). A Textual bump that changes `Pilot._post_mouse_events` should re-run TC-B97-72.
- **Dim is read as colour.** It depends on Textual's dim blend (`#ffa62b` → `#b47d2f`). A theme change re-baselines nothing, because the test compares against the live `footer-key-foreground`.
- **PC-10:** 29 snapshot cells drift until Inc-7's regen. Some of the drift is more than the bottom rows: at 120x30 the Map loses a region row (item 7), and the Diff paints 1 hex row instead of 2 (item 10).
- **Very narrow terminals (code F6).** Below about 30 columns, row 2's mandatory parts (the tag + `? more`) are wider than the row. `pack_key_row` then crops the text and drops the hit ranges past the edge. That is far under the 80x24 floor, and recorded only.
- **Owned-token dimming follows the focus.** A window entered with the focus left on the rail (the Diff, by a rail key) shows its panel keys dimmed until a control inside it takes the focus. This is the decided behaviour (LED-…97.39).
- **The capture harness** now calls `SetProcessDPIAware()`. Without it, captures on a scaled display are cropped silently.

- **Lit means the click acts (code re-read L1).** Owned tokens light by window (LED-…97.39), so a lit token's keyboard press can still go to another widget: in Check Editor with the focus on a tab chip, `space` is lit and presses the chip, while a click on the token runs the action. By design, not a bug.
- **Height-only resize may leave a stale dim (code re-read L2, not tested).** No owner calls `refresh_bindings()` on a regime switch; a height-only resize that changes the Diff regime may keep `f ] [` in the old state until the next focus change. Owed to Inc-7: test it, and if it reproduces, call `refresh_bindings()` at the end of `AbDiffPanel.on_resize`'s regime switch.
- **Two palettes on row 1 (pre-existing).** `^k Palette` (`focus_palette`) and `^p palette` (Textual's command palette) were both shown at HEAD; row 1 repaints them. Routed to the backlog.

## 6 · Pending items / spec deviations

1. **Decisions for the operator:** §*For the operator* items 1–6 (collisions; nothing was relabelled) and items 7–8 (the two gate nodes left RED on purpose: AT-074, Memory Map @120x30; TC-B97-38, Builder @118x53). Items 9–10 are shown for confirmation.
2. **A fourth SOURCE file** (`screens_directionb.py`, one constant) was taken in the gate fold. It is named in §2, with the reason it could not be cut smaller.
3. **Deviations (LED-2026-10-19-batch-97.36):**
   - the bar's `y` is `height − 3` (Screen padding), and row 2 sits on the Footer's row;
   - clicks are posted without the pilot's bounds check;
   - dim is read as colour; 46 page-key presses, not 44; the "not live" clause is added;
   - the repaint is bounded at 3 `settled` pauses instead of one bare `pilot.pause()`;
   - TC-67's control arm is skipped where a window has no focusable control;
   - AT-26's texts are placed and its chips pressed by key;
   - additive `styles=` / `PackedRow.dimmed`;
   - AT-B78-32 is not re-pinned, and TC-B78-38 is rewritten;
   - the Check Editor's `space` tab-chip meaning is dropped with its hand-typed line.
4. **Owed to Inc-7 (gate-fold decisions):**
   - Split / Join / Export's panel label `EXPORT ^E` → `e`, in `s19_app/tui/segment_split_view.py` (a fifth file, not done here);
   - scrollable help modals (ux F3);
   - ux F1 (Diff keys dimmed when they cannot act) is **already covered** by the owner-`check_action` clause, with evidence in §1b. Nothing is owed for it.
   **Pre-existing, owed to Inc-7 or the backlog:**
   - the tall help modals (no scroll);
   - the Map help's stale paging keys;
   - Split / Join's `EXPORT ^E` label against the `e` binding.
5. **Full suite:** run by the orchestrator on the fold tree (§4 Full suite row): no failure beyond the baseline and two load flakes that pass isolated.
6. **Pre-existing flake:** `test_tui_diff_screen.py::test_tc024_report_trigger_*` (1 of 5 isolated on 9793fcd, 3 of 5 on Inc-8; `rerun-nonbaseline.txt`).
7. The worktree `scratchpad/head_9793fcd` is removed after this packet; its outputs are the RED, mutation and frames transcripts above.

## 7 · Suggested next task

The operator's answers to §*For the operator* items 1–8. Then Inc-7 (width sweep on the two-row layout, the snapshot regen reconciling the 29 cells, AT-B97-25 / -26 re-run), with the help-modal overflow (§6 item 3) added to its scope if the operator agrees.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files | all | ✓ | 4 / 4 (§2): the design's three + `screens_directionb.py` (one constant, gate fold, named) |
| 2 | Tests written in this same increment | all | ✓ | 30 new nodes + 10 rewritten by name |
| 3 | Layer 0 where the criterion applies | `core` · `full` | ✓ | `pack_key_row` ×3 (TC-B97-70) |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red.txt` 38; `red-rerun.txt` 7 |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4 reverse census |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b: OK to advance on the re-read (F1 resolved) |
| 7 | No file from another lane touched | all | ✓ | one lane; the patch-integrity investigation's `.dev-flow/design/INVESTIGATION-*` untouched |
| 8 | Frozen interfaces untouched | all | ✓ | I-10 / I-11 landed as frozen + two additive extensions (LED-…97.36); `section_body_text`, message types unchanged |
| 9 | Coverage claims verified on disk | all | ⚠ | `green.txt` + `green-fold.txt`: every non-baseline node folded or explained; **2 open by decision** (AT-074 Map @120x30, TC-B97-38 Builder @118x53), 1 pre-existing flake (tc024) |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | Mutation verdicts per arm | all | ✓ | 34 arms: 30 / 4 / 0; fold 6 arms: 5 / 1 (M13 on AT-26, explained) / 0 |
| 12 | Instrument RED-proof | all | ✓ | 7 instruments |
| 13 | Correction population | all | ✓ | 4 + 6 |
| 14 | Emitted-form assertion | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b: `code-reviewer` and `ux-reviewer` |
| 16 | Evidence files with digests | all | ✓ | §4 |
