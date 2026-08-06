# batch-78 — Phase-1 QA lane: validation method + black-box acceptance design

**Batch:** `2026-08-06-batch-78` · **Branch:** `claude/batch-78-cmdbar-a2bdiff` @ `4df335b`
**Base:** `origin/main` @ `f6ff1d3` (Phase-0 commit is docs-only — no source drift)
**Lane:** QA (the WHAT, observed through the shipped surface) · **Scope:** S-1…S-9 only (Lane 3 OUT)
**Language:** English · **Controls applied:** C-10 · C-12 · C-13 · C-13.1 · C-16 · C-18 · C-22 ·
C-26 · C-28 · C-29 · C-30 · C-31 · C-32 · C-34 · C-39 · C-40 · C-42 · C-43 · C-46
**Every verdict below was EXECUTED** against the pre-change tree. Transcripts are inline, each with
its command. Probes ran with `PYTHONDONTWRITEBYTECODE=1`; **every mutation was applied in-process
(monkeypatch on the imported object) and never written to disk** — a parallel session is live in
this repo. Post-probe `git diff --stat -- s19_app/ tests/` is **empty** (§11).

---

## BLUF

**Eight findings. Two are HIGH and block an acceptance from being finalised; three of the charter's
twelve draft acceptances are measurably wrong — one vacuous, one self-contradictory, one resting on
the wrong producer's width.** The batch's strongest measurement is not in Lane 1 at all:

> **At 120×30 — the shipped diff snapshot cell — the A2B diff results area has a clipped visible
> height of ZERO.** `#diff_columns` clipped against `#screen_diff` = `(92, 0)`; all three result
> columns = 0 visible rows. The shipped golden `[diff-comfortable-120x30].svg` contains **no**
> `Runs`, `Image A` or `Image B` text. S-8 is therefore not cosmetic polish — it is the story that
> makes S-5/S-6/S-7 observable at all at the only size the snapshot matrix covers.

| # | Sev | Story | Finding (all measured, transcripts in §1/§3) |
|---|---|---|---|
| **B-1** | 🔴 **HIGH** | S-5 / S-9 | **Three of the four keys S-5 proposes are already claimed, two of them FROZEN.** `j`→`dump_a2l_json` and `p`→`load_project` are in the `_PRE_BATCH_BINDINGS` literal guarded by live `TC-011`; `k`→`show_legend` is a `show=True` footer chip. **Only `n` is free.** The acceptance cannot state its own expected outcome until the binding-resolution policy is ruled. Batch-77 B-3, one batch later. |
| **B-2** | 🔴 **HIGH** | S-7 | **Measured arithmetic strikes two of the three chartered fallback options at draft time (C-13.1).** A list sharing the row with an unwrapped window needs `width_list ≤ cols_content − 84`: **≤ 8 columns at 120**, **≤ 20 at 132**. So the chartered "12-col list" fallback is **impossible at 120**, and "22-col list + full-width windows at ≥ ~130" first becomes possible at **W = 134**, not 130 — the 132×44 capture the charter cites cannot have had both side by side. |
| **B-3** | 🟠 **MED** | S-1 / S-4 | **Draft acceptance #1's control contradicts S-4.** The palette's 37-action set *contains* `focus_find` and `focus_goto` (executed). "Palette command set unchanged" is true only if S-2 keeps both App actions; if S-4 deletes them the set is 35 and the control is FALSE as worded. Needs one decision. |
| **B-4** | 🟠 **MED** | S-3 | **Half of draft acceptance #3 is VACUOUS today.** `LoadedArtifactsPanel` **already** renders `engine_v3.a2l` (executed). An AT asserting "the A2L name appears in the Loaded panel" is GREEN on the pre-change tree — C-40 limb 1, and the charter-draft-#1 failure of batch-77 repeating. Only the **project name** is RED there (`'DemoProj' in loaded_panel → False`). |
| **B-5** | 🟠 **MED** | S-6 / S-7 | **Phase-0 §9.1's 81-cell row is the WRONG producer for Lane 2.** The diff panel calls `render_hex_view` (**79** cells); `render_hex_view_text` (81) is the *workspace* producer. Every S-7 threshold moves by 2, and the unwrapped-window floor is **94 columns**, not the charter's "~130". |
| **B-6** | 🟠 **MED** | S-3 | **Phase-0's C-26 census missed 16 live call sites in 2 files.** `#cmdbar_project` is the observable for `_project_label()` in `tests/test_tui_variants.py` (7 calls) and `tests/test_tui_patch_variant.py` (9 calls) — the multi-variant `«proj»:«variant» (i/N)` contract (LLR-005.5). Phase 0 §5 concluded `set_context_labels` has "0 test references": true for the *symbol*, false for its *output*. |
| **B-7** | 🟠 **MED** | ordering | **S-8 gates S-6/S-7's observability, and C-30 inverts the chartered lane order.** With `#diff_columns` clipped to 0 rows at 120×30, S-6's height-derived AT has no pane to measure. Separately, S-1 drifts all **29** goldens while every Lane-2 increment drifts **1** — so running Lane 1 first blanket-`xfail`s the matrix and suppresses Lane 2's snapshot coverage (C-30). |
| **B-8** | 🟡 **LOW** | S-2 | **`set_status` does not write `#status_text`.** Executed: it appends to the `#log_line_1..4` tail; `#status_text` moves only via `set_file_status`. S-2's "one status notice" AT read at `#status_text` would be **vacuous** — it stays `'Ready.'` through every search. |

**Plus one self-caught defect in my own work (§10):** my first display-cap predicate stayed **GREEN
under a mutation of the very constant it claimed to certify**, because its expected value was read
from the class under test. It was rewritten, not re-argued, and the rewritten form reddens under
two independent mutations.

**AT/TC ids.** `AT-TC-REGISTRY.jsonl` line 1 `_meta`: `"high_water": {"AT": 281, "TC": 612}`,
`"next_free": {"AT": 282, "TC": 613}` (1 373 rows). **Nothing is minted from the global pool.**
Per PLAN §8 D-7 and `docs/engineering-rules.md:48` this lane uses **batch-scoped**
`AT-B78-nn` / `TC-B78-nn`, which the registry's `_meta.governed` places outside its authority by
spec §2.3 — they cannot collide with the architect lane by construction.

---

## §1 · Executed baseline — the transcripts every predicate is discharged against

Six read-only probes, all under `PYTHONPATH=<repo> PYTHONDONTWRITEBYTECODE=1`. Fixtures are
in-test builders; **no real paths, no PII, no credentials**.

> **Where the probes live.** They were written to this session's **out-of-repo scratchpad**
> (`%LOCALAPPDATA%\Temp\claude\…\scratchpad\qa_p1_{lane1,lane2,geom,keys,s4,mut,mut2}.py`) so that a
> parallel session writing in this working tree could not be disturbed (C-46 / §11). The `$ python
> scratchpad/…` lines below name each probe by basename; **re-run them by copying the file into the
> repo's `scratchpad/` and invoking it from the repo root** — every one is self-contained, imports
> only `s19_app.*` and `textual`, builds its own fixtures, and writes nothing outside its own
> temp workarea directory.

### 1.1 The screen set and find/goto ownership — DERIVED, not hand-listed (C-31)

```
$ python scratchpad/qa_p1_lane1.py
### SCREEN_CONTAINER_IDS derived from code: n=10
    ['workspace','a2l','mac','map','issues','patch','diff','flow','checks','crc_designer']

### (6) local find/goto ownership, per screen container (derived)
  workspace     #screen_workspace     ['search_input', 'goto_input']
  a2l           #screen_a2l           ['alt_search_input', 'alt_goto_input']
  mac           #screen_mac           ['mac_search_input', 'mac_goto_input']
  map           #screen_map           []      issues  #screen_issues  []
  patch         #screen_patch         []      diff    #screen_diff    []
  flow          #screen_flow          []      checks  #screen_checks  []
  crc_designer  #screen_crc_designer  []
```

**The oracle for S-2's two arms is this query, not a hand list.** `owning = {k for k,cid in
SCREEN_CONTAINER_IDS.items() if any('search' in i or 'goto' in i for i in ids(query(#cid, Input)))}`
→ 3 screens; the complement → 7. A hand-listed set survives every code mutation (C-31).

### 1.2 Lane 1 — the bar today (all RED for S-1/S-2, all with the blur assertion)

```
### (2) #command_bar_row present=True height=3   #command_bar height=3

### (3) Ctrl+K per screen  [set_focus(None) + assert app.focused is None before each press]
  workspace…crc_designer   palette_hidden=False   focus=palette_input   items=37   (10 of 10)

### (4) '/' and 'g' focus target per screen
  workspace…crc_designer   / -> find_input        g -> cmdbar_goto_input  (10 of 10)

### (5) Esc from a focused find input
  after '/'  focus=find_input   after 'escape' focus=find_input   returned=False
```

⚠️ **Every focus reading above is preceded by `app.set_focus(None)` and an `assert app.focused is
None`.** Phase-0 §7 records that blurring with `escape` produced a false `g → find_input` on every
screen. **That assertion is mandatory in every Phase-3 focus AT** and is written into `AT-B78-03`,
`AT-B78-05` and `AT-B78-06` as a precondition, not a convention.

### 1.3 The wrong-pane defect, now with an image loaded (S-2's gate)

```
### (7) wrong-pane, loaded image (project DemoProj, image_a.s19 + cal_table.mac + engine_v3.a2l)
  active=a2l  -> {'search_input':'BOOT', 'alt_search_input':'', 'mac_search_input':''}
  active=mac  -> {'search_input':'BOOT', 'alt_search_input':'', 'mac_search_input':''}
  active=map  -> {'search_input':'BOOT', 'alt_search_input':'', 'mac_search_input':''}
```

Phase 0 measured this with **no** file loaded, where `_handle_search` bails at "No file loaded."
before searching. **Re-executed with a loaded image the routing defect is unchanged and the search
actually runs** — the log tail carries `'Search text not found.'`, i.e. the query was executed
against the *workspace* map while A2L was on screen. The story is a real defect fix, not a
refactor.

### 1.4 S-3 — what each surface already carries (the B-4 vacuity measurement)

```
### (8) Loaded panel content TODAY
    'Loaded' / 'S19' / 'image_a.s19  64 B · 1 rng' / 'MAC' / 'cal_table.mac  1 record'
           / 'A2L' / 'engine_v3.a2l  1 tag' / 'unload all'
  A2L filename 'engine_v3.a2l' already in loaded_panel? -> True     <-- VACUOUS clause
  project name 'DemoProj'      already in loaded_panel? -> False    <-- the discriminating clause

### (9) #workspace_status_bar content TODAY
    #status_text   Label  'Ready.'      #progress_bar ProgressBar  <Blank>
    #log_line_1 '' / #log_line_2..4 'Search text not found.'
  'DemoProj' in status bar today?      -> False
  'engine_v3.a2l' in status bar today? -> False

### (10) command bar context labels TODAY
   #cmdbar_project = 'Project: DemoProj'      #cmdbar_a2l = 'A2L: engine_v3.a2l'
```

**This is the C-10 two-branch case in its purest form.** The operator ruled *option C — both
surfaces*. A single AT observing the Loaded panel is GREEN on an implementation that updates only
the Loaded panel **and** already-GREEN on the A2L half today. **Two ATs, one per surface, each
asserting content — and the Loaded-panel one must assert the PROJECT name, not the A2L name.**

**B-8, the surface trap (C-32/C-42):** `set_status` (`app.py:11638`) is
`self._append_log_line(message)` — it writes `#log_line_1..4`. `#status_text` is only written by
`set_file_status`. Observed above: `#status_text == 'Ready.'` after three searches. **S-2's notice
AT must read `#log_line_4` (the newest line) and must assert the line COUNT grew by exactly one.**

### 1.5 Lane 2 — the geometry, content vs outer vs clipped

```
$ python scratchpad/qa_p1_geom.py
### (A) emitted unwrapped row width, PER PRODUCER
  render_hex_view      (the DIFF panel's producer) widest = 79
      |0x00001000  00 01 02 … 0F  |................|| len=79
  render_hex_view_text (the WORKSPACE producer)    widest = 81
      |  0x00001000  00 01 02 … 0F  |................|| len=81
```

**B-5.** Phase-0 §9.1 measured 81 with `render_hex_view_text`. `AbDiffPanel._render_run_windows`
imports **`render_hex_view`** (`screens_directionb.py:7030`), whose row format is
`f"0x{addr:08X}  {hex}  |{ascii}|"` — no leading indent, **79 cells**. Every S-7 threshold shifts.

| terminal | rail | `#diff_columns` **content** | list / hex_a / hex_b **content** | list / hex_a / hex_b **outer** | `#diff_columns` **clipped-visible (w,h)** |
|---|---|---|---|---|---|
| 80×24 | 4 | 70 | 18 / 18 / 19 | 22 / 22 / 23 | **(70, 0)** |
| 120×30 | 22 | 92 | 25 / 26 / 26 | 29 / 30 / 30 | **(92, 0)** |
| 120×44 | 22 | 92 | 25 / 26 / 26 | 29 / 30 / 30 | (92, 11) |
| 130×44 | 22 | 102 | 29 / 29 / 29 | 33 / 33 / 33 | (102, 11) |
| 132×44 | 22 | 104 | 29 / 30 / 30 | 33 / 34 / 34 | (104, 11) |
| 190×44 | 22 | 162 | 49 / 49 / 49 | 53 / 53 / 53 | (162, 11) |

**Phase-0 §9.2 reproduces exactly** — its figures are `widget.size.width` (the CONTENT box). Outer
`region.width` is content + 4 (border 2 + padding 2); `margin-right: 1` sits outside the region, so
**a bordered column costs 5 cells of its parent** (Phase 0's constant is confirmed, and this
document states which of the two widths any figure is).

**Widest emitted line = 79 at every size measured; every window's content width is 18…49. `WRAPS =
True` at 80, 120, 130, 132, 170, 190.** Phase-0 §9.3's conclusion — *the shipped 3-column diff
wraps at every realistic width* — is confirmed with the corrected 79.

### 1.6 The S-7 regime floor, re-derived (C-39 — a carried number is re-derived, not copied)

```
### (3) rail width + #diff_columns content vs terminal width
   W    rail  cols_content  full_width_window_content(=cols-5)  fits79?
   80   4     70            65      False        110  4  100  95   True
   90   4     80            75      False        116  4  106  101  True
   92   4     82            77      False        118  4  108  103  True
   94   4     84            79      True         119  4  109  104  True
   96   4     86            81      True         120  22  92   87   True
   100  4     90            85      True         132  22  104  99   True
```

Three primitives, all measured, none carried:

- `cols_content = W − rail − 6`; **rail is 4 for W ≤ 119 and 22 for W ≥ 120** — the breakpoint is
  exactly 120 (Phase 0 saw both values but not the switch point).
- one bordered box costs **5** cells of `#diff_columns`.
- an unwrapped row needs **79**, so a full-width single window needs `cols_content ≥ 84` ⇒
  **W ≥ 94**. There is **no dead zone** at the rail switch (119 → 104 ✅, 120 → 87 ✅).

**B-2, the C-13.1 deficit match, computed rather than bikeshedded.** For a list of outer width
`L` sharing the row with one unwrapped window: `L ≤ cols_content − 84`.

| regime | `cols_content` | max list width that still leaves an unwrapped window | chartered option | verdict |
|---|---|---|---|---|
| **120** | 92 | **8** | "12-col list (index+offset)" | ❌ **impossible** — 12 > 8, and 8 cells cannot hold `0x00001000` |
| **132** | 104 | **20** | "22-col list + full-width windows (≥ ~130)" | ❌ **impossible at 132** — first feasible at **W = 134** |
| **170** | 142 | 58 | 22-col list beside | ✅ feasible |

⇒ **At 120 the only survivors are list-as-overlay (`o`) and auto-stack (list above the windows).**
The charter's third option is struck at draft time. And "22-col list + full-width windows" is only
unwrapped when the windows do **not** share the row with the list — i.e. stacked below it.

### 1.7 S-8 — the results area is invisible at the only size the snapshot matrix covers

```
  === 120x30 ===  rail=22  #screen_diff w=96 h=15
     #diff_columns     outer=(92,1)  content=(92,1)  clipped=(92, 0)
     #diff_range_list  outer=(29,4)  content=(25,0)  clipped=(29, 0)
     #diff_hex_a       outer=(30,4)  content=(26,0)  clipped=(30, 0)
     #diff_select_row_a  h=3   #diff_select_row_b  h=3   #diff_action_row  h=3
     #diff_status        clipped=(92, 0)
  === 80x24  ===  #screen_diff h=9 ; #diff_columns clipped=(70,0) ; select_row_b clipped h=2
```

```
$ python -c "<entity-decoded text scan of the shipped golden>"
'Runs'    in golden -> False     'Image A' in golden -> False   'Image B' in golden -> False
'Compare' in golden -> True      'Report'  in golden -> True
'Project:' in golden -> True     'A2L:'    in golden -> True
```

Three 3-row rows plus the status line consume the entire 15-row `#screen_diff`. **The shipped
`[diff-comfortable-120x30]` golden proves it: it renders `Compare`/`Report` and nothing from the
results columns.** S-8 is the enabling story, and B-7 follows from it.

### 1.8 S-6 — the emitted row count is height-INDEPENDENT today

```
### (D) emitted window rows at two different pane heights
  (132, 24): hex_a content h=0  clipped h=0  emitted lines=4
  (132, 60): hex_a content h=23 clipped h=27 emitted lines=4
```

`DISPLAY_CONTEXT_BYTES = 16` with `HEX_WIDTH = 16` fixes the window at 4 rows regardless of the
pane. **The charter's draft #6 ("at two different pane heights the window row count differs") is
the right shape and is RED today — 4 == 4.**

### 1.9 G-9 caps and the zero/boundary cases

```
### (C) G-9 display caps
  total runs handed in = 133; panel _runs = 128
  first line = 'Runs: 133'   last 2 = ['', '(showing 128 of 133 runs — full report is complete)']
  BOUNDARY n == DISPLAY_MAX_RUNS (128): stored=128  notice=False
  ZERO runs: hex_a='Image A — no differing runs'  list_first='Runs: 0'
```

**The persisted report is complete by construction:** `on_ab_diff_panel_report_requested`
(`app.py:4952-4977`) reads `self._diff_last_result` — the **uncapped** service result — and
`panel.mem_map_a/b`; it never reads `panel._runs`. That is a *code* fact, so the AT still has to
observe it **through the written file** (C-12), not by citing the line.

### 1.10 Regression baseline, form stated (C-34 / gate-suite reference)

```
$ python -m pytest tests/test_tui_diff_screen.py tests/test_tui_commandbar.py \
      tests/test_tui_diff_compare_realpath.py tests/test_loadfilescreen_input.py -q
58 passed in 70.10s (0:01:10)          # FULL-FILE form, not -k
```

---

## §2 · Premise table — everything I rely on that Phase 0 did not execute (§2.7 form, C-43)

Tier: **P** = premise about the world · **H** = hypothesis carried into this lane.

| # | Tier | Proposition | Verdict | Executed evidence |
|---|---|---|---|---|
| **Q-1** | H | *(Phase 0 §9.1)* the unwrapped hex row that bounds S-7 is **81** cells | ❌ **FALSE for Lane 2 — it is 79** | `render_hex_view` (the diff panel's import, `screens_directionb.py:7030`) emits 79; `render_hex_view_text` emits 81. §1.5 |
| **Q-2** | P | *(Phase 0 §9.2)* the column figures 29/30/30 @132 | ✅ **TRUE — they are CONTENT widths** | outer = content + 4; margin 1 outside; box cost 5 confirmed. §1.5 |
| Q-3 | P | *(Phase 0 §9.3)* the shipped 3-column diff wraps at every realistic width | ✅ TRUE | `WRAPS=True` at 80/120/130/132/170/190. §1.5 |
| **Q-4** | H | *(Phase 0 §9.4)* "a full-width single window fits an unwrapped row **from 120 up**" | ⚠️ **INCOMPLETE — from 94 up** | §1.6 ladder; 94 → 79 = exactly the row width |
| Q-5 | P | rail = 22, collapsing to 4 | ✅ TRUE, **breakpoint measured at exactly 120** | §1.6 |
| **Q-6** | P | *(charter draft #1)* "Ctrl+K opens the palette on every screen" is an acceptance | ⚠️ **GREEN TODAY — it is a PIN, not a gate** | 10 of 10, 37 items each. §1.2 |
| **Q-7** | P | *(charter draft #1)* "control: palette command set unchanged" | ❌ **CONTRADICTS S-4** | `visible_palette_actions()` n=37 **contains `focus_find` and `focus_goto`**. §3.1 |
| **Q-8** | P | *(charter draft #3)* "Project/A2L names appear in the Loaded panel" | ⚠️ **HALF VACUOUS** | `engine_v3.a2l` already present → GREEN today; `DemoProj` absent → RED. §1.4 |
| Q-9 | P | `#workspace_status_bar` carries neither name today | ✅ TRUE | §1.4 (9) |
| **Q-10** | P | *(implied by "one status notice")* `set_status` writes `#status_text` | ❌ **FALSE** | `app.py:11638` → `_append_log_line`; `#status_text` stayed `'Ready.'` through 9 searches. §1.4 |
| Q-11 | P | 29 snapshot goldens drift when the bar row goes | ✅ TRUE — **29 of 29** | entity-decoded scan: 29/29 render both `Project:` and `A2L:`; raw grep also 29/29 (the C-42/4 trap does not bite on these two tokens — stated so nobody re-derives it wrongly). §3.13 |
| **Q-12** | P | the shipped diff golden shows the results columns | ❌ **FALSE** | no `Runs`/`Image A`/`Image B` in `[diff-comfortable-120x30].svg`. §1.7 |
| **Q-13** | P | *(charter S-5)* `j`/`k`/`n`/`p` are available for run navigation | ❌ **FALSE — only `n` is free** | `j`→`dump_a2l_json` (frozen), `p`→`load_project` (frozen), `k`→`show_legend` (`show=True`, footer). §3.9 |
| **Q-14** | P | *(Phase 0 §5)* `set_context_labels` / the label path is **unguarded** ("0 test references") | ❌ **FALSE at the OUTPUT layer** | `#cmdbar_project` is `_project_label()` in `test_tui_variants.py` (7 calls) + `test_tui_patch_variant.py` (9 calls). §3.5 |
| Q-15 | P | the diff window's row count is height-independent today | ✅ TRUE | 4 rows at pane h=0 and at pane h=23. §1.8 |
| Q-16 | P | the persisted diff report is complete (uncapped) | ✅ TRUE by construction | `_diff_last_result`, `app.py:4953`; still owed a **file-level** observation (C-12) |
| Q-17 | P | `tests/test_universal_paste.py` is at risk from S-4 | ❌ FALSE | it targets `#palette_input` and an AST census of *stock* `Input()`; deleting two `OsClipboardInput`s cannot redden it |
| Q-18 | P | `_PRE_BATCH_BINDINGS` does not pin `/` or `g` (Phase-0 P-20) | ✅ TRUE, re-read | 14 tuples: `l r o s p j 1 2 3 q plus minus comma period` |

---

## §3 · Per story: observable outcome · shipped surface · AT nodes · representative / boundary / negative

**Reading key.** *Deliverable* = what the operator gets. *Surface* = the shipped thing the AT
drives and reads — **no AT below names an internal symbol in its assertion.** Every AT maps to
exactly **one** on-disk test node (C-18); "covered by X + Y" appears nowhere.

---

### 3.1 S-1 — the bar row is gone, the palette is not

**Deliverable:** ~3 reclaimed rows on every screen, with Ctrl+K unaffected.
**Surface:** `App.run_test(size=…)` → `action_show_screen(k)` for `k` in `SCREEN_CONTAINER_IDS` →
DOM query + real `pilot.press("ctrl+k")`.

**`AT-B78-01` — GATE. The row is absent everywhere.**

> **Given** the app mounted at 80×24 and at 120×30
> **When** each of the ten screens derived from `SCREEN_CONTAINER_IDS` is activated
> **Then** `app.query("#command_bar_row")` is empty on every one of them, **and** no widget with an
> id in `{find_input, cmdbar_goto_input, cmdbar_project, cmdbar_a2l, command_bar_prompt}` resolves
> anywhere in the app, **and** the total rendered height of `#command_bar_slot` is `0`.

*Quantified set (C-31):* the ten screens come from `SCREEN_CONTAINER_IDS`, the class attribute —
never a literal list, so a screen added later is covered without anyone remembering.
*Why the height clause:* deleting the row from `compose` while leaving `#command_bar` with a
`height: 3` rule would satisfy the query clauses and reclaim nothing.

**`AT-B78-02` — PIN (regression, not a gate). Ctrl+K survives.**

> **Given** each of the ten screens, with `app.set_focus(None)` **asserted** to have taken effect
> **When** `ctrl+k` is pressed **Then** `#command_palette` does not carry `hidden`, focus is
> `#palette_input`, and the **action set** of the rendered entries equals
> `{e.action for e in app._build_palette_entries()}` — a set derived from the producer, never
> hand-listed.

> ⚠️ **B-3 — the charter's "palette command set unchanged" control cannot be written as-is.**
> Executed: the set is **37 actions and contains `focus_find` and `focus_goto`**:
> ```
> visible_palette_actions() n=37   contains focus_find=True  focus_goto=True
> ['before_after_report','cycle_density','dump_a2l_json','focus_find','focus_goto','focus_palette',
>  'hex_page_next','hex_page_prev','load_file','load_project','open_settings_menu','open_workarea',
>  'operations_view','page_down_context','page_next_context','page_prev_context','page_up_context',
>  'patch_redo','patch_undo','quit','refresh_files','save_project','select_variant',
>  'show_help_panel','show_legend',"show_screen('a2l')",…,'unload_all','view_reports']
> ```
> If S-2 keeps `action_focus_find` / `action_focus_goto` and merely re-points them, the set stays at
> **37** and the control is a clean PIN. If S-4 deletes the actions, the set is **35** and
> "unchanged" is FALSE. **One decision, and the acceptance is written either way — I will not
> pick it silently.**

| case | input | expected |
|---|---|---|
| representative | 120×30, workspace | row absent, palette opens |
| boundary | 80×24 (the narrowest supported regime, footer at 78 cols) | identical verdict — this is where a reflow would hide a surviving row |
| negative | `crc_designer` (the screen the bar was never designed against) | identical verdict; nothing crashes |

---

### 3.2 S-2 — `/` and `g` act on the screen the operator is looking at

**Deliverable:** find/go-to reach the pane in front of you, or say why they can't.
**Surface:** real `pilot.press("slash")` / `("g")` after an **asserted** blur; the local `Input`
values; `#log_line_4`.

**`AT-B78-03` — GATE. Golden path, the three owning screens.**

> **Given** the app at 120×30, an image loaded, and for each screen `app.set_focus(None)` followed
> by `assert app.focused is None`
> **When** `/` then (after a second asserted blur) `g` is pressed on each screen in
> `OWNING = {k : the container of k holds an Input whose id contains 'search' or 'goto'}`
> **Then** `app.focused.id` is that screen's own search input, then its own go-to input.

*Executed pre-change:* `/ → find_input`, `g → cmdbar_goto_input` on **10 of 10** → **RED**.
*`OWNING` is computed from the tree in the test body* (C-31), and the test asserts
`len(OWNING) == 3` as a completeness guard — an implementation that empties the query would
otherwise satisfy a universal over nothing.

**`AT-B78-04` — GATE. The wrong-pane fix — the discriminating content assertion.**

> **Given** an image loaded (`mem_map` containing the ASCII run `BOOT`) and the **A2L** screen active
> **When** `/` is pressed, `BOOT` is typed through the focused input, and the search is submitted
> **Then** `#alt_search_input.value == "BOOT"` **and** `#search_input.value == ""` **and**
> `app._alt_goto_focus_address`-equivalent observable moves while the workspace one does not.
> Repeated with **MAC** active for `#mac_search_input`.

*Executed pre-change:* `active=a2l → {'search_input':'BOOT','alt_search_input':'','mac_search_input':''}`
→ **RED**. **The `== ""` clause is the load-bearing half**: an implementation that writes *both*
inputs would pass a presence-only predicate.

**`AT-B78-05` — GATE. The majority path — 7 of 10 screens.**

> **Given** each screen in `SCREEN_CONTAINER_IDS \ OWNING` (7 by measurement, derived not listed),
> blur asserted
> **When** `/` and `g` are pressed **Then** no exception is raised, `app.focused` is still `None`,
> **and** the log tail gained **exactly one** new line whose text names the absence — read at
> `#log_line_4`, **never `#status_text`** (Q-10), asserting both the new line's content **and**
> that `len(app.log_lines)` grew by exactly 1 per key.

*Executed pre-change:* focus moves to `find_input` on all ten and **zero** notice is emitted →
**RED**. *Exactly-one* is what separates "a notice" from "a notice per keystroke in a loop".

**`AT-B78-06` — GATE, mechanism `assumed — verify in target framework at Phase 3` (C-16).**

> **Given** the workspace screen with `/` having focused `#search_input`
> **When** `escape` is pressed **Then** `app.focused` is no longer that input and **is** the
> screen's declared pane widget (named in the LLR), on each of the three owning screens.

*Executed pre-change:* `after '/' focus=find_input → after 'escape' focus=find_input` → **RED**.
⚠️ **A Textual `Input` consumes `escape`; today it keeps focus.** The mechanism (an Input-scoped
binding, an `on_key`, or a screen-level priority binding) is unverified and **must not shadow the
palette's own `escape`-to-close**, which is live (`pilot.press("escape")` closes the palette in
§1.2's probe). Marked `assumed` per C-16 — the *outcome* still gets a pilot test.

**`TC-B78-02`** — routing keys on `_active_screen_key` (Phase-0 **P-10 FALSE**: nothing unmounts, so
all eight inputs resolve on every screen and a presence check cannot discriminate). White-box: with
A2L active, `#search_input` is still `query_one`-resolvable **and** the action still resolves the
A2L input.

| case | input | expected |
|---|---|---|
| representative | workspace, image loaded | `#search_input` focused, search hits |
| alternative | A2L / MAC | their own inputs, `AT-B78-04` |
| empty | no file loaded, `/` on workspace | focus moves, submit yields the existing "No file loaded." line — unchanged |
| boundary | the 7 non-owning screens | one notice each, no crash (`AT-B78-05`) |
| invalid | `g` then a malformed address (`0xZZ`) on a re-homed input | the existing parse-failure line, unchanged |
| negative | `/` while the palette is open | must not steal focus from `#palette_input` — **an arm `AT-B78-03` owes**, since the palette is the one place `/` is a literal character |

---

### 3.3 S-3 — the context labels, on BOTH surfaces (operator option C)

**Deliverable:** the operator can still see which project and which A2L are loaded.
**Surface:** `#loaded_panel` rendered text; `#workspace_status_bar` rendered text; both driven by a
real load/variant-switch, not by calling the refresh directly.

**`AT-B78-07` — GATE. Surface 1: the Loaded panel carries the PROJECT name.**

> **Given** a project `DemoProj` loaded with an image, a MAC and an A2L
> **When** the workspace screen renders **Then** the concatenated rendered text of `#loaded_panel`
> contains the project name, in the multi-variant display form when `N > 1`
> (`«project»:«variant» (i/N)`), and the plain name when `N == 1`.

> 🟠 **B-4 — the charter's A2L half of this clause is VACUOUS.** Executed: `#loaded_panel` already
> renders `'engine_v3.a2l  1 tag'`. An AT worded *"Project/A2L names appear in the Loaded panel"*
> is **GREEN on the pre-change tree** for the A2L half. **Drop the A2L clause from this node** —
> `AT-B78-08` carries A2L on the surface where it is genuinely RED.

**`AT-B78-08` — GATE. Surface 2: the persistent status bar carries BOTH, on all ten screens.**

> **Given** the same load **When** each of the ten screens is activated
> **Then** `#workspace_status_bar`'s rendered text contains **both** the project display string and
> the A2L filename, on every screen.

*Executed pre-change:* the bar renders `Ready.` + a progress bar + four log lines; neither name
present → **RED on both fields, on all ten screens**. **This is the node that closes P-13's
availability regression** (labels visible on 10 screens today, on 1 if only the Loaded panel is
used).

**`AT-B78-09` — GATE. The update PATH, not the initial paint (C-10 non-default value).**

> **Given** a two-variant project with variant 1 active **When** the operator switches to variant 2
> through the shipped affordance **Then** *both* surfaces move to variant 2's display string in the
> same refresh — asserted as `before != after` on each surface **and** `after` equal to the expected
> `«proj»:«v2» (2/2)` string computed in the test from the variant set.

**Labelled a PIN until the successor exists**, then discharged at the Inc gate by removing the
successor call from `update_project_labels` and confirming both surfaces go stale (record the
**substituted value**, not "drop the call").

> 🟠 **B-6 — the blast radius Phase 0 did not see.** `#cmdbar_project` is the observable for
> `_project_label()`:
> ```
> $ grep -c "_project_label(app" tests/test_tui_patch_variant.py tests/test_tui_variants.py
> tests/test_tui_patch_variant.py:9        tests/test_tui_variants.py:7
> tests/test_tui_variants.py:78   return str(bar.query_one("#cmdbar_project").content)
> tests/test_tui_patch_variant.py:85  return str(bar.query_one("#cmdbar_project").content)
> ```
> **16 live call sites across 2 files Phase 0's census never named** (it named
> `test_tui_commandbar.py`, `test_tui_directionb.py`, `test_loadfilescreen_input.py`). They guard
> the LLR-005.5 multi-variant display contract, including
> `test_single_s19_project_label_plain` (the `N == 1` back-compat pin). **They are re-pointed to the
> new surface, never deleted** — and S-3 therefore owes the *display form*, not just the name.

| case | input | expected |
|---|---|---|
| representative | project + A2L loaded | both surfaces carry both |
| alternative | A2L loaded with **no** project | project reads the `(none)` sentinel, A2L reads the filename |
| empty | nothing loaded | both surfaces show the `(none)` sentinels; nothing raises |
| boundary | `N == 1` variant set | plain project name (the `test_single_s19_project_label_plain` contract) |
| boundary | `N == 3`, active index 2 | `«proj»:«v2» (2/3)` |
| invalid | a filename containing `[red]evil[/].s19` | rendered verbatim; **C-17** — both new sinks are `markup=False` at construction or routed through `safe_text`. `TC-B78-03` |
| negative | unload all | both surfaces return to `(none)` |

---

### 3.4 S-4 — delete the dead surface, and prove the live one did not move

**Deliverable:** less code, identical behaviour.
**Surface (control):** the three screens' shipped **Buttons** (`#search_button`, `#alt_search_button`,
`#mac_search_button` and the three go-to buttons), plus the log tail and the focus-address fields.

**`AT-B78-10` — the control, as an output-then-consume pair (C-12).**

The charter's draft #4 says "byte-identical to pre-change". A test that *asserts today's values
inline* is a hand-written oracle; the C-12 shape is:

1. **`TC-B78-06`** — a **test-only commit ahead of every S-1…S-4 edit** drives the shipped buttons
   over a 9-case matrix (3 screens × {hit, miss, empty}) and **writes the payload to
   `tests/_artifacts/`** (with `-text` in `.gitattributes` if any byte-exact blob is stored).
2. **`AT-B78-10`** re-reads that file **from disk** and compares it to a fresh live capture. No shim
   across the seam; the producer is the shipped handler, the consumer is the unmodified AT.

Payload row = `(screen, query, goto, log_line_4_after_search, last_search_address,
log_line_4_after_goto, per-view goto focus address)`. Executed baseline:

```
$ python scratchpad/qa_p1_s4.py
  workspace  q='BOOT' goto='0x1010'  search->(…,4102)  goto->(…,4112)
  workspace  q='NOPE' goto='0xDEAD'  search->(…,None)  goto->(…,None)
  workspace  q=''     goto=''        search->(…,None)  goto->(…,None)
  a2l / mac  … identical triples, per-view goto focus fields set independently
  payload rows = 9
```

**`AT-B78-11` — GATE. The dead surface is actually gone.**

> **Then** an **AST census** (C-42 mechanic 5 — never a line regex, an implicitly-concatenated
> f-string is one template) of `s19_app/tui/command_bar.py` and `s19_app/tui/app.py` finds no
> definition of `CommandBar.Find`, `CommandBar.Goto`, `on_command_bar_find`, `on_command_bar_goto`,
> `CommandBar.focus_find`, `CommandBar.focus_goto`; **and** `styles.tcss` contains no selector for
> `#command_bar_row`, `#command_bar_prompt`, `#cmdbar_project`, `#cmdbar_a2l`, `#find_input`,
> `#cmdbar_goto_input` (Phase-0 P-8: `:55-102` is precisely the deletable span, `#command_palette`
> begins at `:104`).

*Executed pre-change:* every one of them exists → **RED**.

**Named live assertions that go RED by design and must be re-pointed, never deleted:**

| file:line | assertion | disposition |
|---|---|---|
| `test_tui_commandbar.py:169, 279` | `/` focuses `find_input` | re-point to the local input (`AT-B78-03`'s contract) |
| `test_tui_commandbar.py:369` | `g` focuses `cmdbar_goto_input` | re-point |
| `test_tui_commandbar.py:251-256, 419, 545` | typing/paste into the bar's inputs | port the *paste* intent to `#palette_input` (already covered by `test_universal_paste.py`) or to the local inputs |
| `test_tui_directionb.py:753-754` | the bar carries both inputs | **inverted** by `AT-B78-01` |
| `test_tui_directionb.py:897-898` | `#cmdbar_project` / `#cmdbar_a2l` content | re-point to the two new surfaces |
| `test_tui_directionb.py:6325-6326` | `/`→`find_input`, `g`→`cmdbar_goto_input` | re-point |
| `test_tui_variants.py` ×7, `test_tui_patch_variant.py` ×9 | `_project_label()` reads `#cmdbar_project` | **re-point the helper** (one line each file) — B-6 |
| `test_loadfilescreen_input.py:54` | comment citing `action_focus_goto` | inspection only |

---

### 3.5 S-5 — every run selectable

**Deliverable:** the operator can reach any differing run.
**Surface:** a real comparison rendered through `render_comparison`, then **real key presses and
real clicks** — never `.focus()`, never `_render_run_windows(i)`.

**`AT-B78-12` — GATE, keyboard-only.**

> **Given** a comparison of `R = 6` runs **When** the operator uses keyboard input only, starting
> from an asserted blur, through the documented entry key and the documented next/prev keys
> **Then** the set of run indices that become selected over the traversal equals `set(range(R))`,
> with `R` taken from the **fixture's own run list**, and every selection is observable as a
> distinct rendered run header.

**`AT-B78-13` — GATE, mouse-only.** `pilot.click` on each rendered run row (after `scroll_visible`
for rows past the viewport) selects that run; a run **beyond the viewport** is reached, so the
"list scrolls past the viewport" clause is not left to inspection.

**`AT-B78-14` — GATE, the selection is visible.** Exactly one row carries the selection marker and
its resolved style triple `(styles.background, styles.color, styles.text_style)` differs from every
unselected row's. *Fixture must hold ≥ 2 rows and the test must assert that* — with one row the
"differs from every unselected" clause is vacuously true (batch-77 §3.9's boundary, reused).

*Executed pre-change for all three:*
```
type(#diff_range_list) = Static   can_focus=False
ListView descendants under #diff_columns = 0
```
→ **RED**. The run list is one `Static` with newline-joined markup; there is no row to select,
click or highlight.

**`AT-B78-15` — GATE. The G-9 caps and the notice survive (the REWRITTEN predicate, §10).**

> **Given** a comparison of **200** runs (a fixture size, fixed independently of the constant under
> test, with a loud guard `assert 200 > AbDiffPanel.DISPLAY_MAX_RUNS`)
> **When** it is rendered **Then** the number of run rows actually painted is **strictly less than
> 200**, a `showing N of M` notice is present, `N` equals the painted row count and `M` equals 200.

*Nothing in this predicate reads `DISPLAY_MAX_RUNS`.* Executed: GREEN pre-change
(`rendered_rows=128 notice=('128','200')`), **RED** under both mutations (§4).

**`AT-B78-16` — GATE. The report stays complete, observed through the FILE (C-12).**

> **Given** the same 200-run comparison **When** Compare then Report are driven through the shipped
> buttons **Then** the **written report file, re-read from disk**, contains 200 run entries — i.e.
> strictly more than the panel painted.

*Labelled a **PIN** for now:* the report path is correct today (`_diff_last_result`, Q-16), so this
node is GREEN pre-change by construction. **Its falsifiability is discharged the other way** — at
the Inc gate, substitute `runs=panel._runs` into the report kwargs and confirm the file-level count
drops to the cap. That mutation must be executed and pasted, or the node is a file, not a control.

| case | input | expected |
|---|---|---|
| representative | 6 runs | all six reachable by keyboard and by mouse |
| boundary | exactly `DISPLAY_MAX_RUNS` runs | **no** notice (executed: `stored=128 notice=False`), all painted rows reachable |
| boundary | 200 runs | notice `(128, 200)`; report file 200 |
| empty | 0 runs | `'Runs: 0'`, `'Image A — no differing runs'` (executed), no crash, no selectable row |
| boundary | 1 run | selectable; the `AT-B78-14` style clause explicitly skipped with the ≥2 guard |
| negative | keys pressed with **no comparison yet** | no exception, no phantom selection |

> 🔴 **B-1 blocks `AT-B78-12`'s "documented next/prev keys" clause.** Executed census:
> ```
> o -> open_workarea   show=False   p -> load_project   show=False
> j -> dump_a2l_json   show=False   k -> show_legend    show=True
> UNBOUND among the proposed: ['down','enter','escape','n','tab','up']
> _PRE_BATCH_BINDINGS = (l,r,o,s,p,j,1,2,3,q,plus,minus,comma,period)   # j and p are FROZEN
> ```
> `j` and `p` are frozen into the literal guarded by live `TC-011`; `k` is a `show=True` footer chip
> (`Legend`). **Only `n` is free.** Two viable policies — (a) **widget-scoped bindings** on the run
> list, which shadow the non-priority App bindings while focus is on the list and leave `TC-011`
> green, or (b) App-level rebinding, which reddens `TC-011` and owes a supersession record.
> **Recommendation: (a), and drop `j`/`k` entirely** — `up`/`down` are unbound, unambiguous, and
> free. **A discriminating negative is owed either way:** with focus **off** the run list,
> `j`/`k`/`p` must still perform their App actions. I will not fabricate the expected outcome.

---

### 3.6 S-6 — the windows follow the selection, and breathe with the pane

**`AT-B78-17` — GATE.**

> **Given** a 6-run comparison **When** run `i ≠ 0` is selected **through the shipped selection
> surface** (key or click — never `_render_run_windows`) **Then** both windows' headers name run
> `i` with its range and kind, the first data row address of each window lies within
> `[start_i − ctx, start_i]`, and the rendered text differs from run 0's.

*Executed pre-change:* `_render_run_windows` has exactly **one** call site, `screens_directionb.py:6921`,
with the literal `0`; there is no selection surface at all → **RED**. (The mechanism works —
calling `_render_run_windows(3)` directly does change `#diff_hex_a` — which is precisely why the AT
must not call it.)

**`AT-B78-18` — GATE. The row count is derived from the pane, not from a constant.**

> **Given** the same comparison rendered at two terminal heights whose diff pane heights differ
> **Then** the emitted window row counts **differ**, and each is `≤` its pane's clipped visible
> height.

*Executed pre-change:* `(132,24) → 4 lines @ pane h=0` and `(132,60) → 4 lines @ pane h=23` →
**4 == 4 → RED**. The `≤ clipped height` clause is the half that kills a "just make it 40" fix.

> ⚠️ **B-7 · ordering.** At **120×30** the clipped pane height is **0** today. `AT-B78-18` cannot be
> run meaningfully at the shipped snapshot size until **S-8** lands. **S-8 must precede S-6/S-7 in
> the increment order**, and `AT-B78-18` must be written as a **relation** (rows track pane height)
> rather than an absolute count — because S-1 later adds ~3 rows to every screen and would move any
> absolute number.

**`TC-B78-04`** — `DISPLAY_CONTEXT_BYTES` retires or becomes a documented floor; assert the emitted
row count is no longer a pure function of the constant (feed two pane heights and one constant).

| case | input | expected |
|---|---|---|
| representative | select run 3 of 6 | both windows show run 3 |
| alternative | select run 0 after run 3 | returns to run 0's window |
| boundary | a run at the very start of the map (`start < ctx`) | window clamps at 0, no negative address |
| boundary | a run longer than the pane | window scrollable/pageable; the header still names the run |
| negative | selection with 0 runs | the "no differing runs" text stays; no crash |

---

### 3.7 S-7 — width regimes

**`AT-B78-19` — GATE. No wrapped hex row, in either regime.**

> **Given** a comparison rendered at **132×44** and at **120×44**
> **Then** for every hex window, `max(len(line) for line in emitted.splitlines()) ≤ window.size.width`
> (the **content** width, §1.5), and the window's clipped visible width equals its content width
> plus its measured chrome — i.e. the window is not merely un-wrapped but actually on screen.

*Executed pre-change:* widest emitted **79** vs content widths **30 @132** and **26 @120** →
**RED at both**, and at 80/130/170/190 too.

**`AT-B78-20`** — GATE **or dropped**: that the two regimes are observably *different* (some
declared layout property differs at 120 vs 132) and both satisfy `AT-B78-19`. **Labelled a PIN
pending the S-7 design pick** — without it, an implementation that always stacks passes
`AT-B78-19` while never building a second regime, which may be an acceptable simplification.
**That is a design call, not mine to take.**

**Feasibility, stated as arithmetic rather than hope (C-13 / C-29, both axes):**

| primitive | value | derivation |
|---|---|---|
| unwrapped diff row | **79** | `render_hex_view` emitted form, §1.5 |
| bordered box cost | **5** | border 2 + padding 2 + margin-right 1, §1.5 |
| `cols_content` | `W − rail − 6` | measured at 12 widths, §1.6 |
| rail | **4** for `W ≤ 119`, **22** for `W ≥ 120` | §1.6 |
| full-width window floor | **W ≥ 94** | `cols ≥ 84` |
| list sharing the row | `L ≤ cols_content − 84` → **8 @120, 20 @132, 58 @170** | §1.6 |

> 🔴 **B-2.** The chartered "12-col list" fallback is impossible at 120 (needs ≤ 8). "22-col list +
> full-width windows at ≥ ~130" is impossible at 132 (needs ≤ 20; first feasible at **W = 134**).
> **At 120 only list-as-overlay or auto-stack survive.** A rung whose recovery is smaller than the
> measured deficit is struck at draft time (C-13.1) — this is that strike, and it needs the
> operator's/architect's pick before `AT-B78-20` can be worded.

**Vertical axis (C-29's second axis, which the charter does not mention):** at 120×30 the diff pane
is **0 rows** today and 11 at 120×44. **S-7's acceptance must therefore be parametrised over
height as well as width**, or a 120×44-only AT will certify a regime the operator never sees at
120×30.

**`TC-B78-05`** — 80×24 is **below the measured floor of 94** and the charter scopes the fallback at
120. Assert bounded degradation there (no crash, the panel still renders *something*), **not**
unwrapped rows — an unachievable AT is a C-29 violation.

---

### 3.8 S-8 — the selection rows stop starving the results

**`AT-B78-21` — GATE.** The strongest RED in the batch.

> **Given** the diff screen at **120×30** and at **80×24**
> **Then** each of `#diff_select_row_a`, `#diff_select_row_b`, `#diff_action_row` has a clipped
> visible height of **1**, **and** `#diff_columns`'s clipped visible height is **≥ 3**, **and**
> `#diff_status` is visible (clipped height ≥ 1).

*Executed pre-change:*
```
120×30: rows h=3/3/3 ; #diff_status clipped=(92,0) ; #diff_columns clipped=(92,0)
80×24 : rows h=3/3/3 ; select_row_b clipped h=2    ; #diff_columns clipped=(70,0)
```
→ **RED, with the results area and the status line both entirely invisible.**

*Clipping is computed against `#screen_diff`'s region* — the painted layer, per C-32. A predicate
on `widget.region.height` alone reads `4` for `#diff_hex_a` at 120×30 and would ship this green.

**Control:** Compare/Report handlers unchanged — covered by the existing
`tests/test_tui_diff_screen.py` TC-021/TC-024 nodes (baseline `58 passed`, §1.10). **Check for
duplication before minting a new node** (C-18 asks for one node per AT, not for a new file).

| case | input | expected |
|---|---|---|
| representative | 120×30 | 1-row rows, results area ≥ 3 rows |
| boundary | 80×24 | same clause; this is where the overflow is worst today |
| boundary | 132×44 | rows still 1; results area gains the freed rows |
| negative | a long external path typed into `#diff_path_a` | the row stays 1 line (no re-expansion), text elides or scrolls |

---

### 3.9 S-9 — discoverability

**`AT-B78-22` — GATE if S-9 is IN; the charter forbids silent absorption.**

> **Then** the run-navigation keys are reachable through the `?` help panel and, if any is given
> `show=True`, `app.active_bindings` filtered on `.show and .enabled` still contains **all 14**
> pre-existing global chips at 80×24, none truncated.

*Executed today:* **14 chips** — `ctrl+k ctrl+d ctrl+l ctrl+s slash g q x k question_mark plus
minus comma period` — in a **78**-column Footer at 80×24, identical at every size measured.

> ⚠️ **C-28 / C-30.** Any new App-level `show=True` binding renders on every screen. S-1 already
> drifts all 29 goldens, so the *count* does not change — but the **sequencing** does:
> **recommendation, measured** — run **Lane 2 (S-5…S-9) FIRST** (each increment drifts the single
> `[diff-comfortable-120x30]` cell) and **Lane 1 (S-1…S-4) LAST** (one 29-cell regen). Running the
> bar deletion first blanket-`xfail`s the matrix from increment 1 and suppresses snapshot
> regression coverage for the whole of Lane 2 — the exact failure C-30 was written for.
> **Cheapest option: add no `show=True` binding at all** and let `?` carry S-9.

**Enter → open-in-hex** (the memmap `OpenInHexRequested` precedent) is a scope decision. If in, it
owes its own node asserting **exactly one** message posted **with the run's start address as
payload** — a count-only assertion is satisfied by a message carrying the wrong address.

---

## §4 · Falsifiability table — C-40 discharged by EXECUTION, per predicate

Command for M-1…M-4: `PYTHONDONTWRITEBYTECODE=1 python scratchpad/qa_p1_mut.py`;
for M-2b: `scratchpad/qa_p1_mut2.py`. **All mutations in-process; disk never written (§11).**

| AT | Declared subject | Subject in its own expression? | Reddening mutation (substituted VALUE) | Executed transcript | Verdict |
|---|---|:-:|---|---|---|
| `AT-B78-01` | the bar row is absent on every screen | ✅ queries `#command_bar_row` on all 10 | none needed | `#command_bar_row present=True height=3` | **DISCHARGED — RED today** |
| `AT-B78-02` | Ctrl+K opens the palette everywhere | ✅ presses `ctrl+k`, reads the palette | `S19TuiApp.action_focus_palette` body → `None` | `pre GREEN → mutated RED → restored GREEN` | **DISCHARGED (PIN)** |
| `AT-B78-03` | `/`·`g` focus the **active** screen's inputs | ✅ | none needed | `/ → find_input`, `g → cmdbar_goto_input`, 10/10 | **DISCHARGED — RED today** |
| `AT-B78-04` | the find acts on the pane in front of you | ✅ reads all three inputs, incl. the `== ""` clause | none needed | `a2l active → search_input='BOOT', alt_search_input=''` | **DISCHARGED — RED today** |
| `AT-B78-05` | 7 screens get exactly one notice, no crash | ✅ reads `#log_line_4` + `len(log_lines)` | none needed | focus moves on all 10; **zero** notices emitted | **DISCHARGED — RED today** |
| `AT-B78-06` | `Esc` returns focus to the pane | ✅ | none needed | `after '/' find_input → after 'escape' find_input` | **DISCHARGED — RED today**; mechanism `assumed` (C-16) |
| `AT-B78-07` | the **project** name is in the Loaded panel | ✅ | none needed | `'DemoProj' in loaded_panel → False` | **DISCHARGED — RED today** |
| — | *(the charter's A2L clause on that surface)* | ✅ | n/a | `'engine_v3.a2l' in loaded_panel → True` | ❌ **VACUOUS — dropped, B-4** |
| `AT-B78-08` | both names on the persistent status bar | ✅ | none needed | status bar = `Ready.` + progress + 4 log lines | **DISCHARGED — RED today** |
| `AT-B78-09` | the update PATH moves both surfaces | ✅ before≠after per surface | remove the successor call from `update_project_labels` | *feature does not exist yet* | **PIN — labelled**, discharge owed at the Inc gate |
| `AT-B78-10` | local search/goto behaviour is unchanged | ✅ 9-row payload digest | `app_mod.find_string_in_mem` → `lambda …: None` | `0a159da97fa81714 → 9d6c9b6aeadac6fa → 0a159da97fa81714` | **DISCHARGED (PIN)** |
| `AT-B78-11` | the dead symbols and CSS are gone | ✅ AST + selector census | none needed | all six symbols + all six selectors exist today | **DISCHARGED — RED today** |
| `AT-B78-12/13/14` | every run reachable + visibly selected | ✅ | none needed | `type=Static can_focus=False`; `ListView under #diff_columns = 0` | **DISCHARGED — RED today** |
| `AT-B78-15` | the display caps and their notice survive | ✅ **after rewrite** | (a) `DISPLAY_MAX_RUNS` **128 → 100000** · (b) `_render_run_list(total_runs=…)` → `len(self._runs)` | `GREEN → RED (rendered_rows=200, notice=None) → GREEN` and `GREEN → RED (notice=None) → GREEN` | **DISCHARGED — after the first form proved INERT (§10)** |
| `AT-B78-16` | the persisted report is complete | ✅ counts run rows in the **written file** | route the report off `panel._runs` | *correct today by construction* | **PIN — labelled**; mutation owed at the Inc gate |
| `AT-B78-17` | the windows follow the selection | ✅ headers + first row address | none needed | one call site, `:6921`, literal `0`; no selection surface | **DISCHARGED — RED today** |
| `AT-B78-18` | row count derives from pane height | ✅ compares two heights | none needed | `(132,24) 4 lines @h=0` vs `(132,60) 4 lines @h=23` | **DISCHARGED — RED today** |
| `AT-B78-19` | no hex row wraps | ✅ widest emitted vs content width | none needed | `79 > 18/26/29/30/49` at 80/120/130/132/190 | **DISCHARGED — RED today** |
| `AT-B78-20` | the two regimes are observably different | ⚠️ depends on the unpicked design | — | — | **PIN — labelled, blocked on B-2** |
| `AT-B78-21` | the results area is actually visible | ✅ clipped heights vs `#screen_diff` | none needed | `120×30: rows 3/3/3, #diff_columns clipped=(92,0)` | **DISCHARGED — RED today** |
| `AT-B78-22` | discoverability without displacing the 14 | ✅ `active_bindings` filtered | — | 14 chips / 78-col Footer measured | **PIN — blocked on the S-9 in/out decision** |

**Restore proof.** Every mutation was reverted in the same process and the predicate re-run to
GREEN (transcripts above). Additionally, `git diff --stat -- s19_app/ tests/` is **empty** after all
probes — see §11. A hash comparison alone would not prove this (a same-size in-place edit plus a
sub-second restore is invisible to `git status`), so the proof is *the predicate returning GREEN*
plus an empty source diff, per the batch-77 §8.5 rule.

---

## §5 · Validation method per requirement, with `TC-B78-nn` allocation

`demo` is **never** used for acceptance — it is perceptual and unfalsifiable. Where a mechanism is
unverified it is marked `assumed — verify in target framework at Phase 3` (C-16) and the *outcome*
still gets `test (pilot)`.

| Story | Deliverable observed | Method | Node | Notes |
|---|---|---|---|---|
| S-1 | the row is gone on 10 screens | **test (pilot)** | `AT-B78-01` | set from `SCREEN_CONTAINER_IDS` |
| S-1 | reclaimed height | **test (pilot)** | `TC-B78-01` | `#command_bar_slot` height 0; both sizes |
| S-1 | Ctrl+K unaffected | **test (pilot)** — *PIN* | `AT-B78-02` | palette action set from the producer |
| S-1 | palette entry set | **analysis + test** | `TC-B78-07` | **blocked on B-3** (37 vs 35) |
| S-2 | `/`·`g` reach the local inputs | **test (pilot), real presses** | `AT-B78-03` | blur asserted; **never `.focus()`** |
| S-2 | the wrong-pane fix | **test (pilot)** | `AT-B78-04` | the `== ""` clause is the gate |
| S-2 | the 7-screen notice | **test (pilot)** | `AT-B78-05` | read `#log_line_4`, **not** `#status_text` (B-8) |
| S-2 | `Esc` returns focus | **test (pilot)** | `AT-B78-06` | mechanism `assumed — verify at Phase 3` |
| S-2 | routing keys on the active screen | **test (white-box)** | `TC-B78-02` | P-10: presence cannot discriminate |
| S-3 | project name in the Loaded panel | **test (pilot)** | `AT-B78-07` | A2L clause dropped — **B-4** |
| S-3 | both names on the status bar, 10 screens | **test (pilot)** | `AT-B78-08` | closes the P-13 availability regression |
| S-3 | the update path moves both | **test (pilot)** | `AT-B78-09` | **PIN** until the successor exists |
| S-3 | C-17 markup safety on both new sinks | **inspection + test** | `TC-B78-03` | `markup=False` at construction / `safe_text` |
| S-4 | local search/goto unchanged | **test (pilot) + on-disk golden** | `AT-B78-10` + `TC-B78-06` | C-12; golden captured in its **own prior commit** |
| S-4 | the dead surface is gone | **test (AST/source census)** | `AT-B78-11` | C-42 mechanic 5 — never a line regex |
| S-5 | every run reachable, keyboard | **test (pilot), real presses** | `AT-B78-12` | **blocked on B-1** |
| S-5 | every run reachable, mouse | **test (pilot), real clicks** | `AT-B78-13` | incl. one row past the viewport |
| S-5 | selection visibly highlighted | **test (pilot), resolved CSS** | `AT-B78-14` | `≥ 2` rows asserted in the body |
| S-5 | display caps + notice | **test (pilot)** | `AT-B78-15` | rewritten; two mutations executed |
| S-5 | report completeness | **test (pilot) + file re-read** | `AT-B78-16` | **PIN**; C-12 through the written file |
| S-6 | windows follow the selection | **test (pilot)** | `AT-B78-17` | driven by key/click, never `_render_run_windows` |
| S-6 | rows derive from pane height | **test (pilot), two heights** | `AT-B78-18` | **depends on S-8** (B-7) |
| S-6 | `DISPLAY_CONTEXT_BYTES` retires/floors | **test (pilot)** | `TC-B78-04` | |
| S-7 | no wrapped hex row, both regimes | **test (pilot)** | `AT-B78-19` | parametrised over width **and** height |
| S-7 | the regimes actually differ | **test (pilot)** | `AT-B78-20` | **PIN — blocked on B-2** |
| S-7 | sub-floor degradation at 80×24 | **test (pilot)** | `TC-B78-05` | bounded, not unwrapped (C-29) |
| S-8 | rows are 1 line; results visible | **test (pilot), clipped geometry** | `AT-B78-21` | clip against `#screen_diff` (C-32) |
| S-9 | discoverability, no chip displacement | **test (pilot)** + **analysis** | `AT-B78-22` | **PIN — in/out decision** |
| cross | snapshot drift is as predicted | **test (snapshot)** | — | §7, per cell |
| cross | AT/TC ids pass G1–G7 | **test** | existing `tests/test_id_registry.py` | batch-scoped ids, `_meta.governed` §2.3 |

**`TC-B78-08`** — the increment-gate harness node: per-arm verdicts (CC-1). Every AT above is
parametrised over at least two size arms; **an exit code over parametrized tests hid 4 surviving
arms in batch-76**. Verdicts are reported **per resolved node id, per arm**.

---

## §6 · Bidirectional surface-reachability matrix (C-12 · C-18)

| Dimension | Driven through the shipped handler? | Observed through the shipped surface? | Node |
|---|---|---|---|
| **INPUTS** | | | |
| ten screens | ✅ `action_show_screen(k)` for `k ∈ SCREEN_CONTAINER_IDS` | — | 01·02·03·05·08 |
| real key press `/`, `g`, `escape`, `ctrl+k` | ✅ `pilot.press` after an **asserted** blur — never `.focus()` | — | 02·03·05·06 |
| real mouse click / scroll | ✅ `pilot.click` after `scroll_visible` | — | 13 |
| project loaded, `N == 1` variant | ✅ project load flow | — | 07·08 |
| project loaded, `N == 3` variants, active 2 | ✅ variant switch affordance | — | 09 |
| A2L attached, no project | ✅ load flow | — | 07·08 |
| nothing loaded | ✅ | — | 07·08 negative |
| image containing the ASCII run `BOOT` | ✅ `current_file.mem_map` + `update_hex_view` | — | 04·10 |
| search miss / empty query / malformed goto | ✅ the three shipped Buttons | — | 10 |
| comparison of 0 / 1 / 6 / 128 / 200 runs | ✅ `render_comparison` via the Compare button | — | 12·13·14·15·16 |
| terminal 80×24 / 120×30 / 120×44 / 132×44 | ✅ `run_test(size=…)` | — | 19·21 |
| pane heights that differ | ✅ two terminal heights | — | 18 |
| **OUTPUTS** | | | |
| `#command_bar_row` absence, app-wide | — | ✅ `query()` on each screen + `#command_bar_slot` height | 01 |
| palette open state + action set | — | ✅ `hidden` class, `#palette_input` focus, entry actions | 02 |
| focused widget identity | — | ✅ `app.focused.id` | 03·05·06 |
| the value each local Input receives | — | ✅ `#…search_input.value`, incl. the `== ""` clause | 04 |
| the notice | — | ✅ `#log_line_4` + `len(app.log_lines)` delta — **not `#status_text`** | 05 |
| Loaded-panel text | — | ✅ concatenated `Static.render()` under `#loaded_panel` | 07·09 |
| status-bar text | — | ✅ `#workspace_status_bar` children renders | 08·09 |
| search/goto behaviour payload | — | ✅ on-disk golden re-read, then compared to a live capture | 10 |
| symbol + CSS-selector absence | — | ✅ AST census + `styles.tcss` scan | 11 |
| run-row reachability set | — | ✅ selected-index set vs `range(R)` from the fixture | 12·13 |
| selection style | — | ✅ resolved `styles.(background,color,text_style)` triple | 14 |
| cap notice numbers | — | ✅ regex over the painted list text, cross-checked against the painted row count | 15 |
| **the written report file** | — | ✅ re-read from disk, run entries counted | 16 |
| window header + first row address | — | ✅ emitted text of `#diff_hex_a/b` | 17 |
| emitted row count vs pane height | — | ✅ `len(splitlines())` and clipped `region` height | 18 |
| widest emitted line vs content width | — | ✅ `max(len(line))` vs `widget.size.width` | 19·21 |
| clipped visible heights | — | ✅ region ∩ `#screen_diff` | 21 |
| footer chip set | — | ✅ `active_bindings` filtered `.show and .enabled` | 22 |

**Gap check.** Every input row appears in at least one output row's node and every output row is
driven by at least one input. **No orphan on either side.** The three rows I cannot close are
`AT-B78-12`'s key names (**B-1**), `AT-B78-20`'s regime property (**B-2**) and `AT-B78-22`'s in/out
(**S-9 decision**) — named as blockers, not papered over.

---

## §7 · Snapshot-drift expectation, reasoned PER CELL (C-22) + shared-chrome census (C-28)

Matrix re-derived, not carried: `ls tests/__snapshots__/test_tui_snapshot/ | wc -l` → **29**;
exactly **one** diff cell, `[diff-comfortable-120x30]`.

| Cell(s) | Increment | Drifts? | Reason (per cell, not a count) |
|---|---|---|---|
| `diff · comfortable · 120×30` | S-8 | ✅ **YES** | the three selection rows collapse 3 → 1 and the results area becomes visible; the golden currently renders **no** `Runs`/`Image A`/`Image B` (Q-12), so the delta is large |
| `diff · comfortable · 120×30` | S-5 / S-6 / S-7 | ⚠️ **YES, but only once S-8 has landed** | before S-8 the results area is clipped to 0 rows, so a list/window change paints **nothing** into this cell. **Do not read a zero diff as "the change didn't apply"** |
| all 28 non-diff cells | S-5…S-8 | ❌ **NO** | no other screen composes `AbDiffPanel` |
| **all 29 cells** | **S-1** | ✅ **YES, every one** | the command bar is app-level chrome: **29 of 29 render both `Project:` and `A2L:`** (executed, entity-decoded) |
| all 29 cells | S-3 | ⚠️ folded into S-1's regen | the labels move in the same increment window |
| all 29 cells | S-9 | ❌ **NO, if no `show=True` binding is added** | recommended; otherwise the Footer renders everywhere and the drift is width-dependent (14 chips already in 78 columns at 80×24) |

**C-30 sequencing, measured (B-7).** Lane 2's increments each drift **1** cell; S-1 drifts **29**.
**Sequence Lane 2 first and Lane 1 last** so 28 cells stay live as regression guards throughout
Lane 2 and the 29-cell drift collapses into a single canonical-CI regen. Mark cells
`xfail(strict=False)` as an **upper bound** per C-22 (the `_batch45_map_drift_marks` convention).
**Regenerate only in canonical CI** — textual 8.2.8 pin; local regen drifts unrelated baselines.

---

## §8 · Coverage default — covered, and cut *with a reason*

| Case class | Covered by | Notes |
|---|---|---|
| golden path | `AT-B78-01 03 07 08 12 17 19 21` | one per story |
| alternative valid path | `AT-B78-04` (A2L/MAC) · `AT-B78-13` (mouse vs keyboard) · S-3's "A2L, no project" | |
| empty / null / zero input | no file loaded (S-2, S-3) · 0 runs (executed: `'Runs: 0'`) · empty query (`AT-B78-10` row 3) | |
| boundary | 80×24 · 120×30 · **W = 94** (the measured unwrapped floor) · exactly `DISPLAY_MAX_RUNS` (executed: no notice) · 1 run · `N == 1` and `N == 3` variants · a run starting below the context window | the 120×30 **zero-height** regime is the real boundary and it is where the panel breaks |
| invalid / malformed input | malformed goto address (`0xZZ`) · a filename containing `[red]evil[/].s19` reaching the two new label sinks (`TC-B78-03`, C-17) | |
| unauthenticated / wrong role | **CUT, with reason.** Single-user local TUI; no auth surface exists anywhere in the app. | |
| network / error state | **CUT, with reason.** No network surface. The analogous failure — a render exception — is covered by `AT-B78-05`'s no-crash clause and by the full-suite gate. | |
| concurrency | **CUT, with reason.** Nothing in S-1…S-9 adds a worker. The one adjacent hazard, the diff **report** worker, is batch-68's and is untouched here; `AT-B78-16` drives it but asserts only its written output. | |
| regression on adjacent feature | §3.4's table: **8 named live assertions across 5 test files**, of which 16 call sites in 2 files were missed by the Phase-0 census (B-6). Baseline `58 passed in 70.10s` (full-file form). | |

---

## §9 · Validation strategy — how each gate is run

1. **C-34 is mandatory.** Every increment in this batch touches a TUI render module
   (`command_bar.py`, `app.py` compose, `screens_directionb.py`, `styles.tcss`). **Every gate runs
   the FULL `tests/test_tui_directionb.py`**, not a `-k` subset — the markup-safety source scans,
   the rail census, the footer binding census and the `_PRE_BATCH_BINDINGS` reachability guard
   (`TC-011`, directly implicated by **B-1**) all live there.
2. **Plus, at every gate:** `tests/test_tui_commandbar.py`, `tests/test_tui_diff_screen.py`,
   `tests/test_tui_variants.py`, `tests/test_tui_patch_variant.py` (the two B-6 files),
   `tests/test_loadfilescreen_input.py`, and the frozen dual guard (source **and**
   `_ENGINE_TEST_FILES`, C-27).
3. **C-25 — one complete run, owned by the orchestrator, read from its own output.** No verdict
   assembled from fragments.
4. **State the suite form with every ledger figure.** `tui-ci` runs `-m "not slow"` on PRs and the
   FULL suite on pushes (**21 slow tests**). **The FULL form runs before merge.**
5. **Mutation discharge is executed, not described.** Name the mutation, record the **substituted
   VALUE** (not the deleted operator), run it in isolation with `PYTHONDONTWRITEBYTECODE=1`,
   restore, and **prove the restore with a green run plus an empty `git diff`** — not with a hash.
6. **Per-arm verdicts (CC-1).** Report RED/GREEN per resolved node id per size arm.
   `AT-B78-19`/`AT-B78-21` have measurably different arms (120×30 vs 120×44 differ by 11 pane rows)
   and a single aggregate verdict would destroy exactly the information B-7 rests on.
7. **No test file is deleted in the same increment that changes the behaviour it guards.** The
   eight RED-by-design nodes in §3.4 are **re-pointed in place**.
8. **Test results in this document are BLANK** (§12). The only executed results above are
   pre-change probe transcripts and the four mutation discharges, each with its command.

---

## §10 · Self-caught defects in my own probes (recorded, not hidden — C-43)

1. **My first display-cap predicate was INERT, and it took a mutation to see it.**
   ```
   ### M-2 · GATE 'over the cap: notice shown AND only the cap stored'
      pre-mutation  -> GREEN
      MUTATION: AbDiffPanel.DISPLAY_MAX_RUNS 128 -> 100000
      post-mutation -> GREEN          <-- INERT
      restored      -> GREEN
   ```
   The predicate fed `DISPLAY_MAX_RUNS + 5` runs and asserted
   `f"showing {DISPLAY_MAX_RUNS} of {n}"` — **its expected value was read from the class under
   test**, so raising the cap moved the fixture *and* the expectation together. C-40 limb 2 in its
   purest form, landing in my own work. **Rewritten, not re-argued** (§3.5 `AT-B78-15`): a fixture
   size of 200 fixed independently, a loud `assert 200 > DISPLAY_MAX_RUNS` guard, and assertions
   only on the *painted* row count and the notice's own two numbers. The rewritten form reddens
   under two independent mutations (§4). **`C-39`'s "an AT quotes the constant, never its value"
   applies to the *guard*, not to the *expectation* — a cap AT that expects the constant certifies
   the constant, not the capping.**
2. **My first `active_bindings` reader crashed on `too many values to unpack (expected 3)`.** The
   binding tuple shape at this textual version is not the 3-tuple batch-77's document assumed. No
   conclusion was drawn from the crashed run; §1 and §3.9's chip census come from the corrected
   reader. Recorded because a probe that dies *after* printing partial results is exactly the shape
   that gets misread as complete.
3. **My first geometry probe read `region.width` and reported column widths 4 cells wider than
   Phase 0's**, which looked like a Phase-0 contradiction. It was not: Phase 0 read `size.width`
   (content). Caught by printing both. **A disagreement between two honest measurements is usually
   an undefined term** — here, "column width" — and §1.5 now states which of the two any figure is.
4. **Every focus reading in §1.2 is blur-asserted** because Phase-0 §7 recorded the `escape`-blur
   trap. My probes call `app.set_focus(None)` and `assert app.focused is None` before each press;
   without it the `g` readings would have been typed text, not dispatched bindings.

---

## §11 · Probe hygiene (C-46) — nothing was left applied

```
$ git status --short                 # after all six probes
 M .dev-flow/2026-08-06-batch-78/00-measurements.md
 M .dev-flow/2026-08-06-batch-78/PLAN.md
 M .dev-flow/state.json
?? build/  ?? prototypes$f.png  ?? prototypes/memmap2.*  ?? prototypes/out/

$ git diff --stat -- s19_app/ tests/
(empty)
```

**No source file was mutated on disk at any point** — every C-40 mutation was a monkeypatch on the
imported object inside a probe process, reverted in the same process, with the predicate re-run to
GREEN as proof. All probes ran with `PYTHONDONTWRITEBYTECODE=1`.

⚠️ **Reported as found, not swept (C-44):** `prototypes/memmap2.*` (11 untracked files) and
`prototypes/out/` appeared during this lane's work and belong to the **parallel session** active in
this repo. They pre-date nothing of mine and **I touched none of them.** The Phase-0 note listed a
different untracked set, which is itself evidence the other session is writing here — increment
ordering must assume concurrent writes.

---

## §12 · Test results — **left blank for the Phase-4 run / the human**

Per the evidence checklist this section is not filled by me. The only executed results in this
document are the pre-change probe transcripts (§1) and the four mutation discharges (§4), each of
which states its command.

| Node | Arm | Expected pre-change | Observed | Pass/Fail | Notes |
|---|---|---|---|---|---|
| `AT-B78-01` | 80×24 / 120×30 | RED | | | |
| `AT-B78-02` | all 10 screens | GREEN (PIN) | | | must stay GREEN after S-1 |
| `AT-B78-03` | 3 owning screens | RED | | | blur assertion present? |
| `AT-B78-04` | a2l / mac | RED | | | the `== ""` clause |
| `AT-B78-05` | 7 non-owning screens | RED | | | read `#log_line_4` |
| `AT-B78-06` | 3 owning screens | RED | | | mechanism verified at Phase 3? |
| `AT-B78-07` | workspace | RED (project) | | | A2L clause dropped |
| `AT-B78-08` | all 10 screens | RED (both fields) | | | |
| `AT-B78-09` | variant switch | PIN → GATE | | | mutation owed at the gate |
| `AT-B78-10` | 9-row payload | GREEN (PIN) | | | golden captured pre-change |
| `AT-B78-11` | AST + CSS | RED | | | |
| `AT-B78-12` | keyboard | RED | | | **blocked B-1** |
| `AT-B78-13` | mouse | RED | | | incl. off-viewport row |
| `AT-B78-14` | ≥ 2 rows | RED | | | |
| `AT-B78-15` | 200-run fixture | GREEN (PIN) | | | must stay GREEN; 2 mutations at the gate |
| `AT-B78-16` | 200-run report file | GREEN (PIN) | | | mutation owed |
| `AT-B78-17` | run 3 of 6 | RED | | | driven by key/click only |
| `AT-B78-18` | 132×24 vs 132×60 | RED (4 == 4) | | | **after S-8** |
| `AT-B78-19` | 120×44 / 132×44 | RED (79 > 26, 79 > 30) | | | |
| `AT-B78-20` | 120 vs 132 | PIN | | | **blocked B-2** |
| `AT-B78-21` | 80×24 / 120×30 | RED (clipped h = 0) | | | |
| `AT-B78-22` | 80×24 | PIN | | | **S-9 in/out** |
| `TC-B78-01…08` | per §5 | see §5 | | | |
| existing 8 named assertions (§3.4) | — | GREEN → RED by design | | | re-pointed, never deleted |
| FULL `tests/test_tui_directionb.py` | — | baseline, FULL form | | | C-34, every gate |
| 4-file adjacent baseline | — | `58 passed in 70.10s` (FULL-file form) | | | §1.10 |

---

## §13 · Evidence checklist (C-45 artifact requirement)

| # | Item | ✓/✗ | Evidence |
|---|---|:-:|---|
| 1 | Acceptance criteria use Given/When/Then | ✅ | §3.1–3.9, every `AT-B78-nn` |
| 2 | Test cases have explicit **Expected**, not vague "works" | ✅ | §3 predicates are executable expressions; §12 states an expected pre-change verdict per arm |
| 3 | Edge cases include empty, boundary, invalid, error | ✅ | §8 — with **written justifications** for the 3 cut classes; none cut silently |
| 4 | Regression checklist exists | ✅ | §3.4 (8 named assertions, 5 files, **2 of them missed by Phase 0**) + §9 gate list; baseline `58 passed` executed |
| 5 | Exit criteria stated | ✅ | §9 — FULL guard host per gate (C-34), FULL suite before merge, per-arm verdicts (CC-1), executed mutation per gate predicate |
| 6 | No real PII / secrets | ✅ | all fixtures are in-test builders under a temp dir; no client data, no credentials, no host paths in any predicate |
| 7 | Test-results section left **blank** | ✅ | §12 Observed/Pass-Fail columns empty; §1/§4 are pre-change probe transcripts, each with its command |
| 8 | **Layer B (black-box)** — every output-producing story observed through the SHIPPED surface with boundary + negative evidence | ✅ | §6 output half: 19 outputs, all observed post-`action_show_screen` / post-`render_comparison`; boundaries = the 0-row 120×30 regime, `W = 94`, exactly-cap runs; negatives = `AT-B78-04`'s `== ""`, `AT-B78-05`, the 0-run case, the `(none)` sentinels |
| 9 | **Bidirectional surface-reachability** | ✅ | §6 — 13 inputs driven, 19 outputs observed, no orphan either side; the 3 unclosable rows are named blockers (B-1, B-2, S-9), not papered over |
| 10 | **No unfilled template** | ✅ | Every id is minted (`AT-B78-01…22`, `TC-B78-01…08`); no `<...>` placeholder remains; the only empty cells are §12's, which are the human's to fill. **Four "Then" clauses are genuinely undecided (B-1, B-2, B-3, S-9) and are flagged as blockers rather than invented** — *if you cannot determine the expected behaviour, stop and ask.* |
| 11 | C-40 discharged per predicate | ✅ | §4 — subject named, presence in the expression checked, mutation named with its **substituted VALUE**, verdict **executed**, transcript pasted; 4 PINs explicitly labelled and **not** rounded up to discharged |
| 12 | C-46 — probe/mutation hygiene | ✅ | §11 — `git diff --stat -- s19_app/ tests/` empty; all mutations in-process; `PYTHONDONTWRITEBYTECODE=1` throughout |
| 13 | Charter draft acceptances re-derived, not copied | ✅ | draft #1 split into a gate + a PIN and its control found contradictory (**B-3**); draft #3 found half vacuous (**B-4**); draft #6/#7 re-derived against **79** cells, not 81 (**B-5**); drafts #9–#11 are Lane 3, out of scope |
