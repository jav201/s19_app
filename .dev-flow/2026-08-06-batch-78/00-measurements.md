# batch-78 · Phase 0 — measurements & premise evaluation (C-43)

**BLUF — the charter's code facts survive execution almost intact, and the four things it does not
say are what change the work.** Twenty premises evaluated against `origin/main` @ `f6ff1d3`:
**16 TRUE · 1 FALSE · 3 INCOMPLETE**. Every one of the charter's nine cited `app.py` addresses is
**exact to the line** — unusual in this project and worth recording. What the charter omits is
where the cost is: the command bar is app-level chrome, so deleting its row drifts **all 29
snapshot goldens**; there are **10 screens, not 4**, so S-2's "no local find/goto" notice is the
majority path; `Esc` does not return focus today, so that S-2 clause is **net-new work**, not a
preserved behaviour; and re-homing the context labels to `#loaded_panel` **removes them from 9 of
10 screens**, because that panel is composed inside `#screen_workspace` only.

- **Repo:** `C:\Users\jjgh8\Github\s19_app` (the path in the launch prompt, `…\OneDrive\Documents\
  Github\s19_app`, retains only `.claude/` — the repo moved 2026-07-31).
- **Branch:** `claude/batch-78-cmdbar-a2bdiff`, cut off `origin/main` @ **`f6ff1d3`**.
- **Scope of this batch:** Lane 1 (S-1…S-4) + Lane 2 (S-5…S-9). Lane 3 (S-10…S-13) is chartered
  for a following session at this batch's close (operator ruling, kickoff).

---

## 1 · RC-1 base currency

| Check | Result |
|---|---|
| `git fetch origin` | done |
| `origin/main` tip | **`f6ff1d3`** — *batch-77 — land `obsidian_synced` (#188)*, 2026-08-06 |
| merge-base(HEAD, `origin/main`) | **`f6ff1d3`** = tip ✅ |
| Branch cut | `claude/batch-78-cmdbar-a2bdiff` @ `f6ff1d3` |
| Charter's stated base `061a97e` | ✅ **ancestor of `origin/main`**; exactly **1** commit since, and it touches `.dev-flow/state.json` only — **no source drift against the charter** |
| Working tree | clean except the charter's own untracked `prototypes/cmdbar_a2bdiff.*` set (to be committed in this PR) |
| **Reported as found, not swept (C-44)** | `prototypes/out/`, `build/`, and a stray `prototypes$f.png` (88 098 B, 2026-08-06 09:20) — a PowerShell `$f` interpolation artefact from the design session. All **pre-date this session**; none is touched here. |

**Batch number — derived from disk and origin, never from memory.** Highest on disk =
`.dev-flow/2026-08-01-batch-77`; `git ls-remote --heads origin` shows `batch-77-{closeout,
memmap-variant-a,sync-flag}` and **no `batch-78` anywhere**. Next free = **78**.
⚠️ `BACKLOG-CODE.md` already names *"batch-78"* in the `C-77-l` aggregation carry. **Operator
ruling at kickoff: this charter takes 78; the aggregation carry renumbers to batch-79** — the
backlog is edited in this batch's Phase 0 so the two never collide (this project has had two
numbering collisions already).

## 2 · Flow currency (C-45 PULL) — re-executed, not inherited

Manifest `~/.claude/docs/FLOW-VERSION.md` → `flow_version 2026.07.28-rev1`, `flow_hash
0127a2767ff11c8a`, controls **C-1…C-45**.

| Surface | Result |
|---|---|
| 11 control-bearing command + template files | **11 of 11 byte-exact** vs the manifest's per-file hashes |
| `skills/dev-flow-lessons/SKILL.md` | diverges — local `01d608bb14069613` / **641 lines** vs stamped `5c47db86ac2cf4ae` / 620. **Local is AHEAD**; the file's canonical home is `jav201/claude-skills` |
| Local aggregate | `896dcca61cf68d78` ≠ `0127a2767ff11c8a` |

**Verdict: MISMATCH, scoped and NON-BLOCKING.** The flow's *enforceable* surface — every command
and every template — is current; the only divergence is the lessons catalog, where local is ahead
of the stamp. The re-stamp item already lives in `BACKLOG-PROCESS.md` (Lane B) and is **not
duplicated here**. Re-executed per-file this batch rather than inherited from batch-77's identical
note, because *a citation of another document is not evidence* (C-43).

## 3 · Toolchain entry gate

`Python 3.14.4` · `pytest 8.4.2` · `ruff 0.15.17` — verified 2026-08-06.

---

## 4 · Premise table (C-43)

Tier: **A** = axiom (validated + verified) · **H** = hypothesis (this batch's own, or an
unverified design-batch output) · **P** = premise about the world (executed against disk).

### 4.1 Lane 1 — command bar

| # | Tier | Proposition (charter §1) | Verdict | Executed evidence |
|---|---|---|---|---|
| P-1 | P | `#find_input` / `#cmdbar_goto_input` live at `command_bar.py:139-149` | ✅ TRUE | `compose()` spans `:139-154`; the two inputs at `:144-149`, inside `#command_bar_row` (`:140`). Labels `#cmdbar_project`/`#cmdbar_a2l` at `:142-143`; `#command_palette` at `:150` — **a sibling of the row, not a child**, so the row deletes without touching the palette |
| P-2 | P | Workspace owns `#search_input`/`#goto_input` + buttons at `app.py:1992-1998` | ✅ TRUE | `#search_input` `:1993`, `#search_button` `:1994`, `#goto_input` `:1995`, `#goto_button` `:1996`, container `#hex_controls` `:1997` |
| P-3 | P | They route to `_handle_search`/`_handle_goto` at `app.py:11358 / 11448 / 11518` | ✅ TRUE | button dispatch `:11358`; `def _handle_search` `:11448`; `def _handle_goto` `:11518` — **all three exact** |
| P-4 | P | A2L owns `alt_*` (`app.py:5151-5156`), MAC owns `mac_*` (`app.py:5229-5234`) | ✅ TRUE | `alt_search_input` `:5152`, `alt_goto_input` `:5155`; `mac_search_input` `:5230`, `mac_goto_input` `:5233` |
| P-5 | P | The bar's find *"calls `_handle_search` unchanged"* (`app.py:6010-6023`) | ✅ TRUE | `on_command_bar_find` `:5995`; its body is exactly `self.query_one("#search_input", Input).value = event.query` then `self._handle_search()`. `on_command_bar_goto` `:6025` is the same shape onto `#goto_input`. **The "pure duplicate" claim is confirmed at the source, not merely in the docstring** |
| P-6 | P | `/`·`g` focus the BAR inputs today (`action_focus_find/goto`, `app.py:5980/5984`) | ✅ TRUE | Defs exact at `:5980`/`:5984`. **Executed** (`p0_probe_cmdbar2.py`): on all five screens probed, `/` → `find_input`, `g` → `cmdbar_goto_input` |
| P-7 | P | The bar hosts the Ctrl+K palette and the Project/A2L labels (`set_context_labels`, called `app.py:11351`) | ✅ TRUE | `set_context_labels` `command_bar.py:216`; **exactly one** call site, `app.py:11351`, inside `update_project_labels` (`:11290`) |
| P-8 | P | Bar CSS is `styles.tcss:55-102` | ✅ TRUE | Block comment `:55-60`; `#command_bar` `:61`, `#command_bar_row` `:66`, `#command_bar_prompt` `:73`, `#cmdbar_project` `:80`, `#cmdbar_a2l` `:88`, `#find_input` `:96`, `#cmdbar_goto_input` `:100-102`. `#command_palette` begins at `:104` — **`:55-102` is precisely the deletable span** |
| P-9 | P | Deleting the bar row reclaims ~3 rows app-wide | ✅ TRUE | Executed at 132×44: `#command_bar` height **3**, `#command_bar_row` region height **3** |
| **P-10** | **P** | *(charter implies)* screens carry their own find/goto, so `/` can be re-homed by asking which inputs exist | ❌ **FALSE** | `action_show_screen` (`app.py:5817-5824`) swaps the **`hidden` class**; **no `push_screen`, nothing unmounts**. Executed: all eight inputs (`search_input`, `goto_input`, `alt_*`, `mac_*`, `find_input`, `cmdbar_goto_input`) are `query_one`-resolvable on **every** screen. **A presence check cannot discriminate — S-2 must key on `_active_screen_key`** (`app.py:5817`) |
| **P-11** | **P** | *(charter S-2)* *"`Esc` from a focused input returns focus to the pane"* — stated as a property to keep | ⚠️ **INCOMPLETE** | Executed: `/` → `find_input`, then `escape` → focus **stays** `find_input`. **The behaviour does not exist today**; S-2's Esc clause is net-new work and is RED on the current tree |
| **P-12** | **P** | *(charter S-2)* *"On screens with no local find/goto: one status-line notice"* — an edge case | ⚠️ **INCOMPLETE** | `SCREEN_CONTAINER_IDS` has **10** entries: workspace, a2l, mac, map, issues, patch, diff, flow, checks, crc_designer. Only **3** own find/goto inputs. **The notice path is 7 of 10 — the majority case, not an edge** |
| **P-13** | **P** | *(charter S-3)* *"Project/A2L names surface in the Loaded panel"* — a re-home | ⚠️ **INCOMPLETE** | `LoadedArtifactsPanel()` is composed at `app.py:2037`, inside `id="screen_workspace"` (`:2040`). Today the labels are visible on **all 10** screens (app-level chrome); in `#loaded_panel` they are visible on **1**. The charter's "re-home" is measurably a **re-home plus an availability reduction on 9 of 10 screens** — a scope consequence, surfaced rather than absorbed |

### 4.2 Lane 2 — A2B diff

| # | Tier | Proposition | Verdict | Executed evidence |
|---|---|---|---|---|
| P-14 | P | `#diff_range_list` is a `Static` | ✅ TRUE | `screens_directionb.py:6766` — `Static("Runs", id="diff_range_list", markup=True)` |
| P-15 | P | Only `_render_run_windows(0)` is ever called; runs 1..N unreachable | ✅ TRUE | `def _render_run_windows` `:7003`; **exactly one** call site, `:6921`, with the literal `0` |
| P-16 | P | Its docstring cites an `on_data_table_row_selected` handler that does not exist | ✅ TRUE | Cited `:7019`; **zero** definitions of that name anywhere in the module |
| P-17 | P | `DISPLAY_CONTEXT_BYTES = 16` | ✅ TRUE | `:6627`. Siblings: `DISPLAY_MAX_RUNS = 128` `:6623`, `DISPLAY_MAX_TOTAL_BYTES = 2_097_152` `:6624` (the G-9 caps S-5 must preserve) |
| P-18 | P | `#diff_columns` is three rigid `1fr` columns | ✅ TRUE | Container `screens_directionb.py:6769`; CSS `styles.tcss:1481-1490` — `#diff_range_list, #diff_hex_a, #diff_hex_b { width: 1fr; … }`. `#diff_columns` itself `:1152` |
| P-19 | H | **Measured width ceiling**: hex+ASCII row = 81 cells; variant A clean ≥ ~130, ascii gutter wraps at 120; shipped 3-column wraps below ~170 | ⏳ **UNVERIFIED — hypothesis, re-derive at Phase 1** | Produced by the design session's prototype on this box (textual 8.2.8). Not re-executed at Phase 0. It is the number S-7's regime pick rests on, so per *a carried number is re-derived, not copied* it is **re-derived at Phase 1 before it may bound an acceptance** (C-39) |

### 4.3 Cross-cutting

| # | Tier | Proposition | Verdict | Executed evidence |
|---|---|---|---|---|
| P-20 | A | `_PRE_BATCH_BINDINGS` (the frozen keymap guard) does **not** pin `/` or `g`, so re-homing them cannot trip it | ✅ TRUE | `tests/test_tui_directionb.py:6058-6074` — the frozen literal is 14 tuples: `l r o s p j 1 2 3 q plus minus comma period`. **Neither `slash` nor `g` appears.** Verified, not assumed (batch-77 checked the same guard for its own keys) |

---

## 5 · Blast radius (C-26 reverse-grep of every symbol the batch touches)

Run over the whole `tests/` tree, `.pyc` excluded.

**Lane 1** — `command_bar_row`, `find_input`, `cmdbar_goto_input`, `cmdbar_project`, `cmdbar_a2l`,
`set_context_labels`, `focus_find`, `focus_goto`, `CommandBar.Find/.Goto`, `action_focus_find/goto`:

- `tests/test_tui_commandbar.py` · `tests/test_tui_directionb.py` · `tests/test_loadfilescreen_input.py`
- `command_bar_row`, `set_context_labels`, `focus_find`, `action_focus_find` have **0** test
  references — i.e. the bar row itself and the label-update path are **currently unguarded**.
  This is exactly why S-3 demands *a discriminating test, not a vacuous "label exists"*.

**Lane 2** — `diff_range_list`, `diff_hex_a/b`, `diff_columns`, `DISPLAY_CONTEXT_BYTES`,
`_render_run_windows`, `_render_run_list`, `DISPLAY_MAX_RUNS`:

- `tests/test_tui_diff_screen.py` · `tests/test_tui_diff_compare_realpath.py` ·
  `tests/test_tui_directionb.py`
- `diff_columns`, `DISPLAY_CONTEXT_BYTES`, `_render_run_windows`, `_render_run_list` have **0**
  test references.

**Shared file, both lanes: `tests/test_tui_directionb.py`.** Increment ordering must not let the
two lanes collide in it.

### ⚠️ The dominant mechanical cost — 29 snapshot goldens, all of them

`tests/__snapshots__/test_tui_snapshot/` holds **29 SVGs**, every one a full-screen
`test_tc016s_density_layout_snapshot[<screen>-<density>-<W>x<H>]` across 7 screens × 2 densities ×
3 sizes. **The command bar is app-level chrome present in all 29.** Deleting `#command_bar_row`
therefore drifts **29 of 29** — the largest single constraint on Lane 1, and regen is
**CI-only** (textual==8.2.8 pin; local regen drifts unrelated baselines).

Note for S-7: the **only** shipped diff snapshot is `[diff-comfortable-120x30]` — i.e. the shipped
golden sits exactly in the **120-col fallback regime** the charter requires, not in variant A's
≥130 regime.

---

## 6 · Already-shipped check (RC-1 per story)

None of S-1…S-9 is satisfied on `origin/main`: the bar row, both bar inputs, the `Static`
run list, the single `_render_run_windows(0)` call and the three `1fr` columns are all present at
`f6ff1d3` as measured above. **No story is reclassified `SATISFIED-EXTERNALLY`.**

---

## 7 · Self-caught probe defect (recorded, not hidden)

My first focus probe (`p0_probe_cmdbar.py`) pressed `escape` to blur between key presses and
reported **`g` → `find_input` on every screen** — which would have been a false finding that
`action_focus_goto` is broken. An `Input` keeps focus through `escape`, so the `g` was **typed
into the input** rather than dispatched as a binding. Revision 2 calls `app.set_focus(None)` and
**asserts the blur took effect** before each press; corrected result: `g` → `cmdbar_goto_input`,
everywhere. Same class as batch-77's four self-caught lane probes: *executing the wrong thing
returns a plausible number.* The blur assertion is the guard, and it belongs in any Phase-3
keyboard AT.

A second, smaller one: the wrong-pane probe read `.renderable` off `#hex_view` and got
`AttributeError` — the finding did not depend on it and no conclusion was drawn from it.

---

## 8 · The one measurement that reframes S-1/S-2

**Executed** (`p0_probe_wrongpane.py`): with **A2L the active screen**, posting the shipped
`CommandBar.Find("BOOT")` message writes `"BOOT"` into **`#search_input`** — the *workspace*
input — and leaves `alt_search_input` empty.

| widget | before | after |
|---|---|---|
| `search_input` (workspace) | `''` | **`'BOOT'`** ← |
| `alt_search_input` (A2L) | `''` | `''` |
| `mac_search_input` (MAC) | `''` | `''` |

Because nothing unmounts (P-10), the bar's find/goto **always** act on the workspace pane
regardless of the visible screen. So the charter's framing — *the bar inputs are pure duplicates* —
is true but understated: they are duplicates **that silently act on the wrong pane on 9 of the 10
screens**. Lane 1's value is therefore not only ~3 reclaimed rows; **S-2 fixes a latent
wrong-pane defect**, and that gives the story an acceptance that is genuinely RED today rather
than a cosmetic one.

*(Probed with no file loaded, so `_handle_search` bails at "No file loaded." before searching.
The routing is proven by the input write, which happens first and unconditionally. A
loaded-image arm belongs in the Phase-1 acceptance, not here.)*

---

## 9 · P-19 RE-DERIVED at Phase 1 (C-39) — the ceiling holds, two other figures do not

The charter's width figures came from the design prototype. *A carried number is re-derived, not
copied.* Executed against the shipped renderer and the shipped layout on this tree.

### 9.1 The hex row — charter EXACT

```
81  '  0x00001000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |................|'
81  '  0x00001010  10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F  |................|'
max line width = 81 cells over 5 rows
```

`render_hex_view_text` (`s19_app/tui/hexview.py:360`) over a 64-byte map. **A full hex+ASCII row
is exactly 81 cells.** ✅ The charter's headline number is confirmed on this tree.

### 9.2 Shipped layout geometry — measured, `#screen_diff` active

| terminal | `#rail_slot` | `#diff_columns` | `#diff_range_list` | `#diff_hex_a` | `#diff_hex_b` |
|---|---|---|---|---|---|
| 80×24 | **4** | 70 | 18 | 18 | 19 |
| 120×30 | 22 | 92 | 25 | 26 | 26 |
| 132×44 | 22 | 104 | 29 | 30 | 30 |
| 170×44 | 22 | 142 | 42 | 42 | 43 |
| 190×44 | 22 | 162 | 49 | 49 | 49 |

**❌ The rail is 22 columns, not 24** (charter §1). It collapses to **4** at 80×24 — a second
regime the charter does not mention.

**Chrome cost per column box, derived from the residual:** at 132, `29 + 30 + 30 = 89` against a
`#diff_columns` of `104`; the 15-cell difference is `3 × margin-right 1` + `3 × border 2` +
`3 × padding 2`. So `.size.width` is the **content** width and **each bordered column costs 5
cells** (2 border + 2 padding + 1 margin). This is the constant S-7's regime arithmetic needs, and
it is nowhere in the charter.

### 9.3 ❌ The shipped 3-column diff does not wrap "below ~170" — it wraps at EVERY width

An unwrapped hex row needs `81 + 5 = 86` outer cells. Three of them need `258`, i.e. a
`#diff_columns` of 258 → a terminal of roughly **282 columns**. Measured, the widest sampled
terminal (190×44) gives each column **49** content cells — **60 % of one row**. The charter's
*"the shipped 3-column diff wraps below ~170"* implies a width at which it stops wrapping; **there
is no such width at any realistic terminal size.** The defect is worse than chartered, which
strengthens Lane 2 rather than weakening it.

### 9.4 What this hands Phase 1 for S-7 — primitives, not a design

- unwrapped hex row = **81** content cells; one bordered box = **+5**
- `#diff_columns` content width = terminal − 22 (rail) − 6 (shell chrome), measured above
- **A full-width single window fits an unwrapped row from 120 up** (92 − 5 = 87 ≥ 81) ✅
- **A window sitting BESIDE a 22-col list does not, even at 132** (104 − 27 = 77 < 81) ❌

**Therefore the 120-vs-130 regime split is not about the window — it is about whether the run list
shares the row with it.** That is a materially different framing from the charter's, it is derived
from measured constants rather than from the prototype's screenshots, and S-7's option pick must be
made against it. The prototype used class-scoped selectors and inline styles for the contested
boxes, so **its chrome cost is not necessarily the shipped 5** — Phase 1 owns re-deriving that for
whichever regime it picks.

---

## 10 · ⚠️ CORRECTIONS to §5 and §9 — two of my own errors, found by the Phase-1 QA lane

Recorded as corrections beside the original rather than by rewriting it, so the error is auditable
(the batch-77 convention).

### 10.1 ❌ §9.1 measured the WRONG PRODUCER — the diff panel's row is 79 cells, not 81

§9.1 measured `render_hex_view_text`. **The A2B diff panel does not call it.** `_render_run_windows`
imports and calls **`render_hex_view`** (`screens_directionb.py:7021`, used at `:7030-7031`); the
module's own docstring says so at `:6606` and `:7016`. Both renderers exist —
`hexview.py:330` (`render_hex_view`) and `:360` (`render_hex_view_text`). Executed:

```
render_hex_view      (DIFF PANEL) max = 79 cells
    '0x00001000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |................|'
render_hex_view_text (WORKSPACE)  max = 81 cells
    '  0x00001000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |................|'
```

**The difference is exactly the two-space left indent `render_hex_view_text` adds.** So `81` is
correct *for the workspace hex pane* — which is what the charter's §1 sentence is about — and
**`79` is the number every Lane-2 / S-7 threshold must use.**

**This is the C-32 wrong-layer trap, and I documented it in §7 of this very file before committing
it in §9.** The same shape as batch-77's recorded irony. It survived my own review because
executing the wrong producer returns a *plausible* number: 81 is off by 2, not by an order of
magnitude, so nothing looked wrong. Found by the QA lane, verified independently here.

### 10.2 The chrome constant is confirmed at 5 — and it settles a disagreement between the two derivations

The QA lane derived the side-by-side bound as `L ≤ C − 84`; §9.4's accounting gives `L ≤ C − 89`.
The two differ because the QA form charges chrome to the **window box only** and treats the run
list as costing its content width alone. **Settled by measurement, not by argument:** at 132 the
three shipped columns measure `29 + 30 + 30 = 89` content against a `#diff_columns` of `104`, so
chrome is `15` across three boxes = **exactly 5 per box, the last one included**. The list box pays
it too.

**Canonical bound: a run list of content width `L` may share a row with an unwrapped diff window
only where `L + 5 + 79 + 5 ≤ C`, i.e. `L ≤ C − 89`.**

| terminal | `C` (`#diff_columns`) | max list width `L` beside an unwrapped window |
|---|---|---|
| 120×30 | 92 | **3** |
| 132×44 | 104 | **15** |
| 170×44 | 142 | 53 |

**Both of the QA lane's conclusions survive the tighter bound, which is why this is a precision fix
and not a reversal:** a 12-col list at 120 is impossible (`12 > 3`, and `12 > 8` on their looser
form too), and the chartered *"22-col list + full-width windows at ≥ ~130"* does not work at 132
either (`22 > 15`; `22 > 20` on theirs). The first width at which a 22-col list fits beside an
unwrapped window is `C ≥ 111` → **a terminal of ≈ 139**, not 130 and not the charter's cited 132
capture. ⚠️ **The two derivations must not both survive into the requirements** — Phase 2 settles
on this measured one, and the S-7 option pick is re-checked against it.

### 10.3 ❌ §5's Lane-1 census file list is incomplete — the counts and the list came from different patterns

§5 reports `cmdbar_project → 9 files` in its per-symbol counts, then lists files produced by a
**narrower** grep that omitted `cmdbar_project` and `cmdbar_a2l` entirely. The list is therefore
missing real observers. Re-derived:

```
tests/test_tui_directionb.py       cmdbar_* : 2 lines    _project_label : 2
tests/test_tui_patch_variant.py    cmdbar_* : 2 lines    _project_label : 10
tests/test_tui_variants.py         cmdbar_* : 1 line     _project_label : 9
tests/test_tui_app.py              cmdbar_* : 0          _project_label : 3
```

**Four files, not three** — the QA lane named two of the missing ones and did not name
`tests/test_tui_app.py`; neither its figures nor my original list are the derived set, so the table
above is the one to use. `#cmdbar_project` is the **observable** for `_project_label()`, which
guards the LLR-005.5 multi-variant display form — so **S-3 owes the display *form*, not merely the
name**, and the Lane-1 blast radius is four test files.

**The generalisable lesson, which is the reusable part:** §5's counts and its file list were
produced by two different greps and were never reconciled, so the document contradicted itself in
adjacent lines. *A census whose count and whose enumeration come from different patterns has
measured neither.*
