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
