# 01b — QA Strategy & Verification · batch-46 (Patch Editor responsive 3-column redesign)

> Phase-1 companion to `01-requirements.md` (architect, parallel). Defines the **validation
> method per requirement**, the **Layer B black-box acceptance discipline** (AT-063a/b/c,
> AT-064a/b — shared id scheme, registered identically in `01-requirements.md §3`), the
> **Layer A white-box TC plan**, the **geometry oracle spec (C-23)**, the **snapshot-drift
> prediction (C-22)**, and the **Phase-1 evidence checklist**.
> Language: English. Stack: Textual TUI + `pytest` + `pytest-textual-snapshot`.
> Batch is **LAYOUT-ONLY** (compose reparent + CSS; zero wiring/service change — PLAN.md:20-22,75-77).

## BLUF
Two black-box behaviors gate this batch, verified by **Textual Pilot geometry at both the
80×24 floor and the 120×30 comfortable size** (never `fr`-math — C-23):

1. **US-U8 / R-TUI-063** — the panel renders **3 windows**: **3 column-bands (3 distinct
   `region.x`) at ≥120**, **1 column-band / 3 ascending `region.y`-bands at <120**. Oracle:
   distinct-`x` / distinct-`y` **cardinality** over the 3 window-root containers.
2. **US-B2 / R-TUI-064** — **every named action button is reachable** (docked outside its
   window's scroll body, on-screen at scroll 0) **at both sizes**. Oracle: the prototype
   `_fully_visible` containment predicate (`patch_editor_layout.prototype.py:243-259`).

Plus a **reparent-safety AT (AT-063c)** — all load-bearing leaf ids resolve and one action per
window routes — mirroring the proven `test_tui_patch_layout.py::_drive_reparent_safety`
(:208-283). **Snapshot drift: exactly the 2 patch scaffold cells** (`patch-comfortable-80x24`,
`patch-comfortable-120x30`), `xfail(strict=False)`, canonical-CI regen post-merge. **C-28 NOT
triggered** (no `show=True` binding change).

---

## 1. Validation method per requirement

Requirement ids are the architect's (`01-requirements.md`); the amended 2×2 rows are the
before/after of §6.5. Method vocabulary: **Test** (automated pilot assertion) · **Demo** (manual
run) · **Inspection** (read source/CSS) · **Analysis** (reasoned, e.g. drift census).

| Req (proposed) | Statement (WHAT) | Method | Primary artifact | Rationale |
|---|---|---|---|---|
| **R-TUI-063** (HLR-U8) | Panel renders 3 windows: 3-col at ≥120, stacked at <120 via the `width-narrow` regime | **Test** (Pilot geometry, both regimes) | AT-063a (120×30) + AT-063b (80×24) | Rendered layout size/position — C-23 mandates pilot region reads; a responsive both-regimes claim cannot be verified by CSS inspection alone |
| **R-TUI-064** (HLR-B2) | Each window's action buttons dock outside its scroll region → reachable, no button below a fold, at 80×24 & 120×30 | **Test** (Pilot reachability, both regimes) | AT-064a (80×24) + AT-064b (120×30) | "Reachable" is an observed on-screen-at-scroll-0 property; `_fully_visible` is the exact oracle |
| **R-TUI-063/064 reparent-safety** (LLR compose) | All 14 leaf ids + 2 hidden-row ids resolve; one action per window routes to its observable effect after the reparent | **Test** (Pilot routing, both regimes) | AT-063c | The reparent is the risk (C-26); wiring is message/id-based, so id-resolvability + action-routing is the safety net |
| **LLR — window structure** | 3 window-root containers each own a scrollable body + a docked button-row sibling; TextArea/entries-table min-heights preserved; the 14+2 ids present | **Test** (white-box) + **Inspection** | TC-46.1 … TC-46.7 | Guards that a green geometry AT cannot be met by an accidental non-window layout |
| **R-TUI-030 / R-TUI-033 (amend)** | 2×2 four-pane contract **superseded** by the 3-window contract | **Analysis** (§6.5 before/after) + **Test** (superseded tests rewritten RED-first) | `01-requirements.md §6.5`; test-supersession census PLAN.md:97-113 | Locked requirement — never silently edited; C-26 reverse-grep at Phase 2/3 |
| **Snapshot lock (HLR-034 lineage)** | The 2 patch cells re-baseline to the 3-window render | **Test** (snapshot) + **Analysis** (C-22 per-cell drift) | `test_tui_snapshot.py` drift marks | Whole-panel relayout → both patch cells drift; regen is canonical-CI-only |

---

## 2. Layer B — black-box acceptance (the SHIPPED patch screen)

**Common driver** (proven idiom — `test_tui_patch_layout.py:71-96, 228-264`):
```python
app = S19TuiApp(base_dir=tmp_path)
async with app.run_test(size=size) as pilot:
    await pilot.pause()
    app.action_show_screen("patch")
    await pilot.pause()          # a 2nd pause for geometry settle (mirrors :496-497)
    ...                          # read real .region / .content_region
```
All five ATs drive the **real app** through `action_show_screen("patch")` — the shipped surface,
not a bare `PatchEditorPanel` mount. C-10: each AT observes a **changed/non-default** state
through that surface (a specific column cardinality, a specific reachable-set, an action's
observable effect), never a vacuous pass.

> **Window-id binding (Phase-1 coordination — see §7).** AT-063a/b/c bind to the **3 window-root
> container ids** created by the LLR compose reparent (PLAN.md:60-68,75-77). Proposed stable ids:
> `#patch_window_script` · `#patch_window_checks` · `#patch_window_json`. The architect finalizes
> the exact ids in `01-requirements.md`; the oracle below keys off the `_WINDOW_IDS` triple —
> whatever three the LLR designates. **This is the single hard dependency between 01b and 01.**

### AT-063a — 3 windows = 3 columns at 120×30  · [US-U8 wide · R-TUI-063]
- **Given** the app at `size=(120, 30)` (≥120 → `width-narrow` cleared, wide regime — app.py:4930).
- **When** the patch screen is shown.
- **Then** the 3 window-root containers each resolve once; their `region.x` set has **cardinality
  exactly 3** (3 side-by-side columns, ordered left→right); the 3 windows share the same top
  `region.y` band; no two window rectangles overlap; each window's `region.right ≤` panel
  `content_region.right` (no right-edge clip); each width `≤ host_content // 3` budget.
- **Inputs:** representative = default patch screen (empty document, hidden save-back rows).
  Boundary = 120 exactly (the breakpoint edge; app.py:4930 uses `< 120`, so 120 is wide).
  Negative = **RED counterfactual** below.
- **RED counterfactual (current 2×2 tree):** `#patch_editor_panel` is `grid-size: 2 4`
  (styles.tcss:801-809) → 4 `#patch_pane_*` occupy **2** distinct `region.x` (2 columns), plus the
  full-width `#patch_paste_row` — the distinct-`x`-cardinality-==3 assertion flips **RED** (gets 2).
- **C-10:** asserts a specific non-default geometry (3 columns), reachable only through the shipped
  screen at the wide size.

### AT-063b — 3 windows stacked at 80×24  · [US-U8 narrow · R-TUI-063]
- **Given** the app at `size=(80, 24)` (<120 → `width-narrow` set, stacked regime — app.py:4930-4936).
- **When** the patch screen is shown.
- **Then** the 3 window-root containers each resolve once; their `region.x` set has **cardinality
  exactly 1** (all share one left edge — a single full-width column); their `region.y` values form
  **3 strictly ascending, non-overlapping bands** (window N's bottom ≤ window N+1's top); each
  `region.right ≤` panel `content_region.right`.
- **Inputs:** representative = default patch screen at the 24-row floor. Boundary = 80×24 (the
  supported minimum). Negative = RED counterfactual below.
- **RED counterfactual (current 2×2 tree):** at 80×24 the four panes still form 2 columns
  (2 distinct `x`) — the cardinality-==1 assertion flips **RED**. Also, if a future CSS regression
  drops the `width-narrow` stack rule, the wide 3-col rule leaks to 80 and cardinality ≠ 1 → RED.
- **C-10:** asserts the stacked (single-column, 3-row) non-default geometry through the shipped
  narrow surface — the batch-45 map-reflow pattern (styles.tcss:626,649,731) applied to patch.

### AT-063c — reparent-safety: leaf ids resolve + one action per window routes  · [reparent]
- **Given** the app at **80×24 AND 120×30** (asserted at both — mirrors `test_at_033c_*_at_80/at_120`).
- **When** the patch screen is shown and one key action per window is exercised.
- **Then:**
  - **All 14 load-bearing leaf ids resolve to exactly one widget** (PLAN.md:87-91) — the census.
  - **Both hidden-row container ids resolve** (`#patch_saveback_row`, `#patch_before_after_row`;
    PLAN.md:92-93) — Python toggles `.hidden` on them, so they must exist post-reparent.
  - **PATCH SCRIPT window routes:** set `#patch_entry_address_input` + `#patch_entry_bytes_input`,
    `panel.request_action("add_entry")` → `#patch_doc_entries_table.row_count == before + 1`
    (the `_drive_reparent_safety` idiom, :238-244).
  - **CHECKS window routes:** `panel.request_action("run_checks")` → some `app.log_lines` line
    `startswith("Checks:")` (:252-256).
  - **JSON EDIT window routes:** `#patch_paste_parse_button` resolves and `#patch_edit_json_button`
    resolves (present + routable — the batch's JSON-column buttons).
  - **Variant/execute** (whichever window the LLR places it in): `#patch_execute_run_button`
    resolves (:259-261).
- **Inputs:** representative = add one entry + run checks. Negative = any leaf id missing or an
  action producing no observable effect → RED (the C-26 reparent-regression signal).
- **RED counterfactual:** a reparent that renames/drops a leaf id (e.g. `#patch_doc_entries_table`)
  or breaks the `request_action` routing → the census / routing assertion flips RED. This is the
  exact failure the batch-37 C-26 miss produced; AT-063c is the guard.
- **C-10:** observes state **change** (table grows, log line emitted) through the shipped surface —
  not mere presence-of-widget.

### AT-064a — every named action button reachable at 80×24  · [US-B2 floor · R-TUI-064]
- **Given** the app at `size=(80, 24)` (the tight floor — the B2 discriminator regime).
- **When** the patch screen is shown at scroll 0 (no scrolling performed).
- **Then** for **every named action button** (§ list below), `_fully_visible(app, button)` is
  **True** — i.e. the button's `region.area > 0`, is contained by `app.screen.region`, AND is
  contained by **every scrollable ancestor's `content_region`** (so a button docked outside the
  scroll body passes; a button scrolled below a pane fold fails). Assert `off == []` where
  `off = [b.id for b in named_buttons if not _fully_visible(app, b)]`.
- **Named action buttons (from the app read-across):** `patch_doc_load_button`,
  `patch_doc_refresh_button`, `patch_doc_validate_button`, `patch_doc_apply_button`,
  `patch_doc_save_button`, `patch_checks_run_button`, `patch_entry_add_button`,
  `patch_entry_edit_button`, `patch_entry_remove_button`, `patch_entry_edit_json_button`,
  `patch_undo_button`, `patch_redo_button`, `patch_paste_parse_button`, `patch_edit_json_button`,
  `patch_execute_run_button`, `patch_variant_info_button`, `patch_execute_scope_button`.
  (Save-back `Write`/`Don't-save`/`Width` + `before/after` buttons live in `.hidden` rows and are
  **excluded at scroll 0** unless the AT first reveals them — see the reveal note in §3.4.)
- **Inputs:** representative = default screen, no reveal (buttons that are always present).
  Boundary = 80×24 (worst-case vertical budget — 24 rows). Negative = RED counterfactual.
- **RED counterfactual (current 2×2 tree):** at 80×24 the top grid row is `1fr` (starved to ~1 row
  — styles.tcss:808), so `#patch_pane_entries` scrolls and its docked-less buttons
  (`patch_entry_add/edit/remove_button`, `patch_undo/redo_button`, `patch_entry_edit_json_button`)
  plus the change-file `Load/Refresh/Validate/Apply/Save` grid sit **below the pane fold** →
  `_fully_visible` False → `off` is **non-empty** → **RED**. That non-empty `off` set on the current
  tree is the literal B2 bug this AT fixes.
- **C-10:** the discriminator is on-screen-**at-scroll-0** containment through scrollable ancestors
  — the docked-vs-inside-scroll distinction, not mere existence.

### AT-064b — same reachability at 120×30  · [US-B2 wide · R-TUI-064]
- **Given** the app at `size=(120, 30)`.
- **When** the patch screen is shown at scroll 0.
- **Then** identical `off == []` assertion over the same named-button set.
- **Inputs / RED / C-10:** as AT-064a. The wide regime has more vertical room, but the 3-column
  split narrows each window; the docked-row must still not clip horizontally nor fall below a
  column's fold. RED counterfactual: the current tree's starved-column buttons remain below-fold.
- **Rationale for both sizes:** C-13/C-23 — a docked-row that fits at 120 can clip at 80 and vice
  versa (a wider column packs a longer button row that wraps/clips). Reachability is asserted at
  **both** regimes, never inferred from one.

---

## 3. Geometry oracle spec (C-23 — CRITICAL, the core discipline of this batch)

**Rule:** every geometry verdict is a **real Pilot `region` / `content_region` read at the target
size** — never CSS `fr`-fraction arithmetic (which cannot see ancestor caps; C-23 origin =
batch-36 F-01, fr-math was 4.5× off). Measure at **both** 80×24 and 120×30.

### 3.1 Capture helper (per size)
```python
def _drive_windows(tmp_path, size) -> dict:
    async def _run():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause(); app.action_show_screen("patch"); await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            counts = {wid: len(app.query(f"#{wid}")) for wid in _WINDOW_IDS}
            regions = {
                wid: (r.x, r.y, r.width, r.height)
                for wid in _WINDOW_IDS
                if counts[wid] == 1
                for r in (app.query_one(f"#{wid}").region,)
            }
            return {
                "counts": counts, "regions": regions,
                "host_content_w": panel.content_region.width,
                "panel_right": panel.region.right,
                "panel_content_right": panel.content_region.right,
            }
    return asyncio.run(_run())
```
`_WINDOW_IDS = (<script>, <checks>, <json>)` — the 3 window-root container ids from the LLR (§7).

### 3.2 AT-063a oracle (3-col @120×30) — exact assertions
1. `all(counts[w] == 1 for w in _WINDOW_IDS)` — each window resolves once.
2. `xs = {r[0] for r in regions.values()}; assert len(xs) == 3` — **exactly 3 distinct column x**.
3. `ys = {r[1] for r in regions.values()}; assert len(ys) == 1` — the 3 columns share one top band
   (rejects an L-shape / staircase).
4. **No overlap:** for every window pair, `not (ax < bx+bw and bx < ax+aw and ay < by+bh and by <
   ay+ah)`.
5. **Budget:** `for (x,_,w,_) in regions.values(): assert w <= host_content_w // 3` (per-column
   budget — the C-13 arithmetic, measured not assumed).
6. **No clip:** `for (x,_,w,_) ...: assert x + w <= panel_content_right`.

### 3.3 AT-063b oracle (stacked @80×24) — exact assertions
1. Each window resolves once (as above).
2. `xs = {r[0] ...}; assert len(xs) == 1` — **exactly 1 column x** (single full-width column).
3. **3 ascending non-overlapping y-bands:** sort windows by `region.y`; assert 3 distinct `y`, and
   for consecutive windows `prev.y + prev.h <= next.y` (stacked, no vertical overlap).
4. **No clip:** `x + w <= panel_content_right` for each.

> Distinct-`x`/`y` **cardinality** (not fixed x/y literals) is the robust oracle: it survives the
> architect's final gutter/padding choices and any wrapper-container id churn, while still flipping
> RED on the 2×2 tree (2 columns) and on a stack-rule regression (leak of the 3-col rule to 80).

### 3.4 Docked-button reachability oracle (AT-064a/b) — the B2 discriminator
**Predicate** (lift verbatim from `patch_editor_layout.prototype.py:243-259` into the test module):
```python
def _fully_visible(app, w) -> bool:
    r = w.region
    if r.area == 0:            # not laid out (hidden / inactive)
        return False
    if not app.screen.region.contains_region(r):
        return False
    node = w.parent
    while node is not None and node is not app.screen:
        if getattr(node, "is_scrollable", False):
            if not node.content_region.contains_region(r):
                return False   # scrolled below THIS ancestor's fold ⇒ not reachable
        node = node.parent
    return True
```
**Why this is the correct reachability oracle (not `screen.contains` alone):** a docked button-row
is a **sibling of** (not inside) its window's `VerticalScroll` body, so at scroll 0 its region lies
in the window's non-scrolling docked strip → it passes every scrollable-ancestor `content_region`
check. A button left **inside** the scroll body (the current 2×2 defect) sits below the pane's
`content_region.bottom` fold → the ancestor check fails → correctly reported unreachable.

**Assertion:** `off = [b.id for b in _named_action_buttons(app) if not _fully_visible(app, b)];
assert off == [], f"@{size}: buttons below fold / off-screen: {off}"`.

**`_named_action_buttons(app)`** = `app.query(Button)` filtered to the §2 named set (exclude the two
`.hidden`-row button groups at scroll 0). Scroll 0 is the tested state — no `pilot.scroll_*` call;
reachability must hold **without** scrolling (that is the whole point of docking).

**Optional reveal sub-check (recommended, not gate-blocking):** to also assert the save-back /
before-after docked buttons, the AT may first drive the reveal (remove `.hidden` on
`#patch_saveback_row` / `#patch_before_after_row` via the app's save-back path or directly), pause,
then re-run `_fully_visible` on `patch_saveback_confirm_button`, `patch_saveback_decline_button`,
`patch_saveback_width_button`, `patch_before_after_button`. Keep this a labeled secondary assertion
so a reveal-path change doesn't mask the primary always-present-button verdict.

### 3.5 Measurement invariants (write into the test docstrings)
- Two `pilot.pause()` after `action_show_screen` (geometry settle — the at058a idiom, :496-497).
- Read `.region` for on-screen rectangle; `.content_region` for the scrollable interior budget.
- A fully scrolled-out widget reports `region.area == 0` — `_fully_visible` treats that as False
  (correct); the 3.2/3.3 oracles guard with `counts[w] == 1` before dereferencing `.region`.
- Never assert a literal pixel/column x — assert **cardinality, ordering, containment, budget**.

---

## 4. Layer A — white-box TC plan

Each TC is a `pytest` assertion against the composed widget tree (`action_show_screen("patch")` +
`pilot.pause()`), traced to an HLR/LLR. These guard that a green geometry AT is met by the
**intended** structure, not an accidental layout (the batch-22 `test_tc_pane_styles_and_grid`
role, :285-327, superseded here).

| TC | Asserts (white-box) | Trace | Notes |
|---|---|---|---|
| **TC-46.1** | `#patch_editor_panel.styles.layout.name == "grid"` (or the LLR's chosen container layout) at 120×30 **and** its `width-narrow` variant switches to vertical stack at 80×24 | LLR panel-layout; R-TUI-063 | The responsive switch is CSS on `#workspace_body.width-narrow #patch_editor_panel` (styles.tcss precedent :222,:626) — assert the resolved `layout.name` differs across the two sizes |
| **TC-46.2** | Each of the 3 `_WINDOW_IDS` resolves once; each has a **scrollable body** descendant (`overflow_y == "auto"`) **and** a **docked button-row** descendant that is **not** inside that scrollable body | LLR window-structure; R-TUI-064 | The structural precondition for AT-064a/b: docked-row is a sibling of the scroll body |
| **TC-46.3** | Every one of the **14 leaf ids** resolves to exactly one widget; both **hidden-row ids** resolve | LLR compose reparent; PLAN.md:87-93 | The reparent census (static structural half of AT-063c) |
| **TC-46.4** | `#patch_doc_controls` still holds exactly `[load, refresh, validate, apply, save]` (5 buttons) and its section label reads "Patch script"; `#patch_checks_controls` holds `[run, help]`; labels "Patch script"/"Checks" present | LLR (preserve batch-35/37 census); C-26 | Preserves the `test_tc319_regroup_section_structure_census` contract (:351-441) across the reparent — the 5-button census MUST NOT churn |
| **TC-46.5** | `#patch_doc_entries_table.styles.height == 10` (min-height preserved) and `#patch_paste_text` keeps its fixed height (styles.tcss:976-980; :822-823 "fixed 8-line editor") | LLR min-height preservation | A reparent that drops the entries-table/TextArea height rule re-introduces the "1fr table pushes buttons off-screen" bug (styles.tcss:972-975) |
| **TC-46.6** | Each window's docked button-row container has an explicit non-`1fr` height (`auto` or fixed) so it does not steal the scroll body's viewport (the `#patch_variant_row` `height: auto` precedent, styles.tcss:842-852) | LLR docked-row sizing | Guards the C-23 "bare Container defaults to 1fr" trap called out in the CSS |
| **TC-46.7** | At 80×24, `app.query_one("#workspace_body").has_class("width-narrow")` is True; at 120×30 it is False (regime toggled) | R-TUI-063; app.py:4903-4936 | Confirms the responsive rule's driver fires at the boundary — the stacked/3-col switch depends on it |

> **TC ↔ AT relationship:** AT-063a/b/c + AT-064a/b are the WHAT (behavior through the shipped
> surface); TC-46.1…7 are the HOW (the mechanism that produces it). A geometry AT that passes with
> a broken TC (e.g. buttons inside the scroll body but the pane happens to be tall enough at the
> test size) is caught by TC-46.2 — the two layers together, not either alone, gate R-TUI-064.

---

## 5. Snapshot-drift prediction (C-22) + C-28 check

**Prediction: exactly 2 cells drift** — the whole-panel relayout re-renders the entire patch
screen at both scaffold sizes.

| Cell id | Drifts? | Per-cell reasoning |
|---|---|---|
| `patch-comfortable-80x24` | **YES** | The panel goes 2×2 grid → stacked 3-window; the entire visible tree re-lays out (columns, borders, docked rows). Whole-screen delta. |
| `patch-comfortable-120x30` | **YES** | The panel goes 2×2 grid → 3-column windows; whole-screen delta. |

- **These are the only patch snapshot cells.** `patch ∈ _SCAFFOLD_SCREENS`
  (`test_tui_snapshot.py:110`), and `patch ∈ _TWO_SIZE_SCAFFOLDS` (:538) → it renders at
  `comfortable` density only, at `80x24` + `120x30` (:541-559). No compact patch cell, no 160×40
  patch cell. **Upper bound = 2.**
- **No other screen renders the patch panel** → `workspace/a2l/mac/issues` (restyled) and
  `map/diff` (scaffold) cells do **not** drift from this batch.
- **Envelope:** add `_batch46_patch_drift_marks(screen, density, size_key)` returning
  `(pytest.mark.xfail(strict=False, reason="batch-46 patch 3-window relayout — regen in canonical
  CI post-merge"),)` for `screen == "patch"`, `()` otherwise; append it to the `_SCAFFOLD_CELLS`
  marks (:547-554) — mirrors the retired `_batch36/_batch38_drift_marks` pattern (:414-435).
  `strict=False` so a cell that (unexpectedly) does not drift still passes — an exact count would
  over-count per C-22.
- **Regen is canonical-CI-only** (`snapshot-regen.yml`, pinned `textual==8.2.8`) as a **post-merge
  follow-up PR** — **local regen FORBIDDEN** (drifts unrelated baselines;
  `reference_snapshot_regen_env`). The mark is retired in that follow-up once containment confirms
  exactly these 2 cells moved (the batch-44/45 pattern).

**C-28 check — NOT triggered.** No App-level `Binding(…, show=True)` and no shared-chrome
(Footer/Header/activity-rail) element is added, removed, or changed. The patch bindings
(`6`, `ctrl+z`, `ctrl+y`, `b`) are `show=False` (PLAN.md:121-122). The Footer/rail render
identically → wide-cell footer rows do **not** drift. Confirmed: no cross-screen census needed.

---

## 6. Reparent-safety detail (AT-063c) — the C-26 guard

Wiring is **message/id-based, not pane-id-based** (PLAN.md:83-86): the app resolves
`#patch_editor_panel` and calls `set_edit_json_enabled` / `set_undo_redo_enabled` /
`set_entry_edit_json_enabled` / `set_variants` / `set_change_files`, and reacts to
`ActionRequested` / `SaveBackDecision` messages. Therefore the reparent is safe **iff**:
1. every **leaf** id survives (the 14 — buttons, inputs, tables, selects the app queries), and
2. both **hidden-row container** ids survive (Python toggles `.hidden`), and
3. `panel.request_action(...)` still routes each window's key action to its observable effect.

AT-063c asserts all three at **both** 80×24 and 120×30 (structural resolvability is size-invariant,
but the routing pauses can behave differently under a starved layout, so both are run — the
`test_at_033c_*_at_80` / `_at_120` precedent, :267-283).

**Structural-only ids SAFE to retire/rename** (CSS + census tests only, no wiring):
`patch_pane_entries/changefile/checks/variant`, the `patch_editor_panel` grid, `patch_doc_file_row`
structure (PLAN.md:94-95). The **C-26 reverse-grep** (PLAN.md:111-113) must run at Phase 2/3 over:
`patch_editor_panel`, `patch_pane_entries`, `patch_pane_changefile`, `patch_pane_checks`,
`patch_pane_variant`, `patch_doc_file_row`, `patch_paste_row`, `patch_doc_controls`,
`patch_checks_controls` — every test asserting the retired 2×2 ids is superseded RED-first, not
left dangling (the batch-37 C-26 failure mode).

**Superseded tests (rewrite RED-first — PLAN.md:97-110):**
`test_tui_patch_layout.py::test_at_033a/033b` → AT-063a/b; `::test_tc_pane_styles_and_grid` →
TC-46.1/46.2/46.6; `::test_tc319_regroup_section_structure_census` → TC-46.4 (labels + 5-button
census PRESERVED); `::test_at058a_paste_editor_in_viewport_and_separated` → the JSON-EDIT-window
in-viewport check folded into AT-064a/b + TC-46.2; `test_tui_patch_editor_v2.py::test_at057a` /
`test_at058b` / `test_panel_composition` → update the preserved-id set to the window ids (every
**leaf** id stays — TC-46.3).

---

## 7. Phase-1 coordination / open questions (to the architect, `01-requirements.md`)

1. **[HARD DEPENDENCY] The 3 window-root container ids** (`_WINDOW_IDS`). AT-063a/b/c and the §3
   oracle bind to them. Proposed: `#patch_window_script` / `#patch_window_checks` /
   `#patch_window_json`. **Confirm the final ids and the window→content mapping** (PLAN.md:60-68).
   Note the open balance question (PLAN.md:66-68): if variant/execute moves out of PATCH SCRIPT, the
   AT-063c per-window routing action for that window updates accordingly (still `#patch_execute_run_button`).
2. **Docked-row count per window** at 80×24 stacked (C-23 pilot-measured — PLAN.md:68). If a window
   needs 2 docked rows, TC-46.2/46.6 must allow >1 docked-row sibling; the reachability oracle
   (AT-064a/b) already covers every button regardless of row count.
3. **Panel container layout token** for TC-46.1 — is the wide layout `grid` (3 columns) or
   `horizontal`? The oracle is layout-agnostic (cardinality of `region.x`), but TC-46.1 asserts the
   resolved `layout.name`, so name the intended token.
4. **Save-back / before-after button reachability** — confirm these docked buttons live inside one
   of the 3 windows (JSON EDIT per PLAN.md:65) so the §3.4 reveal sub-check targets the right window.

---

## 8. Phase-1 gate evidence checklist (each ✓/✗ + one-line evidence)

- [✓] **Acceptance criteria are behavioral (WHAT), black-box through the shipped surface.** AT-063a/b/c
  + AT-064a/b all drive `S19TuiApp.run_test` + `action_show_screen("patch")` (§2). Evidence: driver
  idiom `test_tui_patch_layout.py:71-96`.
- [✓] **Every AT names its RED counterfactual on the current 2×2 tree.** §2 each AT. Evidence:
  AT-063a RED = 2 distinct x from `grid-size: 2 4` (styles.tcss:801-809); AT-064a RED = non-empty
  `off` from starved `1fr` pane (styles.tcss:808).
- [✓] **Geometry established by pilot measurement at BOTH regimes (C-23).** §3 oracle, 80×24 +
  120×30, real `region`/`content_region`, no `fr`-math. Evidence: §3.1-3.4; C-23 `docs/engineering-rules.md:41-51`.
- [✓] **Reachability oracle is the containment-through-scrollable-ancestors predicate (B2 discriminator).**
  §3.4. Evidence: `_fully_visible` lifted from `patch_editor_layout.prototype.py:243-259`.
- [✓] **Reparent-safety AT covers all 14 leaf ids + 2 hidden-row ids + per-window routing.** AT-063c
  §6. Evidence: PLAN.md:87-93; routing idiom `test_tui_patch_layout.py:238-261`.
- [✓] **White-box TC plan traces each TC to an HLR/LLR and guards the mechanism.** §4 TC-46.1…7.
  Evidence: TC-46.2 (docked-row is scroll-body sibling) guards AT-064; TC-46.4 preserves the
  batch-35/37 census (`test_tui_snapshot`/`test_tc319` :351-441).
- [✓] **Snapshot drift is per-cell + upper-bounded under `strict=False` (C-22).** §5: exactly 2
  patch cells, `xfail(strict=False)`, canonical-CI regen post-merge. Evidence: `test_tui_snapshot.py:538,541-559`.
- [✓] **C-28 checked and NOT triggered.** §5. Evidence: patch bindings `show=False` (PLAN.md:121-122);
  no Footer/rail change.
- [✓] **Layer B observes non-default/changed state (C-10), no default-reliant pass.** §2: each AT
  asserts a specific cardinality / reachable-set / action effect. Evidence: AT-063c table-grows +
  log-line (`:242-256`).
- [✓] **Bidirectional surface-reachability:** input dimensions (both terminal widths — the responsive
  axis) AND deliverables (3-window layout, every action button) exercised through
  `action_show_screen("patch")`, not a bare panel mount. Evidence: §2 common driver.
- [✓] **No unfilled template — the phase actually ran.** All AT/TC ids concrete; the single
  placeholder (`_WINDOW_IDS`) is an explicit, flagged §7 dependency on the parallel architect
  artifact, not an unrun blank. Evidence: §7 item 1.
- [✓] **No real PII / secrets / client data.** All fixtures synthetic (`tmp_path`, empty patch
  document). Evidence: §2 driver uses `base_dir=tmp_path`.
- [✓] **Test-results sections left BLANK for the human/implementer.** This is a Phase-1 spec; no AT
  was executed (Phase 1 is spec-only per task). Evidence: no "Actual"/"Pass" column filled.
- [◻] **Layer B observed through the SHIPPED surface with boundary + negative evidence — VERIFIED
  BY EXECUTION.** Pending Phase 2/3 (tests not yet written/run; this is the spec). The design is
  execution-ready (proven driver + oracle idioms cited), but the ✓ on *observed* evidence is
  deferred to the implementation phase — flagged honestly, not claimed.

---

## 9. Assumptions & limits (fail-loud)
- **A1.** The 3-window container ids are assumed to exist as compose containers (PLAN.md:75-77
  "reparent all widgets into 3 window containers"). If the architect instead keeps 4 `#patch_pane_*`
  and only CSS-columns them, AT-063a/b re-key to the 3 designated **column-lead** containers and the
  distinct-`x` cardinality oracle is unchanged — but the `_WINDOW_IDS` list membership changes. §7.1
  must be resolved before Phase-2 test authoring.
- **A2.** I did **not** execute any AT — Phase 1 is spec-only (task constraint). Every "RED
  counterfactual" is reasoned from the current source (styles.tcss:801-809; the 2×2 `grid-size: 2 4`)
  and must be **confirmed RED-first** in Phase 2 before the green rewrite (the batch's own controls).
- **A3.** The `_fully_visible` predicate is a **prototype** helper (C-16: prototype IS Textual, same
  framework, so it transfers) — but the docked-row reachability numbers for the **full** widget set
  are `assumed — pilot-measure in Phase 3` at both regimes (PLAN.md:123-125; R2).
