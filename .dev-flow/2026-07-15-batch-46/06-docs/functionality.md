# Functionality — Patch Editor responsive three-window layout (batch-46)

> **Audience:** technical stakeholders (engineering, QA, reviewers) who need to understand *what the
> shipped change does* and *why the acceptance shape it has*.
> **Purpose:** understand — not install/operate.
> **Scope class:** LAYOUT-ONLY. No behavior, wiring, key-binding, or message-contract change. Frozen-engine
> diff = 0, `app.py` diff = 0.
> **Closes:** field-audit **B2** (action buttons trapped below a starved grid-cell fold) and **U8** (weak
> visual gestalt — labeled sections read as one crowded surface).
> **Source:** `s19_app/tui/screens_directionb.py::PatchEditorPanel.compose` (`:2272-2588`) +
> `s19_app/tui/styles.tcss` (`:785-891`). Language: English.

---

## 1. BLUF

The Patch Editor is now **three bordered windows — PATCH SCRIPT · CHECKS · JSON EDIT** — instead of a
four-pane 2×2 grid. Each window is a constant title, a scrollable body, and its action buttons **docked
outside that body** so a button is never trapped below a scroll fold. The windows sit **3-across on a wide
terminal (≥120 cols)** and **stack vertically on a narrow one (<120 cols)**. The responsive switch is
**pure CSS** reusing the app's existing `width-narrow` regime — `app.py` is untouched (0 diff), and there
is no new Python breakpoint, resize handler, or `TabbedContent`. Every leaf widget id and the message-based
app wiring are preserved, so nothing the operator does behaves differently — only the arrangement changes.

---

## 2. What the three windows contain

The compose tree yields exactly three window `Container`s (`.patch-window`), each `title Label` +
`VerticalScroll` body + docked button-row sibling(s):

| Window (id) | Body content (scrollable) | Docked rows (outside the body) |
|-------------|---------------------------|--------------------------------|
| **PATCH SCRIPT** `#patch_win_script` | entries `DataTable` + empty-state + entry inputs (addr/value/bytes) + change-file `Select` + path input + patch-script label | (a) Add / Edit / Remove / Edit-JSON `#patch_doc_entry_buttons`; (b) Undo / Redo `#patch_history_controls`; (c) Load / Refresh / Validate / Apply / Save `#patch_doc_controls`; (d) variant group `#patch_variant_row` **above** execute group `#patch_execute_row` (kept in `#patch_pane_variant`) |
| **CHECKS** `#patch_win_checks` | issue count + issues + checks status + results | Run-checks + help `#patch_checks_controls` |
| **JSON EDIT** `#patch_win_json` | paste `CappedTextArea` (`#patch_paste_text`) | Parse-pasted + Edit-JSON `#patch_paste_controls`; revealed save-back `#patch_saveback_row`; revealed before/after `#patch_before_after_row` |

PATCH SCRIPT is the **heaviest** window (it carries the most rows and the most docked buttons), which is
why it drives the tightest geometry budget (§4).

---

## 3. Responsive behavior — one CSS toggle, two regimes

The layout switches on the **existing** App-level `width-narrow` class (toggled on `#workspace_body` at
`width < 120` by `_apply_width_regime`/`on_resize`, `app.py:4903-4940`) — the same mechanism batch-45 used
for the memory-map reflow (`styles.tcss:626`). No new code: `app.py` diff = 0.

- **Wide (≥120 cols)** — `#patch_editor_panel { layout: horizontal }` (`styles.tcss:800-807`). The three
  windows sit side by side. The ratio is **asymmetric** `grid-columns`-style via `#patch_win_script
  { width: 2fr }` vs `1fr`/`1fr` for the other two (`:831-833`), keeping the heavy PATCH SCRIPT column
  wider — a **pilot-measured** design call (FOLD-2), not an fr-guess. Each window is full panel height; its
  body scrolls internally.
- **Narrow (<120, incl. the 80×24 floor)** — `#workspace_body.width-narrow #patch_editor_panel
  { layout: vertical; overflow-y: auto }` (`:809-813`) and `#workspace_body.width-narrow .patch-window
  { width: 100%; height: auto }` (`:835-840`). The windows grow to content and stack; the **panel itself**
  provides the scroll.

Reverting is deleting the CSS rule — a declarative, low-risk one-way-door. The only coupling is the panel's
`#workspace_body` ancestry (if a future refactor moves the panel out, the selector root breaks).

---

## 4. Docked-button reachability model (the B2 fix, and the FOLD-8 amendment)

**Structural fix.** In the old 2×2 grid, the change-file and entry buttons lived *inside* a starved `1fr`
grid cell and fell below its scroll fold — unreachable. The fix: every action-button row is composed as a
**sibling of** its window's `VerticalScroll` body, not a descendant (`.patch-docked-row` /
`.patch-docked-group`, `styles.tcss:863-870`). The body is `height: auto` so it never holds an inner fold
that could trap a docked row; the **window** (wide) or the **panel** (narrow) provides the scroll that
reaches everything. Docked button-rows also **wrap** (`layout: grid; grid-size: 2`, `:872-887`) so no
button clips past a narrow window edge (a horizontally-clipped button is unreachable by vertical scroll
alone).

**Reachability contract — regime-dependent (FOLD-8).** Phase-3 pilot measurement (real app, current tree)
found the patch panel gets only **70w × 5h @80×24** and **92w × 11h @120×30** of viewport — a *deferred
app-start-geometry starvation* in the frozen `app.py` layout. With 17 named buttons + an 8-line paste
editor + a 10-line entries table, **no** CSS restructure can show all buttons at scroll 0 in a 5-row floor.
The requirement — not the implementation — was physically infeasible, so it was refined (iterate-to-refine,
operator-approved):

- **@120×30** — TARGET remains **strict all-visible** (`off == []` at scroll 0).
- **@80×24 floor** — **reachable-under-scroll**: each named button becomes fully visible once its window is
  scrolled into the panel viewport, **and none is trapped below an inner-body fold**. A button reachable
  *only* by scrolling a nested inner body = FAIL. This is exactly the real B2 defect being fixed (buttons
  trapped below a fold with no scroll able to reach them). No D-3 fallback rung (consolidate rows / relocate
  variant / key-binding) was needed — the deficit is bound by the frozen 5-row viewport, not by docked-row
  count. The load-bearing fix that recovered the last two execute buttons from *unreachable* → *reachable*
  was `#patch_variant_select_row { height: 3 }` (a Select-overlay phantom auto-height).

The reachability oracle (`_fully_visible`, `test_tui_patch_layout.py:144-164`) requires the button region
to be non-empty, screen-contained, and contained by every *real* scrollable ancestor's `content_region`;
the structural `trapped` check (docked row must not be a `VerticalScroll` descendant) is the B2
discriminator that a scroll cannot mask.

---

## 5. Reparent-safety (FOLD-1) — nothing behaves differently

The restructure moves widget sub-trees between containers but **preserves every leaf widget id** and the
message-based app wiring. The app resolves the panel by `#patch_editor_panel` and drives it through messages
and method calls — it never queries the pane-container ids — so a container restructure is wiring-safe as
long as leaf ids and the message contract survive (verified: grep of `app.py` for the pane ids = 0 hits).

Per FOLD-1, the four batch-22 grouping containers `#patch_pane_entries`, `#patch_pane_changefile`,
`#patch_pane_variant`, and `#patch_doc_file_row` are **preserved intact as non-scrolling groups**
(`height: auto`; scroll lives on the window body) — not retired. This keeps `test_tui_patch_variant.py`
(variant-above-execute order, TC-035.2) and `test_tui_directionb.py` (`#patch_pane_entries
.patch-section-title` selector) **green unchanged** — both files stay out of the diff entirely. AT-063c
asserts a 46-id `_MUST_PRESERVE` census **plus** one observable route per window (add_entry grows the table,
run_checks emits a `Checks:` log line, parse_paste populates the change document) — proving the wiring, not
merely that ids resolve.

---

## 6. C-17 markup-safety — preserved across the move

The two file-derived-text sinks keep `markup=False` after being reparented into the new windows:
`#patch_checks_status` (`screens_directionb.py:2485`) and `#patch_doc_issues` (`:2476`) — so an untrusted
`{kind!r}` reason or issue string is never markup-interpreted. The paste cell stays a `CappedTextArea`
(64 KiB cap, `#patch_paste_text` `:2534`), and **window titles are CONSTANT strings** — never a
`border_title` carrying file-derived text (C-17 / F3). `test_tui_patch_editor_v2.py::test_at058b` (FOLD-6)
asserts all three invariants survive the reparent.

---

## 7. What this is *not*

- Not a behavior change — patch/check/variant/save-back logic, action routing, key bindings, and the panel
  message contract are untouched.
- Not a new widget or breakpoint — no `TabbedContent`, no resize handler, no Python breakpoint (`app.py`
  diff = 0).
- Not an engine change — parser → range/validation layers untouched (frozen diff = 0).
- No new persistence, network, or external-state surface; no permission or auth surface. Privacy unchanged.

---

## 8. Assumptions · risks · residual

- **Assumption (verified):** app wiring is message/id-based, not pane-container-based (A1) — the reparent is
  therefore wiring-safe.
- **Residual degradation (operator-approved, not a defect):** at wide 120×30 most buttons still require a
  scroll to reach (`off != []` at scroll 0), bounded by the app's frozen ~11-row patch viewport — an
  out-of-scope app-geometry carry, recorded as the FOLD-8 reachable-under-scroll contract.
- **Risk (bounded):** the two `patch-comfortable-{80x24,120x30}` SVG snapshot cells drift with the relayout;
  they ride `_batch46_patch_drift_marks` (`xfail(strict=False)`, C-22) and regenerate in canonical CI
  post-merge (local regen forbidden). They flip to Automated after regen.
- **Reversibility note:** the CSS reuse depends on the panel staying a `#workspace_body` descendant.
- **Next step:** post-merge canonical-CI snapshot regen to retire the two xfail marks.
