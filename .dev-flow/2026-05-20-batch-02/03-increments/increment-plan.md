# Increment Plan — s19_app — Batch batch-02-direction-b-restyle

**Phase:** 3 — Implementation
**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Source contract:** [`01-requirements.md`](../01-requirements.md) — 14 US / 15 HLR / 38 LLR / 38 active TC
**Phase 2 review:** [`02-review.md`](../02-review.md) — `pass` (0 blockers); CV-01..CV-05 cosmetic items folded into increment 1.

---

## 1. Planning constraints applied

- **≤ 5 files per increment** (code + tests counted). `app.py` (5133 lines) is the orchestration hub and is touched in almost every increment — it counts as **one file** each time it appears.
- **Each increment ships a runnable `s19tui`.** No increment leaves the app un-launchable; rail/screen routing degrades gracefully until the screen it points to lands.
- **Dependency order:** theme tokens + keymap proposal → app shell + screen routing → activity rail → command bar → restyled screens (Workspace, A2L, MAC, Issues) → modals → new scaffolds (Memory Map, Patch Editor, A↔B Diff, Bookmarks) → dedicated no-regression / snapshot test increments.
- **No abstraction, helper, widget, or feature** that is not directly derivable from an approved LLR.
- **Engine freeze (C-1 / LLR-014.1):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, and the parse/validate/extract functions of `tui/a2l.py` / `tui/mac.py` are NOT touched by any increment. `render_a2l_view` / `a2l_render.py` are view-layer and re-stylable (A-01 resolved).
- **No new runtime dependency (C-2).** `pytest-textual-snapshot` is dev-only optional, added in increment 1's `pyproject.toml` edit.

### Key structural facts that shaped the split

- The TUI stylesheet is **inline** (`S19TuiApp.CSS`, app.py:416-694). There is **no `.tcss` file today.** Increment 1 extracts the theme into a `styles.tcss` (`CSS_PATH`) so TC-012 / TC-013(b) can parse a stylesheet file and so theme work does not churn `app.py` on every later increment. The five `sev-*` rules move into it verbatim.
- The current view-toggle mechanism is **CSS-class `.hidden` toggling** on three sibling containers (`#main_layout` / `#alt_layout` / `#mac_layout`), driven by `action_view_main/alt/mac`. LLR-002.1 explicitly says to **reuse this show/hide mechanism** — Direction B keeps eight sibling screen containers and toggles `.hidden`, rather than adopting `push_screen` (the handoff sketch uses `push_screen`, but that is a structural reference only, and `push_screen` would break the persistent command bar / footer and the existing `query_one` test harness).
- `BINDINGS` today: `l r o s p j 1 2 3 q + - comma period`. The `1/2/3` keys are remapped from view-toggle to rail items (intended supersession, A-02/Q-04). The new bindings (`ctrl+k`, `/`, `g`, `ctrl+d`, `4`-`8`) are additive.
- New widget classes (`Rail`, `CommandBar`, scaffold screen widgets) live in **new modules under `s19_app/tui/`** to keep `app.py` from growing unboundedly, consistent with the PROJECT_RULES.md decomposition note. Each new module re-exports nothing the engine needs.

---

## 2. Increment sequence — summary

| # | Title | LLRs | One-line scope |
|---|-------|------|----------------|
| 1 | Theme tokens, `styles.tcss` extraction, keymap proposal + req-doc cosmetics (CV-01..CV-05) | LLR-005.1, LLR-005.2 | Extract inline CSS into `styles.tcss`, define the Calm Dark token set + five `sev-*` rules, declare `pytest-textual-snapshot` dev-only, **propose the OQ-8 per-screen keymap** (TC-030 dependency), fold in CV-01..CV-05 doc fixes. |
| 2 | App shell + 8-container screen routing + density toggle | LLR-002.1, LLR-002.3, LLR-006.1, LLR-006.2, LLR-007.1 (layout skeleton) | Replace the 3-layout toggle with an 8-screen `.hidden`-toggled body, a routing action, the empty-state panel, and the `Ctrl+D` density class cycle (default Comfortable). |
| 3 | Activity rail widget + rail navigation wiring | LLR-001.1, LLR-001.2, LLR-001.3 | New `rail.py` Rail/RailItem widgets — 8 ordered items, keys `1`-`8`, Unicode glyphs + ASCII fallback, single active marker; wired to increment 2's routing. |
| 4 | Command bar widget + key bindings + input-focus suppression | LLR-003.1, LLR-003.2, LLR-003.3, LLR-004.1–004.6, LLR-011.3, LLR-013.3 | New `command_bar.py` — palette (`Ctrl+K`, type-to-filter), find (`/`→`find_string_in_mem`), go-to (`g`→`_handle_goto`), single-key suppression during input focus, project/A2L labels relocated here, no extra logging. |
| 5 | Workspace screen 3-pane re-layout | LLR-008.1, LLR-008.2 | Re-lay the Main-view 5-tile grid into the Direction B 3-pane Workspace (ranges/sections · hex · context) with the two-regime width layout; reuse `update_sections` / `update_hex_view`. |
| 6 | A2L Explorer + MAC View re-layout | LLR-009.1, LLR-009.2, LLR-010.1, LLR-010.2 | Re-lay the A2L Tags and MAC screens to the Direction B two-regime layout; preserve filtering, paging, jump, MAC overlay highlight. |
| 7 | Issues Report dedicated screen | LLR-011.1, LLR-011.2 | Promote the `validation_issues_list` table out of the Status tile into its own rail screen; preserve severity colors, filters, paging, jump-to-source. |
| 8 | Modal re-skin (Load / Save / Load-Project) | LLR-015.1, LLR-015.2 | Re-skin the three `screens.py` modals to the Calm Dark tokens; behavior, `validate_project_files`, workarea layout unchanged. |
| 9 | Memory Map + Bookmarks scaffolds | LLR-012.1, LLR-002.2, LLR-012.4 | New `screens_directionb.py` (part 1): Memory Map screen rendering coverage from `LoadedFile.ranges` / `range_validity`; Bookmarks "coming soon" placeholder. |
| 10 | Patch Editor + A↔B Diff scaffolds | LLR-012.2, LLR-012.3, LLR-012.4 | New `screens_directionb.py` (part 2): Patch Editor before/after view shell (inert inputs); A↔B Diff static 3-column placeholder. |
| 11 | No-regression + behavior test increment | LLR-004.4, LLR-013.1, LLR-013.2, LLR-014.1, LLR-014.2 | Binding-regression / keyboard-reachability / status-bar tests; update pre-batch UI tests to the new layout without weakening intent; confirm engine suite untouched. |
| 12 | Snapshot test increment (`pytest-textual-snapshot`) | LLR-007.1, LLR-007.2 | The 27-baseline snapshot matrix over public synthetic fixtures only; register the `snapshot` pytest marker; layout-drift guard. |

**Total: 12 increments.**

Behavioral `run_test()` tests for each restyled/new screen are written **inside the increment that builds the screen** (so the increment ships with its own verification), within the 5-file cap. Increments 11 and 12 are the **dedicated cross-cutting** test increments — the binding/reachability regression sweep and the snapshot matrix — which cannot be scoped to a single screen.

---

## 3. Increment detail

> For each increment: LLRs covered, TCs covered, files to touch (≤5), dependencies, risks.

---

### Increment 1 — Theme tokens, `styles.tcss` extraction, keymap proposal + req-doc cosmetics

**LLRs covered:** LLR-005.1 (theme tokens), LLR-005.2 (severity color source of truth).
Also delivers the **OQ-8 per-screen keybinding-map proposal** that TC-030 depends on (Q-09), and folds in review closure items **CV-01..CV-05**.

**TCs covered:** TC-012 (theme token budget — inspection), TC-013 (severity color round-trip + stylesheet-rule-per-`sev-*` assertion). Unblocks TC-030 by pinning the keymap.

**Files to touch (5):**
1. `s19_app/tui/styles.tcss` — **new.** The extracted + restyled Calm Dark stylesheet: one accent variable, dark-only background/foreground/rule tokens, the five `sev-*` rules (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`) moved verbatim, `mac_out_of_range` overlay rule preserved. All existing `#id` rules from the inline CSS are carried over so the app still renders.
2. `s19_app/tui/app.py` — replace the inline `CSS = """..."""` block with `CSS_PATH = "styles.tcss"`; no behavior change.
3. `pyproject.toml` — add `[project.optional-dependencies]` with `pytest-textual-snapshot` (>= floor consistent with a new `textual` >= floor); add a `>=` floor to `textual` in `[project] dependencies`; register the `snapshot` pytest marker alongside `slow`.
4. `tests/test_tui_theme.py` — **new.** TC-012 inspection-as-test (parse `styles.tcss`: exactly one accent var, five `sev-*` rules present, no light variant) + TC-013(b) (a CSS rule exists for each of the five `sev-*` classes). TC-013(a) re-runs the existing `test_color_policy_round_trip` as a no-regression anchor.
5. `.dev-flow/2026-05-20-batch-02/03-increments/keymap-proposal.md` — **new.** The OQ-8 deliverable: the final per-screen keybinding map (global bindings + per-screen `show=True` set for all 8 rail screens), so TC-030's expected column can be filled. CV-01..CV-05 are also applied as small edits to `01-requirements.md` (counted within this file slot as the doc-fix companion — they are 1-to-few-line cosmetic edits: CV-01 rationale rounding, CV-02 rail-collapse cross-ref, CV-03 empty-state-snapshot note, CV-04 119-col boundary note, CV-05 TC-038/039 label swap).

**Dependencies:** none — foundation increment.

**Key risks:**
- Extracting ~280 lines of inline CSS to a file can drop or reorder a rule and silently change rendering. Mitigation: carry every existing `#id`/`.class` rule over 1:1; the app must render identically before any token retheme is layered on.
- `textual` gaining a `>=` floor could clash with an already-installed older `textual`. Mitigation: set the floor to the currently-installed version or lower; verify `s19tui` still launches.
- The keymap proposal is a **design artifact, not code** — it must be reviewed/approved before increments 2-4 wire bindings against it. Flag it explicitly for owner sign-off.
- `01-requirements.md` is the Phase-1 contract; CV edits must be strictly the 5 cosmetic items, nothing else (no scope creep into requirements).

**Approach:** Pure refactor + additive config. (a) Move `S19TuiApp.CSS` verbatim into `styles.tcss`, switch to `CSS_PATH`, confirm `s19tui` renders unchanged. (b) Layer the Calm Dark tokens on top: define one `$accent` (calm cyan-blue), dark-only `$bg-*` / `$fg-*` / `$rule` tokens; the five `sev-*` rules keep their class names and severity meaning (LLR-005.1/005.2 — names and semantics unchanged), only their hex values are tuned to the calm palette. (c) `color_policy.py` is **not touched** — `SEVERITY_CLASS_MAP`, `css_class_for_severity`, `MAC_ADDRESS_OVERLAY_STYLE`, `FOCUS_HIGHLIGHT_STYLE` stay byte-identical (LLR-005.2, C-6). (d) Author the keymap proposal: global keys `ctrl+k`/`/`/`g`/`ctrl+d`/`l`/`r`/`o`/`s`/`p`/`j`/`q`, rail keys `1`-`8`, and the per-screen `show=True` footer set for each of the 8 screens. (e) Apply CV-01..CV-05 to the requirements doc.

---

### Increment 2 — App shell + 8-container screen routing + density toggle

**LLRs covered:** LLR-002.1 (rail-driven content swap mechanism), LLR-002.3 (empty-state panel), LLR-006.1 (density cycle action), LLR-006.2 (density default Comfortable), LLR-007.1 (the density layout skeleton — the two-regime container structure; pane-width tolerances land per-screen in increments 5-7).

**TCs covered:** TC-003 (rail activation swaps content), TC-014 (`Ctrl+D` cycles density), TC-015 (startup density default), TC-037 (empty-state on no-file). TC-016/016-S layout integrity is set up here but verdicted in increment 12.

**Files to touch (4):**
1. `s19_app/tui/app.py` — replace `#view_bar` + `#main/alt/mac_layout` compose with the Direction B body: a top command-bar mount point (placeholder until increment 4), a horizontal split of `Rail` mount point (placeholder until increment 3) + an 8-child `#workspace_body` of `.hidden`-toggled screen containers. Add `action_show_screen(screen_key)` reusing the `.hidden` toggle mechanism (LLR-002.1). Add `action_cycle_density` toggling `density-compact` / `density-comfortable` on the workspace root, default Comfortable (LLR-006.1/006.2). Retire `#view_bar` / `view_main`/`view_alt`/`view_mac` (intended supersession). The existing `update_*` renderers are re-pointed to the new container ids but not otherwise changed.
2. `s19_app/tui/styles.tcss` — add `density-compact` / `density-comfortable` variant rules; add the `#workspace_body` + 8-screen-container layout rules and the two-regime `@media`-equivalent (Textual has no media queries — width regimes are handled via a `width-narrow` class toggled on `on_resize`, set at the <120 breakpoint).
3. `s19_app/tui/screens_directionb.py` — **new.** A small `EmptyStatePanel` widget ("no file loaded — Ctrl+L to load") and the neutral container scaffolds for the 8 screen slots (the slots are real containers now; their rich content is filled by increments 5-10). This module is the home for all Direction B screen/widget classes built in later increments.
4. `tests/test_tui_directionb.py` — **new.** TC-003 (one screen visible at a time after `action_show_screen`), TC-014/TC-015 (density class cycle + default), TC-037 (empty-state panel shows for Workspace/A2L/MAC/Map with no `LoadedFile`).

**Dependencies:** Increment 1 (`styles.tcss` must exist and be wired via `CSS_PATH`).

**Key risks:**
- Re-pointing every `update_*` renderer's `query_one` target id is the highest-churn edit in the batch; a missed id silently breaks a renderer. Mitigation: keep container ids stable where possible; run the full existing UI suite (`test_tui_app.py`) after this increment — failures localize the misses.
- Retiring `#view_bar` removes `view_hex_button` / `view_a2l_button` / `view_mac_button` / `settings_button`; any test or handler referencing them breaks. Mitigation: grep `view_*_button` and `settings_button` before editing; fix call sites in this increment.
- The `width-narrow` resize class is new behavior (G-1: no density mechanism exists today). The `<120` regime must be exercised at 80×24 in increment 12.
- 8 empty screen containers must not produce 8 visible panes at once — the `.hidden` default must be correct (only Workspace visible at startup).

**Approach:** Reuse the proven `.hidden`-class toggle (LLR-002.1 mandates it). `compose` yields: `Header` → command-bar mount → `Horizontal(Rail-mount, #workspace_body)` → `Footer`. `#workspace_body` holds 8 containers (`#screen_workspace` … `#screen_bookmarks`), all but Workspace carrying `.hidden`. `action_show_screen` clears `.hidden` on the target, sets it on the rest. Density: `action_cycle_density` flips the root class; `on_mount` sets `density-comfortable`. The `<120`-column rail-collapse / proportional regime is a `width-narrow` class toggled in `on_resize`.

---

### Increment 3 — Activity rail widget + rail navigation wiring

**LLRs covered:** LLR-001.1 (rail composition — 8 ordered items, keys `1`-`8`), LLR-001.2 (single active item), LLR-001.3 (Unicode glyphs + ASCII fallback per the glyph→screen table).

**TCs covered:** TC-001 (8 ordered items on keys 1-8), TC-002 (exactly one active, Workspace at startup), TC-035 (Unicode glyph + ASCII fallback per item).

**Files to touch (4):**
1. `s19_app/tui/rail.py` — **new.** `Rail` + `RailItem` widgets (structural reference: handoff `rail.py`). Eight ordered `RailEntry` items (Workspace, A2L, MAC, Map, Issues, Patch, Diff, Bookmarks), the normative glyph→screen mapping from LLR-001.3 (`◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` + ASCII fallback `# = @ M ! P D *`), a single `-active` accent marker, and a `Rail.Selected` message. ASCII-fallback mode is a constructor flag / detected default.
2. `s19_app/tui/app.py` — mount `Rail` in the increment-2 rail slot; bind keys `1`-`8` to `action_show_screen`; handle `Rail.Selected` → `action_show_screen` + move the active marker; set Workspace active at startup. The retired `1/2/3` view-toggle meaning is now rail activation (intended supersession).
3. `s19_app/tui/styles.tcss` — add the `Rail` / `RailItem` / `-active` rules and the `<120`-column collapsed-rail (icon-only, 4±1 col) variant under `width-narrow`.
4. `tests/test_tui_directionb.py` — extend: TC-001, TC-002, TC-035.

**Dependencies:** Increment 2 (`action_show_screen`, the rail mount slot, the `width-narrow` class).

**Key risks:**
- Unicode glyph rendering varies by terminal/font; the ASCII fallback path must be reachable and tested (TC-035 forces fallback mode). Mitigation: fallback is a simple constructor flag — TC-035 exercises both modes.
- Rail keys `1`-`8` collide with digits typed into a command-bar input — but the suppression rule (LLR-004.5) is implemented in increment 4. Between increment 3 and 4 the digits are not yet suppressed; this is acceptable because the command bar does not exist until increment 4 (no input to type into yet). No runnable-app regression.
- Active-marker invariant: exactly one `-active` at all times — a routing path that forgets to clear the old marker breaks TC-002.

**Approach:** `Rail` is a presentational widget — takes entries via `__init__`, emits `Rail.Selected(key)`, never calls the engine (handoff architecture rule). `app.py` owns routing: on `Rail.Selected` or a `1`-`8` keypress, call `action_show_screen` and `Rail.set_active(key)`. Glyph→screen pairing is the explicit LLR-001.3 table.

---

### Increment 4 — Command bar widget + key bindings + input-focus suppression

**LLRs covered:** LLR-003.1 (command-bar composition), LLR-003.2 (palette population — every `BINDINGS` action), LLR-003.3 (type-to-filter), LLR-004.1 (`/` find), LLR-004.2 (`g` go-to → `_handle_goto`), LLR-004.3 (`Ctrl+K` palette), LLR-004.4 (binding regression guard — wiring side), LLR-004.5 (single-key suppression during input focus), LLR-004.6 (`/` find → `find_string_in_mem`), LLR-011.3 (project/A2L labels relocated to command bar), LLR-013.3 (command bar logs no typed text).

**TCs covered:** TC-006 (command bar on every screen), TC-007 (palette lists every `BINDINGS` action), TC-008 (`/` focus + find routing + suppression), TC-009 (`g` focus + `_handle_goto` effect + suppression), TC-010 (`Ctrl+K` palette), TC-036 (palette type-to-filter), TC-038 (project/A2L labels visible on every screen), TC-039 (no typed-text logging — inspection).

**Files to touch (5):**
1. `s19_app/tui/command_bar.py` — **new.** `CommandBar` widget: a `›` prompt, a command-palette trigger, a find `Input`, a go-to `Input`, and project-name / A2L-filename labels (relocated from the old Status tile per LLR-011.3). Palette is type-to-filter over the action list (LLR-003.2/003.3). The widget routes find submission to the app's existing `find_string_in_mem` path and go-to submission to `_handle_goto` — it introduces **no** new parsing/decoding code (LLR-004.6/004.2, S-1) and writes nothing to the log (LLR-013.3).
2. `s19_app/tui/app.py` — mount `CommandBar` in the increment-2 command-bar slot; add `ctrl+k` / `/` / `g` bindings → focus actions; add the single-key suppression: while a command-bar `Input` holds focus, route `g`, `1`-`8`, `+`, `-`, `,`, `.` as text (LLR-004.5); modified keys (`ctrl+k`, `ctrl+d`) stay live. Wire palette entries 1:1 to existing `BINDINGS` action ids (LLR-003.2). Feed project/A2L labels into the bar (re-point `update_project_labels`).
3. `s19_app/tui/styles.tcss` — add `CommandBar` rules (height 3, accent prompt, palette dropdown).
4. `tests/test_tui_directionb.py` — extend: TC-006, TC-010, TC-036, TC-038.
5. `tests/test_tui_commandbar.py` — **new.** TC-007 (iterate the full `BINDINGS` set — every action has a palette entry dispatching the same action id), TC-008 (`/` focus from every screen; find routes to `find_string_in_mem`; `g`/digit/`,`/`+` suppressed while find focused; malformed input via `set_status`), TC-009 (`g` focus; submit → hex scrolled + `Goto 0x…` status; suppression; malformed via `set_status`), TC-039 (inspection: no typed text / file content written to `.s19tool/logs/`).

**Dependencies:** Increment 2 (command-bar mount slot), Increment 3 (rail — palette includes rail navigation; suppression must not block rail keys when no input is focused), Increment 1 (keymap proposal pins the palette action list and the per-screen `show=True` set).

**Key risks:**
- **S-1 / S-2 sensitivity:** the command bar is a new input surface. The find/go-to inputs must route to the **existing validated** `find_string_in_mem` / `_handle_goto` with zero new parsing code. This increment should be flagged for `security-reviewer` review before merge. Mitigation: TC-008/009 assert no new search/decode function exists; TC-039 asserts no new logging.
- `_handle_goto` (`app.py:4993`) takes **no address argument** — it reads `#goto_input` off the widget tree. The command bar's go-to input must either reuse id `#goto_input` or `_handle_goto` reads the new input. Whichever — no signature change to `_handle_goto` (it is view-layer but its contract is depended on by TC-009). Approach: the command-bar go-to `Input` carries the id `_handle_goto` already reads, OR a 2-line view-layer adapter; no parsing logic added.
- Single-key suppression is subtle: Textual delivers key events; the suppression must check `isinstance(self.focused, Input)` and the input's identity. A wrong check either eats keys globally or never suppresses. TC-008/009/029 sub-cases verify both directions.
- Palette parity (Q-02): TC-007 iterates the **full** `BINDINGS` set — a palette missing entries must fail. Build the palette list programmatically from `BINDINGS` so it cannot drift.

**Approach:** `CommandBar` is presentational — emits messages, the app routes. `Ctrl+K` opens/focuses the palette; `/` focuses find; `g` focuses go-to. Palette entries are generated from `BINDINGS` (parity by construction). Suppression: a key handler on the app checks whether a command-bar `Input` is focused and, if so, lets the character fall through to the input instead of firing the binding — only for unmodified single keys. Project/A2L labels move here from the Status tile (LLR-011.3) so they survive increment 7's Issues-table promotion.

---

### Increment 5 — Workspace screen 3-pane re-layout

**LLRs covered:** LLR-008.1 (Workspace three-pane two-regime width layout), LLR-008.2 (data wiring unchanged).

**TCs covered:** TC-017 (three named panes at the two-regime tolerances), TC-018 (data wiring + hex caps honored).

**Files to touch (3):**
1. `s19_app/tui/app.py` — re-compose `#screen_workspace`: from the old 5-tile grid (Workarea Files, Data Sections, Hex Viewer, A2L summary, Status) into the Direction B 3-pane layout — left ranges/sections pane, center hex pane, right context pane. Re-point the `update_sections` / `update_hex_view` / context renderers to the new pane ids; the renderers themselves are **not modified** (LLR-008.2, C-1). The Issues table and project/A2L labels are no longer in this screen (Issues → increment 7, labels → command bar in increment 4).
2. `s19_app/tui/styles.tcss` — Workspace 3-pane rules: the `>=120`-col fixed regime (left 22±2, right 40±2, center `1fr`) and the `<120`-col proportional regime (left 24%±3, right 30%±3, center `1fr`, rail collapsed 4±1) under the `width-narrow` class.
3. `tests/test_tui_directionb.py` — extend: TC-017 (query the 3 panes + rail, assert `region.width` at pinned sizes 120×30 / 160×40 fixed regime and 80×24 proportional regime), TC-018 (panes populate from `LoadedFile`; hex caps `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` unchanged — reuse `test_tui_hexview` invariants).

**Dependencies:** Increments 2 (the `#screen_workspace` container + `width-narrow`), 3 (rail collapse), 4 (project/A2L labels already relocated, so the Workspace need not host them).

**Key risks:**
- The Workspace currently hosts 5 tiles including content that moves elsewhere (Issues, status labels). The re-layout must drop those cleanly without orphaning a renderer. Mitigation: increments 4 and 7 own those moves; this increment only lays out the 3 panes that remain.
- The two-regime width math is the A-03 resolution — the fixed widths must sum correctly at ≥120 and the proportional widths must keep the center pane strictly positive at 80×24. Mitigation: TC-017 asserts exact numeric tolerances at all three pinned sizes.
- The old `#main_layout` was a `grid`; the new Workspace is a horizontal 3-pane. Renderers that assumed grid cells (`row-span`) need their target containers updated, not their logic.

**Approach:** Compose `#screen_workspace` as a `Horizontal` of three panes. The center hex pane reuses the existing `#hex_view` / `#hex_scroll` / hex controls subtree verbatim so `update_hex_view` and `find_string_in_mem` keep working. Left pane = `#sections_list` (+ optionally workarea files). Right context pane = the A2L summary / focus-context content. Width regimes via fixed columns vs. proportional `%` under `width-narrow`.

---

### Increment 6 — A2L Explorer + MAC View re-layout

**LLRs covered:** LLR-009.1 (A2L Explorer two-regime layout), LLR-009.2 (A2L behavior preserved), LLR-010.1 (MAC View two-regime layout), LLR-010.2 (MAC behavior preserved).

**TCs covered:** TC-019 (A2L table + hex pane at two-regime tolerances), TC-020 (A2L filtering/paging/jump preserved), TC-021 (MAC table + hex pane at two-regime tolerances), TC-022 (MAC paging/coloring/overlay/jump preserved).

**Files to touch (3):**
1. `s19_app/tui/app.py` — re-compose `#screen_a2l` and `#screen_mac`: A2L Tags `DataTable` + hex pane (`1fr` table + 40±2 fixed hex at ≥120; proportional at <120), MAC records `DataTable` + hex pane same regime. Re-point `update_a2l_tags_view` / `_filter_a2l_tags` / `update_mac_view` / `update_mac_hex_view` and the A2L/MAC paging actions to the new container ids; renderers and filter/paging/jump logic **not modified** (LLR-009.2/010.2, C-1).
2. `s19_app/tui/styles.tcss` — A2L Explorer and MAC View two-regime rules.
3. `tests/test_tui_directionb.py` — extend: TC-019, TC-021 (pane widths at pinned sizes). TC-020 / TC-022 re-run/extend the existing A2L/MAC behavior tests against the restyled screens.

**Dependencies:** Increments 2, 3, 5 (the Workspace establishes the two-regime CSS pattern this increment mirrors).

**Key risks:**
- A2L is the highest-regression-risk area (`R-A2L-*`, `R-TUI-018/019/020`); a re-pointed id that breaks `_filter_a2l_tags` or `_focus_a2l_tag_absolute_index` silently regresses filtering or jump. Mitigation: TC-020/022 re-run the existing A2L/MAC test functions against the restyled screens — they fail loudly on a behavior regression.
- `render_a2l_view` is in `a2l.py` (engine-frozen module) but is **view-layer** (A-01) — a layout/theme edit to it is permitted. If this increment needs to touch `render_a2l_view`, it must stay within the LLR-014.1 carve-out (view-only, no parse/validate change) and be classified cosmetic by TC-031.
- MAC overlay highlight (`MAC_ADDRESS_OVERLAY_STYLE`) must render identically after re-layout (LLR-010.2). Mitigation: TC-022 asserts the overlay style is preserved.

**Approach:** Same two-regime pattern as increment 5. Both screens are a `Horizontal` of a `1fr` `DataTable` pane + a fixed/proportional hex pane. The hex panes reuse the existing `#alt_hex_view` / `#mac_hex_view` subtrees so their renderers and goto handlers are unchanged. This is one increment because A2L and MAC are structurally identical re-layouts sharing the same CSS rules — splitting them would duplicate the two-regime rules across two increments.

---

### Increment 7 — Issues Report dedicated screen

**LLRs covered:** LLR-011.1 (Issues screen layout — dedicated rail screen), LLR-011.2 (Issues behavior preserved).

**TCs covered:** TC-023 (Issues is a dedicated rail screen, not nested in the Status tile), TC-024 (severity coloring / filters / paging / jump-to-source preserved).

**Files to touch (3):**
1. `s19_app/tui/app.py` — re-compose `#screen_issues`: move the `validation_issues_list` `DataTable`, the `validation_issues_filters` (All/Errors/Warnings), and `validation_issues_summary` out of the old Workspace Status tile into the dedicated Issues screen as its primary content. Re-point `update_validation_issues_view` and `action_validation_issues_page_next/prev` to the new container; logic unchanged. (The project/A2L labels that shared the old Status tile already moved to the command bar in increment 4 — LLR-011.3.)
2. `s19_app/tui/styles.tcss` — Issues screen rules (full-screen `DataTable`, filter row).
3. `tests/test_tui_directionb.py` — extend: TC-023 (`#validation_issues_list` is the Issues screen's primary content, not under `#status_panel`), TC-024 (re-use the existing Issues harness — severity colors round-trip via `css_class_for_severity`, filters/paging/jump work).

**Dependencies:** Increment 4 (project/A2L labels already relocated, so dismantling the Status tile orphans nothing — closes G-2), increments 2/3 (the `#screen_issues` slot + rail item 5).

**Key risks:**
- The Status tile (`#status_panel`) is being dismantled — it also held `status_text`, `progress_bar`, and `log_line_*` labels. Those are not Issues content; they need a defined home (status_text → footer/status bar per LLR-013.2; progress bar → kept near the command bar). Any renderer writing to them breaks if their ids vanish. Mitigation: grep `status_text` / `progress_bar` / `log_line_` and re-home or keep them; do not delete an id a renderer still writes to.
- TC-038 (project/A2L labels visible after the move) was verdicted in increment 4 — confirm it still holds once the Status tile is fully gone.

**Approach:** Lift the `DataTable` + filters + summary subtree intact into `#screen_issues`. `update_validation_issues_view` is unchanged — only its target container id changes. The `status_text` / `progress_bar` / `log_line_*` widgets are re-homed to the persistent footer/status-bar area so no renderer loses its target.

---

### Increment 8 — Modal re-skin (Load / Save / Load-Project)

**LLRs covered:** LLR-015.1 (modal re-skin to Calm Dark tokens), LLR-015.2 (modal behavior preserved).

**TCs covered:** TC-033 (modals adopt Calm Dark theme — inspection), TC-034 (modal behavior — `validate_project_files` + workarea layout + path-traversal containment preserved).

**Files to touch (3):**
1. `s19_app/tui/screens.py` — re-skin `LoadFileScreen`, `SaveProjectScreen`, `LoadProjectScreen`: their per-screen CSS adopts the Calm Dark tokens (accent variable + shared dark token set), no hard-coded hex colors. **No behavior change** — `validate_project_files`, `SaveProjectPayload`, path resolution, the `.s19tool/` workarea layout are untouched (LLR-015.2, C-1, A-5).
2. `s19_app/tui/styles.tcss` — add shared modal rules referenced by the three modals (`#load_dialog` already exists; extend to the modal token set).
3. `tests/test_tui_directionb.py` — extend: TC-034 (re-run the existing modal/workspace tests — `validate_project_files` cardinality, `copy_into_workarea` containment, save-under-workarea — against the re-skinned modals; add the `..\..\` path-traversal containment sub-case). TC-033 is an inspection checklist against `screens.py` styling.

**Dependencies:** Increment 1 (`styles.tcss` tokens exist).

**Key risks:**
- The modals are **security-adjacent** (`resolve_input_path`, `validate_project_files`, `.s19tool/` containment — S-4). The re-skin must be visual-only; any change to path handling is out of scope. Mitigation: TC-034 re-runs the existing containment tests; flag this increment for `security-reviewer` confirmation that path containment is untouched.
- Modal CSS is currently inline `DEFAULT_CSS` per screen; moving rules to `styles.tcss` vs. keeping them inline-but-tokenized is a choice — keep them inline but reference `$accent` etc., which `styles.tcss` defines, to minimize churn.

**Approach:** Visual-only token swap. Each modal's existing `DEFAULT_CSS` keeps its structure; hard-coded colors are replaced with Calm Dark token references. Zero logic edits in `screens.py`.

---

### Increment 9 — Memory Map + Bookmarks scaffolds

**LLRs covered:** LLR-012.1 (Memory Map scaffold), LLR-002.2 (Bookmarks placeholder screen), LLR-012.4 (deferred-logic guard).

**TCs covered:** TC-004 (Bookmarks non-blocking placeholder), TC-025 (Memory Map renders coverage from `LoadedFile`), TC-028 (deferred-logic guard — partial: scaffolds add no processing module).

**Files to touch (4):**
1. `s19_app/tui/screens_directionb.py` — extend: a `MemoryMapScreen` content widget rendering ranges/gaps/coverage **from the existing `LoadedFile.ranges` and `range_validity`** (no new coverage computation — LLR-012.1/012.4); a `BookmarksPlaceholder` widget with neutral "coming soon" text (LLR-002.2). Structural reference: handoff `memory_map.py`.
2. `s19_app/tui/app.py` — populate `#screen_map` and `#screen_bookmarks` with the new widgets; wire the Memory Map renderer to read `LoadedFile` (read-only). Bookmarks activation invokes **no** persistence logic.
3. `s19_app/tui/styles.tcss` — Memory Map + Bookmarks placeholder rules.
4. `tests/test_tui_directionb.py` — extend: TC-004, TC-025, and the scaffold-side of TC-028 (no new processing module; `bincopy`/`pya2l`/`crcmod` absent from imports).

**Dependencies:** Increment 2 (`#screen_map` / `#screen_bookmarks` slots, `EmptyStatePanel` for no-file Memory Map).

**Key risks:**
- Memory Map must render **only** from existing `LoadedFile` data — the temptation to compute a new coverage metric is the main scope-creep risk (C-4/C-5/LLR-012.4). Mitigation: TC-025 + TC-028 assert no new coverage computation / processing module.
- The Bookmarks placeholder must not raise on activation and must not read/write any persistence (LLR-002.2). Mitigation: TC-004 asserts no exception + "coming soon" text.

**Approach:** Memory Map is a read-only visualization — it iterates `LoadedFile.ranges` / `range_validity` and renders coverage bars/labels. Bookmarks is a static placeholder `Static`. Neither imports anything outside the view layer.

---

### Increment 10 — Patch Editor + A↔B Diff scaffolds

**LLRs covered:** LLR-012.2 (Patch Editor view shell), LLR-012.3 (A↔B Diff static placeholder), LLR-012.4 (deferred-logic guard).

**TCs covered:** TC-026 (Patch Editor shell — inert inputs + deferral notice), TC-027 (A↔B Diff three-column placeholder), TC-028 (deferred-logic guard — completes the guard for all scaffolds + the `pyproject.toml` check).

**Files to touch (4):**
1. `s19_app/tui/screens_directionb.py` — extend: a `PatchEditorScreen` content widget — before/after hex-pane layout + address/value `Input` fields that are **not wired** to any patch-apply/undo/redo logic, plus a visible "patch logic deferred" notice (LLR-012.2/012.4); an `AbDiffScreen` content widget — a static three-column layout (range list, hex A, hex B) with **static, clearly-labelled placeholder hex rows** in each column and a visible "PLACEHOLDER / diff deferred" marker (LLR-012.3 — placeholder defined concretely).
2. `s19_app/tui/app.py` — populate `#screen_patch` and `#screen_diff` with the new widgets. No patch engine, no second-file load path, no diff computation wired.
3. `s19_app/tui/styles.tcss` — Patch Editor + A↔B Diff rules.
4. `tests/test_tui_directionb.py` — extend: TC-026, TC-027, and the completion of TC-028 (enumerate `s19_app/` modules — no new processing module outside the view layer; AST-walk the new scaffold modules — `bincopy`/`pya2l`/`crcmod` absent; assert those three absent from `pyproject.toml`; activate every scaffold — no exception).

**Dependencies:** Increment 2 (`#screen_patch` / `#screen_diff` slots), Increment 9 (`screens_directionb.py` scaffold conventions established).

**Key risks:**
- Patch Editor inputs must be **inert** — visibly present but not connected to any apply logic (LLR-012.2). The risk is accidentally wiring an `on_input_submitted` to something. Mitigation: TC-026 asserts no patch-apply handler is wired.
- A↔B Diff "placeholder data" is defined by LLR-012.3 as static, constant, clearly-labelled sample hex rows — **not** sourced from any `LoadedFile` and **not** from any diff computation. Mitigation: TC-027 asserts the deferral; TC-028 asserts no diff module.
- No control to load a second ("B") firmware file may be present or wired (LLR-012.3, OQ-7).

**Approach:** Both are pure view shells. Patch Editor: two hex `Static`s + two `Input`s + a deferral `Static`. A↔B Diff: a `Horizontal` of three columns, each a `Static` with a small fixed set of constant sample hex rows and a "PLACEHOLDER" caption. Neither imports the engine for new logic.

---

### Increment 11 — No-regression + behavior test increment

**LLRs covered:** LLR-004.4 (binding regression guard — verdict), LLR-013.1 (no mouse-only actions), LLR-013.2 (status bar bindings), LLR-014.1 (engine modules untouched), LLR-014.2 (existing suite passes).

**TCs covered:** TC-011 (no pre-batch binding unreachable; `1/2/3` remap is intended supersession), TC-029 (every new control keyboard-reachable; suppression sub-case), TC-030 (status bar shows the active screen's `show=True` bindings — expected set pinned by increment 1's keymap), TC-031 (engine modules show no behavioral change — inspection/analysis), TC-032 (existing `pytest` suite passes unchanged).

**Files to touch (4):**
1. `tests/test_tui_directionb.py` — extend: TC-011 (capture the pre-batch `BINDINGS` action set; assert each keeps a key path; assert the `1/2/3`→rail remap and `#view_bar` removal are recorded supersession), TC-029 (enumerate new controls — rail, command-bar inputs, density, scaffold controls — each has a working keyboard path; input-focus suppression sub-case), TC-030 (footer shows the active screen's `show=True` bindings, compared against increment 1's keymap).
2. `tests/test_tui_app.py` — update the pre-batch UI tests that assert on the old `#main_layout` / `#alt_layout` / `#mac_layout` / `#view_bar` structure to the new Direction B layout, **without weakening their behavioral intent** (LLR-014.2). Engine/parser/validation tests are NOT touched.
3. `tests/test_tui_directionb.py` (TC-031 / TC-032 harness) — TC-031: a test/inspection that diffs `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`a2l.py`/`mac.py` parse/validate functions against the pre-batch branch and classifies every change against the cosmetic-only rubric; TC-032: confirms `pytest -q` green and the engine test files unmodified.
4. `s19_app/tui/app.py` — only if TC-029/TC-030 surface a missing keyboard path or a `show=False` binding that should be `show=True`; otherwise untouched. (Listed so the increment can close a gap it finds — within the cap.)

**Dependencies:** All of increments 1-10 (this is the cross-cutting regression sweep).

**Key risks:**
- Updating `test_tui_app.py` UI assertions risks **weakening intent** (rule 9 / LLR-014.2) — rewriting a test to pass rather than to still verify the behavior. Mitigation: each updated test keeps its original behavioral assertion; only the structural locator (widget id / layout) changes.
- TC-031's cosmetic-only rubric (Q-11): whitespace/comment/import-order = cosmetic; logic/constant/signature = not. The verdict must be applied honestly — if any engine module changed behaviorally, this increment fails loud.
- TC-030's expected `show=True` set depends on increment 1's keymap being approved and stable.

**Approach:** This is the deliberate "dedicated no-regression test increment." It produces the binding/reachability verdicts and the engine-freeze verdict. It is mostly test code; the single `app.py` slot is reserved only to close a keyboard-reachability gap the tests expose.

---

### Increment 12 — Snapshot test increment (`pytest-textual-snapshot`)

**LLRs covered:** LLR-007.1 (density layout integrity — snapshot verdict), LLR-007.2 (baselines render only public synthetic fixtures).

**TCs covered:** TC-016 (density layout integrity — inspection checklist), TC-016-S (density layout integrity — 27-baseline snapshot SVG matrix).

**Files to touch (3):**
1. `tests/test_tui_snapshot.py` — **new.** The 27-baseline snapshot matrix: the 4 restyled screens (Workspace, A2L Explorer, MAC View, Issues Report) × {compact, comfortable} × {80×24, 120×30, 160×40} = 24, plus the 3 scaffolds (Memory Map, Patch Editor, A↔B Diff) at 120×30 only = 3. All rendered **only** against public synthetic fixtures (`examples/case_00_public/`, the `tests/conftest.py` generators) — LLR-007.2. Marked with the `snapshot` pytest marker (registered in increment 1).
2. `tests/__snapshots__/` (baseline `.svg` directory) — **new** (generated baselines, one directory; counted as one file slot). 27 approved baseline SVGs, every one traceable to a public fixture.
3. `tests/conftest.py` — only if a snapshot-specific fixture wiring is needed (e.g. pinning terminal size for the snapshot harness); reuse the existing `make_large_s19/a2l/mac` generators — no new generator.

**Dependencies:** All of increments 1-10 (all 8 screens must exist to snapshot), increment 1 (`pytest-textual-snapshot` declared, `snapshot` marker registered), increment 11 (the suite must be green before baselines are blessed).

**Key risks:**
- **S-2 — client data leak.** Every baseline `.svg` renders actual screen content. A baseline captured against a real client artifact would commit proprietary bytes/addresses/symbols. Mitigation: LLR-007.2 — baselines use **only** public synthetic fixtures; TC-031's no-leak inspection (increment 11) cross-checks every committed `.svg`. Flag for `security-reviewer`.
- A 27-file snapshot diff invites rubber-stamping (Q-06). The matrix is already narrowed to 27; baseline regeneration is a reviewed gate, not auto-accept.
- Snapshot tests are environment-sensitive (font metrics, terminal). The `snapshot` marker allows deselection on constrained CI.
- This increment cannot run until all 8 screens exist — it is correctly last.

**Approach:** Standard `pytest-textual-snapshot` usage — `snap_compare(app, terminal_size=(w,h))` per screen/density/size cell. Baselines generated once, reviewed, committed. The `snapshot` marker keeps them deselectable. This is the dedicated layout-drift regression increment.

---

## 4. Traceability check — every LLR is covered

| LLR | Increment | LLR | Increment |
|-----|-----------|-----|-----------|
| LLR-001.1 | 3 | LLR-008.1 | 5 |
| LLR-001.2 | 3 | LLR-008.2 | 5 |
| LLR-001.3 | 3 | LLR-009.1 | 6 |
| LLR-002.1 | 2 | LLR-009.2 | 6 |
| LLR-002.2 | 9 | LLR-010.1 | 6 |
| LLR-002.3 | 2 | LLR-010.2 | 6 |
| LLR-003.1 | 4 | LLR-011.1 | 7 |
| LLR-003.2 | 4 | LLR-011.2 | 7 |
| LLR-003.3 | 4 | LLR-011.3 | 4 |
| LLR-004.1 | 4 | LLR-012.1 | 9 |
| LLR-004.2 | 4 | LLR-012.2 | 10 |
| LLR-004.3 | 4 | LLR-012.3 | 10 |
| LLR-004.4 | 4 (wiring) / 11 (verdict) | LLR-012.4 | 9, 10 |
| LLR-004.5 | 4 | LLR-013.1 | 11 |
| LLR-004.6 | 4 | LLR-013.2 | 11 |
| LLR-005.1 | 1 | LLR-013.3 | 4 |
| LLR-005.2 | 1 | LLR-014.1 | 11 |
| LLR-006.1 | 2 | LLR-014.2 | 11 |
| LLR-006.2 | 2 | LLR-015.1 | 8 |
| LLR-007.1 | 2 (skeleton) / 12 (verdict) | LLR-015.2 | 8 |
| LLR-007.2 | 12 | | |

All 38 LLRs covered. All 38 active TCs (TC-001..TC-039, TC-016-S; TC-005 retired N/A) covered across increments 1-12.

## 5. Cross-functional handoffs

- **Increment 4** (command bar — new input surface, S-1) and **Increment 8** (modals — path containment, S-4) and **Increment 12** (snapshot baselines — client-data leak, S-2): request `security-reviewer` review before merge.
- **Increment 1** keymap proposal: a design artifact requiring **owner approval** before increments 2-4 wire bindings against it.
- Each restyled/new screen increment proposes its own behavioral acceptance criteria to `qa-reviewer` via the per-increment TCs; increments 11-12 are the consolidated verdicts.

## 6. Notes

- `app.py` appears in 9 of 12 increments. It is one file per increment and never co-occurs with more than 4 other files. The new widget/screen modules (`rail.py`, `command_bar.py`, `screens_directionb.py`, `styles.tcss`) absorb the bulk of new code so `app.py` only grows by routing/wiring, consistent with the PROJECT_RULES.md decomposition guidance.
- `color_policy.py` is never touched (LLR-005.2 / C-6).
- The engine modules (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, parse/validate functions of `a2l.py` / `mac.py`) are never touched (C-1 / LLR-014.1). `render_a2l_view` / `a2l_render.py` may receive a view-only edit in increment 6 if the A2L re-layout requires it (permitted by the A-01 carve-out).
- All new public view functions/methods follow the PROJECT_RULES.md docstring contract (`Summary → Args → Returns → Raises → Data Flow → Dependencies → Example`).
