# 01 — Requirements — 2026-07-11-batch-37

> Phase-0 story intake below (§2.6). §3 Acceptance / §4 HLR-LLR derived in Phase 1. Language: English.
> Run mode: Autonomous + self-merge (operator grant). RC-1 PASS @ `978a900`.

## 2.6 — Story intake & refinement (INVEST + Definition of Ready)

### US-061 (B-11) — Persistent before/after-report surface
- **User / value:** an operator who just saved a patch back and could produce a before/after
  report. Today the offer is a **transient `notify`** ("Before/after report ready — press b…",
  `app.py:1795`) that disappears after its timeout — undiscoverable, easily missed.
- **Outcome (WHAT — black-box):** after a save-back that makes a before/after report available,
  a **persistent, discoverable control** (a button and/or a durable status line) is shown and
  remains actionable until the operator acts or the context changes — pressing it produces the
  report. The transient-only affordance no longer gates the feature.
- **Out of scope:** changing the report CONTENT or the `b` key binding itself (the key may stay
  as an accelerator; this adds the persistent surface).
- **INVEST:** Independent ✓ · Valuable ✓ · Estimable ✓ · Small ✓ · Testable ✓ (pilot: the
  surface is present + drives the report after the notify would have expired).
- **Black-box AC:** "After a save-back, the operator observes a persistent report control; when
  activated it writes/opens the before/after report (the same artifact the `b` path produced)."
- **Class:** **READY.**

### US-062 (B-12) — Entropy viewer pagination + sort
- **User / value:** an operator inspecting entropy over a large image. Today the viewer hard-caps
  at **512 windows** (`ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS = 512`, `screens.py:585-586`)
  in **address order only** — windows beyond the cap are invisible and there is no way to find
  the highest/lowest-entropy regions.
- **Outcome (WHAT — black-box):** the entropy viewer lets the operator (a) **page** through
  windows beyond the 512 cap so all windows are reachable, and (b) **sort** the view by a chosen
  key (address / entropy); the observed strip + jump-list order changes with the sort, and
  paging reveals windows not on the first page.
- **Out of scope:** changing the entropy COMPUTATION (`entropy_service`, Shannon windows) — this
  is presentation (paging + ordering) only.
- **INVEST:** Independent ✓ · Valuable ✓ · Estimable ✓ · Small–Medium ✓ · Testable ✓.
- **Black-box AC:** "Given an image with > 512 windows, the operator can navigate to a window
  beyond the first page; toggling sort to 'entropy' reorders the list so the top row is the
  highest-entropy window (content asserted, not just non-empty)."
- **Open question (Phase 1):** paging model (page buttons / PgUp-PgDn) + sort control placement —
  C-13/C-23 geometry in the modal (**pilot-measure**).
- **Class:** **READY.**

### US-063 (B-13) — Entropy band legend + clickable strip
- **User / value:** the same operator. The entropy strip is colour-banded but has **no legend /
  axis**, and the strip cells are a plain `Static` (`screens.py:676`) — not clickable (only the
  jump-list rows navigate). So the operator can't tell what a band colour means or click a hot
  region directly.
- **Outcome (WHAT — black-box):** the entropy viewer shows a **legend** mapping each band colour
  to its entropy meaning, and **clicking a strip cell navigates** to that window's region (the
  same jump the list row performs).
- **Out of scope:** the entropy computation; the jump-list navigation already works (reused).
- **INVEST:** Independent ✓ (pairs naturally with US-062 on the same surface) · Valuable ✓ ·
  Estimable ✓ · Small–Medium ✓ · Testable ✓.
- **Black-box AC:** "The viewer displays a band-colour legend with each colour's meaning; a click
  (or keyboard activation) on a strip cell returns/navigates to that cell's address."
- **Open question (Phase 1):** legend placement + strip click mechanism (Textual `Static` isn't
  clickable by default → may need a clickable widget per cell or a click-to-address map);
  **C-13/C-23 geometry + C-16 interaction-fidelity** (the click is a real mechanism, AT drives it).
  Reuse the `legend.py` table pattern from batch-36 if the bands map to shared colours.
- **Class:** **READY** (flag C-13 geometry + C-16 click-mechanism).

### US-064 (B-14) — Patch-editor refresh + JSON popup editor
- **User / value:** an operator editing a change-set. (a) If the patch/check file is edited
  **externally**, there's no way to re-read it without reloading; (b) the inline paste box is
  small (batch-36 gave it its own cell but full multi-line editing is a ≥120-col affordance) —
  the operator wants a **full-size JSON editor** (the "expand-to-edit" deferred at batch-36 F-01).
- **Outcome (WHAT — black-box):** (a) a **refresh** action re-reads the currently-selected
  patch/check file from disk into the editor, reflecting external edits; (b) a **JSON popup** (a
  modal) opens the change-set in a large editable surface and, on confirm, applies the edited
  text back to the change document.
- **Out of scope:** undo/redo (B-19, excluded); changing the change-set schema/apply engine.
- **INVEST:** Independent ✓ · Valuable ✓ · Estimable ✓ · **Medium–Large** (2 sub-features) ·
  Testable ✓.
- **Black-box AC:** "(a) After the on-disk patch file changes and the operator presses refresh,
  the editor shows the new content. (b) Opening the JSON popup shows the current change-set in a
  full-size editor; confirming an edit updates the change document (content asserted)."
- **Open questions (Phase 1):** MAY SPLIT into US-064a (refresh) + US-064b (popup) — likely two
  increments. Popup = a new `ModalScreen` (C-13/C-23 geometry). Refresh reuses the `refresh_*`
  service methods (`screens_directionb.py:1477`).
- **Class:** **READY** (may split at Phase 2).

---

## Definition-of-Ready summary
- **READY → Phase 1:** US-061, US-062, US-063, US-064 (US-064 may split).
- **REFINE / SPIKE / OUT:** none.
- **Gate axis check:** Coverage — each story has ≥1 black-box AC through the shipped surface;
  Certainty — each AC observable + falsifiable; Evidence — RC-1 @ 978a900 cited, seams cited.
  No unmet axis → autonomous `approve`, proceed to Phase 1.

---

> **Normative keyword contract (§3-§5):** `shall` appears ONLY inside HLR/LLR statements.
> `should` never appears in a normative statement (informative prose only). Every `file:line`
> below was verified against the worktree tree at base `978a900` (= origin/main tip = HEAD,
> batch-36 merged) during Phase-1 drafting, 2026-07-11, unless flagged `assumed — verify in
> Phase N`. New symbols are flagged `NEW — created in Phase 3`. Requirement-ledger sites
> proposed: **R-TUI-049** (US-061), **R-TUI-050** (US-062), **R-TUI-051** (US-063),
> **R-TUI-052** (US-064a), **R-TUI-053** (US-064b) — highest existing id is `R-TUI-048`
> (REQUIREMENTS.md, batch-36), so 049-053 are free.
>
> **Id sequence (probed 2026-07-11, tree `978a900`):** highest AT in the tree = `AT-060b`
> (batch-36; the `AT-0NNx` companions are counterfactual/RED markers, not new numerics);
> new ATs start at **AT-061a**. Highest TC in use = **TC-323** (batch-36 LLR-060.3); new TCs
> continue at **TC-324**.
>
> **US-064 SPLIT (recommended, confirmed at Phase 1):** US-064 splits into **US-064a**
> (patch-editor refresh — compose+wiring on the existing panel, small) and **US-064b** (JSON
> popup — a NEW `ModalScreen`, C-23 geometry). The two are independent, differently-shaped, and
> land in separate increments. Story count is therefore **5** (US-061, US-062, US-063, US-064a,
> US-064b).

## 3. Acceptance blocks (black-box, first-class)

> Each block is independent of the §4 LLR decomposition. C-10 = the AT drives a non-default
> value / asserts CONTENT, not mere non-emptiness. C-12 = output-then-consume: the AT observes
> the consumer over the HANDLER-PRODUCED artifact, never one the AT wrote itself. C-16 =
> real-interaction fidelity: the AT drives the actual click/keyboard mechanism, never a proxy
> call to the action method. C-23 = geometry is PILOT-MEASURED at 80x24 AND 120x30, never
> fr-arithmetic-estimated. **C-17 (render-mode flip over file-derived text) is N/A for all five
> stories** — US-061 adds a trigger surface (no new file-derived rendered text; the report
> CONTENT is unchanged), US-062/US-063 reorder/annotate viewer-owned entropy windows (no
> file-derived markup — band strings are in-repo literals), US-064a re-reads through the existing
> `set_status`/`refresh_*` markup-inert funnels, US-064b routes edited text through the existing
> `load_text` collect-don't-abort parser. Stated explicitly so the C-17 obligation is discharged,
> not skipped.

### AT-061a — Persistent before/after-report control present + activation writes the report pair (US-061, C-12)
- **Observable outcome:** after a successful patch save-back (the path that today fires only the
  transient `notify` at `app.py:1794-1799`), the Patch Editor shows a **persistent, queryable
  report control** (`#patch_before_after_row` NEW — a revealed button row, mirroring the existing
  `#patch_saveback_row` reveal idiom) that remains present after the notify's timeout would have
  elapsed; **activating that control writes the before/after report PAIR** (`reports/*.md` +
  `reports/*.html`) to the active project's reports directory — the SAME artifact the `b` key
  produces — and the `b` binding still writes the same pair (accelerator retained).
- **Shipped surface:** the Patch Editor panel (`PatchEditorPanel`, `screens_directionb.py:1765`);
  the save-back decision handler (`app.py:1713` `on_patch_editor_panel_save_back_decision`); the
  report writer `action_before_after_report` (`app.py:1856`, writes `result.md_path` /
  `result.html_path` via `compose_before_after_report`).
- **Deliverable + observation:** C-12 output-then-consume — the AT drives a real save-back so the
  handler reveals the persistent control, then **clicks the control** (a real `pilot.click`, not a
  proxy call) so the REAL `action_before_after_report` handler WRITES the pair, then **re-reads the
  produced `reports/*.md` from disk** and asserts the before/after report content (a known section
  heading + the file it names) is in the bytes actually written — never a file the AT wrote. C-10:
  the AT asserts (i) the control is queryable AFTER the notify would have expired (persistence, not
  a transient), and (ii) the specific report artifact exists with expected content, not "a file
  was written".
- **Acceptance test(s):** AT-061a (save-back → persistent control → click → report reread, one
  on-disk node — `tests/test_tui_patch_editor_v2.py` or `tests/test_before_after_report.py`).
- **Persistence proxy note (Q-06):** the AT proves persistence STRUCTURALLY — a durable widget
  (revealed `.hidden` row) survives an unrelated action / re-render, distinguishing it from a
  `notify` Toast. This proxy does NOT clock the notify wall-clock TTL; the assertion is
  widget-durability, not "outlived N seconds". Stated in the AT docstring so the proxy scope is
  explicit, not overclaimed.
- **Boundary catalog:** ☑ empty (save-back declined → no report control revealed; existing
  `event.filename is None` path, `app.py:1762`) · ☑ boundary (the `b` accelerator still writes the
  pair — asserted in the SAME node so the accelerator is not silently dropped) · ☑ boundary
  (clear-on-context, A-04: after a subsequent `load_doc`/`parse_paste` the control is re-`hidden`
  and no stale offer persists — LLR-061.1) · ☑ invalid (a refusal from `compose_before_after_report`,
  e.g. no `last_summary`, surfaces the composer's diagnostic on the status line, no file written —
  existing refusal arm `app.py:1937`) · ☑ error (C-23: the report row is height-starved on the
  5-row @80x24 panel — see LLR-061.3 geometry plan; persistence, not above-the-fold placement, is
  the acceptance).

### AT-062a — Entropy viewer pages past the 512-window cap to reach a later window (US-062)
- **Observable outcome:** given an image with **> 512 windows**, the operator navigates to
  **page 2** (0-based page index 1 = windows `[512, 1024)`, reachable in ONE `page_next` from page 0
  under the FIXED 512 page size, LLR-062.1) and the jump list then shows a window whose index is
  ≥ 512 (a window that is unreachable today because `self._windows[:ENTROPY_MAX_ROWS]` truncates at
  512 and only a truncation indicator is shown, `screens.py:686,703-706`); activating that later
  window still dismisses the modal with THAT window's `start` address.
- **Shipped surface:** `EntropyViewerScreen` (`screens.py:589`); the strip
  (`#entropy_strip`, `:684`) + jump list (`#entropy_jump_list`, `:698`); NEW page control(s)
  (`#entropy_page_*` NEW).
- **Deliverable + observation:** a Textual pilot (`app.run_test(size=...)`) pushes the entropy
  modal over a fixture with > 512 windows (reuse the `large_*` conftest generators), drives the
  page control (real key/click), reads `#entropy_jump_list` rows, and asserts a window with the
  correct `0xADDR band H=…` label for an index ≥ 512 is now listed AND that selecting it dismisses
  with that window's address. C-10: the AT asserts the SPECIFIC later-window content (address +
  band), not merely "more rows appeared". Presentation-only: `compute_entropy` is NOT called with
  different arguments — the same `self._windows` is paged.
- **Acceptance test(s):** AT-062a (page-past-cap + dismiss-with-address, one node —
  `tests/test_tui_entropy_viewer.py`).
- **Boundary catalog:** ☑ empty (0 windows → empty-state affordance `EMPTY_TEXT`, no pager
  rendered, `screens.py:650,673`) · ☑ boundary (exactly 512 windows → single page (page `1/1`), no
  pager or a disabled pager — VALID under the FIXED 512 page size, LLR-062.1; and the last window of
  the last page is reachable) · ☑ invalid (page index clamped to `[0, last_page]`; over-run does not
  crash) · ☑ error (a low-confidence window on a later page still renders dimmed, not dropped).

### AT-062b — Sort by entropy reorders strip + jump list so the top row is the highest-entropy window (US-062)
- **Observable outcome:** with sort set to **entropy (descending)**, the first jump-list row is the
  **highest-entropy** window in the image and the strip cell order matches; toggling back to
  **address** restores ascending-address order. Today the view is address-order only (`self._windows`
  is emitted in computation order, `screens.py:676,686`) with no sort control.
- **Shipped surface:** `EntropyViewerScreen`; the strip + jump list; NEW sort control
  (`#entropy_sort_*` NEW).
- **Deliverable + observation:** a pilot drives the sort control (real click/key), reads
  `#entropy_jump_list` row 0, and asserts its `H=…` value equals `max(w.entropy for w in windows)`
  and its address equals that window's `start` (C-10: the actual extremal window, not "row 0
  changed"). The strip cell order is asserted to follow the same permutation. Presentation-only:
  sorting reorders a copy of `self._windows` for display; `compute_entropy` is untouched.
- **Acceptance test(s):** AT-062b (sort-key reorder + strip/list consistency, one node —
  `tests/test_tui_entropy_viewer.py`).
- **Boundary catalog:** ☑ empty (0 windows → sort control absent/disabled) · ☑ boundary (ties in
  entropy → stable secondary sort by address, pinned in LLR-062.2) · ☑ invalid (N/A — sort key is
  a bounded enum) · ☑ error (sort interacts with paging: after a sort the pager resets to page 0 so
  the extremal window is on the visible page — asserted).

### AT-063a — Entropy band-colour legend present with each band's meaning (US-063)
- **Observable outcome:** the entropy modal displays a **legend** (`#entropy_legend` NEW) mapping
  **each** of the four `ENTROPY_BAND_COLOUR` bands to its meaning — grey→`constant/padding`,
  green→`low`, yellow→`medium`, red→`high/random` (`screens.py:569-574`) — plus the low-confidence
  `dim` cue (`ENTROPY_LOW_CONFIDENCE_STYLE`, `:579`). No legend exists today (`#entropy_legend`
  absent — probe P9).
- **Shipped surface:** `EntropyViewerScreen.compose` (`screens.py:683`); the new legend widget in
  `#entropy_body`.
- **Deliverable + observation:** a pilot pushes the modal and reads the legend widget's rendered
  rows; the AT asserts **all four band meaning strings** and the low-confidence cue are present
  (C-10 — the specific band→meaning mapping, not "a legend heading exists"). The legend rows are
  DERIVED from `ENTROPY_BAND_COLOUR` (single source), not hardcoded (TC-326).
- **Acceptance test(s):** AT-063a (legend content assertion, one node —
  `tests/test_tui_entropy_viewer.py`).
- **Boundary catalog:** ☑ empty (0 windows → the legend still renders — it documents the colour
  vocabulary, independent of window count; asserted with an empty image) · ☑ boundary (the four
  bands are the complete `ENTROPY_BAND_COLOUR` key-set — TC-326 pins `set(legend bands) ==
  set(ENTROPY_BAND_COLOUR)`) · ☑ invalid (N/A — static vocabulary) · ☑ error (N/A).

### AT-063b — Clicking a strip cell navigates to that window's region (US-063, C-16)
- **Observable outcome:** **clicking a strip cell** (a real pointer click on the `#entropy_strip`
  surface) dismisses the modal with **that cell's window `start` address** — the same
  dismiss-with-target the jump-list row performs (`on_list_view_selected` → `dismiss(target)`,
  `screens.py:722-728`). Today the strip is a plain `Static` with no click handler
  (`screens.py:684`), so a click does nothing.
- **Shipped surface:** `EntropyViewerScreen`; `#entropy_strip` (made click-navigable); the
  `ModalScreen[Optional[int]]` dismiss-with-address contract (`screens.py:622-627,728`).
- **Deliverable + observation:** **C-16** — the AT drives a REAL click via the pilot on the BASELINE
  per-cell clickable widget (`pilot.click("#entropy_cell_k")`, a deterministic widget click — no
  offset arithmetic; Q-03/A-05), NEVER a direct call to the click-action method, and asserts the
  modal dismissed with the SPECIFIC address of the clicked cell's window (C-10 — the exact address,
  not "an address was returned"). The click→window mapping goes through the shared
  `(sort,page,row)→window` helper fixed in LLR-063.2/LLR-062.2.
- **Acceptance test(s):** AT-063b (real-click → dismiss-with-address, one node —
  `tests/test_tui_entropy_viewer.py`).
- **Boundary catalog:** ☑ empty (0 windows → the strip shows `EMPTY_TEXT`, a click on it does NOT
  dismiss with an address — no window under the cursor; asserted no-op) · ☑ boundary (a click on
  the FIRST and the LAST visible cell of the current page each map to the correct window —
  first/last are the classic off-by-one edges) · ☑ invalid (a click on strip padding/whitespace
  beyond the last cell is a no-op, not a crash and not a wrong-window dismiss — the S-03
  `0 <= i < len` bound in `action_jump`) · ☑ error (C-16: the BASELINE per-cell clickable widget
  (`#entropy_cell_k`) makes the click deterministic — no offset resolution needed; the optional
  rung-1 `@click`-meta spike, if ever adopted, does not change the AT, which drives a real widget
  click either way).

### AT-064a — Refresh re-reads the selected patch/check file from disk into the editor (US-064a, C-12)
- **Observable outcome:** after the currently-selected change/check file on disk is changed
  externally, the operator presses **Refresh** (`#patch_doc_refresh_button` NEW) and the editor's
  entries table (`refresh_entries`, `screens_directionb.py:2201`) and issue lines
  (`refresh_issues`, `:2245`) reflect the **new** on-disk content — without re-typing the path or
  reloading the app. Today the only re-read is the `load_doc` action driven off
  `#patch_doc_path_input` (`app.py:1652-1659`); there is no one-action refresh of the currently
  selected file.
- **Shipped surface:** the Patch Editor change-file controls (`#patch_doc_file_select` /
  `#patch_doc_path_input`, `screens_directionb.py:1857`) + the NEW `#patch_doc_refresh_button`; the
  `ActionRequested` seam (`app.py:1577`); `ChangeService.load` (`change_service.py:581`) re-invoked
  over `ChangeService.document.source_path` (`model.py:250`), NOT the widget path-input (A-03).
- **Deliverable + observation:** C-12 output-then-consume — the AT WRITES an initial change file,
  loads it, then **overwrites that file on disk with new content**, presses Refresh, and reads the
  entries table / issue lines the REAL `ChangeService.load` produced (never a value the AT injected
  into the table). C-10: the AT asserts a specific entry that exists ONLY in the second on-disk
  version now appears (content, not "the table refreshed").
- **Acceptance test(s):** AT-064a (external-edit → refresh → re-read content, one node —
  `tests/test_tui_patch_editor_v2.py`).
- **Boundary catalog:** ☑ empty (`document.source_path is None` — no file-backed document, e.g.
  paste-authored/empty → Refresh surfaces the existing "enter a change-file path to load" guard,
  `app.py:1654`, no crash) · ☑ boundary (the file is refreshed to
  a document with 0 entries → table shows the empty state, `refresh_entries([])`) · ☑ invalid (the
  file is refreshed to malformed JSON → `MF-JSON-PARSE` finding surfaces via the existing
  collect-don't-abort path, `change_service.py:640`; the editor does not crash) · ☑ error (the file
  was deleted between load and refresh → the `load` read fault surfaces as a status diagnostic).

### AT-064b — JSON popup opens the current change-set + confirm applies the edit back (US-064b, C-12)
- **Observable outcome:** for a **paste-authored** change document (`document.source_path is None`,
  the only case the LLR-064b.4 guard lets the popup open) the operator opens the **JSON popup**
  (`ChangeSetJsonScreen` NEW, a `ModalScreen`) from the Patch Editor; the popup's large editable
  `TextArea` (`#changeset_json_text` NEW) shows the **current change-set JSON** (seeded from the
  `#patch_paste_text` buffer, `screens_directionb.py:1977`, which for a paste-authored document IS
  the document's editable source of truth); the operator edits it and confirms, and the **change
  document is updated** — the entries/issues the editor renders reflect the edited JSON, routed
  through the existing `parse_paste` → `ChangeService.load_text` (`app.py:1660-1662`,
  `change_service.py:633`) seam. Cancel leaves the document unchanged.
- **Shipped surface:** the Patch Editor (a NEW "Edit JSON" button, e.g. beside
  `#patch_paste_parse_button`, `screens_directionb.py:1979`, disabled when `source_path is not None`
  per LLR-064b.4); the NEW `ChangeSetJsonScreen` modal; the existing `load_text` apply seam.
- **Deliverable + observation (Q-07 — fixture seeds via PASTE, not `load`):** C-12
  output-then-consume — the AT FIRST seeds the change document via the PASTE path (parse a pasted
  change-set so `#patch_paste_text` holds real JSON and `document.source_path is None`), THEN opens
  the popup, sets a NEW valid change-set into `#changeset_json_text`, drives the real **Confirm**,
  and observes the CONSUMER — `ChangeService.document` (via the entries table / `service.rows()`),
  which the real `load_text` handler produced — asserting the edited entry is present (C-10 content),
  never inspecting only the TextArea the AT typed into, and never seeding via `load` (a file-loaded
  doc would be disabled per LLR-064b.4 — see AT-064c). A Cancel path asserts `service.document`
  unchanged.
- **Acceptance test(s):** AT-064b (paste-seed → popup open → edit → confirm → document reflects edit,
  one node — `tests/test_tui_patch_editor_v2.py`).
- **Boundary catalog:** ☑ empty (paste-authored document: open the popup → it shows the pasted-buffer
  JSON; confirm with no edit is a genuine no-op re-parse — VALID because buffer == document source
  when `source_path is None`, so no clobber; the false "no-op" claim for the FILE-loaded case is
  eliminated by the LLR-064b.4 guard, covered by AT-064c) · ☑ boundary (C-23: the popup `TextArea`
  shows N_w measured editable lines at 80x24 AND 120x30 — the readability the in-panel box cannot
  give at 80x24, per batch-36 F-01; N_w pilot-measured, LLR-064b.3) · ☑ invalid (confirm with
  malformed JSON → `MF-JSON-PARSE` finding surfaces via `load_text` collect-don't-abort; the popup
  either reports and stays open or applies the fault-carrying document — pinned in LLR-064b.2 — never
  crashes) · ☑ error (Cancel/Escape dismisses with no document mutation).

### AT-064c — "Edit JSON" is DISABLED for a file-backed document → no popup, no clobber (US-064b, A-01 blocker guard)
- **Observable outcome:** after the operator LOADS a change FILE from disk (via `load_doc`, so
  `ChangeService.document.source_path is not None`), the **"Edit JSON" control is disabled** and the
  JSON popup **cannot open** — so the stale `DUMMY_CHANGESET_TEXT` buffer can never be Confirmed to
  `load_text`-REPLACE the loaded document (the A-01 data-loss footgun is closed at the trigger). For a
  paste-authored / empty document (`source_path is None`) the same control is **enabled** and the
  popup opens (the AT-064b case) — the two states are asserted in ONE node so the guard is a real
  discriminator, not a constant.
- **Shipped surface:** the Patch Editor "Edit JSON" control (disabled-state driven by
  `document.source_path`, LLR-064b.4); `ChangeService.document.source_path` (`model.py:250`); the
  `load_doc` seam that sets it (`app.py:1652-1659` → `read_change_document`, `io.py:412,436`).
- **Deliverable + observation:** a Textual pilot (a) LOADS a real change file, asserts the Edit-JSON
  control is `disabled` and that attempting to open the popup does NOT push `ChangeSetJsonScreen`
  (queryable-absent) and does NOT invoke `load_text` (0 document mutation — the loaded document's
  entries are unchanged); then (b) parses a PASTED change-set (`source_path` back to `None`) and
  asserts the control is `enabled` and the popup opens. C-10: the guard predicate is asserted against
  BOTH `source_path` states (file → disabled/no-clobber; paste → enabled), never "the button exists".
- **Acceptance test(s):** AT-064c (file-loaded disable + paste-authored enable, one node —
  `tests/test_tui_patch_editor_v2.py`).
- **Boundary catalog:** ☑ empty (fresh app, no document loaded, `source_path is None` → enabled — the
  MVP paste path) · ☑ boundary (exactly at the file→paste transition: after a `load` the control
  disables; after a subsequent `parse_paste` it re-enables — the state tracks `source_path` live) · ☑
  invalid (a file load that yields a fault-carrying document still sets `source_path` → control
  disabled; the guard keys on `source_path is not None`, not on `document.has_errors`) · ☑ error (no
  document → guard defaults to the safe MVP paste path; the popup never opens against a file-backed
  doc).

## 4. HLR / LLR decomposition

### HLR-061 — Persistent, discoverable before/after-report surface (US-061)
- **Traceability:** US-061 · **Priority:** medium · **Validation:** test (pilot + report reread) ·
  **Ledger:** R-TUI-049 (proposed).
- **Statement:** The system shall present, after a successful patch save-back, a persistent
  operator-activatable control that remains queryable and actionable until the operator acts or the
  editing context changes, whose activation writes the same before/after report pair
  (`reports/*.md` + `reports/*.html`) that the `b` key binding produces, while leaving the report
  CONTENT (`compose_before_after_report`) and the `b` accelerator unchanged.
- **Rationale (informative):** today the only affordance after save-back is a transient
  `severity="information"` notify (`app.py:1794-1799`) that disappears after its timeout, so the
  before/after report is undiscoverable and easily missed; the `b` binding
  (`action_before_after_report`, `app.py:1856`) already writes both paths and stays as an
  accelerator. The reveal idiom already exists on the same panel — `show_save_prompt` /
  `hide_save_prompt` toggle the `.hidden` class on `#patch_saveback_row`
  (`screens_directionb.py:2280,2303`) — so a persistent report row is a like-for-like addition.
- **Executed verification:** `pytest tests/test_tui_patch_editor_v2.py tests/test_before_after_report.py -q`
  + AT-061a via `pytest -k at061`.
- **Numeric pass threshold:** 0 failures; the report control is queryable after the notify TTL and
  after re-render; activating it writes both `reports/*.md` and `reports/*.html`; the `b` path
  writes byte-identical output to the control path; the before/after report goldens are unchanged
  (C-24, LLR-061.3).

#### LLR-061.1 — Persistent report control revealed on successful save-back (reuse the `.hidden`-reveal idiom)
- **Traceability:** HLR-061 · **Validation:** test (pilot).
- **Statement:** `PatchEditorPanel` shall gain a persistent report control row
  (`#patch_before_after_row` — a `patch-field-label` heading + a `#patch_before_after_button`,
  `NEW — created in Phase 3`) that is `hidden` by default and revealed (its `.hidden` class removed,
  mirroring `show_save_prompt`, `screens_directionb.py:2280-2301`) by
  `on_patch_editor_panel_save_back_decision` (`app.py:1713`) on a successful save-back
  (`result.ok`); pressing it shall post a panel message that routes to
  `action_before_after_report`; the control shall remain present and queryable across re-render
  (persistence — it is NOT a `notify`).
- **Clear-on-context (A-04/Q-06, normative — owns the HLR-061 "until the editing context changes"
  clause):** the revealed control shall be re-`hidden` when the editing context changes — i.e. on a
  new document load (`load_doc` / `parse_paste`), which already resets
  `ChangeService.last_summary = None` (`change_service.py:617,669`), so the underlying report input
  is gone and a stale "report ready" offer must not persist. (Even absent the clear, a click after a
  context change is SAFE-by-refusal: with `last_summary is None` the writer's refusal arm surfaces a
  diagnostic and writes 0 files, `app.py:1937` — so clear-on-context is a UX-correctness pin, not a
  data-safety one.)
- **Validation:** test · **Executed verification:** AT-061a (control queryable after the notify TTL
  + click writes the pair + clear-on-context boundary arm) + TC-330 (reveal-on-`result.ok`,
  hidden-when-declined, re-hidden-on-new-load; button→action routing).
- **Numeric pass threshold:** `#patch_before_after_button` queryable after a successful save-back;
  absent/hidden after a declined save-back; re-hidden after a subsequent `load_doc`/`parse_paste`;
  pressing it invokes `action_before_after_report` once.
- **Acceptance criteria:** the transient `notify` MAY remain as a redundant hint but no longer
  GATES the feature; the control is the discoverable surface. C-23 geometry deferred to LLR-061.3.

#### LLR-061.2 — Activation writes the SAME before/after report pair the `b` path produces (C-12)
- **Traceability:** HLR-061 · **Validation:** test (report reread).
- **Statement:** Activating the persistent control shall invoke the existing
  `action_before_after_report` handler (`app.py:1856`) with no change to its arguments or to
  `compose_before_after_report`, so the written `reports/*.md` + `reports/*.html` pair is identical
  to the `b`-key output for the same `last_summary` + loaded image; the handler's refusal path
  (no `last_summary`, filter fault) shall surface its diagnostic on the status line and write
  nothing (unchanged, `app.py:1911-1915,1937`).
- **Validation:** test · **Executed verification:** AT-061a (C-12: click → real handler writes →
  reread the produced `reports/*.md` from disk, assert content) — the report-reread idiom
  (`tests/test_before_after_report.py`, and the report-seam reread `test_tui_report_seam.py:182-221`).
- **Numeric pass threshold:** the control path and the `b` path write byte-identical `*.md` /
  `*.html` for the same input; refusal path writes 0 files and surfaces the diagnostic.
- **Acceptance criteria:** no new report-writing code — the control is a second trigger onto the
  one writer (single-source; avoids a divergent report path).

#### LLR-061.3 — Zero report-content change (C-24 census) + geometry plan (C-23)
- **Traceability:** HLR-061 · **Validation:** test (census) + inspection (pilot geometry).
- **Statement:** The change shall NOT modify `compose_before_after_report`
  (`before_after_service.py:183`) nor any before/after report template, so no before/after report
  golden changes; and the persistent control shall be a queryable, activatable surface at both
  80x24 and 120x30, with its in-viewport placement PILOT-MEASURED (not fr-estimated) given the
  measured 5-row-@80x24 panel budget (batch-36 F-01).
- **C-24 report-content census (report TRIGGER touched, CONTENT not):** US-061 adds a second
  invoker of `action_before_after_report`; it does NOT change the composer. The before/after report
  goldens to CENSUS-CONFIRM unchanged: `tests/test_before_after_report.py` (composer output
  assertions). **Expected disposition: all SURVIVE unchanged (0 content diff).** Recorded so the
  C-24 obligation is discharged as "no content source changed" — LOW risk, but stated, not skipped.
- **C-23 geometry plan (pilot-measured in Phase 3 — NOT fr-math):** the report row lives on the
  height-starved `#patch_editor_panel` (MEASURED content 5 rows @80x24 / 11 @120x30, batch-36
  F-01/P24). Phase 3 shall drive `app.run_test(size=(80,24))` and `(120,30)`, reveal the row, and
  read its real `region` / the panel scroll `content_region`; **persistence + queryability +
  activation is the acceptance, NOT above-the-fold placement** (the row may sit below the fold and
  be reached by scroll at 80x24 — still a strict improvement over the transient notify). If a
  measured rung cannot make the row reachable at all, the fallback (rung-2) is a **durable status
  line** (`set_status`) restated on re-render instead of a button — also persistent + discoverable.
  Provisional: `assumed — pilot-measure in Phase 3`.
- **Validation:** test + inspection · **Executed verification:** AT-061a (persistence across
  re-render) + the C-24 census run + the Phase-3 geometry capture recorded at the gate.
- **Numeric pass threshold:** 0 before/after golden diffs; the control queryable at both widths.

### HLR-062 — Entropy viewer pagination + sort past the 512-window cap (US-062)
- **Traceability:** US-062 · **Priority:** medium · **Validation:** test (pilot) · **Ledger:**
  R-TUI-050 (proposed).
- **Statement:** The system shall let the operator, in the entropy viewer, (a) page through the
  windows beyond the `ENTROPY_STRIP_MAX_CELLS` / `ENTROPY_MAX_ROWS` = 512 cap so every computed
  window is reachable, and (b) sort the displayed strip + jump list by a chosen key (address or
  entropy) with the strip cell order and the jump-list row order kept consistent, WITHOUT changing
  the entropy computation (`entropy_service.compute_entropy` / the `self._windows` snapshot).
- **Rationale (informative):** today `self._windows[:ENTROPY_MAX_ROWS]` truncates the view to the
  first 512 windows in computation (address) order and only shows a truncation indicator
  (`screens.py:686,703-706`), so windows beyond 512 are invisible and the highest/lowest-entropy
  regions cannot be found. Paging + sorting are presentation transforms over the already-computed
  `self._windows` list.
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -q` + AT-062a + AT-062b via
  `pytest -k at062`.
- **Numeric pass threshold:** 0 failures; a window with index ≥ 512 is reachable and dismisses with
  its address; entropy-descending sort puts the max-entropy window at row 0; strip order follows the
  sort permutation; `compute_entropy` call count unchanged (snapshot untouched).

#### LLR-062.1 — Page the strip + jump list past the 512 cap (FIXED page size = 512)
- **Traceability:** HLR-062 · **Validation:** test (pilot + unit).
- **Statement:** `EntropyViewerScreen` shall render the strip and jump list one PAGE at a time over
  a page window of the (sorted) `self._windows`, where the **page size is FIXED at 512** — the
  existing `ENTROPY_STRIP_MAX_CELLS` / `ENTROPY_MAX_ROWS` = 512 caps (`screens.py:585-586`) become
  the per-page WINDOW BUDGET, NOT a hard truncation of the dataset and NOT a pilot-measured value;
  page controls (`#entropy_page_prev` / `#entropy_page_next` and/or `PgUp`/`PgDn` bindings,
  `NEW — created in Phase 3`) move the page index within `[0, ceil(len(windows)/512) - 1]`; both the
  strip cells and the jump rows on a page shall be drawn from the SAME 512-window page slice so their
  indices agree; the 512-row page renders INTO the `#entropy_body` scroll region
  (`overflow-y: auto`, `screens.py:707-717`) — the modal body SCROLLS to reveal rows below the fold
  (paging moves between 512-window blocks; the body scroll moves within a block); the truncation
  indicator (`#entropy_truncated` / `TRUNCATED_TEXT`, `screens.py:651,701-706`) shall be REPLACED by
  a page/position indicator with `page P/Q` semantics (P = 1-based current page, Q = total pages) —
  a silent drop no longer occurs because every window is reachable by paging.
- **Validation:** test · **Executed verification:** AT-062a (page beyond the first → reach a window
  index ≥ 512 + dismiss with its address; page 2 (0-based page index 1) = windows `[512, 1024)`,
  reachable in ONE `page_next` from page 0 because the page size is 512) + TC-324 (page-slice math:
  page index clamp; page slice `windows[p*512:(p+1)*512]`; last page reachable; strip slice ==
  jump slice; `page P/Q` indicator text).
- **Supersession (Q-02 — TWO truncation nodes, not one):** the truncation-semantics change breaks
  BOTH live nodes in `tests/test_tui_entropy_viewer.py` — `test_tc036_5_cost_cap_and_truncation`
  (`:345`, asserts `#entropy_truncated` present) AND `test_tc036_5_truncation_fires_on_either_cap`
  (`:384`, asserts the `min()` either-cap indicator present). Both assert `#entropy_truncated`
  (`:375,:418`), which no longer means "the tail is unreachable" once paging lands — the indicator
  becomes `page P/Q`. BOTH nodes shall be redefined to assert the `page P/Q` position indicator (not
  blanket-xfailed) IN THE SAME US-062 increment (Inc-3); recorded in the supersession census.
- **Numeric pass threshold:** page index clamped to `[0, last]`; `union of all page slices ==
  all windows` (no window unreachable); strip and jump list on a page cover the identical 512-window
  slice; both former-truncation nodes assert `page P/Q`.
- **Acceptance criteria:** the two caps `ENTROPY_STRIP_MAX_CELLS` / `ENTROPY_MAX_ROWS` = 512 become
  the per-page render budget (FIXED), NOT a hard truncation of the dataset; `compute_entropy` remains
  called exactly once at construction (`screens.py:655`).

#### LLR-062.2 — Sort the display by address or entropy (stable, presentation-only)
- **Traceability:** HLR-062 · **Validation:** test (pilot + unit).
- **Statement:** `EntropyViewerScreen` shall maintain a sort key (`address` default / `entropy`)
  toggled by a sort control (`#entropy_sort_button` or a `Select`, `NEW — created in Phase 3`) and
  shall render both surfaces from `sorted(self._windows, key=…)` — `address` → ascending `start`;
  `entropy` → **descending** `entropy` with a **stable secondary ascending `start`** tie-break — WITHOUT
  mutating `self._windows` (a display copy); changing the sort shall reset the page index to 0 so
  the extremal window is on the visible page.
- **Select→window remap (Q-04, normative):** `on_list_view_selected` today resolves the selected
  row via `self._windows[index]` over the RAW snapshot (`screens.py:722-728`, index bound
  `0 <= index < len(self._windows)` verified). Under sort+paging the jump list shows a sorted+paged
  SLICE, so the raw index no longer maps to the intended window. The handler shall be remapped to
  resolve the selected row through a SINGLE mapping helper `(sort, page, row) → window` — the SAME
  helper LLR-063.2's click path uses (no two divergent index schemes) — and shall preserve the
  `0 <= index < len(visible page slice)` bound. The existing `AT-036b`
  (`tests/test_tui_entropy_viewer.py:139-165`, `jump.index=1 → dismiss 0x4000`) is the LOAD-BEARING
  regression guard: it stays green only if the remap is correct (2 windows, address sort, page 0 →
  row 1 is still `0x4000`).
- **Validation:** test · **Executed verification:** AT-062b (entropy sort → row 0 is max-entropy;
  strip follows) + AT-036b (existing — select→window remap regression guard) + TC-325 (sort-key
  function: `entropy` desc + address tie-break; `self._windows` not mutated; page reset to 0 on sort
  change; `(sort,page,row)→window` helper resolves correctly).
- **Numeric pass threshold:** under `entropy` sort, row 0 `.entropy == max(...)`; ties broken by
  ascending address; `self._windows` order identical before/after (display copy only); page index
  == 0 after a sort toggle; AT-036b green (remap preserves the 2-window address-sort mapping).
- **Acceptance criteria:** the jump-list dismiss-with-address contract (`on_list_view_selected`,
  `screens.py:722-728`) resolves the selected ROW through the shared `(sort,page,row)→window` helper
  (index into the sorted+paged view, not the raw `self._windows`) — the SAME correctness pin carried
  into LLR-063.2's click mapping.

#### LLR-062.3 — Geometry: sort/page CONTROL + legend placement PILOT-MEASURED at 80x24 and 120x30 (C-23) — page size is FIXED-512, NOT measured
- **Traceability:** HLR-062 · **Validation:** test (pilot geometry).
- **Statement:** The **page size is FIXED at 512** (LLR-062.1) — it is NOT pilot-measured. What
  Phase-3 pilot-measures at 80x24 AND 120x30 is ONLY (a) the placement of the NEW page/sort CONTROL
  row and (b) the legend geometry (LLR-063.1) within the modal — read via a Textual pilot from
  `#entropy_body.content_region` (and the strip's wrapped width) after the new controls dock — NOT
  computed from CSS fr-arithmetic (batch-36 F-01: fr-math was ~4.5× off). The 512-window page renders
  into `#entropy_body`, which SCROLLS (`overflow-y: auto`), so the whole page need not fit above the
  fold; only the controls + legend must be reachable/non-overflowing.
- **C-23 geometry plan (budget approach; numbers are `assumed — pilot-measure in Phase 3`):** the
  entropy modal is `.modal-dialog` (`width: 70%`, `styles.tcss:1014-1022`) capped by `#entropy_dialog
  { height: 90% }` (`:1058-1060`); `#entropy_body { height: 1fr; overflow-y: auto }` (`:1062-1065`)
  scrolls; `.modal-buttons { dock: bottom }` (`:1077-1083`) and the `.modal-title` (`:1024`) consume
  fixed rows. Approx envelope: dialog ≈ 56 cols × 21 rows @80x24 / ≈ 84 cols × 27 rows @120x30
  (`assumed`); the NEW page+sort control row (docked above the body or in `#entropy_buttons`) and the
  legend (LLR-063.1) each subtract rows from the scrollable body — Phase-3 shall read their real
  `region` and PIN their placement per width. Because the body scrolls and the page size is a FIXED
  512-window logical block, no per-width page-size arithmetic is needed (the earlier "small measured
  page size" reading is RETIRED — see §6.5 A-02/Q-01).
- **Validation:** test · **Executed verification:** the Phase-3 pilot capture at both widths,
  recorded at the gate; AT-062a/AT-062b run at BOTH sizes (one node each, C-18).
- **Numeric pass threshold:** the page/sort controls + legend are reachable (visible or
  scroll-reachable) within `#entropy_body` at both widths with no horizontal overflow (LLR-036.3
  wrap-not-clip preserved); page size == 512 at both widths (fixed constant).

### HLR-063 — Entropy band legend + click-navigable strip (US-063)
- **Traceability:** US-063 · **Priority:** medium · **Validation:** test (pilot + unit) ·
  **Ledger:** R-TUI-051 (proposed).
- **Statement:** The system shall (a) show, in the entropy viewer, a legend mapping each
  `ENTROPY_BAND_COLOUR` band to its entropy meaning (plus the low-confidence dim cue), and (b) make
  each strip cell click-navigable so a real pointer click on a cell dismisses the modal with that
  window's `start` address — the same dismiss-with-target the jump-list row performs — without
  changing the entropy computation.
- **Rationale (informative):** the strip is band-coloured (`ENTROPY_BAND_COLOUR`, `screens.py:569-574`)
  but has no legend, so a colour's meaning is opaque; and the strip is a plain `Static`
  (`screens.py:684`) with no click handler, so only the jump-list rows navigate. The band colours are
  the viewer's OWN vocabulary (grey50/green/yellow/red), deliberately decoupled from the frozen
  `sev-*` severity classes and from `legend.py::LEGEND_TABLE` (A2L/MAC/Issues/Hex) — so the legend is
  built in-modal from `ENTROPY_BAND_COLOUR`, reusing the `legend.py` row-rendering PATTERN but not its
  severity table (D-063).
- **Executed verification:** `pytest tests/test_tui_entropy_viewer.py -q` + AT-063a + AT-063b via
  `pytest -k at063`.
- **Numeric pass threshold:** 0 failures; all four band meanings + the dim cue present in the legend;
  a real click on a strip cell dismisses with that cell's address.

#### LLR-063.1 — In-modal band legend derived from `ENTROPY_BAND_COLOUR` (single source)
- **Traceability:** HLR-063 · **Validation:** test (pilot + unit).
- **Statement:** `EntropyViewerScreen.compose` shall render a legend widget (`#entropy_legend`,
  `NEW — created in Phase 3`) inside `#entropy_body` whose rows are DERIVED by iterating
  `ENTROPY_BAND_COLOUR` (`screens.py:569-574`) — one row per band showing the band's colour swatch
  and its meaning string — plus one row documenting the `ENTROPY_LOW_CONFIDENCE_STYLE` (dim) cue; the
  meaning strings shall be authored free of Textual/console-markup metacharacters (`[` / `]`) if
  rendered through a markup-enabled `Label` (mirrors the batch-36 S-01 authoring constraint,
  `legend.py`), and shall NOT reference the frozen `sev-*` classes.
- **Validation:** test · **Executed verification:** AT-063a (all four meanings + dim cue present) +
  TC-326 (`set(legend bands) == set(ENTROPY_BAND_COLOUR)`; each meaning non-blank; no `[`/`]`; legend
  rows derived, not hardcoded — fails if a band is added to `ENTROPY_BAND_COLOUR` but not the legend).
- **Numeric pass threshold:** legend has exactly 4 band rows + 1 low-confidence row; band set ==
  `ENTROPY_BAND_COLOUR` keys; no meaning blank; no `[`/`]`.
- **Acceptance criteria:** reuses the `legend.py` colour→meaning ROW idiom but is a SEPARATE
  in-modal table (different colour domain) — NOT an entry in `LEGEND_TABLE` (which is severity
  artifacts); recorded so the non-reuse is a decision, not an omission.

#### LLR-063.2 — Click-navigable strip cells → dismiss-with-address (C-16 real mechanism)
- **Traceability:** HLR-063 · **Validation:** test (pilot click).
- **Statement:** Each rendered strip cell shall carry a click-navigation binding such that a real
  pointer click on the cell dismisses the modal with the corresponding window's `start` address,
  resolving the click to the window under the CURRENT sort + page through the shared
  `(sort, page, row) → window` helper (LLR-062.2 correctness pin). The **BASELINE mechanism**
  (deterministic, satisfies C-16, Q-03/A-05) shall be **per-cell clickable widgets**: the current
  page's cells are rendered as individual clickable widgets in a `Horizontal` container, each with a
  stable id (`#entropy_cell_k`, `NEW — created in Phase 3`) — bounded because at most one 512-window
  page of cells is live — and each posting the jump to `action_jump(i)`, which mirrors
  `on_list_view_selected` → `dismiss(window.start)` via the shared helper. The AT drives
  `pilot.click("#entropy_cell_k")` (a real widget click, no offset arithmetic). **`action_jump(i)`
  shall mirror the `on_list_view_selected` index bound** (`0 <= i < len(visible page slice)`, S-03)
  so a click on padding/whitespace beyond the last cell is a no-op, not an IndexError or wrong-window
  dismiss. The Rich `Text` `@click`-meta offset mechanism on the wrapped single `Static`
  (each `█` appended with `Style(meta={"@click": f"jump({i})"})`) — which has ZERO in-repo precedent
  (A-05; grep `@click`/`meta=` → only an unrelated `mac_meta=` at `app.py:7397`) and unproven
  wrapped-`Static` offset→cell resolution — is DEMOTED to an **OPTIONAL Phase-3 spike**, adopted ONLY
  if a pilot proves the offset hit; it is NOT the primary and NOT load-bearing.
- **Validation:** test · **Executed verification:** AT-063b (a REAL `pilot.click("#entropy_cell_k")`
  → modal dismisses with that cell's address, C-16) + TC-327 (index→window mapping under sort+page
  via the shared helper; `action_jump(i)` dismisses with the sorted-view window's `start`; the
  `0 <= i < len` bound → a click beyond the last cell is a no-op).
- **Numeric pass threshold:** a real click on cell k of the visible page dismisses with
  `sorted_windows[page_offset + k].start`; first-cell and last-cell clicks map correctly; an
  out-of-range click does not dismiss with an address (bound held, S-03).
- **Acceptance criteria:** the jump-list rows keep working unchanged (`on_list_view_selected`,
  `screens.py:722`); the click path and the list path resolve to the SAME window for the same
  logical index under the current sort — a single `(sort,page,row)→window` mapping helper, not two
  divergent index schemes. C-16 is satisfied by the deterministic per-cell-widget baseline; the
  rung-1 `@click`-meta spike is `assumed — optional, pilot-verify in Phase 3` and does not gate the
  story.

#### LLR-063.3 — Legend + strip geometry PILOT-MEASURED at 80x24 and 120x30 (C-23)
- **Traceability:** HLR-063 · **Validation:** test (pilot geometry).
- **Statement:** The legend row count and its placement within `#entropy_body` shall be validated
  against the MEASURED `#entropy_body.content_region` at 80x24 AND 120x30 (shared with the LLR-062.3
  capture), never fr-estimated; the legend + one page of strip/jump content shall fit within or
  scroll cleanly inside the body with no horizontal overflow at both widths.
- **Validation:** test · **Executed verification:** the shared Phase-3 pilot capture (LLR-062.3) +
  AT-063a run at both widths.
- **Numeric pass threshold:** legend visible (or scroll-reachable) at both widths; no horizontal
  overflow; `assumed — pilot-measure in Phase 3` for the exact legend/body row split.

### HLR-064a — Patch-editor refresh: re-read the selected change/check file from disk (US-064a)
- **Traceability:** US-064a · **Priority:** medium · **Validation:** test (pilot) · **Ledger:**
  R-TUI-052 (proposed).
- **Statement:** The system shall provide a one-action refresh in the Patch Editor that re-reads the
  currently-selected change/check file from disk through the existing `ChangeService.load` path and
  re-renders the entries table + issue lines, so external edits to that file are reflected without
  re-typing the path or reloading the application, and without changing the change-set schema or the
  apply engine.
- **Rationale (informative):** today re-reading requires re-driving the `load_doc` action off the
  `#patch_doc_path_input` value (`app.py:1652-1659`); there is no single control that re-reads the
  file currently named by `#patch_doc_file_select` / `#patch_doc_path_input`. Refresh is a thin
  re-invocation of the existing `load` seam over the current selection — no new read surface.
- **Executed verification:** `pytest tests/test_tui_patch_editor_v2.py -q` + AT-064a via
  `pytest -k at064a`.
- **Numeric pass threshold:** 0 failures; after an external edit, refresh shows the new content in
  the entries table / issue lines; malformed/missing-file faults surface via the existing
  collect-don't-abort diagnostics without crashing.

#### LLR-064a.1 — Refresh re-invokes `ChangeService.load` over the current selection
- **Traceability:** HLR-064a · **Validation:** test (pilot).
- **Statement:** `PatchEditorPanel` shall gain a `#patch_doc_refresh_button` (`NEW — created in
  Phase 3`) that posts an `ActionRequested` (a new `"refresh_doc"` action) so `app.py` re-invokes
  `ChangeService.load` over **`ChangeService.document.source_path`** (the resolved path the currently
  loaded document was read from, `model.py:250,453`; set to `resolved` by `read_change_document`,
  `io.py:412,436`) — **NOT** the live `#patch_doc_path_input` widget value (A-03): refresh means
  "re-read THAT file to reflect external edits", so a post-load edit of the path input must NOT
  redirect refresh to a different file (that is "load", not "refresh"). It then calls
  `refresh_entries` (`screens_directionb.py:2201`) + `refresh_issues` (`:2245`) with the re-read
  result; when no document is loaded (`document.source_path is None`, e.g. paste-authored or empty)
  it shall surface the existing "enter a change-file path to load" guard (`app.py:1654`), not crash.
- **Validation:** test · **Executed verification:** AT-064a (external-edit → refresh → new content)
  + TC-328 (refresh dispatches `ChangeService.load` with `document.source_path`, NOT the widget
  value; a post-load path-input edit does NOT redirect refresh; entries/issues re-read from the
  returned document; `source_path is None` guard).
- **Numeric pass threshold:** refresh calls `ChangeService.load` once with `document.source_path`;
  the entries table reflects the second on-disk version; `source_path is None` → guard message,
  0 crash.
- **Acceptance criteria:** refresh reuses the existing `load` seam (no new file-read code); the
  markup-inert `set_status` / `refresh_*` funnels carry all output (no injection surface, C-17 N/A).

#### LLR-064a.2 — Zero behaviour change to existing patch controls + id preservation
- **Traceability:** HLR-064a · **Validation:** test (pilot regression).
- **Statement:** The refresh addition shall not alter any existing `on_button_pressed` branch,
  handler, or key binding, and shall preserve every existing patch-editor widget id (the batch-36
  15-id census, `screens_directionb.py:1806-1998`) plus the AT-032a `_CHECKS_HELP_TOKEN` span; it
  adds one new button id only.
- **Validation:** test · **Executed verification:** AT-064a boundary (existing load/validate/apply/
  save/run-checks unaffected) + the existing `tests/test_tui_patch_editor_v2.py` suite rerun green.
- **Numeric pass threshold:** all 15 existing ids queryable; new `#patch_doc_refresh_button`
  queryable; existing patch suite green with 0 assertion-body edits.
- **Acceptance criteria:** mirrors the batch-35/36 no-behaviour-change contract (LLR-058.3); the
  new control is additive.

### HLR-064b — Patch-editor JSON popup: edit the change-set in a full-size modal + apply back (US-064b)
- **Traceability:** US-064b · **Priority:** medium · **Validation:** test (pilot + apply reread) ·
  **Ledger:** R-TUI-053 (proposed).
- **Statement:** The system shall provide a modal JSON editor, opened from the Patch Editor, that
  presents the current change-set JSON in a large editable surface and, on confirm, applies the
  edited text back to the change document through the existing `ChangeService.load_text` seam, with
  Cancel leaving the document unchanged and the change-set schema/apply engine unmodified.
- **Rationale (informative):** the in-panel paste box (`#patch_paste_text`,
  `screens_directionb.py:1977`) cannot show a readable multi-line change-set at 80x24 (the
  height-starved panel, batch-36 F-01 — the "expand-to-edit" affordance deferred there); a modal
  editor gets the full dialog budget. The apply-back reuses the exact seam the "Parse pasted" action
  already uses (`parse_paste` → `ChangeService.load_text`, `app.py:1660-1662`,
  `change_service.py:633`), so no serializer or schema change is introduced.
- **Executed verification:** `pytest tests/test_tui_patch_editor_v2.py -q` + AT-064b via
  `pytest -k at064b`.
- **Numeric pass threshold:** 0 failures; the popup shows the current change-set; confirm updates
  `ChangeService.document` (entries reflect the edit); Cancel leaves it unchanged; malformed JSON
  surfaces `MF-JSON-PARSE` via collect-don't-abort, no crash.

#### LLR-064b.1 — JSON popup modal seeded from the current change-set buffer
- **Traceability:** HLR-064b · **Validation:** test (pilot).
- **Statement:** A new `ChangeSetJsonScreen(ModalScreen)` (`NEW — created in Phase 3`) shall be
  opened from the Patch Editor by a new "Edit JSON" control (e.g. beside `#patch_paste_parse_button`,
  `screens_directionb.py:1979`) — **subject to the LLR-064b.4 disable-guard (opens only for a
  paste-authored / empty document)** — presenting a large editable `TextArea` (`#changeset_json_text`,
  `NEW`) seeded with the current `#patch_paste_text` buffer content (the editable source of truth for
  pasted change-sets), and shall carry Confirm + Cancel controls following the shared `.modal-dialog`
  / `.modal-buttons` box model (`styles.tcss:1014-1095`). Any paste INTO `#changeset_json_text` shall
  route through the existing `os_clipboard_input` 65 536-char clipboard funnel
  (`os_clipboard_input.py:72`) — the SAME bound `#patch_paste_text` uses — NOT a second uncapped
  ingress (S-01).
- **Validation:** test · **Executed verification:** AT-064b (popup shows the current paste buffer) +
  TC-329 (seed == `#patch_paste_text` value; Confirm returns the edited text; Cancel returns
  None/no-mutation).
- **Numeric pass threshold:** the popup `TextArea` initial text equals the `#patch_paste_text`
  value at open; Confirm yields the edited text; Cancel yields no document change.
- **Acceptance criteria / scope boundary (RESOLVED at Phase 2 — was open question):** the popup edits
  the PASTE BUFFER JSON only. Reflecting a FILE-loaded document (loaded via `load`, where
  `#patch_paste_text` still holds `DUMMY_CHANGESET_TEXT`) would require a `document → JSON text`
  serializer, which does NOT exist on `ChangeService` today (verified — only `load` / `load_text`, no
  `to_text`/`serialize`, `change_service.py`; A-01 re-verified). Because seeding from the stale paste
  buffer while a file is loaded and then Confirming would `load_text`-REPLACE the loaded document
  (`change_service.py:668`) = SILENT DATA LOSS, the MVP is made SAFE by the LLR-064b.4 disable-guard:
  the Edit-JSON control is DISABLED whenever `document.source_path is not None`, so the popup opens
  ONLY for a paste-authored/empty document. A file-loaded round-trip remains a separate future
  serializer LLR. **No longer flagged open — closed by the disable-guard (LLR-064b.4).**

#### LLR-064b.2 — Confirm applies the edited text back via `ChangeService.load_text` (C-12)
- **Traceability:** HLR-064b · **Validation:** test (apply reread).
- **Statement:** On Confirm, the popup's edited text shall be written back to `#patch_paste_text`
  and routed through the existing `parse_paste` → `ChangeService.load_text` path
  (`app.py:1660-1662`) so `ChangeService.document` is replaced and the entries table / issue lines
  re-render from the parsed document (collect-don't-abort: malformed JSON yields a
  finding-carrying document, never a raise, `change_service.py:640`); on Cancel the document and the
  buffer shall be left unchanged.
- **Validation:** test · **Executed verification:** AT-064b (C-12: Confirm → real `load_text` →
  observe `ChangeService.document` / `service.rows()` reflect the edited entry, never the TextArea
  the AT typed) + TC-329 (Confirm calls `load_text` with the edited text; malformed → `MF-JSON-PARSE`
  finding; Cancel → 0 `load_text` call).
- **Numeric pass threshold:** after Confirm with a valid edit, `service.document` contains the new
  entry; after Cancel, `service.document` identical to pre-open; malformed confirm → finding
  surfaced, 0 crash.
- **Acceptance criteria:** single apply seam (`load_text`) — no second parse path; the popup is a
  richer editor over the SAME buffer + SAME parser the inline box uses.

#### LLR-064b.3 — Popup editor geometry PILOT-MEASURED at 80x24 and 120x30 (C-23)
- **Traceability:** HLR-064b · **Validation:** test (pilot geometry).
- **Statement:** The popup `TextArea` shall show at least **N_w** visible editable lines, where
  **N_w is a per-width MEASURED pin** read from the modal's real `content_region` at 80x24 AND
  120x30 via a Textual pilot — NOT fr-estimated — each strictly greater than the ~0-1 in-viewport
  lines the in-panel box gives at 80x24 (batch-36 F-01); the dialog shall not overflow horizontally
  at either width.
- **C-23 geometry plan (budget approach; numbers `assumed — pilot-measure in Phase 3`):** the popup
  is `.modal-dialog` (`width: 70%`, `height: auto` unless capped, `styles.tcss:1014-1022`); a modal
  gets the FULL screen budget (unlike the starved patch panel), so the `TextArea` can occupy the bulk
  of the dialog — approx `#changeset_json_text` ≈ 15-18 rows @80x24 / ≈ 22-25 @120x30 (`assumed`) —
  but the ACHIEVABLE line count MUST be read from `#changeset_json_text.content_region` after the
  Confirm/Cancel buttons dock, then N_w PINNED per width at the Phase-3 gate. This is the readable
  multi-line editing surface the in-panel box could not provide at 80x24.
- **Validation:** test · **Executed verification:** AT-064b boundary (N_w visible lines at both
  widths — content-region placement idiom, `test_tui_patch_variant.py:427-438`) + the Phase-3
  capture recorded at the gate.
- **Numeric pass threshold:** `#changeset_json_text` shows ≥ N_80 lines @80x24 and ≥ N_120 @120x30
  (Phase-3-measured, each > the in-panel box's 80x24 count); no horizontal overflow.

#### LLR-064b.4 — "Edit JSON" DISABLED for a file-backed document (data-loss guard, A-01 blocker)
- **Traceability:** HLR-064b · **Validation:** test (pilot).
- **Statement:** The "Edit JSON" trigger (the new button / any binding that opens
  `ChangeSetJsonScreen`) shall be DISABLED (or otherwise refuse to open the popup) whenever the
  loaded change document is file-backed — `ChangeService.document.source_path is not None`
  (`model.py:250`; set to `resolved` by `read_change_document`, `io.py:412,436`; `None` for a
  paste-authored/empty document, `io.py:458,515,575`). The popup shall open ONLY for a
  paste-authored / empty document (`source_path is None`), which is the MVP scope. Rationale
  (A-01, re-verified): a file load refreshes only the entries table and NEVER updates
  `#patch_paste_text` (`app.py:1652-1659`), so with a file loaded the popup would seed from the
  STALE `DUMMY_CHANGESET_TEXT` buffer (`screens_directionb.py:1977`) — not "the current change-set"
  — and Confirm would `load_text`-REPLACE the loaded document with the dummy-derived change-set
  (`change_service.py:667-668`) = SILENT DATA LOSS (no `document → JSON` serializer exists to
  round-trip the loaded doc). Disabling the trigger removes the footgun at its source; the enabled
  path (`source_path is None`) is exactly the case where `#patch_paste_text` IS the document's
  editable source of truth, so seed-then-`load_text` is a faithful round-trip.
- **Validation:** test · **Executed verification:** AT-064c (file loaded → Edit-JSON control disabled
  → no popup, no `load_text` clobber; paste-authored → control enabled → popup opens) + TC-331
  (guard predicate: `source_path is not None → disabled`; `source_path is None → enabled`).
- **Numeric pass threshold:** with a file-backed document (`source_path is not None`) the Edit-JSON
  control is disabled and opening the popup is impossible (0 `load_text` invocations from this path);
  with a paste-authored/empty document (`source_path is None`) the control is enabled and the popup
  opens.
- **Acceptance criteria:** the disable-guard is the data-safety boundary for US-064b MVP; it makes
  AT-064b's "confirm no-op re-parse" boundary valid (that boundary now applies ONLY to the
  paste-authored case, where buffer == document source). A file-loaded round-trip is out of MVP
  scope (would need a serializer LLR).

## 5. Traceability

### 5.1 Behavioral chain (US → AT → observable outcome, black-box)

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-061 | Persistent report control present after save-back (survives notify TTL); activating it writes the same before/after `*.md`+`*.html` pair the `b` path writes | Patch Editor panel + `reports/*` | AT-061a | Phase 4 |
| US-062 | A window with index ≥ 512 is reachable via paging + dismisses with its address | Entropy viewer modal | AT-062a | Phase 4 |
| US-062 | Entropy-descending sort puts the max-entropy window at row 0; strip follows | Entropy viewer modal | AT-062b | Phase 4 |
| US-063 | Legend maps each band colour to its meaning (+ dim cue) | Entropy viewer modal | AT-063a | Phase 4 |
| US-063 | A REAL click on a strip cell dismisses with that cell's address (C-16) | Entropy viewer modal | AT-063b | Phase 4 |
| US-064a | External on-disk edit + Refresh (over `document.source_path`) → editor shows the new content (C-12) | Patch Editor panel | AT-064a | Phase 4 |
| US-064b | JSON popup (paste-authored doc) shows the current change-set; Confirm updates the change document (C-12) | Patch Editor JSON modal | AT-064b | Phase 4 |
| US-064b | "Edit JSON" DISABLED for a file-backed document → no popup, no `load_text` clobber (A-01 data-loss guard) | Patch Editor "Edit JSON" control | AT-064c | Phase 4 |

### 5.2 Functional chain (US → HLR → LLR → TC/AT, white-box)

| US | HLR | LLR | Test case / AT | Notes |
|----|-----|-----|----------------|-------|
| US-061 | HLR-061 | LLR-061.1 | AT-061a + TC-330 | persistent control revealed on `result.ok`; reuse `.hidden` idiom |
| US-061 | HLR-061 | LLR-061.2 | AT-061a | C-12: activation → real `action_before_after_report` writes the pair; reread |
| US-061 | HLR-061 | LLR-061.3 | AT-061a | C-24 census (before/after goldens SURVIVE, composer untouched); C-23 geometry plan |
| US-062 | HLR-062 | LLR-062.1 | AT-062a + TC-324 | FIXED 512 page size; page slices cover all windows; index ≥ 512 reachable on page 2; `page P/Q` indicator (both truncation nodes) |
| US-062 | HLR-062 | LLR-062.2 | AT-062b + AT-036b + TC-325 | entropy sort desc + address tie-break; `self._windows` not mutated; page reset; select→window remap via shared helper (AT-036b regression guard) |
| US-062 | HLR-062 | LLR-062.3 | AT-062a/AT-062b (both widths) | C-23: sort/page CONTROL + legend placement pilot-measured; page size FIXED-512 (not measured) |
| US-063 | HLR-063 | LLR-063.1 | AT-063a + TC-326 | legend rows derived from `ENTROPY_BAND_COLOUR`; no `[ ]`; not `LEGEND_TABLE` |
| US-063 | HLR-063 | LLR-063.2 | AT-063b + TC-327 | C-16 real click → dismiss-with-address; rung-2 per-cell widget (`#entropy_cell_k`) BASELINE, rung-1 `@click`-meta optional spike; shared helper; S-03 index bound |
| US-063 | HLR-063 | LLR-063.3 | AT-063a (both widths) | C-23: legend/body split pilot-measured (shared capture w/ 062.3) |
| US-064a | HLR-064a | LLR-064a.1 | AT-064a + TC-328 | refresh re-invokes `ChangeService.load` over `document.source_path` (A-03); `source_path is None` guard |
| US-064a | HLR-064a | LLR-064a.2 | AT-064a | 15-id census survives + one new button id; existing wiring intact |
| US-064b | HLR-064b | LLR-064b.1 | AT-064b + TC-329 | `ChangeSetJsonScreen` seeded from `#patch_paste_text`; scope: paste-buffer edit; paste→65 KiB funnel (S-01) |
| US-064b | HLR-064b | LLR-064b.2 | AT-064b + TC-329 | C-12: Confirm → real `load_text` → document reflects edit; Cancel no-op |
| US-064b | HLR-064b | LLR-064b.3 | AT-064b (both widths) | C-23: popup N_w editable lines pilot-measured |
| US-064b | HLR-064b | LLR-064b.4 | AT-064c + TC-331 | A-01 data-loss guard: "Edit JSON" DISABLED when `document.source_path is not None`; enabled for paste-authored |

**Coverage:** 5 US → 5 HLR → **15 LLR**; every HLR traces to exactly one US; every LLR to its parent
HLR; every US has ≥1 AT observing its outcome through the shipped surface. New ATs: **AT-061a,
AT-062a, AT-062b, AT-063a, AT-063b, AT-064a, AT-064b, AT-064c (8)** (AT-064c added by the A-01 fold;
`AT-036b` is an EXISTING test reused as the LLR-062.2 select→window remap regression guard — not a
new AT). New TCs: **TC-324 (062.1 page math + `page P/Q`), TC-325 (062.2 sort key + remap helper),
TC-326 (063.1 legend derive), TC-327 (063.2 click map + bound), TC-328 (064a.1 refresh dispatch over
`source_path`), TC-329 (064b popup seed+apply), TC-330 (061.1 reveal+route+clear-on-context),
TC-331 (064b.4 disable-guard predicate) (8)**.

**TC crosswalk (Q-05 — reconcile the 01b story-scoped ids to the sequential §5.2 ids; the sequential
`TC-324…331` are canonical):** `TC-061-1 ↔ TC-330` · `TC-062-1 ↔ TC-325` · `TC-062-2 ↔ TC-324` ·
`TC-063-1 ↔ TC-326` (+ `TC-327` click-map, no 01b local id) · `TC-064-1 ↔ TC-328` ·
`TC-064-2 ↔ TC-329` · `TC-331` (064b.4 disable-guard, NEW at this fold, no 01b local id). Any
`TC-0NN-N`-style local id in `01b` is DROPPED in favour of `TC-324…331`.

## 6. Probe ledger, draft-time findings, decisions, evidence checklist

### 6.1 Probe ledger (executed at draft, 2026-07-11, tree `978a900`)

| # | Claim to verify | Probe (file:line / command) | Result |
|---|-----------------|-----------------------------|--------|
| P1 | Highest AT id in tree | `grep -rhoE 'AT-[0-9]{3}[a-z0-9]?'` | max numeric `AT-060` (batch-36; `-0NNx` = counterfactual markers) → **AT-061a free** ✓ |
| P2 | Highest TC id in use | `grep -rhoE 'TC-[0-9]{3}'` | max **TC-323** → continue **TC-324** ✓ |
| P3 | Highest R-TUI id | `grep -rhoE 'R-TUI-[0-9]{3}'` | max **R-TUI-048** → 049-053 free ✓ |
| P4 | US-061 transient notify offer site | `app.py:1794-1799` (`self.notify(... "press b ...", severity="information")`) | transient-only affordance confirmed ✓ |
| P5 | US-061 `b` binding + report writer | `app.py:798` `Binding("b","before_after_report")`; `action_before_after_report` `:1856` writes `result.md_path`+`result.html_path` via `compose_before_after_report` `:1924` | `b` writes a `*.md`+`*.html` pair ✓ |
| P6 | US-061 save-back handler + reveal idiom | `app.py:1713` `on_patch_editor_panel_save_back_decision` (notify at `:1788-1799` on `result.ok`); `screens_directionb.py:2280` `show_save_prompt`/`:2303` `hide_save_prompt` toggle `.hidden` on `#patch_saveback_row` | persistent reveal idiom exists to reuse ✓ |
| P7 | US-061 report composer (C-24 target) | `before_after_service.py:183` `compose_before_after_report`; goldens `tests/test_before_after_report.py` | composer NOT touched → 0 content change ✓ |
| P8 | US-062 entropy caps + truncation | `screens.py:585-586` (`ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS = 512`); strip `:676` `self._windows[:MAX]`; jump `:686`; truncation indicator `:703-706` | >512 windows unreachable today (RED) ✓ |
| P9 | US-062 snapshot computed once | `screens.py:655` `self._windows = compute_entropy(mem_map)` in `__init__` | paging/sort are display-only over the snapshot ✓ |
| P10 | US-062/063 window fields | `screens.py:691` `window.start` / `window.band` / `window.entropy`; `on_list_view_selected` `:722-728` `dismiss(target)` | sort-by-entropy + dismiss-with-address available ✓ |
| P11 | US-063 band colours (viewer-owned) | `screens.py:569-574` `ENTROPY_BAND_COLOUR` = grey50/green/yellow/red; `:579` `ENTROPY_LOW_CONFIDENCE_STYLE="dim"`; comment `:565-568` "NOT the sev-* classes" | legend built in-modal from this map, not `LEGEND_TABLE` ✓ |
| P12 | US-063 no legend / no click today | `grep entropy_legend/on_click screens.py` → 0; strip is `Static(self._strip_text(), id="entropy_strip")` `:684` | legend + click both RED today ✓ |
| P13 | Entropy modal geometry (C-23) | `styles.tcss:1014-1022` `.modal-dialog {width:70%; height:auto}`; `:1058-1065` `#entropy_dialog{height:90%}` / `#entropy_body{height:1fr; overflow-y:auto}`; `:1077-1083` `.modal-buttons{dock:bottom}` | body scrolls → page size must be MEASURED, not fr-math ✓ |
| P14 | US-064a refresh seam | `app.py:1652-1659` `load_doc` → `service.load(event.path_text, self.base_dir)`; `#patch_doc_path_input`/`#patch_doc_file_select` `screens_directionb.py:1857` | refresh = re-invoke `load` over the selection ✓ |
| P15 | US-064a re-render seam | `screens_directionb.py:2201` `refresh_entries` / `:2245` `refresh_issues` (called at `app.py:1710-1711`) | entries+issues re-render after re-read ✓ |
| P16 | US-064b apply-back seam | `app.py:1660-1662` `parse_paste` → `service.load_text(event.paste_text)`; `#patch_paste_text` `screens_directionb.py:1977` | popup Confirm routes through `load_text` ✓ |
| P17 | US-064b change document model + no serializer | `change_service.py:633` `load_text` sets `self.document = parse_change_document(text)`; `:581` `load`; NO `to_text`/`serialize`/`as_text` (grep 0) | popup seeds from `#patch_paste_text` buffer; file-loaded round-trip needs a new serializer (scope flag) ✓ |
| P18 | US-064b collect-don't-abort | `change_service.py:640` (`MF-JSON-PARSE` on decode failure, "the parser never raises") | malformed confirm → finding, no crash ✓ |
| P19 | US-064 15-id census baseline | `screens_directionb.py:1806-1998` (patch_* ids incl `#patch_paste_text:1977`, `#patch_paste_parse_button:1979`, `#patch_saveback_*:1986-1993`) | refresh + Edit-JSON add ids only; census preserved ✓ |
| P20 | Git base (batch-36 merged) | `git log --oneline -1` → `978a900` "batch-36 canonical snapshot baselines" | base tip = HEAD; ids 049+/324+/061+ free ✓ |

### 6.2 Draft-time findings (contradictions reconciled)
- **DF-1 (US-061) — "persistent surface" placement is height-constrained.** The persistent report
  control lives on the batch-36-measured 5-row-@80x24 patch panel (F-01/P24). It CANNOT be
  guaranteed above-the-fold at 80x24 without more budget. Reconciliation: the acceptance is
  PERSISTENCE + queryability + activation (survives the notify TTL, reachable by scroll), NOT
  above-the-fold placement (LLR-061.3); rung-2 fallback is a durable status line. This is a real
  improvement over the transient notify regardless of fold position.
- **DF-2 (US-064b) — "opens the change-set" vs. no serializer → A-01 data-loss footgun, RESOLVED at
  Phase-2 by a disable-guard.** The story implies the popup shows the CURRENT change document, but
  `ChangeService` has no `document → JSON` serializer (P17), so a FILE-loaded doc (where
  `#patch_paste_text` still holds `DUMMY_CHANGESET_TEXT`) cannot be round-tripped without new code.
  The Phase-2 architect review (A-01) showed the paste-buffer MVP was not merely limited but UNSAFE:
  with a file loaded, opening the popup seeds the stale DUMMY buffer and Confirm `load_text`-REPLACES
  the loaded document = silent data loss (re-verified: `app.py:1652-1659` load never touches
  `#patch_paste_text`; `change_service.py:667-668` replaces `self.document`). Reconciliation
  (LLR-064b.4): the Edit-JSON control is DISABLED when `document.source_path is not None`, so the
  popup opens ONLY for a paste-authored/empty document — the exact case where the paste buffer IS the
  document's editable source of truth and seed-then-`load_text` is a faithful round-trip. AT-064c is
  the file-loaded boundary AT (disabled → no clobber). A file-loaded round-trip remains a separate
  future serializer LLR. **Closed by the disable-guard, no longer an open Phase-2 flag.**
- **DF-3 (US-063) — band colours are NOT the shared legend vocabulary.** `ENTROPY_BAND_COLOUR`
  (grey50/green/yellow/red) is the viewer's own map, decoupled from `sev-*` and from
  `legend.py::LEGEND_TABLE` (severity artifacts). Reconciliation: build the entropy legend in-modal
  from `ENTROPY_BAND_COLOUR` (single source), reusing only the `legend.py` row-rendering PATTERN —
  NOT an entry in `LEGEND_TABLE` (D-063). Recorded so the non-reuse is a decision.

### 6.3 Design decisions
- **D-061 — persistent report control = a revealed `.hidden` row reusing the `#patch_saveback_row`
  idiom**, routing to the existing single writer `action_before_after_report` (no second report
  path); the notify may stay as a redundant hint but no longer gates the feature; the `b`
  accelerator is retained. C-24: composer untouched → goldens survive.
- **D-062 — paging + sort are display transforms over the `self._windows` snapshot.** The caps
  become a FIXED per-page window budget of 512 (A-02/Q-01 — NOT a pilot-measured budget), not a
  dataset truncation; the 512-window page renders into the scrolling `#entropy_body`; sort is a
  display copy (never mutating `self._windows`); `compute_entropy` stays called once; sort resets the
  page to 0; a shared `(sort,page,row)→window` helper feeds both the jump-list select and the click
  path (Q-04); the truncation indicator becomes `page P/Q` (both truncation nodes redefined, Q-02).
- **D-063 — entropy legend is in-modal, built from `ENTROPY_BAND_COLOUR`** (not `LEGEND_TABLE`);
  strip click-navigation BASELINE = per-cell clickable widgets (`#entropy_cell_k`, rung 2 —
  deterministic, guaranteed-testable, satisfies C-16, Q-03/A-05), with the Rich `Text` `@click`-meta
  action-link (former rung 1) demoted to an OPTIONAL Phase-3 spike (zero in-repo precedent, A-05).
  C-16: the AT drives a real widget click.
- **D-064a — refresh re-invokes the existing `ChangeService.load` over `document.source_path`** (A-03,
  NOT the widget path-input) — a thin additive control, no new read surface, existing
  collect-don't-abort diagnostics; a post-load path-input edit does not redirect refresh.
- **D-064b — JSON popup edits the paste-buffer JSON through the existing `load_text` apply seam**;
  MVP scope = paste-authored/empty document ONLY, ENFORCED by the LLR-064b.4 disable-guard
  (`source_path is not None → Edit-JSON disabled`, A-01 data-loss guard); popup paste routes through
  the 65 KiB clipboard funnel (S-01); modal box model reuses `.modal-dialog`/`.modal-buttons`.
- **D-SPLIT — US-064 splits into US-064a (refresh) + US-064b (popup)** — independent, differently
  shaped, separate increments (see §6.6 increment-cut).

### 6.4 Evidence checklist
- ✓ **Constraints stated explicitly** — each story's scope boundary (US-061 report content + `b`
  key unchanged; US-062 computation unchanged; US-063 computation unchanged, jump-list reused;
  US-064 schema/apply engine unchanged, undo/redo excluded) is carried into the HLR/LLR statements.
- ✓ **Normative-keyword compliance** — `shall` only in HLR/LLR statements (§4); informative prose
  uses plain indicative / `should`; verified by reading each statement block.
- ✓ **Traceability completeness** — 5 US → 5 HLR → **15 LLR** (LLR-064b.4 added by the A-01 fold);
  every HLR→one US, every LLR→parent HLR, every US→≥1 AT (§5.1/§5.2); 8 ATs / 8 TCs.
- ✓ **Every output-producing requirement names its deliverable + observation** — AT-061a (report
  `*.md`/`*.html` reread, C-12), AT-062a/b (jump-list rows + dismiss address), AT-063a (legend rows),
  AT-063b (dismiss address via real click), AT-064a (entries/issues re-read), AT-064b
  (`service.document` after `load_text`, C-12).
- ✓ **C-10 honored (no vacuous ATs)** — every AT asserts CONTENT: AT-061a the specific report
  artifact + persistence-after-TTL; AT-062a a specific index-≥512 window's address; AT-062b the
  actual max-entropy window at row 0; AT-063a the four specific band meanings; AT-063b the exact
  clicked-cell address; AT-064a a specific second-version-only entry; AT-064b the edited entry in
  `service.document`.
- ✓ **C-12 honored (output-then-consume)** — AT-061a rereads the handler-written `reports/*.md`;
  AT-064a reads the table the real `load` produced over the AT's on-disk file; AT-064b observes
  `service.document` the real `load_text` produced (never the TextArea the AT typed).
- ✓ **C-16 honored (real interaction, US-063 click)** — AT-063b drives a REAL
  `pilot.click("#entropy_cell_k")` on the BASELINE per-cell clickable widget (Q-03/A-05,
  deterministic), never a proxy call to `action_jump`; the rung-1 `@click`-meta offset is demoted to
  an optional Phase-3 spike (LLR-063.2), so C-16 no longer rests on an unproven mechanism.
- ✓ **C-23 honored (geometry pilot-measured, US-062/063/064b)** — LLR-062.3, LLR-063.3, LLR-064b.3
  each require reading the REAL `content_region` at 80x24 AND 120x30 via `app.run_test(size=...)`,
  never fr-math (batch-36 F-01 cited: fr-math was ~4.5× off); all provisional numbers flagged
  `assumed — pilot-measure in Phase 3`; the modal box model + envelope stated as the budget approach.
  **A-02/Q-01 correction:** US-062 page size is a FIXED 512-window budget (NOT pilot-measured); the
  Phase-3 pilot measures only the sort/page CONTROL + legend placement, and the 512-window page
  scrolls inside `#entropy_body`.
- ✓ **C-24 honored (report-content census, US-061)** — LLR-061.3 records that US-061 touches the
  report TRIGGER not the CONTENT (`compose_before_after_report` untouched, P7), so the before/after
  goldens (`tests/test_before_after_report.py`) are censused as SURVIVING unchanged — LOW risk,
  stated not skipped.
- ✓ **C-18 honored (each AT = one on-disk node)** — 8 ATs → 8 distinct test nodes (AT-064c added);
  the two-width geometry ATs (062a/062b/063a/064b) each run both sizes within one node.
- ✓ **C-17 discharged** — N/A for all five (no file-derived rendered text / render-mode flip);
  stated in §3.
- ✓ **Risks + open questions surfaced** — DF-1 (US-061 fold placement), DF-2 (US-064b serializer
  scope), DF-3 (US-063 legend non-reuse), the C-16 click-forwarding risk (rung-2 fallback), and the
  C-23 measured-vs-estimated pins are all flagged for the Phase-2/Phase-3 gates.
- ✓ **Two-layer / AT-registry reconciled (C-21)** — every US carries a first-class black-box AT
  (§3) + the functional US→HLR→LLR→TC chain (§5.2); registry **RE-RECONCILED at the Phase-2 fold
  (8 ATs, 8 TCs, 15 LLRs)** after AT-064c + LLR-064b.4 + TC-331 were added and the TC crosswalk
  fixed (§5.2); the increment cut (§6.6) re-derived so every AT — incl. AT-064c — has an owning
  increment.
- ✓ **A-01 data-loss guard (blocker, folded)** — US-064b Edit-JSON is DISABLED when
  `document.source_path is not None` (LLR-064b.4), closing the silent-`load_text`-replace footgun;
  AT-064c is the file-loaded boundary AT (disabled → no clobber); re-verified against
  `app.py:1652-1659` + `change_service.py:667-668` + `io.py:412,436,458`.

### 6.5 Amendment log (Phase-2 fold — Before → After)

> Triple review (`02-review-{architect,qa,security}.md`, consolidated `02-review.md`): 1 blocker +
> 3 majors + 5 minors/lows, all corrections/gates (no story killed; security PASS). Each fold below
> was RE-VERIFIED against the worktree at base `978a900` before amending — never folded blind. §2.6
> left intact. Registry re-reconciled (C-21): **8 ATs / 8 TCs / 15 LLRs**.

**A-01 (BLOCKER, US-064b) — file-loaded data-loss footgun → disable-guard.**
- *Before:* LLR-064b.1 acceptance flagged the file-loaded case as an OPEN Phase-2 scope question
  ("MVP = paste-buffer editor … flagged for the Phase-2 gate"); AT-064b's empty boundary claimed
  "confirm with no edit is a no-op re-parse, not a crash" for the DUMMY buffer — factually FALSE
  after a file load. No disable-guard, no file-loaded boundary AT.
- *After:* added **LLR-064b.4** — the "Edit JSON" trigger SHALL be DISABLED whenever
  `document.source_path is not None`, so the popup opens ONLY for a paste-authored/empty document;
  added **AT-064c** (file-loaded → control disabled → no popup, no `load_text` clobber; paste-authored
  → enabled) + **TC-331** (guard predicate). Fixed AT-064b's empty boundary to state the no-op re-parse
  applies to the PASTE-AUTHORED case only (buffer == document source when `source_path is None`).
  Updated LLR-064b.1 acceptance, DF-2, D-064b.
- *Re-verification:* `app.py:1652-1659` — `load_doc` sets `service.document` and never touches
  `#patch_paste_text`; `change_service.py:667-668` — `load_text` REPLACES `self.document`;
  `screens_directionb.py:1977` — `TextArea(DUMMY_CHANGESET_TEXT, id="patch_paste_text")`;
  `io.py:412,436` set `source_path=resolved` on file load vs `io.py:458,515,575` `source_path=None`
  on paste — the guard predicate cleanly separates the two states. **Folded, verified TRUE.**

**A-02 / Q-01 (MAJOR, US-062) — page-size model self-contradictory → PIN 512.**
- *Before:* LLR-062.1/062.3 defined page size as the "C-23 pilot-measured cell/row budget" ("a small
  measured page size at 80x24 is acceptable"), while AT-062a assumed 512/page ("exactly 512 → single
  page", "index ≥ 512 on page 2"). With a measured ~15-row page, index ≥ 512 lands on page ~34 —
  unreachable in one `page_next`; the two readings cannot both hold.
- *After:* **PINNED page size = 512** (FIXED — the existing `ENTROPY_STRIP_MAX_CELLS`/`ENTROPY_MAX_ROWS`
  = 512 caps become the per-page window budget, NOT pilot-measured); the 512-window page renders into
  `#entropy_body` and SCROLLS (`overflow-y: auto`). Rewrote LLR-062.1 (page size fixed-512, page 2 =
  windows `[512,1024)`, `page P/Q` indicator) and LLR-062.3 (pilot-measure now governs ONLY the
  sort/page CONTROL + legend geometry). Fixed AT-062a "page 2" wording + boundary ("exactly 512 →
  single page `1/1`" now VALID). Updated D-062, evidence checklist C-23.
- *Re-verification:* `screens.py:585-586` — both caps = 512; `screens.py:707-717` — `#entropy_body`
  is `overflow-y:auto`. AT-062b (index ≥ 512 on page 2) is valid under the pin. **Folded, verified.**

**Q-02 (MAJOR, US-062) — TWO truncation tests break, not one.**
- *Before:* the supersession census named ONE truncation node ("TC-036.5").
- *After:* LLR-062.1 now names BOTH `test_tc036_5_cost_cap_and_truncation` (`:345`) AND
  `test_tc036_5_truncation_fires_on_either_cap` (`:384`); the truncation indicator is redefined to
  `page P/Q` semantics; BOTH nodes are updated in the SAME US-062 increment (Inc-3), not
  blanket-xfailed. Recorded in the LLR-062.1 supersession note + §6.6 Inc-3.
- *Re-verification:* `tests/test_tui_entropy_viewer.py:345,384` — two functions; both assert
  `#entropy_truncated` (`:375,:418`). **Folded, verified TRUE.**

**Q-03 / A-05 (MAJOR, US-063) — rung-2 per-cell clickable widget → BASELINE.**
- *Before:* LLR-063.2 ordered rung-1 (Rich `@click`-meta offset on the wrapped single `Static`) as
  the PRIMARY mechanism, rung-2 (per-cell widgets) as fallback — inverting the risk (rung-1 has zero
  in-repo precedent; wrapped-`Static` offset→cell resolution unproven; zero prior `pilot.click`).
- *After:* made the **rung-2 per-cell clickable widget (`#entropy_cell_k`) the BASELINE** (deterministic,
  satisfies C-16); AT-063b drives `pilot.click("#entropy_cell_k")`. Rung-1 `@click`-meta demoted to an
  OPTIONAL Phase-3 spike (not primary, not load-bearing). Updated LLR-063.2, AT-063b deliverable +
  error boundary, D-063, evidence checklist C-16.
- *Re-verification:* `screens.py:684` — strip is a plain `Static` (no click handler);
  `app.py:7397` — only `@click`/`meta=` hit is an unrelated `mac_meta=`; jump idiom
  `screens.py:722-728`. **Folded, verified TRUE.**

**Q-04 (MINOR, US-062/063) — select→window remap under sort+page.**
- *Before:* LLR-062.2 acceptance mentioned the mapping obligation as prose only; `on_list_view_selected`
  indexes RAW `self._windows[index]`.
- *After:* LLR-062.2 now states (normative) the handler SHALL resolve the selected row through a
  SINGLE shared `(sort,page,row)→window` helper (the same LLR-063.2's click path uses), preserving the
  `0<=index<len` bound; **AT-036b** (existing) named as the load-bearing remap regression guard;
  TC-325 extended. Updated §5.2 + §6.6 Inc-3.
- *Re-verification:* `screens.py:722-728` — `self._windows[index]` with `0<=index<len` bound;
  `tests/test_tui_entropy_viewer.py:139-165` — AT-036b (`jump.index=1 → 0x4000`). **Folded, verified.**

**A-03 (MINOR, US-064a) — refresh source = `document.source_path`.**
- *Before:* LLR-064a.1 refreshed over the `#patch_doc_path_input`/`#patch_doc_file_select` widget
  value (diverges from QA TC-064-1's `document.source_path` if the operator edits the path input
  post-load).
- *After:* LLR-064a.1 PINS the refresh source to **`ChangeService.document.source_path`** (NOT the
  widget value); a post-load path-input edit does not redirect refresh; empty guard keyed on
  `source_path is None`. Updated AT-064a shipped surface + empty boundary, TC-328, D-064a, §5.2.
- *Re-verification:* `model.py:250,453` — `source_path: Optional[Path]`; set by `io.py:412,436`.
  **Folded, verified TRUE.**

**A-04 / Q-06 (MINOR, US-061) — "until the editing context changes" → owning LLR + AT arm.**
- *Before:* HLR-061's `shall` "remains actionable until the operator acts or the editing context
  changes" had no owning LLR and no AT leg; the persistence proxy's TTL scope was unstated.
- *After (judged: KEEP the clause, give it an owner — cheap + sound):** LLR-061.1 adds a
  clear-on-context clause (control re-`hidden` on `load_doc`/`parse_paste`, which already reset
  `last_summary=None`); AT-061a gains a clear-on-context boundary arm + a note that the persistence
  proxy is STRUCTURAL (durable-widget survives re-render), NOT a wall-clock notify-TTL. TC-330
  extended. Judgement recorded: even without the clear, a stale click is SAFE-by-refusal
  (`last_summary is None` → 0 files), so this is a UX-correctness pin, not a data-safety one.
- *Re-verification:* `change_service.py:617,669` — both `load`/`load_text` reset
  `last_summary = None`; refusal arm `app.py:1937`. **Folded, verified TRUE.**

**Q-05 (MINOR, cross-doc) — TC ids reconciled to TC-324…331.**
- *Before:* `01b` used story-scoped ids (`TC-061-1`…`TC-064-2`); `01-req §5.2` used sequential
  `TC-324…330`; no written crosswalk.
- *After:* added an explicit TC crosswalk under §5.2 (`TC-061-1↔TC-330`, `TC-062-1↔TC-325`,
  `TC-062-2↔TC-324`, `TC-063-1↔TC-326`, `TC-064-1↔TC-328`, `TC-064-2↔TC-329`) + the NEW `TC-327`
  (click-map) and `TC-331` (disable-guard) with no 01b local id; the sequential `TC-324…331` are
  canonical. §5 tables + §6.6 use `TC-324…331` consistently. **Folded.**

**Q-07 (MINOR, US-064b) — AT-064b fixture seeds via PASTE, not `load`.**
- *Before:* AT-064b's "shows the CURRENT change-set" was only meaningful for pasted docs, but the
  fixture path was unspecified.
- *After:* AT-064b deliverable now explicitly seeds the change document via the PASTE path (so
  `source_path is None` and `#patch_paste_text` holds real JSON) BEFORE opening the popup — never via
  `load`. **Folded, verified** (`app.py:1660-1662` paste seam).

**S-01 (LOW, US-064b) — popup paste through the 65 KiB clipboard funnel.**
- *Before:* the new `#changeset_json_text` TextArea's paste ingress was unconstrained (risk of a
  second uncapped clipboard ingress bypassing the batch-29 R-TUI-044 funnel).
- *After:* LLR-064b.1 requires any paste into `#changeset_json_text` to route through the existing
  `os_clipboard_input` 65 536-char funnel — NOT a new direct-clipboard read. **Folded, verified**
  (`os_clipboard_input.py:72` `_CLIPBOARD_READ_CAP_CHARS = 65536`).

**S-03 (LOW, US-063) — index bound in `action_jump` + no-`[`/`]` legend pin.**
- *Before:* the click path's out-of-range bound and the legend markup-authoring pin were implicit.
- *After:* LLR-063.2 states `action_jump` SHALL mirror the `0<=i<len` bound (out-of-range click =
  no-op); AT-063b invalid/empty boundaries assert it. The no-`[`/`]` legend authoring pin is held in
  LLR-063.1 + TC-326 (unchanged). **Folded, verified** (`screens.py:722-728` bound).

**S-02 / S-04 (LOW, US-064a / US-061) — no-regression, noted only.**
- No amendment beyond a note: US-064a refresh inherits the existing (no-regression) symlink/TOCTOU of
  `read_change_document` (re-reads the already-selected path through the SAME guarded loader,
  `io.py:398,417`); US-061's persistent control is a SECOND trigger onto the single report writer
  (`app.py:1856`, no new write surface, no operator-typed output path). Security PASS — 0 HIGH/MEDIUM.
  Recorded, no LLR change.

### 6.6 Increment-cut recommendation (RE-DERIVED at Phase-2 fold, C-21 — AT-064c added, registry 8 ATs / 8 TCs / 15 LLRs)
Five stories, five HLRs — cut along the natural surface + risk boundaries (max 5 files/increment).
Every AT (incl. the NEW AT-064c) is assigned an owning increment; every LLR (incl. NEW LLR-064b.4)
lands in exactly one increment:
- **Inc-1 · US-064a (refresh)** — smallest, lowest-risk warm-up: one new `#patch_doc_refresh_button`
  + one `ActionRequested` branch re-invoking `ChangeService.load` over **`document.source_path`**
  (A-03, NOT the widget value); `screens_directionb.py` + `app.py` + one test. No geometry.
  **Owns: AT-064a, LLR-064a.1/064a.2, TC-328.**
- **Inc-2 · US-061 (persistent report surface)** — reveal row + route to the existing writer + C-24
  census + clear-on-context re-hide (A-04); `screens_directionb.py` + `app.py` + `styles.tcss` +
  test. C-23 geometry (in-panel, modest). **Owns: AT-061a, LLR-061.1/061.2/061.3, TC-330.**
- **Inc-3 · US-062 (entropy paging + sort)** — the entropy-modal core: FIXED-512 paging + sort over
  the snapshot + the shared `(sort,page,row)→window` remap helper + `page P/Q` indicator; **redefine
  BOTH truncation nodes** (`test_tc036_5_cost_cap_and_truncation` AND
  `test_tc036_5_truncation_fires_on_either_cap`, Q-02) IN THIS INCREMENT; `screens.py` +
  `styles.tcss` + test. **C-23 pilot-measure gate** (sort/page CONTROL + legend placement — NOT page
  size). Do this BEFORE US-063 so the click mapping builds on the settled sort+page index scheme.
  **Owns: AT-062a, AT-062b, AT-036b (remap regression guard), LLR-062.1/062.2/062.3, TC-324, TC-325.**
- **Inc-4 · US-063 (legend + clickable strip)** — depends on Inc-3's shared helper; legend + the
  **rung-2 per-cell clickable widget BASELINE** (`#entropy_cell_k`, C-16) with the S-03 `0<=i<len`
  bound in `action_jump`; `screens.py` + `styles.tcss` + test. Shares the Phase-3 geometry capture
  with Inc-3. **Owns: AT-063a, AT-063b, LLR-063.1/063.2/063.3, TC-326, TC-327.**
- **Inc-5 · US-064b (JSON popup + A-01 disable-guard)** — the new `ChangeSetJsonScreen` modal +
  Edit-JSON button (DISABLED when `document.source_path is not None`, LLR-064b.4) + apply-back via
  `load_text` + popup paste through the 65 KiB clipboard funnel (S-01); `screens.py` /
  `screens_directionb.py` + `app.py` + `styles.tcss` + test. **C-23 pilot-measure gate** (N_w
  editable lines). Largest; last. **Owns: AT-064b, AT-064c, LLR-064b.1/064b.2/064b.3/064b.4,
  TC-329, TC-331.**

Ordering rationale: refresh (trivial) → report surface (isolated) → entropy paging/sort (establishes
the shared index scheme + fixes both truncation nodes) → entropy legend/click (consumes that scheme
via rung-2 baseline) → JSON popup (new modal + the data-loss disable-guard, highest surface area).
US-062 before US-063 is the one HARD ordering dependency (the click-to-window mapping needs the
sort+page index + shared helper settled). The A-01 disable-guard (AT-064c/LLR-064b.4) rides WITH the
popup in Inc-5 — the guard and the popup are one indivisible safety unit.
