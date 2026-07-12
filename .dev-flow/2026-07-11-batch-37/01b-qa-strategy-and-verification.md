# 01b — QA Strategy & Verification Plan · batch-37 (US-061 / US-062 / US-063 / US-064)

> Phase 1 QA artifact. Binds to the §2.6 story intake in `01-requirements.md` (US-061/062/063/064).
> Written in PARALLEL with the architect's HLR/LLR/AT derivation (which EXTENDS `01-requirements.md`);
> this file does not edit that file. AT ids here are referenced by story (AT-061x … AT-064x); the
> architect assigns the exact numbers — reconcile at the Phase-1 gate.
> Author: qa-reviewer. Status: strategy locked for Phase-2 review; TC/AT bodies are Phase-3 work.
> Style baseline: `.dev-flow/2026-07-11-batch-36/01b-qa-strategy-and-verification.md`.
> Tree: worktree `heuristic-wu-1c7c49` @ `978a900` (RC-1 PASS), branch `claude/batch-37-p2-b11-b14`.

---

## 0. Scope recap (one sentence each) + recon grounding (file:line)

1. **US-061 (B-11)** — after a save-back that makes a before/after report available, a **persistent,
   discoverable control** (durable button and/or status line) replaces the transient `notify`; activating
   it produces the SAME report the `b` path writes. Seam: `on_patch_editor_panel_save_back_decision`
   fires `self.notify("Before/after report ready - press b …")` at `app.py:1794-1799` only when
   `result.ok`; the `b` binding (`app.py:798`) runs `action_before_after_report` (`app.py:1856-1939`)
   which calls `compose_before_after_report(...)` and writes `result.md_path` + `result.html_path`
   under `<project>/reports/` (surfaced via `set_status`, `app.py:1932-1935`).
2. **US-062 (B-12)** — the entropy viewer lets the operator **page** past the 512-window cap and **sort**
   by address/entropy; the strip + jump-list order changes with the sort and paging reveals windows not
   on page 1. Seam: `EntropyViewerScreen.__init__` snapshots `self._windows = compute_entropy(mem_map)`
   ONCE (`screens.py:653-655`), renders `_windows[:ENTROPY_STRIP_MAX_CELLS]` (strip, `screens.py:676`)
   and `_windows[:ENTROPY_MAX_ROWS]` (jump list, `screens.py:686`) in ascending-address order; caps
   `ENTROPY_STRIP_MAX_CELLS = ENTROPY_MAX_ROWS = 512` (`screens.py:585-586`); truncation Label
   `#entropy_truncated` when `len(_windows) > min(caps)` (`screens.py:703-706`).
3. **US-063 (B-13)** — the viewer shows a **band legend** (colour→meaning) and **clicking a strip cell
   navigates** to that window (same jump as a list row). Seam: strip is a single `Static("#entropy_strip")`
   built from `_strip_text()` (`screens.py:684`, `657-681`) — NOT clickable; band→colour map
   `ENTROPY_BAND_COLOUR` (`screens.py:569-574`: constant/padding→grey50, low→green, medium→yellow,
   high/random→red) is entropy-OWN colours, deliberately NOT the `sev-*` severity family; jump
   navigation already works via `on_list_view_selected` → `dismiss(target)` →
   `app._goto_focus_address` (`screens.py:722-728`, host-side).
4. **US-064 (B-14)** — patch editor gains (a) a **refresh** action re-reading the selected change/check
   file from disk, and (b) a **JSON popup** modal editing the change-set, applying on confirm. MAY SPLIT
   US-064a/b. Seam: `load_doc` → `ChangeService.load(path, base_dir)` sets `self.document` with
   `document.source_path` (`app.py:1652-1659`; `change_service.py:581-617`; `model.py:250` source_path);
   paste box `#patch_paste_text` TextArea (`screens_directionb.py:1977`), `parse_paste` →
   `ChangeService.load_text` replaces the document (`app.py:1660-1662`; `change_service.py:633-669`);
   entries reflected via `panel.refresh_entries(service.rows(...))` (`app.py:1710`).

**RC-1 / ledger base:** `python -m pytest --collect-only -q` → **1369 tests collected** @ `978a900`.

---

## 1. Validation method per story

Layer A = white-box TCs on the mechanism (sort/page helpers, legend↔map coupling, refresh re-read,
popup apply seam, binding registration). Layer B = black-box ATs through the SHIPPED surface: Textual
Pilot (`App.run_test()`) driving the REAL screen/handler + real key/click, then re-reading what the
surface produced (rendered jump-row text, `_goto_focus_address`, the report file on disk, the change
document). **No AT is a perceptual demo.** SVG snapshots are executable pixel-diff `test`s, not
acceptance-by-eye.

| Story | Requirement area | Method | Layer A TC(s) (↔ LLR) | Layer B AT(s) — SHIPPED surface (↔ US) | Counterfactual (RED pre-change) |
|---|---|---|---|---|---|
| US-061 | Persistent report surface | **test** | TC-061-1: after a successful save-back the panel/app exposes a DURABLE widget (button id and/or status line), NOT a `notify` call — id present + enabled; it SURVIVES an unrelated UI action (batch-36 F-Q-11 persistence idiom) | **AT-061a** (Pilot, C-12 output-then-consume): drive save-back (confirm) → do NOT press `b`/rely on notify → activate the persistent control → re-read the written `<project>/reports/*.md` from disk → assert the before/after report CONTENT present in the file bytes | today the ONLY affordance is the transient `notify` (`app.py:1794`); `query_one("#<persistent_id>")` returns 0 and no report file exists until `b` is pressed → RED |
| US-062 | Sort by entropy | **test** | TC-062-1: a sort helper reorders the window VIEW by the chosen key (entropy desc / address asc); equal-entropy ties keep ascending-address secondary order (stable) | **AT-062a** (Pilot, C-10 off-default CONTENT): load a multi-window image, toggle sort→'entropy' via the REAL control → assert the TOP jump row's parsed `H=` equals the MAX entropy over all windows (not "list non-empty") | today there is no sort control; the toggle press has nothing to drive and row 0 is the lowest-ADDRESS window, not max-entropy → RED |
| US-062 | Page past 512 cap | **test** | TC-062-2: the page-slice helper returns `windows[page*N:(page+1)*N]`; page count = `ceil(len/N)`; last-page partial slice correct | **AT-062b** (Pilot, `large_s19` >512 windows): navigate to page 2 via the REAL control → assert a jump row appears for a window whose index ≥ the page-1 cap (an address NOT on page 1) | today `_windows[:512]` truncates the tail (`screens.py:676,686`); windows ≥512 are unreachable → the page-2 address never appears → RED |
| US-063 | Band legend | **test** | TC-063-1: a legend surface lists EACH of the 4 `ENTROPY_BAND_COLOUR` bands with its meaning string; anti-drift — every key in the map has exactly one legend row (add a band → legend must grow) | **AT-063a** (Pilot, C-10 CONTENT): open the modal → assert each band's ACTUAL colour→meaning string is present in the rendered legend Labels (e.g. `constant/padding`, `high/random` + their meaning text), not "legend non-empty" | no legend exists today (`compose`, `screens.py:683-717` has none) → the band-meaning strings are absent → RED |
| US-063 | Clickable strip cell | **test** | — | **AT-063b** (Pilot, C-16 REAL click): with the mixed image loaded, drive a genuine `pilot.click` on the SECOND strip cell → assert `app._goto_focus_address` moved to that window's start (`0x4000`), same jump the list row performs | today the strip is a plain `Static` (`screens.py:684`) — a click posts nothing; `_goto_focus_address` is unchanged → RED |
| US-064a | Refresh re-reads disk | **test** | TC-064-1: the refresh action re-invokes `ChangeService.load(document.source_path)` and re-renders `refresh_entries`; no-doc case is a safe status no-op | **AT-064a** (Pilot, C-10 CONTENT): load a change file → edit the file ON DISK to add a NEW entry → press the REAL refresh control → assert the NEW entry's address appears in the entries table / `issue_lines` (the new content, not "refresh ran") | today no refresh control; after an external edit the editor still shows the OLD document → the new address is absent → RED |
| US-064b | JSON popup edit-apply | **test** | TC-064-2: the popup composes a large editable `TextArea` pre-filled with the current change-set serialization; confirm routes edited text through the `load_text` seam (same as `parse_paste`); cancel is a no-op | **AT-064b** (Pilot, C-12 output-then-consume): open the popup → assert it shows the CURRENT change-set → edit the text (add an entry) → confirm → re-read `app._change_service.document.entries` → assert the edit APPLIED (new entry present) | today no popup modal exists; `query_one("#<popup_id>")`/`push_screen` target is absent → RED |

**Analysis-only items:** none. Every acceptance lands as an executable `test` or a pinned snapshot.
Phase-4 operator demo replays AT-061a/062a/063a/063b manually (script from the ATs) — demo is
illustration, never the acceptance verdict.

---

## 2. C-10 / C-12 / C-16 / C-18 discipline (shift-left — owned here)

### 2.1 C-10 — a passing AT must be IMPOSSIBLE where the behaviour is absent/defaulted
- **AT-062a asserts the TOP row IS the max-entropy window** — parse `H=<h>` from row 0 and assert
  `float == max(H over all windows)`. "Sort control exists / list reorders somehow" is BANNED (a stable
  no-op sort passes it). Pair with a NEGATIVE: sort→'address' returns the ascending-address order (row 0
  is the lowest address), so the two sort keys are provably DIFFERENT orderings on the same image.
- **AT-062b asserts a SPECIFIC page-2 address appears** — a window whose ascending-address index ≥ the
  page-1 cap. "Page 2 is non-empty" is BANNED (page 1 is non-empty too).
- **AT-063a asserts the ACTUAL band meaning strings**, mirroring batch-36's `LEGEND_TABLE[...][1] in
  meanings` idiom (`test_tui_legend.py:181`) against the entropy band set — not "a legend header exists".
- **AT-063b asserts the focus ADDRESS moved to the clicked cell's window start** (`0x4000` for the
  mixed image, reusing the AT-036b `before != after` + `after == 0x4000` idiom, `test_tui_entropy_viewer.py:163-165`)
  — not "the cell is clickable".
- **AT-064a asserts the NEW on-disk entry appears** in the editor; **AT-064b asserts the NEW entry is in
  `document.entries`** after confirm — both assert CONTENT the pre-change tree cannot produce.

### 2.2 C-12 — output-then-consume for US-061 (report file) and US-064b (change document)
- **AT-061a** does NOT assert on `compose_before_after_report`'s return value. It drives the SHIPPED
  save-back → activates the persistent surface (the handler that the operator triggers) → lets the
  handler WRITE `<project>/reports/*.md` → RE-READS that file from disk → asserts the before/after
  content is in the bytes actually written. Idiom home: the report-seam reread pattern
  (`tests/test_tui_report_seam.py`) + `tests/test_before_after_report.py` (composer output on disk). This
  kills the failure mode where a button exists but never reaches the write path.
- **AT-064b** does NOT assert on the popup's `TextArea.text`. It drives confirm → re-reads
  `app._change_service.document.entries` (the change document the confirm produced) → asserts the edit
  applied. The popup's own pre-fill/serialization is the separate Layer-A TC-064-2.

### 2.3 C-16 — US-063 strip click is a REAL mechanism, not a setter
AT-063b MUST use `await pilot.click(<strip-cell target>)` — a genuine Textual Click message. `.focus()`,
a direct `screen._on_cell_click(...)` call, or setting `_goto_focus_address` directly are ALL BANNED
(they bypass the mechanism under test). **Suite note:** there is currently ZERO `pilot.click` usage in
`tests/` (interactions today go through `pilot.press` + direct widget method calls, e.g.
`jump.action_select_cursor()`, `test_tui_entropy_viewer.py:158-159`). AT-063b introduces the first real
`pilot.click` idiom — flagged so Phase-3 budgets for it. The exact click target depends on the Phase-2
mechanism choice (§9.3): per-cell clickable widget → `pilot.click("#entropy_cell_1")`; single Static +
offset→window click-map → `pilot.click("#entropy_strip", offset=Offset(1, 0))`. Both are real Click
events and satisfy C-16.

### 2.4 C-18 — every AT is EXACTLY ONE on-disk node driving the whole chain
| AT | Single on-disk node (target file) | Whole-chain-in-one-node? |
|---|---|---|
| AT-061a | `tests/test_tui_report_seam.py` (new fn) | ✓ one node: save-back → activate surface → reread report file → assert content |
| AT-062a | `tests/test_tui_entropy_viewer.py` (new fn) | ✓ open modal → sort→entropy → assert row 0 == max-H, in one body |
| AT-062b | `tests/test_tui_entropy_viewer.py` (new fn, `large_s19`) | ✓ open → page 2 → assert beyond-cap address present |
| AT-063a | `tests/test_tui_entropy_viewer.py` (new fn) | ✓ open → assert every band meaning string in legend Labels |
| AT-063b | `tests/test_tui_entropy_viewer.py` (new fn) | ✓ open → real click on cell 1 → assert focus == 0x4000 |
| AT-064a | `tests/test_tui_patch_editor_v2.py` (new fn) | ✓ load → external file edit → refresh → assert new entry in table |
| AT-064b | `tests/test_tui_patch_editor_v2.py` (new fn) | ✓ open popup → edit → confirm → reread document.entries |
**Flag:** no AT is realizable only "in parts". AT-061a is the one to watch — do NOT split "surface is
present" (TC-061-1) from "activating it writes the report" (AT-061a); the write-through is the point.

---

## 3. Boundary and negative sets (concrete cases — cut only with written justification)

### 3.1 US-061 persistence + refusal
| # | Case | Expected | Home |
|---|---|---|---|
| P1 | save-back SUCCEEDS (`result.ok`) | persistent control appears + enabled | AT-061a / TC-061-1 |
| P2 | save-back FAILS (`result.ok` False, `app.py:1788`) | NO report-offer surface (nothing to report) | TC-061-1 (negative) |
| P3 | surface SURVIVES an unrelated UI action | still present + actionable after e.g. a screen switch (the "persistent" property, testable proxy for "outlives the notify timeout") | TC-061-1 |
| P4 | activation with NO valid `last_summary` | composer refuses; status shows the refusal diagnostic; NO file written (`app.py:1937-1938`) | AT-061a (negative leg) |
| P5 | context change (new load / project switch) | stale offer clears — not left dangling on a different image | TC-061-1 (flag: confirm the clear-on-context rule with the architect at Phase-1) |

Boundary note: US-061 must NOT change the report CONTENT or the `b` binding (both out of scope, §2.6) —
the `b` accelerator STAYS; regression-rerun the existing `b`-path report tests unchanged.

### 3.2 US-062 sort + paging
| # | Case | Expected | Home |
|---|---|---|---|
| S1 | multi-window image, sort→entropy | row 0 = max-H window (CONTENT) | AT-062a |
| S2 | sort→address (default) | row 0 = lowest-address window; order ≠ the entropy order | AT-062a (negative pairing) |
| S3 | equal-entropy windows | ties keep ascending-address secondary order (stable sort) | TC-062-1 |
| S4 | >512 windows, page 2 | a beyond-cap address is reachable | AT-062b |
| S5 | EXACTLY 512 windows | page 1 full, page 2 empty / next-page disabled (no phantom page) | TC-062-2 (boundary) |
| S6 | 1-window image | sort is identity; paging disabled; no crash | TC-062-2 / reuse `test_at036c_single_window` |
| S7 | empty image | empty-state affordance unchanged; sort/page controls inert (`EntropyViewerScreen({})`, `screens.py:673`) | reuse `test_at036c_no_image_empty_state_text` |
| S8 | truncation indicator vs paging | with paging, the tail is no longer silently dropped — the `#entropy_truncated` semantics change; confirm the indicator's new meaning (all-pages-reachable) or its removal with the architect | flag (Phase-1 design) |

### 3.3 US-063 legend + click
| # | Case | Expected | Home |
|---|---|---|---|
| L1 | legend content | all 4 bands + meanings shown | AT-063a |
| L2 | anti-drift | each `ENTROPY_BAND_COLOUR` key ↔ one legend row (map is the single source) | TC-063-1 |
| L3 | click cell 1 | focus → that window's start (0x4000) via REAL click | AT-063b |
| L4 | click cell 0 | focus → first window start (0x3000) | AT-063b (2nd assert) |
| L5 | click on empty/out-of-range strip area | safe no-op, no crash, focus unchanged | TC-063-1 (negative) |
| L6 | legend with NO image loaded | band legend still shown (static reference, like the classification `LegendScreen`) | AT-063a boundary |

Legend sourcing note: entropy bands are the viewer's OWN colours (grey50/green/yellow/red), NOT the
`sev-*` severity family — do NOT fold them into `LEGEND_TABLE` (severity-keyed). The batch-36 hint to
"reuse the `legend.py` table pattern" applies to the RENDER shape only; the entropy legend is a separate
colour family coupled to `ENTROPY_BAND_COLOUR` (§9.4).

### 3.4 US-064 refresh + popup
| # | Case | Expected | Home |
|---|---|---|---|
| R1 | external edit then refresh | editor shows new entry | AT-064a |
| R2 | refresh, NO document loaded (`source_path` None) | safe status no-op, no crash | TC-064-1 (negative) |
| R3 | file DELETED externally then refresh | refuses with a diagnostic (collect-don't-abort); old content retained | TC-064-1 (negative) |
| R4 | file becomes INVALID JSON then refresh | one ERROR finding, app responsive (reuse the `.cdfx`/v1 legacy-load idiom, `test_tui_patch_editor_v2.py:14-17` TC-019) | TC-064-1 |
| R5 | popup shows current change-set | pre-filled with loaded doc serialization | AT-064b / TC-064-2 |
| R6 | popup confirm with VALID edit | document updated (new entry) | AT-064b |
| R7 | popup confirm with INVALID JSON | refuses (ERROR finding); underlying document UNCHANGED (bad edit not applied) | TC-064-2 (negative) |
| R8 | popup CANCEL | document unchanged (edit discarded) | TC-064-2 (negative) |
| R9 | popup geometry @80x24 | the "full-size" editor fits the modal content budget (C-13), no clip | TC-064-2 (boundary — assert `region.right <= 80`, entropy-geometry idiom `test_tui_entropy_viewer.py:452-457`) |

---

## 4. Snapshot-drift prediction — per-cell (C-22)

Snapshot matrix (`test_tui_snapshot.py:115-116,517,603-617`): restyled screens
`["workspace","a2l","mac","issues"]` × {compact,comfortable} × 3 sizes; scaffold screens
`["map","patch","diff"]` at comfortable, with `patch`+`map` carrying BOTH 80x24 and 120x30; PLUS
`_ENTROPY_CELLS` = the entropy modal at 80x24 + 120x30. On-disk cells confirmed by grep of
`tests/__snapshots__/test_tui_snapshot/`:
`test_tc036s_entropy_modal_snapshot[entropy-comfortable-{80x24,120x30}].svg`,
`test_tc016s_density_layout_snapshot[patch-comfortable-{80x24,120x30}].svg`.

| Cell | US | Drift? | Why (per-cell) | Disposition |
|---|---|---|---|---|
| `entropy-comfortable-80x24` | US-062 + US-063 | **YES** | the modal composition changes: US-062 adds sort + page controls; US-063 adds a legend block and (per §9.3) may restructure the strip into clickable cells — every added child reflows the dialog interior | `xfail(strict=False)` → **canonical-CI regen only** (`snapshot-regen.yml`, `textual==8.2.8`) |
| `entropy-comfortable-120x30` | US-062 + US-063 | **YES** | same interior reflow at the primary width | `xfail(strict=False)` → canonical-CI regen |
| `patch-comfortable-80x24` | US-064a/b | **CONDITIONAL** | drifts IFF US-064 adds a VISIBLE control to the patch screen (a "Refresh" button and/or an "Open JSON editor" launch button). The JSON popup itself is a MODAL (no matrix cell), so US-064b drifts this cell ONLY via its launch button. If the refresh/launch triggers reuse existing controls or a binding with no new widget, this cell HOLDS | `xfail(strict=False)` **if** a control is added; else stays green — decide at Phase-2 once the mechanism is fixed |
| `patch-comfortable-120x30` | US-064a/b | **CONDITIONAL** | same as above at the wider width | as above |
| `map-comfortable-{80x24,120x30}` | — | NO | map scaffold untouched | stay green — any drift = scope violation |
| `diff-comfortable-120x30` | — | NO | diff scaffold untouched | stay green |
| `{workspace,a2l,mac,issues}-{compact,comfortable}-{3 sizes}` (24) | — | NO | no restyled screen is touched; US-064's popup is a NEW modal absent from the matrix; US-061's surface lives on the patch flow, not these screens | stay green |

**Upper bound: 4 cells drift (2 entropy CERTAIN + 2 patch CONDITIONAL); 0 cells for US-061.** US-061's
persistent surface change lands on the patch/save-back flow, which is snapshotted only via the two
`patch-comfortable-*` cells — and only if US-061 adds a durable widget to the patch SCREEN (vs a
save-back-modal or status line). If the persistent control is a status line / save-back-decision surface
rather than a new patch-screen child, US-061 also drifts 0 cells. **Regen rule** (memory
`reference_snapshot_regen_env`): all drifting baselines are regenerated ONLY in canonical CI at the
merge commit, with containment verified in the run log (no unexpected cell moved). **Local regen is
forbidden.** Precedent: batch-22/25/31/33/35 entropy+patch cell xfail→regen.

---

## 5. Supersession census (change-first) — pins this batch moves

| # | Pin (file:line) | What it pins | Disposition |
|---|---|---|---|
| 1 | `app.py:1794-1799` transient `notify` (save-back offer) | the ONLY report affordance today | **SUPERSEDE** — replaced/augmented by the persistent surface; if the `notify` is retained as a secondary hint, TC-061-1 must still assert the DURABLE widget is the primary path |
| 2 | `test_tui_entropy_viewer.py` AT-036a/b/c + TC-036.* | strip cells, jump rows, focus-move, caps, `e` binding | **SURVIVE** — US-062/063 add sort/page/legend/click ON TOP; rerun all as regression. AT-036b (list jump → focus) is the sibling AT-063b clicks; both must stay green |
| 3 | `test_tui_entropy_viewer.py:345-424` TC-036.5 cost cap + either-cap truncation | `_windows[:cap]` truncation + `#entropy_truncated` | **RE-EXAMINE** — paging makes the tail reachable, so the truncation SEMANTICS change (§3.2 S8). Either the indicator is removed or its meaning is redefined; whichever, UPDATE TC-036.5 with a docstring note, do not silently break it |
| 4 | `test_tc036s_entropy_modal_snapshot` 2 cells (`screens.py` modal) | entropy modal pixels | **DRIFT → xfail(strict=False)** until canonical-CI regen (§4) |
| 5 | `test_tui_patch_editor_v2.py` TC-015 / TC-016 (`PATCH_ACTIONS_V2` = 10 actions, `app.py:148`) | the routable action set + widget-id census | **SUPERSEDE if** refresh routes as an 11th action (`refresh_doc`) — update the pin to 11 with a docstring note; the JSON-popup open likely rides a button+`push_screen`, not a routed action (confirm at Phase-2). New widget ids (refresh button, popup-open button) ADD to the census |
| 6 | `test_tc016s_density_layout_snapshot` 2 patch cells | patch scaffold pixels | **CONDITIONAL DRIFT** (§4) — xfail(strict=False) only if a patch-screen control is added |
| 7 | `test_tui_report_seam.py` / `test_before_after_report.py` (`b`-path report) | report content + composer output | **SURVIVE** — US-061 keeps the `b` accelerator + report CONTENT unchanged; rerun as regression; AT-061a ADDS the persistent-surface write-through |
| 8 | `test_tui_entropy_viewer.py:326-336` TC-036.4 (`e` binding registered) | silent-unbind guard | **SURVIVES** — US-062/063 don't touch the `e` binding; rerun |

No engine-frozen module is edited: `screens.py`, `screens_directionb.py`, `app.py`,
`services/entropy_service.py`, `services/change_service.py` are ALL non-frozen. `ENTROPY_BAND_COLOUR`
lives in the non-frozen `screens.py` (not in the frozen `color_policy.py`), so the entropy legend
coupling reads a non-frozen constant — the frozen-diff guards (`test_engine_unchanged.py`,
`test_tui_directionb.py::test_tc031_*`) stay green.

---

## 6. Test-count ledger base

```
python -m pytest --collect-only -q   →   1369 tests collected   (@ 978a900, branch claude/batch-37-p2-b11-b14)
```
Phase-3 ledger tracks: base 1369 → +N new (each named: TC-061-1, AT-061a, TC-062-1, TC-062-2, AT-062a,
AT-062b, TC-063-1, AT-063a, AT-063b, TC-064-1, AT-064a, TC-064-2, AT-064b) → −0 hand-deleted
(supersessions #1/#3/#5 are in-place edits with docstring notes; any snapshot xfail is a mark, not a
deletion). Any hand deletion needs a §5 census row authorizing it.

---

## 7. Exit criteria for the batch's QA gate

- Every AT in §1/§2.4 exists at its single on-disk node; live-RED ones have recorded pre-impl failure
  output (inline paste at the gate).
- US-061: AT-061a green (save-back → activate persistent surface → report FILE reread asserts content);
  TC-061-1 asserts a durable widget that survives an unrelated action; the `b` accelerator + report
  content regression-rerun unchanged (P2/P4/P5 negatives covered).
- US-062: AT-062a (top row == max-H) + AT-062b (beyond-cap page-2 address) green; TC-036.5 truncation
  semantics reconciled with paging (§3.2 S8) and its docstring updated; boundary cells S5/S6/S7 green.
- US-063: AT-063a (all band meaning strings) + AT-063b (REAL `pilot.click` → focus 0x4000) green;
  TC-063-1 anti-drift couples the legend to `ENTROPY_BAND_COLOUR`; L5 negative (click no-op) green.
- US-064: AT-064a (external edit → refresh → new entry) + AT-064b (popup edit → confirm → document
  reread) green; R2/R3/R4/R7/R8 negatives green; R9 popup geometry ≤80 asserted.
- Snapshot: exactly the two `entropy-comfortable-*` cells (+ the two `patch-comfortable-*` IF a control
  was added) are `xfail(strict=False)` pending canonical-CI regen; no other cell drifts. Any other
  drift = scope violation, not a regen candidate.
- Full suite green except the §4 xfail snapshot cells. No engine-frozen module diffs.
- Census rows 1, 3, 4, 5, (6 if triggered), 7 dispositions executed and noted in-test.

## 8. Highest-risk QA gaps (Phase-2 watch-list)

1. **US-061 "persistence" is a time-property that Pilot can't clock.** "Remains actionable until the
   operator acts or context changes" cannot be tested against a wall-clock notify timeout. **Mitigation:**
   test the STRUCTURAL proxy — the affordance is a DURABLE widget (button/status line), asserted present
   + enabled AFTER save-back AND STILL present after an unrelated UI action (batch-36 F-Q-11 persistence
   idiom). The clear-on-context rule (P5) needs an explicit architect decision at Phase-1: does a new
   load/project-switch clear a stale offer? Flag, not blocker.
2. **US-062 paging vs the truncation indicator (census #3).** Today `#entropy_truncated` fires because
   the tail is DROPPED. Once paging makes all windows reachable, that indicator is either wrong or must
   be redefined (e.g. "N pages"). Silently leaving TC-036.5 asserting the old drop-truncation while
   paging ships is a live contradiction. **Mitigation:** reconcile TC-036.5 in the same increment; do
   not blanket-`xfail` it.
3. **US-063 strip-click mechanism is an open design var that fixes the AT selector.** The strip is one
   `Static` today; making cells clickable is either (a) per-cell clickable widgets or (b) a single
   Static with an `on_click` offset→window map. This is a Phase-1/Phase-2 call and it determines
   AT-063b's exact `pilot.click` target (§2.3). Either is testable via a REAL click — but the AT body
   can't be finalized until the mechanism is chosen, and the suite has no prior `pilot.click` idiom to
   copy. Flag: budget the new idiom; pin the selector at Phase-2.
4. **US-063 legend sourcing — couple to `ENTROPY_BAND_COLOUR`, NOT `LEGEND_TABLE`.** The entropy bands
   are a distinct colour family from the `sev-*` severity legend. TC-063-1's anti-drift must import
   `ENTROPY_BAND_COLOUR` and assert one legend row per band — a fragile substring match on "green"/"red"
   would silently pass if a band were dropped. The architect should expose a `band → (colour, meaning)`
   mapping so the coupling is exact.
5. **US-064b apply-seam confirmation.** AT-064b assumes popup-confirm routes through
   `ChangeService.load_text` (the proven `parse_paste` seam, `app.py:1660-1662`). If the popup instead
   introduces a NEW apply path, that path needs its own error-handling coverage (R7 invalid-JSON refusal).
   Confirm the seam at Phase-2; if new, add the refusal TC.

---

## Testability verdict (per story, as specced)

- **US-061 — TESTABLE (with a proxy).** The write-through (save-back → activate → report file on disk)
  is fully black-box testable (C-12). The "persistence" property is tested via the structural proxy
  (durable widget survives an unrelated action), not wall-clock — legitimate and standard here. One
  Phase-1 decision open (clear-on-context, P5). No blocker.
- **US-062 — TESTABLE.** Sort (top row == max-H, cheap crafted image) and paging (beyond-cap address on
  page 2, `large_s19`) are both content-assertable through the shipped modal. One reconciliation required
  (truncation-indicator semantics, census #3). No blocker.
- **US-063 — TESTABLE.** Legend content is a direct string assertion coupled to `ENTROPY_BAND_COLOUR`;
  the strip click is a REAL `pilot.click` asserting `_goto_focus_address` (C-16), reusing the AT-036b
  focus-move idiom. Only the click SELECTOR is mechanism-dependent (§8.3) — testable either way. No blocker.
- **US-064 — TESTABLE, SPLIT-READY.** US-064a (refresh) and US-064b (popup) are independent surfaces,
  each with its own black-box AT (external-edit reread; popup edit→confirm→document reread) and negative
  sets. Recommend the §2.6 split into two increments. No blocker.

---

## Evidence checklist (qa-reviewer, Phase 1)

- [x] Every story has a black-box AT through the SHIPPED surface — US-061 AT-061a (report file reread);
  US-062 AT-062a/b (modal sort+page); US-063 AT-063a (legend) + AT-063b (real click); US-064 AT-064a
  (refresh) + AT-064b (popup). §1 table.
- [x] Every AT has a stated counterfactual (RED pre-change) that fails on the current tree — §1 rightmost
  column; each names the concrete pre-change gap (no control / plain Static / no popup / truncated tail).
- [x] C-10 satisfied — AT-062a asserts row 0 == MAX-H (+ address-sort negative pairing); AT-062b asserts
  a SPECIFIC beyond-cap address; AT-063a asserts EXACT band meaning strings; AT-063b asserts focus ==
  0x4000; AT-064a/b assert NEW content. §2.1. No "exists/non-empty" pass conditions.
- [x] C-12 satisfied — AT-061a rereads the written `reports/*.md`; AT-064b rereads `document.entries`
  after confirm; the composer/serialization unit checks are separate Layer-A TCs. §2.2.
- [x] C-16 satisfied — AT-063b uses a REAL `pilot.click` (not `.focus()`/setter); the new-idiom risk is
  flagged. §2.3, §8.3.
- [x] C-18 satisfied — each AT is one on-disk node driving the whole chain; AT-061a flagged as the
  don't-split watch item. §2.4.
- [x] Snapshot cells named + canonical-CI-regen noted — 2 entropy cells CERTAIN drift, 2 patch cells
  CONDITIONAL, US-061 0 cells; per-cell rationale + upper bound (4); regen ONLY in canonical CI. §4.
- [x] Edge cases include empty/boundary/invalid/error — §3: US-061 fail/refusal/context (P2/P4/P5);
  US-062 exactly-512 / 1-window / empty / ties (S3/S5/S6/S7); US-063 out-of-range click / no-image
  legend (L5/L6); US-064 no-doc / deleted / invalid-JSON / cancel / geometry (R2/R3/R4/R7/R8/R9).
- [x] Regression checklist exists — §5 supersession census (8 rows, file:line).
- [x] Exit criteria stated — §7.
- [x] No real PII / secrets — synthetic in-memory `mem_map` fixtures + the public `large_s19` generator
  + synthetic v2 change-set JSON; no client artifact.
- [x] Test-results sections left BLANK — no execution claimed; only `--collect-only` (1369) + grep/read
  recon were run, outputs quoted (§0, §6).
- [x] Layer B (black-box) present for every output-producing story — US-061 report FILE, US-062 modal
  rows, US-063 legend Labels + focus address, US-064 entries table + document — all through the shipped
  surface, with boundary + negative evidence (§3).
- [x] Bidirectional surface-reachability — inputs (sort key, page nav, strip click, external file edit,
  popup edit) AND outputs (report file, reordered rows, focus address, refreshed table, updated
  document) are exercised THROUGH the handler, not only a service API.
- [x] No unfilled template — no `<...>` placeholders; the mechanism-dependent selectors (US-063 click
  target, US-064 control ids) are explicitly deferred to Phase-2 with both candidate forms named and
  their sources cited, not left blank.

---

## FINAL RETURN block (for the orchestrator) — see the returned message.
