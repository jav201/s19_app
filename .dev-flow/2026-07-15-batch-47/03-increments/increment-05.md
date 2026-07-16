# Increment 5 — US-MAC View MID (R-TUI-070 / R-TUI-071)

> batch-47 screen-upgrades Batch A. Branch `claude/screen-upgrades-handoff-0874f9`
> (HEAD = Inc-4 `61e40a3`). English. Supervised-incremental, ≤5 files.

## 1. What changed

MAC View MID insight layer — render-only, no parser/engine/validation change:

- **LLR-070.1 status-glyph column** — each MAC record row now carries a leading
  coloured status glyph folded into the **Tag** cell. Four-way, derived from the
  **already-computed** `Status` + `InMem` cells (`_mac_status_glyph`) — the render
  layer never re-runs validation: `✗` red (parse-error, `Status == ERR_PARSE`) /
  `⚠` orange (parse-ok + out-of-image, `InMem == "no"`, the existing MAC-warning
  orange) / `✓` green (parse-ok + in-image, `InMem == "yes"`) / `·` grey
  (`InMem == "n/a"` → not image-checked, e.g. MAC-only load — the "not yet
  checked" cue, never a false green "verified present").
- **LLR-070.2 C-17** — the file-derived MAC name is a `Text` span appended into
  the composed Tag cell (never markup-parsed); the glyph is a separate coloured
  span, so a hostile name renders verbatim with no payload-derived style.
- **LLR-070 cyan addresses** — the Address cell renders cyan (`insight_style.CYAN`).
- **LLR-071.1 coverage strip** — a NEW `#mac_coverage_strip` `Static` above
  `#mac_records_list` renders `MAC→S19 X of Y <micro-bar>  ·  A2L↔MAC N matches`
  from `CoverageMetrics.mac_in_s19` / `mac_total` / `a2l_mac_address_matches`,
  built by the new pure `validation_service.build_mac_coverage_strip` (numeric-only,
  C-17-safe by construction; `mac_in_s19_pct` guards `mac_total == 0`).
- **LLR-071.2 gating** — the strip shows whenever a MAC is loaded, **independent
  of the primary file type** (MAC-only → `0 of 0`), superseding the old
  primary-only conditional pct-line. Blanked when no MAC is loaded.

Glyph-state derivation (single source): reuses `_compute_mac_view_payload`'s
`Status` + `InMem` columns (from the frozen `_mac_record_ui_state`); no new
validation. Confirmed row builder indices (app.py:7514-7525): `row[3] = in_mem_text`
(`"yes"`/`"no"`/`"n/a"`), `row[4] = status`.

### Post-review fixes (code-review iterate-to-fix, within Inc-5)
- **F1 (MEDIUM)** — the earlier `else → ✓` (keyed on `Status` only) mislabelled
  un-image-checked records: a MAC-only load (`file_type="mac"`, no primary →
  `memory_checked=False` for all rows) rendered every parse-ok record green `✓`
  while `InMem` read `"n/a"` — a false presence cue against LLR-070.1 / the
  sev-* convention (green = memory-checked + present). **Fixed** by deriving the
  glyph from the `InMem` discriminator (`row[3]`), adding the grey `·`
  not-yet-checked state. `NO_ADDR` (no int address → `InMem "n/a"`) now also
  renders `·`, not `✓`. Spec-explicit fix → **no §6.5 amendment**.
- **F2 (LOW)** — corrected the `_populate_mac_datatable` docstring: it calls
  `DataTable.add_row` once per row (per-row key), not `add_rows`.

## 2. Files modified (4)

- `s19_app/tui/app.py` — `_MAC_GLYPH_*` constants + `_mac_status_glyph(status,
  in_mem)` 4-way helper; `_compose_screen_mac` adds `#mac_coverage_strip`;
  `_populate_mac_datatable` folds the glyph into cell 0 + cyan address; new
  `_update_mac_coverage_strip`; `update_mac_view` renders/blanks the strip;
  import `build_mac_coverage_strip`.
- `s19_app/tui/services/validation_service.py` — new pure `build_mac_coverage_strip`
  (+ `rich.text.Text` / `insight_style` imports, `_MAC_STRIP_BAR_WIDTH`).
- `tests/test_tui_mac_coverage.py` — NEW black-box + boundary suite (fixtures
  inlined: `mac_injection` hostile record + inline malformed `.mac` parse-error).
- `tests/test_tui_snapshot.py` — `_batch47_mac_drift_marks` (C-22 census; 4 wide
  mac cells `xfail(strict=False)`).

No frozen file touched (`tui/mac.py` and the engine/validation set: 0 diff vs `main`).

## 3. How to test

```bash
python -m pytest -q tests/test_tui_mac_coverage.py
python -m pytest -q "tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main" \
  "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" \
  "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main"
python -m pytest -q "tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot" -k mac
python -m ruff check s19_app/tui/app.py s19_app/tui/services/validation_service.py tests/test_tui_mac_coverage.py
```

## 4. Test results (one run each — C-19)

- **RED→GREEN:** before implementing, `tests/test_tui_mac_coverage.py` collection
  failed → `ImportError: cannot import name 'build_mac_coverage_strip'` (RED).
  After implementing + the F1/F2 fixes → **7 passed in 13.51s** (GREEN):
  `test_at070_glyph_branches` (case_02 still ✓ AND ⚠), `test_at070b_c17_name`,
  `test_at070c_parse_error` (still ✗), **`test_at070d_mac_only_unchecked_glyph`
  (NEW — MAC-only parse-ok record → `·`, not `✓`)**, `test_at071_strip`,
  `test_zero_total_no_divzero`, `test_build_mac_coverage_strip_counts` (each AT
  runs both 80×24 and 120×30).
- **C-27 dual-guard:** 4 passed — `test_tc027…`, `test_tc031…`, `test_tc032…` (×2).
  `git diff --stat main -- tui/mac.py core.py hexfile.py range_index.py color_policy.py`
  = empty. Working tree: only `app.py`, `validation_service.py` modified + 2 test files.
- **C-26-affected files:** `test_tui_app.py` + `test_validation_service_supplemental.py`
  + `test_tui_a2l_issue_recolor.py` + `test_tui_directionb.py` → exit 0 (all pass).
- **Snapshot (C-22):** exactly 4 `mac` cells drifted → `mac-{compact,comfortable}-{120x30,160x40}`;
  `mac-*-80x24` stay green (changed pane below the narrow fold). Now `xfail(strict=False)`;
  after marks → `2 passed, 4 xfailed` for `-k mac`. **Post-F1 re-check unchanged**
  (`2 passed, 4 xfailed`) — the snapshot fixture loads a primary S19, so records
  are image-checked (`InMem "yes"/"no"`); F1 only alters the un-checked `"n/a"`
  path, absent here, so the marks need no adjustment. C-28: no other screen's
  cell newly failed → no shared-chrome / footer / binding drift.
- **Full suite (pre-F1):** `python -m pytest -q` → **1429 passed, 2 skipped, 21
  xfailed** (exit 0, 0 failures). The 21 xfailed = pre-existing batch-47
  workspace/a2l/patch drift marks + the 4 new mac drift marks; no new failures/hangs.
- **F1 re-verification (render-only, narrowly scoped):** after the F1/F2 fixes,
  re-ran the direct `_populate_mac_datatable` consumers — `test_tui_app.py` +
  `test_tui_directionb.py -k mac` → **29 passed, 207 deselected**; plus the 7 new
  mac_coverage tests, C-27 3/3, and the 4 mac snapshot cells (unchanged) all green.
- **ruff:** All checks passed.

## 5. Risks

- Un-image-checked records now render grey `·` (F1 fix), so no false green.
  A parse-ok, **in-image** record that fails A2L address matching
  (`A2L_ADDR_MISMATCH`, int address in range → `InMem "yes"`) still renders `✓`
  green — correct per LLR-070.1 (`✓` = parse-ok + in-image); its **row severity
  colour** stays red on the separate validation axis. This two-axis split (glyph =
  image presence, row colour = validation severity) is intended; documented in the
  `_MAC_GLYPH_*` comment.
- Coverage strip numbers come from `self._validation_report.coverage`; both the
  sync (`_build_mac_view_cache`) and worker (`_apply_prepared_load`) paths set
  `_validation_report`, so the strip is fresh in either. `_update_mac_coverage_strip`
  no-ops defensively when the node is unmounted (headless unit tests faking `query_one`).
- SVG baselines are **not** regenerated locally — the 4 wide mac cells regenerate
  in canonical CI (`snapshot-regen.yml`, textual==8.2.8) in the batch-47 theme+regen
  follow-up PR, then the marks retire.

## 6. Pending items

- **Canonical-CI snapshot regen** (batch-47 follow-up): retire
  `_batch47_mac_drift_marks` once the 4 wide mac baselines regenerate.
- Later increments (US-MAP Inc-5-map / R-TUI-072..074) unaffected by this increment.

## 7. Suggested next task

Inc-5 US-MAP (Memory Map BIG) — `screens_directionb.py` bands + 5-tick ruler +
`RegionRow` enrich + inspector hex-peek (AT-072a/072b/073/074), per the crosswalk.

---

## Evidence checklist

- [x] Tests/type checks/lint pass — 6/6 new (both sizes); C-27 4/4; ruff clean; full-suite below.
- [x] No secrets in code or output — synthetic injection payloads only; public `examples/` fixtures.
- [x] No destructive commands run without approval — read/test/edit only.
- [x] File count within cap — 4 files (app.py, validation_service.py, 2 test files); fixtures inlined.
- [x] Review packet attached — this document.

## C-17 payload proof (AT-070b, gate-blocking)

Hostile MAC record `name` = `"[red]PWNED[/red][link=http://x]u[/link]\x1b[31mX\x1b[0msensor[unclosed"`
planted directly into `LoadedFile.mac_records` (bypasses the frozen parser).
`table.get_row_at(0)[0]` is a Rich `Text`; each of the 4 MD-1 payloads appears
**verbatim** in `.plain`; no span style contains `red`/`link`; the unbalanced
`sensor[unclosed` raises **no** `MarkupError` (Tag cell is built via
`Text().append(...)`, never `Text.from_markup`). Passed at 80×24 and 120×30.

## C-22 snapshot-drift list

| Cell | Status |
|---|---|
| `mac-compact-80x24` | PASS (unchanged — below narrow fold) |
| `mac-comfortable-80x24` | PASS (unchanged) |
| `mac-compact-120x30` | xfail(strict=False) — regen pending |
| `mac-compact-160x40` | xfail(strict=False) — regen pending |
| `mac-comfortable-120x30` | xfail(strict=False) — regen pending |
| `mac-comfortable-160x40` | xfail(strict=False) — regen pending |

C-28 shared-chrome: no footer/header/rail binding added or removed → no
cross-screen key drift; only the 4 mac cells above moved.

## C-26 reverse-census (MAC render surfaces × non-frozen tests)

Reverse-grep `#mac_records_list` / `mac_records_list` / `_populate_mac_datatable` /
`mac_records_summary` / `update_mac_view` / `_compute_mac_view_payload` /
`precompute_mac_datatable_payload` across `tests/` (frozen `test_tui_mac.py` excluded):

| File | Reference | Re-validated |
|---|---|---|
| `test_tui_app.py` | `test_update_mac_view_reuses_cached_model_between_pages` (fake table, `#mac_records_list`/`#mac_records_summary`); `test_compute_mac_view_payload_matches_build_cache`; `precompute_mac_datatable_payload` tests | PASS — I did not change `_compute_mac_view_payload` row tuples or `precompute_…`; `_populate_mac_datatable` reads existing `row[4]`/`row[1]`; fake `query_one` returns `None` for `#mac_coverage_strip` → `_update_mac_coverage_strip` no-ops. |
| `test_tui_directionb.py` | MAC pane structure (`#mac_records_pane`/`#mac_records_list`, owns-list), `test…mac…populate`, paging | PASS — id-scoped queries; the new `#mac_coverage_strip` Static does not alter the asserted `["mac_records_list","mac_hex_view"]` ownership or pane order. |
| `test_validation_service_supplemental.py` | `build_validation_report` supplemental issues | PASS — additive new function only; no existing export changed. |
| `test_tui_a2l_issue_recolor.py` | `update_mac_view` mentioned in a comment (freshness) | PASS — no MAC-render assertion; behavior unchanged. |
| `test_tui_snapshot.py` | `app.update_mac_view()` in the snapshot run_before | Updated — `_batch47_mac_drift_marks` added (C-22). |

No stale OLD-render assertion required a code change (only the snapshot census was updated).

## C-27 result

`git diff --stat main` shows **0 diff** on the frozen set (`core.py`, `hexfile.py`,
`range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`,
9 frozen test files). Guards `test_tc027` / `test_tc031` / `test_tc032`: **pass**.

## Strip-gating change (LLR-071.2)

Old: coverage rendered as a pct-line appended to `#mac_records_summary` **only**
when `current_file.file_type in {"s19","hex"}` and a `coverage_line` existed
(`validation_service` returns `None` for MAC-only). New: `#mac_coverage_strip`
is a dedicated always-visible node; `update_mac_view` calls
`_update_mac_coverage_strip(show=False)` after `clear` (covers both no-MAC early
returns → blank) and `_update_mac_coverage_strip(show=True)` after the records
populate (renders from `CoverageMetrics`, any file type incl. MAC-only → `0 of 0`).
The old summary pct-line is left untouched (unchanged behavior).

### Gate outcome (orchestrator, 2026-07-15)
- **Dual review:** security-reviewer **APPROVE-CLEAN** (0 HIGH/0 MEDIUM — 8-col MAC sink inventory all literal Text, strip numeric-only markup=False, AT-070b counterfactual independently reproduced); code-reviewer **APPROVE-WITH-NITS** → one MEDIUM (F1) + LOW (F2).
- **F1 (MEDIUM) FIXED (iterate-to-fix within Inc-5):** `else→✓` mislabeled un-image-checked MAC records (MAC-only load, `primary_file=None` → every parse-ok record a false green `✓`). Glyph now derives from `row[3]` in_mem_text (4-way: `✗`/`⚠`/`✓`/`·`grey), so `✓` = strictly parse-ok+in-image per LLR-070.1; `·` grey = not-yet-checked (Grey convention). No §6.5 amendment (fix conforms to spec). **NEW AT-070d** (MAC-only → `·`, both regimes) closes the C-10 coverage gap. F2 docstring corrected.
- **Re-run:** 7 passed (mac-coverage), C-27 3 passed 0-diff, 29 consumer tests passed, mac snapshot 2/4-xfailed unchanged, ruff clean. Full suite (1429 pass) ran pre-F1; F1 render-only, re-verified via targeted consumers → definitive full run deferred to Phase-4 (orchestrator-owned C-25).
- **Canonical AT registry now 20** (+AT-070d, a Phase-3 C-10 branch addition self-owned by Inc-5; no orphan).
- **Gate axis check:** Coverage OK (AT-070/070b★/070c/070d/071 single-node, C-10 all four glyph branches now covered); Certainty OK (C-17 counterfactual has teeth; AT-070d asserts `·` not `✓`); Evidence OK (dual review + reproduced counts). **APPROVE.** → Inc-6 (US-MAP Memory Map BIG).
