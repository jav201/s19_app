# Increment 04 — US-A2L Explorer MID (HLR-068 / HLR-069)

> Batch 47, Inc-4. Branch `claude/screen-upgrades-handoff-0874f9` (from Inc-3 `4adb672`).
> Supervised-incremental. **This increment opened NEW untrusted-text render sinks → C-17 dominant.**

## 1. What changed

Rendered the A2L Explorer MID insight layer over `_a2l_enriched_tags` — all app/service-side, `tui/a2l.py` untouched (frozen).

- **LLR-068.1/068.3 (MJ-3, C-17):** `_build_a2l_table_cells` now returns `tuple[Text, ...]` — **every** cell is a markup-safe Rich `Text` built via `safe_text` (never `Text.from_markup`, never an f-string into markup). The untrusted cells (name, source, unit, function_group, memory_region, raw_value, physical_value) render literally. Accents: name bright (`VALUE`), address cyan (`CYAN`), source muted (`DGRAY`).
- **Glyph column (folded into the name cell):** the name cell carries a leading in-image glyph — `✓` when `tag["in_memory"]` is truthy, else `·`. **Folded into the name cell (kept the 16-cell tuple)**, NOT a 17th column — this keeps the existing `add_columns(...)` set and all cell-index assertions working; TC-067.1 asserts "all 16 are `Text`", confirming 16 was the intended count.
- **Severity preserved (surfaced conflict, see Risks):** `update_a2l_tags_view` still applies the per-row A2L Red/Green/White/Grey severity (`_SEVERITY_TO_RICH_STYLE`) as an override on top of the builder's accent cells. The rendered table is visually identical to before **except** the glyph prefix + summary; the accents live in the builder output (unit-tested) and are overridden by the mandatory severity colour in the rendered table.
- **LLR-068.2:** `#a2l_tags_summary` now shows a colored in-image count (`… · N in image`, green) via a Rich `Text` passed to `Label.update`.
- **LLR-069.1 (NEW widget):** `A2LDetailCard(Static)` mounted at the TOP of `#a2l_hex_pane`, hex view below it (vertical split, same pane, no new pane). Bounded height (`DEFAULT_CSS` `max-height: 5; overflow-y: auto`) so the hex stays visible at 80×24 (C-29).
- **LLR-069.2 (NEW handler):** `on_data_table_row_highlighted` (DataTable.RowHighlighted) for `#a2l_tags_list` → updates the card with the highlighted tag's description / unit·conversion / record layout / byte order / limits. Distinct from the existing RowSelected jump handler (which stays).
- **LLR-069.3 (C-17, MN-5):** the card is composed at the `Text` level (`_a2l_detail_card_text` — append/join Rich `Text`); no file-derived value is f-strung into markup.

## 2. Files modified (5, within cap)

- `s19_app/tui/app.py` — insight_style import (+`DGRAY`,`LABEL`); NEW module-level `_card_field`, `_a2l_detail_card_text`, `A2LDetailCard(Static)`; `A2LDetailCard` mounted in `_compose_screen_a2l`; `_build_a2l_table_cells` → `tuple[Text,...]` + glyph; `update_a2l_tags_view` cell/severity + colored summary; NEW `on_data_table_row_highlighted`.
- `tests/test_tui_a2l_detail.py` — **NEW** (AT-068/069/069b★/069c★ + TC-067.1/067.5). `a2l_injection` hostile payload is **inline** in the test (no fixture file added).
- `tests/test_tui_a2l_issue_recolor.py` — C-26: `_a2l_row_list` strips the new name-cell glyph prefix.
- `tests/test_validation_service_supplemental.py` — C-26: same `_a2l_row_list` glyph-strip.
- `tests/test_tui_snapshot.py` — C-22: NEW `_batch47_a2l_drift_marks` (6 a2l cells `xfail(strict=False)`), wired into `_RESTYLED_CELLS`.

## 3. How to test

```bash
# new node (both 80x24 + 120x30 inside each AT)
PYTHONIOENCODING=utf-8 python -m pytest -q tests/test_tui_a2l_detail.py
# C-27 dual-guard (tui/a2l.py is FROZEN — confirm 0 diff)
python -m pytest -q tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main \
  tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main \
  tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main tests/test_tui_a2l.py
# C-26 files
python -m pytest -q tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py
# C-22 snapshot drift (a2l xfails; mac/issues green)
python -m pytest -q tests/test_tui_snapshot.py -k "a2l or mac or issues"
```

## 4. Test results (real output)

- **RED-first** (`git stash push s19_app/tui/app.py`): `ImportError: cannot import name 'A2LDetailCard' from 's19_app.tui.app'` → collection error = card/handler/tuple-Text absent. Restored via `git stash pop`.
- **GREEN** `tests/test_tui_a2l_detail.py`: **6 passed** (AT-068, AT-069, AT-069b★, AT-069c★, TC-067.1, TC-067.5).
- **C-17 verbatim proof** (probe + AT-069b/069c): a highlighted tag renders `card.render().plain == '· COOLANT  0x00009000\ndesc Coolant temperature\nunit degC\nbyteorder little'`; the hostile-payload ATs pass with `[red]PWNED[/red]`, `[link=http://x]u[/link]`, ANSI `\x1b[31mX\x1b[0m`, and the unbalanced `sensor[unclosed` all present **verbatim** in `Text.plain`, **no `MarkupError`**, and no payload-derived span (`name_cell.spans == []` for the table cell; card spans carry only developer LABEL/VALUE styles — no `red`/`link`).
- **C-27 dual-guard:** 21 passed (0 frozen src/test diffs; frozen `test_tui_a2l.py`/`test_tui_mac.py` green — the frozen test only exercises the parser, not the render layer).
- **C-26 files:** 6 previously-failing tests fixed → both files green (28 passed with the new file).
- **Regression:** `test_tui_directionb.py` + `test_tui_mac_layout.py` + `test_tui_app.py` = **242 passed, 1 xfailed** (pre-existing) — the card added to `#a2l_hex_pane` broke no layout/pane-ownership/geometry test.
- **Snapshot (C-22/C-28):** the 6 a2l cells now **xfail**; mac + issues (12 cells) **pass** → shared-chrome clean.
- **ruff:** All checks passed (5 touched files).

## 5. C-29 two-axis geometry (measured, both regimes)

Pilot-measured `#a2l_hex_pane` **with the card mounted + a tag highlighted** (`App.run_test`, real `.region`):

| size | pane region | card region h | `#alt_hex_scroll` h |
|---|---|---|---|
| 80×24 | w=32, h=9 | 5 (capped by `max-height`) | **5** (not occluded) |
| 120×30 | w=42, h=15 | 5 | **11** |

Card `DEFAULT_CSS`: `height: auto; max-height: 5; overflow-y: auto`. Content is up to ~5 field lines; the **full** composed `Text` is the widget renderable (ATs read `card.render().plain` regardless of visual clip), so C-17 verbatim holds even if the card visually scrolls. **Hex is not fully occluded at the 80×24 floor** (h=5 ≥ 1). No hard-coded row/col count is asserted — the ATs assert structural invariants (glyph present, description substring present, verbatim payload).

## 6. Snapshot-drift list (C-22 per-cell + C-28 shared-chrome)

Genuinely-drifting cells (per the live snapshot run, `strict=False` upper bound), all in `_batch47_a2l_drift_marks`:
`a2l-compact-80x24`, `a2l-compact-120x30`, `a2l-compact-160x40`, `a2l-comfortable-80x24`, `a2l-comfortable-120x30`, `a2l-comfortable-160x40` (6 cells).
**C-28:** mac + issues (control) cells pass unchanged; no footer/header/rail binding was added or removed this increment → shared-chrome clean. **Regen is deferred to canonical CI** (`snapshot-regen.yml`, textual==8.2.8) per policy — NOT regenerated locally.

## 7. C-26 reverse-census (touched symbols: `_build_a2l_table_cells`, `a2l_tags_list`, `a2l_tags_summary`, `a2l_hex_pane`, `on_data_table_row_highlighted`)

| File | Assertion on OLD render | Disposition |
|---|---|---|
| `test_tui_a2l_issue_recolor.py` | `_a2l_row_list` keyed on bare name (`str(cells[0])`); `name.casefold()=="rpm"`, `TORQUE` control; `cell.style == error_style` | **Updated** — `_a2l_row_list` strips the `✓ `/`· ` glyph prefix. Severity assertions hold: severity override keeps error rows uniformly `red`; accented (non-error) cells are `!= red`. |
| `test_validation_service_supplemental.py` | `_a2l_row_list`; `rows["BROKEN_CHAR"]`, `{"RPM","TORQUE"} <= set(rows)`, `name=="DUP_RPM"` | **Updated** — same glyph-strip; style assertions hold (override preserved). |
| `test_tui_directionb.py` | pane-ownership `owns == ["a2l_tags_list","alt_hex_view"]` (targeted queries); tc019 `#a2l_hex_pane` width 3/7; row-scroll `#a2l_tags_list` | **No change needed** — targeted queries unaffected by the added `#a2l_detail_card`; width unaffected by a vertical child. Verified green (242 passed). |
| `test_tui_mac_layout.py` | comment reference to `#a2l_hex_pane` only | **No change** — no assertion on it. Verified green. |
| `test_tui_app.py` | `_fake_query_one` for `#a2l_tags_list` (no cell read); `on_data_table_row_selected(_Evt)` | **No change** — RowSelected path untouched by the new RowHighlighted handler. Verified green. |

## Evidence checklist

- [x] Tests/type checks/lint pass — `test_tui_a2l_detail.py` 6 passed; ruff clean (5 files); regression 242 passed/1 xfailed.
- [x] No secrets in code or output — synthetic public fixtures + synthetic injection payloads only.
- [x] No destructive commands run without approval — only `git stash`/`git stash pop` (self-reversed for RED evidence).
- [x] File count within cap — 5 files (1 src + 4 test), cap 5.
- [x] Review packet attached — this file.
- [x] C-27 dual-guard — 0 frozen src/test diffs; `tui/a2l.py` not touched.
- [x] C-17 gate-blocking ATs — AT-069b★ (card) + AT-069c★ (table cell) pass, full MD-1 payload verbatim, no `MarkupError`.
- [x] Widget-name shadowing — only new member is public `show_tag`; `set(dir(Widget)) & {"show_tag"} == ∅`; no `_nodes`/`_context`.

## Risks

- **Severity-vs-accent conflict (surfaced, not averaged — eng-rule 7).** The batch-47 spec asks for per-cell accents (name bright / addr cyan / source muted), but the pre-existing A2L row-severity colouring (REQUIREMENTS.md: Red/Green/White/Grey) applies one uniform style per row and is gate-tested (HLR-037). Since every row resolves to a severity, the severity override wins in the rendered table, so the accents are visible only in the builder output (unit-tested), not the live table. I preserved the documented severity contract (dominant) rather than regress it for the accent. If the operator wants accents visible on non-error rows, that is a follow-up requiring a severity-restyle decision + §6.5 amendment.
- Snapshot baselines for the 6 a2l cells are `xfail` pending the canonical-CI regen (Inc-7) — standard batch-47 pattern.

## Pending items

- Canonical-CI SVG regen for the 6 a2l cells (batch-47 Inc-7 theme+regen follow-up) — retires `_batch47_a2l_drift_marks`.
- (Carried) frozen `a2l.py:926` F841 — untouched here.

## Suggested next task

**Inc-5 — US-MAC View MID** (`app.py` glyph column ✓/⚠/✗ + coverage strip, `validation_service` strip-gating, NEW `test_tui_mac_coverage.py` + `mac_injection`/parse-error fixtures): AT-070 / AT-070b★ / AT-070c / AT-071. Reuse this increment's `safe_text` cell pattern and the RowHighlighted precedent.

### Gate outcome (orchestrator, 2026-07-15)
- **Dual review (C-17 sink increment):** security-reviewer **APPROVE-CLEAN** (0 HIGH/0 MEDIUM — full 16-cell + 8-card-field sink inventory, all `safe_text`/`Text` literal, card `markup=False`, both C-17 ATs genuine adversarial proofs past the frozen parser, MD-1 payload complete incl. unbalanced-bracket, no new fs/exec surface); code-reviewer **APPROVE-WITH-NITS** (0 HIGH/0 MEDIUM — reproduced 6 passed + C-27 + C-26 files green).
- **F1 (LOW, accepted tradeoff) → §6.5 Amendment E:** per-cell accents (LLR-068.1) are subsumed by the REQUIREMENTS-level A2L severity contract (HLR-037, Red/Green/White/Grey) which overrides cell `.style`; shipped A2L-table deliverable = in-image glyph column + colored summary + zebra. AT-068/AT-069c don't assert accents → no acceptance unmet. Accents-on-non-error-rows flagged as an operator follow-up. Recorded as Amendment E.
- **F2 (LOW) no-action:** broad `except` on card lookup matches the existing RowSelected idiom (defensive; card may be unmounted).
- **Gate axis check:** Coverage OK (AT-068/069/069b★/069c★ realized single-node, both regimes; C-17 both sinks); Certainty OK (C-17 ATs discriminating — `spans==[]` + unbalanced-bracket counterfactual + hex-styles-can't-false-pass; AT-068 both glyph branches); Evidence OK (dual review reproduced 6 passed + C-27 0-diff + 6-cell drift + C-26 242 passed). **APPROVE.** → Inc-5 (US-MAC).
