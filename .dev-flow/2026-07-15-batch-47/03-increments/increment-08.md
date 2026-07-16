# Increment 08 — US-FND app-wide navy/pastel theme (R-TUI-065, HLR-065 / LLR-065.3 / LLR-065.4)

Batch-47 (screen-upgrades Batch A) · **LAST increment** · the big snapshot-drift one.
Branch `claude/screen-upgrades-handoff-0874f9` (HEAD before this inc = a3fa896, Inc-7).

---

## 1. What changed

The app-wide **navy/pastel dolphie theme** landed in `styles.tcss`, plus its two acceptance
tests and the mandated snapshot-drift / C-26 reconciliation:

1. **App `$`-variables (LLR-065.3):** the five theme vars were re-pointed from the old Calm-Dark
   hues to the `insight_style` navy depth stack (the palette source of truth, Inc-1). A new
   `$odd-row` var was added for zebra rows. Because every screen's `Screen`/panel styling reads
   these vars, the theme is applied app-wide.
2. **Panel chrome (LLR-065.3):** the broad `.db-pane` panel class gained the dolphie idiom — a
   `tall` framed border, an accent `border-title-color`, a panel `border-title-background`, and a
   muted `border-subtitle-color`. A `DataTable > .datatable--odd-row` zebra rule was added over the
   new `$odd-row` surface (inert unless a table enables `zebra_stripes`).
3. **sev-\* hue alignment (LLR-065.4 → §6.5 Amendment C):** all five `sev-*` rules were retuned to
   the pastel palette. Hue **families** (and thus severity semantics) are preserved; class **names**
   are unchanged; `color_policy.py` stays 0-diff (the restyle is CSS-only). `.mac_out_of_range` was
   **left unchanged** (amber #d9a35b) so the explicit "Orange = MAC warning" cue survives regardless
   of the `sev-warning` change. `band-*` entropy rules were left unchanged (separate, non-severity
   domain — out of scope for LLR-065.4).
4. **AT-065a / AT-065b** appended to the existing (non-frozen) `tests/test_tui_theme.py`.
5. **Snapshot drift** — a new `_batch47_theme_drift_marks` helper marks the cells the theme drifts
   that the Inc-3..7 per-screen marks didn't already cover (issues, mac-80×24, diff).
6. **C-26** — the resolved-token test `test_tc033_modals_render_with_calm_dark_tokens`
   (`tests/test_tui_directionb.py`, non-frozen) was updated to the new palette hex constants.

### `$`-variable mapping applied (`styles.tcss:26-31`)

| var | before | after | insight_style |
|-----|--------|-------|---------------|
| `$accent-calm` | `#4ec9d4` | `#91abec` | HILITE |
| `$bg-base` | `#11141a` | `#0a0e1b` | DEPTH_BG |
| `$bg-panel` | `#171b23` | `#0f1525` | DEPTH_PANEL |
| `$fg-base` | `#c8ccd4` | `#e9e9e9` | VALUE |
| `$rule` | `#2a2f3a` | `#1b233a` | DEPTH_BORDER |
| `$odd-row` | *(new)* | `#131a2c` | DEPTH_ODD_ROW |

### sev-\* hue restyle — §6.5 Amendment C (Before → After, per class)

| class | before | after | family | semantics |
|-------|--------|-------|--------|-----------|
| `.sev-ok` | `#5fb98a` | `#54efae` (GREEN) | green | memory-checked + present — **preserved** |
| `.sev-error` | `#e06c75` | `#fd8383` (RED) | red | schema/structural failure — **preserved** |
| `.sev-warning` | `#d9a35b` | `#f6ff8f` (YELLOW) | warm/warning | warning-level — **preserved** |
| `.sev-info` | `#4ec9d4` | `#7dd3fc` (CYAN) | cyan | info — **preserved** |
| `.sev-neutral` | `#6b7280` | `#969aad` (DGRAY) | grey | not-yet-checked — **preserved** |
| `.mac_out_of_range` | `#d9a35b` | *(unchanged)* | orange/amber | **Orange = MAC warning cue retained** |

Class NAMES unchanged; severity SEMANTICS (Red / Green / White / Grey + Orange MAC) preserved;
`color_policy.py` 0-diff. The orchestrator records this table as §6.5 Amendment C (the conditional
placeholder is now filled — hues DID move).

---

## 2. Files modified (4 — within the ≤5 cap; 1 was the census-driven C-26 fix)

- `s19_app/tui/styles.tcss` — `$`-var swap + `$odd-row` + `.db-pane` dolphie chrome + zebra rule +
  sev-* pastel alignment (NON-frozen).
- `tests/test_tui_theme.py` — appended `test_at065a_palette` + `test_at065b_sev_semantics`
  (imports: asyncio / textual.color.Color / textual.widgets.Static / insight_style / app). The
  existing TC-012/TC-013 invariant tests (the TC-065.5 guard) are preserved and still pass.
- `tests/test_tui_snapshot.py` — new `_batch47_theme_drift_marks`; wired into `_RESTYLED_CELLS` +
  `_SCAFFOLD_CELLS`.
- `tests/test_tui_directionb.py` — **C-26**: `test_tc033_*` token constants → new palette.

**Frozen files: 0 touched.** `color_policy.py` is 0-diff (proof below).

---

## 3. How to test

```bash
# AT-065a/b + the TC-012/013 invariant guard (TC-065.5)
python -m pytest tests/test_tui_theme.py -q

# sev-* round-trip frozen anchor + engine-frozen guards (C-27)
python -m pytest tests/test_color_policy_round_trip.py tests/test_engine_unchanged.py -q
python -m pytest "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" \
                "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main" -q

# C-26 resolved-token corroboration
python -m pytest "tests/test_tui_directionb.py::test_tc033_modals_render_with_calm_dark_tokens" -q

# Full app-wide snapshot drift (all cells known-xfail → suite green)
python -m pytest tests/test_tui_snapshot.py -q

# color_policy 0-diff proof (empty output == 0 diff)
git diff --stat main -- s19_app/tui/color_policy.py
```

---

## 4. Test results (all local, textual==8.2.8 == the canonical pin)

- **`tests/test_tui_theme.py` — 18 passed** (TC-012/013 invariants + AT-065a + AT-065b).
  - **AT-065a RED→GREEN:** pre-theme FAIL — `Screen background Color(17,20,26)` (#11141a) `!= #0a0e1b`;
    post-theme PASS — Screen bg == DEPTH_BG **and** `.db-pane` bg == DEPTH_PANEL, app boots, no crash.
  - **AT-065b RED→GREEN:** pre-theme FAIL — `sev-error resolved to Color(224,108,117)` (#e06c75)
    `!= Color(253,131,131)` (#fd8383); post-theme PASS — `css_class_for_severity` round-trip intact
    for all 5 severities **and** a live `sev-error` widget resolves to pastel RED.
- **Snapshot suite — `3 passed, 29 xfailed, 0 unexpected failures`.** The `pytest-textual-snapshot`
  plugin reports **29 mismatched snapshots** — i.e. EVERY one of the 29 tc016s cells drifted from the
  app-wide theme, exactly as predicted (C-28 shared-chrome). Every drifting cell is a known
  `xfail(strict=False)`; the 3 passes are the non-snapshot CV-04 boundary + public-fixture sub-cases.
- **`tests/test_tui_directionb.py` — 174 passed** (includes the C-26 tc033 fix, the tc031×3 / tc032×3
  frozen guards, and the modal token-budget inspection test — `$odd-row` is not referenced in the
  modal block so that budget test is unaffected).
- **Frozen anchors — `test_engine_unchanged.py` + `test_color_policy_round_trip.py` = 17 passed.**
- **ruff:** `All checks passed!` (theme + snapshot + directionb test files).

---

## 5. Risks

- **Snapshot baselines are intentionally stale.** All 29 SVG baselines still encode the pre-theme
  hues; they must be regenerated in **canonical CI only** (`snapshot-regen.yml`, textual==8.2.8) as
  the batch-47 **post-merge follow-up PR** — never locally (reference_snapshot_regen_env). Until then
  the cells ride `xfail(strict=False)`. **Low** — the suite is green; drift is by design.
- **`border: round → tall` on `.db-pane`** is a visible cosmetic change to the workspace panes only
  (the specific `#id` panels keep `round`). Deliberate: surgical, avoids rewriting ~20 individual
  border rules. Snapshot-covered (xfail). **Low.**
- **`sev-warning` moved from amber to pastel yellow.** The explicit "Orange = MAC warning" cue is NOT
  lost — it lives in the separate, unchanged `.mac_out_of_range` overlay (+ frozen
  `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"`). Reported in Amendment C. **Low.**

---

## 6. Pending items

- **Canonical-CI snapshot baseline regen** (29 cells) — post-merge follow-up PR, retires the batch-47
  per-screen marks + `_batch47_theme_drift_marks` together (orchestrator/Phase-6).
- Orchestrator records **§6.5 Amendment C** from the Before→After table in §1.
- `band-*` entropy rules deliberately NOT re-themed (separate domain); flag if visual cohesion later
  wants them aligned — would be its own requirement decision.
- Chip-button styling from the dolphie idiom was **not** added: no widget in this theme-only
  increment consumes a `.chip` class, so adding one would be dead CSS (simplicity/surgical rule). The
  existing `.issue-code-chip` is untouched. Flag for a future screen story if a chip widget lands.

## 7. Suggested next task

Batch-47 is complete (Inc-1..8 shipped). Next: **open the batch-47 PR**, then the **canonical-CI
snapshot-regen follow-up PR** (regenerate the 29 tc016s baselines + retire the batch-47 marks),
mirroring the batch-45/46 regen pattern. Batch B (Patch Editor BIG, blocked on batch-46 lineage) is
the subsequent screen-upgrade batch.

---

## Evidence checklist

- [x] Tests/type checks/lint pass — theme 18/18, directionb 174/174, frozen anchors 17/17, snapshot
  `3 passed / 29 xfailed / 0 unexpected`, ruff clean.
- [x] No secrets in code or output — CSS hex values + tests only.
- [x] No destructive commands run without approval — read/test/edit only.
- [x] File count within cap — 4 files (≤5); the 4th is the mandated C-26 fix.
- [x] Review packet attached — this document.
- [x] **C-27 color_policy.py 0-diff** — `git diff --stat main -- s19_app/tui/color_policy.py` = empty;
  tc031×3 + tc032×3 + round-trip green.
- [x] **C-26 census** — swept `tests/` for the changed hexes + resolved-style assertions; only real
  Python hit was `test_tc033_*` (fixed); all other matches are `.svg` baselines (regen in CI).

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review:** **APPROVE-CLEAN, 0 findings.** sev-* families all correct (each new hue in its right family; class names unchanged; `.mac_out_of_range` Orange preserved + now distinct from the yellow `.sev-warning`; `band-*` untouched). `color_policy.py` 0-diff proven (`git diff main` empty; round-trip green). AT-065a/b real counterfactuals (Screen bg + live sev-error resolve to new palette, RED pre-theme). Snapshot census COMPLETE + NON-MASKING: 29 mismatched = 29 xfailed, **0 xpassed** (a theme-invariant cell would xpass → none did). border round→tall glyph-only, no geometry regression (185 passed). Chip deferral correct; zebra has 3 live consumers.
- **§6.5 Amendment C RECORDED** by orchestrator with the exact sev-* Before→After (5 classes → pastel palette; families + names + color_policy preserved).
- **Gate axis check:** Coverage OK (AT-065a/b realized; LLR-065.3/065.4 done; chip-button deferred to Batch B, no AT orphan); Certainty OK (AT counterfactuals + 0-xpassed drift proof + color_policy 0-diff); Evidence OK (all reproductions green). **APPROVE.** **PHASE 3 COMPLETE — 8/8 increments; all LLRs implemented, 20 ATs realized.** → Phase 4 (validation, orchestrator-owned full gate run C-25).
