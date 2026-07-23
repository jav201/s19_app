# Quick Spec — s19_app · N1 legend per-screen + N2 log-line width

> Minimal spec for `/fast-dev-flow`. Observable acceptance criteria only. Two small increments.

- **Date:** 2026-07-23
- **Batch:** n1-n2-legend-tasklog
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** autonomous end-to-end + self-merge (operator-granted this batch, per-batch).
- **Status:** CLOSED 2026-07-23. N1 legend-per-screen + N2 width-aware log cap shipped.
- **Branch:** `feat/n1-n2-legend-tasklog` off `main` `5ec46b3` (RC-1 verified HEAD == origin/main tip).

---

## 0. Phase-A findings (C-35, honest scoping)

- **N1:** `legend.LEGEND_TABLE` is already keyed by artifact section — exactly `['A2L', 'MAC', 'Issues', 'Hex']`. `screens.LegendScreen.compose` renders **all four** regardless of the active screen. Fix = filter to the active screen's relevant section(s) via a small screen→sections map.
- **N2:** the log-tail truncation is a **code cap** — `_append_log_line` does `line = trimmed[:50]` (app.py:11247), NOT a CSS width (the backlog guessed CSS). The `#log_line_1..4` Labels already sit in the full-width `#workspace_status_bar`; the `[:50]` slice is what truncates long paths. Fix = cap width-aware (to the app's current width) instead of a fixed 50.

---

## 1. Objective (1 line)

Make the Legend modal show only the classes the **current screen** actually paints (N1), and let the status-bar **activity-log lines** use the full viewport width so long `.s19tool/workarea/…` paths are readable at fullscreen instead of being clipped at 50 chars (N2).

---

## 2. User stories (Connextra)

- As an engineer on the A2L (or MAC / Issues / Map) screen, I want the Legend to list only that screen's classifications, so I'm not shown swatches for artifacts that screen doesn't paint.
- As an engineer maximizing the window, I want the activity-log lines to show full file paths, so I can read the whole `.s19tool/workarea/<project>/…` path instead of a 50-char stub.

---

## 3. Acceptance criteria (observable)

**N1 — legend per-screen**
- [ ] **AC-1:** When the Legend modal is opened from the **A2L** screen, it lists the **A2L** section rows and NOT the MAC / Issues / Hex sections.
- [ ] **AC-2:** From the **MAC** screen → MAC only; from **Issues** → Issues only; from **Memory-Map** → Hex only.
- [ ] **AC-3 (fallback, no regression):** From a screen with no single mapped section (e.g. Workspace / Flow / CRC-Designer), the Legend shows the full table (all four sections) — never an empty legend.
- [ ] **AC-4 (frozen round-trip intact):** Every rendered legend row's `sev-*` class still comes from `color_policy.css_class_for_severity` / `COLOUR_SEVERITY` (the frozen `SEVERITY_CLASS_MAP` oracle is unchanged and only read).

**N2 — log-line width**
- [ ] **AC-5:** When a log message longer than 50 chars is appended at a **wide** viewport (e.g. 200×50), the stored/rendered log line contains the full message (untruncated up to the app width), not a 50-char stub.
- [ ] **AC-6:** At a **narrow** viewport the line is still bounded (capped to the app width, with a sensible floor) — it never grows unbounded and never bisects a rendered escape (markup stays off).

---

## 4. Validation strategy

`App.run_test()` Pilot + unit tests in `tests/`. **N1:** open the Legend from each screen (drive `action_show_legend` after `action_show_screen`), read the `LegendScreen`'s rendered `.legend-artifact` heading labels, and assert the set equals the expected section(s) (AC-1/2), the fallback shows all four (AC-3), and each `.legend-row` still carries a frozen `sev-*` class (AC-4). **N2:** append a >50-char path via `_append_log_line` at a wide size, assert the rendered `#log_line_4` label text contains the full path (AC-5); at a narrow size assert it is bounded to the width (AC-6). Each AC maps to a named test; RED shown pre-fix (today the legend renders all four sections from every screen, and `_append_log_line` clips at 50). Manual smoke: open the legend on A2L vs MAC; load a deep path and read the log tail maximized.

---

## 5. Non-goals (OUT)

- No change to the legend **content/meanings** or the frozen `SEVERITY_CLASS_MAP` / `color_policy` (read-only).
- No new legend widget or per-screen legend buttons — the single modal is reused, only its row set is filtered.
- No redesign of the status bar layout; only the per-line character cap becomes width-aware.
- Report/CRC/A2L **progress** indicators (N5 follow-ups) are unrelated and out.

---

## 6. Detected security flags

> Scanned sections 1-4.

- [ ] Auth / identity · [ ] Secrets / config · [ ] External integrations · [ ] Sensitive data · [ ] Destructive DB · [ ] Input / attack surface · [ ] Network / exposure

**`security_required`:** `false`

Both changes are read-only presentation: filtering an existing modal's rows and widening an existing log-line cap. No input surface, no external/secret/network path. The log line keeps `markup=False` (the existing injection scrub) — widening the cap does not reintroduce a markup sink. Engine-frozen `color_policy.py` is read-only. No pattern fires.

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | A |
| Started | 2026-07-23 |
| Closed | - |
| Promoted to /dev-flow | no |
| Notes | Two increments: Inc-1 N1 legend filter; Inc-2 N2 width-aware log cap. Base `5ec46b3`. |

---

## 8. Close (filled in phase C)

### What changed
**N1:** `LegendScreen` now takes an optional `sections` filter; `action_show_legend` passes the active screen's `LEGEND_TABLE` section(s) via a new `_SCREEN_LEGEND_SECTIONS` map (A2L→A2L, MAC→MAC, Issues→Issues, Map/Patch/Diff→Hex, Checks→Issues), tracked by a new `_active_screen_key` set in `action_show_screen`. Unmapped screens (Workspace/Flow/CRC-Designer) fall back to the full table. **N2:** `_append_log_line` caps to `max(50, self.size.width)` instead of a fixed 50, so long paths use the full viewport span.

### Honest scoping note
N2's truncation was a **code cap** (`trimmed[:50]`), NOT a CSS width as the backlog guessed — `styles.tcss` needed no change (the `#workspace_status_bar` Labels already span full width).

### How it was tested
`tests/test_legend_scope_and_logwidth.py` (5): N1 per-screen scope (a2l/mac/issues/map → exactly their section), N1 unmapped→full table, N1 rows keep frozen `sev-*` classes; N2 long path untruncated at 200-wide, N2 bounded at 80-wide. RED-verified (both fixes disabled → legend shows all four, path clips at 50). `test_tui_legend.py` (14) regression green.

### Open risks / pending
- The `_SCREEN_LEGEND_SECTIONS` map is a curated best-fit; if a screen's painted classes change, the map needs updating (a stale entry would mislead). Low risk — the 4 sections are stable.
- `Checks` → `Issues` is a judgement call (checks render pass/fail severity); revisit if checks grow their own palette.

### Security flags — handling
None fired (`security_required: false`). The log line keeps `markup=False`; a wider cap adds no markup sink. Frozen `color_policy` read-only.

### Suggested commit message
```
feat(tui): scope Legend to the active screen + width-aware log lines (N1, N2)
```
