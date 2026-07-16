# Increment 10 — MEDIUM fixes from the final PR-QA (batch-47)

## 1. What changed
- **M-1 (legend label ↔ hue contradiction) — FIXED, and the investigation inverted the orchestrator's framing.** The Inc-10 dev probed the LIVE app instead of trusting comments: `WARNING → .sev-warning → Color(246,255,143)` (pale yellow) while `.mac_out_of_range → Color(217,163,91)` (orange). The legend's `"Orange"` rows describe **WARNING severity**, NOT the MAC out-of-image overlay (`.mac_out_of_range` paints only the Sections-list "MAC out-of-range @ 0x…" labels, `app.py:8553`). A second victim proved it: `LEGEND_TABLE["Issues"]["Warnings"]` also maps `"Orange"` → painted `css_class_for_severity(WARNING)` (`issues_view.py:178`), unambiguously not the MAC overlay. → the swatch is right, the **label** was stale → renamed `"Orange"` → **`"Pale yellow"`**.
  - `"Yellow"` (the obvious name) is **blocked by a real invariant**: `_colour_name_from_style("bold yellow")` = `"Yellow"` is the Hex **focus-highlight** row key; making it a `COLOUR_SEVERITY` key would paint that interaction highlight `sev-warning` — the exact bug `legend.py:44-51` documents and **TC-322** asserts against. `"Pale yellow"` is truthful and keeps TC-322 green.
- **M-4 (2 of 20 ATs ran at one size) — FIXED.** `AT-065a`/`AT-065b` now parametrize `_SIZES = ((80,24),(120,30))` (matching the other AT files). The "every AT at both pilot sizes" claim is now TRUE (20 ATs → 20 nodes × both sizes).
- **NEW AT-065c** — binds every `COLOUR_SEVERITY` label to the hue its severity class RESOLVES to, by **HSV family** (not exact hex, so the palette stays free to retune a shade). Closes the gap that let the stale label ship: AT-065b probes only `sev-error`.
- **Root cause escalated to the operator, not decided silently (§6.5 Amendment F).** The stale label was a SYMPTOM: REQUIREMENTS said *"MAC row colouring adds Orange for warning-level…"*, those rows are `.sev-warning`, and Inc-8 rebound it to yellow — so the documented cue was genuinely broken, and Amendment C's "the Orange cue survives via `.mac_out_of_range`" was FALSE. Operator decision (2026-07-16): **keep yellow + amend REQUIREMENTS**; Orange re-scoped to the MAC-specific cues (⚠ glyph · hex overlay · out-of-range labels).

## 2. Files modified
`s19_app/tui/legend.py` · `tests/test_tui_theme.py` (M-4 parametrize + AT-065c) · `tests/test_tui_legend.py` (2 key lookups + a stale-rationale comment corrected by the orchestrator) · `tests/test_report_service.py` (1 key lookup) · `tests/goldens/batch35/at055b-project-report.md` (2 legend lines). Orchestrator additionally: `s19_app/tui/styles.tcss` (a comment asserting the same falsehood), `REQUIREMENTS.md` (§ severity conventions + the Amendment F section), `.dev-flow/…/01-requirements.md` (Amendment C correction + Amendment F).

## 3. How to test
`pytest -q tests/test_tui_theme.py tests/test_tui_legend.py tests/test_report_service.py tests/test_tui_report_seam.py tests/test_tui_report_filter_surface.py` · `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031 or tc032 or engine or legend or tc033"` · `ruff check`

## 4. Test results
- **RED-first (AT-065c, pre-fix):** `AssertionError: AT-065c: legend colour label(s) contradict the hue the legend row actually renders: {'Orange': ('Color(246, 255, 143)', 'Yellow')}` → **1 failed, 20 passed**. The RED isolates EXACTLY one label; Red/Cyan/Green/Grey passed → the test is calibrated to the defect, not over-tight.
- theme + legend + report consumers **115 passed** · directionb `-k "legend or tc033"` **5 passed** · **C-27 dual-guard 7 passed, 0 frozen diff (both arms)** · snapshots **3 passed / 29 xfailed** (all already xfail'd by the theme marks — no new drift, no local regen) · ruff clean.

## 5. Risks
- **Report-golden drift (2 lines) is intentional and reviewed** — it is the POINT of the fix: the shipped report said "Orange" for a yellow class.
- `"Pale yellow"` is a naming call (deviates from the brief's "Yellow" for the TC-322 collision reason above).
- AT-065c's hue buckets are coarse by design — a within-family retune (yellow→amber) won't trip it. Deliberate: it tests the label's WORD, not the palette.

## 6. Pending items
None open. The §6.5 root-cause question the dev escalated is RESOLVED by operator decision → Amendment F, applied to `REQUIREMENTS.md` + `01-requirements.md` + the `styles.tcss` comment.

## 7. Suggested next task
Re-run the final PR-level QA over the whole diff (HIGH-1 fix in Inc-9 + these MEDIUMs); merge only on MERGE-CLEAR.

### Gate outcome (orchestrator, 2026-07-16)
Both M-1 and M-4 fixed; the deeper REQUIREMENTS breakage the dev surfaced was escalated (not averaged) and resolved by operator decision → **§6.5 Amendment F**. Amendment C's false survival-claim corrected in `01-requirements.md`, `REQUIREMENTS.md`, and the `styles.tcss` comment that asserted it. **Axis check:** Coverage OK (AT-065c closes the label↔hue gap; 20 ATs × both sizes now true); Certainty OK (AT-065c RED isolated exactly one label — calibrated, and a live-app probe, not a comment, settled the semantics); Evidence OK (115/5/7 passed, 0 frozen diff, golden drift intentional + reviewed). **APPROVE.**
