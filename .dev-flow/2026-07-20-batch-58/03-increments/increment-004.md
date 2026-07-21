# Increment 004 — CRC Designer view scaffold + rail wiring + form/preset (LLR-V1.1/V1.2)

**Gate: APPROVED (self, autonomous)** · code-reviewer: OK-to-advance (0 HIGH, 1 MED F1 + 1 LOW F2) → **F1+F2 FIXED** · 2026-07-21

## 1. What changed
10th rail screen `#screen_crc_designer` (key `0`, glyph `⊕`/`R`), data-driven `action_show_screen` UNCHANGED. New `s19_app/tui/crc_designer_view.py::CrcDesignerPanel` — preset selector + 7 algorithm fields + 3 serialization fields, seeded CRC-32/ISO-HDLC; preset selection populates from `PRESETS` read-only. LLR-V1.1/.2, AT-058-02.

## 2. Files (frozen census: 0 frozen diffs — static `git diff --name-only 1e3125b HEAD`)
- `s19_app/tui/crc_designer_view.py` (NEW, 267 L) · `s19_app/tui/rail.py` (10th RailEntry + nine→ten sweep) · `s19_app/tui/app.py` (Binding key `0`, SCREEN_CONTAINER_IDS, `_compose_screen_crc_designer`, mount) · `tests/test_crc_designer_view.py` (NEW, 2 pilot ATs) · `tests/test_tui_directionb.py` (rail census). 5 files ≤ cap.
- Commits: `05682e6` (scaffold, durability) + census fix (this gate).

## 3. Test results
- RED (C-16 real nav): key `0` press → `#screen_crc_designer`/`#crc_preset_select` absent (NoMatches) before scaffold.
- GREEN: `test_crc_designer_view.py 2 passed` (routing + non-default MODBUS preset delta, PRESETS object+value unmutated, C-31 derive `len(PRESETS)>=7`).
- code-reviewer independent: `test_tui_directionb.py -k "not tc031"` 171 passed; static frozen-set clean.

## 4. code-reviewer findings + resolution
- **F1 (MED) — FIXED:** reverse census incomplete — `SCREEN_KEYS`/`SCREEN_IDS` still 9 (EXPECTED_RAIL was updated but siblings missed), ~10 consumer loops incl. `tc029` under-covered the 10th screen; no `len` guard. Fixed: extended both to 10 (+`crc_designer`/`screen_crc_designer`), refreshed "9→10" comments, added an **import-time consistency guard** `assert len(SCREEN_IDS)==len(SCREEN_KEYS)==len(RAIL_ENTRIES)` (trips loudly on future rail drift — C-28).
- **F2 (LOW) — FIXED:** `tc029` mapped position→key via `str(index)` → key `0` (10th) unrepresentable. Fixed: `RAIL_KEYS_IN_ORDER="1234567890"`, iterate `zip(RAIL_KEYS_IN_ORDER, SCREEN_KEYS)`; tc029 passes (1 passed) proving key `0` activates the 10th screen.

## 5. Snapshot drift (C-22/C-28) — NOT regenerated locally
19 baselines drift (rail column, 120x30 + 160x40: workspace/a2l/mac/issues ×{compact,comfortable} + map/patch/diff comfortable-120x30); 10 unchanged (80x24, rail collapses to icon strip). `show=False` binding → no footer chrome drift. **Recorded for the canonical-CI snapshot-regen closeout PR** (local `--snapshot-update` FORBIDDEN).

## 6. Risks / carries
- Snapshot baselines red until the canonical-CI regen PR (expected, listed).
- Markup-safety forward-note (reviewer): when Load/Save lands (Inc-6), preset/template names loaded from JSON become the injection surface — enforce markup=False there (already in LLR-V5.3 + AT-058-06).
- C-23 low: 80x24 rail glyph visibility — verify at regen; key `0` routing works regardless.

## 7. Suggested next
Inc-5 — live KAT verdict (centerpiece, AT-CRC-DSN-016 before/after single-event) + compute-boundary fault guard + custom test vector + `#crc_json_preview` round-trip (LLR-V2.1/.2, V3.1, V4.1; AT-CRC-DSN-016/011, AT-058-03/04).

## Environment note (recorded)
Mid-Inc-4 the shared primary checkout was stranded on `main` by a `tc031` frozen-guard subprocess (`git checkout main`, tool-timeout before restore). Recovered onto the feature branch (work intact). Mitigation: commit per-increment for durability; reviewers verify frozen-set statically (no checkout); re-check branch after each sub-agent.
