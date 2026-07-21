# Increment 005 — live KAT verdict + fault guard + custom vector + JSON preview (LLR-V2.1/V2.2/V3.1/V4.1)

**Gate: APPROVED (self, autonomous)** · code-reviewer: OK-to-advance (0 HIGH/MED, 2 LOW) · commit `4e66c3a` · 2026-07-21

## 1. What changed
`CrcDesignerPanel` recompute-on-change (no Run button), all off real Textual change events via one `_recompute()`:
- `#crc_kat_verdict` tri-state MATCH/MISMATCH/NO-EXPECTED (`CrcAlgorithm.kat_ok`) — LLR-V2.1.
- compute-boundary fault guard: width∉[8,64] (crc_stream/crc_lut ValueError) → markup-safe warning, no crash; per-surface guarded — LLR-V2.2.
- `#crc_custom_vector` (+ ascii/hex mode) CRC under current algorithm — LLR-V3.1.
- `#crc_json_preview` live `emit_template` that round-trips via `parse_template`, markup=False — LLR-V4.1.

## 2. Files (frozen census: 0 frozen diffs, static)
- `s19_app/tui/crc_designer_view.py` (+widgets/handlers) · `tests/test_crc_designer_view.py` (+5 tests). 2 files. Commit `4e66c3a`.

## 3–4. Tests
- RED (view stashed to Inc-4 scaffold): `5 failed` NoMatches `#crc_kat_verdict` absent.
- GREEN: `test_crc_designer_view.py 7 passed`; CRC regression `84 passed`; ruff clean.
- **AT-CRC-DSN-016:** before/after two single `Input.Changed` events — `MATCH→MISMATCH` (break xorout), `MISMATCH→NO-EXPECTED` (clear check), before≠after. **code-reviewer empirically proved RED if the handler wiring is removed** (`_verdict()` reads cached `.content`, doesn't recompute-on-read).
- **AT-058-04:** reads mounted `#crc_json_preview` content, `parse_template(that)==CrcTemplate(...)`, no emit_template in test.
- **AT-CRC-DSN-011 (C-31):** preset set from `crc_kernel.PRESETS` (`len>=7`) → each MATCH.
- **AT-058-03:** custom vector ascii `123456789` == kat; hex form too.
- Fault guard: width `4` → "Cannot compute…" painted, app alive, markup off.

## 5. code-reviewer findings (both LOW, non-blocking carries)
- **F1 (LOW):** preset select drives ~9 recomputes (fan-out); wasteful not incorrect (Static.update posts no events; queued messages → final field set read; trailing recompute needed for endianness/mode selects). → postmortem perf note.
- **F2 (LOW):** `_current_algorithm` carries the preset `name` after params edited — harmless preview-only; becomes a conscious decision at Save. → Inc-6.

## 6. Risks / carries
Markup-safety structurally verified (all Statics markup=False; `_render_markup is False` asserted post-update). Full hostile-input AT + the injectable Load-derived `name` path land in Inc-6. F1/F2 carried.

## 7. Suggested next
Inc-6 — Load/Save (Save via emit_template→file with save-time KAT + bounded name normalization incl. sanitize→None; Load via crc_template.read_template) + hostile-input markup AT (incl. JSON preview sink) + 3 warn conditions (LLR-V5.1/.2/.3/.4; AT-058-05/10/06, AT-CRC-DSN-015).
