# Increment 006 — Load/Save + save-time KAT + markup-safety + warns (LLR-V5.1/V5.2/V5.3/V5.4)

**Gate: APPROVED (self, autonomous)** · code-reviewer OK (0 HIGH/MED, 1 LOW) + security-reviewer OK (0 HIGH/MED, 2 LOW) · commit `6659a43` · 2026-07-21

## 1. What changed
CRC template Load/Save on the panel:
- Save → `emit_template` to `<base>/.s19tool/templates/<sanitized>.crc.json` (new `workspace.WORKAREA_TEMPLATES` + `ensure_template_lib`, additive). `sanitize_project_name`→None (all-symbol/empty) → warn + write nothing. — LLR-V5.1/.2
- Load → `crc_template.read_template` facade (collect-don't-abort, one error, never crash). — LLR-V5.1
- Save-time KAT: `kat_ok()` (check==compute("123456789")) → warn-not-block. — LLR-V5.4
- Live `store_width < ceil(width/8)` truncation warn. (3rd warn fill-no-pad → Inc-7)
- markup=False over name/aliases/warnings/JSON-preview (load-derived injection sink). — LLR-V5.3

## 2. Files (frozen census: 0 frozen diffs, static)
- `s19_app/tui/crc_designer_view.py` · `s19_app/tui/workspace.py` (+33 additive) · `tests/test_crc_designer_view.py` (+6). Commit `6659a43`.

## 3–4. Tests
- RED (2 source files stashed): 6 new tests fail NoMatches `#crc_warnings`. GREEN: `test_crc_designer_view.py 13 passed`; engine 108; workspace 46; ruff clean.
- **AT-058-05 (B2):** real `#crc_save_btn` → `MyVariant.crc.json` lands → real `#crc_load_btn` → `restored == originals` (7 fields + 2 switches). Through-view, not headless.
- **AT-058-06 (C-17):** load `name=[bold]x[/]` + ANSI alias → painted preview `.content` literal `[bold]x[/]`, `_render_markup is False`, **`spans == []`**.
- **AT-CRC-DSN-015:** malformed file → one surfaced error, form unchanged, app alive.
- **None-name (sec F2):** `@@@` → warn "nothing written", `glob("*.crc.json")==[]`, no dir created.
- check-mismatch warn (writes+warns) + store_width warn (painted "truncated"). C-32 painted assertions.

## 5. Reviews + carries
- **code-reviewer:** OK, 6/6 checks pass, `test_tui_workspace.py` 34 passed (no regression). LOW F1: redundant `#crc_field_name` re-write in `_apply_template` (cosmetic). → carry.
- **security-reviewer:** OK to ship, all 5 gate points confirmed (posture reused verbatim; traversal-proof — fixed dir + whitelist sanitize strips `..`/separators; markup=False all sinks; preview-only, only write is bounded .crc.json; workspace additive). LOW: F1 silent overwrite of same-name template (bounded to user's local lib) → optional overwrite-note (Inc-7/backlog); F2 sanitize collision (pre-existing convention, accept). → carries.

## 6. Risks / carries (→ postmortem/BACKLOG)
- Inc-5 F1 (recompute fan-out), Inc-5 F2 (preset-name carry), Inc-6 code F1 (redundant name write), Inc-6 sec F1 (overwrite-note), Inc-6 sec F2 (sanitize collision — accept). None blocking.
- `store_endianness`/`output_address` are placement (job), not the placement-free `CrcTemplate` — Save→Load restores algorithm+name+aliases only (by design).

## 7. Suggested next
Inc-7 (final impl) — coverage strip (ranges + intra/join toggles + pad_byte) + fill-no-pad warn + **AT-058-10** (unified 3-warn) + per-policy preview **AT-058-07** (§3.2 oracles 0x9C5BCBBD/0x2A8A3950 through the widget) + gap-conflict **AT-058-08/AT-CRC-DSN-017** + preview-only guard **AT-058-09**. (LLR-V6.x/V7.1/V8.1)
