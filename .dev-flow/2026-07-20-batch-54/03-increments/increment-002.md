# Increment 002 — Multi-line A2L header parser (US-ML1 / US-ML2 / SAFE)

**BLUF:** The A2L parser now assembles CHARACTERISTIC mandatory headers + AXIS_DESCR bodies that span multiple lines with inline comments. Demo went **0-genuine → 50/50** CHARACTERISTICs with `char_type` + non-None address; single-line path preserved (subset); array `length` stays `None` (batch-55). Independent code-review: **APPROVE, 0 HIGH/MEDIUM**. All gate-blocking ATs green.

## 1. What changed (`s19_app/tui/a2l.py` + facade)
- `_strip_a2l_comments(text)` — linear quote-state machine; `/* */` (spanning) + `//` (→ next newline sentinel only, arch-M2); `/`,`*` inside quotes literal; unterminated `/*`/`"` consume-to-end, never raise.
- `_flatten_body_tokens(lines)` — join-first (`\n` sentinel) → strip → `_split_line_respecting_quotes`.
- `_characteristic_from_tokens(tokens)` — first `CHARACTERISTIC_KINDS` anchor → 7 positional params; fail-closed `None`; shipped dict keys (`address_inline`/`lower_limit`/`upper_limit`/`datatype`).
- `parse_characteristic_header(line)` → delegating shim (back-compat); new public `assemble_characteristic_header(lines)` wired at the CHARACTERISTIC extract branch (MEASUREMENT branch untouched).
- AXIS_DESCR `axis_meta` gains `max_axis_points` (token[3], str) + `external` (`AXIS_PTS_REF` present); `name`/`header_tokens` kept.

## 2. Files (4)
`s19_app/tui/a2l.py` (+249), `s19_app/tui/a2l_parse.py` (+2 re-export), `tests/test_a2l_multiline_headers.py` (NEW, 31 tests), `tests/test_a2l_f841_cleanup.py` (C-26 census reconcile: stale docstring fixed, `deposit` pin added).

## 3. How to test
`ruff check` the 4 files; `pytest -q tests/test_a2l_multiline_headers.py tests/test_a2l_f841_cleanup.py tests/test_a2l_record_layout_length.py tests/test_a2l_missing_length_fix.py tests/test_a2l_enriched.py tests/test_tui_a2l.py`; `pytest -k "tc031 or tc032 or tc027"`.

## 4. Test results (real)
- ruff (4 files): **All checks passed!**
- new file: **30 passed** (incl. `@slow` 2 MB DoS case under bound).
- targeted A2L suite: **69 passed / 2 pre-existing skips**.
- frozen guards: **11 passed**.
- **C-34 full guard-host** `test_tui_directionb.py` + `test_engine_unchanged.py`: **175 passed** (exit 0) — no escape.
- Oracle spot-check via `parse_a2l_file`: 50/50 char_type, 50/50 address-not-None (5 addr==0), STD `CURVE`/`0x810300`/`RL.CURVE.SWORD.SBYTE.DECR`, COM deposit `RL.FNC.SWORD.ROW_DIR`, axis STD 8/False · COM external True · FIX 6/False; STD+MAP length None; MEAS 25/25 datatype/24 length.
- Counterfactual: AT-096/097 RED on pre-fix (demo 0-genuine/50) — measured in Phase-1.

## 5. Independent review
`code-reviewer` → **APPROVE, 0 HIGH/MEDIUM.** Verified stripper (//-newline-only, linear O(n), quote-state, unterminated-safe, escape-parity), kind-anchor fail-closed + correct shipped keys, no MEASUREMENT/single-line regression, oracles vs disk, tests discriminating (32/32). 2 LOW (both intentional): escape-parity by design; `max_axis_points` is str (pinned by AT-100; note for batch-55 to cast).

## 6. Risks
Intended demo behavior change (NUMBER_42 length 42; VIRTUAL.ASCII deposit now resolves) — not snapshot-pinned; C-26 census re-verified. Snapshot suite (`test_tc016s`) NOT run locally (canonical-CI only) → verify 0 drift at Phase-4/CI (Phase-1 R3: synthetic no-kind chars stay None → expected 0 drift). Line-scan comment fragility = known limitation, out of scope.

## 7. Pending / next
Phase 4 orchestrator-owned gate suite (C-25) → PR-A → CI → self-merge → re-freeze PR-B. batch-55 = length summer (consumes the new axis fields).
Gate axis: Coverage (both chains green) / Certainty (through-surface ATs, counterfactuals, hostile+DoS+scope-guard) / Evidence (all cited, oracles disk-verified) — none unmet → **APPROVE** (autonomous).
