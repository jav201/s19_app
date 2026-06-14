# Increment I2 — Comparison service + artifact-usage notes (HLR-002 / HLR-003)

Batch: 2026-06-11-batch-09 · Phase 3 · branch `claude/batch-09`
Scope: HLR-002 / LLR-002.1..002.6 (TC-007..TC-011) + HLR-003 / LLR-003.1..003.4 (TC-012..TC-015)
Status: **IMPLEMENTED — service + tests all green; lean suite 0 failures; no spec/code contradiction.**

---

## 1. What changed

Added the headless comparison **service** `s19_app/tui/services/compare_service.py` — the
seam that sits between the I1 engine and the I3 report / I4 TUI. It resolves the two
comparison sources (in-project variant by id via `ProjectVariantSet`, and/or external
file via the injected `resolve_input_path`), parses each image **fresh** through the
existing `load_service` loaders (never the TUI snapshot), calls the I1 engine
`diff_mem_maps(...)` to produce `runs`/`stats`, computes per-image artifact-usage notes
against the shared A2L tag / MAC record addresses using the `range_index` coverage≥1
primitive, and assembles the §6.2 C-9 `ComparisonResult`. Every per-source failure
(unresolvable path, unknown variant, parse exception) is captured as a diagnostic on a
refused result — the service never raises (LLR-002.3 / LLR-002.5, the
`variant_execution_service` LLR-006.4 isolation precedent). The module imports no Textual
symbol (LLR-002.1). The engine, the external-path resolver, and the two loaders are all
injectable for testability; defaults are the production functions.

New public vocabulary owned by the service (the C-9 `notes` field shape, HLR-003):
`ImageSource` (one requested source), `ArtifactNote` (per-artifact status + covered/total),
`ArtifactUsage` (per-image: a2l note + mac note + summary token). `ComparisonResult.notes`
holds `{"image_a": ArtifactUsage, "image_b": ArtifactUsage}`.

Added `tests/test_compare_service.py` — 12 tests covering TC-007..TC-015, each mapped to
its TC/LLR in the module docstring.

`s19_app/compare.py` was **not** touched (consumed read-only, as instructed). No I3/I4
file was touched.

## 2. Files modified

| File | Purpose |
|---|---|
| `s19_app/tui/services/compare_service.py` (NEW, 593 lines) | Headless comparison service: source resolution, fresh parse, engine call, artifact-usage notes, C-9 assembly, refusal isolation. |
| `tests/test_compare_service.py` (NEW, 450 lines) | TC-007..TC-015 — source resolution, mixed pairings, parse-failure isolation, C-9 field-set identity, coverage, all-four usage summaries, absent artifacts. |

(2 files — within the 2-file target.)

## 3. How to test

```
python -m pytest -q tests/test_compare_service.py     # this increment
python -m pytest -q tests/test_compare_engine.py      # I1 regression
python -m pytest -q -m "not slow"                     # lean suite
python -m pytest -q --collect-only                    # ledger
rg -n "^\s*(from|import)\s+textual" s19_app/tui/services/compare_service.py   # purity probe
```

## 4. Test results (actual)

1. `pytest -q tests/test_compare_service.py` → **12 passed in 0.51s**. 0 failures.
2. `pytest -q tests/test_compare_engine.py` → **11 passed in 1.20s**. I1 regression intact.
3. `pytest -q -m "not slow"` → **703 passed, 29 skipped, 21 deselected, 3 xfailed in 204.70s**. 0 failures.
4. `pytest -q --collect-only` last line → **756 tests collected in 0.60s**.
5. No-textual probe over `compare_service.py` → **0 hits** (rg exit 1). In-regime (`tui/services/` module). Positive control: `report_service.py` → 0 hits (in-regime pre-state precedent, matches spec P-11); `screens_directionb.py` → hits at `:47-49` (`from textual.app...`). Probe regime discharged.

### Ledger reconciliation (signed balance)
Pre-state (orchestrator): **744 collected**. This increment adds **A = 12** new test functions,
**D = 0** deletions. `744 − 0 + 12 = 756` = measured collect-only. ✔
(Note: the §5.3 spec baseline is the MEASURED 733 at draft, probe P-01; the running ledger
carried 744 into this increment after I1's +11. I2 takes it to 756.)

### Per-TC status (all on disk, confirmed via `--collect-only`)
| TC | LLR | Node id(s) | Status |
|---|---|---|---|
| TC-007 | LLR-002.1 (mirror) | `test_module_imports_no_textual` | PASS |
| TC-007 | LLR-002.2 | `test_variant_pair_matches_engine`, `test_variant_pair_reports_real_diff` | PASS |
| TC-008 | LLR-002.3 | `test_external_unresolvable_returns_refused`, `test_external_resolved_pair` | PASS |
| TC-009 | LLR-002.4 | `test_mixed_source_pairings_record_identity` | PASS |
| TC-010 | LLR-002.5 | `test_parse_failure_isolated_to_refused` | PASS |
| TC-011 | LLR-002.6 | `test_result_field_set_matches_c9_contract` | PASS |
| TC-012 | LLR-003.1 | `test_artifact_context_applies_to_external` | PASS |
| TC-013 | LLR-003.2 | `test_coverage_counts_match_hand_computed` | PASS |
| TC-014 | LLR-003.3 | `test_usage_summary_all_four_outcomes` (all 4 summary outcomes asserted) | PASS |
| TC-015 | LLR-003.4 | `test_absent_artifacts_summary_none` | PASS |

### A-3 reconciliation (provisional spec name → actual node id)
The spec gave provisional `-k` selectors, not function names. Actual functions created:

| Spec provisional `-k` | LLR | Actual node id(s) |
|---|---|---|
| `-k variant` | LLR-002.2 | `test_variant_pair_matches_engine`, `test_variant_pair_reports_real_diff` |
| `-k external` | LLR-002.3 | `test_external_unresolvable_returns_refused`, `test_external_resolved_pair` |
| `-k mixed` | LLR-002.4 | `test_mixed_source_pairings_record_identity` |
| `-k parse_failure` | LLR-002.5 | `test_parse_failure_isolated_to_refused` |
| `-k contract` | LLR-002.6 | `test_result_field_set_matches_c9_contract` |
| `-k artifact_context` | LLR-003.1 | `test_artifact_context_applies_to_external` |
| `-k coverage` | LLR-003.2 | `test_coverage_counts_match_hand_computed` |
| `-k usage_summary` | LLR-003.3 | `test_usage_summary_all_four_outcomes` |
| `-k absent` | LLR-003.4 | `test_absent_artifacts_summary_none` |
| (none — LLR-002.1 mirror) | LLR-002.1 | `test_module_imports_no_textual` |

**Drift notes (loud):**
- The spec's `-k variant` / `-k external` selectors would now match MORE than one function each (I added a success-path companion to each refusal test for honest coverage). Phase 4 should re-key against the table above, not the provisional `-k` strings.
- `-k contract` would NOT match `test_result_field_set_matches_c9_contract`? It does (`contract` is a substring). `-k external` would also match `test_artifact_context_applies_to_external` (substring `external`) and `test_external_*` — a known `-k` collision; the canonical mapping is the table above, not `-k`.
- LLR-002.1 is principally the rg inspection probe (verification #5); the pytest mirror (`test_module_imports_no_textual`) is an AST import-scan so the property cannot silently rot. It deliberately ignores the word "textual" appearing in docstring prose (initial naive source-text scan failed for that reason and was corrected to an AST scan).

## 5. Risks
- **Symbol annotation / TUI not yet wired:** `notes` carries `ArtifactUsage` objects; the I3 report and I4 TUI must read `result.notes["image_a"].summary` / `.a2l.covered` etc. The C-9 `notes` cell in §6.2 says "per-artifact status + covered/total; summary token" — this shape satisfies it. No C-9 field added/removed (field-set identity asserted by TC-011), so the contract-touch surface is closed for this increment.
- **`resolve_input_path` returns existing-only paths** (None for non-existent). Correct for the read side (LLR-002.3). The I3 no-project **write** destination is a separate resolver (LLR-004.6) — not in this increment's scope; not reused here.
- **External file_type inference** is by suffix (`.hex`/`.ihex` → hex, else s19). This mirrors how the codebase classifies externals; an exotic-suffix HEX file would be mis-typed, but that is the existing project convention, not a regression introduced here.
- **A2L enrichment cost:** `_a2l_addresses` calls `enrich_tags_and_render` once per image (twice per comparison). For large A2Ls this is the dominant cost in the notes path; acceptable (the variant-execution layer already enriches per variant). Not in the slow regime for this increment's tests.

## 6. Pending items (deferred to later increments — dependency-order respected)
- **I3** — `diff_report_service.py` + `tests/test_diff_report.py` (LLR-004.1..004.6): Markdown diff report, own `DIFF_REPORT_FILENAME_REGEX` + `list_diff_reports`, no-project destination resolver/validator. Will consume `ComparisonResult` (and `notes`) from this service.
- **I4** — `screens_directionb.py` (AbDiffPanel real content + inline selection, G-6) + `app.py` wiring + `tests/test_tui_diff_screen.py` (LLR-005.x). Will call `compare_images` (LLR-005.1 service-only routing) and the I3 report generator. The R-8 placeholder-pinned-test supersession happens here.
- **I5** — `REQUIREMENTS.md` R-* update + batch close artifacts.

No assigned LLR for I2 was found to depend on an I3/I4-only symbol — no dependency-order stop was triggered.

## 7. Suggested next task
**I3:** Implement `s19_app/tui/services/diff_report_service.py` + `tests/test_diff_report.py`
(LLR-004.1..004.6). Start by re-reading the batch-07 `report_service.py` conventions
(`REPORTS_DIR_NAME` :110, `REPORT_TIMESTAMP_FORMAT` :103, `_report_filename` :355,
`REPORT_MAX_TOTAL_BYTES` :79, `compute_hexdump_windows` :232) and `render_hex_view`
(`hexview.py:294`), then build the OWN filename/listing scheme (G-4, no `report_service.py`
edit) and the no-project destination validator (G-8 solo-prompt). `report_service.py` stays
unedited; `tests/test_report_service.py` runs read-only as the NON-edit regression guard (P-09).
```
