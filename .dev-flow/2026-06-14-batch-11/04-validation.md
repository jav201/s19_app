# Phase 4 — Validation Report — s19_app — Batch 2026-06-14-batch-11

**Feature:** US-010 — WRITE the project manifest (`project.json`) + verify-on-write (re-read → compare against intent), mirroring batch-10 verify-on-save for firmware images.

**Validator:** qa-reviewer (Phase-4). **Date:** 2026-06-15.
**Branch:** `claude/batch-11`. **Scope under validation:** §5 of `01-requirements.md` (4 HLR / 14 LLR).

**Environment**
- Python 3.14.4, pytest 9.0.3, pluggy 1.6.0, platform win32.
- Working tree = worktree `competent-clarke-1e8940`; code diff vs `origin/main` = `s19_app/tui/services/manifest_writer.py` (NEW), `s19_app/tui/app.py` (EDIT), 3 NEW test files, `REQUIREMENTS.md`, `.dev-flow/state.json`.

> **Orchestrator-owned rows (A-6):** the lean suite (786) and FULL suite (incl. `slow`) are run SEPARATELY by the orchestrator and are NOT executed here. Those rows below are PLACEHOLDERS — the final batch verdict excludes them, per the prompt.

---

## 1. Per-TC / per-LLR validation matrix

All node ids below are the IMPLEMENTED names read from the test files' docstrings (test→TC→LLR map) and run individually. Spec TC node ids were PROVISIONAL (V-5); the file paths the spec pinned (`tests/test_manifest_writer.py`, `tests/test_manifest_verify.py`) match the implementation, and `tests/test_tui_manifest_save.py` (I4) is the implemented name for the TUI surface — recorded as a V-5 doc-reconciliation, not a failure (see §4). The spec used `-k` selectors (`-k envelope_keys`, `-k roundtrip`, …); the implemented test FUNCTION names differ from those tokens (e.g. `test_envelope_keys_and_active_variant`, `test_roundtrip_equals_intent_in_canonical_form`) — recorded as V-5 selector reconciliation, not a failure.

| Req | TC | Implemented node id | Result | Runtime | LLR threshold MET? (evidence from source) |
|-----|----|--------------------|--------|---------|-------------------------------------------|
| HLR-001 / LLR-001.1 | TC-001a | `test_manifest_writer.py::test_envelope_keys_and_active_variant` | PASS | <0.005s | keys ⊇ {schema_version,active_variant,batch,assignments}; `active_variant=="b"`; `schema_version==1` — asserted L93-100 |
| LLR-001.1 (AC) | TC-001a | `test_manifest_writer.py::test_envelope_empty_project_active_variant_is_null` | PASS | <0.005s | `active_id is None` → `active_variant is None` (JSON null) — L115 |
| HLR-001 / LLR-001.2 | TC-001b | `test_manifest_writer.py::test_relative_paths_resolve_with_no_escape` | PASS | <0.005s | every entry: `_resolve_manifest_entry` non-None, `escape_count==0`, no `\` — L143-150 |
| LLR-001.2 (AC) | TC-001b | `test_manifest_writer.py::test_windows_backslashes_normalized_to_forward_slash` | PASS | <0.005s | `["sub\\nested\\doc.json"]` → `["sub/nested/doc.json"]` — L163 |
| HLR-001 / LLR-001.3 | TC-001c | `test_manifest_writer.py::test_roundtrip_equals_intent_in_canonical_form` | PASS | <0.005s | re-read `issues==[]`; `active_variant=="b"`; `batch`/`assignments` equal intent RESOLVED against project dir (C-1 canonical form) — L198-203 |
| LLR-001.3 (AC) | TC-001c | `test_manifest_writer.py::test_roundtrip_schema_version_survives` | PASS | <0.005s | `schema_version==1` survives round-trip — L217 |
| HLR-001 / LLR-001.4 | TC-001d | `test_manifest_writer.py::test_deterministic_byte_identical_output` | PASS | <0.005s | `first == second` byte-equal over same composition — L241 |
| HLR-001 / LLR-001.5 | TC-001e | `test_manifest_writer.py::test_refuse_escape_and_absolute_entries_writes_nothing` | PASS | <0.005s | `../../x`+absolute → `text is None`, `len(issues)>=1`, all `MANIFEST_WRITE_ESCAPE`, names each entry — L266-272 |
| LLR-001.5 (threshold) | TC-001e | `test_manifest_writer.py::test_clean_composition_passes_the_gate` | PASS | <0.005s | clean composition → `issues==[]`, serialization proceeds (no false positive) — L285-286 |
| LLR-001.5 (∩ HLR-002) | TC-001e | `test_manifest_writer.py::test_refusal_emits_no_file_when_caller_would_write` | PASS | <0.005s | refused serialize → `text is None`, no file written — L297-302 |
| HLR-002 / LLR-002.1 | TC-002a | `test_manifest_writer.py::test_write_places_manifest_and_reads_back` | PASS | <0.005s | `written == project_dir/PROJECT_MANIFEST_NAME`, re-reads as intent, issues==[] — L345-354 |
| HLR-002 / LLR-002.1 (M-1) | TC-002a | `test_manifest_writer.py::test_two_saves_leave_exactly_one_manifest_second_wins` | PASS | 0.01s | two saves → exactly ONE `project.json`, ZERO `project_1.json`, 2nd content wins — L378-384 |
| HLR-002 / LLR-002.2 | TC-002b | `test_manifest_writer.py::test_fixed_name_and_staged_temp_removed` | PASS | <0.005s | `written.name == PROJECT_MANIFEST_NAME`; staged temp file absent — L405-408 |
| HLR-002 / LLR-002.3 | TC-002c | `test_manifest_writer.py::test_destination_outside_workarea_returns_finding` | PASS | <0.005s | escaping root → `written is None`, ≥1 finding all `MANIFEST_WRITE_CONTAINMENT`, no file, no raise — L430-433 |
| LLR-002.3 (∩ 001.5) | TC-002c | `test_manifest_writer.py::test_refused_serialize_short_circuits_without_writing` | PASS | <0.005s | escaping entry → `written is None`, `MANIFEST_WRITE_ESCAPE` (not manufactured containment), no file — L448-451 |
| HLR-003 / LLR-003.1 | TC-003a | `test_manifest_verify.py::test_faithful_write_verifies` | PASS | <0.005s | faithful write → `status==MANIFEST_VERIFIED`, `drift==[]`, `issues==[]`, `written_path` canonical — L98-101 |
| HLR-003 / LLR-003.2 | TC-003b | `test_manifest_verify.py::test_tampered_active_variant_mismatches_naming_the_key` | PASS | <0.005s | tamper active_variant → `MANIFEST_MISMATCH`, `drift==["active_variant"]` (exactly 1), no false-verify — L132-134 |
| HLR-003 / LLR-003.3 | TC-003c | `test_manifest_verify.py::test_reader_issues_force_mismatch_even_if_surviving_keys_match` | PASS | <0.005s | reader degrades (`MANIFEST-PATH-ESCAPE`) with surviving keys equal → `MISMATCH`, `drift==[]`, `issues>=1` (R-1 guard) — L178-182 |
| HLR-003 / LLR-003.1 (M-1) | (canonical-path) | `test_manifest_verify.py::test_verify_reads_canonical_name_not_a_stray_suffixed_file` | PASS | <0.005s | stray `project_1.json` w/ different active_variant ignored; verify reads canonical name → VERIFIED — L224-226 |
| HLR-004 / LLR-004.1 + 004.2 (verified) | TC-004a / TC-D1 | `test_tui_manifest_save.py::test_project_save_writes_and_verifies_manifest` | PASS | 1.45s | save writes `project.json`; `active==active_id`; `issues==[]`; quiet "manifest verified" status; NO mismatch notice — L127-135 |
| HLR-004 / LLR-004.2 (mismatch) | TC-D1 | `test_tui_manifest_save.py::test_manifest_mismatch_surfaces_loud_notice_naming_drift` | PASS | 1.34s | tampered file → MISMATCH status + loud notice naming `active_variant` — L191-202 |
| HLR-004 / LLR-004.2 (refusal) | TC-D1 | `test_tui_manifest_save.py::test_manifest_write_refusal_surfaces_error_notice_no_crash` | PASS | 1.66s | `(None,issues)` → error notice w/ plain-text message, no crash, no `project.json` — L267-280 |
| HLR-004 / LLR-004.3 | TC-004b | `test_tui_manifest_save.py::test_manifest_writer_module_is_headless` | PASS | <0.005s | no `import/from textual`, no `import/from logging`, no `getLogger` (import-statement form, V-4) — L301-305 |

**Targeted matrix result: 23 / 23 PASS** (single combined run: `23 passed in 4.90s`). Every LLR numeric threshold is MET by ≥1 passing TC, verified against test source assertions.

### 1.1 LLR → TC coverage roll-up (§5.2)

| LLR | Method (spec) | Covered by | Verdict |
|-----|---------------|-----------|---------|
| LLR-001.1 | test (unit) | TC-001a (2 tests) | PASS |
| LLR-001.2 | test (unit) | TC-001b (2 tests) | PASS |
| LLR-001.3 | test (integration) | TC-001c (2 tests) | PASS |
| LLR-001.4 | test (unit) | TC-001d | PASS |
| LLR-001.5 | test (unit) | TC-001e (3 tests, incl. write-side short-circuit) | PASS |
| LLR-002.1 | test (integration) | TC-002a (2 tests, incl. M-1) | PASS |
| LLR-002.2 | test (unit) | TC-002b | PASS |
| LLR-002.3 | test (integration) | TC-002c (2 tests) | PASS |
| LLR-003.1 | test (integration) | TC-003a + canonical-path (M-1) | PASS |
| LLR-003.2 | test (integration) | TC-003b | PASS |
| LLR-003.3 | test (integration) | TC-003c | PASS |
| LLR-004.1 | inspection | TC-004a (+ source inspection §2) | PASS |
| LLR-004.2 | demo | TC-D1 (verified/mismatch/refusal, automated via pilot) | PASS |
| LLR-004.3 | test (integration) | TC-004b + V-4 probe (§2) | PASS |

100% of LLRs covered by ≥1 passing TC.

---

## 2. Inspections (command + output + regime — V-4 purity form)

### I-1 — Headless writer (LLR-004.3 / C-3)
- `rg -n "import textual|from textual" s19_app/tui/services/manifest_writer.py` → **0 matches** (import-statement form, V-4).
- `rg -n "getLogger|import logging|from logging" s19_app/tui/services/manifest_writer.py` → **0 matches**.
- Regime: service module at `s19_app/tui/services/` (same import-depth as headless `services/change_service.py`). Negative baseline confirmed by spec's V-4 probe ledger (`app.py` ≥1 textual; `validation_service.py` ≥1 logging).
- Static-import-graph guard: `test_checks_engine.py::test_no_textual_in_static_import_graph` → **PASS** (manifest_writer not reachable as a textual-importing node).
- **Verdict: MET.**

### I-2 — Atomic-replace / no-dedup (M-1)
- Two-saves-one-file test (`test_two_saves_leave_exactly_one_manifest_second_wins`) → **PASS**.
- `copy_into_workarea` LIVE calls in manifest_writer.py (AST walk) → **0** (all 6 `rg` hits are docstring/comment lines 13-15, 325-385 — confirmed via `ast` Name/Attribute call census).
- `os.replace` LIVE calls (AST) → **2** (the placement; line 463 is the destination replace). No copy-with-dedup body routed.
- **Verdict: MET — placement is atomic `os.replace` at the fixed name, never `copy_into_workarea`'s dedup body.**

### I-3 — M-1 canonical-name re-read (LLR-003.1)
- `verify_written_manifest` re-reads via `read_project_manifest(project_dir)` (canonical `project_dir / PROJECT_MANIFEST_NAME`, manifest_writer.py:647-649), NOT the path the writer returns.
- Proven by `test_verify_reads_canonical_name_not_a_stray_suffixed_file` → **PASS** (stray `project_1.json` with a different `active_variant` ignored; verify returns VERIFIED).
- **Verdict: MET.**

### I-4 — R-1 reader-issues ⇒ mismatch (LLR-003.3)
- Source: `status = MANIFEST_VERIFIED if not drift and not manifest.issues else MANIFEST_MISMATCH` (manifest_writer.py:673-677) — any non-empty re-read `issues` forces MISMATCH regardless of key equality.
- Proven by `test_reader_issues_force_mismatch_even_if_surviving_keys_match` → **PASS** (`drift==[]` yet status MISMATCH because reader appended `MANIFEST-PATH-ESCAPE`).
- **Verdict: MET — closes the R-1 false-verify hole.**

### I-5 — LLR-001.5 escape-refusal
- Source: `_reject_unsafe_entry` (manifest_writer.py:178-221) delegates to the reader's `_resolve_manifest_entry` predicate (no second path-safety impl); `serialize_manifest` returns `(None, [finding])` and emits no text on any unsafe entry.
- Proven by `test_refuse_escape_and_absolute_entries_writes_nothing` → **PASS** (`../../x` + absolute → `(None, [finding])`, no file; findings name each offending entry).
- **Verdict: MET.**

### I-6 — app.py orchestration-only (LLR-004.1)
- `rg -n "serialize_manifest|os.replace" s19_app/tui/app.py` → **0** manifest-logic matches.
- `rg -n "json\.dump" s19_app/tui/app.py` → 2 hits (app.py:678 log-handle write; app.py:2744 A2L data dump). Both are **pre-existing / unrelated** — `git diff origin/main -- s19_app/tui/app.py | grep json.dumps` → **no `json.dumps` added/removed vs origin/main**. Confirmed not manifest logic.
- `rg -n "write_project_manifest|verify_written_manifest" s19_app/tui/app.py` → **≥1** (imports L92-93; live calls L3578, L3592). The save handler `_persist_project_manifest` calls both and binds `result`, then routes to `_surface_manifest_verify_result` (L3593). Pre-existing file-copy save behavior unchanged.
- **Verdict: MET — manifest serialize/write/replace logic lives in the service; app.py orchestrates only.**

### I-7 — Change-first census revalidate (A-1 / A-2)
- `_ENGINE_PATHS` resolved set = {`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`} (`test_engine_unchanged.py:120-127`) + `color_policy.py` in the directionb guard. Both edited files (`tui/services/manifest_writer.py`, `tui/app.py`) ∉ frozen set.
- Engine-frozen guards run: `test_tc027_engine_modules_unchanged_vs_main` + `test_tc031_engine_modules_have_no_diff_vs_main` → **2 passed**.
- Package-root / processing-module guards run: `test_tc028_no_new_processing_module_added_outside_view_layer` (+ `_inc10`) → **2 passed** (new file under `tui/services/`, not a `s19_app/` root module).
- Rail untouched: code diff vs origin/main = only `manifest_writer.py` + `app.py` (no compare/diff-rail files).
- **Verdict: MET — both edited files clear the engine-frozen + package-root + AST guards.**

### I-8 — B-1 canonical comparison form
- `verify_written_manifest` resolves intended entries via `_resolve_intended_entries(project_root, ...)` before comparison (manifest_writer.py:658-671); compares reader-resolved `Path`s against intent-resolved `Path`s (not relative strings vs `Path`).
- Round-trip + verify tests assert the resolved form: `manifest.batch == [(project_dir / e).resolve() for e in intended_batch]` (writer L200; verify L353) — the `test_variant_execution.py:163` idiom.
- **Verdict: MET — equality asserted in the C-1 canonical comparison form on both sides.**

---

## 3. Signed-balance reconciliation (§5.3.1)

- `python -m pytest -q --collect-only` last line = **`839 tests collected in 0.54s`**.
- Re-measured base (spec §5.3.1, executed 2026-06-14) = **816**.
- Deletions (D) = **0** (no test removed; all 3 new files absent on `origin/main` — `git show origin/main:tests/test_manifest_writer.py` → absent).
- Additions (A) = **23** (the 3 new files collect exactly 23 nodes; combined `--collect-only` → `23 tests collected`).
- **Signed balance: `839 = 816 − 0 + 23`. ✅ Reconciled.**

**Named additions (23):**
| File (increment) | Nodes | TCs |
|------------------|-------|-----|
| `test_manifest_writer.py` — I1 | 10 | TC-001a (×2), TC-001b (×2), TC-001c (×2), TC-001d (×1), TC-001e (×3) |
| `test_manifest_writer.py` — I2 | 5 | TC-002a (×2), TC-002b (×1), TC-002c (×2) |
| `test_manifest_verify.py` — I3 | 4 | TC-003a, TC-003b, TC-003c, canonical-path (M-1) |
| `test_tui_manifest_save.py` — I4 | 4 | TC-004a/TC-D1 verified, TC-D1 mismatch, TC-D1 refusal, TC-004b headless |

Matches the prompt's expected I1+10 / I2+5 / I3+4 / I4+4 = 23. **Deviation vs §5.3.1 prediction:** the spec predicted A ≈ 13–17 (post-collection 829–833); actual A = 23 (post 839), +6 over the upper bound. Recorded in §4 (DEV-2) — over-coverage, not a shortfall; each TC was implemented with multiple AC-level assertion tests.

---

## 4. Deviations & gaps register

| ID | Type | Description | Disposition |
|----|------|-------------|-------------|
| DEV-1 | V-5 provisional reconciliation | Spec test FILE for I4 was provisional; implemented as `tests/test_tui_manifest_save.py`. I1/I2 in `test_manifest_writer.py` and I3 in `test_manifest_verify.py` match the provisional paths. All spec `-k` selectors (`envelope_keys`, `roundtrip`, `staged_place`, `verified`, `mismatch`, `reader_issue`, …) renamed to descriptive function names. EXPECTED under V-5 (provisional-identifier scope rule) — **not a failure**; Phase-6 doc-reconciliation chore. | Reconcile spec node ids/`-k` in Phase-6 docs. |
| DEV-2 | Baseline-chain / over-coverage | Actual additions = 23 vs §5.3.1 predicted 13–17 (+6). Driven by multiple AC-level tests per TC. Net coverage strictly higher than planned. | Update §5.3.1 final count to 23 in Phase-6. No defect. |
| SCOPE-1 | Scope boundary (not a failure) | The I4 TUI save handler (`_persist_project_manifest`, app.py:3575-3593) calls `write_project_manifest(variant_set, project_dir, self.base_dir)` with **no `batch=` / `assignments=` kwargs** — they default to empty. So a TUI save persists `active_variant` + EMPTY `batch`/`assignments`, because the current save flow composes no batch/assignments. The WRITER fully supports + tests `batch`/`assignments` (TC-001a..003c pass explicit kwargs). HLR-004's LLRs (004.1/004.2/004.3) did NOT pin save-flow composition of batch/assignments — they pin "invoke the pipeline + surface the outcome", which the handler does. **Spec-conformant boundary.** Assessment: US-010's benefit ("variant/A2L/MAC composition AND active-variant selection can be created/updated from the tool") is met at the **active-variant level** today; the batch/assignments composition path is built + tested in the writer but not yet wired from the save UI. | Record for Phase-5 post-mortem + batch-12: decide whether the save flow should compose batch/assignments from the loaded project state to fully realize US-010's composition benefit. Not a Phase-4 failure. |

No defects found. All deviations are doc-reconciliation (V-5), over-coverage, or a spec-conformant scope boundary.

---

## 5. §5.3 batch acceptance criteria — verdicts

| # | Criterion | Verdict | Evidence |
|---|-----------|---------|----------|
| 1 | 100% of LLRs covered by ≥1 TC with a pass result | **PASS** | §1.1 — 14/14 LLR covered, all passing |
| 2 | Round-trip fidelity: every serialize→read case → `issues==[]` and field equality 100% | **PASS** | TC-001c, TC-002a, TC-003a all assert `issues==[]` + C-1 equality |
| 3 | 0 uncaught exceptions on rejected write targets; ≥1 finding per rejection | **PASS** | TC-002c + TC-001e: `(None,[finding])`, no raise |
| 4 | 0 false-verified outcomes on tampered manifests | **PASS** | TC-003b (tamper→MISMATCH), TC-003c (reader-issue→MISMATCH), canonical-path (stray ignored) |
| 5 | 0 `textual` imports in new headless modules (V-4 probe) | **PASS** | I-1: 0 textual + 0 logging; TC-004b PASS |
| 6 | 0 modifications to any engine-frozen file (`test_tc027_*`, `test_tc031_*` green) | **PASS** | I-7: both engine guards pass; edited files ∉ frozen set |
| 7 | No new module at `s19_app/` package root (root-module guards green) | **PASS** | I-7: `test_tc028_*` (+`_inc10`) pass; new file under `tui/services/` |
| — | Lean suite (`pytest -q -m "not slow"`) | **PASS** (orchestrator) | I4 close: **786 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed** (2026-06-15) |
| — | FULL suite incl. `slow` (`pytest -q`) | **PASS** (orchestrator) | **807 passed, 29 skipped, 3 xfailed, 0 failed** in 651.46s (2026-06-15, exit 0). Reconciliation EXACT: 807+29+3 = 839 collected; 786 lean + 21 slow = 807 |

All 7 owned acceptance criteria PASS.

---

## 6. Final verdict

**PASS-WITH-NOTES** — now INCLUDING the orchestrator-owned rows (lean 786/0, full 807/0, reconciliation 839 exact). All §5.3 criteria PASS.

**Orchestrator gate disposition (2026-06-15, autonomous mode):** Phase 4 APPROVED — PASS-WITH-NOTES, 0 code/behavior defects. DEV-1 (V-5 renames) + DEV-2 (§5.3.1 predicted-band → actual 23) routed to Phase 6 doc reconciliation; SCOPE-1 (active-variant-only TUI save; writer fully supports batch/assignments but the save flow composes none) routed to Phase 5 post-mortem + the batch-12 slate. Advancing to Phase 5.

- 23/23 targeted TC nodes PASS; every LLR numeric threshold MET from source.
- All 8 inspections (headless, atomic-no-dedup M-1, canonical-name re-read, R-1 mismatch, escape-refusal, app orchestration-only, change-first census, B-1 canonical form) MET.
- Signed balance reconciled exactly: 839 = 816 − 0 + 23.
- All 7 owned §5.3 acceptance criteria PASS.
- **Notes (not failures):** V-5 node/selector renames (DEV-1), +6 over-coverage vs the predicted addition band (DEV-2), and the active-variant-only TUI save scope boundary (SCOPE-1) — the latter routed to Phase-5 + batch-12 to assess whether US-010's full composition benefit (batch/assignments wired from the save UI) should be realized next.

The "WITH-NOTES" qualifier reflects SCOPE-1 (a spec-conformant boundary worth a Phase-5 product decision) and the V-5/baseline doc-reconciliation items — none of which are defects. No code/test/requirements changes were made during validation.
