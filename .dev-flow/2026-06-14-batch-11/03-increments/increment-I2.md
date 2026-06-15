# Increment I2 — Contained atomic write (HLR-002)

Batch: 2026-06-14-batch-11 · Phase 3 · Branch `claude/batch-11`
Predecessor: I1 (commit 27b34ae, `serialize_manifest`). Successors: I3 (verify-on-write), I4 (TUI surface).

LLRs implemented: **HLR-002 / LLR-002.1 (stage-then-atomic-replace), LLR-002.2 (fixed name, no dedup), LLR-002.3 (containment/IO finding, collect-don't-abort).**

---

## 1. What changed
Added the CONTAINED ATOMIC WRITE side of the manifest writer. `write_project_manifest` calls the I1 `serialize_manifest` (a refusal short-circuits to `(None, refusal_findings)` — nothing staged/written), stages the serialized text to `.s19tool/workarea/temp/project.json`, re-runs `copy_into_workarea`'s containment **CHECKS** against the final destination (`_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point`), then performs an atomic `os.replace(staged, project_root / "project.json")`. The placement uses the fixed name `project.json` (`PROJECT_MANIFEST_NAME`) and **does NOT** reuse `copy_into_workarea`'s copy-with-dedup body, so a re-save overwrites in place — two saves leave exactly one `project.json`, never `project_1.json` (the M-1 / D-3 locked mechanism). Containment / IO failures return one `MANIFEST-WRITE-CONTAINMENT` WARNING finding instead of raising; the staged temp file is always removed in a `finally`.

## 2. Files modified
| File | Δ lines | Purpose |
|------|---------|---------|
| `s19_app/tui/services/manifest_writer.py` | +212 / −2 | Added `write_project_manifest`, `_check_destination_contained`, `_manifest_write_containment_issue`, `MANIFEST_WRITE_CONTAINMENT` const; new imports (`os`, workarea containment symbols, `PROJECT_MANIFEST_NAME`); header docstring updated for I2. |
| `tests/test_manifest_writer.py` | +165 / −1 | Added TC-002a..c (5 test fns) + `_project_dir` workarea fixture helper; imports + docstring map extended. |

Target was 2 files; exactly 2 touched. No other file modified (workspace.py / variant_execution_service.py untouched — checks REUSED via import only).

## 3. How to test
```
python -m pytest -q tests/test_manifest_writer.py
python -m pytest -q tests/test_manifest_writer.py::test_two_saves_leave_exactly_one_manifest_second_wins
rg -n "import textual|from textual|getLogger|import logging" s19_app/tui/services/manifest_writer.py
python -m pytest -q tests/test_engine_unchanged.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only
```

## 4. Test results (actual)
1. `pytest -q tests/test_manifest_writer.py` → **15 passed in 0.45s** (I1's 10 + 5 new).
2. Lean `pytest -q -m "not slow"` → **778 passed, 29 skipped, 21 deselected, 3 xfailed in 223.39s** (0 failures). Pre-baseline re-measured this session: 773 passed → 778 (+5).
3. `--collect-only` last line → **`831 tests collected in 0.66s`** (pre 826 + 5).
4. Purity `rg "import textual|from textual|getLogger|import logging" …manifest_writer.py` → **0 matches** (rg exit 1). Headless + no-logging confirmed (LLR-004.3 / F-S-07).
5. **M-1 regression proof:** `test_two_saves_leave_exactly_one_manifest_second_wins` → **1 passed**. Asserts `project_dir.glob("project*.json")` name list == `["project.json"]`, `not (project_dir / "project_1.json").exists()`, and re-read `active_variant == "b"` (2nd save wins).
6. Engine guard `pytest -q tests/test_engine_unchanged.py` → **1 passed**.

## 5. Risks
- `os.replace` atomicity depends on staged temp + destination being on the same filesystem. Guaranteed here: both live under the one `.s19tool/workarea/` tree (`base_dir` is the staging root, `project_root` is `<base>/.s19tool/workarea/<project>/`). If a future caller passes a `project_root` on a different volume than `base_dir`, `os.replace` would raise `OSError` — which is CAUGHT and returned as a finding (no crash), but the write would fail. Not exercised this batch; I4 must pass the same `base_dir`.
- The reparse-point check is best-exercised under symlink privilege; the failure test uses a non-workarea destination (no `.s19tool/workarea` ancestor) which trips `_find_workarea_root → None` without needing symlink privilege — the reparse branch itself is reused-not-retested code (covered by workspace.py's own suite).
- Edge not covered: a `project_root` that IS inside the workarea but whose parent dir doesn't exist — `destination.parent.mkdir(parents=True, exist_ok=True)` handles it; passing test `test_write_places_manifest_and_reads_back` exercises a pre-created dir only.

## 6. Pending items (deferred to later increments)
- **I3 (HLR-003):** `verify_written_manifest` + `ManifestVerifyResult` + status constants; re-read by canonical fixed name, key-wise compare in C-1 form, reader-issues-as-mismatch. NEW `tests/test_manifest_verify.py` (TC-003a..c).
- **I4 (HLR-004):** wire serialize→write→verify into the `app.py` project-save handler; surface verified/mismatch; possible `services/__init__.py` export; REQUIREMENTS.md traceability. Demo TC-D1 + inspection TC-004a + textual-graph TC-004b.

## 7. Suggested next task
I3 — verify-on-write. Add `verify_written_manifest` to `manifest_writer.py` (re-read via `read_project_manifest(project_dir)` addressed by `project_dir / PROJECT_MANIFEST_NAME`, NOT the returned path), compare against intent in the C-1 canonical form, classify reader `issues` as mismatch. New `tests/test_manifest_verify.py`.

---

## Collection ledger
| | Count |
|---|---|
| Pre lean passed (re-measured this session) | 773 |
| Post lean passed | 778 (+5, 0 failures) |
| Pre collection | 826 |
| Post collection | 831 (+5) |
| New nodes (this increment) | 5 |

## A-3 / V-5 — provisional identifier reconciliation
Spec `-k` selectors are provisional-until-Phase-3 (V-5 covers FILE path, `-k` selector, AND node id). The implemented node ids do NOT match the spec's `-k` tokens; reconcile as follows:

| Spec (§4) | Provisional `-k` token | Implemented node id (actual) |
|-----------|------------------------|------------------------------|
| LLR-002.1 | `staged_place` | `test_write_places_manifest_and_reads_back`, `test_two_saves_leave_exactly_one_manifest_second_wins` |
| LLR-002.2 | `fixed_name` | `test_fixed_name_and_staged_temp_removed` |
| LLR-002.3 | `write_failure` | `test_destination_outside_workarea_returns_finding` (+ `test_refused_serialize_short_circuits_without_writing` covers the LLR-001.5 ∩ HLR-002 short-circuit) |

Test FILE path: `tests/test_manifest_writer.py` (matches spec; not renamed). The Phase-4 validation matrix should use the actual node ids above, not the provisional `-k` tokens.

A-3 new-symbol-into-existing-file: `write_project_manifest` etc. were added to `manifest_writer.py`, a file CREATED in I1 (not frozen, not allowlisted). No new symbol targets a frozen module. `os` + workarea containment helpers are IMPORTED from `workspace.py`; workspace.py is unmodified.

## Deviations
- `write_project_manifest` signature takes `base_dir` as a third positional param (the staging/containment root), in addition to the spec-named `variant_set, project_root, *, batch, assignments, schema_version`. The spec's LLR signature sketch (`write_project_manifest(variant_set, project_root, *, batch=..., assignments=..., schema_version=1, ...)`) left the staging root under the `...`; `base_dir` is required because `ensure_workarea` + the `temp/` staging dir need a base, exactly as `write_change_document(document, base_dir, ...)` does (`io.py:1167`). Documented here as the only signature deviation; matches the I1/io.py style.
- Added one extra test (`test_refused_serialize_short_circuits_without_writing`) beyond the 3 named TC-002 cases to lock the refusal short-circuit at the HLR-002 boundary (no `MANIFEST-WRITE-CONTAINMENT` manufactured on a serialize refusal). 5 new tests total.
