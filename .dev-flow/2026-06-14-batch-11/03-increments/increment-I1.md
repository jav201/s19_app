# Increment I1 — Manifest serializer + refusal gate (HLR-001)

Batch 2026-06-14-batch-11 · Phase 3 · branch `claude/batch-11`

## 1. What changed
Added the WRITE side's serializer for the project manifest. `serialize_manifest`
turns an in-memory `ProjectVariantSet` + project-wide `batch` + per-variant
`assignments` into the canonical `project.json` envelope text the existing
reader (`read_project_manifest`) parses back without findings — the
round-trip-to-reader correctness criterion (D-2). Emission is via the stdlib
`json` encoder (never string assembly). A security input gate (LLR-001.5)
REFUSES any absolute or project-escaping `batch`/`assignments` entry by reusing
the reader's own rejection predicate (`_resolve_manifest_entry`), returning
`(None, [finding, ...])` and emitting nothing. The module is headless: no
`textual` import, no logging. This increment is SERIALIZE ONLY — the contained
write (I2), verify-on-write (I3), and TUI surface (I4) are later increments.

## 2. Files modified
- `s19_app/tui/services/manifest_writer.py` (NEW, 286 lines) — `serialize_manifest`,
  the `MANIFEST_WRITE_ESCAPE` finding constant + `_manifest_write_issue`,
  `_posix_entries` (forward-slash normalization), `_reject_unsafe_entry`
  (reuses `_resolve_manifest_entry`), and `DEFAULT_SCHEMA_VERSION = 1`.
- `tests/test_manifest_writer.py` (NEW, 261 lines) — 10 tests covering
  TC-001a..e (module docstring maps test → TC → LLR).

No other file touched. No frozen-engine module touched.

## 3. How to test
```
python -m pytest -q tests/test_manifest_writer.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only            # last line = total node count
python -m pytest -q tests/test_engine_unchanged.py
rg -n "import textual|from textual" s19_app/tui/services/manifest_writer.py
rg -n "getLogger|import logging" s19_app/tui/services/manifest_writer.py
```

## 4. Test results (actual output)
1. `pytest -q tests/test_manifest_writer.py` → **10 passed in 0.44s**.
2. `pytest -q -m "not slow"` → **773 passed, 29 skipped, 21 deselected, 3 xfailed
   in 246.01s; 0 failures**. (Pre-state batch-10 close = 763 passed; 763 + 10
   new = 773 — the new tests are the only delta, nothing regressed.)
3. Collection ledger:
   - Pre-state baseline: `816 tests collected` (re-measured 2026-06-15 on the
     post-batch-10-merge tree — matches the spec's 816 baseline).
   - Post-I1: `826 tests collected`.
   - Signed balance: `post = 816 − 0 + 10 = 826`. ✓
4. Purity (V-4 import-statement form):
   - `rg "import textual|from textual" manifest_writer.py` → **0 matches**.
   - `rg "getLogger|import logging" manifest_writer.py` → **0 matches**.
5. Engine-frozen guards: `pytest -q tests/test_engine_unchanged.py` → **1 passed**.

### A-3 / V-5 node-id reconciliation (provisional spec name → implemented node)
| Spec provisional `-k` selector | Implemented pytest node id | TC / LLR |
|---|---|---|
| `-k envelope_keys` | `test_envelope_keys_and_active_variant` | TC-001a / LLR-001.1 |
| (LLR-001.1 AC null) | `test_envelope_empty_project_active_variant_is_null` | TC-001a / LLR-001.1 |
| `-k relative_paths` | `test_relative_paths_resolve_with_no_escape` | TC-001b / LLR-001.2 |
| (LLR-001.2 AC backslash) | `test_windows_backslashes_normalized_to_forward_slash` | TC-001b / LLR-001.2 |
| `-k roundtrip` | `test_roundtrip_equals_intent_in_canonical_form` | TC-001c / LLR-001.3 |
| (LLR-001.3 AC schema) | `test_roundtrip_schema_version_survives` | TC-001c / LLR-001.3 |
| `-k deterministic` | `test_deterministic_byte_identical_output` | TC-001d / LLR-001.4 |
| `-k refuse_escape` | `test_refuse_escape_and_absolute_entries_writes_nothing` | TC-001e / LLR-001.5 |
| (LLR-001.5 clean-gate) | `test_clean_composition_passes_the_gate` | TC-001e / LLR-001.5 |
| (LLR-001.5 no-file) | `test_refusal_emits_no_file_when_caller_would_write` | TC-001e / LLR-001.5 |

Drift: the implemented file/node names differ from the provisional `-k` tokens
(expected — V-5 makes them provisional-until-Phase-3). The implemented file is
`tests/test_manifest_writer.py` exactly as the spec pinned. Phase-4 reconciles
the coverage table `-k` tokens to these node ids.

## 5. Risks
- **Signature deviation (loud — see §7).** The prompt's literal signature was
  `serialize_manifest(variant_set, project_root, *, schema_version=1)`. That
  cannot supply non-empty `batch`/`assignments` (they are manifest-level data,
  NOT carried by `ProjectVariantSet`), so a faithful LLR-001.3 round-trip with
  non-empty lists is impossible under it. Per F1 ("Convert a ProjectVariantSet
  + active_variant + project-wide batch list + per-variant assignments"), I
  added two keyword-only params: `batch: Sequence[str] = ()` and
  `assignments: Mapping[str, Sequence[str]] | None = None`. Both default empty,
  so the prompt's call form still works. The I4 wiring must pass the project's
  real batch/assignments — confirm the in-memory source at the gate.
- **`_resolve_manifest_entry` is a private symbol** imported across the
  services package. The spec explicitly mandates reusing the reader's predicate
  ("no second, divergent path-safety implementation", LLR-001.5 AC), so the
  underscore import is the deliberate choice, not an accident. If the reader is
  ever refactored, this import is a coupling point (R-4, accepted single-oracle
  design).
- **Refusal granularity:** `_reject_unsafe_entry` re-reports unsafe entries as
  one `MANIFEST-WRITE-ESCAPE` finding each (distinct code from the reader's
  read-path `MANIFEST-PATH-ESCAPE`). A non-string entry would also be refused
  (the predicate returns None), but the serializer's inputs are typed `str`, so
  that path is defensive only.

## 6. Pending items (I2–I4)
- **I2 (HLR-002):** `write_project_manifest` + `MANIFEST_WRITE_CONTAINMENT` in
  the same module — stage to `temp/` → reuse `copy_into_workarea` containment
  CHECKS → atomic `os.replace` at the fixed `project.json` name (D-3 locked);
  NOT the dedup body. Tests TC-002a..c.
- **I3 (HLR-003):** `verify_written_manifest` + `ManifestVerifyResult` +
  status constants; NEW `tests/test_manifest_verify.py` (TC-003a..c).
- **I4 (HLR-004):** wire the save handler in `app.py`; possible
  `services/__init__.py` export + `REQUIREMENTS.md` traceability. TC-D1 demo,
  TC-004a inspection, TC-004b textual-graph probe.

## 7. Suggested next task
Proceed to **I2 — contained write** (`write_project_manifest`). Before coding,
confirm at the gate: (a) the keyword-only `batch`/`assignments` signature
extension is accepted as the serializer contract feeding I2/I4; (b) the
in-memory source of `batch`/`assignments` at project-save time (the prompt's
A-3 says a `ProjectVariantSet` is available, but batch/assignments come from
elsewhere — likely the loaded manifest or save payload).
