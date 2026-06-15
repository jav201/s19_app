# Increment I3 — Verify-on-write (HLR-003)

Batch 2026-06-14-batch-11 · Phase 3 · branch `claude/batch-11`

## 1. What changed
Added VERIFY-ON-WRITE for the project manifest. `verify_written_manifest`
re-reads the just-written `project.json` via `read_project_manifest` addressed
by the CANONICAL fixed name (`project_dir / PROJECT_MANIFEST_NAME`, the M-1
fix — never a path a write helper returned) and compares the re-read
`active_variant` / `batch` / `assignments` against the intended composition in
the C-1 canonical comparison form (intent resolved against `project_root` so
both sides are resolved-absolute `Path`s). The result is a dedicated
`ManifestVerifyResult` (status / drift / issues / written_path), mirroring the
SHAPE of batch-10's `VerifyResult` but compared key-wise over the manifest
dict — NOT via `diff_mem_maps` (D-1). Status is `MANIFEST_VERIFIED` iff drift
is empty AND the re-read carries no reader issues; otherwise `MANIFEST_MISMATCH`
naming the drift. Any non-empty re-read `ProjectManifest.issues` forces
MISMATCH (R-1) — the false-verify guard for a write the reader degrades.
Headless: no `textual`, no `logging`.

## 2. Files modified
- `s19_app/tui/services/manifest_writer.py` (+~210 lines) — added
  `read_project_manifest` to the existing import; added `MANIFEST_VERIFIED` /
  `MANIFEST_MISMATCH` constants, the `ManifestVerifyResult` dataclass, the
  `_resolve_intended_entries` C-1 canonical-form helper, and
  `verify_written_manifest`; extended the module docstring with the I3
  verify-on-write paragraph.
- `tests/test_manifest_verify.py` (NEW, 4 tests) — TC-003a/b/c + the M-1
  canonical-path test.

## 3. How to test
```
python -m pytest -q tests/test_manifest_verify.py
python -m pytest -q tests/test_manifest_writer.py
python -m pytest -q -m "not slow"
python -m pytest -q tests/test_engine_unchanged.py
rg -n "import textual|from textual|getLogger|import logging" s19_app/tui/services/manifest_writer.py
python -m pytest -q --collect-only | tail -1
```

## 4. Test results (actual)
- `tests/test_manifest_verify.py` → **4 passed** in 0.36s.
- `tests/test_manifest_writer.py` → **15 passed** (I1+I2 intact).
- Lean `-m "not slow"` → **782 passed, 29 skipped, 21 deselected, 3 xfailed**,
  0 failures (183.39s). Lean count 778 → 782 (+4 verify nodes).
- `--collect-only` last line → **`835 tests collected in 0.53s`** (pre 831 → +4).
- Purity probe `rg ... manifest_writer.py` → **0 matches** (no textual, no logging).
- `tests/test_engine_unchanged.py` → **1 passed** (frozen set untouched).

### Coverage-claim discipline
The 4 nodes each plant a fault matching the asserted outcome (Rule 9): TC-003b
flips `active_variant` on disk and asserts `drift == ["active_variant"]` (only
that key); TC-003c writes `project.json` directly with an escaping `batch`
entry (the writer would refuse it via LLR-001.5) so the reader degrades it on
re-read, asserting MISMATCH with `drift == []` and the carried
`MANIFEST-PATH-ESCAPE` issue — the R-1 guard; the canonical-path test plants a
stray `project_1.json` with a different `active_variant` and asserts VERIFIED,
proving verify never honors the suffixed file (M-1). I claim coverage only for
HLR-003 / LLR-003.1–003.3 — not the TUI surfacing (HLR-004), which is I4.

## 5. Risks
- The `_resolve_intended_entries` helper does NOT re-run the reader's
  containment predicate (the serializer already refuses escaping entries at
  LLR-001.5); it only mirrors the relative→absolute resolution for an
  apples-to-apples compare. If a future caller bypasses the writer and feeds
  verify a raw escaping intent string, the intent side would resolve outside
  the root and simply mismatch the reader's skipped (empty) field — still a
  MISMATCH, never a false verify, so the security posture holds.
- An ABSENT manifest at the canonical name returns MISMATCH with
  `drift == ["active_variant","batch","assignments"]` and `written_path=None`
  — a deliberate "nothing to verify" outcome, not covered by a dedicated test
  this increment (the write path guarantees the file exists when verify is
  called in the I4 pipeline). Edge case noted; not exercised.

## 6. Pending items
- I4 (HLR-004): TUI project-save wiring — call serialize→write→verify from the
  save handler in `app.py`, surface the `ManifestVerifyResult` (quiet on
  verified, named drift / reader-issue on mismatch, plain-text issue messages
  per LLR-004.2), possible `services/__init__.py` export, REQUIREMENTS.md
  traceability. Demo TC-D1 + inspection TC-004a + textual-graph TC-004b.

## 7. Suggested next task
I4 — wire the serialize→write→verify pipeline into the TUI project-save handler
and surface the verify outcome, then reconcile the V-5 provisional test
file/node names against the implemented tree at Phase 4.

---
### Ledger (cumulative)
| Increment | Symbol(s) added | Tests | Lean | Collection |
|-----------|-----------------|-------|------|------------|
| I1 (27b34ae) | `serialize_manifest` + refusal gate | — | — | — |
| I2 (8dd8498) | `write_project_manifest` (atomic os.replace) | 15 (writer) | 778 | 831 |
| **I3 (this)** | `ManifestVerifyResult`, `verify_written_manifest`, `MANIFEST_VERIFIED`/`MANIFEST_MISMATCH`, `_resolve_intended_entries` | +4 (verify) | **782** | **835** |

### A-3 / V-5 — actual node ids vs provisional
Spec pinned file `tests/test_manifest_verify.py` (matched) and `-k` selectors
`verified` / `mismatch` / `reader_issue`. Implemented node ids:
- `tests/test_manifest_verify.py::test_faithful_write_verifies` (TC-003a, `-k verified`✓)
- `tests/test_manifest_verify.py::test_tampered_active_variant_mismatches_naming_the_key` (TC-003b, `-k mismatch`✓)
- `tests/test_manifest_verify.py::test_reader_issues_force_mismatch_even_if_surviving_keys_match` (TC-003c, `-k reader_issue` — DEVIATION: implemented name contains `reader_issues` (plural via `issues`); the spec `-k reader_issue` substring still matches `reader_issues`. Provisional-until-Phase-3 per V-5; reconcile the coverage table at Phase 4.)
- `tests/test_manifest_verify.py::test_verify_reads_canonical_name_not_a_stray_suffixed_file` (M-1 canonical-path, no spec `-k`).

### Deviations
- None on behavior. One V-5 provisional-name note: the reader-issue node is
  named `..._reader_issues_force_mismatch...` (the spec selector was
  `reader_issue`, singular — it substring-matches, so `-k reader_issue` still
  selects it). Recorded for the Phase-4 reconciliation, not a blocker.
