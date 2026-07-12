# Increment 002 — US-060 (B-23): relocate test inputs to `examples/` + prune heavy duplicate A2L

Scope: **US-060 only** (HLR-060 · LLR-060.1/.2/.3/.4 · AT-060a + TC-323). Compose/CSS and legend
work (US-058/US-059) untouched.

---

## I-060-1 — HARD verify-before-delete gate (census evidence — RECORDED BEFORE the delete)

The 54 MB `examples/professional_validation/case_06_large_nested_a2l/firmware.a2l`
(56,046,631 B) was proven a **pure SCALE duplicate** of the retained 36 MB
`examples/case_06_large_nested_a2l/firmware.a2l` (37,742,888 B) before any `git rm`.

Command (per file): `grep -ohE '/begin[[:space:]]+[A-Z_]+' <file> | awk '{print $2}' | sort -u`

- **kinds(54 MB)** — 13 kinds:
  `CHARACTERISTIC, COMPU_METHOD, DEF_CHARACTERISTIC, FUNCTION, GROUP, HEADER, MEASUREMENT,
  MODULE, MOD_COMMON, MOD_PAR, PROJECT, RECORD_LAYOUT, REF_CHARACTERISTIC`
- **kinds(36 MB)** — 13 kinds (identical set):
  `CHARACTERISTIC, COMPU_METHOD, DEF_CHARACTERISTIC, FUNCTION, GROUP, HEADER, MEASUREMENT,
  MODULE, MOD_COMMON, MOD_PAR, PROJECT, RECORD_LAYOUT, REF_CHARACTERISTIC`
- **kinds only in 54 MB** (`comm -23 k54 k36`): **∅ (empty)**
- **Verdict:** `kinds(54 MB) ⊆ kinds(36 MB)` — **TRUE**. No unique parser/validator branch lives
  only in the 54 MB copy → the delete is AUTHORIZED. (Matches, and independently re-confirms, the
  draft-time P27 preview of 13 identical kinds — but this is the freshly re-run gate evidence, not
  the preview.)

**Only after this gate passed** was `git rm -r examples/professional_validation/case_06_large_nested_a2l/`
executed.

---

## 1. What changed

- **Relocated** the three git-tracked stress inputs `tmp/stress_smoke/stress.{a2l,mac,s19}` into a
  new discoverable case `examples/case_07_stress_smoke/`, renamed to the discovery-preferred
  `firmware.{s19,a2l,mac}` names (via `git mv`, S-02); removed the now-empty `tmp/stress_smoke/`
  and `tmp/`. These files gain full smoke + pilot pipeline coverage they lacked in `tmp/`.
- **Pruned** the 54 MB slow-only duplicate `examples/professional_validation/case_06_large_nested_a2l/`
  (via `git rm -r`, S-02), gated by I-060-1 above. Retained the 36 MB
  `examples/case_06_large_nested_a2l/` (normal-suite case, operator constraint D-1) and the other
  seven `professional_validation/` cases.
- **Test edits (LLR-060.3):** `SLOW_CASE_IDS → set()` (the only slow case was deleted); module
  docstring case counts updated (top-level 7→8, nested 8→7). No functional assertion removed.
  Added `README.txt` to the new case (matches the `README.txt` convention on case_01..case_06).
- **Doc edits:** `docs/architecture.md` slow-marker note (was "`pv__case_06_large_nested_a2l` is
  pinned slow" → now "no example case pinned slow; large-A2L covered by retained 36 MB case in the
  normal suite"); `examples/case_00_public/MANIFEST.md` gains a `case_07_stress_smoke` entry (the
  existing case_06 line still refers to the retained 36 MB fixture — left as-is).
- **New tests:** AT-060a (`test_at060a_fixtures_relocated_heavy_duplicate_pruned`, one node, C-18) +
  TC-323 (`test_tc323_discovery_and_coverage_map`) in `tests/test_examples_smoke.py`.

## 2. Files modified

Code/doc (4, within ≤5 cap):
1. `tests/test_examples_smoke.py` — `import subprocess`, `REPO_ROOT`, docstring counts,
   `SLOW_CASE_IDS = set()`, + AT-060a + TC-323.
2. `docs/architecture.md:152` — slow-marker note de-staled.
3. `examples/case_00_public/MANIFEST.md` — case_07 entry added.
4. `examples/case_07_stress_smoke/README.txt` — NEW (convention match).

Fixture moves/deletes via git (additional per task authorization):
- `git mv` ×3: `tmp/stress_smoke/stress.{a2l,mac,s19}` → `examples/case_07_stress_smoke/firmware.{a2l,mac,s19}`.
- `git rm -r` ×4 files: `examples/professional_validation/case_06_large_nested_a2l/{README.txt,firmware.a2l,firmware.mac,firmware.s19}`.

## 3. How to test

```bash
pytest tests/test_examples_smoke.py -q --durations=5      # AT-060a + TC-323 + 15 param cases
pytest tests/test_examples_pilot_gifs.py --collect-only -q # discovery: case_07 in, pv__case_06 out
du -sh examples                                            # size after
git ls-files tmp/stress_smoke                              # must be empty
```

## 4. Test results

- **RED (C-20, pre-change, over tracked paths — no stash):** ran AT-060a + TC-323 BEFORE the
  git mv/rm → **2 failed, exit 1**. AT-060a failed on `tmp/stress_smoke` still existing; TC-323
  failed on `SLOW_CASE_IDS == {'pv__case_06_large_nested_a2l'} != set()`.
- **GREEN (C-19, one complete run):** `pytest tests/test_examples_smoke.py -q --durations=5` →
  **17 passed in 10.66s, exit 0**. Slowest = retained 36 MB `case_06_large_nested_a2l` at
  **10.39s** (normal suite, well under a minute — noted, passes). AT-060a = 0.03s.
- **Pilot-gif discovery:** collect shows `case_07_stress_smoke` present, `pv__case_06` absent;
  `-m "not slow"` → 15 deselected (whole test is `@slow`). NO edit required — confirmed by run.
- **Snapshot forbidden-token guard** (`test_tui_snapshot.py:685-703`): 1 passed, no edit — setup
  helpers untouched; `case_07_stress_smoke` not on the forbidden list.
- **ruff** `tests/test_examples_smoke.py`: All checks passed.
- **Frozen-engine diff vs `main`** (core/hexfile/range_index/validation/a2l/mac/color_policy):
  **empty** — 0 frozen diffs.
- **Full-suite collect:** `pytest --collect-only -q` → **1367 tests collected**.

## 5. Risks

- **History weight not reclaimed** (out of scope, LLR-060.4): the 54 MB blob remains in git history;
  working-tree `examples/` dropped 96 M → 42 M only. A filter-repo pass would need separate approval.
- **DF-2 provenance caveat:** the retained 36 MB fixture is documented synthetic
  (`case_00_public/MANIFEST.md:25`); D-1's "real-vendor" intent is satisfied by keeping the
  representative large A2L (no genuinely vendor-sourced larger file exists in-repo). If the operator
  meant a different file, that is a clarification — the keep/delete decision is unchanged.
- **README.txt CRLF:** git emitted the standard `LF→CRLF` autocrlf notice on the new README
  (identical handling to the other case READMEs) — cosmetic, no functional effect.

## 6. Pending items

- Snapshot rebaseline: none for US-060 (no SVG cells touched). US-058's TC-321 xfail set is a
  separate increment.
- Commit/PR: left to the orchestrator (new README staged; renames/deletes/edits in the index).

## 7. Suggested next task

Proceed to the batch-36 US-058 increment (Patch Editor paste-box regroup, AT-058a/b + TC-321) or the
Phase-4 validation roll-up, per the batch plan.

---

### Per-LLR coverage (on-disk test names)

- **LLR-060.1** (relocate) → `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned`
  assertions (1)+(2): `tmp/stress_smoke` absent + `git ls-files` empty; `case_07_stress_smoke` loads
  to non-empty `LoadedFile` (C-10 content via real service layer, C-12).
- **LLR-060.2** (prune, I-060-1-gated) → same AT-060a assertions (3)+(4): 54 MB pv/case_06 absent,
  36 MB `case_06/firmware.a2l` present. Gate evidence recorded above BEFORE the `git rm`.
- **LLR-060.3** (test edits + coverage map) → `tests/test_examples_smoke.py::test_tc323_discovery_and_coverage_map`:
  `SLOW_CASE_IDS == set()`, `case_07_stress_smoke` discovered, `pv__case_06` not discovered,
  `case_06_large_nested_a2l` still discovered (large-A2L pipeline still covered in the normal suite).
- **LLR-060.4** (size + tmp cleanup) → `du -sh examples`: **96 M → 42 M** (~54 M reduction, ≤ 45 M
  threshold met); `tmp/` absent.

### C-18 note

**AT-060a is exactly ONE on-disk node** (`test_at060a_fixtures_relocated_heavy_duplicate_pruned`)
covering all four observable outcomes; TC-323 is a separate white-box discovery/coverage-map node.

### Ledger

`post = base − D + A` = `1365 − 0 + 2 = 1367`. Actual `--collect-only` = **1367** ✓.
(Parametrization nets 0: pv/case_06 drops one param node, case_07 adds one; A = AT-060a + TC-323.)
