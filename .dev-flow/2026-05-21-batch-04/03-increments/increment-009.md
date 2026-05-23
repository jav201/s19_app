# Increment 009 — Round-trip + integration hardening + S57-02 fix — Review Packet

**Batch:** 2026-05-21-batch-04 — memory-field change kind + unified change-set + selective export
**Phase:** 3 — Implementation
**Increment:** 9 of 9 — **final** — `test_unified_roundtrip.py` + `test_cdfx_unchanged.py` + the S57-02 write-path fix
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs:** LLR-006.1 (round-trip corroboration); closes the TC-027 inspection checklist for LLR-004.2 + LLR-009.2 · **TCs:** TC-025, TC-027

---

## 1. What changed

Three pieces, closing Phase 3.

**(a) TC-025 — the unified write→read round-trip** (`tests/test_unified_roundtrip.py`,
new). Builds the production `unified_changeset_factory` change-set — the
parameter half carries a scalar, a 1-D integer array, an ASCII string and the
three adversarial IEEE binary64 floats (`0.1`, the smallest positive denormal
`5e-324`, a 17-significant-digit value); the memory half carries an
inside-range run plus the pinned multi-byte overlap pair — then
`write_unified_to_workarea` → `read_unified` and asserts structural equality.
The equality predicate is split per the Q-06 finding: the **parameter half**
is compared on the `(parameter_name, array_index)` identity key plus the
**exact `==`** value (no tolerance), with resolution `status` asserted
separately; the **memory half** is compared on the `address` key plus the
**exact ordered `new_bytes`** run, with validation `status` *excluded* from the
equality predicate and asserted separately (the reader deliberately re-derives
memory status — A-7). Deterministic per-half insertion order is asserted to
survive. The round-trip is exercised for all four memory-field variants
(`base` / `partial` / `outside` / `gap-spanning`).

**(b) TC-027 — the engine / data-processing-unchanged inspection check**
(`tests/test_cdfx_unchanged.py`, new). An executable two-arm inspection: arm 1
runs `git diff --name-only main` over the engine / data-processing paths
(`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
`tui/mac.py`) and asserts the output is empty — batch-04 changed none of them;
arm 2 pins the SHA-256 of the batch-03 `cdfx/writer.py` and `cdfx/resolve.py`
to their batch-03 state and asserts byte-equality. The writer hash is the exact
value the increment-7 packet recorded (`82d527c0…fe4ac`).

**(c) Security finding S57-02 fix** — `write_unified_to_workarea`
(`unified_io.py`) and `write_memory_field_to_workarea` (`export.py`) caught
**only** `WorkareaContainmentError`; an `OSError` from the staged-temp
`write_bytes` (full disk, denied permission, name too long) would escape
uncaught, breaking the LLR-005.4 / LLR-007.2 "never an uncaught exception"
collect-don't-abort claim. Both functions now have an `except OSError` arm that
converts the fault to one `MF-WRITE-CONTAINMENT` `ValidationIssue` and a `None`
path — collect-don't-abort, no propagation. Each function's `Raises:` docstring
records the new arm. One write test per function was extended to cover it.

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `tests/test_unified_roundtrip.py` | **New** | TC-025 — write→read round-trip, 9 tests; split per-half equality predicate, adversarial-float exact-`==`, all four memory variants. |
| 2 | `tests/test_cdfx_unchanged.py` | **New** | TC-027 — executable inspection check, 2 tests; engine `git diff` arm + batch-03 cdfx byte-unchanged hash-pin arm. |
| 3 | `s19_app/tui/cdfx/unified_io.py` | **Edit** | S57-02 — `except OSError` arm in `write_unified_to_workarea`; `Raises:` docstring updated. |
| 4 | `s19_app/tui/cdfx/export.py` | **Edit** | S57-02 — `except OSError` arm in `write_memory_field_to_workarea`; `Raises:` docstring updated. |

Two existing test files were also extended (not counted toward the new-file
cap — the increment's "extend a write test" step): `tests/test_unified_write.py`
gained `test_tc018_oserror_from_staged_write_surfaces_issue_not_exception`;
`tests/test_unified_export.py` gained
`test_tc031_memory_field_oserror_surfaces_issue_not_exception` (plus the
`write_memory_field_to_workarea` import). **File count: 4 of 5** for the
two new files + the two source edits — within cap.

**No engine / data-processing change** beyond the S57-02 defensive `except`
widening in the two `cdfx/` write functions. The batch-03 `cdfx/writer.py` and
`cdfx/resolve.py` are byte-unchanged — TC-027 now pins that. stdlib only — no
new dependency.

## 3. How to test

```
# from repo root C:\Users\jjgh8\Github\s19_app
python -m pytest -q tests/test_unified_roundtrip.py tests/test_cdfx_unchanged.py   # the new TC-025 / TC-027
python -m pytest -q tests/test_unified_write.py tests/test_unified_export.py       # the extended S57-02 arms
python -m pytest -q                                                               # full suite — baseline + new
python -c "import s19_app.tui.cdfx"                                                # package import
python -m py_compile s19_app/tui/cdfx/unified_io.py s19_app/tui/cdfx/export.py tests/test_unified_roundtrip.py tests/test_cdfx_unchanged.py
```

`ruff` is not installed in this environment — `python -m py_compile` was
substituted per the increment instructions.

## 4. Test results (actual output)

**New test files** — `pytest -q tests/test_unified_roundtrip.py tests/test_cdfx_unchanged.py`:
```
...........                                                              [100%]
11 passed in 0.18s
```
(9 TC-025 round-trip + 2 TC-027 inspection.)

**Extended write / export files** — `pytest -q tests/test_unified_write.py tests/test_unified_export.py`:
```
....................................                                     [100%]
36 passed in 0.34s
```
(18 write incl. the new S57-02 `write_unified_to_workarea` arm; 18 export incl.
the new S57-02 `write_memory_field_to_workarea` arm.)

**Full suite** — `pytest -q`:
```
27 snapshots passed.
762 passed, 2 skipped, 3 xfailed in 203.18s (0:03:23)
```
Baseline was **749 passed / 2 skipped / 3 xfailed / 0 failed**; now **762
passed** (749 + 13 new: 9 TC-025 + 2 TC-027 + 2 S57-02) / 2 skipped / 3 xfailed
/ **0 failed**. No regressions.

**Import / compile:**
```
py_compile: OK
import s19_app.tui.cdfx: OK
```

**TC mapping:**
- **TC-025** (LLR-006.1, corroborating HLR-005 / HLR-006) — a
  `unified_changeset_factory` change-set survives `write_unified_to_workarea` →
  `read_unified`: parameter `(name, array_index)`-keyed values by exact `==`
  (incl. the three adversarial binary64 floats — `0.1`, `5e-324`,
  `8.98846567431158e307` — bit-exact, no tolerance); memory `address`-keyed
  byte runs in exact order (incl. the pinned `DEADBEEF` run at `0x200`);
  deterministic per-half order preserved; resolution status round-trips
  (asserted separately); memory status re-derived to `UNVALIDATED_NO_IMAGE` on
  read (asserted separately, excluded from the equality predicate); holds for
  all four memory variants; per-half counts preserved. ✅
- **TC-027** (LLR-004.2 + LLR-009.2 inspection close-out) — engine /
  data-processing modules report empty `git diff --name-only main`; batch-03
  `cdfx/writer.py` (`82d527c0…fe4ac`) and `cdfx/resolve.py` (`81db0237…0112b9`)
  byte-unchanged by content-SHA-256 pin. ✅
- **S57-02** — both write functions catch a `PermissionError` (an `OSError`
  subclass) from the staged-temp `write_bytes` and return
  `(None, [MF-WRITE-CONTAINMENT])` with the correct per-artifact tag and a
  `PermissionError`-naming message — no exception propagates. ✅

## 5. Risks

- **TC-027 arm 1 needs git + a `main` ref.** The engine-unchanged arm runs
  `git diff --name-only main`. In an environment with no git binary or no
  `main` ref (a detached wheel install, a shallow CI clone) the test
  **skips with a recorded reason** rather than erroring or false-passing — the
  skip is visible in the report, never silent. On this checkout `main` exists
  locally and the arm runs and passes.
- **TC-027 arm 2 hash pins are branch-state, not `main`-state.** `writer.py`
  and `resolve.py` do **not** exist on the `main` baseline — they are batch-03
  additions carried uncommitted on this branch — so a `git diff main` cannot
  express "unchanged since batch-03". The test pins their content SHA-256
  instead. This is the same mechanism (and the same `writer.py` hash) the
  increment-7 TC-030 test uses; the two tests now independently pin `writer.py`,
  so the guard survives a refactor of either. A *deliberate* future change to
  either module must update `_BATCH03_CDFX_HASHES` — the test fails loud and
  prints the new hash. The hash is over file *content*, robust to
  `__pycache__` noise; it is **not** robust to a pure line-ending rewrite (a
  git autocrlf flip on checkout) — on this LF-stored Windows checkout the hash
  is stable. Same caveat the increment-7 packet flagged.
- **S57-02 message wording.** The reused `_containment_issue` /
  `_memory_field_containment_issue` builders say "failed work-area containment
  validation" — slightly broad for a pure `OSError` (a full disk is not a
  containment fault). The fix passes the `OSError` type/detail into the message
  so it remains diagnosable; the issue *code* (`MF-WRITE-CONTAINMENT`) and the
  collect-don't-abort behaviour are correct. A dedicated `MF-WRITE-IO` code was
  considered and rejected as scope creep — `MF-WRITE-CONTAINMENT` is the
  documented "the write target did not produce a file" code and the increment
  instruction explicitly says "`MF-WRITE-CONTAINMENT` (or equivalent
  write-error)". Flagged for the Phase-4 validation review if a finer code is
  wanted.
- **TC-027 / `pyproject.toml`.** Cross-cutting note D mentioned TC-027 could
  also assert `pyproject.toml` / `requirements.txt` unchanged. `pyproject.toml`
  *does* differ from `main` — but that delta is the **batch-02** Direction-B
  restyle (`textual>=8.0.2`, the `pytest-textual-snapshot` dev extra), not a
  batch-04 change. The increment-9 instruction scoped TC-027 to exactly the
  engine-modules + batch-03-cdfx checks and did not request a `pyproject`
  assertion; asserting "unchanged vs main" would false-fail on a pre-existing
  out-of-batch change. TC-027 was kept to the two specified arms. Batch-04's
  no-new-dependency constraint (C-4) still holds — no batch-04 increment
  touched `pyproject.toml`; the whole batch is stdlib-`json` only.

## 6. Pending items

- None within increment-9 scope. All 37 TCs of batch-04 now have an
  implementing test; Phase 3 is complete.
- The S57-02 finding from the increment 5–7 security hand-off is now closed
  for the two write paths it named (`write_unified_to_workarea`,
  `write_memory_field_to_workarea`). If the Phase-4 security review wants a
  distinct `MF-WRITE-IO` code, that is a one-line follow-up (see §5).

## 7. Suggested next task

**Phase 3 is complete — all 9 increments shipped.** The batch-04 implementation
(memory-change model → validation → display → unified container → write → read
→ selective export → Patch Editor UI → round-trip/integration hardening) is
done, the full suite is green at **762 passed / 2 skipped / 3 xfailed /
0 failed**, and `s19tui` imports cleanly.

Batch-04 now advances to **Phase 4 — Validation**: the V-model right-side
verification against `01-requirements.md` — confirm every HLR/LLR has a
passing TC, run the §5.6 inspection items not covered by automation, execute
the QA manual test plan for the Patch Editor screen (TC-032/033/034), and fold
the increment 5–7 security hand-off (now incl. the S57-02 close-out) and the
TC-027 inspection sign-off into `04-validation.md`. Recommended hand-offs:
`qa-reviewer` for the manual Patch Editor acceptance run, `security-reviewer`
to confirm S57-02 is satisfactorily closed across both write paths.

---

*Increment boundary reached — Phase 3 complete. Stopping here.*
