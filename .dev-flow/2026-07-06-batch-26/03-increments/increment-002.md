# Increment 002 — US-037 per-variant entropy section in the project report

> Batch: 2026-07-06-batch-26 · Feature #12(b) · Phase 3, Increment 2
> Scope: US-037 report section ONLY (LLR-037.1, 037.2, 037.3). US-036 (modal) untouched.
> Agent: `software-dev` · Files: 2 (within ≤5 cap). Reuses shipped Inc-1 `entropy_service.py`.

---

## 1. What changed

- **LLR-037.1 — `include_entropy` option + validation.** Added `ReportOptions.include_entropy: bool = True` and a `__post_init__` `ValueError` guard (reject-not-coerce, F-S-05 style) mirroring the `include_legend` field/validation precedent exactly.
- **LLR-037.2 — `_entropy_lines(result)` Markdown builder.** New private helper computes `compute_entropy(result.mem_map)` (reusing Inc-1's shipped `entropy_service`) and emits a `### Entropy` heading plus a per-band **count summary** — one bullet per `ENTROPY_BANDS` band that has ≥1 window (`- **<band>**: <n> window(s)`, with a `(<k> low-confidence)` suffix when any window in that band is low-confidence). Empty / `None` `mem_map` → heading + `No mapped bytes - entropy not computed.` (no crash). **Band-summary only, O(bands) not O(windows), no raw byte dump** (R-2 byte-budget + confidentiality).
- **LLR-037.3 — per-variant emission wired via `emit()`.** In `generate_project_report`, inside the per-variant loop immediately AFTER the `_hexdump_section` block, `_entropy_lines(result)` is appended through the budget-charged `emit()` helper when `options.include_entropy` — NOT via a raw `lines.extend` (the LLR mandates `emit()` so the section is charged against `budget`). Default `True` keeps the section on.

No parser import added; no logging added (F-S-07 confidentiality contract preserved). Engine-frozen set untouched.

## 2. Files modified

| File | Change |
|---|---|
| `s19_app/tui/services/report_service.py` | +`from .entropy_service import ENTROPY_BANDS, compute_entropy`; +`include_entropy` field; +`__post_init__` guard; +`_entropy_lines()` helper; +`emit(_entropy_lines(result))` in the per-variant loop after the hexdump block |
| `tests/test_report_service.py` | +US-037 test block (8 tests): AT-037a, AT-037b, TC-037.1 (×2), TC-037.2 (×2), TC-037.3, TC-037.4; + mixed-image fixture builder driving the shipped capture chain |

(Untracked from Inc-1: `entropy_service.py`, `test_entropy_service.py`. `state.json` = dev-flow bookkeeping.)

## 3. How to test

```bash
# from the worktree root (cwd-first resolves the editable .pth to THIS worktree)
cd C:/Users/jjgh8/OneDrive/Documents/Github/s19_app/.claude/worktrees/hungry-burnell-b75534
python -m ruff check s19_app/tui/services/report_service.py tests/test_report_service.py
python -m pytest tests/test_report_service.py -v
python -m pytest tests/test_entropy_service.py -q      # Inc-1 regression
python -m pytest tests/test_engine_unchanged.py -q     # frozen-set guard
```

## 4. Test results (REAL output)

### 4a. Counterfactual — AT-037a RED (emission stubbed off)

The wiring was temporarily changed to `if options.include_entropy and False:` and AT-037a run. The precondition asserts (capture plumbing) PASSED, then the disk-section assert FAILED — proving the test discriminates the feature, not the fixture:

```
        assert "## Variant:" in text
        variant_block = text.split("## Variant:", 1)[1]
>       assert "### Entropy" in variant_block
E       AssertionError: assert '### Entropy' in ' fw\n\n### Modified files\n\n- ...
E       ... \n### Memory regions\n\nWindow 0x00003000-0x00003010:\n\n```text\n
E       0x00003000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|\n```\n'

tests\test_report_service.py:1041: AssertionError
=========================== short test summary info ===========================
FAILED tests/test_report_service.py::test_report_contains_entropy_section_on_disk
============================== 1 failed in 0.66s ==============================
```

Note the precondition asserts (`result.mem_map` non-empty, `[0x3000]==0x00`, `[0x40FF]==255`) all passed BEFORE the failing disk assert — the capture chain (`capture_mem_maps=True`) is proven end-to-end (QR-4), so an off-chain-populated fixture could not false-pass.

### 4b. GREEN — wiring restored

Ruff:
```
All checks passed!
```

`pytest tests/test_report_service.py -v` (33 passed, 8 new):
```
tests/test_report_service.py::test_report_contains_entropy_section_on_disk PASSED [ 78%]
tests/test_report_service.py::test_report_omits_entropy_when_disabled_byte_identical PASSED [ 81%]
tests/test_report_service.py::test_entropy_lines_shape_direct_call PASSED [ 84%]
tests/test_report_service.py::test_entropy_lines_empty_mem_map_no_crash PASSED [ 87%]
tests/test_report_service.py::test_include_entropy_default_true_and_validated PASSED [ 90%]
tests/test_report_service.py::test_include_entropy_false_not_emitted PASSED [ 93%]
tests/test_report_service.py::test_entropy_section_charged_against_budget PASSED [ 96%]
tests/test_report_service.py::test_entropy_section_confidentiality_no_raw_bytes_or_logging PASSED [100%]

============================= 33 passed in 1.64s ==============================
```

Inc-1 regression + frozen guard:
```
tests/test_entropy_service.py  →  14 passed in 1.05s
tests/test_engine_unchanged.py →   1 passed in 0.06s
```

### 4c. Test → TC/AT + LLR map

| Test | TC/AT | LLR |
|---|---|---|
| `test_report_contains_entropy_section_on_disk` | AT-037a (C-12 GATE) | LLR-037.2 + 037.3 |
| `test_report_omits_entropy_when_disabled_byte_identical` | AT-037b (branch-completeness) | LLR-037.3 |
| `test_entropy_lines_shape_direct_call` | TC-037.1 (GUARD, not gate) | LLR-037.2 |
| `test_entropy_lines_empty_mem_map_no_crash` | TC-037.1 edge | LLR-037.2 |
| `test_include_entropy_default_true_and_validated` | TC-037.2 | LLR-037.1 |
| `test_include_entropy_false_not_emitted` | TC-037.2 | LLR-037.1/037.3 |
| `test_entropy_section_charged_against_budget` | TC-037.3 | LLR-037.3 (`emit()` budget) |
| `test_entropy_section_confidentiality_no_raw_bytes_or_logging` | TC-037.4 | LLR-037.2 (confidentiality) |

## 5. Risks

- **R-2 (report byte-budget):** mitigated as designed — the section is band-summary only (O(bands), ≤4 bullets + heading), routed through `emit()` so it is charged against `_ByteBudget`. TC-037.3 asserts the size increase (proves it lands in the budgeted line list).
- **AT-037b counterfactual caveat (spec-acknowledged):** the `include_entropy=False` branch passes trivially on the pre-fix tree (no section either way), so the US-037 counterfactual is carried by AT-037a alone. AT-037b is the branch-completeness / byte-identical assert — implemented as exact byte-equality between two disabled generations (fixed clock + fixed filename), and it positively asserts the section IS present when enabled, so it is not vacuous.
- **`_entropy_lines` band-summary format is a NEW contract** consumed only by the report; US-036 (modal) will consume `compute_entropy` directly, not `_entropy_lines`, so no cross-surface coupling risk.

## 6. Pending items

- US-036 (entropy viewer modal) — separate increment, NOT this scope.
- REQUIREMENTS.md §-entry for HLR-037 status promotion — Phase-4 reconciliation (per batch convention, not this increment).
- AT/TC id reconciliation in `01b-validation-strategy.md` §8 results table — Phase 4.

## 7. Suggested next task

Increment 3 — US-036 entropy viewer modal (LLR-036.1..036.6): `EntropyViewerScreen(ModalScreen[None])` + `ENTROPY_BAND_COLOUR` map + `action_show_entropy`/`e` binding + strip/jump cost caps, with the measured 48/76 geometry and Pilot ATs. Larger surface (screens.py + app.py + styles.tcss) — likely its own multi-file increment.

---

## Evidence checklist

- [✓] Tests/type checks/lint pass — ruff `All checks passed!`; 33 report + 14 entropy + 1 frozen-guard all PASS (§4).
- [✓] No secrets in code or output — synthetic byte patterns (`0x00` / 0..255 permutation) only; no operator firmware.
- [✓] No destructive commands run without approval — read/edit/pytest/ruff only; RED-capture edit was reverted.
- [✓] File count within cap — 2 files edited (`report_service.py`, `test_report_service.py`), ≤5.
- [✓] Review packet attached — this document.
- [✓] Engine-frozen set unchanged — `test_engine_unchanged.py` PASS; `git status` shows only non-frozen files.
- [✓] Counterfactual captured — AT-037a RED (emission stubbed) → GREEN (wired), §4a/4b.

---

## Post-gate folds

### F2 — strengthen AT-037b to a non-vacuous byte-identical assert

**What changed (tests only; `tests/test_report_service.py`, 1 file).** The prior `test_report_omits_entropy_when_disabled_byte_identical` (AT-037b) generated TWO reports both with `include_entropy=False` and asserted they were byte-equal — this only proved off-branch *determinism*, not the spec (LLR-037.3 / §01b AT-037b): that the `include_entropy=False` report reproduces the pre-feature bytes and the flag suppresses ONLY entropy with zero incidental drift. Strengthened per §01b §2 AT-037b.

**New load-bearing assert.** Generate the SAME fixture report once with `include_entropy=True` (`on_bytes`) and once `False` (`off_bytes`). Take the exact block the shipped builder emits — `report_service._entropy_lines(result)` joined with the file's actual newline — remove exactly that block (with its one leading separator) from the ON report, and assert the remainder equals the OFF report byte-for-byte:

```python
newline = "\r\n" if b"\r\n" in on_bytes else "\n"
entropy_block = newline.join(report_service._entropy_lines(result))
assert entropy_block in on_text                       # precise block, not a fuzzy heading match
on_minus_block = on_text.replace(newline + entropy_block, "", 1)
assert on_minus_block == off_text                     # LOAD-BEARING: flag adds ONLY the block, zero drift
```

This proves the ONLY difference the flag makes is the entropy block — the off-branch adds no drift in any surrounding section. Kept the present/absent discrimination asserts and the two-disabled-generations determinism guard (`off_bytes == reference_bytes`). Label `AT-037b` and the branch-completeness comment preserved. Reused the shipped `_entropy_lines` output rather than hand-parsing headings, so the block match stays precise (not `in`/"plausible"). One correctness detail surfaced while authoring: the report writes with the platform newline (CRLF on Windows), so the block is matched to the on-disk bytes rather than assuming `\n`.

**Real result.** `pytest tests/test_report_service.py -v` → **33 passed** (incl. strengthened AT-037b); `pytest ...::test_report_omits_entropy_when_disabled_byte_identical -v` → **1 passed**. `ruff check tests/test_report_service.py` → **All checks passed!**. Only `test_report_service.py` touched; `report_service.py` and all other files unchanged.
