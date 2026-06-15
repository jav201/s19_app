# Increment I2 — verify-on-save ENGINE (HLR-003)

Batch 2026-06-13-batch-10 · branch `claude/batch-10` · Phase 3 · 2026-06-14

Implements HLR-003 (LLR-003.1 helper + parser dispatch, LLR-003.2 diff +
classification). Engine only — the save-back WIRING (LLR-003.3, carrier onto
`ChangeService.last_summary`) and the TUI surfacing (HLR-004) are deferred to
I3/I4 per the spec increment plan.

## 1. What changed
Added a dedicated headless verify-on-save helper module
`s19_app/tui/changes/verify.py` exposing `verify_written_image(written_path,
intended_mem_map, file_type) -> VerifyResult` plus the `VerifyResult` dataclass
and the `STATUS_VERIFIED`/`STATUS_MISMATCH` tokens. The helper re-reads the
just-written file with the parser matching `file_type` (`IntelHexFile` for
`"hex"`, `S19File` for `"s19"`), builds the re-read memory map, diffs it against
the intended map with `compare.diff_mem_maps(intended, reread)` (A=intended so a
dropped byte classifies `only_a`), and returns `verified` on an empty diff /
`mismatch` (carrying runs + stats + the written path) otherwise. Added
`tests/test_verify_on_save.py` covering identity / mutation / drop fault models
across BOTH file types plus two guard tests. No engine, parser, io, apply,
change_service, or TUI file touched.

## 2. Files modified
- `s19_app/tui/changes/verify.py` (NEW, 196 lines) — `verify_written_image` +
  `_reread_mem_map` (private parser dispatch) + `VerifyResult` dataclass +
  `STATUS_VERIFIED`/`STATUS_MISMATCH`. Headless (stdlib + compare/core/hexfile
  imports only).
- `tests/test_verify_on_save.py` (NEW, 161 lines) — 8 test nodes (3 fault
  models × 2 file_types + 2 guards). Module docstring maps test→TC→LLR;
  element-style thresholds (`len(runs)==1 and runs[0].kind==... and
  runs[0].length==1`).

`__init__.py` re-export facade was intentionally NOT touched — see §6.

## 3. How to test
```
python -m pytest -q tests/test_verify_on_save.py          # new TCs
python -m pytest -q tests/test_hex_emit.py                # I1 regression
python -m pytest -q tests/test_engine_unchanged.py        # engine-frozen guard
python -m pytest -q -m "not slow"                         # lean suite
python -m pytest -q --collect-only | tail -1              # collection count
rg -n "import textual|from textual" s19_app/tui/changes/verify.py   # purity P-2
```

## 4. Test results (actual)
| Check | Command | Result |
|---|---|---|
| 1. New TCs | `pytest -q tests/test_verify_on_save.py` | **8 passed** |
| 2. I1 regression | `pytest -q tests/test_hex_emit.py` | **10 passed** |
| 3. Lean suite | `pytest -q -m "not slow"` | **747 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed** (221.5 s) |
| 4. Collection | `pytest -q --collect-only` | **800 tests collected** (was 792) |
| 5. Purity P-2 | `rg "import textual\|from textual" verify.py` | **0 matches** |
| 6. Engine-frozen | `pytest -q tests/test_engine_unchanged.py` | **1 passed** |

Ledger: pre-state 739 passed / 792 collected → post 747 passed / 800 collected.
Signed balance: `800 == 792 − 0 + 8` (D=0, N_new=8, all additive). Lean
pass-count balance: `747 == 739 + 8`, 0 regressions.

### 7. A-3 / V-5 node-id drift
Provisional spec ids (§5.2) vs actual node ids:

| Spec provisional | Actual node id |
|---|---|
| TC-008 (LLR-003.1 parser selection + purity) | `tests/test_verify_on_save.py::test_identity_write_is_verified[hex]` / `[s19]` |
| TC-009 (LLR-003.2 diff + classify) | `::test_mutated_byte_is_mismatch_changed[hex]` / `[s19]` ; `::test_dropped_byte_is_mismatch_only_a[hex]` / `[s19]` |
| (guard, LLR-003.1) | `::test_unsupported_file_type_raises` |
| (guard, C-10 carrier) | `::test_written_path_is_stamped` |

Drift recorded (loud):
- **Test FILE path matches spec** (`tests/test_verify_on_save.py`).
- **Node ids differ from the provisional TC-008/009/010 naming** — actual ids
  are behavior-descriptive and parametrized by `file_type`, not `TC-0NN`.
  Expected per V-5 (ids provisional until Phase 3). The docstring carries the
  test→TC→LLR map for traceability.
- **TC numbering nuance:** my orchestrator brief used a different provisional
  triple (TC-006/007/008) than the spec §5.2 (TC-008/009/010). Both are
  provisional; the docstring uses the brief's TC-006/007/008. Recorded here so
  the Phase-3 coverage reconciliation can pin one scheme. No behavioral impact.
- **LLR-003.3 (integration wiring) has NO test here** — deferred to I3 by
  design; its `test_changes_apply.py -k verify_on_save` nodes are an I3
  deliverable.

## 5. Risks
- **R-10-PURITY (MEDIUM → mitigated):** verify.py is reachable from
  `change_service` once wired (I3). Probe P-2 = 0 matches now; the static
  import-graph guard (`test_no_textual_in_static_import_graph`) is not yet
  exercising verify.py because nothing reachable imports it yet — it will be
  walked once I3 wires it. The module imports only `compare`/`core`/`hexfile`
  (all stdlib-transitive, headless), so the future walk is expected GREEN.
- **Fault-model direction (LOW):** the drop test plants the fault at the range
  boundary (`max(_INTENDED)`) so it isolates as one `only_a` run; a mid-range
  drop would split the neighbouring run and still be `only_a` runs but a
  different count. The boundary choice is deliberate and documented in the test.
- **File-type domain (LOW):** `_reread_mem_map` raises `ValueError` on any
  `file_type` other than `"hex"`/`"s19"` (e.g. `"mac"`). This is the intended
  contract (save-back only verifies formats it can write); a caller passing an
  unsupported type is a programming error, not a data fault.

## 6. Pending items
- **G-3 facade re-export deferred:** `s19_app/tui/changes/__init__.py` re-exports
  every public package symbol. `verify_written_image` / `VerifyResult` are NOT
  yet added to it — deferred to I3, where the consumer (`change_service`) wires
  the helper and the facade export becomes load-bearing. Kept this increment at
  2 files (surgical) rather than touching the shared facade prematurely. I3 must
  add the two symbols to `__init__.py`'s imports + `__all__`.
- **LLR-003.3 wiring** (save-back handler calls `verify_written_image`, stamps
  `VerifyResult` onto `ChangeService.last_summary`, collect-don't-abort) — I3.
- **HLR-004 surfacing** (quiet pass / loud mismatch) — I4.

## 7. Suggested next task
**I3 — HEX save-back + retire refusal + verify wiring (HLR-002 + LLR-003.3).**
Add the HEX branch to `save_patched_image` (apply.py) with the parametric
`suffix` sanitizer, retire `CHG-HEX-SAVE-UNSUPPORTED` for `"hex"` sources, and
wire `verify_written_image` post-save in `change_service.py` stamping the
`VerifyResult` onto `last_summary` (back-compatible C-10 carrier — 2-tuple
return UNCHANGED). Add the facade re-export of `verify_written_image` /
`VerifyResult` to `changes/__init__.py` in that increment. Tests:
`test_changes_apply.py` (hex_save, verify_on_save), `test_change_service.py`
(hex_suffix). Watch the engine-frozen guards (apply.py is NOT frozen; io.py NOT
frozen) and the static-import-graph purity guard once verify.py joins the
reachable graph.

---

### Boundary / deviation notes (loud)
- **G-3 resolved to a NEW module** (`tui/changes/verify.py`), NOT `apply.py`.
  My brief instructed STOP-and-report if LLR-003.1 placed the helper in an
  existing high-blast-radius file; the spec left G-3 open (new module OR
  apply.py) and the brief directed the dedicated-helper option, so no stop
  condition was hit. apply.py was NOT touched.
- **No frozen module touched** (verified: `test_engine_unchanged.py` green;
  edits confined to a NEW non-frozen, non-package-root module + a NEW test).
- **Collection baseline:** spec §5.3 cites 782 (pre-I1); actual pre-I2 was 792
  (I1 added 10) → post-I2 800. Consistent.
