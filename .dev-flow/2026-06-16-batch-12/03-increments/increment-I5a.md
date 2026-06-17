# Increment I5a — CRC inject + emit modified S19 + verify (headless)

**LLRs:** LLR-003.1 (inject 4-byte LE into a copy, extend on gap), LLR-003.2 (emit + contained write), LLR-003.3 (reader-as-oracle verify), re-scoped LLR-003.5 (write result record). **TCs:** TC-121/122/123/124-headless/126 + containment. **Headless** — the two-stage confirmation gating is I5b. **First write-to-disk surface → security-reviewer sign-off (CLEAN).**

## 1. What changed
Added the side-effectful CRC write mechanics to `crc.py` as pure functions (write only when called):
- `inject_crcs(op_input, crc_regions)` — builds a WORKING COPY of mem_map/ranges, writes each computed CRC as 4 LE bytes at its output address; on a gapped output extends the copy by exactly 4 keys + a sorted/non-overlapping covering range (`_extend_ranges`, D-6/F-A-06). Original snapshot never mutated.
- `write_crc_image(op_input, config, *, workarea_base, dest_dir=None)` — `check_regions` → `inject_crcs` → `emit_s19_from_mem_map` → stage under `.s19tool/workarea/temp/` → place via `copy_into_workarea` (real containment seam: `_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point`, resolved-path; size cap; name-dedup, no overwrite) → `verify_written_image` against the INJECTED map (F-Q-05). Default output dir `.s19tool/workarea/crc/` (sibling of temp/ staging). Any path/IO/containment fault → 1 collected finding, no file (collect-don't-abort; staged temp always unlinked in `finally`).
- `CrcWriteResult` — headless carrier (crc_regions written=True, written_path, verify_status, verify_runs, findings); I5b assembles it into an `OperationResult`. No operator-arbitrary path; file name always `<stem>-crc.s19`.

## 2. Files modified (2)
- `s19_app/tui/operations/crc.py` (EDIT — inject/emit/verify functions + carrier + helpers)
- `tests/test_crc_operation.py` (EDIT — 6 new write tests)

## 3. How to test
```
python -m pytest -q tests/test_crc_operation.py tests/test_crc_engine.py tests/test_crc_config.py
python -m pytest -q -m "not slow"
ruff check s19_app/tui/operations/crc.py tests/test_crc_operation.py
```

## 4. Test results
- `tests/test_crc_operation.py`: 12 passed (6 new write tests + the I2/I3a check/execute tests).
- `pytest -q -m "not slow"`: **824 passed**, 29 skipped, 3 xfailed (exit 0) — orchestrator re-ran (244s).
- ruff clean. **Ledger: 818→824 (+6: TC-121/122/123/124-headless/126 + containment); collection 871→877.** Frozen guards green.

## 5. Independent reviews
- **security-reviewer (MANDATORY — this is the write path): CLEAN, OK to ship.** All 4 gate questions pass: (a) contained via the REAL `copy_into_workarea` resolved-path seam (not string-prefix); (b) no escape — absolute `dest_dir`/`..`/symlink/junction all fail the seam → finding + 0 files; `output_address` is only ever a memory address, never a path; (c) original image immutable (fresh dict/list); (d) collect-don't-abort holds, staged temp always unlinked, no leak. 1 LOW (F-S-06): `emit_s19_from_mem_map` sat just outside the try (hypothetical KeyError, unreachable by construction) — **FOLDED**: emit moved inside the try, `KeyError` caught, message generalized; the containment test now asserts the exception-class name. No blocker/major.
- **code-reviewer: OK to advance, 0 HIGH/MEDIUM.** All 4 rule-ons pass: inject LE-correct + original immutable; `_extend_ranges` sorted-merge correct by construction (adjacent/gap/straddle/duplicate/contained edge cases verified — RK-6 closed not via the order-insensitive oracle but by the invariant); verify uses the injected map (genuine disk-reread, not self-compare); tests non-vacuous (TC-123 corrupted-write negative control; TC-122 asserts sorted+non-overlapping invariant; containment test drives the real seam). 2 LOW: F1 (`verify_runs: List[object]` — left; `DiffRun` not a simple public export, reviewer said List[object] fine to keep) + F2 (per-region index rebuild — intentional/required, left).

## 6. Risks
- F2: the in-loop `build_sorted_range_index` rebuild is REQUIRED (a prior region's extension must be visible to a later region) — do not "optimize" to a single hoisted build (correctness regression). Noted to forestall.
- Default `crc/` output dir is the dev's choice (both temp/ and crc/ are inside the workarea root, containment unchanged); confirm in I5b as the on-disk location.

## 7. Pending / next
- **I5b** — TUI confirm modal (two-stage: after check, operator confirms write) + worker + assemble `CrcWriteResult` → `OperationResult` (status/notes/crc_regions written=True + emitted path + verdict) + render. `screens.py`/`app.py`/`tests/test_tui_crc_surface.py`. TC-124 confirmation half (decline → 0 files) + TC-125 (inject reaches surface via handler, pilot-driven). security-reviewer already cleared the write mechanics; I5b adds the R-6 confirmation gate.
- New TC ids reconcile into §5.2 at Phase 4 (V-5).
