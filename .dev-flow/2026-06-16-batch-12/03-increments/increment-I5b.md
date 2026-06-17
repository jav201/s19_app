# Increment I5b — TUI two-stage confirmation + write surface (LAST impl increment)

**LLRs:** LLR-003.4 (two-stage confirm — NO write without confirmation), re-scoped LLR-003.5 (write `OperationResult` = emitted path + `written=True` + verdict, rendered). **TCs:** TC-124 (decline→0 files / confirm→1 file), TC-125 (write outcome reaches surface via handler). **Phase 3 COMPLETE after this.**

## 1. What changed
Wired the I5a headless write mechanics into the TUI as the operator-confirmed write. `OperationsScreen` gains a `ConfirmWriteScreen(ModalScreen[bool])` (Confirm/Cancel) and a "Write CRC" button — disabled by default, hidden for non-crc ops, enabled only after a real check lands `crc_regions`. Press → confirm modal (the FR9 stage-2 gate). On decline/dismiss(None) → NO write, 0 files. On confirm → re-parse the config TextArea (honors edits; parse error → no write) → run `write_crc_image(op_input, config, workarea_base=self.app.base_dir)` on a `@work(thread=True, exclusive=True, group="crc_write")` worker, guarded by a SECOND dispatch token (`_crc_write_token`, mirroring the I3b fix) → assemble an `OperationResult(status="ok")` → render the write outcome. F-L1 three-way: verified → "wrote … (verified)"; mismatch → "VERIFY MISMATCH"; written_path None/findings → "WRITE FAILED" + finding. No headless `crc.py` code changed (call-only).

## 2. Files modified (2)
- `s19_app/tui/screens.py` (EDIT — `ConfirmWriteScreen`, Write button + gating, `_on_write_pressed`/`_on_confirm_write`/`_run_crc_write_worker`/`_present_write_result`, write-token guard, F1 write-oriented region rows)
- `tests/test_tui_crc_surface.py` (EDIT — TC-124, TC-125 + helpers; TC-125 strengthened for F1)

## 3. How to test
```
python -m pytest -q tests/test_tui_crc_surface.py tests/test_tui_operations_view.py tests/test_crc_operation.py
python -m pytest -q -m "not slow"
ruff check s19_app/tui/screens.py tests/test_tui_crc_surface.py
```

## 4. Test results
- `tests/test_tui_crc_surface.py`: 6 passed (4 prior + TC-124 + TC-125).
- `pytest -q -m "not slow"`: **826 passed**, 29 skipped, 3 xfailed (exit 0) — orchestrator re-ran (232s).
- ruff clean. **Ledger: 824→826 (+2: TC-124/125); collection 877→879.** Frozen guards green.

## 5. Independent review (code-reviewer) — OK, 0 HIGH; 1 MEDIUM fixed
Ruled: (a) **NO-write-without-confirmation is AIRTIGHT** — mutation-tested (removing the decline guard makes TC-124 emit a file → fails); the only caller of `write_crc_image` is reachable only via the confirm callback with `True`; Cancel AND modal-dismiss(None) both write nothing. (b) **write-token guard SOUND** — independent `_crc_write_token` + `crc_write` group, bumped on dispatch/decline/config-error, stale results dropped; no interference with the check worker. (c) **F-L1 distinction** — prefixes mutually exclusive; a failure/mismatch cannot read as a clean pass; WRITE-FAILED leaves prior check hex but the status line leads unambiguously.
- **F1 (MEDIUM, FIXED):** on a VERIFIED corrective write the per-region rows reused the check verdict and printed a STALE "MISMATCH" beside "(verified)" (inverse F-L1 ambiguity — `inject_crcs` carries forward pre-write `matched`). Fixed: the written path now renders write-oriented rows (`region @ 0x…: wrote 0x… (4 LE bytes)`); the check verdict (`_crc_region_lines`) is kept ONLY for WRITE FAILED. TC-125 strengthened (fixture has a mismatching stored value → asserts the verified-write surface contains "(4 LE bytes)" and NO "MISMATCH").
- F2 (LOW, left): the hex pane re-derives the injected image via a 2nd `inject_crcs` (deterministic; acceptable, flagged for a possible later "worker returns the injected map" follow-up).
- Security: nothing new — write mechanics/containment signed off in I5a; the I5b confirmation gate is airtight.

## 6. Integrity note (handled)
During mutation-testing the code-reviewer ran a `git checkout` that discarded the uncommitted `screens.py` edits, then reconstructed the file from its captured diff. **Orchestrator verified working-tree integrity:** `git status` shows only `screens.py` + `test_tui_crc_surface.py` modified (the I5b files); committed `crc.py`/`crc_config.py` intact; all I5b symbols + TC-124/125 present; lean 826 green. Reconstruction is clean.

## 7. Pending / next
- **Phase 3 COMPLETE** (I1a/I1b/I2/I3a/I3b/I5a/I5b; 7 increments; I4 withdrawn). Suite 879 collected / 826 lean / 0 failures; full suite to be measured at Phase 4.
- **Phase 4 (validation)** next: qa-reviewer runs the per-requirement matrix + reconciles the Phase-3 TC ids into §5.2 (V-5), the surface-reachability matrix, full-suite run. Then Phase 5 (post-mortem) → 6 (docs) → close/PR/CI/merge/sync.
- A2L not in scope; CLI deferred (TUI-only); RK-3 non-default-vector residual stays "assumed" (operator fixture).
