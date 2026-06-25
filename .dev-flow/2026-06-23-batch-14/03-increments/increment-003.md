# Increment 3 (FINAL) — Selector UI + S0 policy + C3 pilot AT (US-015)

**Batch:** 2026-06-23-batch-14 · **Branch:** claude/batch-14-us015 · **Status:** awaiting gate · **Not committed.**
**LLR:** LLR-015.3 (UI half). **Dispositions closed:** C3 (black-box pilot AT), F1 (app.py caller now threads both params), C2 (CRC inherits default — no code).

## 1. What changed
Wired the operator's {16,32} choice end-to-end through the Patch Editor save-back surface: a cycling **Width selector** (default 32, mirrors `#patch_execute_scope_button`) rides the `SaveBackDecision` message; the handler applies the **preserve/synthesize S0 policy** (32 → preserve `LoadedFile.source_s0_header` else synth-from-filename ≤252 ASCII; 16 → empty S0) and threads `bytes_per_line`+`s0_header` to `save_patched`. **C3 black-box pilots** drive the real selector + Write button via `run_test` and read the written `.s19` off disk.

## 2. Files modified (3; ≤5)
- `s19_app/tui/screens_directionb.py` — `SAVEBACK_WIDTHS=(32,16)`, `_saveback_width` (default 32, reset-on-show), width button, `bytes_per_line` additive on `SaveBackDecision`.
- `s19_app/tui/app.py` — `_synth_s0_header_from_filename` (`_SAVEBACK_S0_MAX_BYTES=252`); save-back handler reads `event.bytes_per_line`, applies S0 policy, threads both params (closes F1).
- `tests/test_tui_patch_editor_v2.py` — AT-015.1 (32-mode) + AT-015.3 (16-mode) pilots, on-disk via frozen `S19File`.

## 3. How to test
`pytest tests/test_tui_patch_editor_v2.py -q` · `pytest -q -m "not slow"` · `pytest tests/test_engine_unchanged.py -q` · `ruff check <changed>`.

## 4. Test results
New pilots **2 passed**; patch-editor file **15 passed** (+2); full regression `-m "not slow"` **868 passed / 0 failed**; engine guard 1 passed (0 frozen diffs). Ledger **919 → 921 (+2)**. Spot-check: diff = 3 files (0 frozen); pilots on disk; selector wired; app.py ruff = 6 pre-existing (C-7), 0 introduced.

## 5. Independent review + carries to Phase 4
code-reviewer: **APPROVE-WITH-NITS** (0 HIGH / 0 MED / 3 LOW). C3 pilot genuine black-box = YES (the AT pair observes the real surface → on-disk file, no stub). **Phase-4 hardening (binding):**
- **F1** — AT-015.1 (32-mode) asserts on the *default* selector value (0 presses); AT-015.3 (16-mode) carries the discriminating load. Phase 4: tighten AT-015.1 to cycle the selector off 32 and back so the press path is exercised.
- **F2** — the genuine *preserve* leg (non-empty source S0 → disk) is unit-tested at the load seam (`test_build_loaded_s19_captures_source_s0_header`) but not observed black-box. Phase 4: add a preserve-leg AT (load image with a content-bearing S0, assert the written S0 == source bytes, not the filename). Also document the "empty source S0 → synthesize" semantics.
- **F3** — trim the `_data_record_map` comment (cosmetic).
No security surface (write via the Inc2-secured sanitizer path).

## 6. Phase-3 complete (on approval)
3 increments: Inc1 (emitter+S0 data) / Inc2 (backend threading) / Inc3 (selector UI + policy + pilot). Ledger **903 → 921 (+18)**. 0 frozen edits across all three. US-015 end-to-end: operator picks 16/32 at save → 32 emits ≤32-byte records + populated S0 (preserve-or-synthesize), re-parses byte-equal on the data-record map; 16 preserves legacy framing.

## Gate
0 HIGH; awaiting operator approval to commit Inc3 → Phase 3 complete → advance to Phase 4 (validation, with F1/F2/F3 as binding hardening).
