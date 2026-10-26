# HANDOFF — batch-99 Increment 4 (HLR-157, US-146) — worktree s19_app-b99-inc4

## What is done

- **Requirement**: HLR-157 / LLR-157.1 / LLR-157.2 / LLR-157.4 (LLR-157.3
  retired) + PDR condition UX-C6, per `.dev-flow/2026-10-25-batch-99/kimi/
  BRIEF-inc-4.md` and `BRIEF-COMMON.md`.
- **SOURCE (2 of 3)**: `s19_app/tui/services/change_service.py` (editor-image
  journal with in-place restore; save re-derivation; applied-set naming;
  `save_back_status_suffix`; `_SourceOverlayMap` / `source_image_view`),
  `s19_app/tui/app.py` (UX-C6 verify-suffixed final status; `_strip_source_map`
  at the 4 strip push sites; save-back passes mac/a2l for re-derived linkage).
  `tui/changes/apply.py` untouched, as the brief predicted. Both files CRLF,
  syntax-checked, hashes recorded (`evidence/inc-4/fixed-tree-hashes.txt`).
- **Tests**: `tests/test_b99_editor_image.py` (new, CRLF) — TC-B99-21
  (p05 + alias + all-undone + overlap arms), TC-B99-22 (remove/edit/add/redo
  arms), TC-B99-40 (summary + before/after report), TC-B99-40a (strip),
  AT-B99-08 (full pilot, independent-reader oracle, UX-C6 status).
- **RED first**: all 5 nodes FAILED on the unmodified tree on their exact
  oracles (`evidence/inc-4/red-initial.txt`; AT reproduces P-6 `deadbeef`).
- **GREEN**: new file 5 passed; per-`-k` transcripts; 30 reverse-census files
  570 passed; `tests/test_address_census.py` 23 passed.
- **Mutations (C-40)**: 4 applied, all KILLED, all reverted by hash —
  skip-restore (TC-21 RED), rebind-restore alias arm (TC-21 RED at the alias
  assertion), skip save re-derive (TC-22 RED at the remove arm), capture-after-
  write before_bytes (TC-40 + TC-40a RED).
- **Reverse census**: 28 files probed, 0 re-pins; `test_at031b_two_saves_
  distinct_no_clobber` is pre-existing (red in `baseline-pytest-a293213.txt`);
  4 pilot timing flakes pass in isolation and touch no HLR-157 assertion.
- **Packet**: `.dev-flow/2026-10-25-batch-99/03-increments/increment-004.md`
  filled (§1-§7, §4b `pending — orchestrator`); 16 evidence artifacts with
  SHA-256 + `SHA256SUMS.txt`.
- No commit made (orchestrator commits). Worktree import proven:
  `python -c "import s19_app; print(s19_app.__file__)"` →
  `C:\Users\jjgh8\Github\s19_app-b99-inc4\s19_app\__init__.py`.

## Declared interpretation (also in packet §6)

The brief's "reset the journal when … the document is replaced (Load)" is
implemented as "a new image file loaded" (dict-identity reset at the next
apply/save via `_note_image`): the journal deliberately survives
change-document load/replace because it records SOURCE bytes of the loaded
image; dropping it re-introduces the P-6 stale-byte defect across a document
reload.

## What is left

- §4b independent review (orchestrator spawns the code-reviewer).
- The orchestrator's full-suite run owns the pre-existing `test_at031b`
  failure and the 4 bound flakes.
- The full suite (~2 h 20) was NOT run here, per the brief.

__KIMI_UNIT_DONE__

Files changed: 2 SOURCE (change_service.py, app.py) + 1 test (test_b99_editor_image.py); apply.py untouched as predicted.
Tests added: 5 nodes (TC-B99-21/22/40/40a + AT-B99-08) in tests/test_b99_editor_image.py.
RED/GREEN: RED 5/5 on the unmodified tree (red-initial.txt); GREEN 5/5 new file, 570 census files passed, address census 23 passed.
Mutations: 4 run (157.1 skip-restore, 157.1-alias rebind, 157.2 skip-re-derive, 157.4 capture-after-write) — all KILLED, all reverted by SHA-256.
Open questions: none blocking; UX-C6 closed on the verified arm only (mismatch arm keeps its old line, declared in packet §5).
