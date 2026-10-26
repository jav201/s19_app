# HANDOFF — batch-99 Increment 4 review fixes (code-reviewer F1–F7) — worktree s19_app-b99-inc4

## What is done

- **F1 [HIGH]** — `save_patched` (`s19_app/tui/services/change_service.py`) now runs
  the SAME collision refresh as `apply` before the save re-derive, and refuses a
  blocked document: nothing is written, `message` names the blocked count
  ("Patched image not saved - N entries blocked - see issues"), `issues` carry the
  `CHG-COLLISION` findings. New arm `test_tc_b99_22_save_blocks_overlapping_entries`
  runs the reviewer's exact probe (add `0xEB10`, apply, add `0xEB12`, SAVE — no apply
  after the overlapping add). Mutation (skip the refresh) KILLED — `mut-F1.txt`
  reproduces the probe symptom (`ok=True`, both entries listed). Honesty note: the
  arm's first RED was a `NameError` (test import) and its first structure was
  VACUOUS (the premise apply stamped the collision, masking the save's missing
  refresh) — restructured and proven load-bearing.
- **F2 [HIGH]** — `source_image_view` returns `mem_map` unchanged when it is not the
  bound dict (`mem_map is not self._image_map`) and rebinds via `_note_image`, so the
  journal resets onto the new map at the strip refresh. New arm
  `test_tc_b99_40_strip_shows_new_file_source_byte`: load A, apply, load B — the
  strip's `was` line shows B's `99 98 97 96`, never A's `20 41 70 70` (RED on the
  round-1 tree reproduced the defect verbatim).
- **F3 [MEDIUM]** — AT-B99-08 extended: a third entry (`0xEB60 05 06`) is added
  WITHOUT an apply before the save; the painted status must name it with the
  singular "1 entry" count (pilot widened to 160 columns so the width-aware log cap
  `max(50, width)` paints the two-clause line untrimmed). Mutation (drop the names)
  KILLED — `mut-F3.txt`.
- **F4 [MEDIUM]** — the 3 wrong packet digests corrected from the stored bytes
  (transposed characters; `green-address-census` was 63 digits); every digest in the
  packet re-verified programmatically against the evidence files (21/21 OK);
  `SHA256SUMS.txt` regenerated.
- **F5 [MEDIUM]** — `_surface_verify_result` (`s19_app/tui/app.py`) composes the
  SAME `save_back_status_suffix` on the `mismatch` arm (UX-C6 allows no exception).
  New arm `test_at_b99_08_verify_mismatch_status_still_names_entries` forces a
  verify mismatch (patches `change_service.verify_written_image`; the pilot itself
  stays black-box). The round-1 §5 mismatch scope cut is rescinded in the packet.
- **F6 [MEDIUM]** — `test_tc_b99_40a_strip_shows_source_byte` renamed
  `test_tc_b99_40_strip_shows_source_byte`; all packet references updated (the only
  remaining `40a` in the repo is the unrelated pre-existing `AT-040a` in
  `test_tui_directionb.py`).
- **F7 [LOW]** — the "pass deterministically in isolation" claim corrected: the
  packet's own `green-flake-isolation.txt` shows `test_at077c_stale_provenance`
  FAILING in isolation — it is flaky on main, not bound to this increment.
- SOURCE budget unchanged: 2 of 3 files (`change_service.py`, `app.py`); tests
  uncapped. Both source files + the test file pure CRLF, syntax-checked. No commit.

## Verification

- RED-first of the fix round: `red-fix-round.txt` — 4 failed / 4 passed on the
  round-1 tree (the 4 new/extended nodes failed on their oracles).
- GREEN: `green-fix-round.txt` — 8 passed. AT-B99-08 driven 8 times:
  `green-at_b99_08-x8.txt` — 8/8 runs "2 passed, 6 deselected".
- Mutations: the 4 round-1 mutations re-run + F1 + F3 — 6/6 KILLED, each reverted
  by SHA-256 to the refreshed `fixed-tree-hashes.txt`; no mutant left in place.
- Round-2 reverse census (32 files): 586 passed, 5 failed (`green-regression.txt`)
  — the pre-existing `test_at031b…` (red at the batch baseline) + 4 load-flakes
  (`test_save_back_prompt` flakes 3/6 SOLO on the base `9d7fb18`;
  `test_verify_quiet_pass…`, `test_at068b…`, `test_ac2_1…` — the 4-test combination
  flaked on base too; each passes solo on the fixed tree). None asserts an
  HLR-157 behaviour; no re-pins.
- `tests/test_address_census.py` — 23 passed (`green-address-census.txt`).
- Packet `.dev-flow/2026-10-25-batch-99/03-increments/increment-004.md` updated:
  "Review round 1 fixes" subsection (F1–F7 with evidence), corrected digests, F7
  claim, node renames, 8-node ledger; §4b left `pending — orchestrator`.

## What is left

- §4b independent review of the fixes (orchestrator).
- The orchestrator's full-suite run owns the pre-existing/flaky failures bound above.
- The full suite (~2 h 20) was NOT run here, per the brief.

__KIMI_UNIT_DONE__

Files changed: 2 SOURCE (change_service.py — save collision refresh + blocked-refusal gate + source_image_view binding guard; app.py — mismatch-arm naming suffix + docstrings) + 1 test (test_b99_editor_image.py, 8 nodes).
Tests added: 3 new nodes (test_tc_b99_22_save_blocks_overlapping_entries, test_tc_b99_40_strip_shows_new_file_source_byte, test_at_b99_08_verify_mismatch_status_still_names_entries) + AT-B99-08 extended (add-without-apply step) + 1 rename (F6).
RED/GREEN: fix-round RED 4/4 new-extended nodes on the round-1 tree; GREEN 8/8 file, AT ×8 all green, census 586 passed, address census 23 passed.
Mutations: 6 run (157.1, 157.1-alias, 157.2, 157.4 re-run + F1, F3 new) — all KILLED, all reverted by SHA-256.
Open questions: none blocking; round-2 census failures shown pre-existing/flaky on base 9d7fb18 and bound in the packet.
