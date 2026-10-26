# Kimi brief — batch-100 Increment 1 · one placement function, reuse, containment

Read `BRIEF-COMMON.md` first. The orchestrator gives you the worktree path and the base commit when it launches you. The packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-001.md`, already seeded with its header filled.

**Design:** `design/design-proposal-b100.md` §5.1 is the authority for this increment. The contract is `01-requirements.md`: HLR-163, LLR-163.1 to LLR-163.7, and LLR-171.4's guard clause (the guard ships here; its seam and listing uses come at Inc 7 and 8b). Interfaces frozen before this increment: B100-I6 (as amended), I13, I14 and I22 in `docs/architecture.md` §11.

**SOURCE files (3):** `s19_app/tui/workspace.py`, `s19_app/tui/segment_split_view.py`, `s19_app/tui/app.py`. Nothing else under `s19_app/`.

**What to build** (summary only; §5.1 governs):
- `find_identical` in `workspace.py`.
  - It lists the destination once and keeps `<name>` and `<stem>_<digits><suffix>`, case-folded on Windows.
  - It compares sizes before reading any bytes.
  - It never reuses links, reparse points or 0-byte files.
- `place_into_workarea(...) -> PlacementResult(path, reused)` owns every guard, in this order:
  - source and destination reparse checks;
  - `contained_in_workarea(destination, workarea)`, meaning THIS work area, resolved, with junctions refused (S-02);
  - the 256 MiB cap;
  - private staging;
  - reuse, or an `O_EXCL` claim of the lowest free `_<N>`;
  - `os.replace`.
- `copy_into_workarea` becomes the one line `return place_into_workarea(...).path`, with no second claim loop. Its 15 call sites keep their `Path` return.
- `predict_placement(digest_or_bytes, size, destination, name)` walks the same candidates and the same free names, with no staging and no claim.
- `segment_split_view.py`: the export takes its `reused`/`wrote` word from the `PlacementResult` it received. `_export_reuse_target`'s requested-name-only rule goes away (LLR-163.6).
- `app.py`: `_sync_loaded_file_to_project` names the existing variant when `reused` is true, with no "Added variant" status (LLR-163.5).

**Tests** (ids from the contract):
- TC-B100-01, -02, -03, -57, -62 (the guard arm: a junction to another work area, so 0 bytes are written outside), -68.
- AT-B100-01.
- **Re-pins**, each recorded old → new:
  - `tests/test_unified_write.py::test_tc018_existing_name_is_dedup_suffixed` (LLR-163.3);
  - `tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber` (LLR-163.3);
  - `tests/test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name` (LLR-163.4). Its sibling `::test_tc_b99_31_bin_pair_placed_under_one_suffix` stays **unchanged**; run it, but do not edit it (PDR C-QA-8).
- **RED evidence:** the RED side of tc018 and at031b is their current failure; both fail at base. AT-B100-01 is RED today (P-6). TC-B100-62 is RED today (the S-02 probe).
- **Enablers:**
  - E1 `tests/support/b100_links.py` (junction helpers built on `_winapi.CreateJunction`, which needs no privilege; on other platforms they skip with a named reason, counted in the packet, PDR C-QA-6);
  - E3, the two `firmware.s19` sources (`examples/case_01_basic_valid`, `examples/case_02_gaps_and_patch_targets`).

**Re-pins and arm extensions for this increment** (contract §5.3, PDR C-QA-7): the three re-pins above. The TC-B100-62 guard arm is written here; its seam (Inc 7) and listing/load arms (Inc 8b) come later, so do not write them now.

**Reverse census:** `grep -rln "copy_into_workarea\|_export_reuse_target\|_sync_loaded_file_to_project" tests/ --include=*.py`. Re-validate each hit; the contract's §5.4 lists them.

**Snapshot cells:** this increment must not change any. If one changes, STOP.

Finish with the whole-tree guards (`guards.txt`), the packet §1–§7 (§4b `pending — orchestrator`), then `HANDOFF.md` ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
