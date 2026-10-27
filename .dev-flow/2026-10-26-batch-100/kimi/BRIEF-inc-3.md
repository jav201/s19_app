# Kimi brief — batch-100 Increment 3 · a project load starts clean (PH-2)

Read `BRIEF-COMMON.md` first. The orchestrator names your worktree and its base commit at launch; the base is `main` with Inc 1 and Inc 2 merged. Your packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-003.md`. If it is missing, copy the seed shape from `increment-001.md`.

**Design authority:** `design/design-proposal-b100.md` §5.3.

**Contract (`01-requirements.md`):**
- HLR-165
- LLR-165.1 to 165.4
- LED .51: the interim discard notice in LLR-165.3
- LED .50: project paths stay unresolved, and every placement call passes `workarea_root=self.workarea`

**State inventory:** `design/ARQ-batch-100.md` §2.2 (rows S1–S13) and §2.3 (the seam). The 11 extra names come from the P2 architect probe A-07: `_mac_view_cache_*` ×7, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address`, `_a2l_row_key_to_tag`.

**Interfaces:** this increment freezes B100-I4 and B100-I19.

**SOURCE files (1):** `s19_app/tui/app.py` only.

**What to build** (§5.3 governs):
1. **`_reset_project_session()`.** It is called ONCE in `_handle_load_project`, after the project validates and before the first install. It resets S1–S13 and the 11 names. It rebinds `self._change_service = ChangeService()` and re-pushes `set_image_generation(self._image_generation)`. Do not add a reset method to the service.
2. **Interim notice (LED .51).** If the outgoing Patch Editor document holds N > 0 unsaved entries, the load's status line reads `Discarded N unsaved Patch Editor entries`. Read the dirty or unsaved state from what the app already holds. Do NOT edit `screens_directionb.py`; Inc 10 adds the public reader. If no app-side way to count unsaved entries exists without touching another file, STOP and write it in `HANDOFF.md`.
3. **Unload clears the parsed A2L.** `_apply_unload("all" | "a2l")` clears `current_a2l_data` (LLR-165.4).
4. **`_session_snapshot()`.** It returns the normalised projection of every attribute name that `S19TuiApp`'s own source assigns. Derive the set by a census at test time, minus a declared exclusion list of Textual internals, each with its reason. The normaliser:
   - turns paths into relative ones;
   - turns objects into counts or keys;
   - removes the mtime from stat-keyed caches (QA R2-07).

**Tests** (ids from the contract):
- TC-B100-08, -09, -10, -11
- AT-B100-03
- the interim-notice arm under TC-B100-10

**TC-B100-09 compares snapshots:**
- two cold loads of the same project → equal;
- cold load vs load-over → differs only in the declared sets.

**RED must be behavioural, against the base code:**
- P-2: P2 re-saves `firmware.a2l` and `firmware.mac` from P1 (AT-B100-03).
- The leak names in the snapshot.
- P-25: Unload leaves the tags.

A missing module or symbol is NOT a RED. Run each new test against base `app.py` with the seam removed.

**Enablers:** E4 projects. P1 = `case_01` S19 + MAC + A2L; P2 = `prg.s19`, the `p03` scenario.

**Mutations, from §5.3's table:**
- move the reset after `load_selected_file`;
- drop one reset line;
- drop a census name without an exclusion;
- keep the old `ChangeService`;
- no A2L clear on unload.

**Reverse census:** `grep -rln "_handle_load_project\|_apply_unload\|current_a2l_data\|_change_service" tests/ --include=*.py`. Note that `test_tui_patch_variant.py` calls `_handle_load_project` with a project already open (contract §5.4).

**Snapshot cells:** none should change. If one does, STOP.

Finish with the guards (`guards.txt`, `guards-census.txt`), packet §1–§7 (§4b `pending — orchestrator`), and `HANDOFF.md` ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
