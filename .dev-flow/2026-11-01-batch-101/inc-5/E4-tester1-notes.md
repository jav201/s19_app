# Inc 5 — E4 tester 1 notes (CRC Designer refresh after in-place writes)

File: `tests/test_b101_designer_writes.py` (10 nodes). Base `c2cba35`. State of all results below: `executed` on base; GREEN with the fix is `not-run` (the fix did not exist when this was written).
RED transcript: `.dev-flow/2026-11-01-batch-101/evidence/inc-5/red-01-tester1-base.txt` (one complete run: 8 failed, 2 passed; `s19_app.__file__` printed first, it is the detached worktree on c2cba35).

## Tests per case

| Case | Node | Full / partial |
|---|---|---|
| R-CRC-PREVIEW-002.5/3 | `test_r_crc_preview_002_5_3_apply_then_display` | full (Load dialog, key 6, typed path, Load and Apply clicks, key 0) |
| 002.5/4 | `test_r_crc_preview_002_5_4_save_back_then_display` | full (Edit button, save-back row, confirm) |
| 002.5/5 | `test_r_crc_preview_002_5_5_save_project_then_display` | full (real `ctrl+s` dialog, committed with the designer hidden by key 1) |
| 002.5/6 | `test_r_crc_preview_002_5_6_apply_error_still_refreshes` | partial: `apply_change_document` wrapped to raise `KeyError("probe")` after writing (as the case says) |
| 002.5/7 | `test_r_crc_preview_002_5_7_blocked_save_back_still_refreshes` | full |
| 002.5/8 | `test_r_crc_preview_002_5_8_zero_applied_restore_still_refreshes` | full, one drive deviation (see findings) |
| 002.1/6 (a) | `test_r_crc_preview_002_1_6_save_project_commit_while_displayed_schedules_a_recompute` | full (Q = 10 s: count unchanged, one pending, after two pauses) |
| 002.1/6 (b) | `..._while_displayed_recomputes_after_the_quiet_time` | full (Q = 0.05 s: exactly +1, exact three preview lines) |
| S13 *loaded image changes* (amended definition) | no node of its own: it is a definition; its three in-place-write sites are exactly /3, /6, /8 (apply, both outcomes), /4, /7 (save-back, any outcome), 002.1/6 and /5 (project commit). | covered through those rows |
| Integrity (not a case) | `test_oracle_constants_are_the_crc32_of_the_stated_byte_states`; `test_control_other_patch_actions_do_not_mark_the_coverage_stale` | pass on base by design (see below) |

Each case node runs 3 fresh apps (the "3/3"). Every node asserts, at the end: exactly 1 recompute (0 before key 0), painted concat and fill equal `zlib.crc32` of the 16 range bytes of `app.current_file.mem_map` read after the write, the literal values of the case, and window line 2.

## RED on base: reasons (all behavioural: stale CRC)

- /3, /6 (apply error): after key 0 the count stays and the preview keeps `0x9C5BCBBD` while the session bytes give `0x08DAAFB7`.
- /4, 002.5/5, 002.1/6 (b): the preview keeps `0x08DAAFB7` while the session bytes give `0x614BD0E8`.
- /7, /8: the preview keeps `0x08DAAFB7` while the session bytes give `0x9C5BCBBD`.
- 002.1/6 (a): no recompute is pending after the commit (the designer was never told).
- Before each of those final assertions the node already passed its own preconditions on base: exact `Apply:` status, `Patch Editor: 'probe'`, `Patched image not saved - 2 entries blocked - see issues`, no `fixture-blocked.s19`, `mem_map` 0x8002/0x8003 = `02`/`03` (/7), `0x8003` = `03` after the 0-applied apply (/8), `0x8003` = `BB` after the commit, and 0 recomputes while hidden. No import or fixture error.
- Setups never depend on the behaviour under test: where a case says "one display showing 0x08DAAFB7", the display is made fresh by an operator edit of Ranges (a spelling change), which recomputes on base and fix alike.

## Passing on base by design

- `test_oracle_constants_...`: the case literals (PRE, AA, BB) equal `zlib.crc32` of the stated byte states (confirms the E1 constants).
- `test_control_other_patch_actions_do_not_mark_the_coverage_stale`: an unapplied Add writes nothing, so a display of a clean designer recomputes nothing (graph: "any other action → no notice"). Guards against a hook on every Patch Editor action. Must stay green with the fix.

## Findings

1. 002.5/8 wording: "the entry's address edited to 0x9000" cannot be done with the entry editor (`ChangeService.edit_entry` finds the entry by its address and only rebuilds its content; a file-backed document disables the JSON edit). The node does Remove of `0x8003` and Add of `0x9000` = `AA`; the observable result (`Apply: 0 applied, 1 skipped, 0 blocked`, `0x8003` back to `03`) is the case's. Suggest the case text say "remove and re-add at 0x9000".
2. Cases /3 … /8 say "two pauses" before key 0; the nodes use several short pauses (a count that must not move is never read after one), which is stricter, not different.
3. Rail digits: with a text field focused (after typing an address) a rail key is typed into the field; the nodes release focus first (as a click on empty space does). Not a requirement gap, but any E5 black-box script must do the same.
4. 002.1/6 was split into limbs (a) and (b) so the base shows RED for each; the case names one node.
5. Mutants of the case table (hook gated on `ok`, on `applied > 0`, in the success branch only, recomputing while hidden) are covered by /7, /8, /6, and the "0 recomputes before key 0" assertion; none was run (no fix to mutate). Planned for E5, `not-run`.
6. No requirement found contradictory or unverifiable in this group.

## Limits

GREEN-with-fix not run (no fix yet). Linux host only; Windows terminal not exercised. The full file takes about 6.5 min on base (fail waits of 20 s per node), longer when GREEN (3 reps x 8 nodes).
