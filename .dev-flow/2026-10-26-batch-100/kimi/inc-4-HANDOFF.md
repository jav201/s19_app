# HANDOFF — batch-100 Inc 4 (worktree s19_app-b100-inc4) — DONE

All increment work is complete and verified. Packet: `.dev-flow/2026-10-26-batch-100/03-increments/increment-004.md` (§4b `pending — orchestrator`). No commit made; changes left in the working tree.

## What was built
- `s19_app/tui/app.py` (1 SOURCE file, CRLF preserved): `_FOCUS_TARGETS` per-window focus-target table (13 windows: the 12 rail windows of `SCREEN_CONTAINER_IDS` + the palette-only Split/Join window), `_WINDOW_CONTAINER_IDS` (derived frozenset), `_focus_needs_rehome` (region area 0 / hidden window / text input), `_rehome_focus_after_load` (synchronous `Screen.set_focus` — `Widget.focus()` defers via call_later and would be overridden by queued load steps); one call in the load tail `_step_finalize` and one in the A2L tail of `load_a2l_from_path`.
- `tests/test_b100_focus.py` (new, CRLF): 10 nodes — TC-B100-12 (6 arms), TC-B100-13 (2 arms), AT-B100-04 (parametrized 118×54 + 220×60, notifications on). `tests/test_id_registry.py` 217 → 218.
- Evidence under `.dev-flow/2026-10-26-batch-100/evidence/inc-4/` (RED ×3, GREEN ×7, mutants ×4, guards ×2, probes/scripts).

## Verification
- RED at base: 10 failed (behavioural P-16 line `_SegTable#sje_table, region Region(0,0,0,0)`); GREEN on final tree: 10 passed.
- 4 mutants all KILLED (a2l-tail removal → 2 failed; input-target → 1; drop-window → 1; finalize-tail removal → 3), every restore hash-verified RESTORE OK.
- Reverse census: 615 passed; 3 failures pre-existing at base (`red-03-census-failures-at-base.txt`); `tc330` flake green in isolation on this tree.
- Whole-tree guards: 75 passed + 29 snapshots unchanged (`guards.txt`); census sweep 87 passed (`guards-census.txt`).

## Open questions
- None. Modal-close arms (panel/dialog/question) remain scheduled at Inc 6 / 9b / 10 per the contract — deliberately not written here.

__KIMI_UNIT_DONE_ROUND1__
Files changed: s19_app/tui/app.py (source) + tests/test_b100_focus.py (new) + tests/test_id_registry.py (218 bump) + packet/evidence under .dev-flow.
Tests added: 10 nodes — TC-B100-12 (6 arms), TC-B100-13 (2 arms), AT-B100-04 (2 size arms).
RED/GREEN: RED 10 failed at base (P-16 shape, twice captured); GREEN 10 passed; reverse census 615 passed (3 pre-existing base failures + 1 flake); guards 75 + 29 snapshots; census sweep 87.
Mutations: 4 run, 4 KILLED (A2L-tail removal, Input target, dropped window, finalize-tail removal), all restores hash-verified.
Open questions: none — modal-close focus arms are Inc 6/9b/10 per LLR-166.1's schedule; independent review pending the orchestrator.

## Fix pass 1 (2026-10-27, complete)

Reviewer verdict: BLOCK — BLOCK-UNTIL F1, F2 (2 HIGH) + F3–F5 MAJOR + F6–F10. Orchestrator rulings LED .57 (a)–(d) read and implemented; all findings discharged with executed evidence.

Plan (all inside app.py as SOURCE + tests/test_b100_focus.py):
- F1/LED(a): Diff target `ab_diff_panel` → `diff_compare_button` (always-painted Button, never disabled); Map keeps `memory_map_panel` but the panel gets `can_focus = True` at compose in `_compose_screen_map` (app.py is the only SOURCE file). Census arm asserts `can_focus`. New parametrized per-window load arm over all 12 rail keys (+ existing Split/Join boundary) with `p` reaching LoadProjectScreen.
- F2: rename current healthy arm → `rehome_lands_on_the_active_windows_target` (settled helper); new real healthy arm per probe S4: `#hex_scroll` focus survives an A2L load.
- F3: new arm — visible `#search_input` (content window) re-homes on the A2L tail; R2 must go RED.
- F4: boundary arm polls the precondition with `_focus_is_settled_on`.
- F5/LED(b): `_rehome_focus_after_load` falls back (target area 0 / not displayed) to the window's first visible focusable non-text widget, else the rail's `-active` entry. New bare-session A2L-only arm.
- F6/LED(c): text-input clause re-homes only inputs inside content windows; chrome inputs (`#palette_input`) with area > 0 are never taken. New palette arm.
- LED(d): rule reads `default_screen.focused`; new modal arm.
- F9: new synchronous-landing arm (direct call, no pause) that R5 (`Widget.focus()`) turns RED.
- F7: re-run all mutants on the full module. F8: delete scratch files from evidence, re-derive rows. F10: comment fix.
- Then: module run, reverse-census files, guards, packet §1/§2/§4/§6, HANDOFF. — all executed, see below.

### Executed 2026-10-27 (fix pass 1)
- app.py implemented: `_FOCUS_TARGETS` Diff → `diff_compare_button`; Map keeps `memory_map_panel` with `can_focus = True` at the `_compose_screen_map` compose site; `_focus_needs_rehome` re-ordered (text-input clause first, scoped to content windows — chrome inputs never taken); `_fallback_focus_target` + `_resolve_focus_target` (LED .57 (b)); `_reassert_focus_target` — a `call_after_refresh` re-landing scheduled inside `_rehome_focus_after_load`, needed because the map panel's LLR-116.5 selection-follow hook runs AFTER the tail and would otherwise leave the focus on an id-less `RegionRow` (HLR-166 requires a NAMED landing); `_rehome_focus_after_load` reads `default_screen.focused` (LED .57 (d)). CRLF preserved (14822/14822); 1 SOURCE file.
- Probe (all executed): bare-session empty-state fallback lands on `window_help_workspace`, `p` → dialog; Map settles on the panel (area 504) with `p` → dialog; Diff settles on `#diff_compare_button` with `p` → dialog; palette keeps the focus + typed text through an A2L tail; `#hex_scroll` healthy focus survives; visible `#search_input` re-homes; modal keeps `#load_path` and the default screen keeps `#hex_scroll`.
- tests/test_b100_focus.py: 29 nodes — census arm now asserts `can_focus`; the old healthy arm renamed `rehome_lands_on_the_active_windows_target` (settled helper); boundary arm precondition now polls `_focus_is_settled_on`; new arms: `every_window_load_lands_on_its_target` (parametrized over all 12 registry windows), `healthy_focus_is_not_moved` (probe-S4 shape), `text_input_in_a_content_window_is_rehomed`, `empty_state_target_falls_back`, `palette_input_is_never_taken`, `modal_keeps_its_focus_while_a_load_finishes`, `bad_default_focus_is_rehomed_behind_a_modal`, `rehome_lands_synchronously`. No new test file → registry count unchanged.
- GREEN on the fixed tree: 29 passed in 182 s (`green-08-fix1-focus-module.txt`). Base (24d5b7f archive + the new module): 24 failed / 4 passed (`red-04-fix1-module-at-base.txt`, 240 s) — every_window[diff] RED at base (P-16 line); the 4 survivors pin unchanged behaviour.
- Mutants (F7): 14 mutants on the FULL module — 13 KILLED with true per-arm counts (K4→19, K2→11, K1→5, R1→3, K3/F1-map/F1-diff→2, R2/R5/FB/LC/LD/RA→1), 1 SURVIVED (R7 — the re-assertion covers the None-focus landing; recorded note-only). F1-diff-old-target is the RED-on-current-tree proof for Diff. Every restore hash-verified `RESTORE OK ac449a2e…`.
- Guards: 75 passed + 29 snapshot cells unchanged (`guards.txt`); census sweep 87 passed (`guards-census.txt`).
- Reverse census: 17 files (`green-09-reverse-census.txt`) — 730 passed, 1 skipped, 5 failed: 3 pre-existing at base (`red-03`), 2 before/after-report contention flakes green in isolation (`green-10-census-flakes-isolation.txt`, 3 passed with tc330).
- Evidence (F8): scratch files and superseded transcripts deleted; 26 files remain, every one with a packet row (paths + SHA-256) re-derived via `devflow-evidence.py --write … --rederive`; the only `--check` limb is "not staged" (expected pre-commit).
- Packet: §1, §2, §4, §5, §6 + gate checklist rewritten; §4b left `pending — orchestrator`. No commit made.

__KIMI_UNIT_DONE_FIX1__
Files changed: s19_app/tui/app.py (focus targets + predicate + fallback + re-assertion, 1 SOURCE file) + tests/test_b100_focus.py (29 nodes) + packet/evidence under .dev-flow; tests/test_id_registry.py unchanged from round 1.
Tests added: 8 new TC-B100-12 arms (every-window parametrized over 12 windows, healthy focus, text-input re-home, empty-state fallback, palette, 2 modal, synchronous landing) + can_focus census assertion + boundary precondition polling.

## Fix pass 2 (2026-10-29, in progress)

Reviewer verdict round 2: BLOCK — BLOCK-UNTIL R2-1 (HIGH: `_reassert_focus_target` breaks batch-77 LLR-116.5 — after a load on Map the focus is re-landed on `#memory_map_panel` and `up`/`down` stop walking the region rows) + R2-2 (MAJOR: a visible Find input is still taken, against LED .57 (c)) + R2-3 (MINOR: `red-04` was captured on a 28-node earlier module; re-capture at base with full headers) + R2-4 (LOW: fall back also when a target is painted but not focusable). Orchestrator rulings LED .58 (a)–(c) read: (a) Map keeps the LLR-116.5 auto-selected `RegionRow`, never move a `RegionRow`; (b) the general deferred re-assertion goes; (c) only STALE text inputs are re-homed (hidden window or area 0) — a visible Find input keeps the focus.

Plan (1 SOURCE file `app.py` + `tests/test_b100_focus.py`):
- R2-1/LED(a)(b): delete `_reassert_focus_target` (method + the `call_after_refresh` scheduling + docstring references); add the `RegionRow` early-False guard to `_focus_needs_rehome`; fix `every_window[map]` to LLR-116.5's threshold (focused ∈ live `RegionRow`s, `region_start` = the panel's resolved selection `_selected_cell_start`, area > 0) + `p`; new black-box arm: Map shown via rail key `4`, load through the Load file dialog, press `down`, the selected row advances — RED on the current (fix-pass-1) tree, where the focus sits on the panel and `down` does nothing. Re-run mutant R7 — expected KILLED again (TC-B100-13 caught it in round 1 before the re-assertion existed).
- R2-2/LED(c): rewrite the text clause of `_focus_needs_rehome` to stale-only (area 0, or inside a hidden window); rewrite `text_input_in_a_content_window_is_rehomed` to the STALE shape (focus `#a2l_tag_find_input`, hide the A2L window with a rail key, A2L load, focus re-homed); new arm: a visible `#search_input` keeps the focus AND its typed text across an A2L load. R2 (text clause deleted) becomes a no-op/equivalent mutant — expected SURVIVOR, recorded (the clause now only restates the stale conditions).
- R2-3: re-capture the base RED on the FINAL module against `git archive` of main `31eb572` (PYTHONPATH = that archive, NO_COLOR unset, both in the transcript header); replaces `red-04`.
- R2-4: `_resolve_focus_target` falls back when `not target.focusable or target.region.area <= 0`.
- Then: GREEN module run, map tests (`grep -rln "RegionRow\|memory_map" tests/`), guards + census sweep, all mutants on the FULL module, reverse census LAST (focus/map files only), packet §1/§4 (digests re-derived)/§6, HANDOFF close. No commit.

Progress: exploration complete (probe `probe-map-arrows.txt` + `RegionRow.on_key` read; `p` bubbles from a row). New arms written and RED on the fix-pass-1 tree (`red-05`, 3 failed: `every_window[map]`, the down-walk arm, the visible-Find arm — 12 passed). app.py fixed (re-assertion deleted, `RegionRow` guard, stale-only text clause, R2-4 focusable fallback; CRLF 14798/14798, import OK). `red-06` (base 31eb572 + final module, PYTHONPATH/NO_COLOR in header) first captured 25F/6P but the down-walk arm tripped on case_01's two-row map (second `down` is a no-op at the list end) — arm switched to case_02 (probe shape) and `red-06` is being re-captured. Next: GREEN module run, map tests, guards, 13 mutants, reverse census, packet.

Progress (cont.): `red-06` re-captured — 24 failed, 7 passed at base 31eb572 (survivors pin unchanged behaviour: Split/Join boundary, healthy focus, `every_window[map]` + the down-walk arm — LLR-116.5 works at base — the visible-Find arm, palette, modal). GREEN on the fix-2 tree: 31 passed in 234 s (`green-11-fix2-focus-module.txt`) — the Map landing, the `down` walk, the stale-input re-home and the visible-Find focus all hold. Packet §1/§2/§5 rewritten for LED .58. Next: map tests (21 grep files), guards + census sweep, 13 mutants on the full module, reverse census LAST, then §4/§6 + HANDOFF close.

Progress (cont. 2): map tests (`green-12`, 21 files, 24 min) found ONE failure — `test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later` — a real regression dating from fix pass 1 (the tail call reads `default_screen.focused`, which raises `NoScreen` on an app that never mounted; that file was not among fix 1's 17 census files). Fixed in app.py: the focus READ is now inside the mount guard, making the documented "unmounted tree = no-op" true at both ends (`green-12` + the tui_app re-run re-validate). Re-running: the focus module (supersedes green-11), `test_tui_app.py`, guards, census sweep — then mutants, reverse census LAST, packet §4/§6, HANDOFF close.

Progress (cont. 3, 2026-10-29 resume): the mutant ladder (12 of 13 done before the session dropped) — all restores hash-verified `RESTORE OK 77bb9aa6eae8`. R7 KILLED with 3 failed (`empty_state_target_falls_back` + both TC-B100-13 arms — the `None` focus at an A2L tail re-homes again once the re-assertion is gone, exactly the round-1 kill). K1→5, K2→11, K3→3, K4→18, R1→4, LD→1, F1-diff→2, F1-map→1 (the census only — LLR-116.5's hook heals the landing), all full-module. Two patches were malformed (FB left an empty `if`, LC a bad indent — collection errors, not kills) and R2/R5 were interrupted — all four re-run with fixed patches. app.py was restored from the pristine byte-copy (sha 77bb9aa6eae8, pure CRLF, syntax OK) after the interruption. Per the resumed order: re-running the module + tui_app + guards + census sweep on the restored final tree, then the 4 remaining mutants, then the reverse census LAST.

## Fix pass 2 — closed (2026-10-29)

Closing pass finished by a second implementer. Final `s19_app/tui/app.py` sha256 `77bb9aa6eae8f02d57e29caf8bc9d08f575ffec51dbba52ee8736a7f237e9f0a` (equals the pristine backup before and after the mutant run). Done in this pass: FB/LC/R2/R5 patches verified (applied once, `ast.parse` OK) and run on the FULL module; focus module re-run on the final tree (`green-14`, 31 passed); guards (75 passed + 29 snapshot cells) and census sweep (87 passed) re-run with headers; reverse census over all 32 grep files (976 passed, 1 xfailed, 5 failed: 3 pre-existing at base, `at_061a` flaky at base 2/12 vs 3/12 here, `tc_b97_55` green solo 5/5, not compared at base); packet section 4 and 6 rewritten with digests re-derived over 51 evidence files; 4b left `pending — orchestrator`. No product code changed in this pass; nothing committed.

__KIMI_UNIT_DONE__
1. What changed: no product code; patches fixed, evidence completed, packet 4/6 rewritten, HANDOFF closed.
2. RED: base 31eb572 + final module = 24 failed / 7 passed (`red-06`); fix-2 arms on fix-1 tree = 3 failed (`red-05`).
3. GREEN: focus module 31 passed on final tree (`green-14`); guards 75 + 29 cells; census 87; tui_app 62.
4. Mutants: 13 rows, 12 KILLED, R2 SURVIVED (equivalent: text block duplicates the generic tail); FB 1F, LC 1F, R5 3F.
5. Census: 32 files, 976 passed / 5 failed (3 pre-existing, at_061a flaky at base, tc_b97_55 isolation-green, unverified at base); snapshots unchanged.

## Round 3 — orchestrator (2026-10-29)

1. What changed: orchestrator removed the `Input`/`TextArea` branch of `_focus_needs_rehome` (tree `79df3ae1`), then, for reviewer finding R3-1 under LED .59, the `RegionRow` exemption and its import (final `app.py` sha256 `7168c1c9fb37033131abd91157bc19fbaba4406ab0fc3c17b48c72999be9ff2a`); new test `test_tc_b100_12_hidden_map_row_is_rehomed` (focus module 32 nodes). Reviewer round 3: PASS-WITH-NOTES, R2-1 discharged; `tc_b97_55` routed to the test-race backlog (Inc 4 ruled out mechanically, 0/40 failures on each tree under load; `tc-b97-55-diagnosis.txt`, `green-19`).
2. RED: `red-07-r3-1-hidden-map-row.txt` — with the exemption present, `-k hidden_map_row` = 1 failed, 31 deselected (focus left on a `RegionRow` of area 0); mutant RG killed by the new test.
3. GREEN: `green-20` 31 passed (tree `79df3ae1`); `green-21` focus module + `test_tui_app.py` 94 passed, 1 xfailed (final tree); `orch-guards-final` 75 passed + 29 snapshots; `orch-guards-census-final` 87 passed.
4. Pending: `green-22-r3-map-files.txt` (map files on the final tree) is RUNNING, orchestrator fills; packet §4b `pending — orchestrator`; packet evidence table has 60 rows, `green-22` row not yet added. No commit.
