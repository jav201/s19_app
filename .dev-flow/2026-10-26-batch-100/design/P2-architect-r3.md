# P2 — architect bounded verification, round 3 — batch 2026-10-26-batch-100

Reviewer: `architect`.
- **Scope:** by operator decision after the P2 iteration cap, this verifies **only** the closure of my open findings B-01..B-14, plus the agreement of the contract with my B100-I13..I22 rows. It is not a new full review.
- **Under review:** `01-requirements.md`, ledger LED .14–.23, and `02-review.md` "Round 2", at `4e9c8f1`.
- **Read-only:** nothing else was edited, and nothing was committed.

## Verdict

**All of B-01..B-14 are closed: 0 open, no HIGH.** From my side, the gate can go to PDR.

Three alignment items between the contract and the map are recorded as **PDR conditions** (C-1..C-3). None is HIGH, so none blocks.

## Closure table

| id | round-2 severity | state | where it closes | check |
|---|---|---|---|---|
| B-01 | HIGH | **closed** | LLR-167.1, LLR-167.2, LED .14 | Emit-or-copy is decided on data (the change document re-derived onto a copy, compared with the source data); a check document never counts and goes to `checks/` without blocking. The threshold carries all three arms: "a check document with 1 entry → copy", "a change entry writing the bytes already there → copy", "a change entry writing new bytes → emit" (`01-requirements.md:809`). |
| B-02 | MAJOR | **closed** | LLR-174.4 (`_confirm_then_load`), LLR-174.1, LED .17 | One seam for the router, the Workarea Files pick (`_load_from_item`), the variant switch (`v` and the panel's `v`) and project load, one arm per route. Attach (MAC / A2L) never asks. The table has 24 cells, 11 ask. |
| B-03 | MAJOR | **closed** | LLR-169.8, LED .20 | The tightening is a manifest-key mode used only by `read_project_manifest` and `_reject_unsafe_entry`. Both flow-reference callers are named with their sites and keep the default mode, and `test_tc_b97_20_hostile_refs_render_literally` is named as staying green. |
| B-04 | MAJOR | **closed** | LLR-167.7, LLR-167.6, LED .14, .15 | The `save_patched` split is Inc 5's API, and `save_patched` is composed of the two parts, so B99-I7 stays one rule. The image digest is computed once per dialog open and passed in; names are debounced at 150 ms with no hashing; `project_gather_service` gains no import. |
| B-05 | MAJOR | **closed** | LLR-163.7, LLR-167.6, LED .15 | `predict_placement` shares `find_identical` and the free-name walk with the placement. The handler checks each landed path against the plan, and a mismatch is an error naming both paths. |
| B-06 | MAJOR | **closed** | §5.3 TC rows (`01-requirements.md:1915-1916`), LLR-171.4 threshold ("at Inc 1"), LED .23 | The arms moved to ARQ §8.1's increments:<br>- LLR-164.2(b): Inc 8a;<br>- TC-B100-59: Inc 5, 7, 8a and 8b;<br>- TC-B100-12: Inc 4, 6, 9b and 10;<br>- the `derived_from` comparison: Inc 7;<br>- the containment junction arm: Inc 1. |
| B-07 | MAJOR | **closed** | LED .23; §5.5; `docs/ARCHITECTURE.md` §11 B100-I13..I22 (in `4e9c8f1`) | The map rows are present, and the contract refers to them by id. Name drift: C-1..C-3 below. |
| B-08 | MINOR | **closed** | P-34 (`01-requirements.md:290`), LED .20 | "15 call sites … (17 grep lines, 2 of them docstrings)". |
| B-09 | MINOR | **closed** | HLR-163 Statement, LED .20 | Narrowed to the two statuses that claim "added" or "written": the variant append and the export. |
| B-10 | MINOR | **closed** | LLR-176.2, LED .19 | Begin, **step** or end. |
| B-11 | MINOR | **closed** | LLR-176.1, LLR-178.2, LED .16, .19 | `begin_busy` owns `#status_text` (`set_file_status` included) until `end_busy`, which paints the outcome, then the project + file line, then the file state. The announcement passes its line to `end_busy`. |
| B-12 | MINOR | **closed** | LLR-164.1 (`is_windows_device_name`, shared by LLR-169.8 and LLR-172.2), LED .20 | The older lists are filed in the backlog. |
| B-13 | MINOR | **closed** | LLR-169.4 | A contained key outside the scope gives `MANIFEST-BAD-STRUCTURE`; an unsafe key gives `MANIFEST-PATH-ESCAPE`. |
| B-14 | MINOR | **closed** | LLR-163.6 | The status word comes only from that call's `PlacementResult.reused`; "no separate `find_identical` call shall decide the word". |

## Agreement with B100-I13..I22 and ARQ §8

| Check | Result |
|---|---|
| Containment at Inc 1 | ✓ LLR-171.4: "B100-I14, frozen before Inc 1"; LLR-163.1 puts it inside `place_into_workarea`. The TC-B100-62 threshold starts "at Inc 1". Listing and load uses stay at Inc 8b. |
| `derived_from` at Inc 7 | ✓ LLR-168.4: "shall set it from Inc 7 on; an emit before Inc 7 records nothing"; LED .16. |
| §5.5 file sets = ARQ §8 | ✓ Row by row identical: 1:3 · 2:2 · 3:1 · 4:1 · 5:3 · 6:3–4 · 7:3–4 · 8a:4 · 8b:3 · 9a:2 · 9b:3–4 · 10:3–4 · 11:3 · 12a+12b:2–3. No increment is above 4. |
| Signatures and record shape vs the map rows | ✗ drift in three rows; the contract is the better text in each case (C-1..C-3). |

## PDR conditions (non-blocking, recorded per the bounded-round rule)

- **C-1 — the B100-I15 names and signatures differ.**
  - **Map:** `rederive_onto_copy(mem_map, ranges, mac_records, a2l_tags) -> RederivedImage(...)` and `emit_and_verify(rederived, …)`.
  - **Contract (LLR-167.7):** `rederive_for_save(copy) -> (map, summary)` and `emit_and_verify(map, ranges, …)`.
  - **Fix:** the map row takes the contract's names at PDR. One name per interface; the code follows the frozen one.
- **C-2 — the B100-I22 signature differs.**
  - **Map:** `predict_placement(staged_bytes, destination, name)`.
  - **Contract (LLR-163.7):** `predict_placement(digest_or_bytes, size, destination, name)`. This is the better form, because the plan holds a digest and a size and not the bytes of every file.
  - **Fix:** the map takes the contract's form.
- **C-3 — the B100-I16 record shape and panel wording differ.**
  - **Contract (LLR-168.4):** records the base's name, SHA-256 **and the number of differing bytes**, computed at the write. When the base is not in the project, the panel says "patched from `<base>` (not in this project); N bytes differ from it".
  - **Map:** the record has no count, and the panel declines to count in that case.
  - **Fix:** the contract's shape is better, because the count survives without the base. The map takes it.
- **C-4 — typo in LLR-174.4.** It names `_handle_project_load` for the direct test entry. The app method is `_handle_load_project` (`app.py:8444`), as everywhere else in the contract (1 occurrence).
- **C-5 — Inc 10's conditional file is now required.** LLR-174.1 makes the W accessor ("a public accessor added to the panel", `screens_directionb.py`) part of the requirement, not an option. Inc 10 is therefore 4 files (at cap), not 3–4. §5.5 and ARQ §8 should drop the parentheses at PDR.

## Evidence checklist (architect, bounded scope)

| Item | ✓/✗ | Evidence |
|---|---|---|
| Each open finding checked against the cited LLR text | ✓ | The statements of LLR-163.1/.6/.7, 164.1, 167.1/.2/.6/.7, 168.4, 169.4/.8, 171.4, 174.1/.4, 176.1/.2 and 178.2 were read at `4e9c8f1`. |
| Ledger entries cited | ✓ | LED .14–.20 and .23 |
| File-set agreement | ✓ | §5.5 (`01-requirements.md:1945-1969`) vs ARQ §8 |
| Map agreement | ✗ (non-blocking) | C-1..C-3 |
| New full review | `n/a — bounded round by operator decision` | — |
