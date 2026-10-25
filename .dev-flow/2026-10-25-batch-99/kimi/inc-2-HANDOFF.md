# HANDOFF — batch-99 Increment 2 (HLR-153 · S0 is not image data)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc2` (detached at e4c4324). No commits made; all changes are in the working tree for the orchestrator.

## What was done

- **Requirement**: US-142 / HLR-153 / LLR-153.1–153.4; TC-B99-04..07; AT-B99-02. Packet: `.dev-flow/2026-10-25-batch-99/03-increments/increment-002.md` (§4b left `pending — orchestrator`).
- **SOURCE (2 files)**: `s19_app/core.py` — new `_is_data_record` predicate (S1/S2/S3 only, R18), filtering `get_memory_map` / `get_record_for_address` / `_build_overlap_map` (`get_memory_ranges` inherits via the map); `s19_app/render/hexview.py` — `build_mem_map_s19` / `build_range_validity_s19` import and use the same predicate. CRLF preserved in both (717/717 and 397/397 `\r\n`).
- **New tests**: `tests/test_b99_s0.py` — 6 nodes (TC-B99-04 + boundary, TC-B99-05, TC-B99-06, TC-B99-07, AT-B99-02 Textual pilot). All 6 RED on the unmodified tree (per-node transcripts), all 6 GREEN after the fix.
- **Mutation (C-40)**: re-admitting S0 in the predicate kills 6/6 nodes; reverted, `core.py` SHA-256 back to `6821f378…` (pre-mutation value recorded).
- **Reverse census**: 27-file batch (`green-census.txt`). 15 first-run failures triaged: 8 S0-phantom re-pins (recorded old → new in the packet), 4 CPU-contention flakes (pass idle), 1 pre-existing (`test_at031b_two_saves_are_distinct_no_clobber`, fails identically on pristine HEAD), 2 STOPs (below). Final idle re-run: 39 passed (`census-repinned.txt`).
- **Snapshots**: 16 cells changed (all pass at pristine HEAD); regenerated scoped to exactly those 16 node ids; per-cell text-element multiset proof shows every delta is the disappeared 6-byte S0 range (`repin-snapshot-svg-multiset.txt`); pre-update SVGs backed up under `evidence/inc-2/snapshot-pre-b99-inc2/`. Final suite: 33 passed (`green-snapshot.txt`).
- **Goldens re-pinned (S0-only, proven, backed up)**: AT-288 capture (diff = one deleted entropy `low` line), AT-054b md+html (diff = the 0x0–0xF "only in B" region built from the save-back S0 text).

## STOP — left failing on purpose (orchestrator decision required)

1. `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main`
2. `tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main`

These freeze-guard nodes fail by design on any engine-module diff; LLR-153.1 is the *named* engine-layer crossing and B99-I1 records the contract change, so the failure is the guard doing its job. The implementer must not whitelist the crossing — that is a requirement/ledger decision for the orchestrator. Everything else in the 27-file census passes.

## Open questions

- TC-B99-06: the two `case_04_bad_checksums` examples carry a checksum-defective data record; the app loads its bytes, the independent reader skips them. TC-06 asserts written == loaded image exactly + reader-byte preservation; strict reader equality would need a checksum-policy decision outside this increment's 2-file budget.
- Brief says Patch Editor opens with `p`; the app binds `p` = Load project — AT-B99-02 drives the real bindings (`6` patch, `4` map, `l` load). Recorded in the packet.
- `emit_s19_from_mem_map` always writes an S0 record (empty when no header is forwarded) — sources without S0 round-trip with a legacy empty S0; never data at an undeclared address.

__KIMI_UNIT_DONE__
Files changed: 2 SOURCE (core.py, render/hexview.py) + 1 new test (tests/test_b99_s0.py) + 8 census re-pins in 4 test files + 16 SVG snapshots, 2 goldens, 1 report capture regenerated (all S0-proven, originals backed up).
Tests added: 6 nodes in tests/test_b99_s0.py (TC-B99-04+boundary, TC-B99-05, TC-B99-06, TC-B99-07, AT-B99-02 pilot).
RED/GREEN: 6/6 RED before the fix (per-node transcripts), 6/6 after; census 27 files (743 passed/15 failed first run → triaged); final idle re-run 39 passed; snapshot suite 33 passed.
Mutations: 1 (re-admit S0 in `_is_data_record`) — KILLED 6/6, reverted, hash-verified.
Open questions: 2 tc031 engine-freeze guard nodes left RED on purpose (named crossing needs orchestrator classification); TC-06 checksum-defective oracle semantics; brief's `p` key vs the app's real bindings.
