# Inc 6 HANDOFF — implementer: Claude software-dev (final)

Packet: `.dev-flow/2026-10-26-batch-100/03-increments/increment-006.md` (§4b pending — orchestrator).
Evidence: `.dev-flow/2026-10-26-batch-100/evidence/inc-6/`. Nothing committed. Base worktree `i6b` removed.

## Open questions / rulings requested
- OQ-1: a writer in a project with NO `project.json` now creates one (literal HLR-168). Execute in such a
  project moves from "no manifest" fallback to "manifest present". A damaged `project.json` is replaced by
  the next writer. Ruling requested (packet §5/§6).
- Guard measured in instead of STOP: `tests/test_import_census.py::MEASURED_SAFE_TEXT_CONSUMERS` += `s19_app.tui.screens`
  (LLR-178.3 requires safe_text in the panel; the guard's comment prescribes "measured in"). Revert + rule if a STOP was wanted.
- `devflow-evidence --check` reports "packet records no digest" because it reads the newest-numbered packet
  (`increment-015.md`, the hotfix); the digests are in `increment-006.md` §4.

__KIMI_UNIT_DONE__
1. Files: 4 sources (app.py, variant_execution_service.py, screens.py, styles.tcss); tests/fixtures/config 14.
2. Tests added: TC-B100-18 x5, -19 x3, -20 x4, -55 x9, -56 x3, -67 x6, -12 panel arms x2; AT-B100-06 x4, -19 x2, -20 x2; AT-04/-05 Inc 6 arms.
3. RED vs base: red-04 17F/1P, red-02 27F/1P, red-03 3F; GREEN: green-01 138 passed, green-02 144 passed; guards 75 passed + 29 snapshots; census sweep 87 passed.
4. Mutations: 9 run (168.1, 168.2, 168.3 x2, 178.1, 178.2 x2, 178.3 x2), all KILLED, all RESTORE OK.
5. Open: OQ-1 (manifest created/replaced), the measured-in guard, deferred arms (Inc 7 derived_from/"patched", Inc 8a/9b preview + Execute scope).

## Corrective pass 1 (2026-10-30) — implementer: Claude software-dev

Packet: `increment-006.md` §1 / §2 / §3 / §4 ("Corrective pass 1") / §5 / §6 / §7 updated. Nothing committed. Sources still 4 (app.py, variant_execution_service.py, screens.py; styles.tcss untouched in this pass).
Final source hashes: app.py 762d1a98c8a65903 · screens.py ea549ab4bd9d3ef4 · variant_execution_service.py 395dcbde3b28851b · styles.tcss 781f04ed2cc30897.

1. F1 / SEC6-1: `_rewrite_project_manifest` (one read; damaged -> no write, placed file stays, one status line naming project + file). 12 arms (4 writers x 3 damage kinds), bytes identical.
2. F2 / SEC6-4: "now opens" only when written AND verified; read-only project.json arm.
3. SEC6-6: line kept, routed through safe_text(...).plain; ESC/BEL arm.
4. UX-1: prototype colours via insight_style (YELLOW / GREEN / DGRAY). NOT DONE: the "not readable" error-colour mark — no readability state exists before Inc 7.
5. UX-2: rows name the recorded entry (issue `details` marks); 30 distinct rows asserted; rows hang under the label.
6. UX-3: summary is a label/value grid; wrapped values hang at column 10.
7. F3 docstrings; F5a `dismiss_load_result_panel`; F5b `scope` mark replaces message equality.
8. Evidence: fix1-red-01 18 failed (behavioural, vs the reviewed tree rebuilt hash-identical); fix1-green-01 155 passed; fix1-green-02 144 passed; fix1-census-manifest-readers 265 passed; fix1-guards 75 passed + 29 snapshots (no cell changed); fix1-guards-census 87 passed. 8 mutants, all KILLED, RESTORE OK. Reviewer MA/MB cited in the mutation table.
9. Deferred, named in §6: F4 -> Inc 11; SEC6-2 -> Inc 7; SEC6-3 -> LED .50 backlog; SEC6-5 -> Inc 7; "details: p" preview -> Inc 9b.

## Corrective pass 2 (2026-10-30) — SEC6-7 — implementer: Claude software-dev

Nothing committed. 1 source touched (variant_execution_service.py); budget still 4.
Final source hashes: app.py 762d1a98c8a65903 · screens.py ea549ab4bd9d3ef4 · variant_execution_service.py e494c50cd7266bff · styles.tcss 781f04ed2cc30897.

1. `_resolve_manifest_entry`: OSError / ValueError around resolve() + containment + reparse walk -> one MANIFEST-PATH-ESCAPE finding (row: Manifest entry skipped), never a crash.
2. `_entry_mark`: every finding's details['entry'] clipped to 120 chars with an ellipsis (strings and non-strings).
3. Tests +2: TC-B100-67 over-long batch/assignments/gathered via the Load project dialog (3 rows, entry <= 119 chars + ellipsis); TC-B100-20 A2L sync on such a manifest (no crash, seeded keys carried).
4. Evidence: fix2-red-01 2 failed (ValueError, pass-1 tree 395dcbde); fix2-green-01 157 passed; fix2-green-02 144 passed; fix2-census-manifest-readers 265 passed; fix2-guards 75 passed + 29 snapshots; fix2-guards-census 87 passed. Mutant SEC6-7-no-resolve-catch KILLED 2, RESTORE OK.
5. Packet: section 2 stale _MANIFEST_TOP_LEVEL_MESSAGE row fixed; Corrective pass 2 subsections in sections 1, 2, 4, 6, 7; gate row 11.

## Corrective pass 3 (2026-10-30) — SEC6-7 remainder, SEC6-8 — implementer: Claude software-dev

Nothing committed. 1 source touched (variant_execution_service.py); budget still 4. tools/e13/ and evidence/inc-6/e13/ (orchestrator) untouched.
Final source hashes: variant_execution_service.py 76b276077ded9717; app.py 762d1a98c8a65903 · screens.py ea549ab4bd9d3ef4 · styles.tcss 781f04ed2cc30897 unchanged.

1. SEC6-7 remainder: the resolver guard catches RuntimeError (junction to itself -> Symlink loop) -> one Manifest entry skipped row.
2. SEC6-8: the manifest parse catches a plain ValueError (integer over 4,300 digits) -> MANIFEST-JSON-PARSE, manifest_is_damaged True, writers skip the rewrite.
3. Tests +7: TC-B100-67 junction loop (dialog, Windows-only) and 5,000-digit integer (dialog); TC-B100-20 append with junction loop (Windows-only); TC-B100-20 damaged int-over-digit-limit x 4 writers. Junctions created with cmd /c mklink /J, removed with os.rmdir in finally.
4. Evidence: fix3-red-01 7 failed (pass-2 tree e494c50c); fix3-green-01 164 passed; fix3-green-02 144 passed; fix3-census-manifest-readers 265 passed; fix3-guards 75 passed + 29 snapshots; fix3-guards-census 87 passed. Mutants SEC6-7-loop-not-caught KILLED 2, SEC6-8-plain-valueerror-not-caught KILLED 5, RESTORE OK.
