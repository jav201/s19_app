# Kimi brief — batch-99 Increment 3a · US-144 / HLR-155 · private staging, atomic placement, PH-3

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-155 (all clauses EXCEPT the D7 and D9 ones, which are Inc 3b), LLR-155.1, 155.2, 155.3, 155.4, 155.7; TC-B99-11, 12, 13, 14, 39; AT-B99-05 (and AT-B99-04's distinct-name parallel arm as a regression guard, with no RED claim). Design: `design/design-proposal-b99.md` §3 "Write placement" diagram and §4 B99-I2. PDR conditions: `design/PDR-2026-10-25-batch-99.md` rows **C1, C2, PQ-8, UX-C4, UX-C5, UX-C10** (UX-C5: the placement-error text and a caller-census column with the text the user sees; UX-C10: one hostile-name TC per new file-derived sink — the Save project file name and the placement-error path — asserting 0 markup spans). Read `design/PDR-architect.md` (C1, C2), `design/PDR-qa.md` (PQ-8) and `design/PDR-ux.md` (UX-C4) for their detail.

## SOURCE files (max 4)
`s19_app/tui/workspace.py`, `s19_app/tui/changes/apply.py`, `s19_app/tui/app.py`, `s19_app/tui/changes/io.py`.

## What to build
1. **`copy_into_workarea`** (`workspace.py`) per LLR-155.1/155.2/155.3:
   - check that `<workarea>/temp` and `<workarea>/temp/.staging` are not reparse points (`lstat`);
   - stage in a `tempfile.mkdtemp(dir=<workarea>/temp/.staging)` directory under the requested name;
   - B8 reuse only of a NON-EMPTY, byte-identical target (C1: a 0-byte file may be another writer's claim);
   - claim the final name with `os.open(path, O_CREAT|O_EXCL|O_WRONLY)`, or else the next free `_<N>`; close the handle;
   - `os.replace(staged, claimed)` with ≤ 5 attempts within ≤ 1 s on `PermissionError`. When they run out, remove your own claim and raise `WorkareaPlacementError(WorkareaContainmentError)`, whose message leads with the outcome and names the file and the next step (UX-C4, e.g. `Not saved: <name> is locked by another program — close it and retry`);
   - never move, rename or delete `source`;
   - remove the staging dir only through an ownership flag set right after `mkdtemp`.

   The signature and the `Path` return stay unchanged.
2. **`save_patched_image`** (`apply.py`): stop staging at `temp/<user name>`. Write the emitted bytes into a private staging dir and place them through `copy_into_workarea`. Remove the `finally: staged.unlink()` that deletes a re-derived name (`apply.py:776-778`, the TC-B99-39 RED site).
3. **`changes/io.py:1586`** — the 14th placement path (PDR C2): convert it the same way, with private staging and deletion of owned paths only.
4. **`_handle_save_dialog`** (`app.py`, LLR-155.4): a missing source file or a `WorkareaPlacementError` paints a failure-severity status that leads with the outcome (`Project not saved: <file> is missing`), leaves no empty project folder, and keeps the app running.
5. Make the Workarea Files list (`refresh_files`) skip the `.staging` subfolder. Inc 7 changes what the list reads, so add only the skip here, if needed.

## Tests — `tests/test_b99_staging.py`
- **TC-B99-11:** same-name save-back keeps the work copy (P-15 is the RED).
- **TC-B99-12:** 8 threads × 20 trials requesting ONE name, distinct markers, each reported path checked with the independent reader. PQ-8: the RED on today's tree must show a NONZERO mismatch count (e.g. `rw-p02` showed 35/40). If the race does not reproduce reliably, add a deterministic hook (a monkeypatched pause between stage and copy) so the RED is certain. Add the forced-`PermissionError` arm (0 zero-byte files, `WorkareaPlacementError`) and the source-unchanged arm (bytes and mtime).
- **TC-B99-13:** a hook replaces the target between check and reuse, modelling a concurrent placement (C1). Add a 0-byte-target arm: never reused.
- **TC-B99-14:** Save project with a missing source.
- **TC-B99-39:** AST census of the delete calls in the four writers per LLR-155.7's predicate (it also covers the CRC write site, which Inc 5 converts; mark that site `expected RED until Inc 5` and assert exactly that one known exception).
- **AT-B99-05** (Textual pilot): load `firmware.s19`, Patch Editor add + apply, save back as `firmware.s19`, then Save project through the real `SaveProjectScreen`: the app is running, the project folder holds the image, and the status names it.
- **AT-B99-04 distinct-name arm:** a chain set of 8 lanes with distinct output names, run in parallel through Flow Execution (`#fx_run`): each file holds its lane's marker. This is a regression guard with no RED claim; say so in the packet.
- Mutations: shared `temp/<name>` staging (TC-12 RED); check-then-copy (TC-13 RED); no verify of the source (TC-12 source arm); the re-derived unlink (TC-39 RED). Revert each one.

## Reverse census
`grep -rln "copy_into_workarea\|save_patched_image\|staging_block\|WorkareaContainmentError" tests/`. The qa census expects `staging_block` arms and `tests/test_manifest_writer.py:406` to change. Re-pin only what HLR-155 changes, recording old → new → LLR. For each of the 14 placement paths, write in the packet whether its caller handles `WorkareaContainmentError` (file:line).

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-003.md`, REQ-ID `HLR-155` (Inc 3a). State in §6 which PDR conditions were discharged.
