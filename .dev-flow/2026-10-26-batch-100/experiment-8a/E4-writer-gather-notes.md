# E4 — implementer B notes (`manifest_writer.py`, `project_gather_service.py`)

Spec: `codewire/proto-8a-writer-gather.md`, `codewire/interfaces-8a.md`, `E3-rulings.md` (R18 owned here). Every node of the prototype is implemented as written except the points below.

## Deviations

### D-B1 — R18 checks every folder between the work-area root and the source, not only the parent

`classify_active_document` decides R18 for a source OUTSIDE the target project that lies under a `.s19tool/workarea` (found textually with `workspace._find_workarea_root`): `workspace._path_traverses_reparse_point(source, stop_at=<work-area root>)`, so the source's parent and every folder above it up to the work-area root are `lstat`-ed. R18 names the parent only. The parent is included, so R18's example (`P/patches` swapped for a junction, Save into Q → class `missing`, 0 bytes copied) and its mutant (file-only check → RED) hold. The extra folders cover a junctioned project folder `P` itself at no extra rule; it reuses an existing helper, so there is no new path-safety code.

### D-B2 — R18 is applied only to a source outside the target project

R18 (round 3) would also turn the round-2 example "`P/patches` is a junction and the source is `P/patches/x.json` (saving into P) → `inside_elsewhere`" into `missing`. Both examples are kept: the inside test runs first (unresolved text), so an inside source gives `in_home` / `inside_elsewhere` as the prototype says, and R18 decides only the `outside` branch. The two classes have the same outcome (0 rows, nothing copied, one finding; A3R3-5 already records this sameness for the `P/patches`-is-a-file case).

### D-B3 — finding codes the prototype left open

The prototype says "one GATHER finding" without a code for three cases. Chosen:
- `inside_elsewhere` and a landing that fails `is_active_document_form` (e.g. `boost.txt`) → new constant `GATHER_DOCUMENT_NOT_RECORDED = "GATHER-DOCUMENT-NOT-RECORDED"` (WARNING).
- `missing` because the source is a link, goes through a link (R18) or is not a regular file → `GATHER-CONTAINMENT`. A source absent from disk (`os.path.lexists` False) keeps `GATHER-SOURCE-MISSING` as today.
- The classifier returns only `(kind, name)`; the gather tells "absent" from "link" with one `os.path.lexists`.

### D-B4 — P-B3 finding is decided before the walk

A sub-folder `files` key that is not the `active_document` text gives one `MANIFEST-WRITE-ESCAPE` finding and is not walked, so one key gives one finding (the same shape as the form refusal of `active_document`).

### D-B5 — the document's read failure in `check_project_files` says "could not be read" (R16)

Found by the tester's `test_tc_b100_30_held_document_is_not_readable_and_stays_recorded`: a document held by another program, WITH a `files` record, gives `not readable` from `_disk_problem` (reason "the file cannot be read") AND from the reopen ("could not be read"). Equal rank in `merge_load_problems` → the first seen (the check's) is kept, so R16's one reason was lost. The graph did not cover this pair. Fix in my file: `_disk_problem` uses "could not be read" for its two read-failure branches when it names the active document (other records keep "the file cannot be read"). The painted next step after the reason ("replace the file, or Save project to drop it" today vs R16's "check that the file can be opened, then Load again") is the app's wording, not mine: group A should check it.

## Notes for the tester / orchestrator (no change made)

- Tester run of `tests/test_b100_document.py` (in progress, 22:01Z): 125 passed, 3 failed. The held-document one is D-B5 (now passing). `test_tc_b100_29_second_save_of_the_bound_document_writes_nothing` times out adding an entry through the panel (UI / app). `test_tc_b100_30_refused_record_is_one_manifest_damaged_row_and_no_reopen` gets 2 `manifest damaged` rows (`firmware.s19` refused `active_document` + the `files` key `patches/boost.json`, now out of scope because the document was refused) — reader / fixture expectation, not the writer or gather.
- `tests/test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` counts 8 `app.py` placement calls vs 7 pinned (group A's file).

- `plan_project_save` gives the `project.json` row `merge` for every `target_kind == "merge"`, as the prototype and LLR-167.6 say. The app names any existing folder that is not the open project a merge target, also one with no `project.json`; the plan then says `merge` for a file that will be new. `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload` pins `new` for that case (Inc 5) and fails. Re-pin or rule.
- `project_gather_service` now imports `stat` (stdlib; one `lstat` decides "regular and not a reparse point"). `test_tc_b100_59_gather_service_imports_no_change_module` pins the exact import set and fails on `stat`; its stated intent (no edge to the change service / `changes`) still holds.
- `test_tc_b100_59_pending_patch_in_the_open_project` now sees the app's document row (`changes.json`, `new`) — the Inc 8a arm of TC-B100-59; re-pin.
- `test_tc_b100_61_sec6_5_entries_under_an_existing_folder_are_all_checked` failed once on its 1 s timing arm (`appended` 1.69 s) while three agents ran tests in parallel; 2 of 2 re-runs alone pass (worst 0.85 s). It has no `active_document`; the writer adds one `re.split` per `files` key. Load-sensitive, not a regression from this change as far as I can tell.
- The `ManifestVerifyResult` docstring still lists the three original drift names (pre-existing staleness, not touched).
