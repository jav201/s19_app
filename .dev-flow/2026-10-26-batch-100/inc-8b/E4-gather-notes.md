# Inc 8b — E4 build notes, group G2 (`project_gather_service.py`, `workspace.py`)

Implementer G2, stage E4. Spec: `codewire/proto-8b-gather.md` (12 nodes), `codewire/interfaces-8b.md`, `E3-rulings.md` (R1–R16). Only the two files changed; no tests written (the tester owns them).

## Deviations and interpretations (each one decided and recorded)

- **D1. Entry ceiling checked before classification (R13).** `inventory_project_tree` collects the walker's output first (the walker yields at most `SAVE_AS_ENTRY_CEILING + 1` paths, so the list is bounded) and tests the entry ceiling before it classifies any entry. Reason: the node example "one folder of `50000` files → over_ceiling `entries`" cannot hold if entries are classified one at a time, because the file stop (more than 2 004 counted files) is reached at entry 2 005, well before entry 10 001 (measured: per-entry order gave `files`). Effect: the entry ceiling takes precedence over the depth and file ceilings; at the entry ceiling no `lstat` runs. The file arm ("the walk stops at the 2 005th") stops the *classification* at the 2 005th counted file; the walker itself may already have yielded up to 10 001 entries. Every refusal text is the same "too many files to copy" family, so the user-visible result changes only in "over 2 000" vs "over 10 000 entries".
- **D2. Walk refusals only when a copy list is planned.** Steps (2) ceiling and (3) unreadable of `plan_project_save` run under the same predicate as step (4): `target_kind == "new"` and `inventory` given. A merge or open-project plan given an inventory (the LLR-171.1g examples) ignores it entirely: no folders, no copies, no walk refusal.
- **D3. Top-level exclusion by requested name.** Step (4a) leaves out top-level names equal (`normcase`) to `Path(planned.name).name` of the image / MAC / A2L rows. For a new target the top level is empty, so this equals the predicted landing name; computing the predictions first would move `predict_placement` ahead of the refusals.
- **D4. No logging in the gather module.** The module docstring makes it headless ("no `logging`"). The "at most the first 100 names plus the count, each as `%r`" log line (S3R2-1, S3R2-4) belongs to the caller that has a logger (G1, `app.py`). `inventory_project_tree` and `painted_names` log nothing.
- **D5. Entries below an unopenable folder are not classified.** When a folder's name ends in "." / " " or has a reserved stem, it is the `unreadable` entry. Its children, read through a path Windows may redirect to a sibling (S3-2), are not classified. The plan refuses anyway, and the user sees one name, not one per child.
- **D6. Landing-owner comparison.** "Source text equal to `root / relative`, `normcase`" is implemented as `os.path.normcase(os.path.abspath(...))` on both sides, the same `abspath` form `classify_active_document` uses.
- **D7. `_second_file_refusal(planned=...)` is unused in its body.** The parameter is kept because the graph's signature names it; the caller only calls it when a planned file of that kind exists. The article ("a MAC" / "an A2L") is derived from the label.
- **D8. An `OSError` listing the target for the MAC / A2L rule propagates.** `validate_project_files(target)` is called only when a MAC or A2L row is planned and the target is a directory. G1's step (6) maps an `OSError` from planning to today's "could not be read. Nothing written." refusal.
- **D9. `unreadable` is de-duplicated.** It is a sorted set of the walker's unlisted folders and the classifier's entries.

## Existing tests — intended changes for the tester

- `tests/test_b100_save_image.py::test_tc_b100_59_gather_service_imports_no_change_module` fails on the pinned import set. New imports: `stat` (lstat mode in the inventory), `unicodedata` (`painted_names`, S3R2-4) and `..` (`from .. import workspace`, so `DEFAULT_COPY_SIZE_CAP_BYTES` is read at call time, pre-ruling 4). The intent still holds: 0 imports of a change module. Re-pin needed.
- `test_tc_b100_59_open_project_unchanged`, `test_tc_b100_59_pending_patch_in_the_open_project` and `test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from[carried-True]` fail when base `app.py` is paired with the new plan. A spy shows the plan refusing `"Project NOT saved: 'P1' already has a MAC file (firmware.mac) — choose another name." exempt= None`. This is the DR-6 / pre-ruling 5 seam: G1 must pass `exempt` (the open project's own MAC / A2L names). The failures should clear with G1's `app.py`. That is not verified yet, because G1's file was mid-edit at run time.

## Measurements

- R16 (nested fixture, every folder opened through `os.scandir`, spy on the open count). Main thread, Windows 11, NTFS. The 5 s bound holds on all three shapes:
  - Wide tree: 11 top files, 999 folders × 9 files, 10 001 entries → `entries`. 1 000 folders opened. Max 0.182 s over 3 runs.
  - Deep listing: 2 files, `reports/` and 9 998 empty sub-folders, 10 001 entries → `entries`. 2 folders opened, because the walker stops inside the `reports` listing before it sorts or opens more. Max 0.578 s.
  - The same tree at exactly 10 000 entries → `None`. All 9 999 folders opened, every entry classified. Max 1.689 s.
- 50 000 files in one folder: the walker yields exactly 10 001 entries (spy), result `entries`, 0.091 s.
- R12 (a 2 000-file save as end to end) is not measured here: it needs G1's copy. The plan side passed: 2 000 copyable files, `copies` 2 000, refusal `None`.
