# Increment 002 — HLR-164 / LLR-164.1–164.4 · `Save project name guards`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `002` |
| Lane (if the batch forked) | `main` · `s19_app/tui/app.py · s19_app/tui/workspace.py · s19_app/tui/services/project_gather_service.py` (3 SOURCE files per LED .53) |
| Requirement(s) | `HLR-164 / LLR-164.1–164.4` |
| Acceptance | `AT-B100-02` · white-box `TC-B100-04 · TC-B100-05 · TC-B100-06 · TC-B100-07` · A-09 guard `test_save_second_s19_into_project_appends_variant` (unchanged, green) |
| Agent | `software-dev` |
| Date | `2026-10-26` |

---

## 1 · What changed

BLUF: Save project now refuses unsafe names **before any folder is created**, in the contract's
order, and a failed save leaves nothing behind. `_handle_save_dialog` (`app.py`) runs one name
check ahead of any `mkdir`: (1) an empty name paints `name is empty` / `type a project name`;
(2) `is_windows_device_name` — the NEW one shared predicate in `workspace.py`, case-folded, with
or without an extension (`con.txt`) or a superscript digit (`LPT¹`, whose digits fold the way the
Windows file namespace treats them) — applied to the RAW typed name, every path component of it,
and the sanitised name; (3) reserved work-area homes, case-folded (`Reports` refuses, `Splits` no
longer saves or lists); (4) the 64-character cap (`PROJECT_NAME_MAX_CHARS = 64`, NEW in
`workspace.py`) painting `name too long` / `shorten the name`; (5) the full-path limit
`len(workarea) + 1 + len(name) + 53 ≤ 259` (the 53-character before/after-report suffix, the
`_MAX_FULL_PATH` idiom) painting `path too long`; (6) the Q-2 disguised clash — the sanitised name
equal to an existing project's folder case-folded while the typed name differs — refused BEFORE
any write, naming BOTH names with `already a project` / `choose another name`, never suggesting a
merge (UX-35); the open project is exempt (its name typed exactly or unsanitised saves into it,
LLR-164.2(c)); the exact name against a project that is not open still merges by adding a variant
(LLR-005.1 — the full merge carry is Inc 8a's); (7) a target that exists and is a link or junction
is refused before any `resolve()` with `link or junction` (the target stays unresolved per LED
.50). From the folder's creation on, the WHOLE body of the handler runs under ONE `OSError`
handler that paints `could not save` / `check the folder`, removes only the folder THIS call
created via `_remove_created_project_dir`, and keeps the app running; every early return after
the creation (validation, the single-MAC / single-A2L guards, placement / containment refusals,
a failed manifest write) removes the folder too — an exception census, not a returns census
(S-05). `_write_and_verify_manifest` now reports success (`-> bool`) so a refused manifest write
also removes the created folder; `current_project` / `current_project_dir` install only on
success. `list_projects` omits every reserved home compared case-folded. Every refusal paints
its fixed token and a next step (UX-07); none of the painted strings carries an internal id.

**User-visible outcome:** typing `Reports`, `CON`, a 65+ character name, a path-breaking name, a
disguised clash or a junction target into Save project now refuses with the reason and the next
step painted on the status line, and the work area on disk is exactly as it was. A 300-character
name no longer crashes the app with a `FileNotFoundError` (P-13); a 262-character path no longer
leaves a folder behind (S-05); `a b` no longer silently merges into `ab` (P-10); `CON` is no
longer saved (S-04); `reports`/`Splits` are no longer saved or listed (P-14).

**Fix pass 1 (code-reviewer F1–F11, security SEC2-1..3, LED .52 (a)/(b)/(c)):**
(1) a failed save now rolls BACK, not just removes — the one `_abort_save`
helper every failure exit calls restores `_variant_set`, the current variant,
the report filter and `current_project` to the snapshot taken before the save
body ran, unlinks every file the save placed into an existing project folder
(a byte-identical reuse is kept — its bytes predate the save) and removes the
folder this call created (F1 / F5 / SEC2-3 / LED .52(b)); the `Saved project
to …` success line paints only after `project.json` is on disk, and a
`(None, issues)` manifest refusal is armed (`manifest-refused` stage).
(2) `is_windows_device_name` takes the stem up to the FIRST dot with
trailing spaces and dots stripped — `con.tar.gz`, `NUL.tar.gz`, `com1.a.b`
and `CON .txt` are refused, `COM⁴` is not, the superscript digits ¹²³ stay
refused (F3 / SEC2-2). (3) the open project's on-disk name typed in another
case saves into it under the ON-DISK spelling (`current_project` keeps the
spelling its folder has; LED .52(a) / F4), while a case-only match against
ANOTHER project stays a disguised clash. (4) the Q-2 clash scan compares the
name case-folded FIRST and lists inside only the matching folder; a folder
that cannot be read is skipped (`except OSError`), the same as
`list_projects`, so it never crashes the save (F8 / SEC2-1). (5) tests: the
empty-name refusal is armed (F6); the reserved-name oracle also asserts the
work-area folder list, and the phantom `sPlItS` folder is dropped (F9);
AT-B100-02 drives HLR-164's acceptance scene literally — `prg` (P2) and `ab`
built by real saves, P2 opened through the shipped Load project surface by
keys, `a b` refused naming `ab` (F7 / LED .52(c)); every forced-failure arm
asserts the APP STATE, not only folders and tokens (F1).

**Fix pass 2 (code-reviewer round 2 R2-1..R2-5, security SEC2-4):**
(1) R2-1 / SEC2-4: the pre-save snapshot is now the RECURSIVE set of
files AND folders under the project folder (sub-folders included, POSIX
relative paths), taken before ANY placement; on abort, `_abort_save`
removes every path absent from it, DEEPEST FIRST, unlinking files and
removing a folder only when it is empty — so the gather's
change/check copies in `patches/` / `checks/` / `templates/` and the
home folders it created are rolled back too, and a byte-identical file
the placement or the gather REUSED at a pre-existing path is never
deleted (the bare-name skip would have deleted it — demonstrated RED
against the naive variant in `red-fix2-naive-trap.txt`). `placed_paths`
is gone. (2) R2-3: the committed statements (the success line,
`current_project` / `current_project_dir`, `update_project_labels()`,
`refresh_files()`) moved OUT of the rollback `try` — once
`project.json` is on disk, an error there is never rolled back (the
rollback would unlink a variant the manifest lists). (3) R2-5: a
manifest verify MISMATCH (LLR-004.2 — reported, not a failure) is
re-painted as the NEWEST status line after `Saved project to …`, via
the `_last_manifest_verify_result` channel `_write_and_verify_manifest`
now sets; the notice still fires once, inside the verify surfacing.
(4) R2-4: the AST census accepts ONLY `_abort_save` for post-creation
exits — a bare `_remove_created_project_dir` exit no longer passes
(mutant `mut-fix2-r24.txt`: the census goes RED, 4 failed). (5) R2-2:
this packet's §2 now carries the row for the touched
`tests/test_b99_staging.py` (2 re-pins named) and the test-file count
is 3. New arms: `test_tc_b100_07_failed_save_removes_every_placed_path`
(3 cases — a merge with a gathered document, the byte-identical reuse
trap, a fresh-folder save) and
`test_tc_b100_07_manifest_mismatch_is_the_newest_status_line`.

**Fix pass 3 (code-reviewer round 3 R3-1, R3-2 — bounded pass):**
(1) R3-1: the pre-save snapshot and the rollback's removal walk no longer
use `Path.rglob` — on Python 3.11 `rglob` skips symlinks but descends into
NTFS junctions, so the rollback enumerated (and could unlink) the
junction's TARGET, outside the work area (executed probe: a file a
concurrent writer dropped into the target was DELETED), and a junction
cycle (`ab\loop` → `ab`) made the snapshot raise on a ~260-character path,
refusing every save into that project. ONE reusable walker,
`workspace.walk_tree_no_links(root)`, now drives BOTH walks: `os.scandir`
with `follow_symlinks=False`, each directory child re-checked with the
lstat-based `_is_reparse_point` (a junction reads as a plain directory to
`DirEntry.is_dir` on 3.11), a reparse point yielded as a LEAF and never
entered — so the walk cannot escape the project folder and cannot loop.
The rollback may remove a junction only when this save created it (it
creates none); a pre-existing junction is in the snapshot and never
touched. New arms: a junction-to-outside forced-failure merge (the
outside file survives, the project tree equals its snapshot), a junction
cycle arm (the exact-name merge saves), and a walker unit arm. (2) R3-2:
`_last_manifest_verify_result` is initialised in `__init__`, next to
`_variant_set`. The walker is written for reuse by save-as in Inc 8b
(LLR-171.1) — named in §5.

**Fix pass 4 — the LED .53 redesign (operator decision "Lista exacta" at the
Inc 2 gate; security round 3 SEC2-5 / SEC2-6):** the snapshot-difference
rollback is replaced by exact-list removal. (1) A failed save now removes
EXACTLY what THIS save created, collected during the save: every placement
whose `PlacementResult.reused` is false (the save body places the image,
MAC and A2L through `place_into_workarea` so the reuse flag is known — a
byte-identical file the placement reused is never recorded), every file the
gather actually wrote (`GatherOutcome` gains `written: list[Path]`, recorded
only on `copied=True` — a reused byte-identical sibling never appears), and
every folder this save created (`GatherOutcome` gains `created_homes:
list[Path]`, the project homes the gather created on demand, plus the
project folder when this call created it). (2) On failure `_abort_save`
unlinks only those files, then removes the created folders deepest first,
each only while empty. The rollback walks NO folder and diffs against NO
snapshot — `_project_tree_snapshot` and the snapshot-difference code are
gone from the rollback path — so a pre-existing file inside a folder that
was unreadable when the save started survives (SEC2-5, probe R7 executed
the deletion on the old design: `ab/patches/keep.json` was deleted) and so
does a file another writer added during the save (SEC2-6, probe R8). The
app-state restore of LED .52(b) and the manifest-MISMATCH re-paint are
unchanged. (3) `workspace.walk_tree_no_links` stays, with its unit arm,
for Inc 8b's save-as (LLR-171.1) — its only remaining consumer. New arms:
`test_tc_b100_07_rollback_keeps_denied_folder_content_r7` (Windows-only:
an `icacls` read-denied `ab/patches` at save start, lifted during the
save, then a forced refusal — `keep.json` must survive and the placed file
must still be removed) and
`test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8` (another writer
creates `ab/notes.txt` during the save, then the save is refused —
`notes.txt` survives, the placed file is removed). Re-pins (recorded in
§4): the forced-failure `copies` stage now breaks `place_into_workarea`
(the seam the save body actually calls) and the AST census's folder-removal
pin follows the helper (`rmdir` on the created folders instead of the
deleted `_remove_created_project_dir` helper).

**Fix pass 5 — the redesign corrective pass (security round 4 SEC2-7/8/9,
review round 5 R5-1/R5-2):** the design stays — a failed save removes exactly
what it created — this pass fixes its implementation. (1) **SEC2-7 (HIGH):**
`_gather_copy` no longer runs its own reuse pre-check: the case-sensitive
`_same_artifact_name` sibling scan is RETIRED (the function is deleted) and
the gather calls `place_into_workarea` directly, translating only the
placement's `PlacementResult.reused` flag into the `copied` word. The
placement (case-folded on Windows, LLR-163.1) is the SOLE byte-identity
judge — a byte-identical file under a case-variant name (`BOOST.json`,
`boost.JSON` for a `boost.json` source) is reported as REUSED, never lands
in `GatherOutcome.written`, and a failed save's rollback can no longer
delete a pre-existing user file (the round-4 probe's exact deletions,
`survives: False` ×2, are armed RED-then-GREEN). The TC-B100-57
byte-identity census is re-pinned: the gather's sibling scan leaves the
declared-rules set. (2) **SEC2-8:** when this save CREATES `project.json`
(no manifest before the write), the new file joins `placed_files` the
MOMENT the write returns — `_write_and_verify_manifest` gains an
`on_written` hook invoked between the write and the verify — so a failure
after that point (the verify re-read raising) leaves no folder behind (the
old rollback's `rmdir` failed silently on the folder still holding
`project.json`). (3) **SEC2-9:** a merge keeps the previous `project.json`
bytes in memory BEFORE the write; when the write returns, `(path,
previous-bytes)` arms `manifest_restores`, and every `_abort_save` exit
consumes it — the previous bytes are staged in the private staging home and
put back with `os.replace` (atomic, never a torn write) before the folder
removals. A failed merge leaves `project.json` byte-identical to its
pre-save content. (4) **R5-1:** the gather records a home as created from
whether it NOW exists, on BOTH the copy-success and the copy-failure path
(`not home_preexisted and home_dir.is_dir()`), never from whether the copy
wrote — the placement mkdirs the home before staging, so a copy that then
dies (a full disk) leaves a home this gather created; the rollback removes
it (only while empty) and no folder is left behind. (5) **R5-2:** an empty
pre-existing `patches/` now has a discriminating arm — mutant Mf (the
`home_preexisted` guard dropped) SURVIVED round 5 and is KILLED here. New
arms (7, all TC-B100-07):
`test_tc_b100_07_gather_reuse_never_ends_in_written` (the census/unit arm
— nothing reused ever ends in `written` — plus a fresh-write control limb),
`test_tc_b100_07_case_variant_reused_file_survives_failed_save[BOOST.json]` /
`[boost.JSON]` (Windows-only),
`test_tc_b100_07_failed_verify_leaves_no_folder_fresh`,
`test_tc_b100_07_failed_verify_restores_previous_manifest`,
`test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left` (the
disk-full shape) and
`test_tc_b100_07_empty_preexisting_home_survives_failed_save`.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/workspace.py` | source | LLR-164.1 · LLR-164.3 · B100-I11 (as amended, frozen here) | `PROJECT_NAME_MAX_CHARS = 64`; `is_windows_device_name` — the one shared device-name predicate (case-folded; stem before the FIRST dot with trailing spaces/dots stripped per F3 / SEC2-2, so `con.tar.gz` / `NUL.tar.gz` / `com1.a.b` / `CON .txt` refuse and `COM⁴` does not; superscript digits ¹²³ fold via `_DEVICE_DIGIT_TRANSLATION`; bases `con/prn/aux/nul/conin$/conout$` + the `comN`/`lptN` ports) + `_WINDOWS_DEVICE_BASES`; consumed later by LLR-169.8 / LLR-172.2 per the contract · `walk_tree_no_links` — the ONE non-following tree walk (`os.scandir`, `follow_symlinks=False`, reparse points yielded as leaves, cycle-safe; R3-1) — fix pass 4 (LED .53): the Save rollback no longer consumes it (it walks no folder at all); its remaining consumer is save-as in Inc 8b (LLR-171.1), with the unit arm kept |
| `s19_app/tui/app.py` | source | HLR-164 · LLR-164.1 · LLR-164.2 · LLR-164.3 · LLR-164.4 | `_handle_save_dialog`: the ordered pre-`mkdir` name guards (empty → device on raw/components/sanitised → reserved case-folded → 64-cap → full-path limit → Q-2 disguised clash naming both, name-compared FIRST with the open-project exemption and LED .52(a) on-disk-spelling adoption, unreadable folders skipped per SEC2-1 → link/junction target before `resolve()`); ONE post-creation `OSError` handler and every post-creation early return roll back through the ONE `_abort_save` helper — restore the pre-save app state (variant set, current variant, report filter, `current_project`), then remove EXACTLY what THIS save created (LED .53): unlink only the placed-files list (the placements whose `PlacementResult.reused` is false — the image/MAC/A2L place through `place_into_workarea` — plus `gather_outcome.written`) and remove the created folders (`gather_outcome.created_homes` plus the project folder when this call created it) deepest first, each only while empty; the rollback walks no folder and diffs against no snapshot — `_project_tree_snapshot`, `_remove_created_project_dir` and the snapshot-difference code are gone (SEC2-5 / SEC2-6 close by construction); the committed block (success line, `current_project` install, label/file refresh) runs OUTSIDE the rollback try (R2-3); the `Saved project to …` line paints only after `project.json` is on disk and a manifest verify MISMATCH re-paints as the NEWEST status line via `_last_manifest_verify_result` (R2-5); `list_projects` filters reserved homes case-folded; `_write_and_verify_manifest -> bool` (+ the verify-result channel and, fix pass 5, the `on_written` hook invoked the moment the manifest write returns, before the verify can raise); `_SAVE_REPORT_SUFFIX_CHARS = 53` / `_SAVE_FULL_PATH_LIMIT = 259` module constants — fix pass 5 (SEC2-8/SEC2-9, security round 4): the handler keeps the previous `project.json` bytes BEFORE the manifest write; the moment the write returns the created manifest joins `placed_files` (a fresh folder's verify failure leaves no folder behind) or `(path, previous-bytes)` arms `manifest_restores`; `_abort_save` consumes `manifest_restores` FIRST — the previous bytes staged in the private staging home (`workspace._private_stage_dir`) and put back with `os.replace`, atomic, never a torn write — then the unlinks and the created-folder removals; all 7 abort exits pass the list |
| `s19_app/tui/services/project_gather_service.py` | source | LLR-164.4 (LED .53) · LLR-138.4 (the exact-created lists ride the existing gather semantics) | `GatherOutcome` gains `written: list[Path]` (the files the gather actually wrote — recorded only when the placement did NOT reuse, so a reused byte-identical sibling never appears) and `created_homes: list[Path]` (the project homes created on demand — a home's existence is read BEFORE the copy decides); `gather_project_artifacts` populates both — the failed-save rollback consumes them verbatim (LED .53) — fix pass 5 (SEC2-7, R5-1): `_gather_copy` places through `place_into_workarea` and translates ONLY its `PlacementResult.reused` flag into the `copied` word — the placement (case-folded on Windows, LLR-163.1) is the sole byte-identity judge and the gather's own case-sensitive `_same_artifact_name` pre-scan is RETIRED (deleted), so a case-variant byte-identical file is reused, never recorded, never deleted by a rollback; a home is recorded as created from whether it NOW exists on BOTH the copy-success and the copy-failure paths (`not home_preexisted and home_dir.is_dir()`), never from whether the copy wrote — the placement mkdirs the home before staging, and a copy that then fails (a full disk) must not leave an unrecorded home behind |
| `tests/test_b100_save_guards.py` | test | HLR-164 · LLR-164.1–164.4 | TC-B100-04 (5 nodes: reserved ×3 casings with the file AND folder manifest oracle, empty names, device names raw/sanitised + multi-dot/trailing-space arms, the predicate unit arm, `list_projects` case-folded) · TC-B100-05 (7 nodes: disguised clash naming both with the digest manifest oracle, case-only clash, exact-name variant add, open-project unsanitised save, open-project CASE-VARIANT save under the on-disk spelling (LED .52(a)), case-only match against ANOTHER project refused, Windows-only junction target) · TC-B100-06 (2 nodes: 64/65/300 cap boundary, the L = 150 path-limit pair) · TC-B100-07 (27 nodes: the AST census (re-pinned per R2-4; fix pass 4 re-pins its folder-removal pin to `rmdir` on the created folders), 6 forced-failure stages incl. `manifest-refused` — the `copies` stage re-pinned to the `place_into_workarea` seam, all asserting the APP STATE restore (F1), 3 failed-merge arms asserting placed-file removal (F5), the recursive-tree rollback arms incl. the gather and the byte-identical reuse trap (R2-1 / SEC2-4), the LED .53 arms R7 (a read-denied folder's content survives) and R8 (a concurrent writer's file survives), the manifest-MISMATCH newest-status arm (R2-5), the Windows-only `icacls` unreadable-folder arm (F8), the Windows-only junction-target rollback arm, the junction-cycle arm and the walker unit arm (R3-1); fix pass 5 (SEC2-7/8/9, R5-1/R5-2): the gather-reuse census/unit arm (`written` never holds a reused file + a fresh-write control limb), the two case-variant save arms (Windows-only), the fresh-verify no-folder arm (SEC2-8), the merge-verify manifest-restore arm (SEC2-9), the disk-full gather-home arm (R5-1) and the empty-pre-existing-home arm (R5-2, Mf's kill)) · AT-B100-02 (2 parametrized arms, 118×54 and 220×60, notifications on — P2 opened through the shipped Load project surface by keys per LED .52(c)) — 43 nodes (fix pass 5: 5 + 7 + 2 + 27 + 2) |
| `tests/test_b100_reuse.py` | test | LLR-163.1 (B100-I13's byte-identity census, TC-B100-57) | 1 re-pin (fix pass 5, recorded in §4): `test_tc_b100_57_export_holds_no_byte_identity_rule` — the declared-rules set drops `("s19_app/tui/services/project_gather_service.py", "_gather_copy")` (the gather's sibling byte-scan is retired; the placement's rule is the SOLE judge, SEC2-7); the direct `_gather_copy` containment/root-threading arms re-validated unchanged — 38 passed (`reverse-census-fix5-1.txt`) |
| `tests/test_id_registry.py` | config | HLR-164 (registry hygiene for the Inc 2 test file) | `EXPECTED_SCANNED_TEST_FILES` 215 → 216 (MEASURED: `scanned_test_files()` reports 216) |
| `tests/test_b99_staging.py` | test | LLR-164.4 · LLR-155.3 | 2 re-pins (fix pass 1, recorded in §4): `test_at_b99_05_save_project_after_same_name_save_back` — the newest painted status after a save starts with `Saved project to` (was `Project saved`); `test_tc_b99_13_no_final_name_replace_outside_placement` — the app.py LLR-155.3 unlink allow-list gains `_abort_save`. Both re-verified GREEN on the fix-pass-2 tree (`green-fix2-guards-nodes.txt`). Fix pass 4 (LED .53): the allow-list entry and its comment are updated in place (`_abort_save` still the only app.py writer; every unlink is one path of the placed-files list); the pre-named M-F6a docstring mention of the removed `_remove_created_project_dir` helper is historical (the mutant named there targeted the round-1 shape) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 4 (uncapped) |
| Doc files | 0 (outside the count) |

---

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>
unset NO_COLOR
python -m pytest -q -p no:cacheprovider tests/test_b100_save_guards.py
python -m pytest -q -p no:cacheprovider tests/test_tui_variants.py::test_save_second_s19_into_project_appends_variant
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (AST census) | `core` · `full` | `test_tc_b100_07_ast_census_every_post_creation_return_removes` (re-pinned to `_abort_save` per R2-4; its folder-removal pin re-pinned to `rmdir` per LED .53, see below) | 1 passed — part of the 43 |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `TC-B100-04` (5) · `TC-B100-05` (7) · `TC-B100-06` (2) · `TC-B100-07` (27) | 40 passed |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | `AT-B100-02` at (118×54) and (220×60), notifications on | 2 passed |

Round 1: all 18 nodes passed in 152 s (`green-04-save-guards.txt`). **Fix pass 1:** all 27
nodes pass in 181 s (`green-fix1-save-guards.txt`); the A-09 guard
`test_save_second_s19_into_project_appends_variant` stays GREEN unchanged
(`green-fix1-a09-variant.txt`, 1 passed). The reverse census re-validates 15 files plus the
new module: chunk 1 = 150 passed + 2 re-pinned nodes (re-run green, `repin-b99-staging.txt`),
chunk 2 = 132 passed, 1 xfailed, chunk 3 = 116 passed. Whole-tree guards pass
(`guards-fix1.txt`, 75 passed — NO snapshot cell changed); the census sweep passes
(`guards-census-fix1.txt`, 85 passed).

**Fix pass 2:** all 31 nodes pass in 194 s (`green-fix2-save-guards.txt`); the A-09
guard and both fix-1 re-pinned b99 nodes stay GREEN unchanged
(`green-fix2-guards-nodes.txt`, 3 passed). RED first: the extended module against
the fix-pass-1 tree gave 2 failed / 29 passed (`red-fix2-save-guards.txt` — the
`merge-gathered` recursive-tree arm and the manifest-MISMATCH newest-status arm;
the `merge-gathered-reused` and `fresh-gathered` guard cases are GREEN at base by
construction — the reuse trap is demonstrated RED against the naive bare-name
variant in `red-fix2-naive-trap.txt`, where the pre-existing
`patches\hotfix.json` is deleted). Whole-tree guards pass
(`guards-fix2.txt`, 75 passed + 29 snapshot cells unchanged — none
changed, as required); the census sweep passes (`guards-census-fix2.txt`,
85 passed).

**Fix pass 3:** all 34 nodes pass in 205 s (`green-fix3-save-guards.txt`); the
A-09 guard and both b99 re-pinned nodes stay GREEN unchanged
(`green-fix3-guards-nodes.txt`, 3 passed). RED first: the three R3-1 arms
against the fix-pass-2 tree give 3 failed (`red-fix3-save-guards.txt` — the
junction-target arm finds the outside file DELETED, the junction-cycle arm is
refused with `[WinError 3] … ab\loop\loop\…` on a ~260-character path, the
walker unit arm cannot import `walk_tree_no_links`). Whole-tree guards pass
(`guards-fix3.txt`, 75 passed + 29 snapshot cells unchanged — none changed, as
required); the census sweep passes (`guards-census-fix3.txt`, 85 passed). The
reverse census re-validates the 16 census files on the fix-pass-3 tree: chunk 1
= 375 passed, 1 xfailed; chunk 2 (`test_b99_staging.py`) = 31 passed; chunk 3
(`test_tui_report_seam.py`, the `_write_and_verify_manifest` direct caller) =
28 passed — 434 passed + 1 xfailed, no new re-pins
(`reverse-census-fix3-{1,2,3}.txt`). The three fix-pass-2 rollback mutants
re-run on the fix-pass-3 tree against the 18 TC-B100-07 nodes all stay KILLED —
M-R2-1 (`mut-fix3-mr1.txt`, 1 failed: `merge-gathered-reused`), the reuse-skip
deletion (`mut-fix3-mr2.txt`, 6 failed), the shallowest-first removal
(`mut-fix3-mr3.txt`, 1 failed: `merge-gathered`) — plus the new M-R3-1
(`mut-fix3-r31.txt`, 1 failed: the junction-target arm); all four reverts
hash-verified (`restore-fix3.txt`, `RESTORE OK`).

**Fix pass 4 (the LED .53 redesign):** all 36 nodes pass in 240 s
(`green-fix4-save-guards.txt`). RED first: the two new arms (R7 the
read-denied folder, R8 the concurrent writer) against the fix-pass-3 tree
give 2 failed (`red-fix4-r7-r8.txt` — the snapshot-diff rollback DELETES
`ab/patches/keep.json` and `ab/notes.txt` — the exact deletions the
security round-3 probe executed: SEC2-5's `keep.json after rollback:
False`, SEC2-6's `user_added.json after rollback: False`). The kept arms
stay GREEN unchanged: the merge-gathered arms (a gathered file removed; a
pre-existing identical file survives), the fresh-folder arm (no folder
left behind), the junction arms (nothing outside touched), the
junction-cycle arm (the save works) and the F1 state assertions — all in
the same 36-node run. The reverse census re-validates the 16 census files
on the redesigned tree: chunk 1 = 369 passed, 1 xfailed; chunk 2
(`test_b99_staging.py`) = 31 passed — 436 passed + 1 xfailed with the
module run, 2 re-pins recorded below (`reverse-census-fix4-{1,2}.txt`).
Whole-tree guards pass (`guards-fix4.txt`, 75 passed + 29 snapshot cells
unchanged — none changed, as required); the census sweep passes
(`guards-census-fix4.txt`, 85 passed). The three LED .53 mutants are all
KILLED — (a) the reused placements removed too (`mut-fix4-a.txt`, 1
failed: the open-case reused `a.s19` deleted), (b) the snapshot difference
back (`mut-fix4-b.txt`, 2 failed: R7 + R8), (c) the gather's `written`
including reused files (`mut-fix4-c.txt`, 1 failed:
`merge-gathered-reused`) — all three reverts hash-verified
(`restore-fix4.txt`, `RESTORE OK` — all three sources equal
`pre-mutation-hashes-fix4.txt`: app.py fcb1bf400645…, workspace.py
8ef1763e180c…, project_gather_service.py c2d8cc2864a1…; the 6
discriminating arms re-run green on the reverted tree).

**Fix pass 5 (the redesign corrective pass — SEC2-7/8/9, R5-1/R5-2):** all
43 nodes pass in 241 s (`green-fix5-save-guards.txt`) — the kept arms stay
GREEN unchanged (the 6 forced-failure stages, the merge arms, the R7/R8
arms, the MISMATCH re-paint, the junction arms). RED first: the 7 new arms
and the re-pinned TC-B100-57 census against the reconstructed pre-pass
tree (the three sources reversed byte-exact — the gather and workspace
hashes equal the recorded pre-pass snapshot `pre-mutation-hashes-fix5.txt`,
c2d8cc2864a1… / 8ef1763e180c…) give 6 failed / 3 passed
(`red-fix5-new-arms.txt` — the reused-in-`written` census arm, BOTH
case-variant arms (`the failed save deleted the pre-existing file` — the
round-4 probe's `survives: False`), the fresh-verify arm (`freshv` left
behind), the merge-verify arm (`project.json` not restored) and the R5-1
arm's first form (an `AttributeError` on the old seam name — superseded by
the behavioral `red-fix5-r5-1.txt`: `freshp` left behind)); the re-pinned
census alone gives 1 failed (`red-fix5-census57.txt` — the gather rule
unexpected). Whole-tree guards pass (`guards-fix5.txt`, 75 passed + 29
snapshot cells unchanged — none changed, as required); the census sweep
passes (`guards-census-fix5.txt`, 85 passed). The reverse census
re-validates the census files on the fix-pass-5 tree: chunk 1
(`test_b100_reuse.py`, incl. the re-pinned TC-B100-57 census and the
direct `_gather_copy` arms) = 38 passed; chunk 2 (`test_b99_staging.py`
incl. the LLR-155.3 final-name census, `test_project_gather.py`,
`test_copy_into_workarea_content_dedup.py`) = 48 passed; chunk 3
(`test_tui_report_seam.py`, the `_write_and_verify_manifest` direct caller,
+ the A-09 guard node) = 29 passed (`reverse-census-fix5-{1,2,3}.txt`) —
158 passed with the 43-node module run, 1 re-pin recorded below. Six
mutants, all KILLED: Mf — round 5's SURVIVED mutant (the `home_preexisted`
guard dropped) dies on the empty-pre-existing-home arm
(`mut-fix5-mf.txt`, 1 failed); fix5-sec2-8 (the created manifest not
recorded) dies on the fresh-verify arm (`mut-fix5-sec2-8.txt`, 1 failed);
fix5-sec2-9 (the restore never armed) dies on the merge-verify arm
(`mut-fix5-sec2-9.txt`, 1 failed); fix5-r5-1 (the failure path records
nothing) dies on the disk-full arm (`mut-fix5-r5-1.txt`, 1 failed); the two
redesign mutants re-run on this tree stay KILLED — fix4-(a)
(`mut-fix5-fix4-a.txt`, 1 failed: `[open-case-AB-gather]`) and fix4-(c)
(`mut-fix5-fix4-c.txt`, 3 failed: the census arm + both case-variant arms;
the fresh control limb stayed green) — all six reverts hash-verified
against the fix-pass-5 fixed-state snapshot
(`pre-mutation-hashes-fix5-mutants.txt`: app.py e30805c44126…,
workspace.py 2ab2ba749fb5…, project_gather_service.py bc8b6eeacac4…;
`RESTORE OK`).

### RED / GREEN / mutation rows

| Kind | Transcript | Command (first line of the transcript names it) | Result |
|---|---|---|---|
| RED (new module at base) | `red-01-save-guards.txt` | `pytest tests/test_b100_save_guards.py` on the unmodified tree (`2edfee2`) | collection ImportError, exit 2 — `PROJECT_NAME_MAX_CHARS` does not exist yet; the module could not even load, so no node could pass vacuously (same RED shape as Inc 1's `red-01-new-module.txt`) |
| GREEN (full module, fixed tree) | `green-04-save-guards.txt` | `pytest tests/test_b100_save_guards.py` | 18 passed, 0 failed |
| GREEN (A-09 guard, unchanged) | `green-02-a09-variant.txt` | the variant-append node | 1 passed |
| mutation LLR-164.1 (KILLED) | `mut-llr-164-1.txt` | the declared mutant — the device-name check restricted to the sanitised name (raw name + components unchecked) | `con.txt` saved as `contxt` → the device node 1 failed (the reserved/listing arms stayed green, named) |
| mutation LLR-164.2 (KILLED) | `mut-llr-164-2.txt` | the disguised-clash refusal bypassed (`if typed_name != item.name:` → never taken) | `a b` merged silently into `ab` and the digests moved → the clash node 1 failed |
| mutation LLR-164.3 (KILLED) | `mut-llr-164-3.txt` | the full-path limit disabled (bound raised to 99999) | the 56-character name saved → the path-limit node 1 failed |
| mutation LLR-164.4 (KILLED) | `mut-llr-164-4.txt` | the declared mutant — the `except OSError` handler's `_remove_created_project_dir` call deleted | the AST census names that exit AND the forced-`OSError` copies arm finds the folder left behind → 2 failed |
| RED (fix pass 1, unfixed tree) | `red-fix1-save-guards.txt` | the extended module (27 nodes) against the round-1-fixed tree, BEFORE the fix-pass-1 source changes | 14 failed, 13 passed — every new/changed arm RED for its finding (device multi-dot arms, the F4 case-variant arm, the census re-pin, the F1 state assertions at gather/manifest/manifest-refused, the F5 merge arms, the F8 deny-folder arm, the AT's P2-by-keys scene); the empty-name node is GREEN by construction and is armed by M6/M7 below |
| GREEN (fix pass 1, full module) | `green-fix1-save-guards.txt` | `pytest tests/test_b100_save_guards.py` after the fix | 27 passed, 0 failed |
| mutation M6 (KILLED) | `mut-fix1-m6.txt` | the first empty-name status reverted to `"Invalid project name."` (reviewer M6) | the empty-name node 1 failed — the branch is no longer vacuous (F6) |
| mutation M7 (KILLED) | `mut-fix1-m7.txt` | the "no usable characters" status reverted to `"Invalid project name."` (reviewer M7) | the empty-name node 1 failed (`"!!!"` arm) |
| mutation M-F1 (KILLED) | `mut-fix1-f1.txt` | the state restore deleted from `_abort_save` (review F1's own revert) | the forced-failure arms at gather AND manifest-refused find the app state pointing into the removed folder → 2 failed |
| mutation M-F5 (KILLED) | `mut-fix1-f5.txt` | the placed-file unlink deleted from `_abort_save` | the failed-merge arms at exact/gather AND exact/manifest-refused find `firmware.s19` left in `ab` → 2 failed |
| mutation M-F4 (KILLED) | `mut-fix1-f4.txt` | the LED .52(a) on-disk-spelling adoption bypassed | the open-project case-variant node finds `current_project == 'AB'` → 1 failed |
| mutation M-F3 (KILLED) | `mut-fix1-f3.txt` | the device predicate back to the LAST-dot split | `con.tar.gz` / `NUL.tar.gz` arms saved instead of refused → the device node AND the predicate unit node 2 failed |
| RED (fix pass 2, unfixed tree) | `red-fix2-save-guards.txt` | the extended module (31 nodes) against the fix-pass-1 tree, BEFORE the fix-pass-2 source changes | 2 failed, 29 passed — the `merge-gathered` arm (the gather's copies survive: `ab` after = `['a.s19', 'patches', 'patches\\hotfix.json']`) and the manifest-MISMATCH newest-status arm |
| RED (fix pass 2, the SEC2-4 trap) | `red-fix2-naive-trap.txt` | the NAIVE variant (the gather's project-relative destinations appended to `placed_paths` with the bare top-level name skip) — the hazard SEC2-4(b) warns about, applied by hand and reverted | 2 failed — `merge-gathered` (the `patches/` home left behind) AND `merge-gathered-reused`: the pre-existing byte-identical `patches\hotfix.json` is DELETED by the rollback — the trap the recursive-path snapshot closes |
| GREEN (fix pass 2, full module) | `green-fix2-save-guards.txt` | `pytest tests/test_b100_save_guards.py` after the fix | 31 passed, 0 failed |
| mutation M-R2-1 (KILLED) | `mut-fix2-r21.txt` | the pre-save snapshot back to a TOP-LEVEL name set (sub-folder paths not recorded) | `merge-gathered-reused` finds the pre-existing `patches\hotfix.json` deleted → 1 failed (the `merge-gathered` case stays green: with nothing pre-existing in the sub-folder the deepest-first removal still cleans it — the reused arm is the discriminating one) |
| mutation M-R2-4 (KILLED) | `mut-fix2-r24.txt` | the manifest-not-ok exit rolls back with a bare `_remove_created_project_dir` — no state restore, no placed-path removal | the AST census names the exit (a bare removal no longer counts) AND the behavioural arms find the state unrestored and the placed files left behind → 4 failed |
| mutation M-R2-5 (KILLED) | `mut-fix2-r25.txt` | the mismatch re-paint after the success line skipped | the newest-status arm finds `Saved project to …` painted over the MISMATCH → 1 failed |
| mutation M-F6a (KILLED) | `mut-fix2-f6a.txt` | `_remove_created_project_dir` no-op (the b99 F6a mutant named in `test_tc_b99_14`) | `test_tc_b99_14_placement_failure_removes_created_folder` finds the created folder left behind → 1 failed |
| mutation M-S-F5 (KILLED) | `mut-fix2-sf5.txt` | `created_project_dir` forced True on the `FileExistsError` branch (the b99 S-F5 mutant named in `test_tc_b99_14_preexisting_folder_survives_placement_failure`) | the pre-existing folder's sentinel is destroyed → 1 failed |
| RED (fix pass 3, unfixed tree) | `red-fix3-save-guards.txt` | the extended module (34 nodes, the 3 R3-1 arms selected) against the fix-pass-2 tree, BEFORE the fix-pass-3 source changes | 3 failed — the junction-target arm (the rollback DELETES the outside file: `assert 'user-work.txt' in ['keep.txt']`), the junction-cycle arm (`could not save — [WinError 3] … ab\\loop\\loop\\…` on a ~260-character path) and the walker unit arm (`ImportError: cannot import name 'walk_tree_no_links'`) |
| GREEN (fix pass 3, full module) | `green-fix3-save-guards.txt` | `pytest tests/test_b100_save_guards.py` after the fix | 34 passed, 0 failed |
| mutation M-R3-1 (KILLED) | `mut-fix3-r31.txt` | the walker follows reparse points — the `not _is_reparse_point(child)` guard deleted from `walk_tree_no_links` | the junction-target arm finds the outside file deleted again → 1 failed |
| RED (fix pass 4, unfixed tree) | `red-fix4-r7-r8.txt` | the two LED .53 arms (R7, R8) against the fix-pass-3 tree, BEFORE the redesign | 2 failed — the snapshot-diff rollback DELETES the pre-existing `ab/patches/keep.json` (R7: the folder was read-denied at snapshot time) and the concurrently written `ab/notes.txt` (R8) |
| GREEN (fix pass 4, full module) | `green-fix4-save-guards.txt` | `pytest tests/test_b100_save_guards.py` after the redesign | 36 passed, 0 failed — the kept arms (merge-gathered ×3, fresh-folder, junction ×2, the F1 state assertions, the MISMATCH re-paint) stay GREEN unchanged |
| mutation fix4-(a) (KILLED) | `mut-fix4-a.txt` | the rollback removes the reused placements too — the `placed_image.reused` guard forced True | `test_tc_b100_07_failed_merge_removes_placed_files[open-case-AB-gather]` finds the reused byte-identical `a.s19` DELETED → 1 failed |
| mutation fix4-(b) (KILLED) | `mut-fix4-b.txt` | the rollback back to the snapshot difference — an `rglob` walk deletes every file the placed list does not name | arms R7 AND R8 find `keep.json` / `notes.txt` deleted → 2 failed |
| mutation fix4-(c) (KILLED) | `mut-fix4-c.txt` | the gather's `written` list includes the reused files — `outcome.written.append(destination)` unconditional | `test_tc_b100_07_failed_save_removes_every_placed_path[merge-gathered-reused]` finds the pre-existing `patches\hotfix.json` DELETED → 1 failed (the two non-reused arms stay green, named) |
| RED (fix pass 5, unfixed tree) | `red-fix5-new-arms.txt` + `red-fix5-r5-1.txt` + `red-fix5-census57.txt` | the 7 new arms + the re-pinned census against the reconstructed pre-pass tree (the three sources reversed byte-exact) | 6 failed / 3 passed + 1 failed — the reused-in-`written` census arm, BOTH case-variant arms (the pre-existing case-variant file DELETED — the round-4 probe's `survives: False`), the fresh-verify arm (`freshv` left behind holding `project.json`), the merge-verify arm (`project.json` keeps the new bytes), the disk-full arm's first form (superseded: `red-fix5-r5-1.txt` shows the behavioral `freshp` left behind) and the census re-pin (the gather rule unexpected) |
| GREEN (fix pass 5, full module) | `green-fix5-save-guards.txt` | `pytest tests/test_b100_save_guards.py` after the corrective pass | 43 passed, 0 failed — the kept arms (6 forced stages, merge arms, R7/R8, the MISMATCH re-paint, the junction arms, the F1 state assertions) stay GREEN unchanged |
| mutation Mf (KILLED — round 5's survivor) | `mut-fix5-mf.txt` | the `home_preexisted` guard dropped from the success-path `created_homes` recording | `test_tc_b100_07_empty_preexisting_home_survives_failed_save` finds the pre-existing empty `patches/` removed → 1 failed — Mf now dies |
| mutation fix5-sec2-8 (KILLED) | `mut-fix5-sec2-8.txt` | the observer records nothing when this save created the manifest (`placed_files.append(written)` → `pass`) | `test_tc_b100_07_failed_verify_leaves_no_folder_fresh` finds `freshv` left behind → 1 failed |
| mutation fix5-sec2-9 (KILLED) | `mut-fix5-sec2-9.txt` | the previous-bytes restore never armed (`manifest_restores.append(...)` → `pass`) | `test_tc_b100_07_failed_verify_restores_previous_manifest` finds `project.json` holding the new bytes → 1 failed |
| mutation fix5-r5-1 (KILLED) | `mut-fix5-r5-1.txt` | the failure path records nothing — the R5-1 except-path block deleted | `test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left` finds `freshp` left behind → 1 failed |
| mutation fix5-fix4-a (KILLED, re-run) | `mut-fix5-fix4-a.txt` | the rollback removes the reused placements too — the `placed_image.reused` guard deleted | `[open-case-AB-gather]` finds the reused byte-identical `a.s19` DELETED → 1 failed |
| mutation fix5-fix4-c (KILLED, re-run) | `mut-fix5-fix4-c.txt` | `_gather_copy` reports `copied=True` unconditionally — the `reused` flag ignored | the gather-reuse census arm AND both case-variant arms find the reused file in `written` / deleted → 3 failed (the fresh control limb stayed green, named) |

All four round-1 mutants were reverted; the restore is proven by SHA-256 — both sources hash-equal the
fixed-state snapshot `pre-mutation-hashes.txt` after every restore (`RESTORE OK` verified on
`app.py` after M1; the final `sha256sum` after M4 equals the snapshot for BOTH files:
`app.py` 935726ca3b6c…, `workspace.py` 6c7db1448758…).

All six fix-pass-1 mutants (M6, M7, M-F1, M-F3, M-F4, M-F5) were reverted; the restore is
proven by SHA-256 against the fix-pass-1 fixed-state snapshot
`pre-mutation-hashes-fix1.txt` — `app.py` b2dcf23c1f9a… and `workspace.py`
d2137e1d5b5d… verified after the M6+M7 reverts, after the M-F1+M-F5 reverts, after the M-F4
revert, and for BOTH files after the M-F3 revert (`RESTORE OK — all 6 mutants reverted`).

All five fix-pass-2 mutants (M-R2-1, M-R2-4, M-R2-5, M-F6a, M-S-F5) were reverted; the
restore is proven by SHA-256 against the fix-pass-2 fixed-state snapshot
`pre-mutation-hashes-fix2.txt` — `app.py` 52b5f9495107… and `workspace.py`
d2137e1d5b5d… verified for BOTH files after the last revert
(`restore-fix2.txt`, `RESTORE OK - all 5 fix-pass-2 mutants reverted`).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | 4 live mutants (one per LLR, the proposal table's mutations), each applied by hand via the editor, run, and reverted — details per row above |
| Instrument | project code, own hand via targeted edits; restore verified by SHA-256 against `pre-mutation-hashes.txt` |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b100-inc2`), implementer agent |
| Transcript | `evidence/inc-2/mut-llr-164-{1,2,3,4}.txt` |
| Restore proven by | `pre-mutation-hashes.txt` + the post-restore `sha256sum` checks |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` in every run (C-46) |
| Arms resolved at baseline | round 1: 18 nodes in `tests/test_b100_save_guards.py` + 1 A-09 guard node; fix pass 1: 27 nodes + 1 A-09 guard node; fix pass 3: 34 nodes + 3 guard nodes — counts asserted per transcript; fix pass 4: 36 nodes + 3 guard nodes (A-09 variant append + the two b99 re-pinned nodes re-verified in `reverse-census-fix4-2.txt` / batch 1); fix pass 5: 43 nodes + the A-09 guard node re-verified in `reverse-census-fix5-3.txt` / chunk 3 |
| Verdict granularity | per node id, per transcript |
| Arms that stayed GREEN | named per mutation verdict: for each mutant the sibling arms of the same TC stayed green (e.g. M1 left the reserved/listing arms green; M6 left the device arms green while killing the empty-name node) |

| Field | Value |
|---|---|
| **RED counterfactual** | The whole new module is RED at base by construction (collection ImportError — `red-01-save-guards.txt`); the contract's executed premises name the behavioural REDs this increment fixes, all executed on `1d677ba` and quoted in the contract: P-14 (`Splits` saved and listed), S-04 (`CON` saved), P-13 (`RAISED FileNotFoundError` on a 300-character name), S-05 (a 262-character path left a folder), P-10 (`'a b' -> project='ab'` saved silently). Plus 4 live-mutation REDs, one per LLR. |

| Field | Value |
|---|---|
| **Mutation verdicts** | `LLR-164.1` — sanitised-only device check → `test_tc_b100_04_device_names_refused_raw_and_sanitised` KILLED · `mut-llr-164-1.txt` · restore ✓. `LLR-164.2` — clash bypass → `test_tc_b100_05_disguised_clash_refused_naming_both` KILLED · `mut-llr-164-2.txt` · restore ✓. `LLR-164.3` — path limit disabled → `test_tc_b100_06_path_limit_met_and_exceeded` KILLED · `mut-llr-164-3.txt` · restore ✓. `LLR-164.4` — one removal call deleted → `test_tc_b100_07_ast_census_every_post_creation_return_removes` AND `test_tc_b100_07_forced_oserror_leaves_no_folder[copies]` KILLED · `mut-llr-164-4.txt` · restore ✓ (hash-verified for both sources). **Fix pass 1:** M6 → `test_tc_b100_04_empty_names_refused` KILLED · `mut-fix1-m6.txt` ✓ · M7 → same node KILLED · `mut-fix1-m7.txt` ✓ · M-F1 → the forced gather + manifest-refused arms KILLED · `mut-fix1-f1.txt` ✓ · M-F5 → the failed-merge exact arms KILLED · `mut-fix1-f5.txt` ✓ · M-F4 → `test_tc_b100_05_open_project_case_variant_saves_under_on_disk_name` KILLED · `mut-fix1-f4.txt` ✓ · M-F3 → the device node AND the predicate unit node KILLED · `mut-fix1-f3.txt` ✓. **Fix pass 2:** M-R2-1 → `test_tc_b100_07_failed_save_removes_every_placed_path[merge-gathered-reused]` KILLED · `mut-fix2-r21.txt` ✓ · M-R2-4 → the AST census AND the manifest-refused forced arm AND both gathered merge arms KILLED · `mut-fix2-r24.txt` ✓ · M-R2-5 → `test_tc_b100_07_manifest_mismatch_is_the_newest_status_line` KILLED · `mut-fix2-r25.txt` ✓ · M-F6a → `test_tc_b99_14_placement_failure_removes_created_folder` KILLED · `mut-fix2-f6a.txt` ✓ · M-S-F5 → `test_tc_b99_14_preexisting_folder_survives_placement_failure` KILLED · `mut-fix2-sf5.txt` ✓. **Fix pass 3:** M-R3-1 (the walker follows reparse points) → `test_tc_b100_07_rollback_never_touches_junction_target` KILLED · `mut-fix3-r31.txt` ✓; the three fix-pass-2 rollback mutants re-run on the fix-pass-3 tree stay KILLED (`mut-fix3-mr1.txt`, `mut-fix3-mr2.txt`, `mut-fix3-mr3.txt`, restore `restore-fix3.txt`). **Fix pass 4 (LED .53):** mutant (a) — the reused placements removed too → `test_tc_b100_07_failed_merge_removes_placed_files[open-case-AB-gather]` KILLED · `mut-fix4-a.txt` ✓ · mutant (b) — the snapshot-difference tree walk back → arms R7 AND R8 KILLED · `mut-fix4-b.txt` ✓ · mutant (c) — the gather's `written` includes reused files → `test_tc_b100_07_failed_save_removes_every_placed_path[merge-gathered-reused]` KILLED · `mut-fix4-c.txt` ✓ — all three reverts hash-verified (`restore-fix4.txt`, `RESTORE OK`, all three sources equal `pre-mutation-hashes-fix4.txt`; the 6 discriminating arms re-run green on the reverted tree). **Fix pass 5:** Mf (the `home_preexisted` guard dropped) → `test_tc_b100_07_empty_preexisting_home_survives_failed_save` KILLED · `mut-fix5-mf.txt` ✓ — round 5's survivor now dies · fix5-sec2-8 (the created manifest not recorded) → `test_tc_b100_07_failed_verify_leaves_no_folder_fresh` KILLED · `mut-fix5-sec2-8.txt` ✓ · fix5-sec2-9 (the restore never armed) → `test_tc_b100_07_failed_verify_restores_previous_manifest` KILLED · `mut-fix5-sec2-9.txt` ✓ · fix5-r5-1 (the failure path records nothing) → `test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left` KILLED · `mut-fix5-r5-1.txt` ✓ · fix4-(a) re-run → `[open-case-AB-gather]` KILLED · `mut-fix5-fix4-a.txt` ✓ · fix4-(c) re-run → the gather-reuse census arm + both case-variant arms KILLED · `mut-fix5-fix4-c.txt` ✓ — all six reverts hash-verified against `pre-mutation-hashes-fix5-mutants.txt` (`RESTORE OK`). No mutation survived. |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest tests/test_b100_save_guards.py` at base | the unmodified tree (new symbols absent) | collection ImportError, exit 2 — `red-01-save-guards.txt` |
| the device-name node | M1 (sanitised-only check) | `AssertionError` on `con.txt` — `mut-llr-164-1.txt` |
| the clash node | M2 (clash bypass) | digest-manifest inequality + missing tokens — `mut-llr-164-2.txt` |
| the path-limit node | M3 (limit disabled) | the 56-character name saved — `mut-llr-164-3.txt` |
| the census + forced-OSError arms | M4 (removal deleted) | census names the handler exit; the folder survives — `mut-llr-164-4.txt` |
| the empty-name node | M6 (first status reverted) and M7 ("no usable characters" status reverted) | missing `name is empty` / `type a project name` tokens — `mut-fix1-m6.txt`, `mut-fix1-m7.txt` |
| the forced-failure state assertions | M-F1 (the restore reverted, review F1's own counterfactual) | variant ids/paths and `current_project` left pointing into the removed folder — `mut-fix1-f1.txt` |
| the failed-merge arms | M-F5 (the placed-file unlink deleted) | `firmware.s19` survives in `ab`; the digest moved — `mut-fix1-f5.txt` |
| the case-variant arm | M-F4 (the LED .52(a) adoption bypassed) | `current_project == 'AB'` instead of the on-disk spelling — `mut-fix1-f4.txt` |
| the device arms | M-F3 (predicate back to the LAST-dot split) | `con.tar.gz` / `NUL.tar.gz` saved instead of refused — `mut-fix1-f3.txt` |
| the recursive-tree rollback arms | M-R2-1 (the snapshot back to a top-level name set) | the pre-existing `patches\hotfix.json` deleted on abort — `mut-fix2-r21.txt` |
| the SEC2-4 trap guard | the naive bare-name variant (applied by hand, reverted) | the rollback DELETES the reused pre-existing `patches\hotfix.json` — `red-fix2-naive-trap.txt` |
| the AST census | M-R2-4 (one exit reduced to a bare folder-removal) | the census names the exit: a bare `_remove_created_project_dir` no longer counts — `mut-fix2-r24.txt` |
| the mismatch newest-status arm | M-R2-5 (the re-paint skipped) | `Saved project to …` is the newest line, the MISMATCH buried — `mut-fix2-r25.txt` |
| the b99 F6a placement-failure node | M-F6a (`_remove_created_project_dir` no-op) | the created folder survives the placement failure — `mut-fix2-f6a.txt` |
| the b99 S-F5 pre-existing-folder node | M-S-F5 (`created_project_dir` forced True) | the pre-existing folder's sentinel destroyed — `mut-fix2-sf5.txt` |
| the junction-target rollback arm | the unfixed fix-pass-2 tree (its `rglob` walks follow the junction) AND M-R3-1 (the walker's reparse guard deleted) | the outside file `victim\user-work.txt` deleted — `red-fix3-save-guards.txt`, `mut-fix3-r31.txt` |
| the junction-cycle arm | the unfixed fix-pass-2 tree | the save refused with `[WinError 3] … ab\loop\loop\…` (~260 characters) — `red-fix3-save-guards.txt` |
| the walker unit arm | the unfixed fix-pass-2 tree (`walk_tree_no_links` absent) | `ImportError` — `red-fix3-save-guards.txt` |
| the denied-folder rollback arm (R7) | the unfixed fix-pass-3 tree (its snapshot cannot list the denied folder) AND mutant (b) (the tree-walk deletion back) | `ab/patches/keep.json` deleted — `red-fix4-r7-r8.txt`, `mut-fix4-b.txt` |
| the concurrent-writer rollback arm (R8) | the unfixed fix-pass-3 tree (its snapshot predates the file) AND mutant (b) (the tree-walk deletion back) | `ab/notes.txt` deleted — `red-fix4-r7-r8.txt`, `mut-fix4-b.txt` |
| the gather-reuse census arm | the pre-pass tree (the old gather's case-sensitive pre-check) AND mutant fix5-fix4-c (the `reused` flag ignored) | the reused `BOOST.json` lands in `written` — `red-fix5-new-arms.txt`, `mut-fix5-fix4-c.txt` |
| the case-variant save arms | the pre-pass tree | the pre-existing `BOOST.json` / `boost.JSON` deleted by the rollback — `red-fix5-new-arms.txt` |
| the fresh-verify no-folder arm | the pre-pass tree AND mutant fix5-sec2-8 | `freshv` left behind holding `project.json` — `red-fix5-new-arms.txt`, `mut-fix5-sec2-8.txt` |
| the merge-verify manifest-restore arm | the pre-pass tree AND mutant fix5-sec2-9 | `project.json` keeps the new bytes — `red-fix5-new-arms.txt`, `mut-fix5-sec2-9.txt` |
| the disk-full gather-home arm | the pre-pass tree AND mutant fix5-r5-1 | `freshp` (holding the empty `patches\`) left behind — `red-fix5-r5-1.txt`, `mut-fix5-r5-1.txt` |
| the empty-pre-existing-home arm | mutant Mf (round 5's survivor) | the pre-existing empty `patches/` removed — `mut-fix5-mf.txt` |
| the re-pinned TC-B100-57 census | the pre-pass tree | the census names the gather's rule unexpected — `red-fix5-census57.txt` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 31 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the painted status line | `"reserved name" in #log_line_4` (via `Label.render()`), at (118, 54) and (220, 60), after driving the dialog by keys | both tokens found at both sizes — `green-04` |
| the work area on disk | the SHA-256 manifest of every file under the work area before/after each refusal (TC-B100-04) and under `ab/` around the refused clash (TC-B100-05) | equalities held — `green-04` |
| the painted refusal tokens through the dialog | `already a project` + `'ab'` + `choose another name` in `#log_line_4` after typing `a b` with `ab` on disk | found — `green-04` |
| the junction's target on disk | the victim folder's SHA-256 manifest after the refused save | empty — `green-04` |
| the junction's target on disk during a FAILED save (R3-1) | the victim folder's file list after the forced gather failure — the concurrent writer's `user-work.txt` must survive | `['keep.txt', 'user-work.txt']` — `green-fix3` |
| `ab/patches/keep.json` after a failed save whose folder was read-denied at save start (SEC2-5 / R7) | the folder's file list after the forced refusal — the pre-existing `keep.json` must survive AND the placed `firmware.s19` must be gone | `['keep.json']` and `ab == ['a.s19', 'patches']` — `green-fix4` |
| `ab/notes.txt` after a failed save during which another writer created it (SEC2-6 / R8) | the file's bytes and the project folder's name list after the forced refusal — `notes.txt` must survive AND the placed `firmware.s19` must be gone | bytes equal, `ab == ['a.s19', 'notes.txt']` — `green-fix4` |
| `ab/patches/BOOST.json` (and `boost.JSON`) after a failed save that gathered `boost.json` (SEC2-7) | the file's bytes and the home's name list after the forced manifest failure — the case-variant file the placement REUSED must survive AND the placed image must be removed | bytes equal, home unchanged, `ab == ['a.s19', 'patches']` — `green-fix5` |
| the fresh folder `freshv` after a save whose manifest write succeeded and whose verify raised (SEC2-8) | the work-area folder list after the failure | `freshv` absent — `green-fix5` |
| `ab/project.json` after a merge whose manifest write succeeded and whose verify raised (SEC2-9) | the manifest's bytes and the project tree's digest manifest after the failure | byte-equal to the pre-save content, tree digest equal — `green-fix5` |
| the fresh folder `freshp` after a gather copy died post-`mkdir` (a full disk) and the manifest was refused (R5-1) | the work-area folder list after the failure | `freshp` absent — `green-fix5` |
| the empty pre-existing `ab/patches/` after a failed save that wrote into it (R5-2) | the home's existence and content after the forced refusal | still exists, empty — `green-fix5` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 13 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| correction-population-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/correction-population-fix2.txt | a2b6e507e46ff952196e8d40876ca2a8ca273c00fa162d4a4dbf6f9fb268f8a3 |
| correction-population-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/correction-population-fix3.txt | 98a10bce09cd44d3ccb2c30c097cb26b47212c262070d469512cef9784026c31 |
| correction-population-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/correction-population-fix4.txt | f5811b3d797805a749408410755094a873073fe50f81f7d9e37ab5d2469d735e |
| correction-population-fix5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/correction-population-fix5.txt | 37f783b090ef9fcc511bd491bfa6f7608a19ea193b262fe665d36c720cc69508 |
| correction-population.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/correction-population.txt | 8b52e57bdffc637dc39f98af9c375ce5bb0d601044de9757e5edc6d9608d6598 |
| green-01-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-01-save-guards.txt | dab6b2cae3b68209dc22708dafbf0768c1549c85539ffded4d548b7d9c5e4d75 |
| green-02-a09-variant.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-02-a09-variant.txt | 778f16d6bfdd78a2c34e3fac916ffed353f46ee17fb49636a6f8030b14711975 |
| green-03-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-03-save-guards.txt | e65d032aa0e142f467e60f10ddd1930e021d47c7c0bf379849825ef134156777 |
| green-04-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-04-save-guards.txt | a22ab542d31ef3ee064cfc44770d77cbb044b211159f719972b35cf58a42961b |
| green-fix1-a09-variant.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix1-a09-variant.txt | 6e160a5625da461c93b5a0e7b76879e15f8acab1b2f5eb3d882bbfc5becf23fc |
| green-fix1-save-guards-iter1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix1-save-guards-iter1.txt | da6f7f5ee6492a935fabd6b16b66d2f0219c5f5737793f378ea918e65527c8b2 |
| green-fix1-save-guards-iter2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix1-save-guards-iter2.txt | f7a2c56ae7b5e5e89fabc5dae587203ff90a879620cc245db42a8c57b946f99d |
| green-fix1-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix1-save-guards.txt | fcf112e19728661db1cbdfe7706353197aca6dfcde0372b9f9e63bbb9576c856 |
| green-fix2-guards-nodes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix2-guards-nodes.txt | c87e4605bd59734109098c9b82cb3eb73cae6d102fb74022118a8f71dce5d1a5 |
| green-fix2-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix2-save-guards.txt | fd246d58eac0ba60cc402d708303d20c542f89f2c7b8e861aa882ce51612229c |
| green-fix3-guards-nodes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix3-guards-nodes.txt | be69edfb27276df20f545f0a961fbad7fbbf54e5d5e27d0dbdd65b52f52d60c4 |
| green-fix3-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix3-save-guards.txt | f611b911e54bad913a59dcb61d52c9d0272ad04fd4de89ad396fb0158c03620c |
| green-fix4-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix4-save-guards.txt | 69e7e1a93c99ddfe38c19910c9f787e85a5bfa1a0f93a62d7d310ce4f2abfbac |
| green-fix5-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/green-fix5-save-guards.txt | cf4fc40d423a9a9b0c83fe50a09dfe54eb1ef31f4b8f6cae5885107204704570 |
| guards-census-fix1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census-fix1.txt | 79b1f6754a0548398cd29cb38f3be2d0dc1d0cbdf31799532fada33909815f6d |
| guards-census-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census-fix2.txt | 83afed2840759294d875c54e2aa8718b4c4870e56dd57aeeaccbd8a71ac03581 |
| guards-census-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census-fix3.txt | d8b1bdab02c1ade4ae81954e56742e7ddc4cfe0962bbc7a4b737b79f1d8cf82e |
| guards-census-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census-fix4.txt | ce7b0cced894b672c931ce822731e099e3060a6aebe79a63083bb6d639001ffb |
| guards-census-fix5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census-fix5.txt | f6784ffa816ceac37ce2fd57f9edf28c32f953735efff9d316708b96f7053837 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-census.txt | 49b3e6982b626b3462a3737e79e4e10b0f4f1ef85551d86413078a4598068d63 |
| guards-fix1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-fix1.txt | 71e12d58563202b8bc22503d304625875c87ba1c034b15e28d5a2915a45d6610 |
| guards-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-fix2.txt | d7a338dd115cd4178fb1cba5dbe8044b7f52bbba908007c6d724602093968704 |
| guards-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-fix3.txt | 1678846009380e9fd1dc66ec3e84ac12b8625557aad71496a00b5a90cab66a2e |
| guards-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-fix4.txt | ed2dc0d6ebf531de6dc54deea2be1aaafbc7c50b719fa9fe861ef07b0c7889d7 |
| guards-fix5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards-fix5.txt | 5379f37616eb6bcec703f9c624c8c42f14faccd9ac0379f345653b324cd4d80e |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/guards.txt | 2c380395fc4971d547f0fafc423e2fb4c6a09141c126a7d00f0bb6bbd3a660ef |
| import-proof-fix1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/import-proof-fix1.txt | 8813a367a85965da10d019dc06a5f317e64bae943020551887bd77f85475791c |
| import-proof-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/import-proof-fix2.txt | 1af71df5b7795a32e5acab43a5ef0e0d9aaebdcd5bf69f0310c0e4ec4d7cfb26 |
| import-proof-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/import-proof-fix4.txt | ff75d54a8ed73ac2c3b09376228c814c7f3a57484d9bd0e5b2639c5dcf9b0bd9 |
| import-proof-fix5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/import-proof-fix5.txt | c581be5d6533f9eca0b05a79d4f2d5f70daca2583d4edba2ee7ac84c62d670cc |
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/import-proof.txt | a693903c7bc3c213a016824c144ebeaa48c897c6f60dc7f45e72760b2636c3b6 |
| mut-fix1-f1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-f1.txt | 76cbae6e8e5c7fb3dc3c54a7810e6d0af499c3cd4584de2639d3e8805a11ec53 |
| mut-fix1-f3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-f3.txt | 78346f32261aaf7f6daf27900c4e1d0203ffae7afce7edb299f7a22d46c53a21 |
| mut-fix1-f4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-f4.txt | 4f0877a6281d0facda1c50dfee5075f32d73d1fd0738471d59464fe1f0828eca |
| mut-fix1-f5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-f5.txt | 3a1d531087e0b7c913b0a1628561803ecb453d28cff398d1dc4054a3c99f3b99 |
| mut-fix1-m6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-m6.txt | ad21ed28575fc2a73d9fd5fc2268d0b0d0740ed451a200ac61642940b63019c7 |
| mut-fix1-m7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix1-m7.txt | a046d9f0f6d67b68b9726a33dc77f0fd427fcd18d0aadaa6722d9b144184ec77 |
| mut-fix2-f6a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix2-f6a.txt | ecda7161d7d9966ed7bd2bffc68770125bcfda91e174e2c9e8519055631231f8 |
| mut-fix2-r21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix2-r21.txt | 60ed36bdd5e27371ccedd353a5d177e5af91b5cfc8ac417073eb79cff59850c3 |
| mut-fix2-r24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix2-r24.txt | 41d846a743fad2bd25a400791814e2c6597437faa9fae84b1cfe15d078623e46 |
| mut-fix2-r25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix2-r25.txt | 3c2ff24e565f0eb413a1556272476ceb2ae1445f5c297de5737c6e59e03170a2 |
| mut-fix2-sf5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix2-sf5.txt | b9fe8619120707f7ed3e60c17472b3e215c9a7b795118b8debe2837bcc1f08e7 |
| mut-fix3-mr1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix3-mr1.txt | 9e04f96d953a05a510fc34e1aea5e8ec4d2a73de7d8b1c76a6d5ab998f6fcb71 |
| mut-fix3-mr2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix3-mr2.txt | 6e4b20ab936e939e0f9232e68a4adc5adaad76f0510f5298e91fc4e99e92dfb4 |
| mut-fix3-mr3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix3-mr3.txt | 43c0409b9cac215b804012c7f439cc01ba4a967bd7dd1f14c1fe37873548dfa7 |
| mut-fix3-r31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix3-r31.txt | 871860c345494583055b375aa7d8c34f80e4f1473d4f79a2922c07fb8e44450e |
| mut-fix4-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix4-a.txt | 928f9a51b63f69a13ff96fe1cb3640d4a57fbb71e43620f8fe59b10472d779b1 |
| mut-fix4-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix4-b.txt | b7c8fcf286d44777bd3fdf0020bb75dde3efd5a97cc67df4ef5943e82bb834e7 |
| mut-fix4-c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix4-c.txt | 2ec9b401abaff367fb36d5862a6f755877f6ffb684cb4ba5bfb8e43e348e93b3 |
| mut-fix5-fix4-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-fix4-a.txt | ae6764c0555a5734fce5fe350c1e1c5684e69366327369ad5d198de0ae872b5c |
| mut-fix5-fix4-c.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-fix4-c.txt | 6ee6434dc4ba783fdc5e114ba1e5aa47c6858e40f128673dc6981f7263b90c62 |
| mut-fix5-mf.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-mf.txt | 24671325d46f9d33d9558b5a4b240a7bfe63865ba7ec56ec0058330cb520a202 |
| mut-fix5-r5-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-r5-1.txt | 32646f6888683cdeb8677e56edb9f64bc548925a5b4fb6692e2d510cbd4295df |
| mut-fix5-sec2-8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-sec2-8.txt | 7e5ae6e2b4b386ec615177e8f74b2ca3c863aa4aad2d0185daddf0a5c9555125 |
| mut-fix5-sec2-9.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-fix5-sec2-9.txt | f5ea9b01b2779b573be8cb62e527839fc2b7db0e9bf9d26b6180a0017155939c |
| mut-llr-164-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-llr-164-1.txt | 3b63e2afd40fae8eca23832fbbf3486c93d626d1bab4a8ef378dfa19eb87c99c |
| mut-llr-164-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-llr-164-2.txt | a347369b785e3c154b9745201e0e106e40ef8c24b78ded3ab410359b20b6a913 |
| mut-llr-164-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-llr-164-3.txt | 31dffd21cf045b63f29d7cfd6c2851978b4bd64ea44e75bc3ea021977943de3c |
| mut-llr-164-4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/mut-llr-164-4.txt | dbffaab9dbad8dbde87b66f3cf9ec4707f42ef403784452501c05d69c32759d0 |
| pre-mutation-hashes-fix1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix1.txt | 27bcb71931a2d4ba3a1e04a48739cb7e30b4365438926790955ccb94b033b793 |
| pre-mutation-hashes-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix2.txt | a4c9f9e7bdba2c568c76ba8a3545b22a6f0f22ad52f5e87ec3b38d8e713f6c3b |
| pre-mutation-hashes-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix3.txt | 5fb4a5869c6bac917d3e8dd064a8e2afb6881c34579c381aedb9c6b8f8fb47e0 |
| pre-mutation-hashes-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix4.txt | 43ab4db7d0881d9a7613cccc003781c1dc1a5c1d3d9bdb64b9d4abe83cec224f |
| pre-mutation-hashes-fix5-mutants.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix5-mutants.txt | cfcf64bb7ffc91b2d968e5d81adfdd3d977b283cbbc65b72eabdeccc07c75386 |
| pre-mutation-hashes-fix5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes-fix5.txt | 8b7d6b588ffcd0df69cabdf5925f71c5157fded96f20e545481ea3fd1291b8d0 |
| pre-mutation-hashes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/pre-mutation-hashes.txt | 7723161657925ee90d1e6585ca4f1f5bc2864cb389bfccfd04eae40351c6a31f |
| red-01-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-01-save-guards.txt | d7a356fb7c732437f537ddbbec9a621ed44cb4b0382e63117568909b636f4808 |
| red-fix1-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix1-save-guards.txt | c2ab567235a373fb4303b7b9b71dd23198de6ae477db8a92c6d7c6a86609f534 |
| red-fix2-naive-trap.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix2-naive-trap.txt | e24068832d2b32c711588a2dafc405855b40d1ee5ee548a130eb1557281beb66 |
| red-fix2-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix2-save-guards.txt | dec3c553ccebd8b7c197e128ad2392c294af55e623b1fb3cf17f151301fd8602 |
| red-fix3-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix3-save-guards.txt | 55bf798e87d55fa08a2622781424e418b526db127a3302728155a3eb2ea86c29 |
| red-fix4-r7-r8.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix4-r7-r8.txt | e4383ed65890d1652170053cd82d84cf4b1ed5c5a0996f684316c1337945e7e1 |
| red-fix5-census57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix5-census57.txt | 865458d2cb85a76f67cf5d2add320066bd3cb74bf3fee0e529d49d2d60cc8539 |
| red-fix5-new-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix5-new-arms.txt | db1f10761bcf40ef56068ebe77265f472a79b89a3aa9bed53efe552b79101ad5 |
| red-fix5-r5-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/red-fix5-r5-1.txt | c4617ed4660712b03910ec79df7ae4f7d073d5cf5626caed72878771415a2a94 |
| repin-b99-staging.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/repin-b99-staging.txt | 75c5349981e212ae1a4c951d140ce8fa29f4db792c1ff1cdbf7edae93f537e9f |
| restore-fix2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/restore-fix2.txt | dcaff7ca07095a23a9fb6c3ce513d565796478a3281e5584b0cdf49487ac1892 |
| restore-fix3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/restore-fix3.txt | 5b832cb812451cea4bd39167e1d86d2ff2d820f103124c1742e756096f7fcd61 |
| restore-fix4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/restore-fix4.txt | d31022037afa9d94309b9fe503c398baed7be61844b3bf2aebd8a3000daaff7d |
| reverse-census-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-1.txt | b126fbdf6aba1a7089b986780c32393f2df6bbb2e1bc524d594745f0ba7d611f |
| reverse-census-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-2.txt | 950befbcab31aa0d498329d3a87781a46c7274bf54d93f9a6d85845c9c1b1087 |
| reverse-census-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-3.txt | 81832fa16d6ba690756165d31fdc92d5aa312274ddf4d2c29a4636904c503bdf |
| reverse-census-fix1-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix1-1.txt | 09682dd091e52d7e37d1196178c2d3c04e04a22ffb0db89efc0fb523bf05dcb8 |
| reverse-census-fix1-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix1-2.txt | 715fc53217d4fcb626cabbc5a777fb81d2d32c2f7b6c6cfab1c98792b5d89078 |
| reverse-census-fix1-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix1-3.txt | df7fd7b30ed3a4be4b28a8f3d01c90d532c8b840305aecc2a53864ffa9b579a9 |
| reverse-census-fix2-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix2-1.txt | 27590dd5679036c45247bb943debb67303a8f8f5a4c930cb42b8bf462703de83 |
| reverse-census-fix2-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix2-2.txt | 50bcaeb94085e2949f503245b0e38961f88ad3f28359bbc0c1ab91682af3dbb1 |
| reverse-census-fix2-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix2-3.txt | df00257350b8437a19ea905e04d8731635540ee26d0d4602ca82b6ce3b15d4ab |
| reverse-census-fix3-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix3-1.txt | 02291eb4f326a71a2e7acab8e3ad6138b0dbab4500b4092a113aae85fb9ed154 |
| reverse-census-fix3-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix3-2.txt | 8e603a546cee42a9df3d082518de6ce419b13d172bf18c4d59b3b2ae17ffa1f6 |
| reverse-census-fix3-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix3-3.txt | bc95585647aeb4e2645a33dc089a01a0f69d7b9fc59471f8d7086ee8698c9d5d |
| reverse-census-fix4-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix4-1.txt | 3e3c5968bcc5f79bf1bae48c1657f2645a34513a96d8fb054cd153e266fe62f4 |
| reverse-census-fix4-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix4-2.txt | 35e3a62438b452cc59325468c435647198496b92c1638598b7ad84736bcfd883 |
| reverse-census-fix5-1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix5-1.txt | bee156066a69f8b3b0bd5807157da017d9b2195179fd4a88646843efdd86415f |
| reverse-census-fix5-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix5-2.txt | 28fe934a1e19b00386bdee1e20fb9049df9ecce555e09d65d836ef70590fd9a5 |
| reverse-census-fix5-3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/reverse-census-fix5-3.txt | d1f553fabe65dfc2ecbd5c72fb3e6125d0aec7c404f15cafcac8db70bc2e112e |
| orchestrator-gate.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-2/orchestrator-gate.txt | eeeb12f17409b0578bdb6411cfee2172740ddc63df79529076f982393ac269c4 |

| Field | Value |
|---|---|
| **Evidence files** | `102 artifact(s), each at the declared home, with the digest of its bytes on disk` |

Superseded, kept on disk unhashed (F10): round-1 intermediates `green-01-save-guards.txt` and
`green-03-save-guards.txt` (superseded by `green-04-save-guards.txt`), and the fix-pass-1
debug iterations `green-fix1-save-guards-iter1.txt` / `green-fix1-save-guards-iter2.txt`
(test-only corrections; superseded by `green-fix1-save-guards.txt`). Fix pass 5: the R5-1 arm's first RED form in `red-fix5-new-arms.txt` (an `AttributeError` on the old seam name) is superseded by the behavioral `red-fix5-r5-1.txt`. Every transcript's first
line names the command, the tree and the environment (`PYTHONUTF8=1
PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>`, `NO_COLOR`
unset).

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | Yes — one per pass: (round 1) the TC-B100-07 census asserted NO post-creation `return` whose exit path skips the removal, and exactly one OSError handler; (fix pass 1, re-pinned) the census asserts NO post-creation `return` whose exit path skips the `_abort_save` rollback, and exactly one OSError handler AFTER the folder's creation; (fix pass 2, re-pinned again per R2-4) the census accepts ONLY `_abort_save` — a bare `_remove_created_project_dir` exit is NOT a rollback anymore; (fix pass 3) the snapshot and removal walks assert NO descent into a reparse point — a symlink or junction is yielded as a leaf and never pushed on the walker's stack; (fix pass 4, re-pinned per LED .53) the census asserts the rollback holds NO tree walk at all — no snapshot, no `rglob`, no walker — every deletion is one element of the placed-files / created-folders lists; (fix pass 5, re-pinned per SEC2-7) the TC-B100-57 census asserts the package holds NO byte-identity rule besides the placement's — the gather's own compare is gone. Each of the six is an ABSENCE claim. |
| If the result is an ABSENCE, what made the search wide enough | the probe parses the whole module AST: every `Return` after the `mkdir` line inside `_handle_save_dialog`, walking EVERY enclosing block (statements and `ExceptHandler` bodies), plus every `ExceptHandler` typed `OSError` (scoped post-`mkdir` in fix pass 1 — the pre-creation clash scan's skip-handler is deliberate, SEC2-1) and the `_abort_save` helper's own body (removal call + `unlink`/`rmdir` + state restore) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b100_07_ast_census_every_post_creation_return_removes` — its docstring says the census is the LLR-164.4 conclusion (every post-creation exit rolls the failed save back), not a behaviour pin; the behavioural arms are the forced-failure stages and the failed-merge arms |
| Conjunctive criteria: one mutation per conjunct | LLR-164.4's mutation (M4) kills both the census AND the forced-`OSError` arm while the sibling stage arms stay green — two conjuncts, one transcript (`mut-llr-164-4.txt`, 2 failed). Fix pass 1: M-F1 kills two stage arms (gather + manifest-refused), M-F5 kills two merge arms, M-F3 kills two device arms — each one transcript. Fix pass 2: M-R2-4 kills the census AND three behavioural arms (one transcript, `mut-fix2-r24.txt`, 4 failed) |
| Synthetic instance of the absent case | M4 is the synthetic re-introduction of the absent case (a removal-free exit) and the census names it; M1 is the synthetic re-introduction of the sanitised-only device check the raw-name arm exists to refuse; fix pass 1: M-F4 re-introduces the case-folded exemption width the LED .52(a) arm exists to refuse; fix pass 2: M-R2-4 re-introduces a removal-only exit (no state restore, placed files left) and the re-pinned census names it; fix pass 3: M-R3-1 re-introduces the reparse-point descent the junction arm exists to refuse, and the junction-target arm names it |
| **Positive control for every probe that returned an ABSENCE** | the positive control is the mutated tree itself: on M4 the census returns the NON-absent output (the handler exit without removal) and fails; on the base tree the module could not even collect (`red-01`); fix pass 1: on M-F1/M-F5 the behavioural arms return the NON-absent output (stale app state / placed files left behind) and fail; fix pass 2: on M-R2-4 the census returns the NON-absent output (an exit whose only rollback is the bare folder-removal) and fails; fix pass 3: the absence claim is "the snapshot and removal walks never descend into a reparse point" — M-R3-1 re-introduces the descent and the junction-target arm returns the NON-absent output (the outside file deleted) and fails (`mut-fix3-r31.txt`), and the unfixed fix-pass-2 tree fails the same arm for the same reason (`red-fix3-save-guards.txt`); fix pass 4: the absence claim is "the rollback walks no folder" — mutant (b) re-introduces the tree-walk deletion and arms R7/R8 return the NON-absent output (`keep.json` / `notes.txt` deleted) and fail (`mut-fix4-b.txt`), and the unfixed fix-pass-3 tree fails the same arms for the same reason (`red-fix4-r7-r8.txt`); fix pass 5: the absence claim is "no second byte-identity rule" — the pre-pass tree itself is the positive control (the census returns the NON-absent output, the gather rule unexpected, and fails — `red-fix5-census57.txt`), and mutant fix5-fix4-c re-introduces the disagreement at the flag level and the census arm fails (`mut-fix5-fix4-c.txt`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "_handle_save_dialog\|list_projects\|sanitize_project_name\|_remove_created_project_dir\|_abort_save\|is_windows_device_name\|_write_and_verify_manifest\|walk_tree_no_links\|gather_project_artifacts\|GatherOutcome\|created_homes\|home_preexisted\|_gather_copy\|_same_artifact_name\|manifest_restores\|on_written" tests/ --include=*.py` | 17 files on the union (the per-symbol census: `_gather_copy` → `test_b100_reuse.py` + `test_b99_staging.py` + `test_copy_into_workarea_content_dedup.py`; `_same_artifact_name` → NO test references — the deleted symbol is clean; `created_homes` / `home_preexisted` → the new module only; `_abort_save` → the new module + `test_b99_staging.py`; `_write_and_verify_manifest` → `test_tui_report_seam.py`; `on_written` / `manifest_restores` → no test references; the remaining files of the union reference only `copy_into_workarea`, whose wrapper is untouched — `correction-population-fix5.txt` records all greps verbatim). Round 1: chunk 1 152 passed; chunk 2 132 passed, 1 xfailed; chunk 3 116 passed (`reverse-census-{1,2,3}.txt`). Fix pass 1: chunk 1 150 passed + 2 re-pinned nodes (re-run green — `repin-b99-staging.txt`), chunk 2 132 passed, 1 xfailed, chunk 3 116 passed (`reverse-census-fix1-{1,2,3}.txt`). Fix pass 2: chunk 1 (every census file except `test_b99_staging.py` / `test_tui_report_seam.py`) 372 passed, 1 xfailed; chunk 2 (`test_b99_staging.py`, incl. the two pre-named F6a / S-F5 nodes) 31 passed; chunk 3 (`test_tui_report_seam.py`, the `_write_and_verify_manifest` direct caller) 28 passed (`reverse-census-fix2-{1,2,3}.txt`). Fix pass 3 (the grep gains `walk_tree_no_links` — still 16 files, the walker referenced only by the new module, `correction-population-fix3.txt`): chunk 1 375 passed, 1 xfailed; chunk 2 31 passed; chunk 3 28 passed (`reverse-census-fix3-{1,2,3}.txt`). Fix pass 4 (LED .53 — the grep gains `gather_project_artifacts` / `GatherOutcome` / `created_homes`, still 16 files: the gather is referenced by `test_b100_reuse.py`, `test_b99_staging.py` and `test_project_gather.py`, all already in the census, `correction-population-fix4.txt`): chunk 1 369 passed, 1 xfailed; chunk 2 (`test_b99_staging.py`, incl. the LLR-155.3 final-name census over the redesigned `_abort_save`) 31 passed (`reverse-census-fix4-{1,2}.txt`). Fix pass 5 (the per-symbol census above, `correction-population-fix5.txt`): chunk 1 (`test_b100_reuse.py`, incl. the re-pinned TC-B100-57 census and the direct `_gather_copy` arms) 38 passed (`reverse-census-fix5-1.txt`); chunk 2 (`test_b99_staging.py` incl. the LLR-155.3 final-name census over the SEC2-9-extended `_abort_save`, `test_project_gather.py`, `test_copy_into_workarea_content_dedup.py`) 48 passed (`reverse-census-fix5-2.txt`); chunk 3 (`test_tui_report_seam.py` + the A-09 guard node) 29 passed (`reverse-census-fix5-3.txt`) |
| B1 `_write_and_verify_manifest` | `grep -rln "_write_and_verify_manifest" tests/ --include=*.py` | 1 file (`test_tui_report_seam.py`, in chunk 3) — its callers ignore the return value; 28 passed unchanged on the fix-pass-2 tree (the new `_last_manifest_verify_result` side channel changes no signature) and re-validated on the fix-pass-5 tree (chunk 3 — the new `on_written` keyword defaults to None, every existing call site unchanged) |
| B2 file moved on disk | n/a — no file moved | no readers |
| B3 byte-identical golden captures this source | `grep -rn "workspace.py\|app.py" tests/goldens/ 2>/dev/null` | no hits |
| B4 artifact produced here is consumed elsewhere | `list_projects` output feeds the Load project dialog (Inc 9b's consumer) | its existing tests re-validated unchanged |
| A3 interface consumed by another module changed | B100-I11 frozen HERE (as amended by F3 / SEC2-2 — first-dot stem, frozen again at fix pass 1); B100-I13 consumed unchanged — `copy_into_workarea` still the one-line wrapper (its AST shape pinned by TC-B100-01, re-run in chunk 1) | chunk 1 green |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1 ×2, B2, B3, B4, A3): 16 test files found. Round 1: 400 passed, 1 xfailed. Fix pass 1: 398 passed, 1 xfailed across `reverse-census-fix1-{1,2,3}.txt`, plus the 2 re-pinned nodes green in `repin-b99-staging.txt`. Fix pass 2: 431 passed, 1 xfailed across `reverse-census-fix2-{1,2,3}.txt` — no new re-pins; both fix-1 re-pins re-verified green in `green-fix2-guards-nodes.txt`. Fix pass 3: 434 passed, 1 xfailed across `reverse-census-fix3-{1,2,3}.txt` (375 + 1 xfailed, 31, 28) — no new re-pins; the A-09 guard and both b99 re-pins re-verified green in `green-fix3-guards-nodes.txt`. Fix pass 4: 436 passed, 1 xfailed across the 36-node module run + `reverse-census-fix4-{1,2}.txt` (369 + 1 xfailed, 31) — 2 re-pins recorded (below), the A-09 guard and both b99 re-pins re-verified green inside the census chunks. Fix pass 5: 158 passed across the 43-node module run + `reverse-census-fix5-{1,2,3}.txt` (38, 48, 29) — 1 re-pin recorded (below); the A-09 guard re-verified green inside chunk 3; `test_project_gather.py` re-validated (48-node chunk 2) per the brief |

**Re-pins recorded (old → new → requirement):**

1. `test_tc_b100_07_ast_census_every_post_creation_return_removes` — old: a post-creation
   exit's block must contain a `_remove_created_project_dir` call and exactly one OSError
   handler anywhere in the handler — new: the call may be the one `_abort_save` rollback
   (the helper itself is censused: removal call + `unlink` + `_variant_set` restore), and
   the OSError-handler count scopes to handlers AFTER the `mkdir` (the pre-creation clash
   scan keeps its own `except OSError` skip) — requirement: LED .52(b) / F1 / F5 / SEC2-1.
2. `test_at_b99_05_save_project_after_same_name_save_back` — old: the newest painted
   status after a save starts with `"Project saved"` (the manifest line) — new: it starts
   with `"Saved project to"` (the success line paints LAST, after `project.json` is on
   disk; the manifest-verify line is asserted in the painted log) — requirement: F1 (a
   save that can still fail must not have said "Saved").
3. `test_tc_b99_13_no_final_name_replace_outside_placement` — old: the app.py
   LLR-155.3 allow-list is `{action_dump_a2l_json}` — new: adds `_abort_save` (every
   unlink is guarded by the pre-save folder snapshot — nothing pre-existing is removed) —
   requirement: LED .52(b) / F5.
4. `test_tc_b100_07_forced_oserror_leaves_no_folder[copies]` helper `_force_stage` —
   old: the `copies` stage monkeypatches `app_module.copy_into_workarea` — new: it
   monkeypatches `app_module.place_into_workarea` (the seam the save body actually
   calls since the LED .53 redesign, which needs the `PlacementResult.reused` flag) —
   requirement: LED .53 / LLR-164.4.
5. `test_tc_b100_07_ast_census_every_post_creation_return_removes` — old: the census
   required a `_remove_created_project_dir` call inside `_abort_save` — new: the
   folder-removal pin is `_abort_save` containing a `rmdir` (the created folders go
   deepest first, each only while empty; the helper `_remove_created_project_dir`
   and the snapshot machinery are gone) — requirement: LED .53 / LLR-164.4. The
   census's standing rules are unchanged: every post-creation exit rolls back through
   the ONE `_abort_save`, and `_abort_save` restores the pre-save app state.
6. `test_tc_b100_57_export_holds_no_byte_identity_rule` — old: the declared-rules
   set of the package's byte-identity census holds TWO declared rules besides the
   single-file placement rule — the group placement rule (R30) AND the gather's
   sibling byte-scan (`project_gather_service._gather_copy`) — new: the declared
   set holds ONLY the group rule; the gather places through `place_into_workarea`
   and translates only its `reused` flag, so the placement's rule is the SOLE
   byte-identity judge and no second rule can disagree with it (the case-variant
   deletion SEC2-7's probe executed) — requirement: SEC2-7 (security round 4).

`tests/test_tui_variants.py::test_save_second_s19_into_project_appends_variant` stayed GREEN
unchanged (A-09, `green-fix1-a09-variant.txt`). No `#project_parent_path` test was touched.

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| every exit after the folder's creation must remove the folder it created | every post-creation `return` and `except OSError` handler of `_handle_save_dialog` | AST census at test time (the census derives the set from the handler's source, ≥ 3 returns per the contract's threshold) | 7 removal sites on 7 post-creation exits (validation, the MAC guard, the A2L guard, placement, containment, the manifest write, the OSError handler) | 7 (the pre-existing 2 placement/containment calls kept; 5 added) | 0 |
| reserved homes must never list as projects | every `list_projects` name comparison | `grep -n "RESERVED_WORKAREA_HOMES" s19_app/tui/app.py` | 2 call shapes (the save guard, the listing) | 2 | 0 |
| a failed save restores the app state and removes the files it placed | every post-creation failure exit of `_handle_save_dialog` + every placement call in the save body | the AST census (each exit's block must call `_abort_save`) + `grep -n "copy_into_workarea" s19_app/tui/app.py` for the 3 placement calls whose results are tracked | 7 exits folded into ONE `_abort_save` helper (its own body censused: restore + unlink + remove); 3 placement results tracked in `placed_paths` | 8 (the helper + 7 exit call sites) | 0 |
| the open project's case-variant name saves under the on-disk spelling | the open-project exemption branch of the clash scan | code read of the scan loop | 1 adoption site (`cleaned = item.name`, guarded `item.name != cleaned`) | 1 | 0 |
| a failed save removes EVERY file and folder it placed, including the gather's copies and their home folders, and never a pre-existing path (R2-1 / SEC2-4) | the whole project tree under the target, recursively — the pre-save snapshot + the abort's removal walk | code read of the save body (the snapshot precedes every placement) + `grep -n "rglob\|rmdir\|unlink" s19_app/tui/app.py` on the `_abort_save` window | 1 snapshot site (`_project_tree_snapshot`, first statement of the try) + ONE removal walk in `_abort_save` (deepest first; `unlink` for files, `rmdir` for folders; skip when the relative path is in the snapshot) + 7 exit call sites (unchanged) | 9 | 0 |
| the rollback never follows a reparse point — a junction/symlink inside the project is a leaf, never entered; nothing outside the work area is reachable and a junction cycle cannot loop the walk (R3-1) | BOTH walks (the pre-save snapshot and the abort's removal walk) | code read: `grep -n "rglob\|walk_tree_no_links" s19_app/tui/app.py` on the save-rollback window + the walker unit arm enumerates the yield contract | ONE walker (`workspace.walk_tree_no_links`) consumed at 2 sites (the snapshot + the removal walk) | 2 | 0 |
| the rollback removes exactly what THIS save created — the non-reused placements and the files the gather wrote, plus the created folders while empty — and never a pre-existing or concurrently-written path (LED .53, SEC2-5 / SEC2-6) | every file-creating statement of the save body: the 3 placements (`place_into_workarea` results tracked by `reused`), every `_gather_copy` destination (`copied` only), the home folders' existence read BEFORE the copy, and the project folder's mkdir | code read of the save body + `grep -n "place_into_workarea\|copy_into_workarea\|_gather_copy\|mkdir" s19_app/tui/app.py s19_app/tui/services/project_gather_service.py` + the gather loop | 3 placement sites + the gather loop (ONE `written` append + ONE `created_homes` append) + ONE rollback helper consuming both lists + 7 exit call sites (unchanged) | 11 | 0 |

| Field | Value |
|---|---|
| **Correction population** | 7 corrections, each enumerated with its command (`correction-population.txt` records the round-1 symbol census; `correction-population-fix2.txt` re-runs it — the population is unchanged at 16 files and the new `_project_tree_snapshot` symbol is referenced by no test; `correction-population-fix3.txt` re-runs it with `walk_tree_no_links` added to the grep — still 16 files, the walker referenced only by the new module; `correction-population-fix4.txt` re-runs it with `gather_project_artifacts` / `GatherOutcome` / `created_homes` added — still 16 files: the gather is referenced by `test_b100_reuse.py`, `test_b99_staging.py` and `test_project_gather.py`, all in the census); the return census is derived from the AST by the test itself |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| the case-SENSITIVE reserved filter in `list_projects` | replaced by the case-folded set (`app.py`, `list_projects`) | yes | `test_tc_b100_04_list_projects_omits_reserved_homes_casefolded` in `green-04` |
| the bare `"Invalid project name."` refusal | replaced by the token-painted empty-name refusal | yes | `test_tc_b100_04_empty_names_refused` — armed in fix pass 1 (F6; M6/M7 in `mut-fix1-m6.txt` / `mut-fix1-m7.txt` prove the revert dies) |
| the snapshot-difference rollback (`_project_tree_snapshot` + the deepest-first diff walk + `_remove_created_project_dir`) | replaced by the exact-list rollback (LED .53): `placed_files` (non-reused placements + `GatherOutcome.written`) + `created_dirs` (`GatherOutcome.created_homes` + the created project folder), `rmdir` while empty | yes — `grep -n "_project_tree_snapshot\|_remove_created_project_dir" s19_app/tui/app.py` returns no hit; the only surviving mention is the historical M-F6a docstring in `test_b99_staging.py` | arms R7 / R8 (`red-fix4-r7-r8.txt` on the fix-pass-3 tree; GREEN in `green-fix4-save-guards.txt`); mutant (b) in `mut-fix4-b.txt` proves the revert dies |
| the gather's case-sensitive sibling byte-scan (`_same_artifact_name` + the `read_bytes` pre-scan in `_gather_copy`) | replaced by the placement's own byte-identity rule — `_gather_copy` calls `place_into_workarea` and translates only `PlacementResult.reused` (SEC2-7) | yes — `grep -n "_same_artifact_name" s19_app/` returns no hit; the TC-B100-57 census re-pinned (§4 re-pin 6) | arms `gather_reuse_never_ends_in_written` + both `case_variant` arms (`red-fix5-new-arms.txt` on the pre-pass tree; GREEN in `green-fix5-save-guards.txt`); mutant fix5-fix4-c in `mut-fix5-fix4-c.txt` proves the revert dies |

### Signed-balance test ledger

Scanned-file ledger (what `EXPECTED_SCANNED_TEST_FILES` pins):
`post = base − deleted + added` → `216 = 215 − 0 + 1` ✓ reconciles
(`tests/test_b100_save_guards.py` is the one added scanned file; `tests/test_id_registry.py`
bumps the bound by the measured count; nothing deleted.)

Node ledger (test functions collected in the module):
round 1: `18 nodes = 3 (TC-B100-04) + 5 (TC-B100-05) + 2 (TC-B100-06) + 6 (TC-B100-07) + 2 (AT-B100-02)`;
fix pass 1: `27 nodes = 5 (TC-B100-04) + 7 (TC-B100-05) + 2 (TC-B100-06) + 11 (TC-B100-07) + 2 (AT-B100-02)`
(the added 9: empty names, the device-predicate unit, the case-variant save, the
case-only-against-another arm, the `manifest-refused` stage, 3 failed-merge arms, the
unreadable-folder arm; the reserved/device/listing/census/forced arms gained assertions);
fix pass 2: `31 nodes = 5 (TC-B100-04) + 7 (TC-B100-05) + 2 (TC-B100-06) + 15 (TC-B100-07) + 2 (AT-B100-02)`
(the added 4: the recursive-tree rollback node with its 3 cases — merge-gathered,
merge-gathered-reused, fresh-gathered — and the manifest-MISMATCH newest-status node;
the census re-pinned to `_abort_save` ONLY per R2-4);
fix pass 3: `34 nodes = 5 (TC-B100-04) + 7 (TC-B100-05) + 2 (TC-B100-06) + 18 (TC-B100-07) + 2 (AT-B100-02)`
(the added 3: the Windows-only junction-target rollback arm, the
junction-cycle arm and the `walk_tree_no_links` unit arm — R3-1);
fix pass 4 (LED .53): `36 nodes = 5 (TC-B100-04) + 7 (TC-B100-05) + 2 (TC-B100-06) + 20 (TC-B100-07) + 2 (AT-B100-02)`
(the added 2: `test_tc_b100_07_rollback_keeps_denied_folder_content_r7` and
`test_tc_b100_07_rollback_keeps_concurrent_writer_file_r8`; the census and
the `copies` stage re-pinned, recorded in §4);
fix pass 5 (the corrective pass): `43 nodes = 5 (TC-B100-04) + 7 (TC-B100-05) + 2 (TC-B100-06) + 27 (TC-B100-07) + 2 (AT-B100-02)`
(the added 7: `test_tc_b100_07_gather_reuse_never_ends_in_written`,
`test_tc_b100_07_case_variant_reused_file_survives_failed_save` ×2,
`test_tc_b100_07_failed_verify_leaves_no_folder_fresh`,
`test_tc_b100_07_failed_verify_restores_previous_manifest`,
`test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left` and
`test_tc_b100_07_empty_preexisting_home_survives_failed_save`; the
TC-B100-57 census re-pinned, recorded in §4).
Deleted: none. Windows-only arms: 8 of 43 (`test_tc_b100_05_junction_target_refused_without_writing`,
`test_tc_b100_07_unreadable_workarea_folder_skipped`,
`test_tc_b100_07_rollback_never_touches_junction_target`,
`test_tc_b100_07_junction_cycle_does_not_block_save`,
`test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf`,
`test_tc_b100_07_rollback_keeps_denied_folder_content_r7`,
`test_tc_b100_07_case_variant_reused_file_survives_failed_save` ×2 —
executed here on Windows; on other
platforms they skip with the named PDR C-QA-6 reason).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS after 6 rounds (r1 BLOCK-UNTIL F1/F2 HIGH; r2 BLOCK-UNTIL R2-1/R2-2; r3 BLOCK-UNTIL R3-1 HIGH; r4 PASS-WITH-NOTES; r5 PASS-WITH-NOTES after the LED .53 redesign; r6 PASS, 0 HIGH / 0 MAJOR) — `review-increment-002.md`. `security-reviewer` · r1 PASS-WITH-NOTES (SEC2-1 MAJOR); r2 PASS-WITH-NOTES; r3 PASS-WITH-NOTES (SEC2-5 MAJOR → operator redesign LED .53); r4 BLOCK-UNTIL SEC2-7 HIGH; r5 PASS-WITH-NOTES, SEC2-10 routed to Inc 7 (LED .54) — `security-increment-002.md`. Orchestrator re-run on the final tree: 130 passed (Inc 2 files + A-09), guards 75 passed + 29 snapshots, census sweep 85 passed — `evidence/inc-2/orchestrator-gate.txt`. Operator decisions: bounded pass 3 at the iteration cap; "Lista exacta" redesign at the stop it triggered. |

---

## 5 · Risks

- **(Inc 11 dependency — review finding F11, no code change here):** the
  path-limit check and the Q-2 clash scan measure against `self.workarea`,
  while the save target is built from the `#project_parent_path` field
  (`parent_resolved / cleaned`). Choosing another parent therefore skips the
  clash check and mis-measures the length check (`resolve_input_path` can also
  lengthen an 8.3 base). The contract names `self.workarea`, so this stays a
  note: removing the parent field at Inc 11 (D7) closes it.
- The exact-name merge carry (`gathered`, `active_document`, the carried
  manifest keys) is Inc 8a's work per the proposal's table and LED .52(b) —
  TC-B100-05 here covers only the Inc 2 arms (refusals, open-project save in
  both spellings, exact-name variant add); the mid-merge failure rollback
  (placed files + app state) is covered HERE by the TC-B100-07 merge arms.
  The junction arm is covered HERE (LLR-164.2's "refused before `resolve()`"
  clause); the merge's own carry arrives with Inc 8a.
- `_write_and_verify_manifest`'s verify-MISMATCH path remains a drift report (LLR-004.2), not a
  save failure: only a failed WRITE rolls the save back. Both surfaces are armed: a
  forced `OSError` at the manifest stage exercises the handler; a `(None, issues)` writer return
  exercises the rollback via the success flag (the writer never raises by design,
  collect-don't-abort) — TC-B100-07's `manifest-refused` arm, with the app-state and
  placed-file assertions of LED .52(b).
- The Q-2 enumeration compares the typed name case-folded FIRST and lists
  inside only the matching folder (F8); an unreadable folder is skipped
  (`except OSError`), the same as `list_projects` treats it, so it never
  crashes the save (SEC2-1). LED .50 applies: the enumeration uses
  `_is_reparse_point` (lstat-based) and never resolves.
- The device predicate folds superscript digits ¹²³ → 123 the way the
  Windows file namespace does and matches the stem before the FIRST dot with
  trailing spaces/dots stripped (F3 / SEC2-2 — `NUL.tar.gz` names `NUL`);
  `COM⁴` is not a device name. On a POSIX host the predicate still refuses
  the Windows device names (harmless over-refusal — the work areas this tool
  writes target Windows path limits).
- **(Fix pass 3, R3-1 — for Inc 8b):** `workspace.walk_tree_no_links` is the
  ONE non-following tree walk this batch reuses. Inc 8b's save-as
  (LLR-171.1) must consume this same walker for its snapshot/removal walks
  instead of `rglob` — it never descends into a symlink or junction, yields
  reparse points as leaves and cannot loop on a cycle. Unit arm:
  `test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf`.
- **(Fix pass 3 — bounded pass):** this pass changes ONLY what
  `kimi/BRIEF-inc-2-fix3.md` lists (R3-1, R3-2). Anything else found stays
  unfixed; the record items the rounds carried (`HANDOFF.md`'s location at
  the worktree root) remain with the orchestrator.
- **(Fix pass 4, LED .53 — the new exactness trade-off, by design):** a
  created folder (the project folder included) is removed only while
  empty — a file another writer drops into it during the save is NOT
  removed (it is not something this save created; SEC2-6's ruling covers
  every folder, not only pre-existing ones). Symmetrically, the rollback
  no longer "cleans up" anything it cannot attribute — the
  snapshot-difference's over-deletion (SEC2-5) is traded for this
  under-deletion, which loses nothing the save did not own.
- **(Fix pass 4, LED .53 — for Inc 8b):** `workspace.walk_tree_no_links`
  stays the ONE non-following tree walk, but the Save rollback is no
  longer its consumer — the rollback walks no folder at all. Inc 8b's
  save-as (LLR-171.1) must still consume this walker (never descends into
  a symlink or junction, yields reparse points as leaves, cannot loop on a
  cycle); its unit arm `test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf`
  is kept.
- **(Fix pass 4, LED .53 — for Inc 8a):** `GatherOutcome.written` /
  `GatherOutcome.created_homes` are the exact-created lists a future
  save-as or merge-carry rollback consumes the same way — a caller that
  rolls a gather back must unlink `written` and `rmdir` `created_homes`
  (deepest first, only while empty), never a tree difference.

## 6 · Pending items / spec deviations

- **(Resolved by LED .52(c) — the round-1 reading is withdrawn):** HLR-164's
  black-box acceptance phrase "With project `ab` saved and P2 open" means
  ANOTHER project (E4's P2, `prg.s19`) is open. AT-B100-02 drives exactly
  that: it builds `prg` and `ab` by REAL saves through the shipped dialog,
  opens P2 through the shipped Load project surface by keys (rail `1`, then
  the `#ws_load_project_button` click — the Segment Split window binds `p`
  for its own pad cycle once a file is loaded, the documented drive in
  `test_b99_load_project`), asserts the painted log names
  ``Loaded project 'prg'``, and only then refuses `a b` naming `ab`. The
  earlier §6 reading (P2 = a loaded file) is superseded.
- Windows-only arms: `test_tc_b100_05_junction_target_refused_without_writing`
  uses `_winapi.CreateJunction`;
  `test_tc_b100_07_unreadable_workarea_folder_skipped` uses an `icacls`
  deny-read folder;
  `test_tc_b100_07_rollback_never_touches_junction_target`,
  `test_tc_b100_07_junction_cycle_does_not_block_save` and
  `test_tc_b100_07_walk_tree_no_links_yields_reparse_point_as_leaf` use
  `_winapi.CreateJunction` too (fix pass 3, R3-1);
  `test_tc_b100_07_rollback_keeps_denied_folder_content_r7` uses an
  `icacls` deny-read folder lifted mid-save (fix pass 4, LED .53 / SEC2-5);
  `test_tc_b100_07_case_variant_reused_file_survives_failed_save` ×2 rely
  on case-insensitive names (fix pass 5, SEC2-7).
  On other platforms all eight `pytest.skip` with the named reason (PDR
  C-QA-6; counted per PDR C-QA-6; this run executed them on Windows).
- **(Fix pass 5, SEC2-9 — the restore's staging):** the manifest restore
  stages the previous bytes in the work area's private staging home
  (`workspace._private_stage_dir`) and `os.replace`s them over the failed
  manifest — the staging idiom of LLR-155.1, never a torn write; the
  rollback catches every `OSError` / containment refusal and still never
  raises (LLR-164.4). The merge-carry of the pre-save manifest's keys is
  Inc 8a's; this pass only restores its bytes.
- The AT drives the CURRENT Save project dialog (with `#project_parent_path`),
  per the brief; Inc 11 replaces that dialog and re-pins its ids — no
  `#project_parent_path` test was touched.
- No snapshot cell changed (`guards.txt`: 29 passed; re-confirmed at fix
  pass 3 — `guards-fix3.txt`: 75 passed, none changed — and at fix pass 5 —
  `guards-fix5.txt`: 75 passed + 29 snapshot cells unchanged). None was
  expected to.
- **(Fix pass 2, R2-5):** the ux-reviewer's question ("is the toast enough,
  or should the success line carry `(manifest MISMATCH)`?") is resolved by
  the brief's instruction: the MISMATCH status line is re-painted as the
  NEWEST line after `Saved project to …` (the notice still fires once, and
  the mismatch stays in the 4-line log). The painted order on a mismatch
  save is: `Project saved + manifest verified` (absent) / verify surfacing →
  `Saved project to …` → `Manifest verify MISMATCH`. On a clean save the
  order is unchanged from fix pass 1: verify line → `Saved project to …`.

## 7 · Suggested next task

Increment 3 (LLR-165.x — a project load starts clean), per the proposal's hard order.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 source files (per LED .53) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b100_save_guards.py` (round 1: 18 nodes; fix pass 1: 27 nodes — 5 + 7 + 2 + 11 + 2; fix pass 2: 31 nodes — 5 + 7 + 2 + 15 + 2; fix pass 3: 34 nodes — 5 + 7 + 2 + 18 + 2; fix pass 4: 36 nodes — 5 + 7 + 2 + 20 + 2; fix pass 5: 43 nodes — 5 + 7 + 2 + 27 + 2) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the AST census node — `green-04`, re-pinned and green in `green-fix1-save-guards`, re-pinned again per LED .53 (folder-removal pin → `rmdir`) and green in `green-fix4-save-guards`, green again in `green-fix5-save-guards` |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 RED table: `red-01` (base collection error) + `red-fix1` (14 failed on the unfixed tree) + `red-fix2` (2 failed) + `red-fix3` (3 failed) + `red-fix4` (2 failed) + `red-fix5` (6 failed / 3 passed + 1 failed, against the byte-exact reconstructed pre-pass tree) + 28 mutation transcripts (4 round-1 + 6 fix-pass-1 + 5 fix-pass-2 + 4 fix-pass-3 + 3 fix-pass-4 + 6 fix-pass-5), restores hash-verified |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 reverse census, 5 probes, 16 files re-validated (fix pass 4: 436 passed, 1 xfailed + A-09/b99 re-pins green inside the census chunks, 2 re-pins recorded; fix pass 5: 158 passed with the 43-node module — chunks 38 / 48 / 29, 1 re-pin recorded) |
| 6 | `code-reviewer` passed | `core` · `full` | pending | §4b |
| 7 | No file from another lane touched | all | ✓ | only the 3 named source files |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | B100-I11 frozen HERE (as amended); B100-I13 consumed unchanged — `copy_into_workarea` still the one-line wrapper (its AST shape pinned by TC-B100-01, re-run in chunk 1); LED .53 and SEC2-7 amend only the consumers' internals — the save body and the gather still place through the one placement function (`place_into_workarea` is B100-I13's own entry point, not a second claim loop), and the placement's byte-identity rule is the sole judge |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every `N passed` appears in a cited transcript |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 load-bearing emptiness (M1/M4/M-F4 synthetic instances) |
| 11 | **Mutation verdicts** declared — **per arm** | all | ✓ | §4 mutation verdicts (28/28 KILLED — 4 round-1 + 6 fix-pass-1 + 5 fix-pass-2 + 4 fix-pass-3 + 3 fix-pass-4 + 6 fix-pass-5 incl. round 5's survivor Mf, restores hash-verified) |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 instrument table (31 instruments) |
| 13 | **Correction population** declared | all | ✓ | §4 correction population (7 corrections) |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 emitted-form table (13 artifacts) |
| 15 | **Independent review** names somebody | all | pending | §4b |
| 16 | **Evidence files** declared | all | ✓ | §4 evidence table (101 paths + SHA-256) |
