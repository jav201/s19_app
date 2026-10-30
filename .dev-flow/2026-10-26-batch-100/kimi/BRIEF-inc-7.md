# Implementer brief — batch-100 Increment 7 · `files` digests, every problem listed, caps, private staging, `derived_from` (PH-5, L-4, D3, O-2, O-11, UX-26)

Read `BRIEF-COMMON.md` first; every rule there applies (the file name says Kimi, but since 2026-10-29 the implementer is a Claude `software-dev` agent; the rules are unchanged). The orchestrator gives you the worktree and the base commit at launch; the base is `main` with Inc 1–6 merged. Your packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-007.md`. If it is missing, copy the seed shape from `increment-006.md` (its §2–§4 structure and the evidence table header `| Evidence artifact | Path — under ... | SHA-256 |`).

**Work in three parts.** At the end of each part, write `HANDOFF.md` with what is done, then continue. At about 200k context, write `HANDOFF.md` and end; the orchestrator resumes you.

**Design authority:** `design/design-proposal-b100.md` §5.7 (lines 321–355; read it whole) and §5.15–§5.16.

**Contract (`01-requirements.md`):** HLR-169 (LLR-169.1 to LLR-169.9) and LLR-168.4; US-159. The AT written here is AT-B100-07. TC-B100-21 to -27, -60, -61 and -71 are written here. TC-B100-59 gains its `files` row (LED .63, LED .19 B-06). TC-B100-55 gains the "first variant by name" mutation arm (LED .47: `derived_from` replaces "first by name").

**Ledger entries to read:** grep the ledger for `Inc 7`. Read these in full: LED .47, .48 (you fix the JSON field names of a `derived_from` record in the packet; they freeze with B100-I16), .54 (a), .63, .67 and .68.

**Interfaces** (`docs/architecture.md` §11): freezes B100-I1, B100-I2 (`files`, `derived_from`), B100-I3, B100-I16 and B100-I21. Consumes B100-I13 (`place_into_workarea`), the Inc 5 seam (`_write_and_verify_manifest`, `_save_manifest_keys()`) and the Inc 6 helpers (`_rewrite_project_manifest`, `manifest_is_damaged`, `compose_load_announcement`, `LoadProblem`).

**SOURCE files (3 planned):**
- `s19_app/tui/services/manifest_writer.py`
- `s19_app/tui/services/variant_execution_service.py`
- `s19_app/tui/app.py`

A fourth file is allowed only if the Load-result panel (`screens.py`) cannot show the new rows through the Inc 6 `LoadAnnouncement` fields: the "patched, N bytes differ" line and the "not readable" mark in the error colour. If you take `screens.py`, declare it in §2 and stay at 4. `workspace.py` is not in scope. Import `contained_in_workarea` and `_guarded_destination` from it; do not edit it.

## Part A — the writer: `files`, `derived_from`, staging, containment, restore

1. **The `files` envelope and the seam computing it from disk** (LLR-169.1, LLR-169.2; TC-B100-21, -22). The scope is the top-level data and A2L files plus the active document (O-2). Never walk sub-folders. Mutations: emit an empty `files`; walk sub-folders; key on `.s19` only.
2. **Verify covers the new keys** (LLR-169.3, TC-B100-23).
3. **`derived_from`** (LLR-168.4, TC-B100-71): name, SHA-256 and byte count, computed at the write. The save-back and Save project's emit write it, and every rewrite carries it. Fix the field names in the packet (LED .48).
4. **Private manifest staging** (LLR-169.7, TC-B100-27, O-11). The QA race probe was RED at `1d677ba` (`ok=3 cross-content=12 failed-writes=60`).
5. **SEC6-3 (pulled in from the LED .50 backlog item; `manifest_writer.py` is now in scope).** `_check_destination_contained` checks the UNRESOLVED destination through `contained_in_workarea` / `_guarded_destination` (SEC PDR-C1), so a project folder swapped for a junction after placement cannot carry the manifest into another work area. Executed arm: replace the project folder with a junction to a second work area between placement and the manifest write. RED at base, then GREEN.
6. **SEC2-10 / LED .54 (a): a failed restore never loses the previous `project.json`.** In `app.py` `_abort_save`, the restore retries `os.replace` on `PermissionError`. If the retry fails, it writes the previous bytes to a claimed `project.json.previous-<UTC timestamp>` and the status names that copy. Arms: a held `project.json` during the rollback, and staging out of space. Each arm is RED first.

**Checkpoint:** `HANDOFF.md`.

## Part B — the reader: caps, the manifest-keys mode, problems

7. **The reader treats `project.json` as untrusted** (LLR-169.4, TC-B100-24): 1 MiB; 1 000 entries in each array; `assignments` 1 000 in total and 1 000 keys; type checks (a `bool` size is refused). P-40 timing arm: 1 001 entries → 1 `manifest damaged`, load under 1 s.
8. **The manifest-keys mode of `_resolve_manifest_entry`** (LLR-169.8, TC-B100-60): it refuses drive-relative (`C:x.s19`), stream and device names. Only the reader and `_reject_unsafe_entry` use it. Both flow callers stay on the default mode (P-41: tightening every caller breaks `test_tc_b97_20_hostile_refs_render_literally`).
9. **SEC6-2 (from LED .68):** an in-project rewrite must not silently drop unknown top-level keys, must not write `schema_version` 1 over a higher one, and must not drop skipped entries. Decide the rule with the reader's mode (carry unknown keys verbatim, or refuse the rewrite with the damaged-manifest status of LED .67 (b)). Record the decision in HANDOFF and in the packet §6. Give each of the three an arm.
10. **`check_project_files`** (LLR-169.5, TC-B100-25): manifest and disk problems. The P-4 cases 2 and 7 were RED at `1d677ba`. Mutation: drop the `not recorded` kind → the hand-copied arm turns RED.
11. **Load opens the valid files and writes one summary line** (LLR-169.6, TC-B100-26). P-5 was RED at `1d677ba`. The fallback rule is in `choose_install_set`, a pure module-level function in `app.py`; Inc 9b reuses it. TC-B100-55's "first variant by name" mutation arm lands here.
12. **One problem per file, by precedence, worded for the user** (LLR-169.9, TC-B100-61). `_handle_load_project` adds `not readable` from the install result. Mutations: keep every kind per file (case 6 then gives 2 problems); paint the issue code (a `MANIFEST-` code on screen).
13. **SEC6-5 (from LED .68): the panel stays responsive under many problems.** At Inc 6, 6 000 bad entries froze load and panel for 10.2 s. With the caps and one problem per file this is bounded. Arm: a manifest at each array cap with every entry bad → Load and the panel open under 1 s, and the panel row count is ≤ the cap. Name the bound in the packet.

**Checkpoint:** `HANDOFF.md`.

## Part C — the panel lines, the AT, the fixtures

14. **The panel shows `not readable` in the error colour** (P-E verdict B, `prototypes/load_projects/png/pe_B.*.png`). It also shows the **"patched, N bytes differ"** line against `derived_from`. Read the prototype; never import from it, edit it or commit it.
15. **AT-B100-07** (black-box, at 118 and 220 columns): the image is edited on disk, P is reopened, the summary line holds `1 problem` and the panel names `firmware.s19` as `changed on disk`.
16. **Enablers:**
    - **E4:** the `p04` cases 2/5/6/7/9, a legacy project and a hand-copied variant, in `tests/support/b100_projects.py`.
    - **E8:** `tests/support/b100_manifests.py`, holding 1 001-entry arrays, 75 × 1 000 `assignments`, a 1 MiB + 1 file and hostile keys.

**qa-reviewer F6 (Inc 3) ruling:** Inc 7 owes no real-worker boundary arm. It goes to Inc 12b, where loads move onto workers. Record this in packet §6.

**Snapshot cells:** if any cell changes, STOP and write it in `HANDOFF.md` with the text diff. Do not regenerate.

**RED must be behavioural at base.** Use the P-4 and P-5 transcripts, the QA race probe and S-09. RED for SEC6-3 and SEC2-10 must also be executed at base.

**Reverse census (trigger B1).** Run all three greps and re-run every file found:
- `grep -rln "project.json\|_write_and_verify_manifest\|serialize_manifest\|read_project_manifest\|write_project_manifest\|_resolve_manifest_entry\|_reject_unsafe_entry\|check_project_files" tests/ --include=*.py`
- `grep -rln "Loaded project\|_handle_load_project\|LoadResult\|derived_from\|_abort_save" tests/ --include=*.py`
- `grep -rln "b97_fixtures\|b100_projects" tests/`

Save the list as `evidence/inc-7/reverse-census-grep.txt` and the runs as `census-*.txt`. Run every failure on base too, for base-vs-tree. Use a detached base worktree under your scratch with `PYTHONPATH` pointing at it, and remove it at the end.

**Lessons from Inc 1–6** (`03-increments/review-increment-00*.md`, `security-increment-00*.md`):
- RED is behavioural, never a missing module or symbol.
- Every failure path after a file exists rolls back what it created. Every read of a user file handles `OSError`, `ValueError` and `RuntimeError` (Inc 6: a junction loop raises `RuntimeError`, and an over-limit integer raises `ValueError`) without crashing the app.
- A writer never rewrites a damaged `project.json` (LED .67 (b)). The new keys must not reopen that hole.
- Each ordering rule ("only after X") needs an arm whose mutant moves the call.
- Test scenarios SET every state they check. Polling, never a single pause.
- Status assertions read the full `set_status` message when the line can carry a path. The painted check is for what must be visible.
- A test reading the panel uses the painted-strip helpers in `tests/support/b100_projects.py`; the panel renders Rich `Table` grids.
- Every §2 row carries a closed-six `Kind` and a real LLR or HLR in `Traces to`.
- Evidence uses full repo paths. Transcript headers name the command, the tree, the source hashes, `PYTHONPATH` and `NO_COLOR`.
- Docstrings on new public functions follow `PROJECT_RULES.md` (Summary/Args/Returns plus Data Flow, Dependencies, Used by).

Finish with the guards (`guards.txt`, `guards-census.txt`) and packet §1–§7, with §4b set to `pending — orchestrator`. End `HANDOFF.md` with `__KIMI_UNIT_DONE__` and the 5-line summary.
