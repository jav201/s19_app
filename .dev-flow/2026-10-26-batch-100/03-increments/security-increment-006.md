# Security check — batch-100 Inc 6 (in-project manifest rewrites, `gathered` reader, Load-result panel)

| Field | Value |
|---|---|
| **Reviewer** | `security-reviewer`, independent (read-only toward the diff) |
| **Subject** | The uncommitted Inc 6 diff in worktree `C:\Users\jjgh8\Github\s19_app-b100-inc6` against base `093a7c0`: `s19_app/tui/app.py`, `s19_app/tui/screens.py`, `s19_app/tui/services/variant_execution_service.py`, `s19_app/tui/styles.tcss`, plus the untracked `tests/support/b100_projects.py`, `tests/test_b100_active_variant.py` and `tests/test_b100_announce.py`. Read against the packet `increment-006.md` (§1, §5 OQ-1, §6), `HANDOFF.md`, the contract (HLR-168, LLR-168.1–.3, HLR-178, LLR-178.1–.3, and HLR-169's caps, which are Inc 7's) and the ledger's SEC routing (LED .50, .56, .65, .66). Precedent: `security-increment-005.md`. |
| **Execution** | One probe, `sec_inc6_probe.py`, ran against the worktree (`python -B`, worktree first on `sys.path`, `PYTHONPATH` set to the worktree, `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1`). It printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc6\s19_app\__init__.py`. Runtime: Python 3.11.15 (s19env), Textual 8.2.8, Windows 11. Every scenario drives the **real app routes** in Textual `run_test`: `_handle_load_project` / `_route_load_project`, then `load_a2l_from_path` (A2L sync), `load_from_path` (MAC sync and variant append) or `on_patch_editor_panel_save_back_decision` (save-back). Project folders are built with the batch's own builder (`tests/support/b100_projects.py`, `seed_project_with_every_key`). Snapshots use an `lstat` walk that never descends a reparse point. Two helper scripts checked single points: `dbg_d2.py` (the manifest writer called directly with a junction project folder) and `esc_probe.py` (whether an ESC byte in a markup-off `Label` reaches the rendered strip). The TC modules of this increment were re-run on the tree: `tests/test_b100_active_variant.py tests/test_b100_announce.py` → **38 passed**. All scratch lived under `…\scratchpad\s6\`; every junction was removed with `rmdir` and the scratch folder was deleted at the end (brief). The worktree's source and tests were not edited; this report is the only file written into the worktree. |
| **VERDICT** | **`BLOCK — BLOCK-UNTIL: SEC6-1`** (1 HIGH). SEC6-1 is executed: each of the four new in-project writers silently replaces a damaged `project.json` with an empty manifest and reports `Project saved + manifest verified`. That contradicts the orchestrator's ruling (preserve, skip the rewrite, say so) and destroys a pre-existing user file without confirmation, the same class as SEC2-7. The containment of every new write held in every executed case. SEC6-2..SEC6-6 are MINOR. This verdict authorises nothing, and it is not the operator's authorization. |

## Questions asked of this diff

1. **Does every new write stay inside this work area?** Yes, in every executed non-race case.
   - **C (junction project folder).** Project `evil` is a junction into another work area's `T` (which holds a full project). Opening `evil` then running each writer gave **other-work-area diff `created: [] removed: [] changed: []`** four times out of four. The refusals: A2L `A2L sync rejected: Refusing to place: destination traverses a symbolic link or reparse point …\workarea\evil`; MAC and append `Project sync rejected: Refusing to place: …`; save-back `[MF-WRITE-CONTAINMENT] … the patched image was not written: Refusing to place: …`. In each case the placement guard (`place_into_workarea(…, workarea_root=self.workarea)`, or the emit's guard for the save-back) raises **before** `_manifest_carry` / `_write_and_verify_manifest`, so no manifest write is attempted.
   - **E (hard link).** `project.json` was a hard link to `outside\victim.json`. After the A2L sync the outside file was byte-identical and the link was broken (`st_nlink == 1`): `os.replace` swaps the directory entry, it never writes through. **E2 (file symlink to outside, creatable on this machine).** The outside file was unchanged and the link still present: the write did not follow it (the writer's containment check refuses a target outside every work area; `predicted` cause, `executed` consequence).
   - **Race (SEC6-3).** When the project folder is swapped for a junction **between** the placement and the manifest write, the manifest lands in the other work area. That is a pre-existing weakness of the manifest writer, now reachable from four more callers.
2. **Can a hostile `project.json` make a writer write or delete outside the project?** No in every executed case.
   - The reader resolves `batch`, `assignments` and the new `gathered` entries through `_resolve_manifest_entry` (NUL, absolute under either convention, `resolve()`-escape, reparse below the root → skipped). `_manifest_carry` only converts what the reader kept, with `relative_to(project_dir.resolve())`, the same root the reader checked with `is_relative_to`, so the conversion cannot raise or emit an absolute path (reasoned; B shows `../outside.json`, `C:/abs/evil.json`, `7` and `gathered.templates: ["../../t.json"]` all dropped, 0 absolute strings written).
   - A carried entry is never a write target: the manifest is the only file written, at the fixed `project_dir / "project.json"`. `gathered` home keys are arbitrary strings, but they are only carried back as JSON keys (`grep -n "\.gathered\b"` → the carry is the only consumer).
   - **Nothing in the new writers deletes anything.** There is no rollback in the append, MAC, A2L or save-back paths; a failed manifest write leaves the placed file in the project (H: `firmware_1.s19` stays). So the rollback-scope question is `n/a` for this increment.
3. **Does a damaged `project.json` survive?** **No** (SEC6-1). Today the code does this, executed for each writer with a truncated JSON manifest:

   | writer | damaged bytes preserved | `project.json` afterwards | newest manifest status |
   |---|---|---|---|
   | A2L sync | False | `{"schema_version": 1, "active_variant": "firmware", "batch": [], "assignments": {}}` | `Project saved + manifest verified` |
   | MAC sync | False | same | `Project saved + manifest verified` |
   | variant append | False | same, `active_variant: "firmware_1"` | `Project saved + manifest verified`, then `Project 'P' now opens firmware_1.s19` |
   | save-back | False | same, `active_variant: "firmware_1"` | `Project saved + manifest verified` |

   No backup or side-car copy is made (`backup/sidecar files: []`). The damaged manifest's readable intent (here a `batch` and an `assignments` row) is gone, and the status tells the user the project was saved and verified.
4. **Can a name read from disk inject markup or terminal escapes?** Not through the new surfaces (F, executed at 118×54).
   - Project folder `[b]P[link=x][reverse]y`, variant file `[red]v[blink].s19`, recorded `active_variant` = `ESC[31mZ[red]q` + BEL.
   - Panel: the title, the summary block and the problem row render the brackets literally. Span counts: title 0, summary 0, problem row 1 (the developer's `bold` on the label). No C0 byte in any painted panel text: the ESC and BEL in `active_variant` were scrubbed by `safe_text`.
   - Summary line in `#log_line_4`: `Loaded project '[b]P[link=x][reverse]y' -> [red]v[blink].s19 - variant 1 of 2, 1 problem - details: p` (literal, `safe_text(...).plain` into a `markup=False` label). `#status_text`: `Loaded project '[b]P[link=x][reverse]y' -> [red]v[blink].s19` (a `Text` from `safe_text`).
   - The append's new line `f"Project '{project_name}' now opens {saved.name}"` is not scrubbed, but it reaches the `markup=False` log, and Windows file and folder names cannot hold C0 bytes. On POSIX a file name can; that is the same exposure as the many pre-existing status lines with file names, so I record it here without a finding.
   - One **pre-existing** line in the same load handler still paints the raw `active_variant` string with its ESC byte (SEC6-6).
5. **Are list sizes capped?** Not yet (SEC6-5). The panel builds one `Static` per problem with no cap, and at Inc 6 the reader's only bound is the 256 MB size cap. HLR-169's 1 MiB / 1 000-entry caps and its one-problem-per-file rule are Inc 7's.
6. **Secrets or private data in the diff or the evidence?** None. No operator name, no key material, no tokens. The new test builder writes only example files and JSON. Paths in this report contain the Windows account folder, as in every earlier increment; informational.

## Findings

| id | severity | location | finding | evidence | what closes it |
|---|---|---|---|---|---|
| SEC6-1 | **HIGH** (this increment's new code) | `app.py:10224` `_manifest_carry` (returns the empty carry for a manifest the reader could not read), its four new callers `app.py:3742` (save-back), `:10409` (variant append), `:10457` (MAC sync), `:10487` (A2L sync), all ending in `_write_and_verify_manifest` (`:9609`) | **A damaged `project.json` is silently destroyed by any in-project writer.** When the reader returns a manifest with `MANIFEST-SIZE-CAP`, `MANIFEST-JSON-PARSE` or a non-object top level, `_manifest_carry` carries empty `batch` / `assignments` / `declared_regions` / `gathered`, and the writer replaces the file with that empty envelope. Nothing asks, nothing is backed up, and the surfaced status is `Project saved + manifest verified` (the verify re-reads the file it just wrote, so it always passes). Loading an A2L or a MAC, or appending a variant, with a project open is enough: the operator never chose to save the project. The user's recorded composition (batch, per-variant assignments, declared regions, gather rows) is lost irreversibly. The packet discloses the behaviour (§5 "A damaged project.json is replaced", OQ-1); the orchestrator's ruling is that it must be preserved, the rewrite skipped and the status must say so. The code does not do that. The panel's next-step text for a damaged manifest ("defaults used; Save project rewrites it", `variant_execution_service.py:642-654`, `:780-785`) points the user at the same destructive rewrite. | `executed` (§Q3 table; `out_A.txt`): 4 of 4 writers replaced the damaged bytes; 0 backups; status `Project saved + manifest verified` in all 4. A folder named `project.json` (H) is read as `MANIFEST-JSON-PARSE` too; there the replace fails on its own (`Manifest write failed`), so it is not a loss case. | Treat "the manifest could not be read" as **do not rewrite**: e.g. `_manifest_carry` returns a sentinel (or raises a small private signal) when `_manifest_damaged(manifest)` is true, and each of the four callers then skips `_write_and_verify_manifest` and paints one status line such as `project.json could not be read - not rewritten; <file> was placed` (user terms, no code). The session-side activation can stay. Align the panel's damaged-manifest next step with the ruling. The fix is in `app.py` (and the two text constants in `variant_execution_service.py`), both already touched. **TC arm:** for each of the 4 writers, a truncated-JSON, a non-object and an over-cap manifest (size via the `size_probe` seam or a patched cap) → `project.json` bytes identical afterwards, 0 `Project saved` lines, 1 line saying it was not rewritten. **Mutant:** drop the damaged check → RED. I re-verify before the verdict changes. |
| SEC6-2 | MINOR (this increment's new code; contract wording) | `app.py:10224-10273` `_manifest_carry` → `manifest_writer.serialize_manifest` (fixed envelope, `schema_version` default 1) | **A readable manifest loses its unknown keys and a newer `schema_version` on every in-project rewrite, silently.** The carry passes only the four keys the writer knows. A hand-added top-level key (`custom_user_key`) is dropped; `schema_version: 2` is rewritten as `1`. Entries the reader skipped are dropped too; those are unsafe or malformed by definition, so dropping them matches HLR-169's "reported and skipped, never trusted", but the user is not told at write time. HLR-168 says the writer carries "every key it does not own … unchanged". Not an escape and not a crash. | `executed` (B; `out_BCDE.txt`): before keys `[active_variant, assignments, batch, custom_user_key, declared_regions, gathered, schema_version]`, `batch` 4 entries; after keys without `custom_user_key`, `batch: ['patches/cs_seed.json']`, `schema: 1`; status `Project saved + manifest verified`. | Either carry unknown top-level keys verbatim (the serializer can take a pass-through mapping it does not interpret), or treat a manifest with a newer `schema_version` or unknown keys like SEC6-1 (preserve, skip, say so). Decide with Inc 7's manifest-keys mode (LLR-168.4 / HLR-169), which already reopens the envelope. TC arm: an unknown key and `schema_version: 2` survive, or the rewrite is skipped with a status line. |
| SEC6-3 | MINOR (pre-existing in `manifest_writer.py`, **surface widened**: 4 new callers) | `manifest_writer.py:366-410` `_check_destination_contained` (`resolved = destination.resolve()` at `:400`, then the anchor search and the reparse walk run on the **resolved** path) | **The manifest writer accepts a project folder that is a junction into another work area, because it resolves before it checks** (the SEC-4 pattern, still present in this writer). From the app this is reachable only by a race: the placement guard refuses a junction project before the manifest write, but if the folder is swapped for a junction **after** the placement and before the write, `project.json` is replaced inside the other work area. Inc 6 adds four placement-then-manifest windows (append, MAC, A2L, save-back). The serializer's per-entry check refuses the write by accident when the carry holds any entry (D: `refusing to serialize manifest … escapes the project directory`), so an entry-free manifest, or no manifest at all (OQ-1), is the exposed shape. Blast radius: files named `project.json` under some `.s19tool/workarea` the user can write. | `executed`: **I**: an A2L sync with the swap injected after `_manifest_carry` → other work area `changed: ['.s19tool\\workarea\\T\\project.json']`, its seeded keys replaced by an empty envelope, status `Project saved + manifest verified`. **D** (carry with entries) → refused, other work area unchanged. `dbg_d2.py`: `write_project_manifest(vs, <junction P>, base)` returns the path with no issue. | Pass the app's work area into the writer and guard the **unresolved** destination with `_guarded_destination(project_root, workarea_root)` (as the placement already does) before staging and `os.replace`. `_write_and_verify_manifest` passes `self.workarea`. `manifest_writer.py` would be a fifth source file here (Inc 6 is at 4/4), so route it with SEC-9 to the LED .50 backlog item (`workarea_root` mandatory for the remaining callers), with this probe's scenario I as the RED side. TC arm: a junction project folder handed to `write_project_manifest` → refused, 0 entries changed in the other work area. |
| SEC6-4 | MINOR (this increment's new code; integrity of the status) | `app.py:10409-10414` (variant append: `_write_and_verify_manifest(...)` return value ignored, then `set_status(f"Project '{project_name}' now opens {saved.name}")`) | **The append says "now opens X" after the manifest write failed.** The session's active variant is switched and the line is painted unconditionally, so the newest lines read `Manifest write failed`, `Project 'P' now opens firmware_1.s19`, `Added variant …`. A fresh Load will not open `firmware_1.s19`, because `project.json` does not record it. Not a containment problem; it is a wrong statement about disk state, the class LLR-168.3's status line exists to prevent. | `executed` (H; `out_FH.txt`): with a folder named `project.json`, statuses `['Manifest write failed', "Project 'P' now opens firmware_1.s19", "Added variant 'firmware_1' to project 'P'"]`. | Paint the "now opens" line only when `_write_and_verify_manifest` returned True **and** the verify result is `MANIFEST_VERIFIED`; otherwise say the variant was added but Load still opens the recorded one. One condition in `app.py`. After SEC6-1's fix the "not rewritten" case needs the same treatment. TC arm: a failing manifest write → 0 "now opens" lines. |
| SEC6-5 | MINOR (this increment's new code; local DoS; routed to Inc 7's caps) | `screens.py:1090` (`LoadResultScreen.compose`: one `Static` per problem, no cap) fed by `variant_execution_service._manifest_problems` (one problem per manifest issue) | **A small hostile manifest freezes the load for seconds; a large one for much longer.** At Inc 6 every manifest issue becomes a panel row, and the reader's only bound is the 256 MB size cap. Measured about 1.7 ms per row on the main thread. | `executed` (G; `out_G.txt`): `batch` of N integers → N rows. N=500 (2.7 KB) → 1.14 s; N=2000 (11 KB) → 3.51 s; N=6000 (35 KB) → **10.19 s** load + panel. | HLR-169 (Inc 7) brings the 1 MiB read cap, the 1 000-entry caps and **at most one problem per file**. With all three, the manifest findings collapse to one `project.json` row. Route to Inc 7 with an explicit arm: 6 000 malformed entries → at most 1 manifest row in the panel, load + panel under 1 s. If Inc 7 keeps per-issue rows, cap the rendered rows and show a count of the rest. |
| SEC6-6 | MINOR (pre-existing, not made worse; in a function this increment edits) | `app.py:10145` (`set_status(f"Manifest active_variant '{manifest.active_variant}' not found - activating the first variant.")`; present on base at `:10064`) | **The raw `active_variant` string from `project.json` still reaches the status log unscrubbed.** The log labels are `markup=False`, so markup is inert, but C0/C1 bytes are not removed: the ESC byte reached the rendered strip. `active_variant` is any JSON string (only `isinstance(str)` is checked), so a crafted manifest puts terminal escape sequences on screen. The new panel row for the same condition scrubs the value through `safe_text`. | `executed` (F): log line 3 = `"Manifest active_variant '\x1b[31mZ[red]q' not found …"`, ESC present in the label's render; `esc_probe.py`: a `markup=False` `Label` updated with `ESC[31m…` keeps the ESC in `render_line(0)` segments (`ESC in rendered strip: True`). | Paint it through `safe_text(...).plain`, or drop the line now that the panel's `Missing variant` row carries the same fact. One line in `app.py`. TC arm: a recorded `active_variant` holding ESC → 0 C0 bytes in `#log_line_1..4`. |

## Evidence checklist

- [x] Each finding has what, where, why, a recommendation and a severity: SEC6-1..SEC6-6 above.
- [x] Each finding has a severity: 1 HIGH (SEC6-1), 0 MAJOR, 5 MINOR.
- [x] No secret values, operator name or key material appear in this report. Hostile test strings are quoted with the ESC/BEL bytes written as names.
- [x] The verdict is explicit: `BLOCK — BLOCK-UNTIL: SEC6-1`. The HIGH carries no applied-and-verified mitigation yet; I re-verify the fix (4 writers × 3 damage shapes, bytes identical) before it changes.
- [x] The probe ran against the worktree with `s19_app.__file__` printed. The worktree's source and tests were not edited. Every junction was removed with `rmdir`; the scratch folder was deleted.
- [x] Containment checked on every new write path (append, MAC, A2L, save-back) with a junction project folder (C, 4 of 4 refused, 0 entries outside), a hard-linked and a symlinked `project.json` (E, E2), and the swap race (D, I). Hostile `project.json` entries checked (B). Markup and escape injection checked on the panel, the summary line and `#status_text` (F). List-size cost measured (G). Rollback scope: no rollback exists in the new writers; nothing is deleted (H).
- [ ] Not tested: Python 3.12 (only 3.11.15 ran); POSIX file names with control bytes (Windows cannot create them); the Load dialog preview (deferred by the packet, §6).

## Evidence files

The brief allows only this report in the worktree, so the probe artifacts were **not** copied in. They were deleted with the scratch folder at the end of the review. Their hashes, for the record:

| Artifact | SHA-256 |
|---|---|
| `sec_inc6_probe.py` (scenarios A–I) | `526dc0518e227358fd76367cc9ce019e372c9c6ce9ee8f6b91a89e8fe040247e` |
| `out_A.txt` (SEC6-1) | `54cd38add11cc3b629af76090aa623df02aef6a25b61343252d9871219d0bfa0` |
| `out_BCDE.txt` (SEC6-2, containment C/E) | `c471abd03f5289e420cd72eb1c5b3ebb66dc6fb576f568ae4ee81672c8fb7cc9` |
| `out_D.txt` (race, carry with entries) | `fcef4c19e6b35d65eefe3bf5309d759a581095fe7893b34c4dea25946085f6b4` |
| `out_I.txt` (SEC6-3, race, entry-free carry) | `24ac443efb9627c28eff5d3a801550a983fe25270eda93a448a331507ea3e9a3` |
| `out_FH.txt` (markup F, SEC6-4, SEC6-6) | `7b38666048c4448672dcaadbef8cc602b181c55960e6eedb6fa8647cd228cbbe` |
| `out_G.txt` (SEC6-5) | `d7a1aed9fa5f26e77afba7e76ff28832483000a3c63815002fb044846134cf47` |
| `esc_probe.py` (SEC6-6) | `20031b09ff8de9cc00ff6a8cefd707567debb4135649e214f376e6519d989b65` |

The load-bearing transcript lines are quoted in the tables above. Re-running needs only the probe and the worktree; its scenarios take arguments (`A`..`I`).

**VERDICT: `BLOCK — BLOCK-UNTIL: SEC6-1`.** SEC6-1 (HIGH, this increment's code): every in-project writer replaces a damaged `project.json` with an empty manifest and reports it as saved and verified. Recommended in the same corrective pass, because they are small and in touched files: SEC6-4 (status after a failed write) and SEC6-6 (one `safe_text`). Routed: SEC6-2 to Inc 7 (manifest-keys mode), SEC6-3 to the LED .50 backlog item with SEC-9, SEC6-5 to Inc 7 (caps and one problem per file).


---

# Round 2 — re-check after corrective pass 1

| Field | Value |
|---|---|
| **Subject** | Corrective pass 1, uncommitted in the same worktree. Source sha256 (first 16 hex digits), checked against the coordinator's list: `app.py 762d1a98c8a65903`, `screens.py ea549ab4bd9d3ef4`, `variant_execution_service.py 395dcbde3b28851b`, `styles.tcss 781f04ed2cc30897`. New surface: `_rewrite_project_manifest(project_dir, placed)` (`app.py:10288`), the public `manifest_is_damaged` (`variant_execution_service.py:847`), the gated "now opens" line (`app.py:10490`), the scrubbed `active_variant` line (`app.py:10153-10158`), and skipped-entry strings recorded in `ValidationIssue.details['entry']` (`variant_execution_service.py:282-325`) and painted by `LoadResultScreen._problem_row`. |
| **Execution** | A new probe, `sec_inc6_r2_probe.py`, plus two helpers: `longentry.py`, the reader on base `093a7c0` (extracted with `git archive` into scratch) vs. the worktree, and `crash.py`, the real Load dialog route. Same interpreter and environment as Round 1; each script printed `s19_app.__file__` from the tree it tested. Inc 6's TC modules were re-run on the tree: `tests/test_b100_active_variant.py tests/test_b100_announce.py` → **55 passed**. The worktree was not edited except for appending this section. The scratch folder `…\scratchpad\s6\` was deleted at the end. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH). **SEC6-1 is discharged** by executed evidence: 12 of 12 writer × damage cases left `project.json` byte-identical. SEC6-4 and SEC6-6 are closed. **One new MAJOR, SEC6-7**: the reader crashes the app on an over-long entry string, and this increment makes `gathered` a new carrier for it. It does not block, but it should land in the same corrective pass because the fix is small and in a touched file. SEC6-2 and SEC6-5 stay routed to Inc 7, SEC6-3 to the LED .50 backlog item. This verdict authorises nothing beyond the increment gate, and it is not the operator's authorization. |

## Status of the Round 1 findings

| id | state | evidence (`executed` unless marked) |
|---|---|---|
| SEC6-1 (HIGH) | **closed (discharged)** | `r2_AH.txt` §A: 4 writers (A2L sync, MAC sync, variant append, save-back) × 3 damage kinds. The kinds are truncated JSON, a top level that is a JSON array, and valid JSON over the size cap (the cap lowered in-process to 256 bytes, as the `size_probe` seam would). All **12 of 12 cases: `bytes identical: True`**. In every case the placed file stayed (`firmware.a2l`, `firmware.mac` or `firmware_1.s19`), and exactly one manifest status line was painted: `project.json in project 'P' is damaged and was not rewritten - <file> stays in the project; Save project rewrites it`. No `Project saved + manifest verified` line appeared in any damaged case. A folder named `project.json` (OSError on open, §H) takes the same damaged path, with no write and no "now opens". Source: all four writers call `_rewrite_project_manifest`, which reads once and returns before `_write_and_verify_manifest` when `manifest_is_damaged` is true. The predicate keys on the codes and on the `scope` mark, not on message text. The remaining advice "Save project rewrites it" names an explicit operator action, which matches the ruling (OQ-1 (b)). |
| SEC6-4 (MINOR) | **closed** | §H, read-only `project.json`: `Manifest write failed`, then `Added variant 'firmware_1' …`, with **0 "now opens" lines** and the bytes identical. `_rewrite_project_manifest` returns True only when the write ran and the verify status is `MANIFEST_VERIFIED` (`app.py:10339-10343`), and the line is gated on that (`app.py:10490`). |
| SEC6-6 (MINOR) | **closed** | `r2_FL.txt` §F: the `Manifest active_variant '…' not found` log line now paints `'[31mZ[red]q'` with the ESC and BEL removed. C0/C1 bytes in `#log_line_1..4`: `[False, False, False, False]`. |
| SEC6-2 (MINOR) | routed to Inc 7, unchanged | Not in this pass (coordinator). |
| SEC6-3 (MINOR) | routed to the LED .50 backlog item with SEC-9, unchanged | `manifest_writer.py` is not in the diff. |
| SEC6-5 (MINOR) | routed to Inc 7, unchanged | Inc 6 still paints one row per finding. |

## The new path: skipped-entry strings painted by the panel

- **Markup and escapes: clean.** `r2_FL.txt` §F used these `batch` entries:
  - `../` + ESC`[31mred` + OSC 8 hyperlink + BEL + `[link=http://e]x[/link]`
  - `C:/[b]abs[/b]` + C1 CSI (`\x9b`) `31m`
  - `evil` + NUL + `[reverse]nul`
  - the object `{"[b]obj": ESC"[2J"}`

  Each became one panel row. The brackets show literally. The NUL, ESC, BEL and C1 bytes are gone, and the rendered strips of every `.result-problem` row carry **no C0/C1 byte**. A non-string entry is shown as its JSON (`{"[b]obj": "\u001b[2J"}`), clipped at 60 characters. The row uses `safe_text` for the label, the entry and the detail (`screens.py`, `_problem_row`). The code and the message, which hold `{text!r}`, still go only to the log.
- **Length: string entries are not clipped** (SEC6-7, part b). `details['entry']` holds the whole stripped string; only non-string entries go through `_clip(…, 60)`. A 30 003-character entry reached the panel with `len(details['entry']) == 30003`. That is not a DoS on its own: load plus panel took 0.56 s and the row rendered 3 lines high. Longer strings do not get that far, because of part (a).

## Findings (Round 2)

| id | severity | location | finding | evidence | what closes it |
|---|---|---|---|---|---|
| SEC6-7 | **MAJOR** (pre-existing for `batch` / `assignments`; **new carrier in this increment**: `gathered`, LLR-168.1, plus the writers' re-read) | `variant_execution_service.py:308` (`resolved = (project_root / text).resolve()` in `_resolve_manifest_entry`; no `try`), reached from `read_project_manifest` for `batch`, `assignments` and now `gathered`; callers `_handle_load_project` (`app.py:10141`) and `_rewrite_project_manifest` (`app.py:10288`) | **(a) An entry string longer than about 32 760 characters crashes the app.** On Windows, `Path.resolve()` raises `ValueError: stat: path too long for Windows`. The reader's contract is "every failure mode is a collected ValidationIssue", but nothing catches this, so the exception escapes the Load dialog callback and Textual exits. A 40 KB `project.json` with one such entry is enough. `_reset_project_session()` runs before the read, so the outgoing session is already reset when the app dies. Base `093a7c0` crashes the same way for `batch` and `assignments`, but it **ignored** `gathered`. Inc 6 parses `gathered` through the same function, so it adds a carrier, and the four writers now re-read the manifest after placing (a manifest changed after the load crashes the writer). **(b)** `details['entry']` keeps the full string (see above). Not a containment escape and no file loss. | `executed`: `r2_longentry.txt`, base vs. worktree reader. Base: `batch` / `assignments` at 33 003 characters → `RAISES ValueError`, `gathered` → `ok, issues=0` (ignored). Worktree: all three keys at 33 003 and 200 003 characters → `RAISES ValueError`; at 30 003 → `ok, issues=1, entry-detail-len=[30003]`. `r2_crash.txt`, the real Load dialog route with a 40 003-character `gathered` entry: `exc: 'ValueError: stat: path too long for Windows', return_code: 1` (the app exited); 30 003 characters → the panel opened in 0.56 s. | Wrap the `resolve()` (and `_path_traverses_reparse_point`) in `try … except (OSError, ValueError, RuntimeError)` and record one `MANIFEST-PATH-ESCAPE` (or `-BAD-STRUCTURE`) issue with the entry skipped, as the NUL branch already does. Clip `details['entry']` for strings too (e.g. `_clip(text, 120)`), so the panel never holds an unbounded string. Both changes are in `variant_execution_service.py`, a touched file. Inc 7's 1 MiB cap does **not** close (a): 40 KB is well under it. **TC arm:** a 40 000-character entry in each of `batch`, `assignments` and `gathered` → the project opens, 1 skipped-entry row each, the painted entry at most 120 characters. **Mutant:** remove the `except` → RED (the app exits). I re-verify when it lands; it does not block this gate. |

## Evidence checklist (Round 2)

- [x] SEC6-1's mitigation is **applied** (the diff) and **verified by me** (12 of 12 byte-identical, executed).
- [x] SEC6-4 and SEC6-6 re-verified closed, executed.
- [x] The new `details['entry']` path checked for markup, C0/C1 escapes and length (executed). One new finding, SEC6-7, with what, where, why, a recommendation and a severity.
- [x] No secret values, operator name or key material. Hostile strings are described, not pasted raw.
- [x] Verdict explicit: `PASS-WITH-NOTES`, 0 HIGH open.
- [ ] Not tested: Python 3.12; POSIX, where the path-length limit and its exception differ (`OSError: File name too long` is likely, also uncaught; `predicted`).

## Evidence files (Round 2, deleted with the scratch folder per the brief)

| Artifact | SHA-256 |
|---|---|
| `sec_inc6_r2_probe.py` (A, H, F, L) | `78ac35520d14bdd00667fc1994ceb2b47ddee193a38cd763a18b5b6480d92227` |
| `r2_AH.txt` (SEC6-1, SEC6-4) | `fdf53c8c1214f895080e5f3eb5340bf8e0d16ba9c443ba897d47a283dc5c5d3b` |
| `r2_FL.txt` (injection; long entry run, stopped by SEC6-7) | `90bd09948ff41dc1857618bbed7caf50f9f4f24d9678845366f768842055aeeb` |
| `longentry.py` / `r2_longentry.txt` (base vs. worktree reader) | `15b00f86ac124c2bd9abbff57c609ba112d4aeca9a3f044e818486fe3a3ca89e` / `93d1402fbb9edbd8462b7200107dc1a8de39c62ffcad5fff697864394bfad992` |
| `crash.py` / `r2_crash.txt` (Load dialog route) | `d33d5456e5de62311f9c7548e99e09448c86165447bac20cd49956f453cf0b4a` / `0686cb08b6a61cfe7be27f353cb13e876100ef2cda4b79bc1e99edfc098f65f9` |

**VERDICT (Round 2): `PASS-WITH-NOTES`.** SEC6-1 is discharged; SEC6-4 and SEC6-6 are closed. SEC6-7 (MAJOR: an over-long manifest entry string crashes the app on Load; this increment adds `gathered` as a carrier) is recommended in the same corrective pass, but it does not block. SEC6-2 and SEC6-5 go to Inc 7, SEC6-3 to the LED .50 backlog item.


---

# Round 3 — re-check after corrective pass 2 (SEC6-7)

| Field | Value |
|---|---|
| **Subject** | Corrective pass 2, uncommitted. Only `variant_execution_service.py` changed; its sha256 (first 16 hex digits) is `e494c50cd7266bff`. The other three match the coordinator's list: `app.py 762d1a98c8a65903`, `screens.py ea549ab4bd9d3ef4`, `styles.tcss 781f04ed2cc30897`. The change: `_resolve_manifest_entry` wraps `resolve()`, the containment check and the reparse walk in one `try … except (OSError, ValueError)` (`:330`), and a new `_entry_mark` clips every `details['entry']` to 120 characters. |
| **Execution** | `sec_inc6_r3_probe.py` (P1–P5), `p2b.py` (writers) and `p5b.py` (rendering detail). Same interpreter and environment as before; each printed `s19_app.__file__` from the worktree. I re-ran Inc 6's TC modules on the tree: `tests/test_b100_active_variant.py tests/test_b100_announce.py` → **57 passed**. The only change to the worktree is this appended section. The scratch folder `…\scratchpad\s6\` was deleted at the end. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH). **SEC6-7 is closed for the long-entry case, but not fully.** Its own named trigger is fixed: a 40 003-character entry in `batch`, `assignments` or `gathered` no longer crashes Load or a writer. **The same crash class is still reachable** through a junction loop inside the project: `resolve()` raises `RuntimeError`, which the new `except` does not catch. Round 2's recommendation listed `RuntimeError`. SEC6-7 therefore stays **open as a MAJOR**, now narrowed to one missing exception class. **New, SEC6-8 (MINOR, pre-existing):** a 5 000-digit integer anywhere in `project.json` crashes the reader at `json.load`. Neither blocks the gate. Both are one-token fixes in the file this pass touched, so I recommend landing them before the commit. SEC6-2 and SEC6-5 remain routed to Inc 7, and SEC6-3 to the LED .50 backlog item. This verdict authorises nothing beyond the increment gate, and it is not the operator's authorization. |

## Re-checks

| case | result (`executed`) |
|---|---|
| **P1:** a 40 003-character `../AAA…` entry in each of `batch`, `assignments[firmware]` and `gathered[patches]`, through the real Load dialog (`action_load_project` → `LoadProjectScreen.dismiss("P")`) | The app stays alive (`return_code: None`). The panel opens with **3 rows** (`Manifest entry skipped: ../AAAA…`), each painting **167 characters** in total: the label, the entry clipped to 120 characters with `…`, and the next step. The summary line reads `… variant 1 of 1, 3 problems - details: p`. Round 2's crash with the same entry on the same route was `return_code: 1`. |
| **Writers (`p2b.py`):** after the load, the manifest gains 40 003-character entries in `batch` and `gathered`; then a variant append, and separately a MAC sync | No crash in either. The rewrite carries the safe entries unchanged and **drops** the long ones: `batch: ['patches/cs_seed.json']`, `gathered: {patches: ['patches/cs_seed.json'], checks: [...]}`. That matches HLR-169's "reported and skipped, never trusted" (see SEC6-2 for whether the user should be told at write time). The append's newest lines are `Project saved + manifest verified`, `Project 'P' now opens firmware_1.s19`, `Added variant …`. |
| **P5:** a non-string entry with a large body (`list(range(100000))`), and a lone UTF-16 surrogate in an entry and in `active_variant` | The reader does not raise. The non-string entry's mark is clipped to 120 characters. Both surrogate strings reach the panel and render (`p5b.py`: rows `(75, 2)` with text; the app stays alive). The app logger prints `--- Logging error --- UnicodeEncodeError … '\udfff'` to stderr; `logging` swallows it, so nothing breaks. Whether a real terminal driver can write a lone surrogate: `not-run`; it predates this increment (NTFS file names can hold one too). |

## Can anything else in the reader still raise on a hostile manifest?

I walked every parse path of `read_project_manifest`:
- the size probe;
- `json.load`;
- the top level;
- `schema_version` (`isinstance` only);
- `active_variant` (`isinstance` only);
- `batch`, `assignments` and `gathered` (through `_resolve_manifest_entry`);
- `declared_regions` (`isinstance` checks, then `DeclaredRegion`, which raises only `ValueError`, and that is caught).

I probed the two paths that still raise:

| id | severity | location | finding | evidence | what closes it |
|---|---|---|---|---|---|
| SEC6-7 (residual) | **MAJOR, open** (narrowed to one exception class; pre-existing for `batch` / `assignments`, and `gathered` is this increment's new carrier) | `variant_execution_service.py:330` (`except (OSError, ValueError)` around `(project_root / text).resolve()`) | **A junction loop inside the project still crashes Load and the writers.** Creating a junction needs no privilege: `mklink /J loop loop`. With the entry `loop/x.json`, Python 3.11's `Path.resolve()` turns `WinError 1921` into **`RuntimeError: Symlink loop from …`**, which is not an `OSError` or a `ValueError`. The exception escapes the reader. **Load:** the Load dialog route dies with `return_code: 1`. **Writer:** a variant append whose manifest gained the entry after the load dies with `WorkerFailed: … RuntimeError("Symlink loop …")`, `return_code: 1`. The placed `firmware_1.s19` stays and `project.json` is not rewritten, so no file is lost. | `executed` (`r3.txt` P3: `reader RAISES RuntimeError Symlink loop …`, dialog `exc: RuntimeError …, return_code: 1`; `r3_writers.txt` `[loop-append] rc=1 exc='WorkerFailed: Worker raised exception: RuntimeError("Symlink loop …'`). | Add `RuntimeError` to the `except` at `:330`, making it `(OSError, ValueError, RuntimeError)`, as Round 2 recommended. **TC arm:** a junction `loop` → itself inside the project, with `loop/x.json` in `gathered`, opened through the Load dialog → the project opens with 1 skipped-entry row. **Mutant:** drop `RuntimeError` → RED (the app exits). |
| SEC6-8 | MINOR (pre-existing: base `093a7c0` has the same `except` list; reached by more callers since Inc 6's writers re-read the manifest) | `variant_execution_service.py:512-518` (`json.load` guarded by `except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, OSError)`) | **A 5 000-digit integer anywhere in `project.json` crashes the reader.** Python 3.11 limits int-from-string conversion to 4 300 digits. `json.load` then raises a plain **`ValueError`** ("Exceeds the limit (4300 digits) …"). `JSONDecodeError` is a subclass of `ValueError`, not the other way round, so the guard misses it. A 5 KB manifest is enough, and the key can be any key, even an unknown one. **Load:** crashes. **Writer:** crashes after the placement; nothing is lost. With `ValueError` caught, the manifest would become `MANIFEST-JSON-PARSE`, which `manifest_is_damaged` already turns into "do not rewrite" (SEC6-1's path). | `executed` (`r3.txt` P4: `reader RAISES ValueError Exceeds the limit (4300 digits) …`, dialog `return_code: 1`; `r3_writers.txt` `[bigint-append] rc=1 exc="WorkerFailed: … ValueError('Exceeds the limit (4300 digits) …"`). Base: the same `except` list (`git show 093a7c0:…variant_execution_service.py`, lines 454-457); base behaviour `not-run`, reasoned from that identical code. | Replace `json.JSONDecodeError` with `ValueError` in that `except` (it still covers `JSONDecodeError` and `UnicodeDecodeError`). **TC arm:** a manifest with a 5 000-digit `pad` → the project opens with `Manifest damaged`, and a writer leaves `project.json` byte-identical. One token in a touched file. |

## §4b-style cell

`security-reviewer` — Round 3: PASS-WITH-NOTES (0 HIGH). SEC6-1 discharged (12/12 byte-identical); SEC6-4 and SEC6-6 closed; SEC6-7 fixed for long entries (40 003-character entry: 3 clipped rows, no crash) but still open (MAJOR) for a junction loop (`RuntimeError` not caught at `variant_execution_service.py:330`); SEC6-8 new (MINOR, pre-existing): a 5 000-digit integer crashes `json.load` (`ValueError` not caught at `:512`). Both are one-token fixes in the touched file, recommended before commit and not blocking. SEC6-2 and SEC6-5 → Inc 7; SEC6-3 → LED .50 backlog.

## Evidence checklist (Round 3)

- [x] SEC6-7's named trigger re-verified closed by executed evidence (P1, writers). The residual is shown with an executed RED (P3).
- [x] Every other parse path of the reader reviewed (list above). The two that still raise were probed and are reported (SEC6-7 residual, SEC6-8).
- [x] Each finding has what, where, why, a recommendation and a severity.
- [x] No secret values, operator name or key material.
- [x] Verdict explicit: `PASS-WITH-NOTES`, 0 HIGH.
- [ ] Not tested: Python 3.12 (its `resolve()` handles loops differently; `predicted`); the real terminal driver writing a lone surrogate; the size probe's `stat()` raising, which sits outside any `try` and is pre-existing (`not-run`).

## Evidence files (Round 3, deleted with the scratch folder per the brief)

| Artifact | SHA-256 |
|---|---|
| `sec_inc6_r3_probe.py` (P1–P5) | `df116b1602b3d6ef26fec47960642c3bb42ded991297b5a34f944c6bac7b4b64` |
| `r3.txt` (P1–P5 results) | `d7bb2762cd29f9be6a92d6c81ed6053e44aeb92508dcbc1ba3d3b2f70e783b8d` |
| `p2b.py` / `r3_writers.txt` (writers) | `d5c842a1dee31be6884a0e51c0f2d75b6bb7b806cf1cdf6701fd44044c4d60e8` / `8b4d31489e3da145368d02b1195d539614f76c2b218df42dd93f2ba2c9ee0456` |
| `p5b.py` / `r3_p5b.txt` (surrogate rendering) | `c0977095c45b26565e4dca69a178cd721062572869e23b418ef5f2f4d54e0604` / `2402a8228a2ef422e098ffe79a600917e0ecd90b5baf24a4f30c29d5355dbc22` |

**VERDICT (Round 3): `PASS-WITH-NOTES`.** 0 HIGH. SEC6-7 is open as a MAJOR for the junction-loop `RuntimeError` only; SEC6-8 is a new MINOR (pre-existing `ValueError` from `json.load`). Both are recommended before commit. Neither blocks.


---

# Round 4 (final) — re-check after corrective pass 3 (SEC6-7 residual, SEC6-8)

| Field | Value |
|---|---|
| **Subject** | Corrective pass 3, uncommitted. Only `variant_execution_service.py` changed; its sha256 (first 16 hex digits) is `76b276077ded9717`. The other three are unchanged: `app.py 762d1a98c8a65903`, `screens.py ea549ab4bd9d3ef4`, `styles.tcss 781f04ed2cc30897`. The change: `_resolve_manifest_entry` now catches `(OSError, ValueError, RuntimeError)` (`:330`), and `read_project_manifest` catches a plain `ValueError` next to `JSONDecodeError` around `json.load` (`:517-518`). |
| **Execution** | `sec_inc6_r4_probe.py`, run through the real Load dialog (`action_load_project` → `LoadProjectScreen.dismiss("P")`) and then a variant append (`load_from_path`). Same interpreter and environment as before; it printed `s19_app.__file__ = C:\Users\jjgh8\Github\s19_app-b100-inc6\s19_app\__init__.py`. I re-ran Inc 6's TC modules on the tree: `tests/test_b100_active_variant.py tests/test_b100_announce.py` → **64 passed**. Every junction loop was removed with `rmdir`, and the scratch folder `…\scratchpad\s6\` was deleted. The only change to the worktree is this appended section. |
| **VERDICT** | **`PASS-WITH-NOTES`** (0 HIGH, 0 MAJOR open). **SEC6-7 and SEC6-8 are discharged** by executed evidence. The open notes are the three routed MINORs: SEC6-2 and SEC6-5 to Inc 7, and SEC6-3 to the LED .50 backlog item with SEC-9. This verdict authorises nothing beyond the increment gate, and it is not the operator's authorization. |

| id | state | evidence (`executed`, `r4.txt`) |
|---|---|---|
| SEC6-7 (MAJOR) | **closed (discharged)** | **Junction loop present at Load.** The reader returns one `MANIFEST-PATH-ESCAPE` with entry `loop/x.json`, and `manifest_is_damaged` is False. The Load dialog opens the panel with one row, `Manifest entry skipped: loop/x.json  a recorded entry points outside the project; …`, and `return_code: None`. The variant append that follows rewrites the readable manifest without the skipped entry: `Project saved + manifest verified`, `Project 'P' now opens firmware_1.s19`. **Loop added after the load, then the append:** no crash (`return_code: None`), with the same lines. In Round 3 both of these exited with `return_code: 1`. The long-entry case was closed in Round 3 and is unchanged. |
| SEC6-8 (MINOR) | **closed** | **5 000-digit integer, present at Load.** The reader returns `MANIFEST-JSON-PARSE` and `manifest_is_damaged` is True. The panel shows `Manifest damaged: project.json  not valid JSON - defaults used; …`. The variant append leaves `project.json` **byte-identical** and paints `project.json in project 'P' is damaged and was not rewritten - firmware_1.s19 stays in the project; …`. **Integer added after the load, then the append:** byte-identical, the same line, `return_code: None`. In Round 3 both exited with `return_code: 1`. |
| SEC6-1, SEC6-4, SEC6-6 | closed (Rounds 2–3), unchanged | `app.py`, `screens.py` and `styles.tcss` hashes are unchanged since Round 2. |
| SEC6-2, SEC6-5 | routed to Inc 7 | — |
| SEC6-3 | routed to the LED .50 backlog item with SEC-9 | — |

**Not tested:** Python 3.12; the size probe's `stat()` outside any `try` (pre-existing, `not-run`); a real terminal driver writing a lone surrogate (`not-run`).

## Evidence files (Round 4, deleted with the scratch folder per the brief)

| Artifact | SHA-256 |
|---|---|
| `sec_inc6_r4_probe.py` | `a582af7e6ba0f0f18d0e13cd6cd1847544cc31645f10480e44300dd54cd3d64c` |
| `r4.txt` | `41f9f8980a0c143c4daec193570fa3a8bf0b35cbeea73b293542bce4e2735e0e` |

## Final §4b cell

`security-reviewer` — final (Round 4): PASS-WITH-NOTES (0 HIGH, 0 MAJOR open). SEC6-1 discharged (12/12 damaged manifests byte-identical across the 4 writers); SEC6-4, SEC6-6 closed; SEC6-7 discharged (40 003-character entry and junction loop → one skipped-entry row, no crash, Load dialog and append); SEC6-8 closed (5 000-digit integer → "Manifest damaged", writers leave `project.json` byte-identical). Routed MINORs: SEC6-2 and SEC6-5 → Inc 7; SEC6-3 → LED .50 backlog with SEC-9.

**VERDICT (final): `PASS-WITH-NOTES`.**
