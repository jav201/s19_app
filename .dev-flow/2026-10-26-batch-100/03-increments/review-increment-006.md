# Code Review — Increment 006 (batch-100, "save-back active variant, manifest carry, the Load-result panel", HLR-168 / HLR-178)

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: `software-dev` implemented it, not me. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc6`, base `093a7c0`, uncommitted. Source sha256 (16): `app.py` `d37ee857f64b202d`, `screens.py` `a957b576658777b0`, `variant_execution_service.py` `8e2e8cf059eb48aa`, `styles.tcss` `781f04ed2cc30897`. These equal the packet §4 hashes. New test files: `test_b100_active_variant.py` `a8fa71b063a08099`, `test_b100_announce.py` `75ab528348a68420`, `tests/support/b100_projects.py` `bbe74da61a4ed72a`. I did not edit the worktree. My only commands inside it were `git diff` / `git status` / `sha256sum`; this report is the one file I created there. |
| Contract | `01-requirements.md`: HLR-168 (LLR-168.1/.2/.3), HLR-178 (LLR-178.1/.2/.3), LLR-166.1 (TC-B100-12 panel arms), AT-B100-04/-05/-06/-19/-20. Ledger LED .59, .61–.66. `design/design-proposal-b100.md` §5.6. `PROJECT_RULES.md` (docstring contract). Briefs `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-6.md`. Precedent: `review-increment-005.md` (main checkout). The orchestrator's OQ-1 ruling as handed to me: (a) a writer creating `project.json` where none existed is ACCEPTED; (b) a DAMAGED `project.json` must not be silently replaced — the writer keeps the file it placed, skips the rewrite, and the status says `project.json` is damaged and was not rewritten. |
| Interpreter proof | s19env Python 3.11.15. Trees under `…\scratchpad\r6\`:<br>• `base\` = `git archive 093a7c0`;<br>• `fixed\` = base plus the 15 changed and 3 new files, hash-equal to the worktree (18/18 `OK`);<br>• `mut\<id>\` = one tree per reviewer mutant (`s19_app`, `tests`, `examples`, `tools` copied from `fixed\`, one single-occurrence edit, CRLF kept).<br>Every transcript prints `s19_app.__file__` from its own tree. Runs used `PYTHONPATH` set to that tree, `NO_COLOR` unset (`env -u`), `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `-p no:cacheprovider`. |
| **Verdict** | **FAIL (reject until fixed).** Recorded token: **`BLOCK — BLOCK-UNTIL: F1`** (1 HIGH). This verdict authorises nothing. The increment does not advance until F1 is fixed and I have re-read the fix on the diff and re-run probe P1. F2 (MAJOR) should land in the same corrective pass. |

Scratch trees `base\`, `fixed\`, `mut\` were deleted after the runs; the transcripts and `probes	est_r6_probes.py` remain under `…\scratchpad6\`.

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`.

## BLUF

The increment does what HLR-168 and HLR-178 ask on the happy paths, and the tests for them are strong. One failure path contradicts the OQ-1 ruling and loses data, so it blocks.

- **What works:**
  - The save-back activates the landed file and rewrites `project.json`; `current_file.path` stays on the loaded image (TC-19 A/B).
  - The carry converts the reader's absolute paths to project-relative POSIX strings against the same resolved root the reader used, so `relative_to` cannot raise (every entry the reader returns passed its containment check).
  - The four writers carry `batch`, `assignments`, `declared_regions`, `gathered` byte-for-key (TC-20 ×4, AT-20 ×2). My mutant ME (the carry drops `assignments`) is KILLED, 4 nodes, so the equality oracle is live for a key the packet's mutants did not touch.
  - `compose_load_announcement` is pure (no file read, no clock); "latest" is tied to `reason == recorded` only.
  - The panel: focus on `#result_body`, `escape` from anywhere, `enter` only on `#result_ok`, `v`, every disk name through `safe_text`, no truncation (30 rows, geometry oracle asserted false-before / true-after).
  - The packet's 9 mutants are meaningful and their kills are behavioural (I read the failure lines of `mut-178.2-markup-on` and `mut-178.2-status-before-load`: an assertion on painted text, not a `NameError`).
- **The TC-B100-12 panel arms do have killing mutants** (the packet declared none): my MA (the panel callback always opens the variant selector) and MB (the close drops the main screen's focus) are each KILLED, 2 of 2 arms. Add MA to the packet's mutation table.

What blocks, and what should land with it:

- **F1 (HIGH). A damaged `project.json` is silently replaced, and the user's records in it are lost.** For an unparseable file, a top level that is not an object, and an over-cap file, every writer rewrites `project.json` with `batch: []`, `assignments: {}` and no `declared_regions` / `gathered`, and paints `Project saved + manifest verified`. That is case (b) of the OQ-1 ruling, executed: 6 of 6 probe arms (2 writers × 3 damage kinds).
- **F2 (MAJOR). The variant append says `Project 'P' now opens firmware_1.s19` after `Manifest write failed`.** The seam's return value is ignored; on disk `active_variant` is still `firmware` (probe P2, a real read-only `project.json`).
- The router's "only a NEW announcement opens the panel" rule is pinned: my mutant MD (the identity guard removed) is KILLED by AT-B100-04 ×2, through the dialog's cancel path.

## Scope reviewed

- `s19_app/tui/app.py`, the whole diff:
  - imports and `_SESSION_SNAPSHOT_NAMES` (`_last_load_announcement`);
  - the save-back `:3734-3744`;
  - `action_load_project` → `_route_load_project` `:6989-7014`, `_handle_load_result` `:7016-7040`;
  - `_write_and_verify_manifest` `:9609-9745` (unchanged body; read for the return contract and the status it paints);
  - `_handle_load_project` tail `:10181-10200`;
  - `_manifest_carry` `:10224-10273`, `_activate_project_file` `:10275-10318`;
  - `_sync_loaded_file_to_project` `:10355-10466`, `_sync_loaded_a2l_to_project` `:10468-10493`.
- `variant_execution_service.py`: the reader's `gathered` parse, `_resolve_manifest_entry` (containment and resolution, to check the carry's `relative_to`), `LOAD_REASON_*`, `LoadProblem`, `LoadAnnouncement` (`summary_line` clipping), `_manifest_problems`, `_manifest_damaged`, `compose_load_announcement`.
- `screens.py` `LoadResultScreen` `:1022-1145`; `styles.tcss` panel rules.
- `workspace.place_into_workarea` (raised types), `manifest_writer.write_project_manifest` / `verify_written_manifest` (both collect, never raise), `load_selected_file` (synchronous, so the announcement reads the installed state).
- All of `test_b100_active_variant.py`, `test_b100_announce.py`, `tests/support/b100_projects.py`; the diffs of the 7 re-pinned files, `test_b100_focus.py`, `test_b100_save_image.py`, `test_id_registry.py`, `test_import_census.py`.
- The packet, `HANDOFF.md`, `mutation_harness.py`, the 9 `mut-*.txt` verdicts; evidence digests spot-checked (`red-04` `cdce7e02…`, `mut-178.3-focus-on-close` `34fe9dd2…`, `green-01` `5d4220e1…`, `mutation_harness.py` `67af605f…` — all equal the packet).

## What I executed (evidence state: `executed`)

| Run (`…\scratchpad\r6\<file>`) | Result |
|---|---|
| GREEN, fixed tree (`green-fixed.txt`): `test_b100_active_variant.py`, `test_b100_announce.py`, `test_b100_focus.py`, `test_b100_save_image.py` | **120 passed** (673 s). The packet's `green-01` (138) also holds `test_b100_session_reset.py` (18); 120 + 18 = 138. |
| **P1** (`probe-p1-p3.txt`, `probes\test_r6_probes.py`). Project P seeded with every not-owned key; `project.json` then made (i) unparseable (`{"schema_version":1,…,"batch":["patches/cs_seed.json"],` — truncated), (ii) a top-level list, (iii) valid but over the read cap (cap lowered to 16 bytes by `monkeypatch`); P opened with `_handle_load_project`; then (a) an A2L sync, (b) a variant append | **6 of 6 arms: `project.json replaced: True`.** Each now reads `{"schema_version": 1, "active_variant": …, "batch": [], "assignments": {}}` — the seeded `batch` entry, `assignments`, `declared_regions` and `gathered` are gone. Status after the writer: `… 'A2L loaded: firmware.a2l', 'Project saved + manifest verified'` (i, ii); the append adds `"Project 'P' now opens firmware_1.s19"`. In (iii) the verify paints `Manifest verify MISMATCH` only because my lowered cap also refuses the re-read; the replacement happened all the same. → F1 |
| **P2** (`probe-p1-p3.txt`). P open; `project.json` made read-only (`os.chmod S_IREAD`, a real Windows trigger); Load file of case_02 `firmware.s19` (variant append) | Statuses: `['…', 'Loaded firmware.s19', 'Manifest write failed', "Project 'P' now opens firmware_1.s19", "Added variant 'firmware_1' to project 'P'"]`. Session `active_id = 'firmware_1'`; `project.json` `active_variant = 'firmware'`. → F2 |
| P3 (`probe-p1-p3.txt`). A valid manifest whose `batch` is a string (one structure finding); A2L sync | The rewrite writes `batch: []`; status `Project saved + manifest verified`. This is HLR-169's "malformed record reported and skipped, never trusted", and the Load panel already said "Save project rewrites it" — recorded as a note under F1, not a finding. |
| **MA** (`mut-MA.txt`): `_handle_load_result` → `if True: self.action_select_variant()` | **KILLED**, 2 of 2 `tc_b100_12_panel_*` arms (`last painted focus: ListView#variant_list`). |
| **MB** (`mut-MB.txt`): `self.screen.set_focus(None)` at the top of `_handle_load_result` | **KILLED**, 2 of 2 arms (`last painted focus: OsClipboardInput#palette_input, region … width=0`). |
| MD (`mut-MD.txt`): `_route_load_project` → `if announcement is None:` (the `is before` identity guard removed); 23 dialog-route nodes | KILLED, 2 failed / 21 passed: `test_at_b100_04_…[size0]`, `[size1]` (`timed out waiting for the Legend screen`). The `p` → Cancel step re-pushes the previous announcement's panel, which then swallows `k`. The guard is pinned. |
| ME (`mut-ME.txt`): `_manifest_carry` → `"assignments": {}` | KILLED, 4 of 4 `tc_b100_20_*` (`{'assignments': {}} != {'assignments': {'firmware': ['checks/ck_seed.json']}}`). |

## Findings

| id | Severity | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| **F1** | **HIGH** (data loss; contradicts the OQ-1 ruling (b)) | `app.py:10255-10257` (`_manifest_carry`), the four seam calls `:3742`, `:10409`, `:10457`, `:10487`; `variant_execution_service.py:793` (`_manifest_damaged`, already written) | **Every in-project writer replaces a damaged `project.json` with a near-empty one and reports success.** `_manifest_carry` returns `{}` only when the file is absent. For a file the reader could not read as a manifest (size cap, JSON parse — which includes an `OSError` on open — or a top level that is not an object) `read_project_manifest` returns an empty `ProjectManifest` with one issue, the carry converts its empty lists, and the seam writes `batch: []`, `assignments: {}` and no `declared_regions` / `gathered`. The status is `Project saved + manifest verified`. The user's records in the damaged file — often one stray comma away from valid — are overwritten, with nothing on screen saying so. The ruling requires: keep the placed file, skip the rewrite, and say `project.json` is damaged and was not rewritten. The packet's §5 bullet 2 states the replacement as intended; no test covers it. | P1: 6 of 6 arms replaced (2 writers × 3 damage kinds), with the before/after bytes and the status list in `probe-p1-p3.txt`. | Put the decision in ONE helper the four writers call, instead of four copies of `self._write_and_verify_manifest(project_dir, **self._manifest_carry(project_dir))`:<br>`def _rewrite_project_manifest(self, project_dir) -> bool:` read the manifest once; if it exists and `_manifest_damaged(manifest)` (make it public in the service, or export a `manifest_is_damaged`), paint `project.json is damaged and was not rewritten - <file> was placed; fix or remove project.json, then Save project` and return False; otherwise build the carry from that same manifest and return the seam's bool.<br>Arms: for each writer, a damaged `project.json` (unparseable; top level a list) → bytes unchanged, the placed file present, the status line read in full. Mutant: drop the damaged check → RED.<br>**Discharge:** I re-read the helper on the diff and re-run P1 (6 arms: bytes unchanged, the status present). |
| **F2** | MAJOR (false status after a failure) | `app.py:10409-10414` | **The append paints `Project 'P' now opens <file>` whether or not the manifest was written.** `_write_and_verify_manifest` returns False when the write fails, and paints `Manifest write failed` plus an error toast; the next line then claims the opposite. A fresh Load opens the OLD variant. The save-back has the same shape (`:3741-3744`, return ignored) but paints no claim, so only the append misleads. With F1's fix the same line would also follow a skipped rewrite. | P2: `'Manifest write failed', "Project 'P' now opens firmware_1.s19"`; disk `active_variant 'firmware'`. | Paint the line only when the rewrite returned True (`if self._rewrite_project_manifest(project_dir): self.set_status(...)`). Arm: read-only `project.json` (or `monkeypatch` `app_module.write_project_manifest` to return `(None, [issue])`) → statuses hold `Manifest write failed` and 0 lines containing `now opens`. Mutant: paint unconditionally → RED. |
| F3 | MINOR (convention) | `app.py:6989` `_route_load_project`, `:10275` `_activate_project_file`; `variant_execution_service.py:775` `_manifest_problems`, `:736` `summary_line`; `screens.py:1124` `_problem_row(problem)` | **Docstring contract gaps on non-trivial new code.** `PROJECT_RULES.md` asks for Data Flow and Dependencies where a helper carries an invariant. `_route_load_project` (the new-announcement identity rule) and `_activate_project_file` (the filename-match id, the `landed.stem` fallback, the label repaint) have no Data Flow; `_manifest_problems` is a one-liner but holds the top-level override; `summary_line` has no Dependencies. `_problem_row`'s parameter is untyped (`LoadProblem`). | code read | Add the sections (2–4 bullets each) and the type. |
| F4 | MINOR (UX wording, declared in packet §5) | `app.py:9779` (seam status, unchanged) | **`Project saved + manifest verified` now follows a MAC sync, an A2L sync and a variant append.** After an A2L sync it is the newest line (`P1` status lists). Nothing was "saved" by the user; and in F1's case it calls a replacement "verified". | P1, P3 status lists | Route to Inc 11 as the packet proposes; meanwhile F1's helper can paint a writer-specific line (`project.json updated (active variant firmware_1)`) — optional. |
| F5 | LOW (duplication; fragile coupling) | 6 re-pinned tests (`test_b99_crc_region.py`, `test_b99_staging.py`, `test_b100_reuse.py`, `test_b99_patch_truth.py`, `test_b99_truncation.py`, `test_b99_export.py`); `variant_execution_service.py:782`, `:797` | (a) The same 11-line "wait for the panel, press escape, wait" block is pasted 6 times, and its closing wait has no assertion (a panel that does not close fails later and less clearly). (b) The composer recognises the top-level finding by **message equality** with `_MANIFEST_TOP_LEVEL_MESSAGE`; any rewording of one site silently turns a damaged manifest into an "entry skipped". | grep; code read | (a) One helper in `tests/support/b100_projects.py` that asserts the close. (b) Give the top-level finding its own code (or a flag on the issue) and test the code, not the text — or keep the constant and add an assert-style unit pin (TC-55 damaged arm with the reader's real output, not a hand-made issue). |

Notes (no finding):

- **OQ-1 (a), a writer creating `project.json` in a project that had none:** the code does it (`_manifest_carry` → `{}` → the seam writes). Accepted per the ruling; Execute in such a project then reads a manifest (packet §5).
- **Entries the reader skipped are not carried** (unsafe or malformed; P3). Consistent with HLR-169 ("reported and skipped, never trusted") and with the panel's "Save project rewrites it". Keep it, but name it in the F1 helper's docstring, and keep F1's "damaged" set to the three whole-file cases.
- **A failed parse still announces the variant as opened** (`load_selected_file` paints `Load failed: …`, then the summary and panel say `Opened firmware.s19`, 0 problems). Base painted `Loaded project 'P' -> firmware.s19` after the same failure, so it is not a regression; "not readable" is declared for Inc 7. Make sure the Inc 7 brief carries it.
- **`_activate_project_file`'s `landed.stem` fallback** (moved unchanged from the append) can stamp an id that is not in the rebuilt set if validation dropped the landed file; the manifest would then record an unknown `active_variant`. Low likelihood (the save-back always writes `.s19`). Returning `None` in that case would be safer — optional.
- **The guard change** (`MEASURED_SAFE_TEXT_CONSUMERS += s19_app.tui.screens`): acceptable. LLR-178.3 requires `safe_text` in the panel; the census's own comment prescribes "measured in" with the reason, and batch-99 Inc 6 did the same for `segment_split_view`. It is a declared deviation from BRIEF-COMMON step 5 ("any other guard failure: STOP"); the orchestrator should record that it accepts it.
- **`#status_text`** is a `Label(markup=False)` (`app.py:2368`), so `safe_text` there is defence in depth; the summary is passed as `.plain` into the markup-off log. Both correct.
- **`summary_line`** clips by `len()`, not by cell width; wide (CJK) names could exceed 118 cells. Not a contract case today.
- **With a discarded document**, the interim LED .55(a) notice is painted after the summary, so `#log_line_4` is not the summary line in that one case — pre-existing order, superseded at Inc 10.
- **App single keys behind the panel** (declared, §5): consistent with the other modals.
- **4-source cap:** 4 of 4, declared. No speculative code beyond the declared Inc 7 / 9b hooks (`_PROBLEM_RANK_*`, `_last_load_announcement`), both of which have a caller today.

## Checks the brief named

| Check | State |
|---|---|
| 1. Writers: placement, seam, carry, rollback, `OSError` | ✓ All four place through `place_into_workarea`. It raises the containment class (every caller catches it) and `FileNotFoundError` for a vanished source; the latter is unchanged from base, whose `copy_into_workarea` is a thin wrapper over the same function. ✓ All four end in the seam. ✓ Absolute → relative is correct (same resolved root; ME KILLED). ✓ Skipped entries are dropped (note). ✗ **A damaged manifest is replaced (F1).** ✗ **The append's status ignores the seam's result (F2).** Rollback: the placed file is kept on a manifest failure, which HLR-168's error boundary allows (the existing mismatch notice); the session's `active_id` then differs from disk until the next rewrite — acceptable once F2 stops the false claim. `OSError` on the manifest read is collected by the reader (JSON-PARSE); the write and verify collect too, so no writer can crash on them. |
| 2. OQ-1 (a) / (b) | (a) ✓ as ruled. (b) **✗ F1 — replaced silently today, 6/6 arms; HIGH.** |
| 3. Panel and route split | ✓ Focus starts on `#result_body` (mutant KILLED, packet). ✓ `escape` anywhere, `enter` only on `#result_ok` (the button's own press; the app has no `enter` binding to leak to). ✓ `v` → `SelectVariantScreen`. ✓ Focus after close lands on the window target (TC-12 arms; MA, MB KILLED). ✓ Every disk name through `safe_text`; labels static. ✓ No truncation (30 rows; packet mutant KILLED). ✓ Direct `_handle_load_project` meets no modal (TC-56 asserts it). ✓ The new-announcement guard is pinned (MD KILLED by AT-04 ×2). |
| 4. Composer purity, reasons, counts, order | ✓ Pure. ✓ 5 reasons, distinct user text, "latest" only for recorded. ✓ Precedence sort is stable. ✓ The summary line follows the loads (packet ordering mutant KILLED, behavioural). |
| 5. Test quality | ✓ RED claims are honest: the missing-symbol REDs (TC-18, TC-55) are labelled as such and backed by behavioural mutants. ✓ The 13 re-pinned nodes add a panel dismissal (with a presence assert) or update an exact string to the new exact string; none weakens an oracle. The one changed wait (`test_b99_export.py` AT-B99-11, `#log_line_4` → any of the 4 painted lines) is a synchronisation wait, and its reason (the seam's line now follows the MAC load) is correct. ✓ TC-12 panel arms are killable (MA, MB). ✗ No arm for a damaged manifest (F1) or a failed write (F2). |
| 6. Guard change | Acceptable (note). |
| 7. Simplicity / convention | ✓ Small, typed dataclasses; one composer; `_activate_project_file` removes the append's inline copy. F1's fix should also fold the four identical seam calls into one helper. F3 docstrings, F5 duplication. |

## Evidence checklist

- [x] Diff read in full: `app.py` hunks `:67-75`, `:197-203`, `:1605-1610`, `:1905-1910`, `:3677-3744`, `:6984-7040`, `:9693-9698`, `:10178-10200`, `:10221-10318`, `:10337-10493`; `variant_execution_service.py` `:105-115`, `:183-215`, `:422-430`, `:482-600`, `:600-900`; `screens.py` `:6-75`, `:1019-1145`; `styles.tcss` `:3606-3642`; all 3 new test files; the 11 test diffs.
- [x] Correctness pass: damaged manifest (F1, executed), failed write (F2, executed), router guard (MD KILLED), absolute→relative (ME), focus after close (MA, MB).
- [x] Simplicity pass: no premature abstraction; one fold recommended (F1 fix).
- [x] Reuse checked: `place_into_workarea`, `_write_and_verify_manifest`, `_resolve_manifest_entry`, `safe_text`, `action_select_variant` reused; `_manifest_damaged` exists but no writer uses it (F1).
- [x] Tests reviewed for intent: re-pins (no weakening), REDs (honest), panel arms (killable), gaps F1/F2.
- [x] Verdict explicit: `BLOCK — BLOCK-UNTIL: F1`, with executed evidence (P1).

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1** (1 HIGH, 1 MAJOR, 2 MINOR, 1 LOW) · F1 open.

- **F1:** a damaged `project.json` (unparseable, top level not an object, over the cap) is replaced by every writer with an almost empty manifest — the user's `batch`, `assignments`, `declared_regions`, `gathered` are lost — and the status says `Project saved + manifest verified` (probe P1, 6/6 arms, executed). This contradicts the OQ-1 ruling (b). Fix: one rewrite helper that skips a damaged manifest, keeps the placed file and says so; arms per writer.
- **F2:** the append paints `Project 'P' now opens …` after `Manifest write failed` (probe P2). Gate the line on the seam's result.

F1 is discharged only when I re-read the fix on the diff and re-run P1. The rest is sound: the carry, the composer, the panel's keys and focus, and the tests that pin them (my mutants MA, MB, MD, ME are all KILLED).

---

## Round 2 — corrective pass 1 (2026-10-30)

| Field | Value |
|---|---|
| Tree re-reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc6`, base `093a7c0`, uncommitted. Source sha256 (16): `app.py` `762d1a98c8a65903`, `screens.py` `ea549ab4bd9d3ef4`, `variant_execution_service.py` `395dcbde3b28851b`, `styles.tcss` `781f04ed2cc30897` (unchanged). These equal the coordinator's hashes and packet §4 "Final source hashes after corrective pass 1". `tests/support/b100_projects.py` is `4027c3fd47f7197d`. I did not edit the worktree; this section is my only change. |
| Interpreter proof | s19env Python 3.11.15. `…\scratchpad\r6\fixed2\` = `git archive 093a7c0` plus the 15 changed and 3 new files, hash-equal to the worktree (18/18). `mut\MA2`, `mut\MB2`, `mut\MV` = one tree per reviewer mutant. Each transcript prints `s19_app.__file__` from its own tree. Same environment as round 1. I deleted those trees after the runs; the transcripts below remain. |
| **Verdict** | **PASS-WITH-NOTES.** F1 (HIGH) is discharged: I re-read the fix on the diff and re-ran P1, now on all 4 writers. F2 is discharged. F3 and F5 are resolved. F4 (MINOR, UX wording) stays open, as declared, and goes to Inc 11. Nothing blocks. |

### What I executed (evidence state: `executed`)

| Run (`…\scratchpad\r6\<file>`) | Result |
|---|---|
| **P1, re-run and widened** (`r2-probe-p1-p3.txt`; probe source `probes\test_r6_probes.py`): 3 damage kinds (unparseable, top-level list, over the cap) × **4 writers** (A2L sync, variant append, MAC sync, save-back). The assertions are unchanged from round 1: the bytes are identical, the placed file exists, and the status names `damaged` and `project.json`. | **12 of 12 passed.** `project.json replaced: False` in every arm, and the seeded records survive byte-for-byte. Status: `project.json in project 'P' is damaged and was not rewritten - <file> stays in the project; Save project rewrites it`. No `manifest verified` and no `now opens` line is painted. In the save-back arm, the change verify line `Saved + verified: firmware_1.s19 …` follows as the newest line, and the damaged line stays visible above it. |
| **P2, re-run** (`r2-probe-p1-p3.txt`): read-only `project.json`, then a variant append | **Passed.** `['…', 'Manifest write failed', "Added variant 'firmware_1' to project 'P'"]`, with 0 `now opens` lines. On disk `active_variant` is still `firmware`. |
| P3 (malformed `batch` string) | Unchanged: the rewrite drops the skipped record (HLR-169 "never trusted"). Still a note, not a finding. |
| **MA** (`r2-mut-MA.txt`): the panel callback always opens the variant selector | **KILLED**, 2 of 2 `tc_b100_12_panel_*` arms. |
| **MB** (`r2-mut-MB.txt`): `set_focus(None)` at the top of `_handle_load_result` | **KILLED**, 2 of 2 arms. |
| **MV** (`r2-mut-MV.txt`, vacuity check on the new instruments): `tests/support/b100_projects.painted_lines` → `return []`, which also empties `load_result_panel_text` and `read_load_result_panel`. 15 panel-reading nodes. | **KILLED, 9 failed**: TC-67 thirty, damaged-manifest, hanging indent; AT-19 ×2; AT-20 ×2; AT-05 ×2. The 6 survivors read no panel text (focus, esc, tab-enter, `v`), or read colour segments directly (`_colour_of`; its own oracles are killed by the packet's UX-1 mutants). Every negative text oracle (`not EXCEPTION_NAME…`, `"latest" not in …`) sits in a node that also holds a positive oracle on the same text, so an empty read cannot pass it. **The helpers are not vacuous.** |
| GREEN (`r2-green-fixed2.txt`, then `r2-id-registry.txt`): `test_b100_active_variant.py`, `test_b100_announce.py`, `test_b100_focus.py`, `test_b100_save_image.py`, `test_b100_session_reset.py`, `test_import_census.py`, `test_id_registry.py` | **158 passed, 12 errors.** All 12 errors are `test_id_registry.py` raising `could not locate the repository root`, because an archive tree has no `.git`. That is an artefact of my tree, not of the code. With an empty `.git` marker added, `test_id_registry.py` gives **13 passed**. The implementer's `fix1-guards.txt` (75 passed, 29 snapshots, on the worktree) agrees. |
| Implementer evidence, read | `fix1-mut-F1-no-damaged-check`: KILLED 12. `fix1-mut-F2-now-opens-unconditional`: KILLED 4. `fix1-mut-F5b-scope-mark-ignored`: KILLED 4. `fix1-mut-168.3-append-no-rewrite`: KILLED 5. SEC6-6, UX1 ×2 and UX2 mutants: each KILLED. Every transcript ends `RESTORE OK`. |

### Disposition of round-1 findings

| id | Round-1 severity | State | Evidence on the diff |
|---|---|---|---|
| **F1** | HIGH | **Discharged.** | `_rewrite_project_manifest(project_dir, placed)` (`app.py:10288-10336`) is the one rewrite of the four writers (`:3745`, `:10490`, `:10534`, `:10564`). It reads the manifest once and checks `manifest_is_damaged`, now public in the service. On damage it paints the ruled status through `safe_text(...).plain`, logs, and returns False without writing. Otherwise the carry is built from the same read. OQ-1 (a) is unchanged. P1 passes 12/12, and `fix1-mut-F1-no-damaged-check` is KILLED 12. |
| **F2** | MAJOR | **Discharged; the stricter form is accepted.** | `now opens` is painted only when the helper returns True, which needs a successful write AND `MANIFEST_VERIFIED`. My ruling on the strictness: correct. A verify MISMATCH means the re-read does not show what was intended, so "Load now opens X" would be unproven, and the seam's mismatch notice already speaks for that case. P2 passes; the packet's mutant is KILLED 4. Accepted consequence: after a skipped or failed rewrite, the session's `active_id` names the new file while disk names the old one, and the status says why. |
| F3 | MINOR | Resolved. | Data Flow sections added to `_route_load_project` and `_activate_project_file`. Full docstrings on `_rewrite_project_manifest`, `manifest_is_damaged` and `_manifest_problems`. Dependencies added on `summary_line`. `_problem_row(problem: "LoadProblem")` is now typed. |
| F4 | MINOR | **Open (declared).** | `Project saved + manifest verified` still follows MAC/A2L syncs and the append when the write succeeds (P3 status list). Route it to Inc 11, as packet §6 says. It no longer follows a damaged manifest (F1). |
| F5 | LOW | Resolved. | (a) `dismiss_load_result_panel` replaces the 6 pasted blocks, and its closing wait raises `the Load-result panel did not close on esc`. (b) The top-level finding is recognised by `details["scope"] == "manifest"`, never by message text. The message is back to its base bytes, and `fix1-mut-F5b-scope-mark-ignored` is KILLED. |

### New code in this pass (SEC6-6, UX-1..UX-3), read

- **SEC6-6.** The recorded `active_variant` in `Manifest active_variant '<x>' not found …` now goes through `safe_text(...).plain` (`app.py:10153-10159`). TC-B100-56's control-byte arm pins it, and its mutant is KILLED.
- **UX-2.** Each skipped entry names its recorded string, from `details["entry"]`. The string is disk-derived, and it renders through `safe_text` in `_problem_row`. A non-string entry shows its JSON form clipped to 60. `ValidationIssue.details` defaults to a dict, so `.get` is safe on issues built elsewhere (for example the tests' hand-made issues).
- **UX-1 / UX-3.** `Table.grid` cells. The plain-`str` cells (`"Opened"`, `"Variants"`, `"Others"`, `"MAC"`, `"A2L"`, `""`) are developer constants. They are the only cells Rich would parse as markup, and none carries disk text. Every disk name is a `safe_text` `Text`. Colours are `Text` styles from `insight_style`.
- **Simplicity.** One helper replaces four copies of the seam call, and `_manifest_carry` now takes the manifest the caller read (one read per rewrite). No speculative code. Still 4 of 4 sources; `styles.tcss` was not touched in this pass.

Notes (no finding):

- Packet §2's original "Files modified" table still lists `_MANIFEST_TOP_LEVEL_MESSAGE` for `variant_execution_service.py`. The "Corrective pass 1 — files touched" table below it is correct, and says the constant was removed. Fix the stale row at commit, or mark it as the reviewed tree.
- The damaged status ends `Save project rewrites it`. That matches the ruling (Save project is the recovery). Save project will then write a fresh manifest without the damaged file's records, and that is the operator's explicit act.
- `HANDOFF.md` sits at the worktree root. Move it under `kimi/` at commit, as in earlier increments.

### Evidence checklist (round 2)

- [x] Diff re-read: `app.py` save-back `:3735-3746`, `_handle_load_project` SEC6-6 `:10150-10160`, `_manifest_carry` / `_rewrite_project_manifest` `:10236-10336`, `_activate_project_file` `:10338-10383`, the writers `:10470-10567`. `variant_execution_service.py` `:100-170`, `:270-330`, `:490-505`, `:815-875`. `screens.py` `LoadResultScreen`. `tests/support/b100_projects.py` `:140-195`. The new TC-20 damaged, now-opens, TC-56 and TC-67 arms.
- [x] Correctness: P1 12/12 and P2 re-run (both executed).
- [x] Tests can fail: MV KILLED 9 (helpers); MA and MB KILLED (panel arms); packet fix1 mutants read.
- [x] Verdict explicit: PASS-WITH-NOTES; the round-1 HIGH has applied-and-verified evidence (P1 re-run on the diff).

### §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **PASS-WITH-NOTES** (round 2) · F1 HIGH resolved: the four writers share `_rewrite_project_manifest`, a damaged `project.json` is never rewritten, the placed file stays, and the status says so. Verified on the diff: P1 re-run 12/12 (3 damage kinds × 4 writers), and the packet's F1 mutant is KILLED 12. F2 resolved (stricter form accepted): `now opens` appears only after a written and verified manifest (P2 re-run). F3 and F5 resolved. F4 (MINOR, the seam's "Project saved" wording after syncs) is open and routed to Inc 11. The new panel-reading test helpers are not vacuous (reviewer mutant MV KILLED 9), and the TC-12 panel arms are killable (MA, MB KILLED).
