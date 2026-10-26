# P2 review — qa-reviewer — round 2 — batch 2026-10-26-batch-100

**Mode: plan.** This round re-reviews the contract at `0c7ca1d`: `01-requirements.md` (69 LLR, 67 TC, 21 AT), ledger entries LED .2–.13, and `02-review.md`, with `design/P2-dispositions-r1.md` as the rulings. Nothing outside this file was edited.

**How the probes ran.** Every probe was executed by **qa-reviewer** on a `git archive 1d677ba` snapshot (`<scratch>/snap1d677ba`), using `s19env` Python 3.11.15 and Textual 8.2.8 with `NO_COLOR` unset. The import probe printed `s19_app.__file__ = <scratch>\snap1d677ba\s19_app\__init__.py`. `git diff --stat 3060d66 0c7ca1d -- s19_app tests` is empty, so the base is unchanged.

## Verdict

- **Gate (qa-reviewer's recommendation): `iterate-to-refine`.** There are **0 HIGH** findings. The **6 MAJOR** findings are all requirement defects in the contract text, each with a small closure. Under `p2-review.md`, a requirement-defect major goes back to P1 unless the orchestrator approves it as `open` with its owning station.
- **Round-1 closures:**
  - **Closed: 21** — QA-02, 03, 04, 07, 08, 09, 10, 11, 13, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27.
  - **Closed differently but acceptable: 3.**
    - QA-01: the snapshot can be decided, with one normaliser gap (R2-07).
    - QA-05: the `Path` return is kept; R2-10 is a scoping gap.
    - QA-06: superseded by A-06. The emit rule itself carries R2-01.
  - **Still open: 3.**
    - QA-12: the cap arm is still mis-sized (R2-08).
    - QA-14: the Inc 9b ripple remains for typed-path ATs (R2-06).
    - QA-20: routed to the orchestrator; still unfixed at `PLAN.md:115` (R2-14).
- **New findings:** 0 HIGH · **6 MAJOR** · **8 MINOR**. R2-06, R2-08 and R2-14 continue QA-14, QA-12 and QA-20, which are counted here and not again as "still open".
- **Open count: 14** (6 MAJOR, 8 MINOR).
- **Re-runs on the snapshot:**
  - **Snapshot derivation (A-07):** decidable. Cold vs cold differs in 1 name, `_mac_view_cache_key`, which holds an mtime. Load-over vs cold differs in 20 names, all of them in a declared set.
  - **Markup fixtures:** all 5 can exist on disk, and the negative control turns RED.
  - **80/80 race:** RED at base (8/80).
  - **16-cell P-B table:** reproduces (11 ask, 5 load; dropping F → 1 wrong cell, dropping W → 1).
  - **Recent-store cap arm:** still mis-sized.
  - **Save-project emit rule:** an emit with no data change lands a byte-different `firmware_1.s19`.

## Closure table (round-1 findings)

| id | r1 severity | closure in the contract | status | executed check / note |
|---|---|---|---|---|
| QA-01 | HIGH | LLR-165.2, HLR-165; LED .8 | closed differently, acceptable | `snapshot_probe.py`: census of `self.<name>` assignments in class `S19TuiApp` → 67. Cold P2 vs cold P2 (two bases) → **1** differing name, `_mac_view_cache_key`. P2-over-P1 vs cold P2 → **20** names, each in a declared set: K1 `_image_generation`; K2 `log_lines`, `_a2l_cache_key`, `_a2l_cache_data`; S2/S3 `current_a2l_path`, `current_a2l_data`; S12 `_a2l_enriched_*`, `_a2l_filtered_tags`, `_a2l_summary_lines`; S13 `_mac_view_cache_*` ×7, `_validation_issues`, `_mac_row_key_to_address`, `_a2l_row_key_to_tag`. Residual: R2-07. (The emulation normalises `current_file` and the service coarsely, so the MAC and document leaks do not appear in it.) |
| QA-02 | HIGH | HLR-172 AT-13, LLR-172.6, LLR-173.3, LLR-178.2; LED .10 | closed | `markup_r2.py`: `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, `a\x9bb.s19` and `[b]P` (file and dir) all exist on disk. Markup on → spans=1 (and ctrl=1 for U+009B). `Label(safe_text(n))` → spans=0, ctrl=0, plain = the name with the control removed. |
| QA-03 | HIGH | LLR-174.1 (W term), LLR-174.2, P-32; LED .3 | closed | `LoadGuardScreen` is cited correctly. New gaps on the same table: R2-02 and R2-03. |
| QA-04 | MAJOR | HLR-164 (a), LLR-164.2 (a)/(b)/(c), §1.3 *Project*; LED .5 | closed | (1)–(5) are each decided. The case-only clash (`AB`) is refused, the exact name merges, and the open project's unsanitised name saves into it. |
| QA-05 | MAJOR | LLR-163.1 (`place_into_workarea → PlacementResult`, `copy_into_workarea` keeps `Path`), LLR-163.6, Inc 1 = 3 files; LED .9 | closed differently, acceptable | The deviation in §6.3 is sound: P-34 has 17 call sites. Residual: R2-10. |
| QA-06 | MAJOR | superseded by A-06: HLR-167, LLR-167.2, LLR-167.6; LED .4, .13 | superseded | A single rule is acceptable. The OR-clause emit rule carries R2-01. |
| QA-07 | MAJOR | HLR-169 precedence, LLR-169.9; LLR-169.5 limits `not recorded` to a present `files`; LED .7 | closed | Case 6 → `not readable` only; case 7 → `manifest damaged` only; legacy → `no digests saved` only. Each is consistent with LLR-169.5. |
| QA-08 | MAJOR | LLR-169.6 (one summary line, fixed order), HLR-178 / LLR-178.3 (panel, 30 rows); LED .7 | closed | — |
| QA-09 | MAJOR | AT-B100-05 consumer oracle (Loaded panel; the panel from Inc 6); LED .4 | closed | Before Inc 6, the Loaded-panel oracle is also true at base. The disk oracle carries the RED until the panel oracle arrives. Accepted. |
| QA-10 | MAJOR | AT-B100-11 rebuilt on the junction RED, LLR-171.4; LED .6 | closed | The RED path exists after D7 (S-02 probe). |
| QA-11 | MAJOR | LLR-169.7 (80 of 80, source predicate); LED .6 | closed | `race_probe.py` re-run → `ok=8 cross-content=9 failed-writes=52 reported-ok-but-missing=11`. 8 of 80 is far from 80 of 80, so the arm is RED. |
| QA-12 | MAJOR | LLR-172.2 (65 536 / 65 537 arms, `too large`); LED .6 | **open** (→ R2-08) | The oversize arm is fixed. The 1 900-entry cap arm still does not fit. |
| QA-13 | MAJOR | LLR-176.2 (per-action table); LED .11 | closed | — |
| QA-14 | MAJOR | §5.3 AT-by-increment index; LED .12 | **open** (→ R2-06) | AT-01 and AT-12 are marked "no re-pin", but `pa_C` auto-focuses `#load_list`. |
| QA-15 | MAJOR | §5.4 reverse census, P-35; LED .12 | closed (residual R2-11) | Re-counted on the snapshot: `copy_into_workarea` 15, `_handle_load_project` 13, `Loaded project '` 4, manifest API 9, `LoadFileScreen` 4 and `#load_path`/`#load_ok` 10, `LoadProjectScreen` 7 and `#project_list`/`#project_ok` 7, `progress_bar`/`set_progress` 5. All match. |
| QA-16 | MAJOR | §3 preface (no private access or calls, setup included); case_06 fixture (P-33); LED .11 | closed (residual R2-12) | — |
| QA-17 | MAJOR | verdict fills every slot fill-only; HLR-166 panel focus; VS-PA-6; LED .2 | closed | — |
| QA-18 | MINOR | LLR-164.3 (64; path check `+ 53 > 259`); LED .5 | closed (residual R2-13) | 53 checked: `\reports\` (9) + `%Y%m%dT%H%M%SZ` (16) + `-NN` (3) + `-before-after-report.html` (25) = 53 (`before_after_service.py:78-85`). |
| QA-19 | MINOR | HLR-170, LLR-170.2; LED .10 | closed | — |
| QA-20 | MINOR | routed to the orchestrator (PLAN) | **open** (→ R2-14) | `PLAN.md:115` still says "covered by Inc 3's `vars(app)` comparison AT". |
| QA-21 | MINOR | LLR-174.1 Negative control; LED .3 | closed | Re-executed on the new table: `ask 11 load 5`, drop-F → 1 wrong cell, drop-W → 1 wrong cell. |
| QA-22 | MINOR | LLR-164.1 device names; LED .5 | closed | — |
| QA-23 | MINOR | LLR-173.1 (`_handle_load_dialog` keeps `Path`); IFC `load_dialog` consumers list `tests/test_tui_app.py`; LED .12 | closed | — |
| QA-24 | MINOR | §5.1 one command | closed | All 6 files exist at `1d677ba`, `test_engine_unchanged.py` included. |
| QA-25 | MINOR | AT-B100-01 (P's data files listed from disk) | closed | — |
| QA-26 | MINOR | LLR-176.3 (read in a `call_after_refresh` callback) | closed | — |
| QA-27 | MINOR | LLR-163.3 last sentence | closed | — |

## New findings (round 2)

| id | severity | location | finding | executed evidence | what closes it |
|---|---|---|---|---|---|
| R2-01 | MAJOR | HLR-167, LLR-167.2 (emit when "differs from source **or** the document holds ≥ 1 entry"); LED .4, LED .13 (R-TUI-012 restated); §6.3 | **The emit rule writes images whose data did not change.** It is not listed among §6.3's deviations; it lives only in LED .4/.13. Three consequences follow. (a) **A spurious variant.** The emitter writes 32 bytes per line, while sources such as `case_01` use 16. A document whose entries change no byte (an entry that writes the bytes already there, or a reopened project's document already contained in the active variant) still emits. The emitted file is data-identical but byte-different, so M-1 does not reuse it: it lands as `<stem>_<N>` and **becomes `active_variant`**. A save-back emitted at 16 bytes per line (the save-back keeps its {16,32} selector) followed by Save project gives the same result. (b) **Check documents count too.** "The document holds ≥ 1 entry" does not exclude a check-kind document. `tests/test_project_gather.py::test_tc700_active_editor_document_is_gathered_by_kind` saves a project while a check document is active, so it now goes through `save_patched`, which no row in §5.4 records. (c) **R-TUI-012 now reads falsely.** The restated text ("otherwise it copies the loaded file byte for byte") no longer holds for a document whose entries change nothing; HLR-167's boundary "an entry that writes the bytes already there" has no expected outcome. | `emit_identity.py` on `1d677ba`: the unchanged `case_01` data emitted into a project already holding the 16-bytes-per-line `firmware.s19` → `firmware_1.s19`; `data identical: True \| bytes identical: False`. `case_01` record lengths: 6 × `S315` (16 data bytes). `test_project_gather.py:330-360` (TC-700 loads a `kind: check` document, then `_save_project`). | Decide on data, not on predicates. Emit iff the re-derived image (source + the **change**-kind document, computed on a copy, which `plan_project_save` already does) differs **in data** from the source file. Otherwise copy byte for byte. A check document never triggers an emit. When the target holds a file with identical data, state the outcome (reuse it, or land `_<N>` without making it active) and add the arm. List the rule in §6.3 and correct R-TUI-012's restatement. Arms: a same-byte entry, a 16-bytes-per-line save-back followed by Save project, a check document → copy. |
| R2-02 | MAJOR | LLR-174.1 (load kind "file": asks iff D) vs HLR-174 ("a load that would lose nothing shall not ask") | **An A2L or MAC attach asks although nothing is lost.** The "file" kind covers every Load-dialog file, but a MAC or A2L load attaches to the session and leaves the image bytes alone. With an unsaved patch, the table asks anyway, which contradicts HLR-174 and UX-11. An AT could encode either behaviour. | `app.py:11041-11047` at `1d677ba`: "a MAC/A2L attach that leaves the image bytes alone". `_merge_primary_with_existing_mac` (`:10067`). | Split the kind into *image replace* (S19/HEX) and *attach* (MAC/A2L). An attach never asks. Re-derive the table and its counts. Add an arm: D true, then an A2L load → no question, patch kept. |
| R2-03 | MAJOR | HLR-174 ("when a load would lose unsaved work") vs LLR-173.1 / HLR-174 ("the load question runs in this router", the Load dialog's route) | **Two existing load routes replace the image without passing the guard.** (1) The Workarea Files rail pick: `_load_from_item` → `load_selected_file` (`app.py:9031`). HLR-166 itself lists it as a load path. (2) The variant selector: `select_variant` (`v`, also offered from the Load-result panel) → `_handle_select_variant` (`app.py:6736`) → `load_from_path` (`app.py:6789`). An unsaved patch is lost through either route with no question. TC-B100-44/45 and AT-B100-15 drive only the dialog. | Reads at `1d677ba`: `app.py:9021-9031`; `app.py:6687-6789` (the docstring: "… `load_from_path` so parsing runs on the load worker"; the call at `:6789`). | Enumerate every user-initiated image-replacing route (Load dialog, Workarea Files pick, variant selector) in LLR-174.1. Guard each at its entry (still never inside `_handle_load_project`). Add one TC arm per route, and an AT arm: patched, then a rail pick → question. |
| R2-04 | MAJOR | AT-B100-20 (HLR-168 lists it; §5.3 row; LED .7 prose) | **AT-B100-20 has no stated oracle.** HLR-168's Acceptance block describes AT-B100-06 only. AT-20 exists as an index row ("variant append / MAC / A2L sync → `project.json` → fresh Load and Execute scope") and a ledger sentence, with no observable outcome, shipped surface or threshold. How the MAC and A2L syncs are driven, which keys are compared, and what "Execute scope" shows are not stated. | Text of HLR-168 (`01-requirements.md:432-437`), §5.3 row `:1817`. | Write AT-20's observable outcome. With P open (`batch`, `assignments`, `declared_regions`, `gathered` and `active_document` all set), the engineer (1) loads a new S19, (2) loads a MAC, (3) loads an A2L through Load. After each, `project.json` on disk keeps those five keys equal (JSON compare) with 0 absolute paths, and after (1) it names the new `active_variant`. A fresh app opening P shows the variant in the panel, the document in the Patch Editor ledger, and the batch documents in the named Execute-scope widget. One node, three arms, plus the existing RED. |
| R2-05 | MAJOR | AT-B100-21 / HLR-175 ("the rows the summary painted equal, by path and digest, the files found on disk") | **AT-B100-21 compares things the screen does not show.** (1) No digest is painted (LLR-175.4 paints source, landing name and action), so a black-box AT cannot read one; reading the plan object would be a private access. (2) The preface makes a cut row end with `…` at 118 columns, so painted paths do not equal disk paths. (3) Row granularity is undefined: whether save-as sub-folders are one row per file or per folder, and how `kept` rows (on disk, not written) and the `project.json` row compare with "files found on disk". | LLR-175.4 statement; §3 preface *Sizes*. | Define the comparison on what is painted. Each painted row gives (landing name, action); for each, the disk state must agree: new/renamed files exist, reused and kept files are unchanged by digest, and nothing is unlisted. Compare digests in the test between each copied file and the **source path the row names**, and run the independent-reader oracle on the emitted image. Fix one row per file, sub-folders included. Make the summary scroll uncut (or run the arm at 220 columns). |
| R2-06 | MAJOR | §5.3 (AT-B100-01 and AT-B100-12 "re-pinned at —"); LLR-173.2; P-30 | **QA-14, residual: typed-path ATs break at Inc 9b.** `pa_C` auto-focuses `#load_list` (P-30; LLR-173.2 "start with the focus on `#load_list`"). An AT written before 9b that presses `l`, types a path and presses Enter therefore types into the list, and Enter loads the highlighted row. AT-01 and AT-12 (and every earlier AT that loads a file by typed path) break at 9b, while §5.3 marks them as needing no re-pin. LLR-173.2 also leaves undefined which input wins when `#load_ok` is clicked, since the focus is then on the button. | P-30 (`#load_list (auto-focus)`); LLR-173.2. | Mark those ATs re-pinned at Inc 9b (focus `#load_path` by `tab` or a click before typing). Define `#load_ok`'s rule: for example, the typed text when it is non-empty, otherwise the highlighted row. Add an arm. |
| R2-07 | MINOR | LLR-165.2 (the normaliser; the exclusion list scoped to "Textual internals") | **The cold-vs-cold arm differs in one app-owned name.** `_mac_view_cache_key` = `(str(path.resolve()), st_mtime_ns, st_size)`. Two cold loads differ on it, through the mtime and the absolute path, so "cold vs cold → 0 differing names" fails as written. | `snapshot_probe.py`: `cold vs cold differing: 1 ['_mac_view_cache_key']`; `app.py:11519`. | Normalise stat-keyed caches (drop the mtime, relativise the path), or exclude the name with its reason. |
| R2-08 | MINOR | LLR-172.2 ("1 900 valid entries (< 64 KiB) → exactly 20") | **QA-12, residual: 1 900 valid entries do not fit in 64 KiB.** 1 900 *distinct* valid entries take 70 332 bytes (`C:\NNNN.s19`, compact) or 77 934 (default `json.dumps`). Only 1 900 *identical* entries fit, and only compact (64 632; default 72 234), which makes "the first 20 in order" a weak oracle. The arm now fails loudly rather than vacuously. | `recents_size.py`: the sizes quoted. | Use 1 000 distinct `C:\NNN.s19` entries (about 41 KB) → exactly the first 20, in order. |
| R2-09 | MINOR | AT-B100-07 ("reports `MANIFEST-PATH-ESCAPE` as a damaged record") vs HLR-178, LLR-169.9 and the token table | The AT expects an internal issue code painted, while the panel must word problems in user terms and the problem token is `manifest damaged`. | The text of HLR-169 and HLR-178. | Match the `manifest damaged` token and the record's name; keep the code for the log only. |
| R2-10 | MINOR | HLR-163 ("every status that reports a placement shall say whether the file was reused") | The HLR is broader than its LLRs. Only `_sync_loaded_file_to_project` (LLR-163.5) and the export (LLR-163.6) use `PlacementResult`. The save-back, the Patch Editor `save_doc` and the flow-template save keep reporting from a `Path`. | LLR-163.1, P-34. | Narrow the HLR to the two named statuses, or add an LLR plus a TC per remaining status. |
| R2-11 | MINOR | §5.4 | **The census has no row for `_handle_save_dialog` callers.** That is 7 files: `test_b99_staging`, `test_project_gather`, `test_tui_app`, `test_tui_evidence_packs`, `test_tui_manifest_save`, `test_tui_report_seam`, `test_tui_variants`. They fall under the new emit rule, the R-PC plan execution and the refusals. AT-B99-05 (a save-back, then Save project, which now emits) asserts `status.startswith("Project saved")` on `#log_line_4`; the census says only that it "keeps its outcome". | `grep -rl --include=*.py _handle_save_dialog tests` → 7; `test_b99_staging.py:1309-1349`. | Add the row with a disposition per file, including TC-700 (R2-01) and AT-B99-05's status line under LLR-167.3. |
| R2-12 | MINOR | HLR-176 / HLR-177 / P-33 (case_06 as the slow fixture) | The P-33 figure (about 5 s) covers the whole load, including the A2L tag-table build that stays on the main thread and freezes the indicator. The worker share is not measured. AT-18's `l` press is processed only after the main thread frees up, so it can miss the run. | P-33 cell; HLR-176's declared freeze. | Measure the worker share at P3 (it must exceed one timer tick on CI). Time the `l` press after the painted worker step. |
| R2-13 | MINOR | LLR-164.3 boundary ("the path limit exactly met and exceeded by 1") | The threshold has only the all-refused arm: work area 207, `207 + 1 + 0 + 53 = 261`. The 0 is not a possible name length. The "exactly met" arm has no numbers. | LLR-164.3 text. | Give L and n with `L + 1 + n + 53 = 259` → saved and `= 260` → refused. |
| R2-14 | MINOR | `PLAN.md:115` (QA-20, routed) | The PLAN still names the `vars(app)` comparison as an AT. | `grep -n "vars(app)" PLAN.md` → `:115`. | The orchestrator updates the PLAN row (TC-B100-09, `_session_snapshot`). |

## Review of the new text (asked items)

- **AT-B100-20 and AT-B100-21:** R2-04 and R2-05.
- **Rebuilt AT-B100-11:** sound. The junction RED exists at base (S-02 probe), the positive arm is "saved through the dialog → listed", and it is one node. On a non-Windows CI the junction becomes a directory symlink; the AT should create whichever link the platform supports, not skip.
- **§5.4 reverse census:** every count re-run matches (closure table, QA-15). Missing: the `_handle_save_dialog` row (R2-11). The `test_loadfilescreen_input.py:898` hit is a docstring in `test_ac2_paste_reaches_project_name_input`, so it is harmless.
- **§5.3 AT index:** right for the project-pick re-pins (9b) and the `y` answers (10). Wrong for typed-path ATs (R2-06).
- **16-cell P-B table:** the arithmetic reproduces. The kind axis (R2-02) and the route coverage (R2-03) are open.
- **Every new LLR's threshold and negative control:**
  - LLR-163.6, 164.1–164.4, 167.5, 169.4, 169.5, 169.8, 169.9, 170.1, 171.1, 171.4, 173.5, 173.6, 173.7, 174.2, 175.3, 175.4, 176.1, 176.2 and 178.3 each have a numeric threshold and a mutation or executed RED that can turn RED.
  - LLR-167.6's plan needs the emitted bytes without writing. A pure emitter exists (`changes/io.py:1729` `emit_s19_from_mem_map`, `:1879` the HEX one), so this is feasible within Inc 5's files.
  - The timing thresholds ("load under 1 s", "read under 1 s") run on CI. Keep them as guards with a stated tolerance, never as the only oracle.
- **§6.3 deviations:**
  - The `copy_into_workarea` `Path` return: acceptable.
  - The P-B trigger per load kind: acceptable in direction, incomplete (R2-02).
  - `p` opens the one dialog: acceptable.
  - S-15 with no file-count cap: acceptable as stated.
  - **The Save-project emit rule is not listed in §6.3 at all**, and it is the deviation with consequences (R2-01).

## Evidence checklist (qa-reviewer)

- [✓] **Mode declared:** plan.
- [✓] **Acceptance criteria use Given/When/Then:** every AT reads as session, then keys, then disk, painted text or stack. Exceptions: AT-20 (R2-04, no outcome) and AT-21 (R2-05, an oracle that cannot be observed).
- [✗] **Explicit Expected:** R2-01 (the same-byte boundary has no outcome), R2-04, R2-08, R2-13.
- [✓] **Edge cases include empty, boundary, invalid, error:** every HLR and LLR has a catalog. The markup fixtures are executed and real (QA-02).
- [✓] **Regression checklist exists:** §5.4 with per-symbol dispositions, re-counted. One row is missing (R2-11).
- [✓] **Exit criteria stated:** §5.2.
- [✓] **No real PII or secrets:** fixtures and `<scratch>` only.
- [✓] **Plan mode:** the batch's TC and AT results are `planned`. The probes here are `executed` (executor: qa-reviewer).
- [✗] **Layer B (black-box):** AT-21's digest comparison cannot be made through the surface (R2-05), and AT-20 has no oracle (R2-04).
- [✗] **Bidirectional surface-reachability:** the load question is unreachable on two load routes (R2-03).
- [✓] **No unfilled template:** no `<...>`, every TC id is assigned, and every slot is filled by LED .2.

## Probe scripts (scratch, not committed)

`<scratch>/qa-p2r1-scripts/`: `snapshot_probe.py`, `markup_r2.py`, `race_probe.py`, `recents_size.py`, `emit_identity.py`, plus the round-1 scripts. Each takes the snapshot path and runs with `python -I`.
