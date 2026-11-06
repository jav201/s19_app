# Increment 006 — Inc 6 · R-TUI-049.3.x, R-BEFORE-AFTER-REPORT-001.x, R-PATCH-DOC-DROPDOWN-001.x, R-CHKED-031…044, R-DIFF-CHK.x, R-CHK-PE-008…014, R-CHKS-001/004/009 · Patch Editor document lifecycle

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-6/`: `01-requirements.md` (US-PE-LIFE-1 … 4, the rows above), `02-test-cases.md` (85 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E4-impl-notes-app.md`, `E4-impl-notes-svc.md`, `E4-tester1-notes.md`, `E4-tester2-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc6.md`, the pilot under `evidence-e1/` and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-6/`. Branch `b101-inc6` from `main` (base `98d94d7`), head `18420f6c` plus the uncommitted E5 records, this packet and `04-validation.md`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1–E3 (requirements, rulings, both code-free design reviews, the E3 correction), the E4 integration step, the E5 code and security reviews, the coverage audit (as the `qa-reviewer`), and the E5 corrective pass; **DeepSeek v4 Pro** — the E4 implementers (2 units), the E5 mutant battery (M1…M42), and this record; **Sonnet** — the E4 testers ×2 (lifecycle; document homes / lists).

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `006` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-TUI-049.3.1, .3.2 · R-BEFORE-AFTER-REPORT-001.1, .36 (and the unchanged .11) · R-PATCH-DOC-DROPDOWN-001.1 … .4 · R-CHKED-031, -032, -034, -040, -042, -044 · R-DIFF-CHK.1, .3, .5, .8 · R-CHK-PE-008 … 012, -014 · R-CHKS-001, -004, -009 (stories US-PE-LIFE-1 … 4) |
| Acceptance | the 85 cases of `02-test-cases.md`; black-box through the shipped controls (keys `6`, `7`, `=`, `9`, `b`, `p`, `ctrl+s`, `ctrl+l`, `ctrl+z`, `ctrl+y`, the dropdown values, the buttons and dialogs) · unit: the 37 changed units of `E1-slice.md` §1 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

A save-back now offers the before/after report **only with a project open** (and the persistent control, kept by D-2, still gives the `.11` refusal). Every route that replaces the document — a typed Load, a dropdown pick, the guarded accept, a project load, a paste, undo/redo, and an image load — hides both the before/after control and the save-back prompt, and **never** on Save project (which replaces no document). With a project open the Patch Editor File dropdown, the Check Editor Spec dropdown and the A2B Diff check-spec list show the project's `checks/<n>` and `patches/<n>` entries (the spec lists show `checks/<n>` only — their canon source is the check home), then the common library as `library/<n>`, sorted per home; a pick of a link, a linked folder or a name outside its folder is refused with the exact status, and the unsaved-changes popup re-checks before it loads. Check Editor Write lands in the project home (`<project>/checks/`) and the Write status names that home (`wrote checks/<name>` in a project, the bare name without one); a collision claims a free name and never overwrites. The Checks tab and the Checks screen reset to `no run yet` / the zero strip after a load and after every in-place write (an apply, a save-back, a Save project that writes the image) through Inc 5's one hook, and the current-run gate now follows the amended definition (document signature **and** image generation). The in-app help (`window_help.py`, text only) and the four guide/README/DOSSIER texts are updated to match.

## 2 · Files modified

Committed: `git diff --stat origin/main...HEAD` (101 files, +20 444 / −184). Uncommitted: the E5 record edits (`02-test-cases.md` RA-1…RA-5), this packet and `04-validation.md`. **SOURCE files: 4 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 · US-PE-LIFE-4 | the offer gate (`on_patch_editor_panel_save_back_decision`); the hide (`_hide_replaced_document_controls` #9) in the paste arm, undo/redo (only when the document moved), `_patch_editor_load` (#31, first), `_reset_project_session` (#7) and `_apply_prepared_load` (#10, only when a new image dict is installed); the Checks-tab writer `_refresh_patch_checks_tab` (#8) at every site that can end a run; the homes/scans/guard `_change_homes` (#12), `_check_home` (#13), `_scan_patch_change_files` (#14), `_scan_spec_files` (#15), `_resolve_listed_file` (#16, returns the unresolved `folder / name`, refuses `.` and `..`), `_spec_homes` (#32); the pick handlers (#17–#19); `_prefill_check_editor` / `_prefill_diff_check_files` / `_compose_screen_diff` (#20–#22); Write `dest_dir=self._check_home()` (#23); the hook's three prepended statements (`end_check_run`, load tail, `update_checks_view`, #33); `_refill_document_lists` (#35) after both `current_project_dir` assignments (#36, #37); `update_checks_view` gated on `check_run_is_current` (#11) |
| `s19_app/tui/services/change_service.py` | source | US-PE-LIFE-3 | `_last_check_message` stored (#24/#25); `check_run_is_current` (#26), `check_status_line` (#27), `check_aggregates` (#28), `_check_glyphs` (#29) gated on it; `end_check_run` (#34) |
| `s19_app/tui/screens_directionb.py` | source | US-PE-LIFE-3 | `PatchEditorPanel.refresh_check_results` (#30): subtitle `<n> checked` iff the status line is non-empty, `no run yet` otherwise |
| `s19_app/tui/window_help.py` | source | US-PE-LIFE-2 | text only: the File and Refresh help lines and the Spec help line now say the lists show the project's `checks/`/`patches/` then the common `library/` (E3A-09) |
| `tests/test_b101_patch_lifecycle.py` | test | US-PE-LIFE-1 · US-PE-LIFE-3 · US-PE-LIFE-4 | new file, 43 nodes: the offer, the eight hide routes, the Save-project guards, and the Checks tab/screen reset nodes |
| `tests/test_b101_document_homes.py` | test | US-PE-LIFE-2 | new file, 36 nodes: the three lists, the picks and refusals, Write homes and the free-name claim, the library arms |
| `tests/test_b101_help_legend_docs.py` | test | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 | `_FIXED` 8 → 11 rows by named supersession (F-05, F-06, F-40), `_CAPTURES_BEFORE` 4 → 6; the README stale-sentence pin now names `checks/`, a project and `.s19tool/workarea/patches/` |
| `tests/test_b101_symbol_reads.py` | test | US-PE-LIFE-2 | the `ab-diff-project-a2l-not-implicit` arm stages the check document in `P/checks/` and picks `checks/<name>` |
| `tests/test_before_after_report.py` | test | US-PE-LIFE-1 | `test_at_038a…` keys on the title `Before/after report` and pins the exact offer text |
| `tests/test_id_registry.py` | test | US-PE-LIFE-2 | `EXPECTED_SCANNED_TEST_FILES` 265 → 267 (two new test modules, measured) |
| `tests/test_tui_check_chain_b94.py` | test | US-PE-LIFE-2 | `test_tc_b94_15_dropdown_population`: option labels and values exact and in order, settled waits, fixture amended |
| `tests/test_tui_check_editor.py` | test | US-PE-LIFE-2 | `_write_calls` spy takes and passes `dest_dir` (I-D9) |
| `tests/test_tui_checks_screen.py` | test | US-PE-LIFE-3 | the two injected runs carry the provenance stamp (a state a real run leaves) |
| `tests/test_tui_patch_editor_v2.py` | test | US-PE-LIFE-2 | `test_at030a…` waits for the pick's document, asserts the source `workarea/patches/<name>` and the option list exactly |
| `README.md` | doc |  | Check Editor Write sentence: the check home (project's `checks/` with a project, the common folder without), the common specs stay reachable as `library/<n>` |
| `docs/user-guide/DOSSIER.md` | doc |  | §5 F-05, F-06, F-40 Kind cells `fixed in 1.0.0`; F-47 `carried to backlog (not reproduced on the base)` |
| `docs/user-guide/ch08-patch-editor.md` | doc |  | §8.9 no offer without a project (§8.10 keeps the refusal); §8.19 the Checks tab shows no stale run after the project load; capture notes beside ch08-09 / ch08-20 |
| `docs/user-guide/ch10-check-editor.md` | doc |  | Spec dropdown: the project's check specs then the common library's `library/<n>` |
| `.dev-flow/2026-11-01-batch-101/inc-6/01-requirements.md` | doc |  | EARS rows (R-TUI-049.3 split, R-BEFORE-AFTER-REPORT-001.36 new, the list/trigger/condition amendments, R-CHKED-032 amended at E5) + Definitions + US-PE-LIFE-1 … 4 |
| `.dev-flow/2026-11-01-batch-101/inc-6/02-test-cases.md` | doc |  | 85 ISO 29119-3 cases; audited, re-audited and closed with RA-1…RA-5 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E1-rulings.md` | doc |  | scope census, canon changes, D-1 … D-6 and the orchestrator rulings; F-47 not reproduced |
| `.dev-flow/2026-11-01-batch-101/inc-6/E1-slice.md` | doc |  | 37 functions in 4 source files, the writer/site censuses, the Inc 5 overlap |
| `.dev-flow/2026-11-01-batch-101/inc-6/E3-architect.md` | doc |  | E3 design review: FAIL (4 MAJOR, 11 MINOR), then Round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-6/E3-rulings.md` | doc |  | E3A-01…E3A-18, S-1…S-9 folded; revised D-3; Round 2 closure |
| `.dev-flow/2026-11-01-batch-101/inc-6/E3-security.md` | doc |  | E3 security review: PASS-WITH-NOTES (2 MAJOR, 4 MINOR, 1 LOW), Round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-6/E4-impl-notes-app.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, app unit) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E4-impl-notes-svc.md` | doc |  | E4 implementer notes (DeepSeek v4 Pro, service/panel/help/docs unit) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E4-tester1-notes.md` | doc |  | E4 tester (Sonnet, lifecycle): RED 38 failed / 8 passed on base, findings |
| `.dev-flow/2026-11-01-batch-101/inc-6/E4-tester2-notes.md` | doc |  | E4 tester (Sonnet, homes/lists): RED 34 failed / 9 passed on base, findings |
| `.dev-flow/2026-11-01-batch-101/inc-6/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN on the LAN host, I-D1 … I-D10, the M1…M42 table |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-mutants.md` | doc |  | mutant table M1…M42 (39/41) + the M43/M44 corrective additions; C-2 ruling |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES (F1–F3 MINOR, F4–F6 NIT) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES (E5-1, E5-2 LOW, E5-3…6 INFO) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-coverage-audit.md` | doc |  | coverage audit (17/81 marks changed) + Re-audit (85 covered, 0 partial) |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-rulings.md` | doc |  | E5 rulings C-1 … C-12 and the Re-audit rulings RA-1 … RA-5 |
| `.dev-flow/2026-11-01-batch-101/inc-6/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 … C-12, the e5c-01…08 runs, M43/M44 |
| `.dev-flow/2026-11-01-batch-101/inc-6/codewire/graph-inc6.md` | doc |  | Code-wire graph: 30 nodes, 3 groups, 6 pinned interfaces |
| `.dev-flow/2026-11-01-batch-101/inc-6/steps.log` | doc |  | stage log, models and UTC stamps |
| `.dev-flow/2026-11-01-batch-101/inc-6/04-validation.md` | doc |  | this increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-006.md` | doc |  | this packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-6/evidence-e1/i6e1-pilot-transcript.txt` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 | E1 pilot on `9bb0e3a`: F-05, D10-30, F-06 (+D9-15, D14-17), F-40 reproduced; F-47 not |
| `.dev-flow/2026-11-01-batch-101/inc-6/evidence-e1/i6e1-pilot.py` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 | the pilot script (service-level probes, no TUI) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-6/int-00.txt` … `int-08.txt` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 · US-PE-LIFE-4 | E4 integration: GREEN on LAN Linux host 2, tree `4d71b9b7…` on `98d94d7`; 9 transcripts |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-6/e5c-01.txt` … `e5c-08.txt` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 · US-PE-LIFE-4 | E5 corrective on LAN Linux host 2, tree `2dedfdeb…`; e5c-08 the Windows 10 junction / file-link arms; 8 transcripts |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-6/mut-01.txt` … `mut-42.txt` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 · US-PE-LIFE-4 | DeepSeek mutant battery M1…M42; 42 transcripts |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-6/red-01-tester1-base.txt`, `red-01-tester2-base.txt` | generated | US-PE-LIFE-1 · US-PE-LIFE-2 · US-PE-LIFE-3 · US-PE-LIFE-4 | the testers' RED-on-base runs (38/8 and 34/9) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 10 (2 new, 8 changed; uncapped) |
| Doc files | 23 (4 product docs + 19 `.dev-flow` records; outside the count) |
| Generated | 63 (62 transcripts + the pilot script) under `evidence/inc-6/` and `inc-6/evidence-e1/` |

- ⚠ **At exactly 4 source files:** this increment could not be cut smaller. `app.py` owns every replacement route, the three lists, the pick guard, the Write call and the hook; `change_service.py` owns the run state and its gate; `screens_directionb.py` owns the subtitle render; `window_help.py` changes text only (E3A-09, ruled into the 4th slot). The E5 corrective changed the same `app.py` sites only (C-7, C-9).

## 3 · How to test

```bash
# the two new files and the edited nodes (LAN Linux host 2, Python 3.11)
python -m pytest -q -n 10 -m "not serial_timing" tests/test_b101_patch_lifecycle.py tests/test_b101_document_homes.py \
  tests/test_before_after_report.py tests/test_tui_checks_screen.py tests/test_b101_symbol_reads.py tests/test_b101_help_legend_docs.py
# the law guards
python -m pytest -q -n 10 -m "not serial_timing" tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py tests/test_b101_doc_hygiene.py
# the serial-timing lane over the touched files
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_patch_lifecycle.py tests/test_b101_document_homes.py
# the 10 junction / file-link arms, once each, isolated app-state folders, no clipboard (Windows PC)
#   LOCALAPPDATA / APPDATA / TEMP / TMP = a fresh scratch folder; one process: import s19_app + pytest.main
```

All of these ran on the LAN Linux host only (operator rule); the Windows PC ran only the 10 junction / file-link arms (`e5c-08`). The transcripts are `evidence/inc-6/int-00.txt` … `int-08.txt` and `e5c-01.txt` … `e5c-08.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_patch_lifecycle.py` (43) + `tests/test_b101_document_homes.py` (36) + 5 edited existing nodes | **215 passed** (int-01) + **261 passed** (int-07, final tree); 85 cases, 85 covered / 0 partial / 0 gap |
| **A · neighbours** | the QC-BC set (61 files) + the 26 other importers + the law guards | **2701 passed** (int-02, 4 failed: I-D9 + 3 known) · **518 passed** (int-03, 1 known) · **217 passed** (int-04, 1 I-D10); serial lane **54 passed, 2 skipped** (int-05) |
| **B · black-box** (keys and dialogs) | the offer (Write file, `b`), the hides (typed Load, dropdown, popup accept, paste, `ctrl+z`/`ctrl+y`, `ctrl+l`, `p`), the lists (keys `6`, `=`, `7`; `p` and `ctrl+s` dialogs), the Checks screen (key `9`, `p` while displayed) | passed in int-01 / e5c-02; the 12 route rows re-driven through `p`, `ctrl+s` and the owning tab (e5c-04, 20 passed ×3) |

Details: `inc-6/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base `823d0c93` (before the fix) and on pristine `98d94d7` with only the two new test files |
| Instrument | project code: the testers' own nodes; the corrective's staged-tree copy; restore checked by the transcript's tree fingerprint |
| Where it ran | the LAN Linux host (testers), LAN Linux host 2 (integration, corrective); the trees are the commit (recomputed with git plumbing) |
| Transcript | `red-01-tester1-base.txt` (38 failed / 8 passed), `red-01-tester2-base.txt` (34 failed / 9 passed), `e5c-01.txt` (15 failed / 3 passed), `e5c-05.txt` (M43), `e5c-06.txt` (M44) |
| Restore proven by | each mutant copy restored byte-exact and deleted; `git worktree list` clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 79 new nodes (43 lifecycle + 36 homes) + 5 edited nodes, every node named in the transcripts' FAILED / PASSED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the declared standing guards (8 lifecycle, 9 homes) — each named in `E4-tester1-notes.md` / `E4-tester2-notes.md` |

| Field | Value |
|---|---|
| **RED counterfactual** | The 79 new + 5 edited nodes were RED on base for behavioural reasons (testers: 38 + 34 failed); the E5 corrective re-drove 20 nodes and re-proved them RED on a pristine `98d94d7` copy (`e5c-01`, 15 failed / 3 passing standing guards); M43 (`patches/.` accepted) turned `001_4_refused[unknown-folder]` RED (`e5c-05`), M44 (status back to the bare name) turned `032[project]`, `032[collision]`, `031[after-library-pick]` RED (`e5c-06`) — the restore was byte-exact and the copy deleted after. |

| Field | Value |
|---|---|
| **Mutation verdicts** | 44 mutants. DeepSeek M1…M42 (per resolved node, `E5-mutants.md`): **39 KILLED, 3 SURVIVED** — M10 (`_reset_project_session` hide) and M35 (its Checks-tab refresh) are equivalent under every buildable project load (C-2), and M27 is the expected E3A-16 survivor (M28 its effective control). Corrective M43 (drop the `.` refusal) and M44 (status names the bare file) **KILLED** (`e5c-05`, `e5c-06`). Score 39/41 = 95.1 %; with the two equivalents set aside, 39/39. The arms that stayed GREEN are named (M44's `032[no-project]` by design; the linked-folder arms double-defended). Transcripts `evidence/inc-6/mut-01.txt` … `mut-42.txt`, `e5c-05.txt`, `e5c-06.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test files on base (38 + 34 failed, `red-01-*`); the corrective's re-driven nodes on pristine base (`e5c-01`, 15 failed); the mutant harness (each mutant's guard nodes GREEN on the unmutated copy first, then the mutant RED); the coverage audit (first pass moved 17 of 81 marks and found the 12 route holes) — `E5-coverage-audit.md` §3. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 emitted forms asserted exactly: the offer text and the refusal statuses (painted notification / status-log lines, `test_before_after_report.py`, `test_b101_patch_lifecycle.py`); the Write status `Check Editor: wrote checks/<name> (… fields, kind=check).` (exact, `test_b101_document_homes.py::test_r_chked_032_write_status_names_the_home`); the written files on disk (`proj/checks/s1.chk.json` and no `workarea/patches/s1.chk.json`, the free-name claim's gained file); the option values and painted strips (the three lists, the Checks subtitle/strip/note/groups). All passed in `e5c-02` / `e5c-04`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-6/` and the pilot in `inc-6/evidence-e1/`.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| i6e1-pilot-transcript.txt | inc-6/evidence-e1/i6e1-pilot-transcript.txt | eaf82f0a4c27dd77b44b124ac055da82b351dc94706a1c228c74eab3c3e3bfb9 |
| int-00.txt | evidence/inc-6/int-00.txt | 25dda8c614e6d8c0c0b09844261c4da32ff022a7947e55a4cd102f36fe5fe039 |
| int-01.txt | evidence/inc-6/int-01.txt | e80c993d969ada7b9da93bb8b4f80ed4edf1968dd73b1eaa2c4c6cfd044f68d0 |
| int-02.txt | evidence/inc-6/int-02.txt | a8086e8a8eafcac044884a314dcc5e9e8af705dd3cb0f92dc0223afeeaa84bf0 |
| int-03.txt | evidence/inc-6/int-03.txt | fbee1b0c516bdde3baf64bd257a33cb4ef4df5cba3d60e615582a2135ca4924d |
| int-04.txt | evidence/inc-6/int-04.txt | c7dce2f02f917c69da267e801cb4135a9699e0820dfcf201b0c4d85f194e0b12 |
| int-05.txt | evidence/inc-6/int-05.txt | 60ecd34e2d07554201b8d1d20887ceda13bfd8863be4f2d79b4891edec3fe555 |
| int-06.txt | evidence/inc-6/int-06.txt | e2ebd0e019962f3fcd4a6744404604e9e5ad9dacdd1342372ac7664b3180a448 |
| int-07.txt | evidence/inc-6/int-07.txt | 32a2b35f467490c23e71e23c1a699573ff15a9b8fd048fb457641b1cdca9a464 |
| int-08.txt | evidence/inc-6/int-08.txt | cc1379d45c2f9977fa154aa9b0098889024c802c23e0e85ffff9e161f63b68ef |
| e5c-01.txt | evidence/inc-6/e5c-01.txt | b807e6401896b1aa47bee530a1fb93283b9027a62f5c93801bf3806c2335e6b7 |
| e5c-02.txt | evidence/inc-6/e5c-02.txt | bb7cc426b8f3480cd7dc8729304bc1c8e80799f98d2cddd63da48ca88feb76cc |
| e5c-03.txt | evidence/inc-6/e5c-03.txt | fcdae2d621416083109199e42e25f0632437d30cd5e6d4713c2d062ca2e145ad |
| e5c-04.txt | evidence/inc-6/e5c-04.txt | 137743fc5d70a7db6e0e2de0a70e16bf4923863192df2b9fcd2c14d04fa46365 |
| e5c-05.txt | evidence/inc-6/e5c-05.txt | 6da33550a4f36533c1db6538c9fff85f5441b008ab116b1b830da5f39e95fc5f |
| e5c-06.txt | evidence/inc-6/e5c-06.txt | dbfe93df2c6095419fa8d2771f6bbb5f7ad6c5de4a280319481ec2854366256c |
| e5c-07.txt | evidence/inc-6/e5c-07.txt | 4019599465e8820709ab5b02f8683fc2d0e613e2021d13c1b6eb99863849e336 |
| e5c-08.txt | evidence/inc-6/e5c-08.txt | 3f1aa7b78bb59e22c0a2aec7bb23c590df179d4248015ec24f8f15b117c2b045 |
| mut-01.txt … mut-42.txt | evidence/inc-6/mut-01.txt … mut-42.txt | (each cited in `E5-mutants.md`; the full digest list is in `evidence/inc-6/`) |
| red-01-tester1-base.txt | evidence/inc-6/red-01-tester1-base.txt | 7a1547d78826e8351be1abcbabe82296c3e56f401841104211d0273fa782ce3d |
| red-01-tester2-base.txt | evidence/inc-6/red-01-tester2-base.txt | a34258cb6dda8fb40d7c3090bd795b8e65bfb5e41d18f90a4e48c841ab8e6ab6 |

| Field | Value |
|---|---|
| **Evidence files** | 63 artifacts (62 transcripts + the pilot script) at the declared home, cited with the digest of their stored bytes; the 42 mutant transcripts are each digest-verified in `E5-mutants.md`'s run record and enumerated in `evidence/inc-6/`. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no product code changed at integration" (I-D1) and "no write lands outside the work area or the open project" (the security lens) |
| If the result is an ABSENCE, what made the search wide enough | `git diff origin/main HEAD -- s19_app` shows only the 4 slice files; the observables grep over `tests/` (I-D8: the three lists and picks, where Save/Write land, the offer, the prompt/control, the Checks tab/screen, the docs/help) enumerated 82 files; the engine-frozen guards (`test_engine_unchanged`, `test_tui_directionb`) confirm no frozen parser/engine module moved |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_doc_readme_4_1_no_stale_claim` (the README sentence the change makes false); `test_r_chked_032_write_status_names_the_home` (the Write-status form) |
| Conjunctive criteria: one mutation per conjunct | the current-run gate has two conjuncts (document signature **and** image generation): M38 (signature only) and M35/M27 (the reset repaint) each kill one route |
| Synthetic instance of the absent case | the linked-folder and dangling-link fixtures (a junction / file link, a swapped folder while the popup is open) built under `tmp_path`; the security probes A–H |
| **Positive control for every probe that returned an ABSENCE** | M4/M5 (a hide removed) and M22/M18 (the link walk removed) turned the absent-control / refusal reads RED — the same probe reads the painted absence and fails when the control/prompt or the refusal is present |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC observables grep (I-D8) + the 61-file QC-BC run + the 26 importers + the law guards | int-02 2701 passed (1 fixable I-D9 + 3 known), int-03 518 passed (1 known), int-04 217 passed (1 fixable I-D10) |
| B2 file moved on disk | no file moved; `window_help.py` text lines and the docs changed in place | 0 readers of a moved path; the help text is pinned by `test_b101_help_legend_docs.py` |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the four changed sources | no golden captures `app.py`, `change_service.py`, `screens_directionb.py` or `window_help.py` |
| B4 artifact produced here is consumed elsewhere | the written spec (`<project>/checks/<name>`) and the saved change file | consumed by the Spec/A2B/Diff lists and the Save project classifier (asserted in the homes file) |
| A3 interface consumed by another module changed | Check Editor Write now passes `dest_dir` to `write_change_document` | the one spy that did not take the keyword was fixed (I-D9); the other stand-ins already accepted it |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it (the two fixable failures are the test defects I-D9 / I-D10, the others are the batch's known failures identical on base); B2 no moved file; B3 no golden hit; B4 the list/classifier consumers; A3 the `dest_dir` keyword with the one fixed spy. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result / control no longer matches its node | the coverage audit's row-by-row read (`E5-coverage-audit.md` §3, C-1 … C-12), then the re-audit's RA-1 … RA-5 | 17 marks at first audit + 4 rows added (C-9) + 3 control citations + 5 "carried over by inspection" + 10 Windows rows (RA-4) | all, by the E5 corrective and this close unit | none; re-audit: 85 covered, 0 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (C-1 … C-12, RA-1 … RA-5) before the corrective edited its first site: 17 substantive mark changes + the 4 added R-CHKED-032 rows + the record-only control/wording fixes. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `267 = 265 − 0 + 2` (`tests/test_id_registry.py`, measured; two new modules). Cases `85 = 53 + 24 + 4 + 4` (E1 53, E3 +24, E4 integration +4, E5 +4 R-CHKED-032). No test node deleted, no function renamed, no assertion weakened (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §5).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; F1–F3 MINOR — guide §8.9 and the ch08-09/ch08-20 captures, the stale guard/offer docstrings, the vacuous "no file written" clause; F4–F6 NIT — the `.` name, the duplicated scan/refusal text, the double ledger render — all folded by the corrective C-6/C-7 or recorded) — `inc-6/E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES** (0 HIGH; E5-1, E5-2 LOW; E5-3 … E5-6 INFO; every E3 mitigation executed and approved by a mutant) — `inc-6/E5-security.md`. `qa-reviewer` · coverage audit (17/81 marks changed, 15 rows to `partial`, the 12 route holes) and re-audit (85 covered, 0 partial, 0 gap, RA-1…RA-5) — `inc-6/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **FAIL** (4 MAJOR E3A-01…04, 11 MINOR) → Round 2 **PASS-WITH-NOTES** · `security-reviewer` **PASS-WITH-NOTES** (2 MAJOR S-1/S-2, 4 MINOR, 1 LOW) → Round 2 **PASS-WITH-NOTES** — `inc-6/E3-architect.md`, `inc-6/E3-security.md`, `inc-6/E3-rulings.md`. The independent `testers` (E4, Sonnet ×2) wrote the 79 nodes from the design records only and ran them RED on base — `inc-6/E4-tester1-notes.md`, `inc-6/E4-tester2-notes.md`. |

## 5 · Risks

- **A project load repaint is double-covered, not isolated** (M10, M35 equivalent; M27 expected survivor): a future route that installs no variant would rely on the `_reset_project_session` calls alone, and no case builds that route (I-D3) — the redundant calls stay by C-2.
- **The Windows junction / file-link arms are executed but not yet traced per node** (RA-4): `e5c-08` elides its node list, so the 10 Windows rows read `not_run (evidence incomplete)` until the batch-end battery re-runs them with node ids.
- **A dangling `workarea/patches` link still ends the app on Check Editor Write** (E5-1/C-10, pre-existing, outside the slice): nothing is written, so containment holds, but the session's unsaved state is lost.
- **The three refusal texts still say "patches folder"** for a `checks/` or `library/` pick (E3A-10, backlog, UI text out of scope by P0); an A2B check row left empty after its list empties (E3A-11) and bidi/format characters in listed names (S-7) stay open.

## 6 · Pending

- **C-10 backlog** (SEC E5-1, pre-existing, outside the slice): a dangling `workarea/patches` link ends the app on Check Editor Write (`FileExistsError` through `changes/io.py:1648`); nothing is written.
- **RA-4 Windows re-run** — the batch-end battery re-runs the 10 junction / file-link arms on Windows with node ids (the `e5c-08` transcript elides its node list).
- **Merge-time full suite** — this increment ran its slice, every importer, the QC-BC set, the law guards and the serial lane, but not all nodes in one lane; the mutant table is also re-run against the re-driven nodes at batch end.
- **S-7 / E3A-10 / E3A-11** — bidi and format characters in listed names; the "patches folder" wording of the three refusal texts; an A2B check row left empty after its list empties (each in the backlog, `E1-rulings.md` §1).
- **S-9** — Save project gives no unsaved-edits warning when the edited document came from the library (`library/<n>`); backlog.
- **Uncommitted records** — this packet, `04-validation.md` and the E5 record edits (`02-test-cases.md` RA-1…RA-5) are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 6; run the full suite and the Windows junction arms with node ids at batch end; carry C-10 (the dangling-link crash) and S-7/E3A-10/E3A-11/S-9 into the backlog; open the next increment on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 / 4 — `app.py`, `change_service.py`, `screens_directionb.py`, `window_help.py` (text only); reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_patch_lifecycle.py` (43), `tests/test_b101_document_homes.py` (36) + 8 edited files |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the 37 slice units traced node-for-node in `codewire/graph-inc6.md`; int-01 215 passed |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 38/34 failed, `e5c-01` 15 failed, M43/M44 RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES, 0 HIGH |
| 7 | No file from another lane touched | all | ✓ | single lane |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the 4 slice files are outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-04 / e5c-03) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 85 covered, 0 partial, 0 gap — `E5-coverage-audit.md` Re-audit |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the linked-folder/dangling-link fixtures, the observables grep |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 39/41 killed, M10/M35 equivalent, M27 expected, M43/M44 killed |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 1 correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — 4 emitted forms |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer, security-reviewer, qa-reviewer, architect, security-reviewer, testers ×2 |
| 16 | **Evidence files** declared | all | ✓ | §4 — 63 artifacts with SHA-256 |
