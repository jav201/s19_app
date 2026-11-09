# Validation — s19_app — Batch 2026-11-01-batch-101

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label** — the reserved field names are declared in §✅ Verdict and are read literally.
> Phase 4 artifact. Content owner: `qa-reviewer`, who **EVALUATES** the results of the validation strategy fixed in Phase 1, **names who executed each one** and returns the rows; the orchestrator writes `04-validation.md` (`stations/shared-homes-roles.md` §Delegation). The ONE complete gate-suite run is the orchestrator's (`C-25`); a sub-agent consumes the result and never owns the run.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/validation-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> This draft: `qa-reviewer`, at the batch close. It evaluated the close records and ran none of the test nodes it cites. The one complete gate run is the orchestrator's batch-end battery on the final tree `b982846` (operator ruling 2026-11-06 — the full suite runs once at batch end, never per increment); this draft consumes its transcripts.

**`Mode`:** `validation`

## ✅ Verdict (read first)

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Result` · `Gate run` · `Layer 0` · `Evidence checklist` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.
>
> **And so are the three verdict tokens** `PASS` · `PASS-WITH-NOTES` · `FAIL`, which are VALUES and not prose.
> A Spanish batch writes `- **Result:** PASS`, not `- **Resultado:** aprobado`: the label, the tokens and the
> reviewer-identity tokens below are the machine's vocabulary.

- **Result:** PASS-WITH-NOTES
- **Gate run:** the batch-end battery on the final tree `b982846` (all increments merged), executed by the orchestrator. Lane 1 `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs -n 12 --dist loadfile -m 'not serial_timing' tests` → **6 failed / 6113 passed / 182 skipped / 4 xfailed** in 3540.10 s (0:59:00); lane 2 `-m serial_timing -p no:xdist tests` → **69 passed / 2 skipped / 6305 deselected** in 383.49 s, **QC-TM: 95 bounds, 0 under 20 % margin**; combined `exit=0`. Transcripts: `evidence/close/full-suite-final.txt`. Sibling batteries on the same tree: snapshots `evidence/close/snapshots-final.txt` (CI-recipe venv, **31 passed + the 2 known `tc016s` density snapshots**), the doc-pass law guards `evidence/close/docpass-guards.txt` (**196 passed**), and the Inc 6 Windows arms `evidence/close/win-inc6-final.txt` (**82 passed**, node ids — closes Inc 6 RA-4).
  - **Triage of the 6 failures.** 4 are the batch's known failures, unchanged on base and on every CI run: `test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_at_056e_a2b_diff_report_byte_identical_despite_selection`, and `test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` / `[patch-comfortable-120x30]` (`evidence/ci/*.txt`; the snapshot lane is CI-advisory `continue-on-error`, and the two `tc016s` cells are the pre-existing density-drift family, batch-58/59). The other 2 are `test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker[files_list]` / `[load_dialog]` — a load flake under `-n 12`, re-run alone, serial, on the same tree: **2 passed (4:41), 2 passed (4:44)**, the same behaviour as at the Inc 6 and Inc 10a merges. No new product defect was found by the gate run.
- **Layer 0:** `18 unit(s) met the criterion · 18 carry a named reddening mutation` — one row per packet below (Inc 1 … 16 with the splits 10a/10b and 12/12b). Each packet's gate row names its unit nodes and its mutation verdicts; the per-requirement Layer A tables live in each increment's `04-validation.md` (`inc-*/04-validation.md`) and the packets (`03-increments/increment-0NN*.md`). The batch-level `01-requirements.md` is the template (not folded), so the batch-level Layer A is the sum of the increment tables, named here rather than restated.
- **Requirements:** the batch-level canon is the **template** — the increment rows cite the strict-EARS canon ids owned by the requirements re-write session, so the canon fold is a **hand-over**, not a fold: `close/FORWARD-requirements-session.md` holds **273 rows** (234 new · 29 changed · 8 withdrawn · 2 brought in) for the requirements session to fold into `REQUIREMENTS.md`. `devflow-init --fold-canon` **folded 0** rows and **refused the 2 template rows** of `01-requirements.md` (they are the scaffold's own placeholder rows, not canon). No requirement of the 16 increments is a blocker: every increment closed with 0 BLOCKER / 0 HIGH open (the residual findings are backlog rows, §Backlog).
- **Black-box acceptance (Layer B):** ✓ every increment's user story has at least one `AT` that observes its outcome through the shipped surface, driven by pilot keys and asserted on painted text / written bytes; each increment's `02-test-cases.md` and `04-validation.md` carry the rows. The batch-level acceptance is the per-increment sum (the operator order of 2026-11-06 replaced the per-increment full suite with partial merge verification, so the black-box rows are read off the increment packets, not a single batch-level table).
- **Surface-reachability (bidirectional):** ✓ all named inputs AND outputs/deliverables of the 16 increments were reached/observed at the surface in their increment gates — ⚠ `3` named residual gaps are carried as backlog rows flagged for the batch-end review page: BL-I10b-1 (the Hex Peek panes keep pre-write bytes until their row is re-selected), BL-I12-5 (seven dialogs still ignore Escape, R-DLG.2 `Partly`), BL-I12-6 (a Generate press in flight under Escape / a double click runs a popped dialog's handler and raises `ScreenStackError`).
- **Supersession inspection (read off the P3 packets):** ⚠ no packet ran a whole-tree supersession sweep; each increment ran its own E1/E3 census against the guard families (reach/opener censuses in Inc 12/12b, the I-3 grep pins, the `-k` / importer / law-guard runs at every E4/E5 gate). The whole-tree guards (TC-027, TC-B94-18, TC-031, the redaction gate `test_r_tst_070_2`, `test_id_registry`) ran green on the final tree in the merge gates and the batch-end battery. No live dependency on a superseded symbol survives: the dead surfaces (`VariantHelpScreen`, the three view aliases, `action_a2l_tag_find_next`, the issue-jump trio, `run_checks_for_project`) were removed by Inc 12 / Inc 4 and their censuses are pinned.
- **Test ledger:** ✓ reconciles at the batch end — the final tree collects **6305 + 71 = 6376** nodes (lane 1 `6 failed + 6113 passed + 182 skipped + 4 xfailed` = 6305 collected; lane 2 `69 passed + 2 skipped` = 71 collected, the `serial_timing` lane). The base−D+A decomposition is not separately re-measured in this records-only close (the full suite is the only whole-tree run, by operator order 2026-11-06); the base count batch-100 closed on was 5254 collected (`2026-10-26-batch-100/04-validation.md`).
- **Evidence checklist (qa-reviewer):** `qa-reviewer · 8 of 8 rows ✓ with evidence` (the gate battery, the snapshots, the doc pass, the Inc 6 Windows arms, the Inc 5 mutant re-run, the CI comparison list, the canon hand-over, and the backlog reconciliation — each cited below)

> If every line is ✓, the Detail below is reference only. Any ⚠/✗ → read the matching part.

**Declared test scope (the operator's per-increment override, 2026-11-06).** The batch's merge gate normally runs the full suite on the LAN Linux host. The operator ruled on 2026-11-06: **no full suite per increment; partial merge verification per increment (new/edited files, QC-BC, other importers, law guards, serial_timing); the full suite once at batch end.** This is the memory of the batch (`PLAN.md` "Merge verification"). Every increment's merge evidence is `evidence/merge/lan-merge-*.txt` (and `evidence/merge/fix13-*.txt`); the CI comparison list across pushes is `evidence/ci/*.txt`.

**What the batch-end battery covered.** It ran on the final tree `b982846` (main `15e90c4` adds records only) on LAN host 2, origin/main `7d641d9` + `git diff 7d641d9 b982846c` applied, staged tree `df08c07a` (`evidence/close/full-suite-final.txt` opens with the commit and the `s19_app.__file__` probe). Lane 1 is the parallel lane (`-n 12`, `not serial_timing`), lane 2 the serial `serial_timing` lane, plus the three sibling batteries above (snapshots, doc-pass guards, Inc 6 Windows arms). It is the ONE complete gate-suite run of the batch.

**CI comparison list (every run, the same 4 known failures).** `evidence/ci/` holds 14 runs. After Inc 2's first push run (`42059144223`) and the Inc 7/8 merges, the FAILED set of every push run is the batch's 4 known failures — `test_at_b78_03`, `test_at_056e_a2b`, and the 2 `tc016s` density snapshots — plus, in exactly one run (`42326527453`), a transient redaction-gate failure `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` (an `inc-12/E3-architect.md` round-2 note held a user-profile path), fixed in the next commit `09b4808` and green again in `42335545221`. The earlier runs (`41372953464`, `42037470050`, `42059144223`, `42096538034`) also carry `tc1802` / `tc707_copy` / `tc707_numbering` (the `prototypes/cambios_10_12_2026/help_sections.md` absence), which Inc 16 removed from the suite by re-bodying them on a tracked fixture; the batch's **final** known-failure set is the 4 above. The deferred batch-100 post-close CI confirmation (`41372953464`, `f72eef1`) is read in `evidence/ci/41372953464.txt`: tui-ci `5 failed / 5034 passed` = the 5 batch-100 known failures, 0 new; snapshot job `success` 29/29 (the 29 density cells of LLR-173.2m).

**Batch classification (the 6 failures on `b982846`).**

| Class | Nodes | What happened | Evidence |
|---|---:|---|---|
| Known failures | 4 | `test_at_b78_03` (palette freeze), `test_at_056e_a2b` (`baseline wrote []`), `test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` / `[120x30]` (density-drift family) — unchanged on base and on every CI push run | `evidence/close/full-suite-final.txt`; `evidence/close/snapshots-final.txt`; `evidence/ci/*.txt` |
| Load flake under `-n 12` | 2 | `test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker[files_list, load_dialog]` — re-run alone, serial, on the same tree: 2 passed (4:41), 2 passed (4:44); same behaviour at the Inc 6 and Inc 10a merges | `evidence/close/full-suite-final.txt` (classification note) |

4 + 2 = 6. No new product defect.

**Inc 5 mutant re-run (closes Inc 5 RA-1).** The Inc 5 mutant table was re-run on the final tree at the batch end: `inc-5/E5-mutants.md` section "Batch-end re-run on the final tree" + `evidence/close/inc5-mut-*.txt` (24 transcripts) — **24/24 killed** on `b982846`. This is the last owed act of Inc 5's E5.

**Who did what.**
- **Orchestrator:** the batch-end battery on `b982846` (lane 1 + lane 2, snapshots, doc-pass guards, Inc 6 Windows arms) and the CI comparison list across pushes (`evidence/close/*.txt`, `evidence/ci/*.txt`). It ran the partial merge verification per increment (`evidence/merge/lan-merge-*.txt`) and the Inc 5 mutant re-run on the final tree (`evidence/close/inc5-mut-*.txt`).
- **`qa-reviewer` (this draft)** executed no test node and consumed the transcripts; it verified the close records against the evidence files, the CI list, the canon hand-over and the backlog reconciliation (below). The real `%LOCALAPPDATA%\s19_app` and the isolated app-state folders were not created here.
- **Increment implementers and reviewers:** per increment, the `steps.log` names the model for each task — Opus for E1/E2/E3 design, the code-free review (architect + security + ux), integration and most correctives; DeepSeek v4 Pro for E4 implementation (from Inc 9 on, after Kimi K2.8 hit its weekly quota — 429 at Inc 8's E5), the mutant batteries and the close records; Sonnet for the independent testers (G-T1/G-T2/W), the narrow correctives (records, oracles, docstrings) and some records; Kimi K2.8 for the early increments' implementation and testers (Inc 1–8). See each `inc-*/steps.log`.

> Any ⚠ above → read the matching Gap row.

---

## Detail (reference)

### Layer 0 — unit

The criterion is boundary plus cyclomatic ≥ 3 (C-51), applied per increment through the design-first E1→E5 pipeline. Each packet's gate row names its unit nodes; the batch-level canon is a template, so the unit rows below name the packet and its mutation verdict, and the per-requirement rows are read off each `inc-*/04-validation.md` (Layer A of the increment).

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| Inc 1 — strict-EARS canon swap + 29119-3 TC records | boundary + census | `test_b101_*` canon guards (RED 11/11 on `e273181`, GREEN 11/11) | pass — `executed` (requirements re-write session; merged `6a4eadb`) |
| Inc 2 — test hygiene (serial_timing lane, QC-TM margins, shared waits, CI lanes, version-agnostic goldens, redaction gate) | boundary + census | hygiene RED 54/54 on base `84d4507`, GREEN 65/65; `test_r_tst_*` | pass — `executed` (merged `8e5127a`, PR #212) |
| Inc 3 — gather once per name, no folder re-creation, paint-timing verifiers R-TST-110..113 | boundary | `test_project_gather.py`, `test_b100_project_check.py` | pass — `executed` (merged `b7b77c4`) |
| Inc 4 — documents resolve symbols through the loaded A2L (six session reads; variant/report runs use the project A2L) | boundary + invalid | `test_b101_symbol_reads.py` (R-CHG-SYM.*) | pass — `executed` (merged `990db24`) |
| Inc 5 — CRC Designer refresh after in-place write + Check Editor picks/spec bytes | boundary | `test_b101_designer_recompute.py`, `test_b101_document_homes.py` | pass — `executed` (merged `98d94d7`); mutant re-run on the final tree 24/24 |
| Inc 6 — Patch Editor document lifecycle (patches//checks//library/ lists, before/after offer) | boundary | `test_b101_patch_lifecycle.py` (82 Windows nodes) | pass — `executed` (`evidence/close/win-inc6-final.txt` closes RA-4) |
| Inc 7 — diff/before-after reports: uncapped hex windows, atomic writes, escaping, provenance | boundary + invalid | `test_diff_report_service.py`, `test_tui_diff_screen.py` | pass — `executed` (merged `011fdd8`) |
| Inc 8 — Flow CRC block reads designer templates, external outputs stay current, CRC model + refusal reasons | boundary + invalid | `test_b101_flow_ext_copy.py`, `test_b101_crc_model_and_reasons.py` | pass — `executed` (merged `2a70774`) |
| Inc 9 — confirm re-run report, saved flow names, guarded flow/chain-set saves | boundary + invalid | `test_b101_flow_saves.py` (R-FLOW-FILE.14, R-FLOW-SET.8) | pass — `executed` (merged `2f54c7d` region) |
| Inc 10a — hex navigation, unload state, focus landing | boundary | `test_b101_goto_marker.py`, `test_tui_app.py` focus arms | pass — `executed` (merged `6f1743c`) |
| Inc 10b — views after an in-place write (three hex panes, A2L values, Split/Join) | boundary + performance | `test_b101_inplace_views.py` (W, 21 nodes) | pass — `executed` (QC-TM-10b-1 0.35 s / 1 s) |
| Inc 11 — A2L validation/parsing (62 ASAM block names, IF_DATA skip, MEMORY_SEGMENT reader, severity order) | boundary + invalid | `test_b101_a2l_blocks.py`, `test_tui_issues_triage_b94.py` | pass — `executed` (merged at the Inc 11 close) |
| Inc 12 — unreachable code removed, reach/opener censuses, Escape closes Reports | boundary + census | `test_b101_reach_and_reports_escape.py`, `test_b101_shown_widgets.py` | pass — `executed` (21 dialogs / 80 actions, 51 ids walked; merged `b982846`) |
| Inc 12b — Flow Builder/Execution hidden widgets removed | boundary + census | `test_b101_shown_widgets.py` (populations 53 / 38, 0 never shown) | pass — `executed` (merged `f481e8a`) |
| Inc 13 — CRC Designer / Split/Join responsive at 10 MB | boundary + performance | `test_b101_designer_recompute.py` (D-2 AST), timing arms | pass — `executed` (recompute 1×/load, debounce 150 ms, preview ≤ 2.5 s) |
| Inc 14 — help, legend, README describe the shipped app | boundary + text | `test_b101_help_legend_docs.py`, `test_docs_canon.py` | pass — `executed` (SECURITY.md held out of the merge on `gh-pvr.txt` `{"enabled":false}`) |
| Inc 15 — Windows-only test failures (single pauses → shared `settled` waits) | boundary (tests only) | `test_tui_patch_editor_v2.py::test_tc331_*`, `test_tui_flow_execution_b94.py::test_tc_b94_27_*` | pass — `executed` (0 product files; Windows 20/20 per node) |
| Inc 16 — documentation hygiene | boundary + census | `test_b101_doc_hygiene.py` (44 doc-hygiene checks) | pass — `executed` (0 product files; comment-only source fixes) |

**Measured by mutation, never by line coverage.** Per packet, the mutation verdicts (each packet's E5). The transcripts are under `evidence/inc-*/mut-*.txt`; each ends with its restore line.

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| Inc 1 | 20 / 20 canon-guard mutants | yes — 20 / 20 KILLED | `evidence/inc-1/mut-*.txt` |
| Inc 2 | 45 / 46 hygiene mutants, then the survivor killed | yes — 46 / 46 KILLED | `evidence/inc-2/mut-*.txt` |
| Inc 3 | 14 / 14 (Windows junction arms on Windows, the rest on the LAN Linux host) | yes — 14 / 14 KILLED | `evidence/inc-3/mut-*.txt` |
| Inc 4 | 17 / 17 | yes — 17 / 17 KILLED | `evidence/inc-4/mut-*.txt` |
| Inc 5 | 39 / 41 (3 equivalent) + batch-end re-run 24 / 24 | yes — all KILLED | `evidence/inc-5/mut-*.txt`; `evidence/close/inc5-mut-*.txt` |
| Inc 6 | per-row mutants (Inc 6 E5) | yes | `evidence/inc-6/mut-*.txt` |
| Inc 7 | 30 / 30 | yes — 30 / 30 KILLED | `evidence/inc-7/mut-*.txt` |
| Inc 8 | 20 / 20 | yes — 20 / 20 KILLED | `evidence/inc-8/mut-*.txt` |
| Inc 9 | 31 / 32 (M14 the one survivor, equivalent) + corrective M14b/M22…M31 | yes — all KILLED | `evidence/inc-9/mut-*.txt`, `e5c-*.txt` |
| Inc 10a | DeepSeek mutants + corrective M-c02…M-c12 | yes — all KILLED | `evidence/inc-10/mut-*.txt`, `mut-c-*.txt` |
| Inc 10b | M1…M8 (8/8) + 7 E4 controls (15/15) + corrective M-c02…M-c12 (11/11) | yes — all KILLED | `evidence/inc-10b/mut-*.txt`, `mut-c-*.txt` |
| Inc 11 | 32 / 32 + 9 corrective (8 KILLED, 1 equivalent `m-042b-1-enc`) | yes — 40 KILLED / 1 equivalent | `evidence/inc-11/mut-*.txt`, `e5c-mut-*.txt` |
| Inc 12 | 17 / 17 (M14 the focus-clear mutant included) + corrective M14b | yes — 17 / 17 KILLED | `evidence/inc-12/mut-01.txt` … `mut-17.txt` |
| Inc 12b | 7 / 7 rows (11 / 11 runs, M5 once per removed widget) | yes — 7 / 7 KILLED | `evidence/inc-12b/mut-00.txt` … `mut-11.txt` |
| Inc 13 | 24 / 25 (M-12 equivalent, dropped by C-5) + corrective negative controls | yes — 24 / 24 effective | `evidence/inc-13/mut-M-1.txt` … `mut-M-25.txt` |
| Inc 14 | 45 / 45 KILLED, 2 N/A (M19/M24) | yes — 45 / 45 KILLED | `evidence/inc-14/mut-*.txt` |
| Inc 15 | holds/controls (D1…D9, base form RED under its own hold) — tests-only, no product mutant | yes — each base form RED, fixed form GREEN | `evidence/inc-15/int-*.txt`, `e5c-*.txt` |
| Inc 16 | 35 / 35 + corrective controls (22/22 as expected, e5c-09 4/4 FAIL as expected) | yes — 35 / 35 KILLED | `evidence/inc-16/mut-01.txt` … `mut-35.txt` |

### UX walkthrough — trigger family D fired (D1)

No prototype round in this batch (operator ruling); D2 did not fire. The increments that changed what the user sees were driven through the shipped surface by pilot keys at every E4/E5, and the Inc 6 Windows arms re-ran the Windows-only nodes with node ids at the close (`evidence/close/win-inc6-final.txt`, 82 passed). The three residual visible gaps are the review-page rows (BL-I10b-1, BL-I12-5, BL-I12-6) recorded in the backlog.

**Mechanism used:** `a UI test driver` (Textual `run_test` pilot keys; files on disk read by the independent readers)

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | the per-increment criteria, driven through the REAL mechanism | `performed` — each increment's E4/E5 (`inc-*/04-validation.md`) |
| Expert inspection | a cognitive walkthrough against declared criteria, by a reviewer and not a user | `performed` — `ux-reviewer` at Inc 12's E3 (`inc-12/E3-ux.md`); no standalone P4 inspection (the UI rows are known failed checks KF-101-*, by operator ruling) |
| Evaluation with users | real users of the system, doing the tasks named in the context of use | `not performed — one operator (ISO 9241-210; batch-100's standing declaration carried forward)` |

- **Method:** automated pilot drives through the shipped key bindings and widget ids at the declared geometries; the 10 MB demo image (F-23/F-24) is driven in Inc 13. The Windows-only arms ran on the Windows host with isolated app-state folders and no clipboard (operator rule), node ids recorded.
- **Participants or population:** none — no human participant.
- **Evidence of the evaluation:** each increment's `04-validation.md` and `02-test-cases.md`; `evidence/close/win-inc6-final.txt`; the review page `close/review-b101.html`.
- **Limits:** the pilot proves the text is painted, not that an engineer reads it correctly; the 37 UI rows are known failed checks (KF-101-*) by operator ruling, not evaluated here.

### Layer A — functional (white-box): per-requirement results
> `TC-NNN` ↔ LLR/HLR. `Result` = pass / fail. `Evidence` = command output, observed behavior, inspection note, or analysis result.

> How the batch-level rows were built: this batch's `01-requirements.md` is the **template** — the batch did not fold a canon (the strict-EARS canon is owned by the requirements re-write session and its fold is the hand-over in `close/FORWARD-requirements-session.md`, 273 rows). Each increment's `01-requirements.md` + `02-test-cases.md` + `04-validation.md` carries the per-requirement rows (the `Per requirement` / `Layer A` table of each `inc-*/04-validation.md`), with `Result` = pass per row, each mutant verdict, and the coverage audit totals. The batch-level Layer A is therefore the **sum of the 18 increment tables**, not restated here — restating them would claim a verification nobody re-ran at the batch level. The roll-up per increment (rows · cases · mutants · verdict) is in the Layer 0 table above; the per-requirement detail is at `inc-*/04-validation.md` and `03-increments/increment-0NN*.md`.

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| *(per increment)* each increment's rows | test (unit/integration) + mutation | each increment's `04-validation.md` runs table | per row, in the increment's `01-requirements.md` | `executed` pass — per increment gate (Linux LAN host; Windows arms where owned) | `inc-*/04-validation.md`, `03-increments/increment-0NN*.md` |

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| *(per increment)* each increment's US | each increment's `AT-*` (in `02-test-cases.md`) | pilot keys / CLI subprocess / files on disk | each increment's `04-validation.md` AT rows | per AT | `executed` pass — per increment gate |

The batch-level acceptance is the per-increment sum (operator order 2026-11-06: partial merge verification, full suite once at batch end). No increment closed with an unobserved AT; the residual un-observed surfaces are the three review-page backlog rows named in the verdict.

### Bidirectional surface-reachability matrix (extends A-5)
> Every named INPUT dimension AND every named OUTPUT/deliverable is exercised/observed through the handler — not only the service API.

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| input | per increment — the findings the increment fixes (F-01…F-51, D-*) | per increment's `E1-slice.md` | yes — each increment's E1 pilot reproduced the finding | per increment's `02-test-cases.md` | ✓ |
| output | per increment — the deliverable the increment writes/paints | per increment's `E4/E5` producers | yes — each increment's AT row | per increment's `AT-*` | ✓ |

⚠ `3` gaps: BL-I10b-1 (Hex Peek panes keep pre-write bytes — observed only until re-selection), BL-I12-5 (7 dialogs ignore Escape), BL-I12-6 (double Generate / Escape-in-flight runs a popped handler). All three are recorded in the backlog and flagged on the review page `close/review-b101.html`.

### Signed-balance test ledger
> `post = base − D + A`. State counts in collected / passed-lean / passed-full form.

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| `5254` (batch-100 close, `2026-10-26-batch-100/04-validation.md`) | not re-measured | not re-measured | `6376` (final tree) | `6376` (6305 lane 1 + 71 lane 2) | 6113 / 6113 (+ 4 known + 2 load-flake fails) | yes — post matches the final tree's collection; the D/A decomposition is not separately re-measured in this records-only close |

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-101-1 | R-DLG.2 | seven dialogs still ignore Escape (BL-I12-5) | major | batch-102 (D7-20 family) — recorded in the backlog, flagged on the review page |
| G-101-2 | R-TUI-004 / R-A2L (post-write views) | Hex Peek panes keep pre-write bytes (BL-I10b-1) | minor | batch-102 — recorded in the backlog, flagged on the review page |
| G-101-3 | R-DLG (dismiss handlers) | a Generate press in flight under Escape / a double click raises `ScreenStackError` (BL-I12-6) | minor | batch-102 — recorded in the backlog, flagged on the review page |

### Escaped-bug regression (if a defect escaped the suite)

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` | CI run 42326527453 (main `6189588`, Inc 12b) — `FAILED` (a `inc-12/E3-architect.md` round-2 note held a user-profile path) | value — a home/account path in a committed record | yes — the redaction gate re-runs on the fixed commit | pass — CI run 42335545221 (main `09b4808`) green | `evidence/ci/42326527453.txt`, `evidence/ci/42335545221.txt` |

### Evidence checklist — qa-reviewer (full)
> Attach `qa-reviewer`'s completed evidence checklist (items in `agents/qa-reviewer.md`), each marked ✓/✗ with one-line evidence. An unchecked or evidence-less item blocks the gate.

| # | Checklist item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | The ONE complete gate-suite run exists and is the orchestrator's | ✓ | `evidence/close/full-suite-final.txt` (lane 1 + lane 2, `b982846`, exit 0) |
| 2 | The failure set is triaged, every failure attributed | ✓ | 4 known + 2 load-flake (re-run 2/2 alone) — classification note in the transcript |
| 3 | The sibling batteries (snapshots, doc pass, Inc 6 Windows arms) are read | ✓ | `evidence/close/snapshots-final.txt` (31+2), `docpass-guards.txt` (196), `win-inc6-final.txt` (82) |
| 4 | The CI comparison list is read | ✓ | `evidence/ci/*.txt` — 4 known failures every run, 1 transient redaction-gate failure fixed in `09b4808` |
| 5 | The canon fold / hand-over is named | ✓ | `close/FORWARD-requirements-session.md` (273 rows); `devflow-init --fold-canon` folded 0, refused the 2 template rows |
| 6 | The backlog reconciliation is complete | ✓ | 35 BL rows appended to `.dev-flow/BACKLOG-CODE.md` (§Backlog of 05-close) |
| 7 | The Inc 5 mutant re-run closes RA-1 | ✓ | `inc-5/E5-mutants.md` "Batch-end re-run on the final tree" + `evidence/close/inc5-mut-*.txt` (24/24) |
| 8 | The human review ledger is honest | ✓ | `05-close.md` §6 — `none`; the operator has not reviewed yet (instrument: `close/review-b101.html`) |
