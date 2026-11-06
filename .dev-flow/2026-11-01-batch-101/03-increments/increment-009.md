# Increment 009 — Inc 9 · R-FLOW-CHAIN.19/.20, R-FLOW-FILE.11…14, R-FLOW-SET.7…10, R-FB-SAVE.8, R-FX-SET.15 · Confirm re-run report, saved flow names, flow and chain-set saves inside the work area

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-9/`: `01-requirements.md` (US-I9-1 … 3, the rows above), `02-test-cases.md` (43 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-rulings.md`, `E3-security.md`, `E4-impl-notes-app.md`, `E4-impl-notes-svc.md`, `E4-tester1-notes.md`, `E4-tester2-notes.md`, `E4-integration-notes.md`, `E4-rulings.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc9.md`, the pilot under `evidence-e1/` and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-9/`. Branch `b101-inc9` from `main` (base `e07fb00`), head `286405a` plus the uncommitted E5 records, this packet and `04-validation.md`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1–E3 (requirements, rulings, both code-free design reviews, the E3 correction), the E4 integration step, the E5 code and security reviews, the coverage audit (as the `qa-reviewer`), and the E5 corrective pass; **DeepSeek v4 Pro** — the E4 implementers (2 units, groups G1 services and G2 app/Builder/docs), the E5 mutant battery (M1…M21), and this record; **Sonnet** — the E4 testers ×2 (G-T1 flow saves; G-T2 flow names / UI).

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `009` |
| Lane (if the batch forked) | none — single lane |
| Requirement(s) | R-FLOW-CHAIN.19, .20 · R-FLOW-FILE.11, .12, .13, .14 · R-FLOW-SET.7, .8, .9, .10 · R-FB-SAVE.8 · R-FX-SET.15 (stories US-I9-1 … 3) |
| Acceptance | the 43 cases of `02-test-cases.md`; black-box through the shipped controls (the Chapter 18.8 confirm `c`, the Builder and FX save dialogs, Save… / Save Set, the Load / Import… pickers) · unit: the changed units of `E1-slice.md` §1 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

A confirm re-run in Flow Execution now writes a chain-set report of that lane alone, with `- **Mode:** confirm re-run`, `- **Chains:** 1` and one ledger row naming the confirmed lane (was `- **Mode:** sequential`, which misstated a sequential set that was never run). A flow saved as `<stem>` and a chain set saved as `<stem>` now hold that file stem as the file's `name` — cut to 64 characters when the stem is longer, also on a name clash and after Clear — so a lane's flow report titles the flow it actually ran, and Load Set never refuses a chain-set file that Save Set wrote. A flow or chain-set save refuses a `flows/` / `flowsets/` home that passes through a link or resolves outside the work area, and never writes a byte through a link in the home that carries the file's own name (a dangling link included): the payload is built first, the name is taken with `lexists`, claimed with an exclusive create (`O_CREAT|O_EXCL|O_WRONLY|O_BINARY`, mode `0o666`), then re-verified before any byte — a regular file with one link, the same file as the descriptor, no reparse point, and a real parent equal to the home the guard already resolved; on refusal the claim is removed only when it is provably ours, and the two handlers paint the exact status texts. `flow_screens.py` changes its module docstring only (the A16-4 import census).

## 2 · Files modified

Committed: `git diff --stat e07fb00 HEAD -- s19_app tests docs README.md` (11 files, +1 788 / −67). Uncommitted: the E5 record edits (RR-1 residual wording, RR-4 Windows column, the orchestrator note in `E5-mutants.md`), this packet and `04-validation.md`. **SOURCE files: 4 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/flow_execution_service.py` | source | US-I9-1 | `CHAIN_RUN_CONFIRM_RERUN = "confirm re-run"` beside `CHAIN_RUN_MODES`; `run_chain_set` accepts the token (dispatch unchanged: lane order like `sequential`), `ChainSetRunRecord(mode=mode)` keeps it, so `compose_chain_set_report` prints it; three docstrings name the token (E3A-07) |
| `s19_app/tui/services/flow_persistence_service.py` | source | US-I9-2 · US-I9-3 | `save_flow_json` / `save_chain_set` gain `workarea_root`; `_guarded_destination` before the `mkdir` (a refusal raises and creates nothing), then the new private `_create_new_json` (the house claim: `lexists` → render → exclusive create → the check after the claim → write); `_unlink_own_claim` (E5 SE5-2); `render` writes the stem cut to the format cap; `save_chain_set` gains its Data Flow / Dependencies; docstrings (CR-05, CR-06) |
| `s19_app/tui/app.py` | source | US-I9-1 · US-I9-3 | `on_flow_execution_panel_external_step_confirmed` passes `mode=CHAIN_RUN_CONFIRM_RERUN`; `_do_save` and the FX save handler pass `workarea_root=self.workarea` inside `try`, and on `WorkareaContainmentError` paint the two exact I-3 status texts and return (no `mark_saved`) |
| `s19_app/tui/flow_screens.py` | source | — (A16-4) | module docstring only: the measured edges (panels post messages and never call the executor; the module reads `flow_model` and `flow_persistence_service`); no `docs/architecture.md` section cited (D-8) |
| `tests/test_b101_flow_saves.py` | test | US-I9-2 · US-I9-3 | new file, 38 nodes: the name/stem cases, the guard, the claim's eleven defences /14/1 … /14/11 and /8/1 … /8/9, the error arms, the mode |
| `tests/test_b101_flow_names_ui.py` | test | US-I9-1 · US-I9-2 · US-I9-3 | new file, 10 nodes: the confirm's report, the after-Clear save, the lane-report title, the two refusal statuses, AT-I9-1 … AT-I9-3 |
| `tests/test_b101_help_legend_docs.py` | test | US-I9-1 · US-I9-2 | `_FIXED` 11 → 13 rows by named supersession (F-45, F-46) |
| `tests/test_b99_staging.py` | test | US-I9-3 | TC-B99-13 census: the two saves drop from `_FINAL_NAME_DECLARED_EXCEPTIONS`; `_FINAL_NAME_ALLOWLIST` names `_unlink_own_claim` (the own-claim `os.unlink`, moved there at E5) |
| `tests/test_id_registry.py` | test | US-I9-2 · US-I9-3 | `EXPECTED_SCANNED_TEST_FILES` 267 → 269 (two new test modules, measured) |
| `docs/user-guide/ch18-flow-execution.md` | doc |  | the confirm's report records `confirm re-run` (the `(finding F-45)` pointer dropped) |
| `docs/user-guide/DOSSIER.md` | doc |  | §5 F-45, F-46 `· fixed in 1.0.0` |
| `.dev-flow/2026-11-01-batch-101/inc-9/*.md` | doc |  | the E1–E5 records, the codewire graph, `04-validation.md` and `steps.log` (uncommitted records listed here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-9/*.txt` | generated | US-I9-1 · US-I9-2 · US-I9-3 | 48 transcripts (int-01 … int-09, e5c-01 … e5c-07, e5s-probe, mut-01 … mut-21, mut-r-11 … mut-r-21, red-01 ×2, win-01, win-02); `mut-r-14b.txt` the orchestrator's untracked addition |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 5 (2 new, 3 changed; uncapped) |
| Doc files | 2 product docs + the `.dev-flow` records (outside the count) |
| Generated | 49 (48 committed transcripts + `mut-r-14b.txt`) under `evidence/inc-9/` and `inc-9/evidence-e1/` |

- ⚠ **At exactly 4 source files:** `flow_execution_service.py` owns the mode token; `flow_persistence_service.py` owns both saves and the shared claim; `app.py` owns the three handlers; `flow_screens.py` changes its docstring only (A16-4, ruled into the 4th slot). The E5 corrective changed the same `flow_persistence_service.py` sites and docstrings only.

## 3 · How to test

```bash
# the two new files and the edited nodes (LAN Linux hosts, Python 3.11)
python -m pytest -q -n 10 -m "not serial_timing" tests/test_b101_flow_saves.py tests/test_b101_flow_names_ui.py \
  tests/test_b99_staging.py tests/test_b101_help_legend_docs.py
# the law guards
python -m pytest -q -n 10 -m "not serial_timing" tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py tests/test_b101_doc_hygiene.py
# the serial-timing lane over the touched files
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_flow_saves.py tests/test_b101_flow_names_ui.py
# the Windows-only arms, once each, isolated app-state folders, no clipboard (Windows PC)
#   LOCALAPPDATA / APPDATA / TEMP / TMP = a fresh scratch folder; one process: import s19_app + pytest.main
```

All of these ran on the LAN Linux hosts only (operator rule); the Windows PC ran only the Windows-only arms (`win-01` on `b204c7d4`, `win-02` on `3f8b9e98`). The transcripts are `evidence/inc-9/int-01.txt` … `int-09-e4r3.txt`, `e5c-01.txt` … `e5c-07.txt`, `win-01.txt`, `win-02.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_flow_saves.py` (38) + `tests/test_b101_flow_names_ui.py` (10) + 3 edited existing nodes | **297 passed, 0 failed, 0 skipped** (e5c-07, final tree); 43 cases, 43 covered / 0 partial / 0 gap |
| **A · neighbours** | the QC-BC set (24 files) + the 21 other importers + the law guards | **1254 passed, 147 skipped, 1 xfailed** (int-02) · **761 passed, 10 skipped** (int-03) · **218 passed** (int-04); serial lane **46 passed, 2 skipped** (int-05) |
| **B · black-box** (keys and dialogs) | the confirm (`c` after the dwell), Save… after Clear, the lane-report title, the two refusal statuses through the dialogs (AT-I9-1 … AT-I9-3) | passed in int-01 / int-07 / e5c-07; Windows arms in win-02 |

Details: `inc-9/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base `e07fb00` (before the fix) and the guard removed from both saves |
| Instrument | project code: the testers' own nodes; the corrective's staged-tree copy; restore checked by the transcript's tree fingerprint |
| Where it ran | the LAN Linux hosts (testers, integration, corrective); the trees are the commits (recomputed with git plumbing) |
| Transcript | `red-01-tester1-base.txt` (20 failed / 4 passed), `red-01-tester2-base.txt` (9 failed / 1 passed), `int-06.txt` (5 failed, behavioural), `e5c-02.txt` / `e5c-03.txt` (each corrective mutant RED) |
| Restore proven by | each mutant copy restored byte-exact and deleted; `git worktree list` clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 48 new nodes (38 saves + 10 UI) + 3 edited nodes, every node named in the transcripts' PASSED / FAILED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the declared standing guards (4 flow-saves, 1 UI) — each named in `E4-tester1-notes.md` / `E4-tester2-notes.md` |

| Field | Value |
|---|---|
| **RED counterfactual** | The 48 new + 3 edited nodes were RED on base for behavioural reasons (testers: 20 + 9 failed); the five home rows failed on base by `TypeError` and int-06 shows their behavioural failure (the guard removed → each file at its link's target); the corrective mutants M14b / M22…M31 each turned their target nodes RED (e5c-02, e5c-03). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 32 mutants on the final tree. DeepSeek M1…M21 (pre-corrective): **21 KILLED**. Corrective M14b, M22…M31: **11 KILLED** (e5c-02, e5c-03). Re-mapped M11…M14, M21 (the old step (d)): M11, M12, M13, M21 KILLED, **M14 equivalent survivor** — its dropped `S_ISREG`/`samestat` clauses are each isolated by /14/10 + /8/8 (M22) and /14/11 + /8/9 (M23), and `S_ISREG` is subsumed by `samestat` (see `mut-r-14b.txt`). Score 31/32; with the equivalent set aside, 31/31. Transcripts `evidence/inc-9/mut-01.txt` … `mut-21.txt`, `mut-r-11.txt` … `mut-r-21.txt`, `e5c-02.txt`, `e5c-03.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test files on base (20 + 9 failed, `red-01-*`); the guard-removed mutant (int-06, 5 failed); the mutant harness (each mutant's guard nodes GREEN on the unmutated copy first, then the mutant RED); the coverage audit (first pass found the QA-2 partial and the QA-1…QA-4 gaps) — `E5-coverage-audit.md` §3. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 emitted forms asserted exactly: the confirm report's `- **Mode:** confirm re-run` / `- **Chains:** 1` / ledger row (`test_b101_flow_names_ui.py`); the two refusal statuses painted on the status line, exact (`test_r_fb_save_8_1_…`, `test_r_fx_set_15_1_…`); the saved file's `name` field and the lane report's `# Flow report — rep\_b` title (`test_b101_flow_saves.py`, `test_b101_flow_names_ui.py`); the bytes on disk at the link targets (0 bytes, the link kept, the free-name claim). All passed in `e5c-02` / `e5c-07`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-9/` and the pilot in `inc-9/evidence-e1/`. Each transcript prints the base commit, the staged tree, `s19_app.__file__` and (the corrective) the exact command line; home paths and account names are redacted.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` |
|---|---|
| i9e1-pilot-transcript.txt | inc-9/evidence-e1/i9e1-pilot-transcript.txt |
| int-01.txt … int-08.txt, int-09-e4r3.txt | evidence/inc-9/int-01.txt … evidence/inc-9/int-09-e4r3.txt |
| e5c-01.txt … e5c-07.txt | evidence/inc-9/e5c-01.txt … evidence/inc-9/e5c-07.txt |
| e5s-probe.txt, e5s-probe.py.txt | evidence/inc-9/e5s-probe.txt, evidence/inc-9/e5s-probe.py.txt |
| mut-01.txt … mut-21.txt | evidence/inc-9/mut-01.txt … evidence/inc-9/mut-21.txt |
| mut-r-11.txt … mut-r-21.txt (mut-r-14b.txt) | evidence/inc-9/mut-r-11.txt … evidence/inc-9/mut-r-21.txt (mut-r-14b.txt) |
| red-01-tester1-base.txt, red-01-tester2-base.txt | evidence/inc-9/red-01-tester1-base.txt, evidence/inc-9/red-01-tester2-base.txt |
| win-01.txt, win-02.txt | evidence/inc-9/win-01.txt, evidence/inc-9/win-02.txt |

| Field | Value |
|---|---|
| **Evidence files** | 48 committed transcripts at the declared home, each printing the base commit and the staged tree; the pilot script and transcript sit under `inc-9/evidence-e1/`. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no byte written outside the work area" (the security lens) and "no product code changed at integration" (I-D1) |
| If the result is an ABSENCE, what made the search wide enough | `git diff e07fb00 HEAD -- s19_app` shows only the 4 slice files; the observables grep over `tests/` (I-D10) enumerated 32 files; the engine-frozen guards (`test_engine_unchanged`, `test_tui_directionb`) confirm no frozen parser/engine module moved |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_13_no_final_name_replace_outside_placement` (no `write_text` outside the allow-list — the claim-then-write form); the `_link_points_at` link-kept assertions (/14/1, /14/2, /8/1, /8/2) |
| Conjunctive criteria: one mutation per conjunct | the check after the claim has four conjuncts (regular, one link, same file, real parent): M23 (nlink), M22 (samestat), M12/M13 (real parent), M14b (link clauses) each isolate one |
| Synthetic instance of the absent case | the dangling-link, followed-create, swapped-home, planted-file, hard-link and re-pointed-home fixtures built under `tmp_path`; the security probes P1…P10 |
| **Positive control for every probe that returned an ABSENCE** | M22/M23 (a clause dropped) and the guard-removed mutant (int-06) turned the absent-byte / no-file reads RED — the same probe reads the painted absence and fails when a defence is removed |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC observables grep (I-D10) + the 24-file QC-BC run + the 21 importers + the law guards | int-02 1254 passed (147 skipped, 1 xfailed), int-03 761 passed (10 skipped), int-04 218 passed |
| B2 file moved on disk | no file moved; the two docs and the `flow_screens.py` docstring changed in place | 0 readers of a moved path; the help/docs pins hold in int-04 |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the four changed sources | no golden captures `app.py`, `flow_screens.py`, `flow_execution_service.py` or `flow_persistence_service.py` |
| B4 artifact produced here is consumed elsewhere | the saved flow / chain-set file (`name` = stem) and the confirm's chain-set report | consumed by Load Set, the lane-run report title, and the reports folder (asserted in the two test files) |
| A3 interface consumed by another module changed | `save_flow_json` / `save_chain_set` gain `workarea_root`; the two handlers pass it | the one keyword is passed by both call sites; the 7 other test callers use the derived-root arm (read) |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it; B2 no moved file; B3 no golden hit; B4 the Load Set / report-title / reports consumers; A3 the `workarea_root` keyword with the derived-root arm read. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result / control no longer matches its node | the coverage audit's row-by-row read (`E5-coverage-audit.md` §3, QA-1 … QA-10), then the corrective's per-ruling edits (CR-02 … CR-10, SE5-1 … SE5-5) | 1 mark at first audit (QA-2, R-FLOW-CHAIN.20/2) + 9 cases added (R-FLOW-FILE.14/7 … /11, R-FLOW-SET.8/6 … /9) + the Result/Windows re-citations | all, by the E5 corrective and this close unit | none; re-audit: 43 covered, 0 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (QA-1 … QA-10) before the corrective edited its first site: the QA-2 partial and the 9 added cases, plus the record-only Result / Windows / control re-citations. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `269 = 267 − 0 + 2` (`tests/test_id_registry.py`, measured; two new modules). Cases `43 = 34 + 9` (E4-R3 34, E5 corrective +9). No test node deleted, no function renamed, no assertion weakened (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §5).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (0 HIGH; CR-01 … CR-10 MINOR — the clash cut, the unproven `samestat` clause and error arms, the raw `os.symlink` nodes, the docstring drift, the check outside the `try`, the triple next-candidate step, the weak /8/1 and /14/5 oracles, the BL-I9-4 wording) — `inc-9/E5-code-review.md`. Re-review of the corrective `3f8b9e9`: **PASS-WITH-NOTES** (0 HIGH; RR-1 LOW the parent-swap residual leaves the empty claim inside the outside `flows/`, RR-2 LOW the `st_nlink == 1` clause widens the unprobed-volume false-refusal carry, RR-3 LOW /14/9 does not assert its re-point ran, RR-4 INFO the Windows column not yet re-cited to `win-02`). `security-reviewer` · **PASS-WITH-NOTES** (0 HIGH; SE5-1, SE5-2, SE5-3 LOW; SE5-4 … SE5-6 INFO; every E3 mitigation executed and approved by a mutant) — `inc-9/E5-security.md`. `qa-reviewer` · coverage audit (33 `full`, 1 `partial` → 43 `full`, 0 `partial`, 0 `gap`, QA-1 … QA-10) — `inc-9/E5-coverage-audit.md`. **Design reviews (E3, code-free):** `architect` **FAIL** (1 HIGH E3A-01, 1 MAJOR E3A-02, 8 MINOR) → Round 2 **PASS-WITH-NOTES** · `security-reviewer` **FAIL** (2 MAJOR S-1/S-2, 4 MINOR) → Round 2 **PASS-WITH-NOTES** — `inc-9/E3-architect.md`, `inc-9/E3-security.md`, `inc-9/E3-rulings.md`. The independent `testers` (E4, Sonnet ×2) wrote the 48 nodes from the design records only and ran them RED on base — `inc-9/E4-tester1-notes.md`, `inc-9/E4-tester2-notes.md`. |

## 5 · Risks

- **The `st_nlink == 1` clause is carried on two volumes only** (RR-2): it is evidenced on local NTFS (`win-02`, probe 1) and Linux ext4/btrfs (`e5c-07`) only. A filesystem that reports `st_nlink != 1` for a newly created file would refuse every save with the I-3 status — a false refusal, not a leak. Network, virtual and cloud-sync volumes are unprobed, and the work area is `<cwd>/.s19tool/workarea`, so it can sit on any of them. The batch-end Windows run does one plain save on the operator's real volume type.
- **The claim is the house TOCTOU class, not closed** (BL-I9-4, BL-I9-10): with no concurrent writer nothing lands outside; under an active local attacker racing the save, content can reach a new file outside only under a double home swap, and the cleanup can delete another file only under a swap inside its last window (SE5-1, SE5-2, probes P3/P9). Never an overwrite (`O_EXCL`). The descriptor-bound check (BL-I9-10) is platform-specific and not taken.
- **A saved file's `name` can still equal another file's stem on a long clash** (BL-I9-9): `<"C"×64>_2.json` holds `"C"×64`, the stem of the first file. The loader still loads both; the suffix-keeping cut is a design change ruled backlog.
- **The stale name after Clear is carried** (BL-I9-5, D-2 = no): the ribbon, the Save dialog's suggestion and the load question keep the cleared flow's name; no file carries it (R-FLOW-FILE.12 fixes the file, and Clear empties the chain).
- **Loads and `reports/` remain unguarded** (BL-I9-3, BL-I9-7): the Load / Import… / Load Set lists read through a linked home, and the chain-set/flow reports are written into `<project>/reports/` with no destination guard.

## 6 · Pending

- **Merge verification** — per the operator's order (2026-11-06), no full suite runs per increment: each increment ran partial sets (its slice, the importers, the QC-BC set, the law guards, the serial lane) on the merged tree; the full suite runs once at batch end, when the batch's increments are all on `main`.
- **Canon ids to forward to the requirements session** — the 10 new rows (R-FLOW-CHAIN.19, .20; R-FLOW-FILE.12, .13, .14; R-FLOW-SET.8, .9, .10; R-FB-SAVE.8; R-FX-SET.15), the 2 changed rows (R-FLOW-FILE.11, R-FLOW-SET.7), the 1 withdrawn row kept by id (R-FB-RUN.8, D-2 = no), and the context-note changes (CTX-CHAIN confirm re-run; CTX-FLOWREPORT Mode values; CTX-FLOWFILE file stem / link / passes through a link / exists / status texts) go into `REQUIREMENTS.md` at the batch-end requirements session.
- **Backlog** — BL-I9-1, BL-I9-3 … BL-I9-10 (BL-I9-2 closed at E3) carried into the batch backlog, each named in `04-validation.md` §Owed.
- **Uncommitted records** — this packet, `04-validation.md`, the E5 record edits (RR-1 residual wording, RR-4 Windows column, the orchestrator note in `E5-mutants.md`) and the `mut-r-14b.txt` transcript are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 9; run the full suite once at batch end and the Windows arms with node ids; forward the 10 new / 2 changed / 1 withdrawn canon ids to the requirements session; carry BL-I9-1 … BL-I9-10 into the backlog; open the next increment on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 / 4 — `flow_execution_service.py`, `flow_persistence_service.py`, `app.py`, `flow_screens.py` (docstring only); reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_flow_saves.py` (38), `tests/test_b101_flow_names_ui.py` (10) + 3 edited files |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the slice units traced node-for-node in `codewire/graph-inc9.md`; e5c-07 297 passed |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 20/9 failed, int-06 5 failed, e5c-02 / e5c-03 mutants RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES, 0 HIGH (re-review also PASS-WITH-NOTES) |
| 7 | No file from another lane touched | all | ✓ | single lane |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the 4 slice files are outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-04 / e5c-07) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 43 covered, 0 partial, 0 gap — `E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the link/swap/hard-link fixtures, the observables grep |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 31/32 killed, M14 equivalent, M14b/M22…M31 killed |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 1 correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — 4 emitted forms |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer, security-reviewer, qa-reviewer, architect, security-reviewer, testers ×2 |
| 16 | **Evidence files** declared | all | ✓ | §4 — 48 committed transcripts at the declared home |
