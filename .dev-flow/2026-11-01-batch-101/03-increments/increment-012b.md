# Increment 012b — Inc 12b · R-TUI-059.25, R-FX-SCR.4 · Every widget of the Flow Builder and Flow Execution shown in some state

Flow: dev-flow-v3-beta (operator ruling 2026-11-01), split from Inc 12 by ruling D-5 B. Records live in `.dev-flow/2026-11-01-batch-101/inc-12b/`: `01-requirements.md` (US-I12b-1, the two rows above), `02-test-cases.md` (4 cases), `E1-rulings.md`, `E1-slice.md`, `E3-rulings.md`, `E4-impl-notes.md`, `E4-integration-notes.md`, `E4-tester-g-t3-notes.md`, `E4-tester-g-t4-notes.md`, `E5-review.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `E5-mutants.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc12b.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-12b/`. The E1 pilot and census live under `../inc-12/evidence-e1/`. Branch `b101-inc12b` from `main` (base `2f54c7d`, Inc 9 in), head `9087b8ab` plus the uncommitted E5 records, this packet and `04-validation.md`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1–E3 (requirements, rulings, the D-5 B split and the E3 correction), the E4 integration step, the E5 code + security review, the coverage audit (as the `qa-reviewer`), the E5 corrective pass, and the Windows arms (as the orchestrator); **DeepSeek v4 Pro** — the E4 implementer (group G4, `s19_app/tui/flow_screens.py`), the E5 mutant battery (M1…M7), and this record; **Sonnet** — the E4 testers ×2 (G-T3 the 39 re-pointed nodes in 13 files; G-T4 the new `tests/test_b101_flow_shown_widgets.py`, 4 nodes) and the E5 R-1 tester.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `012b` |
| Lane (if the batch forked) | none — single lane (split from Inc 12 by D-5 B; merges after Inc 9 and before Inc 12) |
| Requirement(s) | R-TUI-059.25, R-FX-SCR.4 (story US-I12b-1; the cited R-FB-ADD.1, .2, .3, R-FB-RIB.2, .3, R-FB-PIPE.1, R-TUI-059.21, R-FX-SCR.2 unchanged) |
| Acceptance | the 4 cases of `02-test-cases.md` (R-TUI-059.25/1, R-FX-SCR.4/1, R-FB-ADD.1/2, AT-I12b-1); black-box through the shipped controls (the 7 kind chips, Add, Variables, Run, Save Set, the ribbon) · unit: the changed units of `E1-slice.md` §1 (codewire graph nodes) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

The Flow Builder and Flow Execution windows no longer mount the hidden widgets: `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind` and `#flow_ext_session` (Flow Builder) and `#fx_help` (Flow Execution) are removed with their painters — the batch-94 framed canvas, its grid helpers, and the numbered ledger strip — so no hidden copy of the screen is repainted on every chain change, and no test proves a behaviour on a widget the operator never sees. The block kind moves from the hidden `#flow_kind` select to `FlowBuilderPanel._kind`, set only by the kind chips and written only with a value of `_KIND_OPTIONS` (the S-1 guard replaces the select's refused-value check: a press from a `flow_palette_` button whose suffix names no kind returns with nothing changed). Every test that read the hidden list, canvas, session line or kind select now reads the visible pipeline (`#flow_pipeline`), the ribbon (`#flow_name_strip`), the kind tag (`.flow-kind-tag`) and the chip's `chip-selected` mark; the hostile-input security nodes keep their inputs whole and their painted-text assertions on the cards. `flow_screens.py` changes no module docstring beyond its "fb_a doctrine" paragraph (Inc 9 owns the adjacent import sentences).

## 2 · Files modified

Committed: `git diff --stat 2f54c7d HEAD -- s19_app tests docs README.md` (17 files, +816 / −708). Uncommitted: the E5 record edits and this packet with `04-validation.md`. **SOURCE files: 1 / 1.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/flow_screens.py` | source | US-I12b-1 | 9 changed functions, 3 changed docstrings outside functions; removed: the painter family (19 names — 4 `FlowBuilderPanel` methods, 8 module functions or classes, 7 constants) and the `LABEL` import; `FlowBuilderPanel.__init__` gains `self._kind: str = BLOCK_SOURCE`; the kind chip branch stores `self._kind` only when the suffix is a value of `_KIND_OPTIONS` (S-1); `+ Add` and the first sync read `self._kind`; `set_session_dir` refreshes the ribbon only; the docstrings describe the shipped surface |
| `tests/test_b101_flow_shown_widgets.py` | test | US-I12b-1 | new file, 4 nodes (G-T4): the two state walks (whole window, widget identity, QA-1/QA-7), R-FB-ADD.1/2, AT-I12b-1 (keys only, ribbon ends with the folder name, QA-6) |
| `tests/test_b97_flow_builder.py` | test | US-I12b-1 | 13 nodes re-pointed to the pipeline, ribbon and chip mark (G-T3) |
| `tests/test_tui_flow_builder_b94.py` | test | US-I12b-1 | 5 nodes re-pointed; AT-B94-18 anchored on the A2B `in · B` row (R-2); AT-B94-15 / TC-B94-20 bound the painted lines by the width read before the first card (R-1 ruling) |
| `tests/test_flow_builder_render.py` | test | US-I12b-1 | 3 nodes; AT-088b anchored on the CHECK card's `in · doc` row (I-D5) and the span clause pins the value style (R-3) |
| `tests/test_tui_flow_persistence_ui.py` | test | US-I12b-1 | 3 nodes; AT-006 report asserts `"≡ REPORT"` (R-4) |
| `tests/test_b101_flow_names_ui.py` | test | US-I12b-1 | Inc 9's `_add_load_block` helper waits on the LOAD chip mark (E3A-05) |
| `tests/test_b97_chips_help.py` | test | US-I12b-1 | 2 nodes re-pointed |
| `tests/test_flow_crc_ribbon.py` | test | US-I12b-1 | 2 nodes re-pointed |
| `tests/test_flow_crc_ui.py` | test | US-I12b-1 | 2 nodes re-pointed |
| `tests/test_tui_directionb.py` | test | US-I12b-1 | the 2 flow nodes re-pointed (the markup node gains the row anchor and style clause) |
| `tests/test_b100_project_homes.py` | test | US-I12b-1 | TC-B100-31 reads the ribbon tail |
| `tests/test_b102_flow_file_chooser.py` | test | US-I12b-1 | TC-B102-FILE-02 presses the A2B chip |
| `tests/test_flow_external_step_b96.py` | test | US-I12b-1 | TC-1804 re-pointed; module docstring reworded (R-5/QA-4) |
| `tests/test_flow_funnel_b96.py` | test | US-I12b-1 | TC-1817 presses the LOAD chip |
| `tests/test_id_registry.py` | test | US-I12b-1 | `EXPECTED_SCANNED_TEST_FILES` 269 → 270 (measured, I-D3) |
| `docs/requirements/review/CODE-CHANGES.md` | doc | US-I12b-1 | D16-6 marked `done (batch-101 Inc 12b)` (I-D10) |
| `.dev-flow/2026-11-01-batch-101/inc-12b/*.md` | doc | | the E1–E5 records, the codewire graph, `04-validation.md` and `steps.log` (uncommitted records listed here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-12b/*.txt` | generated | US-I12b-1 | 35 transcripts (int-00 … int-08, int-07b, int-base-01, e5c-01 … e5c-07, mut-00 … mut-11, base-01 ×2, red-01 ×1, win-01, win-02) |

| Count | Value |
|---|---|
| **SOURCE files** | **1 / 1** |
| Test files | 15 (1 new, 14 changed; uncapped) |
| Doc files | 1 (CODE-CHANGES.md) + the `.dev-flow` records (outside the count) |
| Generated | 35 transcripts under `evidence/inc-12b/` |

- ⚠ **At exactly 1 source file:** `flow_screens.py` owns the removal and the kind state; no other source file moves. The E5 corrective changed the same file's comments and docstrings only (an AST pass with docstrings masked gives the same tree for `092fffd` and the final file).

## 3 · How to test

```bash
# the new file and the 13 re-pointed files (LAN Linux hosts, Python 3.11)
python -m pytest -q -n 10 -m "not serial_timing" tests/test_b101_flow_shown_widgets.py \
  tests/test_b97_flow_builder.py tests/test_tui_flow_builder_b94.py tests/test_flow_builder_render.py \
  tests/test_tui_flow_persistence_ui.py tests/test_b101_flow_names_ui.py tests/test_b97_chips_help.py \
  tests/test_flow_crc_ribbon.py tests/test_flow_crc_ui.py tests/test_tui_directionb.py \
  tests/test_b100_project_homes.py tests/test_b102_flow_file_chooser.py \
  tests/test_flow_external_step_b96.py tests/test_flow_funnel_b96.py
# the law guards
python -m pytest -q -n 10 -m "not serial_timing" tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py \
  tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py
# the serial-timing lane over the touched files
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_flow_shown_widgets.py \
  tests/test_tui_flow_builder_b94.py
# the Windows-only arms, once each, isolated app-state folders, no clipboard (Windows PC)
#   LOCALAPPDATA / APPDATA / TEMP / TMP = a fresh scratch folder; one process: import s19_app + pytest.main
```

All of these ran on the LAN Linux hosts only (operator rule); the Windows PC ran only the Windows-only arms (`win-01` on `092fffd`, `win-02` on the final tree after the corrective). The transcripts are `evidence/inc-12b/int-00.txt` … `int-08.txt`, `int-07b.txt`, `int-base-01.txt`, `e5c-01.txt` … `e5c-07.txt`, `mut-00.txt` … `mut-11.txt`, `base-01-g-t3.txt`, `base-01-g-t3-mutants.txt`, `red-01-g-t4-base.txt`, `win-01.txt`, `win-02.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_flow_shown_widgets.py` (4) + the 13 re-pointed files (39 nodes, 54 items) + the registry | **709 passed, 29 skipped, 0 failed** (e5c-04, final tree); 4 cases, 4 covered / 0 partial / 0 gap |
| **A · neighbours** | the QC-BC set (13 files) + the other importers + the law guards | **511 passed, 4 skipped** (int-02) · **182 passed, 10 skipped, 2 failed** (int-03, the 2 known `tc016s` patch-comfortable snapshots, fail the same on base) · **218 passed** (int-04); serial lane **3 passed, 1 skipped** (e5c-05) |
| **B · black-box** (keys and chips) | the two state walks, the S-1 stray press, AT-I12b-1 through the keys (the `8` rail key, `tab`, `space`, typed ref, `enter`) | passed in int-01 / int-08 / e5c-04; Windows arms in win-01 / win-02 |

Details: `inc-12b/04-validation.md`.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base `2f54c7d` (before the fix) and the mutants M1…M7 / C1…C6, C4a in copies of the tree |
| Instrument | project code: the testers' own nodes; the corrective's staged-tree copy; restore checked by the transcript's tree fingerprint |
| Where it ran | the LAN Linux hosts (testers, integration, corrective, mutants); the trees are the commits (recomputed with git plumbing) |
| Transcript | `red-01-g-t4-base.txt` (3 failed / 1 passed), `base-01-g-t3-mutants.txt` (10 RED + 4 RED), `int-07b.txt` (M1, M2, M3), `e5c-03.txt` (C1 … C6, C4a), `e5c-07.txt` (the R-1 bound RED ×2), `mut-01.txt` … `mut-11.txt` |
| Restore proven by | each mutant copy restored byte-exact and deleted; the worktree list clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 4 new nodes + 39 re-pointed nodes (54 items), every node named in the transcripts' PASSED / FAILED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | AT-I12b-1 on base (a declared standing guard, `red-01-g-t4-base.txt`); the 39 re-pointed nodes on base by design (their visible oracles exist there, `base-01-g-t3.txt`) |

| Field | Value |
|---|---|
| **RED counterfactual** | The two walks were RED on base for the row's own negative control (the five hidden Flow Builder ids and `fx_help`); R-FB-ADD.1/2 RED on base by `InvalidSelectValueError`; the mutants M1…M7 each turned their guard nodes RED (11/11 runs), and the corrective controls C1…C6, C4a each turned their strengthened clause RED and left the `092fffd` form GREEN (C4a RED both). |

| Field | Value |
|---|---|
| **Mutation verdicts** | 7 rows on the final tree, all killed (11/11 runs). M1 (S-1 guard removed) RED at the tag; M2 (card refs through `Text.from_markup`) and M3 (a span over half the value row) RED ×4 on the markup nodes; M4 (`nul_add_refusal` → `None`) RED ×10; M5a … M5e and M6 RED by id on their walk; M7 (`flow_add` reads `BLOCK_SOURCE`) RED ×5 on the Add nodes of non-SOURCE kinds. Score 7/7 = 100 %. Transcripts `evidence/inc-12b/mut-00.txt` … `mut-11.txt`, `e5c-03.txt`, `e5c-07.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test file on base (3 failed, `red-01-g-t4-base.txt`); the 39 re-pointed nodes' oracle controls (10 RED + 4 RED, `base-01-g-t3-mutants.txt`); the mutant harness (the guard nodes GREEN first, `mut-00.txt` 20 passed, then each mutant RED); the coverage audit (first pass found QA-1 … QA-9 and the corrective closed them) — `E5-coverage-audit.md`. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | The two walks' populations are exact (53 / 38 widgets with an id, 0 never shown, `e5c-02`); the kind is read by its painted effect only (the tag `✓ CHECK` / `◉ LOAD` and the `chip-selected` mark, never `_kind`); the ribbon after `session` ends with the project folder's name (`…/workarea/proj1`, `e5c-02`); the report card paints `≡ REPORT` (not the `· REPORT` fallback); and the hostile refs paint literally on the cards' `in · doc` / `in · B` value rows with the covering span equal to the card's value style (R-3). All passed in `e5c-02` / `e5c-04`. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-06. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-12b/`; there is no `inc-12b/evidence-e1/` (the E1 pilot and census are Inc 12's, under `inc-12/evidence-e1/`). Each transcript prints the base commit, the staged tree, `s19_app.__file__` and (the corrective and the mutants) the exact command line or the mutation diff; home paths and account names are redacted.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| base-01-g-t3-mutants.txt | evidence/inc-12b/base-01-g-t3-mutants.txt | 8547b3bc51e9ea11275509504b9d44148531566e85b56ac0e00e55503922cccb |
| base-01-g-t3.txt | evidence/inc-12b/base-01-g-t3.txt | ec280cb0ce28c91a68b1b409ccd5c219db0e3e276ceefedd9e25a82afbc0df8e |
| e5c-01.txt | evidence/inc-12b/e5c-01.txt | d2e93abaeb3c69ba3ea751021181e419604cea1d68173fa081360bfeaed16a8e |
| e5c-02.txt | evidence/inc-12b/e5c-02.txt | 82743a11fe55f87105a1eb68c898f513f10fb4b9a0dcbed7e80c4a09cee53bcb |
| e5c-03.txt | evidence/inc-12b/e5c-03.txt | 62ede8842264a2dbd957e1410110ffd002275d0b548e810ae03495aa6432aa67 |
| e5c-04.txt | evidence/inc-12b/e5c-04.txt | 273edf61ed41eb9823428590e49f9e36e430802ea21d80d39b7d14d3c7b99341 |
| e5c-05.txt | evidence/inc-12b/e5c-05.txt | 715b964a5e836945c6af6d7a9f6eb01d8d9f2430b6586eb373ec266b147d0778 |
| e5c-06.txt | evidence/inc-12b/e5c-06.txt | e4dff63e85e6ba22dd7201d60279c17c4c4aa25219c5f8c4ba1808db4c0c67d9 |
| e5c-07.txt | evidence/inc-12b/e5c-07.txt | a17707ffb56580449dded2bc74a4af104136b580bc5b99c7a5c35e440e22e9ce |
| int-00.txt | evidence/inc-12b/int-00.txt | 1a3c8e5582f6ead6b1b4c4655499265dfb82dc2f00bc9ee50965177ec03f175d |
| int-01.txt | evidence/inc-12b/int-01.txt | 89a2a9d746b4d20af7563f9b77a4fe2caf569beaf376cf0c297c40c1f720ddce |
| int-02.txt | evidence/inc-12b/int-02.txt | 7c015e3a1d079d49cbccb5aab832184a218b4fbcfd2535b5e0a4f6bf83a8d87a |
| int-03.txt | evidence/inc-12b/int-03.txt | 313e4f67fa0d781ac5656553ea8dfb5e2bc65af0784bf98750f6cb33e8062bfa |
| int-04.txt | evidence/inc-12b/int-04.txt | db04c9d3a18178be161c4b57fff7e40d85d2928e3cc5f973292a217a8c4dad17 |
| int-05.txt | evidence/inc-12b/int-05.txt | b7aa9f96eb5a88bc684a2c62caaaecfda12f4c59570d1c63716669af81cb3e67 |
| int-06.txt | evidence/inc-12b/int-06.txt | 9d6d3c366e47958d58418e2aaeb7fa273eb1689d92fd105b89eda23174447bc7 |
| int-07.txt | evidence/inc-12b/int-07.txt | 80b32bdeb841d7a3db180929924250ac0da107db39a473c3fa78cca13cd9c395 |
| int-07b.txt | evidence/inc-12b/int-07b.txt | 7cd8ac53d28474df674fa2f1be911b1b14fcdff611daffd6ae56f352a007288c |
| int-08.txt | evidence/inc-12b/int-08.txt | e4127a38f5ecc8053d6e6586826af4d2cb04441991c9ccef7f17717835e66652 |
| int-base-01.txt | evidence/inc-12b/int-base-01.txt | b4571a9990e4156d0fbc955dd89550235e8f46bcabfcc507186291d70dcd62b3 |
| mut-00.txt | evidence/inc-12b/mut-00.txt | 58f1dca66d43a7bbdd02b11f254e2de6b830986941025a35bba37f05221187a5 |
| mut-01.txt | evidence/inc-12b/mut-01.txt | 78dd67398a94dba2e835c99dc30c9e136ef7d75899325722913230ea11cbe384 |
| mut-02.txt | evidence/inc-12b/mut-02.txt | 01f1e5bf83b35d43ef85980dc3decf20e3b1209e2ce040b49b3bad279a990492 |
| mut-03.txt | evidence/inc-12b/mut-03.txt | f642e7bffed7fde334defffa8d503b43d94bea83477dbaee89eb20f70b4a039a |
| mut-04.txt | evidence/inc-12b/mut-04.txt | a77724443af99ae14a5334cca214d904812e5aaf89a315578569940f26180a4c |
| mut-05.txt | evidence/inc-12b/mut-05.txt | 85c4b53e28373ce61949a70cadb876061fa69ba7a9c36e7a98fdba0f50732efc |
| mut-06.txt | evidence/inc-12b/mut-06.txt | 26a466ef6b74707a638515f7188e7dd888796510b141d414992a2403c8fabce2 |
| mut-07.txt | evidence/inc-12b/mut-07.txt | 73fefd3391dd2cf62f102ff0655e7bf7dbcd9874b24547f2a1c0ff79afbcc91c |
| mut-08.txt | evidence/inc-12b/mut-08.txt | 1f25ee62ca8ff901f9ecbe30bba230440752ce32ec675cf9ee3a4c52b09a790c |
| mut-09.txt | evidence/inc-12b/mut-09.txt | 4b460c90aeda89f87709fc04d7e199d3946f00002211b96c5002ee9a9b207a4c |
| mut-10.txt | evidence/inc-12b/mut-10.txt | dc7316c1c01fa1f51a13a2508280ca781bd53360393e003644d52d408286b598 |
| mut-11.txt | evidence/inc-12b/mut-11.txt | 1d2401754f514fba5a8b9fab955884285110c6130a17062e6122952f9ce28dbf |
| red-01-g-t4-base.txt | evidence/inc-12b/red-01-g-t4-base.txt | b64a1985da3def13017fec6a6ffbb41a8176652ff2b1cd1394c58b22f8299132 |
| win-01.txt | evidence/inc-12b/win-01.txt | 8fbf1958fa0556fe03a8369fdeac2a7126863cdb483a1bce3826e8e1a045a3ab |
| win-02.txt | evidence/inc-12b/win-02.txt | 938fe27479239d93cb44ff0e9d848a84618ed35e174cbb71af22ebbcdd5bce1d |

| Field | Value |
|---|---|
| **Evidence files** | 35 committed transcripts at the declared home, each printing the base commit and the staged tree (the corrective and the mutants also the command line or the mutation diff). No `inc-12b/evidence-e1/` exists; the E1 pilot and census are Inc 12's records. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no source or test names a removed id or painter-family name" (the three pinned I-3 greps) and "no product source line changed at integration" (I-D1) |
| If the result is an ABSENCE, what made the search wide enough | the three pinned `git grep -n -w` commands over `s19_app tests` (and `flow_screens.py` / `tests` for `_layout`), empty ×3 on the final tree (`e5c-04`); a wider grep outside `s19_app` and `tests` finds nothing; a stdlib AST pass over `flow_screens.py` (base = head) finds no unused import and no unread removed name |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the three pinned I-3 commands (expected output empty; base controls 146 lines and 2 + 0); the walks R-TUI-059.25/1 and R-FX-SCR.4/1, RED on base for the restored-hidden ids |
| Conjunctive criteria: one mutation per conjunct | the kind's guard is one check before the write (M1); the markup scrub and the span clause isolate the two card-sink properties (M2, M3); the NUL refusal isolates the add-path kind (M4); each removed widget restore isolates one id (M5a … M5e, M6) |
| Synthetic instance of the absent case | M5a … M5e / M6 mount the removed widget with its id and hide it at mount; C1 hides the `OpenFolderChip`s; C2 composes a hidden `Static(id="label")` beside the shown `Select` `label` |
| **Positive control for every probe that returned an ABSENCE** | base RED (the five ids, `fx_help`, `red-01-g-t4-base.txt`); the mutants M1…M7 turned their guard nodes RED; C1 / C2 turned the strengthened walks RED (`e5c-03`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC observables grep (I-D12: `FlowBuilderPanel`, `flow_palette_`, `flow_pipeline`, `flow_name_strip`, `flow-kind-tag`, `KindChip`, `_refresh_blocks`, `FlowExecutionPanel`) + the 13-file QC-BC run + the other importers + the law guards | int-02 511 passed (4 skipped), int-03 182 passed (10 skipped, 2 known `tc016s`), int-04 218 passed |
| B2 file moved on disk | no file moved; `flow_screens.py` changed in place | 0 readers of a moved path; the import census holds (e5c-06, 2 passed) |
| B3 byte-identical golden captures this source | the 29 `.svg` snapshot baselines (a2l, diff, issues, mac, map, patch, workspace) hold no Flow Builder or Flow Execution window | no golden captures `flow_screens.py`'s Flow windows (I-D13) |
| B4 artifact produced here is consumed elsewhere | the kind state `FlowBuilderPanel._kind` and the visible oracles (`#flow_pipeline`, `#flow_name_strip`, `.flow-kind-tag`) | consumed by Add, the NUL refusal, the A2B / EXT-STEP branches, and the re-pointed tests |
| A3 interface consumed by another module changed | `FlowBuilderPanel._kind` replaces the removed `#flow_kind` select | no reader outside the panel (`app.py` has none); the 13 re-pointed files and the new file read only the painted effect |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it; B2 no moved file; B3 no golden hit; B4 the Add / NUL / A2B / EXT-STEP and re-pointed-test consumers; A3 the `_kind` state with no external reader. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records and tests that no longer matched the strengthened walks or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result / control no longer matches its node | the coverage audit's row-by-row read (`E5-coverage-audit.md` §3, QA-1 … QA-9), then the corrective's per-ruling edits (R-2 … R-5, QA-1, QA-6, QA-7, QA-8) | 4 cases re-cited with their executors and win-01; 2 rows' thresholds re-pinned to 53 / 38; R-1 re-ruled test-side | all, by the E5 corrective and the R-1 tester | none; the walks and the S-1 / markup / NUL / report oracles each shown RED by a control (C1 … C6, C4a, e5c-03; e5c-07) |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (QA-1 … QA-9) and the review (R-1 … R-5) before the corrective edited its first site: the strengthened walks (whole window, identity keying, the folder-name ribbon), the row-anchored and style-pinned security clauses, the `≡ REPORT` oracle, and the record re-citations. R-1 stopped (E-1) then re-ruled test-side. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `270 = 269 − 0 + 1` (`tests/test_id_registry.py`, measured; one new module). Cases `4 = 4` (no case added or removed at E5; marks changed 0). No test node deleted, no function renamed, no assertion weakened — the ruled drops (hidden-is-hidden, canvas glyphs) are carried by the walks, which were RED on base (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §3).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` (code + security, one agent, E5) · **PASS-WITH-NOTES** (0 HIGH; R-1 MEDIUM the re-pointed width bound could no longer fail, R-2 … R-5 LOW) — `inc-12b/E5-review.md`. R-1 closed at the corrective (test side; the product defect is BL-I12b-1). `security-reviewer`'s lens in the same review: the S-1 guard sits before any write, hostile refs reach the cards only as plain text, and the re-pointed security nodes keep their hostile inputs whole. `qa-reviewer` · coverage audit (4 `full`, 0 `partial`, 0 `gap`, marks changed 0, QA-1 … QA-9) — `inc-12b/E5-coverage-audit.md`. **Design reviews (E3, code-free, Inc 12's, split at E3):** `architect` **FAIL** (1 MAJOR E3A-01, 7 MINOR) → round 2 **PASS-WITH-NOTES** for 12b · `security-reviewer` **PASS-WITH-NOTES** (3 MINOR) → round 2 **PASS-WITH-NOTES** (S-1, S-2 closed; S2-1, S2-2 LOW) — `../inc-12/E3-architect.md`, `../inc-12/E3-security.md`, `../inc-12/E3-rulings.md`, `inc-12b/E3-rulings.md`. The independent `testers` (E4, Sonnet ×2) re-pointed the 39 nodes and wrote the 4 new nodes from the design records only, and ran them RED on base — `inc-12b/E4-tester-g-t3-notes.md`, `inc-12b/E4-tester-g-t4-notes.md`. |

## 5 · Risks

- **The 120×30 rail still scrolls sideways by 2 cells (BL-I12b-1):** pre-existing and identical on base `2f54c7d` — from the first card on, `#flow_panel`'s vertical scrollbar narrows the rail to 90 while the chain stays laid out for 92, because `FlowBuilderPanel._apply_layout` does not re-run. AT-B94-15 / TC-B94-20 now bound by the width read before the first card (the R-1 ruling) and leave the product defect out of scope.
- **A widget restored displayed is unguarded:** the walks are RED only for a removed widget restored hidden; the I-3 grep is a one-off integration check. A second chain view beside the pipeline, or a session line beside the ribbon, would pass every standing node (QA-4, accepted residual). The removal is by design and no defect is in view.
- **The hostile refs' card-sink kill geometry:** AT-B94-18 is now anchored on the A2B `in · B` row, so its M2 kill no longer rests on the origin note's clip (R-2 applied); AT-B97-08 keeps its base form and its `clip_tail` clause is effectively anchored to the value row. A larger box or a shorter note prefix cannot resurrect the old GREEN-under-M2 path.

## 6 · Pending

- **Merge verification** — per the operator's order (2026-11-06), no full suite runs per increment: this increment ran its slice, the 13 re-pointed files, the QC-BC set, the other importers, the law guards and the serial lane on the merged tree; the full suite runs once at batch end, when the batch's increments are all on `main`.
- **Canon ids to forward to the requirements session** — the 2 new rows R-TUI-059.25 and R-FX-SCR.4 (moved from Inc 12 with their ids, thresholds re-pinned to the whole-window populations 53 / 38), the CTX-SHELL terms *shown widget* and *state of a window* (identical text in Inc 12), and CODE-CHANGES D16-6 (`done (batch-101 Inc 12b)`).
- **Inc 12 owns the DOSSIER marks and `_FIXED`** — Inc 12b marks no DOSSIER row and edits no user-guide passage (E3A-04 + U-1). Inc 12 owns F-33, F-34, F-35, F-51 and the pinned set `_FIXED`, and marks F-35 because it merges after 12b; if the merge order flips, the increment that merges second marks F-35.
- **Backlog** — BL-I12b-1 (E-1, R-1) carried into the batch backlog, named in `04-validation.md` §Owed.
- **Uncommitted records** — this packet, `04-validation.md` and the E5 record edits are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 12b (after Inc 9, before Inc 12); run the full suite once at batch end and the Windows arms with node ids; forward the 2 new canon ids and the CTX-SHELL terms to the requirements session; carry BL-I12b-1 into the backlog; let Inc 12 (merging last) mark DOSSIER F-35 and `_FIXED`; open the next increment on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 1 / 1 — `flow_screens.py` only; reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_flow_shown_widgets.py` (4) + the 39 re-pointed nodes in 13 files |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the slice units traced node-for-node in `codewire/graph-inc12b.md`; e5c-04 709 passed |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 3/1, base oracle controls 10+4 RED, M1…M7 11/11 killed, C1…C6/C4a RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES, 0 HIGH (R-1 closed test-side) |
| 7 | No file from another lane touched | all | ✓ | single lane |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the slice file is outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-04 / e5c-04) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 4 covered, 0 partial, 0 gap — `E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the three pinned I-3 greps, the AST pass, the M5/M6 and C1/C2 synthetic restores |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 7/7 killed (11/11 runs), 0 survivors |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 1 correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — the populations, kind tag / chip mark, ribbon tail, `≡ REPORT`, literal hostile refs |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer (+security lens), qa-reviewer, architect, security-reviewer, testers ×2 |
| 16 | **Evidence files** declared | all | ✓ | §4 — 35 committed transcripts at the declared home |
