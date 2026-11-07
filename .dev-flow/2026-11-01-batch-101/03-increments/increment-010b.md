# Increment 010b — Inc 10b · R-A2L-048, .049, .105, .106 · R-TUI-004.7, .8, .9 · R-SEG-PREV.21, .22 · R-SEG-EXP.15 · Views that follow in-place writes

Flow: dev-flow-v3-beta (operator ruling 2026-11-01), split from Inc 10 at E3. Records live in `.dev-flow/2026-11-01-batch-101/inc-10b/`: `01-requirements.md` (US-FRESH-3, the rows above), `02-test-cases.md` (21 cases + QC-TM-10b-1), `E1-rulings.md`, `E1-slice.md`, `E4-impl-notes-app.md`, `E4-impl-notes-split.md`, `E4-tester-w-notes.md`, `E4-integration-notes.md`, `E5-review.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-mutants.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc10b.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-10b/`. The E1 confirmation runs and the E3 rulings that 10b inherits live under `../inc-10/` (Inc 10a's merged history). Branch `b101-inc10` from `main` (base `569e446` = Inc 10a in; the E5 corrective worked from origin/main `6f1743c`), head `68e9a084` plus the uncommitted E5 close records, this packet and `04-validation.md`.

Models per stage (from `steps.log` and the orchestrator's assignment): **Opus** — E1 (the requirement split from Inc 10), the E4 integration step, the E5 code+security review (the FAIL verdict), the E5 coverage audit (as the `qa-reviewer`), and the E5 corrective pass; **DeepSeek v4 Pro** — the E3 correction round 2, the E4 implementers (2 units, G1 `app.py`, G2 `segment_split_view.py`), and the E5 mutant battery (M1 … M8 plus the reused E4 controls); **Sonnet** — the E4 tester (W) and the E5 re-review of the corrective with its RR-1 … RR-5 fixes.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `010b` |
| Lane (if the batch forked) | none — single lane, served serially after Inc 10a |
| Requirement(s) | R-A2L-048, .049, .105, .106 · R-TUI-004.7, .8, .9 · R-SEG-PREV.21, .22 · R-SEG-EXP.15 (story US-FRESH-3) |
| Acceptance | the 21 cases of `02-test-cases.md`; black-box through the shipped controls (the Patch Editor apply, the save-back *Write file*, the Save project dialog, the A2L tag table, the three hex panes, the Split / Join window) · unit: the changed units of `E1-slice.md` §1 (codewire graph nodes) · plus the QC-TM-10b-1 measurement on case_06 |
| Agent | `software-dev` |
| Date | 2026-11-07 |

---

## 1 · What changed

The in-place write hook `S19TuiApp._note_image_bytes_written` (Inc 6's body) now switches its Check Editor block from `except Exception: return` to the `checks = None` idiom (A10-08), runs the Split / Join notice first (E-2), and appends the three notices — `_refresh_hex_views_after_write()`, `_refresh_a2l_values_after_write()`, then the Split / Join window's `note_image_bytes_written()` — each outside its own `try`, with no `refresh_window` and no focus call. `_refresh_hex_views_after_write` re-renders the three panes from their kept window: the main view with no focus (10a's clamp keeps `_hex_window_start`, the scroll and the `> ` marker), the A2L and MAC views at the index of their first shown row (I-3). `_refresh_a2l_values_after_write` recomputes only the tags whose raw bytes differ from the image now — the tags whose range intersects the bytes the write changed — instead of a full enrichment (R-1, 3.952 s → 0.350 s on case_06's 220,040 tags); it re-points `_a2l_filtered_tags` to the recomputed tags (total on an `id()` miss, re-filtering and returning — R-2), keeps the summary lines (S-8), and returns early with no image. `_repaint_a2l_tag_cells` repaints the shown page in place (`update_cell_at(..., update_width=True)`, I-7 / R2-7): no `clear()`, no cursor or scroll call, the row keys re-pointed. `SplitJoinWindow.note_image_bytes_written` calls `_bump()` (disarm + one `_sync`) while displayed and sets `_armed = False` only while hidden (S-7 / A10-09).

## 2 · Files modified

Committed: `git diff --stat 569e446 HEAD -- s19_app tests docs README.md` (4 files, +1 918 / −12). Uncommitted: the E5 close records, this packet and `04-validation.md`. **SOURCE files: 2 / 4.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | US-FRESH-3 · R-A2L-048, .049, .105, .106 · R-TUI-004.7, .8, .9 | `_note_image_bytes_written`: the Check Editor `checks = None` idiom (A10-08), the Split / Join notice first (E-2), the three notices appended; `_refresh_hex_views_after_write` (new); `_refresh_a2l_values_after_write` (new, the R-1 partial recompute, the R-2 total re-point, the no-image early return, the pane guards moved after the recompute per RR-3); `_repaint_a2l_tag_cells` (new, I-7 / R2-7); the hook docstring matches the code (R-6) |
| `s19_app/tui/segment_split_view.py` | source | US-FRESH-3 · R-SEG-PREV.21, .22 · R-SEG-EXP.15 | `SplitJoinWindow.note_image_bytes_written` (new): displayed → `self._bump()`; hidden → `self._armed = False`; no focus, no selection reset, no `refresh_window` (I-1) |
| `tests/test_b101_inplace_views.py` | test | US-FRESH-3 | new file, 21 non-serial nodes + the QC-TM-10b-1 `serial_timing` node: the value/table/hex/preview/disarm cases, the repaint sign, the R-A2L-048/4 widening and /5 second-page cases, the RR-1 filter and RR-4 row-key asserts |
| `tests/test_id_registry.py` | test | US-FRESH-3 | `EXPECTED_SCANNED_TEST_FILES` 272 → 273 (the new module, measured, I-D2), history comment names Inc 10b |
| `.dev-flow/2026-11-01-batch-101/inc-10b/*.md` | record | — | the E1–E5 records, the codewire graph, `04-validation.md` and `steps.log` (uncommitted close records listed here) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-10b/*.txt` | generated | US-FRESH-3 | 53 transcripts (int-01 … int-07 with int-01a / int-01b, e5c-01 … e5c-14, e5c-rr-01 … e5c-rr-07, mut-01 … mut-08, mut-c-01 … mut-c-12, red-01-tester-w-base) |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |
| Test files | 2 (1 new, 1 changed; uncapped) |
| Doc files | 0 product docs + the `.dev-flow` records (outside the count) |
| Generated | 53 committed transcripts under `evidence/inc-10b/` |

- ⚠ **At 2 source files, under the cap:** `app.py` owns the hook and the two repaint methods; `segment_split_view.py` owns the window notice. The E5 corrective changed the same `app.py` functions only (the R-1 partial recompute), keeping the slice at 2 source files.

## 3 · How to test

```bash
# the new file and the edited nodes (LAN Linux hosts/laptop, Python 3.11)
python -m pytest -q -n 6 -m "not serial_timing" tests/test_b101_inplace_views.py
# the law guards
python -m pytest -q -n 6 -m "not serial_timing" tests/test_address_census.py tests/test_suite_hygiene.py \
  tests/test_id_registry.py tests/test_engine_unchanged.py tests/test_docs_canon.py tests/test_b101_doc_hygiene.py \
  tests/test_b101_help_legend_docs.py
# the serial-timing lane over the touched files (the QC-TM-10b-1 figure)
python -m pytest -q -m serial_timing -p no:xdist tests/test_b101_inplace_views.py
# the QC-BC set and the other importers, one run each (the batch's known-failure list applies)
# Windows: nothing owed — no case of this increment has a Windows-only arm (operator rule)
```

All of these ran on the LAN Linux hosts/laptop only (operator rule); the Windows PC ran nothing that imports `s19_app`. The transcripts are `evidence/inc-10b/int-01.txt` … `int-07.txt`, `e5c-01.txt` … `e5c-14.txt`, `e5c-rr-01.txt` … `e5c-rr-07.txt`.

## 4 · Test results

| Layer | Nodes | Result |
|---|---|---|
| **0 / A · unit and white-box** (`R-*` ↔ case) | `tests/test_b101_inplace_views.py` (21 non-serial nodes + QC-TM-10b-1) + the edited `test_id_registry.py` | **21 passed ×3** (e5c-06/07/08, final tree `43e7fcaf…`; re-run 21 passed ×3 on the re-review tree `3e432888…`, e5c-rr-03/04/05); 21 cases, 21 covered / 0 partial / 0 gap |
| **A · neighbours** | the QC-BC set (54 files) + the 3 other importers + the law guards | **1903 passed, 115 skipped, 2 xfailed, 2 failed on the known list** (int-02) · **31 passed** (int-03) · **218 passed** (int-04, e5c-12, e5c-rr-06); serial lane **24 passed** (int-05) / **2 passed** (e5c-13) |
| **B · black-box** (keys and dialogs) | the apply, the save-back *Write file*, the Save project dialog, the A2L table, the three hex panes, the Split / Join window (the 21 cases) | passed in int-01 / int-01b / int-07 / e5c-06/07/08; no Windows arm |

Details: `inc-10b/04-validation.md`. QC-TM-10b-1 on case_06 (220,040 tags): 3.952 s full refresh (e5c-02) → 0.350 s / 1.000 s, 65.0 % (e5c-13) → 0.360 s / 1.000 s, 64.0 % (e5c-rr-07), equal to a full recompute.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the shipped nodes run on base `09b4808` + Inc 10a (before the fix), the repaint-sign controls (M-A, M-B, M-C1–C3, M-D, M-F) and the E5 mutants (M1–M8, M-c02–M-c12) |
| Instrument | project code: the tester's own nodes; the integrator's and corrective's staged-tree copies; restore checked by the transcript's tree fingerprint |
| Where it ran | the LAN Linux host (tester RED) and laptop (integration, corrective, mutants); the trees are the commits (recomputed with git plumbing) |
| Transcript | `red-01-tester-w-base.txt` (18 failed / 1 passed, plus the QC-TM 1 failed), `int-06.txt` / `int-06a.txt` / `int-06b.txt` (each repaint-sign control RED), `mut-01.txt` … `mut-08.txt`, `mut-c-01.txt` … `mut-c-12.txt` |
| Restore proven by | each mutant copy restored byte-exact and deleted; `git worktree list` clean after |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 21 new nodes (the 19 E4 cases + R-A2L-048/4, /5), every node named in the transcripts' PASSED / FAILED lines or in the case map |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the declared standing guard R-SEG-PREV.21/2 (passes on base by design) — named in `E4-tester-w-notes.md` |

| Field | Value |
|---|---|
| **RED counterfactual** | The 19 delivered nodes were RED on base for behavioural reasons (tester: 18 failed / 1 standing guard); 10 RED at their own clause (value, pane byte, band, arm) and 8 RED at the repaint sign only, whose clauses are first observable on the fixed tree and shown RED under their own controls in int-06 (I-D6). The corrective mutants M-c02 … M-c12 each turned their target nodes RED. |

| Field | Value |
|---|---|
| **Mutation verdicts** | DeepSeek M1 … M8 plus the reused M-A, M-B, M-C1–C3, M-D, M-F: **15/15 killed** on the pre-corrective tree (100 %). Corrective M-c02 … M-c12: **11/11 killed** on the final tree. A10-08 declared an equivalent mutant on every shipped route (QA-3). No survivor. Transcripts `evidence/inc-10b/mut-01.txt` … `mut-08.txt`, `mut-c-01.txt` … `mut-c-12.txt`. |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the new test file on base (18 + 1 failed, `red-01-*`); the repaint-sign mutants (int-06, int-06a/b); the QC-TM node (e5c-02 the full refresh 3.952 s RED before the partial recompute); the coverage audit (first pass found the QA-1 owed 3/3 runs and the QA-2 width gap) — `E5-coverage-audit.md` §1. |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 emitted forms asserted exactly: the A2L Raw/Physical cells painted whole after a write, including the 22-character `-9.876539885039906e+25` (R-A2L-048/4) and the page-2 `17677` (R-A2L-048/5) — `test_r_a2l_048_4_…`, `test_r_a2l_048_5_…`; the hex pane row `FF FF FF AA FF FF FF FF` in `#hex_view`, `#alt_hex_view`, `#mac_hex_view` (R-TUI-004.7) — `test_r_tui_004_7_…`; the band `data 8 · fill 13 · conflict 2 · fill 9 · data 8` and the state `⚠ 2 B would clobber source — abort on export` (R-SEG-PREV.21) — `test_r_seg_prev_21_1_…`; the disarm `— e will ask` then `— e again to confirm` with 0 `*_joined*` files (R-SEG-EXP.15) — `test_r_seg_exp_15_…`. All passed in e5c-06/07/08. |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-07. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/inc-10b/`. Each transcript prints the base commit, the staged tree, `s19_app.__file__` and (the corrective and mutants) the exact command line and the mutation diff; home paths and account names are redacted.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| e5c-01.txt | evidence/inc-10b/e5c-01.txt | b5f63cf1b163687ddbed1f6353caec60fa7664d5c99bcbaaed55e734fc6cdc02 |
| e5c-02.txt | evidence/inc-10b/e5c-02.txt | b5baa87f32285ec5e631f22774ea621860a2135a2ae73322dc1b4a8c513a5f71 |
| e5c-03.txt | evidence/inc-10b/e5c-03.txt | 7d98294b3c3567a10831d53f172f6e0eb33edf3a0d1fa9793e27ed8f04c5a5d1 |
| e5c-04.txt | evidence/inc-10b/e5c-04.txt | 5b14fdc28d6ef1eec7bb31be2cf81c71c4da49d8460b9ff8b09c8bdbe2eb38de |
| e5c-05.txt | evidence/inc-10b/e5c-05.txt | 8dfe5ad3dfecef73531e2ed6aca835bf7e75850a557e8f6e7ebbe771066575c1 |
| e5c-06.txt | evidence/inc-10b/e5c-06.txt | 66e128ae489ce2335062092cda1b5db3afea4d30698700b377f6cc03eaab455e |
| e5c-07.txt | evidence/inc-10b/e5c-07.txt | a1d5a68871320865d5aa028f47764c2b96ec469845f895d3347c5c3173e5479a |
| e5c-08.txt | evidence/inc-10b/e5c-08.txt | 61c5b8a5e201e5c3d74c8a61412df6fc37b969e1ae7c311c56cb62f56668ee3a |
| e5c-09.txt | evidence/inc-10b/e5c-09.txt | c1bbd5b1ca629884954079bc5fe6a1cc876a0174dfaf4c299bd54b359a863d29 |
| e5c-10.txt | evidence/inc-10b/e5c-10.txt | c66e06948861816beedc7cd1fb775268be8a13266c143eef07c859c9eb8f2b45 |
| e5c-11.txt | evidence/inc-10b/e5c-11.txt | 200b5a005eb93c5ebb638d6c1c34dc9fff482873659a6ed64a9a1db994711eae |
| e5c-12.txt | evidence/inc-10b/e5c-12.txt | 2c50c1687123a46750f0c7e9e64f6de1c45d28257213308b806876074d91525b |
| e5c-13.txt | evidence/inc-10b/e5c-13.txt | 3dbf920cef17f4b91e08df98c6027b9c791668893154308d3556e8fd014665a9 |
| e5c-14.txt | evidence/inc-10b/e5c-14.txt | 89d6e663c0c2ebd07d96538f37f5583f274a01a485f3b675a2c01f61620f316f |
| e5c-rr-01.txt | evidence/inc-10b/e5c-rr-01.txt | 8782f4e85311388b5181a484a222162d82beaecf4c8f48054156ba070cff0b0b |
| e5c-rr-02.txt | evidence/inc-10b/e5c-rr-02.txt | acc5deba2fa0032b22f0eae5566ad388be6b58c5529f9324b23b71d078838d8c |
| e5c-rr-03.txt | evidence/inc-10b/e5c-rr-03.txt | 3993ff30fffe92c7dd530627e764eb72a53d2af8dbacff3a97a5155ebfaca48c |
| e5c-rr-04.txt | evidence/inc-10b/e5c-rr-04.txt | 1a451de9432bfe85d15c4b468ca4d92745ba214377e49841079c0cceb27e52d7 |
| e5c-rr-05.txt | evidence/inc-10b/e5c-rr-05.txt | 254d0e643bc2252f01b37f5646b8aec42cd5f94d914712515dadf7167ed4ae4d |
| e5c-rr-06.txt | evidence/inc-10b/e5c-rr-06.txt | d3d70147e89273d9c74d1928067cb358dfb92956b22f601eb1bff598be2e2908 |
| e5c-rr-07.txt | evidence/inc-10b/e5c-rr-07.txt | 3b5460f5f729e4226ca6b40c486e3e2cf5e14224b2af33653d0fec044ab02067 |
| int-01.txt | evidence/inc-10b/int-01.txt | fcd12c62943080899881bf6f87bd83a29bd1027dcb349ca2d1ca3ef8bd274054 |
| int-01a-registry-measure.txt | evidence/inc-10b/int-01a-registry-measure.txt | 0fd628620a19412b60341efd81be82db1f272a1cdcdfb840c6fd21837744b011 |
| int-01b.txt | evidence/inc-10b/int-01b.txt | 900193b635abd3c58854c7bfabd15ea81708de2ee560f57a9935a96c59966807 |
| int-02.txt | evidence/inc-10b/int-02.txt | 6068c6d8b8eb4df47c4e18ca036414151304e42347666ebd22ce1ddfbc4c2a13 |
| int-03.txt | evidence/inc-10b/int-03.txt | 256e925e4b40ae1a8056b566485008462bff7aa19401a666e3dc8c29d28de586 |
| int-04.txt | evidence/inc-10b/int-04.txt | 7cfc5a7b22b9adad2bda4299394191ed1f79ca47c6a76a9ff1f9ce998d28f0f8 |
| int-05.txt | evidence/inc-10b/int-05.txt | 1faa261bcea4b96010e523cda37e6e60e6eb93df0460cb37c5ef05f61cd78571 |
| int-06.txt | evidence/inc-10b/int-06.txt | e2fbd877400789fc340d44b221f48ed69e117a021c37038d9bc834755a5ee729 |
| int-06a.txt | evidence/inc-10b/int-06a.txt | 226dc0a580c3bf3cccfb7a4a7ec65cf3f5dc2318276ff84b1187aff9a8e24e4b |
| int-06b.txt | evidence/inc-10b/int-06b.txt | ba918284c27244113fd905bee3bfadc1f2bac428932d2e3ba4226934dda48ac8 |
| int-07.txt | evidence/inc-10b/int-07.txt | 3db1ae4d52c7a60896a80dcd03ad8e70d47538c690ebd324ac1a87ea188a7155 |
| mut-01.txt | evidence/inc-10b/mut-01.txt | 3a7269cb65bf908bb3887f064e27fb95c7edd0c0d8f205e23881dbae05ce2dd9 |
| mut-02.txt | evidence/inc-10b/mut-02.txt | 76782d38272502e42dda849a8aaf9a103930b26e3ce26767ca9a45840f757901 |
| mut-03.txt | evidence/inc-10b/mut-03.txt | b6dfd34eccc4a0a7f55a2c7f4eaaaf36870a0536e8aef4ce4988542ebd61b55e |
| mut-04.txt | evidence/inc-10b/mut-04.txt | ba72efdd19bf6403b4b649b35bbaddc477bd6c57efead3cc9596ba0b3e40eaeb |
| mut-05.txt | evidence/inc-10b/mut-05.txt | a367665c4bb1f58a20e732ce621990ad586307ab0644624a4c44712db5b33d2a |
| mut-06.txt | evidence/inc-10b/mut-06.txt | 0b286c85fe3cd9836d5c80e92d7b61fa95600f1e633ad95619677ad8b95f60d7 |
| mut-07.txt | evidence/inc-10b/mut-07.txt | 6fef6384975c447a1ae5e7eadbfe2d0197a51809e39ae0db25080f5142bf89c7 |
| mut-08.txt | evidence/inc-10b/mut-08.txt | d54f67105ec5d62d40d9cf76fa35f0ede452ef3ffcfc64daec959200f654a6eb |
| mut-c-01.txt | evidence/inc-10b/mut-c-01.txt | 679430e593634a119f4508cbbcb3934a62d5142d925b1cfcf8be18a8ad32085f |
| mut-c-02.txt | evidence/inc-10b/mut-c-02.txt | 53bf7c2de9bf7ac05aac309ab8e76d68a1789428b7854eb2e33abd43ea1e9f23 |
| mut-c-03.txt | evidence/inc-10b/mut-c-03.txt | b997424342c1e234b34c74fffad9cc7331d7784000b86e5370818fe26d7d3d80 |
| mut-c-04.txt | evidence/inc-10b/mut-c-04.txt | ff4a189b386cb1e27036832c9a08ce08228458b96b0f119154a9d79b4d77f6f2 |
| mut-c-05.txt | evidence/inc-10b/mut-c-05.txt | dcdcb92bdcf05631a88e125b44f0ec441fc4e958b74dbacb9de092f519e2bedf |
| mut-c-06.txt | evidence/inc-10b/mut-c-06.txt | 389f50642104aa4f3b080f301b91d1376d73a3330107232b9420f9af838fead4 |
| mut-c-07.txt | evidence/inc-10b/mut-c-07.txt | 3aeec0f1b56b1085b8cf849c95113313d4cf8a732bcf1d71736d7755941e0104 |
| mut-c-08.txt | evidence/inc-10b/mut-c-08.txt | dc39d33f9f868116bb84c22e3c82b2ea6d6f2a2eee491cd28f1dfb6453b8f22c |
| mut-c-09.txt | evidence/inc-10b/mut-c-09.txt | 30c586fb31daa5bbb17b29e64e8e5e2a2dfe809b628dba101281d798eacc94f0 |
| mut-c-10.txt | evidence/inc-10b/mut-c-10.txt | a957a759bed438ecc40108daca8104a98fd5847d8697b1cf62287c6a5783ff27 |
| mut-c-11.txt | evidence/inc-10b/mut-c-11.txt | 683b0cb9d5012721a4c08805530b41b6b59b12b43a72a3b4d7f558e9cba11734 |
| mut-c-12.txt | evidence/inc-10b/mut-c-12.txt | 2cee7f0ea444bb4614103519045331036d798546ca8f8322805860162ddd71bc |
| red-01-tester-w-base.txt | evidence/inc-10b/red-01-tester-w-base.txt | ae853eac1b494d883297943ad1a15e45f233302edbd181122fd2d7aea8bb9fab |

| Field | Value |
|---|---|
| **Evidence files** | 53 committed transcripts at the declared home, each printing the base commit and the staged tree; the corrective and mutant transcripts also print the exact command line and the mutation diff. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: "no stale byte shown after a write" (the security lens) and "no product code changed at integration" (I-D1) |
| If the result is an ABSENCE, what made the search wide enough | `git diff 569e446 HEAD -- s19_app` shows only the 2 slice files; the observables grep over `tests/` (I-D9) enumerated 72 files, cut to the 54-file QC-BC set; the engine-frozen guards (`test_engine_unchanged`, `test_tui_directionb`) confirm no frozen parser/engine module moved |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the QC-TM-10b-1 equality of the enriched list to a full recompute (no recomputed row differs); the 0-files export scan of R-SEG-EXP.15; the I-D1 no-product-change census |
| Conjunctive criteria: one mutation per conjunct | the partial-recompute cache test and the changed-byte test each isolate one conjunct (M-c03 first-byte-only, M-c05 list-not-installed, M-c06 `tags[i]`, M-c07 `update_width=False`); the hex window's scroll half (M-B) and first-row half (M8 / M-c08 / M-c09) are each pinned alone |
| Synthetic instance of the absent case | the mutated copies of the final tree (one mutation at a time); the tester's base RED; the e5c-02 full-refresh RED |
| **Positive control for every probe that returned an ABSENCE** | M-c03 (58 tags differ), M-c05 (list not installed) and M-c02 (full refresh 3.926 s) turned the equality/absence reads RED — the same probes read the recomputed list and fail when a defence is removed |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | the QC-BC observables grep (I-D9) + the 54-file QC-BC run + the 3 importers + the law guards | int-02 1903 passed (115 skipped, 2 xfailed, 2 known F), int-03 31 passed, int-04 / e5c-12 / e5c-rr-06 218 passed |
| B2 file moved on disk | no file moved; the two source files changed in place, no doc moved | 0 readers of a moved path; the law guards hold |
| B3 byte-identical golden captures this source | `grep` over `tests/goldens/**` for the two changed sources | no golden captures `app.py` or `segment_split_view.py` |
| B4 artifact produced here is consumed elsewhere | the recomputed `_a2l_enriched_tags` (reports, check runs, the editors' pickers), the painted hex panes, the Split / Join plan | consumed by the A2L report/check readers and the Split / Join export; asserted in W and the RR-1 filter node |
| A3 interface consumed by another module changed | `_note_image_bytes_written` extended (body only, no signature change); `SplitJoinWindow.note_image_bytes_written` is new, not a change to an existing interface | the three hook callers are unchanged (apply, save-back, commit); the graph's I-1 / I-7 interfaces read as pinned |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict: B1 re-validated every hit by running it; B2 no moved file; B3 no golden hit; B4 the report/check/export consumers; A3 no existing interface signature changed. |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| case records and nodes that no longer matched the strengthened tests or the audit | every `02-test-cases.md` row whose Tests / Coverage / Result / control no longer matches its node | the coverage audit's row-by-row read (`E5-coverage-audit.md` §3, QA-1 … QA-8), then the corrective's per-ruling edits (R-1 … R-6, QA-1 … QA-8) | 1 mark at first audit (QA-1 3/3 owed) + 2 cases added (R-A2L-048/4, /5) + the R-TUI-004.8 threshold amendment (QA-4) + the Result re-citations | all, by the E5 corrective and the re-review | none; re-audit: 21 covered, 0 partial, 0 gap |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated by the audit (QA-1 … QA-8) before the corrective edited its first site: the QA-1 owed runs, the QA-2 widening case and R-4's page-2 case, plus the record-only Result / threshold re-citations. |

### Signed-balance test ledger

`post = base − deleted + added`: scanned test modules `273 = 272 − 0 + 1` (`tests/test_id_registry.py`, measured; the one new module). Cases `21 = 19 + 2` (E4 19, E5 corrective +2). No test node deleted, no function renamed, no assertion weakened (`E5-corrective-notes.md` §1, `E4-integration-notes.md` §5).

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` (code + security, one agent) · **FAIL — BLOCK-UNTIL R-1** (no HIGH; R-1 MAJOR the large-A2L refresh cost unmeasured; R-2 … R-6 MINOR) — `inc-10b/E5-review.md`. Re-review of the corrective `3e432888`: **PASS-WITH-NOTES** (no HIGH; RR-1 MINOR the cache install guarded only by the serial QC-TM node; RR-2 … RR-5 NIT; R-1 discharged by reading and by measurement) — `inc-10b/E5-review.md` re-review section. `qa-reviewer` · coverage audit **PASS-WITH-NOTES** (QA-1 MAJOR owed 3/3 runs; QA-2 MINOR; QA-3 … QA-8 NIT; 19 `full`, 0 `partial`, 0 `gap`) — `inc-10b/E5-coverage-audit.md`. **Design reviews (E3, code-free, split from Inc 10):** `architect` round 2 **10b PASS-WITH-NOTES** · `security-reviewer` round 2 **10b PASS**; round 3 closed SR2-1 / SR2-2; **E3 closed for 10a and 10b** — `../inc-10/E3-rulings.md`. The independent `tester` (E4, Sonnet) wrote the 20 nodes from the design records only and ran them RED on base — `inc-10b/E4-tester-w-notes.md`. |

## 5 · Risks

- **The partial recompute's equivalence is proven on the classes the fixture contains** (RR-2, and the re-review's R-1 table): no fixture has a duplicated `(section, name)` group, and the equality to a full recompute runs only in the serial lane (RR-1). A later change of the service's group merge must add that fixture first.
- **The cache install is guarded only by the serial QC-TM node** (RR-1): in the normal lane, a dropped install (`_a2l_enriched_tags = new`) would still paint the written values, because the filtered list is re-pointed to the local list; the RR-1 filter assertion closes this on the re-review tree, but the assertion reads the installed list after a filter typed post-write.
- **A raise inside the hook still ends the app on shipped routes** (R-2 note): the Split / Join notice runs first so the disarm is never skipped, but Textual does not catch a later raise; the re-point is now total (no `KeyError`), recorded as defensive because no deterministic route reaches the miss.
- **Stale Hex Peek panes are carried** (BL-I10b-1, R-3): the Issues and Checks "Hex Peek" panes keep pre-write bytes until their row is re-selected; nothing exports them, and they are flagged for the batch-end review page.
- **The repaint copies `update_a2l_tags_view`'s bounds, styling and summary** (BL-I10b-2, R-5): two painters can drift; only the `tags a-b / T` span is checked.

## 6 · Pending

- **Merge verification** — per the operator's order (2026-11-06), no full suite runs per increment: this increment ran its slice, the QC-BC set, the 3 other importers, the law guards and the serial lane on the merged tree; the full suite runs once at batch end, when the batch's increments are all on `main`.
- **Canon ids to forward to the requirements session** — the 10 rows (R-A2L-048, .049 moved from Inc 10 with their ids; R-A2L-105, .106, R-TUI-004.7, .8, .9, R-SEG-EXP.15 new; R-SEG-PREV.21, .22 moved) go into `REQUIREMENTS.md` at the batch-end requirements session, with the definition changes (CTX-A2L *first shown row*, CTX-HEX *shown window*, the *in-place write* scope widened to S4).
- **Requirement-text changes to forward** — R-TUI-004.8's threshold amended at E5 QA-4 (the scroll reads (10, 40) for main, (0, 40) for the A2L and MAC views, marked "(changed at E5, QA-4)"); the R-A2L-048 case texts for the two E5-added cases (/4 the widening, /5 the second page).
- **Backlog** — BL-I10b-1 (the stale Hex Peek panes, flagged for the batch-end review page) and BL-I10b-2 (share the tag repaint's bounds / styling / summary with `update_a2l_tags_view`) carried into the batch backlog, each named in `04-validation.md` §Owed.
- **QC-TM figure** — QC-TM-10b-1 on case_06 (220,040 tags) is 0.36 s of 1 s on the final re-review tree (0.350 s / 1.000 s, 65.0 % on the corrective final tree; 0.360 s / 1.000 s, 64.0 % on the re-review tree), to be forwarded with the measurement record.
- **Uncommitted records** — this packet, `04-validation.md`, and the E5 close records are for the orchestrator to commit; nothing here is committed by this record.

## 7 · Suggested next task

Commit the records and merge Inc 10b; run the full suite once at batch end; forward the 10 canon ids and the requirement-text changes to the requirements session; carry BL-I10b-1 and BL-I10b-2 into the backlog; open the next increment on the batch plan.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 / 4 — `app.py`, `segment_split_view.py`; reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_inplace_views.py` (21 non-serial + QC-TM-10b-1) + the edited `test_id_registry.py` |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the slice units traced node-for-node in `codewire/graph-inc10b.md`; e5c-06/07/08 21 passed ×3 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4 — base RED 18 failed / 1 standing guard, int-06 repaint-sign controls RED, e5c-02 full refresh RED |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4 — B1·B2·B3·B4·A3, each with command and verdict |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — FAIL then re-review PASS-WITH-NOTES, 0 HIGH |
| 7 | No file from another lane touched | all | ✓ | single lane, served serially after Inc 10a; only the 2 slice files + W + `test_id_registry.py` |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | the 2 slice files are outside the frozen engine set; `test_engine_unchanged` / `test_tui_directionb` pass (int-04 / e5c-12 / e5c-rr-06) |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | 21 covered, 0 partial, 0 gap — `E5-coverage-audit.md` |
| 10 | Load-bearing emptiness declared, with its synthetic instance | all | ✓ | §4 — the mutant copies, the tester base RED, the QC-TM equality |
| 11 | **Mutation verdicts** declared | all | ✓ | §4 — 15/15 killed (DeepSeek), 11/11 killed (corrective), A10-08 equivalent |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4 — 4 instruments |
| 13 | **Correction population** declared | all | ✓ | §4 — 1 correction, enumerated before editing |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4 — 4 emitted forms |
| 15 | **Independent review** names somebody | all | ✓ | §4b — code-reviewer, qa-reviewer, architect, security-reviewer, tester |
| 16 | **Evidence files** declared | all | ✓ | §4 — 53 committed transcripts at the declared home |
