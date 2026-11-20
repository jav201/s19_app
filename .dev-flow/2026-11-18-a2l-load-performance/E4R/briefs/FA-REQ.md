# Unit FA-REQ — E4R requirement records and canon rows [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`25161a00`** (HEAD check mandatory). Common rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

**Q1 at launch** (the orchestrator fills this in): `Q1 = A` (operator verdict 2026-11-19, PENDING P-191: the 100 ms tick bound covers preparation until installation is dispatched; install + publication are a held step, as D-12).
- If unanswered: do not touch the canon rows .040–.042 and do not add .050. Write them in `E4R/01-requirements.md` under a heading `## Held for Q1` (FA-REQ2 applies them).

## Fixed design (architect, FA-DESIGN §3.1; do not reword sentences)
This is a transcription unit. Copy the texts below exactly. If a canon row you must replace does not hold the "current text" quoted, STOP that row and report.

## Files you may edit
`.dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md` (new), `.../E4R/02-test-cases.md` (new), `.../E4R/E4R-rulings.md` (new), `REQUIREMENTS.md`.

## Rows
| row | what | proof |
|---|---|---|
| 1 | Create `E4R/01-requirements.md` with the header, definitions, the table and the slice section below | file exists; every sentence holds `shall` exactly once (`grep -o shall` per row) |
| 2 | Create `E4R/02-test-cases.md` (planned cases table below) | file exists |
| 3 | Create `E4R/E4R-rulings.md` (text below) | file exists |
| 4 | In `REQUIREMENTS.md`, replace the sentence of each amended row; insert the new rows right after `R-A2L-REFRESH.048` and after `R-A2L-DEF.165` (same 3-column format: `\| Id \| Form \| Requirement \|`) | for every id in the table, the canon sentence is byte-equal to the E4R sentence (write `../scratch/canon_eq.py`: parse both tables, compare, print `diffs=0`) |
| 5 | In `R-A2L-DEF.162`–`.165`, replace `on the E1 reference host` with `on the reference host` | same script; `git grep -c "E1 reference host" REQUIREMENTS.md` = 0 for these ids |
| 6 | Laws: `tests/test_requirements_canon.py tests/test_id_registry.py` (`-n 0`) | no new failure against `frontA\baseline\laws.txt` (base-alp failing set, from `laws.txt`: `test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing`, `::test_r_tst_040_041_every_upper_timing_bound_is_reported`, `::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`, `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` (3 offenders at base: R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008; your rows must add none), `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors`, `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token`); paste the summary |

Negative control (rows 4–5): in `../scratch/nc-4`, add a second `shall` to the canon `.049` sentence, run `tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once`, and paste the RED line naming `.049`.

## Text of `E4R/01-requirements.md`
```
# E4R — E4 return of batch 2026-11-18-a2l-load-performance — requirements

Fixes forward the reviews of 2026-11-19 (R4–R6, DX) under the operator verdicts recorded in `E4R-rulings.md`. Rows here supersede the same ids in `inc-1/`…`inc-3/01-requirements.md`, which stay unchanged (PP-06). Each sentence holds one `shall`.

## Definitions (terms only)
reference host   The HT-01 CachyOS laptop with the `s19ci` Python 3.11 environment; a measured run is quiet when the 1-minute load average is below 1.0 at its start (recorded). Replaces "E1 (reference) host".
key delivery     The moment the test posts the key event to the application's message queue.
index node visit One read of an internal tree node's `min_first` navigation summary during candidate selection.
unresolved array-like record  An occupancy record that `is_array_entry` classifies as array-like and that the request has neither described nor materialized.
held step        A busy step during which the screen waits for the step to end (CTX-BUSY, R-PROGRESS-LINE.3).

## Requirements
| Id | Form | Requirement | Numeric pass threshold | Negative control | US | Status |
|---|---|---|---|---|---|---|
| R-A2L-REFRESH.033 | While | While a direct A2L attach copies, parses or performs post-parse work on its worker, the system shall acknowledge each operator key within 1.0 second of its delivery to the application. | 5/5 scenarios × 2 keys: held copy, held parse, held enrichment, held definition preparation and the real case_06 attach with keys delivered while copy, parse or preparation runs; every latency ≤ 1.0 s on the reference host, measured from key delivery to the existing focus acknowledgement polled every 5 ms, never through `pilot.press` while a worker is busy; no median substitution. | Run a held phase on the UI thread, or block the UI thread 1.5 s in a worker-phase UI callback → a latency ≥ 1.5 s → RED. | US-ALP-01 | amended at E4R (supersedes the E4 D-11 text; R4-F3 split) |
| R-A2L-REFRESH.049 | While | While a direct A2L attach captures its request snapshot on the UI thread, the system shall acknowledge each operator key within 1.0 second of its delivery to the application. | 1/1 scenario × 2 keys: a loaded 1,000,000-byte image, the parse held; both keys delivered immediately before the attach starts its capture; each latency ≤ 1.0 s; both acknowledged while the parse is still held (0 enrichment calls). | Delay the capture by 1.2 s on the UI thread → RED. | US-ALP-01 | new at E4R (D-11, operator P-167b) |
| R-A2L-REFRESH.034 | While | While a direct A2L attach captures its request snapshot or performs post-parse work, the system shall update its existing busy progress line at least once per 1.0 second. | 4/4: enrichment held 1.5 s, definition preparation held 1.5 s, the real case_06 attach sampled from attach start until installation is dispatched, and the capture over a 1,000,000-byte image; every interval between visible progress updates in those windows ≤ 1.0 s; step labels and bar bounds unchanged. The preserved common refresh is a held step (operator D-12, P-167c): its gap is recorded, not asserted. | Freeze the progress line or stop its timer in a held phase, add an out-of-range bar value, or delay the capture 1.2 s → RED. | US-ALP-01 | amended at E4R (supersedes the E4 D-12 text; non-shall clause removed) |
| R-A2L-REFRESH.037 | When | When a picker handles an accepted direct-attach generation or a later population request, the system shall make the generation's single worker-built bulk definition snapshot, shared read-only by the Check and Patch pickers, available exclusively to a matching mounted request while preserving the legacy `a2l_data=None` call and the accepted snapshot for an unmounted panel. | 5/5 scenarios as at E1; an accepted direct generation runs exactly 1 bulk describe off the UI thread (1 `_describe_one` build per name) and both picker snapshots hold the same read-only mapping; rebuild/no-op arms describe 0 times; mismatches invalidate without consuming stale definitions; unmounted calls read no mapping and keep the snapshot until a matching mount consumes it; declared lengths/formats exact. R-PICKER-CORRECT.018 is read as "at most one bulk describe per picker per changed generation" (operator D10). | Describe the generation once per picker (2 describes), describe per row/page or on the UI thread, reuse a stale generation, describe on an unchanged signature, consume a mismatched snapshot, read/invalidate while unmounted, or fail to consume the surviving snapshot at mount → RED. | US-ALP-01, US-103-04 | amended at E4R (D10) |
| R-A2L-REFRESH.051 | When | When a direct A2L attach, image load or project load ends with any outcome, the system shall leave the cyclic garbage collector enabled. | 6/6 outcomes checked after the route has ended (outside Textual's exception re-raise): attach success, attach failure, attach superseded, attach install exception, loose image install exception, project load success; `gc.isenabled()` is True in each. | Drop the re-enable in the attach install exception branch → the attach-exception arm RED; drop it in the loose-route worker exception branch → the image-exception arm RED. | US-ALP-01 | new at E4R (R5-F3) |
| R-A2L-REFRESH.052 | When | When a direct A2L attach, image load or project load installs its result, the system shall complete the installation without a full cyclic garbage collection on the UI thread. | 3/3 routes on a generated mid-size A2L: 0 product calls of `gc.collect` during installation; case_06 attach: no MainThread generation-2 collection longer than 0.25 s from attach start to outcome. | Restore `gc.collect()` at any install site → RED. | US-ALP-01 | new at E4R (DX-F3, R5-F5) |
| R-A2L-REFRESH.053 | When | When the system loads the same A2L five times in a row, the system shall retain at most 10 % more garbage-collector-tracked objects after the fifth load than after the second. | Attach route, generated mid-size A2L, 5 loads; after each outcome the test runs `gc.collect()` and counts `len(gc.get_objects()) + gc.get_freeze_count()`; loads 3–5 ≤ 1.10 × load 2; a single describe of an 8,000-object disjoint A2L with the collector disabled leaves fewer than 1,000 cyclic-garbage objects. | Remove the closure-cycle break in `describe_definitions` → the describe arm RED and, with freezing installs, the reload count grows → RED. | US-ALP-01 | new at E4R (DX-F3 leak guard) |
| R-A2L-DEF.166 | When | When the system indexes an unresolved array-like occupancy record, the system shall give that record an unbounded upper end. | 3/3: index shape (an unresolved array-like record with provisional length 4 has an unbounded upper end; a requested or cached record has its final end); randomized equivalence over ≥ 4,000 seeded trials mixing kinds, lengths, aliases, homonyms and arrays whose final length exceeds the provisional one → 0 `shared_with` differences from a global-scan reference that materializes every candidate in walk order; the CURVE/COM_AXIS/standing-size write-safety case refuses with `A2L-DEF-OVERLAP` where the parser can produce it (reachability recorded). | Bound unresolved arrays by their provisional tag length → index-shape and equivalence arms RED. | US-ALP-01, US-103-05 | new at E4R (operator D2; ruling D-4) |
| R-A2L-DEF.167 | When | When the system evaluates 8,000 pairwise-disjoint definitions declared in address order, in shuffled address order or with 1,000 AXIS_PTS declared first, the system shall visit on average at most 4·log2(8,000) + 16 (67.9) index nodes per definition. | 3/3 layouts, all names described in one request; mean index node visits per definition ≤ 67.9; plus the R-A2L-DEF.159 no-gather arm: one `next()` on a 4,000-alias population visits ≤ 2·log2(4,000) + 4 nodes. | Keep the walk-order tree (no address ordering) → shuffled layout RED; gather all candidates before the first yield → no-gather arm RED. | US-ALP-01 | new at E4R (operator D3) |
| R-A2L-DEF.168 | When | When the system evaluates 8,000 pairwise-disjoint definitions with 1,000 AXIS_PTS declared first, the system shall perform at most 200,000 candidate-overlap checks in total. | Dense layout of R-A2L-DEF.167; total `_entry_overlaps` calls ≤ 200,000 (25·n); 0 `shared_with` differences from the reference. | Never tighten a materialized record's bound → RED. | US-ALP-01 | new at E4R (operator D3) |

R-A2L-REFRESH.029: sentence unchanged; fit criterion now reads "each route records enrichment, summary and the one shared bulk describe off the UI thread before the install callback" (D10).
R-A2L-DEF.162–.165: "on the E1 reference host" → "on the reference host" (ruling R1 in `E4R-rulings.md`); thresholds unchanged.

## Q1-dependent rows
<if Q1 = A: put this table under "## Requirements"; if B: same, replace the .050 sentence by the B text; if unanswered: keep it under "## Held for Q1">
| R-A2L-REFRESH.040 | When | When the system loads a primary image with case_06 A2L attached, the system shall complete the image+A2L load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the reference host. | 3 serial runs in fresh apps on the quiet reference host; total from before admission/copy to the outcome, four named phases; median ≤ 80 s, every run < 100 s; QC-TM margin reported. 80/100 s is a regression guard until the final bound (measured median × 1.25, operator D1) is approved. | Hold the producer 105 s → RED. | US-ALP-01 | amended at E4R (D1; responsiveness moved to .050) |
| R-A2L-REFRESH.041 | When | When the system loads a project containing a primary image and case_06 A2L, the system shall complete the project load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the reference host. | As .040, per project shape. | As .040. | US-ALP-01 | amended at E4R (D1) |
| R-A2L-REFRESH.042 | When | When the system loads an A2L-only project containing case_06, the system shall complete the project load with a median total duration of at most 80 s over 3 runs and no individual run of 100 s or more on the reference host. | As .040. | As .040. | US-ALP-01 | amended at E4R (D1) |
| R-A2L-REFRESH.050 | While | (A) While the system performs post-parse preparation for an image+A2L or project load, the system shall fire each due 50 ms UI timer tick no more than 100 ms late. | 50 ms UI timer; window from preparation entry until installation is dispatched (A) / until the final publication (B); every observation in the window ≤ 100 ms late (`timing_bound` on CI); ≥ 3 ticks during the 0.20 s producer gate; case_06 on the three routes (push lane) and a generated 8,000-object disjoint A2L on the three routes (PR lane, no duration budget); under A the install/publication worst stall is recorded. | Run the preparation on the UI thread, or block the UI thread 0.3 s inside the window → RED. | US-ALP-01 | new at E4R (split from .040–.042; window per Q1) |
(B) sentence: "While the system performs post-parse preparation, installation or publication for an image+A2L or project load, the system shall fire each due 50 ms UI timer tick no more than 100 ms late."

## Slice (changed product files → rows)
| File | Rows |
|---|---|
| `s19_app/tui/a2l_definition.py` | R-A2L-DEF.166, .167, .168; R-A2L-REFRESH.053 |
| `s19_app/tui/app/file_load.py` | R-A2L-REFRESH.037, .051, .052 |
| `s19_app/tui/app/loaded_state.py` | R-A2L-REFRESH.052 |
| `s19_app/tui/app/project_load.py` | R-A2L-REFRESH.052 |
| `s19_app/tui/app/patch.py` | LLR-078.2 (C-7), R-A2L-REFRESH.037 |
| `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` | LLR-078.2 (C-7), R-A2L-REFRESH.037 |
| `s19_app/tui/app/shared.py` | <the row(s) its `f34b998d` change implements: read `git show f34b998d -- s19_app/tui/app/shared.py` and the inc-3 rows; R4-F9 premise> |
```

## Text of `E4R/02-test-cases.md`
A table `| Row | Planned case | Unit | Lane |`, with one line per row:
- .033 held arms + case06 arm via the new instrument (FA-KEY; PR + push);
- .049 capture arm (FA-KEY; PR);
- .034 4 arms (FA-KEY; PR + push);
- .037 count/identity (FA-D10) and adapter arms (FA-C7b);
- .050 case_06 ×3 routes (FA-D11b; push) and the 8,000-object ×3 routes (FA-D11b; PR);
- .051 r038/r043 + outcome arms (FA-GC2T);
- .052 spy (FA-GC2T; PR) and MainThread pause (FA-GC2T; push);
- .053 describe-garbage (FA-GC1) and reload count (FA-GC2T);
- .166 shape + equivalence + write-safety (FA-IDX1);
- .167/.168 scale cases + no-gather (FA-IDX2T);
- .040–.042 budget nodes (existing; push).

State: planned.

## Text of `E4R/E4R-rulings.md`
```
# E4R rulings and operator verdicts

## Operator verdicts
- D-11 (P-167b, 2026-11-19): «Restaurar 1 s y arreglar» — the 1.0 s key bound holds during the request capture (R-A2L-REFRESH.049); the product must meet it. The conductor's uncommitted .033 wording is not adopted (three responses in one row); it is superseded by .033 + .049.
- D-12 (P-167c): «Aceptar» — the preserved common refresh is a held step outside the 1.0 s cadence (R-A2L-REFRESH.034).
- D1 (P-168): 80/100 s stays as a regression guard on the reference host; the final bound is the measured median × 1.25 after Front A, shown to the operator before it is fixed.
- D2 (P-168): unresolved array-like and AXIS_PTS records are open-ended; the .140/11 index-shape assertion is added (R-A2L-DEF.166).
- D3 (P-168): shuffled and AXIS_PTS-dense scale cases with a node-visit counter, ≤ 4·log2 n + 16 visits per query at n = 8,000 on all three layouts and ≤ 25·n checks dense; Opus redesign; back to the operator with numbers if unmet (R-A2L-DEF.167/.168).
- D4 (P-168): C-7 restored by injection — 2 main sites (fix-round G2) and 2 alp sites.
- D10 (P-168): one shared bulk describe; R-PICKER-CORRECT.018 is read as "at most one bulk describe per picker per changed generation; one describe may serve both pickers" (its text is unchanged). PLAN contract 5's per-picker reading is superseded by this verdict.
- D11 (P-168): heavy case_06 arms run only in the push lane; a small same-oracle version runs in PR.
- Q1–Q3 (operator verdict 2026-11-19, «Ok a todo.» = every recommended option): Q1 = A — the 100 ms tick bound (R-A2L-REFRESH.050) covers post-parse preparation until installation is dispatched; installation and publication are a held step, as D-12. Q2 = A — the heavy case_06 arms run in a separate push-only CI job with its own limit (FA-D11c). Q3 = A — the reported "EOF never read" was the case_06 project load (DX-F1); nothing to add.

## Architect / orchestrator rulings (DF-02; the operator may object)
- R1 Reference host: R-A2L-REFRESH.040–.042 and R-A2L-DEF.162–.165 are measured on the HT-01 laptop (`s19ci`, Python 3.11), not the E1 Windows host (D1 + HT-01). Thresholds unchanged.
- R2 D3 mechanism: AXIS_PTS and unresolved array-like bounds are tightened when first materialized instead of being resolved eagerly at index build, so R-A2L-DEF.158 ("0 materializations during build") and .161 (laziness) stay intact; one mechanism covers D2 and D3.
- R3 C-7: the Patch picker snapshot adapter of I-ALP-2.3 (match, consume, invalidate the whole mapping before the fallback; unmounted panels untouched) moves from `PatchEditorPanel` to its app caller in `s19_app/tui/app/patch.py`; behaviour unchanged.
- R4 The E4 tester's census re-pin of `_accepted_a2l_picker_snapshots` in `tests/test_b100_session_reset.py` (`SNAPSHOT_EXCLUSIONS`) is accepted: the mapping is a hand-off, never consumed across a source change. Known cost: it keeps the previous payload alive after a session reset until the next accepted attach (backlog).
- R5 The conductor's status note of 2026-11-19 09:35 is not committed; its claims are corrected in `CORRECTIONS.md`.
```

## Nodes you may run (`-n 0`, `timeout 300`)
`tests/test_requirements_canon.py`, `tests/test_id_registry.py`, `../scratch/canon_eq.py`. Nothing else.
