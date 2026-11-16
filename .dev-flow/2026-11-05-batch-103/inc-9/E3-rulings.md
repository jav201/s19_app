# Inc 9 — E3 rulings (orchestrator, relevo-8)

Source: `E3-architect.md` (6 MAJOR, 5 MEDIUM, 2 MINOR, 1 INFO) and `E3-security.md` (4 MAJOR, 2 MEDIUM, 2 MINOR, 1 INFO), commit `10912cc1`. Both FAIL. Every finding is ruled below; the E3R1 corrector applies them with targeted edits (no rewrite), then the same reviewer re-reviews the corrected parts only.

## MAJOR: all accepted, fixed as the reviewer proposed, with these choices
- **E3A-01** (I-9.1 `KindOps` literal invalid): accepted. Fix the literal against the final I-8.5 (`decode` present, `editable` a callable, `detail(row, preview, width, state, room)`). `decode` must not call I-2 for array rows at `build_row`: array kinds decode lazily (on selection / bench open), never per page row on the UI thread.
- **E3A-02** (`show_page` superseded form; record stage blind to a conversion change): accepted. Use the final `show_page(names, definitions, a2l_data, image)`. The record stage compares address, length, shape **and the conversion identity**; any mismatch refuses with a visible status (fail loud), never re-encodes silently.
- **E3A-03** (I-9.2 writes the document from the worker): accepted. Encode in the worker, write on the UI thread through I-8.2 `_stage_encoded`, so the R-PE-BENCH.78 check (and `_refuse_if_busy`) can stop it.
- **E3A-04** (R-PE-BENCH.2 start row / `↑` line has no seam): **withdraw R-PE-BENCH.2 and its 3 cases** (SKILL E3 "prefer removing a feature over guarding it"; DF-04 c). Inc 8's E3R2 row window already keeps the bench row and its detail in view. Record the withdrawal with a reason; the idea goes to the batch backlog (P-026) as BL-I9-E3-1.
- **E3A-05** (the bench `◆` / `●` mark has no seam; vacuous negative control): **accept the reviewer's additive I-8.5 field** `mark: Callable[[SheetRow, object | None], str | None] | None = None` (None keeps Inc 8's rule). This is an Inc 8 interface amendment, ruled by the orchestrator: it enters Inc 8 at its E4 integration (one optional field + one call site in `row_line`), recorded in Inc 8's records. Inc 9 sets it for its array kinds only. Re-derive the negative control so it can turn RED (e.g. the mark from the formula text instead of the bench state).
- **E3A-06** (§7 reword of R-PE-BENCH.72 never applied): accepted. Apply the reword so the row holds over Inc 8's `staged as <shown>` template.
- **E3S-01** (NaN from an erased FLOAT32 cell → `round()` raises): accepted. Non-finite cell values are shown as such and every tool refuses on them with a visible status; no exception escapes.
- **E3S-02** (`1e999` / 400 nines → `inf`, `InvalidOperation`): accepted. Operands are bounded and must be finite; out-of-range or non-finite operands refuse with a visible status before any arithmetic.
- **E3S-03** (unbounded decode / preview workers): accepted. One worker at a time (exclusive group; a newer request supersedes the pending one).
- **E3S-05** (grid geometry divides by zero at widths 6–11): accepted. Guard every width-derived divisor; below the minimum width the bench shows its one-line fallback, never raises.

## MEDIUM: fix in E3R1 as the reviewer proposed
- E3A-07, E3A-09, E3A-10, E3A-11, E3S-04, E3S-06: as proposed.
- **E3A-08** (seam check): remove I4, I6 and the `styles.tcss` line from group I (Inc 8 owns them now). Record the two residual one-line Inc 8 edits — C-1 (`PatchEditorPanel.__init__` builds `ArrayBenchSheet`) and C-4 (`LayoutMixin.compose` appends ` · arrays open the bench`, split by Inc 8 E3A-15) — as **named exceptions** to the seam rule "Inc 9 may only add functions, modules and I-8.5 keys", owned by Inc 9's integrator after Inc 8 merges. E3A-05's `mark` field is not an exception: it enters through Inc 8.

## MINOR / INFO
- E3A-12, E3A-13, E3S-07, E3S-08: E4 addenda (the corrector lists them in `E1-slice.md` § "E4 addenda"). E3A-14, E3S-09: no action.

## Stale tags
- Fix all 22 stale "per Inc 8 E3R1" sites (15 old Inc 8 forms, 7 old statuses) and the untagged `select_next` / `formula_label` uses in `E1-slice.md`, against Inc 8's final records (E3R2 included).

## Order
- Inc 9 group B (pure modules) builds only after this E3R1 and the re-review close.

## E3R1 corrections

Worker claude-opus-5-5 (Inc 9 E3R1 corrector), 2026-11-13 (time in `steps.log`, from `date`). Records only: no source or test code, no Inc 8 record touched.

**Counts:**
- Requirements: 80 → 82 active. Added 7 (.7, .9, .19, .28, .29, .49, .67); R-PE-BENCH.2 withdrawn; Inc 9's 4 active Inc 8 copies removed (plus the retired R-PE-DEF.1 copy).
- Cases: 167 → 186, of which 184 are on Inc 9 rows and 2 are regression cases on Inc 8 rows.
- Graph: 47 → 47 nodes (45 new, 2 Inc 8 exceptions), 7 entities, 13 → 15 edges.

**Paths.** Relative to this folder: `R` = `01-requirements.md`, `C` = `02-test-cases.md` (regenerated from `evidence-e1/cases.py` on `<runner>`, never hand-edited), `G` = `codewire/graph-inc9.md`, `S` = `E1-slice.md`, `E1` = `E1-rulings.md` (new §8, old text kept with supersede markers, PP-06).

**Evidence:**
- `evidence-e2/examples_e3r1.py` and its transcript (keys `GEOM.*`, `CHART.*`, `FINITE.*`, `OPERAND.*`, `RESULT.*`, `MEM.*`, `MSG.*`, `B1.*`; `uptime` beside it, load 2.3);
- `evidence-e2/codewire_lint-graph-inc9-e3r1.txt`;
- `evidence-e1/trace_check-e3r1.txt` (0 CASE gaps; the TEST gaps are expected before E4).

**MAJOR**
- **E3A-01** → fixed.
  - I-9.1 re-pinned as Inc 8's final `KindOps`: `editable=lambda definition: True`, `decode=_FALLBACK_OPS.decode` (no I-2 call), the 5-argument `detail`, `mark` (G:35-54).
  - Every bench decode runs only in `_run_job` (G:53, G:656).
  - `register_bench_kinds` node G:497. `bench_detail(row, preview, width, state, room)` G:398, and `room` dropped from `BenchState` G:64.
  - Slice B3, B14 S:27, S:45; E1 S-1 E1:189, S-3 E1:191.
  - Import case R-PE-BENCH.3/4 (R:152, C:14) and the build-time decode count R-PE-BENCH.20/3 (R:177, C:61), example EX-I1 G:137.
- **E3A-02** → fixed.
  - The `show_page(names, definitions, a2l_data, image)` override passes all four arguments to `super()` (G:633, S:68).
  - Every bench decode and encode uses `self.a2l_data`, never `app.current_a2l_data` (G:54, G:656; CTX *page A2L* R:108).
  - R-PE-BENCH.77 compares the whole definition (`Definition ==`, the conversion included) R:252, in the handler G:700. EX-F7 case R-PE-BENCH.77/3 C:176, G:135.
- **E3A-03** → fixed.
  - The worker only encodes (G:656). The write happens on the UI thread in the app's handler G:700 through I-9.2, re-pinned as `ChangeService.stage_record(name, encoded, count)` (G:55, node G:688, S:78-79).
  - The examples EX-T1, EX-O1, EX-F1, EX-R12 moved to `stage_record` (G:688), EX-T7 to the handler.
  - New `ArrayBenchSheet.record_staged` G:679, S:72. `RecordStageRequested(name, definition, count, outcome, generation)` G:35.
  - **Ruling choice recorded:** the reviewer's app-side record worker conflicts with E3S-03's single worker. The record encode therefore runs as a job of the bench's one worker, and E1's `_record_stage_done` is folded into the handler (G:807 F-5; E1 S-9 E1:197).
- **E3A-04** → fixed: R-PE-BENCH.2 is withdrawn with its reason, and its 3 cases are removed (R:151, cases gone from C). EX-L3 is withdrawn (G:123). The selection handler no longer does the start row (G:612). Backlog **BL-I9-E3-1** for P-026 (E1 S-5 E1:193).
- **E3A-05** → fixed: the additive I-8.5 field `mark` is consumed as pinned (G:28, R:5); it enters Inc 8 at its E4 through the orchestrator.
  - New node `bench_mark` G:369, S:37.
  - R-PE-BENCH.18 has a negative control that can turn RED: operand typed, no Enter → no `◆` (R:171, C:55, EX-T9 G:134).
  - R-PE-BENCH.79 shows `●` while the operand stays in the input (R:254, C:179).
- **E3A-06** → fixed: R-PE-BENCH.72 is reworded to `… staged as <k> <value word> (…)`, with the new negative control `shown` = the edit's text (R:247, C:165-166). EX-T1 and EX-M2 now use `staged as` (G:85, G:95), as do `stage_record` G:688 and the handler G:700. Messages `MSG.*` are in the transcript.
- **E3S-01** → fixed.
  - CTX *finite values*, *cell look*, *chart look*, strip and legend (R:59-79).
  - New R-PE-BENCH.19 (R:202, C:56-58). R-PE-BENCH.64 widened to values that are not finite (R:236, C:153).
  - Nodes `grid_canvas` G:410, `chart_canvas` G:424, `legend_line` G:447, `summary_strip` G:379, `apply_tool` G:323; EX-N1, EX-N2 G:126-127; `FINITE.*`.
- **E3S-02** → fixed.
  - CTX *operand* and *result text* are finite only (R:89-107).
  - R-PE-BENCH.62 adds `1e999` and 400 × `9` (R:234, C:149-150). New R-PE-BENCH.67 (R:239, C:159).
  - Nodes `parse_operand` G:314, `result_text` G:342, `apply_tool` G:323; EX-N3, EX-N4; `OPERAND.*`, `RESULT.*`.
- **E3S-03** → fixed.
  - New R-PE-BENCH.28 (memory AT ≤ 320 MiB and ≤ 1 running job; R:185, C:74-75) and CTX *bench job* R:110.
  - The one worker and its waiting slots, with record jobs ordered and never replaced by a decode (G:59, `_run_job` G:656, `_job_done` G:667, S:70-71). EX-J1; `MEM.*`.
- **E3S-05** → fixed.
  - CTX: nc clamped, rows and columns shown ≥ 1, the chart h clamped, the bench minimum width of 12 (R:44-58, R:68).
  - New R-PE-BENCH.7 (R:156, C:25-28). R-PE-BENCH.5 gains the room 0 and 1 cases (R:154, C:21-22).
  - Nodes `bench_detail` G:398, `grid_canvas` G:410, `chart_canvas` G:424, `window_for` G:285; EX-W2, W3 G:124-125; `GEOM.*`, `CHART.*`.

**MEDIUM**
- **E3A-07** → fixed: Inc 9's copies of R-PE-DEF.1, .1.1, .1.2, .36 and .60 are removed. M1 cites them as Inc 8's (R:146). Two regression cases stay, numbered after Inc 8's: R-PE-DEF.1.2/2 and R-PE-DEF.60/5 (C:10, C:24; generator in `evidence-e1/cases.py`). Count and fold lines R:269-271; E1 S-10 E1:198.
- **E3A-08** → fixed: group I is down to 2 nodes in 2 files (G:17, S:11). I4, I6 and the `styles.tcss` line are removed. C-1 and C-4 are recorded as the named exceptions, with owner and order (E1 S-12 E1:200; S:81-90; nodes G:714, G:723). C-4 is split by Inc 8 E3R2 (E1 S-11 E1:199; R:150).
- **E3A-09** → fixed: new node `ArrayBenchSheet.check_action` G:517, and B23 S:59. The edges' `when:` now names the mechanism (G:767-780). New R-PE-BENCH.49 with the cases `s` → `save_project` once and Escape on a number row (R:217, C:123-124, EX-K7 G:133).
- **E3A-10** → fixed: the list "Inc 8 names Inc 9 reads" with its types, and the definition line through `_FALLBACK_OPS.detail(row, None, width, None, 1)[0]` (G:29). Build-order condition S:15. Routed to the orchestrator for Inc 8's E4 integrator (E1 §8, last item).
- **E3A-11** → fixed: CTX *bench state lifetime* R:44. New R-PE-BENCH.9 (R:157, C:29-31) and R-PE-BENCH.26/2 (R:183, C:71). Selection handler G:612, `show_page` G:633, EX-B1 G:132.
- **E3S-04** → fixed.
  - The sheet `generation` is bumped by every `set_document`, with a view counter for page and selection (G:35 I-9.1, G:741, `set_document` G:645, S:69).
  - R-PE-BENCH.78 widened to the image (R:253, C:177-178).
  - `_refuse_if_busy()` is checked when the encode ends, before the write: R-PE-BENCH.83 (R:258, C:184-185) and the handler G:700. EX-F8, EX-F9.
- **E3S-06** → fixed.
  - `_job_done` stores the diff runs, the finite lo/hi and the strip once (G:667, G:64). `bytes_line` takes `runs` (G:474, S:52). `legend_line` and `bench_cells` read the stored values.
  - New budget row R-PE-BENCH.29 (quiet host, R:186, C:76; EX-J2).
  - Inc 8's `staged` cost on a 1 MiB entry is routed to the orchestrator (E1 §8, last item).

**MINOR / INFO**
- E3A-12, E3A-13, E3S-07 and E3S-08 are listed as E4 addenda (S:113-119). E3A-14 needed no new action: the idempotent registration is in B23 S:59 and G:497. E3S-09: no action.

**Stale tags.**
- The 22 stale sites, the 27 valid ones and the untagged superseded forms are rewritten to Inc 8's final forms in R, S and G: 0 occurrences of the re-check tag remain in R, S, G and C.
  - `select_next` → `select_after` (S:102);
  - `formula_label` removed (S:111);
  - the C-7 signature line corrected;
  - `show_page(names, definitions, image)` → the 4-argument form.
- In E1 the old ruling text stays (PP-06). Each stale site carries a supersede marker pointing to §8 S-1 … S-14 (E1:31, :33, :97, :104, :110, :116, :123, :129, :134, :137, :177). The 6 tag words left there are history; the valid line E1:119 and the instruction E1:179 are unchanged.

**Lint:** `codewire_lint.py` (Code-Wire `v3.1.0-8-gb6cd30d`, core only) on G → `not read=0 nodes=47 entities=7 edges=15`, `exit=0` (`evidence-e2/codewire_lint-graph-inc9-e3r1.txt`).

**Not done here:**
- Inc 8's records (the `mark` field enters them at Inc 8's E4, by the orchestrator);
- PENDING entries (BL-I9-E3-1 → P-026);
- the re-review of the corrected parts (next step).

## E3R2 corrections

Worker claude-opus-5-5 (Inc 9 E3R2 corrector), 2026-11-13 (time in `steps.log`, from `date`). This pass applies the orchestrator's rulings on the re-review `E3-rereview.md` (`5b7843b5`, PASS-WITH-NOTES). Records only; abbreviations as in §E3R1.

**Counts:** 82 active rows (unchanged); 186 → 189 cases, regenerated from `evidence-e1/cases.py` on `<runner>`; 47 → 48 nodes; 15 → 17 edges.

**Evidence:**
- `evidence-e2/codewire_lint-graph-inc9-e3r2.txt`;
- `evidence-e1/trace_check-e3r2.txt` (0 CASE gaps; the 82 TEST gaps are expected before E4).

**Findings and what changed:**
- **E3S-06 (MEDIUM)** → fixed. The worker computes the whole-object work and posts it with its result: the 1 MiB diff runs, the finite lo/hi, the strip and `axis_labels`. `_job_done` only assigns it.
  - Graph: bench job G:71; `_run_job` G:668; `_job_done` G:680 (new input `derived`); `axis_labels` G:448; `BenchState.labels` G:81; EX-J2 G:690.
  - Slice: B33, B34 S:70-71.
  - Requirements: R-PE-BENCH.29 gains the case "a `right` pressed while LARGE's preview result is arriving, handled within 0.5 s", with a negative control (R:186, C:77).
- **R2-01 (MEDIUM)** → fixed. After a fresh record result, `_job_done` starts nothing. The new `ArrayBenchSheet.record_done(name)` resumes the queue, so the next record job's snapshot and generation come after the write.
  - Graph: `record_done` I-9.1 G:51, node G:703; the handler calls it on every branch G:724; edges G:811-812; EX-Q1 G:691, G:703.
  - Slice: B36 S:73; A2 S:80.
  - Requirements: R-PE-BENCH.70 gains the case "two queued record stages → both staged, 2 entries" (R:245, C:164).
- **R2-02 (MEDIUM)** → fixed. `RecordStageRequested` carries `edit` (G:39), and `record_staged(name, edit)` clears only while the row's edit still equals it (I-9.1 G:48, node G:693, EX-Q2; S:72).
  - R-PE-BENCH.79 is now "When … while the row's bench edit is still the edit it staged". It gains the newer-edit case and the negative control "clear unconditionally" (R:254, C:182).
- **R2-03, R2-04 (MINOR)** → E4 addenda S:121-122. The no-op rule for a name with no state is also stated in I-9.1 (G:48-51).
- **R2-05 (MINOR)** → fixed: the I-2 consumer note names the preview and record jobs (`_run_job`), not `stage_values` (G:24).
- Records: `E1-rulings.md` §8 S-15 E1:208; slice counts S:19 (46 new, 48 nodes); graph counts G:5, G:15, G:236.

**Lint:** `not read=0 nodes=48 entities=7 edges=17`, `exit=0` (`evidence-e2/codewire_lint-graph-inc9-e3r2.txt`).
