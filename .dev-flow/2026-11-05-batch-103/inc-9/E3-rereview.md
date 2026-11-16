# Inc 9 — E3 re-review after E3R1 (corrected parts only)

Reviewer: agent K (Opus 5.5), the same single E3 reviewer, both lenses, one pass. Reviewed: `E3-rulings.md` (`b9b86d79`) and the E3R1 correction `30660e0a` on `b103-inc9`, read through the §"E3R1 corrections" file:line list and `E1-rulings.md` §8 S-1 … S-14. I re-read the changed rows, cases, slice entries and graph nodes (`git diff 10912cc1 30660e0a`) against Inc 8's final records. The product tree is unchanged (`a95d0ea9`).

## Verdict: PASS-WITH-NOTES

All 10 original MAJOR findings are closed, and so is the orchestrator's choice to run the record encode in the bench's one worker (§Record encode in the one worker). Still open:
- **One original MEDIUM is only partly closed** (E3S-06): the whole-object work moved off the paint but onto the UI thread.
- **Two new MEDIUM** findings are in the hand-off between the record job and the app handler (R2-01, R2-02). Both fail loud or lose only an unstaged edit; neither writes wrong bytes.
- **3 new MINOR** findings.

None of these blocks the E3 goal ("no open MAJOR or worse"). The three MEDIUM need a ruling before B3 is built: fix in a small E3R2, or carry them as E4 addenda.

**Dependencies outside Inc 9 (the orchestrator's):**
1. The additive I-8.5 field `mark` must enter Inc 8 at its E4. I-9.1's `KindOps(..., mark=bench_mark)` raises `TypeError` at import without it.
2. Inc 8's E4 integrator must confirm "Inc 8 names Inc 9 reads" (`graph-inc9.md:29`) before B1 and B2 start.
3. The cost of Inc 8's `staged` pass on a 1 MiB entry is still to be checked.

## Original MAJOR / MEDIUM findings

| Id | Sev | Status | Evidence of the fix (file:line, `30660e0a`) | Note |
|---|---|---|---|---|
| E3A-01 | MAJOR | **closed** | I-9.1 literal `graph-inc9.md:47-54` (`editable=lambda definition: True`, `decode=_FALLBACK_OPS.decode`, the 5-argument `detail`, `mark`); `bench_detail` `:398-408`; `room` gone from `BenchState` `:64-71`; EX-I1 `:137`; R-PE-BENCH.20/3 (`01-requirements.md:177`) | The literal now matches Inc 8's final `KindOps` field for field, plus `mark` (dependency 1). |
| E3A-02 | MAJOR | **closed** | `show_page(names, definitions, a2l_data, image)` passes all four arguments to `super()` (`graph-inc9.md:633-643`); every job uses `self.a2l_data` (`:54`, `:660`); CTX *page A2L* (`01-requirements.md:108-109`); R-PE-BENCH.77 is `Definition ==` (`:252`), checked in the handler (`graph-inc9.md:704`), case EX-F7 (`:135`) | The encode uses the page payload. The write happens only when the fresh describe equals the bench's definition, so the written bytes are valid under the loaded A2L. |
| E3A-03 | MAJOR | **closed** | The worker writes nothing (`graph-inc9.md:660`); the write is in the app handler on the UI thread (`:700-712`) through I-9.2 `stage_record` (`:55-58`, `:688-698`); busy, generation and definition are checked before it | See §Record encode in the one worker and R2-01 / R2-02 for the hand-off. |
| E3A-04 | MAJOR | **closed** | R-PE-BENCH.2 withdrawn with its reason (`01-requirements.md:151`); its cases removed; EX-L3 withdrawn (`graph-inc9.md:123`); the selection handler has no start row (`:616`); backlog BL-I9-E3-1 (`E1-rulings.md` §8 S-5) | — |
| E3A-05 | MAJOR | **closed** | `bench_mark` reads only the bench state (`graph-inc9.md:369-377`); R-PE-BENCH.18/4 "operand typed, no Enter → no `◆`", whose negative control (`mark` left None) turns it RED (`01-requirements.md:171`); R-PE-BENCH.79 `●` with the operand still in the input (`:254`) | The control can now fail. Dependency 1. |
| E3A-06 | MAJOR | **closed** | R-PE-BENCH.72 is `staged as <k> <value word>` (`01-requirements.md:247`), with negative control `shown` = the edit's text; EX-T1, EX-M2 (`graph-inc9.md:85`, `:95`); `stage_record` (`:694-695`) and the handler (`:712`) | It matches I-8.2's template (`:26`). |
| E3A-07 | MEDIUM | **closed** | Inc 9's copies of R-PE-DEF.1 … .60 are gone (`grep '^\| R-PE-DEF' 01-requirements.md` → 0 rows); 2 regression cases are numbered after Inc 8's (`02-test-cases.md:10`, `:24`); the fold takes Inc 8's text (`E1-rulings.md` §8 S-10) | — |
| E3A-08 | MEDIUM | **closed** | Group I has 2 nodes in 2 files (`graph-inc9.md:17`); C-1 and C-4 are named exceptions with owner and order (`:714-729`; `E1-rulings.md` §8 S-12); the `-bench` rule is Inc 8's (`graph-inc9.md:19`) | — |
| E3A-09 | MEDIUM | **closed** | `ArrayBenchSheet.check_action` (`graph-inc9.md:517-525`); the edges name the mechanism (`:769-780`); R-PE-BENCH.49 (`01-requirements.md:217`), case `s` → `save_project` once | Toolkit check (source read on `<runner>`, textual 8.2.8): `App.run_action` returns False when `check_action` is falsy (`textual/app.py:4245-4248`), and `_check_bindings` then goes on to the next namespace's bindings (`:3978-3987`). The app's `s` therefore runs. The E4 key pilot still decides it under Windows Terminal. |
| E3A-10 | MEDIUM | **closed** in Inc 9's records | The list of Inc 8 names with types (`graph-inc9.md:29`); the definition line through `_FALLBACK_OPS.detail(row, None, width, None, 1)[0]`; the build-order condition (`:19`) | Dependency 2. |
| E3A-11 | MEDIUM | **closed** | CTX *bench state lifetime* (`01-requirements.md:44-47`); R-PE-BENCH.9 (`:157`); R-PE-BENCH.26/2 (`:183`); the selection handler (`graph-inc9.md:616-622`); `show_page` drops the states of rows no longer on the page (`:637`) | — |
| E3S-01 | MAJOR | **closed** | CTX *finite values* (`01-requirements.md:59-79`); R-PE-BENCH.19 (`:202`); .64 widened (`:236`); `summary_strip`, `grid_canvas`, `chart_canvas`, `legend_line`, `apply_tool` (`graph-inc9.md:379-455`, `:327`); EX-N1, N2 | lo and hi are taken over finite values only, with no `round` of a non-finite `t`, and every tool refuses before arithmetic. |
| E3S-02 | MAJOR | **closed** | `parse_operand` → None for a non-finite double (`graph-inc9.md:318-321`); R-PE-BENCH.62 adds `1e999` and 400 × `9` (`01-requirements.md:234`); R-PE-BENCH.67 (`:239`); `result_text` is never called on a non-finite value (`graph-inc9.md:346`) | — |
| E3S-03 | MAJOR | **closed** | CTX *bench job* (`01-requirements.md:110-111`); R-PE-BENCH.28, an AT on memory with ≤ 1 running job (`:185`); the waiting slots (`graph-inc9.md:59-63`); `_run_job` (`:656-665`) | A waiting request holds no decoded data, so the peak is one job's. |
| E3S-04 | MEDIUM | **closed** | `generation` +1 at every `set_document` (`graph-inc9.md:43-45`, `:649`, `:741-743`); R-PE-BENCH.78 widened to the image (`01-requirements.md:253`); R-PE-BENCH.83 checked when the encode ends (`:258`, handler `graph-inc9.md:704`) | An Apply ends with the image push, so a job that may have read a torn view is dropped. The handler re-checks the generation after the message hop. |
| E3S-05 | MAJOR | **closed** | Clamped CTX geometry and the bench minimum width of 12 (`01-requirements.md:44-58`, `:68`); R-PE-BENCH.7 (`:156`); `window_for` (`graph-inc9.md:289`); `bench_detail`, `grid_canvas`, `chart_canvas` (`:402`, `:414`, `:428`); EX-W2, W3 | — |
| E3S-06 | MEDIUM | **not closed (partly)** | `bytes_line` takes `runs` (`graph-inc9.md:474-484`); `legend_line` and `bench_cells` read stored values (`:451`, `:362`); R-PE-BENCH.29 (`01-requirements.md:186`) | **Still open:** (1) The whole-object work moved from every paint into `_job_done`, which runs **on the UI thread** (`graph-inc9.md:671`). Per preview it does the diff runs against the record over the snapshot (1,048,576 Mapping lookups for LARGE; ≥ 0.105 s on a plain dict, E3 probe `BYTES.*`, slower through the overlay) and the finite lo/hi over 1,048,576 shown values. The UI is blocked once per job. R-PE-BENCH.29 times a key *after* the preview, so it cannot catch that. (2) `axis_labels` still returns every axis label (`:436-445`, unchanged). **Fix:** compute the runs, lo/hi and the strip in the worker, over the snapshot and the result, and post them with it. `_job_done` only stores them. `axis_labels` takes the window (origin, rows and columns shown). Add an R-PE-BENCH.29 case: a `right` pressed while LARGE's preview result is arriving is handled within 0.5 s (quiet host). |

## Record encode in the one worker (the orchestrator's choice, F-5 / §8 S-9)

**Sound.** It meets both fixes at once:
- E3A-03: the worker only encodes, and the write runs on the UI thread after the busy check (`_refuse_if_busy()`), the generation check and the `Definition ==` check.
- E3S-03: one job runs at a time, and a record job is never replaced by a decode.

Folding `_record_stage_done` into the app handler is right. The handler is the first UI-thread point after the result's message hop, and it re-checks `event.generation` against the sheet's (`graph-inc9.md:704`), so nothing can change between the check and the write. A record job is dropped only on a generation change, not on a view change. A selection or page change during the encode therefore does not lose the stage, and a reload is caught by `Definition ==`.

Expected cost: a record waits at most for the one running job (≤ ≈ 11 s behind a LARGE decode or preview, [B1]).

The hand-off has two defects (R2-01, R2-02).

## New findings

| Id | Sev | Tag | About (file:line) | Defect | Fix |
|---|---|---|---|---|---|
| R2-01 | MEDIUM | design-gap | bench job "record jobs in order, one per row" (`graph-inc9.md:59-63`); `_job_done` "posts RecordStageRequested … then starts the next waiting job" (`:671`); `set_document` generation +1 (`:649`) | **A second queued record stage always goes stale.** After record job A's `_job_done`, the next record job B starts at once. Its snapshot and generation are taken *before* the app handler writes A. A's write ends in `refresh_entries` → `set_document` → generation +1, so B is dropped with R-PE-BENCH.78's "changed … stage it again". The ordered record queue cannot deliver its second job. This fails loud and writes no wrong bytes, but the queue's purpose is lost. | After a "record" job's `_job_done`, keep the worker idle until the handler calls back. Pin `ArrayBenchSheet.record_done(name)`, called by the handler on every branch (after `record_staged` on ok, and on each refusal), to resume the queue. Case: alt+s on VAL_BLK_DEF_0001 then on MAP_DEF_0001 during one held encode → both staged, 2 entries, no changed status. Negative control: start the next job in `_job_done` → MAP RED. |
| R2-02 | MEDIUM | design-gap | `action_stage_record` captures the edit items at alt+s (`graph-inc9.md:596-598`); `on_array_bench_sheet_bench_apply_requested` has no record-pending check (`:602-610`); `record_staged(name)` clears `edit` and `undo` unconditionally (`:679-686`) | **An edit made while the row's record job waits or runs is lost silently.** Alt+s queues edit E1. The operator applies another tool, so the edit becomes E2 (allowed: nothing refuses it). The record writes E1's record, then `record_staged` clears E2 and its undo. E2 is neither staged nor kept. | Pass the staged edit through: `RecordStageRequested(…, edit)` and `record_staged(name, edit)`. Clear only while `states[name].edit == edit`, else keep the newer edit (its `◆`) and its undo. Case: alt+s with a held encode, +Δ 1 on another cell, release → the entry holds E1 only, and the bench still shows E2 with `◆`. Negative control: the unconditional clear → RED. |
| R2-03 | MINOR | impl | `record_staged(name)` (`graph-inc9.md:679-686`); lifetime: a page without the row drops its state (`01-requirements.md:44-47`, `graph-inc9.md:637`) | A record job is not dropped on a page change, so the handler can call `record_staged` for a name with no state. | State that `record_staged` (and R2-01's `record_done`) is a no-op for a name with no state. Case: page turn during a held record encode → staged, no exception. |
| R2-04 | MINOR | design-gap | `set_document` re-requests the selected row's current **and** staged decode on every call (`graph-inc9.md:649`) | After the operator's own record stage of LARGE, the image is unchanged, yet two full decodes are queued (≈ 2 × 11 s of worker time) and the next apply's preview waits behind them. R-PE-BENCH.25 asks only for the staged recompute. | Request the current decode only when the image argument changed (an image push), and the staged decode only when the row's span holds or held an entry byte. This is efficiency only: memory stays bounded by the one worker. |
| R2-05 | MINOR | design-gap | I-2 consumer note "Inc 2 E3A-07 / E3S-08 overlay → `ChangeService.stage_values` and the preview job" (`graph-inc9.md:24`) | The name `stage_values` was replaced by `stage_record` at E3R1. | Change it to "the preview and record jobs (`_run_job`) encode over `StagedOverlay`". |

## Checks not run, and why

- No Code-Wire extractor re-run, because the changed nodes are all new, with no code. The corrector's lint output stands (`evidence-e2/codewire_lint-graph-inc9-e3r1.txt`: `not read=0`, exit 0).
- I did not re-run the corrector's `examples_e3r1.py`. Its keys repeat this reviewer's E3 probe on the CTX formulas, and the transcript is committed.
- No Textual run of `check_action`. The textual 8.2.8 source was read on `<runner>` as text only; the E4 key pilot decides the behaviour.
- `trace_check-e3r1.txt` shows 0 CASE gaps and 82 TEST gaps, as expected before E4. It was taken as recorded.
