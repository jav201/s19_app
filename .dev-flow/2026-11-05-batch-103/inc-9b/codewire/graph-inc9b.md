# Inc 9b — Code-Wire graph: the bench busy cue (P3 BUSY pill) and the stepped record-stage refresh (E2 prototype)

Batch `2026-11-05-batch-103`, increment 9b, stage E2, 2026-11-14, model Opus (E1 + E2 by one agent, DF-03). Base `09001bbc`. Code-Wire `v3.1.0-8-gb6cd30d` (`b6cd30d`, README v3.2), core only: one node per function the change adds or touches, examples from the requirements, real callers read from the code and from `tools/codewire_extract.py` on a throwaway clone. The prototype is this graph only: nothing in the source.

Inputs: `../01-requirements.md` (13 rows, R-PE-BENCH.94 … .106), `../02-test-cases.md` (36 cases), `../E1-rulings.md` (R-1 … R-4, ED-1 … ED-5, VP-1 … VP-7), `../E1-slice.md` (17 nodes, 4 source files). Earlier graphs this one layers on: `../../inc-8/codewire/graph-inc8.md`, `../../inc-9/codewire/graph-inc9.md` (the bench widget, I-9.1).

### Groups for E4 (file ownership)

| Group | Files | Nodes |
|---|---|---|
| W — the cue | `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py`, `s19_app/tui/definition_bench_view.py` | 7: `busy_job`, `ArrayBenchSheet.on_mount`, `ArrayBenchSheet._enqueue`, `ArrayBenchSheet._job_done`, `ArrayBenchSheet.record_done`, `ArrayBenchSheet._busy_tick`, `busy_title` |
| S — the stepped write and refresh (O-E) | `s19_app/tui/app/patch.py`, `s19_app/tui/screens_directionb/patch_editor/panel.py` | 10: `PatchMixin.on_array_bench_sheet_record_stage_requested`, `PatchMixin._stage_bench_record`, `PatchMixin._refresh_patch_history_view`, `PatchMixin._patch_refresh_steps`, `PatchMixin._patch_refresh_tail`, `PatchMixin._run_refresh_steps`, `PatchMixin._patch_document_token`, `PatchMixin._note_image_bytes_written`, `PatchEditorPanel.refresh_entries`, `PatchEditorPanel.refresh_sheet_document` |

W and S own disjoint files. Their one contract is I-9b.2 (below). E4: W ∥ S, then the AT tester and the integrator; the pilots of `../E1-slice.md` §4 first (S runs pilot 1, W pilots 2 and 3).

### Interfaces

**Pinned here.**
- **I-9b.1** `PatchEditorPanel.refresh_entries(rows, mem_map=_UNSET, document=_UNSET, *, sheet: bool = True) -> None` (additive keyword; `False` skips the staging sheet's `set_document`) and `PatchEditorPanel.refresh_sheet_document() -> None` (the skipped part, over the rows and map the panel keeps). Users: the six refresh sites (`app/patch.py:294`, `:692`, `:1656`, `app/loaded_state.py:675`, `app/project_load.py:1029`, `panel.py:750`) keep `sheet=True`; only `PatchMixin._patch_refresh_steps` passes `False`. Inc 8b: no known caller (its slice decides; `../E1-slice.md` §7).
- **I-9b.2** `ArrayBenchSheet.record_done(name)` is called once per record stage, **after the last refresh step** (or at once when the write did not reach the service, or when the chain is skipped), never before; until then the sheet's record hold stays and the cue shows `stage <name>`. Caller: `PatchMixin.on_array_bench_sheet_record_stage_requested` only (W ↔ S contract).
- **I-9b.3** `Container#patch_sheet_win` (composed by `LayoutMixin.compose`, `patch_editor/layout.py:45-47`; styled by `styles.tcss:2893-2900`, `:2920-2923`): while a busy cue shows, `ArrayBenchSheet` owns its inline border and its `border_title`; it keeps the title found when the cue appears and puts it back for the idle look. Whoever else sets that title or border at run time (Inc 8b, if its slice does) must not do it while the cue shows; a stylesheet change to the window's border is safe (the inline style wins while busy and is cleared after). **P9b (merged base `e4485817`):** Inc 8b sets neither the window's title nor its border at run time (`git diff 09001bbc e4485817 -- s19_app` has no `border_title`, `border`, `styles` write; `layout.py`, `styles.tcss` untouched); toggling the inline border causes 0 `StagingSheet._paint` calls and no size change (pilot P2), so Inc 8b's new `StagingSheet.on_resize` is not triggered by the cue.

**Consumed, pinned elsewhere, unchanged.** I-9.1 (`../../inc-9/codewire/graph-inc9.md` §Interfaces): `BenchState.job` (`definition_bench.py:135`), the single-job queue `_enqueue` / `_start_next` / `_job_done`, the record hold `_held`; `definition_bench_view.EDIT` (`"bold #f5c26b"`, `:54` — a style string: the busy colour is its foreground, `Style.parse(EDIT).color`, pilot finding P9b-F1); `insight_style.DEPTH_BG` (`#0a0e1b`, `:141` on the merged base, was `:134`); `definition_sheet.name_echo` (`:93-96` merged, was `:58-61`; body unchanged by Inc 8b); I-8.4 `StagingSheet.on_mount` (`sheet.py:143-145` merged, was `:133-135`; unchanged); `ChangeService.history_depths`.

### Examples (data; `EX-BC*` ids are cited by the cases)

| Id | Example |
|---|---|
| EX-BC1 | LARGE selected at t = 0 (key handled), decode gated: ticks at ~0.1 s → idle look; first tick with pending time ≥ 0.2 s (≤ 0.5 s) → `#patch_sheet_win` border `round #f5c26b`, title `STAGING SHEET  ` + ` ◓ BUSY · decode LARGE · 0.2 s · keys still work ` (frame and seconds as of that tick). Same with `preview VAL_BLK_DEF_0001` (Enter on `+Δ 5`) and `stage VAL_BLK_DEF_0001` (alt+s). |
| EX-BC2 | MAP_DEF_0001's summary gated running (the sheet's active job), LARGE selected: LARGE's `BenchState.job == "decode"` but its worker has not started → `busy_job` → `("decode", "LARGE")` → the cue shows at the 0.2 s tick. |
| EX-BC3 | MAP_DEF_0001 selected, decode gated 0.15 s then released: tick 1 (0.1 s, pending 0.1 < 0.2) idle; the job ends before 0.2 s → `busy_job` → `None` → idle at every tick, the tick pauses. |
| EX-BC4 | `busy_title("STAGING SHEET", "decode", "LARGE", 1.7, 0, 200)` → plain `STAGING SHEET   ◐ BUSY · decode LARGE · 1.7 s · keys still work ` (two spaces after `SHEET`, then the pill, which starts with a space); the pill span styled `bold #0a0e1b on #f5c26b`. |
| EX-BC5 | LARGE's real decode, 50 ticks: titles t1 … t50 all differ from their predecessor; frames `◐ ◓ ◑ ◒ ◐ …`; seconds rise by ~0.1 per tick; gaps median ≤ 0.2 s, max ≤ 0.5 s (prototype: median 0.16, max 0.45). |
| EX-BC6 | LARGE, Set `7` on 256 × 16 cells, alt+s: the encode ends → write step (`_stage_bench_record` without the refresh ~0.04 s, `stage_record` ~0.02 s) → gap (STEP_GAP_S, a tick and a paint) → step 1 serialize (~0.16 s) → gap → step 2 ledger + card + JSON view (~0.22 s) → gap → step 3 sheet `set_document` (~0.26 s) → gap → step 4 checks and enable states (~0.004 s) → `record_done("LARGE")` → idle. Largest step ~0.26 s. Step times measured on the merged base `e4485817` (Inc 8b's sheet paint), quiet rtx, 3 runs: write 0.041 / 0.041 / 0.041, s1 0.160 / 0.163 / 0.161, s2 0.212 / 0.221 / 0.219, s3 0.256 / 0.258 / 0.256, s4 0.004, block 0.673 / 0.687 / 0.682 s (`../evidence-e4/pilots/out/ex-bc6-t*.txt`). |
| EX-BC7 | EX-BC6, `down` posted when the write step ends → handled after that step, before step 1's frame; ≤ 1.0 s. |
| EX-BC8 | `record_done("VAL_BLK_DEF_0001")` → `_stage_name = None`, `_busy_tick()` at once → `busy_job` `None` → inline border cleared, title `STAGING SHEET`. |
| EX-BC9 | Set `60` on VAL_BLK_DEF_0001, alt+s, encode gated past 0.2 s → cue `stage VAL_BLK_DEF_0001`; released → `Refusal` → status `Patch Editor: VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50`; `_stage_bench_record` → `False` → `record_done` at once → idle. A worker raising → `_job_done(…, result None)` → `state.job` cleared → `busy_job` `None` → idle at the next tick. |
| EX-BC10 | LARGE decode gated, `down` to DISPLAY_0001: the selected row is a scalar → `busy_job(None, "DISPLAY_0001", None)` → `None` → idle at the next tick (≤ 0.1 s), LARGE's ask time dropped; its worker still runs. |
| EX-BC11 | name `[@click=app.quit]X[/]` → `busy_title(…)` is a `Text` whose plain text holds `[@click=app.quit]X[/]` literally; set as the `border_title` object, never as a `str`. |
| EX-BC12 | name `A\x1b[2J` → `name_echo` → `A�[2J` in the title; U+0085 → `�`. |
| EX-BC13 | 300 × `N`, room 66 (an 80-column terminal: window content width 70, B = width − 4, pilot P3; 106 at 118, 190 at 220): F = len(title without the name); name → the first max(1, 76 − F) − 1 `N`s and `…`; the title's plain text ends ` keys still work `; a 1-character name at the same room → unchanged. |
| EX-BC14 | alt+s on VAL_BLK_DEF_0001, step 1 runs (token T1), Undo or Apply handled before step 2 (its own synchronous refresh paints the changed document/image) → step 2 sees token T2 ≠ T1 → steps 2–4 skipped, `record_done` → the views equal a full refresh. Apply writes `current_file.mem_map` in place, so the write generation changes the token even when `id(current_file)` and history depths do not. |

### Baseline (code in scope at `09001bbc`; extractor run on a throwaway clone)

Run: `codewire_marks.py --repo <clone> --layered --graph inc-8/codewire/graph-inc8.md --graph inc-9/codewire/graph-inc9.md` → 90 marks, 2 nodes without code (`PatchEditorPanel._TABS`, `WINDOW_HELP_SECTIONS`: attributes, not functions), 2 replaced by the later graph (`PatchEditorPanel.__init__`, `LayoutMixin.compose`). `codewire_extract.py --layered … --path <file>` for the three slice files that hold marked nodes:

| Path | Marks | Findings | Ruling |
|---|---|---|---|
| `patch_editor/bench_sheet.py` | 20 | 100 (72 nodes of other files "without mark": expected, one path per run; 22 unannotated parameters; 2 unannotated returns; **`_run_job` has `snapshot`, `edit` not in Inc 9's node** (FX9c/FX9d added them); **`bench_submit` returns `ArrayBenchSheet.BenchApplyRequested`, Inc 9's node says `Message`**) | The two drifts are Inc 9's graph being stale after FX9c/FX9d, outside this slice (`_run_job`, `bench_submit` unchanged here): recorded for the batch-end extraction (skill, Batch end), not edited in Inc 9's graph by this increment. Nodes this graph changes are written from the code at `09001bbc`. |
| `app/patch.py` | 2 | 92 (90 other-file nodes; `on_array_bench_sheet_record_stage_requested`'s `event` unannotated) | No drift on this slice. |
| `patch_editor/panel.py` | 6 | 88 (other-file nodes; `PatchEditorPanel.__init__` replaced, info) | No drift on this slice. |

This graph layered on top (`--graph inc-8 … --graph inc-9 … --graph graph-inc9b.md`, a second throwaway clone): 93 marks; exactly the 8 new nodes have no code yet (plus the two attribute nodes above); the 7 changed nodes all resolve to their functions (4 replace an earlier graph's node: `ArrayBenchSheet._job_done`, `.record_done`, `PatchMixin.on_array_bench_sheet_record_stage_requested`, `PatchEditorPanel.refresh_entries`; 3 had no earlier node: `ArrayBenchSheet._enqueue`, `PatchMixin._stage_bench_record`, `._refresh_patch_history_view`). Lint: `codewire_lint.py graph-inc9b.md` → `not read=0 nodes=15 entities=6 edges=20`, exit 0.

Base signatures and lines of the changed nodes: `ArrayBenchSheet._enqueue(self, kind: str, name: str, edit: tuple | None = None) -> None` (`bench_sheet.py:123-132`); `._job_done(self, kind, name, generation, result, derived)` (`:218-250`); `.record_done(self, name) -> None` (`:475-478`); `PatchMixin.on_array_bench_sheet_record_stage_requested(self, event) -> None` (`app/patch.py:379-402`); `._stage_bench_record(self, event, sheet) -> None` (`:404-441`); `._refresh_patch_history_view(self) -> None` (`:654-728`); `PatchEditorPanel.refresh_entries(self, rows, mem_map=_UNSET, document=_UNSET) -> None` (`panel.py:696-709`). `definition_bench_view.py` and `ArrayBenchSheet.on_mount` / `_busy_tick` / `busy_job` have no base code.

### E4-prep re-check on the merged base (P9b, `e4485817` = `3daea03d` + Inc 8b `103a72df`)

Layered run on a throwaway clone of `e4485817`: `codewire_marks.py --layered --graph inc-8 … --graph inc-9 … --graph inc-8b/codewire/graph-inc8b.md --graph graph-inc9b.md` → 117 marks; without code exactly the 8 new nodes (plus the attribute nodes `PatchEditorPanel._TABS`, `WINDOW_HELP_SECTIONS`); the 7 changed nodes resolve. `codewire_extract.py --layered … --path` on the three slice files that hold marked nodes: `bench_sheet.py` — only F-9b-3's two Inc 9 drifts (`_run_job` `snapshot`/`edit`, `bench_submit` return); `app/patch.py` — `_stage_bench_record` returns `None` in code vs `bool` here (the planned change); `panel.py` — `refresh_entries` `sheet` (the planned keyword) and `mem_map` written `object` here vs `Union[Mapping[int, int], None, _Unset]` in code → node corrected. Every other finding is "graph node without mark" or "unannotated" (one path per run).

**Names Inc 8b changed (function-level AST diff `09001bbc` → `e4485817`) that a 9b node calls, or that call a 9b node:**

| Inc 8b name | Change | 9b relation | Effect on this graph |
|---|---|---|---|
| `StagingSheet._paint` (`sheet.py:333-373`), `_fit_window` (`:438-450`), new `_view_width` (`:415-419`), `_detail_geometry` (`:421-428`) | changed / new (grid scroller `#patch_sheet_grid`, header rule, odd rows) | reached from step 3 (`refresh_sheet_document` → `ArrayBenchSheet.set_document` → `StagingSheet.set_document` → `_fit_window`, `_paint`) and from the synchronous refresh | step 3 re-measured: 0.256–0.258 s (EX-BC6); no node text change |
| `sheet_widths`, `header_line`, new `header_rule`, `row_line`, `detail_lines` (`definition_sheet.py`); `bench_cells`, `summary_strip` (`definition_bench.py`) | changed / new | inside `_paint` (step 3) | timing only (above) |
| `StagingSheet.on_resize` (`sheet.py:272-274`, new), `_SheetBody.on_resize` (`:51-55`, ancestors) | new / changed | could be reached if the cue's inline border changed the window's size | P2: 0 `_paint` calls and no size change while the border toggles (same `round` edges) |
| `ArrayBenchSheet._bench_geometry` (`bench_sheet.py:305-309`) | changed (3 lines fewer) | none (called by `_reveal`) | line shift only: `record_staged` `:463-470`, `record_done` `:472-475`, `on_staging_sheet_selection_changed` `:477-507`, `set_document` `:525-551`; `_enqueue` `:123-132`, `_start_next` `:134-163`, `_job_done` `:218-250` unchanged |
| `StagingSheet.compose` (`#patch_sheet_grid` scroller around the body) | changed | `busy_tick` writes the parent window `#patch_sheet_win`, not the sheet | none: the window is still `LayoutMixin.compose`'s `Container`; its content width equals the view width V (70 / 110 / 194) |

Not changed by Inc 8b (checked): `app/patch.py`, `panel.py`, `entries.py`, `layout.py`, `styles.tcss`, `definition_bench_view.py`, `name_echo`, `plain`, `EDIT`, `DEPTH_BG`, `StagingSheet.on_mount`, `set_document`. Callers of the 9b nodes are unchanged (`_enqueue` callers now `:421`, `:461`, `:504`, `:506`, `:546`, `:548`, `:550`; `refresh_entries`, `_refresh_patch_history_view`, `record_done` callers at the same `app/patch.py` lines). Inc 8b's verdict-hue rule (`insight_style.py:86-91`, R-PE-DEF.101: GREEN / YELLOW / RED only with their glyph) is not touched: the busy colour is EDIT's amber, not YELLOW `#f6ff8f`.

**Pilots (`../E4-pilots.md`):** P1 → `set_timer(0.1, …)` between steps; P2 → clear the four edge rules + `refresh()`; P3 → B = window content width − 4 = 66 / 106 / 190 at 80 / 118 / 220 columns (a longer title is cropped by Textual to B − 1 characters plus its own `…`); the pill's span style survives the window's `border-title-color`.

### Coverage — every requirement → nodes and examples (owner group)

| Requirement | Nodes | Examples | Group |
|---|---|---|---|
| R-PE-BENCH.94 | busy_job, ArrayBenchSheet._enqueue, ArrayBenchSheet._busy_tick, ArrayBenchSheet._job_done | EX-BC1, EX-BC2 | W |
| R-PE-BENCH.95 | busy_job, ArrayBenchSheet._busy_tick | EX-BC3 | W |
| R-PE-BENCH.96 | busy_title, ArrayBenchSheet._busy_tick | EX-BC4 | W |
| R-PE-BENCH.97 | ArrayBenchSheet.on_mount, ArrayBenchSheet._busy_tick | EX-BC5 | W |
| R-PE-BENCH.98 | PatchMixin.on_array_bench_sheet_record_stage_requested, PatchMixin._patch_refresh_steps, PatchMixin._patch_refresh_tail, PatchMixin._run_refresh_steps, PatchEditorPanel.refresh_entries, PatchEditorPanel.refresh_sheet_document | EX-BC6 | S |
| R-PE-BENCH.99 | PatchMixin._run_refresh_steps | EX-BC7 | S |
| R-PE-BENCH.100 | ArrayBenchSheet.record_done, ArrayBenchSheet._busy_tick, PatchMixin.on_array_bench_sheet_record_stage_requested | EX-BC8 | W, S |
| R-PE-BENCH.101 | PatchMixin._stage_bench_record, PatchMixin.on_array_bench_sheet_record_stage_requested, ArrayBenchSheet.record_done, ArrayBenchSheet._busy_tick | EX-BC9 | S, W |
| R-PE-BENCH.102 | busy_job, ArrayBenchSheet._busy_tick | EX-BC10 | W |
| R-PE-BENCH.103 | busy_title | EX-BC11 | W |
| R-PE-BENCH.104 | busy_title | EX-BC12 | W |
| R-PE-BENCH.105 | busy_title | EX-BC13 | W |
| R-PE-BENCH.106 | PatchMixin._run_refresh_steps, PatchMixin._patch_document_token, PatchMixin._note_image_bytes_written, PatchMixin._patch_refresh_steps, PatchMixin._patch_refresh_tail | EX-BC14 | S |

Shared-file edits and their one owner: `bench_sheet.py` W; `definition_bench_view.py` W (one function appended; Inc 8b may also edit this file — `../E1-slice.md` §7); `app/patch.py` S; `panel.py` S. `PatchMixin._refresh_patch_history_view`'s five other callers: S (same calls, same order; regression only).

### Node count

17 nodes: 9 new (`busy_job`, `ArrayBenchSheet.on_mount`, `ArrayBenchSheet._busy_tick`, `busy_title`, `PatchMixin._patch_refresh_steps`, `PatchMixin._patch_refresh_tail`, `PatchMixin._run_refresh_steps`, `PatchMixin._patch_document_token`, `PatchEditorPanel.refresh_sheet_document`), 8 changed. 4 source files. 13 requirements, each with at least one example.

## Nodes

busy_job
req: R-PE-BENCH.94, R-PE-BENCH.95, R-PE-BENCH.102
in: str? name; BenchState? state; str? stage_name
out: tuple[str, str]? job
func: pure. The busy job of CTX-PE-BENCH: a record stage name → ("stage", stage_name); else a selected bench row whose state.job is "decode" or "preview" → (state.job, name); else None. A summary or staged job, a scalar row (state None) and no row give None.
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-BC1) name "LARGE", state.job "decode", stage_name None → job ("decode", "LARGE")
examples: (EX-BC2) name "LARGE", state.job "decode" while another row's summary runs → job ("decode", "LARGE")
examples: (EX-BC9) name "MAP_DEF_0001", state.job None, stage_name "VAL_BLK_DEF_0001" → job ("stage", "VAL_BLK_DEF_0001")
examples: (EX-BC10) name "DISPLAY_0001", state None, stage_name None → job None
examples: (EX-BC3) name "MAP_DEF_0001", state.job "summary" → job None

busy_title
req: R-PE-BENCH.96, R-PE-BENCH.103, R-PE-BENCH.104, R-PE-BENCH.105
in: str idle; str word; str name; float seconds; int frame; int room
out: Text title
func: pure. idle + two spaces + the busy pill " <f> BUSY · <word> <name echo> · <seconds, one decimal> s · keys still work " with f = "◐◓◑◒"[frame % 4]; the pill styled bold DEPTH_BG on the colour of EDIT; BUSY_COLOR = Style.parse(EDIT).color.get_truecolor().hex, defined in this module (no new colour literal); the name is name_echo(name) (controls → U+FFFD, 256 + "…") cut to max(1, room − F) characters, the last "…" when cut, F = the title's length without the name. Plain Text: no markup is parsed.
module: s19_app/tui/definition_bench_view.py
examples: (EX-BC4) idle "STAGING SHEET", word "decode", name "LARGE", seconds `1.7`, frame `0`, room `200` → title "STAGING SHEET   ◐ BUSY · decode LARGE · 1.7 s · keys still work "
examples: (EX-BC5) frame `1` → title holds "◓ BUSY"; frame `4` → title holds "◐ BUSY"
examples: (EX-BC11) name "[@click=app.quit]X[/]" → title holds "[@click=app.quit]X[/]"
examples: (EX-BC12) name "A\x1b[2J" → title holds "A�[2J"
examples: (EX-BC13) name 300 × "N", room `66` → title ends " keys still work " and holds "N…"; name "N", room `66` → title holds "decode N · "

ArrayBenchSheet.on_mount
req: R-PE-BENCH.97
in: (none)
out: None
func: Textual dispatches on_mount along the MRO, so StagingSheet.on_mount runs exactly once through framework dispatch; ArrayBenchSheet.on_mount does NOT call super(). It initializes the ask times {}, the frame 0 and the stage name None, and creates the paused 0.1 s (BUSY_TICK_S) cue tick: set_interval(BUSY_TICK_S, _busy_tick).
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet._busy_timer] (replace)
examples: (EX-BC5) mounted → the timer exists and is paused; no tick runs until a job is asked

ArrayBenchSheet._enqueue
req: R-PE-BENCH.94, R-PE-BENCH.96
in: str kind; str name; tuple? edit = None
out: None
func: as at base (queue the record, the selected-row slot or the page job; then _start_next), plus: for kind "record", "decode" or "preview", keep the ask time monotonic() under (word, name) unless one is kept already ("record" → word "stage"), and resume the cue tick. Page jobs ("summary", "staged") keep no ask time.
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet._busy_asked] (replace)
examples: (EX-BC1) kind "decode", name "LARGE" → _busy_asked gets ("decode", "LARGE"), the timer resumed
examples: (EX-BC1) kind "decode", name "LARGE" again (an image push re-asks, set_document) → the first ask time kept
examples: (EX-BC3) kind "summary" → no ask time

ArrayBenchSheet._job_done
req: R-PE-BENCH.94, R-PE-BENCH.98
in: str kind; str name; int generation; object result; object derived
out: None
func: as at base (`bench_sheet.py:218-250`, unchanged on the merged base `e4485817`), plus: a fresh "record" result that sets the hold also keeps name as the stage name (the cue keeps `stage <name>` through the write and refresh, I-9b.2).
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet._stage_name] (replace)
examples: (EX-BC6) "record", "LARGE", fresh → hold set, _stage_name "LARGE", RecordStageRequested posted
examples: (EX-BC9) "decode" with result None (the worker raised) → state.job cleared as at base; no stage name

ArrayBenchSheet.record_done
req: R-PE-BENCH.100, R-PE-BENCH.101
in: str name
out: None
func: as at base (release the hold, _start_next), plus: clear the stage name and run _busy_tick once at once, so the cue leaves without waiting for the next tick.
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet._stage_name] (clear); [Data: ArrayBenchSheet._held] (replace)
examples: (EX-BC8) "VAL_BLK_DEF_0001" after the last step → _stage_name None, idle look painted in the same call

ArrayBenchSheet._busy_tick
req: R-PE-BENCH.94, R-PE-BENCH.95, R-PE-BENCH.96, R-PE-BENCH.97, R-PE-BENCH.100, R-PE-BENCH.101, R-PE-BENCH.102
in: (none)
out: None
func: the cue tick (UI thread). job = busy_job(selected name, its state, the stage name, or the name of a record still queued or encoding); drop the ask times of every other key; no job, or pending time < BUSY_GRACE_S (0.2 s) → the idle look (clear the inline border rule of #patch_sheet_win; put back the title kept when the cue appeared) and, with no job asked at all, pause the timer; else the inline border ("round", the busy colour = BUSY_COLOR = Style.parse(EDIT).color.get_truecolor().hex, #f5c26b) and border_title = busy_title(kept idle title, word, name, pending time, frame, room B = the window's `size.width` − 4), then frame + 1. BUSY_GRACE_S = 0.2 and BUSY_TICK_S = 0.1 are defined in this module; no new colour literal. The idle look clears the four inline edge rules (`styles.clear_rule("border_top" | "border_right" | "border_bottom" | "border_left")`) and then calls the window's `refresh()`: `clear_rule("border")` clears nothing (the shorthand is stored as four edges) and a clear without `refresh()` leaves the busy border painted (pilot P2). A window not mounted (the bench outside the Patch Editor) → nothing.
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Interface: patch_sheet_win border and title] (replace); [Data: ArrayBenchSheet._busy_asked] (replace)
examples: (EX-BC1) LARGE asked at 0.0, tick at 0.31 → border round #f5c26b, title holds "decode LARGE · 0.3 s"
examples: (EX-BC3) MAP_DEF_0001 asked at 0.0, tick at 0.1 → idle; job ended before 0.2 → idle, timer paused
examples: (EX-BC10) the selection moved to DISPLAY_0001 → idle within one tick, ("decode", "LARGE") dropped
examples: (EX-BC8) called from record_done with no job → title "STAGING SHEET", inline border cleared

PatchMixin.on_array_bench_sheet_record_stage_requested
req: R-PE-BENCH.98, R-PE-BENCH.99, R-PE-BENCH.100, R-PE-BENCH.101
in: ArrayBenchSheet.RecordStageRequested event
out: None
func: wrote = _stage_bench_record(event, sheet) (a raise → record_done, then re-raise, as base's finally); wrote False → sheet.record_done(name) at once; wrote True → _run_refresh_steps(_patch_refresh_steps(), on_done = sheet.record_done(name)); the hold and the cue last until on_done (I-9b.2).
module: s19_app/tui/app/patch.py
examples: (EX-BC6, root on_array_bench_sheet_record_stage_requested) LARGE written → record_done called after step 4, not before
examples: (EX-BC9) Set `60` refused by the encode → wrote False → record_done at once, no refresh

PatchMixin._stage_bench_record
req: R-PE-BENCH.98, R-PE-BENCH.101
in: ArrayBenchSheet.RecordStageRequested event; ArrayBenchSheet sheet
out: bool wrote
func: as at base (`app/patch.py:404-440`: busy guard, no A2L, stale generation, A2L changed, refusal, outside span, stage_record, report, notices, note_staged, record_staged) without the last line (the synchronous refresh); returns True when stage_record ran (ok or refused by the service), else False.
module: s19_app/tui/app/patch.py
modify: [Data: ChangeService.document] (replace)
examples: (EX-BC6) VAL_BLK_DEF_0001 Set `10` on (0,0) → wrote True, one bytes entry at 0x800090
examples: (EX-BC9) no A2L loaded → status "Patch Editor: no A2L is loaded — nothing staged." → wrote False
examples: (EX-BC9) a session action running → the busy line → wrote False

PatchMixin._refresh_patch_history_view
req: R-PE-BENCH.106
in: (none)
out: None
func: runs every step of _patch_refresh_steps() at once, in order: the same calls in the same order as base (`app/patch.py:687-728`), for the five synchronous callers (bytes stage, Undo, Redo, load, and any later site).
module: s19_app/tui/app/patch.py
examples: (EX-BC14) Undo → ledger, JSON view, sheet, checks and enable states repainted in one call (digests equal base's)

PatchMixin._patch_refresh_steps
req: R-PE-BENCH.98, R-PE-BENCH.106
in: (none)
out: list[Callable] steps
func: the refresh as 4 callables, each reading the service and the loaded file when it runs: (1) document view = _patch_document_view() kept for step 2; (2) panel.refresh_entries(service.rows(ranges), mem_map=_strip_source_map(loaded), document=view, sheet=False); (3) panel.refresh_sheet_document(); (4) _patch_refresh_tail (its body).
module: s19_app/tui/app/patch.py
examples: (EX-BC6) → 4 steps; step 3 is the sheet's set_document (~0.25 s, the largest)

PatchMixin._patch_refresh_tail
req: R-PE-BENCH.98, R-PE-BENCH.106
in: (none)
out: None
func: step 4's body: refresh_bindings, refresh_issues, _refresh_patch_checks_tab, update_checks_view, set_edit_json_enabled, set_undo_redo_enabled(history_depths), set_entry_edit_json_enabled, in that order.
module: s19_app/tui/app/patch.py
examples: (EX-BC6) LARGE, after step 3 → checks and enable states updated (~0.004 s), then record_done("LARGE")

PatchMixin._run_refresh_steps
req: R-PE-BENCH.98, R-PE-BENCH.99, R-PE-BENCH.106
in: list[Callable] steps; (Callable) None->None on_done
out: None
func: token = _patch_document_token(); run steps[0] now; schedule each next step with `set_timer(STEP_GAP_S, …)`, STEP_GAP_S = 0.1 s (one cue tick), so ticks and keys run and the screen paints between steps — never `call_after_refresh` (no key and no paint between steps: the screen runs its after-refresh callbacks at once when nothing is dirty) and never `set_timer(0, …)` (Textual 8.2.8's `Timer._run` divides by the interval: the step never runs and the hold would never be released) (pilot P1); before a later step, a token different from the first, or `#patch_editor_panel` no longer queryable, → skip the remaining steps as on a token change; ALWAYS call on_done exactly once, including a skip and any step raising; a raise is re-raised after on_done.
module: s19_app/tui/app/patch.py
examples: (EX-BC6) 4 steps → ≥ 1 tick and ≥ 1 paint between each two; on_done once, after step 4
examples: (EX-BC7) `down` queued during step 1 → handled before step 2
examples: (EX-BC14) an Undo between steps 1 and 2 → token changed → steps 2–4 skipped, on_done once

PatchMixin._patch_document_token
req: R-PE-BENCH.106
in: (none)
out: tuple token
func: (id(service.document), tuple(sorted(service.history_depths().items())), id(self.current_file), self._image_write_generation): changes on every document change (stage, Undo, Redo, load) and on every in-place image write (Apply, save-back, Save project commit) that refreshes the views. Apply mutates current_file.mem_map in place, so the object id alone cannot detect it; _note_image_bytes_written's monotonic generation can.
module: s19_app/tui/app/patch.py
examples: (EX-BC14) before and after an Undo → tokens differ; between two steps with no change → equal
examples: (EX-BC14) Apply writes current_file.mem_map in place → the token changes even when id(current_file) and the history depths do not

PatchMixin._note_image_bytes_written
req: R-PE-BENCH.106
in: (none)
out: None
func: as at base (the in-place-write hook: the Split / Join window, end_check_run, the Patch Editor load tail, the Checks screen, the CRC Designer, the Check Editor, the three hex views and the A2L tag table), plus: increment the per-instance monotonic _image_write_generation before that work; all prior hook behaviour is unchanged.
module: s19_app/tui/app/patch.py
examples: (EX-BC14) Apply writes current_file.mem_map in place → the token changes even when id(current_file) and history depths do not

PatchEditorPanel.refresh_entries
req: R-PE-BENCH.98
in: Sequence[object] rows; Union[Mapping[int, int], None, _Unset] mem_map = _UNSET; object document = _UNSET; bool sheet = True
out: None
func: as at base (EntriesMixin.refresh_entries: ledger, strip, tally, card, JSON view; then the sheet's set_document), with sheet False the sheet's set_document is skipped (step 3 runs it).
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-BC6) sheet False → the ledger and the JSON view repainted; the sheet's rows unchanged until refresh_sheet_document
examples: (EX-BC14) the six refresh sites, sheet True (default) → as base

PatchEditorPanel.refresh_sheet_document
req: R-PE-BENCH.98, R-PE-BENCH.106
in: (none)
out: None
func: the sheet's half of refresh_entries: self._sheet.set_document(self._sheet_entries(self._entry_rows), self._mem_map) over the rows the last refresh_entries kept.
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-BC6) after step 2 → the sheet's VAL_BLK_DEF_0001 row shows `●` and New `1 cells`

## Entities

[Data: ArrayBenchSheet._busy_asked]
in: dict[tuple[str, str], float]
desc: the ask time (monotonic seconds) of each asked busy job, keyed by (job word, name); written at the ask, kept while that job stays asked, dropped by the tick when it is no longer the busy job
sequence:
  select: ArrayBenchSheet._enqueue wins → ArrayBenchSheet._busy_tick
  leave: ArrayBenchSheet._busy_tick wins

[Data: ArrayBenchSheet._stage_name]
in: str?
desc: the name of the record stage whose write and refresh run (from the fresh record result to record_done)
sequence:
  stage: ArrayBenchSheet._job_done wins → PatchMixin.on_array_bench_sheet_record_stage_requested → ArrayBenchSheet.record_done

[Data: ArrayBenchSheet._held]
in: bool
desc: Inc 9's record hold (I-9.1); with I-9b.2 it lasts through the stepped refresh

[Data: ArrayBenchSheet._busy_timer]
in: Timer
desc: the 0.1 s cue tick; paused with no asked job, resumed by an ask

[Interface: patch_sheet_win border and title]
desc: `Container#patch_sheet_win` (layout.py:45-47; styles.tcss:2893-2900, :2920-2923): its border and border_title, written by ArrayBenchSheet._busy_tick while the cue shows (I-9b.3)

[Data: ChangeService.document]
in: ChangeDocument
desc: the change document; the write step changes it once, the refresh steps read it as it is when each runs
sequence:
  recordStage: PatchMixin._stage_bench_record wins → PatchMixin._run_refresh_steps → PatchEditorPanel.refresh_entries → PatchEditorPanel.refresh_sheet_document
  undoBetweenSteps: PatchMixin._stage_bench_record → PatchMixin._refresh_patch_history_view wins → PatchMixin._run_refresh_steps (!)

## Edges

[Outside: timer cue tick 0.1 s] ──▶ ArrayBenchSheet._busy_tick
when: a busy job is asked (the timer is resumed by ArrayBenchSheet._enqueue)
ArrayBenchSheet._enqueue ──▶ [Data: ArrayBenchSheet._busy_asked]
[Data: ArrayBenchSheet._busy_asked] ──▶ ArrayBenchSheet._busy_tick
[Data: ArrayBenchSheet._stage_name] ──▶ ArrayBenchSheet._busy_tick
ArrayBenchSheet._busy_tick ──▶ [Interface: patch_sheet_win border and title]
ArrayBenchSheet._busy_tick ──▶ busy_job
ArrayBenchSheet._busy_tick ──▶ busy_title
ArrayBenchSheet._job_done ──▶ [Data: ArrayBenchSheet._stage_name]
ArrayBenchSheet._job_done ──▶ PatchMixin.on_array_bench_sheet_record_stage_requested
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ PatchMixin._stage_bench_record
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ PatchMixin._run_refresh_steps
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ ArrayBenchSheet.record_done
PatchMixin._run_refresh_steps ──▶ PatchMixin._patch_document_token
PatchMixin._patch_refresh_steps ──▶ PatchEditorPanel.refresh_entries
PatchMixin._patch_refresh_steps ──▶ PatchEditorPanel.refresh_sheet_document
PatchMixin._patch_refresh_steps ──▶ PatchMixin._patch_refresh_tail
PatchMixin._refresh_patch_history_view ──▶ PatchMixin._patch_refresh_steps
PatchMixin._stage_bench_record ──▶ [Data: ChangeService.document]
[Data: ChangeService.document] ──▶ PatchMixin._patch_document_token
ArrayBenchSheet.record_done ──▶ [Data: ArrayBenchSheet._stage_name]
ArrayBenchSheet.record_done ──▶ ArrayBenchSheet._busy_tick

## Findings

finding F-9b-1 The prototype's cue could not show the wait between the key and the job start
anchor: ArrayBenchSheet._busy_tick
seen: (proto8 sidecars) the cue keyed on the running job showed nothing for 0.89–2.50 s after the key
cause: the prototype's `_job_running` read `_active_job`, set only when the single-job queue starts the worker (`bench_sheet.py:135`, `:160`); part of the gap is probably the capture driver's own `wait_for_idle` (K1)
effect: a user waiting behind a queued job sees a still window
decision: the cue keys on the ask (BenchState.job, the record queue, the stage name), R-PE-BENCH.94/4; E4 diagnoses K1–K6 (`../E1-slice.md` §5)

finding F-9b-2 Every prototype design froze during the record-stage block
anchor: PatchMixin._run_refresh_steps
seen: (proto8 ROUND.md) P1, P2 and P3 stop during `_stage_bench_record` / `_refresh_patch_history_view` (~0.5–0.9 s; 0.674 s after FX9d)
cause: the write and the whole refresh run in one UI-thread call (`app/patch.py:398-441`, `:654-728`); no frame is painted until it returns
effect: the cue the operator requires (P-127) would stop exactly when the app looks frozen
decision: O-E — the refresh as 4 steps chained by call_after_refresh, the hold released after the last (I-9b.2), skipped on a document change (R-PE-BENCH.98, .106)

finding F-9b-3 Inc 9's graph is stale on two nodes after FX9c/FX9d
anchor: busy_job
seen: (extractor, clone of `09001bbc`) `ArrayBenchSheet._run_job` has `snapshot`, `edit` not in Inc 9's node; `bench_submit` returns `ArrayBenchSheet.BenchApplyRequested`, Inc 9's node says `Message`
cause: FX9c/FX9d changed the code after Inc 9's E2 and did not bring the graph up to date
effect: the next layered extraction reports the drift again
decision: not this slice; recorded for the batch-end extraction (skill, Batch end)

finding F-9b-4 call_after_refresh gives the loop no turn between two refresh steps
anchor: PatchMixin._run_refresh_steps
seen: (pilot P1, merged base, quiet rtx, 3 runs each) three 0.3 s UI-thread steps chained by call_after_refresh: gap 7–13 ms between steps 1 and 2, 0 paints, and a `down` sent during step 1 handled only after step 3 (3/3); with `set_timer(0.02, …)` the key still waits for the chain's end (3/3); with `set_timer(0.1, …)` the key is handled between steps 1 and 2 and ≥ 1 paint with a new title lands in every gap (3/3)
cause: `Screen._invoke_later` runs the callbacks at once from `_on_idle` when nothing is dirty, and a queued key needs about 0.08–0.1 s of free loop (three queue hops: app, body, app bindings) after a UI block
effect: the design's call_after_refresh chain would freeze the cue and the keys exactly as base does (R-PE-BENCH.98, .99 RED)
decision: DF-04 (a) fix to the design: STEP_GAP_S = 0.1 s via `set_timer`; `set_timer(0, …)` is forbidden (P1 run 1: the timer task dies on a division by its zero interval, the chain stops after step 1, `out/p1-run1.txt`)

finding F-9b-5 EDIT is a style string, not a colour
anchor: ArrayBenchSheet._busy_tick
seen: (pilot P2 run 1) `styles.border = ("round", EDIT)` raised `ColorParseError: failed to parse 'bold #f5c26b' as a color`
cause: `definition_bench_view.EDIT = "bold #f5c26b"` (`:54`) is a Rich style
effect: the cue would raise on its first tick
decision: DF-04 (a): the busy colour is `Style.parse(EDIT).color` (#f5c26b); no new literal (ED-1 kept)

finding F-9b-6 clear_rule("border") clears nothing, and a clear needs a refresh
anchor: ArrayBenchSheet._busy_tick
seen: (pilot P2) `clear_rule("border")` returns False and the inline amber stays; clearing the four edge rules restores the computed stylesheet border (rule colour, or the accent with the focus within) but the painted corner stays amber until a refresh; with `refresh()` the painted border is the stylesheet's in both focus states, and `:focus-within` works after it; setting `("round", rule colour)` back freezes the rule colour and loses the accent
cause: Textual stores the `border` shorthand as four edge rules; `clear_rule` does not schedule a repaint
effect: the idle look of R-PE-BENCH.95, .100, .101, .102 would never return
decision: DF-04 (a): clear the four edge rules, then `refresh()` the window

finding F-9b-7 A later-step stall does not control the key sent at the write
anchor: PatchMixin._run_refresh_steps
seen: (E5 control copies) the roster's 1.3 s sheet-step stall left .99/1 GREEN at 0.662 s; moving the same stall to the first serialize step made the existing AT RED at 1.585 s; `evidence/e5/runs/control-m9b-residuals.txt`, `control-corrected.txt`
cause: the key sent at the write is handled in the gaps before the later sheet step, so that stall starts too late to control its latency
effect: the original negative control did not test R-PE-BENCH.99's key-at-write bound
decision: DF-04 (a): the .99 negative control names the first refresh step (serialization); the requirement and 1.0 s bound are unchanged
