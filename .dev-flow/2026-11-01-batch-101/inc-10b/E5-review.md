# Inc 10b — E5 independent review (code and security lens)

Batch 2026-11-01-batch-101, increment 10b. Reviewer: code-reviewer, independent of the implementers (DeepSeek v4 Pro, G1 / G2), the tester (W) and the integrator. One pass with both lenses: code (correctness, simplicity, reuse, conventions, tests) and security (stale bytes shown or exported, reach outside the work area, painted names).

Scope: `git diff 569e446 -- s19_app` (`s19_app/tui/app.py` +209 / −5, `s19_app/tui/segment_split_view.py` +14) and `git diff 569e446 -- tests` (`tests/test_b101_inplace_views.py` new, 1411 lines; `tests/test_id_registry.py` 272 → 273) at head `08ed10f` of branch `b101-inc10` (worktree `<HOME>/Github/s19_app-b101-inc10`). I read the full diff, then read it against `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md`, `E1-slice.md`, `codewire/graph-inc10b.md` (I-1, I-7, the 10a interfaces), `E4-integration-notes.md` (I-D1 … I-D10, O-1), `E4-tester-w-notes.md`, the implementer notes and `../inc-10/E3-rulings.md` (S-1, A10-04, S-7 / A10-09, A10-08, A10-12, AR2-7) with `../inc-10/E3-architect.md` A10-12. I also read the code the change relies on: the three writers and their hook calls, `ChangeService.apply` / `_restore_journal` / `rederive_for_save` / `adopt_rederived` / `save_patched` / `undo` / `redo`, `apply_change_document`, `_compute_a2l_enriched_tags`, `_replace_current_a2l`, `_invalidate_a2l_view_cache`, `update_a2l_view`, `_refresh_a2l_filtered_tags`, `_filter_a2l_tags`, `update_a2l_tags_view`, `_build_a2l_table_cells`, the staged load (`_apply_prepared_load`, `_step_*`), `_apply_unload`, the three hex renderers, `_hex_view_rows`, `SplitJoinWindow.refresh_window` / `_bump` / `_sync` / `action_export`, and Textual 8.2.8's `DataTable.update_cell` and `App.call_from_thread`.

I ran nothing that imports `s19_app` (operator rule). Statements about test runs come from the integrator's transcripts `../evidence/inc-10b/int-01` … `int-07` and `red-01-tester-w-base.txt`. To tie them to this head I rebuilt the staged tree with a temporary index (`git read-tree 09b4808`, then `git diff --binary 09b4808 HEAD -- s19_app tests docs README.md | git apply --cached`, `git write-tree`): it gives `9cf01b0259cf…`, the index tree int-07 prints, and the working tree equals HEAD for `s19_app`, `tests` and `docs`.

Severity scale: the project's HIGH / MAJOR / MINOR (HIGH = correctness bug, data loss or a test that gives false confidence; MAJOR = a defect or gap that must be answered before the increment advances; MINOR = recommendation).

## Verdict

**FAIL — BLOCK-UNTIL: R-1.**

The product code is correct on every in-place write route, and it matches the graph. I found no route that writes the image without calling the hook. The three hex panes, the A2L value column and Split / Join follow the written bytes. The tag table keeps its listing, page, cursor and scroll (I-7). A hidden Split / Join window only disarms. Nothing new reads or writes outside the work area.

The block is R-1, a measurement gap. E3 A10-12 asked for the per-write A2L refresh to be timed on a *large* A2L, because 462 tags (case 08) did not answer the question. QC-TM-10b-1 timed 462 tags again: every synth release case carries the same 462-object A2L (I-D8). Meanwhile the repo ships a 220,040-object A2L, the batch-100 freeze benchmark. On that file the refresh runs a full enrichment on the UI thread at every apply, save-back and commit. Until that cost is measured, I-D8's conclusion that no fallback is owed is unsupported.

R-2 … R-6 are MINOR recommendations.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | Code = graph | **I-1** `segment_split_view.py:1752-1764`: displayed → `_bump()` (disarm + one `_sync`, `:2025-2027`); hidden → `_armed = False` only; no focus, no selection reset, no `refresh_window`. **I-7** `app.py:21009-21089`: reads `_a2l_filtered_tags` / `_a2l_window_start`; calls only `get_cell_at`, `update_cell_at(..., update_width=True)` and `summary_label.update`; no `clear`, `move_cursor`, `scroll_to`. Textual 8.2.8's `update_cell` (`_data_table.py:897-913`) sets the cell, marks widths and refreshes; it posts no highlight message, so the detail card keeps its tag. Widths only grow. **Hook** `app.py:18737-18814`: Inc 6's body is unchanged up to the Check Editor block, which uses the `checks = None` idiom (D-10b-5), and is followed by the three notices, each outside its `try`. **Hex** `:18816-18864` and **A2L** `:18866-18913` match their nodes. `Coordinate` and `bisect_left` are imported locally (R2-7, the house's form). | executed (read) |
| 2 | Every writer of the image bytes | The live `mem_map` is written in three places: `apply_change_document` (`changes/apply.py:341`), `_restore_journal` (`change_service.py:1846`) and `adopt_rederived` (`:2364`). Their app routes are the apply (`app.py:4906`, hook `:4972`), the save-back (`save_patched` → `adopt_rederived` `change_service.py:2589`, hook `app.py:5105`) and the Save project commit (`adopt_rederived` `app.py:13394`, hook `:13400`). `rederive_for_save` works on a copy. **No product route is missed.** Undo / redo (`change_service.py:994`, `:1030`; `app.py:5444`, `:5479`) swap the document and write no byte. The CRC write uses `inject_crcs` on a copy (`operations/crc.py:1392`). The Check Editor's `write_doc` writes a check document. The flow and variant executions build their own `loaded` image (`flow_execution_service.py:352`, `variant_execution_service.py:2541-2551`). Save project emits from `request.image.derived` (`app.py:12888`). Every write lands on an address already in `mem_map` (`apply.py:337-341` INSIDE only; `adopt_rederived` keeps `address in mem_map`), so `len(mem_map)` and with it the enrichment key `(_a2l_view_generation, _image_generation, len)` are unchanged by a write. That is why the explicit `_a2l_enriched_key = None` is needed. | executed (read, grep) |
| 3 | The `id()` re-point (O-1) | Every writer of `_a2l_filtered_tags` (`app.py:14327`, `:18909`, `:20676`, `:20830`, `:20882`) and of `_a2l_enriched_tags` (`:14325`, `:19162`, `:20674`, `:20748`, `:20761`, `:20881`). On every product path, `_replace_current_a2l` empties both on an A2L attach, a project install and an image install that carries an A2L (`:19132-19136`). A recompute outside a write is followed by `update_a2l_view`'s re-filter (`_apply_unload` `:18122`, `_step_a2l` `:19230`). `_filter_a2l_tags` keeps the same dict objects, and `enrich_tags_and_render` keeps the A2L's tag order (`a2l_service.py:19-24`), so "position in `old`" names the same tag. **The invariant holds on the paths read**, as O-1 says. If it breaks, the result is a `KeyError` that exits the app, and one narrow window can break it (R-2). | executed (read) |
| 4 | Hex panes keep window, scroll, marker | The main view calls `update_hex_view()` with no focus: one clamp of `_hex_window_start`, the marker kept (`app.py:20231-20233`), no scroll reset. For the A2L / MAC views, `_alt_first_visible_address` / `_mac_first_visible_address` is `rows[effective_start]` of the last render, and an in-place write changes neither `row_bases` nor `_hex_view_rows`' key, so `bisect_left` returns the same index. A changed row list degrades to the nearest row, and `update_*_hex_view` clamps `start_row` (`:20339-20341`). Hidden views are re-rendered too (D-10b-2). Mutants M-B and M-C1 … C3 are RED (int-06). | executed (read; int-06 read) |
| 5 | Split / Join | Hidden: only the arm is cleared, and the next open re-syncs in `refresh_window` (`segment_split_view.py:1737`). Displayed: `_bump()`; `_sync` moves no focus. The export reads live bytes at the `e` and re-runs the conflict check (`segment_split_view.py:2106-2160`), so with the arm cleared no confirm given for other bytes reaches a file. | executed (read) |
| 6 | Cost on a large A2L (QC-TM) | Not established: see R-1. | not-run (462 tags only) |
| 7 | Security | **No new I/O**: no file, path, clipboard or process is touched, so nothing new reaches outside the work area. **Names**: the repaint writes the cells `_build_a2l_table_cells` builds through `safe_text` (markup-safe), the same cells the load painter writes. Tag names are not stripped of Cf characters there, which is pre-existing, identical to base and of the E3 S-6 backlog class; 10b adds no name sink. **Stale bytes**: fixed in the three panes, the A2L values and Split / Join. Two peek panes still show pre-write bytes (R-3). Nothing that exports reads a stale copy. | executed (read) |
| 8 | Tests: oracles, base RED, can they fail | The oracles are the painted state (hex Statics, table cells, summary, card, scroll offsets, the band blocks, files on disk), each read after a positive wait. 10 nodes are RED on base at their own clause; the 8 repaint-sign nodes are RED under their own controls (M-A, M-B, M-C1–C3, M-D) and R-A2L-106/1 under M-F (int-06, 0 survivors). I-D5's fix makes R-SEG-PREV.22/1 able to fail (int-06a vs int-06b). R-SEG-PREV.21/2 is a declared standing guard. No node asserts less than its case's expected result. The I-D3 / I-D4 corrections are documented and keep the thresholds. Gaps: R-4. | executed (read) |
| 9 | Edited existing nodes | `EXPECTED_SCANNED_TEST_FILES` 272 → 273 with its history line (measured, int-01a). No assertion is weakened. | executed (read) |
| 10 | Reuse, simplicity, conventions | The change reuses `_build_a2l_table_cells`, `_a2l_tag_row_severity`, `_severity_style`, `_get_window_bounds`, the 10a renderers and `_bump`. Docstrings follow the house sections. One copied block (R-5) and one stale sentence (R-6). | executed (read) |

## Findings

### R-1 — the per-write A2L refresh is unmeasured on a large A2L; A10-12 is not discharged  [MAJOR · QC gap / false confidence · blocks]
- **Where:**
  - `s19_app/tui/app.py:18905-18907`: `_a2l_enriched_key = None`, then `_compute_a2l_enriched_tags()`, a full `enrich_tags_and_render` over every tag on the UI thread.
  - `:18808`: the hook calls it on every apply, save-back and commit. It runs whether or not the A2L Explorer is shown, and on an Apply with no image loaded (the hook is unconditional at `:4971-4972`).
  - The node: `tests/test_b101_inplace_views.py:1363-1411` (`LARGE_SIZE_MB = 10.0`, 462 tags).
  - The record: `02-test-cases.md` QC-TM-10b-1 and `E4-integration-notes.md` I-D8.
- **Scenario:**
  - The operator works with `examples/case_06_large_nested_a2l/firmware.a2l` (37.7 MB, 220,040 `CHARACTERISTIC` / `MEASUREMENT` blocks by grep) or with `examples/case_00_public/software_a.a2l` (5.2 MB, 13,990), and presses Apply.
  - The batch-100 record `inc-12b/codewire/baseline-12b.md:342` puts the main-thread share of `update_a2l_view` for case_06 at about 3.5 s (HLR-176's declared freeze, accepted for the one-off attach). The refresh runs that function's enrichment step on every write.
  - A linear extrapolation of 0.023 s / 462 tags gives about 0.7 s at 13,990 tags and about 11 s at 220,040. This is crude and not measured.
- **Why it matters:**
  - E3 A10-12 said: "measured only for 462 tags (case 08) … the cost on the largest A2L the project supports is not stated. Measure at E4 … with a large A2L." The E4 measurement is again 462 tags, because every `tools/synth` release case carries the same inventory (I-D8's own residual).
  - The 97.7 % margin therefore answers a question A10-12 had already set aside. I-D8's "no fallback is owed" rests on that answer.
  - If the bound fails, every write in a large-A2L session freezes the UI, the defect class US-167 / HLR-176 removed from loads.
- **Fix:**
  - On the LAN host, run QC-TM-10b-1 again on case_06 (its `firmware.s19` + `firmware.a2l`, one byte written inside the image). Add `software_a.a2l` if an image that matches it exists. Record the tag count and the time.
  - If the time is above `timing_bound(1.0)`, rule the D-10b-6 fallback: mark the values stale while the A2L Explorer is hidden and recompute on its show. A cheaper alternative is to recompute only the tags whose `[address, address + length)` overlaps the written spans; the service knows them from its journal and document spans.
  - Whatever the result, return early when `current_file` is `None`: an Apply with no image wrote nothing.
- **Discharge:** the case_06 figure in `02-test-cases.md` and int-05's successor, plus the orchestrator's ruling. I re-read the record.

### R-2 — a broken re-point invariant exits the app inside the write hook, and skips the disarm  [MINOR · robustness]
- **Where:** `app.py:18908-18911` (`new[position_by_tag[id(tag)]]`), the hook order `:18807-18814`, and the callers: `:4972` (after the apply's `try … except (ValueError, KeyError)`), `:5105`, and `:13400` (`_on_project_saved` re-raises by design, CR12a-1).
- **Scenario:** the one window I found that can break O-1 (not reproduced):
  - An image reload whose attached A2L re-parse returns no data. `loaded.a2l_data` is falsy (`:19132`), so `_replace_current_a2l` is skipped and the old filtered dicts stay.
  - The load's busy run ends from the worker (`call_from_thread(end_busy)`, `asyncio.run_coroutine_threadsafe`), while `_step_a2l` still waits behind two `call_later` hops in the message queue.
  - An Apply processed in that window recomputes at `:4842`: the image generation has changed, so the cache misses. The re-point then raises `KeyError`.
- **Why it matters:**
  - Nothing catches the error, so Textual exits the app after the bytes were written in memory, and the session's unsaved work is lost.
  - The Split / Join notice runs last. Any raise in the two cosmetic repaints therefore skips the security-relevant disarm (S-7).
- **Fix:**
  - Make the re-point total: on any `position_by_tag.get(id(tag))` miss, call `self._refresh_a2l_filtered_tags(preserve_anchor=True)` and return. The listing was already stale, and the load chain would re-filter anyway.
  - Run the Split / Join notice before `_refresh_hex_views_after_write()`. This needs a graph ruling (I-1's position).

### R-3 — the Issues and Checks "Hex Peek" panes keep pre-write bytes  [MINOR · design-gap (security lens), needs a ruling]
- **Where:**
  - `#issues_hex_pane`: `app.py:17140-17186`, repainted only by `on_issue_row_selected` (`:17540-17561`).
  - `#checks_hex_pane`: `:17587-17638`, repainted only by `on_check_row_selected` (`:17585`).
  - The hook touches neither pane.
- **Scenario:**
  - On the Issues window, select an issue at `0x8013`; the peek paints `FF`. Apply `0x8013 = AA`, then return to Issues: the peek still paints `FF` at `0x8013`, while the main, A2L and MAC panes paint `AA`.
  - On the Checks screen, Inc 6 ends the run at a write and the screen reads `no run yet`, but its peek keeps the bytes of the old selection.
- **Why it matters:**
  - This is the S-1 class: bytes painted that the image no longer holds.
  - R-TUI-004.7 names three views, so the rows are met, but the security intent "stale bytes can no longer be shown" holds only for those three.
  - Nothing exports these panes.
- **Fix (ruling):** fold or backlog.
  - Fold: remember the peeked address in the two helpers and re-render both from the hook, or reset them to their placeholder in the hook.
  - Backlog: list it beside E3 S-6.

### R-4 — the A2L nodes all run on page 1; a page-offset defect in the repaint survives  [MINOR · test-gap]
- **Where:** the A2L nodes `tests/test_b101_inplace_views.py:681-914`. Case 08 has 462 tags at `a2l_tags_page_size` 200 (`app.py:2820`), which is 3 pages, and every node stays at `_a2l_window_start` 0. In the product: `app.py:21060` (`tags[absolute_index]`) and `:21079` (`a2l:{absolute_index}`).
- **Scenario:**
  - A regression to `tags[i]` would repaint pages 2 and 3 with page 1's tags. The comparison sees every cell differ and rewrites all 16, so the rows show other tags' names and values under a kept cursor.
  - A regression to the key `a2l:{i}` would map the shown rows to the wrong tags for the card, the jump and `d`.
  - Both survive every node.
  - Also with no node: R2-7's widening (a written value wider than its column, `update_width=True`, graph example only), and A10-08 (the hook with no `#check_editor_panel`). A10-08 cannot be reached through the product, because every panel is composed at startup.
- **Fix:** add one node:
  - Page to 2 with `+` and pick a page-2 tag that sits in the image.
  - Apply a byte at its address.
  - Assert its Raw / Physical cells, the summary's `tags 201-400 / 462`, the row names and the cursor all unchanged.
  - Optionally add an R2-7 node: write a value whose text is wider than the Raw column's widest cell, and assert the painted cell is not clipped.
  - Accept A10-08 as "no product route" in the coverage audit.

### R-5 — the repaint copies `update_a2l_tags_view`'s bounds, styling and summary text  [MINOR · duplication]
- **Where:** `app.py:21046-21089` against `:20965-20999`. Copied: the page bounds, the issue-severity map, the per-row style loop and the summary label's f-strings, character for character.
- **Why it matters:** a later change to the summary format or the styling rule in one painter drifts from the other. Only the `tags a-b / T` span is checked (R-A2L-106/1).
- **Fix:** extract `_a2l_tags_summary_text(start, end, total, page_size, tags) -> Text` and `_styled_a2l_cells(tag, severity_map)`, and use both from both painters. The slice keeps `update_a2l_tags_view` unchanged, so put this in the backlog.

### R-6 — the hook's docstring still says a missing panel is a no-op  [MINOR · doc]
- **Where:** `app.py:18749-18751`: "A not-yet-mounted panel (headless unit path) is tolerated as a no-op".
- **Why it matters:** the new notices query `#hex_view`, `#alt_hex_view`, `#mac_hex_view`, `#a2l_view`, `#a2l_tags_list` and `#a2l_tags_summary` without a guard. On an unmounted app with a file loaded, the hook now raises `NoMatches`. In the running app all six are composed at startup (`:3534`, `:3545`, `:8567`, `:8572`, `:8593`, `:8678`), so only the sentence is wrong.
- **Fix:** say which panels are guarded (Patch Editor, CRC Designer, Check Editor, Split / Join). Say that the hex views and the A2L table are composed at startup and queried without a guard.

## Evidence checklist

- ✓ Diff read in full: `app.py:18737-18913`, `:21009-21089`; `segment_split_view.py:1752-1764`; `tests/test_b101_inplace_views.py:1-1411`; `tests/test_id_registry.py:189-190`.
- ✓ Correctness pass (edge, `None`, error paths): no file, no A2L, empty filtered list, unset first-visible address, hidden window; the `KeyError` arm (R-2).
- ✓ Simplicity pass: no premature abstraction; one copied block (R-5).
- ✓ Reuse checked against existing helpers (check 10).
- ✓ Tests reviewed for intent: base RED, repaint sign, mutants, the I-D5 fix; gaps in R-4.
- ✓ Verdict explicit: FAIL — BLOCK-UNTIL R-1. No HIGH.

## Packet §4b cell

`code-reviewer · FAIL (BLOCK-UNTIL: R-1) · no HIGH; R-1 (MAJOR) open — QC-TM-10b-1 owed on case_06 (A10-12), then the D-10b-6 ruling; R-2 … R-6 MINOR, recommendations`
