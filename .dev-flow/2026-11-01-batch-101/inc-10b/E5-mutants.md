# Inc 10b — E5 mutant table (views that follow in-place writes)

Batch 2026-11-01-batch-101, increment 10b. Executor: E5 unit (single-unit mutant run).
Base: origin/main `6f1743c1ad54ff7db89e8fcd4e96266414950f42` (holds Inc 10a) with the
Inc 10b product-and-test diff applied onto it (the 4 files of
`git diff --binary 6f1743c -- s19_app tests docs README.md` of the local tree at head
`08ed10f`: `s19_app/tui/app.py`, `s19_app/tui/segment_split_view.py`,
`tests/test_b101_inplace_views.py`, `tests/test_id_registry.py`).

All runs on the LAN Linux laptop only (operator rule; nothing importing `s19_app` ran
on the Windows PC). The baseline first ran the union of every row's nodes on the
unmutated copy: **19 passed, 0 failed** — all GREEN before any mutation (the QC-TM-10b-1
`serial_timing` node is not targeted by any row and was already measured GREEN at E4,
`int-05.txt`: 0.023 s against 1.000 s, 97.7 %). Each new mutant was applied **one at a
time** in a fresh copy of the base worktree (`<HOME>/work/s19_i10bmut_m<N>`, `cp -a`),
the mutation was verified to have landed (a non-unique edit site aborts the run), only
the row's nodes were run from the copy (`-p no:cacheprovider -q -rf --tb=line`,
cwd = the copy, `s19_app.__file__` printed from inside the copy = the copy), and the
copy was then deleted. Transcripts: `evidence/inc-10b/mut-01.txt` … `mut-08.txt` (each
starts with the base commit, the mutation diff and the redacted `s19_app.__file__`;
home folder → `<HOME>`, account name → `<USER>`, host address → "LAN Linux laptop",
`pytest-of-<name>` → `pytest-of-<user>`).

The E4 integration already ran the repaint-sign negative controls one mutant at a time
(`int-06.txt`, `int-06a/b.txt`): M-A, M-B, M-C1–C3, M-D, M-F — 0 survivors. They are
reused as rows here (their transcripts live in the same evidence folder). The rows
run fresh at E5 are M1–M8: the notice's three calls (hex, A2L, Split / Join), the
enrichment-cache clear, the displayed / hidden disarm guards, the `id()` re-point and
the window bisect. File: **W** `tests/test_b101_inplace_views.py`.

| M | Row | Mutation (file · function) | Nodes | Result | Killing node(s) / failure line | Transcript |
|---|---|---|---|---|---|---|
| M-A | R-A2L-049, .105 | `app.py` `_repaint_a2l_tag_cells`: replaced by the clear-and-refill `update_a2l_tags_view(...)` + `return` | W `049_1_…`, `049_2_…`, `105_1_…` | KILLED | `049_1`, `049_2` — `the first shown row moved: scroll_y 0, was 30`; `105_1` — `the cursor moved to row 0` | int-06.txt |
| M-B | R-TUI-004.8 | `_refresh_hex_views_after_write`: `_reset_scroll_to_top("#hex_scroll")`; `update_alt_hex_view(..., reset_scroll=True)`; `update_mac_hex_view(..., reset_scroll=True)` | W `004_8[main]`, `[a2l]`, `[mac]` | KILLED | `004_8[main]` — `the scroll changed: (0, 0), was (10, 40)`; `[a2l]`, `[mac]` — `(0.0, 0), was (0.0, 40)` | int-06.txt |
| M-C1 | R-TUI-004.9 | `_refresh_hex_views_after_write`: `update_hex_view(self._hex_view_rows()[self._hex_window_start])` | W `004_9_1_…` | KILLED | `004_9` — `#hex_view: marked lines []` | int-06.txt |
| M-C2 | R-TUI-004.9 | `_refresh_hex_views_after_write`: `update_alt_hex_view(rows[start] if start is not None else None, start_row=start)` | W `004_9_1_…` | KILLED | `004_9` — `#alt_hex_view: marked lines []` | int-06.txt |
| M-C3 | R-TUI-004.9 | `_refresh_hex_views_after_write`: `update_mac_hex_view(rows[start] if start is not None else None, start_row=start)` | W `004_9_1_…` | KILLED | `004_9` — `#mac_hex_view: marked lines []` | int-06.txt |
| M-D | R-SEG-PREV.22 | `segment_split_view.py` `note_image_bytes_written`: displayed branch `self._bump()` → `self.refresh_window()` | W `prev_22_1_…` | KILLED | `prev_22_1` — `the focus moved from #sje_export to #sje_table` | int-06b.txt |
| M-F | R-A2L-106 | `_refresh_a2l_values_after_write`: the re-point replaced by `_refresh_a2l_filtered_tags(preserve_anchor=True)` | W `106_1_…` | KILLED | `106_1` — `VALUE_0001 paints None, expected ('147', '147')` | int-06.txt |
| M1 | R-TUI-004.7 | `_note_image_bytes_written`: `_refresh_hex_views_after_write()` call removed | W `004_7_1_…`, `_2_…`, `_3_…` | KILLED | `004_7_1` `#hex_view` / `004_7_2` `#alt_hex_view` / `004_7_3` `#mac_hex_view` — `row 0x8010 paints 'FF FF FF FF FF FF FF FF', expected 'FF FF FF AA FF FF FF FF'` | mut-01.txt |
| M2 | R-A2L-048, .106 | `_note_image_bytes_written`: `_refresh_a2l_values_after_write()` call removed | W `048_1_…`, `_2_…`, `_3_…`, `106_1_…` | KILLED | `048_1`/`106_1` — `VALUE_0001 paints ('108', '108'), expected ('147', '147')`; `048_2`/`048_3` — `expected ('85', '85')` | mut-02.txt |
| M3 | R-SEG-PREV.21, R-SEG-EXP.15 | `_note_image_bytes_written`: `split_window.note_image_bytes_written()` → `pass` | W `prev_21_1_…`, `exp_15_1_…`, `exp_15_2_…` | KILLED | `prev_21_1` — `the band is [('data', 8), ('fill', 11), ('conflict', 1), …]` (stays `conflict 1`); `exp_15_1`/`exp_15_2` — `the commit did not disarm` / `the reopen shows an armed confirm` | mut-03.txt |
| M4 | R-A2L-048, .106 | `_refresh_a2l_values_after_write`: `self._a2l_enriched_key = None` removed (cache kept) | W `048_1_…`, `_2_…`, `_3_…`, `106_1_…` | KILLED | `048_1`/`106_1` — `VALUE_0001 paints ('108', '108'), expected ('147', '147')`; `048_2`/`048_3` — `expected ('85', '85')` | mut-04.txt |
| M5 | R-SEG-EXP.15/1 | `note_image_bytes_written`: displayed branch `self._bump()` → `self._sync()` (re-plans, keeps the arm) | W `exp_15_1_…` | KILLED | `exp_15_1` — `the commit did not disarm: … '⚠ GUARD  1.00 MiB span — e again to confirm'` | mut-05.txt |
| M6 | R-SEG-EXP.15/2 | `note_image_bytes_written`: hidden branch `self._armed = False` → `pass` (arm survives a hidden write) | W `exp_15_2_…` | KILLED | `exp_15_2` — `the reopen shows an armed confirm: … '⚠ GUARD  1.00 MiB span — e again to confirm'` | mut-06.txt |
| M7 | R-A2L-106, .049 | `_refresh_a2l_values_after_write`: the `id()` re-point replaced by `self._a2l_filtered_tags = list(new)` (all tags, filter dropped) | W `049_2_…`, `106_1_…` | KILLED | `049_2`, `106_1` — `the A2L Explorer did not show its tag table` (`CellDoesNotExist: No cell exists at Coordinate(row=…, column=0)`: the repaint walks a page of the 462-tag list against the filtered table) | mut-07.txt |
| M8 | R-TUI-004.8 | `_refresh_hex_views_after_write`: the A2L and MAC `start_row=start` bisect → `start_row=None` | W `004_8[main]`, `[a2l]`, `[mac]` | KILLED | `004_8[a2l]`, `[mac]` — `the shown window moved: first rows [0x00000000, 0x00000010]`; `004_8[main]` GREEN (the mutation touches only the A2L/MAC paths; the main window is kept by 10a's no-focus clamp) | mut-08.txt |

## Score

- Total mutants run: **15** (7 reused from E4's int-06 controls + 8 run fresh at E5; no row skipped).
- Killed: **15**.
- Survived: **0**.
- Mutation score (killed / total): **15 / 15 = 100%**.

### Notes on the one row with a GREEN node

- **M8** kills the A2L and MAC arms of R-TUI-004.8 (the bisect that re-anchors the
  shown window to the first visible address): `004_8[a2l]` and `[mac]` fail `the shown
  window moved: first rows [0x00000000, 0x00000010]` — the view re-renders from the
  first view row. `004_8[main]` stays GREEN and is not a gap: the main pane keeps its
  window through `update_hex_view()`'s no-focus clamp (Inc 10a I-3), a path this
  mutation never touches. The two halves of the "shown window" definition are each
  pinned alone — the scroll half by M-B, the first-row half by M8.

### Not-a-mutant (coverage gaps, ruled as in `E4-integration-notes.md` "For E5")

- **A10-08** — reverting the Check Editor block to `except Exception: return` has no
  node: no case mounts the app without `#check_editor_panel`. Declared, not run.
- **S-8 / D-10b-3** — `_update_a2l_summary_buffer()` and the summary-label recompute in
  `_repaint_a2l_tag_cells` read no byte value (`_a2l_summary_start` is 0 on every product
  path and the `tags <a>-<b> / <T>` span is unchanged by an in-place write), so skipping
  them has no observable. Not a mutant.
- **R2-7** — the widening example (a written Raw value wider than its column,
  `update_width=True`) has no case in `02-test-cases.md`; the graph example has no row.
  For the audit.
- **No-file / no-A2L guards** — `if not self.current_file: return` and
  `if not self.current_a2l_data: return` have no observable (an in-place write already
  requires a file, and with no A2L the recompute/repoint yields an empty list that the
  empty-table early return of `_repaint_a2l_tag_cells` absorbs). Not mutants.
- **QC-TM-10b-1** is a cost node, not a coverage item; no mutant targets it. Verified at
  E4 (`int-05.txt`).

### Reuse of the int-06 controls

M-A, M-B, M-C1–C3, M-D and M-F were run at E4 integration (`int-06.txt`,
`int-06a.txt`, `int-06b.txt`) one mutant at a time on the final integrated tree, which
equals this record's base-plus-diff tree (the E4 index tree `9cf01b02` and head `08ed10f`
carry the same 4 product/test files). Their verdicts — every target RED at its clause,
0 survivors — carry over unchanged, so they are listed here as rows and not re-run.
M1–M8 complete the table: each call the notice makes, the cache clear, the two disarm
guards, the `id()` re-point and the window bisect.
