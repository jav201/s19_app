# Inc 12b — E5 mutant table (Flow Builder / Flow Execution: every widget shown in some state)

Batch 2026-11-01-batch-101, increment 12b. Executor: E5 unit (single-unit mutant run, DeepSeek).
Base commit: `2f54c7dea27d826483e5c5e596421b8b3a68bb2f` (origin/main; the Inc 12b integrated tree is applied onto it).

All runs on the LAN Linux host only (operator rule; nothing importing `s19_app` ran on the
Windows PC). Each mutant was applied **one at a time** in a fresh copy of the base copy
(`<HOME>/work/s19_i12bmut`, a detached worktree at `2f54c7d` with this tree's
`git diff --binary 2f54c7d -- s19_app tests docs README.md` applied), the mutation was
verified to have landed (`diff -u` + a grep; `s19_app.__file__` printed inside the copy and
must read `<HOME>/work/s19_i12bmut_mNN/s19_app/__init__.py`), only the row's guard nodes were
run from the copy (cwd = the copy), and the copy was then deleted. Every row's guard nodes were
confirmed GREEN on the unmutated base first: **20 passed in 134.23s** (`mut-00.txt`).

Sources: the M1–M7 mutant table in `E4-integration-notes.md` (Negative-control column of
`01-requirements.md` plus the E3 S-1/S-2 addenda and I-D4's span-clause control). M5 is the
R-TUI-059.25 negative control "restore any one of the five removed widgets" — run once per
widget (five copies). The four S-2 markup-literal nodes are the card refs (`_card_rows`) and
the S-1 node is the `_KIND_OPTIONS` membership guard.

| M | Row | Mutation (`flow_screens.py`) | Nodes | Result | Killing node(s) / failure line | Transcript |
|---|---|---|---|---|---|---|
| M1 | R-FB-ADD.1/2 neg (S-1) | `on_button_pressed`: the `_KIND_OPTIONS` guard removed | `test_r_fb_add_1_2_a_press_naming_no_kind_changes_nothing` | KILLED | `test_b101_flow_shown_widgets.py:319` — `assert '✓ CHECK' in '· BOGUS'` (the stray `flow_palette_bogus` press stored the kind unchecked) | `mut-01.txt` |
| M2 | E3 S-2 (b) | `_card_rows`: `scrub` interprets markup after `safe_text` (`Text.from_markup(safe_text(s).plain).plain`) | AT-088b (`test_at088b_check_ref_label_renders_literally`), AT-B94-18 (`test_at_b94_18_hostile_names_render_literally`), AT-B97-08 (`test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject`), `test_at_flow_block_label_markup_safe` | KILLED ×4 | AT-088b:546 `sensor[31mx`; b94:427 `_evil[red]` gone; b97:1618 `…31m_evil[red]1m8;;u`; directionb:5855 `evil.s19` (the literal brackets left the card) | `mut-02.txt` |
| M3 | I-D4 (span clause) | `_card_lines`: the value row keeps its text but gains a red span over the first half of the input | the same 4 | KILLED ×4 | the injected span cuts the input text: AT-088b:552 / b94:434 / directionb:5860 `cutting != []`; AT-B97-08:1620 `_foreign == ['#800000 | ansi_red']` | `mut-03.txt` |
| M4 | E3 S-2 (a) | `nul_add_refusal` returns `None` | the 9 params of `test_tc_b97_62_nul_pasted_into_the_add_form_is_refused`, AT-B97-08 | KILLED ×10 | each arm `a NUL <kind> <field> was added (1 -> 2)`; AT-B97-08 `(4, 5, [])` (the pasted NUL added a card, no refusal line) | `mut-04.txt` |
| M5a | R-TUI-059.25 neg | restore `#flow_help`, hidden at mount | `test_r_tui_059_25_1_every_flow_builder_widget_is_shown_in_a_state` | KILLED | `mounted and never shown: ['flow_help']` | `mut-05.txt` |
| M5b | R-TUI-059.25 neg | restore `#flow_canvas`, hidden at mount | the same | KILLED | `mounted and never shown: ['flow_canvas']` | `mut-06.txt` |
| M5c | R-TUI-059.25 neg | restore `#flow_blocks`, hidden at mount | the same | KILLED | `mounted and never shown: ['flow_blocks']` | `mut-07.txt` |
| M5d | R-TUI-059.25 neg | restore `#flow_kind`, hidden at mount | the same | KILLED | `mounted and never shown: ['flow_kind']` | `mut-08.txt` |
| M5e | R-TUI-059.25 neg | restore `#flow_ext_session`, hidden at mount | the same | KILLED | `mounted and never shown: ['flow_ext_session']` | `mut-09.txt` |
| M6 | R-FX-SCR.4 neg | restore `#fx_help`, hidden at mount | `test_r_fx_scr_4_1_every_flow_execution_widget_is_shown_in_a_state` | KILLED | `mounted and never shown: ['fx_help']` | `mut-10.txt` |
| M7 | I-2 | `flow_add` reads `BLOCK_SOURCE` in place of `self._kind` | AT-I12b-1 (`test_at_i12b_1_kind_chip_add_and_ribbon_by_keys`), R-FB-ADD.1/2, `test_at_b97_07_each_kind_its_inputs_and_an_ext_step_card`, `test_at088_gating_selector_appends_block_own_op_check`, `test_at_flow_add_blocks_and_run_renders_result` | KILLED ×5 | the CHECK/EXT-STEP/PATCH/WRITE-OUT Add paints a LOAD card (or `Add needs image file`) instead: AT-I12b-1:392, R-FB-ADD.1/2:326, b97:1563, flow_builder_render:617, directionb:5795 | `mut-11.txt` |

## Score

- Total mutants (rows): **7** — M1, M2, M3, M4, M5 (the five widget restores), M6, M7.
- Total mutant runs (copies): **11** (M5 is one row run once per removed widget).
- Killed: **7 / 7 rows** (11 / 11 runs).
- Survived: **0**.
- Mutation score (killed / total): **7 / 7 = 100%** (raw kill ratio over runs: 11 / 11 = 100%).

No survivor: every negative control and every S-1/S-2 oracle turns its guard nodes RED. The
walks R-TUI-059.25/1 and R-FX-SCR.4/1 each catch their own restored hidden widget by id; the
S-1 guard removal is caught by R-FB-ADD.1/2 at its first painted-tag assertion; both S-2
security oracles (`nul_add_refusal` → `None`, card refs through `Text.from_markup`) and the
I-D4 span-clause control are caught on every node they name, and I-2's "Add reads the chosen
kind" is caught on all five Add nodes of non-SOURCE kinds.

Notes:
- The M5/M6 restores mount the removed widget with its id and hide it at mount (the walk keys
  on id + `is_displayed`, never on content). For `#flow_canvas` and `#flow_blocks` the restored
  `Static` content is empty (the canvas/list painters were removed with the widget); this is
  declared and does not affect the walk's oracle.
- The four S-2 markup-literal nodes run here are the four of `E4-tester-g-t3-notes.md`'s
  security table; `test_at088b_every_render_sink_renders_hostile_literally` (the `render_result`
  sinks) is not a `_card_rows` node and stays GREEN under M2/M3 by design, so it is not a row
  node here.
- M7's node set is AT-I12b-1, R-FB-ADD.1/2 and the three clearest re-pointed "Add nodes of
  other kinds" (EXT-STEP, CHECK, PATCH/WRITE-OUT). Other re-pointed Add nodes that also build a
  non-SOURCE block (e.g. `test_at_b94_15/16/17`, `test_tc_b97_58_add_with_an_empty_field`'s
  CHECK/WRITE-OUT arms) would go RED for the same reason; they are outside this row's cited set.
- Transcripts are redacted (home → `<HOME>`, account → `<USER>`, host → `LAN Linux host 2`,
  `pytest-of-<name>` → `pytest-of-<user>`); grep-checked, no leak line.
