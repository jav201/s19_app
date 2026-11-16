# Inc 8 E4 — negative controls run as mutants (worker, claude-sonnet-5-5)

Tree `b103-inc8` f524a4be (Inc 8 E4 final GREEN). Every control of `01-requirements.md` (89 active rows, the "Negative control" column) was written as a literal source edit and run against the nodes that cover its row. Scripts and raw transcripts: `evidence-e4/mutants/` (`mutants.py` = the edits, `nodes.json` = row to nodes, `results.txt` = every runner transcript, paths redacted). Nothing under `s19_app/` or `tests/` in the worktree was touched (HT-09): the mutations ran on two copies of a `git archive` of f524a4be under the runner's `~/work/zq-e4-8-mut/`.

## Score

| Measure | Result |
|---|---|
| Rows (requirements) | 89, none "not expressible" |
| Controls as scored | 106 (rows whose control text names two or three mutations are split `#a`, `#b`, `#c`) |
| Killed by the mapped nodes | **99 / 106** (93.4 %) |
| Survived the mapped nodes | 6 (2 are killed by a test the case files do not map; 4 are real survivors) |
| Timeout, no verdict | 1 (R-PE-DEF.12#b, 300 s) |
| Not expressible | 0 |
| Rows fully killed by their mapped nodes | 82 / 89 (the 7 others: R-PE-DEF.7, .12, .19, .23, .24, .36, .40) |
| Extra mutants (not in a control text, not scored) | 2: R-PE-DEF.19#x and .81#x (both survive; see findings) |

After the wider run (survivors re-run against all 14 Inc 8 test files, not only the mapped nodes): 101 / 106 killed, 4 survivors, 1 timeout.

## Method

1. `evidence-e4/mutants/build_nodes.py` maps each row to its nodes: the tests the case files name (`02-test-cases.md` and the group files) plus every `tests/test_b103_inc8_*` test whose name starts with the row's id. Acceptance nodes (`test_b103_inc8_at*.py`) are kept apart and run only when the unit nodes pass.
2. Baseline on the pristine copy: the mapped nodes of all 14 test files are GREEN (14 of 14 files rc 0, load 0.16-1.83).
3. Per control, `apply_mutant.py` applies the edit (each `old` string must occur exactly once). The mapped nodes then run with the HT-02 environment (HOME basename `<runner-home>`), `-n 2`, `--maxfail=1`, `timeout 300`, `< /dev/null`. The 11 touched files are then restored from the pristine copy and `sha256sum -c` confirms the restore is exact (every mutant `RESTORE_OK`, no mismatch).
4. Two workers ran in parallel on separate copies. `uptime` load is recorded before and after each mutant (column "Load"). The quiet-host gate (wait above load 8) never fired: observed range 0.22-3.51 (HT-08).
5. `pytest` exits with 2 (interrupted) when `--maxfail=1` stops a run under xdist. The first driver filed those as inconclusive; the table classifies by the `FAILED` line, and `run_mutants.sh` carries the fix.

### Revisions made in this run (declared)

The first expression of seven controls did not match the control text, so its survivor said nothing about the tests. Each was re-expressed and re-run; the first versions are not scored.
- R-PICKER-CORRECT.020: first widened the filter input; the control is a fixed-width filter row. Now `#patch_filter_row { width: 90 }`.
- R-PE-DEF.11#c: first only passed the app's A2L data; the control reads the app's A2L at paint time, so the rows are now re-described from it.
- R-PE-DEF.12#a: first at the panel's seam; the S2 timing tests call `show_page` directly, so the describe-per-row edit is now in `show_page`.
- R-PE-DEF.19: first dropped a branch in `_missing` that no refused row can reach; now the fallback ops decode through I-2. The first edit stays as the extra `19#x`.
- R-PE-DEF.52#b: first used a field that does not exist (killed by an `AttributeError` that said nothing); now `dataclasses.replace(old, encoded_bytes=...)`.
- R-PE-DEF.78: first removed only the editor guard (the decode is gated too, so nothing changed); now it also decodes every text span.
- R-PE-DEF.81#b: first removed the cut in `detail_lines`; the control is the cut in `row_window`. The first edit stays as the extra `81#x`.

## Controls

One line per control. Evidence = the first failing line of the run (`<tree>` = the runner copy). Nodes = unit + acceptance nodes mapped to the row.

| Row | Control (requirement text) | Mutation as applied | Nodes (unit+AT) | Result | Evidence line | Load |
|---|---|---|---|---|---|---|
| R-TUI-063.1 | Compose the landing pane before the sheet → order RED. | move the staging-sheet block after the landing pane in compose | 4+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:71: AssertionError: the regions are not strictly increasing in ('patch_identity_ribbon', 'patch_filter_row', 'patch_sheet_win', 'p` | 1.17-1.38 |
| R-PE-DEF.1.1 | Give the sheet a fixed height → the 220×60 case RED. | sheet window height 1fr -> fixed 30 | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:125: AssertionError: sheet 30 != panel - the other regions 31` | 1.17-1.24 |
| R-PE-DEF.1.2 | No `-bench` rule → height 9 RED. | delete the .-bench rule | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:152: AssertionError: assert 9 == 6` | 1.38-1.43 |
| R-PE-DEF.74 | No minimum height → the 80×24 case RED. | delete min-height: 12 of the sheet window | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:160: AssertionError: Region(x=5, y=6, width=72, height=2)` | 1.24-1.38 |
| R-TUI-063.3 | Keep the A2L chip → RED. | keep the A2L chip in _TABS | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:312: AssertionError: assert ['Patch scrip...hecks', 'A2L'] == ['Patch scrip...ON', 'Checks']` | 1.43-1.55 |
| R-TUI-063.4 | Initial pane `patch_pane_inspector` → RED. | initial pane patch_pane_inspector | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:320: AssertionError: assert 'patch_pane_inspector' == 'patch_win_script'` | 1.38-1.55 |
| R-TUI-063.6 | Keep the per-tab titles → RED. | Inspector tab keeps its own title INSPECTOR | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:334: AssertionError: assert 'INSPECTOR' == 'LANDS IN'` | 1.55-2.02 |
| R-PE-041 | Drop the subtitle with the ledger border → RED. | no subtitle on the landing pane for Patch script / Inspector | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_p_ledger.py:70: AssertionError: Inspector tab: ''` | 1.55-1.85 |
| R-PE-DEF.2 | Compose the picker inside a tab → RED. | compose the picker inside the Inspector tab, not on the filter row | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:200: AssertionError: patch_param_filter has no region` | 2.02-2.10 |
| R-PICKER-CORRECT.011 | Highlight mode or a duplicate id → RED. | the bulk button takes the include button's id (duplicate id) | 2+0 | killed (unit) | `<runner-home>/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/widget.py:1463: textual.widget.MountError: Tried to insert 2 widgets with the same ID 'patch_para` | 1.85-2.02 |
| R-PICKER-CORRECT.020 | A fixed-width filter row wider than 80 → RED. | the filter row fixed 90 cells wide | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:244: AssertionError: #patch_filter_row overflows the panel horizontally: Region(x=5, y=-2, width=90, height=1) vs Region(x=5, y=4,` | 0.22-0.45 |
| R-PE-DEF.3 | Leave them on a hidden container → RED. | the Use row sits in a hidden container | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:264: AssertionError: assert 0 > 40` | 2.02-2.17 |
| R-PE-DEF.4 | Remove the `:focus-within` rule → RED. | no :focus-within border rule | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_layout.py:279: AssertionError: assert '#1b233a' == '#91abec'` | 2.17-2.32 |
| R-PE-DEF.5 | Swap New and Current → RED. | swap the New and Current header labels | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:79: AssertionError: ('current', 29, '  Parameter         Kind     New               Current      Unit   Limits                          ` | 2.17-2.17 |
| R-PE-DEF.6 | A fixed 118-column table → W = 96 RED. | widths computed for a fixed 118-column table | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:67: AssertionError: assert {'current': 1...its': 34, ...} == {'current': 1...its': 25, ...}` | 2.32-2.37 |
| R-PE-DEF.7#a | Drop the Limits cap → 220 RED; a `len()`-based clip → the wide-character case RED (24 and 8 cells). | drop the Limits cap (64) | 2+0 | survived; wider run: killed-wider-by-s1 | `<tree>/tests/test_b103_inc8_s1.py:79: AssertionError: ('delta', 172, '  Parameter               Kind      Current                                     New                 ` | 1.00-2.17 |
| R-PE-DEF.7#b | Drop the Limits cap → 220 RED; a `len()`-based clip → the wide-character case RED (24 and 8 cells). | clip counts characters (len), not cells | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:314: AssertionError: assert ('温度温度温度温度 …' == '温度温度温度温度…'` | 2.37-2.37 |
| R-PE-DEF.10 | Rows from `filtered_params` → page-turn RED. | rows from filtered_params instead of the shown page | 6+1 | killed (unit) | `<tree>/tests/test_b103_inc8_p_wiring.py:115: AssertionError: assert 'PNAME_0200' in '  Parameter         Kind     Current           New          Unit   Limits            ` | 2.32-2.34 |
| R-PE-DEF.11#a | A describe at each page change → the spy counts 1 → RED; definitions kept across a signature change → the reload case RED; the app's A2L read at paint time with the old definitions → `287` before the repopulation RED. | describe every shown name at each page change | 12+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_wiring.py:153: AssertionError: a page change described ['describe_definition', 'describe_definitions', 'describe_definition', 'describe_defi` | 2.36-2.37 |
| R-PE-DEF.11#b | A describe at each page change → the spy counts 1 → RED; definitions kept across a signature change → the reload case RED; the app's A2L read at paint time with the old definitions → `287` before the repopulation RED. | definitions kept across a signature change (first population wins) | 12+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_picker_definitions.py:78: AssertionError: assert ('IDLEX' in ['OFF', 'IDLE', 'RUN', 'FAULT'])` | 2.34-2.41 |
| R-PE-DEF.11#c | A describe at each page change → the spy counts 1 → RED; definitions kept across a signature change → the reload case RED; the app's A2L read at paint time with the old definitions → `287` before the repopulation RED. | the app's A2L read at paint time: rows re-described from it, not the picker's own describe | 12+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_wiring.py:153: AssertionError: a page change described ['describe_definition', 'describe_definitions', 'describe_definition', 'describe_defi` | 0.45-0.64 |
| R-PE-DEF.12#a | One `describe_definition` per row (200 × ≈ 0.12 s) → RED; a full decode of each hostile span over the image and the overlay (≈ 400 × the `S.decode_1MiB` time) → RED. | one describe_definition per row at each page change (in show_page) | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:216: AssertionError: assert '1048576 B' in '  Parameter         Kind     Current           New          Unit   Limits        ` | 0.64-1.01 |
| R-PE-DEF.12#b | One `describe_definition` per row (200 × ≈ 0.12 s) → RED; a full decode of each hostile span over the image and the overlay (≈ 400 × the `S.decode_1MiB` time) → RED. | full decode of every text span (no span bound) | 2+0 | timeout (unit, 300 s) | `—` | 1.17-2.57 |
| R-PE-DEF.13 | Paint an empty sheet → RED. | empty sheet when a filter matches nothing | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:272: AssertionError: assert 'No parameters on this page: type a filter above.' in ''` | 2.41-2.54 |
| R-PE-DEF.14 | Paint the no-page line → RED. | paint the no-page line when no A2L is loaded | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:281: AssertionError: assert 'Load an A2L file to edit parameters by definition.' in 'No parameters on this page: type a filte` | 1.17-1.17 |
| R-PE-DEF.15 | Markup on → the `[b]` case RED. | cells parsed as markup | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:304: AssertionError: assert (True and 'A[b]' in '  A                 VALUE    143.5             ·            deg C  -40 ├───────────────` | 2.54-2.54 |
| R-PE-DEF.16 | Show the I-2 `kind` (`enum`) → RED. | Kind column shows I-2 kind word | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:155: AssertionError: assert 'number' == '?'` | 1.17-1.24 |
| R-PE-DEF.17 | Show the stored value for a number → `287` RED. | number Current shows the stored value | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:229: assert {'enum': '1 I..."Hello ASAM"'} == {'enum': '1 I..."Hello ASAM"'}` | 2.54-2.57 |
| R-PE-DEF.18 | Zero-fill the missing byte → RED. | zero-fill the byte an image lacks | 7+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:309: AssertionError: assert '0.0' == '--'` | 1.24-1.24 |
| R-PE-DEF.75 | Decode it through I-2 → `--` from `A2L-DEF-ELEMENTS` for the first case RED. | fallback rows decode through I-2 and read as numbers | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:274: AssertionError: assert '143.5' == '24 values'` | 2.57-2.57 |
| R-PE-DEF.88 | Decode the span → `"AAAA…` RED. | decode text spans over 4096 bytes | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:284: assert '"AAAAAAAAAAAAAAAA…' == '4097 B'` | 1.24-1.30 |
| R-PE-DEF.19 | Decode a refused definition → exception or a value RED. | a refused definition is decoded through I-2 (fallback decode = scalar decode) | 2+0 | survived; wider run: survived-wider | `—` | 1.01-3.17 |
| R-PE-DEF.19#x | Decode a refused definition → exception or a value RED. | EXTRA (not the control text): no refused branch in _missing (dead for refused rows) | 2+0 | extra, not scored: survived; wider run: survived-wider | `—` | 0.22-3.31 |
| R-PE-DEF.20 | Raw unit → the ESC case RED. | raw unit (no control-character cleaning) | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:327: AssertionError: assert '%\x1b' == '%�'` | 1.30-1.30 |
| R-PE-DEF.21 | Place `●` by stored value → RED. | ruler dot placed by the stored value | 8+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:399: AssertionError: the track is Limits width - 12 cells` | 2.69-2.69 |
| R-PE-DEF.76 | The plain division → `ZeroDivisionError` RED. | no guard for limits that do not ascend (plain division) | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:456: AssertionError: assert '9 ├────────────────────▶ 1' == '9 … 1'` | 1.30-1.36 |
| R-PE-DEF.77 | The plain division → `ZeroDivisionError` RED. | no guard for limits that do not ascend in the percent | 1+0 | killed (unit) | `<tree>/s19_app/tui/definition_sheet.py:674: ZeroDivisionError: float division by zero` | 2.69-2.69 |
| R-PE-DEF.22 | Mark every row → RED. | mark every row with the pointer | 1+2 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:349: AssertionError: assert '▶' == ' '` | 1.36-1.36 |
| R-PE-DEF.23#a | Read New from the formula text → RED after the selection moves; staged state from a decode for the fallback → the `cuboid` case RED. | New read from the formula input text, not the row's pending text | 8+2 | survived; wider run: survived-wider | `—` | 2.53-3.51 |
| R-PE-DEF.23#b | Read New from the formula text → RED after the selection moves; staged state from a decode for the fallback → the `cuboid` case RED. | staged state of a fallback row from a value-text decode | 8+2 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:365: AssertionError: assert ' ' == '●'` | 1.33-1.36 |
| R-PE-DEF.24#a | Echo the typed text: typed `25.50` shows `25.50` where the preview's text is `25.5` → RED; pending = any formula text → the V171 case RED. | New echoes the typed text | 7+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:564: AssertionError: assert ('\u25c6' == '\u25c6'` | 2.53-2.57 |
| R-PE-DEF.24#b | Echo the typed text: typed `25.50` shows `25.50` where the preview's text is `25.5` → RED; pending = any formula text → the V171 case RED. | pending = any formula text | 7+0 | survived; wider run: survived-wider | `—` | 1.00-3.27 |
| R-PE-DEF.25 | Show the refusal code → RED. | New shows the refusal code | 4+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:577: AssertionError: assert (False)` | 2.57-2.57 |
| R-PE-DEF.26 | p over the extended limits → `-47.2%` RED. | percent taken over the extended limits | 5+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:588: AssertionError: assert '-118.0 (-47.2%)' == '-118.0 (-62.1%)'` | 1.33-1.38 |
| R-PE-DEF.27 | Show the previous Δ → RED. | a refused preview keeps the previous delta | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:621: AssertionError: assert '' == '✗ refused'` | 2.52-2.57 |
| R-PE-DEF.28 | Show the current value in New → RED. | New shows the current value for an untouched row | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:355: AssertionError: assert '143.5' == '·'` | 1.38-1.38 |
| R-PE-DEF.30 | Keep every expanded row → RED. | every row keeps its expanded detail | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:246: AssertionError: ['  Parameter               Kind      Current                                     New                 Un` | 2.52-2.52 |
| R-PE-DEF.31#a | Leave out `>> <shift>` → MASK RED; drop the layout word → the `RL_U16` case RED. | leave out '>> <shift>' of the mask formula | 6+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:141: AssertionError: assert '└ IDENTICAL ...0800010 · 2 B' == '└ IDENTICAL ...0800010 · 2 B'` | 1.35-1.38 |
| R-PE-DEF.31#b | Leave out `>> <shift>` → MASK RED; drop the layout word → the `RL_U16` case RED. | drop the record layout word | 6+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:157: AssertionError: assert ['└ LINEAR ph...800020 · 2 B'] == ['└ LINEAR ph...800020 · 2 B']` | 2.48-2.52 |
| R-PE-DEF.32 | Show the definition line → RED. | a refused row shows the definition line, not its message | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:168: AssertionError: assert ['└ NO_COMPU_...--- · None B'] == ['└ NO_SUCH_P...e in the A2L']` | 1.35-1.35 |
| R-PE-DEF.33 | Mark the current entry after a choice → RED. | mark the current entry after a choice (ignore the preview) | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:191: assert ('( ) 0 OFF   ...NKNOWN_STATE"' == '( ) 0 OFF   ...NKNOWN_STATE"'` | 2.48-2.48 |
| R-PE-DEF.34 | Strip from the unmasked word only → RED. | bit strip's after word is the before word | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:213: AssertionError: assert False` | 1.35-1.35 |
| R-PE-DEF.35 | 8 bytes per row → RED. | text rows show 8 bytes per row | 3+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:236: AssertionError: assert ['+00', '+08'... '+20', '+28'] == ['+00', '+10', '+20']` | 2.48-2.52 |
| R-PE-DEF.36#a | Enable the input → RED; no span bound → the 4,097 case RED. | formula input enabled for a row with no editor | 7+0 | survived; wider run: killed-wider-by-s2_sheet_formula | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:264: AssertionError: assert False is True` | 1.32-3.27 |
| R-PE-DEF.36#b | Enable the input → RED; no span bound → the 4,097 case RED. | no span bound on a text row's editor | 7+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:359: AssertionError: assert '' == 'edit ASCII o...Inspector tab'` | 2.52-2.52 |
| R-PE-DEF.37 | One label for all → RED. | one label for every kind | 3+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:70: AssertionError: assert 'new =' == 'text ='` | 1.32-1.32 |
| R-PE-DEF.38#a | Leave it empty → RED; always the current text → the `ABC` case RED. | text row fill left empty | 3+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:83: AssertionError: assert '' == 'Hello ASAM'` | 2.48-2.52 |
| R-PE-DEF.38#b | Leave it empty → RED; always the current text → the `ABC` case RED. | fill is always the current text | 3+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:389: AssertionError: assert 'Hello ASAM' == 'ABC'` | 1.30-1.32 |
| R-PE-DEF.39 | Clear pending text on move → RED. | pending text cleared when the selection moves | 3+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:124: AssertionError: assert '' == '25.5'` | 2.48-2.48 |
| R-PE-DEF.40 | Preview over the image, not the overlay → the masked case of .51 RED. | preview over the image, not the overlay | 10+1 | survived; wider run: survived-wider | `—` | 1.15-3.21 |
| R-PE-DEF.41 | Wrap the tail → RED. | the bar's tail is not cut at its edge | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:349: assert (False)` | 2.44-2.48 |
| R-PE-DEF.42 | No `max_length` → RED. | formula input without max_length | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:224: AssertionError: assert 'yyyyyyyyyyyy...xxxxxxxxxxxxx' == 'yyyyyyyyyyyy...yyyyyyyyyyyyy'` | 1.15-1.15 |
| R-PE-DEF.78 | Fill the current text → 4,097 characters RED. | a row with no editor fills the current (decoded) text | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:407: AssertionError: assert 'AAAAAAAAAAAA...AAAAAAAAAAAAA' == ''` | 0.22-0.45 |
| R-PE-DEF.79 | Paint every text row → 65,536 rows for the 1 MiB case RED. | text rows paint every row of the span | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:267: AssertionError: assert 7 == 6` | 1.15-1.22 |
| R-PE-DEF.80 | A direct `value =` → 5,000 characters RED. | fill is not capped (direct value =) | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1_detail.py:415: AssertionError: assert 'EEEEEEEEEEEE...EEEEEEEEEEEEE' == 'EEEEEEEEEEEE...EEEEEEEEEEEEE'` | 2.44-2.49 |
| R-PE-DEF.45 | Wrap around → RED. | selection wraps around | 5+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_keys.py:104: AssertionError: assert 'ENUM_0001' == 'DISPLAY_0001'` | 1.20-1.22 |
| R-PE-DEF.46 | No binding → RED. | no enter binding on the sheet | 1+3 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_keys.py:131: AssertionError: assert _SheetBody(id='patch_sheet_body') is OsClipboardInput(id='patch_sheet_input')` | 2.49-2.49 |
| R-PE-DEF.47 | Set the stored value as text → `2` RED (A2L-DEF-ENUM, `ENC.ENUM_0001.'2'`). | enum choice sets the stored value as the formula text | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_keys.py:149: AssertionError: assert ['2', '2', '2', '0'] == ['RUN', 'FAUL...FAULT', 'RUN']` | 1.20-1.20 |
| R-PE-DEF.48 | Keep the text → RED. | escape keeps the pending text | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_keys.py:167: AssertionError: assert '◆' != '◆'` | 2.49-2.53 |
| R-PE-DEF.49 | Leave the picker cursor at 0 → RED. | picker cursor left at row 0 | 4+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_wiring.py:227: AssertionError: assert 'ENUM_0001' == 'MASK_FIELD_0001'` | 1.20-1.32 |
| R-PE-DEF.81#a | Paint every row from row 0 → the first case RED (the selected row on body line 40); no cut → the stand-in case paints no row RED. | paint every row from row 0 (no row window top) | 6+0 | killed (unit) | `<runner-home>/miniconda3/envs/s19ci/lib/python3.11/asyncio/base_events.py:654: RuntimeError: coroutine raised StopIteration` | 2.41-2.53 |
| R-PE-DEF.81#b | Paint every row from row 0 → the first case RED (the selected row on body line 40); no cut → the stand-in case paints no row RED. | the detail is not cut to the window (row_window paints every detail line) | 6+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:659: assert (4, 3) == (3, 2)` | 0.45-0.61 |
| R-PE-DEF.81#x | Paint every row from row 0 → the first case RED (the selected row on body line 40); no cut → the stand-in case paints no row RED. | EXTRA (not the control text): detail_lines does not cut to the room | 6+0 | extra, not scored: survived; wider run: survived-wider | `—` | 0.61-3.21 |
| R-PE-DEF.50 | Stage through `add_symbol_entry` (the pre-I-2 encode) → the masked case RED. | stage through add_symbol_entry (the pre-I-2 encode) | 6+2 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:77: assert False` | 2.41-2.42 |
| R-PE-DEF.51#a | Encode over the image → first-staged field reverts (`174` or `1`) RED; encode over the live (applied) map → `1F F6`, the removed field back, RED. | encode over the image, not the overlay | 7+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:134: AssertionError: assert '1' == '0'` | 1.19-1.40 |
| R-PE-DEF.51#b | Encode over the image → first-staged field reverts (`174` or `1`) RED; encode over the live (applied) map → `1F F6`, the removed field back, RED. | stage over the live (applied) map | 7+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:216: AssertionError: assert [(8388624, b'\x1f\xf6')] == [(8388624, b'\x1a\xe6')]` | 2.42-2.46 |
| R-PE-DEF.52#a | Append a second entry → `CHG-COLLISION` RED; replace only the bytes of a `string` entry → the reload decodes the old text RED. | append a second entry for an equal span | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:176: AssertionError: assert 2 == 1` | 1.40-1.40 |
| R-PE-DEF.52#b | Append a second entry → `CHG-COLLISION` RED; replace only the bytes of a `string` entry → the reload decodes the old text RED. | replace only the bytes of the old entry (a string entry keeps its type and value) | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:187: AssertionError: assert ('string' == 'bytes'` | 1.36-1.36 |
| R-PE-DEF.53 | Symbol `None` → RED. | appended entry carries symbol None | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:202: AssertionError: assert None == 'DISPLAY_0001'` | 1.40-1.40 |
| R-PE-DEF.54 | Overwrite the symbol → RED. | replace overwrites the symbol with the row name | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:207: AssertionError: assert 'MASK_BIT_0001' == 'MASK_FIELD_0001'` | 2.51-2.51 |
| R-PE-DEF.55 | Replace the partial entry → RED. | a partial overlap replaces the entry instead of refusing | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:219: AssertionError: assert not True` | 1.40-1.45 |
| R-PE-DEF.56 | Stage the image bytes → RED. | a refusal stages the image bytes of the span | 4+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:247: AssertionError: assert not True` | 2.51-2.55 |
| R-PE-DEF.57 | Show the code only → RED. | refusal status shows the code only | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:239: AssertionError: assert 'Patch Editor: A2L-DEF-NUMBER' == 'Patch Editor... not a number'` | 1.45-1.50 |
| R-PE-DEF.58#a | Show `entry added.` → RED; an unbounded `<text>` → the 300-character case RED. | success status reads 'entry added.' | 4+2 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:277: AssertionError: assert 'Patch Editor: entry added.' == 'Patch Editor...at 0x800000).'` | 2.50-2.55 |
| R-PE-DEF.58#b | Show `entry added.` → RED; an unbounded `<text>` → the 300-character case RED. | the shown <text> is not bounded | 4+2 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:285: AssertionError: assert 'staged as xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | 1.49-1.50 |
| R-PE-DEF.59#a | Drop the notice → RED; report it as an issue → the line reads `[…] warning: …` RED. | drop the encode notices | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:297: AssertionError: assert () == ('Patch Edito...ts -50..200',)` | 2.34-2.50 |
| R-PE-DEF.59#b | Drop the notice → RED; report it as an issue → the line reads `[…] warning: …` RED. | report the notices as issues | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:297: AssertionError: assert () == ('Patch Edito...ts -50..200',)` | 1.45-1.49 |
| R-PE-DEF.60#a | Keep the selection → RED; select from the current selection → the third case RED. | no advance of the selection after a stage | 12+1 | killed (unit) | `<tree>/tests/test_b103_inc8_p_ledger.py:126: AssertionError: assert 'ENUM_0001' == 'CURVE_DEF_0001'` | 2.34-2.45 |
| R-PE-DEF.60#b | Keep the selection → RED; select from the current selection → the third case RED. | advance from the current selection, not the staged row | 12+1 | killed (unit) | `<tree>/tests/test_b103_inc8_p_ledger.py:126: AssertionError: assert 'MASK_BIT_0001' == 'CURVE_DEF_0001'` | 1.43-1.45 |
| R-PE-DEF.82 | Keep the pending text → `◆` after the Undo RED. | keep the staged row's pending text | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_s2_sheet_keys.py:263: AssertionError: assert '◆' != '◆'` | 2.45-2.45 |
| R-PE-DEF.61 | No `_push_history` → RED. | no history step on a stage | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a1_service.py:311: assert 0 == (0 + 1)` | 1.36-1.43 |
| R-PE-034 | No writer for the stage → RED. | no dirty writer for the stage | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:179: assert (False, False) == (False, True)` | 2.45-2.53 |
| R-PE-035 | Set the flag before the encode → RED. | set the dirty flag before the encode | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:252: AssertionError: assert True is False` | 1.36-1.41 |
| R-PE-DEF.62#a | Track staged rows in the sheet only → the Undo case RED; keep the rows of the old image → the new-image case RED. | the sheet tracks staged rows itself (no set_document on a ledger refresh) | 11+0 | killed (unit) | `<tree>/tests/test_b103_inc8_p_wiring.py:270: AssertionError:   DISPLAY_0001      VALUE    143.5             ·            deg C  -40 ├───────────●┤ 150` | 2.53-2.65 |
| R-PE-DEF.62#b | Track staged rows in the sheet only → the Undo case RED; keep the rows of the old image → the new-image case RED. | keep the rows of the old image (no set_document on a new map) | 11+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:428: AssertionError: assert False` | 1.41-1.47 |
| R-PE-110 | No busy check in the stage → RED. | no busy check in the stage handler | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:445: AssertionError: assert 'Patch Editor...at 0x800020).' == 'busy: Loadin...it to finish.'` | 2.47-2.65 |
| R-PE-DEF.63 | Stage with the old definition → RED. | stage with the old (sheet's) A2L when the app has none | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:456: AssertionError: assert 'Patch Editor...at 0x800020).' == 'Patch Editor...thing staged.'` | 1.44-1.47 |
| R-PE-DEF.64 | Use the page's definition → 0x800020 RED. | stage with the page's definition, not a fresh describe | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:470: assert [8388640] == [8388656]` | 2.43-2.47 |
| R-PE-DEF.70#a | Render one cell as a markup `str` → RED; the bar's name as a markup `Label` → the last case RED. | one Current cell rendered as a markup str | 6+0 | killed (unit) | `<runner-home>/miniconda3/envs/s19ci/lib/python3.11/site-packages/rich/markup.py:167: rich.errors.MarkupError: closing tag '[/x]' at position 3 doesn't match any open tag` | 1.40-1.44 |
| R-PE-DEF.70#b | Render one cell as a markup `str` → RED; the bar's name as a markup `Label` → the last case RED. | the bar's name label updated with a markup str | 6+0 | killed (unit) | `<runner-home>/miniconda3/envs/s19ci/lib/python3.11/site-packages/textual/markup.py:320: textual.markup.MarkupError: closing tag '[/x]' does not match any open tag` | 2.40-2.43 |
| R-PE-DEF.71 | Paint the raw word → RED. | plain() leaves control characters in | 2+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:682: AssertionError: assert 'A\x1b[2J' == 'A�[2J'` | 1.40-1.40 |
| R-PE-DEF.72 | Unbounded name → RED. | name_echo not bounded | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_s1.py:694: AssertionError: assert 'NNNNNNNNNNNN...NNNNNNNNNNNN…' == 'NNNNNNNNNNNN...NNNNNNNNNNNN…'` | 2.40-2.40 |
| R-PE-DEF.73 | `markup=True` status → RED. | status line label with markup=True | 1+0 | killed (unit) | `<tree>/tests/test_b103_inc8_a2_app.py:483: AssertionError: the painted status line ate the brackets: "Patch Editor: DISPLAY_0001: 'A' is not a number"` | 1.34-1.40 |
| R-PE-DEF.83 | Keep today's step 1 → RED. | keep the pre-Inc-8 step 1 text | 2+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a3_help.py:44: AssertionError: step 1 does not name ['filter row', 'STAGING SHEET', 'LANDS IN', 'Patch script']: 'Edit a change-set: the PATCH` | 2.36-2.40 |
| R-PE-DEF.84 | No line → TC-B97-32 lists `Patch script` as missing RED. | delete the Patch script help line | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a3_help.py:57: AssertionError: ['--', '?', 'Add', 'Add list', 'Address', 'Apply loaded changes', ...]` | 1.34-1.34 |
| R-PE-DEF.85 | Drop the line → RED. | delete the STAGING SHEET help line | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a3_help.py:64: AssertionError: ['--', '?', 'Add', 'Add list', 'Address', 'Apply loaded changes', ...]` | 2.36-2.36 |
| R-PE-DEF.86 | Only a `new =` line → the `field =` case RED. | delete the field = help line (only the new = line stays) | 3+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a3_help.py:74: AssertionError: no `field = — …` line: ['--', '?', 'Add', 'Add list', 'Address', 'Apply loaded changes', 'Bytes', 'Checks', "Do` | 1.31-1.34 |
| R-PE-DEF.87 | Today's line → RED. | keep the pre-Inc-8 Use parameter line | 1+1 | killed (unit) | `<tree>/tests/test_b103_inc8_a3_help.py:94: AssertionError: on the A2L tab, copies the highlighted parameter's address and the loaded image's current bytes into the entry ` | 2.36-2.42 |

## Findings

### Survivors (the test cannot fail for this edit)

| # | Control | Mapped nodes | Why it survives | Class |
|---|---|---|---|---|
| S-1 | R-PE-DEF.19 (a refused definition decoded through I-2) | `test_r_pe_def_19_*` (2) | A refused row's Current is painted by `_value_fallback`, which reads `definition.refusal` and ignores `row.current`; `decode_definition` returns a refusal object without raising. No test asserts that `SheetRow.current` of a refused row is `None`. Survives all 14 files. The edit may be an equivalent mutant at the painted level. | test gap or equivalent |
| S-2 | R-PE-DEF.23#a (New read from the input text, not the row's pending text) | R-PE-DEF.23 unit (8) + AT-1, AT-3 | No test paints a pending row other than the selected one and reads its New cell: after the selection moves, the pending text is asserted only through the formula input (R-PE-DEF.39), not through the New column. Survives all 14 files. | test gap |
| S-3 | R-PE-DEF.24#b (`pending` = any formula text) | `test_r_pe_def_24_*` (3) and the others mapped (7 in all) | The widget never stores a pending text equal to the base text (`_set_formula_text` pops it), so `_is_pending`'s `!= _base_text(row)` clause is unreachable through the sheet, and no S1 test calls `row_line` with `pending == base text` for a text row. Survives all 14 files. | test gap (clause redundant through the widget) |
| S-4 | R-PE-DEF.40 (preview over the image, not the overlay) | `test_r_pe_def_40_*` (10) + AT-1 | The "masked case of .51" that the control names is covered only at the service level (`test_r_pe_def_51_*`, another seam). No sheet-level test previews a masked word after another field of it is already staged. Survives all 14 files. | test gap |

### Survivors that a test outside the mapping kills (mapping gap in the case files)

- R-PE-DEF.7#a (drop the Limits cap): killed by `test_b103_inc8_s1.py::test_r_pe_def_6_widths_follow_the_examples_of_every_class` (line 79, wider run). The control cell sits on row .7, whose nodes (`no_painted_line_is_wider...`, wide characters) do not check the cap.
- R-PE-DEF.36#a (enable the input for a row with no editor): killed by `test_b103_inc8_s2_sheet_formula.py::test_r_pe_def_78_n_a_text_row_without_an_editor_keeps_the_input_empty` (line 264, `disabled is True`). The case rows of .36 say "input disabled is S2" without naming a node.

### Extra mutants, not scored

- R-PE-DEF.19#x: the `refused` branch of `_missing` is dead code (a refused row has kind `none`, which takes the fallback ops). No test can reach it; candidate for deletion (rule "no se usa, borra").
- R-PE-DEF.81#x: `detail_lines`' cut to `room` is redundant with `row_window`'s own cap and `_paint`'s slice; it survives all 14 files.

### No verdict

- R-PE-DEF.12#b (full decode of every text span): the run hit the 300 s timeout, and a timeout is not a kill (MD-07). The mutation makes the hostile 1 MiB page decode about 400 MiB; the test would fail by its own 0.5 s assertion, but only after five such passes. Not re-run longer: a mutant battery does not decide timing (HT-08).

### Weak kills worth knowing

R-PE-DEF.81#a is killed by a `RuntimeError: coroutine raised StopIteration` in the event loop, not by an assertion about the window. R-PE-DEF.70#a/#b are killed by Textual/Rich `MarkupError` (the expected symptom of parsing markup), R-PE-DEF.77 by `ZeroDivisionError` (the control text names it) and R-PICKER-CORRECT.011 by Textual's duplicate-id `MountError`. These are real detections, but the first one does not show the assertion the requirement is about.

## Notes

- R-PICKER-CORRECT.011's control reads "highlight mode or a duplicate id"; only the duplicate id is expressible as an edit.
- The help rows (R-PE-DEF.83-.87) were mutated by restoring the pre-Inc 8 text (.83, .87) or deleting the new line (.84-.86).
- Runner scratch `~/work/zq-e4-8-mut/` deleted after the evidence was committed (PF-04, explicit list: `mut`, `pristine`, `w1`, `w2`, `res`, `res-pass1`, `run`).

## Survivor follow-up (relevo-9, tester, claude-sonnet-5-5)

Orchestrator rulings applied to the 4 survivors, the 2 mapping gaps and the timeout. Each new test was run RED with its mutation applied on a copy of the tree on the runner (`~/work/zq-e4-8-surv/tree`, a `git archive` of 053b54be plus the three edited test files; never the worktree, HT-09) and GREEN on the pristine copy (`~/work/zq-e4-8-surv/pristine`). `s19_app.__file__` printed from the pristine copy: `<runner-home>/work/zq-e4-8-surv/pristine/s19_app/__init__.py`. Host load 0.31-0.67 (quiet, HT-08). No product file was touched.

### New score

| Measure | Before | After |
|---|---|---|
| Controls killed | 101 / 106 (99 by the mapped nodes + 2 by unmapped nodes) | **106 / 106** |
| Survivors | 4 | 0 |
| Timeout, no verdict | 1 | 0 |
| Rows fully killed | 82 / 89 | **89 / 89** |
| Extra mutants (not scored) | 2 survive | 2 survive (findings below) |

### Survivors: new tests (RED with the mutation, GREEN pristine)

| Control | Test (path::name) | Asserts (observable outcome) | RED with the mutation | GREEN |
|---|---|---|---|---|
| R-PE-DEF.19 | `tests/test_b103_inc8_s1.py::test_r_pe_def_19_a_refused_definition_is_never_decoded_so_its_row_holds_no_value` | for the real refusal (unknown name) and the stand-in (`A2L-DEF-MASK`): the row is kind `none`, holds no current and no staged value, is not staged, and paints `refused` | `<tree>/tests/test_b103_inc8_s1.py:281: AssertionError: assert ('none', Refu... A2L'), False) == ('none', None, None, False)` | 1 passed |
| R-PE-DEF.23#a | `tests/test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_23_5_a_pending_rows_new_cell_belongs_to_its_own_text_after_the_selection_moves` | DISPLAY_0001 typed `25.50`, selection moved to ENUM_0001 (the input is now empty): DISPLAY_0001 still shows `◆` and New `25.5` | `<tree>/tests/test_b103_inc8_s2_sheet_rows.py:381: AssertionError: {'Current': '143.5', 'Kind': 'VALUE', ... 'New': '·', ...}` | 1 passed |
| R-PE-DEF.24#b | `tests/test_b103_inc8_s1.py::test_r_pe_def_24_a_pending_text_equal_to_the_rows_own_text_is_not_pending` | V171 text row, formula text equal to its base text, through `row_line`: no `◆`, New `·`; control arm: base text plus `!` is pending (`◆`, New echoes it) | `<tree>/tests/test_b103_inc8_s1.py:588: AssertionError: assert ('◆' != '◆')` | 1 passed |
| R-PE-DEF.40 | `tests/test_b103_inc8_s2_sheet_formula.py::test_r_pe_def_40_5_the_tail_previews_over_the_staged_bytes_of_a_shared_word` | MASK_FIELD `255` staged, MASK_BIT `0` typed: the tail shows `<image word> → <I-2 encode over the staged bytes>`; the encode over the bare image is absent. Both words come from `encode_definition` itself | `<tree>/tests/test_b103_inc8_s2_sheet_formula.py:203: AssertionError: (0 … 1)  raw 1→0 · 1A E7 → 1A E6  ✓ in limits  enter stage ↓` | 1 passed |

GREEN transcript: `4 passed in 2.63s` (the four nodes together on the pristine copy, `-n 2`). The three edited files whole, pristine: `test_b103_inc8_s1.py` 97 passed in 1.26s; `test_b103_inc8_s2_sheet_rows.py` 34 passed in 6.13s; `test_b103_inc8_s2_sheet_formula.py` 25 passed in 8.79s. Every mutant restore was checked with `diff -r` against the pristine copy (`RESTORE_OK`).

Notes per survivor:
- **.19** An I-2 decode of a refused definition returns the refusal object without raising, so the painted `refused` cannot tell the mutant from the product. The test asserts the model: a refused row carries no decoded value (the graph's "none (no I-2 call)" for the fallback). It is a model-level assertion because no painted path differs.
- **.23#a** The control's "RED after the selection moves" had no test: the pending text of a row that is not selected was asserted only through the formula input (R-PE-DEF.39), never through its New cell.
- **.24#b** The `pending != base text` clause is unreachable through any public path: `StagingSheet._set_formula_text` pops a pending text equal to `formula_fill(row, None)`, which is the row's base text for an editable row, so the sheet never hands the model such a text. The test therefore drives `row_line` with `pending == base text` for a text row (model level), as the ruling allows. The sheet-level `test_r_pe_def_24_3_...` stays as it is.
- **.40** The "masked case of .51" was covered only at the service seam. The new test goes through the sheet, previews the second field of a word whose first field is already staged, and reads the raw bytes in the tail.

### Mapping fixes (`02-test-cases.md`, test-name column)

- R-PE-DEF.7/3 now names `test_r_pe_def_6_widths_follow_the_examples_of_every_class` (kills 7#a, the Limits cap at 220). Evidence: the wider run above, `test_b103_inc8_s1.py:79`.
- R-PE-DEF.36/3 now names `test_b103_inc8_s2_sheet_formula.py::test_r_pe_def_78_n_a_text_row_without_an_editor_keeps_the_input_empty[78-1-4097-bytes]` (kills 36#a, input disabled for a row with no editor). Evidence: the wider run above, `test_b103_inc8_s2_sheet_formula.py:264`.
- The new tests are named in rows .19/1, .23/1, .24/3 and .40/1 of the same file. No row was added, so the alternative counts of the requirements do not change.

### R-PE-DEF.12#b (full decode of every text span), rerun alone

Mutation applied on the tree copy; nodes `test_r_pe_def_12_1_...` and `test_r_pe_def_12_2_...` of `test_b103_inc8_s2_sheet_rows.py`; `timeout 900`, `-n 2`, `--maxfail=1`, started after the GREEN runs above had ended, no other job of mine running. `uptime` before: `up 1 day, 5:47, load average: 0.74, 0.32, 0.72`; after: `up 1 day, 5:57, load average: 1.10, 1.13, 1.01`.

```
START 2026-11-14T02:58:32Z
<tree>/tests/test_b103_inc8_s2_sheet_rows.py:215: assert 85.83862843000679 <= 0.5
FAILED tests/test_b103_inc8_s2_sheet_rows.py::test_r_pe_def_12_2_a_page_of_200_one_mebibyte_text_spans_paints_within_half_a_second
1 failed, 1 passed in 597.67s (0:09:57)
RC 2   RESTORE_OK
END 2026-11-14T03:08:30Z
```

Verdict: **killed (unit)**, by the test's own 0.5 s assertion (one pass took 85.8 s). The first run's 300 s timeout was only the five passes of the 0.5 s retry loop; this run finished inside 900 s on a quiet host. The timing value is load-sensitive and not a number to quote; the verdict does not depend on it (85.8 s against a 0.5 s bound).

### Findings for the Inc 8 E5 reviewer (no product change by this worker)

- **19#x** The `refused` branch of `_missing` (`definition_sheet.py`, `if row.definition.refusal is not None: return "refused"`) is dead: a refused row has kind `none`, takes the fallback ops, and `_value_fallback` answers `refused` itself. No test can reach it. Candidate for deletion (rule "no se usa, borra"). Still survives.
- **81#x** `detail_lines`' cut to `room` is redundant with `row_window`'s own cap and `_paint`'s slice. Still survives all 14 files. Candidate for deletion, or for a test if the cut is meant to be the model's own contract.
- **Case gap** `02-test-cases.md` R-PE-DEF.36/1 and /2 (a refused row, the `cuboid` copy) say "input disabled", but no sheet test asserts `disabled is True` for them; only the 4,097-byte text row does. Not a surviving mutant today; a coverage hole in the case rows.
- **Graph wording** `codewire/graph-inc8.md` line 366 (`build_row`): "A refused definition keeps its refusal". The code and the fallback row of the same graph (line 129, "none (no I-2 call)") hold no decoded value. The new .19 test follows the second; the E5 reviewer may want the first corrected (DF-04 (b): adjust the document).
