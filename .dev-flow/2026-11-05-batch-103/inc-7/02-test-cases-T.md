# Inc 7 - test cases written by the E4 tester (T7)

One row per test: the case id (from the test's docstring), the test, and the requirement's negative control (copied from `01-requirements.md`), which the test's closing assertion is written against: the control changes exactly the value that assertion reads. The controls were NOT run (no implementation exists at base `63791549`; mutants run on copies at integration/E5, HT-09).

## G-T-L - `tests/test_b103_label_list.py` (111 tests)

| Case | Test | Negative control (requirement) |
|---|---|---|
| R-A2L-LIST.001/1 | `test_r_a2l_list_001_1` | split on new lines only → the G2 list gives 9 names → RED |
| R-A2L-LIST.001/2 | `test_r_a2l_list_001_2` | split on new lines only → the G2 list gives 9 names → RED |
| R-A2L-LIST.001/3 | `test_r_a2l_list_001_3` | split on new lines only → the G2 list gives 9 names → RED |
| R-A2L-LIST.002/1 | `test_r_a2l_list_002_1` | case folded → `value_0002` found → RED |
| R-A2L-LIST.002/2 | `test_r_a2l_list_002_2` | case folded → `value_0002` found → RED |
| R-A2L-LIST.002/3 | `test_r_a2l_list_002_3` | case folded → `value_0002` found → RED |
| R-A2L-LIST.003/1 | `test_r_a2l_list_003_1` | no duplicate check → #10 found → counts `10 found` → RED |
| R-A2L-LIST.003/2 | `test_r_a2l_list_003_2` | no duplicate check → #10 found → counts `10 found` → RED |
| R-A2L-LIST.004/1 | `test_r_a2l_list_004_1` | missing treated as found → `11 found` → RED |
| R-A2L-LIST.004/2 | `test_r_a2l_list_004_2` | missing treated as found → `11 found` → RED |
| R-A2L-LIST.004/3 | `test_r_a2l_list_004_3` | missing treated as found → `11 found` → RED |
| R-A2L-LIST.005/1 | `test_r_a2l_list_005_1` | mode ignored in list mode → `found` → RED |
| R-A2L-LIST.005/2 | `test_r_a2l_list_005_2` | mode ignored in list mode → `found` → RED |
| - | `test_i7_resolution_rows_are_the_tag_objects_and_equal_when_repeated` | (interface check, I-7; no requirement row) |
| - | `test_i7_display_text_never_raises_and_keeps_length` | (interface check, I-7; no requirement row) |
| - | `test_i7_list_row_cells_reads_text_cells_by_the_shipped_labels` | (interface check, I-7; no requirement row) |
| R-A2L-LIST.033/1 | `test_r_a2l_list_033_1` | first line kept (R-PASTE.1) → `VALUE_0002` → RED; a list taken in field `source` → `VALUE_0002, CURVE_0001, …` → RED |
| R-A2L-LIST.033/2 | `test_r_a2l_list_033_2` | first line kept (R-PASTE.1) → `VALUE_0002` → RED; a list taken in field `source` → `VALUE_0002, CURVE_0001, …` → RED |
| R-A2L-LIST.033/3 | `test_r_a2l_list_033_3` | first line kept (R-PASTE.1) → `VALUE_0002` → RED; a list taken in field `source` → `VALUE_0002, CURVE_0001, …` → RED |
| R-A2L-LIST.033/4 | `test_r_a2l_list_033_4` | first line kept (R-PASTE.1) → `VALUE_0002` → RED; a list taken in field `source` → `VALUE_0002, CURVE_0001, …` → RED |
| R-A2L-LIST.033/5 | `test_r_a2l_list_033_5` | first line kept (R-PASTE.1) → `VALUE_0002` → RED; a list taken in field `source` → `VALUE_0002, CURVE_0001, …` → RED |
| R-A2L-LIST.034/1 | `test_r_a2l_list_034_1` | names taken from the raw text → ESC in the box → RED; the hook given the raw text → ESC reaches the override → RED |
| R-A2L-LIST.034/2 | `test_r_a2l_list_034_2` | names taken from the raw text → ESC in the box → RED; the hook given the raw text → ESC reaches the override → RED |
| R-A2L-LIST.034/3 | `test_r_a2l_list_034_3` | names taken from the raw text → ESC in the box → RED; the hook given the raw text → ESC reaches the override → RED |
| R-PASTE.1/1 | `test_r_paste_1_1` | the hook called for every box → the Load box's value `VALUE_0002, CURVE_0001, …` → RED; the hook called on a `restrict` box → the refusal bypassed → RED |
| R-PASTE.1/2 | `test_r_paste_1_2` | the hook called for every box → the Load box's value `VALUE_0002, CURVE_0001, …` → RED; the hook called on a `restrict` box → the refusal bypassed → RED |
| R-PASTE.1/3 | `test_r_paste_1_3` | the hook called for every box → the Load box's value `VALUE_0002, CURVE_0001, …` → RED; the hook called on a `restrict` box → the refusal bypassed → RED |
| R-PASTE.1/4 | `test_r_paste_1_4` | the hook called for every box → the Load box's value `VALUE_0002, CURVE_0001, …` → RED; the hook called on a `restrict` box → the refusal bypassed → RED |
| R-TUI-043.4/1 | `test_r_tui_043_4_1` | the hook called for every box → the Load box takes the list → RED |
| R-TUI-043.4/2 | `test_r_tui_043_4_2` | the hook called for every box → the Load box takes the list → RED |
| R-TUI-043.4/3 | `test_r_tui_043_4_3` | the hook called for every box → the Load box takes the list → RED |
| R-PASTE.29/1 | `test_r_paste_29_1` | the hook called for every box → the Load box takes the list → RED |
| R-PASTE.29/2 | `test_r_paste_29_2` | the hook called for every box → the Load box takes the list → RED |
| R-PASTE.29/3 | `test_r_paste_29_3` | the hook called for every box → the Load box takes the list → RED |
| R-A2L-LIST.073/1 | `test_r_a2l_list_073_1` | `rank` on the UI thread → RED |
| R-A2L-LIST.073/2 | `test_r_a2l_list_073_2` | `rank` on the UI thread → RED |
| R-A2L-LIST.071/1 | `test_r_a2l_list_071_1` | no stale check → `cu`'s names painted last → RED |
| R-A2L-LIST.071/2 | `test_r_a2l_list_071_2` | no stale check → `cu`'s names painted last → RED |
| R-A2L-LIST.075/1 | `test_r_a2l_list_075_1` | a ranking started per keystroke → 6 `rank` calls → RED |
| R-A2L-LIST.085/1 | `test_r_a2l_list_085_1` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.085/3 | `test_r_a2l_list_085_3` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.085/5 | `test_r_a2l_list_085_5` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.085/6 | `test_r_a2l_list_085_6` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.084/1 | `test_r_a2l_list_084_1` | the guard removed → `RuntimeError('App is not running')` from `call_from_thread` (E3 Probe A §3) → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.084/2 | `test_r_a2l_list_084_2` | the guard removed → `RuntimeError('App is not running')` from `call_from_thread` (E3 Probe A §3) → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.084/3 | `test_r_a2l_list_084_3` | the guard removed → `RuntimeError('App is not running')` from `call_from_thread` (E3 Probe A §3) → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.087/1 | `test_r_a2l_list_087_1` | no retry → `0017` gives no dropdown until the next A2L load → RED; a retry per request → 6 builds → RED |
| R-A2L-LIST.087/2 | `test_r_a2l_list_087_2` | no retry → `0017` gives no dropdown until the next A2L load → RED; a retry per request → 6 builds → RED |
| R-A2L-LIST.063/1 | `test_r_a2l_list_063_1` | 20 rows → RED |
| R-A2L-LIST.063/2 | `test_r_a2l_list_063_2` | 20 rows → RED |
| R-A2L-LIST.065/1 | `test_r_a2l_list_065_1` | <n> = <k> → `8 of 8` → RED |
| R-A2L-LIST.065/2 | `test_r_a2l_list_065_2` | <n> = <k> → `8 of 8` → RED |
| R-A2L-LIST.064/1 | `test_r_a2l_list_064_1` | no highlight → RED |
| R-A2L-LIST.064/2 | `test_r_a2l_list_064_2` | no highlight → RED |
| R-A2L-LIST.066/1 | `test_r_a2l_list_066_1` | dropdown closed → RED; the text echoed whole or raw → a NUL reaches the terminal → RED |
| R-A2L-LIST.066/2 | `test_r_a2l_list_066_2` | dropdown closed → RED; the text echoed whole or raw → a NUL reaches the terminal → RED |
| R-A2L-LIST.066/3 | `test_r_a2l_list_066_3` | dropdown closed → RED; the text echoed whole or raw → a NUL reaches the terminal → RED |
| R-A2L-LIST.067/1 | `test_r_a2l_list_067_1` | key line swapped → RED |
| R-A2L-LIST.067/2 | `test_r_a2l_list_067_2` | key line swapped → RED |
| R-A2L-LIST.068/1 | `test_r_a2l_list_068_1` | unclamped → no choice → RED |
| R-A2L-LIST.068/2 | `test_r_a2l_list_068_2` | unclamped → no choice → RED |
| R-A2L-LIST.068/3 | `test_r_a2l_list_068_3` | unclamped → no choice → RED |
| R-A2L-LIST.069/1 | `test_r_a2l_list_069_1` | the display text inserted for a name with U+0007 → U+FFFD in the box → RED (I-3 obligation 3) |
| R-A2L-LIST.069/2 | `test_r_a2l_list_069_2` | the display text inserted for a name with U+0007 → U+FFFD in the box → RED (I-3 obligation 3) |
| R-A2L-LIST.069 | `test_r_a2l_list_069_control_inserts_the_name_not_its_display_text` | the display text inserted for a name with U+0007 → U+FFFD in the box → RED (I-3 obligation 3) |
| R-A2L-LIST.070/1 | `test_r_a2l_list_070_1` | Esc clears the box → RED |
| - | `test_i7_filter_box_esc_clears_a_list_text` | (interface check, I-7; no requirement row) |
| R-A2L-LIST.076/1 | `test_r_a2l_list_076_1` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.076/2 | `test_r_a2l_list_076_2` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.076/3 | `test_r_a2l_list_076_3` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.076/6 | `test_r_a2l_list_076_6` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.076/7 | `test_r_a2l_list_076_7` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.077/1 | `test_r_a2l_list_077_1` | no cap → 300 characters → RED; the dropdown row uncapped → a 1,024-character line in a 64-wide box → RED |
| R-A2L-LIST.077/2 | `test_r_a2l_list_077_2` | no cap → 300 characters → RED; the dropdown row uncapped → a 1,024-character line in a 64-wide box → RED |
| R-A2L-LIST.077/3 | `test_r_a2l_list_077_3` | no cap → 300 characters → RED; the dropdown row uncapped → a 1,024-character line in a 64-wide box → RED |
| R-A2L-LIST.077/4 | `test_r_a2l_list_077_4` | no cap → 300 characters → RED; the dropdown row uncapped → a 1,024-character line in a 64-wide box → RED |
| R-A2L-LIST.042/1 | `test_r_a2l_list_042_1` | focus on the add line → RED |
| R-A2L-LIST.043/1 | `test_r_a2l_list_043_1` | placeholder text differs → RED |
| R-A2L-LIST.044/1 | `test_r_a2l_list_044_1` | note left out → RED |
| R-A2L-LIST.045/1 | `test_r_a2l_list_045_1` | labels differ → RED |
| R-A2L-LIST.046/1 | `test_r_a2l_list_046_1` | ribbon budget 80 → 60 glyphs → RED |
| R-A2L-LIST.046/2 | `test_r_a2l_list_046_2` | ribbon budget 80 → 60 glyphs → RED |
| R-A2L-LIST.047/1 | `test_r_a2l_list_047_1` | wide columns at 118 → RED; the columns re-read on resize → 5 columns → RED |
| R-A2L-LIST.047/2 | `test_r_a2l_list_047_2` | wide columns at 118 → RED; the columns re-read on resize → 5 columns → RED |
| R-A2L-LIST.047/3 | `test_r_a2l_list_047_3` | wide columns at 118 → RED; the columns re-read on resize → 5 columns → RED |
| R-A2L-LIST.048/1 | `test_r_a2l_list_048_1` | line left out → RED |
| R-A2L-LIST.049/1 | `test_r_a2l_list_049_1` | each missing name ranked as one query of the whole paste → RED (E3S-01) |
| R-A2L-LIST.049/2 | `test_r_a2l_list_049_2` | each missing name ranked as one query of the whole paste → RED (E3S-01) |
| R-A2L-LIST.050/1 | `test_r_a2l_list_050_1` | line left out → RED; one token for all similar requests → only #11's line → RED |
| R-A2L-LIST.050/2 | `test_r_a2l_list_050_2` | line left out → RED; one token for all similar requests → only #11's line → RED |
| R-A2L-LIST.051/1 | `test_r_a2l_list_051_1` | no cap → 11 lines → RED |
| R-A2L-LIST.051/2 | `test_r_a2l_list_051_2` | no cap → 11 lines → RED |
| R-A2L-LIST.052/1 | `test_r_a2l_list_052_1` | no stale check → earlier lines painted → RED |
| R-A2L-LIST.052/2 | `test_r_a2l_list_052_2` | no stale check → earlier lines painted → RED |
| R-A2L-LIST.057/1 | `test_r_a2l_list_057_1` | appended without new line → `VALUE_0118VALUE_0042` → RED |
| R-A2L-LIST.057/2 | `test_r_a2l_list_057_2` | appended without new line → `VALUE_0118VALUE_0042` → RED |
| R-A2L-LIST.058/1 | `test_r_a2l_list_058_1` | the typed text appended → RED |
| R-A2L-LIST.059/1 | `test_r_a2l_list_059_1` | the first closest name replaces the missing one → RED |
| R-A2L-LIST.061/1 | `test_r_a2l_list_061_1` | list-aware check applied → `0042 val` gives no dropdown → RED |
| R-A2L-LIST.070/2 | `test_r_a2l_list_070_2` | Esc clears the box → RED |
| R-A2L-LIST.078/1 | `test_r_a2l_list_078_1` | no cap → 32,768 rows → 5.6–6.3 s per rebuild (E3 security Probe A §4) → RED |
| R-A2L-LIST.078/2 | `test_r_a2l_list_078_2` | no cap → 32,768 rows → 5.6–6.3 s per rebuild (E3 security Probe A §4) → RED |
| R-A2L-LIST.078/3 | `test_r_a2l_list_078_3` | no cap → 32,768 rows → 5.6–6.3 s per rebuild (E3 security Probe A §4) → RED |
| R-A2L-LIST.086/1 | `test_r_a2l_list_086_1` | no guard → `NoMatches` on `#a2l_list_counts` → RED; an always-drop guard → no counts line → RED |
| R-A2L-LIST.086/2 | `test_r_a2l_list_086_2` | no guard → `NoMatches` on `#a2l_list_counts` → RED; an always-drop guard → no counts line → RED |
| R-A2L-LIST.086/3 | `test_r_a2l_list_086_3` | no guard → `NoMatches` on `#a2l_list_counts` → RED; an always-drop guard → no counts line → RED |
| R-A2L-LIST.085/4 | `test_r_a2l_list_085_4` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-LIST.075/2 | `test_r_a2l_list_075_2` | a ranking started per keystroke → 6 `rank` calls → RED |
| R-A2L-LIST.076/4 | `test_r_a2l_list_076_4` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.076/5 | `test_r_a2l_list_076_5` | markup parsed or controls deleted → RED; the bidi controls passed → RED |
| R-A2L-LIST.077/1 | `test_r_a2l_list_077_1_similar_line` | no cap → 300 characters → RED; the dropdown row uncapped → a 1,024-character line in a 64-wide box → RED |

## G-T-V - `tests/test_b103_a2l_list_view.py` (116 tests)

| Case | Test | Negative control (requirement) |
|---|---|---|
| R-A2L-LIST.006/1 | `test_r_a2l_list_006_1` | text filter kept → 0 rows (`No A2L tags match …`) → RED |
| R-A2L-LIST.006/2 | `test_r_a2l_list_006_2` | text filter kept → 0 rows (`No A2L tags match …`) → RED |
| R-A2L-LIST.006/3 | `test_r_a2l_list_006_3` | text filter kept → 0 rows (`No A2L tags match …`) → RED |
| R-A2L-LIST.007/1 | `test_r_a2l_list_007_1` | tag left `FILTER` → RED |
| R-A2L-LIST.008/1 | `test_r_a2l_list_008_1` | no tag → RED; the kept resolution painted after the unload → 12 rows → RED |
| R-A2L-LIST.008/2 | `test_r_a2l_list_008_2` | no tag → RED; the kept resolution painted after the unload → 12 rows → RED |
| R-A2L-LIST.008/3 | `test_r_a2l_list_008_3` | no tag → RED; the kept resolution painted after the unload → 12 rows → RED |
| R-A2L-LIST.009/1 | `test_r_a2l_list_009_1` | text-mode columns kept → RED |
| R-A2L-LIST.010/1 | `test_r_a2l_list_010_1` | fixed columns 0 → `#` scrolls away → RED |
| R-A2L-LIST.011/1 | `test_r_a2l_list_011_1` | status glyph left out → `VALUE_0002` → RED |
| R-A2L-LIST.011/2 | `test_r_a2l_list_011_2` | status glyph left out → `VALUE_0002` → RED |
| R-A2L-LIST.011/3 | `test_r_a2l_list_011_3` | status glyph left out → `VALUE_0002` → RED |
| R-A2L-LIST.011/4 | `test_r_a2l_list_011_4` | status glyph left out → `VALUE_0002` → RED |
| R-A2L-LIST.012/1 | `test_r_a2l_list_012_1` | a fixed word (`found`) → RED |
| R-A2L-LIST.012/2 | `test_r_a2l_list_012_2` | a fixed word (`found`) → RED |
| R-A2L-LIST.012/3 | `test_r_a2l_list_012_3` | a fixed word (`found`) → RED |
| R-A2L-LIST.012/4 | `test_r_a2l_list_012_4` | a fixed word (`found`) → RED |
| R-A2L-LIST.013/1 | `test_r_a2l_list_013_1` | section always → `CHARACTERISTIC` → RED |
| R-A2L-LIST.013/2 | `test_r_a2l_list_013_2` | section always → `CHARACTERISTIC` → RED |
| R-A2L-LIST.013/3 | `test_r_a2l_list_013_3` | section always → `CHARACTERISTIC` → RED |
| R-A2L-LIST.014/1 | `test_r_a2l_list_014_1` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/2 | `test_r_a2l_list_014_2` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/3 | `test_r_a2l_list_014_3` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/4 | `test_r_a2l_list_014_4` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/5 | `test_r_a2l_list_014_5` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/6 | `test_r_a2l_list_014_6` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/7 | `test_r_a2l_list_014_7` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/8 | `test_r_a2l_list_014_8` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.014/9 | `test_r_a2l_list_014_9` | `Len` from enriched `byte_size` → `MAP_0003` differs → RED |
| R-A2L-LIST.015/1 | `test_r_a2l_list_015_1` | `n/a` painted (R-A2L-006.4) → RED |
| R-A2L-LIST.015/2 | `test_r_a2l_list_015_2` | `n/a` painted (R-A2L-006.4) → RED |
| R-A2L-LIST.016/1 | `test_r_a2l_list_016_1` | the text-mode summary kept → RED |
| R-A2L-LIST.016/2 | `test_r_a2l_list_016_2` | the text-mode summary kept → RED |
| R-A2L-LIST.017/1 | `test_r_a2l_list_017_1` | hidden counted as missing → RED |
| R-A2L-LIST.017/2 | `test_r_a2l_list_017_2` | hidden counted as missing → RED |
| R-A2L-LIST.018/1 | `test_r_a2l_list_018_1` | no budget → 100 glyphs → RED |
| R-A2L-LIST.018/2 | `test_r_a2l_list_018_2` | no budget → 100 glyphs → RED |
| R-A2L-LIST.019/1 | `test_r_a2l_list_019_1` | count of all tags painted as shown → RED; the text echoed whole → 300 characters → RED |
| R-A2L-LIST.019/2 | `test_r_a2l_list_019_2` | count of all tags painted as shown → RED; the text echoed whole → 300 characters → RED |
| R-A2L-LIST.019/3 | `test_r_a2l_list_019_3` | count of all tags painted as shown → RED; the text echoed whole → 300 characters → RED |
| R-A2L-LIST.020/1 | `test_r_a2l_list_020_1` | line left out → RED |
| R-A2L-LIST.020/2 | `test_r_a2l_list_020_2` | line left out → RED |
| R-A2L-LIST.021/1 | `test_r_a2l_list_021_1` | <h> counted with the filter text → RED |
| R-A2L-LIST.021/2 | `test_r_a2l_list_021_2` | <h> counted with the filter text → RED |
| R-A2L-LIST.021/3 | `test_r_a2l_list_021_3` | <h> counted with the filter text → RED |
| R-A2L-LIST.022/1 | `test_r_a2l_list_022_1` | line left out → RED |
| R-A2L-LIST.022/2 | `test_r_a2l_list_022_2` | line left out → RED |
| R-A2L-LIST.023/1 | `test_r_a2l_list_023_1` | line kept with `Missing 0` → RED; the outgoing list's missing line kept after the unload → RED |
| R-A2L-LIST.023/2 | `test_r_a2l_list_023_2` | line kept with `Missing 0` → RED; the outgoing list's missing line kept after the unload → RED |
| R-A2L-LIST.024/1 | `test_r_a2l_list_024_1` | no cap → 1,636 names in one line → RED |
| R-A2L-LIST.024/2 | `test_r_a2l_list_024_2` | no cap → 1,636 names in one line → RED |
| R-A2L-LIST.025/1 | `test_r_a2l_list_025_1` | today's `No A2L tags match 'VALUE_0002'.` kept → RED; the text echoed whole → RED |
| R-A2L-LIST.025/2 | `test_r_a2l_list_025_2` | today's `No A2L tags match 'VALUE_0002'.` kept → RED; the text echoed whole → RED |
| R-A2L-LIST.025/3 | `test_r_a2l_list_025_3` | today's `No A2L tags match 'VALUE_0002'.` kept → RED; the text echoed whole → RED |
| R-A2L-LIST.026/1 | `test_r_a2l_list_026_1` | binding left out → mode kept → RED |
| R-A2L-LIST.026/2 | `test_r_a2l_list_026_2` | binding left out → mode kept → RED |
| R-A2L-LIST.027/1 | `test_r_a2l_list_027_1` | card cleared (`Highlight a tag…`) → RED |
| R-A2L-LIST.028/1 | `test_r_a2l_list_028_1` | rank with `difflib` → `MAP_0024` lists `MAP_0020` → RED |
| R-A2L-LIST.028/2 | `test_r_a2l_list_028_2` | rank with `difflib` → `MAP_0024` lists `MAP_0020` → RED |
| R-A2L-LIST.029/1 | `test_r_a2l_list_029_1` | line left out → RED |
| R-A2L-LIST.030/1 | `test_r_a2l_list_030_1` | line left out → RED |
| R-A2L-LIST.031/1 | `test_r_a2l_list_031_1` | row key mapped to the pasted position → wrong tag → RED; a missing row jumps to address 0 → RED |
| R-A2L-LIST.031/2 | `test_r_a2l_list_031_2` | row key mapped to the pasted position → wrong tag → RED; a missing row jumps to address 0 → RED |
| R-A2L-LIST.031/3 | `test_r_a2l_list_031_3` | row key mapped to the pasted position → wrong tag → RED; a missing row jumps to address 0 → RED |
| R-A2L-LIST.031/4 | `test_r_a2l_list_031_4` | row key mapped to the pasted position → wrong tag → RED; a missing row jumps to address 0 → RED |
| R-A2L-LIST.032/1 | `test_r_a2l_list_032_1` | Esc ignored → list kept → RED |
| R-A2L-LIST.035/1 | `test_r_a2l_list_035_1` | resolve each name by a scan of all tags (no map) → 2,048 × 13,990 compares → RED |
| R-A2L-LIST.036/1 | `test_r_a2l_list_036_1` | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED; the list repainted by a clear and refill → `scroll_y` 0, cursor 0 → RED |
| R-A2L-LIST.036/2 | `test_r_a2l_list_036_2` | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED; the list repainted by a clear and refill → `scroll_y` 0, cursor 0 → RED |
| R-A2L-LIST.036/3 | `test_r_a2l_list_036_3` | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED; the list repainted by a clear and refill → `scroll_y` 0, cursor 0 → RED |
| R-A2L-LIST.036/4 | `test_r_a2l_list_036_4` | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED; the list repainted by a clear and refill → `scroll_y` 0, cursor 0 → RED |
| R-A2L-LIST.036/5 | `test_r_a2l_list_036_5` | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED; the list repainted by a clear and refill → `scroll_y` 0, cursor 0 → RED |
| R-A2L-LIST.085/2 | `test_r_a2l_list_085_2` | no guard → `RuntimeError` from `call_from_thread` or `NoMatches` from a widget lookup → RED; an always-drop guard → the positive arm paints nothing → RED |
| R-A2L-007.1/1 | `test_r_a2l_007_1_1` | substring applied to a list text → RED |
| R-A2L-007.1/2 | `test_r_a2l_007_1_2` | substring applied to a list text → RED |
| R-A2L-007.2/1 | `test_r_a2l_007_2_1` | list text matched as one text → RED |
| R-A2L-007.6/1 | `test_r_a2l_007_6_1` | — (unchanged behaviour in text mode; RED control: mode not reset) |
| R-A2L-007.7/1 | `test_r_a2l_007_7_1` | list rows removed instead of marked (R-A2L-LIST.005) → RED in list mode |
| R-A2L-007.8/1 | `test_r_a2l_007_8_1` | as .7 |
| R-TUI-042a.4/1 | `test_r_tui_042a_4_1` | — |
| R-TUI-069.6/1 | `test_r_tui_069_6_1` | 5-line cap kept → RED at a 6-line card |
| R-TUI-069.7/1 | `test_r_tui_069_7_1` | content clipped, no scroll → `max_scroll_y` 0 → RED |
| R-TUI-069.7/2 | `test_r_tui_069_7_2` | content clipped, no scroll → `max_scroll_y` 0 → RED |
| R-TUI-069.7/3 | `test_r_tui_069_7_3` | content clipped, no scroll → `max_scroll_y` 0 → RED |
| R-TUI-037.1/1 | `test_r_tui_037_1_1` | the stacked layout below 32 rows → the tags pane the whole body width → RED |
| R-TUI-037.1/2 | `test_r_tui_037_1_2` | the stacked layout below 32 rows → the tags pane the whole body width → RED |
| R-TUI-037.1/3 | `test_r_tui_037_1_3` | the stacked layout below 32 rows → the tags pane the whole body width → RED |
| R-TUI-037.2/1 | `test_r_tui_037_2_1` | the stacked layout below 32 rows → the hex pane under the tags pane → RED |
| R-TUI-037.2/2 | `test_r_tui_037_2_2` | the stacked layout below 32 rows → the hex pane under the tags pane → RED |
| R-TUI-037.2/3 | `test_r_tui_037_2_3` | the stacked layout below 32 rows → the hex pane under the tags pane → RED |
| R-A2L-LIST.080/1 | `test_r_a2l_list_080_1` | today's side-by-side panes → the hex view is 42 columns at 118 and 78 at 220, and every hex row wraps in two (P2 §3) → RED |
| R-A2L-LIST.080/2 | `test_r_a2l_list_080_2` | today's side-by-side panes → the hex view is 42 columns at 118 and 78 at 220, and every hex row wraps in two (P2 §3) → RED |
| R-A2L-LIST.081/1 | `test_r_a2l_list_081_1` | 4/7 split kept → hex pane wider than 90 → RED |
| R-A2L-LIST.082/1 | `test_r_a2l_list_082_1` | the wide rules applied → an 8-line card → RED; the stacked rules applied → the card left of the hex box → RED |
| R-A2L-LIST.082/2 | `test_r_a2l_list_082_2` | the wide rules applied → an 8-line card → RED; the stacked rules applied → the card left of the hex box → RED |
| R-A2L-LIST.083/1 | `test_r_a2l_list_083_1` | the stacked layout below 32 rows high → at 160×40 the tags pane is 11 rows → 0 table rows → RED; the find box in a second toolbar row (E3 Probe C) → 0, 7, 7 rows → RED; chips lines wrapping at the pane width (P4) → 0 rows at 120×30 → RED |
| R-A2L-LIST.083/2 | `test_r_a2l_list_083_2` | the stacked layout below 32 rows high → at 160×40 the tags pane is 11 rows → 0 table rows → RED; the find box in a second toolbar row (E3 Probe C) → 0, 7, 7 rows → RED; chips lines wrapping at the pane width (P4) → 0 rows at 120×30 → RED |
| R-A2L-LIST.083/3 | `test_r_a2l_list_083_3` | the stacked layout below 32 rows high → at 160×40 the tags pane is 11 rows → 0 table rows → RED; the find box in a second toolbar row (E3 Probe C) → 0, 7, 7 rows → RED; chips lines wrapping at the pane width (P4) → 0 rows at 120×30 → RED |
| R-A2L-LIST.040/1 | `test_r_a2l_list_040_1` | no binding → nothing opens → RED |
| R-A2L-LIST.040/2 | `test_r_a2l_list_040_2` | no binding → nothing opens → RED |
| R-A2L-LIST.041/1 | `test_r_a2l_list_041_1` | empty text area always (the scene's code) → RED |
| R-A2L-LIST.041/2 | `test_r_a2l_list_041_2` | empty text area always (the scene's code) → RED |
| R-A2L-LIST.053/1 | `test_r_a2l_list_053_1` | names joined by new lines → box keeps one line → RED |
| R-A2L-LIST.053/2 | `test_r_a2l_list_053_2` | names joined by new lines → box keeps one line → RED |
| R-A2L-LIST.054/1 | `test_r_a2l_list_054_1` | filter cleared → RED |
| R-A2L-LIST.055/1 | `test_r_a2l_list_055_1` | apply on Esc → RED |
| R-A2L-LIST.055/2 | `test_r_a2l_list_055_2` | apply on Esc → RED |
| R-A2L-LIST.056/1 | `test_r_a2l_list_056_1` | outgoing statuses kept → RED |
| R-A2L-LIST.060/1 | `test_r_a2l_list_060_1` | no dropdown → RED |
| R-A2L-LIST.060/2 | `test_r_a2l_list_060_2` | no dropdown → RED |
| R-A2L-LIST.060/3 | `test_r_a2l_list_060_3` | no dropdown → RED |
| R-A2L-LIST.062/1 | `test_r_a2l_list_062_1` | dropdown kept → RED |
| R-A2L-LIST.062/2 | `test_r_a2l_list_062_2` | dropdown kept → RED |
| R-A2L-LIST.072/1 | `test_r_a2l_list_072_1` | prepared on the UI thread → thread-id assertion RED |
| R-A2L-LIST.072/2 | `test_r_a2l_list_072_2` | prepared on the UI thread → thread-id assertion RED |
| R-A2L-LIST.074/1 | `test_r_a2l_list_074_1` | dropdown opened only on the next keystroke → RED |

## G-T-AT - `tests/test_b103_a2l_list_at.py` (10 tests)

| Case | Test | Negative control (requirement) |
|---|---|---|
| AT-B103-I7-1/1 | `test_at_b103_i7_1_list_mode_from_paste` | (interface check, I-7; no requirement row) |
| AT-B103-I7-1/2 | `test_at_b103_i7_1_jump_from_list` | (interface check, I-7; no requirement row) |
| AT-B103-I7-1/3 | `test_at_b103_i7_1_esc_back_to_text` | (interface check, I-7; no requirement row) |
| AT-B103-I7-2/1 | `test_at_b103_i7_2_window_live_status` | (interface check, I-7; no requirement row) |
| AT-B103-I7-2/2 | `test_at_b103_i7_2_add_from_dropdown` | (interface check, I-7; no requirement row) |
| AT-B103-I7-2/3 | `test_at_b103_i7_2_apply_to_viewer` | (interface check, I-7; no requirement row) |
| AT-B103-I7-3/1 | `test_at_b103_i7_3_dropdown_typo` | (interface check, I-7; no requirement row) |
| AT-B103-I7-3/2 | `test_at_b103_i7_3_tab_completes` | (interface check, I-7; no requirement row) |
| AT-B103-I7-4/1 | `test_at_b103_i7_4_layout_118` | (interface check, I-7; no requirement row) |
| AT-B103-I7-4/2 | `test_at_b103_i7_4_layout_220` | (interface check, I-7; no requirement row) |

Total: 237 tests.
