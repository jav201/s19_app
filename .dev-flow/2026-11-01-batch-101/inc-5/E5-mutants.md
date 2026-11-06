# Inc 5 — E5 mutant table (M1 … M24)

Batch 2026-11-01-batch-101, increment 5, stage E5 (design-first flow). Battery: DeepSeek, one unit. Base `c2cba35`; branch `b101-inc5`; head `8fc3cd3`. Runs: **LAN Linux host** only (operator rule; nothing that imports `s19_app` ran on the Windows PC), Python 3.11.18. The integrated tree was built in a detached worktree at `c2cba35` with `git diff --binary c2cba35 8fc3cd3 -- s19_app tests docs` applied (uncommitted); every mutant ran in a `cp -a` copy of that tree, one mutation at a time, over only its own guard nodes.

- Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -n 6 --tb=short <nodes>`.
- Guard files: `tests/test_b101_designer_writes.py` (**D**), `tests/test_b101_check_spec_keep.py` (**C**), `tests/test_b101_symbol_reads.py` (**S**).
- Source files mutated: `s19_app/tui/app.py`, `s19_app/tui/crc_designer_view.py`, `s19_app/tui/screens_directionb.py` — only.
- Baseline: the 30 guard nodes GREEN on the integrated tree (30 passed, first run).
- Transcripts: `../evidence/inc-5/mut-01.txt` … `mut-24.txt` (each prints the base commit and `s19_app.__file__` = the copy's path).

## Verdict

**24 / 24 KILLED.** Every row of the table turns its guard nodes RED for the stated reason; no mutant survives.

## Table

| id | row | mutation (file:line · before → after) | guard nodes | result | first assertion line |
|---|---|---|---|---|---|
| M1 | 002.5 hook absent (apply site) | `app.py:4913` · `if event.action == "apply_doc": self._note_image_bytes_written()` → deleted | D 002_5_3, 002_5_6, 002_5_8 | KILLED | `E   AssertionError: no settled recompute: count 8 (snapshot 8), pending None` |
| M2 | 002.5 hook absent (save-back site) | `app.py:5046` · `self._note_image_bytes_written()` → deleted | D 002_5_4, 002_5_7 | KILLED | `E   AssertionError: no settled recompute: count 9 (snapshot 9), pending None` |
| M3 | 002.1/6, 002.5 hook absent (project-save site) | `app.py:12636` · `self._note_image_bytes_written()` → deleted | D 002_5_5, 002_1_6 (both limbs) | KILLED | `E   AssertionError: no recompute is pending after the Save project commit: the designer was not told; it paints ['concat: 0x08DAAFB7', 'fill:   0x35D90BC3']` |
| M4 | 002.5 hook recomputing while hidden | `crc_designer_view.py:724` · `self._on_image_changed()` → `self._schedule_recompute()` | D 002_5_3 … 002_5_8 | KILLED | `E   AssertionError: a hidden CRC Designer recomputed` |
| M5 | 002.5/6 hook in the success branch only | `app.py:4913` · apply hook moved inside the arm after `set_status(f"Apply: …")` (inside the `try`) | D 002_5_6 | KILLED | `E   AssertionError: no settled recompute: count 8 (snapshot 8), pending None` |
| M6 | addendum 2a (SEC5-2): save-back hook under `result.ok` | `app.py:5046` · `self._note_image_bytes_written()` → moved into `if result.ok:` | D 002_5_7 | KILLED | `E   AssertionError: no settled recompute: count 9 (snapshot 9), pending None` |
| M7 | addendum 2b (A-2): apply hook under `applied > 0` | `app.py:4913` · `if event.action == "apply_doc":` → `if event.action == "apply_doc" and counts["applied"] > 0:` | D 002_5_8 | KILLED | `E   AssertionError: no settled recompute: count 9 (snapshot 9), pending None` |
| M8 | R-CHKED-010 picks cleared on a repopulation (base) | `screens_directionb.py:7300` · `self._picker.include_names(kept)` → deleted | C 010_2, 010_3, 026_4, 055_1, 025_3 | KILLED | `E   AssertionError: []` |
| M9 | R-CHKED-055 every earlier name kept without the new ledger | `screens_directionb.py:7300` · `include_names(kept)` → `self._picker._picked_params.extend(n for n in kept if n not in self._picker._picked_params)` | C 055_1 | KILLED | `E   AssertionError: ['VALUE_0001', 'VALUE_0002']` |
| M10 | R-CHKED-054 post-Write refresh clears the picks | `app.py:7416` · before `self._prefill_check_editor()` → insert `panel._picker.clear_picks()` | C 054_1 | KILLED | `E   AssertionError: []` |
| M11 | R-CHKED-041.1 earlier fields kept | `screens_directionb.py:7317` · `self._picker.clear_picks()` and `self._memory_rows = []` → deleted | C 041_1 | KILLED | `E   AssertionError: (['VALUE_0003', 'VALUE_0001', 'VALUE_0002'], [('0x00001000', 'OLD_A', 'u16'), ('0x00001010', 'OLD_B', 'u8'), ('0x00C00FFC', '—', 'u32')])` |
| M12 | R-CHKED-041.1 an entry dropped | `screens_directionb.py:7326` · before `for item in items:` → insert `items = list(items)[:-1]` | C 041_1, 041_2_1 | KILLED | `E   AssertionError: ['2 fields: 2 params · 0 memory rows', '◆ 0x00000000 VALUE_0001', '◆ 0x00000014 VALUE_0002']` |
| M13 | R-CHKED-041.2 resolution removed (base) | `screens_directionb.py:7333` · `name = self._named_parameter(…)` → `name = None` | C 041_2_1, 041_2_3, 026_4, 056_1, 056_2, 056_3; S `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` | KILLED | `E   AssertionError: []` |
| M14 | R-CHKED-041.2 symbol ignored | `screens_directionb.py:7399` · the `isinstance(symbol, str) …` branch → deleted | C 041_2_3 | KILLED | `E   AssertionError: []` |
| M15 | R-CHKED-041.2/.3 size ignored (address only) | `screens_directionb.py:7323,7403` · `by_key.setdefault((address, size), …)` / `by_key.get((address, size), …)` → keyed by `address` only | C 041_3_3 | KILLED | `E   AssertionError: ['VALUE_0002']` |
| M16 | R-CHKED-041.3/4 first match on an ambiguity | `screens_directionb.py:7404` · `if len(names) == 1 and names[0] not in taken:` → `if names and names[0] not in taken:` | C 041_3_4 | KILLED | `E   AssertionError: ['ALPHA']` |
| M17 | R-CHKED-041.3/5 duplicate included twice / dropped | `screens_directionb.py:7404` · drop the `not in taken` test → `if len(names) == 1:` | C 041_3_5 | KILLED | `E   AssertionError: timed out waiting for the seam load: '1 field: 1 param · 0 memory rows'` |
| M18 | R-CHKED-041.3/6 symbol range mismatch falls back to the address rule (A-6) | `screens_directionb.py:7402` · `return None` after the symbol range test → deleted (falls through) | C 041_3_6 | KILLED | `E   AssertionError: ['GAMMA']` |
| M19 | R-CHKED-025/2 spec bytes never pruned on a toggle | `screens_directionb.py:7871` · `self._prune_spec_bytes()` → deleted | C 025_2 | KILLED | `E   AssertionError: [(20, b'\xa0\xbe'), (0, b'l'), (12587004, b'\xff\xff\xff\xff')]` |
| M20 | R-CHKED-026 expected bytes re-read from the image (base) | `app.py:7324` · the `spec_expected` branch → deleted | C 026_1, 026_2, 026_3, 026_4, 027_2 | KILLED | `E   AssertionError: ['Check Editor: 3 field(s) outside the loaded image — not declared.', 'Check Editor: wrote noimage.chk.json (0 fields, kind=check).']` |
| M21 | R-CHKED-026/4 spec bytes dropped on every repopulation | `screens_directionb.py:7297` · after `set_parameters` returns → insert `self._spec_bytes = {}` | C 026_4 | KILLED | `E   AssertionError: [(0, b'\x93'), (20, b'\xa0\xbe'), (12587004, b'\xff\xff\xff\xff')]` |
| M22 | R-CHKED-056/2 R-CHKED-055's drop applied to a spec field | `screens_directionb.py:7433` · `self._memory_rows.append(…)` → deleted | C 056_1, 056_2, 056_3 | KILLED | `E   AssertionError: [('0x00C00FFC', '—', 'u32')]` |
| M23 | R-CHKED-056/3 byte count left out of the key | `screens_directionb.py:7430,7447,7494` · `[:2] == spec[:2]` / `spec[:2] == (address, size)` → `[:1]` (address only) | C 056_3 | KILLED | `E   AssertionError: ['VALUE_0001', 'VALUE_0002']` |
| M24 | addendum 2c (SEC5-1 + Round-2 NOTE): name-only spec-bytes key (the E1 design) | `screens_directionb.py:7427` return `kept` unchanged (no demotion); `:7442` keep by name only (drop the range test); `:7494` `expected = spec[2]` whenever `spec is not None` | C 056_1, 056_2, 056_3, 025_3 | KILLED | `E   AssertionError: ['VALUE_0001', 'VALUE_0002']` |

## Score

**KILLED 24 / 24 · SURVIVED 0 · mutation score 100 %.**

No source file and no test body changed by this battery. The remote worktree, its copy and the `i5m-*` helpers were removed after the runs.
