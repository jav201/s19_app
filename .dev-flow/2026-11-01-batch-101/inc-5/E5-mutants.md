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

## Batch-end re-run on the final tree (b982846)

RA-1's batch-end battery: M1 … M24 re-ran on the merged final tree (head `b982846`, every increment merged). Base copy = a detached worktree at `7d641d9` with `git diff --binary 7d641d9 b982846 -- s19_app tests docs README.md AT-TC-REGISTRY.jsonl` applied (content = `b982846`). Runs on the LAN Linux host only (operator rule), Python 3.11.18, `env -u NO_COLOR python -m pytest -p no:cacheprovider -q -rf <nodes>` under `timeout 1800`; nothing that imports `s19_app` ran on the Windows PC. Baseline: the 30 unique guard nodes all GREEN (30 passed). Each mutant ran in a `cp -a` copy, one mutation at a time, over only its own guard nodes; transcripts print the base commit, the mutation diff and `s19_app.__file__` from inside the copy, and are redacted (home folder → `<HOME>`, account name → `<USER>`, host address → `LAN Linux laptop`, `pytest-of-<name>` → `pytest-of-<user>`).

Every row applied **unchanged**: its target code is byte-identical between `8fc3cd3` and `b982846` (only line numbers relocated); none was re-expressed and none lost its target. The mutated files changed between the two commits only in ways outside the mutation targets — a `Data Flow` block on `note_image_bytes_written` and the `_spec_bytes` annotation (C-9), the `_check_items_to_document` Summary docstring (C-7), and unrelated Patch/Check Editor docstring + compose edits (Inc 12).

| M | Original mutation | Final-tree mutation (unchanged / re-expressed / no target) | Nodes | Result | Transcript |
|---|---|---|---|---|---|
| M1 | 002.5 hook absent (apply site) | unchanged — `app.py:4971-4972` | D 002_5_3, 002_5_6, 002_5_8 | KILLED | `evidence/close/inc5-mut-01.txt` |
| M2 | 002.5 hook absent (save-back site) | unchanged — `app.py:5105` | D 002_5_4, 002_5_7 | KILLED | `evidence/close/inc5-mut-02.txt` |
| M3 | 002.1/6, 002.5 hook absent (project-save site) | unchanged — `app.py:13384` | D 002_5_5, 002_1_6 (both limbs) | KILLED | `evidence/close/inc5-mut-03.txt` |
| M4 | 002.5 hook recomputing while hidden | unchanged — `crc_designer_view.py:729` | D 002_5_3 … 002_5_8 | KILLED | `evidence/close/inc5-mut-04.txt` |
| M5 | 002.5/6 hook in the success branch only | unchanged — delete `app.py:4967-4972`, insert after `app.py:4922` | D 002_5_6 | KILLED | `evidence/close/inc5-mut-05.txt` |
| M6 | addendum 2a (SEC5-2): save-back hook under `result.ok` | unchanged — `app.py:5105` into `if result.ok:` (`app.py:5107`) | D 002_5_7 | KILLED | `evidence/close/inc5-mut-06.txt` |
| M7 | addendum 2b (A-2): apply hook under `applied > 0` | unchanged — `app.py:4971` | D 002_5_8 | KILLED | `evidence/close/inc5-mut-07.txt` |
| M8 | R-CHKED-010 picks cleared on a repopulation (base) | unchanged — `screens_directionb.py:7308` | C 010_2, 010_3, 026_4, 055_1, 025_3 | KILLED | `evidence/close/inc5-mut-08.txt` |
| M9 | R-CHKED-055 every earlier name kept without the new ledger | unchanged — `screens_directionb.py:7308` | C 055_1 | KILLED | `evidence/close/inc5-mut-09.txt` |
| M10 | R-CHKED-054 post-Write refresh clears the picks | unchanged — `app.py:7871-7872` | C 054_1 | KILLED | `evidence/close/inc5-mut-10.txt` |
| M11 | R-CHKED-041.1 earlier fields kept | unchanged — `screens_directionb.py:7325, 7327` | C 041_1 | KILLED | `evidence/close/inc5-mut-11.txt` |
| M12 | R-CHKED-041.1 an entry dropped | unchanged — `screens_directionb.py:7334` | C 041_1, 041_2_1 | KILLED | `evidence/close/inc5-mut-12.txt` |
| M13 | R-CHKED-041.2 resolution removed (base) | unchanged — `screens_directionb.py:7341-7343` | C 041_2_1, 041_2_3, 026_4, 056_1, 056_2, 056_3; S sym_9 | KILLED | `evidence/close/inc5-mut-13.txt` |
| M14 | R-CHKED-041.2 symbol ignored | unchanged — `screens_directionb.py:7407-7410` | C 041_2_3 | KILLED | `evidence/close/inc5-mut-14.txt` |
| M15 | R-CHKED-041.2/.3 size ignored (address only) | unchanged — `screens_directionb.py:7331, 7411` | C 041_3_3 | KILLED | `evidence/close/inc5-mut-15.txt` |
| M16 | R-CHKED-041.3/4 first match on an ambiguity | unchanged — `screens_directionb.py:7412` | C 041_3_4 | KILLED | `evidence/close/inc5-mut-16.txt` |
| M17 | R-CHKED-041.3/5 duplicate included twice / dropped | unchanged — `screens_directionb.py:7412` | C 041_3_5 | KILLED | `evidence/close/inc5-mut-17.txt` |
| M18 | R-CHKED-041.3/6 symbol range mismatch falls back to the address rule (A-6) | unchanged — `screens_directionb.py:7410` | C 041_3_6 | KILLED | `evidence/close/inc5-mut-18.txt` |
| M19 | R-CHKED-025/2 spec bytes never pruned on a toggle | unchanged — `screens_directionb.py:7872` | C 025_2 | KILLED | `evidence/close/inc5-mut-19.txt` |
| M20 | R-CHKED-026 expected bytes re-read from the image (base) | unchanged — `app.py:7776-7784` | C 026_1, 026_2, 026_3, 026_4, 027_2 | KILLED | `evidence/close/inc5-mut-20.txt` |
| M21 | R-CHKED-026/4 spec bytes dropped on every repopulation | unchanged — `screens_directionb.py:7305` | C 026_4 | KILLED | `evidence/close/inc5-mut-21.txt` |
| M22 | R-CHKED-056/2 R-CHKED-055's drop applied to a spec field | unchanged — `screens_directionb.py:7441-7443` | C 056_1, 056_2, 056_3 | KILLED | `evidence/close/inc5-mut-22.txt` |
| M23 | R-CHKED-056/3 byte count left out of the key | unchanged — `screens_directionb.py:7438, 7455, 7502` | C 056_3 | KILLED | `evidence/close/inc5-mut-23.txt` |
| M24 | addendum 2c (SEC5-1 + Round-2 NOTE): name-only spec-bytes key (the E1 design) | unchanged — `screens_directionb.py:7432-7446, 7451-7456, 7502` | C 056_1, 056_2, 056_3, 025_3 | KILLED | `evidence/close/inc5-mut-24.txt` |

### Score

**KILLED 24 / 24 · SURVIVED 0 · mutation score 100 %** on the final tree `b982846`. No survivors, so no per-survivor judgement. Every mutant turned its guard nodes RED for the same behavioural reason as the `8fc3cd3` battery (the transcripts' first assertion lines match), and the baseline of all 30 unique guard nodes was GREEN before the runs.
