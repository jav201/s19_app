# U1-recite — apply `recite-map.tsv` with one mechanical script

- Unit: U1-recite
- HEAD: `b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80`
- Start: Thu Nov 19 01:42:50 PM CST 2026
- Files written (outside the repo): `../apply_recite.py` (299 lines, functions ≤ 35), `../test_apply_recite.py`

## Step 1 — script test file

```
S=$(realpath ../state); ... ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q ../test_apply_recite.py
11 passed in 0.50s
```

## Step 2 — base collection + base trace

- Base collection: `9834 tests collected` (N0 = 9834).
- Base trace (`../in/reverse_trace.py --repo . --out ../state/rt-before --tmp ../state/rt-tmp --ta2`):

```
tests: 6966 {'O': 1563, 'K?': 602, 'S': 1215, 'K': 3062, 'X': 484, 'U': 40}
```

(expects `6966 … 'X': 484, 'U': 40` — matches.)

## Step 3 — dry run, then --apply

```
REPLACE rows: 144 (applied=144, already=0)
ADD rows: 242 (applied=242, already=0)
NEEDS-RULING rows: 4 (skipped=4)
files: 65
```

144 REPLACE + 242 ADD = 386 applied, 4 skipped, 65 files. `git diff --stat`: 65 files changed, 334 insertions, 155 deletions (all under `tests/`).

## Step 4 — negative controls

- **NC-a (bad id refused):** `nc-map.tsv` with seq 368 new_ids → `R-NOPE-999.1`; dry run on a fresh `git archive HEAD` base tree → `recite: non-canon new_ids: 368=R-NOPE-999.1`, exit 2.
- **NC-b (idempotent):** rerun `--apply` on the applied tree → `REPLACE rows: 144 (applied=0, already=144)`, `ADD rows: 242 (applied=0, already=242)`, `files: 0`; `git diff | md5sum` identical before/after (`97fcbbb60367d589e2a2e291c1619af6`).

## Step 5 — after collection + trace + scope join

- After collection: `9834 tests collected` — delta 0 vs N0.
- After trace (`../state/rt-after`):

```
tests: 6966 {'O': 1561, 'K?': 625, 'S': 1215, 'K': 3280, 'X': 278, 'U': 7}
```

(expects `6966`, `X 278`, `U 7` — matches.)

- Join `../state/rt-after/TA2-matrix.tsv` × `../in/scope-before.tsv` on (file, test); scope tests still class X or U (exactly 3):

```
U	U-STALE	tests/test_b101_designer_recompute.py::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named
U	U-STALE	tests/test_examples_pilot_gifs.py::test_case_pilot_capture_and_gif
X	TR01-RETRACE	tests/test_validation_mac.py::test_validate_mac_records_reports_parse_and_empty_fields
```

The 4th NEEDS-RULING test `tests/test_b102_patch_picker.py::test_tc_b102_pe_06_empty_states_mirror_check` is class O. Matches the brief (2 U + 1 X + 1 O).

## Step 6 — end

```
$ git diff --stat | tail -1
 65 files changed, 334 insertions(+), 155 deletions(-)
$ git diff | grep -c $'\r'
0
$ ... pytest -q ../test_apply_recite.py
11 passed in 0.46s
```

## Deviations

None. The apply script was exercised with both the miniconda base `python3` and `~/miniconda3/envs/s19ci/bin/python` (3.11); the final idempotent rerun under s19ci 3.11 reports all `already` (no further diff), so the applied tree is interpreter-stable. No map row was edited — all 386 rows applied as mapped; the 4 NEEDS-RULING rows were skipped and left untouched.

## Open questions

None.

UNIT_DONE U1-recite
