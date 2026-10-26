# DDR fixes — evidence index (batch 2026-10-25-batch-99)

Worktree `C:\Users\jjgh8\Github\s19_app-b99-ddr`, branch `b99-ddr` at `bab3bff`.
Tests-only increment: no file under `s19_app/` was modified (verified with
`git status --porcelain -- s19_app/` — empty). All runs use
`env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8
PYTHONPATH=<worktree>` and the `s19env` interpreter; the import probe
(`python -c "import s19_app; print(s19_app.__file__)"`) printed a path inside
this worktree before every test run.

## Change → DDR condition map

### C-18 / DQ-1 — one joined node per AT (HIGH, gate-blocking)

| AT | Joined node (one pilot session, whole named outcome) | Renamed TC sub-arms | Stability |
|---|---|---|---|
| AT-B99-03 (HLR-154) | `tests/test_b99_truncation.py::test_at_b99_03_status_leads_defect_flow_source_fails` — load cut S19 → `#status_text` leads with `S19-NO-TERMINATOR`, issues panel names it → flow over it: SOURCE fails, nothing written | `test_at_b99_03_hostile_name_renders_literally` → `test_tc_b99_10_hostile_name_renders_literally` | 8/8 runs `1 passed` (`green-at03-8x.txt`) |
| AT-B99-04 (HLR-155) | `tests/test_b99_staging.py::test_at_b99_04_duplicate_refused_distinct_parallel_markers` — 8 distinct lanes run in parallel, each file byte-equal to its lane marker → the `same.s19`/`SAME.s19` set refused, both lanes named, nothing written | the two old `test_at_b99_04_*` nodes merged into the joined node (no TC arm needed) | 8/8 runs passed (`green-at04-8x.txt`) |
| AT-B99-08 (HLR-157) | `tests/test_b99_editor_image.py::test_at_b99_08_save_back_keeps_editor_image` (already carried the whole chain — designated) | `test_at_b99_08_verify_mismatch_status_still_names_entries` → `test_tc_b99_22_verify_mismatch_status_still_names_entries` | full file 8 passed (in `green-b99.txt`) |
| AT-B99-11 (HLR-160) | `tests/test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix` — hostile segment `x/../../../ESCAPED` exports inside the destination under a sanitised name → MAC-only export holds no data record (independent reader) → patched second export lands as `<name>_1`, status names it, first file intact | `…_part_way_failure_status_names_the_first_file` → `test_tc_b99_41_…`; `…_junctioned_project_home_shows_refusal` → `test_tc_b99_29_…` | 8/8 runs passed (`green-at11-8x.txt`) |

### DQ-2 — AT-B99-04 entry is black-box

`tests/test_b99_staging.py`: no `app._handle_load_project`, no `Button.press()`,
no `ModeToggle.set_mode`, no `Input.value =`. Entry is the Load project dialog
(rail key `p`, click the `#project_list` row, `#project_ok`), parallel mode by
clicking the `#fx_mode` toggle's "parallel" word, run by `pilot.click("#fx_run")`;
waits observe painted `#log_line_4` / `#fx_log` and files on disk
(`green-staging.txt`, 31 passed; `green-at04-8x.txt`).

### DQ-3 — AT-B99-09 entry is black-box

`tests/test_b99_a2l_encode.py::_load_through_dialog` now types the path with
`pilot.press(*text)` after clicking `#load_path`, clicks `#load_ok`, and waits
on the painted `#log_line_4` status — `Input.value =`, `Button.press()` and
the `app.current_file` wait are gone (`green-a2l.txt`, 7 passed).

### DQ-4 — AT-B99-12 clicks Add / Apply

`tests/test_b99_bytes_field.py::test_at_b99_12_typed_hex_run_saves_back`:
`#patch_entry_add_button` and `#patch_doc_apply_button` are clicked. The
save-back confirm keeps a single `Button.press()` with a re-verified
justification: at the test's 120×40 geometry the prompt row lives in the
hidden JSON-pane tab and its region is clipped under the status bar, so the
confirm is genuinely not clickable (probed; clicking `#patch_tab_json` still
misses; the click works only at height 54, which would change the acceptance
scenario) (`green-bytes.txt`, 3 passed).

### F-2 (LOW) — a lane carrying both terminal-line riders

`tests/test_b99_patch_truth.py::test_tc_b99_18_lane_line_carries_patch_and_crc_riders`
(new TC-B99-18 sub-arm): one lane with a partial PATCH (`0xEB10` applied,
`0x20000` skipped-outside) and a partial CRC (region `0xFA00–0xFC00` straddling
a gap, 466 absent bytes computed from the independent reader's map). The painted
lane terminal line carries BOTH `PATCH: 1 of 2 entries not applied
(0x00020000 skipped-outside)` AND `CRC: 466 of 512 region bytes absent
(0xFA00-0xFC00)` plus the `wrote o.s19` tail (driven at 280×60 because the
combined line exceeds 220 cells — the clipping under test is the F-2 shape)
(`green-tc18-riders.txt`, 1 passed; `green-patch-truth.txt`, 20 passed).

### F-6 (MEDIUM) — signed-balance ledger drift

Packets corrected (each cites its count command):
`03-increments/increment-005.md` `5 → 8` (test_b99_crc_region.py),
`increment-006.md` `17 → 25` (test_b99_export.py),
`increment-009.md` `20 → 25` (test_b99_truncation.py).
Count basis: `pytest --collect-only -q tests/test_b99_<file>.py | grep -c "::"`
(8 / 25 / 25), with `git show HEAD:tests/test_b99_<file>.py | grep -c
"^def test_"` as the def-level cross-check (8 / 25 / 18 — truncation's 7
parametrized expansions account for the difference). The three increments now
sum to the DDR's 142 collected nodes; this increment's joins/renames then take
the batch total to 139 collected (see `03-increments/increment-012.md`).

### DQ-6 — the two qa-reviewer mutants re-run with transcripts

| Mutant | Transcript | Result |
|---|---|---|
| PQ-2(c) "skip claim removal": `place_group_into_workarea` PermissionError branch `if claims_owned:` → `if False:` | `mut-PQ2c.txt` | KILLED — `test_tc_b99_31_forced_failure_rolls_back_every_own_claim` FAILED, `t_isle_1.addr`/`t_isle_1.bin` left behind (1 failed, 5 passed) |
| PQ-6 help-arm revert: Bytes help line reverted to the `5021bb6^` text | `mut-PQ6.txt` | KILLED — `test_tc_b99_33_field_and_help_state_the_hex_rule` FAILED at the `0x` assertion |

Both were run in a scratch extract of `git archive HEAD` (the current
`tests/test_b99_export.py` / `tests/test_b99_bytes_field.py` overlaid), because
mutating live `s19_app/` files would have raced the parallel test runs; the
import probe in each transcript prints the scratch path. Each mutant was
reverted by hash (`git show HEAD:<file>` byte-compared with `cmp`, recorded in
the transcript) and the scratch deleted. The worktree's `s19_app/` was never
touched.

## Full sweep

`green-b99.txt` — `tests/test_b99_*.py` + `tests/test_address_census.py` +
`tests/test_id_registry.py`, one run.

## Per-file green transcripts

| Transcript | Scope |
|---|---|
| `green-truncation.txt` | tests/test_b99_truncation.py (24 passed) |
| `green-staging.txt` | tests/test_b99_staging.py (31 passed) |
| `green-export.txt` | tests/test_b99_export.py (23 passed) |
| `green-patch-truth.txt` | tests/test_b99_patch_truth.py (20 passed) |
| `green-a2l.txt` | tests/test_b99_a2l_encode.py (7 passed) |
| `green-bytes.txt` | tests/test_b99_bytes_field.py (3 passed) |
| `green-tc18-riders.txt` | the new TC-B99-18 lane-riders node (1 passed) |
| `green-at03-8x.txt` / `green-at04-8x.txt` / `green-at11-8x.txt` | joined-AT stability, 8 runs each |

## Node-count ledger for this increment

`grep -c "^def test_"` per file, before → after:
truncation 18 → 17 (−1 merge), staging 32 → 31 (−1 merge), export 25 → 23
(−2 merge), patch_truth 12 → 13 (+1 F-2 node); editor_image 8 → 8, a2l_encode
7 → 7, bytes_field 3 → 3 (renames / entry fixes only). Net −3 defs
(128 → 125); collected nodes 142 → 139.
