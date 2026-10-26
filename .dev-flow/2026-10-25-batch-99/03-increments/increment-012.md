# Increment 012 — batch-99 DDR fixes (tests and packets only)

| Field | Value |
|---|---|
| Brief | `kimi/BRIEF-ddr-fix.md` + `kimi/BRIEF-COMMON.md` |
| Base | `bab3bff` (all 12 increments merged; DDR reviews on disk) |
| Mode | tests-only increment — **no SOURCE file changed** (`git status --porcelain -- s19_app/` empty, re-verified at handoff) |
| Conditions discharged | C-18/DQ-1 (one joined node per AT: AT-B99-03/04/08/11), DQ-2 (AT-04 black-box entry), DQ-3 (AT-09 entry), DQ-4 (AT-12 clicks), F-2 LOW (dual-rider lane), F-6 MEDIUM (ledger drift in Incs 5/6/9), DQ-6 (PQ-2(c) + PQ-6 mutants re-run with transcripts) |

## 1 · What changed

1. **C-18 joins.** AT-B99-03, AT-B99-04 and AT-B99-11 each became ONE joined
   node driving every named outcome of the AT's HLR "Observable outcome" in a
   single pilot session; the leftover arms moved off the `at_b99` id onto the
   TC they serve. AT-B99-08 needed no new node — its first node already
   carries the whole chain and is now the designated AT; the mismatch arm was
   renamed to a TC-B99-22 sub-arm.
2. **DQ-2..DQ-4 black-box entries.** AT-B99-04 loads through the Load project
   dialog (`p`, row, `#project_ok`), sets parallel mode by clicking `#fx_mode`,
   runs via `pilot.click("#fx_run")` — no `_handle_load_project`,
   `Button.press()`, `set_mode` or `Input.value =`. AT-B99-09 types the path
   and clicks `#load_ok`, waiting on painted `#log_line_4`. AT-B99-12 clicks
   Add/Apply; the save-back confirm keeps one `Button.press()` with a
   re-verified geometry justification (hidden JSON-pane tab + clipped region
   at 120×40).
3. **F-2 coverage.** `test_tc_b99_18_lane_line_carries_patch_and_crc_riders`:
   one lane, partial PATCH + partial CRC, both riders asserted on the painted
   terminal line plus the `wrote …` tail.
4. **F-6 ledger.** `increment-005.md` `5→8`, `increment-006.md` `17→25`,
   `increment-009.md` `20→25`, each citing its count command; the three
   increments now reconcile at the DDR's 142 collected nodes.
5. **DQ-6 mutants.** PQ-2(c) and PQ-6 re-run in a scratch extract, both
   KILLED, reverted by hash, transcripts in `evidence/ddr/`.

## 2 · Files modified

| File | Kind | Change |
|---|---|---|
| `tests/test_b99_truncation.py` | test | joined AT-03 node; hostile arm → `test_tc_b99_10_hostile_name_renders_literally`; 2 old AT nodes merged |
| `tests/test_b99_staging.py` | test | joined AT-04 node (black-box); 2 old AT nodes merged; local `_fx_import_lane_click` helper |
| `tests/test_b99_editor_image.py` | test | AT-08 mismatch arm → `test_tc_b99_22_verify_mismatch_status_still_names_entries` |
| `tests/test_b99_export.py` | test | joined AT-11 node; part-way arm → `test_tc_b99_41_…`; junctioned arm → `test_tc_b99_29_…` |
| `tests/test_b99_a2l_encode.py` | test | `_load_through_dialog` black-box (DQ-3) |
| `tests/test_b99_bytes_field.py` | test | AT-12 Add/Apply clicked (DQ-4) |
| `tests/test_b99_patch_truth.py` | test | new `test_tc_b99_18_lane_line_carries_patch_and_crc_riders` |
| `03-increments/increment-005/006/009.md` | packet | signed-balance ledger lines corrected (F-6) |
| `evidence/ddr/*` | evidence | transcripts, this packet's evidence home |
| **SOURCE files** | **0 / 4** | none |

## 3 · How to test

```
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
  PYTHONPATH=<worktree> python -m pytest -q -p no:cacheprovider \
  tests/test_b99_*.py tests/test_address_census.py tests/test_id_registry.py
```
(import probe first: `python -c "import s19_app; print(s19_app.__file__)"`.)

## 4 · Test results

- Joined AT-B99-03: 8/8 runs `1 passed` (`green-at03-8x.txt`).
- Joined AT-B99-04: 8/8 runs passed (`green-at04-8x.txt`).
- Joined AT-B99-11: 8/8 runs passed (`green-at11-8x.txt`).
- New TC-B99-18 dual-rider node: 1 passed (`green-tc18-riders.txt`).
- Full sweep `tests/test_b99_*.py` + `tests/test_address_census.py` +
  `tests/test_id_registry.py`: see `green-b99.txt`.
- Per-file runs: truncation 24, staging 31, export 23, patch-truth 20,
  a2l 7, bytes 3 — transcripts listed in `evidence/ddr/README.md`.

### RED counterfactual

This increment changes no shipped behaviour, so the joined nodes have no
base-commit RED shape (they pass on the unmodified tree by construction —
they re-pack existing green coverage into one node). The RED evidence for
this increment is the two DQ-6 mutants, both KILLED with the discriminating
assertion named: `mut-PQ2c.txt` (forced-failure arm leaves `t_isle_1.addr` /
`t_isle_1.bin`) and `mut-PQ6.txt` (help revert fails at the `0x` assertion).

### Evidence files

Every `N passed` figure above appears in a transcript under
`evidence/ddr/`; sha256 per file is listed in `evidence/ddr/README.md`'s
sibling table (hashes recorded in `HANDOFF.md`).

### Reverse census

Renamed nodes are test-only ids; `grep -rln <old name> tests/` was run for
each old name (`test_at_b99_03_hostile_name_renders_literally`,
`test_at_b99_03_pilot_status_and_issues`, `test_at_b99_03_pilot_flow_source_fails`,
`test_at_b99_04_distinct_names_parallel_regression_guard`,
`test_at_b99_04_duplicate_names_refused_nothing_written`,
`test_at_b99_08_verify_mismatch_status_still_names_entries`,
the three old `test_at_b99_11_*` outcome nodes,
`test_at_b99_11_part_way_failure_status_names_the_first_file`,
`test_at_b99_11_junctioned_project_home_shows_refusal`) — zero surviving
references outside the historical `.dev-flow` DDR/increment records, which
stay as history. The joined-node names are new; nothing pinned them.
Re-pin ledger: none (no requirement changed; renames only).

### Signed-balance test ledger

`post = base − deleted + added` per file (def-level, `grep -c "^def test_"`
before → after): truncation 18 → 17, staging 32 → 31, export 25 → 23
(merges), patch_truth 12 → 13 (the F-2 node); editor_image 8 → 8,
a2l_encode 7 → 7, bytes_field 3 → 3 (renames/fixes only). Net **−3 defs**
(128 → 125); collected nodes **142 → 139** (−1 −1 −2 +1). Combined with the
F-6 corrections in Incs 5/6/9 (→ 142 at `bab3bff`), the batch ledger now
reconciles: 139 collected on disk = 142 − 4 (this increment's merges) + 1
(this increment's addition).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | qa-reviewer — spawned as a generic agent with agents/qa-reviewer.md (DDR reviewer) · OK: DQ-1..DQ-4, DQ-6 discharged, 152 passed; also re-checked by software-dev (DDR reviewer, agents/software-dev.md): C-DDR-SD-1 met, ledger met, no SOURCE change, 139 passed |

## 5 · Risks

- The joined AT-04 runs the parallel set before the refused duplicate set
  (lanes have no removal control); both outcomes are still driven in one
  pilot session, and the refusal is additionally pinned by TC-B99-15.
- AT-B99-12's confirm keeps a `Button.press()` — DQ-4 explicitly allows this
  when the button is not clickable; the geometry justification was probed,
  not assumed.

## 6 · Pending items / spec deviations

- Historical `.dev-flow` records (DDR tables, increment traceability rows)
  still cite the old node names; left as history deliberately.
- DQ-5 (TC-B99-44 assignment) and DQ-7/DQ-8 are orchestrator/backlog items,
  not part of this brief.

## 7 · Suggested next task

Orchestrator: independent review of this increment, then the Phase-4 gate
re-read of C-18 (AT→node table) and the summed ledger (now 139, reconciled).
