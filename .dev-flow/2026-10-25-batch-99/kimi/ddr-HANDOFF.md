# HANDOFF — batch-99 DDR test fixes (increment 012)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-ddr`, branch `b99-ddr` at `bab3bff`.
Tests-and-packets-only increment: **no file under `s19_app/` was changed**
(`git status --porcelain -- s19_app/` is empty, re-verified at handoff).
Nothing committed; all changes are in the working tree for the orchestrator.

Import proof (before every test run):
`python -c "import s19_app; print(s19_app.__file__)"` →
`C:\Users\jjgh8\Github\s19_app-b99-ddr\s19_app\__init__.py` (inside the worktree).

## What was done (per BRIEF-ddr-fix.md)

1. **C-18 / DQ-1 — one joined node per AT** (each run 8× for stability):
   - AT-B99-03 → `tests/test_b99_truncation.py::test_at_b99_03_status_leads_defect_flow_source_fails`
     (load cut S19 → status leads with the defect + issues panel names it → flow SOURCE fails, nothing written);
     hostile arm renamed `test_tc_b99_10_hostile_name_renders_literally`; the two old AT nodes merged.
   - AT-B99-04 → `tests/test_b99_staging.py::test_at_b99_04_duplicate_refused_distinct_parallel_markers`
     (parallel 8-lane distinct set, each file its lane's marker → duplicate-name set refused naming both lanes, nothing written);
     the two old AT nodes merged.
   - AT-B99-08 → `test_at_b99_08_save_back_keeps_editor_image` kept as the designated AT;
     mismatch arm renamed `test_tc_b99_22_verify_mismatch_status_still_names_entries`.
   - AT-B99-11 → `tests/test_b99_export.py::test_at_b99_11_sanitised_mac_only_second_export_takes_suffix`
     (hostile segment name stays inside → MAC-only export holds no data record → second export after a patch takes `_1`, status names it, first file intact);
     arms renamed `test_tc_b99_41_part_way_failure_status_names_the_first_file` and
     `test_tc_b99_29_junctioned_project_home_shows_refusal`.
2. **DQ-2..DQ-4 — black-box entries**: AT-04 loads via the Load project dialog
   (`p` → row → `#project_ok`), parallel mode by clicking `#fx_mode`, run via
   `pilot.click("#fx_run")` (no `_handle_load_project` / `Button.press()` /
   `set_mode` / `Input.value =`). AT-09 types the path, clicks `#load_ok`,
   waits on painted `#log_line_4` (no `Input.value =` / `Button.press()` /
   `app.current_file` wait). AT-12 clicks Add and Apply; the save-back confirm
   keeps one `Button.press()` with a re-verified justification (hidden
   JSON-pane tab + region clipped under the status bar at the 120×40
   acceptance geometry — probed, not assumed).
3. **LOW/F-2** — `tests/test_b99_patch_truth.py::test_tc_b99_18_lane_line_carries_patch_and_crc_riders`:
   one lane with a partial PATCH and a partial CRC; the painted terminal line
   carries both riders (`PATCH: 1 of 2 entries not applied (0x00020000
   skipped-outside)` + `CRC: 466 of 512 region bytes absent (0xFA00-0xFC00)`)
   plus the `wrote …` tail; the absent count is computed from the independent
   reader's map.
4. **MEDIUM/F-6** — signed-balance ledger lines corrected with the count
   commands cited: `increment-005.md` 5→8, `increment-006.md` 17→25,
   `increment-009.md` 20→25 (`pytest --collect-only -q tests/test_b99_<file>.py
   | grep -c "::"`, cross-checked with `git show HEAD:… | grep -c "^def test_"`).
   The three increments now reconcile at the DDR's 142 collected nodes.
5. **DQ-6** — both qa-reviewer mutants re-run in a scratch extract of
   `git archive HEAD` (the live `s19_app/` was never mutated; each transcript
   carries the import probe and before/mutant sha256, and the revert
   `cmp`-verified against the HEAD blob):
   - `mut-PQ2c.txt`: PQ-2(c) skip-claim-removal → KILLED,
     `test_tc_b99_31_forced_failure_rolls_back_every_own_claim` leaves
     `t_isle_1.addr`/`t_isle_1.bin` (1 failed, 5 passed).
   - `mut-PQ6.txt`: help-arm revert → KILLED,
     `test_tc_b99_33_field_and_help_state_the_hex_rule` fails at the `0x`
     assertion.

## Verification

- Full sweep (`green-b99.txt`): `tests/test_b99_*.py` +
  `tests/test_address_census.py` + `tests/test_id_registry.py` →
  **175 passed in 502.86s, exit 0** (139 collected b99 nodes + census +
  registry). sha256 `d3b08d72113129d05d55cd2c0cffb2f628fe2a44e7cd26a2c80bf6e1c28def20`.
- Joined-AT stability: AT-03 8/8, AT-04 8/8, AT-11 8/8 (`green-at03/04/11-8x.txt`).
- Per-file: truncation 24, staging 31, export 23, patch-truth 20, a2l 7,
  bytes 3 (all transcripts in `evidence/ddr/`).
- All seven edited test files are pure CRLF (`crlf == line count`, 0 bare LF).
- Increment packet: `03-increments/increment-012.md` (§4b pending — orchestrator).
- Evidence index mapping every change to its DDR condition:
  `evidence/ddr/README.md`.
- Node ledger: defs 128 → 125 (−3 merges +1 addition); collected 142 → 139,
  matching `pytest --collect-only` on the final tree (139).

## Evidence files (`.dev-flow/2026-10-25-batch-99/evidence/ddr/`)

| File | sha256 |
|---|---|
| green-b99.txt | d3b08d72113129d05d55cd2c0cffb2f628fe2a44e7cd26a2c80bf6e1c28def20 |
| green-at03-8x.txt | d0e69effa0c118fb748546e12477db6d750a6c3df7b33deab898628e41810868 |
| green-at04-8x.txt | 11be7af46692304327acb5b4be81b87eec9c5529ab72c8d58ec4bb86a22c06db |
| green-at11-8x.txt | a95d62e819785a65b7edfb40c3627c7e600f5dbe1007fa074eb874e413f9059c |
| green-truncation.txt | b546610b7daf22b35f8acd2a679d0dcfa8636a4e44b9817eebb07f59fb19681a |
| green-staging.txt | fa6e402957d533bd9286d2a8647c8f6f752c835ca48d65201b17bbe629c6f4b0 |
| green-export.txt | 9254c8ada3232cbbc79aba46470e174c29ac79b4fbd7890dbcc1ec2fed18a76 |
| green-patch-truth.txt | bcf7be3151639c6e65817e71019b20f88a6045c44649d0f92fbc027cab6814f5 |
| green-tc18-riders.txt | 87752365aa869046469b03bf329d6f5c14b5d82c1c8455b31d17b74f7e403922 |
| green-a2l.txt | 3b6228ade0a9780c3651f3c8a774cdb00a83eda4b33452f3f1124a042894c9d3 |
| green-bytes.txt | 2662339370e1e14fb0a3801efbe3b6617f5cc7ebced8f02f9c0a53034a1b4093 |
| mut-PQ2c.txt | a191ae494f868d7f2cbbd5c183b1428871929f5459a65a7db5d16b2f9f329878 |
| mut-PQ6.txt | 8446ed8ee0907702b8377fa12005fc7675fc7bab0b4d06e15f4ee5141b6f6f3d |

## Open questions / notes for the orchestrator

- DQ-5 (TC-B99-44 assignment), DQ-7 (P-5 flip wording) and DQ-8 (PQ-7 payload
  arm) are orchestrator/backlog items outside this brief — untouched.
- Historical `.dev-flow` records (DDR tables, earlier packets' traceability
  rows) still cite the old AT node names; left as history deliberately.
- No RED-first transcripts were taken for the joined nodes: this increment
  changes no shipped behaviour, so the joined nodes pass on the unmodified
  tree by construction; the increment's RED evidence is the two DQ-6 mutants.
- The full ~2h20 suite was NOT run (per BRIEF-COMMON the orchestrator runs it).

__KIMI_UNIT_DONE__
Files changed: 7 test files + increment packets 005/006/009 corrected + increment-012.md added; s19_app untouched, no commits.
Tests added: 1 (`test_tc_b99_18_lane_line_carries_patch_and_crc_riders`); 3 ATs joined (AT-03/04/11), AT-08 designated, 5 arms renamed to TC sub-nodes, 3 black-box entry fixes (DQ-2/3/4).
RED/GREEN counts: GREEN 175 passed full sweep (139 b99 collected); joined ATs 8/8 stable each; RED = 2 mutants KILLED (PQ-2(c), PQ-6), reverted by hash.
Mutations run: 2 (PQ-2(c) skip-claim-removal, PQ-6 help-arm revert), both in scratch extracts, both reverted cmp-clean; no source file changed.
Open questions: DQ-5/DQ-7/DQ-8 left for orchestrator/backlog; historical .dev-flow records keep old node names as history; full suite not run (orchestrator's).
