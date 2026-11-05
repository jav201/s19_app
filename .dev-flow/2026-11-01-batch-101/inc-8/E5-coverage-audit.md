# Inc 8 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 8, stage E5. Worktree head `e455a07`. Role: coverage auditor (did not write the cases or the tests). Mode: **validation** of the coverage records. This file is the only file written.

Inputs read: `02-test-cases.md` (82 cases), `01-requirements.md` (18 rows), `E4-tester-notes.md`, `E4-integration-notes.md` (SR-1 … SR-6, §6), `tests/test_b101_crc_model_and_reasons.py` (G1), `tests/test_b101_flow_ext_copy.py` (G2), the existing tests the covered rows name, and `s19w/test-cases/TC-PROFILE.md` (TCP-MAP-1, -3, -5, -6, -7; TCP-DER-3; TCP-TRC-4; TCP-EVD-3). The increment plan (`PLAN.md`) does not name TCP-MAP itself; the TCP-MAP rules were read from the profile it cites.

Evidence: **inspection** of the two test files and the product call sites, plus one **executed** collection by this auditor (`pytest --collect-only` on the two files: 82 node ids). No test was run by this auditor. Every pass/fail cited below comes from the orchestrator's E4 integration runs `INT-03` (RED on `origin/main` `f11b3f4`) and `INT-04` (GREEN on the merged tree, win32), read from `evidence/inc-8/`. Inspection cannot show behaviour on Linux; no Linux run exists.

Rule applied: a test verifies a case only if it asserts the case's expected result; it is `full` only when the product itself produces what it asserts. A stand-in echo, a fixture that already shows the result, an entry no product route calls, an unasserted clause, or a pinned value that differs from the case's expected result make it `partial` (TCP-MAP-1, -5, -6, -7). Where the case text and the pinned value differ, the record is `conflict` until the case is corrected (TCP-DER-3 applied to the case's design example).

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 82 (+ 2 owed rows: R-FLOW-EXT.12/9, /10 → 84) |
| Requirements with no case | **0 of 18** (8 requirement clauses have no case — §4) |
| Coverage column wrong as it stands | **79 of 82** — 78 rows say `gap` while a test is listed and passing (TCP-TRC-4: `gap` requires an empty `verified_by`); R-FLOW-CRC.4/3 says `partial` though a `full` G2 test exists |
| Coverage as the records stand (82) | covered 56 · partial 5 · **conflict 21** (case text differs from what the test pins after SR-1 … SR-6 / N-1) · gap 0 |
| Coverage after the owed case corrections (84) | covered 72 · partial 12 |
| Marks changed `full` → `partial` | **11** (13.4%): 001.17/2, EXT.9/1, /2, /3, /5, /9, /10, /11, /13, /14, /15 — plus new row 12/10 enters as `partial` |
| Expected result / preconditions to correct (case changes) | **21** (25.6%) |
| Tests-column node ids not collectable (TCP-MAP-3) | **12** (14.6%): 001.1/3, /4; DESIGNER-001.1/1 … /6; 001.16/1 … /3; EXT.12/6 |
| "Through keys" annotations that are false | 4 (001.11/8, 001.16/5, 001.17/2, EXT.9/11) |
| **Cases changed, any column but Result** | **80 of 82 = 97.6%** (only R-FLOW-CRC.1/1 and R-FLOW-EXT.2/3 unchanged) |
| **Cases changed, excluding the mechanical coverage column** | **39 of 82 = 47.6%** |
| Black-box ATs owed (keys and dialogs) | 7 (§5) |

Top issues:
1. **The coverage column was never updated.** Result says `verified (win32, int-04)` on all 82 rows while Coverage says `gap` on 78 — the record contradicts itself (TCP-TRC-4).
2. **21 cases still state values the tests no longer pin** (SR-1 … SR-6, N-1). The tests are right; the cases must change.
3. **EXT.9/3's byte clause is vacuous**: it reads `out.s19`, which is run 1's image; run 3 could read the wrong document and the test still passes (TCP-MAP-5(c)/-6).
4. **EXT.9/15 arm (b) no longer tests S-4**: after SR-4 its junction resolves outside the project, so the ref never names the output file and never reaches the rebind. The S-4 order is pinned by arm (a) only, and the whole test is skipped off Windows although arm (a) is platform-neutral.
5. **None of the four "through keys" ATs is driven by keys end to end**; the Operations-dialog three use `action_operations_view()`, `ListView.index`, `TextArea.text` and `Button.press()`.

## 2. Change table

"Who" = which artifact changes: **case** (`02-test-cases.md`), **test** (the G1/G2 file), **row** (`01-requirements.md`).

| Case | Column | Old → new | Reason (one line) | Who |
|---|---|---|---|---|
| (78 rows) | Coverage | `gap` → `covered` / `partial` / `conflict` per §3 | TCP-TRC-4: tests are listed and passed in INT-04 | case |
| R-FLOW-CRC.4/3 | Coverage | `partial` → `covered` | G2 `test_r_flow_crc_4_not_json_cause` is `full` (exact summary + cause prefix, the case says "starts") | case |
| R-CRC-ENGINE-001.1/3, /4 | Tests | `…catalogue_32_bit_checks[MPEG-2]`, `[JAMCRC]` → ids that collect | collected ids are `[MPEG-2-False-0-58124007]`, `[JAMCRC-True-0-873187033]` (TCP-MAP-3); add `ids=` to the parametrize | test |
| R-CRC-ENGINE-001.1/7 | Expected result; Coverage | "CRC block ok" → CRC block `notices`, summary `injected 1 CRC region`, one finding `CRC before PATCH: the image is finalized before any patch is applied`, run `completed-with-issues`, bytes `31 74 8B 0F` at 0x1010; `conflict` → `covered` once corrected | SR-1 (canon R-FLOW-CRC.7, no PATCH before the CRC block) | case |
| R-CRC-DESIGNER-001.1/1 … /6 | Tests | `[ARC]` … `[MPEG-2]` → ids that collect | collected ids carry every parameter (`[ARC-16-32773-0-True-True-0-47933]` …) (TCP-MAP-3); add `ids=` | test |
| R-CRC-CONFIG-001.11/7 | Inputs; Expected result; Coverage | `a` × 1 000 000 → `z` × 1 000 000; oracle `"` + 63 × `z` + `…`; `conflict` → `covered` | N-1: an all-`a` string is a valid hex number under the designed grammar | case |
| R-CRC-CONFIG-001.11/8 | Tests annotation | "(full, through keys)" → "(full, widget-driven)" | screen opened by `action_operations_view()`, row by `ListView.index`, editor by `TextArea.text`, Execute by `Button.press()`; mark stays full (product handler paints the `markup=False` Static). Harden: `status == expected`, not `in` (extra reason lines would pass) | case; test (hardening) |
| R-CRC-CONFIG-001.16/1 … /3 | Tests | `[saved]`, `[width16]`, `[algorithm-not-object]` → ids that collect | collected ids are `[saved-None]`, `[width16-{…json…}]`, `[algorithm-not-object-{"algorithm": 5}]` (TCP-MAP-3); add `ids=` | test |
| R-CRC-CONFIG-001.16/5 | Tests annotation | "through keys" → "widget-driven" | the case's input `x` is never pressed (the test calls the action); Load config / Execute by `Button.press()`; mark stays full; AT owed (§5 A-1, A-2) | case |
| R-CRC-CONFIG-001.17/2 | Mark; Coverage; annotation | full → **partial**; "through keys" → "widget-driven" | "a later key still acts" is not asserted: `tab` is pressed, nothing is checked after it, and the status is read before the key | test: assert the key's effect (focus moved, or a second Execute repaints) |
| R-FLOW-EXT.9/1 | Expected result; Mark | "`out.s19` data record `S1071000424203045D`" → "the image this run's WRITE-OUT wrote (`out_1.s19`) holds `42 42 03 04` at 0x1000 … 0x1003"; full → **partial** | SR-2; the test pins 2 of the record's 4 bytes (TCP-MAP-1) | case; test (pin 4 bytes) |
| R-FLOW-EXT.9/2 | Mark | full → **partial** | pins 2 of 4 bytes of `S1071000414103045F` | test |
| R-FLOW-EXT.9/3 | Mark | full → **partial** | byte clause reads `project/"out.s19"` = run 1's AA image; a run 3 that read the BB copy would write a BB image (reusing `out_1.s19`), leave `out.s19` untouched, and still pass (TCP-MAP-5(c), -6) | test: read `_written_image(third)`, assert its name is `out.s19`, assert PATCH summary exactly `applied 1 entry`, pin 4 bytes |
| R-FLOW-EXT.9/5 | Expected result; Mark | `out.s19` → the image run 2's WRITE-OUT wrote (`out_1.s19`); full → **partial** | SR-2; asserts the 4 addresses exist, not that they hold the CRC (TCP-MAP-1) | case; test (pin the 4 CRC bytes from an independent `crc_stream` oracle) |
| R-FLOW-EXT.9/6 | Expected result | `out.s19` → the image run 2's WRITE-OUT wrote | SR-2; mark stays full (both of image B's bytes pinned) | case |
| R-FLOW-EXT.9/9 | Expected result; Mark | SR-2 file name; full → **partial** | SR-2; 2 of 4 record bytes | case; test |
| R-FLOW-EXT.9/10 | Expected result; Mark | SR-2 file name; full → **partial** | SR-2; 2 of 4 record bytes | case; test |
| R-FLOW-EXT.9/11 | Expected result; Mark; annotation | `terminal_out.s19` → the confirm re-run's image (`terminal_out_1.s19`); full → **partial**; "through keys" → "Run (`enter`) and confirm (`c`) by key; project load, screen, import widget-driven" | SR-2; "the lane is done" is not asserted; the image path is read from private `panel._lanes[0].last_outputs` | case; test (assert the lane status as painted; take the image from the WRITE-OUT summary) |
| R-FLOW-EXT.9/12 | Preconditions / inputs | run 2's change document declares 0x1002 (it follows the v2 A2L) | SR-3. Mark stays full; note: the discrimination now rests on the existing drift refusal (base refuses → no record) | case |
| R-FLOW-EXT.9/13 | Mark | full → **partial** | 2 of 4 record bytes | test |
| R-FLOW-EXT.9/14 | Mark | full → **partial** | 2 of 4 bytes of `b.s19` | test |
| R-FLOW-EXT.9/15 | Preconditions; Mark | (b) "junction `<proj>/jl` → `<proj>`" → "junction to a folder outside the project"; full → **partial** | SR-4; arm (b)'s ref resolves outside, never names the output file, never reaches the rebind — the S-4 order is killed by arm (a) only; the whole test skips off Windows though arm (a) is platform-neutral and the case asks for a symlink on Linux | case; test (run (a) on every platform; Linux symlink arm) |
| R-FLOW-EXT.10/1 | Expected result | report cell `step.changes_1.json` → `step\.changes\_1\.json` (escaped); record field raw | SR-5 (shipped `md_safe`) | case |
| R-FLOW-EXT.10/2 | Expected result | `- Chain <name>: 0x00009000 <disposition> (step.changes_1.json)` → `- Chain lane1: 0x00009000 <the disposition word the product writes> (step\.changes\_1\.json)` | SR-5; `<name>` and `<disposition>` are placeholders that name nothing (TCP-DER-3 wants exact text) | case; test may then pin the whole line |
| R-FLOW-EXT.10/3 | Expected result | Change document cell → escaped form of `./step.changes.json` | SR-5 (the test asserts `md_safe(...)`) | case |
| R-FLOW-EXT.10/4, /5 | Preconditions | run 2's `doc.json` declares 0x1002 | SR-3 | case |
| R-FLOW-EXT.11/2 | Expected result | folder set gains `out_1.s19` (run 2's WRITE-OUT image) | SR-2. Note: its RED on base now comes from WRITE-OUT naming, not from R-FLOW-EXT.11; its negative control is the "rotate" mutant, not red-on-base | case; row (threshold "no other new file" → "no other file from the copy") |
| R-FLOW-EXT.12/2 | Expected result | `step_1.chk.json` → `step.chk_1.json` | SR-6 (R-TUI-006.2 numbered name) | case |
| R-FLOW-EXT.12/3 | Expected result | `step_1.crc.json` → `step.crc_1.json` | SR-6 | case |
| R-FLOW-EXT.12/6 | Expected result; Tests | `step_1.crc.json` → `step.crc_1.json`; Tests `…[error]` → `test_r_flow_ext_12_6_summary_names_the_copy_error` | SR-6; the listed node is not a collectable id (TCP-MAP-3) | case |
| R-FLOW-EXT.13/1 | Expected result | line with `md_safe` ref and copy (`fw\.s19`, `fw\_1\.s19`) | SR-5 | case |
| R-FLOW-EXT.13/2 | Expected result | `base.s19` → escaped `base\.s19` in the line | SR-5 (same escaper, TC-B94-30 form) | case |
| R-FLOW-EXT.12/9 (new) | New row | add: PATCH whose document apply raises after an in-place read → error summary `error · read step.changes_1.json in place of step.changes.json`; `covered` (full) | N-4 ordered it; test exists and passes (INT-04). The raise is injected by monkeypatching `apply_change_document`, which the product route calls; the summary is product-written | case |
| R-FLOW-EXT.12/10 (new) | New row | add: in-place read + junction-refused A2L → summary keeps the refusal token last, carries the suffix, one `[MANIFEST-PATH-ESCAPE]`; `partial` | N-2(c), SR-4; summary-level only (`endswith` + `in`, not exact), the FX-lane ✗ line is not observed, Windows only | case; AT owed (§5 A-5) |
| (table note) | Count line | "82 cases … 78 `gap`; 82 `not_run`" → 84 cases with the §3 coverage | stale since E3 round 2 and INT-04 | case |
| (all rows) | Result | `verified (win32, int-04)` → keep for win32 (TCP-EVD-3), add `not_run (linux)` | no Linux run exists; 9/10, 9/15, 12/10 skip off Windows by design. Executor of INT-04: the orchestrator (E4 integration) | case |
| R-FLOW-EXT.12 | Row text; threshold | state the N-2(c) placement (suffix before a trailing `unresolved`); "8/8" → "10/10" | N-2(c), N-4; integration §6 item 3 | row |

Hardening only (mark unchanged, full): 9/7 should also assert that run 1's report lacks `0x00001000` (the case's "run 1: none"); R-FLOW-CRC.1/1's existing `test_at123…` takes its oracle from the product's own `check_regions`, so the model value rests on 001.1/7 as the row says.

## 3. Coverage after audit, per case

`C` = covered (full), `P` = partial, `X` = conflict now (case text ≠ pinned value) → value after the case correction.

- **R-CRC-ENGINE-001.1**: /1 C, /2 C, /3 C, /4 C, /5 C, /6 C, /7 X→C. (/5 and /6 drive `check_regions` and `write_crc_image`, both on the product route: `crc.py:1459/1703` and `screens.py:4312`.)
- **R-CRC-ENGINE-002.2**: /1 C, /2 C.
- **R-CRC-DESIGNER-001.1**: /1 … /6 C (node ids to fix).
- **R-CRC-CONFIG-001.10**: /1 … /8 C.
- **R-CRC-CONFIG-001.11**: /1 … /6 C, /7 X→C, /8 C.
- **R-CRC-CONFIG-001.16**: /1 … /5 C.
- **R-CRC-CONFIG-001.17**: /1 C, /2 P.
- **R-FLOW-CRC**: 1/1 C, 3/1 C, 4/1 C, 4/2 C, 4/3 C, 9/1 C.
- **R-FLOW-EXT.2**: /1 C, /2 C, /3 C.
- **R-FLOW-EXT.9**: /1 X→P, /2 P, /3 P, /4 C, /5 X→P, /6 X→C, /7 C, /8 C, /9 X→P, /10 X→P, /11 X→P, /12 X→C, /13 P, /14 P, /15 X→P.
- **R-FLOW-EXT.10**: /1 … /5 X→C.
- **R-FLOW-EXT.11**: /1 C, /2 X→C.
- **R-FLOW-EXT.12**: /1 C, /2 X→C, /3 X→C, /4 C, /5 C, /6 X→C, /7 C, /8 C, /9 C (new), /10 P (new).
- **R-FLOW-EXT.13**: /1 X→C, /2 X→C.
- **R-FLOW-EXT.14**: /1 C, /2 C, /3 C.

The tester's RED header listed 9/15 as passing on base while its body showed a failure; after SR-4 the INT-03 run confirms 9/15 now holds on base (a true control), and every other mark above was re-derived from the test bodies, not from the tester's mapping.

## 4. Requirements and clauses with no case

No requirement row lacks a case. These clauses do:

| Row | Clause with no case | Owed |
|---|---|---|
| R-FLOW-EXT.14 | Threshold: "the log is checked (climb, then existence) before the output (climb, then existence)" — no case where both fail | EXT.14/4: log and output both climb → the log cause; EXT.14/5: log missing and output climbs → the log's existence cause |
| R-FLOW-CRC.4 | `<first three errors, separated by "; ">` — every case has one error | FLOW-CRC.4/4 with ≥ 4 errors, or reword the row if the parser can only give one |
| R-FLOW-CRC.3 | "is refused" branch — exact summary and cause unpinned (`test_at127a/b` assert statuses only) | FLOW-CRC.3/2: absolute ref and escaping ref → exact `config unresolved` + cause |
| R-FLOW-CRC.9 | The shipped cap `268435456` in the cause (the test lowers the cap to 16) | one pin of the cause text at the shipped cap (size probe stand-in is acceptable as `partial`) |
| R-FLOW-EXT.12 | N-2(c) placement and N-4 raise exit | rows 12/9, 12/10 (§2) |
| R-FLOW-EXT.9 | Linux halves: 9/15 symlink arm; 12/10 on Linux | Linux symlink arms (or `n/a — <reason>` recorded per case) |
| R-FLOW-EXT.9 / SR-4 | A junction back **into** the project is not refused by the guard; on the tree the ref then reads the copy in place with the suffix — no case pins this | a case documenting the current behaviour, or a backlog item, per the security reviewer's ruling |
| R-CRC-CONFIG-001.10 / .11 | Defined fields not exercised: required — region `end`, region `output_address`, span `start`; number — region `start`, region `output_address`, group `output_address`, span `end` | low priority: the thresholds fix 8/8 cases and are met |

## 5. Acceptance tests owed (black box, through keys and dialogs)

| Id | What the operator does (keys only) | Observed through | Covers |
|---|---|---|---|
| A-1 | Load image K, press `x`, move to the crc row, type Config K variants into the editor, Execute by key | `#operation_result_status` exact text (`==`), hex view empty | 001.11/8, 001.17/2 (with a later key whose effect is asserted) |
| A-2 | Save a template in the CRC Designer by key; open Operations (`x`), type its path, Load config and Execute by key | the template reason in the result area | 001.16/5 as B4 output-then-consume (today the file is written by the fixture) |
| A-3 | Operations Execute with Config K over image K | the region line shows computed `0x0F8B7431`; Write writes `31 74 8B 0F` | 001.1/5, /6 through the dialog (today: the service calls; the region line is not asserted) |
| A-4 | Flow Execution lane with a CRC block that names a Designer-saved file; Run by key | the lane shows `config malformed` and the template cause | R-FLOW-CRC.4/1 (F-28, US-I8-1) on the shipped surface |
| A-5 | Flow Execution lane, run 2 with an in-place read, then the junction-refused A2L | the lane's ✗ line keys on the trailing token and shows the suffix | 12/10, N-2(c) |
| A-6 | Flow Execution 18.9 path (9/11) completed: open the project and import the lane by key | the lane status painted done; the PATCH card shows ` · read step.changes_1.json in place of step.changes.json` | 9/11 lane clause, R-FLOW-EXT.12 visibility (US-I8-4 "without saying so") |
| A-7 | Flow Execution lane with output `bench/../../x.json`; Run and confirm by key | the lane shows `external step refused` and the climb cause | R-FLOW-EXT.14 on the shipped surface |

## 6. Evidence checklist

- ✓ Mode declared: validation of the coverage records (top).
- ✓ Every case carries a result state: `verified (win32)` from INT-04 (executor: the orchestrator), `not_run (linux)` — no Linux run.
- ✓ Expected results are explicit; the 21 that disagree with the pinned values are listed with the side that changes.
- ✓ Edge/negative cases checked for discrimination (9/3 vacuous, 9/15 arm (b) not reaching the rebind).
- ✗ Layer B: the shipped TUI surface is reached by keys only for Run/confirm in 9/11; seven ATs owed (§5).
- ✓ Bidirectional reachability: `check_regions`, `write_crc_image`, `action_operations_view` (bound to `x`), `emit_template` (the Designer's Save, `crc_designer_view.py:1259`) all have product callers.
- ✓ No real PII, no secrets, no host or home paths in this file.

## Re-audit (2026-11-05)

Scope: only the cases the corrective pass changed or added (`E5-rulings.md` C-1 … C-9, `E5-corrective-notes.md`, `git diff e455a07..HEAD -- 02-test-cases.md tests/`), head `a27b9ee`. Re-checked: **45 cases** (28 changed in a field other than Coverage/Result, 17 new). Mode: validation. Evidence: **inspection** of the test bodies and the product call sites, plus one **executed** `--collect-only` by this auditor over the six cited test files (144 ids). Pass/fail is consumed from the orchestrator's corrective run `e5c-03` (97 passed, win32, Python 3.11.15; executor: the orchestrator) — this auditor ran no test. No Linux run exists.

### Earlier top issues

| # | Issue | Now |
|---|---|---|
| 1 | Coverage column contradicts Result | **closed** — 96 `covered`, 3 `partial`, 0 `gap`, 0 `conflict`; every `covered` row cites a `(full` test and every `partial` row cites none (checked row by row) |
| 2 | 21 cases with pre-ruling values | **closed** — SR-1 … SR-6, N-1 values now match the pinned values in every re-checked row |
| 3 | 9/3 vacuous byte clause | **closed** — the test reads the file named by run 3's own WRITE-OUT summary (`_written_image(third)`), asserts it is `out.s19` and holds `41 41 03 04`. Discriminating: the product's WRITE-OUT verifies the placed file against the run's own memory map before it writes `wrote <name>` (`flow_execution_service.py`, `verify_written_image`), so a run 3 that read the BB copy would either name another file (`out_1.s19`/`out_2.s19`, fails the name) or hold BB (fails the bytes); run 1's image can no longer satisfy the assertion |
| 4 | 9/15(b) does not reach the rebind | **accepted as partial** (C-8) — reason recorded in the case; S-4 is carried by arm (a); still skipped off Windows (routed, BACKLOG-CODE) |
| 5 | "through keys" ATs were method-driven | **closed for 001.11/8, 001.16/5, 001.17/2, 001.11/10** — `x`, typed path, Load config and Execute by `enter`, focus moved by `tab` only; 001.17/2 asserts the later key's effect (focus lands on `operations_close`). 9/11 now asserts the painted lane head `▓ terminal · done · …` and takes the image from the painted `wrote` list, not from private state. Fixture-driven preconditions are declared in the cases |
| — | Uncovered clauses | **closed** — FLOW-CRC.3/2, /3; FLOW-CRC.4/4; FLOW-CRC.9/2; EXT.14/4, /5; 001.10/9 … /11; 001.11/11 … /14; Linux halves and the junction-into-project case ruled not-testable here with reasons (S8-2, Inc 9) |
| — | 4 bytes and the CRC value | **closed** — 9/1, /2, /3, /9, /10, /13, /14 pin all four data bytes; 9/5 pins `CD FB 3C B6` at 0x1020 from the Designer engine (`crc_stream`), an oracle independent of the operation engine; this auditor confirmed CRC-32(`01 02 03 04`) = 0xB63CFBCD with a third implementation (`zlib.crc32`) |

### Marks of the re-checked cases

- **FLOW-CRC.4/4 `partial` — agreed.** The four errors come from a monkeypatched `parse_crc_config`; the shipped parser returns at most one, so the product never produces the asserted three-way join from its own input. The join code is the product's, but the asserted cause exists only under the injection (TCP-MAP-5). Pending: reword R-FLOW-CRC.4 or keep the join as defence (requirements session).
- **12/9 `full` — kept**, unlike 4/4: the injected raise stands for an I/O failure the shipped callee can produce, and the asserted summary is product-written.
- **12/10 `partial` — agreed**; the exact summary is now pinned, the lane ✗ line is still unobserved, Windows only.
- **9/1, /2, /3, /5, /9, /10, /11, /13, /14 and 001.17/2: `partial` → `full` — agreed.**
- Every other changed or new case: `full` agreed.

### Collection

All **101** node ids cited in the Tests column of the 99 rows collect (`--collect-only`, s19env, `PYTHONPATH=.`, `LOCALAPPDATA` redirected): 0 missing. `ids=` now makes `[MPEG-2]`, `[JAMCRC]`, `[ARC]` … `[MPEG-2]`, `[saved]` … collect as cited.

### Remaining issues

1. **9/11 wording** — the Expected result names `terminal_out_1.s19`; the test reads whatever `.s19` the painted head lists and asserts its bytes, not its name. Either assert the name or mark it as illustrative. (case wording; mark unaffected)
2. **001.11/9 and 001.11/10 are stack-depth sensitive** — the bands 800 … 1000 and 500 … 1000 assume the JSON reader's limit falls inside them; a deeper caller stack (xdist, plugins, another Python) can move it and fail the test without a product defect. Not vacuous; a flakiness risk to watch on the Linux run.
3. **FLOW-CRC.9/2** extends a file to 256 MiB; on a file system without sparse extension this reserves real disk. Acceptable; note for CI.
4. **Not ruled, still open from §2/§5:** 9/7 hardening ("run 1: none"); black-box ATs A-2 (Designer save by key, then consume) and A-3 … A-7. A-1 is now met by 001.11/8 and 001.17/2.
5. **Row thresholds** R-CRC-CONFIG-001.10 / .11 still read "8/8" with 11 and 14 cases (requirements session).

### Final totals

| Item | Value |
|---|---|
| Cases | 99 (82 + 17) |
| Coverage | **96 covered · 3 partial** (9/15, 12/10, FLOW-CRC.4/4) · 0 gap · 0 conflict — agreed |
| Cited node ids not collecting | 0 of 101 |
| `gap` with a passing full test | 0 |
| Re-checked cases I would still change | **1 of 45 = 2.2%** (9/11 wording); marks to change: **0 of 45** |
| Result column | `verified (win32, e5c)` on 99 rows — executor the orchestrator; `not-run` on Linux for all rows (no Linux run) |
