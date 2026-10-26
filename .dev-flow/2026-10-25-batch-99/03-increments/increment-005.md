# Increment 005 — HLR-159 · `CRC never covers an empty region; CRC write stages privately`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `005` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-148 / HLR-159 / LLR-159.1 · LLR-159.2 · LLR-155.8` |
| Acceptance | `AT-B99-10` · white-box `TC-B99-26 · TC-B99-27 · TC-B99-38` + census `TC-B99-39 (exception removed)` · unit `none (no new pure function without a TC)` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: a CRC operation no longer covers an empty region. The coverage count
(the absent bytes across a target's declared spans) is computed once in
`check_regions` and travels on the region result as a `CrcCoverageResult`
(`absent_bytes`, ARCH R23 / PDR condition C5); the flow CRC arm,
`write_crc_image` and `CrcOperation.execute` all read that one number. 0
present bytes → status `error`, nothing injected, no file written; the
user-facing cause (`CRC region 0x20000-0x30000 holds 0 image bytes - nothing
written`, UX-C2) is the last diagnostic of the error block. Partial coverage →
`notices` naming the exact absent count — legacy regions included (the Q4
legacy-silence pin lifts for coverage; the golden CRC values are untouched
because compute over present bytes is unchanged). The CRC write
(`<stem>-crc.s19`) now stages through `workspace._private_stage_dir` (the
`temp/.staging/` mkdtemp home from Inc 3a) instead of the shared
`temp/<name>`, and removes only the owned staging directory — TC-B99-39's
`expected RED until Inc 5` exception for the CRC site is removed; the census
passes with zero exceptions.

Shipped surface the user reaches: the Flow Execution lane cells + run log
(AT-B99-10), the CRC operation result notes, and the CRC write's emitted file.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/operations/crc.py` | SOURCE | HLR-159, LLR-159.1/.2, LLR-155.8 | new `CrcCoverageResult` (R23 carrier, `absent_bytes`) + `first_empty_target_span`; `check_regions` computes and carries the count; `crc_diagnostics` names the absent count for legacy regions too; `inject_crcs` preserves the count; `write_crc_image` refuses empty targets (no injection, no file, UX-C2 finding) and stages privately via `_private_stage_dir`; `CrcOperation.execute` ends `error` on an empty target (cause last, UX-C2) — **review round 1**: `crc_diagnostics` reads the count from the results (R23) and skips a fully empty target (the error note only, UX-C2); `first_empty_target_span` typed `list[CrcCoverageResult]` |
| `s19_app/tui/services/flow_execution_service.py` | SOURCE | HLR-159, LLR-159.2 | the flow CRC arm reads the count from the region results: empty target → `_record_error` abort (stops before any later WRITE-OUT, 0 files); partial coverage → `notices` block with one finding per partly covered target naming the exact absent count — **review round 1**: the finding names the count against the declared span length (`CRC: <k> of <n> region bytes absent (0x…-0x…)`), the single carrier the lane terminal line and the chain-set report paint; `compose_chain_set_report` gained the always-present `## Notices` section (per-lane advisory findings through `md_safe`) |
| `s19_app/tui/flow_screens.py` | SOURCE | HLR-159, LLR-159.2, UX-C2 | **review round 1 (orchestrator-widened budget, 3/4)**: the FX lane terminal line carries the CRC absent-count rider (`_crc_absent_note`, the Inc-8 UX-C1 PATCH pattern) |
| `tests/test_b99_crc_region.py` | test | HLR-159, LLR-155.8 | new: TC-B99-26, TC-B99-27 (+R23 arm), TC-B99-38, AT-B99-10 — **review round 1**: + TC-B99-26 F2 arm (empty region → error note only), TC-B99-27 1-present-byte boundary arm (F3), TC-B99-27 chain-set-report arm (F1), AT-B99-10 asserts the painted count (F1); TC-B99-27 count-form re-pin (F1) |
| `tests/test_b99_staging.py` | test | LLR-155.7/.8 | TC-B99-39: the CRC-site exception removed — zero-exception census |
| `tests/test_crc_operation.py` | test | HLR-159 | AT-044a / AT-045c re-pinned (legacy coverage silence lifted) — recorded in §4 |
| `tests/test_b99_patch_truth.py` | test | HLR-156, LLR-159.2 | **review round 1**: TC-B99-19 re-pinned — the chain-set report gained the `## Notices` section, so the clean lane lists `none` in 3 sections (old 2 → new 3) — recorded in §4 |
| `tests/b97_fixtures.py` | fixture | HLR-159 | the FX fixture `crc.json` now covers bytes prg.s19 holds (the example config's regions are empty over prg.s19 and would now refuse the block; the FX fixtures test execution mechanics) |
| `tests/test_id_registry.py` | test | — | `EXPECTED_SCANNED_TEST_FILES` 209 → 210 (measured) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-005.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-5/*` | doc | — | transcripts, hashes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** (review round 1: the orchestrator widened the budget to 3 — `flow_screens.py` added) |
| Test files | 5 changed + 1 new (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
pytest tests/test_b99_crc_region.py -v               # -> 5 passed
pytest tests/test_b99_crc_region.py -k tc_b99_26     # -> 1 passed, 4 deselected
pytest tests/test_b99_crc_region.py -k tc_b99_27     # -> 2 passed, 3 deselected
pytest tests/test_b99_crc_region.py -k tc_b99_38     # -> 1 passed, 4 deselected
pytest tests/test_b99_crc_region.py -k at_b99_10     # -> 1 passed, 4 deselected
pytest tests/test_b99_staging.py -q                  # -> census GREEN incl. TC-B99-39
pytest tests/test_crc_operation.py -q                # -> re-pinned AT-044a/045c GREEN
pytest tests/test_address_census.py -q               # -> companion
# review round 1 (F1–F4):
pytest tests/test_b99_crc_region.py -q               # -> 8 passed (3 new/updated arms + re-pins)
pytest tests/test_b99_patch_truth.py -q              # -> Inc-8 nodes stay green incl. the TC-B99-19 re-pin
pytest tests/test_id_registry.py -q                  # -> scanned-file count unchanged (no new module)
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — the new carrier is exercised by the TCs below | n/a |
| **A · white-box** `TC-B99-26/27/38` ↔ LLR-159.1/.2/155.8 | `core` · `full` | `test_tc_b99_26_empty_region_errors_and_writes_nothing` · `test_tc_b99_27_partial_region_notices_name_absent_count` · `test_tc_b99_27_r23_coverage_count_travels_on_the_region_result` · `test_tc_b99_38_concurrent_crc_writes_of_the_same_stem` | 4 passed |
| **B · black-box** `AT-B99-10` ↔ US-148, Textual pilot `#fx_run` | `core` · `full` | `test_at_b99_10_flow_crc_region_pilot` | 1 passed |
| **Census** `TC-B99-39` (exception removed) ↔ LLR-155.7/.8 | `core` · `full` | `test_tc_b99_39_delete_calls_delete_only_owned_staging` | 1 passed |

Regression companions: `tests/test_b99_staging.py tests/test_id_registry.py
tests/test_crc_operation.py tests/test_crc_engine.py tests/test_flow_crc_block.py`
— 98 passed (`green-batch1.txt`); `tests/test_flow_crc_ribbon.py
tests/test_flow_report_ac6_golden.py tests/test_flow_report_wire.py
tests/test_flow_crc_ui.py tests/test_flow_a2b_b94.py tests/test_flow_persistence.py
tests/test_operations.py tests/test_address_census.py` — 107 passed
(`green-batch2.txt`); `tests/test_tui_crc_surface.py
tests/test_crc_designer_view.py` — 54 passed (`green-batch3.txt`);
`tests/test_b97_flow_builder.py` — 69 passed (`green-batch5.txt`);
`tests/test_b97_flow_execution.py tests/test_tui_flow_execution_b94.py
tests/test_flow_chainset_b94.py` — 94 passed, exit 0 (`green-batch4.txt`; the
first run, under three-way CPU contention, showed one dwell-timing flake,
`test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one` — real-time
`pause(0.6)` dwells, its `two_wait` lanes carry NO CRC block; it passed solo,
`green-b97_64-solo.txt`).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | two, one per LLR (see Mutation verdicts below): the empty-region refusal bypassed (the empty stream gets a CRC again) · the shared `temp/<name>` staging restored — both reverted by hash |
| Instrument | project code: the implementer's own hand via the Edit tool, restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc5`), run by the implementer |
| Transcript | `evidence/inc-5/mut-LLR-159.1.txt` · `mut-LLR-155.8.txt` (each: node FAILED) |
| Restore proven by | file hash returned to its pre-mutation value: crc.py → `ec932e16cabab0528863bc3eec6b43a15951b0e58cc6fa0153c50abe5bf5d3ba`; flow_execution_service.py untouched by the mutations (baseline `d0f69981d3b26a2239e0f4af01391b4bc14abcae9fac578741871e688f9859d2`) — both recorded in `baseline-hashes.txt` |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | baseline RED `red-baseline.txt`: all 5 new nodes FAILED on the unmodified tree (TC-26/27/R23/AT fail on statuses/count/cause; TC-38 fails with a nonzero mismatch count — 20 of 40 writes, PQ-8) |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **RED counterfactual** | the baseline RED (`red-baseline.txt`, 5 failed on the unmodified tree) plus the two C-40 mutations below, each shown RED then reverted |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-159.1 · TC-B99-26: the empty-region refusal bypassed (`first_empty_target_span`: `absent_bytes == declared` → `> declared`, so the empty stream gets a CRC again) · KILLED — `test_tc_b99_26_empty_region_errors_and_writes_nothing FAILED` (`mut-LLR-159.1.txt`, 1 failed / 4 deselected) · arms GREEN: none · transcript `mut-LLR-159.1.txt` · restore digest `ec932e16…` (crc.py back to its pre-mutation bytes) ‖ LLR-155.8 · TC-B99-38 + TC-B99-39: the shared `temp/<name>` staging restored (`stage_dir = workarea / "temp"` + `finally: staged.unlink()`, the pre-Inc-5 shape) · KILLED — BOTH nodes FAILED (`mut-LLR-155.8.txt`: `test_tc_b99_38_concurrent_crc_writes_of_the_same_stem FAILED` — nonzero mismatch count — and `test_tc_b99_39_delete_calls_delete_only_owned_staging FAILED` — the re-derived-name unlink re-flagged) · arms GREEN: none · transcript `mut-LLR-155.8.txt` · restore digest `ec932e16…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the tree before the source change, new tests present | all 5 nodes FAILED (`red-baseline.txt`) |
| `pytest` + TC-B99-26 | the LLR-159.1 mutation (empty refusal bypassed) | `test_tc_b99_26_empty_region_errors_and_writes_nothing FAILED` (`mut-LLR-159.1.txt`) |
| `pytest` + TC-B99-38 | the LLR-155.8 mutation (shared staging restored) | `test_tc_b99_38_concurrent_crc_writes_of_the_same_stem FAILED` (`mut-LLR-155.8.txt`) |
| AST delete census (TC-B99-39) | the LLR-155.8 mutation (a re-derived name unlinked again) | `test_tc_b99_39_delete_calls_delete_only_owned_staging FAILED` (same mutation, second instrument) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the flow WRITE-OUT file of the partial-coverage flow (TC-B99-27) | the independent reader parses the written S19 and the 4 LE slot bytes at 0xFC00 are compared to `zlib.crc32` over the present bytes derived from the independent reader's map of `prg.s19` | slot == oracle CRC |
| the two `<stem>-crc.s19` files of every TC-B99-38 trial | the independent reader parses each written file; its slot at 0x100000 is compared to `zlib.crc32` of the payload that wrote it | 0 mismatches over 20 trials × 2 writers |
| the `notices` block of the TC-B99-27 run | the recorded finding text is compared to the absent count computed from the independent reader's map | `"466 absent byte(s)"` named |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-5/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| AT-B99-10 ×8 (8 × `1 passed`), orchestrator after the Kimi fix session timed out | `stability-at10.txt` | `10bcddd86cddc5d87bcd745d449dcf5f72ab9973d2a0a80add166809b90f7393` |
| affected sweep after the fixes (210 passed), orchestrator | `green-fix-sweep.txt` | `5016dde16b13383898bb2ab0cf44dbf4a8402b9bc9fa6083d06ac3237e96cd43` |
| RED baseline, unmodified tree (5 failed) | `red-baseline.txt` | `2bff9c00fd113d49d3b3eda820f0765d6f9eeadd3353c3512d8903bdbac546c7` |
| GREEN: the increment's module (5 passed) | `green-b99_crc_region.txt` | `8c3e20db2202dbc743e9775db3eae7b5fce7555cafc3413a4da592f4edfcb187` |
| GREEN: batch 1 — staging, registry, crc operation/engine, flow crc block (98 passed) | `green-batch1.txt` | `b45835ea80233faee375868d90077e76a402a1fc71fb57ddac881ec8d0c1c857` |
| GREEN: batch 2 — ribbon, golden report, report wire, crc ui, a2b, persistence, operations, address census (107 passed) | `green-batch2.txt` | `035002a206cc8e70b9f765034b8cd5eb4835317125651f56177cfa328ef4e953` |
| GREEN: batch 3 — TUI CRC surface + designer view (54 passed) | `green-batch3.txt` | `6a23dc6f6770cee970308ded2c1edd71c7cf3a66d2c04e245ad33d153a28cd22` |
| GREEN: batch 4 first run (93 passed, 1 dwell-timing flake under contention) | `green-batch4-first-run.txt` | `38de8d1aba695fa48b893254db2042c18540a48e793efb0c53a7e9c27e956cb6` |
| GREEN: batch 4 clean re-run — b97 FX execution, tui flow execution, chainset (94 passed) | `green-batch4.txt` | `f815727653358c741d3194bdb08244286a19affe1ee88da51a3bf0eeb4ad1b4d` |
| GREEN: TC-B97-64 solo re-run (1 passed) | `green-b97_64-solo.txt` | `f1c95d14a4a43cca71ea4d463c81d2edb92f483e45973e672122c6a80c1d8e0b` |
| GREEN: batch 5 — b97 flow builder (69 passed) | `green-batch5.txt` | `2267621ff7bf568466529e54314a9fb4bafd9caf60d77942e9c44ccb17db2bdb` |
| Mutation LLR-159.1 (KILLED — TC-B99-26) | `mut-LLR-159.1.txt` | `28e5aea33fcb243f800fd02c2b11a57b334903e5fb7fdc9877272e127c210ce5` |
| Mutation LLR-155.8 (KILLED — TC-B99-38 AND TC-B99-39) | `mut-LLR-155.8.txt` | `524cc10309d6cd7b48a45f16cbb5e58f49be039df43e17c456f4b0afa3c6f7d9` |
| Reverse census probes | `reverse-census.txt` | `fbab3d05cf60c46d57a88c38db2caab58b7b7bf195f63790ea1ffb4f439c188d` |
| Pre-mutation hashes (fixed tree) | `baseline-hashes.txt` | `524e12fef268bcf50973496462d8315f8f11bf5bbd81c33e8413e39a500b256d` |

| Field | Value |
|---|---|
| **Evidence files** | 13 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) the TC-B99-39 census holding ZERO violating delete calls (the exception is gone); (2) TC-B99-38 resting on 0 mismatches over 20 trials |
| If the result is an ABSENCE, what made the search wide enough | (1) the AST census walks every `unlink`/`rmtree`/`os.remove` in the five writers and binds each to its creating call — the search is the whole function body, not a sample; (2) all 40 written files are checked, none sampled |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_39_delete_calls_delete_only_owned_staging` — the zero-violation assertion is its own named node; `test_tc_b99_38_concurrent_crc_writes_of_the_same_stem` — the 0-mismatch assertion is the node |
| Conjunctive criteria: one mutation per conjunct | the LLR-155.8 mutation is read by TWO nodes (TC-B99-38 and the TC-B99-39 census) — one mutation, two instruments |
| Synthetic instance of the absent case | the LLR-155.8 mutant IS a writer that stages at the shared `temp/<name>` again (the transient pre-Inc-5 shape); the LLR-159.1 mutant IS the empty-stream CRC the requirement forbids |
| **Positive control for every probe that returned an ABSENCE** | (1) both mutants make the identical probes return violations (`mut-LLR-159.1.txt`, `mut-LLR-155.8.txt`); (2) the baseline RED shows TC-38 reporting 20/40 mismatches under the HEAD staging |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "region_segments\|crc_diagnostics\|write_crc_image\|EMITTED_NAME_SUFFIX\|injected 1 CRC" tests/` | 6 hits — `goldens/batch71` (re-validated via `test_flow_report_ac6_golden.py`, GREEN — the golden's own config is fully covered, compute unchanged), `test_b99_crc_region.py` (own), `test_b99_staging.py` (TC-B99-39/44, GREEN), `test_crc_designer_view.py` (an ABSENCE census that `write_crc_image`/`inject_crcs` stay out of the designer view source — symbols still present in crc.py, GREEN), `test_crc_operation.py` (re-pinned, GREEN), `test_tui_crc_surface.py` (GREEN) — probe output in `reverse-census.txt` |
| B2 file moved on disk | n/a — no pre-existing file moved | no readers lost |
| B3 byte-identical golden captures | covered inside B1 — the batch71 golden compares byte-for-byte; GREEN because its fixture config is fully covered (absent 0 → silent) | no re-pin |
| B4 artifact produced here consumed elsewhere | `grep -rn "first_empty_target_span\|CrcCoverageResult\|absent_bytes" s19_app/` | consumers are crc.py itself and the flow arm (this increment's own); `screens.py` re-inject path feeds `inject_crcs`, which preserves the count via `getattr(..., 0)` — GREEN (`test_tui_crc_surface.py` 54 passed) |
| A3 interface consumed by another module changed | the changed interfaces (`check_regions` result type widened to a subclass with a defaulted field; `write_crc_image` staging) keep every existing call site valid — default-arg construction unchanged; `to_dict` keys unchanged (`test_operations.py` pins them, GREEN) | re-validated, no re-pin beyond the two recorded |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared — 1 B1 population re-validated file by file; no foreign re-pin beyond the two recorded below |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| legacy coverage silence lifted (HLR-159) | tests pinning "a gapped legacy region emits no coverage note / `ok`" | `grep -rln "stays_silent\|legacy_stays\|absent byte" tests/` + the crc_diagnostics census | 2 | `test_at045c_gap_note_names_group_and_count_legacy_stays_silent` (body re-pinned; node name registry-pinned) · `test_at044a_legacy_gapped_golden_compat` (notes list re-pinned; golden CRC unchanged) | 0 |
| flow-CRC fixtures with empty regions over prg.s19 | FX fixtures feeding CRC-arm flows | `grep -rln "crc_config.example" tests/` | 1 | `tests/b97_fixtures.py` `flow_project` — the fixture `crc.json` now covers 0xEB08-0xFA00 (present bytes) | 0 — the example config itself stays as the empty-region RED instrument (`test_crc_config.py` only parses it) |

Re-pins recorded (old → new → requirement):
- `tests/test_crc_operation.py::test_at045c_gap_note_names_group_and_count_legacy_stays_silent` — 1 coverage note (group only) → 2 coverage notes (group aggregate + legacy notice naming 2 absent bytes) — HLR-159 / LLR-159.2
- `tests/test_crc_operation.py::test_at044a_legacy_gapped_golden_compat` — notes == [summary] → notes == [summary, "CRC region 0x1000-0x1020: 1 absent byte(s) - the CRC covers present bytes only"] — HLR-159 / LLR-159.2

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, 3 sites, enumerated by grep before the first edit; both are requirement-driven re-pins |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the TC-B99-39 "expected RED until Inc 5" exception | `grep -rn "expected RED until Inc 5\|_CRC_EXPECTED" tests/` | yes — zero hits | tests/test_b99_staging.py (exception block replaced by the zero-exception census) |
| the shared `temp/<name>` CRC staging | `grep -n "WORKAREA_TEMP" s19_app/tui/operations/crc.py` | yes — zero hits | s19_app/tui/operations/crc.py (`reverse-census.txt`) |

### Signed-balance test ledger

`post = base − deleted + added` → `5 = 0 − 0 + 5` ✓ reconciles
(`tests/test_b99_crc_region.py`: 0 baseline nodes — new file — 0 deleted, 5
added: TC-B99-26, TC-B99-27 + its R23 arm, TC-B99-38, AT-B99-10)

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH: the partial-coverage count never reached the Flow Execution surface; F2, F3 MEDIUM; F4 LOW) · round 2: OK to advance, F1–F4 fixed and verified, no mutant residue; its MEDIUM (the chain-set `## Notices` section lists findings with no per-block cap) routed to BACKLOG-CODE |

---

## 5 · Risks

- ~~The FX painted surface shows the notices STATUS but not per-block
  finding text~~ — **resolved by review round 1 (F1)**: the lane terminal
  line now carries the exact absent count
  (`466 of 512 region bytes absent (0xFA00-0xFC00)`, asserted painted by
  AT-B99-10) and the chain-set report lists every advisory finding in the
  always-present `## Notices` section.
- The R23 carrier is a crc.py-local subclass (`CrcCoverageResult`) with a
  defaulted field, not a `model.py` field: the increment budget names two
  SOURCE files and `model.py` is not one of them. **Review round 1 (F4)
  corrects the original claim**: construction and `to_dict` stay unchanged
  for existing callers (`test_operations.py` pins the serializer keys), but
  equality is deliberately NOT unchanged — a `CrcCoverageResult` never
  equals a plain `CrcRegionResult` sibling (the extra `absent_bytes` field
  participates in the dataclass compare), and no caller relies on that
  equality. If a later increment widens `CrcRegionResult` itself, the
  subclass folds into it mechanically.
- `CrcOperation.execute` now returns `status="error"` for an empty region;
  any batch-99+ consumer that assumed `ok` with a `00000000` slot sees the
  refusal instead (that is HLR-159's point — P-9).

## 6 · Pending items / spec deviations

- None blocking. ~~Declared: the AT-B99-10 partial arm's count-text
  observable rides the recorded block result (TC-B99-27), not the painted
  FX surface~~ — **resolved by review round 1 (F1)**; see §"Review round 1
  fixes".
- PDR conditions discharged: C5 (R23 carrier = the region result, one number
  read by the flow arm, `write_crc_image` and the operation path) · PQ-8
  (the TC-B99-38 race RED shows a nonzero mismatch count — 20 of 40 at
  HEAD; no deterministic hook needed) · UX-C2 (the error block's last
  diagnostic is the cause with the region range: `CRC region 0x20000-0x30000
  holds 0 image bytes - nothing written`, painted by the run log's terminal
  line and asserted by AT-B99-10).

## 7 · Suggested next task

Batch-99 Increment 8 (HLR-156, the PATCH truth roll-up): its lane roll-up
must see Inc 5's CRC `error`/`notices` block statuses (ARQ: "Inc 5 before
Inc 8").

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 SOURCE files (`git status` — only `s19_app/tui/operations/crc.py` + `s19_app/tui/services/flow_execution_service.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_crc_region.py` (5 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no shipped-source unit node; the carrier is TC-covered |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED + 2 mutations with transcripts + restore digests |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, population re-validated, 2 re-pins recorded |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only the 2 SOURCE + 4 test/fixture files |
| 8 | Frozen interfaces untouched | all | ✓ | ARCHITECTURE §7 engine untouched; `to_dict` keys unchanged |
| 9 | Coverage claims verified **on disk** | all | ✓ | TC-B99-27/38 and AT-B99-10 read every written byte with the independent reader |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (both mutants) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 2 corrections, 3 sites, enumerated pre-edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 3 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` |
| 16 | **Evidence files** declared | all | ✓ | §4, hashes filled below |

## Review round 1 fixes

- **F1 (HIGH):** the CRC `notices` count reaches the Flow Execution lane log line (`CRC: N of M region bytes absent (span)`, the Inc-8 UX-C1 pattern) and the chain-set report's always-present `## Notices` section; AT-B99-10 asserts the painted count (mutation `mut-f1`: count dropped → RED). Source budget widened by the orchestrator to 3 files (`flow_screens.py` added; cap 4).
- **F2 (MEDIUM):** `crc_diagnostics` reads `absent_bytes` from the region result (R23 single carrier); an empty region gets only its error, last (UX-C2) (mutation `mut-f2` → RED).
- **F3 (MEDIUM):** the 1-present-byte boundary arm added to TC-B99-27.
- **F4 (LOW):** equality claim corrected; `first_empty_target_span` typed.
- Re-pin: TC-B99-19 `- Chain good: none` count 2 → 3 (the new Notices section) — LLR-159.2.
- The Kimi fix session timed out (rc=124) after implementing and reverting both mutations; the orchestrator ran the final sweep (`green-fix-sweep.txt`, 210 passed) and AT-B99-10 ×8 (`stability-at10.txt`), and wrote this section.
