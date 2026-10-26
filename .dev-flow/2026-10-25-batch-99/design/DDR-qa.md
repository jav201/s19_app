# DDR — qa-reviewer (tester's lens) — s19_app — Batch 2026-10-25-batch-99

**Mode:** `validation` (design-review lens). This record covers the tests as built on main `e7732f6` (all 12 increments merged), checked against the PDR's proposed test cases (`design/design-proposal-b99.md` §5), the contract (`01-requirements.md` as amended through the ledger), and the PDR qa conditions (`design/PDR-qa.md` PQ-1..PQ-8). It is an `inspection` of the test files and the evidence on disk, plus targeted runs, all executed by `qa-reviewer` and listed in §6. The full gate suite is not consumed here. The orchestrator runs it for Phase 4 (`evidence/suite-full-e7732f6.txt`).

| Field | Value |
|---|---|
| Reviews | `tests/test_b99_*.py` at `e7732f6`; `03-increments/increment-*.md` §4 mutation rows; `evidence/inc-*/`; `kimi/BRIEF-COMMON.md`; `evidence/p4-premises/FLIP-TABLE.md`; `.dev-flow/BACKLOG-CODE.md` (batch-99 rows) |
| Lens | `qa-reviewer`, DDR (`stations/p4-validation.md` §DDR) |
| **Verdict** | `approved with conditions` (DQ-1..DQ-5 below; each can be discharged on its own) |

**Why it is not `approved`:**
- Four ATs realise in more than one on-disk node, and the C-18 row of `00-checklists.md` (row 4) is still empty (DQ-1).
- Three ATs keep private calls that BRIEF-COMMON names as forbidden, and none of them is routed to the backlog (DQ-2..DQ-4).
- One test id, TC-B99-44, has no home in the contract (DQ-5).

**Why it is not `rejected`:**
- All 40 live LLRs have their TC on disk.
- Every declared negative control has a RED transcript: a post-fix mutant, or the base-commit RED where the contract declared that.
- PQ-1..PQ-8 are discharged when the tests are re-read.
- Every gap above is a test or ledger amendment. None changes a design characteristic.

---

## 1 · LLR → TC → negative control (40 rows; LLR-157.3 and TC-B99-37 retired, ledger .2 / A2-1)

States: **KILLED** = a post-fix mutant shows the TC RED (transcript named). **BASE-RED** = the contract declares the base-commit run as the negative control, and an in-increment transcript at the unmodified tree reproduces it. Paths are under `evidence/`.

| LLR | TC on disk (`tests/…`) | Negative control: what ran | State |
|---|---|---|---|
| 152.1 | TC-B99-01 `test_b99_corpus.py` | timestamp into S0 · `inc-1/mut-LLR-152.1.txt` | KILLED |
| 152.2 | TC-B99-02 | class dropped from `manifest.json` (first attempt in `generate.py` survived, re-aimed) · `inc-1/mut-LLR-152.2.txt` | KILLED |
| 152.3 | TC-B99-03, 03b | reader copies S0 · `inc-1/mut-LLR-152.3.txt`; HEX wrap · `mut-F4.txt` | KILLED |
| 153.1 | TC-B99-04 ×2 `test_b99_s0.py` | re-admit S0 · `inc-2/mut-LLR-153.1.txt` (6 failed) | KILLED |
| 153.2 | TC-B99-05 | same mutant, TC-05 FAILED in the transcript | KILLED |
| 153.3 | TC-B99-06 | same mutant + `mut-F5.txt` (checksum-defective arms) | KILLED |
| 153.4 | TC-B99-07 | `inc-2/red-tc_b99_07.txt` (P-2) + also RED under the 153.1 mutant | BASE-RED + KILLED |
| 154.1 | TC-B99-08 ×7 `test_b99_truncation.py` | terminator check dropped · `inc-9/mut-LLR-154.1.txt` | KILLED |
| 154.2 | TC-B99-09 ×6 | EOF check dropped · `inc-9/mut-LLR-154.2.txt` | KILLED |
| 154.3 | TC-B99-10 ×2 | codes mapped to `notices` · `inc-9/mut-LLR-154.3.txt` (5 arms) | KILLED |
| 155.1 | TC-B99-11 ×3 `test_b99_staging.py` | shared staging · `inc-3a/mut-155.1-shared-staging.txt`, `mut-fix2-f3-temp-staging.txt` | KILLED |
| 155.2 | TC-B99-12 ×7 | check-then-copy · `inc-3a/mut-155.2-check-then-copy.txt` (140 mismatches), `mut-fix2-155.2-check-then-copy.txt` (35); S-F1, S-F6 arms | KILLED |
| 155.3 | TC-B99-13 ×6 | delete-and-recopy in `_gather_copy` · `inc-3b/mut-LLR-155.3.txt`; drift-re-save · `mut-LLR-138.4.txt` (3a `mut-155.3-no-source-verify` superseded by LED .7) | KILLED |
| 155.4 | TC-B99-14 ×3 | `inc-3a/red-tc_b99_14.txt` (P-15) + `mut-fix2-f6a-no-cleanup.txt`, `mut-fix2-sf5-flag-always-true.txt` | BASE-RED + KILLED |
| 155.5 | TC-B99-15 ×2 | refusal disabled · `inc-3b/mut-LLR-155.5.txt` (3 nodes) | KILLED |
| 155.6 | TC-B99-16 ×2 | verify disabled · `inc-3b/mut-LLR-155.6.txt` | KILLED |
| 155.7 | TC-B99-39 | re-derived unlink · `inc-3a/mut-155.7-rederived-unlink.txt`; 155.8 mutant re-flags it · `inc-5/mut-LLR-155.8.txt` | KILLED |
| 155.8 | TC-B99-38 `test_b99_crc_region.py` | shared `temp/<name>` · `inc-5/mut-LLR-155.8.txt` (20 of 40 mismatches) | KILLED |
| 156.1 | TC-B99-17 ×6 `test_b99_patch_truth.py` | error arm disabled · `inc-8/mut-LLR-156.1.txt` | KILLED |
| 156.2 | TC-B99-18 ×2 | `refusals=` copy dropped · `inc-8/mut-LLR-156.2.txt` | KILLED |
| 156.3 | TC-B99-19 | `inc-8/red-tc17-20-at06-07.txt` (TC-19 FAILED; P-14) — no post-fix mutant | BASE-RED (as declared) |
| 156.4 | TC-B99-20 | section made conditional · `inc-8/mut-LLR-156.4.txt` | KILLED |
| 157.1 | TC-B99-21 `test_b99_editor_image.py` | skip restore · `inc-4/mut-LLR-157.1.txt`; rebind · `mut-LLR-157.1-alias.txt` | KILLED |
| 157.2 | TC-B99-22 ×2 | skip re-derive · `inc-4/mut-LLR-157.2.txt` | KILLED |
| 157.3 | — | retired with TC-B99-37 (ledger .2, A2-1) | n/a — retired |
| 157.4 | TC-B99-40 ×3 | journal after write · `inc-4/mut-LLR-157.4.txt` | KILLED |
| 158.1 | TC-B99-23, TC-B99-42 `test_b99_a2l_encode.py` | `MOD_COMMON` step deleted · `inc-10/mut-LLR-158.1.txt`; first module wins · `mut-LOWa-first-module-wins.txt` | KILLED |
| 158.2 | TC-B99-24, TC-B99-43 | old direction · `inc-10/mut-LLR-158.2.txt`; denominator check · `mut-LOWb-denominator-check.txt` | KILLED |
| 158.3 | TC-B99-25 | silent nearest/clamp · `inc-10/mut-LLR-158.3.txt`; `mut-F1-nearest-entry.txt`, `mut-F2-clipping.txt` | KILLED |
| 159.1 | TC-B99-26 ×2 | refusal bypassed · `inc-5/mut-LLR-159.1.txt` | KILLED |
| 159.2 | TC-B99-27 ×4 | `inc-5/red-baseline.txt` (TC-27 ×2 FAILED; P-9) — no post-fix mutant | BASE-RED (as declared) |
| 160.1 | TC-B99-28 `test_b99_export.py` | sanitiser bypass · `inc-6/mut-LLR-160.1.txt`, `mut-fix-LLR-160.1.txt` | KILLED |
| 160.2 | TC-B99-29 ×4 | destination-rooted check · `inc-6/mut-LLR-160.2.txt` | KILLED |
| 160.3 | TC-B99-30 | MAC placeholders as data · `inc-6/mut-LLR-160.3.txt` | KILLED |
| 160.4 | TC-B99-31 ×6 | per-file `_<N>` · `inc-6/mut-LLR-160.4.txt` (3 arms); skip claim removal: **not run by Inc 6**, run by qa-reviewer (§6, KILLED) | KILLED |
| 160.5 | TC-B99-41 ×8 | collision check in loop · `inc-6/mut-LLR-160.5.txt`, `mut-fix-LLR-160.5.txt` | KILLED |
| 161.1 | TC-B99-32 `test_b99_bytes_field.py` | base-0 first · `inc-11/mut-LLR-161.1.txt` (+ 2 fix-round mutants) | KILLED |
| 161.2 | TC-B99-33 | placeholder revert · `inc-11/mut-LLR-161.2.txt`; help revert: **not run by Inc 11**, run by qa-reviewer (§6, KILLED) | KILLED |
| 162.1 | TC-B99-34 `test_b99_load_project.py` | `str(label_widget)` · `inc-7/mut-LLR-162.1.txt` | KILLED |
| 162.2 | TC-B99-35 | `!= WORKAREA_TEMP` only · `inc-7/mut-LLR-162.2.txt` | KILLED |
| 162.3 | TC-B99-36 | root listing · `inc-7/mut-LLR-162.3.txt` | KILLED |

**Totals:**
- 40 live LLRs: 40 with a TC on disk, 40 with an executed negative control.
- Gaps: none.
- Two LLRs, 156.3 and 159.2, rely on the declared base RED only. That is what the contract states, so it is not a gap. A post-fix mutant would be stronger (advisory).
- **Stray id:** `test_tc_b99_44_*` ×2 (`test_b99_staging.py:993`, `:1037`) has no LLR in the contract or the ledger (DQ-5).

---

## 2 · AT black-box table (BRIEF-COMMON rule)

| AT | Node(s) | Drive → observe | Residual private call | C-18 |
|---|---|---|---|---|
| AT-B99-01 | `test_at_b99_01_check_mode` | generator CLI subprocess → exit code, stdout | none | 1 node ✓ |
| AT-B99-02 | `test_at_b99_02_save_back_excludes_s0` | keys/clicks → reader on disk, painted Memory Map | `type(app.screen).__name__` used as a branch predicate only | 1 node ✓ |
| AT-B99-03 | `…_pilot_status_and_issues`, `…_hostile_name_renders_literally`, `…_pilot_flow_source_fails` | Load dialog, `#fx_run` → painted status/issues, files | `app.workarea` to stage fixture files; `isinstance(app.screen, …)` waits | **3 nodes; the outcome's two clauses (load notice, flow SOURCE fail) sit in different nodes** (DQ-1) |
| AT-B99-04 | `…_duplicate_names_refused_nothing_written`, `…_distinct_names_parallel_regression_guard` | painted `#fx_log`, `#log_line_4`, files | **`app._handle_load_project` (via `b97_fixtures.load_project`), `#fx_run` `Button.press()` (via `run_lanes`, `key=False`), wait on `panel.last_run_record`; guard node: `ModeToggle.set_mode("parallel")`** — the docstring "driven by keys and clicks" overstates (DQ-2) | **2 nodes, one per outcome clause** (DQ-1) |
| AT-B99-05 | `…_save_project_after_same_name_save_back` | clicks/keys → `#log_line_4`, files | none found | 1 node ✓ |
| AT-B99-06 | `…_flow_execution_patch_truth` | Load project dialog, rail key, `#fx_run` → painted cells, log, reports, reader | none found | 1 node ✓ |
| AT-B99-07 | `…_hostile_symbol_name_renders_literally` | same drive → painted strip, report file | none found | 1 node ✓ |
| AT-B99-08 | `…_save_back_keeps_editor_image`, `…_verify_mismatch_status_still_names_entries` | clicks/keys → reader, painted status | second node monkeypatches `change_service.verify_written_image` (a declared fault seam); exact status text not asserted (already routed, BACKLOG Inc-4 N3) | 2 nodes; the first carries the whole chain — designate it (DQ-1) |
| AT-B99-09 | `…_a2l_window_physical_column` | Load dialog → painted rows + describe modal at 118×40 and 80×24 | **`_load_through_dialog` sets `Input.value` and calls `#load_ok` `Button.press()`; wait on `app.current_file`** (DQ-3) | 1 node ✓ |
| AT-B99-10 | `…_flow_crc_region_pilot` | Load project dialog, `#fx_run` → reader, painted count | `app.workarea` for fixture staging; `isinstance(app.screen, …)` waits | 1 node ✓ |
| AT-B99-11 | 5 nodes (`…_hostile_segment_name…`, `…_mac_only_export…`, `…_second_export_after_patch…`, `…_part_way_failure_status…`, `…_junctioned_project_home…`) | Load project dialog, export key → reader, status | `app.workarea` for fixture staging; `type(app.screen)` waits | **5 nodes; the outcome's three clauses sit in three nodes** (DQ-1) |
| AT-B99-12 | `…_typed_hex_run_saves_back` | typed keys → reader on disk | **`Button.press()` ×3 (Add, Apply, save-back confirm); the comment justifies only the confirm** (DQ-4) | 1 node ✓ |
| AT-B99-13 | `…_project_and_file_pickers_load_by_name` | dialog keys/clicks | reads `app.screen` type and `app.workarea` (already routed, BACKLOG Inc-7 F3) | 1 node ✓ |
| AT-B99-14 | `…_codec_api_encode_surface` | codec API `(raw_bytes, error, flags)` | declared US-152 / P-22 exception | 1 node ✓ |

---

## 3 · PDR qa conditions: discharge by re-reading the tests

| # | Discharge asked | Re-read at `e7732f6` | State |
|---|---|---|---|
| PQ-1 | a producing increment for `place_group_into_workarea`; `segment_ops` must not import `tui.workspace` | `tui/workspace.py:695` has the declared signature; `segment_split_view.py:82/:949` calls it; the `segment_ops.py` imports are `tui.changes.io` and `tui.operations.crc_designer_model` only | discharged |
| PQ-2 | TC-B99-31 arms (a) orphan `_1.addr`, (b) mismatched sidecar, (c) forced failure, each RED under its mutant | arms present: `…_orphan_sidecar_claims_the_pair_suffix`, `…_mismatched_sidecar_never_reuses_the_pair`, `…_forced_failure_rolls_back_every_own_claim`. (a) and (b) are KILLED in `inc-6/mut-LLR-160.4.txt`. (c)'s "skip claim removal" mutant was absent from Inc 6, so qa-reviewer ran it (§6): KILLED, `t_isle_1.addr` and `t_isle_1.bin` left behind | discharged (the (c) transcript is not on disk; see DQ-6) |
| PQ-3 | TC-B99-39's census includes the group writer | `test_b99_staging.py:956` lists `(workspace.py, place_group_into_workarea)` | discharged |
| PQ-4 | corpus A2L pins (6 items) | `tests/fixtures/synth/synth_a2l.a2l` + `manifest.json` `a2l_expect`: (1) NOINTP 10/15/20, no 13 ✓ (2) INTP [0, 62.5] inside (−50, 500), step 2.5, off-grid 3.4 → raw 1 / written 2.5 (no tie), grid 5.0 ✓ (3) limits −10..100 and 0..30 enclose ✓ (4) `SYM_U16_MSB` / `RL_U16_NO_BO` carry no `BYTE_ORDER`, only `MOD_COMMON MSB_FIRST` ✓ (5) LINEAR declares `BYTE_ORDER MSB_LAST` (the ASAP2 spelling of LSB-first) → `0F00` ✓ (6) RAT_FUNC `012C` ✓ | discharged |
| PQ-5 | flag and reason checked by content | TC-25: the off-grid flag asserts `"2.5"` and `"3.4"`; the −50 / 500 refusals assert `"[0.0, 62.5]"` (table range; the limits would read −10..100); grid `flags == []` | discharged |
| PQ-6 | TC-33 pins text HEAD lacked; one mutant per arm | TC-33 asserts `0x`, `decimal` and `not accepted` on the help line. The pre-Inc-11 text (`5021bb6^`) is "a run of hex bytes, such as `DE AD BE EF`.", which lacks all three. The placeholder mutant is in `inc-11/mut-LLR-161.2.txt`. The help-arm mutant was absent, so qa-reviewer ran it (§6): KILLED at the `0x` assertion | discharged (help transcript not on disk; DQ-6) |
| PQ-7 | a painted-sink mutant with markup on, shown RED | `inc-8/mut-f4-painted.txt`: lane failure-detail through `Text.from_markup` → AT-B99-07 FAILED; report-side `mut-PQ7.txt` also KILLED | discharged (note DQ-8) |
| PQ-8 | race REDs show nonzero counts or a deterministic hook | TC-12: `parallel mismatches: 140` (forced interleaving) and `35`; TC-13: `68`; TC-38: `20 of 40` | discharged |

---

## 4 · Premise flip table: 3 rows spot-checked against their transcripts

| Row | Before (`p0-premises/`) | After (`p4-premises/`) | Matches the table? |
|---|---|---|---|
| P-8 | `rw-p06…:5` `TAB_NOINTP 13.0 -> raw 01 … err=None`; `:7` `TAB_INTP 500.0 -> raw 02 … err=None` | `rw-p06a…:6` refused "nearest table values are 10.0 and 20.0"; `:8` "outside the table range [0.0, 20.0]" | ✓ |
| P-15 | `proj-p08…:76` `work copy exists after save-back: False`; `:78` `return_code: 1` | `proj-p08.txt:3` `True`; `:5` `app running? True \| return_code: None` | ✓ |
| P-5 | `rw-p02…:36` `parallel mismatches: 35 files now: ['same.s19']` | `rw-p02…:1` `parallel mismatches: 0 files now: []` | ✓ as quoted. The "after" is an absence over **zero** files: D7 refuses the set, so the probe no longer exercises the race (DQ-7) |

The three adapted probes carry their header comment (`adapted/*.py`, first line).

---

## 5 · Findings

| # | Sev | Finding | Discharge | Owner |
|---|---|---|---|---|
| DQ-1 | major | **C-18 is not reconciled.** AT-B99-03 (3 nodes), AT-B99-04 (2), AT-B99-08 (2) and AT-B99-11 (5) each realise in several nodes. For AT-03, AT-04 and AT-11, the outcome's clauses are split across nodes, so no single node drives the whole named chain. `00-checklists.md` row 4 is empty. C-18 blocks the Phase-4 gate for an AT satisfied only in parts. | Before Phase 4, for each of the four ATs: either one joined node drives every clause in one pilot session, or the orchestrator records which node is the AT and moves the other clauses into a ledger amendment (each becomes its own AT, or a TC arm). AT-08 only needs its first node designated. | orchestrator (ledger) + `tester`/`software-dev` for joined nodes |
| DQ-2 | minor | **AT-B99-04 is not black-box on entry.** Both nodes load the project through `app._handle_load_project` and press Run with `Button.press()`. The guard node sets parallel mode with `ModeToggle.set_mode`. The duplicate node's docstring says "driven by keys and clicks". All of these are forbidden by BRIEF-COMMON. The observations (painted log, status line, files) are black-box. Not routed to the backlog. | Load through `#project_ok`, run with `run_lanes(…, key=True)`, choose the mode by key or click; or route as a BACKLOG row and correct the docstring. | orchestrator |
| DQ-3 | minor | **AT-B99-09 enters through `Input.value =` and `Button.press()`** (`test_b99_a2l_encode.py:524-526`), and waits on `app.current_file`. The painted observations are sound. Not routed. | Type the path with `pilot.press`, click `#load_ok`, wait on painted status; or route. | orchestrator |
| DQ-4 | minor | **AT-B99-12 uses `Button.press()` ×3** (`test_b99_bytes_field.py:199-213`). The comment justifies only the hidden confirm button. Add and Apply are visible and clickable. Not routed. | Click Add and Apply; keep the confirm justification; or route. | orchestrator |
| DQ-5 | minor | **TC-B99-44 is an unassigned id.** Two nodes (`test_b99_staging.py:993`, `:1037`) were minted in the Inc-3a fix round, which committed after the never-invent rule (`793c477`). They appear in neither `01-requirements.md` nor the ledger, so traceability from TC to requirement exists only in the packet. | A ledger line assigns TC-B99-44 to LLR-155.1 (PDR C2 path), or the nodes are renamed as TC-B99-11 sub-nodes. | orchestrator |
| DQ-6 | minor | **Two declared mutants were run only at the DDR, by qa-reviewer.** These are PQ-2(c) "skip claim removal" and PQ-6 help-arm revert, both KILLED (§6). Their transcripts are not in `evidence/` because this reviewer writes nothing else. | The orchestrator re-runs the two commands in §6 and saves the transcripts under `evidence/inc-6/` and `evidence/inc-11/`, or cites this record as their evidence. | orchestrator |
| DQ-7 | low | **The P-5 flip is shown by an absence over zero files.** After D7 the probe writes nothing, so "0 mismatches" no longer exercises placement. The flip of P-5's mechanism lives in TC-B99-12 (GREEN at 0, RED at 35/140 under the mutant). | Reword the FLIP-TABLE row to point at TC-B99-12 as the race evidence. | orchestrator |
| DQ-8 | low | **The PQ-7 painted mutant reddens through a render crash** (`MissingStyle '@click app.quit'`), not through the 0-markup-span assertion. | Advisory: a payload arm without `@click` would show the literal-render assertion discriminating. | backlog, optional |

**Already routed (BACKLOG-CODE, batch-99):**
- AT-B99-08 does not assert the exact text (Inc-4 N3).
- AT-B99-13 reads `app.screen` and `app.workarea` (Inc-7 F3).
- Flake: `test_b97_flow_execution::test_tc_b97_64_a_new_set_run_restarts_the_dwell`.
- The writers excepted from LLR-155.3 (Inc-3b).
- The placement residuals R1 and R2 (Inc-3a).

**Accepted residuals (not findings):**
- `app.workarea`, used only to stage fixture files.
- `isinstance(app.screen, …)`, used only as a wait predicate.
- AT-08's declared `verify_written_image` fault seam.
- AT-14's declared codec-API exception.

---

## 6 · Runs executed by qa-reviewer

| Run | Where | Result |
|---|---|---|
| `pytest -q -p no:cacheprovider tests/test_b99_export.py -k tc_b99_31` | main `e7732f6`, `PYTHONPATH` = repo (probe: `…\s19_app\s19_app\__init__.py`), `NO_COLOR` unset | `6 passed, 29 deselected` |
| `pytest -q -p no:cacheprovider tests/test_b99_bytes_field.py tests/test_b99_a2l_encode.py` | same | `10 passed` |
| PQ-2(c) mutant: in `place_group_into_workarea`'s PermissionError branch, `if claims_owned:` → `if False:` (skip claim removal); `pytest tests/test_b99_export.py -k tc_b99_31` | scratch extract of `git archive e7732f6` (`PYTHONPATH` = scratch, probe confirmed); repo untouched | `1 failed, 5 passed` — `test_tc_b99_31_forced_failure_rolls_back_every_own_claim`: left `['t_isle.addr', 't_isle.bin', 't_isle_1.addr', 't_isle_1.bin']` vs expected two → KILLED |
| PQ-6 help mutant: `window_help.py` Bytes line reverted to the `5021bb6^` text; `pytest tests/test_b99_bytes_field.py -k tc_b99_33` | scratch extract (workspace.py restored and `cmp`-verified first) | `1 failed` — "the help must state the 0x prefix is optional; got 'Bytes — a run of hex bytes, such as `DE AD BE EF`.'" → KILLED |

---

## 7 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | ✓ | the contract's HLR *Observable outcome* + *Shipped surface*; not re-authored at DDR |
| Test cases have explicit Expected | ✓ | each LLR's *Numeric pass threshold*; §1 shows each TC asserting it |
| Edge cases include empty, boundary, invalid, error | ✓ | QC-3 catalogs per HLR; e.g. TC-27 1-present-byte, TC-41 over-long, TC-26 empty |
| Regression checklist exists | ✓ | reverse census per packet (`evidence/inc-*/reverse-census.txt`); full suite at `e7732f6` run by the orchestrator |
| Exit criteria stated | ✓ | `01-requirements.md` §5.2 |
| No real PII / secrets | ✓ | synthetic corpus `tests/fixtures/synth/`; no person names |
| Mode declared | ✓ | `validation` (DDR lens), top of file |
| Every result carries a state and names its executor | ✓ | §1 states; §6 runs named as qa-reviewer; full suite attributed to the orchestrator, not consumed |
| Layer B through the shipped surface, boundary + negative | ⚠ | §2: every AT observes the shipped surface; entry residuals DQ-2..DQ-4 |
| Bidirectional surface reachability | ⚠ | outputs observed at the surface for every story; inputs reach it except the US-152 declared exception and the DQ-2..DQ-4 entries |
| C-18 one node per AT | ✗ | DQ-1 |
| No unfilled template | ✓ | no `<...>`; every DQ names an owner |
