# Increment 003b — HLR-155 D7 + D9 · `duplicate output names refused; WRITE-OUT verifies`

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `003b` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-144 / HLR-155 (D7 = rechazar, D9 = si) / LLR-155.5 · LLR-155.6 · LLR-155.3 (LED-2026-10-25-batch-99.7)` |
| Acceptance | `AT-B99-04 duplicate-name arm` · white-box `TC-B99-15 · TC-B99-16` · TC-B99-13's census + gather-drift arms · `UX-C2 / UX-C4 / UX-C10` (PDR `design/PDR-ux.md`) |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: two HLR-155 clauses close. **D7 (LLR-155.5)** — `run_chain_set` now
resolves every lane's WRITE-OUT output name before any lane runs and refuses
the set, case-folded, when two or more lanes resolve to one name: the refusal
rides the record's existing `ChainSetRunRecord.diagnostics` shape (no new
return type — the panel's `render_run` already paints diagnostics into the
run log, so `app.py` needed no edit), leads with the outcome
(`Chain set not run:` at index 0, well inside UX-C4's first 50 characters),
names the lanes and the colliding file, and writes nothing — no lane
executes, no chain-set report is emitted. **D9 (LLR-155.6)** — the flow
WRITE-OUT arm now re-reads the placed file through the existing
`verify_written_image` seam right after placement; a mismatch ends the block
`error`, aborts the chain, and the LAST diagnostic — the painted cause
(UX-C2) — names the first differing address (`first difference at 0x……`,
plus one `kind 0x……..0x……` line per diff run before it). An intact write
verifies and stays `ok`.

**LLR-155.3's LED-.7 conversion** — `project_gather_service._gather_copy`'s
delete-and-recopy (`unlink` then `shutil.copy2` onto the existing final
name, the `:290-299` site) is converted to HLR-155's placement: a drifted
source is placed through `copy_into_workarea` and takes the next free `_<N>`
name; the existing final name is never replaced or deleted, so a placed
artifact is immutable once placed. The `(copied, destination)` return
contract is unchanged (byte-identical → `False` + the requested name; drift
→ `True` + the `_<N>` name); the one caller's expectations are untouched.
The module docstring's snapshot-semantics paragraph and `_gather_copy`'s
docstring now describe placement instead of overwrite.

Shipped surface the user reaches: Flow Execution (`#fx_run`, the painted
`#fx_log`); Save project (a drifted gathered artifact now lands under
`_<N>` instead of being overwritten).

---

## 1a · Review round 1 fixes (code-reviewer F1–F4, 2026-10-25)

BLUF: the independent review found four defects; all four are fixed here
(source budget now 3/4: `flow_execution_service.py`, `project_gather_service.py`,
`app.py`).

- **F1 [HIGH] — unchanged re-saves stacked `_<N>` copies after one drift.**
  `_gather_copy` byte-compared only against `<name>`; after a drift the
  current bytes live at `_<N>`, so every unchanged re-save placed another
  copy (`_2`, `_3`, …) — LLR-138.4 broken. Fixed: before placing,
  `_gather_copy` scans the home for a `stem(_N)?suffix` sibling
  (`_same_artifact_name`, symlinks and foreign stems excluded) that already
  holds the source's exact bytes and returns it as reused (`copied=False`).
  New TC-B99-13 arm `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`;
  mutation (name-only compare) KILLED, `mut-LLR-138.4.txt`.
- **F2 [MEDIUM] — the D7 refusal was not on the status line.** LLR-155.5
  requires it there; it appeared only in the run log. Fixed:
  `on_flow_execution_panel_run_requested` now paints the record's
  outcome-first diagnostic on `#log_line_4` (`set_status`) when the set was
  refused (no outcomes, non-empty diagnostics). The label's markup stays
  off, so lane names paint literally (UX-C10) and the outcome leads inside
  UX-C4's first 50 characters. AT-B99-04's duplicate arm now asserts the
  painted status line (RED first, `red-f2-at04-status.txt`). The confirm
  re-run handler needs no such paint: it drives ONE lane and D7 cannot
  refuse a single lane. The pre-fix §6 claim "`app.py` was NOT edited" is
  corrected below.
- **F3 [MEDIUM] — two evidence hashes mismatched and batch 3 was
  misdescribed.** Both hashes recomputed (`green-census-b97.txt` →
  `3024393a…`, `green-census-batch3.txt` → `96acb69e…`; the other 21
  verified unchanged); batch 3 was a FULL run — "5 failed, 500 passed in
  2459.16s", not "timed out at ~85 %". The 5 failures classified against
  the batch baseline ledger (main-checkout `PLAN.md`): one is the
  documented pre-existing base-RED (`test_at031b_two_saves_are_distinct_no_clobber`,
  in the `a293213` baseline list); the other four are long-run load/ordering
  flakes that passed on the isolated re-runs already on disk
  (`green-census-batch3-rest.txt` 359 passed + only that base-RED;
  `green-census-batch3-width.txt` 145 passed) — none in any increment's
  source path.
- **F4 [LOW]** — (a) the LLR-155.3 census now also flags `write_text`; the
  probe catches 7 sites on the real tree (`red-f4a-census.txt`): four
  allow-listed (the diff reports' M-5 collision-counter names, the
  operator-picked A2L dump export, the split/join export, the CRC
  designer's same-name template save) and two pinned as **declared
  exceptions** — `flow_persistence_service.save_flow_json` (:1032) and
  `save_chain_set` (:1506), which share the house `exists()` + counter
  dedup (never an overwrite, but not the pinned placement either); they are
  recorded for the backlog, NOT fixed here. (b) the UX-C10 D7 test now
  drives the shipped panel through the pilot and asserts the PAINTED
  `#fx_log` (hostile literal verbatim in `.plain`, 0 style spans) — it no
  longer calls `safe_text` itself. (c) the `test_flow_chainset_b94.py:565`
  comment's wrong "D7's placement" attribution corrected to HLR-155's
  placement (LLR-155.3).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/flow_execution_service.py` | SOURCE | HLR-155 D7/D9, LLR-155.5/.6, B99-I11/I12 | `run_chain_set`: `_write_out_collisions` case-folded pre-flight refusal in `diagnostics`, nothing written; `run_flow` WRITE-OUT arm: `verify_written_image` read-back, `error` naming the first differing address (UX-C2 last-diagnostic); `verify` import; docstrings |
| `s19_app/tui/services/project_gather_service.py` | SOURCE | LLR-155.3 (LED .7), HLR-155 | `_gather_copy`: drift limb converted to `copy_into_workarea` placement (next free `_<N>`, never an overwrite); `shutil` import dropped; module + function docstrings |
| `tests/test_b99_staging.py` | test | TC-B99-15/16, TC-B99-13 arms, AT-B99-04 dup arm, UX-C2/C4/C10 | 8 nodes added (see the ledger); Inc-3b imports + module docstring |
| `tests/test_flow_chainset_b94.py` | test (re-pin) | HLR-155 D7 | `_clean_chain` writes `out_<name>.s19`; the reloaded-set test saves a second template (`base_b`) |
| `tests/test_tui_flow_execution_b94.py` | test (re-pin) | HLR-155 D7 | `_base_blocks(output=…)`; three two-lane tests import a `base_b` template (own WRITE-OUT name) instead of importing `base` twice; lane-name refs `base_2` → `base_b` |
| `tests/test_project_gather.py` | test (re-pin) | LLR-155.3 (LED .7) | TC-702 re-pinned: drifted re-save places the next free `_<N>` (2 copies), the placed copy stays immutable |
| `tests/b97_fixtures.py` | test fixture (re-pin) | HLR-155 D7 | `err_chain_demo` writes `fw_err.s19`; `fx_project` adds the `flash_b` / `six_ok_c` / `six_ok_d` twin templates (own WRITE-OUT names) |
| `tests/test_b97_flow_execution.py` | test (re-pin) | HLR-155 D7 | `TWO_WAIT` → `("flash_chain", "flash_b")`; `DEEP` → four distinct templates; `test_tc_b97_53…` drives five `cap_*` templates |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-003b.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-3b/*` | doc | — | transcripts, hashes, census (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** (2 in the first round + `app.py` in review round 1) |
| Test files | 6 (uncapped; review round 1 amended 3 of them, added 1 node) |
| Doc files | 2 (outside the count) |

**Review round 1 amendments** (code-reviewer F1–F4):

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/project_gather_service.py` | SOURCE (amended) | LLR-138.4 (F1) | `_same_artifact_name` helper; `_gather_copy` now byte-compares the source against the requested name AND every `_<N>` sibling before placing (unchanged re-save after a drift is skipped, `copied=False`); module + function docstrings |
| `s19_app/tui/app.py` | SOURCE (new) | LLR-155.5 (F2) | `on_flow_execution_panel_run_requested`: a refused set (no outcomes, diagnostics) also paints its outcome-first diagnostic on the status line via `set_status`; handler docstring |
| `tests/test_b99_staging.py` | test (amended +1 node) | F1/F2/F4a/F4b | new arm `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`; AT-B99-04 duplicate arm extended with the painted `#log_line_4` assertions; census extended with the `write_text` limb + 4 allow-list entries + 2 declared exceptions + a `write_text` positive control; UX-C10 D7 node rewritten as a painted-text pilot drive |
| `tests/test_flow_chainset_b94.py` | test (comment) | F4c | the `:565` comment's "D7's placement" attribution corrected to HLR-155's placement (LLR-155.3) |

- ✓ No file from another lane touched; `prototypes/` untouched; no commit (working tree only).
- Interface note: **no new return type** — the D7 refusal reuses `ChainSetRunRecord.diagnostics` (one line per colliding name) with empty `outcomes` and `report_path=None`; `app.py`'s existing handlers paint it via `render_run` with no edit (map rows B99-I11/I12 name `app.py:2800/:2890` as the show-the-refusal sites — they show it unchanged).

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # must print a path inside the worktree
pytest tests/test_b99_staging.py -k "tc_b99_15 or tc_b99_16" -v          # -> 4 passed
pytest tests/test_b99_staging.py -k "tc_b99_13" -v                        # -> 6 passed
pytest tests/test_b99_staging.py -k "at_b99_04 or ux_c10_d7" -v           # -> 3 passed
pytest tests/test_b99_staging.py tests/test_address_census.py tests/test_id_registry.py -q  # -> 68 passed

# review round 1 (F1–F4):
pytest tests/test_project_gather.py tests/test_flow_chainset_b94.py -q    # -> 23 passed
pytest tests/test_tui_flow_execution_b94.py tests/test_b97_flow_execution.py -q  # -> 85 passed + 1 long-run flake (isolated re-run green)
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-B99-15` ↔ LLR-155.5 | `core` · `full` | `test_tc_b99_15_duplicate_write_out_names_refused` · `test_tc_b99_15_distinct_names_run` | 2 passed |
| **A · white-box** `TC-B99-16` ↔ LLR-155.6 | `core` · `full` | `test_tc_b99_16_corrupted_write_out_is_error_naming_address` · `test_tc_b99_16_intact_write_out_is_ok` | 2 passed |
| **A · white-box** `TC-B99-13` arms ↔ LLR-155.3 | `core` · `full` | `test_tc_b99_13_gather_drift_places_next_free_name` · `test_tc_b99_13_no_final_name_replace_outside_placement` | 2 passed |
| **B · black-box** `AT-B99-04` duplicate arm ↔ HLR-155 D7 | `core` · `full` | `test_at_b99_04_duplicate_names_refused_nothing_written` | 1 passed |
| **B · black-box** `UX-C10` D7 lane-name sink | `core` · `full` | `test_tc_b99_ux_c10_d7_lane_name_renders_literally` | 1 passed |

**Review round 1 results** (fix round, against the fixed tree):

| Layer | Nodes | Result |
|---|---|---|
| `TC-B99-13` F1 arm `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate` ↔ LLR-138.4 | 1 | 1 passed (RED first, `red-f1-gather-reuse.txt`) |
| TC-B99-13 neighbourhood re-run (6 nodes, incl. the census arm with the F4a `write_text` limb) | 6 | 6 passed (`green-f1-gather-reuse.txt`) |
| AT-B99-04 duplicate arm (extended, F2) + distinct-names guard + UX-C10 | 3 | 3 passed (`green-f2-at04-status.txt`) |
| UX-C10 D7 painted-text rewrite (F4b) | 1 | 1 passed (`green-f4b-uxc10.txt`) |
| `tests/test_b99_staging.py` + `tests/test_address_census.py` + `tests/test_id_registry.py` | 68 | 68 passed (`green-fix-staging-census-registry.txt`) |
| `tests/test_project_gather.py` + `tests/test_flow_chainset_b94.py` (F4c comment) | 23 | 23 passed (`green-fix-gather-chainset.txt`) |
| `tests/test_tui_flow_execution_b94.py` + `tests/test_b97_flow_execution.py` | see §4 evidence | see `green-fix-b94-b97.txt` |
| AT-B99-04 ×8 stability runs (F2) | 8 | 8 passed (`green-at04-x8.txt`) |

Regression companion: `tests/test_address_census.py` — 23 passed.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | three (one per LLR), each applied, shown RED, reverted and the file hash returned to baseline |
| Instrument | project code: the implementer's own hand via the Edit tool; restore checked by SHA-256 against `baseline-hashes.txt` |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc3b`), run by the implementer |
| Transcript | `evidence/inc-3b/mut-LLR-155.5.txt` · `mut-LLR-155.6.txt` · `mut-LLR-155.3.txt` (each: target nodes FAILED) |
| Restore proven by | `flow_execution_service.py` → `262b233c…85b557` and `project_gather_service.py` → `04f30496…4b0f5` both RESTORED (post-revert hash check, same transcript as `baseline-hashes.txt`) |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | RED runs: `red-tc15-16.txt` (2 failed / 2 control arms passed), `red-census-gather.txt` (2 failed), `red-at04-uxc10.txt` (2 failed) — 6 nodes RED, 0 vacuous |
| Verdict granularity | per resolved node id |
| Arms that stayed GREEN | the 2 control arms (`test_tc_b99_15_distinct_names_run`, `test_tc_b99_16_intact_write_out_is_ok`) — boundary/invalid-catalog controls, GREEN at baseline by design |

| Field | Value |
|---|---|
| **RED counterfactual** | baseline RED (unmodified tree): `red-tc15-16.txt` — `test_tc_b99_15_duplicate_write_out_names_refused` FAILED (the lanes ran; no refusal exists) and `test_tc_b99_16_corrupted_write_out_is_error_naming_address` FAILED (`result.status == 'ok'` on a corrupted write); `red-census-gather.txt` — both TC-B99-13 arms FAILED (the census names `project_gather_service.py:299 shutil.copy2 outside the pinned placement allow-list`); `red-at04-uxc10.txt` — the AT FAILED (the set wrote `same.s19`; no `Chain set not run` line painted) and the UX-C10 node FAILED (the hostile lane ran as a real lane). |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-155.5 · TC-B99-15 + AT-B99-04-dup + UX-C10-D7: the `if collisions:` refusal arm disabled · KILLED — 3 nodes FAILED (`mut-LLR-155.5.txt`) · arms GREEN: none · restore `262b233c…` ‖ LLR-155.6 · TC-B99-16: the verify branch disabled (`if False and …`) · KILLED — the corrupted-write arm FAILED (`mut-LLR-155.6.txt`; the intact control stayed GREEN, as the LLR's negative control predicts) · restore `262b233c…` ‖ LLR-155.3 · TC-B99-13 census + gather-drift arms: the delete-and-recopy restored inside `_gather_copy` · KILLED — both arms FAILED (`mut-LLR-155.3.txt`) · restore `04f30496…` ‖ **LLR-138.4 (review round 1, F1)** · the new drift-re-save arm: the `_<N>` sibling scan disabled — the compare runs only against `<name>` · KILLED — `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate` FAILED (the drift control stayed GREEN) · revert proven by hash `8e4f018c…` (`post-f1-hash.txt`) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the unmodified tree against the new TC-B99-15/16 | `test_tc_b99_15_duplicate_write_out_names_refused` / `…_16_corrupted…` FAILED (`red-tc15-16.txt`) |
| the AST census (TC-B99-13 arm) | the unmodified tree (gather still unlink+copy2) | `project_gather_service.py:299 shutil.copy2 outside the pinned placement allow-list` (`red-census-gather.txt`) |
| the painted-surface AT | the unmodified tree (P-5's set) | `test_at_b99_04_duplicate_names_refused_nothing_written` FAILED — no `Chain set not run` line (`red-at04-uxc10.txt`) |
| the census positive control | a sample module holding the restored delete-and-recopy | the identical probe reports exactly 2 violations inside `test_tc_b99_13_no_final_name_replace_outside_placement` (runs on every tree, GREEN run included) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the WRITE-OUT file (emitted by `save_patched_image`, corrupted by the hook) | `verify_written_image` re-reads the emitted file and `diff_mem_maps` classifies the flipped byte; the painted cause is asserted verbatim as `first difference at 0x{addr:06X}` against the address `flip_one_data_byte` returned | the corrupted arm's last diagnostic equals `first difference at 0x001000` (the flipped record's address), re-read by the engine's own verify, not the test's expectation (`green-tc15-16-census.txt`) |
| the gathered artifact (emitted by the converted `_gather_copy`) | re-read from disk after each gather: drift → `patches/hotfix_1.json` holds v2 while `patches/hotfix.json` still holds v1 (the independent byte compare) | `test_tc_b99_13_gather_drift_places_next_free_name` passed (`green-tc15-16-census.txt`) |
| the painted refusal line (emitted by `render_run` → `#fx_log`) | the AT reads `app.query_one("#fx_log", Static).render().plain` and asserts the emitted line leads with `Chain set not run`, names both lanes and the file | `test_at_b99_04_duplicate_names_refused_nothing_written` passed (`green-at04-dup.txt`) |
| every image byte comparison | `tests/support/independent_reader.py` (`_data` helper) | TC-B99-16's intact arm and AT-B99-04's arms re-read written images with the independent reader only |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 4 artifacts, each asserted against the form its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-3b/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline TC-B99-15/16 | `red-tc15-16.txt` | `c40ef15ba9af8cf9bfe943d8e5dbb68e51d95549c2b6427cbf3cd7e706f2e7ac` |
| RED baseline census + gather | `red-census-gather.txt` | `7fb985f71cb620bb2da73d55a12571059efd295c86828fb5123af9e853f0ddb7` |
| RED baseline AT + UX-C10 | `red-at04-uxc10.txt` | `5ffd6243009e3ca6de8074c8b06bbf7cc35b01fa48e7d4e432623aab7f05d0e3` |
| GREEN TC-B99-15/16 + TC-B99-13 arms + UX-C10 (7 passed) | `green-tc15-16-census.txt` | `41bc27c68c67093313cb2d72bb0221a4559ef5406cc3717a154620b4e81111e5` |
| GREEN AT-B99-04 duplicate arm | `green-at04-dup.txt` | `18f0f9ca631da8f751daee09281d3f693683c10f6fe697de9bc1813bcda51e9b` |
| GREEN full staging + address census (54 passed) | `green-full-staging.txt` | `59dc5a61cf434af7142f6443e75aeea5ef6deddb8545e3f1029bb33ea07df70e` |
| Mutation LLR-155.5 (KILLED) | `mut-LLR-155.5.txt` | `9a37aea0f9d64d1ec8abf31e5a845c09099e66201e7becf391dc7580cd0f621c` |
| Mutation LLR-155.6 (KILLED) | `mut-LLR-155.6.txt` | `9fe9960a5ab4f415cc5df04b3ca7b1371fe7ede460e0585af188cc8c501a33f8` |
| Mutation LLR-155.3 (KILLED) | `mut-LLR-155.3.txt` | `cf6474f6c2f394888afdfb4302846d8526f6bfe081af960f0fa48786a29b395d` |
| Pre-mutation hashes (baseline tree) | `baseline-hashes.txt` | `a8d48a1ea955f57bed44a48ffe22275f1586e9fecd321952b6ea0d55c4d4b3c8` |
| Reverse census probe | `reverse-census.txt` | `eeb520a876ae33783bc8415e44e87d959a1a10012c6236c9bf14b18687c7f09b` |
| Census batch 1 (discovery run: 9 re-pins found, 57 other nodes passed) | `green-census-flows.txt` | `e89fbab33f6d8d8c6f5bf54a90f7abf6b1f62ce800de165f5e6f8d3e7ec0252d` |
| Census batch 1 re-run after the re-pins (34 passed) | `green-repin.txt` | `60ad208a45461a4395b297058a9cfc638c64df7e63b3dfd32c0d5dfd2a14ece8` |
| Census batch 2: b97/verify/gather files (discovery run: 31 THREE-set nodes flagged, 184 other nodes passed) | `green-census-b97.txt` | `3024393a6e73d3735c65abee28e9a100c9b7b5acc9a9170bef8eacb138a6e438` |
| Census batch 2 re-pin spot checks (11 passed then 8 passed) | `green-repin-b97-spot.txt` · `green-repin-b97-spot2.txt` | `819addf77f64c9b69b5d95a6582ffe6dafb4949248cc733c4c384a02dcd3168b` · `819addf77f64c9b69b5d95a6582ffe6dafb4949248cc733c4c384a02dcd3168b` |
| Census batch 2 full re-run (153 passed + 1 load-flaky dwell-timing node, see below) | `green-repin-b97-full.txt` | `e85c2713f7d10f9626edfb371fd878b02e8ef3952488379b5635677e8753db9d` |
| The flaky node's isolated re-run (1 passed) | `green-repin-b97-burst.txt` | `bf872aa7f69c36d06538a612d0b385d960a1f8a8d16906c04b0a2d54cec36f5d` |
| Census batch 3 (**FULL run, not a timeout**: 5 failed, 500 passed in 2459.16s — description corrected in review round 1; the 5 failures classified against the baseline ledger in §6) | `green-census-batch3.txt` | `96acb69e8942a75d7d7354f78913b7bbe507e5379e06cdba7b5c38051a387a22` |
| Census batch 3 re-run: the remaining files (359 passed + 1 pre-existing base-RED, see §6) | `green-census-batch3-rest.txt` | `51eb6acdd6afafd6c5bbd5d6243a1921dc85a9cf27d69f8861da91c892c42016` |
| The pre-existing node's re-observation (deterministic base-RED, unchanged by this increment) | `green-batch3-at031b.txt` | `8481582be93451e6c16678734e2a692981113545e6f8f096d1371046f797caad` |
| Census batch 3 re-run: `test_b97_width.py` (145 passed) | `green-census-batch3-width.txt` | `79539abcbb10e8669bca6490e12b66de306807048209ec2847787dba233931b2` |
| GREEN final tree, the increment's nodes against the finished worktree (11 passed) | `green-final-nodes.txt` | `7be6abfacc3a1a922acdca6844ef098f13651fc3812ce19defa9fdaa430ea4af` |
| Review round 1 — pre-fix baseline hashes (the 4 files the round edits) | `baseline-hashes-fix.txt` | `8d687bc3cbb9d0c2ce824c0dc6a235c64f984742898a2448edbb60af275c3faf` |
| Review round 1 — RED: the F1 drift re-save arm against the unfixed `_gather_copy` | `red-f1-gather-reuse.txt` | `2f36769d6b62293930fee11093b713417ebde4da1c669250e6765a7dbc302fdc` |
| Review round 1 — GREEN: the TC-B99-13 neighbourhood incl. the F1 arm (6 passed) | `green-f1-gather-reuse.txt` | `6a622bb1c228a9948b103d90f6f418c6b037dd9f8a3b83362c32c6ce892af664` |
| Review round 1 — mutation LLR-138.4 (sibling scan disabled, KILLED; drift control GREEN) | `mut-LLR-138.4.txt` | `2257c5cf1e24afe2c2362d5f78c9eddbcd82c47d7d3965a833d6fa57145ce389` |
| Review round 1 — post-revert restore proof (`project_gather_service.py` → `8e4f018c…`) | `post-f1-hash.txt` | `699c811dd15fd4010b4eac4b4f3102bc63613d0b09ca489aa5179c3b988c6888` |
| Review round 1 — RED: the F2 status-line assertion against unfixed `app.py` | `red-f2-at04-status.txt` | `78f63dc9d42787103c62b1916b838ffef57a44b1ebbfaa1b235a5e2201b261c5` |
| Review round 1 — GREEN: AT-B99-04 (extended) + distinct-names guard + UX-C10 (3 passed) | `green-f2-at04-status.txt` | `2ccf515e9e9b4215b64cf752246e4f6352472f9ce419eb332fe5246eb53135e2` |
| Review round 1 — RED probe: the F4a `write_text` census limb vs the pre-F4a dispositions (7 sites) | `red-f4a-census.txt` | `c95099203318b5c98839ced22a3737bcf754d7100db1d37967807a9c02c5f2de` |
| Review round 1 — GREEN: the census arm (extended) + both gather arms (3 passed) | `green-f4a-census.txt` | `6237cdc6a4b90a34ebd06641ede6055ab4ac997c936c5fb485cc990946de99f0` |
| Review round 1 — GREEN: the UX-C10 D7 painted-text rewrite through the pilot (1 passed) | `green-f4b-uxc10.txt` | `5c1214166dc09f67219629c42ebcb9cdfc1224f56f69275f2a13c7ab4714bb75` |
| Review round 1 — GREEN: AT-B99-04 ×8 stability runs (8 passed) | `green-at04-x8.txt` | `e2e66923956442409cc9d11b2622b33d557fabc26b836105de728c08b6386505` |
| Review round 1 — GREEN: staging + address census + id registry (68 passed) | `green-fix-staging-census-registry.txt` | `37337a137db6e8a8e3ed36af96b2ff5a8aeb66b0f5b7af7fc25036685ca1793c` |
| Review round 1 — GREEN: project gather + chainset b94 (23 passed, F4c comment) | `green-fix-gather-chainset.txt` | `259df932368bd40162e16e52462c4bb6df236c446e3912e792167736be071676` |
| Review round 1 — GREEN: b97 flow execution green; b94 TUI flow execution 85 passed + 1 long-run flake (`test_tc_b94_27_lane_binding_isolation_and_noop` — pilot timing, NOT in the baseline ledger, isolated re-run green, see the row below) | `green-fix-b94-b97.txt` | `fd20fc810cca9a4cb5ed6493a82ef0dcb0227ae6ccd19451e21fd071e4bb851f` |
| Review round 1 — the flaky node's isolated file re-run (11 passed) | `green-fix-b94-rerun.txt` | `7c5472f7a374b99809ed4119aa4e8dec9a454abd4daa2cbd4bdbcceca3b6f360` |

| Field | Value |
|---|---|
| **Evidence files** | 37 artifacts, each at the declared home and cited with the digest of its stored bytes (the two F3 mismatches corrected; every figure re-verified against disk in review round 1) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) `s19_app/` holding ZERO `unlink`/`os.replace`/`shutil.copy2`/`write_bytes`/`write_text` calls outside the pinned placement/writer functions and the two declared-exception functions (the `write_text` limb is review finding F4a); (2) `_gather_copy` holding none of the five primitives at all |
| If the result is an ABSENCE, what made the search wide enough | (1) the census parses EVERY `*.py` under `s19_app/` (`rglob`) and walks every `ast.Call` — receiver forms (`x.unlink`, `x.write_bytes`), `shutil.copy2`, `os.replace` — so a call added in any module, method or nested function surfaces; (2) the gather-specific re-run asserts the converted module's hits are empty by name |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc_b99_13_no_final_name_replace_outside_placement` — the census assertion is its own named test node, with the gather-emptiness assertion and the positive control inside it |
| Conjunctive criteria: one mutation per conjunct | the LLR-155.3 mutation (restored delete-and-recopy) is the synthetic instance of the absent case for BOTH the census and the drift arms; LLR-155.5/.6 mutations each disable one conjunct |
| Synthetic instance of the absent case | the restored delete-and-recopy mutant IS a final-name replace outside placement — it exists only as a transient mutation, reverted by hash (`mut-LLR-155.3.txt`) |
| **Positive control for every probe that returned an ABSENCE** | the in-test positive control feeds a sample module holding the restored delete-and-recopy through the IDENTICAL probe and asserts exactly 2 violations — the non-absent output of the identical probe, run on every tree |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "run_chain_set\|write_out\|verify_written_image\|CHAIN_RUN" tests/` | 19 hits (`reverse-census.txt`) — every consumer re-validated by running its file (3 background batches, all outcomes recorded in §4 evidence); see the re-pin ledger below |
| B2 file moved on disk | n/a — no pre-existing file moved | no readers lost |
| B3 byte-identical golden captures this source | `grep -rl "compose_chain_set_report\|_gather_copy" tests/goldens/ tests/__snapshots__/` | 0 hits — no golden pins these sources |
| B4 artifact produced here is consumed elsewhere | the census hits above; `_gather_copy`'s only caller is `gather_project_artifacts` (in-module), exercised by `tests/test_project_gather.py` | re-validated, see batches |
| A3 interface consumed by another module changed | `run_chain_set`'s return shape is UNCHANGED (diagnostics-only refusal); `_gather_copy`'s `(copied, destination)` contract unchanged; WRITE-OUT `BlockResult` keeps its ok-shape on success | the 19-file census is the re-validation; no foreign assertion pins the refusal-free behaviour except the re-pins below |

Re-pin ledger (each: `test::node — old value → new value — requirement`):
- `tests/test_flow_chainset_b94.py::_clean_chain` + 5 nodes (`test_tc_b99_…` n/a — `test_tc_b94_05_mode_capture_in_run_record_and_report`, `test_tc_b94_05_parallel_dispatch_runs_chains_concurrently`, `test_tc_b94_28_run_consumes_each_chains_own_bindings`, `test_tc_b94_30_chain_set_report_provenance_lines`, `test_at_b94_24_service_half_reloaded_set_reruns`) — two fixture chains both writing `out.s19` (the set ran and clobbered — P-5's mechanism) → each fixture chain writes its own `out_<name>.s19`, and the reloaded-set test saves a second template `base_b` so the reloaded lanes still resolve one name per lane — HLR-155 D7/LLR-155.5 (the set is refused now; the tests pin lane semantics, not output-name clobbering).
- `tests/test_tui_flow_execution_b94.py` — 3 nodes (`test_at_b94_20_rebind_run_reads_each_chains_own_inputs`, `test_tc_b94_29_run_log_emission_and_all_clean_arm`, `test_at_b94_24_save_reload_rerun_regenerates_and_notices`) — the second lane imported the SAME template `base` twice (lanes `base`/`base_2` both writing `base_out.s19`) → a second template `base_b` differing only in the WRITE-OUT name is imported as the second lane (`base`/`base_b`), and the lane-name references (`base_2` → `base_b`) and the output globs follow — HLR-155 D7/LLR-155.5.
- `tests/test_project_gather.py::test_tc702_resave_refreshes_stale_copies` — a drifted re-save "refreshes the project copy in place (same name, new bytes), never duplicated", asserting `copy_count == 1` → the drifted copy is placed at the next free name and the placed copy is immutable, asserting `copy_count == 2`, `boost_1.json` holds the new bytes, `boost.json` keeps the old — LLR-155.3 as amended by LED-2026-10-25-batch-99.7 (the ledger-mandated behaviour change).
- `tests/b97_fixtures.py::err_chain_demo` + 31 nodes of `tests/test_b97_flow_execution.py` (every THREE-set test: `test_tc_b97_21…`, `test_tc_b97_23…`, `test_tc_b97_25…`, `test_tc_b97_52…`, `test_tc_b97_53_no_blank_row…`, `test_tc_b97_54…`, `test_tc_b97_55…`, `test_tc_b97_56…`, `test_tc_b97_63…`, `test_tc_b97_64…`, `test_at_b97_09…`, `test_at_b97_20…`, and the FX_THREE consumers) — the set `("patch_chain", "flash_chain", "err_chain")` had `patch_chain` AND `err_chain` both writing `fw_app_patched.s19` (P-5's exact defect) → `err_chain` writes its own `fw_err.s19` — HLR-155 D7/LLR-155.5.
- `tests/b97_fixtures.py::fx_project` + `tests/test_b97_flow_execution.py` — `TWO_WAIT = ("flash_chain", "flash_chain")` (two waiting lanes sharing `fw_app_flashed_copy.s19`) → a twin template `flash_b` with its own WRITE-OUT name; `DEEP`'s duplicated `six_ok_a`/`six_ok_b` pair → distinct twins `six_ok_c`/`six_ok_d` (own names, same blocks) — HLR-155 D7/LLR-155.5.
- `tests/test_b97_flow_execution.py::test_tc_b97_53_run_log_paints_at_most_eight_lines` — five lanes imported from ONE template (`("patch_chain",) * 5`, lane names `patch_chain_2…5`) → five `cap_*` templates differing only in the WRITE-OUT name (lane names `cap_0…4`); the 8-line cap, the fold line and the report-completeness assertions are unchanged in substance — HLR-155 D7/LLR-155.5.

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared — 19 B1 hits re-validated by execution (4 batches), B3 0 hits, A3 contract unchanged; **40+ re-pinned nodes across 6 files, each recorded above with its old → new value** (9 from batch 1, 31+ from batch 2's `err_chain` population; all re-runs green — `green-repin*.txt`) |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| delete-and-recopy of an existing final name inside the work area | every call of `unlink` / `os.replace` / `shutil.copy2` / `write_bytes` in `s19_app/` | `grep -n "os\.replace\|shutil\.copy2\|\.unlink(\|write_bytes(" s19_app/` — 19 raw hits, each mapped to its enclosing function | 1 correction site (`project_gather_service._gather_copy`) + 12 allow-listed writer functions (4 placement writers own the invariant; the fixed-name writers hold their own non-clobber/atomic schemes — the manifest's fixed `project.json` and the M-5 report names checked non-existing before the write; `write_bin_with_sidecar` converts with Inc 6, LLR-160.4) | `_gather_copy` (converted); census allow-list pinned in the test | the 12 allow-listed sites: out of scope by ledger (LLR-155.8/Inc 5 for the CRC writer, LLR-160/Inc 6 for the export writer, the manifest/report fixed-name schemes) |

| Field | Value |
|---|---|
| **Correction population** | 1 correction site + 16 allow-listed writer functions (12 first round + 4 in review round 1's `write_text` extension) + 2 declared exceptions, enumerated from the raw grep before any edit |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| `project_gather_service.py:290-299` delete-and-recopy (the LLR-155.3 amendment's named site) | `grep -n "unlink\|shutil.copy2" s19_app/tui/services/project_gather_service.py` → only docstring prose | yes — no live call survives; the census arm pins it | `project_gather_service.py` (post-edit); `green-tc15-16-census.txt` |

### Signed-balance test ledger

`post = base − deleted + added` → `31 = 23 − 0 + 8` ✓ reconciles for the
first round; review round 1 adds one node → `32 = 23 − 0 + 9` ✓ reconciles
(`tests/test_b99_staging.py`: 23 baseline nodes — 0 deleted, 8 added in the
first round: TC-B99-15 ×2, TC-B99-16 ×2, TC-B99-13 gather-drift + census
arms, the AT-B99-04 duplicate arm, the UX-C10 D7 lane-name node — plus the
F1 arm `test_tc_b99_13_unchanged_resave_after_drift_adds_no_duplicate`;
the AT-B99-04 duplicate arm, the census arm and the UX-C10 D7 node were
AMENDED in place, not added).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: BLOCK (F1 HIGH: after one drift every unchanged re-save added another `_<N>` — LLR-138.4 regression; F2 MEDIUM D7 refusal not on the status line; F3 MEDIUM evidence hashes; F4 LOW) · round 2: F1, F2, F4 closed; F3 (three new digests) recomputed by the orchestrator; the CRC designer `_save_template` moved from the census allow-list to the declared exceptions (a real in-place overwriter, routed to BACKLOG-CODE). The 40+ re-pins were audited and found intent-preserving (fixtures moved to distinct output names) |

---

## 5 · Risks

- The D7 refusal compares WRITE-OUT names case-folded but reports the
  first-seen spelling; a set with `same.s19`/`SAME.s19` is refused naming
  `same.s19`. Lane names that differ only by case are likewise one group.
- The refusal intentionally writes NO chain-set report (D7's "write
  nothing"); an operator who expected a report for a refused set finds the
  refusal only in the painted log. This matches the requirement text and
  the AT asserts it (`reports` absent).
- The WRITE-OUT verify re-reads through the app's own parsers
  (`verify_written_image`); a file that parses with dropped records is a
  mismatch (`only_a`), which is the D9 intent.
- The gather drift limb now accumulates `_<N>` files across re-saves with
  drifted sources (never reusing an existing name with different bytes);
  the manifest records the name actually placed each save. Projects that
  relied on the old overwrite-in-place refresh see `_<N>` siblings — the
  LED-.7 amendment's declared behaviour change.
- The census allow-list pins 12 writer functions; a future writer added
  outside the list fails the census until it is pinned or converted —
  intended friction, but it makes the allow-list a maintained contract.

## 6 · Pending items / spec deviations

- None blocking. The AT-B99-04 duplicate arm is this increment's RED arm;
  the distinct-name parallel arm (regression guard) and AT-B99-05 shipped
  with Inc 3a and re-run green here.
- One load-flaky node: `test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one`
  (a 0.6 s dwell-timing test) reported a double-confirm under the 16-minute
  full-file run (`green-repin-b97-full.txt`) and passed in isolation
  (`green-repin-b97-burst.txt`, 1 passed). Its own docstring names the
  dwell race; it is unrelated to D7/D9 (no source in its path changed).
- `tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber`
  fails deterministically on this tree too — it is a **pre-existing RED at
  the base commit**, documented by Inc 3a's packet (§6 there: "two
  serializations of the same document are byte-identical … the pre-existing
  B8 byte-identical reuse returns the same path; the behavior predates this
  increment … NOT fixed here"). No causal link to D7/D9; re-observed in
  `green-batch3-at031b.txt` and left for the orchestrator's backlog decision.
- ~~`app.py` was NOT edited~~ **CORRECTED in review round 1 (F2)**: the
  independent review found LLR-155.5's "status line" requirement unmet —
  the refusal painted only into the run log. `app.py` IS now edited (3/4
  SOURCE budget): `on_flow_execution_panel_run_requested` paints a refused
  set's outcome-first diagnostic on `#log_line_4` as well; AT-B99-04's
  duplicate arm asserts the painted status line. The confirm re-run handler
  drives one lane and needs no such paint (D7 cannot refuse a single lane).
- **Review round 1, F3 — batch-3 evidence corrected**: `green-census-b97.txt`
  and `green-census-batch3.txt` carried wrong digests (recomputed:
  `3024393a…`, `96acb69e…`; the other 21 verified unchanged), and batch 3
  was a **full run — 5 failed, 500 passed in 2459.16s**, not "timed out at
  ~85 %". The 5 failures, classified against the batch baseline ledger
  (main-checkout `PLAN.md`, full-suite baseline at `a293213`):
  `test_at031b_two_saves_are_distinct_no_clobber` is IN that baseline list
  (pre-existing deterministic base-RED, see the bullet above);
  `test_at_b97_16_in_session_resize_grows_and_returns` and the three
  `test_tui_patch_editor_v2.py` nodes (`test_paste_parse_then_apply_matches_file_loaded`,
  `test_save_back_prompt`, `test_at064c_edit_json_disabled_for_file_backed_document`)
  are NOT in the baseline and passed on the isolated re-runs already on
  disk (`green-census-batch3-width.txt` 145 passed; `green-census-batch3-rest.txt`
  359 passed + only the base-RED) — long-run load/ordering flakes, none in
  this increment's source paths.
- **Review round 1, F4a — two declared census exceptions (backlog, NOT
  fixed)**: `flow_persistence_service.save_flow_json` (:1032) and
  `save_chain_set` (:1506) — the extended `write_text` census flags both;
  they hold the house `exists()` + counter dedup (never an overwrite) but
  not the pinned HLR-155 placement. Conversion candidates for the backlog.

## 7 · Suggested next task

Batch-99 Increment 5 (HLR-159 / LLR-155.8, `write_crc_image`'s private
staging) — TC-B99-39's one known CRC census exception is its declared RED
site; this increment's census arm already pins the surrounding allow-list.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 SOURCE files (`git diff --stat` — 3 under `s19_app/`: `flow_execution_service.py`, `project_gather_service.py`, `app.py`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_staging.py` +8 nodes first round, +1 review-round node (see ledger) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — LLR-155.5/.6 are integration-layer; verified by TC-B99-15/16 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: 3 mutations, transcripts + restore digests; baseline RED `red-*.txt` |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, 19 B1 hits re-validated by execution |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — 2 SOURCE + 6 test + `.dev-flow/` artifacts |
| 8 | Frozen interfaces untouched | all | ✓ | `run_chain_set`/`_gather_copy` contracts unchanged; engine layer untouched |
| 9 | Coverage claims verified **on disk** | all | ✓ | census parses every `s19_app/**/*.py` from disk; AT asserts files on disk |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with in-test positive control |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: 3 mutations, all KILLED, inert arms named |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 1 site + 12 allow-list functions, pre-edit enumeration |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 4 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ⚠ | §4b `pending — orchestrator` |
| 16 | **Evidence files** declared | all | ✓ | §4: 23 artifacts, each with its stored-byte SHA-256 |
