# Inc 9 — E5 mutant table (flow and chain-set saves: names, homes, claims)

Batch 2026-11-01-batch-101, increment 9. Executor: E5 unit (single-unit mutant run).
Base: origin/main `e07fb00f9fc13afd314d0334fac683fe33b29b6c` with the b101-inc9 head
`b204c7d44a42383f2a7c63295280b0a4b7f3ad58` applied onto it (the 11 files of
`git diff --binary e07fb00 -- s19_app tests docs README.md`; staged tree not needed —
the mutation diff is the `b/`-side of the copy).

All runs on the LAN Linux host only (operator rule; nothing importing `s19_app` ran on
the Windows PC). The baseline first ran the union of every row's nodes (34 unique nodes)
on the unmutated copy: **34 passed, 0 failed** — all GREEN before any mutation. Each mutant was
applied **one at a time** in a fresh copy of the base worktree (`<HOME>/work/s19_i9mut_m<N>`),
the mutation was verified to have landed (a non-unique edit site aborts the run), only the
row's nodes were run from the copy (`-p no:cacheprovider -q -rf`, cwd = the copy,
`s19_app.__file__` printed from inside the copy = the copy), and the copy was then deleted.
Transcripts: `evidence/inc-9/mut-01.txt` … `mut-21.txt` (each starts with the base commit,
the mutation diff and the redacted `s19_app.__file__`; home folder → `<HOME>`, account
name → `<USER>`, host address → "LAN Linux host 2", `pytest-of-<name>` → `pytest-of-<user>`).

Sources: the M1–M19 table in `E4-integration-notes.md` (Negative-control column of
`01-requirements.md` plus the E3 addenda, R2-1, E4-R1), plus M20 (E4-R3, the claim's
mode argument) and M21 (E4-R1 re-run: the real-path clause changed back to
`contained_in_workarea`, which re-resolves the approved home). Files: **S**
`tests/test_b101_flow_saves.py`, **U** `tests/test_b101_flow_names_ui.py`, **D**
`tests/test_b101_help_legend_docs.py`, **Q** `tests/test_b99_staging.py`.

| M | Row | Mutation (file · function) | Nodes | Result | Killing node(s) / failure line | Transcript |
|---|---|---|---|---|---|---|
| M1 | R-FLOW-CHAIN.20 | `app.py` confirm handler: `mode="sequential"` (base) | U `flow_chain_20_1_…`, `flow_chain_20_2_…`, `test_at_i9_1_…` | KILLED | `flow_chain_20_1`, `flow_chain_20_2`, `at_i9_1` — `E   AssertionError: report shows '- **Mode:** sequential' (expected 'confirm re-run')` | mut-01.txt |
| M2 | R-FLOW-CHAIN.20 (graph neg) | `flow_execution_service.py` `run_chain_set`: map `CHAIN_RUN_CONFIRM_RERUN` to `"sequential"` before `ChainSetRunRecord(mode=…)` | U `flow_chain_20_1_…`, `flow_chain_20_2_…`, `test_at_i9_1_…` | KILLED | `flow_chain_20_1`, `flow_chain_20_2`, `at_i9_1` — `E   AssertionError: report shows '- **Mode:** sequential' (expected 'confirm re-run')` | mut-02.txt |
| M3 | R-FLOW-CHAIN.19 (D-1 option A) | `flow_execution_service.py` `run_chain_set`: skip `write_chain_set_report` for the confirm token | U `flow_chain_19_1_…`, `flow_chain_20_*`, `test_at_i9_1_…`; `test_b97_flow_execution.py::test_tc_b97_55_…` | KILLED | `flow_chain_19_1`, `flow_chain_20_1`, `flow_chain_20_2`, `at_i9_1`, `tc_b97_55` — `E   AssertionError: did not settle: the confirm re-run wrote its report and Run is enabled again` | mut-03.txt |
| M4 | R-FLOW-FILE.12 | `flow_persistence_service.py` `save_flow_json` render: `flow_to_dict(flow)` (base payload) | S `flow_file_12_2_…`, `12_3_…`, `12_4_…`, `13_1_long_…`, `13_2_…`; U `flow_file_12_1_…`, `12_5_…`, `test_at_i9_2_…` | KILLED | `flow_file_12_2` (… `flow_file_13_2`, `flow_file_12_1`, `flow_file_12_5`, `at_i9_2`) — `E   AssertionError: assert 'tune_a' == 'tune_b_2'` | mut-04.txt |
| M5 | R-FLOW-FILE.13 | `flow_persistence_service.py` render: `name=stem` uncut | S `flow_file_13_1_long_stem_is_cut_to_64`, `13_2_clash_suffix_is_cut` | KILLED | `flow_file_13_1`, `flow_file_13_2` — `E   AssertionError: assert 'B'*65 == 'B'*64 (name not cut)` | mut-05.txt |
| M6 | R-FLOW-SET.9 | `flow_persistence_service.py` `save_chain_set` render: `chain_set_to_dict(chain_set)` (base) | S `flow_set_9_1_…`, `9_2_…`, `10_1_long_…`; U `test_at_i9_2_…` | KILLED | `flow_set_9_1`, `flow_set_9_2`, `flow_set_10_1`, `at_i9_2` — `E   AssertionError: assert 'Nightly Set!' == 'NightlySet'` | mut-06.txt |
| M7 | R-FLOW-SET.10 | `flow_persistence_service.py` render: `name=stem` uncut | S `flow_set_10_1_long_stem_is_cut_to_64`; U `test_at_i9_2_…` | KILLED | `flow_set_10_1`, `at_i9_2` — `E   AssertionError: assert 'D'*65 == 'D'*64 (set name not cut)` | mut-07.txt |
| M8 | R-FLOW-FILE.11 | `flow_persistence_service.py` `save_flow_json`: guard replaced by `resolved_home = flows_dir.resolve()` | S `flow_file_11_1_…`, `11_2_…`, `11_3_…`; U `fb_save_8_1_…`, `test_at_i9_3_…` | KILLED | `flow_file_11_1`, `flow_file_11_2`, `flow_file_11_3` (… `fb_save_8_1`, `at_i9_3`) — `E   Failed: DID NOT RAISE WorkareaContainmentError` | mut-08.txt |
| M9 | R-FLOW-SET.7 | `flow_persistence_service.py` `save_chain_set`: guard replaced by `resolved_home = flowsets_dir.resolve()` | S `flow_set_7_1_…`, `7_2_…`; U `fx_set_15_1_…`, `test_at_i9_3_…` | KILLED | `flow_set_7_1`, `flow_set_7_2` (… `fx_set_15_1`, `at_i9_3`) — `E   Failed: DID NOT RAISE WorkareaContainmentError` | mut-09.txt |
| M10 | R-FLOW-FILE.14/3, R-FLOW-SET.8/3 (E3 S-2 a) | `flow_persistence_service.py` `_create_new_json` (a): `candidate.exists()` for `os.path.lexists` | S `flow_file_14_3_…`, `flow_set_8_3_…` | KILLED | `flow_file_14_3`, `flow_set_8_3` — `E   AssertionError: assert 1 == 0 (os.open called on the taken name)` | mut-10.txt |
| M11 | R-FLOW-FILE.14/4, R-FLOW-SET.8/4 (E3 S-2 b) | `flow_persistence_service.py` `_create_new_json`: step (d) removed | S `flow_file_14_4_…`, `flow_set_8_4_…`, `flow_file_14_5_…` | KILLED | `flow_file_14_4`, `flow_set_8_4`, `flow_file_14_5` — `E   Failed: DID NOT RAISE WorkareaContainmentError` | mut-11.txt |
| M12 | R-FLOW-FILE.14/5 (R2-1, E4-R1) | `_create_new_json` (d): the real-parent clause dropped | S `flow_file_14_5_swapped_home_gets_no_byte` | KILLED | `flow_file_14_5` — `E   Failed: DID NOT RAISE <class 's19_app.tui.workspace.WorkareaContainmentError'>` | mut-12.txt |
| M13 | E4-R1 | `_create_new_json` (d): the graph's first form, `contained_in_workarea(Path(os.path.realpath(candidate)), resolved_home)` | S `flow_file_14_5_…` | KILLED | `flow_file_14_5` — `E   Failed: DID NOT RAISE <class 's19_app.tui.workspace.WorkareaContainmentError'>` | mut-13.txt |
| M14 | (d) regular-file / same-stat test | `_create_new_json` (d): `owned` without `stat.S_ISREG` and `samestat` | S `flow_file_14_4_…`, `flow_set_8_4_…`, `flow_file_14_5_…` (may survive) | KILLED | `flow_file_14_4`, `flow_set_8_4` — `E   AssertionError: assert False (the link swapped in at the free name was unlinked)`; `flow_file_14_5` GREEN (equivalent — owned is already True under the swap) | mut-14.txt |
| M15 | TC-B99-13 (E3A-09) | `save_flow_json`: back to `target.write_text(…)` | Q `test_tc_b99_13_no_final_name_replace_outside_placement`; S `flow_file_14_3_…` | KILLED | `tc_b99_13`, `flow_file_14_3` — `E   AssertionError: LLR-155.3: … write_text outside the pinned placement allow-list (in 'save_flow_json')` | mut-15.txt |
| M16 | R-FB-SAVE.8 | `app.py` `_do_save`: the `except` shows `Flow name is empty after sanitising - not saved.` | U `fb_save_8_1_…`, `test_at_i9_3_…` | KILLED | `fb_save_8_1`, `at_i9_3` — `E   AssertionError: did not settle: the refusal status is painted, or the file landed (base)` | mut-16.txt |
| M17 | R-FB-SAVE.8 | `app.py` `_do_save`: no `try` / `except` | U `fb_save_8_1_…`, `test_at_i9_3_…` | KILLED | `fb_save_8_1`, `at_i9_3` — `E   AssertionError: did not settle: the refusal status is painted, or the file landed (base)` (the `WorkareaContainmentError` escapes) | mut-17.txt |
| M18 | R-FX-SET.15 | `app.py` FX save handler: the `except` shows `Chain set not saved - the set is empty or the name sanitised away.` | U `fx_set_15_1_…`, `test_at_i9_3_…` | KILLED | `fx_set_15_1`, `at_i9_3` — `E   AssertionError: did not settle: the refusal status is painted, or the file landed (base)` | mut-18.txt |
| M19 | DOSSIER (E4-R2) | `DOSSIER.md` F-45: the ` · fixed in 1.0.0` mark removed | D `doc_guide_2_1_fixed_rows_marked`, `doc_guide_2_2_no_other_row_marked` | KILLED | `doc_guide_2_1`, `doc_guide_2_2` — `E   AssertionError: rows without the fixed mark: ['F-45']` | mut-19.txt |
| M20 | R-FLOW-FILE.14/6, R-FLOW-SET.8/5 (E4-R3) | `flow_persistence_service.py` `_create_new_json`: the claim's mode argument `0o666` deleted | S `flow_file_14_6_saved_file_mode_matches_write_text[flow]`, `[set]` | KILLED | `flow_file_14_6[flow]`, `flow_file_14_6[set]` — `E   AssertionError: assert '0o755' == '0o644'` | mut-20.txt |
| M21 | R-FLOW-FILE.14/5 (E4-R1, re-resolved home) | `_create_new_json` (d): the real-path clause → `contained_in_workarea(Path(os.path.realpath(candidate)), resolved_home)` (re-resolves the home; imported from `..workspace`) | S `flow_file_14_5_swapped_home_gets_no_byte` | KILLED | `flow_file_14_5` — `E   Failed: DID NOT RAISE <class 's19_app.tui.workspace.WorkareaContainmentError'>` | mut-21.txt |

## Score

- Total mutants run: **21** (no row skipped).
- Killed: **21**.
- Survived: **0**.
- Mutation score (killed / total): **21 / 21 = 100%** (no expected survivors; M14, the only
  row the table marked "may survive", was in fact killed — see below).

### Notes on the two rows the table flagged

- **M14** (the regular-file / same-stat term of `owned`, dropped). The table's caveat
  read "may survive: under the emulated follow the candidate's real path is `<O>/followed.json`,
  so the real-parent clause refuses it too". The refusal still fires (the reparse-point term
  and the real-parent clause both still refuse the swapped-in link), but the mutant is
  killed by the **unlink arm**: with `owned = True` the check's failure path unlinks the
  candidate even when it is not ours, so `flow_file_14_4` / `flow_set_8_4` fail their
  `(home / "z.json").is_symlink()` assertion (`assert False`) — the swapped-in link is gone
  after the refusal. `flow_file_14_5` stays GREEN (equivalent: under the home swap the
  created file is regular and same-stat, so `owned` was already `True`; dropping the two
  checks changes nothing on that case). The kill is honest: the "unlink only its own
  same-stat claim" fact is exactly what `_FINAL_NAME_ALLOWLIST` pins for `_create_new_json`.

- **M21** re-runs E4-R1 (the same clause mutation as M13) after E4-R3: with the
  `contained_in_workarea` form, the second argument (`resolved_home`) is re-resolved at
  call time through the link the home was swapped for, so the check passes and the payload
  lands outside — `flow_file_14_5` fails `DID NOT RAISE`, exactly as E4-R1 predicted.
  It is a second, post-E4-R3 confirmation of the same negative control, not a new row.

- **M15**'s two kills name both faces of the write_text revert: the TC-B99-13 census flags
  `write_text` outside the allow-list (the schema-level fact), and `flow_file_14_3`'s
  `os.open` spy sees zero claims (the behavioral fact — no exclusive create at all).

The render-before-claim and write-failure arms remain not-a-mutant (no requirement row, no
node: a coverage gap already ruled for the audit in `E4-integration-notes.md`), as do the
`ch18-flow-execution.md` sentence, the `flow_screens.py` docstring, and `_keep_previous_manifest`'s
default mode (backlog BL-I9-5).

## Re-map on the final tree (d6f1801)

The corrective (`3f8b9e9`) restructured `_create_new_json` — one candidate walk, every
check read inside one `try`, the cleanup through `_unlink_own_claim`, and the `st_nlink == 1`
clause — so the rows of M1 … M21 whose mutated code it changed (M11 … M14 and M21, all in the
old step (d)) no longer apply as written. They were re-expressed against the final code (same
intent) and re-run one at a time on the final tree, on the LAN Linux host 2 only, same rules
as the first run: base copy `~/work/s19_i9rm` at `origin/main` `e07fb00` with the local tree's
`git diff --binary e07fb00 -- s19_app tests docs README.md` applied (head `d6f1801`); the union
of the rows' nodes ran GREEN on the unmutated copy first (3 passed); each mutant in a `cp -a`
copy, the edit verified to have landed, only the row's nodes run, `s19_app.__file__` printed
from inside the copy. Transcripts: `evidence/inc-9/mut-r-11.txt` … `mut-r-21.txt`.

The other 16 rows (M1 … M10, M15 … M20) still apply unchanged — the corrective did not touch
their mutated lines — so their pre-corrective verdicts (all killed) stand on the final tree:
M1 … M3 are in `app.py`'s confirm handler and `flow_execution_service.py` `run_chain_set` (only
docstrings changed there); M4 … M9 are the `save_flow_json` / `save_chain_set` render and guard
lines (docstrings only); M10 is the `os.path.lexists` name check, whose line the one-walk change
(CR-08) left intact; M15 is the `write_text` revert in `save_flow_json` (the `_create_new_json`
call site is unchanged; only the TC-B99-13 allow-list moved, in the test); M16 … M18 are the
`app.py` `except` messages; M19 is `DOSSIER.md` F-45; M20 is the claim's `0o666` mode argument
(E4-R3's change, untouched by the corrective).

| M | old mutation | new mutation | nodes | result | transcript |
|---|---|---|---|---|---|
| M11 | `_create_new_json`: step (d) removed | the whole post-claim check block removed; the write-arm cleanup reverted to a direct best-effort `os.unlink` (its `claim` argument is gone with the check) | S `flow_file_14_4_…`, `flow_set_8_4_…`, `flow_file_14_5_…` | KILLED — all three `DID NOT RAISE WorkareaContainmentError` | mut-r-11.txt |
| M12 | `_create_new_json` (d): the real-parent clause dropped | `and Path(os.path.realpath(candidate)).parent == resolved_home` dropped from `verified` | S `flow_file_14_5_…` | KILLED — `DID NOT RAISE WorkareaContainmentError` | mut-r-12.txt |
| M13 | `_create_new_json` (d): the graph's first form `contained_in_workarea(Path(os.path.realpath(candidate)), resolved_home)` | the same clause re-expressed on the `verified` conjunction (+ `contained_in_workarea` import) | S `flow_file_14_5_…` | KILLED — `DID NOT RAISE WorkareaContainmentError` | mut-r-13.txt |
| M14 | `_create_new_json` (d): `owned` without `stat.S_ISREG` and `samestat` | `stat.S_ISREG(st.st_mode)` and `os.path.samestat(claim, st)` dropped from `verified` (`st_nlink == 1`, the reparse and the real-parent clauses kept) | S `flow_file_14_4_…`, `flow_set_8_4_…`, `flow_file_14_5_…` | SURVIVED (equivalent) — 3 passed | mut-r-14.txt |
| M21 | `_create_new_json` (d): the real-path clause → `contained_in_workarea(Path(os.path.realpath(candidate)), resolved_home)` (re-resolves the home) | identical to M13 on the final code | S `flow_file_14_5_…` | KILLED — `DID NOT RAISE WorkareaContainmentError` | mut-r-21.txt |

### Combined score with the corrective's M14b, M22–M31

- Re-mapped on the final tree (this table): **4 killed / 5** — M11, M12, M13, M21 killed; **M14 survived as an equivalent mutant** (below).
- Unchanged rows (M1 … M10, M15 … M20): **16 killed / 16** — verdicts carry over unchanged.
- Corrective battery (`e5c-02`, `e5c-03`): M14b, M22 … M31 — **11 killed / 11**.
- **Combined on the final tree: 31 killed / 32 mutants**; the one survivor is M14, equivalent.

### Why M14 now survives (was killed pre-corrective)

Pre-corrective, dropping `S_ISREG`/`samestat` made `owned := True`, so the refusal's unlink arm
deleted a swapped-in link by name and `flow_file_14_4` / `flow_set_8_4` failed their `is_symlink()`
assertion — an honest kill of the "unlink only your own same-stat claim" fact. On the final tree
the unlink goes through `_unlink_own_claim` (re-read + `samestat` + real parent), so a swapped-in
link is never removed by the mutant, and the check still refuses the row's nodes through its
other clauses: the reparse clause on `flow_file_14_4` / `flow_set_8_4` (the link at the name),
the real-parent clause on `flow_file_14_5` (the swapped home). The dropped clauses are not a
coverage gap — the same-file clause is pinned alone by /14/10 (M22), the one-link clause by
/14/11 (M23), and `S_ISREG` is subsumed by `samestat` (a non-regular entry cannot samestat-equal
the claim's regular-file descriptor). M14 is therefore an equivalent mutant on the final tree,
not a survivor that hides a bug.
