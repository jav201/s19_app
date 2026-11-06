# Inc 9 E4 tester 1 (G-T1, service cases) - notes

Node file: `tests/test_b101_flow_saves.py`, 24 nodes (21 case nodes + R2-1 `/5` + 2 standing controls). No product file touched.
RED run: base `e07fb00f` (origin/main), LAN Linux host, detached worktree `s19_i9t1`, `s19_app.__file__` resolved inside the worktree. Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs tests/test_b101_flow_saves.py -n 6 --dist loadfile`. Transcript (redacted, one complete run): `.dev-flow/2026-11-01-batch-101/evidence/inc-9/red-01-tester1-base.txt`. Summary: **20 failed, 4 passed in 1.71s**. State: `executed` on base. GREEN on the integrated tree: `not-run` (implementers still editing). No `serial_timing` node.

## How the nodes read and drive
- Public calls only: `save_flow_json` / `save_chain_set` (I-2 forms, `workarea_root=` keyword), read back through `load_flow_json` / `load_chain_set` and the file bytes. Fixture `area`: R = `<tmp>/.s19tool/workarea`, W = `R/p` with `prg.s19`, O = `<tmp>/outside`.
- Links: `tests/b97_fixtures.make_junction` for folders (junction on Windows, symlink elsewhere), `os.symlink` for file links (Linux arm; the Windows file-link arm is `not_run` until E5, per the case table).
- The claim primitive is wrapped at `os.open` (I-7): a Create spy (records paths, calls through), an emulated Windows follow (creates `O/followed.json`, links the candidate to it, returns that descriptor), and a home swap (renames `flows/` aside, puts a symlink to O in its place, then calls through).
- Assertions are outcomes: raise, bytes on disk, directory listings, load findings. No call sequence beyond the two S-2 spies the cases require.

## Cases -> nodes, RED on base
| Case | Node | Base result and reason |
|---|---|---|
| R-FLOW-FILE.12/2 | `test_r_flow_file_12_2_clash_file_holds_its_stem` | RED: name `tune_a`, stem `tune_b_2` |
| R-FLOW-FILE.12/3 | `test_r_flow_file_12_3_cleaned_name_is_written` | RED: name `a` |
| R-FLOW-FILE.12/4 | `test_r_flow_file_12_4_stem_of_64_is_whole` | RED: name `a` |
| R-FLOW-FILE.13/1 | `test_r_flow_file_13_1_long_stem_is_cut_to_64` (+ control, below) | RED: name `a` |
| R-FLOW-FILE.13/2 | `test_r_flow_file_13_2_clash_suffix_is_cut` | RED: name `a` |
| R-FLOW-SET.9/1 | `test_r_flow_set_9_1_cleaned_name_is_written` | RED: `Nightly Set!` |
| R-FLOW-SET.9/2 | `test_r_flow_set_9_2_clash_file_holds_its_stem` | RED: `s` vs stem `s_2` |
| R-FLOW-SET.10/1 | `test_r_flow_set_10_1_long_stem_is_cut_to_64` | RED: 65 characters written |
| R-FLOW-FILE.11/1, /2, /3 | `test_r_flow_file_11_1_..`, `_11_2_..`, `_11_3_..` | RED: `TypeError` unexpected keyword `workarea_root` (the interface is absent on base; the saved-outside behaviour itself is not reached) |
| R-FLOW-SET.7/1, /2 | `test_r_flow_set_7_1_..`, `_7_2_..` | RED: same `TypeError` |
| R-FLOW-FILE.14/1 | `test_r_flow_file_14_1_dangling_link_gets_no_file` | RED: `O/dangling/z.json` created |
| R-FLOW-FILE.14/3 | `test_r_flow_file_14_3_no_create_on_a_taken_name` | RED: 0 `os.open` calls on the returned path (base uses `write_text`) |
| R-FLOW-FILE.14/4 | `test_r_flow_file_14_4_followed_create_gets_no_byte` | RED: no raise (base never calls `os.open`) |
| R-FLOW-FILE.14/5 (R2-1, new) | `test_r_flow_file_14_5_swapped_home_gets_no_byte` | RED: no raise |
| R-FLOW-SET.8/1 | `test_r_flow_set_8_1_dangling_link_gets_no_file` | RED: `O/dangling/s.json` created |
| R-FLOW-SET.8/3 | `test_r_flow_set_8_3_no_create_on_a_taken_name` | RED: 0 calls on the returned path |
| R-FLOW-SET.8/4 | `test_r_flow_set_8_4_followed_create_gets_no_byte` | RED: no raise |

## Standing guards (pass on base) and why each still has a failure mode
- `test_r_flow_file_14_2_link_to_file_is_not_written`, `test_r_flow_set_8_2_link_to_file_is_not_written`: base `exists()` follows the link to a file, so the dedup already skips it (case says "holds on base"). Fail if a save writes through the link or returns the link.
- `test_r_flow_file_13_1_control_whole_65_name_is_refused_by_loader`, `test_r_flow_set_10_1_control_whole_65_name_is_refused_by_loader` (extra, mine): show the loader refuses a 65-character name, so the `findings == []` assertions of the cut nodes can fail. Fail if the loader ever accepts it.
- The "0 calls on the taken name" half of /14/3 and /8/3 passes on base (no `os.open` at all); its failure mode is shown by the mutant below, not by base.

## Sensitivity check beyond the brief (not evidence of the product)
On the remote throwaway worktree only (since removed) I wrote a scratch reference of `_create_new_json` from graph I-7 and ran the 24 nodes: 24 pass. Mutants of that scratch reference: no post-claim check -> /14/4, /14/5, /8/4 RED; `exists()` instead of `lexists` -> /14/3, /8/3 RED; realpath clause dropped -> only /14/5 RED. This shows each node can fail for its defence; it is not the E5 mutant run on the real code.

## Findings for the integrator
1. **Design trap in the real-path clause.** I-7(d) reads `contained_in_workarea(Path(os.path.realpath(candidate)), resolved_home)`. `contained_in_workarea` re-resolves its second argument at call time (`workspace.py:637`, "inside `workarea.resolve()`"). After a home swap, `resolved_home` (`<W>/flows`, now a link) resolves to O, so the check passes and the bytes land outside. My scratch reference with exactly that call let `/14/5` fail (file written to O). The clause only holds if the comparison is against the already-resolved home as a plain path (e.g. `os.path.dirname(realpath(candidate)) == resolved_home`). `/14/5` is the node that catches it; expect it RED on a literal reading of I-7(d).
2. R-FLOW-FILE.11/x and R-FLOW-SET.7/x are RED on base by `TypeError` (absent keyword), not by the saved-outside behaviour; the outside-write behaviour is only observable once the keyword exists. Their listing assertions still fail without the guard on the fixed tree.
3. `/14/5` is an addition (R2-1), name chosen here; the case table should list it. The `run_chain_set` / I-1 service case is not in G-T1's rows (R-FLOW-CHAIN.19/20 are G-T2), so no service node for it.
4. File-link arms use `os.symlink` (Linux); the Windows dangling-junction arms stay `not_run` until E5.
