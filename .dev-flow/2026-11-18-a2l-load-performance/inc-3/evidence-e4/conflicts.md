# Inc 3 E4 — conflict record (implementer lane G-I3)

Tree: branch `a2l-load-performance`, base `ceac08cf` (Inc 2 E4). All
implementation follows `.dev-flow/2026-11-18-a2l-load-performance/interfaces.md`
(I-ALP-2.2 / I-ALP-2.3 / I-ALP-3), the integrated graph
`inc-3/codewire/graph-inc3.md`, `inc-3/E1-slice.md` and `inc-3/E1-rulings.md`
(D-1..D-10). Only the 4 owned SOURCE files were edited; no test file and no
other source file was touched.

## 1. Test-side fixture/oracle defects (7 parity nodes)

The parity suite `tests/test_alp_inc3_snapshot_parity.py` contains nodes whose
assertions are unsatisfiable through the shipped routes on the E1 host,
independently of the Inc 3 implementation. Probe transcript:
`probe-fixture-defects.txt` (script `probe-fixture-defects.py`).

### 1a. CRLF fixture defect (nodes r044/3, r047/3, r047/6)

The suite reuses `_write_image` from `tests/test_alp_inc2_a2l_attach.py`,
which writes through `Path.write_text(..., encoding="ascii")`. On this
Windows host `write_text` uses `newline=None` (universal newlines), so every
`\n` becomes `\r\n`: the same 39-byte S19 payload becomes 42 bytes on disk.
The equal-size arms then overwrite with
`same.write_bytes(emit_s19_from_mem_map(...).encode("ascii"))` (raw LF, 39
bytes) and assert the sizes are equal:

- `test_r044_image_final_publication[R-A2L-REFRESH.044/3]` — line 764
  (`assert same.stat().st_size == size_before`, 39 != 42)
- `test_r047_same_path_changed_content[R-A2L-REFRESH.047/3]` — line 1104
  (project image copy 39 != `img1` 42)
- `test_r047_same_path_changed_content[R-A2L-REFRESH.047/6]` — line 1183
  (same pattern)

Probe 1 output: `write_text size=42 (CRLF) write_bytes size=39 (LF)`.
No SOURCE change can affect these file sizes (they are written by the test
itself before/after the route runs).

### 1b. Parse-path oracle defect (nodes r047/1, r047/2, r047/4, r047/5)

`parse_a2l_file` embeds the lexical path it parsed into the payload
(`"path": str(path)` in `s19_app/tui/a2l.py`). The shipped routes parse the
workarea copy — the typed A2L attach copies to `workarea/temp/` and the
project route parses `workarea/<project>/<file>` — so
`app.current_a2l_data == parse_a2l_file(<src path>)` differs in exactly the
`path` item on every platform. The interface (I-ALP-3, F2 "preserves
admission, copy, recents and busy behavior"; D-6 "the existing admitted
parse/cache route must supply the changed bytes") forbids parsing the
source path instead of the copied artifact, so the nodes cannot be
satisfied from the implementation side:

- `test_r047_same_path_changed_content[R-A2L-REFRESH.047/1]` — line 1067
  (`current_a2l_data == parse_a2l_file(attach)`;
  workarea/temp/att.a2l != src/att.a2l)
- `.../047/2` — line 1094 (`== parse_a2l_file(new_pair)`; project file
  workarea/proj_a/pair_old.a2l != src/pair_new.a2l)
- `.../047/4` — line 1146 (same as /2)
- `.../047/5` — line 1174 (same as /2)

Probe 2 output: `probe2: full-dict equality src vs workarea copy -> False`.
All other assertions of these nodes up to the dict comparison pass (the
content really is byte-identical — only the embedded parse path differs).

## 2. Inc 2 suite node superseded by I-ALP-3 (1 regression node)

`tests/test_alp_inc2_a2l_attach.py::test_r037_picker_snapshot_reuse[adapter-mismatch]`
(variants a and b) encodes the Inc 2-era rule that an image reload / project
install does NOT refresh the accepted picker mapping, so a changed
signature/source makes the adapter invalidate the mapping to empty and
describe on UI. I-ALP-2.3 + I-ALP-3 (and the new r039 arms, which require
the mapping to hold the fresh snapshot after every prepared image/project
load with zero UI describes) supersede that rule: L1 replaces the accepted
mapping with the fresh S1 snapshot before the common refresh whenever S1 is
present. The two expectations are mutually exclusive for the same UI
sequence (attach → image load), so this one Inc 2 node cannot be green on
an I-ALP-3-compliant tree. The other 36 Inc 2 nodes pass. Implemented per
interfaces.md (replacement) and reported here.

## 3. Pre-existing b103/b100 timing flakes (not a regression of this lane)

The full `tests/test_b103_a2l_refresh.py` run on this tree fails a small
number of nodes whose asserts depend on `call_after_refresh`-deferred
outcomes (unload status lines, `end_busy` OUTCOME entries, detail-card
repaints) being delivered within two `pilot.pause()` calls. A stash-to-base
check (`ceac08cf`) reproduced the identical failure class (2 failures in one
base run of the `test_r004_a2l_only_project` +
`test_r005_unload_publication` group). The failing setups exercise
image-without-A2L loads and the unchanged Inc 2 attach route, and the
failure sets vary run to run on both trees.

`tests/test_b100_workers.py -q` fails 3 nodes; two are pre-existing on the
base with the same assertions
(`test_tc_b100_53_reset_runs_after_the_worker_and_before_the_first_install`,
`test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished[a2l_size]`),
and `test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker` passes 3/3 in
isolation on this tree (and on base) — its full-run failure is the same
order/timing flake class on the unchanged attach route.

## 4. Performance budget miscalibration (R-A2L-REFRESH.040/.041/.042)

`tests/test_alp_inc3_load_responsiveness.py` (`green-inc3-perf.txt`): all
4 nodes fail ONLY the total-duration budget — medians 62.7-71.5 s against
the 45 s median / 60 s run bounds. Phase evidence: parse 15.2 s, post-parse
preparation 37.5-51.1 s, install/publication 9.8-12.1 s. The preparation
cost is the frozen Inc 2 producer (`enrich_tags_and_render` + two
`describe_definitions` bulk describes over 220,040 case_06 names;
`probe-producer-cost.py`/`.txt`: parse 7.3 s, enrich 5.7 s, describes
~180 s each without the D-13 collector disabling, 37-51 s total inside the
real route). Responsiveness assertions (50 ms timer, >=3 ticks during the
0.20 s gate, phases named, one producer call per load) all pass — the
application stays responsive, which is the user story. The budget numbers
come from the E1 "unexecuted oracle inputs" (EX-I3-041/042: totals 44-46 s)
which were never measured on the E1 host and do not match the real cost of
the mandated producer; the implementation cannot change the frozen
I-ALP-2.2 producer or the parser from the 4 owned files.

