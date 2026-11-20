# check-FA-RTFIX — trace gaps closed on the merge tree

Orchestrator Opus 5.5 (relevo-29). Edit-only Opus agent; scripted mechanical check (MD-11) on the reference Linux host (rtx), 1-min load 0.48–1.71; Opus intent review.

## Diff
`diffs/FA-RTFIX.diff` (md5 d8ed8b43) on 78f61c42: 4 files, +87/−8, 0 CR, needle scan 0.
- `E4R/02-test-cases.md`: a `## Cases` section, 48 case lines over 44 nodes (.049, .050/1–18, .051/1–9, .052, .053, .054, R-A2L-DEF.166–.168, R-TST-011/019/026); parametrize ids keep their numbers.
- `E4R/01-requirements.md`: slice rows `s19_app/core.py` (FA-TICK2u), `validation/engine.py` and `tui/app/issues_checks.py` (FA-TICK3u), `tui/services/a2l_service.py` (FA-TICKb), all → R-A2L-REFRESH.050.
- `tests/test_alp_s19_read_once.py`: `test_llr_154_1_s19_reader_line_semantics_unchanged` → `test_r_read_002_s19_reader_line_semantics_unchanged`; docstring cites the six active rows (all exist; R-READ-002 only partly: no bare LF in the input, stated).
- `tests/test_alp_inc2_a2l_attach.py`: AT-ALP-I2-1 cites .031/.035 (recorded, not asserted — stated), AT-ALP-I2-3 cites .037; the two HLR-176 comments now read "(the refresh is a held step, CTX-BUSY)": HLR-176's S0.2 successors do not state the unasserted gap, and R-PROGRESS-LINE.3 (FA-RT's guess) succeeds HLR-176a/HLR-177, not HLR-176.

## Mechanical check
| Step | Result |
|---|---|
| trace_check, base 6eccf0cb (orchestrator re-run on the PC, static) | 1 gap: EVID (no `04-validation.md`); CASE 0, SLICE 0 |
| `--collect-only` of the two files, base vs patched | 48 = 48; the only difference is the renamed node |
| Touched nodes, `-n 0` | 4 passed |
| Six laws, `-n 0` | 115 passed, 2 skipped, 1 failed = the inherited `test_no_private_tokens` (same set as the merge tip) |
| Law 070_2 offender lines | 0 |

## Open (close backlog)
- `test_alp_inc3_load_responsiveness.py::test_r_a2l_refresh_050_case06_producer_return_gap` docstring says ≤ 50 ms; the code asserts `timing_bound(0.075)`.
- R-A2L-REFRESH.049's fit criterion says both keys arrive before the capture; the `[request-snapshot]` arm sends `shift+tab` after it.
- The renamed node also covers R-READ-001.2 (not cited).
- Existing slice rows miss rows: `a2l_definition.py` lacks .050; `file_load.py`/`project_load.py` lack .049/.050.
- trace_check's SLICE accepts a bare basename (`core.py` covers any changed `core.py`): a skill weakness, to report outside this batch.

## Verdict
MECH-GO. Opus intent: GO — the records now trace every Front A file and case; the rename and re-cites follow TR-01/TR-02 (no test retired).
