# Inc 8 — E5 mutant table

Tree: commit e455a07 (branch b101-inc8), mutated only in a detached copy (removed afterwards). Interpreter: s19env Python; env `-u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<TMP>/la`, `--basetemp <TMP>/bt`, `timeout 900`. Each transcript prints `s19_app.__file__` (the copy). Per mutant, both whole test files were run (a superset of the nodes the cases name): `tests/test_b101_flow_ext_copy.py` (G2) and `tests/test_b101_crc_model_and_reasons.py` (G1). Control run on the unmutated copy: 82 passed (`evidence/inc-8/mut-00-base.txt`). After each mutant `git diff --quiet` was true (restored byte-exact). Transcripts are under `.dev-flow/2026-11-01-batch-101/evidence/inc-8/`; each ends with the mutation diff.

| Id | Requirement | Mutation | Tests that went RED | Result | Transcript |
|---|---|---|---|---|---|
| M01 | R-CRC-ENGINE-001.1, 002.2 | `crc.py` `crc32_stream`: seed register with reflected init when reverse | 001_1_1, 001_1_2, 001_1_5, 001_1_6, 001_1_7, 002_2_1, 002_2_2 (7) | KILLED | mut-M01.txt |
| M02 | R-CRC-DESIGNER-001.1 | `crc_kernel.py` `crc_stream` and `crc_lut`: reflect init when refin | designer_001_1 RIELLO, TMS37157; 002_2_1, 002_2_2 (4) | KILLED | mut-M02.txt |
| M03 | R-CRC-CONFIG-001.10 | `_required_field`: reason from bare key (`'reverse'`) | config_001_10 x8, flow_ext_12_6, flow_crc_4_missing_field (10) | KILLED | mut-M03.txt |
| M04 | R-CRC-CONFIG-001.11 | `_number_field`: pass parser's own message through | config_001_11 x6, 001_11_7, 001_11_8 (8) | KILLED | mut-M04.txt |
| M05 | R-CRC-CONFIG-001.11/7 [S-1] | remove the 64-character clip | config_001_11_7 (1) | KILLED | mut-M05.txt |
| M06 | R-CRC-CONFIG-001.16 | delete the Designer-template check | config_001_16 x3, 001_16_5 (dialog), flow_crc_4_designer_template (5) | KILLED | mut-M06.txt |
| M07 | R-CRC-CONFIG-001.17 [S-6] | drop `RecursionError` from the reader's caught faults | config_001_17_1, 001_17_2 (2) | KILLED | mut-M07.txt |
| M08 | R-FLOW-CRC.1 | CRC block skips `inject_crcs` | flow_ext_9_5, engine_001_1_7 (2) | KILLED | mut-M08.txt |
| M09 | R-FLOW-CRC.3 | change summary `config unresolved` text | flow_crc_3 (1) | KILLED | mut-M09.txt |
| M10 | R-FLOW-CRC.4 | delete the template check (same edit as M06) | flow_crc_4_designer_template (RED in the M06 run; `flow_crc_4_missing_field` stays green there by design, it is M03's) | KILLED | mut-M06.txt |
| M11 | R-FLOW-CRC.9 [S-5] | CRC block reads config with bare `path.read_text` (no cap) | flow_crc_9 (1) | KILLED | mut-M11.txt |
| M12 | R-FLOW-EXT.2 | read relative output against the working directory | flow_ext_2_2, 14_inside_accepted (2) | KILLED | mut-M12.txt |
| M13 | R-FLOW-EXT.9 | resolve later refs without the copy (rebind lookup off) | 26 tests (12_x, 9_x, 13, 11 names, ...) | KILLED | mut-M13.txt |
| M14 | R-FLOW-EXT.9/15 [S-4] | rebind lookup before the project-ref guard | flow_ext_9_15 (1; killed by the absolute-ref arm) | KILLED | mut-M14.txt |
| M15a | R-FLOW-EXT.10 | change records keep declared `block.change_doc_ref` | flow_ext_10_1, 10_2 (2) | KILLED | mut-M15a.txt |
| M15b | R-FLOW-EXT.10 | A2L refs keep the declared ref (own override and LOAD-inherited) | flow_ext_10_4, 10_5 (2) | KILLED | mut-M15b.txt |
| M16 | R-FLOW-EXT.12 | drop the read suffix | flow_ext_12_1..12_7, 12_9, 12_10, 10_5 (14) | KILLED | mut-M16.txt |
| M17 | R-FLOW-EXT.13 [S-2] | provenance keeps the pre-run resolved input | flow_ext_13 (1) | KILLED | mut-M17.txt |
| M18 | R-FLOW-EXT.14 [S-3] | `_climbs_above_project` always False | flow_ext_14 log, 14 output (2) | KILLED | mut-M18.txt |
| M19 | R-FLOW-EXT.11 | rotate: earlier copy renamed, new output placed under the plain name | flow_ext_11 bytes, 11 names, +21 more (23) | KILLED | mut-M19.txt |

## Score

killed / (killed + survived) = **20 / 20** (M10 shares the M06 run: same edit, different row). N/A: none.

## Survivors

None.

## Notes and limits

- Table source: the Negative-control column of `01-requirements.md`. E1/E3 rulings add no further mutants (S-1, S-4, S-6 are already rows); E4-integration-notes section 6 says E4 adds none.
- R-FLOW-EXT.2 /1 (relative log) is a positive control that holds on base (the table says "Yes for the log"), so no mutant targets it.
- M13 and M19 are broad: many tests die because later blocks fail outright, so their kill count says little about which assertion is sharpest. The sharper single-purpose kills are M14 (9_15), M17 (13), M09, M11, M05.
- M02 mutates both Designer engines (`crc_stream`, `crc_lut`); the catalogue tests that die are the two with a non-symmetric init (RIELLO, TMS37157), as the row predicts.
- Windows only; 9_15 (junction/link arm) ran, not skipped. No Linux run.
- Not run: the full suite (batch end).
