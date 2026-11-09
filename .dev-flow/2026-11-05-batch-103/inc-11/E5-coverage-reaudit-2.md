# Inc 11 E5 independent static coverage re-audit 2: STATIC PASS; VERIFIED PENDING

## Verdict

**Static coverage of the 37 previously partial IDs is now complete: 37 full, 0 partial, 0 gap, and 0 false-premise.** Lane A closes all 35 of its claimed IDs statically; lane B closes both of its claimed IDs statically.

`full` below means that the required fixture, assertion, and consumer route are present on disk. It does **not** mean runtime-verified. This focused update re-reviewed only the three corrections for READ.60/4, READ.60/8, and READ.61/9; the other 34 dispositions are carried forward. No tests or probes were run on Windows, no product/test/matrix files were edited, no result cell was changed, and no commit was made. The only file written by this review is this report.

The three former static partials are closed. P18 remains outside this scope. READ.52 remains RED and is not counted among the 37 IDs or declared closed. The 37-ID static pass is therefore not an E5-wide `verified` claim.

## Resolution of the three former static blockers

### READ.60/4 — closed statically

The agreeing `ECU_ADDRESS 0x10` pair now retains address 0x10 and asserts the exact required diagnostic `Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X` (`tests/test_b103_a2l_reader_coverage.py:1041-1045`). The agreeing header-address and BIT_MASK arms remain present, including the BIT_MASK duplicate diagnostic (`:1046-1052`). This closes the only residual identified in the preceding review.

### READ.60/8 — closed statically

Both consumer fixtures now contain the eight forms required by `02-test-cases.md:211`: the round-2 ECU_ADDRESS and BIT_MASK surplus forms, same-line `3E00`, split-line `3E00`, `E00`, `2D3E00`, `_4026`, and `BIT_MASK 0x0F F0` (`tests/test_b103_a2l_reader_coverage.py:1390-1399`, `:2109-2118`). The former duplicate `_4026` and substitute `0x1C2D 2D3E00` forms are gone.

The backend loops over all eight names and requires `entry is None` plus `CHG-SYMBOL-UNRESOLVED` (`:1400-1404`), while SIG_X remains the positive control (`:1405-1407`). The real Patch route attaches the same eight-form A2L, reads `#patch_param_table`, rejects every `X0`…`X7`, and requires SIG_X (`:2124-2138`). The route is not mocked.

### READ.61/9 — closed statically

The backend now parses all four no-length shapes as `X0`…`X3` and requires each `resolve_symbol_entry` call to refuse the entry with `CHG-SYMBOL-UNRESOLVED` (`tests/test_b103_a2l_reader_coverage.py:1366-1381`). The direct enrichment arms continue to require `byte_size`, `raw_value`, and `physical_value` as `None` for all four shapes (`:1348-1363`).

The real-route helper now preserves each row's name and format, and `expected` is exactly `{X0: "u8", X1: "u8", X2: "u8", X3: "u8"}` (`:2161-2167`). Both the real Patch table and real Check Editor table are compared for exact dictionary equality (`:2174-2184`). This proves 4/4 names and formats in each route, with no missing, extra, blank, `u16`, or otherwise substituted row allowed by the oracle.

## Per-ID disposition

| ID | Verdict | Static evidence / residual |
|---|---|---|
| R-A2L-READ.55/2 | full | Binary refusal is exact and both sections and tags are empty (`tests/test_b103_a2l_reader_coverage.py:269-277`). |
| R-A2L-READ.55/3 | full | NUL-after-address refusal is exact and both collections are empty (`:279-281`). |
| R-A2L-READ.55/4 | full | NUL-in-comment refusal is exact and both collections are empty (`:283-285`). |
| R-A2L-READ.56/1 | full | The 101-error reading preserves all 100 entries from the 100-error reading and appends only the exact marker (`:1817-1823`). |
| R-A2L-READ.56/2 | full | Every first-100 entry is a U+00E9 unexpected-character error; count and `… 399900 more parse errors` are exact (`:1827-1831`). |
| R-A2L-READ.56/3 | full | Parser, rendered summary, and issue model are capped (`:1833-1841`); a real app loads an image and A2L, then inspects Workspace `#a2l_view` and Issues `#validation_issues_groups` for at most 101 errors (`:2030-2087`). Loading the image is necessary because internal A2L issues are added on the primary-file validation route (`s19_app/tui/services/validation_service.py:303-335`). |
| R-A2L-READ.66/3 | full | Exact `Line 23: /end <U+FFFD>X does not close /begin MEASUREMENT` is asserted (`tests/test_b103_a2l_reader_coverage.py:1897-1902`). |
| R-A2L-READ.9/2 | full | Only the comment terminator is replaced with the parametrized CRLF/CR; there is no subsequent LF replacement and therefore no CR-CR-LF (`:288-296`). |
| R-A2L-001.3.2/4 | full | The fixture is exactly the standalone three lines `"a\`, `"`, `/end X`; exact Line-3 stray-end text is asserted (`:404-410`). The error also proves that the string closed before line 3. |
| R-A2L-READ.14/1 | full | The complete multiline string is present as one section word, separate `a`/`b`/`c` words are absent, and later BIT_MASK is preserved (`:445-465`). |
| R-A2L-001.1/3 | full | Address and zero errors are asserted, and `end_line` equals the actual inline `/end MEASUREMENT` line (`:504-511`). |
| R-A2L-READ.19/2 | full | `/endX` remains an own word and `end_line` equals X's own `/end` line (`:540-548`). |
| R-A2L-001.4/1 | full | `/end X` on line 30 yields the exact Line-30 diagnostic (`:551-557`). |
| R-A2L-001.4/2 | full | `junk /end X` on line 30 yields the exact Line-30 diagnostic (`:554-557`). |
| R-A2L-001.5/1 | full | Exact Line-23 `/end IF_DATA` mismatch is asserted (`:560-564`). |
| R-A2L-001.5/2 | full | Exact Line-23 reverse `/end MEASUREMENT` mismatch is asserted (`:565-567`). |
| R-A2L-READ.64/1 | full | The 33-level multiline form has exactly the cap error and zero sections/tags (`:592-594`). |
| R-A2L-READ.64/2 | full | The one-line form has exactly the Line-1 cap error and zero sections (`:595-597`). |
| R-A2L-READ.65/5 | full | The 10,000,000-`a` string with escaped-quote pairs is parsed and rendered; the complete string is one section word and 1,000-`a` fragments are rejected (`:635-645`). |
| R-A2L-READ.65/6 | full | The fixture builds both 4.8-million-word forms, including one body line (`tests/test_b103_a2l_reader_perf.py:88-112`, `:115-124`); both are parsed **and rendered**, with the exact surplus error and no address (`:271-282`). |
| R-A2L-READ.27/1 | full | All 12 case-07 tags have hand-written exact addresses, lengths, limits, and units (`tests/test_b103_a2l_reader_coverage.py:684-708`), matching `examples/case_07_stress_smoke/firmware.a2l:10-103`. |
| R-A2L-READ.32/2 | full | BYTE_ORDER is on lines 22 and 23; exact second-keyword Line-23 error and no address are asserted (`tests/test_b103_a2l_reader_coverage.py:798-801`). |
| R-A2L-READ.58/3 | full | Exact Line-22 zero-argument and Line-23 four-argument MATRIX_DIM diagnostics are asserted (`:827-835`). |
| R-A2L-READ.58/5 | full | Round-2 ECU_ADDRESS/LENGTH/BIT_MASK surplus diagnostics are exact on Line 22 (`:838-848`); all round-3 forms, the split keyword line, and SIG_X are covered (`:851-871`). The standalone Line-22 keyword fixtures agree with `01-requirements.md:204` and `codewire/graph-inc11.md:444-446`; the matrix's preceding-address wording is not used to invent a new blocker. |
| R-A2L-READ.59/6 | full | All four exact Line-20 size errors are asserted, and both two-LENGTH forms also assert the duplicate error (`tests/test_b103_a2l_reader_coverage.py:928-949`). |
| R-A2L-READ.60/2 | full | Missing ECU_ADDRESS argument gives no address while exact BIT_MASK `0x0FF0` survives (`:1033-1035`). |
| R-A2L-READ.60/4 | full | All three agreeing addresses are retained; the exact Line-23 agreeing-ECU_ADDRESS duplicate diagnostic and the BIT_MASK duplicate diagnostic are asserted (`:1041-1052`). |
| R-A2L-READ.60/6 | full | Both no-address shapes emit their exact Line-23 missing-argument errors (`:1036-1040`). |
| R-A2L-READ.39/1 | full | All four out-of-bounds messages are exact on Line 20 (`:1264-1271`). |
| R-A2L-READ.61/1 | full | The previously omitted undeclared-layout VAL_BLK now asserts length `None` (`:906-912`), supplementing the six existing disagreement arms. |
| R-A2L-READ.50/1 | full | The complete required XH section line, including quotes, comment removal, values, and line span, is asserted (`:1744-1755`). |
| R-A2L-READ.65/4 | full | The mutation loop catches only permitted `OSError`, fails on any other exception, and asserts `executed == 160 * 1000` (`:1707-1736`). This is a real executed-mutant oracle, not merely loop construction. |
| R-A2L-READ.48/1 | full | The real tracked-file parse/REF comparison loop is timed and asserts `elapsed <= 120` (`tests/test_b103_a2l_reader.py:1635-1648`). The bound is present statically; its runtime result is pending. |
| R-A2L-READ.49/2 | full | D5b declares and references `RL.FNC.SWORD.ROW_DIR`, with `FNC_VALUES 1 SWORD ROW_DIR DIRECT`, `MATRIX_DIM 3 4 1`, and exact length 24 (`:1780-1787`). |
| R-A2L-READ.60/8 | full | Both backend and real-picker fixtures contain the exact eight required forms (`tests/test_b103_a2l_reader_coverage.py:1390-1399`, `:2109-2118`); all eight backend entries are refused and absent from the real picker, with SIG_X as positive control (`:1400-1407`, `:2124-2138`). |
| R-A2L-READ.60/9 | full | Own/layout/inherited invalid sources all lose the address; the holding case uses the same invalid MOD_COMMON but a valid own BYTE_ORDER and keeps 0x10/little (`:1071-1096`). |
| R-A2L-READ.61/9 | full | All four backend symbols are refused (`:1366-1381`), direct enrichment remains 4/4 (`:1348-1363`), and both real tables equal the exact `{X0: u8, X1: u8, X2: u8, X3: u8}` map (`:2161-2184`). |

**Totals: 37 full, 0 partial, 0 gap, 0 false-premise (37/37 accounted).**

## P17 check (outside the 37-ID totals)

P17 now has static coverage for both negative conversion branches in the public enrichment route:

- raw 2 is a **missing entry**: `physical_value is None` and `conversion_status == "error"` (`tests/test_b103_a2l_reader_coverage.py:1978-1981`);
- changing `compu_tab_ref` to `MISSING` is a **missing table**, with the same refusal assertions (`:1983-1986`).

The happy path still resolves raw 1 to `on` (`:1964-1976`). Product code returns `lookup table missing` for an absent table and `raw value not in verbal table` for an unmatched exact raw key, without identity fallback (`s19_app/tui/a2l.py:2729-2736`). This supports P17 statically; it is not new Linux runtime evidence.

## Explicit blockers to `verified`

1. **Linux execution is pending for all 37 IDs.** Lane A reports only `py_compile` and no pytest (`evidence-e5/deepseek-coverage-a-report.md:62-74`); lane B reports the same (`evidence-e5/deepseek-coverage-b-report.md:68-77`). Older green transcripts predate these new assertions and UI routes. Run the changed reader, coverage, and performance nodes on the mandated Linux runner before any `verified` claim.
2. **The slow mutant oracle needs an explicit run.** `test_cov_read_65_hostile_corpus_mutations` is marked `slow` (`tests/test_b103_a2l_reader_coverage.py:1707-1708`). Lane A's suggested `-m "not slow and not serial_timing"` command (`evidence-e5/deepseek-coverage-a-report.md:84-90`) would deselect it and therefore cannot establish the 160,000-mutant runtime result.
3. **READ.52 remains RED.** The supplied performance transcript still fails case_06 time: 12.714064 s against a 10.579511 s bound, with family exit 1 (`evidence-e5/coverage-perf.txt:18-24`, `:34-37`). The added render/one-body-line coverage for READ.65/6 does not repair that separate failure. Do not mark READ.52/1, /2, or /3 verified from this review.
4. **P18 remains outside this re-audit and unresolved.** Its DATA_SIZE/full-span correction still awaits the ruled RED/product-oracle work (`E5-rulings.md:26`). Nothing here closes P18.

No matrix cell was updated. All 37 `full` verdicts are static-coverage judgments only, not authorization to mark result cells `verified` without the scoped Linux transcripts.
