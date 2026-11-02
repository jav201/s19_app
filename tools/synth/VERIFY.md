# VERIFY — synthetic release demo case (case_08)

Run of `tools/synth/make_release_case.py --out examples/case_08_release_demo
--seed 20260001 --size-mb 10` (Python `s19env`). No `s19_app/` source was
edited; every load below goes through the app's own loaders/validators with
`PYTHONPATH=.` and a redirected `LOCALAPPDATA` (the real `%LOCALAPPDATA%\s19_app`
was never created).

## 1. Generated file sizes (full case)

| file | bytes | purpose |
|---|---|---|
| firmware.s19 | 10,618,548 | clean Motorola S19 image (4 regions + gaps) |
| firmware.hex | 10,221,439 | same image as Intel HEX (compare pair) |
| firmware_v2.s19 | 10,628,788 | v2 = clean + 512-byte window + 4,096-byte extension |
| firmware.a2l | 99,950 | clean ASAP2 (462 tags), every decoded COMPU_METHOD |
| firmware.mac | 4,754 | clean 200-line `NAME=0xADDR` subset |
| demo_patch.changes.json | 918 | 7-entry `kind=change` document |
| demo_check.chk.json | 472 | 3-entry `kind=check` document, all-PASS |
| demo_check_fails.chk.json | 479 | 3-entry `kind=check` document, all-FAIL |
| firmware_issues.a2l | 101,581 | clean A2L + 8 injected-fault tags |
| firmware_issues.mac | 4,991 | clean MAC + 9 injected-fault lines |
| README.txt | 2,042 | description + regeneration command |

`firmware.s19` is 10.13 MiB — within ±10% of 10 MiB. Image data is 4,247,392
bytes across 4 regions (boot / app / cal / config). The four firmware/hex/mac
and the clean A2L are **byte-identical** to the previous revision: only the two
change/check documents, README, and the three new files were added/changed.

## 2. Per-file issue counts through the app's loaders

Loaded with the same functions the TUI calls (`S19File`/`build_loaded_s19`,
`parse_a2l_file` + `enrich_a2l_tags_with_values` + `validate_a2l_tags` +
`validate_a2l_internal_issues`, `parse_mac_file`,
`parse_change_document`, `run_check_document`, `validate_artifact_consistency`).

| artifact | errors | warnings | notes |
|---|---|---|---|
| firmware.s19 | 0 | 0 | 13,262 records; checksums valid; no overlaps; ascending |
| firmware.hex | 0 | 0 | mem_map byte-identical to the S19 |
| firmware_v2.s19 | 0 | 0 | differs only in window + extension |
| firmware.a2l | 0 | 102 `A2L_UNRECOGNIZED_BLOCK` | 0 parse / 0 tag-level / 0 decode / 0 limits |
| firmware.mac | 0 | 0 | 200 records, 0 diagnostics |
| demo_patch.changes.json | 0 | 0 | 7 entries (bytes / string / bytes+symbol) |
| demo_check.chk.json | 0 | 0 | 3 checks, aggregate `passed=3` |
| demo_check_fails.chk.json | 0 | 0 | 3 checks, aggregate `failed=3` |
| firmware_issues.a2l | 1 | 5 + 102 | see §4 |
| firmware_issues.mac | 9 | 6 + 102 (cross run) | see §5 |

Clean A2L tag-level validation is fully clean: 462 tags (358 CHARACTERISTIC,
104 MEASUREMENT), 0 schema failures, 0 memory-check failures, 0 decode errors,
0 values outside limits. Every clean A2L address+span and every clean MAC
address lies inside the image; every clean MAC name matches an A2L object.

## 3. TAB_VERB / COMPU_VTAB (task point 1)

The app **does** decode table conversions, and the case exercises them:

- `extract_compu_tables` (s19_app/tui/a2l.py) reads both `COMPU_TAB` and
  `COMPU_VTAB`; for `COMPU_VTAB` it records the `TAB_VERB` keyword as the table
  `kind` (`tabs["TBL_NOINTP"]["section"] == "COMPU_VTAB"` and
  `tabs["TBL_NOINTP"]["kind"] == "TAB_VERB"`).
- There is **no** `TAB_VERB` *COMPU_METHOD* conversion type — the conversion
  keywords are `IDENTICAL / LINEAR / RAT_FUNC / TAB_INTP / TAB_NOINTP / FORM`.
  `TAB_VERB` is only the COMPU_VTAB content keyword.
- `CM_TAB_INTP` (`TAB_INTP` → `COMPU_TAB TBL_INTP`) and `CM_TAB_NOINTP`
  (`TAB_NOINTP` → `COMPU_VTAB TBL_NOINTP`, declared `TAB_VERB`) both exist, and
  the scalar cycling places 47+ objects on each, all valid and in-image.
  No new objects were required — the conversion round-robin already produces
  them; the test now asserts the extractor output directly.

## 4. Object census (task point 2)

Clean A2L array inventory (all in-image, all derived byte spans present):

| kind | count | requirement | axis/span |
|---|---|---|---|
| CURVE | 60 | ≥ 10 | `AXIS_DESCR STD_AXIS` (32 pts), `length` derived |
| MAP | 20 | ≥ 10 | two `AXIS_DESCR` (8×8), `length` derived |
| VAL_BLK | 60 | ≥ 5 | `LENGTH 256` |
| ASCII | 10 | ≥ 2 | `NUMBER 32` |

The app reads all four kinds; nothing was missing. Each CURVE/MAP carries a
non-empty `axis_meta` and a non-None `length`, so `validate_a2l_tags` reports
`in_memory=True` for every array tag.

## 5. Change / check documents (task point 3)

`demo_patch.changes.json` (7 entries, all in-image, all before≠after):

1. `bytes` @ cal base (XOR-derived) — calibration region change
2. `string` `"CAL_MODE=7"` @ erased config tail — config region change
3. `bytes` + `symbol` `VALUE_0185` (physical value by A2L tag name) — cal
4. `bytes` + `symbol` `MEASUREMENT_0065` — cal
5. `bytes` @ app+0x100 (XOR-derived) — application region change
6. `string` `"HW_REV=99"` @ erased config tail — config region change
7. `bytes` @ cal+0x80 (XOR-derived) — calibration region change

The two `symbol` entries resolve only when the reader is given the A2L context
(`parse_change_document(..., a2l_context=a2l)` — exactly what the Patch
Editor/ChangeService does when a project A2L is loaded); their declared address
and byte length equal the tag's, so they parse with zero `CHG-SYMBOL-*` issues.
The XOR-derived byte runs and the erased-flash strings guarantee the after
bytes differ from the before bytes at any seed/size.

`demo_check.chk.json` / `demo_check_fails.chk.json`: one entry per check kind
(`bytes`, `string`, `bytes`+`symbol`). The first asserts the bytes actually
present (aggregate `passed=3`); the second declares deliberately wrong bytes
(XOR 0xFF / `"WRONG_ID_STRING"`) → aggregate `failed=3`. Both parse with zero
declaration issues.

## 6. Injected faults and the app's own reports (task point 4)

### firmware_issues.a2l (clean A2L + 8 tags; still valid ASAP2, 0 parse errors)

| fault | count | app report |
|---|---|---|
| address outside every image region | 3 (`OUT_OF_RANGE_1..3` @ 0x00D00000/10/20) | `CROSS_A2L_S19_OUT_OF_RANGE` (WARNING) "A2L symbol '…' range is not fully present in S19 image." + tag `in_memory=False`, reason "characteristic address not in S19" |
| span crosses a region end | 2 (`SPAN_OVER_1..2`, ULONG @ 0x00C00FFE/0x00C00FFF) | `CROSS_A2L_S19_OUT_OF_RANGE` (WARNING), same message + `in_memory=False` |
| duplicate symbol | 1 (second `VALUE_0001`) | `A2L_DUPLICATE_SYMBOL` (ERROR) "A2L symbol 'value_0001' is defined multiple times." |
| missing COMPU_METHOD reference | 1 (`MISSING_CM`, conversion `CM_MISSING`) | tag enrichment `conversion_status="identity_fallback"`, `conversion_error="compu method missing"` (no typed code; the general validators treat it as a decode-level signal) |
| value outside its limits | 1 (`LIMIT_BREAKER`, UBYTE 0xFF @ 0x00C00200 vs limits [100,120]) | tag `value_outside_limits=True`; `validate_a2l_tags` reason "value outside limits" |

### firmware_issues.mac (clean 200-line MAC + 9 lines)

| fault | count | app report |
|---|---|---|
| name absent from the A2L | 3 (`ABSENT_ALPHA/BETA/GAMMA`) | `CROSS_MAC_ONLY_SYMBOL` (WARNING) "MAC symbol '…' missing from A2L." |
| address outside the image | 3 (`MEASUREMENT_0017/18/19` @ 0x00FF0000/0x01000000/0xFFFF0000) | `CROSS_MAC_S19_OUT_OF_RANGE` (WARNING) "MAC symbol '…' address 0x… not present in S19 image." **and** `TRIPLE_NAME_ADDRESS_MISMATCH` (ERROR) "Symbol '…' has address mismatch (A2L=0x…, MAC=0x…)." |
| duplicate name | 1 (repeated `VALUE_0001`) | `MAC_DUPLICATE_NAME` (ERROR) "MAC symbol 'value_0001' is defined multiple times." **and** `MAC_DUPLICATE_ADDRESS` (ERROR) "Address 0x00000000 has duplicate MAC symbols (hard conflict): VALUE_0001." |
| bad hex value | 1 (`BAD_HEX_VALUE=0xGGGGGGGG`) | `MAC_PARSE_ERROR` (ERROR) "invalid hex address" + parse diagnostic "Line 209: invalid hex address" |
| no `=` separator | 1 (`NO_EQUALS_LINE_0x00800000`) | `MAC_PARSE_ERROR` (ERROR) "expected one '=' separator" + parse diagnostic "Line 210: expected one '=' separator" |

Every injected fault is surfaced by a shipped validator; the test asserts the
exact code counts and the tag-level signals above.

## 7. App finding (recorded, not fixed)

`validate_a2l_structure` reports **102 `A2L_UNRECOGNIZED_BLOCK` WARNINGs**
(0 errors) for `MOD_PAR` (1), `MOD_COMMON` (1), and `AXIS_DESCR` (100) —
standard ASAP2 blocks absent from `s19_app/validation/rules.py::
RECOGNIZED_A2L_BLOCKS`. The generated A2Ls are valid ASAP2 (0 parse errors, 0
duplicates in the clean file, 0 broken references). This is an app-side finding
the orchestrator routes; it is recorded here, never worked around in the A2L,
and no `s19_app/` file was changed.

## 8. Test result

```
12 passed in 6.14s
```

Command: `timeout 900 python -m pytest tests/test_synth_release_case.py -q
--basetemp C:/Users/jjgh8/AppData/Local/Temp/s19rel/bt` (Python `s19env`,
`PYTHONPATH=.`, redirected `LOCALAPPDATA`).

## 9. Regeneration

```bash
python tools/synth/make_release_case.py --out examples/case_08_release_demo --seed 20260001 --size-mb 10
```
