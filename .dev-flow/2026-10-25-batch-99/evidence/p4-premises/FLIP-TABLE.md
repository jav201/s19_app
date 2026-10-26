# Premise flip table — the investigation probes re-run on main `e7732f6` (all 12 increments)

Run 2026-10-26 with `S19_WT=C:/Users/jjgh8/Github/s19_app`, `s19env`. Before-state: `../p0-premises/` (on `307065f`). Three probes were written against the pre-batch API and crash on the new one (the export now returns `PlacedExport(path, action)`; the flow writes nothing when PATCH errors). Their adapted copies sit in `adapted/` with a header comment; the probe logic is otherwise unchanged.

| Premise | Before (`307065f`) | After (`e7732f6`) | Transcript |
|---|---|---|---|
| P-1 H-1 S0 phantom | 15 of 16 S19 sources `BAD … extra=12@0x0..0xb` | `32 OK`, 0 BAD (S19 and HEX output of every example) | `rw-p03_roundtrip_examples.txt` |
| P-2 H-1 patch at 0x0 | `('patch','ok','applied 1 entry')` | `patch error 'applied 0 of 1 entries'`, `['skipped-outside']`, nothing written | `rw-p13a_s0_phantom_patcha.txt` |
| P-4 H-2 PATCH always ok | `outside_0x20000 run=ok patch=ok:'applied 0 entries' wrote=[…]` | `run=error patch=error:'applied 0 of 1 entries' wrote=[]`; `malformed_json run=error … refusals=['MF-JSON-PARSE'] wrote=[]` | `rw-p01_flow_patch_truthfulness.txt` |
| P-5 H-3 shared staging | `parallel mismatches: 35` | the probe's shared-name set is now **refused by D7 and writes 0 files** (`parallel mismatches: 0 files now: []` counts nothing, so it is not by itself the flip). The same-name concurrency flip is TC-B99-12: 8 writers requesting one name × 20 trials → 0 mismatches (`evidence/inc-3a/`), RED 35/68 mismatches under the check-then-copy mutant | `rw-p02_chainset_parallel_and_report.txt`; `evidence/inc-3a/` TC-B99-12 transcripts |
| P-14 H-10 run records | `outcome status: ok … ('patch','ok','applied 0 entries')` | `outcome status: error … ('patch','error','change document unreadable'), ('write_out','skipped',…)`; the report names `MF-JSON-PARSE` | `rw-p02…`, `rw-p09_flow_report.txt` |
| P-6 H-4 editor undo | `file @0xEB10 = deadbeef`, `verify: verified` | `file @0xEB10 = 20417070 (source: 20417070)`; status `1 entry applied before this save (0x0000EB40)` | `rw-p05_editor_apply_undo_save.txt` |
| P-7 H-5 byte order | `effective_byte_order = little` | `effective_byte_order = big`; encode 4113 → `1011` | `rw-p06a_a2l_encode_and_symbol_refusala.txt` |
| P-8 H-6 COMPU_TAB | `TAB_INTP 500.0 -> raw 02 … err=None` | `TAB_INTP 500.0 -> raw None err=the value 500.0 is outside the table range [0.0, 20.0]`; `TAB_NOINTP 13.0` refused naming 10.0 and 20.0 | `rw-p06a…` |
| P-9 H-7 CRC empty region | `region_no_bytes run=ok crc=ok … slot_bytes=00000000` | `region_no_bytes run=error crc=error:'empty CRC region'`, nothing written | `rw-p07_crc_block.txt` |
| P-10 H-8 truncated images | `s19_truncated_no_terminator run=ok source=ok notices=0`; `hex_data_after_eof … out_bytes=32` | `run=error source=error … out_bytes=0` for both | `rw-p04_loader_edge_cases.txt` |
| P-11 H-9 export containment | `inside dest: False`; `first content survived: False` | `inside dest: True` (name `prg_x__________ESCAPED.s19`); first file intact, second written as `prg_range_00_1.s19` | `rw-p10a_split_export_paths.txt` |
| P-15 PH-3 | `work copy exists after save-back: False`; `return_code: 1` | `work copy exists after save-back: True`; `app running? True | return_code: None` | `proj-p08.txt` |
| P-12 emitters exact | `mismatches = 0` | unchanged | `rw-p12_emitters.txt` |
| P-16 CW-D-4 decimal Bytes tokens (code-read premise) | `0F 10 1F 20` → `0F 0A 1F 14` (audit T2 t2b) | `0F 10 1F 20` → `[0x0f,0x10,0x1f,0x20]`; `G1`, `100` refused naming the token | qa-reviewer probe on main (`../p4-qa/`); TC-B99-32, AT-B99-12 GREEN (`../inc-11/`, `../ddr/`) |
| P-17 CW-D-10 RAT_FUNC direction (audit premise) | encode used the inverse direction | AT-B99-14 asserts raw 300 for physical 30 | TC-B99-24/43 GREEN, RED `../inc-10/mut-LLR-158.2.txt` |
| P-18 CW-D-7 MAC-only phantom byte (audit premise) | plan `{packed 0, empty True}`, written `S306800000000079` | MAC-only export writes no data record (`image_b.data == {}`) | TC-B99-30, AT-B99-11 MAC-only arm GREEN (`../inc-6/`, `../ddr/`) |
| P-19 `_load_from_item` reads `str(label)` (code-read premise) | label text used as the name | `app.py:9021-9031` reads `item.data`; Inc-7 V-3 grep 0 hits | qa-reviewer inspection on main; TC-B99-34, AT-B99-13 GREEN (`../inc-7/`) |
| P-20 reserved work-area homes listed as projects (code-read premise) | homes listed | `app.py:8519-8524` filters `RESERVED_WORKAREA_HOMES` (`workspace.py:40-50`) | qa-reviewer inspection on main; TC-B99-35, AT-B99-13 GREEN |
| P-21 no HEX fixtures in the corpus | 0 HEX files | the synthetic corpus ships HEX files checked by the independent reader | AT-B99-01, TC-B99-02/03 GREEN (`../inc-1/`) |

**Verdict:** every premise that served as a RED side has flipped on the merged tree. Rows P-16..P-21 were added at P4 (validation G-007). They are code-read or audit premises with no probe of their own, so their after-state cites the node that now holds them and who checked it.
