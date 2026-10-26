# Premise flip table — the investigation probes re-run on main `e7732f6` (all 12 increments)

Run 2026-10-26 with `S19_WT=C:/Users/jjgh8/Github/s19_app`, `s19env`. Before-state: `../p0-premises/` (on `307065f`). Three probes were written against the pre-batch API and crash on the new one (the export now returns `PlacedExport(path, action)`; the flow writes nothing when PATCH errors). Their adapted copies sit in `adapted/` with a header comment; the probe logic is otherwise unchanged.

| Premise | Before (`307065f`) | After (`e7732f6`) | Transcript |
|---|---|---|---|
| P-1 H-1 S0 phantom | 15 of 16 S19 sources `BAD … extra=12@0x0..0xb` | `32 OK`, 0 BAD (S19 and HEX output of every example) | `rw-p03_roundtrip_examples.txt` |
| P-2 H-1 patch at 0x0 | `('patch','ok','applied 1 entry')` | `patch error 'applied 0 of 1 entries'`, `['skipped-outside']`, nothing written | `rw-p13a_s0_phantom_patcha.txt` |
| P-4 H-2 PATCH always ok | `outside_0x20000 run=ok patch=ok:'applied 0 entries' wrote=[…]` | `run=error patch=error:'applied 0 of 1 entries' wrote=[]`; `malformed_json run=error … refusals=['MF-JSON-PARSE'] wrote=[]` | `rw-p01_flow_patch_truthfulness.txt` |
| P-5 H-3 shared staging | `parallel mismatches: 35` | the probe's shared-name set is now **refused by D7 and writes 0 files** (`parallel mismatches: 0 files now: []` counts nothing, so it is not by itself the flip). The same-name concurrency flip is TC-B99-12: 8 writers requesting one name × 20 trials → 0 mismatches (`evidence/inc-3a/`), RED 35/68 mismatches under the shared-staging mutant | `rw-p02_chainset_parallel_and_report.txt`; `evidence/inc-3a/` TC-B99-12 transcripts |
| P-14 H-10 run records | `outcome status: ok … ('patch','ok','applied 0 entries')` | `outcome status: error … ('patch','error','change document unreadable'), ('write_out','skipped',…)`; the report names `MF-JSON-PARSE` | `rw-p02…`, `rw-p09_flow_report.txt` |
| P-6 H-4 editor undo | `file @0xEB10 = deadbeef`, `verify: verified` | `file @0xEB10 = 20417070 (source: 20417070)`; status `1 entry applied before this save (0x0000EB40)` | `rw-p05_editor_apply_undo_save.txt` |
| P-7 H-5 byte order | `effective_byte_order = little` | `effective_byte_order = big`; encode 4113 → `1011` | `rw-p06a_a2l_encode_and_symbol_refusala.txt` |
| P-8 H-6 COMPU_TAB | `TAB_INTP 500.0 -> raw 02 … err=None` | `TAB_INTP 500.0 -> raw None err=the value 500.0 is outside the table range [0.0, 20.0]`; `TAB_NOINTP 13.0` refused naming 10.0 and 20.0 | `rw-p06a…` |
| P-9 H-7 CRC empty region | `region_no_bytes run=ok crc=ok … slot_bytes=00000000` | `region_no_bytes run=error crc=error:'empty CRC region'`, nothing written | `rw-p07_crc_block.txt` |
| P-10 H-8 truncated images | `s19_truncated_no_terminator run=ok source=ok notices=0`; `hex_data_after_eof … out_bytes=32` | `run=error source=error … out_bytes=0` for both | `rw-p04_loader_edge_cases.txt` |
| P-11 H-9 export containment | `inside dest: False`; `first content survived: False` | `inside dest: True` (name `prg_x__________ESCAPED.s19`); first file intact, second written as `prg_range_00_1.s19` | `rw-p10a_split_export_paths.txt` |
| P-15 PH-3 | `work copy exists after save-back: False`; `return_code: 1` | `work copy exists after save-back: True`; `app running? True | return_code: None` | `proj-p08.txt` |
| P-12 emitters exact | `mismatches = 0` | unchanged | `rw-p12_emitters.txt` |

**Verdict:** every premise that served as a RED side has flipped on the merged tree.
