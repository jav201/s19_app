# Inc 10 E4 implementation hand-back (conductor C10, Sonnet driving DeepSeek v4-pro)

Base `439860c4`. Tree `b103-inc10`. Four units, one opencode call each (fresh session, `deepseek/deepseek-v4-pro`, `--auto`, timeout 2700, no quota problem, exit 0 every time). Records use `<runner>` for the Linux host (PP-03). Every check ran on `<runner>` with the HT-02 environment (`HOME` basename `<runner-home>`, `timeout 300`); `s19_app.__file__` printed at the top of each transcript was the shipped scratch tree.

## Units

| Unit | Commit | Files | DeepSeek outcome | Verification (all executed) |
|---|---|---|---|---|
| U1 G3 `emit_intel_hex_from_mem_map` | `bc17ac98` | `changes/io.py` | delivered, no defect | x64u (32 bytes at 0xFFF8) -> the six lines of `data/x64u.hex` line for line; docstring example; x64 (36 bytes at 0xFFF0) 2 type-04 records and rows unchanged; no record crosses a multiple of 0x10000. HELD |
| U2 G1 `panel.py` + `styles.tcss` | `85a0c15b` | `panel.py`, `styles.tcss` | delivered, no defect | `SAVEBACK_FORMATS` value; new panel `_saveback_format "s19"`, `_saveback_width 32`; `SaveBackDecision` parameters, `(None)` and `("x.hex")` give `output_format None` (E3-5); chip width 17 = `len("Format: Intel HEX")`, `.patch-chip` has `padding: 0`. HELD (E5 wording fix: this checked the label attribute, not the painted text; the Button's line-pad needs 19 cells, set at integration `9d78a652`, R-PE-EXPORT.9) |
| U3 G1 `actions.py` | `d4ddfec8` | `actions.py` | fixed by C10 (formatting only, see below) | at 118x54 and 220x60: dock is the panel's child between `#patch_doc_controls` and `#patch_legend`; row x and width equal the document row's; heights 3 / 1 / 4 (prompt / before-after alone / both); doc row y 38, row y 39-41, legend y 42 at 118x54; Format press switches label, name suffix, hides Width without moving `Write file` / `Don't save` (regions equal); the rename examples R-PE-EXPORT.14/1-4 and .15/1-2; width kept across formats; a new prompt resets to the given format and width 32; confirm posts `output_format`, decline posts none; the row is shown from the inspector, json and checks tabs. HELD |
| U4 G2 `app/patch.py` | `137c6474` | `app/patch.py` | fixed by C10 (docstring line, see below) | Applied case01 (S19) and Applied HEX, through the real buttons: apply line equals the R-PE-EXPORT.4 text, no notice, suggestion `firmware-patched.s19` / `.hex`; add, edit, remove each hide the prompt; a refused remove keeps it; zero apply hides it and gives one warning `Nothing applied` / `Apply: 0 applied, 1 skipped, 0 blocked`; S19 -> Intel HEX `Write file`: `Saved + verified: firmware-patched.hex — 1 entry applied before this save (0x8000007C)`, first line `:0200000480007A`; Intel HEX -> S19: `Saved + verified: firmware-patched.s19 ...`, S0 data `firmware-patched.s19`; same S19 -> HEX at 220x60; before/after control shown after the write; per-entry JSON edit: ok hides, refused and cancel keep. HELD |

## DeepSeek defects found

None that fails an example. Two deviations from "minimal, surgical", both fixed by C10 before the commit:
1. U3 reflowed the `Apply loaded changes` and `Save` buttons of `_compose_doc_controls` onto one line each; restored the original layout (out of scope). Also removed a blank line it added after `import re`.
2. U4 left the `on_staging_sheet_stage_requested` docstring's Data Flow saying only `note_staged`; C10 added the `hide_save_prompt` clause.

## Not run, and open

- `on_staging_sheet_stage_requested` ok path (R-PE-EXPORT.17/5): the code is the one call beside `note_staged` (read); the no-A2L return keeps the prompt (executed). The ok path needs an A2L and a staged definition: left to the tester's case 17/5. State: not-run.
- P-022 / BL-I10-E3-8 (HIGH, open, not one of the 12 edits): `_synth_s0_header_from_filename` still writes a typed full path into the S0 header (executed: a typed `C:\...` name comes back verbatim). After this increment every Intel HEX -> S19 export at width 32 takes that path. Unchanged by design; needs the ruling.
- Unreachable guard: `_set_saveback_format` with a format outside `SAVEBACK_FORMATS` would fail on `None` suffix; the panel only sends `SAVEBACK_FORMATS` values (I-10.5), so no guard was added.
- No full suite, no test files written or changed (retarget of the shipped pins, G-T1 / G-T2 belong to the testers). Load on `<runner>` was 3 to 9 during the runs; nothing here is a timing result.

## Checks on the diff

`git diff 439860c4..HEAD`: 5 source files, +173 -70; 0 CR; `ast.parse` of every changed Python file; scan with the PP-02 patterns: 0 hits.
