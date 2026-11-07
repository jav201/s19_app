# Inc 10 — test cases (ISO/IEC/IEEE 29119-3), E1

One case per coverage item `<requirement id>/<n>` of `01-requirements.md` (27 active rows and 15 cited rows), plus the acceptance cases `AT-I10-1` … `AT-I10-3`. Written at E1, before any test: **Tests** is empty, **Coverage** is `gap` (E4 writes the tests) and **Result** is `not_run` everywhere, except the four cases owed by open code changes D8-27, D8-28 and D8-29, whose Coverage is `conflict` until the orchestrator rules D-6 (`E1-rulings.md` §3). Proposed test files (fixed at E4): G-T1 = `tests/test_b103_pe_export_prompt.py` (the prompt, the apply line, the notice, the Format and Width controls, the layout rows, the ATs); G-T2 = `tests/test_b103_pe_export_write.py` (what is written and verified). Rows marked PROPOSED in `01-requirements.md` keep their cases; a G2 verdict or a ruling that picks another option replaces them (`E1-rulings.md` §3).

Common fixtures:
- **Sizes** — `app.run_test(size=…)` at 118×54 and 220×60 (the screen is 116×52 and 218×58 inside the frame, C).
- **Tabs** — the inspector tab chips `#patch_tab_inspector`, `#patch_tab_json`, `#patch_tab_checks`, `#patch_tab_a2l` (four at `e07fb00`).
- **Applied case01 (tab T)** — the app with an isolated `base_dir`; a copy of case01 loaded through the Load dialog (`l`, the path typed into `#load_path`, `#load_ok`; the shape of `tests/test_b100_save_image._load_file_through_dialog`); the entry 0x8000007C `DE AD BE EF` added through the panel's own boxes and Add; tab chip T clicked; `Apply loaded changes` clicked; the final painted status read from the log strip after every handler has run. No tab chip is pressed after Apply unless the case says so.
- **Applied HEX (tab T)** — as Applied case01, with `firmware.hex` written beside the copy by the system's HEX writer from case01's image (the probe's shape, `../design/pe-probe/probe3.py`).
- **Shown at its place** — the control and every widget that holds it are displayed (*shown widget*), its region is not empty and lies inside the screen, and `app.screen.get_widget_at(<centre of its region>)` returns the control itself.
- **Conversion sources** — case00, s2src, case01, x64 and their four Intel HEX twins (`01-requirements.md` Definitions; the census builds them, `evidence-e1/i10e1_convert_census.py`). "Through the prompt" = Applied case01 / Applied HEX, the format and width set with the prompt's controls, the name typed into the name box, `Write file`; "through the writer" = the save-back writer the prompt's handler calls, given the output format (the census's call).
- **Work area** — `<base_dir>/.s19tool/workarea/`, no project open (the destination of R-CHG-003.8).

| Case | Objective | Class | Preconditions | Inputs | Expected result | Tests | Coverage | Result |
|---|---|---|---|---|---|---|---|---|
| R-CHG-003.1/1 | Verify that the prompt is shown after an apply from the Inspector tab at 118×54 | normal | 118×54 | Applied case01 (Inspector) | the prompt and `Write file` are shown at their place; the shown tab is the one before Apply (D-1 A) or the Inspector (D-1 B) (base: 0×0, hidden by `#patch_win_json`, C) | | gap | not_run |
| R-CHG-003.1/2 | … from the JSON tab at 118×54 | normal | 118×54 | Applied case01 (JSON) | as /1 (base: shown, C) | | gap | not_run |
| R-CHG-003.1/3 | … from the Checks tab at 118×54 | normal | 118×54 | Applied case01 (Checks) | as /1 (base: 0×0, C) | | gap | not_run |
| R-CHG-003.1/4 | … from the A2L tab at 118×54 | normal | 118×54 | Applied case01 (A2L) | as /1 (base: 0×0, C) | | gap | not_run |
| R-CHG-003.1/5 | … from the Inspector tab at 220×60 | normal | 220×60 | Applied case01 (Inspector) | as /1 (base: 0×0, C) | | gap | not_run |
| R-CHG-003.1/6 | … from the JSON tab at 220×60 | normal | 220×60 | Applied case01 (JSON) | as /1 (base: shown, C) | | gap | not_run |
| R-CHG-003.1/7 | … from the Checks tab at 220×60 | normal | 220×60 | Applied case01 (Checks) | as /1 (base: 0×0, C) | | gap | not_run |
| R-CHG-003.1/8 | … from the A2L tab at 220×60 | normal | 220×60 | Applied case01 (A2L) | as /1 (base: 0×0, C) | | gap | not_run |
| R-CHG-003.1/9 | Verify that the prompt is shown after an apply on an Intel HEX image | normal | 118×54 | Applied HEX (Inspector) | as /1 (base: hidden by `#patch_win_json`, B) | | gap | not_run |
| R-PE-EXPORT.1/1 | Verify that the prompt sits between the document row and the legend at 118×54 | normal | 118×54; Applied case01 (Inspector) | — | prompt top row > `#patch_doc_controls` row; prompt bottom row < `#patch_legend` row; prompt x and width = `#patch_doc_controls` x and width (base: inside `#patch_win_json`, R) | | gap | not_run |
| R-PE-EXPORT.1/2 | … at 220×60 | normal | 220×60; Applied case01 (Inspector) | — | as /1 | | gap | not_run |
| R-TUI-063.1/1 | Verify the top-to-bottom order with the prompt hidden at 118×54 | normal | 118×54; case01 loaded, no apply | — | top rows strictly increase: ribbon, `#patch_main`, `#patch_doc_file_row`, `#patch_doc_controls`, `#patch_legend` (base: holds, C) | | gap | not_run |
| R-TUI-063.1/2 | … with the prompt shown at 118×54 | normal | 118×54; Applied case01 (Inspector) | — | ribbon, `#patch_main`, file row, document row, prompt, legend, strictly increasing | | gap | not_run |
| R-TUI-063.1/3 | … with the prompt hidden at 220×60 | normal | 220×60; case01 loaded | — | as /1 | | gap | not_run |
| R-TUI-063.1/4 | … with the prompt shown at 220×60 | normal | 220×60; Applied case01 (Inspector) | — | as /2 | | gap | not_run |
| R-PE-EXPORT.2/1 | Verify that every prompt control is on screen without scrolling (118×54, Inspector) | normal | 118×54 | Applied case01 (Inspector) | the name box, the Format control, the Width control, `Write file`, `Don't save` lie inside the screen; the Patch Editor's scroll offsets are 0 (base: 0×0, C) | | gap | not_run |
| R-PE-EXPORT.2/2 | … (118×54, JSON) | normal | 118×54 | Applied case01 (JSON) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/3 | … (118×54, Checks) | normal | 118×54 | Applied case01 (Checks) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/4 | … (118×54, A2L) | normal | 118×54 | Applied case01 (A2L) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/5 | … (220×60, Inspector) | normal | 220×60 | Applied case01 (Inspector) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/6 | … (220×60, JSON) | normal | 220×60 | Applied case01 (JSON) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/7 | … (220×60, Checks) | normal | 220×60 | Applied case01 (Checks) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/8 | … (220×60, A2L) | normal | 220×60 | Applied case01 (A2L) | as /1 | | gap | not_run |
| R-PE-EXPORT.2/9 | … with Intel HEX at 118×54 | normal | 118×54 | Applied HEX (Inspector) | the name box, the Format control, `Write file`, `Don't save` inside the screen, scroll offsets 0 | | gap | not_run |
| R-PE-EXPORT.2/10 | … with Intel HEX at 220×60 | normal | 220×60 | Applied HEX (Inspector) | as /9 | | gap | not_run |
| R-TUI-049.1/1 | Verify that the before/after control is shown after a save-back from the Inspector tab | normal | 118×54; Applied case01 (Inspector) | `Write file` | status `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)`; `Write before/after report` shown at its place (base: inside `#patch_win_json`, R) | | gap | not_run |
| R-TUI-049.1/2 | … from the JSON tab | normal | 118×54; Applied case01 (JSON) | `Write file` | as /1 (base: shown, R) | | gap | not_run |
| R-TUI-049.1/3 | … from the Checks tab | normal | 118×54; Applied case01 (Checks) | `Write file` | as /1 | | gap | not_run |
| R-TUI-049.1/4 | … from the A2L tab | normal | 118×54; Applied case01 (A2L) | `Write file` | as /1 | | gap | not_run |
| R-PE-EXPORT.3/1 | Verify that an apply that applies nothing hides the prompt (118×54) | robustness | 118×54; Applied case01 (Inspector), prompt shown | the entry 0x8000007C removed (Remove), the entry 0x00000010 `AA` added, Apply | status `Apply: 0 applied, 1 skipped, 0 blocked`; the prompt is not a shown widget (base: still shown, C) | | gap | not_run |
| R-PE-EXPORT.3/2 | … (220×60) | robustness | 220×60; as /1 | as /1 | as /1 (base: still shown, C) | | gap | not_run |
| R-PE-EXPORT.3/3 | Verify that an apply of a blocked document hides the prompt | robustness | 118×54; Applied case01 (Inspector), prompt shown | the entry 0x8000007D `00` added (a collision), Apply | 0 applied, 2 blocked; the prompt is not a shown widget | | gap | not_run |
| R-PE-EXPORT.4/1 | Verify the apply line after one applied entry | normal | 118×54 | Applied case01 (Inspector) | the painted apply line reads exactly `Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it` (base: no line, C) | | gap | not_run |
| R-PE-EXPORT.4/2 | Verify the apply line counts applied and skipped entries | normal | 118×54; case01 loaded; entries 0x8000007C `DE AD`, 0x80000040 `11`, 0x00000010 `AA` | Apply | `Apply: 2 applied, 1 skipped, 0 blocked · changed in memory only — Write file saves it` | | gap | not_run |
| R-PE-EXPORT.4/3 | Verify that a new apply refreshes the apply line | normal | 118×54; Applied case01 (Inspector) | the entry 0x80000040 `11` added, Apply | `Apply: 2 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it` | | gap | not_run |
| R-PE-EXPORT.5/1 | Verify the warning notice when no image is loaded | robustness | 118×54; no image loaded; the entry 0x100 `AA` added | Apply | 1 notice, severity warning, title `Nothing applied`, text `Apply: 0 applied, 1 skipped, 0 blocked` (base: none, B) | | gap | not_run |
| R-PE-EXPORT.5/2 | Verify the warning notice when the entry is outside the image | robustness | 118×54; case01 loaded; the entry 0x00000010 `AA` | Apply | 1 warning notice `Nothing applied` / `Apply: 0 applied, 1 skipped, 0 blocked` (base: none, C) | | gap | not_run |
| R-PE-EXPORT.5/3 | Verify the warning notice for a blocked document | robustness | 118×54; case01 loaded; entries 0x8000007C `DE AD BE EF` and 0x8000007D `00` | Apply | 1 warning notice `Nothing applied` / `Apply: 0 applied, 0 skipped, 2 blocked` | | gap | not_run |
| R-PE-EXPORT.6/1 | Verify that a successful apply shows no notice (S19) | normal | 118×54 | Applied case01 (Inspector) | 0 notices (base: 0, C) | | gap | not_run |
| R-PE-EXPORT.6/2 | … (Intel HEX) | normal | 118×54 | Applied HEX (Inspector) | 0 notices | | gap | not_run |
| R-PE-EXPORT.7/1 | Verify the default output format for an S19 image | normal | 118×54 | Applied case01 (Inspector) | the Format control shows `S19` (base: no control, R) | | gap | not_run |
| R-PE-EXPORT.7/2 | … for an Intel HEX image | normal | 118×54 | Applied HEX (Inspector) | `Intel HEX` | | gap | not_run |
| R-PE-EXPORT.7/3 | Verify that each new prompt starts from the loaded image's format | normal | 118×54; Applied case01 (Inspector) | Format pressed (Intel HEX), `Don't save`, Apply | the Format control shows `S19`; the name box `firmware-patched.s19` | | gap | not_run |
| R-PE-EXPORT.8/1 | Verify that one press changes S19 to Intel HEX, shown and written | normal | 118×54; Applied case01 (Inspector) | Format, `Write file` | the control shows `Intel HEX`; the written file's first line starts with `:` (base: no control, R) | | gap | not_run |
| R-PE-EXPORT.8/2 | Verify that a second press changes back to S19 | normal | 118×54; Applied case01 (Inspector) | Format, Format, `Write file` | the control shows `S19`; the written file's first line starts with `S0` | | gap | not_run |
| R-PE-EXPORT.9/1 | Verify the Format control's label for S19 | normal | 118×54; Applied case01 (Inspector) | — | the painted control holds `S19` and not `Intel HEX` | | gap | not_run |
| R-PE-EXPORT.9/2 | Verify the label after a press | normal | as /1 | Format | the painted control holds `Intel HEX` | | gap | not_run |
| R-PE-EXPORT.10/1 | Verify no Width control for an Intel HEX image | normal | 118×54 | Applied HEX (Inspector) | the Width control is not painted; Tab through the prompt never focuses it; a click at its place leaves the width and the name box unchanged (base: shown, B) | | gap | not_run |
| R-PE-EXPORT.10/2 | Verify no Width control after switching to Intel HEX | normal | 118×54; Applied case01 (Inspector) | Format | as /1 | | gap | not_run |
| R-PE-EXPORT.11/1 | Verify the Width control for S19 | normal | 118×54 | Applied case01 (Inspector) | `Width: 32 bytes/line` shown at its place (base: shown in the JSON tab, C) | | gap | not_run |
| R-PE-EXPORT.11/2 | Verify the Width control after switching Intel HEX to S19 | normal | 118×54 | Applied HEX (Inspector); Format | `Width: 32 bytes/line` shown | | gap | not_run |
| R-PE-EXPORT.12/1 | Verify that Write file and Don't save stay put, S19 → Intel HEX (118×54) | normal | 118×54; Applied case01 (Inspector) | Format | the regions of `Write file` and `Don't save` equal those before the press | | gap | not_run |
| R-PE-EXPORT.12/2 | … Intel HEX → S19 (118×54) | normal | as /1, Format pressed once | Format | as /1 | | gap | not_run |
| R-PE-EXPORT.12/3 | … S19 → Intel HEX (220×60) | normal | 220×60; Applied case01 (Inspector) | Format | as /1 | | gap | not_run |
| R-PE-EXPORT.12/4 | … Intel HEX → S19 (220×60) | normal | as /3, Format pressed once | Format | as /1 | | gap | not_run |
| R-PE-EXPORT.13/1 | Verify that a format change keeps the width | normal | 118×54; Applied case01 (Inspector) | Width (16), Format, Format, `Write file` | `Width: 16 bytes/line`; every S3 record of the written file holds at most 16 data bytes | | gap | not_run |
| R-PE-EXPORT.14/1 | Verify the suggested name follows a switch to Intel HEX | normal | 118×54; Applied case01 (Inspector) | Format | name box `firmware-patched.hex` | | gap | not_run |
| R-PE-EXPORT.14/2 | Verify an upper-case suffix is replaced | normal | as /1 | name box `MyImage.S19`; Format | name box `MyImage.hex` | | gap | not_run |
| R-PE-EXPORT.14/3 | Verify a switch to S19 replaces `.hex` | normal | 118×54; Applied HEX (Inspector) | name box `a.hex`; Format | name box `a.s19` | | gap | not_run |
| R-PE-EXPORT.15/1 | Verify a name without a format suffix is kept, and the write adds it | robustness | 118×54; Applied case01 (Inspector) | name box `release_v2`; Format; `Write file` | name box still `release_v2`; the written file is `release_v2.hex` | | gap | not_run |
| R-PE-EXPORT.15/2 | Verify a name with another extension is kept | robustness | as /1 | name box `x.bin`; Format; `Write file` | name box still `x.bin`; written `x.bin.hex` | | gap | not_run |
| R-HEX-SAVE-001.1/1 | Verify S19 → S19 through the prompt | normal | 118×54; Applied case01 (Inspector) | `Write file` | `firmware-patched.s19` in the work area, first line starts with `S0` | | gap | not_run |
| R-HEX-SAVE-001.1/2 | Verify S19 → Intel HEX through the prompt | normal | as /1 | Format, `Write file` | `firmware-patched.hex`, first line starts with `:` (base: S19 written, R) | | gap | not_run |
| R-HEX-SAVE-001.1/3 | Verify Intel HEX → Intel HEX | normal | 118×54; Applied HEX (Inspector) | `Write file` | `firmware-patched.hex`, first line `:0200000480007A` (base: as the probe, B) | | gap | not_run |
| R-HEX-SAVE-001.1/4 | Verify Intel HEX → S19 | normal | as /3 | Format, `Write file` | `firmware-patched.s19`, first line starts with `S0` (base: HEX written, R) | | gap | not_run |
| R-HEX-SAVE-001.2/1 | Verify `.s19` gets `.hex` added when written as Intel HEX | robustness | the writer; case01 | name `firmware-patched.s19`, output Intel HEX | written `firmware-patched.s19.hex` (base: same, C) | | gap | not_run |
| R-HEX-SAVE-001.2/2 | Verify an upper-case `.HEX` is kept | normal | as /1 | `firmware-patched.HEX`, Intel HEX | `firmware-patched.HEX` (C) | | gap | not_run |
| R-HEX-SAVE-001.2/3 | Verify a bare name gets `.hex` | normal | as /1 | `firmware-patched`, Intel HEX | `firmware-patched.hex` (C) | | gap | not_run |
| R-HEX-SAVE-001.2/4 | Verify `.hex` gets `.s19` added when written as S19 | robustness | as /1 | `firmware-patched.hex`, S19 | `firmware-patched.hex.s19` (C) | | gap | not_run |
| R-S19-SAVE-REUSE-001.1/1 | Verify 16-byte HEX records at width 32 from an S19 source | normal | 118×54; Applied case01 (Inspector) | Format, `Write file` (width 32) | every type-00 record holds ≤ 16 data bytes (C: `max_data 16`) | | gap | not_run |
| R-S19-SAVE-REUSE-001.1/2 | … at width 16 from an S19 source | normal | as /1 | Width (16), Format, `Write file` | as /1 | | gap | not_run |
| R-S19-SAVE-REUSE-001.1/3 | … at width 32 from an Intel HEX source | normal | Applied HEX (Inspector) | `Write file` | as /1 | | gap | not_run |
| R-S19-SAVE-REUSE-001.1/4 | … at width 16 from an Intel HEX source | normal | Applied HEX (Inspector) | Format (S19), Width (16), Format (Intel HEX), `Write file` | as /1 | | gap | not_run |
| R-PE-EXPORT.16/1 | Verify HEX record types from case00 (S1, S0 data, S9 0xFFFF) | normal | the writer | case00 as Intel HEX, width 32 | only types 00, 01, 04 (C: 16 × 00, 1 × 01, 1 × 04) | | gap | not_run |
| R-PE-EXPORT.16/2 | … from s2src (S2, S0 data, S8) | normal | the writer | s2src as Intel HEX | only 00, 01, 04 (C) | | gap | not_run |
| R-PE-EXPORT.16/3 | … from case01 (S3, S0 data, S7 0x80000000) | normal | the writer | case01 as Intel HEX | only 00, 01, 04 (C) | | gap | not_run |
| R-PE-EXPORT.16/4 | … from x64 (crosses 64 KiB) | normal | the writer | x64 as Intel HEX | only 00, 01, 04 (C) | | gap | not_run |
| R-PE-EXPORT.16/5 | … from case00 as Intel HEX | normal | the writer | its HEX twin as Intel HEX | only 00, 01, 04 (C) | | gap | not_run |
| R-PE-EXPORT.16/6 | … from s2src as Intel HEX | normal | the writer | as /5 | as /5 | | gap | not_run |
| R-PE-EXPORT.16/7 | … from case01 as Intel HEX | normal | the writer | as /5 | as /5 | | gap | not_run |
| R-PE-EXPORT.16/8 | … from x64 as Intel HEX | normal | the writer | as /5 | as /5 | | gap | not_run |
| R-S19-S0HEADER-001.1/1 | Verify the source's S0 data at width 32 (case01) | normal | 118×54; Applied case01 (Inspector) | `Write file` | first line's S0 data `CASE01_BASIC` (C) | | gap | not_run |
| R-S19-S0HEADER-001.1/2 | … (case00) | normal | the writer | case00 as S19, width 32 | S0 data `Debug\stm8s003.sm8` (C) | | gap | not_run |
| R-S19-S0HEADER-001.1/3 | Verify the source's S0 data at width 16 | normal | the writer | case01 as S19, width 16 | S0 data `CASE01_BASIC` (base: empty, C — D8-27, open; D-6) | | conflict | not_run |
| R-S19-S0HEADER-001.2/1 | Verify the written name as header for an Intel HEX source (case01) | normal | 118×54; Applied HEX (Inspector) | Format (S19), `Write file` | S0 data `firmware-patched.s19` (C) | | gap | not_run |
| R-S19-S0HEADER-001.2/2 | … (case00 twin) | normal | the writer | `s19_sample.hex` as S19, width 32, name `s19_sample-patched.s19` | S0 data `s19_sample-patched.s19` (C) | | gap | not_run |
| R-S19-S0HEADER-001.2/3 | … (s2src twin) | normal | the writer | as /2 with `s2_source-patched.s19` | S0 data `s2_source-patched.s19` (C) | | gap | not_run |
| R-S19-S0HEADER-001.2/4 | … (x64 twin) | normal | the writer | as /2 with `cross64k-patched.s19` | S0 data `cross64k-patched.s19` (C) | | gap | not_run |
| R-S19-S0HEADER-001.2/5 | Verify the header is the written name when it differs from the typed one | robustness | Applied HEX; `firmware-patched.s19` already in the work area with other content | Format (S19), `Write file` | written `firmware-patched_1.s19` (the numbered name, CTX-WORKAREA) with S0 data `firmware-patched_1.s19` (base: the typed name — D8-28, open; D-6) | | conflict | not_run |
| R-S19-S0HEADER-001.3/1 | Verify empty header data at width 16 for an Intel HEX source (case01 twin) | normal | the writer | `firmware.hex` as S19, width 16 | first line `S0030000FC` (C) | | gap | not_run |
| R-S19-S0HEADER-001.3/2 | … (case00 twin) | normal | the writer | as /1 | `S0030000FC` (C) | | gap | not_run |
| R-S19-S0HEADER-001.3/3 | … (s2src twin) | normal | the writer | as /1 | `S0030000FC` (C) | | gap | not_run |
| R-S19-S0HEADER-001.3/4 | … (x64 twin) | normal | the writer | as /1 | `S0030000FC` (C) | | gap | not_run |
| R-S19-EMIT.11/1 | Verify the source's S9 address (case00) | normal | the writer | case00 as S19 | last line `S9` with address 0xFFFF (base: 0, C — D8-29, open; D-6) | | conflict | not_run |
| R-S19-EMIT.11/2 | Verify the source's S7 address (case01) | normal | the writer | case01 as S19 | last line `S7` with address 0x80000000 (base: 0, C — D8-29) | | conflict | not_run |
| R-HEX-VERIFY-001.1/1 | Verify S19 → S19 is read back as S19 and verified | normal | 118×54; Applied case01 (Inspector) | `Write file` | status `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)` (base: same, B) | | gap | not_run |
| R-HEX-VERIFY-001.1/2 | Verify S19 → Intel HEX is read back as Intel HEX | normal | as /1 | Format, `Write file` | `Saved + verified: firmware-patched.hex — 1 entry applied before this save (0x8000007C)` | | gap | not_run |
| R-HEX-VERIFY-001.1/3 | Verify Intel HEX → Intel HEX | normal | Applied HEX (Inspector) | `Write file` | `Saved + verified: firmware-patched.hex — …` (base: same, B) | | gap | not_run |
| R-HEX-VERIFY-001.1/4 | Verify Intel HEX → S19 | normal | Applied HEX (Inspector) | Format, `Write file` | `Saved + verified: firmware-patched.s19 — …` | | gap | not_run |
| R-HEX-VERIFY-001.1/5 | Verify the conversion matrix verifies | normal | the writer and the verify | the 8 conversion sources × (S19 w32, S19 w16, Intel HEX w32, Intel HEX w16) | 32/32 `verified`; the negative control (each file read with the other format's reader) gives `mismatch` 8/8 (C) | | gap | not_run |
| R-HEX-VERIFY-002.3/1 | Verify the suggested name for an S19 image | normal | 118×54 | Applied case01 (Inspector) | name box `firmware-patched.s19` (base: same, B) | | gap | not_run |
| R-HEX-VERIFY-002.3/2 | … for an Intel HEX image | normal | 118×54 | Applied HEX (Inspector) | name box `firmware-patched.hex` (base: same, B) | | gap | not_run |
| R-S19-WIDTH-001.1/1 | Verify the width is 32 on every new prompt | normal | 118×54; Applied case01 (Inspector) | Width (16), `Don't save`, Apply | `Width: 32 bytes/line` | | gap | not_run |
| R-S19-WIDTH-001.2/1 | Verify Width switches 32 ↔ 16 in the new placement | normal | 118×54; Applied case01 (Inspector) | Width, Width | `Width: 16 bytes/line`, then `Width: 32 bytes/line` (base: same in the JSON tab, B) | | gap | not_run |
| R-CHG-003.2/1 | Verify Don't save hides the prompt, from the Inspector tab | normal | 118×54; Applied case01 (Inspector) | `Don't save` | prompt not a shown widget; status `Patch Editor: save-back declined`; no new file in the work area | | gap | not_run |
| R-CHG-003.5/1 | Verify Write file hides the prompt, from the Checks tab | normal | 118×54; Applied case01 (Checks) | `Write file` | prompt not a shown widget; one new file in the work area | | gap | not_run |
| R-HEX-VERIFY-002.1/1 | Verify the verified status of an S19 image written as Intel HEX | normal | 118×54; Applied case01 (Inspector) | Format, `Write file` | status `Saved + verified: firmware-patched.hex — 1 entry applied before this save (0x8000007C)` | | gap | not_run |
| R-HEX-VERIFY-002.1/2 | … of an Intel HEX image written as S19 | normal | Applied HEX (Inspector) | Format, `Write file` | `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)` | | gap | not_run |
| R-S19-EMIT.3/1 | Verify S1 records for an Intel HEX source up to 0xFFFF | normal | the writer | case00 twin (highest 0x80F1) as S19 | data records `S1`, terminator `S9` (C) | | gap | not_run |
| R-S19-EMIT.4/1 | Verify S2 records up to 0xFFFFFF (s2src twin) | normal | the writer | s2src twin (highest 0x20010) as S19 | `S2`, `S8` (C) | | gap | not_run |
| R-S19-EMIT.4/2 | … (x64 twin) | normal | the writer | x64 twin (highest 0x10013) as S19 | `S2`, `S8` (C) | | gap | not_run |
| R-S19-EMIT.5/1 | Verify S3 records above 0xFFFFFF | normal | the writer | case01 twin (highest 0x8000007F) as S19 | `S3`, `S7` (C) | | gap | not_run |
| R-HEX-EMIT-001.2/1 | Verify a type-04 record before the first data record of an S19 source | normal | the writer | case01 as Intel HEX | first line `:0200000480007A` (C) | | gap | not_run |
| R-HEX-EMIT-001.3/1 | Verify a type-04 record when the upper 16 bits change (two ranges) | normal | the writer | s2src as Intel HEX | 2 type-04 records, `:020000040001F9` first (C) | | gap | not_run |
| R-HEX-EMIT-001.3/2 | … within one range crossing 64 KiB | normal | the writer | x64 as Intel HEX | 2 type-04 records (upper 0x0000, then 0x0001) (C) | | gap | not_run |
| R-IMG-WRITE.2/1 | Verify every conversion reads back to the same image with no diagnostic | normal | the writer | the 8 conversion sources × 4 outputs | 32/32 read back by the system's reader to the source image, 0 diagnostics (C: `reread_equal True`) | | gap | not_run |
| R-TUI-064.1/1 | Verify Validate, Apply and Save without scrolling with the prompt shown (118×54) | normal | 118×54 | Applied case01 (Inspector) | the three buttons inside the screen at scroll offset 0 | | gap | not_run |
| R-TUI-064.1/2 | … with the prompt shown for Intel HEX (118×54) | normal | 118×54 | Applied HEX (Inspector) | as /1 | | gap | not_run |
| R-TUI-064.2/1 | Verify no painted row wider than the screen with the prompt shown (118×54) | normal | 118×54 | Applied case01 (Inspector) | every painted line ≤ 116 cells | | gap | not_run |
| R-TUI-064.2/2 | … (220×60) | normal | 220×60 | Applied case01 (Inspector) | every painted line ≤ 218 cells | | gap | not_run |
| R-TUI-064.4/1 | Verify the prompt's buttons are one-row chips | normal | 118×54 | Applied case01 (Inspector) | the Format control, Width, `Write file`, `Don't save`: height 1 | | gap | not_run |
| AT-I10-1 | Verify the operator's story: apply from the Inspector tab, see it, export Intel HEX | normal | 118×54; case01 loaded through the Load dialog; the Inspector tab (the default) | the entry 0x8000007C `DE AD BE EF` typed and Add; Apply; Format; `Write file` | no tab chip pressed; the apply line `Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it` shown; after Format the control shows `Intel HEX`, the name box `firmware-patched.hex`, no Width control; status `Saved + verified: firmware-patched.hex — 1 entry applied before this save (0x8000007C)`; the file `firmware-patched.hex` in the work area reads back (Intel HEX reader) with `DE AD BE EF` at 0x8000007C and case01's bytes elsewhere | | gap | not_run |
| AT-I10-2 | Verify an Intel HEX image exported as S19 at 16 bytes per line | normal | 220×60; `firmware.hex` (case01 twin) loaded; the Checks tab shown | the entry 0x8000007C `DE AD BE EF`; Apply; Format; Width; `Write file` | the Format control showed `Intel HEX` first, then `S19`; `Width: 16 bytes/line`; `firmware-patched.s19` written: first line `S0030000FC`, data records `S3` of ≤ 16 data bytes, terminator `S7`; status `Saved + verified: firmware-patched.s19 — …` | | gap | not_run |
| AT-I10-3 | Verify an apply that applies nothing is seen | robustness | 118×54; case01 loaded; Applied once (prompt shown) | Remove the entry; add 0x00000010 `AA`; Apply | a warning notice `Nothing applied` / `Apply: 0 applied, 1 skipped, 0 blocked`; the prompt hidden; the byte at 0x8000007C back to 0x3C | | gap | not_run |
