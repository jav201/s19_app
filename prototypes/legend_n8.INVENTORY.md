# N8 — Per-view informational-element inventory (design input)

THROWAWAY design input for N8 (comprehensive per-view Legend). Condensed from a
code-grounded sweep of each rail screen. Each line: **element** — meaning
(source hint). This is the backbone the enriched Legend must explain. Views MAC
+ Memory Map appended when that sweep lands.

## Workspace (`#screen_workspace`)  — ~30 elements

**Memory strip `#ws_memstrip`** (one glyph per address cell; glyph carries meaning, colour is secondary — C-10):
- `·` constant/padding (grey) · `░` low-entropy structured/table (green) · `▒` medium calibration (amber) · `▓` high code/random (red) · `╱` gap/unmapped · fallback `█` valid(green)/invalid(red)/gap(grey) when no entropy.

**Loaded panel `#loaded_panel`** (3 slots + unload-all):
- `S19` slot: `firmware.s19  1.2 KiB · 3 rng` = name · mapped byte size · contiguous range count.
- `MAC` slot: `checks.mac  5 records` = name · MAC record count.
- `A2L` slot: `model.a2l  42 tags` = name · A2L tag count.
- `(none)` = that artifact not loaded · `[u]` per-slot unload · `[U]` unload all.

**Left pane — Data Sections** (per contiguous range):
- `✓ 0x00000000 – 0x000004FF  1.2 KiB ▒` = validity marker · start addr · inclusive end · humanized size · dominant band glyph.
- Row colour green `sev-ok`=valid / red `sev-error`=invalid.
- Coverage micro-bar `█░░░░░░░` (8 cells) = this range's size vs largest range.
- `... 37 more ranges (see log) ...` truncation (>200).
- `MAC out-of-range @ 0x0000ABCD` (amber) = MAC address outside loaded ranges; `... 12 more … ...` (>50).
- `Workarea Files` list = file names in workarea temp; `Load project (p)` button.

**Center pane — Hex View**: `0x00001000  DE AD BE EF … 00  |.....|` = addr · 16 byte values (blank=unmapped) · ASCII gutter (`.`=non-printable). Search ASCII / Goto 0xADDR controls.

**Right pane — Context / Coverage Stats**:
- `Coverage: 87.50%` (or `—`) = % of image span covered by valid ranges.
- `Ranges: 3` = total ranges · `Errors: 0` (ERROR issues) · `Warnings: 2` (WARNING issues).
- `Loader 0 err · ⚠4 OOO · Entry 0x00000000` = loader error count (red if >0) · out-of-order S19 record count (yellow if >0) · S7/S8/S9 entry-point (`Entry —` when absent, e.g. HEX).
- A2L summary window header `A2L summary lines 1-20 / 142` + body; `No A2L loaded.` empty state.

**Empty state**: `No file loaded - press Ctrl+L (or 'l') … 'p' … project.`
**Status bar** (under every screen): `#status_text` last-action · `#progress_bar` · up to 4 log-tail lines.

## A2L Explorer (`#screen_a2l`)

**DataTable — 16 columns**: `Tag` (name + in-image glyph `✓`/`·`) · `Address` (0x8-hex) · `Length` (bytes, `n/a`) · `Source` (assigned/formula) · `Raw` (decoded int/float) · `Physical` (engineering value) · `InMem` (yes/no/n/a) · `Region` (flash/ram/unknown) · `Limits` (lo..hi) · `Unit` (rpm/degC) · `Bits` (bit mask) · `Endian` (MSB_FIRST) · `Virt` (yes/no) · `Func` (FUNCTION group) · `Access` (read_only/calibratable) · `Dtype` (UWORD/FLOAT32_IEEE).
**Summary line**: `Page 2/7 | tags 201-400 / 1394 (page size 200; +/- to change) · 312 in image` (last = green in-image counter).
**Filter row**: text filter + `Field: <name>` (targets one field) + `All`/`Invalid`/`In-Memory` mode buttons + `Find next` + `Page Prev/Next`.
**Detail card** (adds beyond table): `desc` · `unit`/`conv` · `layout` (RECORD_LAYOUT) · `byteorder` · `limits` · `display_identifier`.
**Row colours (Red/Green/White/Grey)**: Red=schema/structural fail OR schema_ok False · Green=memory-checked + in image · White=valid, not image-backed · Grey=not memory-checked / no primary image.
**Parsed-but-not-shown (~10)**: char_type, conversion_status/error, value_outside_limits, decode_error, matrix_dim, symbol_link, axis_meta, raw_bytes/missing_ranges/overlap_conflict — candidates the legend could mention as "diagnostics in the detail/log, not the table".

## Issues (`#screen_issues`)

**Severity strip** `Errors 3 ███░░  Warnings 1 █░░░░  Info 2 ██░░░` = whole-list distribution + proportional micro-bars (RED/YELLOW/CYAN).
**Filter row**: `Issues: All` / `Errors` / `Warnings` (no Info button — Info only under All) + `Legend`.
**Grouped list** (order ERROR→WARNING→INFO): group header `✗ ERRORS (3)` / `⚠ WARNINGS (1)` / `• INFO (2)` (count = whole filtered list). Issue row = **code chip** · **detail** (`symbol · 0xADDR · message`) · **related** (`a2l, mac, s19`). Notes: `No validation issues to group.` / `More issues on other pages — use PgUp/PgDn`.
**Summary**: `total=6 | errors=3 | warnings=1 | info=2 | filter=all | page 1/1 rows 1-6/6`.
**Hex Peek**: ±6 rows around the selected issue's address; `(issue has no address …)`.
**17 issue codes** (chip values):
- MAC: `MAC_PARSE_ERROR`, `MAC_EMPTY_NAME`, `MAC_INVALID_ADDRESS`, `MAC_DUPLICATE_NAME` (ERROR); `MAC_DUPLICATE_ADDRESS` (classified E/W/I).
- A2L: `A2L_STRUCTURE_ERROR`, `A2L_INVALID_ADDRESS`, `A2L_DUPLICATE_SYMBOL` (ERROR); `A2L_UNRECOGNIZED_BLOCK`, `A2L_BROKEN_REFERENCE` (WARNING).
- Cross: `CROSS_MAC_S19_OUT_OF_RANGE`, `CROSS_MAC_S19_OVERLAP_AMBIGUOUS`, `CROSS_A2L_S19_OUT_OF_RANGE`, `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` (WARNING); `TRIPLE_NAME_ADDRESS_MISMATCH` (ERROR); `CROSS_MAC_ONLY_SYMBOL`, `CROSS_A2L_ONLY_SYMBOL` (WARNING).
**Colours**: Errors=Red · Warnings=Pale-yellow · Optional-info=Cyan.

## Checks (`#screen_checks`)  — read-only mirror of last Patch-Editor check run

**Aggregate strip**: `Pass 2 / Fail 1 / Uncheck 1  ████░░░░` (bar = passed/total, green).
**Grouped list** (order FAIL→UNCHECKABLE→PASS): header `✗ FAILED (1)` / `◐ UNCHECKABLE (1)` / `✓ PASSED (2)`. Row detail: `0x8000-0x8003 expected [DE AD BE EF] actual [DE AD BE EF] -> pass`; uncheckable appends `(reason)`; linkage cell = matching MAC/A2L symbol. States: `No check run yet — run checks from the Patch Editor.` / `No check entries to group.` / `More check entries … see the Patch Editor.`
**Result vocab**: `✓ pass` (green) · `✗ fail` (red) · `◐ uncheckable` (yellow) · `·` no-result. No severity filter, no dedicated legend button, no "Checks" block in LEGEND_TABLE today.
**Hex Peek**: bytes around selected entry.

## Memory Map (`#screen_map`)  — entropy-band view (NOT a validity map)

**Header**: `Entropy bands - 7 region(s), 262144 B mapped`; empty states `No file loaded …` / `No entropy detail for this image.`
**Band bar `.map-band-bar`** (proportional strip, one seg per merged run; glyph repeated, coloured by band). 4 bands (bits/byte, half-open, boundary→higher band; window=256B):
- `·` constant/padding `[0,1)` grey `#6b7280` = padding/fill
- `░` low `[1,5)` green `#5fb98a` = structured/tables
- `▒` medium `[5,7.2)` amber `#d9a35b` = calibration/data
- `▓` high/random `[7.2,8]` red `#e06c75` = code/compressed/random
- `╱╱╱` gap hatch = unmapped gap between runs (NOT a band).
**Address ruler**: 5 ticks `80000000 … 8000FFFF` at 0/25/50/75/100% of span (8-hex, no `0x`).
**Region list** (clickable): `░ 0x80000000  256 B  ██░░  3 sym  low ↵` = band glyph · start addr · size · size-microbar(4) vs largest · symbol count · band label · `↵` open-in-hex.
**Band legend `.map-band-legend`** (always all 4): `· constant/padding — padding / fill` etc.
**"At a glance"**: histogram per occupied band `░ low 4 ████ 66%` (glyph·band·count·6-cell bar·% of regions); **sparkline** ` ▁▂▅█` 24-col entropy profile, 9-level ramp `" ▁▂▃▄▅▆▇█"` (0≈none→8≈max), band-coloured.
**Coverage stats** (7): `Coverage: 98.44%` · `Bytes covered` · `Valid ranges` · `Invalid ranges` · `Gaps` · `Largest gap: N bytes` · `Total issues`.
**Region inspector** (on click): `Status: VALID/INVALID/GAP` · `Cell: 0x…-0x…` · `Region: 0x…-0x… (N bytes, valid)` (+A2L symbol) · `N issue(s)` list · `Size` · `Dominant band: ░ low` · `Peek @ 0x…:` ≤3 hex rows. Pre-select hint: `Click a region row to inspect it and jump to the hex view.`

## MAC (`#screen_mac`)

**Coverage strip**: `MAC→S19 1 of 2 █████░░░░░ · A2L↔MAC 3 matches` = MAC addrs in image (count+green bar) · # A2L↔MAC addr matches.
**DataTable — 8 columns**: `Tag` (status glyph + name) · `Address` (0x8-hex/`n/a`) · `InA2L` (yes/no) · `InMem` (yes/no/n/a) · `Status` (OK/OUT_OF_IMAGE/NO_A2L/NOT_IN_A2L/NO_ADDR/ERR_PARSE/A2L_ADDR_MISMATCH) · `SourceLine` (1-based .mac line) · `ParseErr` (diagnostic) · `A2LMatch` (`section:name` of best A2L tag).
**Tag status glyphs**: `✗` red=parse error · `⚠` orange=out-of-image (valid but addr not in S19) · `✓` green=in image · `·` grey=not image-checked (MAC-only/no primary — deliberately not green).
**Status→severity→row colour**: ERR_PARSE/A2L_ADDR_MISMATCH/NO_ADDR=ERROR(red) · NOT_IN_A2L=WARNING(orange3) · OUT_OF_IMAGE=INFO(white) · NO_A2L=NEUTRAL(grey70) · OK=OK(green).
**Summary**: `Page 1/3 | rows 1-50/120 … Total=120 Verified=98 Invalid=4 Neutral=10 NameInA2L=110 OutOfMem=6 ParseErrs=2` + `Coverage MAC->S19=95% A2L->S19=88.5% A2L<->MAC=91.7%`. Empty: `No MAC loaded.`/`No MAC records parsed.`
**Legend words (modal)**: Red=parse fail/invalid name-addr/A2L↔MAC mismatch · Pale yellow=warning (symbol-only-in-MAC, dup-addr alias, overlap) · Green=exact name+addr match · White=structurally valid, not cross-confirmed · Grey=no A2L/no context.
**Hex overlays**: MAC-addr byte = bold orange3 (`#d9a35b`) · search/goto focus = bold yellow. (Interaction highlights, NOT severities.)

## ⚠ Cross-cutting notes for the legend author
- **Bands ≠ severities**: the Memory-Map 4 `band-*` colours are an ENTROPY domain, separate from the `sev-*` severity domain. Two different legends.
- **Two colour pipelines**: Memory-Map bands + MAC *legend words* come from CSS classes; but MAC *DataTable rows/strips/overlays* are painted by INLINE Rich styles (`green`/`red`/`orange3`/`white`/`grey70`) — which is why a MAC WARNING row renders **orange** while the legend calls it **"Pale yellow"**. The N8 legend should reconcile/explain this (say what the row actually looks like).
- **Glyph carries meaning, colour is secondary** (C-10 colour-blind accessibility) — every band/status has a distinct glyph.
