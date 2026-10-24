# Reconcile 2026-10-23 — follow-ups to the operator's verdict (R-054, R-069, R-006/R-016, R-049)

Read-only research, 2026-10-23, tree at `5cb7618` (another agent had uncommitted edits in
`screens_directionb.py`, `segment_split_view.py`, `styles.tcss` and several `.dev-flow` files; none
of them touch the code paths cited below except `styles.tcss`, which is not load-bearing here).
Probes ran from a scratch directory with the s19env interpreter, `PYTHONDONTWRITEBYTECODE=1`, and
read-only imports of the repo. Nothing was written into the repo except this file.

Scratch probes (not committed):
`C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad\q3\probe_a2l_addr.py`, `...\q3\probe2.py`, `...\q4\probe_checks.py`, `...\q4\probe_btn.py`, `...\q4\probe_run.py`.

---

## Q1 (R-054) — the description of one specific CRC algorithm

**Answer.** It exists. It is the operator's **CRC_F2 draft (FR1–FR9) of 2026-06-16**, recorded
verbatim in `.dev-flow/2026-06-16-batch-12/01-requirements.md:150-162` (commit `71cef36`; vault copy
under `dev-flow-batches/2026-06-16-batch-12/`). That draft is the algorithm that the Operations
modal (`x`) implements today. It names the parameters (polynomial, init, reverse, final XOR, ranges,
output addresses) and "CRC32 IEEE". It does **not** state real per-firmware polynomial or address
values. At the Phase-0 Q&A the operator ruled that real values stay outside the repo, so the repo
holds only a dummy template with fake ranges. The operator confirmed on 2026-08-06 that this is "a
known algorithm" that the CRC Designer must reproduce, and asked for it to be saved as a CRC
Designer config file (harvest line 409, session `2628d42b`). Cambio6 (vault
`assets/Refactor_10_11_2026/Refactor, Cambios.md`) asked for it again: "en algún punto di una
descripción detallada de un algoritmo CRC ... crea el archivo JSON para poder correrlo". That file
was never made. It is backlog `S-10` of the BATCH-81 charter (`.dev-flow/BACKLOG-CODE.md:854`),
which was never run. R-010 tracks it.

**Recovered parameters.**

| Parameter | Value | Source |
|---|---|---|
| Algorithm family | CRC-32 "IEEE" (= CRC-32/ISO-HDLC, the zlib/PKZIP CRC-32) | FR5 (`batch-12/01-requirements.md:158`); glossary `:95` |
| Width | 32 bits | FR5; `operations/crc.py:2-13` |
| Polynomial | `0x04C11DB7` (normal form) | Glossary `:95`; `operations/crc.py:41` `DEFAULT_POLYNOMIAL` |
| Init | `0xFFFFFFFF` | `:95`; `crc.py:42` |
| Reflection | `reverse=true` = refin **and** refout (the operator's "reverse bit order before the CRC operation", ruled as standard zlib refin/refout at Phase 0) | FR1 `:154`; Phase-0 Q&A `:171`; `crc.py:43`, `:138-150` |
| Final XOR (xorout) | `0xFFFFFFFF` | `:95`; `crc.py:44` |
| Check value ("123456789") | `0xCBF43926` | `docs/crc-algorithm-designer/01-requirements.md:131`; `crc.py:124` doctest |
| Ranges to compute over | One or more `(start, end)` hex ranges, half-open `[start, end)`. Bytes are sorted by ascending address. Segments split on any gap. **Gaps add no bytes** (no fill). One CRC state runs across the segments of a region **without reset** | FR1–FR4, FR7, FR8 (`:154-161`); `crc_config.py:98-105`; `crc.py:154-269` |
| Where to store | One output address per range ("each range has an output address"). The op also accepts `groups` (several ranges → one output) with `output_bytes` 1/2/4/8. Fewer than 4 bytes keeps the low-order bytes and gives a truncation warning | FR1 `:154`; `crc_config.py:70-73`, `:126-154`; `crc.py:846`, `:887` |
| Store endianness / width | **4 bytes, little-endian, fixed** (`crc & 0xFF` at `addr`, then `>>8` at `addr+1` ...) | Phase-0 Q&A `:171`, glossary `:98`; `crc.py:46-48` `LE32_WIDTH` "NOT parameterized" |
| Two-stage finish | (1) Compare the computed CRC with the value stored at the output address (non-mutating check). (2) After the operator confirms, write it and emit a modified S19 | FR9 `:162`; `screens.py:1910-1994` (confirm modal) |
| Real ranges / addresses | **Not recorded anywhere.** Repo carries only fake ones by design | `batch-12/01-requirements.md:90`, `:195`, `:242`; `crc_config.py:41-45` ("FAKE poly / init / ranges / output-addresses only") |

**Where these values appear.**

- `.dev-flow/2026-06-16-batch-12/01-requirements.md:95, 98, 145, 150-162, 171` is the primary source (operator draft + Phase-0 rulings).
- `s19_app/tui/operations/crc.py:39-48` holds the defaults and the fixed LE32 codec. `:82-151` is `crc32_stream`: the default params take the `zlib.crc32` fast path, other params run a bitwise loop.
- `s19_app/tui/operations/crc_config.py:41-66` `DUMMY_CONFIG_TEXT` is the text the Operations modal pre-fills (`screens.py:2109`). It is byte-identical to `examples/crc_config.example.json`. Its ranges are dummies: `0x10000–0x20000 → 0x1FFFC`, `0x20000–0x30000 → 0x2FFFC`, group `0x30000–0x34000 + 0x40000–0x42000 → 0x42000`.
- `s19_app/tui/operations/requirements/REQ-crc.md` is the co-located requirement for the op.
- `docs/crc-algorithm-designer/01-requirements.md:122-158` (commit `84180b4`, 2026-07-20) holds the same algorithm as a Designer **template** (`CRC-32/ISO-HDLC`, `check 0xCBF43926`). Its **job** example uses illustrative ranges `0x8000–0x8008 + 0x8010–0x8018`, `join: fill`, `pad 0xFF`, output `0x8018`, `store_width 4`, `store_endianness little`. Those values are design examples, not the operator's.
- `s19_app/tui/operations/crc_kernel.py:395-401` `PRESETS` holds the Designer's seed catalogue. CRC-32 and its siblings are there. There is no saved `.crc.json` of the Operations algorithm, and none exists in the repo or in `C:\Users\jjgh8\.s19tool`.
- `.dev-flow/BACKLOG-CODE.md:854` is charter S-10: "encode the modal's known CRC as a saved Designer `.crc.json` (width 32, poly `0x04C11DB7`, init/xorout `0xFFFFFFFF`, refin=refout=true)". It carries an **open decision**: the Operations config allows several regions with one output each, but the Designer serializes a single output.

**Not found.** No message in the transcript harvest (1060 operator messages, 2026-07-14 → 10-23) gives
concrete polynomial or address values. Checked: grep `crc|polin|polyn|endian|checksum`. The CRC
messages there are the Designer brief (line 170: "memory range or ranges, the polynomial, the
operation (XOR), the fill of gaps, the endianness, the start and finish values") and a review of the
Designer infographic (line 174). Neither is a specific algorithm. The 2026-06-16 draft predates
the harvest window, so it is known only through the batch-12 file. `git log --all -S` for the
polynomial finds only `0x04C11DB7`. No other polynomial was ever committed in a JSON file. The
vault `assets/Cambios_10_12_2026/Cambios.md` has no CRC content.

**What this means for R-054 / R-010.** The operator remembered the parameters correctly: ranges,
store location, polynomial and endianness. The algorithm can be encoded today as a Designer template
(`CRC-32/ISO-HDLC`) plus a job with `store_width 4`, `store_endianness little` and `intra_gap skip`.
The real ranges and output addresses must come from the operator's own config file. The single
open point is the multi-output decision above.

---

## Q2 (R-069) — the format the operator delivered for showing A2L parameter definitions / curves

**Answer.** The only delivered format found is **page 3 of the handwritten scan**
`G:\My Drive\Scan_20261018_153449.pdf` (4 pages, scanned images, no text layer; pages were rendered
to read them). Page 3, "Request", says that A2Ls have custom data types the app does not recognise,
which matters most for patching. It gives this layout:

```
/begin RECORD_LAYOUT <name> \n
  FNC_VALUES <number> <datatype> <ROW_DIR or COL_DIR> DIRECT \n
  NO_AXIS_PTS_X <number> <number type> \n
  NO_AXIS_PTS_Y <number> <number type> \n
/end RECORD_LAYOUT
```

(The `\n` marks are the operator's own line-end notation on paper.) Page 4 has the enhancement this
format supports. "ENHANCEMENT — A2L Parameter description using data from A2L and S19/HEX. There
are tables and functions that depict response curves, maybe there are more than those behaviors."

So the "format" defines the **record layout**: the function values, then the per-axis point counts
for X and Y. That is the information needed to cut a CURVE (1 axis) or MAP (2 axes) out of the image.
It is not a mock-up of a screen. No other format was found. Checked: vault `assets/` (both Cambios
files; no image assets present beside them), `design/`, the transcript harvest (grep
`RECORD_LAYOUT|AXIS_PTS|CURVE|curva|curve|FNC_VALUES`: only a 2026-07-20 batch-56 brief about
alignment padding), `C:\Users\jjgh8\Downloads` (no A2L or curve file since 2026-09-25), and
`prototypes/` (no A2L curve prototype). The verdict note on R-069 says "No, las curvas sirven, además
entregué un formato". The note answers "are the tables enough?" and reads two ways: "no — drawn curves are useful"
or "the (text) curves work". **Orchestrator: ambiguous; the operator is asked to confirm.**

**What the app does with it today.**

- **Layout recognition (scan p3 → R-067, DONE).** `47e0cc9` (batch-96 feature C) added
  `_walk_record_layout_components` (`s19_app/tui/a2l.py:1368`). It walks FNC_VALUES / NO_AXIS_PTS_* /
  AXIS_PTS_* with aligned offsets, accepts a standalone `DIRECT`, and counts RESERVED.
  `_extended_kind_anchor` (`a2l.py:562-586`) keeps vendor CHARACTERISTIC kinds that use those
  layouts (R-065).
- **Description (scan p4 → R-069).** On the A2L Explorer, `d` (`app.py:1407`, action `:6753`; on the
  A2L window key bar, `window_help.py:770-771`) opens `CurveDescriptionScreen`
  (`s19_app/tui/a2l_describe.py:31`). `describe_curve_tag` (`a2l.py:2691`) builds it.
  `render_curve_description` (`a2l.py:3013`) renders it as fixed-width text:
  - Header: kind, name, long identifier, `address 0x…`, byte size, unit and limits, conversion type,
    COMPU_METHOD name and its description.
  - One line per axis: kind, max points, external flag, unit.
  - **Single-axis CURVE:** an `x → y` point table in physical units, `(!)` on points outside the
    tag's limits, and a sparkline `y shape:` row.
  - **MAP (2 axes):** the axes, then the values as **one flat comma list**. The note says "a 2-D grid
    view is not part of this description yet" (`a2l.py:2938-2942`).
  - Scalars get a "not a CURVE/MAP" header. An unresolved layout, an unresolved axis or missing
    image bytes give a status line, never invented data.
- **Declared gaps** (`PENDIENTES-batch96.md:32, 41-42`): no 2-D MAP grid, FLOAT16 not decoded, and
  no encode for external axes.

**Gap against the operator's format.** Page 3 shows 2-axis layouts (NO_AXIS_PTS_X **and** _Y). A
2-D MAP still shows as a flattened list. If the operator wants maps shown like curves, the open item
is the **MAP grid view** (already a declared batch-96 follow-up). It is not a plotted curve.

---

## Q3 (R-006 addition + R-016) — A2L addresses with extra characters, once a literal `\n`

**Answer.** In every rendering path found, an A2L address reaches the screen **only as an integer
formatted `0x{addr:08X}`, or as `n/a`**. Raw address text is never displayed. A trailing comment,
CR/LF, tab, suffix or literal `\n` after the address token therefore **cannot** carry into the
address cell. Each of those cases makes `int(x, 0)` fail, and the cell shows `n/a`. Two
integer-formatting cases **do** produce extra characters:

1. **Addresses above 32 bits.** `:08X` pads but never truncates. `0x180001234` renders as 11 chars
   and `0x8000001234` as 12, which is one or two extra characters. This is the original field-audit B3
   hypothesis. batch-38 added the `A2L_ADDRESS_EXCEEDS_32BIT` **warning**
   (`services/validation_service.py:177-245`), but the cell still shows the long value.
2. **Negative addresses.** `int("-0x10", 0)` is accepted. It renders as `0x-0000010`, a stray `-`.
   No warning fires, because the check is only `address <= 0xFFFFFFFF`
   (`validation_service.py:225`).

**No code path was found that puts a newline into an address.** The integrity investigation's
H-1…H-10 **do not cover this**. The nearest are H-5 and H-6 (A2L encode) and H-9 (MEMORY_SEGMENT
names), and none parses or renders addresses. **R-016 needs its own item.** It should keep a "needs
a repro" arm for the `\n` sighting.

**Code path.**

- Read: `build_section_tree` opens the file in text mode with `encoding="utf-8", errors="replace"`
  (`a2l.py:176`). Universal newlines: CRLF and lone CR become line breaks.
- CHARACTERISTIC header: `assemble_characteristic_header` → `_flatten_body_tokens` (`a2l.py:433-434`)
  joins body lines with `"\n"` (`_A2L_LINE_SENTINEL`, `:328`), strips `/* */` and `//` comments
  (`_strip_a2l_comments`, `:331`), splits on whitespace while respecting quotes, then
  `int(params[1], 0)`; on `ValueError` the address is `None` (`a2l.py:543-546`).
- MEASUREMENT / body keywords: `stripped.split()` then `int(parts[1], 0)` for `ECU_ADDRESS`, and
  `None` on error (`a2l.py:2372-2378`). Comments are **not** stripped on this path, so
  `ECU_ADDRESS 0x…/*x*/` gives `None` (`n/a`).
- Display sites, all `f"0x{addr:08X}" if isinstance(addr, int) else "n/a"`: the A2L table cell
  `app.py:12516`; the A2L summary text `a2l.py:3328`; the curve description `a2l.py:3029`; the status
  line `app.py:8918`. The name cell removes `\n` (`app.py:12518`). The section-tree line in the
  summary prints the raw `/begin` meta (`a2l.py:3290-3292`), which is the only place raw A2L text
  near an address is shown.

**Probe results** (`q3/probe_a2l_addr.py`, `q3/probe2.py`; crafted A2L files in scratch):

| Case (address token) | Parsed | Displayed |
|---|---|---|
| plain, CRLF file, tab after, `/* */` spaced or glued after (CHARACTERISTIC), NBSP after, quoted `"0x…"` | `0x12345` | `0x00012345` (clean) |
| `0x…//c` glued, `12345h`, `0x12345UL`, zero-width space after, `0x…\n` (literal backslash-n) glued, `ECU_ADDRESS 0x…/*x*/` | `None` | `n/a` |
| `0x8000_1234` (underscore) | `0x80001234` | clean (Python accepts `_`) |
| Arabic-Indic or full-width digits `١٢٣` / `１２３` | `123` | `0x0000007B`. **Silent reinterpretation**: `int()` accepts any Unicode decimal digit |
| `0x180001234` / `0x8000001234` | > 32-bit | `0x180001234` / `0x8000001234`: **+1 / +2 chars** |
| `-0x10` | `-16` | `0x-0000010`: **stray `-`**, no warning |
| Header on the `/begin` line (`/begin CHARACTERISTIC C "d" VALUE 0x12345 RL …`) | `None` | `n/a`. The section-tree line still shows the address inside the raw meta |
| Description with an ASAP2 `\n` escape (`"a\nb"`) | address clean | the section-tree line shows the literal `"a\nb"` |

`examples/` corpus: 234,648 tags in 34 A2L files. **0 odd renders.** `software_a.a2l` has 10,538 of
13,990 tags with no address, and `software_b.a2l` has 67 of 67. These are MEASUREMENTs with no
`ECU_ADDRESS` line (verified in `software_b.a2l:1021-1053`), so they are legitimate `n/a`.

**Two plausible sources for the `\n` sighting, both unconfirmed:**

- The A2L summary's section-tree line prints raw `/begin` meta. A description with an ASAP2 `\n`
  escape followed by an address on the same `/begin` line would look like an address with `\n` next
  to it.
- Hex rows in the A2L viewer that wrap to two lines (R-009).

Neither was reproduced against an operator file. Side finding (not asked, unverified against the
ASAM spec text): a CHARACTERISTIC whose whole header sits on the `/begin` line loses its address.

**Suggested item (own row, merged R-016 + R-006 addition):**

- Reject or flag addresses that are negative or above 32 bits at parse. Do not display them as
  `0x-…` or as 9+ digits without a marker.
- Accept only ASCII hex/decimal address tokens.
- Strip comments on the `ECU_ADDRESS` path the same way the header path does.
- Keep a needs-repro arm: ask the operator for the A2L line and the screen where the `\n` appeared.

---

## Q4 (R-049 addition) — "the Checks window seems to do nothing"

**Answer.** This is the rail entry **"Checks"** (`☑`/`C`, key `9`; `rail.py:89`, `app.py:1432`).
It is not the **Check Editor** (`✔`/`K`, key `=`, inserted by batch-94 at `app.py:230-236`). The
operator's impression is correct for a normal session. Checks is a **read-only mirror of the last
check run started from the Patch Editor** (`checks_view.py:1-9`), and nothing in a normal session
starts one. With an S19 and an A2L loaded, it shows only `Pass 0 / Fail 0 / Uncheck 0 ░░░░░░░░` and
"No check run yet — run checks from the Patch Editor."

**What it does, step by step (from the code).**

1. `action_show_screen('checks')` calls `update_checks_view` (`app.py:~9280-9324`).
2. That reads `self._change_service.last_check_result`. If it is `None`, the view calls
   `GroupedChecksPanel.render_no_run()` (`checks_view.py:389-412`, text at `:310`). Otherwise it
   groups `check_display_rows()` as fail → uncheckable → pass, with per-row address and A2L/MAC
   symbol (`checks_view.py:313-387`), and fills the aggregate strip.
3. `last_check_result` is set in exactly one place, `ChangeService.run_checks`
   (`services/change_service.py:1766-1817`). It is called only by the Patch Editor's `run_checks`
   action (`app.py:3262-3275`).
4. That action is fired only by the **Run checks** button (`patch_checks_run_button`,
   `screens_directionb.py:5146-5149`, `:5797`). The button sits inside the Patch Editor's
   **"Checks" tab** (`patch_win_checks`, `:4439`, `:5110`). Until that tab is opened, the button has
   a 0×0 region (probe `q4/probe_btn.py`: the parent `patch_win_checks` has `display: none`).
5. The run needs a **`kind: "check"` document loaded in the Patch Editor**. With the default
   (change-set) document, the run is blocked: "Checks: not run — this is a change-set (kind
   'change') …". The rail view then switches to "No check entries to group."
6. The Check Editor (`=`) writes and validates `.chk.json` files but **cannot run them**. This is the
   no-apply/no-run doctrine (`CHECK_EDITOR_ACTIONS = {"write_doc", "validate_doc"}`, `app.py:240`).
   Nothing connects the Check Editor to the Checks window.

**Inputs needed before it shows anything:**

- a loaded image;
- a check-kind document loaded **into the Patch Editor** (dropdown or path);
- Patch Editor → **Checks** tab → **Run checks**.

Headless confirmation (`q4/probe_run.py`, `case_01_basic_valid` S19 + A2L, 220×60):

- Steps A/B (no file; then S19 + A2L): the no-run text only.
- Step E (Run checks with the default doc): "No check entries to group."
- Step F (load a 3-entry `.chk.json` into the Patch Editor's service, then Run checks): the window
  fills with `Pass 1 / Fail 1 / Uncheck 1`, then grouped rows such as
  `0x80000010-0x80000010 expected [FF] actual [03] -> fail` / `CAL_BLOCK_A` and
  `0x10-0x10 … -> uncheckable (range outside the loaded image [outside])`.

So the window works, but only after a three-step route through the wrong editor.

**Background that bears on the choice.** Cambio3 (vault `Refactor, Cambios.md`) says: "Esto es para
la actual ventana de Check, que será Check Editor". The operator's intent was that the current Checks
window **becomes** the Check Editor. batch-94 instead added a new Check Editor and left Checks in
place, still pointing at the Patch Editor.

**Options.**

| Option | What changes | Consequences |
|---|---|---|
| **A. Remove the Checks rail entry.** Results stay in the Patch Editor's Checks tab, the A2B report (check docs load there per Cambio3) and the flow CHECK block | Rail 12 → 11 entries. Key `9` is freed. Delete or hide `_compose_screen_checks`, `checks_view.py` and the mirror refresh | Matches Cambio3's intent (one check window, the editor) and the R-049 view/build/execute regrouping. Loses the larger grouped view with hex-peek. Tests pinning the 12-entry rail census and the CHECKS screen (batch-49 R-TUI-084) must be retired |
| **B. Make Checks the "execute" window for check docs.** Give it its own document picker (the `.chk.json` files in `checks/` / `patches/`) and a **Run** button against the loaded image. Remove Run checks from the Patch Editor | Checks becomes the execute half of Check Editor (build) → Checks (run). The Patch Editor loses its Checks tab | Fits R-049's view/build/execute split exactly, and the window then does something by itself. It is a new feature that needs a prototype round. The batch-94 rule that the Check Editor never runs stays intact |
| **C. Keep it as a mirror, but make it honest.** Change the empty text to name the real route (load a `.chk.json` in the Patch Editor → Checks tab → Run checks), or add a "Run in Patch Editor" jump | Copy and one link | Cheapest. It still needs two editors for one task, contradicts the batch-94 split, and the operator's "does nothing" impression largely remains |

Recommendation for the operator's decision: **B** if checks should be runnable outside flows, **A**
if flows and A2B are enough. **C** only as a stopgap.
