# Inc 11 — E3 round 1 rulings (2026-11-06T23:33:54-06:00, orchestrator Opus 5.5)

Round 1: architect **FAIL** (1 HIGH, 3 MAJOR, 4 MEDIUM, 5 MINOR, 1 LOW, 2 INFO; READ.52 re-measured 1.02–1.26×, inside the bound); security **FAIL** (5 MAJOR, 6 MEDIUM, 4 MINOR, 1 LOW, 1 INFO; public corpus 0 exceptions, linear). Every finding is **accepted with its fix column**, with these rulings:

| Finding | Ruling |
|---|---|
| E3A-01 HIGH (named kinds other than tags stay UNKNOWN: 8,422 COMPU_METHODs, 4,338 COMPU_VTABs, 144 RECORD_LAYOUTs) | accept: **one builder rule for every named section kind** (the name and long identifier may sit on later lines), in `a2l.py` only; no consumer change. Without it the newly readable tags fall back to identity conversion — a raw value shown as physical, and a symbol encode writing raw = physical. |
| E3A-02 MAJOR (uncapped per-word errors: UTF-16 without BOM 1,003,075; binary 51,810) | accept: a file that holds a NUL byte is refused (one diagnostic); the error list is capped (the fix column's cap, with a "… <n> more" line). |
| E3A-03 = E3S-01 MAJOR (address cut at the pane edge for names of 46+ characters at 118 columns) | accept: the Tag cell is capped (36 cells, the fix column) with a visible `…`; the detail card keeps the full name; cases with long names at 118 and 220 columns. **Visible change:** E5's real Windows Terminal captures (before/after, 118x54 and 220x60) go to the operator with the padding fix. |
| E3A-04 MAJOR (ARRAY_SIZE ignored; 2,070 corpus objects) | accept: a MEASUREMENT's length is its datatype size × ARRAY_SIZE (and × the MATRIX_DIM product where both appear, per the fix column); READ.49's V161 pin changes. |
| E3S-02 MAJOR (a keyword with no argument swallows the next keyword) | accept: a keyword is never an argument; the missing argument is an error and the tag gets no value for that keyword (no address for ECU_ADDRESS). The differential oracle gains this shape (REF shared the bug). |
| E3S-03 MAJOR (D-6 "last wins" unsafe for writes) | accept: **D-6 revised** — when keywords that set an address or a size disagree (duplicates, DATA_SIZE vs LENGTH, ECU_ADDRESS vs the header address), the tag gets no address / no length and an error; agreeing duplicates keep the value. Consistent with the disagreeing-size ruling of E2. |
| E3S-04 MAJOR (nesting past ~990 levels → RecursionError, the app exits) | accept: a nesting cap of 32 with an error; a robustness row: reading an A2L file raises no exception other than OSError. |
| E3S-05 MAJOR (refused lengths come back downstream) | accept: I-11.8 obligations — **Inc 11 removes Inc 2a's MEASUREMENT header fill that re-derives a length the reader refused** (`a2l_definition.py`, Inc 11's 4th source file; Inc 2a merges to `batch-103` before Inc 11's E4); **Inc 6** removes the picker's and "Use parameter"'s `or 1` (a missing length is refused) — PLAN row 6. |
| F-E2-2 / E3A-05 | accept: "header" = the words on the keyword's line; READ.50 and R-A2L-076 reworded. |
| E3A-08 (oracle not independent enough) | accept: the reference compares sections as well as tags; the 226 defect tags get explicit expected values from synthetic reductions, not only REF. |
| E3S-07 (cap on echoed words) and all others | accept with their fix columns; INFO noted. |

**Next:** an Opus correction pass (records and graph; Inc 11's source files become `a2l.py`, `app.py`, `a2l_extract.py`, `a2l_definition.py`), then a round-2 re-check by both reviewers.

## Round 2 rulings (2026-11-07T00:50:01-06:00, orchestrator Opus 5.5)

Round 2: architect **FAIL** (all 16 round-1 findings closed; the named-kind rule names all 8,422 COMPU_METHODs / 4,338 COMPU_VTABs / 144 RECORD_LAYOUTs, identity fallbacks 136,592 → 878; 0 tracked tags change; READ.52 1.38× / 1.31×; new MAJOR **E3A-17**; 1 MEDIUM, 1 MINOR, 4 INFO); security **FAIL** (E3S-02, -04 closed; -01, -03, -05 closed as ruled with residuals; new MAJORs **E3S-18**, **E3S-19**, **E3S-20**; 4 MEDIUM, 1 MINOR, 1 INFO). Accepted with their fix columns, ruled:

| Finding | Ruling |
|---|---|
| E3A-17 = E3S-20 (Address/Length still cut below 100 columns; a 64-bit address cut at 118) | **Address and Length become the first two columns of the tag table and stay fixed** (they never scroll out); their widths fit their longest content, 64-bit addresses included; the Tag cell takes what is left, with its `…` cap. A row: at every width from 80 to 220 columns the Address and Length cells show whole. **Visible change (column order):** the E5 real Windows Terminal captures before/after at 80, 118 and 220 columns go to the operator for approval before the merge. |
| E3S-18 (a refused CHARACTERISTIC length comes back as the layout's element size via `enrich_a2l_tags_with_values`, `a2l.py:2890`) | accept: the enrichment never sets a size the reader refused (no length → no `byte_size`); a case through "Use parameter" and the Check Editor size. |
| E3S-19 (DATA_SIZE vs LENGTH never compared when no datatype size is known) | accept: the two are compared directly whenever both appear; disagreement → no length + error (D-6 revised). |
| Architect's MEDIUM (the pilot's string regex takes ~1 GB on READ.52/3's file) | accept: READ.52 gains a memory clause — the reader's peak memory stays within a stated multiple of the file's size (the fix column's figure, measured); no whole-file regex. |
| all other round-2 findings | accept with their fix columns. |

**Next:** an Opus correction (records and graph), then round 3 by both reviewers on these items only.

## Round-2 correction rulings (2026-11-07T01:16:25-06:00, orchestrator Opus 5.5)

Correction applied (Opus, 27 min): 80 rows, 262 cases + 3 AT, 39 nodes; E3S-18 (no length → no enriched `byte_size`; **visible consequence:** 187 tracked CURVE/MAP tags show blank Raw/Physical in the A2L Explorer until Inc 3a's lengths land — more honest than today's first-element value; shown to the operator with the E5 captures), E3S-19, E3S-21 … -25, E3A-18, -19, -22, -23 applied; READ.52's peak memory ≤ 2× the base reader's. `fixed_columns=2` checked on cachyos-rtx: Address/Length whole 40/40 from 80 to 220 columns (scrolled too) vs 13/40 today.
- **Split accepted:** the tag-table view rows (R-TUI-042a.2 padding, .3 Tag cap, .4 Address/Length first and fixed — E3A-17 = E3S-20) leave Inc 11 for a **new Inc 12 — A2L tag table: no glued or cut values** (`app.py` only; visible change; the operator approves its before/after captures). Inc 11 is the reader only: `a2l.py`, `a2l_extract.py`, `a2l_definition.py`. Inc 12 also owns the open item "at 80–118 columns the capped Tag is cut unmarked — size the cap from the width left".
- **Open in Inc 11:** `3E00` (no number word) still slips past E3S-24 — round 3 checks it.
**Next:** round 3 on Inc 11 (reader items only), and Inc 12's E1 from the moved rows.

## Round 3 rulings (2026-11-07T01:45:35-06:00, orchestrator Opus 5.5) — Inc 11 E3 done

Round 3 (security): **PASS-WITH-NOTES** — E3S-18, -19, -21, -22, -23, -25 closed; E3S-24 open (`ECU_ADDRESS 0x1C2D 3E00` gives 0x1C2D with no error — the symbol entry and "Use parameter" use it); new MEDIUM E3S-27 (BYTE_ORDER fallback), E3S-28 (peak memory 6.7× the base reader's against READ.52's 2×), 1 MINOR, 1 INFO. The architect's only open MAJOR (E3A-17) moved to Inc 12 with its rows; its other findings are closed. **E3 is done for Inc 11**, with addenda applied before E4 (one Opus pass):
- **E3S-24 (address integrity, treated as blocking for the write consumers):** the hex-like surplus rule — a word after an address argument that a number or hex continuation could be (`3E00`, `_4026`, …) is an error and the tag gets no address; cases with each shape.
- **E3S-27:** the fix column (BYTE_ORDER fallback).
- **E3S-28:** READ.52's memory clause holds as 2×: the design reaches it (the fix column's streaming change) or, if measured impossible, the orchestrator rules a restated bound with the measurement — no silent loosening.
- MINOR / INFO: fix columns.
- **Addenda applied** (2026-11-07T02:08:27-06:00, Opus, 23 min): 79 rows (new R-A2L-READ.68), 265 cases + 2 AT, 37 nodes; E3S-24 hex-like surplus words (`0x1C2D 3E00`, next-line `3E00`, `E00`, `2D3E00`, `_4026`, `BIT_MASK 0x0F F0`) → error, no value; E3S-27 BYTE_ORDER outside the four → no address; E3S-28 streaming words: peak memory 1.04–1.19× the base reader (the 19.8 MB corpus file 1.11×, was 6.7×).
- **Ruling on the time of the largest file:** the design model reads the 19.8 MB corpus file in 4.6 s against the base reader's 0.75 s (6×). Real ECU A2L files are often this size, so **R-A2L-READ.52's 1.5× time bound holds for every file, the largest included**: the lexer tokenises each line with a compiled regular expression (C-level), keeping cross-line state only for an open block comment or string; a synthetic 20 MB file of the same shape joins READ.52's cases (the corpus file stays evidence). E4 measures it first; if 1.5× is not reachable the implementer stops and the orchestrator rules with the measurement.
