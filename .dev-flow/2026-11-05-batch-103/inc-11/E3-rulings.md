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
