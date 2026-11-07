
## Round 2 (TIMESTAMP)

Re-review of the round-1 correction (`git diff 1bc0d686 HEAD -- .dev-flow/2026-11-05-batch-103/inc-11/`, HEAD `0b0a7239`: 80 rows, 249 cases + 3 AT, graph 37 nodes), with `E3-rulings.md` as the authority. Product tree unchanged (`e07fb00`). Reviewer: E3 architect (Opus 5.5), 2026-11-07.

**Runs (cachyos-rtx, clone `e07fb00`, 0 changed files before and after every run; Python 3.11.18, textual 8.2.8; HOME under `/tmp/b103-e3-11-A2/zq_iso_user`; no display, no clipboard, stdin closed; corpus files sha256-checked against the manifest, read only, nothing copied; derived temp files deleted after each read).** Scripts and transcripts: runner `/tmp/b103-e3-11-A2/{scripts,out}/`, copies in `C:\Users\jjgh8\AppData\Local\Temp\claude\107abb51e32da120\c57f44a4-8a42-42ee-9fb3-80f699575124\scratchpad\e3a11r2\` (counts only, no file text, no object names). The orchestrator may copy them into `inc-11/evidence-e3/`.
- `e3a2-named.py` — the named-kind rule (READ.54, DE-3 revised) modelled in E1's CANON emit (CANON1 = DE-3 before, CANON2 = DE-3 revised), read by the e07fb00 line readers; truth = REF's own words. Corpus and the 35 tracked files.
- `e3a2-followup.py` — why the remaining RECORD_LAYOUTs give no FNC_VALUES datatype; an independent REF count, on the 35 tracked files, of the tags on which a rule the correction added would fire.
- `e3a2-cap.py` — the real A2L Explorer, headless, `cell_padding=1` and R-TUI-042a.3's cap (the first cell's name replaced by 16 + `…` + 17 cells; nothing else changed), names of 34 … 100 characters at 10 widths; `cap 0` = the E2 design.
- `e3a2-time.py`, `pilot3.py` — round 1's READ.52 model plus the correction's per-line, per-section and per-tag rules; `e3a2-mk-e3s14.py`, `e3a2-strmem.py` — READ.52/3's 200,000-line string.

### Verdict: VERDICT

SUMMARY

### Round-1 findings

| Id | Round 1 | Round 2 | Evidence |
|---|---|---|---|
| E3A-01 | HIGH | **closed** | R-A2L-READ.54 (`01-requirements.md:180`), DE-3 revised (`graph-inc11.md:17`, `:273`). Re-measured over the corpus (`e3a2-named-transcript.txt`), sections whose `/begin` stands alone, CANON1 → CANON2: COMPU_METHOD named 0 → **8,422 of 8,422**; conversion type, coefficients and table reference equal to REF 0 → 8,422; the decode of raw 5 equal to REF's 0 → 8,422. COMPU_VTAB named 0 → **4,338 of 4,338**; entries equal to REF on the 4,023 written several words per line (the 315 written one word per line: E3A-20). RECORD_LAYOUT named 0 → **144 of 144**; FNC_VALUES datatype 53 → 91; the other 53 all start with AXIS_PTS_X, the base first-line rule, as 937 of the 2,867 layouts named on their `/begin` line do (`e3a2-followup-transcript.txt`). AXIS_PTS 751, FUNCTION 4,522, GROUP 531, MEMORY_SEGMENT 57, INSTANCE 10, MODULE 15, PROJECT 6, UNIT 5, COMPU_TAB 2: all named. Tags whose conversion names a method: identity fallback **136,592 → 878** of 240,533 (878: below). 0 sections of a named kind whose first run follows a child section. Memory segments: 0 files differ between CANON1 and CANON2 (corpus and tracked) |
| E3A-02 | MAJOR | **closed** | R-A2L-READ.55 (`:144`, NUL refusal, UTF-16 without BOM and binary in its threshold), READ.56 (`:145`, cap 100 + `… <k> more parse errors`), `_CappedErrors` (`graph-inc11.md:475-482`), the NUL test on every non-tier-1 line (`:229`). Residual: E3A-19 (MINOR) |
| E3A-03 | MAJOR | **closed as ruled** (118 and 220) | R-TUI-042a.3 (`:261`), `_build_a2l_table_cells` (`graph-inc11.md:718-727`). Real Explorer, headless (`e3a2-cap1-transcript.txt`): names of 46, 48, 50, 54 and 100 characters paint `0x1C2D3E00` and `2266` whole at 110, 118, 130, 160 and 220 columns; at 100 the address whole and Length not shown at all. The same rows without the cap (the E2 design, `e3a2-cap0-transcript.txt`) paint `0x1C2D3` at 118, `0x1` at 130, `0x` at 110. Between 81 and 99 columns the cut comes back: **E3A-17** |
| E3A-04 | MAJOR | **closed** | R-A2L-READ.57 (`:227`), R-A2L-014 changed (`:226`), the V161 tag in the list as class D7 (`:298`), 227 exceptions and 234,427 identical (`:254`, `:300`). Tracked: 1 MEASUREMENT with ARRAY_SIZE, without MATRIX_DIM (`e3a2-followup`). "Sizes compared, not multiplied" for ARRAY_SIZE with MATRIX_DIM: E3A-21 |
| E3A-05 | MEDIUM | **closed** | CTX *begin words* (`:108`), READ.50 (`:262`) and R-A2L-076 (`:264`) reworded, case READ.50/4; the CTX *section header* clause removed |
| E3A-06 | MEDIUM | **closed** | R-A2L-READ.62 (`:205`); READ.28/2 expects address and kind none (`graph-inc11.md:580`) |
| E3A-07 | MEDIUM | **closed** | R-A2L-READ.63 (`:216`), 13 shapes, 0 on the tracked files (confirmed independently, `e3a2-followup`: 0 tags) |
| E3A-08 | MEDIUM | **closed as ruled** | READ.48 compares sections (`:253`); READ.49's 227 tags pinned per class D1 … D7 by synthetic reductions with hand-written values (`:254`, `graph-inc11.md:634`); `ref_read_a2l` a character loop with an AST and shared-literal guard (`graph-inc11.md:744`) |
| E3A-09 | MINOR | **closed** | CG-6's ratio on files of 1 MB or more (`graph-inc11.md:755`); the O(n·m) axis lookup routed to Inc 3a (I-11.8 (i), `:45`) |
| E3A-10 | MINOR | **closed** | I-11.1: both new keys read with `.get` and defaults (`graph-inc11.md:38`) |
| E3A-11 | MINOR | **closed** | considered and not taken, with the reason (`graph-inc11.md:38`: READ.32, .58 and .63 name the keyword's line) |
| E3A-12 | MINOR | **closed** | routed to Inc 3a, I-11.8 (e) (`graph-inc11.md:45`) |
| E3A-13 | MINOR | **closed** | R-A2L-013 changed in place (`:225`), CTX *sizes* and *length rows* (`:124-125`), the exact text of READ.59 (`:203`), "keyword" for "line" |
| E3A-14 | LOW | **closed** | in the change list (`:312`; `graph-inc11.md:88`) |
| E3A-15 | INFO | **updated** | 234,427 identical (`:254`). Round 2 confirms it for what the correction adds: the named-kind rule changes 0 tracked tags on the six fields (CANON1 vs CANON2: 0 of 234,654; raw vs CANON: 108 both ways, E1's 122 less the 14 MATRIX_DIM-product tags CANON does not model), and the fail-closed rules (READ.58, .59, .60, .61, .63, duplicates, MATRIX_DIM arity) fire on 0 tracked tags, counted by an independent REF (`e3a2-followup`) |
| E3A-16 | INFO | **closed** | READ.52 reports the peak memory beside each file (`:271`); see E3A-18 |

### New findings

| Id | Sev | About | Defect | Fix |
|---|---|---|---|---|
NEW

### Measurements

MEAS

### Evidence checklist (architect, round 2)

CHECK

Time spent: TIME.
