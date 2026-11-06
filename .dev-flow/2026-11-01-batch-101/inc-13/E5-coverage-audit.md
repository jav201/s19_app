# Inc 13 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 13, stage E5. Worktree head `a086fa5` (merge-base with main `b7b77c4`). Role: coverage auditor. I did not write the cases or the tests. Mode: **validation** of the coverage records. This file is the only file I wrote.

**Inputs read:** `02-test-cases.md` (39 cases); `01-requirements.md` (24 active rows); `E4-tester-notes.md`; `E4-integration-notes.md` (SR-1, OR-1 / E4-F1, OR-2); `evidence/inc-13/int-*.txt` and `red-01-tester-base.txt`; `git diff main...HEAD -- tests` (8 files); the existing nodes the cases cite (`tests/test_crc_designer_view.py`, `tests/test_crc_kernel.py`, `tests/test_segment_split_window.py`); and the product call sites the tests rely on (`crc_designer_view.py` `_compute_coverage`, `_on_image_changed`, `on_show`; `crc_designer_model.py` `compute_target_crc` / `evaluate_target`; `segment_split_view.py` `_conflict_marks` / `build_plan`). Mapping rules TCP-MAP-1, -3, -5, -6 and -7 come from `s19w/test-cases/TC-PROFILE.md`. `PLAN.md` does not name TCP-MAP itself; the rules were read from the profile, as at Inc 8.

**Evidence:**
- **Inspection** of the tests and the product. It cannot show behaviour. No mutant was run.
- **Executed by this auditor on the Windows PC:**
  - `pytest --collect-only` on the six cited test files: 176 node ids collected, every cited node among them.
  - A text diff of `tests/support/b101_inc13_reference.py` against `git show b7b77c4:s19_app/tui/segment_split_view.py` lines 288–351.
  - No test was run.
- **Not executed by this auditor:** every pass, fail and timing quoted below. They come from two sources, read from the transcripts:
  - The orchestrator-spawned E4 integrator: `int-lane1-r2` (804 passed, 16 skipped), `int-ast-r1`, `int-serial-r1..r3`. The tree was `f9f3cb09` plus the uncommitted branch diff (11 files: 38e31bf plus the integration edits).
  - The E4 tester: `red-01-tester-base`, base RED.

**Rule applied:**
- A test verifies a case only if it **asserts** the case's expected result.
- It is `full` only when the product itself produces what the test asserts.
- These make it `partial`: a stand-in, a fixture that already shows the result, an entry no product route calls, an unasserted clause, or a pinned value different from the case's.
- An injected quiet time or cap is judged by whether the product's own scheduler or check still runs. In this increment it does: the constants are read at use by `_schedule_recompute` and `_compute_coverage`.
- A timing row needs 5/5 runs, as its threshold says.

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 39 |
| Cited node ids that do not collect (TCP-MAP-3) | **0**. All 30 distinct cited ids collect. |
| Marks changed `full` → `partial` (case level) | **3**: R-CRC-DESIGNER-007.2/1, 007.3/1; R-CRC-PREVIEW-001.1/1. In addition, R-CRC-DESIGNER-001.2.2/3's coverage column goes covered → partial (its mark was already partial). |
| Marks changed `partial` → `full` | **2**: R-CRC-PREVIEW-002.2/2, 001.3/2 |
| Node marks corrected inside a case whose coverage holds | 3 nodes in 2 cases (001.5/1, 001.8/1), all `full` → `partial` |
| Results that cannot stand | **5**. 002.2/1, 002.3/1, 002.4/1: `pass 3/3` → `executed 3 of 5` (2 runs owed). R-SEG-PREV.20/1: → `failed` on its state-line clause. R-SEG-PREV.7/1: `blocked` → `failed`. |
| Expected results / inputs / preconditions to correct | 6 (001.2.1/1, R-CRC-DESIGNER-001.1/1, 001.11/1, R-SEG-PREV.20/1, plus 007.2/1 and 007.3/1 through their tests) |
| Coverage as it should stand (39) | covered 33 · partial 5 (001.2.2/3, 007.2/1, 007.3/1, 001.1/1, SEG-PREV.20/1) · gap 1 (SEG-PREV.7/1). 001.2/1 counts as covered only once the matrix node is cited (§2). |
| Result as it should stand (39) | pass 34 · executed 3 of 5 runs: 3 · failed 2 (SEG-PREV.20/1, SEG-PREV.7/1) |
| **Cases changed (any column)** | **17 of 39 = 43.6 %** |
| Requirement clauses with no case | 5 (§4) |
| Black-box ATs owed (keys and dialogs) | 7 (§5) |
| Stale cap value 67108864 left in records | 8 sites (§3) |

### Top issues
1. **R-SEG-PREV.7/1 and the state-line half of R-SEG-PREV.20/1 are `failed`, not `blocked` / `pass`.**
   - The serial runs observed the product painting `⚠ GUARD  9.20 MiB span — e will ask` where both cases expect `⚠ <size> would clobber source — abort on export`. That is an executed observation that contradicts the expected result. A product defect (E4-F1) makes a case fail; it does not block it.
   - The arm deliberately pins the wrong line, so it will turn RED when E4-F1 is fixed. Keep that pin, but do not count it as coverage.
2. **The timing rows are 3 of 5.** 002.2/1, 002.3/1, 002.4/1 and 20/1 each state "5/5 runs". Three serial runs are on record (margins 58.5 %–73.4 %, 0 under 20 %), so none can read `pass` yet.
3. **Two "recomputes once" cases assert a value the first-shown form already shows (TCP-MAP-5(c) / -6):**
   - 007.3/1's `✓ MATCH`: CRC-32/ISO-HDLC also matches its own check. A preset pick that filled no field and recomputed once would pass.
   - 007.2/1's `Reflection in/out on`: CRC-32/ISO-HDLC already has refin = refout = True. The F-23 template definition ("differs from the first-shown form in every algorithm field") is false for those two fields.
4. **M-12 cannot turn R-SEG-PREV.2/2 RED.** This is by inspection; no mutant was run.
   - `build_plan` feeds the conflict marks only to `_sweep`, which merges adjacent equal classes. The conflict count is `sum(b.size for b in blocks if b.cls == "conflict")`, so marks split at a touching source boundary yield the same plan.
   - The nodes that compare `_conflict_marks` as a list (2/3, 2/5) have no touching source ranges. M-12 therefore survives every node, and the requirement's "(2) RED" claim is wrong.
5. **Several existing nodes cited as `full` assert substrings on one surface** while the case asks for the exact text on both. This affects 001.1/1 (`"Load an image" in`), 001.5/1 and 001.8/1. Only 001.1/1 has no full node behind it.

## 2. Per-case table

Mark = this audit's verdict for the case (the strongest node). "Δ" = the case row changes. The source of each pass is `int-lane1-r2` or `int-serial-r1..r3`, executed by the E4 integrator.

| Case | Mark (old → new) | Coverage (old → new) | Result (old → new) | Δ | Reason (one line) | Who changes |
|---|---|---|---|---|---|---|
| R-CRC-DESIGNER-001.2.1/1 | full → full | covered | pass | **yes** | The precondition "recomputes settled" is false. The image is set before key `0`, so the display schedules a 10 s recompute that is still pending when the dropdown changes. The node asserts `pending is None` afterwards, which confirms tester ambiguity 3 (the dropdown stops the pending timer, E1-D2). Write that precondition and the extra expected clause into the case. | case |
| R-CRC-DESIGNER-001.2.1/2 | full | covered | pass | no | Seed `✓ MATCH` → `✗ MISMATCH`, delta 1. Discriminates. | — |
| R-CRC-DESIGNER-001.2.2/1 | full | covered | pass | no | (a) 10 s: delta 0, pending ≠ None, MATCH; (b) 0.05 s: delta 1, none pending, MISMATCH. The injection keeps the product timer real. | — |
| R-CRC-DESIGNER-001.2.2/2 | full | covered | pass | no | (a) delta 0, pending, `EMPTY_STATE` exact; (b) delta 1, `FIXTURE_PREVIEW` exact. | — |
| R-CRC-DESIGNER-001.2.2/3 | partial | covered → **partial** | pass | **yes** | It reads the constant. A product scheduling with another literal would pass. The injection nodes show the constant is the one read, but this case alone does not. | case |
| R-CRC-DESIGNER-007.1/1 | full | covered | pass | no | 5 back-to-back sets, delta == 1, MISMATCH. M-2 → 5 and M-4 → 2 both turn it RED. | — |
| R-CRC-DESIGNER-007.2/1 | full → **partial** | covered → **partial** | pass | **yes** | The `reflects == (True, True)` clause is already shown by the first-shown form (TCP-MAP-5(c), -6). The other 7 fields, the count and the status discriminate. Fix: give the template refin/refout `False` (and a matching check), or drop the clause and correct the F-23 template definition in `01-requirements.md`. | test; row (definition) |
| R-CRC-DESIGNER-007.3/1 | full → **partial** | covered → **partial** | pass | **yes** | `✓ MATCH` is already shown by CRC-32/ISO-HDLC, so a no-op fill passes (TCP-MAP-6). Fix: also assert Width `16`, Polynomial `0x8005`, Init `0xFFFF` after the pick; add those to the case's expected result. | case; test |
| R-CRC-PREVIEW-002.1/1 | full | covered | pass | no | Exact preview within 1 s with the shipped quiet time; window line 2 exact. | — |
| R-CRC-PREVIEW-002.1/2 | full | covered | pass | no | Preview and window both exactly `EMPTY_STATE`. | — |
| R-CRC-PREVIEW-002.1/3 | full | covered | pass | no | Line 2 = `concat: 0x<zlib.crc32 of the changed bytes>`. The integration fix `split("\n")[1:2]` keeps the exact check. | — |
| R-CRC-PREVIEW-002.5/1 | full | covered | pass | no | `hidden == (0, None)`, `shown == (1, FIXTURE_PREVIEW)`, re-display delta 1. M-16 shows up as pending ≠ None; M-18 fires within the 0.3 s. | — |
| R-CRC-PREVIEW-002.2/1 | full | covered | pass 3/3 → **executed 3 of 5** | **yes** | Line 2 is checked against `zlib.crc32` oracles, which equal the guide's `0x6CD65EAE` / `0xA7B4C7F5`; reads ≤ 2. The 20 % margin clause is not asserted: `report_margin` never asserts. It is read from the QC-TM block of each transcript, which is acceptable under QC-TM if the gate cites that block. 2 runs owed. | case (result) |
| R-CRC-PREVIEW-002.2/2 | partial → **full** | covered | pass | **yes** | The case's expected result is the read count (≤ 2 in 6/6). The spy delegates; it is not a stand-in. Every window read goes through the module-global `crc_designer_model.gather_target`, which `compute_target_crc` resolves at call time, so the count is not vacuous. The "not the time" reason belongs to 002.2/1. Dirty-abort is 2 on base too, so it does not discriminate base; the other 5 states do. | case |
| R-CRC-PREVIEW-002.3/1 | full | covered | pass 3/3 → **executed 3 of 5** | **yes** | Last update after the press ≤ bound; recompute delta == 1. 2 runs owed. | case (result) |
| R-CRC-PREVIEW-002.4/1 | full | covered | pass 3/3 → **executed 3 of 5** | **yes** | First update − (t0 + `CRC_RECOMPUTE_S`) ≤ bound; line 2 oracles. 2 runs owed. | case (result) |
| R-SEG-PREV.20/1 | partial | covered (partial) → **partial** | pass → **failed** (state-line clause, E4-F1); timing and stats executed 3 of 5 | **yes** | (1) Expected text says `<pct>` is "pinned from one base run at E4". The test derives it instead: `fill = 100·(span − packed − len(gap_conflict(…)))/span`, 2 decimals. Correct the case to the derivation. (2) The state line pinned (GUARD) differs from the expected result (clobber line). (3) The setup writes `window._sel["ranges"] = {0, 2}` and calls `app.action_open_split_join_export()` rather than ticking and opening through keys (black-box, §5). | case |
| R-CRC-DESIGNER-001.1/1 | full | covered | pass | **yes** | The inputs do not match the tests. The case reads "200 random vectors" and "widths 8 … 64 not a multiple of 8". The tests run 45 vectors (5 fixed + 40 random of length 0–199, seed 20260720) and widths 12 and 24 only, each with all four refin/refout pairs. The equality assertion is full and M-11 is caught (`bytes(range(256))` holds `0x01`). Correct the case and the row 001.1 threshold. | case; row |
| R-CRC-PREVIEW-001.1/1 | full → **partial** | covered → **partial** | pass | **yes** | Both cited nodes assert `"Load an image" in …` on one surface each. The case asks for the exact text on both surfaces. No full node exists for the no-image-at-start state. Fix: `==` `EMPTY_STATE` on both (D-2 forbids editing those nodes, so add a new node). | test (new) |
| R-CRC-PREVIEW-001.1/2 | full | covered | pass | no | It is the 002.1 node, exact on both surfaces. | — |
| R-CRC-PREVIEW-001.2/1 | partial | covered → covered (with the added node) | pass | **yes** | The cited node is substring-only. `test_r_crc_preview_001_2_coverage_field_state_matrix[fixture-w32-fill-abort]` asserts the exact three lines holding both oracles: cite it as full. Without it, coverage is `partial`. | case (Tests) |
| R-CRC-PREVIEW-001.2/2 | full | covered | pass | no | 24 states, exact text from canon formats and `zlib.crc32`. | — |
| R-CRC-PREVIEW-001.3/1 | full | covered | pass | no | Line 2 exact. The tail is built from an independent `store_word` (`to_bytes(4,"little")`). M-9 was RED 11/25 on base source. | — |
| R-CRC-PREVIEW-001.3/2 | partial → **full** | covered | pass | **yes** | The node asserts the case's expected result exactly (line 2 `Cannot compute: width 4 …` in all 12 width-4 states, line 1 glyph-only), and the product produces it. "Non-canon text" describes the requirement, not the evidence. | case |
| R-CRC-PREVIEW-001.4/1 | full | covered | pass | no | Matrix: exact refusal text. The existing node stays partial (0x800A map). | — |
| R-CRC-PREVIEW-001.5/1 | full (matrix) | covered | pass | **yes** | `test_coverage_window_dirty_gap_abort_refuses_store` is cited `full` but asserts the substring `"refused"` and the absence of a store word. It checks neither the exact line 3 nor line 2, and its dirty byte is `0x800A`, not `0x800B`. Mark that node `partial`; the matrix node stays full. | case (Tests) |
| R-CRC-PREVIEW-001.6/1 | full | covered | pass | no | Preview line 4 and the window's last line are both `GAP_NOTE_WARN` exactly. | — |
| R-CRC-PREVIEW-001.7/1 | full | covered | pass | no | Exact three lines, no note. | — |
| R-CRC-PREVIEW-001.8/1 | full (new node) | covered | pass | **yes** | The two existing nodes are cited `full`, but each asserts `"Invalid coverage" in` on one surface. The case says "starts", on both. The window node uses `0x8010-0x8000`, not `0x8008-0x8000`. Mark both `partial`. `test_r_crc_preview_001_8_inverted_range_names_the_reason` is full. | case (Tests) |
| R-CRC-PREVIEW-001.8/2 | full | covered | pass | no | Exact text on both surfaces, no `link` span, `markup=False`. | — |
| R-CRC-PREVIEW-001.11/1 | full | covered | pass | **yes** | The expected results match the pinned values (16777216, `0x00000000-0x01000001`, 0 reads; 23 / 24). The read count is real (see 002.2/2), so M-19 → 2 reads. The inputs differ: (b)/(c) go through `_load_and_recompute`, which also edits Ranges to the first-shown coverage without the space. The cap is injected before each fresh app, not "before start" of a single app. Correct the inputs. | case |
| R-CRC-PREVIEW-001.12/1 | full | covered | pass | no | 15 / 51 (48 empty) / 24 → 49; line 2 values match the pins, including the cap text 16777216. The hostile node was never run on base, by design. | — |
| R-SEG-PREV.2/1 | full | covered | pass | no | Independent per-address classifier, 200 seeds; `band_lo` also asserted. | — |
| R-SEG-PREV.2/2 | full | covered | pass | no (but see M-12) | Product plan vs plan with the verbatim base functions patched in, 220/mode. The comparison is sound, but M-12 is unobservable through the plan (top issue 4). Add a touching-source list comparison of `_conflict_marks`, or drop M-12 from the mutant table and from row R-SEG-PREV.2's negative control. | mutant table; row; test |
| R-SEG-PREV.2/3 | full | covered | pass | no | List equality with the reference; `sum(e−s) == len(gap_conflict) > 0`. | — |
| R-SEG-PREV.2/4 | full | covered | pass | no | 5000 marks, block equality, ≥ 4 classes. | — |
| R-SEG-PREV.2/5 | full | covered | pass | no | 256 pads, list equality; the image is not degenerate. | — |
| R-SEG-PREV.7/1 | — | gap | blocked → **failed** (E4-F1) | **yes** | Executed and observed: the arm's state line is the GUARD chip in 3/3 serial runs. No node asserts the clobber line, and the arm asserts the contrary. Coverage stays `gap`. | case (result) |
| R-SEG-PREV.7/2 | full | covered | pass | no | TC-710 unchanged. | — |

Changed rows: 001.2.1/1, 001.2.2/3, 007.2/1, 007.3/1, 002.2/1, 002.2/2, 002.3/1, 002.4/1, SEG-PREV.20/1, DESIGNER-001.1/1, PREVIEW-001.1/1, 001.2/1, 001.3/2, 001.5/1, 001.8/1, 001.11/1, SEG-PREV.7/1. **17 of 39 = 43.6 %.**

### Checks requested
- **Clock-free cases still discriminate (inspection; head mutants not run).** No clock-free case decides by sampling the wall clock. Each mutant shows up as follows:
  - M-1: the preview still reads `join=concat` after one pause with a 10 s quiet time.
  - M-2: delta 1 in (a); 5 in 007.1.
  - M-3: the (b) waits time out.
  - M-4: delta 2.
  - M-16: pending ≠ None after the hidden pauses.
  - M-17: the wait times out.
  - M-18: +1 within 0.3 s.
  - **Exception: 007.2/1 and 007.3/1 decide on a fixed `pilot.pause(1.5)` window, not on a wait.** With the debounce in place, M-5 and M-6 yield **2** recomputes, the second about 0.6 s after the first, not the "about 11 / about 9" the rows' negative controls state (those are base counts). On a quiet host the window catches it. On a stalled loop it could miss it, which would be a false pass. Correct the negative-control texts, and consider waiting on the count plus a settle pause.
- **Reference copies are verbatim (executed by me).** `reference_sweep` and `reference_conflict_marks` equal `b7b77c4` lines 288–351, ignoring blank lines, with only the two names changed. 2/2 patches them into `build_plan`; 2/3, 2/4 and 2/5 compare the product functions against them directly; 2/1 uses an independent classifier.
- **D-2 AST check:** GREEN in `int-ast-r1`, run by the integrator, not skipped. Its control node shows the check can fail on synthetic sources. The record text names the snapshot `before = designer_recomputes()`, but the tests use `recomputes_before`. The check accepts any name, so this is a record wording fix only.
- **Timing:** 3/5 per row. Base values: the integration notes swap two base times. `red-01` gives 002.3 = 531.7 s and 002.4 = 60.3 s; the notes print 60.3 s / 531.7 s in case order.
- **Run revision:** the runs used `f9f3cb09` plus the uncommitted diff, not a commit hash. The changed-file count (11) matches `b7b77c4..a086fa5`. The integration edits between 38e31bf and a086fa5 are one predicate, the id-registry bound, and docstring/comment-only changes in the perf file (verified). Run the 2 owed timing runs at `a086fa5` and record the hash.

## 3. Pinned values the records no longer match

| Where | Stale text | Pinned value |
|---|---|---|
| `codewire/graph-inc13.md` l.43 | `64 * 1024 * 1024` (67108864), cost "≈ 16 s" | `16 * 1024 * 1024` = 16777216; ≈ 8.1 s (row Definitions) |
| graph l.45 | `== 67108864` | `== 16777216` |
| graph l.192 | `0x00000000-0x04000001`, size 67108865, `size_cap = 67108864` | `0x00000000-0x01000001`, 16777217, 16777216 |
| graph l.193, l.215, l.231, l.233 | `size_cap = 67108864`; `Cannot preview: coverage exceeds 67108864 bytes`; `0x00000000-0x04000001` | 16777216; `0x00000000-0x01000001` (`bytes_per_glyph` 89478486 at l.231 is correct and independent of the cap) |
| `E1-slice.md` row 18 | `_COVERAGE_CAP_BYTES = 64 * 1024 * 1024` | `16 * 1024 * 1024` |
| `E1-rulings.md` §5 M-0 | "cap stays 64 MiB", "≈ 32 s" | 16 MiB (E3 round 2); the row's cost note |
| `E3-rulings.md` row A-6 + SEC-2 | "provisional 64 MiB" | superseded by the same file's round-2 line (16 777 216). Leave as history, but say so. |
| `01-requirements.md` row R-CRC-DESIGNER-001.1 threshold | "200 random vectors", "widths 8 … 64 not a multiple of 8" | 45 vectors; widths 12 and 24 |
| `01-requirements.md` Definitions, F-23 template | "differs … in every algorithm field" | not Reflection in/out (both True in both) |
| `01-requirements.md` rows 007.2 / 007.3, negative control | "about 11" / "about 9" | base counts. On head the mutant gives 2. |
| `02-test-cases.md` R-SEG-PREV.20/1 | `<pct>` "pinned from one base run at E4" | derived from `gap_conflict` (the test) |
| `E4-integration-notes.md` base times | 002.3 = 60.3 s, 002.4 = 531.7 s | 002.3 = 531.7 s, 002.4 = 60.3 s (`red-01`) |

`01-requirements.md` (Coverage cap, rows 001.11 and 001.12 (b)), `02-test-cases.md` (001.11/1, 001.12/1), the product (`_COVERAGE_CAP_BYTES = 16 * 1024 * 1024`) and the tests (`SHIPPED_CAP = 16777216`) all agree on 16777216.

## 4. Requirement clauses with no case

1. **"every result surface"** in 001.2.1, 001.2.2, 007.1–007.3, 002.1 and 002.5. The Definitions make it observable as "each of the six result-surface widgets is updated once". No case observes the JSON strip, the Warnings or the custom-vector CRC; the `_recompute` call count stands in for them. Either add one case (update stamps on all six widgets per recompute) or reword the definition so the count is the observable.
2. **"Loaded image changes: a load, a project load, an unload"**, and the 001.2.2/2 rationale that "a project load that sets the image twice recomputes once". Every case assigns `app.current_file` directly; no case goes through a load, a project load or an unload route.
3. **R-CRC-PREVIEW-001.12, "at most 48 glyphs per range or gap"** (the run cap). The rows declare it defensive with no mutant, so it is accepted as declared, not covered.
4. **R-SEG-PREV.20's state-line clause** duplicates R-SEG-PREV.7 and is now failed (E4-F1). The requirements session decides whether row .20 keeps it or defers it to .7.
5. **R-SEG-PREV.2 negative control (2) for M-12**: no node can observe it (top issue 4).

## 5. Black-box ATs owed (keys and dialogs)

Every Designer node sets widget values directly: `Input.value`, `Select.value`, `Switch.value`, `Button.press()`, `app.current_file`. Only the rail keys `0` / `1` are real keys. The Split/Join arm opens the window by method call and writes `_sel`. Same messages, not the operator's route:

1. **Designer typing burst:** focus XOR out and type characters with `pilot.press` → one recompute after the quiet time, last value's verdict.
2. **Preset through the dropdown with keys** (open, arrows, Enter) → one recompute; Width / Polynomial / Init filled.
3. **Template load:** Load path typed, Load button clicked (`pilot.click`) → one recompute, fields, status.
4. **Image load / project load / unload through the shipped routes**, with the Designer displayed (F-24, one recompute) and hidden (stale → recompute on key `0`).
5. **Join gaps / On conflict dropdowns driven by keys**, with the preview and window text checked.
6. **Split/Join opened through its shipped key or palette entry**, `range_00` / `range_02` ticked by keys, then `m` and `g` → band, stats line, state line (the canon clobber line once E4-F1 is fixed).
7. **Split/Join `e` in the F-23 scene** → export refused on conflicts (LLR-136.4). In a guard-only scene → the "e will ask" dialog confirmed and cancelled by keys.

## 6. Still owed at E5

- Mutants M-1 … M-8, M-12, M-15 … M-25 on the implemented tree; none has run. M-12 needs a new node first (top issue 4).
- 2 more serial runs for each timing row (5/5), at a recorded commit.
- E4-F1: `_state_text` checks GUARD before conflict, which contradicts R-SEG-PREV.7 / .8. Route it to a slice that owns the state line. Then flip the R-SEG-PREV.20/1 pin and re-run 7/1.
- `test_tc_b97_69_page_keys_do_nothing_where_disabled`: one "A2L loaded did not settle" under `-n 12`. Re-run in the full battery before calling it a flake. The new `current_file` watcher is not excluded.
- Tester ambiguity 3 (a dropdown stops a pending timer) is confirmed by the passing `pending is None` assertion in 001.2.1/1 (`int-lane1-r2`), once that case's precondition is corrected.
