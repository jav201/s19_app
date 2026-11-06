# Inc 11 — E5 code review

Reviewer: independent code reviewer (not an author of the design, the code or the tests). Worktree head `688ca2b`. Scope: `git diff main...HEAD -- s19_app tests` (4 source files, 8 test files). No test or probe was run on the Windows PC; the integrator's transcripts were read instead. One stand-alone script read A2L text without importing `s19_app` (evidence below).

## Verdict

**PASS-WITH-NOTES.** No BLOCKER and no MAJOR finding. The code matches the graph and the requirements, including every point the brief named. The test files assert exact expected values and can fail. The integrator's test fixes made the tests stricter and weakened none. Two MINOR record gaps (one doc, one requirements text) and three NITs remain open. None of them changes behaviour.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1a | 62 names | `RECOGNIZED_A2L_BLOCKS` (`rules.py:9-74`) and the Definitions list of `01-requirements.md` were compared by a script: 62 = 62, symmetric difference empty | executed |
| 1b | IF_DATA flag | `_iter_sections` (`rules.py:450-460`) passes `inside_if_data or name == INTERFACE_DATA_BLOCK` down as an argument and never recomputes it from ancestors (E3 S-3). The IF_DATA node itself gets its parents' flag. The loop at `rules.py:533-535` checks `section_name and not inside_if_data and not in RECOGNIZED`. Message, severity and line number are unchanged | executed |
| 1c | `_a2l_number` | `a2l.py:950-980`. Explicit string scans that are equivalent to `[+-]?(0[xX][0-9A-Fa-f]{1,8}\|[0-9]{1,10})`: ASCII-only (`"0" <= ch <= "9"`), `0400` gives 400, and `0x`, `+`, `00x10`, `0x1_000`, 9 hex digits, 11 decimal digits and `٣` all give `None`. Never called on a quoted word (the caller checks the flag) | executed |
| 1d | Quote reset per line | `_memory_segment_record_words` (`a2l.py:983-1060`) resets `in_string` for each text and carries `in_block_comment` across texts. `meta` comes first, then the block's own `lines`. Nested-block lines are children in `build_section_tree`, so they give no word | executed |
| 1e | Anchored rule and 2^32 bound | `a2l.py:1091-1126`. The anchor is the first unquoted word `k ≥ 1` that starts with an ASCII digit or a sign. Base and size are kept only when `base ≥ 0`, `size > 0` and `base + size <= 2**32`; otherwise every field is `None` and nothing further is scanned. Usage and kind are the last type word among words `1…k-1`. Offset is word `k+2` when it is unquoted. Matches graph I-3 and `func:` line 171 | executed |
| 1f | Display rank | `_ISSUE_DISPLAY_RANK` (`app.py:752`) is built from `issues_view.SEVERITY_ORDER`. `_filtered_validation_issues` (`app.py:16385-16398`) runs a stable `sorted` with default rank `len(SEVERITY_ORDER)`, so OK and NEUTRAL sort after INFO, in every filter mode. It is distinct from `_A2L_ISSUE_SEVERITY_RANK`. No caller indexes the filtered list against `_validation_issues` (grep) | executed |
| 1g | F-21 | `render_curve_description` (`a2l.py:3421-3428`) sits inside the `if points:` branch, so 0 points gives no note line (R-A2L-121). When every point has `x_note`: one line `  x: point index (axis points unavailable)` before the header and no row suffix. Mixed points keep the per-row suffix. `x_note` has one source (`a2l.py:3227`) | executed |
| 2 | Correctness with concrete inputs | Walked through: `S7 "oops` + `/* 0x10 0x20 */ …`; `""` as the name (block name `None`); a one-line `/begin MEMORY_SEGMENT … /end` (the section stays open per O-5, segments that follow become children and are still walked); an address and a size on different lines; `-0`; `+0x10`. No defect found beyond the accepted residuals N-2 and N-3 | executed |
| 3 | Re-labelling removal | Grep over `s19_app` and `tests` for `adjust_counts_for_a2l_triage`, `a2l_reclassified_severity`, `CURATED_STANDARD_A2L_BLOCKS`, `A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` and `_UNRECOGNIZED_BLOCK_RE` finds no reference. `issue-reclassify-note` and `Cambio4` appear only in negative assertions. The imports `re`, `replace` and `Iterable` were dropped, and `Dict`, `List`, `Optional` and `Sequence` are still used. `_split_line_respecting_quotes` and `parse_begin_meta` keep other callers. **`docs/architecture.md` was not updated (F1)** | executed |
| 4 | Tests | The values are the requirements' exact values. The negative controls discriminate: S1b and S1c (scan-on rule), `0400` (`int(w,0)`), S12 and S13 (bound and boundary), M2 and M3 (first type word), the 45-issue paging, the nested FROBNICATE, and the 3-level IF_DATA. The typed 62-name oracle is never imported from the engine. Integrator fixes: `_rows_composed` strengthens the waits and changes no assertion; AT-I11-3 now uses a real click; AT-I11-4 now goes through the palette plus `t`, Tab, `t` (SR-1); `EXPECTED_SCANNED_TEST_FILES` 253 is measured. `test_a2l_zero_issues` now asserts `== []`, where the old assertion was vacuous. TC-B94-18 fails in int-07 at line 279 (the freeze arm), so its engine arm passed first. The corpus walker is independent of the engine (see below) | executed (read); the suite itself is the integrator's, int-07/09/15 |
| 5 | `app.py` scope | The only changes are: the import line (`adjust_counts_for_a2l_triage` replaced by `SEVERITY_ORDER`), the new constant, `_filtered_validation_issues`, the docstring and comment lines removed in `update_validation_issues_view`, and the two count dicts with the wrapper removed. All of these lines are in the slice | executed |

### Is the corpus oracle independent?

`_walk_names_outside_if_data` (`tests/test_b101_a2l_blocks_and_segments.py:175`) shares no code with `_iter_sections` or with `RECOGNIZED_A2L_BLOCKS`. It does walk the tree that `build_section_tree` builds, which the Definition makes the reference ("inside IF_DATA as the section tree nests it"); that parser is unchanged in this increment. As an extra check, a stand-alone raw-text census was run over the 35 A2L files under `examples/` and `tests/fixtures/synth/`. It has its own line reader and tokenizer, imports nothing from `s19_app`, and is kept in the session scratchpad. Results:

- 47 distinct section names sit outside IF_DATA, and all of them are in the 62 (this matches the E3 census).
- The 15 MEMORY_SEGMENTs give the pinned name, base, size, usage and kind: V161 and V171 (0x16000/0x86C …, `TRANSFORMER_CALIBRATION` `NOT_IN_ECU`), `software_a.a2l` (0xA001C000/0x1000 ×3, DATA FLASH), `memorysegment.a2l`, and `case_07` `main` (no program type, FLASH, 0x08000000/0x400).

## Findings

### F1 — `docs/architecture.md` still describes the removed view triage  [MINOR · impl]
- **What:** E3 ruling A-8 is binding, and `E1-slice.md` §4 lists `docs/architecture.md:396-416` as a node to change (text only, owner G2). `git diff main...HEAD -- docs` is empty.
- **Where:** `docs/architecture.md:39` (screen table: "batch-94 triages curated standard A2L blocks to INFO"), `:398` (the "view-level reclassification … shipped in Inc-004" paragraph), `:416` (risk R12).
- **Scenario:** a reader of the architecture doc is told that the Issues screen re-labels standard A2L block warnings as INFO and that the engine is frozen. Both are false after this increment.
- **Fix:** text-only update as the slice states. Say that the view-level reclassification is removed, that an issue's severity is final (I-2), and that the guarantee lives in `validate_a2l_structure` (R-VAL-032.2, .3). Close R12, since the seam moved parser-ward with OR-3.

### F2 — E3 round-2 addenda N-1, N-3 and N-4 were not folded into the records  [MINOR · design-gap]
- **What:** N-1 was marked "fix before E4". It asks for the `base + size ≤ 2^32` bound in the text of R-A2L-036.2's trigger and of R-A2L-036.4. N-4 asks to correct R-A2L-036.5 ("the pair rule") and R-A2L-036.6 ("a number", lower case). N-3 (address typo shifts the anchor) and N-2 (`٣ 0x10 0x20` gives base 0x10) were to be stated as accepted residuals in D-5. None of this is in `01-requirements.md:72-76` or in `E1-rulings.md` D-5 (`:42`). `E4-impl-notes-a2l.md:41` says N-1 … N-4 are folded, which is true of the code only.
- **Where:** `.dev-flow/2026-11-01-batch-101/inc-11/01-requirements.md:72, :74, :75, :76`; `E1-rulings.md:42`.
- **Scenario:** as written, R-A2L-036.2 still requires base 0xFFFFF000 for S12, while R-A2L-036.13 and the code give no base. The canon carries the contradiction the architect flagged.
- **Fix:** apply the row wording N-1 and N-4 give, and add the N-2 and N-3 residuals to D-5. No code change.

### F3 — The acceptance file's docstring names the wrong wait helper  [NIT · impl]
- **Where:** `tests/test_b101_inc11_acceptance.py:14`. The docstring says the waits use `tests/support/timing.py::wait_until`, but the file defines its own `wait_until` (`:62`) that rides out `WaitForScreenTimeout`.
- **Fix:** change the sentence to say that the file uses a local `wait_until`, built on `timing.POLL_S`, that tolerates `WaitForScreenTimeout`.

### F4 — S11 cannot show the anchor reading of a non-ASCII digit  [NIT · design-gap]
- **Where:** `tests/test_b101_a2l_blocks_and_segments.py:385`. `S11 "" DATA FLASH INTERN ٣ 0x10` gives no base only because no word follows `0x10` (E3 N-2). The case does catch an `int()`-based reader (that one would give base 3). It does not pin the accepted residual.
- **Fix (optional):** add a pin `S11b "" DATA FLASH INTERN ٣ 0x10 0x20` → base 0x10, size 0x20. A later change to the anchor rule would then show up in a test diff instead of passing silently.

### F5 — An unrealistic quote style in a re-pinned fixture  [NIT · impl]
- **Where:** `tests/test_segment_split_window.py:126-140, :1218`. The rewritten fixtures keep the single-quoted names `'AscetCode'` from base, and the new reader returns the quotes as part of the name. The assertions do not read names, so nothing breaks, and E3 A-2 changed only the record shape.
- **Fix (optional):** write the names unquoted (`AscetCode ""`) to match `memorysegment.a2l`.

## Evidence checklist

- [x] Diff read in full: `s19_app/tui/a2l.py` (`+217`), `app.py` (`107`), `issues_view.py` (`-263`), `rules.py` (`+85`); the three new test files in full; the diffs of `test_tui_issues_triage_b94.py`, `test_segment_split_window.py`, `test_synth_release_case.py`, `test_engine_unchanged.py` and `test_id_registry.py`.
- [x] Correctness pass (edge, None and error paths): checks 1c–1g and 2.
- [x] Simplicity pass: no premature abstraction. The two helpers are single-purpose and the graph requires them. The sort is one expression.
- [x] Reuse and duplication: the record-word helper duplicates the rules of `_strip_a2l_comments` and `_split_line_respecting_quotes` on purpose (E3: per-line quote reset plus the quoted flag; graph line 143). Accepted.
- [x] Tests reviewed for intent: each has a "Why" docstring and a discriminating negative (check 4).
- [x] Verdict explicit: PASS-WITH-NOTES, with no BLOCKER or MAJOR open.

## What I read

- `01-requirements.md`, `E1-slice.md`, `codewire/graph-inc11.md` (contract lines), `E1-rulings.md` (D-5, D-8, O-5, folds), and `E3-rulings.md` (round 1, the addendum, round 2 N-1…N-4).
- `E3-architect.md` (N-1…N-4), `E4-impl-notes-a2l.md`, `E4-impl-notes-rules.md`, `E4-impl-notes-view.md` (the deviation sections), `E4-tester-notes.md` and `E4-integration-notes.md`.
- Transcripts `evidence/inc-11/int-06`, `int-07` (TC-027 and the TC-B94-18 freeze arm at `:279`; 326 passed), `int-09` (TC-031 ×2 only; 245 passed), `int-15` (490 passed), and `red-01-tester-base.txt` (summary lines).
- Source context: `build_section_tree` and `_split_line_respecting_quotes` (`a2l.py:154-345`), and the generator's segment line (`tools/synth/make_release_case.py:593`).

## Items carried (not findings of this review)

The OR-3 freeze guards (TC-027, the TC-B94-18 freeze arm, TC-031 ×2) must be GREEN on the merged tree. The six `a2l-*` snapshot baselines are still owed in the CI-matching environment. `tc_b100_52[case_06]` must be checked under the full battery. These are integrator items 1–3; this review does not re-rule them.
