# Increment 011 — Inc 11 · R-VAL-032, R-A2L-036, R-A2L-120…123, R-TUI-042b · A2L block names, IF_DATA skip, anchored memory-segment reader, curve description, severity order

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-11/`: `01-requirements.md` (US-I11-1 … 4, 28 active rows, 2 withdrawn), `02-test-cases.md` (78 cases), `E1-rulings.md`, `E1-slice.md`, `E3-architect.md`, `E3-security.md`, `E3-rulings.md`, `E4-impl-notes-a2l.md`, `E4-impl-notes-rules.md`, `E4-impl-notes-view.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc11.md`, and the transcripts under `.dev-flow/2026-11-01-batch-101/evidence/inc-11/`. Branch `b101-inc11` from `main` (`b7b77c4`), head `fa35466` plus the E5 close commit (snapshot baselines, `snap-*` transcripts, `04-validation.md`, this packet, `steps.log`).

Models per stage (from `steps.log`): Opus — E1–E3 (requirements, rulings, graph, both design-review rounds), the E4 integration step, the E5 code and security reviews, the coverage audit, the E5 corrective pass, the snapshot re-record and these records; DeepSeek v4 Pro — the three E4 implementer units and the E5 mutant battery; Sonnet — the E4 independent tester.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `011` |
| Requirement(s) | R-VAL-032.1, .2, .3; R-TUI-042b.1, .2, .4, .5, .6; R-TUI-025.2, .6; R-A2L-036.1, .2, .3, .4, .6 … .13; R-A2L-034; R-SEG-SRC.6; R-A2L-120, 121, 122, 123 (28 active; R-VAL-032 and R-A2L-036.5 withdrawn) |
| Acceptance | 78 cases of `02-test-cases.md` (71 requirement cases, AT-I11-1 … AT-I11-7); nodes in `tests/test_b101_a2l_blocks_and_segments.py` (G1), `tests/test_b101_issues_severity_view.py` (G2), `tests/test_b101_inc11_acceptance.py` (G3) |
| Agent | `software-dev` (DeepSeek v4 Pro implementers, Opus integrator), independent `tester` (Sonnet) |
| Date | 2026-11-05 |

## 1. What changed

Four operator-visible fixes. (1) **A valid A2L raises no "unrecognized block" (F-02, D3-12):** `validate_a2l_structure` knows the 62 ASAM MCD-2 MC block names and skips every section inside an IF_DATA block, at any depth; a block the standard does not have, outside IF_DATA, stays one WARNING `A2L_UNRECOGNIZED_BLOCK`. The clean release demo goes from 102 such warnings to none. (2) **Each issue under its own severity, errors first (F-03, F-39):** the batch-94 view triage (re-labelling standard-block warnings as INFO, the count adjustment and the note under the group header) is removed from `issues_view.py`; the filtered list is ordered ERROR, WARNING, INFO across pages, so the Warnings filter lists only warnings and the headers, strip and rows agree. (3) **CURVE without axis points (F-21):** the description window shows one line `x: point index (axis points unavailable)` above the point table instead of a note on every row; the mixed case keeps the per-row note. (4) **Anchored MEMORY_SEGMENT reader (F-29):** name, base and size are read from the record words wherever they sit (`/begin` line, line after the long identifier, one line with the name), anchored on the first unquoted address word; a broken record or one whose end exceeds 2^32 gives no base and no size. The release demo's tags now show Region `flash` and Split / Join lists the demo's four `a2l(4)` segments. The four `tc016s` snapshot baselines that paint these values are re-recorded in the CI recipe (Region `unknown` → `flash`, `60` → `59` issues).

## 2. Files modified

Committed vs `main` (`git diff --stat main...HEAD` at `fa35466`: 99 files, +13 491 / −674) plus this close commit. SOURCE files: **4 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/validation/rules.py` | source | US-I11-1 | ASAM block-name list (62), `IF_DATA` constant, `_iter_sections` yields `(section, inside_if_data)`, the unknown-block check skips sections inside IF_DATA (+68 / −17) |
| `s19_app/tui/a2l.py` | source | US-I11-3, US-I11-4 | `PROGRAM_TYPE_WORDS`, `MEMORY_TYPE_WORDS`, `_a2l_number`, `_memory_segment_record_words`, anchored `extract_memory_segments` with the 2^32 bound; `render_curve_description` index line (+185 / −32) |
| `s19_app/tui/issues_view.py` | source | US-I11-2 | Batch-94 triage removed (`a2l_reclassified_severity`, `adjust_counts_for_a2l_triage`, the header note); groups paint each issue's own severity (+7 / −256) |
| `s19_app/tui/app.py` | source | US-I11-2 | Filtered issue list sorted by severity rank (stable, unknown severities last); strip, summary and pages read true severities (+53 / −54) |
| `tests/test_b101_a2l_blocks_and_segments.py` | test | US-I11-1, US-I11-3, US-I11-4 | New G1 (+599): block names, IF_DATA skip, 37-file corpus, segment shapes, broken records, bound, regions, CURVE note |
| `tests/test_b101_issues_severity_view.py` | test | US-I11-2, US-I11-4 | New G2 (+458): group order, header counts, colour, filters, ordering across pages, Split / Join a2l rows |
| `tests/test_b101_inc11_acceptance.py` | test | US-I11-1, US-I11-2, US-I11-3, US-I11-4 | New G3 (+515): AT-I11-1 … AT-I11-7 through keys, dialogs and the palette |
| `tests/test_engine_unchanged.py` | test | US-I11-1, US-I11-4 | Comment: TC-027 is unfrozen for Inc 11 by OR-3 and re-freezes by merge (+4) |
| `tests/test_id_registry.py` | test | US-I11-1, US-I11-2, US-I11-4 | `EXPECTED_SCANNED_TEST_FILES` 250 → 253 (measured) |
| `tests/test_segment_split_window.py` | test | US-I11-4 | Two fixtures rewritten to the standard record shape, names unquoted (E3 A-2, F5); values unchanged |
| `tests/test_synth_release_case.py` | test | US-I11-1 | Clean demo A2L asserts `issues == []` (was "all unrecognized", vacuous on an empty list) |
| `tests/test_tui_issues_triage_b94.py` | test | US-I11-2 | Triage tests rewritten to the true-severity view; composed-row waits (SR-2); hostile-name arm with C0 bytes (C-8) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-compact-160x40].svg` | fixture | US-I11-4 | Re-recorded (CI recipe): Region `unknown` → `flash` on the 9 in-memory rows |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-comfortable-160x40].svg` | fixture | US-I11-4 | Re-recorded (CI recipe): Region `unknown` → `flash` on the 9 in-memory rows |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-80x24].svg` | fixture | US-I11-1 | Re-recorded (CI recipe): status `60 iss` → `59 iss` |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` | fixture | US-I11-1 | Re-recorded (CI recipe): status `60 issues` → `59 issues` |
| `docs/architecture.md` | doc |  | Screen table row 5, the US-004 seam paragraph and R12: view triage removed, recognition lives in `validate_a2l_structure` (C-1) |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | Twelve lines: the Inc 11 routed rows (E5-1 fill cap, E5-2, E5-5/O-6, E5-6, O-4, O-5) |
| `.dev-flow/2026-11-01-batch-101/inc-11/01-requirements.md` | doc |  | EARS requirements: 4 user stories, 28 active rows, definitions; N-1, N-4 folded |
| `.dev-flow/2026-11-01-batch-101/inc-11/02-test-cases.md` | doc |  | 78 ISO 29119-3 cases; covered 76, partial 2; Result filled at E5 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E1-rulings.md` | doc |  | E1 rulings (C-, D-, O-, OR-), D-5 residuals N-2, N-3, E5-3 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E1-slice.md` | doc |  | E1 implementation slice: nodes, owners G1/G2/G3, unchanged list |
| `.dev-flow/2026-11-01-batch-101/inc-11/E3-architect.md` | doc |  | E3 architect round 1 FAIL (1 HIGH, 3 MAJOR, 8 MINOR); round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-11/E3-security.md` | doc |  | E3 security review: PASS-WITH-NOTES, S-1, S-2 MEDIUM |
| `.dev-flow/2026-11-01-batch-101/inc-11/E3-rulings.md` | doc |  | E3 round-1 addendum and round-2 rulings, E4 addenda N-1 … N-4 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E4-impl-notes-a2l.md` | doc |  | E4 implementer notes, `a2l.py` unit |
| `.dev-flow/2026-11-01-batch-101/inc-11/E4-impl-notes-rules.md` | doc |  | E4 implementer notes, `rules.py` unit |
| `.dev-flow/2026-11-01-batch-101/inc-11/E4-impl-notes-view.md` | doc |  | E4 implementer notes, view unit (`issues_view.py`, `app.py`) |
| `.dev-flow/2026-11-01-batch-101/inc-11/E4-tester-notes.md` | doc |  | E4 independent tester notes: the three files, RED on base |
| `.dev-flow/2026-11-01-batch-101/inc-11/E4-integration-notes.md` | doc |  | E4 integration: GREEN, 0 code fixes, SR-1, SR-2, OR-5 … OR-8 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-mutants.md` | doc |  | E5 mutant table: 32 mutants, 32/32 KILLED |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES, F1 … F5 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, E5-1 … E5-6 |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-coverage-audit.md` | doc |  | Independent coverage audit: 77 cases, 26.0 % changed substantively |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-rulings.md` | doc |  | E5 rulings C-1 … C-8 and the routed rows |
| `.dev-flow/2026-11-01-batch-101/inc-11/E5-corrective-notes.md` | doc |  | E5 corrective pass: C-1 … C-8 done, 0 product changes, 9 mutants |
| `.dev-flow/2026-11-01-batch-101/inc-11/04-validation.md` | doc |  | This increment's validation record (close commit) |
| `.dev-flow/2026-11-01-batch-101/inc-11/steps.log` | doc |  | Stage log, models and UTC stamps (E5 end appended) |
| `.dev-flow/2026-11-01-batch-101/inc-11/codewire/graph-inc11.md` | doc |  | Code-wire graph of Inc 11: nodes, contracts, examples |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-011.md` | doc |  | This packet (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/red-01-tester-base.txt` | generated | US-I11-1, US-I11-2, US-I11-3, US-I11-4 | Tester RED on base: G1 102 failed / 50 passed, G2 10 failed / 1 passed, acceptance RED, split window 56 passed (pins) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-01-new-and-repinned.txt` | generated | US-I11-1, US-I11-2, US-I11-4 | E4 first run: 5 failed, 236 passed (superseded) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-02-fix-round-1.txt` | generated | US-I11-2, US-I11-4 | E4 fix round 1: 1 failed (OR-3 freeze arm), 16 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-03-importers.txt` | generated | US-I11-1, US-I11-2, US-I11-4 | E4 importers: INVALID (stray re-sync), 1 failed, 489 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-04-law-guards.txt` | generated | US-I11-1, US-I11-4 | E4 law guards: 2 failed (TC-607 count, TC-027), 86 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-05-app-directionb-snapshot.txt` | generated | US-I11-2 | E4 app / directionb / snapshot: treated as invalid; 2 failed (TC-031), 245 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-06-serial-lane.txt` | generated | US-I11-2 | E4 serial lane: 30 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-07-new-repinned-guards-final.txt` | generated | US-I11-1, US-I11-2, US-I11-3, US-I11-4 | E4 final: 2 failed (OR-3), 326 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-08-importers-rerun.txt` | generated | US-I11-1, US-I11-2, US-I11-4 | E4 importers rerun: 1 failed (tc_b100_52[case_06], load), 489 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-09-app-directionb-snapshot-rerun.txt` | generated | US-I11-2 | E4 app / directionb / snapshot rerun: 2 failed (TC-031, OR-3), 245 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-10-b100-52-branch.txt` | generated | US-I11-4 | tc_b100_52 alone on the branch: 2 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-11-b100-52-base.txt` | generated | US-I11-4 | tc_b100_52 alone on base: 2 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-12-importers-on-base.txt` | generated | US-I11-4 | The 28 importer files on base: 490 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-13-a2l-progress-branch-n6.txt` | generated | US-I11-4 | `test_b100_a2l_progress.py` on the branch (`-n 6`): 10 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-14-a2l-progress-base-n6.txt` | generated | US-I11-4 | `test_b100_a2l_progress.py` on base (`-n 6`): 10 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/int-15-importers-third.txt` | generated | US-I11-1, US-I11-2, US-I11-4 | E4 importers third run: 490 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-00a-changed-tests-first-run.txt` | generated | US-I11-2, US-I11-3 | E5 corrective development run: 2 failed (test causes), 85 passed (superseded) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-00b-changed-tests-second-run.txt` | generated | US-I11-2 | E5 corrective development run: 1 failed, 1 passed (superseded) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-01-new-repinned-guards.txt` | generated | US-I11-1, US-I11-2, US-I11-3, US-I11-4 | E5 final: 2 failed (OR-3), 331 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-02-serial-lane.txt` | generated | US-I11-2 | E5 serial lane: 1 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-03-importers-app-directionb-snapshot.txt` | generated | US-I11-1, US-I11-2, US-I11-4 | E5 importers + app + snapshot: 8 failed (OR-3 ×2, snapshot ×6), 758 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-04-snapshot-branch.txt` | generated | US-I11-1, US-I11-4 | Snapshot suite on the branch (host 2): 6 failed, 27 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-05-snapshot-base.txt` | generated | US-I11-1, US-I11-4 | Snapshot suite on base (host 2): 2 failed, 31 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-06-snapshot-text-diffs.txt` | generated | US-I11-1, US-I11-4 | SVG text diffs of the failing snapshot nodes |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-2-comment.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.2/4: `/* */` not skipped in the record words — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-default0.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4/2: no address word → base 0, size 0 — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-hex8.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4/10: 8-hex-digit limit dropped — KILLED (by S10b) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-int0.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4/9 (and /10 via S10b): Number read with `int(w, 0)` — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-quoted.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4/8: a quoted word may anchor / be the size — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-1-enc.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.1/1: groups painted in list-encounter order — SURVIVED (equivalent: `_filtered_validation_issues` sorts by rank before the panel sees the list, R-TUI-042b.5) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-1-rev.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.1/1: groups painted in reversed `SEVERITY_ORDER` — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-4-colour.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.4/1: `.sev-warning` colour → `#d9a35b` (class kept) — KILLED (the old class-only assertion would pass) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-121-nopoints.txt` | generated | US-I11-3 | Mutant transcript R-A2L-121/2: index note emitted outside `if points:` — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-025-2.txt` | generated | US-I11-2 | Mutant transcript R-TUI-025.2: re-introduce the count triage (Warnings 1, Info 3) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-025-6.txt` | generated | US-I11-2 | Mutant transcript R-TUI-025.6: as R-TUI-042b.1 (remap → Warnings view shows an INFO header) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-1.txt` | generated | US-I11-1 | Mutant transcript R-VAL-032.1: skip the check for every nested section (a "top level only" walker) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-2.txt` | generated | US-I11-1 | Mutant transcript R-VAL-032.2: drop `AXIS_DESCR` from the recognized names — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-3.txt` | generated | US-I11-1 | Mutant transcript R-VAL-032.3: treat only direct children of IF_DATA as inside — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-034.txt` | generated | US-I11-4 | Mutant transcript R-A2L-034: the base segment reader (462 `unknown`) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-1.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.1: take the first word of the `/begin` line only (base) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-10.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.10: take the first word after the name as the program type — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-11.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.11: as R-A2L-036.10 → memory type `INTERN` — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-12.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.12: keep the words found anyway (`DATA` / `FLASH`) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-13a.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.13: drop the bound — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-13b.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.13: compare with "at least 2^32" (reject sum == 2^32) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-2a.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.2: read a Number with `int(w, 0)` (so `0400` is not a Number) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-2b.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.2: take the fourth word of the first line of 5+ words (base, positional) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-3.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.3: take the word after the size (the offset) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-4a.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4: scan on for the next two adjacent Numbers (the E1 rule) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-4b.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.4: accept a single Number as the base — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-6.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.6: take the offset from the sixth word of the line (base) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-7.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.7: fall back to the text `UNKNOWN` (base) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-8.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.8: take the first program-type word after the name — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-9a.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.9: take the first memory-type word after the name — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-9b.txt` | generated | US-I11-4 | Mutant transcript R-A2L-036.9: take the word two before the base (positional) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-1.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.1: re-introduce a presentation remap of `A2L_UNRECOGNIZED_BLOCK` to INFO — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-2.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.2: re-introduce the count triage (WARNING → INFO) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-4.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.4: as R-TUI-042b.1 (remap → row is `sev-info`) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-5.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.5: page the unsorted list (base line) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-6.txt` | generated | US-I11-2 | Mutant transcript R-TUI-042b.6: restore the justification note after the header — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-120.txt` | generated | US-I11-3 | Mutant transcript R-A2L-120: count from 1 — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-121.txt` | generated | US-I11-3 | Mutant transcript R-A2L-121: emit the line per point — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-122.txt` | generated | US-I11-3 | Mutant transcript R-A2L-122: keep the per-row suffix (base) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-123.txt` | generated | US-I11-3 | Mutant transcript R-A2L-123: emit R-A2L-121's line for any missing axis value — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-seg-src-6.txt` | generated | US-I11-4 | Mutant transcript R-SEG-SRC.6: the base segment reader (`a2l(0)`) — KILLED |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-00-summary.txt` | generated | US-I11-1, US-I11-4 | Snapshot re-record summary: runs, per-node diff, refused nodes, baseline digests (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-01-base-origin-main.txt` | generated | US-I11-1, US-I11-4 | CI recipe on `origin/main` alone: 2 failed (known patch-comfortable), 27 passed (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-02-inc11-before-rerecord.txt` | generated | US-I11-1, US-I11-4 | CI recipe on the Inc 11 tree: 6 failed, 23 passed (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-03-rerecord-four-nodes.txt` | generated | US-I11-1, US-I11-4 | `--snapshot-update` per node, 4 × 1 passed (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-04-svgdiff-per-node.txt` | generated | US-I11-1, US-I11-4 | Element-level diff of the 4 re-recorded SVGs (close commit) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-05-inc11-after-rerecord.txt` | generated | US-I11-1, US-I11-4 | CI recipe after the re-record: 2 failed (known), 27 passed (close commit) |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** |
| Test files | 9 (3 new, 6 changed) + 4 snapshot fixtures (uncapped) |
| Doc files | `docs/architecture.md`, `.dev-flow/BACKLOG-CODE.md` and the records (outside the count) |

- ⚠ **At exactly 4 source files:** planned at E1 (`E1-rulings.md` D-10). Removing the display triage (D-2) leaves its import and two count wrappers in `app.py`, and the severity sort of R-TUI-042b.5 is one expression in `app.py` (rulings OR-1, OR-2: yes). Keeping the triage dormant to save `app.py` would still re-label a top-level `PAGE` WARNING as INFO against R-VAL-032.1, so the increment could not be cut smaller.

## 3. How to test

```bash
# LAN Linux host, Python 3.11, own worktree with the branch diff applied (never the Windows PC)
env -u NO_COLOR python -m pytest -n 8 -m "not serial_timing" \
  tests/test_b101_a2l_blocks_and_segments.py tests/test_b101_issues_severity_view.py \
  tests/test_b101_inc11_acceptance.py tests/test_tui_issues_triage_b94.py \
  tests/test_synth_release_case.py tests/test_segment_split_window.py \
  tests/test_engine_unchanged.py tests/test_id_registry.py tests/test_suite_hygiene.py \
  tests/test_requirements_canon.py
python -m pytest -m serial_timing <same files>
# snapshot job, CI recipe (venv: pip install -r requirements.txt && pip install -e ".[dev]")
env -u NO_COLOR python -m pytest tests/test_tui_snapshot.py -m snapshot
```

## 4. Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | G1 (152 at E4 + 3), G2 (11 + 2) | passed in `e5c-01` (331 passed; the 2 failures are OR-3) |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | the 71 requirement cases of `02-test-cases.md` | verified (linux py3.11, `e5c-01`, `e5c-03`) |
| **B · black-box** `AT-NNN` ↔ story | `core` · `full` | AT-I11-1 … AT-I11-7 (G3) | 7 passed (`e5c-01`); AT-I11-7 new at E5 |

Snapshot job (CI recipe, laptop host): before 6 failed, 23 passed; after the re-record 2 failed, 27 passed — the 2 known `patch-comfortable` nodes, which fail on `origin/main` alone (`snap-01`, `snap-05`). OR-3 freeze guards (TC-027, TC-B94-18 freeze arm, TC-031 ×2): RED on the branch by design; owed GREEN on the merged tree. Coverage after the corrective pass: 78 cases, 76 covered, 2 partial, 0 gap. Code coverage (line, branch): `not-run`.

trace_check (`--req inc-11/01-requirements.md inc-11/E1-slice.md --tests tests --base b7b77c4 --src s19_app`), last line: `trace_check: 4 US, 28 active requirements (2 withdrawn), 2 gap(s)` — the 2 gaps are TEST lines: R-A2L-036.3 and R-A2L-036.6 are named by no file under `tests` (their cases run through `test_a2l_enriched.py::test_tc682_*` and G1's `test_r_a2l_036_name_first_record_line_software_a`, which do not cite the ids); 0 EVID gaps after the close files were staged

Validator (`devflow-validate.py --brief`): `4 block · 776 notice · 39 not applicable` — the 4 blocks are V20 (`.dev-flow/_derived/ATLAS-*.md`, the orchestrator's atlas regeneration); none names an Inc 11 file. Inc 11's own line is the V9 notice (4 source files, reason in §2)

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The increment's own new assertions on base `origin/main` (no difference from `b7b77c4` in the touched modules): G1 102 failed, G2 10 failed, acceptance RED — `evidence/inc-11/red-01-tester-base.txt`; and one mutant per negative control on the branch tree (32/32 KILLED, `evidence/inc-11/mut-*.txt`), each restored to the branch baseline digests `rules.py` d3fd869193b6a207040d67c75cdc3d03b88115a9938715732131759640081130, `issues_view.py` f543a58ecc7274d03adf3dd95a6c670187242ad6225ebbcf5206236012c1dd3a, `a2l.py` e99d9e15da3f31160046889300ac41f0741ca917166ecea18da6f27c0d9f89a8, `app.py` c3197405780f9d871045c8ba3e6684681d6eb95eaa912b2e995a664d208d9fe3 (verified after every restore, `E5-mutants.md`) |

| Field | Value |
|---|---|
| **Mutation verdicts** | 41 mutants: the E5 battery 32/32 KILLED (one per negative control of the 28 active rows; per-row verdicts and nodes in `E5-mutants.md`, transcripts `evidence/inc-11/mut-*.txt`) + the corrective pass 9 (8 KILLED, 1 SURVIVED as equivalent: `m-042b-1-enc`, the list reaches the panel already sorted by rank, R-TUI-042b.5; `evidence/inc-11/e5c-mut-*.txt`, restore by sha256 with `ok=True`, tree fingerprint `3095a2c7fd8b4a6b` before and after every mutant). Arms that stayed GREEN: `m-036-4-hex8` leaves `[nine_hex_digits-*]` GREEN (the bound masks it) and is killed by `[nine_hex_digits_small-*]`; no real survivor |

### Instrument RED-proof

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| G1 / G2 / G3 (the new test files) | the base tree (no Inc 11 code) | 102 + 10 failed, acceptance RED — `red-01-tester-base.txt` |
| R-TUI-042b.4/1 colour assertion | `.sev-warning` colour changed, class kept (`m-042b-4-colour`) | `#D9A35B` ≠ `#F6FF8F` — `e5c-mut-042b-4-colour.txt` (the old class-only check would pass) |
| Snapshot suite, CI recipe | the Inc 11 tree against the old baselines | 6 failed, naming the 4 changed nodes + the 2 known — `snap-02-inc11-before-rerecord.txt` |
| SVG element diff helper | the 4 re-recorded SVGs vs their HEAD baselines | 9 changed rows per a2l node, 1 per map node (non-empty) — `snap-04-svgdiff-per-node.txt` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown reporting a FAILURE before its PASS was believed (table above) |

### Emitted-form assertion

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| The rendered TUI screens (tc016s SVG captures) | `pytest tests/test_tui_snapshot.py -m snapshot` compares the SVG the app paints with the stored baseline | 27 passed, 2 failed (known patch-comfortable) — `snap-05-inc11-after-rerecord.txt` |
| The Issues screen and Split / Join window painted through keys | G3 reads the painted status line, group headers and table rows (e.g. `total=262 … warnings=262`, `(boot, 0x00000000)` …) | 7 ATs passed — `e5c-01-new-repinned-guards.txt` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 2 artifacts, each asserted against the form the app emitted (table above) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 (`sha256sum`) of the bytes at the cited path, taken at the close commit. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/` — the home `artifact_homes.evidence` declares.

| Evidence artifact | Path — under `artifact_homes.evidence`, repo-relative | SHA-256 |
|---|---|---|
| e5c-00a-changed-tests-first-run.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-00a-changed-tests-first-run.txt | 10b6e9bc7a89bfc55b81ff286fefeb1308ff91a4c52ad90441b8737ee17fe694 |
| e5c-00b-changed-tests-second-run.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-00b-changed-tests-second-run.txt | 2981cccf4ce45fd28293af4a249a4c1519acb8f73bc5023b67a471ec6fa7864c |
| e5c-01-new-repinned-guards.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-01-new-repinned-guards.txt | dbb78b639ea92c731a243a57c902f436118dac0e15cafd1fb07916b63dd65cd9 |
| e5c-02-serial-lane.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-02-serial-lane.txt | 62387372aa0a210133b482127e54ccc14862ff840e8c15dd3f7ae33ae23684aa |
| e5c-03-importers-app-directionb-snapshot.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-03-importers-app-directionb-snapshot.txt | f4f83718a25bfa30e5dba8e4b3aebf44de9123371db5bf7938e3f94d44e27efa |
| e5c-04-snapshot-branch.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-04-snapshot-branch.txt | fc4ba56cd3b53e722104f69922e20eabb8c4cc539a2592c851a06fe098c3d7d3 |
| e5c-05-snapshot-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-05-snapshot-base.txt | e6dacba6432e76b9c92345f1c7728164e30787e7911578948007d5b12fe8b3c3 |
| e5c-06-snapshot-text-diffs.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-06-snapshot-text-diffs.txt | eec43d07461235ae606a752fbbff68e9033f2497e4f457402366aaa2109e7776 |
| e5c-mut-036-2-comment.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-2-comment.txt | 2add91aa8ec017523405b0b9051b38c05d051f56f9f1ceaa7b531131bd47e83d |
| e5c-mut-036-4-default0.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-default0.txt | f4c99662783f5aa0515dbc76f516ba0106e4fa4e4acd96031860bf2d13a88173 |
| e5c-mut-036-4-hex8.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-hex8.txt | b0e562c54659f580b2287c429adfd8908594405e48435ed5f2cea8930c6ac6d1 |
| e5c-mut-036-4-int0.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-int0.txt | 3b6c2c90221c9cc1bc0555e9fd6f788cac3743f3a4c0dab875089b9c8b30bec2 |
| e5c-mut-036-4-quoted.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-036-4-quoted.txt | 5b97622ab2458ef2132dc60f8ce4d9bef497b76fae808ed9afce230b2586e150 |
| e5c-mut-042b-1-enc.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-1-enc.txt | ed4ba0e2865957fb6920905d641ee664617972aa970178bd6cdb9b80cf2f9ed6 |
| e5c-mut-042b-1-rev.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-1-rev.txt | 56243b305c1e0bc0fe26e52da7eb706efb18feb4beb8cb0ad9aa431660e6fb1c |
| e5c-mut-042b-4-colour.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-042b-4-colour.txt | 2db635efc0e44ad9b7bfa94494d68f1018e5548f0719bfa320b555bf2db1462e |
| e5c-mut-121-nopoints.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/e5c-mut-121-nopoints.txt | 261ec40e4bfb93aeb56f60ac54ac98febea1e223fb983892564ad043c4032f7d |
| int-01-new-and-repinned.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-01-new-and-repinned.txt | 92eef320a2ac6c99d14d293a336c60bfc47c9753a924a353ef23454f210667e7 |
| int-02-fix-round-1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-02-fix-round-1.txt | 0f8ad6c8cb66a7aaf5bb743b55c1f848033862ddf3b0699e116dda5a732dd074 |
| int-03-importers.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-03-importers.txt | ac0a6b2fb19365bad057eeec9c0dc9237410598b000dd2fadfd866dab890ff32 |
| int-04-law-guards.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-04-law-guards.txt | 9cb463aef6bf934c372208c17402dd08967f3be2f8f468bfe58df31f5826c687 |
| int-05-app-directionb-snapshot.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-05-app-directionb-snapshot.txt | 3ae07ab5134dd20d57d545b4073efbf64cd6fcec4587348f5c84c0b0c87dfc4c |
| int-06-serial-lane.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-06-serial-lane.txt | 991988cb65e54f0c2b6f9616133496746fdf085e28e58d796cceafed9abc2c70 |
| int-07-new-repinned-guards-final.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-07-new-repinned-guards-final.txt | 39a58b6972581ee7eabd67bc4c95a529dbcf277d22a1978bc5011c70a320ac06 |
| int-08-importers-rerun.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-08-importers-rerun.txt | b80ebaa21648881f64f6ffddfdf955c5460d2eeeb8f1f73bc17f384eb39c3504 |
| int-09-app-directionb-snapshot-rerun.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-09-app-directionb-snapshot-rerun.txt | a5760db8ebacf22913cb81db7aba3c9f6976a1fd90005982a8e83c2315aa67dc |
| int-10-b100-52-branch.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-10-b100-52-branch.txt | 73c7af0674e7403afd0378dd039925c2d931bbe7b9fa93722d02d9e77600aaeb |
| int-11-b100-52-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-11-b100-52-base.txt | 3b79204c7ef0692de6214f1594bc9351995b8cce338acebac7647347676d2196 |
| int-12-importers-on-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-12-importers-on-base.txt | 3153d315cc0679a1aefbac34544501c554980db3eb27b0a720c565b3434fa65d |
| int-13-a2l-progress-branch-n6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-13-a2l-progress-branch-n6.txt | 21c19c9e55009bfdf4054d6084be107ab84cb1263de292ad76868d53d23c4ea0 |
| int-14-a2l-progress-base-n6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-14-a2l-progress-base-n6.txt | 3887b47f76b944a881061308a61fcbf73fba3f29abc6cb7a7042291bdd4cf33e |
| int-15-importers-third.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/int-15-importers-third.txt | 604aaac63b5931fe919e961513ff122092b8e82c1ef7d39cfbca1e823fd23669 |
| mut-025-2.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-025-2.txt | 51aa790a667e8eabc1223543bdec7a0aa34f4953bc2585a049cf8ed63f91183f |
| mut-025-6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-025-6.txt | c68b4d6ba21dcfc1ebe1268b3d72dc5e4b3d5c26560be762502b364e65fc2eb0 |
| mut-032-1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-1.txt | 6353b38964acb2a65bbdda54a0ecc6f2b50ec8b3fa263f1f24989626eb8b9e7a |
| mut-032-2.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-2.txt | df5e39128e1d19ded5fa86f19eefd810ef45b4bd0cb8c1828acbecf8137dc337 |
| mut-032-3.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-032-3.txt | 460a108d310c0ac9eb9617756197251575589ecff8c5b823bea597311fd996df |
| mut-034.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-034.txt | 0f90a5ead03c52561fb559cbf998a41b92f5747dc7c3c324be3753801debddb2 |
| mut-036-1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-1.txt | e2d5a82c5f23c1c900fdfd190ff872313cff73c6977a6e4e141b6605dfdcbc42 |
| mut-036-10.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-10.txt | 2fcfb84eac466e28d841a7903fefe16244158b0100b619c128d66105e18dfd8f |
| mut-036-11.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-11.txt | a0b5d3cbd5028f168e9d4773c1de0b06570874fd696481455d090616085e84ba |
| mut-036-12.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-12.txt | 742018a2ff6e01b7184d7c5306f165a854d31721824f595c90f1b8448f287e66 |
| mut-036-13a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-13a.txt | 0251af2d502cbeeca130e34c03e1b0e3f9ba9931d1da58a7a54e8a68d6938760 |
| mut-036-13b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-13b.txt | b59d30886aea27eed5a2cfb70b7b740ffdb0d2430079da28a790cc85103bcd5c |
| mut-036-2a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-2a.txt | e1a30df9298911d855f3c10ffcbf9017b1b4c847ff070ac1af4d1c8404a3ff79 |
| mut-036-2b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-2b.txt | 1447c95baac1c63b6951839da4e6b6398d4aa4ca7af33af3ef809c450d28c3f0 |
| mut-036-3.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-3.txt | ba9f37cfd6d22536c13cdeb5c1bac078fb8a17602e2727c3569cc4c2da0fad82 |
| mut-036-4a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-4a.txt | 0f559c5753aaca04c1f2db1f99bf9fb1442de409e351fae9626547eb489943c6 |
| mut-036-4b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-4b.txt | 01a938bc4652fbbc86ce3ffb91b7d94ed1b25b8ea47ed0cc557eaee70863da8f |
| mut-036-6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-6.txt | b113cdec011ac6a1db21f635f50df7650eaaef723abb6fc257e90917793f9205 |
| mut-036-7.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-7.txt | eb569c020a23ab770e494b35d162ab5bd21e7a4de3a597e07710ea2e624900c4 |
| mut-036-8.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-8.txt | efc6b806aff4e249fea6168a94d3ecd4c7b985158a830d3b7a64d8683051f92b |
| mut-036-9a.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-9a.txt | cfa7030aadd228d396e856a109acd0d85d8067871b420bea48fde2905ffeb366 |
| mut-036-9b.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-036-9b.txt | bfc19559efc433b55330250dcd5aa3ade9ea999db5a380b9beb6b2d695da8cf4 |
| mut-042b-1.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-1.txt | 3f8c1c3ecdd9deae4dfa0c96efdc10d04e25cd2c6b97931cbd52c2182b835d60 |
| mut-042b-2.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-2.txt | 6c618d178f382185e836b965cedcb4017d815379e41bb116f32bb43949312d41 |
| mut-042b-4.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-4.txt | 18b399972312653fabb25eee23f9dbd6823aa0c900f16a1fcba9a50fe14aa31f |
| mut-042b-5.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-5.txt | b2c5126b68a43e07dc8c795b08cead8cace32a59e5e53549ba2e54004fc25b71 |
| mut-042b-6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-042b-6.txt | 8ed84a88de9d4750fb85fc690d6458564400de6bb6e6886d35fd3b376054fc97 |
| mut-120.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-120.txt | 81127199d7bd23bfb01dedc603819f5d72873e1f9932b6143d913a0f908041cc |
| mut-121.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-121.txt | 5908dcd08231f03fec0d0bd699ab1fd29ad3582f8831a120e57dc5e76709f19c |
| mut-122.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-122.txt | 0a7f6e027999e9f717631cff709cb3381db7834a0309e2d64a421dacd8fc5a4b |
| mut-123.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-123.txt | f7d67e6961cbe85033e6e555cd71dd6b781e8c07dc25703ec6a9c802c9a638b3 |
| mut-seg-src-6.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/mut-seg-src-6.txt | 12fca48b392e107c17987eff53765dce562c09115647a049d02c533322556a15 |
| red-01-tester-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/red-01-tester-base.txt | 35ae820976fa437bf654f8cca465430e6fc40c5036516212c9861891b7b865d2 |
| snap-00-summary.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-00-summary.txt | 0f29a635cfff1b663ae3deef44750111c2892fc75e996c4892cd065fb87a0dba |
| snap-01-base-origin-main.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-01-base-origin-main.txt | 578f3bb4bac8aeaeff7804040eb866cc090f08eb417ff6ee3628592dc9bcb527 |
| snap-02-inc11-before-rerecord.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-02-inc11-before-rerecord.txt | 22708e577153f1aa401a4102f0793e45c4ac1a045c6a522cc8be7712ca4f9e3e |
| snap-03-rerecord-four-nodes.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-03-rerecord-four-nodes.txt | 3757a3b1fca8e4dd69faf1d343f1c6f93559ff034d53c4f6d1248e62d1dfd458 |
| snap-04-svgdiff-per-node.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-04-svgdiff-per-node.txt | ddfc56ea5372b2de958f73b753741e0f973d88e2216ab7382991673adce20825 |
| snap-05-inc11-after-rerecord.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-11/snap-05-inc11-after-rerecord.txt | 21cadd318cceceb0eab8a8f63f8aea2863d0639fa86605d8edb3a20e79a51c2d |

| Field | Value |
|---|---|
| **Evidence files** | 71 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names (`repo:.dev-flow/2026-11-01-batch-101/evidence/`) |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: the 37-file A2L corpus and the clean release demo raise no `A2L_UNRECOGNIZED_BLOCK` (R-VAL-032.2, .3); the re-recorded SVGs change in no other element |
| If the result is an ABSENCE, what made the search wide enough | every tracked A2L file (37) is walked; the SVG diff compares every element of each file, not only the text |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_val_032_3_software_a_raises_no_unrecognized_block`, the corpus ids of `test_r_val_032_2_*`, `test_synth_release_case.py::test_a2l_zero_issues` |
| Conjunctive criteria: one mutation per conjunct | R-A2L-036.4: `mut-036-4a` (scan on) and `mut-036-4b` (single Number); R-A2L-036.13: `mut-036-13a` (no bound) and `mut-036-13b` (≥ instead of >) — all KILLED |
| Synthetic instance of the absent case | G1 records S1 … S13, S10b, S11b; unknown names at top level and nested (R-VAL-032.1) |
| **Positive control for every probe that returned an ABSENCE** | R-VAL-032.1 nodes report the WARNING for an unknown block outside IF_DATA; `mut-032-2` (drop `AXIS_DESCR`) is KILLED by the corpus/zero-issue tests; base reports 102 warnings on the clean demo; the SVG diff reports the 9 / 1 changed rows on the same files |

### Reverse census

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by other tests | `grep -rln -E 'a2l_reclassified_severity\|adjust_counts_for_a2l_triage\|_UNRECOGNIZED_BLOCK_RE' s19_app tests docs` | 0 hits (removed symbols have no reader) |
| B2 file moved on disk | none moved | n/a |
| B3 golden captures of this source | `test_tui_snapshot.py` tc016s SVGs paint the Region column and the issue count | 4 baselines re-recorded in the CI recipe; `tests/goldens/**` holds no `A2L_UNRECOGNIZED_BLOCK` text (grep 0) |
| B4 artifact consumed elsewhere | `extract_memory_segments` output | `a2l.py` (`extract_a2l_tags`), `a2l_parse.py`, `segment_split_view.py`; tests `test_a2l_enriched.py`, `test_segment_ops.py`, `test_segment_split_window.py` — all in the E4/E5 importer runs, GREEN |
| A3 interface consumed by another module | `grep -rn _iter_sections s19_app tests` | 1 caller (`rules.py:533`), inside the diff |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run (B1, B2, B3, B4, A3); B3 and B4 hits re-validated by the snapshot re-record and the importer runs (`e5c-03`, `snap-05`) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 2 corrections: the view triage removal (every reader of the three removed symbols, enumerated by the B1 grep before E4: `issues_view.py`, `app.py`, `test_tui_issues_triage_b94.py` — all edited, 0 left); the record-shape fixtures of E3 A-2 (`test_segment_split_window.py:120-140, :1205-1222`, enumerated in `E1-slice.md` §4 — both edited) |

### Signed-balance test ledger

n/a — not computed for this increment; the node counts per file are in `E4-integration-notes.md` and `E5-corrective-notes.md` (331 = 326 + 5 new nodes in the same set).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** — no BLOCKER or MAJOR; F1 (`docs/architecture.md` triage text) and F2 (N-1, N-4 row wording, D-5 residuals) MINOR, F3 … F5 NIT, all closed by the E5 corrective pass (F5 partial: `tc710` keeps `'PrgCode'`, which pins the sanitiser) — `inc-11/E5-code-review.md`, `inc-11/E5-corrective-notes.md`. `security-reviewer` · **PASS-WITH-NOTES** — no HIGH; S-1, S-2, S-5, S-6 closed on the code; E5-1 MEDIUM (Split / Join fill size cap) routed to the backlog; E5-4 hostile-name arm strengthened (C-8) — `inc-11/E5-security.md`. `qa-reviewer` coverage audit — 77 cases, 20 changed substantively; after the corrective pass 78 cases, 76 covered, 2 partial, 0 gap — `inc-11/E5-coverage-audit.md`. The independent `tester` (Sonnet) wrote G1, G2, G3 from the design records and ran them RED on base only — `inc-11/E4-tester-notes.md`. **Design reviews (E3, code-free):** `architect` round 1 **FAIL** (A-1 HIGH; A-2 … A-4 MAJOR) and `security-reviewer` round 1 **PASS-WITH-NOTES** (S-1, S-2 MEDIUM) → round 2 **PASS-WITH-NOTES**, all six closed, N-1 … N-4 folded — `inc-11/E3-architect.md`, `inc-11/E3-security.md`, `inc-11/E3-rulings.md`. |

## 5. Risks

- The OR-3 freeze guards (TC-027, TC-B94-18 freeze arm, TC-031 ×2) are RED until the merge puts the new `rules.py` / `a2l.py` bytes on `main`; a push without the merge-tree run would leave CI red on them.
- E5-1: a hostile A2L can still declare a segment covering the whole 32-bit space (`0 4294967296`); a Split export with intra-gap fill on that row has no size guard (backlog).
- `tc_b100_52[case_06]` timed out once under heavy shared-host load (int-08); it passed in every later run, including `e5c-03`.
- The snapshot baselines were re-recorded on the laptop host with the CI pins, not on GitHub's runner; the CI snapshot job after the push confirms them.

## 6. Pending

- **Clean-up on LAN Linux host 2** (unreachable over ssh since the corrective pass): `<HOME>/work/s19_c11`, `/tmp/c11e5_*`, `/tmp/pytest-s19c11`.
- OR-3 guards GREEN on the merged tree before the push; the CI snapshot job read after the push.
- Partial cases R-A2L-036.7/1 and R-SEG-SRC.6/2 (black-box route owed); the R-VAL-032.2/3 corpus oracle still walks the parser's tree (O-5 backlog bullet).
- Backlog rows already in `.dev-flow/BACKLOG-CODE.md`: E5-1, E5-2, E5-5/O-6, E5-6, O-4, O-5.
- The snapshot before/after goes on the batch-end review page (`snap-00-summary.txt`).

## 7. Suggested next task

Merge `b101-inc11` into the batch line, run the OR-3 freeze guards and the snapshot job on the merged tree, then do the host-2 clean-up when it answers.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4 / 4, reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | 3 new + 6 changed test files, 78 cases |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | G1, G2 in `e5c-01` (331 passed) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | `red-01-tester-base.txt`; 32/32 mutants with the restore digests, §4 |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | five probes, §4 |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | PASS-WITH-NOTES, §4b |
| 7 | No file from another lane touched | all | ✓ | single lane |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ⚠ | `rules.py`, `a2l.py` unfrozen by OR-3; re-freeze by merge (TC-027, TC-031 owed GREEN on the merged tree) |
| 9 | Coverage claims verified on disk | all | ✓ | 78 cases' nodes collected and run in `e5c-01`, `e5c-03` |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 |
| 11 | **Mutation verdicts** declared | all | ✓ | 32/32 + 9 (8 KILLED, 1 equivalent), §4 |
| 12 | **Instrument RED-proof** declared | all | ✓ | 4 instruments, §4 |
| 13 | **Correction population** declared | all | ✓ | 2 corrections, §4 |
| 14 | **Emitted-form assertion** declared | all | ✓ | 2 artifacts, §4 |
| 15 | **Independent review** names somebody | all | ✓ | §4b |
| 16 | **Evidence files** declared | all | ✓ | 71 transcripts with digests, §4 |
