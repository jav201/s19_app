# 02 — Cross-agent review · batch-35 · Report filter file + patch-editor regroup

**BLUF.** Three independent lenses reviewed `01-requirements.md` @ `79699a5` (2026-07-10).
Verdict: **iterate to Phase 1 (amendment pass)** — 3 blockers, 10 majors, 12 minors; every
finding carries a named bounded fix. The draft's verification hygiene held up (all three
reviewers re-read the citations and found them exact, shall/should discipline clean, derivation
complete, ledger base 1270 reproduced); the gaps are semantic pins, observation arms, and one
architecture correction — none reopens the operator-locked scope.

## Verdicts
| Lens | Verdict | Blockers | Majors | Minors |
|------|---------|----------|--------|--------|
| architect | iterate | F-01, F-02 | F-03..F-06 | F-07..F-11 |
| qa-reviewer | iterate | Q-1 | Q-2..Q-7 | Q-8..Q-12 |
| security-reviewer | PASS-with-conditions | — | S-F1, S-F2 | S-F3..S-F6 (+S-F7 pre-existing, out of scope) |

## Blockers

**F-01 (architect) — unconditional artifact-record forwarding breaks byte-identity.**
LLR-054.1 forwards `a2l_records`/`mac_records` into both diff generators unconditionally; those
kwargs feed `_annotate_run` (diff_report_service.py:653-693), which today renders `-` for every
run on the before/after path — forwarding changes UNFILTERED run-table bytes, contradicting
LLR-054.4/HLR-054.

**F-02 (architect) — project-report filter half unimplementable as decomposed.**
(i) The claim "check entries carry no `linkage_symbol`" is FALSE (`CheckRunEntry.linkage_symbol`
at changes/model.py:678, populated at changes/check.py:346/:387) — range-only checklist matching
would hide a symbol-matched check row while the same symbol's Modifications row shows.
(ii) No LLR delivers A2L/MAC records to `generate_project_report`, so match branch (c) cannot be
built on that path.

**Q-1 (qa) — byte-identity goldens not executable through the specced surface.**
Neither handler passes `now_fn` (app.py:1868-1873, :2372-2374); surface-driven output embeds real
timestamps in content AND filename, so bytes can never equal a golden. The cited service seams
exist but are unreachable from the ATs as written.

## Unifying resolution — D-9 "resolved-matcher" architecture (adopted for the amendment)
Parse + resolve on the UI THREAD at trigger time: the app parses the selected filter file and
resolves it against `loaded.mac_records` + `_compute_a2l_enriched_tags()` into a
`ReportFilterMatcher` (patterns + pre-built sorted matched-address ranges). ONLY the matcher
(default None) flows onward — composer kwarg, `ReportOptions` field, worker argument. NO
`a2l_records`/`mac_records` kwargs are added to any generator call; annotation inputs stay
byte-identical (kills F-01); the matcher carries branch (c) to the project report (kills
F-02-ii); UI-thread capture + refusal-before-worker kills F-04's stale/torn window and moves the
refusal ahead of the expensive variant run. Q-1 resolves by pinning golden mechanism (a):
surface-driven ATs with the services' `_default_now` monkeypatched as an environment pin (same
pin used for base-revision golden capture).

## Majors (disposition)
| Id | Finding (short) | Fix folded |
|----|-----------------|-----------|
| F-03 + Q-2 | Merged-window semantics: excluded run's bytes can render inside a window spanning two matched runs; TC-312 threshold self-contradicts | Pin: the filter hides ITEMS (rows + windows SEEDED by unmatched runs); merged-window/context rows MAY cover excluded addresses, disclosed informatively; re-scope TC-312 threshold to linkage rows + window headings; add the A9 TC |
| F-04 | Worker-thread read of the sticky selection (stale/torn); parse-inside-worker refuses too late | D-9: UI-thread capture+parse+resolve; matcher passed as worker arg |
| F-05 | (i) Selector not re-seeded on screen reopen (lying UI); (ii) hostile filenames as Select option prompts | (i) seed from `_report_filter_path` (declared_regions precedent screens.py:894-900); (ii) escape option labels (`rich.markup.escape` or Text) + C-15 runtime probe on textual==8.2.8 + AT-056b opens the overlay |
| F-06 | 01↔01b AT-id registry collides (AT-053b, AT-056c double-booked; census row 1 contradiction) | §6.4 reconciliation table 01b→01; 01 canonical; LLR-057.3 threshold reworded to permit census-authorized extends |
| Q-3 | Hostile file-side sanitation has no black-box observer (AT-053b tied to refusal which writes nothing) | AT-053b redefined: VALID filter, hostile filename+patterns → generation proceeds → status literal AND all written files re-read + sanitation asserted |
| Q-4 | Typed-path selector arm has no Layer-B coverage | NEW AT-056d: typed path → filtered report; symlink/missing → refusal via surface |
| Q-5 | A/B-diff-stays-complete guard lost its black-box arm (sticky-state leak is handler-level) | NEW AT-056e: filter selected → drive A2B report → byte-identical to no-filter A2B run |
| Q-6 | AT-056a spans 3 concerns (C-18 strain) | Split: AT-056a (selection→both triggers), AT-056a2 (geometry both regimes), AT-056a3 (project-switch reset); AT-053a explicitly stays ONE node |
| Q-7 | 50-char status cap makes combined refusal assertion unsatisfiable | Message budget: confirmation carries filename, refusal carries fault; ATs assert per-message |
| S-F1 | C-17 not closed over `notify()` (markup-interpreting, in active use) and Select option labels | LLR-053.6 extended: filter-derived text shall not route via `notify()`/`set_file_status`, grep-verified at Phase 3; option labels per F-05(ii) |
| S-F2 | Symlink check scan-time-only on dropdown arm (TOCTOU swap window) | `read_report_filter_text` refuses symlink/non-regular-file at READ time; TC-317 swap case |

## Minors folded in the same pass
Q-8 (TC-319/320 bodies defined), Q-9 (extent discriminators: byte_size None/0 fallback, extent-END
negative twin, MAC-point vs A2L-extent fixture), Q-10 (address domain bound 2^32 + hex/int
equivalence + unbalanced-bracket `CAL_[` case), Q-11 (record AT-053c→TC-310 supersession),
Q-12 (zero-match vs refusal wording pin in AT-054c), F-07 (per-section shown/hidden counts
definition), F-08 (citation precision: `_compute_a2l_enriched_tags` def app.py:8009; Select.NULL
runtime handling screens_directionb.py:2148-2159; A2B precedent is partial — allow_blank
divergence noted), F-09 (project-switch reset funnel named), F-10 (informative note: extent-matched
row may annotate `-`), F-11 (empty-include=valid→zero-match recorded as D-10), S-F3 (filter-specific
4 MiB size cap — amend "not redefined" to "not larger than"; correct §6.3 risk-6's threading claim:
the `b` path is synchronous), S-F4 (never-raise extends to match-engine classification; all per-run
filter computation completes before the first file write), S-F5 (non-cell header lines pass
ctl-strip minimum; out-of-project free path pinned ALLOWED read-only), S-F6 (informative
audit-header position pin + TC-312/314 position assertion).

**S-F7 (pre-existing, NOT this batch):** `report_service.py:696-704` interpolates
`entry.linkage_symbol` raw — byte-identity locks it unfiltered; proposed as a backlog follow-up
(sanitize `_modifications_lines` under golden-regen discipline).

## Positive verification (evidence, all three lenses)
- shall/should: 0 modal `should` in normative statements; 44 `shall` all inside HLR/LLR (architect grep).
- Derivation complete; no orphans (architect walk).
- Grid-3 layout pin RE-VERIFIED surviving 4 buttons (test body asserts layout+columns only) — QA
  corrected its own 01b census row; residual: LLR-057.1 implicitly locks grid-3, now stated.
- Refusal sequencing parse-before-any-write correct as written on both surfaces (security).
- `filters/` workspace neutrality verified (workspace.py:360-369); no new write path into it.
- No LLR echoes matched artifact names into any new surface (security sweep).
- Ledger base 1270 reproduced by execution; all id probes reproduce (QA).
- F-1 extent semantics coherent: `byte_size` int-or-None verified; corrupt values non-crashing by
  construction; no existing consumer assumes point semantics for the net-new matched set (architect).

## Gate decision
**iterate (Phase-1 amendment pass)** — blockers force it per the flow. All folds enumerated above
are bounded one-paragraph LLR edits + AT registry updates; the amendment agent applies them, an
independent checklist verification confirms, then this phase re-gates. Increment cut for Phase 3
adopted from the architect (goldens-first Inc-0; regroup Inc-5 independent).

## Re-gate (2026-07-10, after the amendment pass)
- Amendment applied: ALL 25 findings folded, none skipped (agent report: 29 §6.4 rows + 5-row
  01b→01 AT registry sub-table; 18 §6.5 records = 17 Amended + 1 New LLR-053.7; final census
  17 ATs / 14 TCs; S-F7 correctly left untouched as pre-existing/backlog).
- Independent checklist verification: **CLEAN 12/12** with quoted evidence per item — F-01 dead
  (record kwargs prohibited, ONE `report_filter` kwarg), F-02 corrected (linkage_symbol branch
  cited), Q-1 pinned (`_default_now` environment pin + no-now_fn citations both paths),
  F-03/Q-2 pin + re-scoped TC-312 threshold + A9 case, F-04 UI-thread capture, F-05 seeding +
  option-label escape + probe flag + overlay AT, S-F1 notify/set_file_status prohibition +
  exit grep, S-F2/S-F3 read-time refusal + swap case + 4 MiB cap, 17-AT chain exact, shall
  discipline clean, record counts match, contradiction sweep clean.
- **Decision: APPROVE (under standing authorization).** Exit axes: Coverage — dual chains
  complete, every LLR has a TC/AT; Certainty — all blocker classes closed with discriminating
  pins; Evidence — checklist verification with quoted fragments. Phase 3 begins with Inc-0
  (byte-identity guard goldens at the base revision) per the architect's increment cut.
