# Inc 7 — E3 rulings (orchestrator)

Orchestrator claude-opus-5-5, 2026-11-13 (time in `steps.log`, from `date`). The E3 verdicts in `E3-architect.md` and `E3-security.md` are both FAIL: 1 HIGH and 9 MAJOR. One correction pass (E3R1) applies the rulings below to `01-requirements.md`, `02-test-cases-*.md`, `E1-slice.md`, `codewire/graph-inc7.md` and `E1-rulings.md`. The same reviewer then re-reviews only the corrected parts.

## HIGH

**E3A-01 (Box A of the clipboard suite).** Accepted, with an owner and an order different from the reviewer's proposal.
- Inc 7 changes R-PASTE.1 (listed in its changed canon rows), so moving the clipboard suite's Box A from the filter box to `#a2l_tag_find_input` is **Inc 7's E4 retarget**, not an Inc 1b task.
- Each retargeted node cites the changed row.
- **Order constraint (DF-10):** Inc 7's E4 starts only after `b103-inc1b` is final, meaning its WinCI rounds are closed (PENDING P-001 / P-002). Inc 7 then builds on that final tree, and no two writers touch the Inc 1a/1b test files at the same time.
- Record the full list of the 13 affected nodes in `E1-slice.md`'s E4 retarget list.
- The WinCI re-run at Inc 7 E5 (already ruled) covers Box A on Windows.

## MAJOR: all accepted, fixed as the reviewer proposed, with these choices
- **E3A-02:** remove the back-reference, or exclude it from equality (`field(compare=False, repr=False)`). Add a case that compares two equal entries.
- **E3A-03:** complete I-7 so G-L and G-V can be built in parallel: the filter box's constructor and its dropdown link, the app method, `LabelListApplied` with its fields, and the pane ids. Re-pin it.
- **E3A-04:** the ranker keeps one token per *request key*, not per consumer, so the 10 "similar" requests do not cancel each other. Keep the bound from D-8.
- **E3A-05:** every worker callback, held request and debounce gets the R-COPY.26 teardown guard: drop the work when the app is not running, and raise no error. Add one robustness row per entry point (the same family as PENDING P-002), plus cases.
- **E3A-07:** keep the `id()` mapping valid in list mode, or change the write route to a stable key. Keep R-A2L-049/105 green.
- **E3A-08:** after an unload, the viewer clears its rows (R-TUI-068.3 wins: approved canon).
- **E3A-10:** the D-2 layout gets a fallback below 118×54. At the 80×24 floor, rows stay visible (the pre-Inc-7 stacking or a reduced hex pane). This is visible: it is added to the capture verdicts (DF-09).
- **E3A-11:** add R-TUI-069.7, and list the E4 retargets (the tc019 tests and the 6 A2L SVG snapshots). Snapshots are regenerated only by the canonical CI (HT-09).
- **E3S-01:** cap the paste window's preview rows, with a visible `+<k> more` line, and move the rebuild off the UI thread or debounce it. Add the hostile 32,768-row case.

## MEDIUM: fix in E3R1
E3A-06, E3A-09 (add the two attributes to the session census), E3A-12 (`_take_paste` makes a list only in the list-capable fields, per D-3), E3S-02 (cap the echoed text), E3S-03 (pin where the hook sits relative to `restrict`), E3S-04.

## MINOR / LOW
- Fix in E3R1 when the fix is a row or case text: E3A-13, E3A-14, E3S-05, E3S-06 (also replace bidi controls in `display_text`).
- Otherwise, add a backlog line in `E1-rulings.md` §7 (E3A-15). The orchestrator copies it to PENDING.

## Unchanged
- The provisional visible decisions (DF-09).
- The size cap. If E3R1 goes past about 95 requirements or 48 nodes, stop and report the split point.

## E3R1 corrections

Correction worker claude-opus-5-5 (architect), 2026-11-13 (time in `steps.log`, from `date`), on `b103-inc7` at `1d47d12f`; records only. Paths: **R** `01-requirements.md`, **CL** / **CV** `02-test-cases-L.md` / `-V.md`, **S** `E1-slice.md`, **E1R** `E1-rulings.md`, **G** `codewire/graph-inc7.md`; line numbers as committed. Size after E3R1: **95 active rows** (82 new, 13 changed, 0 retired; was 85), **229 cases** (L 103, V 116, AT 10; was 179), **44 graph nodes** (33 new, 11 changed; was 42) — at the 95-row ceiling, not past it; no split. Checks (on <runner>): `evidence-e1/trace_check-e3r1.txt` (US 0, CASE 0, SLICE 0 gaps; 91 TEST gaps for rows no test names yet and the EVID line, both expected before E4/E5), `evidence-e1/i7e3r1-coverage-check-transcript.txt` (95 rows, 212 example lines, 0 gaps), `codewire/extractor-e3r1/` (callers), `evidence-e1/i7e3r1-layout-pilot-transcript.txt` (P3).

| Finding | What changed | Where |
|---|---|---|
| E3A-01 HIGH | Owner/order as ruled: E4 retarget list with the 13 Box A nodes, each citing its changed row, the move to `#a2l_tag_find_input` in every Inc 1a/1b clipboard test and the WinCI manifest, the class census counted by `isinstance`; E4 waits for `b103-inc1b` final. R-PASTE.1, R-TUI-043.4, R-PASTE.29 say "a single line with a space counts". New cases: a one-name paste (`P_CTRL`) on each route of the filter box | S:111-135; R:142-144; CL:30, CL:34, CL:37; G:21 |
| E3A-02 MAJOR | `LabelListEntry` loses `row`; `LabelListResolution.rows` (the tag object, or `{"name", "_list_pos"}` for a missing name); the card finds its entry by `_list_pos` or the cursor row; equality example | G:63-78, G:171, G:546, G:588, G:662, G:685 |
| E3A-03 MAJOR | I-7 re-pinned whole: `TEXT_CELL_LABELS`, `ListAwareFilterInput(*, suggest, list_enabled, placeholder, id)` with `action_move_choice` / `esc` / `complete` (SkipAction when closed), `LabelListHost.a2l_open_label_list`, dismiss callback as the one route (`LabelListApplied` struck), `A2LExplorerBody(tags_pane, hex_pane, *, id)` and its child ids, `deliver` = `functools.partial(box.show_ranked, query)`; new node L29 | G:34, G:42-133, G:360, G:521; E1R:76; S:63 |
| E3A-04 MAJOR | One token per request key (`filter`, `add`, `card`, `similar:1` … `similar:10`), so the similar requests do not cancel; D-8's bound of 10 kept; .050/1 now expects both lines | G:83-95, G:255, G:393, G:412; R:165 |
| E3A-05 MAJOR | R-COPY.26-family guards: workers `exit_on_error=False`, one worker body `_work` (L30) catching every error and `RuntimeError` from `call_from_thread`, `_install`/`_deliver` return when the app is not running, `current`/`deliver` hold their widget (`is_attached`, no `query_one`), the paste debounce on the screen's own timer. Rows .084 (preparation + held requests), .085 (rankings, four askers), .086 (paste debounce), each with a positive arm. The viewer's filter debounce stays R-COPY.26's | R:214-222; CL:88-98; CV:79; G:230, G:242, G:268, G:283, G:393, G:631, G:662 |
| E3A-06 MEDIUM | Per key at most one ranking runs and one waits; row .075 (held + 5 keystrokes → 2 `rank` calls) | R:196; CL:86-87; G:255 |
| E3A-07 MAJOR | Write route kept without `patch.py`: found/duplicate/hidden rows are the tag objects (the route's `id()` map holds); a list with a missing row reaches V4 with `preserve_anchor=True` (the route's only `True` caller), which calls V8; V8 re-resolves and writes the page in place (no clear). .036 gains cases /3–/5 (R-A2L-048/2, -049/1, -105/1 in list mode with a missing and a duplicate row) | R:131; CV:76-78; G:560, G:609; S:89-102 |
| E3A-08 MAJOR | List mode needs a loaded A2L (definition); the absent branch clears the resolution; .004/3 is the paste window's case; cases .008/3, .023/2 (unload → `No A2L tags.`, `FILTER`, no missing line) | R:36, R:94, R:103, R:118, R:245; CV:13, CV:55; G:534, G:620 |
| E3A-09 MEDIUM | Session census: `SNAPSHOT_EXCLUSIONS` gains `_a2l_label_ranker` and `_a2l_list_resolution` with reasons (a G-T-V test edit) | S:137-141; G:691-695 |
| E3A-10 MAJOR | Body regimes defined (wide / stacked / short, from P3's measured bodies). R-TUI-037.1/.2 come back as changed rows for the short body (the pre-Inc-7 split); .080 scoped to the stacked body; new .082 (card ≤ 5 lines in the short body) and .083 (≥ 1 table row from 15 body rows). The 80×24 fallback is in the capture verdicts (CV-1: 80×24, 120×30, 160×40, 80×54). **Fact, not fixable in E3R1:** at 80×24 the body is 9 rows and base already shows 0 table rows (P3); Inc 7's chips lines make that true in both modes, so "rows stay visible at 80×24" holds at no layout of this design; the operator rules (CV-1, BL-I7-6) | R:62-70, R:146-147, R:209-212; CV:91-96, CV:118-122; G:461, G:697; E1R:37, E1R:82, E1R:110; `evidence-e1/i7e3r1-layout-pilot-transcript.txt` |
| E3A-11 MAJOR | R-TUI-069.7 changed ("longer than the detail card's height") with 3 cases; E4 retarget table for tc019 (re-run, valid: short bodies), tc020, the six `tc016s` A2L SVGs (canonical CI only, the batch-47 xfail bridge) and Inc 12's R-TUI-042a.5 | R:149; CV:88-90; S:143-152; E1R:39 |
| E3A-12 MEDIUM | A list paste only while the field is `name` or `all` (`list_enabled()`): .033 and the three R-PASTE rows scoped; case .033/4 (field `source`) | R:128, R:142-144; CL:25; G:322, G:521 |
| E3A-13 MINOR | Case-text fix: .031/4 — enter on a missing row leaves the status line and the hex pane unchanged (the card already says `not in this A2L`) | R:126; CV:71; G:588 |
| E3A-14 MINOR | Row-text fix: .047's extra columns are fixed when the window opens; case .047/3 | R:162; CL:46; G:370 |
| E3A-15 MINOR | Backlog BL-I7-5 (refresh every paste window in the screen stack); for the orchestrator to copy to PENDING | E1R:109 |
| E3A-16 INFO | Pinned with E3S-03: in `action_paste` the hook sits after the empty-text check | G:30, G:508; E1R:72 |
| E3A-17 INFO | No change (answered) | — |
| E3S-01 MAJOR | Preview capped at 200 rows plus the *more line*; row .078 with the 4,906- and 32,768-name cases and a ≤ 0.25 s rebuild (`serial_timing`); the rebuild was already debounced (0.15 s); CV-6 shows the line | R:71, R:175; CL:60-62; G:370, G:393; E1R:87 |
| E3S-02 MEDIUM | *Short text* (display text, cut at 64) for every echo of the filter or query text: .019, .025, .066, each with a 300-character case (NUL and TAB in field `unit` for .019; NUL and ESC for .025/.066, since TAB splits a field-`name` text into a list) | R:59, R:114, R:120, R:187; CV:46, CV:60; CL:72; G:159, G:293, G:560, G:571 |
| E3S-03 MEDIUM | I-1 placement pinned: the routes call the hook with `_strip_paste_controls(text, multiline=True)` and never on a `restrict` box; cases R-PASTE.1/4 and .034/3 | G:30, G:488-519; E1R:72; R:129, R:142; CL:27, CL:31 |
| E3S-04 MEDIUM | Solved by E3A-04/E3A-06 as ruled (per-key coalescing; ≤ 2 `rank` calls per similar slot after any number of edits); case .075/2 | R:196; CL:87; G:393 |
| E3S-05 MINOR | Case-text fix: .033/5 — a 65,535-character paste of one-character names gives a 98,302-character value, accepted and stated; BL-I7-4 updated | R:128; CL:26; E1R:108 |
| E3S-06 LOW | Display text also replaces U+061C, U+200E/F, U+202A–U+202E, U+2066–U+2069; case .076/7 | R:55, R:202; CL:105; G:159 |
| E3S-07, E3S-08 INFO | No change; E3S-08's log rule is in `_work` (error type and key only, never a name) | G:283 |
| E3S-09 INFO | Folded into E3S-02 as the reviewer proposed: .077 covers the dropdown row and the card's `✗` line; cases .077/3–/4 | R:203; CL:108-109; G:218, G:293 |

Not done or deviations, for the orchestrator:
- The 80×24 floor (E3A-10): see the row above; BL-I7-6 and CV-1 carry it.
- The extractor resolved no call in `core.py`, `patch.py` or `navigation.py:1374/1483/1497` (35 ambiguous names); `git grep` filled them (S:89-102).
- On this PC I ran `--help` of `codewire_marks.py` and `codewire_extract.py` and a read-only `json.load` of the E1 extractor output (`python -I -B`; nothing written); on <runner> one temporary listing was written to `/tmp` and deleted in the same command. Neither is a test or a timing.
- Decisions E3R1 made inside the rulings (DF-02): the write route is kept by V4/V8, not by editing `patch.py` (G-V stays at 3 files); the short-body thresholds 110 columns and 32 rows; the E3A-05 rows folded to one per entry point (3) to stay at 95 rows.
