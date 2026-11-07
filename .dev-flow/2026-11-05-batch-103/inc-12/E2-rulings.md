# Inc 12 — orchestrator rulings on the E2 graph (2026-11-07T02:34:39-06:00, Opus 5.5)

Graph: 13 nodes (4 changed, 5 new, 4 context); lint 0 unread; extractor exit 0 against the measured prototype.
| Item | Ruling |
|---|---|
| I-12.1 PROPOSED (`_build_a2l_table_cells(tag, name_width=None)`, cells Address, Length, Tag, …) | **accepted** |
| I-12.2 / .3 / .4 pinned | noted |
| E2-1 … E2-3 (the fit runs on the table's own resize — the `BandBar.Measured` pattern — and after every page build; `on_resize` and `action_show_screen` unchanged) | **accepted** (measured: a fit scheduled from `on_resize` ran before the table resized) |
| E2-4 (widths only grow during a session), E2-5 (two case texts wrong), E2-6 (E4 test list, `test_b99_a2l_encode`), E2-7 (at w ≤ 9 names sharing a long prefix look identical) | **to E3** |
| E2-4, at E3 (2026-11-07, `E3-rulings.md` "Questions routed from E2") | **(a)**, as both lenses agree: recorded, not a defect; *w* is computed from the actual widths |
| E2-5, at E3 | both case texts **accepted** (R-TUI-042a.3/4, .4/4 in `02-test-cases.md`). *w* **corrected**: at 118 columns with a vertical scrollbar the visible width is 58, so a page with a 64-bit address gives *w* = 29, not 31 (31 without a scrollbar); at 80 columns 12 with a scrollbar, 14 without (E3A [O deep]; `01-requirements.md` "What else the operator sees") |
| E2-6, at E3 | the red list is **complete for its files** (E3A §4: 16 RED on the design, green on base; `test_b99_a2l_encode` executed). Added: b101 Inc 10b's tests of `_repaint_a2l_tag_cells` (re-checked at the rebase for column-0 reads and the Tag text) and Inc 1b's right-click cases (the Tag cell found by its label; R-COPY.4/3's expected name per `../inc-1b/E1-rulings.md`). AT-069c stays on the Tag cell, with payloads placed where they fit and one across the cut, asserting the exact shortened text, no spans, no control character (E3S-06); AT-069b re-points to each payload's non-control projection (E3S-02) |
| E2-7, at E3 | **no floor**. The extent is wider than E2-7 said: some names read alike at every *w* (46 tracked at *w* = 34), and most names of V171, V161, BalanceTube and from_source do at *w* = 12, the ordinary 80-column page with a vertical scrollbar, not only at *w* ≤ 9 (E3S-03, E3A-04); counts in `01-requirements.md` "What else the operator sees"; the operator judges it at AT-B103-I12-2 |
