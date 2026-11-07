# Inc 12 — orchestrator rulings on the E2 graph (2026-11-07T02:34:39-06:00, Opus 5.5)

Graph: 13 nodes (4 changed, 5 new, 4 context); lint 0 unread; extractor exit 0 against the measured prototype.
| Item | Ruling |
|---|---|
| I-12.1 PROPOSED (`_build_a2l_table_cells(tag, name_width=None)`, cells Address, Length, Tag, …) | **accepted** |
| I-12.2 / .3 / .4 pinned | noted |
| E2-1 … E2-3 (the fit runs on the table's own resize — the `BandBar.Measured` pattern — and after every page build; `on_resize` and `action_show_screen` unchanged) | **accepted** (measured: a fit scheduled from `on_resize` ran before the table resized) |
| E2-4 (widths only grow during a session), E2-5 (two case texts wrong), E2-6 (E4 test list, `test_b99_a2l_encode`), E2-7 (at w ≤ 9 names sharing a long prefix look identical) | **to E3** |
