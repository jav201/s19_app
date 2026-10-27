# Kimi brief — batch-100 Increment 4 · the focus lands where you can work (CW-U-2)

Read `BRIEF-COMMON.md` first. The orchestrator gives you the worktree path and base commit at launch. The base is `main` with Inc 1–3 merged. The packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-004.md`; if it is missing, copy the seed shape from `increment-001.md`.

**Design:** `design/design-proposal-b100.md` §5.4 is the authority. Contract: `01-requirements.md` HLR-166, LLR-166.1, LLR-166.2. Read them with LED .50 (project paths stay unresolved; placements pass `workarea_root=self.workarea`).

**SOURCE files (1):** `s19_app/tui/app.py` only.

**What to build** (§5.4 governs):
- **Focus-target table in `app.py`.** One focus target per window.
  - Derive it from the window registry and assert it against that registry: every displayed window has a target, and no target is missing.
  - A target never names an `Input` or `TextArea`; a typed key must reach the app's bindings.
- **Re-home the focus after a load.** `_step_finalize` (the load tail) and the A2L load tail move the focus to the active window's target when the focused widget:
  - has region area 0, or
  - sits in a window that is not displayed, or
  - is a text input.
- **Modal-close arms** (the panel at Inc 6, the dialog at Inc 9b, the question at Inc 10) are NOT this increment's. Do not write them.

**Tests** (ids from the contract):
- TC-B100-12 (Inc 4 arms only), TC-B100-13, and AT-B100-04, run at 118×54 and 220×60.
- **AT-B100-04 is black-box.** It loads by keys and the real dialog. It observes that `p`, `k` and `t` reach their screens after a load. It also observes the focused widget's region through the pilot's painted state, never a private attribute.
- **RED must be behavioural at base.** P-16: after a Load file or a Load project, `focused: _SegTable#sje_table`, region area 0, and `p` stays on `Screen`.
- **Mutations from §5.4:** remove the re-home from the A2L tail; let the table name an `Input`; drop one window from the table, which the registry assertion must then catch.

**Reverse census:** `grep -rln "_step_finalize\|set_focus\|focus_target\|_SegTable" tests/ --include=*.py`. Snapshot cells must not change; if one does, STOP.

**Lessons from Inc 1–3** (`03-increments/review-increment-00{1,2,3}.md`):
- RED is behavioural against the base code, never a missing module.
- Every §2 row has `Kind` in the closed six and a real LLR/HLR id in `Traces to`.
- Transcript headers name the command, the tree, `PYTHONPATH` and `NO_COLOR`.

Finish with the guards (`guards.txt` + `guards-census.txt`), packet §1–§7 (§4b `pending — orchestrator`), and `HANDOFF.md` ending with `__KIMI_UNIT_DONE__` and the 5-line summary. If you approach your time budget, write `HANDOFF.md` with what is left BEFORE running the long reverse census.
