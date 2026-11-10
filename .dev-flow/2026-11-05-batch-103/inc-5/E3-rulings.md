# Inc 5 — E3 rulings (orchestrator Kimi, 2026-11-10)

E2 supplied 18 nodes, 56 concrete examples and 103 not_run cases for 28 requirements. The following dispositions are binding for E3 review and E4; no product or test has run.

1. **E2-Q1 — publication order.** `_apply_prepared_load` calls the common fan-out synchronously when `publish_a2l=True`, before returning to the worker's scheduled outcome. `_install_prepared_project` uses `publish_a2l=False` for image/MAC and publishes once after final installation and after assigning `current_project/current_project_dir`. Direct attach and unload register their outcomes after the common fan-out and detail barrier.
2. **E2-Q2 — filter reset order.** Set mode `all` and the button variants before `update_a2l_view`, so no obsolete predicate filters the new payload. Exact filter text and selected field remain untouched. This replaces the contradictory order in E1 D-1.
3. **E2-Q3 — identity changed during confirmation.** No worker/install occurs and the visible refusal is exactly `A2L NOT loaded: project or its A2L changed — load again.` It applies when the captured project identity or exactly-one-A2L listing changes before Yes. R-A2L-REFRESH.022 and its two cases carry this text; no new row is needed.
4. **E2-Q4 — project identity precedes fan-out.** Loaded and all other views read the incoming project identity. No fan-out occurs during reset or before the final image/MAC installation.
5. **E2-Q5 — Detail Card barrier.** Dismiss a top CurveDescriptionScreen, invalidate immediately and register `card.show_tag(None)` with `call_after_refresh`; the outcome is registered after that barrier so queued table highlights cannot auto-select a tag. Buried/unrelated screens are not popped.
6. **E2-Q6 — Split / Join selection.** A2L-derived selection/cursor indexes are invalidated when A2L content changes or clears, while manual text is preserved. R-A2L-REFRESH.016 and SNAP carry this rule; no hidden window is opened.
7. **E2-Q7 — visible mode.** Existing Textual variants are sufficient: All gets `primary`, In-Memory/Invalid get `default`; no CSS edit or new visual prototype is required.
8. **Ledger consistency.** R-A2L-REFRESH.011 has five explicitly named routes; it does not say “5/5 routes of .010” (which has six including the description-modal race). The 103-case total and all other thresholds are unchanged.

E3 architecture and security reviews must check these decisions, all 28 rows and the real callers. E4 may start only after both reviews return PASS or PASS-WITH-NOTES with no HIGH/MAJOR open.


## Round 1 corrective rulings — E3A-01…03 and security HIGH/MAJOR

- **Split / Join (E3A-01 and security MAJOR).** Add a small public `invalidate_a2l_selection()` seam to `segment_split_view.py`. It clears A2L selection/cursor and `_armed`, preserves manual text and then refreshes. N1 calls it beside `watch_current_file`. The source boundary becomes `app.py`, `a2l_parameter_picker.py` (reuse only) and `segment_split_view.py`; implementation graph becomes 19 nodes. Tests also assert `_armed=False`.
- **Picker oracles (E3A-02).** The pickers expose only full name, address and format plus the fresh enrichment signature. Remove physical/raw-value expectations from their requirements/cases; those values remain asserted in A2L Viewer. This narrows incorrect test expectations, not product behavior or the picker API.
- **Busy races (E3A-03).** R-A2L-REFRESH.025 covers two post-Yes boundaries: N2's accepted callback and N3 immediately before worker creation. `.025/1` passes initial idle confirmation, holds the accepted callback, starts an image action and releases it. `.025/2` passes N2, holds N3, starts Save project and releases it. The cases no longer claim an unreachable pre-Yes busy trigger through the modal.
- **Prepared snapshot (security HIGH).** Before any `current_file`, A2L, enrichment, MAC or Issues write, C6 validates the expected post-install generation pair whenever a prepared enrichment key exists. A mismatch discards the whole prepared load as superseded: no state/widget write and no success publication. C6 returns a boolean publication result; C7 aborts final publication if either C6 call rejects. Current state remains authoritative; no stale cache is reused for fallback.
- **Session-only confirmation (security MAJOR).** `A2LAttachRequest` gains `sync_project=True`; N3 accepts the same keyword. The accepted replacement uses `sync_project=False`, and C5 skips `_sync_loaded_a2l_to_project` for that request. A later external A2L disappearance therefore cannot cause a copy or manifest write. Add a race case after Yes/before install asserting no project-file change.
- **Count changes.** 28 requirements unchanged. The prepared external-race arm is absorbed into R-A2L-REFRESH.023's existing two acceptance cases (no new requirement or case count target is invented here); .025's two cases are rewritten, not duplicated. Graph total becomes 19 nodes (9 implementation + 10 context).


## Round 1 completion — E3R1-Q8/Q9

- Add `_complete_prepared_load` between `_start_load_worker` and C6 for loose-file worker loads. C6 returns a boolean. On success the wrapper retains the existing project sync and `Loaded …` outcome; on preflight rejection it performs no sync and closes busy with `Load superseded — current state kept.` This is not a success publication and leaves no action running.
- C7 continues to call C6 directly and aborts its final publication if either C6 rejects.
- The implementation count is therefore **11 nodes** (6 changed functions + 5 new/extracted helpers); with 10 context nodes the graph has **21 nodes**. R-A2L-REFRESH.028 states the complete discard and exact superseded outcome. The 103-case total remains unchanged.


## Round 2 — picker format oracle

E3A-02's remaining note is accepted: `set_parameters` renders `u<size * 8>`, so picker cases expect `u8` for UBYTE and `u16` for UWORD, not `dec`. The 103 cases are otherwise unchanged. Architecture and security re-reviews now close E3 with no HIGH/MAJOR open once this expectation is confirmed.
