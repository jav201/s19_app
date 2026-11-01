# Inc 12a — E1 orchestrator rulings

The operator delegated every 9b–12b decision to the orchestrator's recommendation on 2026-10-31. Rule: remove a feature rather than guard it, and stay within the 4-file cap.

| Id | Ruling | Why |
|---|---|---|
| Q1 | **As recommended.** LLR-176.3 and LLR-176.4 move to 12b with their text unchanged. AT-B100-17 is split into two halves under one id. | 12a builds the indicator; the worker moves belong to 12b. |
| Q2 | **As recommended.** 12a owns LLR-176.2d: one step per save phase and an end on every exit. 12b owns the save worker, its animation, the busy refusal and the quit question. The R12 row moves to 12b without its cancel. | The P-D verdict says "no cancel". |
| Q3 | **As recommended.** Show the newest action. A begin under a running key restarts it, and steps or ends from the replaced run are ignored. | It matches the workers' `exclusive=True` behaviour. |
| Q4 | **As recommended.** The outcome goes to the status log, and `#status_text` shows the final line, falling back as the draft states. | One row has room for one line only; the old three-part end painted lines the user never saw. |
| Q5 | **As recommended.** Remove "bytes copied, read" from the within-step promise. | Those callbacks live outside the increment's files. Removing the claim beats adding plumbing. |
| Q6 | **As recommended.** The "Load" / "Projects" labels are applied at 12a (LLR-173.2m restored), and the Workspace button keeps "Load project (p)". The 29 snapshot files are regenerated only through `.github/workflows/snapshot-regen.yml`, and only those 29 files are committed. | This was deferred from 9b by ruling Q8. The snapshot-regen environment rule applies. |
| Q7 | **As recommended.** 12a stays one increment, with two E2 groups (indicator; labels and sweep). | Both halves live in `app.py`, so splitting the increment gains no parallelism. |
| Q8 | **As recommended.** At 12a an exception only guarantees the end runs first, with a failure outcome. Keeping the app alive stays in LLR-177.2 (12b). | Keeps 12a and 12b from overlapping. |
| Q9 | **As recommended.** As pd_A: a 0.1 s tick, a braille spinner, mm:ss elapsed, and at most one `styles.tcss` rule. | This is the prototype verdict. |
| Q10 | **As recommended.** The 12a half of AT-B100-17 loads a generated S19 with 8 MiB of data, by keys. | P12a-3 measures that load at 2.38 s, long enough to watch the indicator. |
| Backlog | **As recommended.** Fix B3, B4, B5, B7 and B10. Declare B1 and B2. Move B6, B8, B11 and B12 as stated. Close B9 after the E2 probe confirms it. | Every fix stays in `app.py`; each item that would need `workspace.py` is declared or moved. |

**Sequencing.** E2 runs after Inc 11's design fixes `_prepare_project_save`, because LLR-176.2d hooks into it, and after 9b fixes `_load_workarea_file`. G-A and G-B are both in `app.py`, so their E4 implementers work in sequence, or one implementer does both.
