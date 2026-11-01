# Diagram — the busy model: begin → step → end/fail, busy refusal, quit question (flowchart)

> **Role:** `docs-writer`. Mermaid flowchart, 10 nodes. It shows the progress indicator's life, the busy refusal and the quit question (US-166, US-167; HLR-176/176a/176b/176c/176d, HLR-177/177a/177b/177c; LLR-176.1/176.2, LLR-177.3/177.4). Facts come from `03-increments/increment-021.md` and `increment-022.md` §1 and `01-requirements.md` §3/§4. Node names are the implementing functions on the current tree.

```mermaid
flowchart TD
    BEGIN["begin_busy (app.py:20213)<br/>first progress line, bar from 0 · LLR-176.1"]
    STEP["step_busy (app.py:20249)<br/>bar moves within a step; out-of-range clamped · LLR-176.1c/d"]
    WORK["Worker runs: project load / Save project / A2L parse<br/>_parse_loaded_file (app.py:17390) · LLR-177.1"]
    LINE["_busy_line (app.py:20371)<br/>one status-line owner while the action runs · HLR-176d"]
    END["end_busy (app.py:20299)<br/>outcome to the log, file state back, bar cleared · LLR-176.1i/k"]
    FAIL["_busy_fail (app.py:20408)<br/>an exception still ends the indicator · LLR-176.1l"]
    REF{"_refuse_if_busy (app.py:20440)<br/>a second request while a session action runs?"}
    BUSY["Refused: 'busy' + the running action's label · changes nothing (LLR-177.3f/g)"]
    QUIT{"Quit while a worker runs (LLR-177.4a)"}
    QQ["ConfirmQuestionScreen / _QuitQuestionScreen<br/>Quit?/Stay? — 'still working' + the action; safe answer emphasised"]

    BEGIN --> STEP --> WORK --> LINE --> END
    WORK -- "raises" --> FAIL
    REF -- "yes" --> BUSY
    QUIT -- "yes" --> QQ
    QQ --> STAY["Stay (n): the app waits, idle · LLR-177.4c"]
    QQ --> LEAVE["Quit (y): no partial save left · LLR-177.4d"]
```

**Reading notes.**
- One timer advances the line (spinner, step and `mm:ss` elapsed) while an action runs and stops when none runs (LLR-176.1e/176.1f); progress widgets are written only on the main thread (LLR-176.1q).
- Only the seam sets the bar (LLR-176.2a); the action table names the seven long actions and each ends on every success and failure exit (LLR-176.2b/176.2c).
- The busy refusal covers a second load, a variant switch, an unload, a Save project and Patch Editor changes, and stops when the action ends (LLR-177.3a…177.3h).
- The quit question reuses the Inc 10 confirm modal (`ConfirmQuestionScreen`), with the safe answer carrying the emphasis (`PRIMARY_BUTTON`), and a confirmed quit leaves no partial save (LLR-177.4…177.4e).
- The project sync helpers (`_sync_loaded_file_to_project`, `_sync_loaded_a2l_to_project`) are guarded so an unreadable project folder during a sync paints one refusal line instead of failing the worker (SE5-12b-2, `fix-round-2.md`).
