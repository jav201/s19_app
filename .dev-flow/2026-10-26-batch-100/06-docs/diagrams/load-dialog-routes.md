# Diagram — the Load dialog routes (flowchart)

> **Role:** `docs-writer`. Mermaid flowchart, 10 nodes. It shows the one Load dialog's sources and the routes a confirmed load takes to the worker and the main-thread install (US-163; HLR-173/173a/173b/173c/173e, LLR-173.1…173.6; US-162 / HLR-172/172a, LLR-172.4/172.5; US-167 / HLR-177, LLR-177.1). Facts come from `03-increments/increment-018.md` §1 and `01-requirements.md` §3/§4. Node names are the implementing functions on the current tree.

```mermaid
flowchart TD
    DL["LoadDialog (screens.py) — opened by l / ctrl+l (path field)<br/>or p (list) · LLR-173.2"]
    SRC["Three sections read: projects list_projects (app.py:13869) ·<br/>work-area files refresh_files (app.py:7931) ·<br/>recents read_recent_sources (workspace.py:2245)"]
    PRE["Preview marks the install set<br/>choose_install_set (app.py:1965) · LLR-173.6"]
    KEY{"Key: Enter (load) or esc (close, no result)?<br/>LLR-173.2k"}
    RTR["One router receives every result<br/>_handle_load_dialog (app.py:15018) · LLR-173.1"]
    PROJ["Project route<br/>_route_load_project (app.py:8313) · LLR-173.1a"]
    WA["Work-area file route<br/>_load_workarea_file (app.py:15534) · LLR-173.1b"]
    PATH["Typed / recent path route<br/>_load_path_from_user_input (app.py:14918) · LLR-173.1c"]
    WORK["Worker: parse the file off the main thread<br/>_parse_loaded_file (app.py:17390) · LLR-177.1"]
    INST["Main thread: install the snapshot<br/>_apply_loaded_file (app.py:17437) · LLR-177.1d"]

    DL --> SRC --> PRE --> KEY
    KEY -- "esc" --> ESC["Closed with no result · changes nothing (HLR-173e)"]
    KEY -- "Enter" --> RTR
    RTR --> PROJ --> WORK
    RTR --> WA --> WORK
    RTR --> PATH --> WORK
    WORK --> INST
```

**Reading notes.**
- The three source sections are the project list (`list_projects`), the one work-area lister (`refresh_files`), and the recent-sources store read (`read_recent_sources`); the list order is projects, files, recents (LLR-173.4l). A folder that is not a project is not listed (LLR-173.4a).
- A project choice opens the project through the project route and shows the Load-result panel; a work-area choice loads the file as the list pick does; a path choice takes the typed-path route; a recent choice loads the recorded path unchanged (LLR-173.1a/173.1b/173.1c/173.1f).
- The preview's `●` marks equal the set `choose_install_set` installs (HLR-173a); the dialog itself reads nothing beyond that (LLR-173.6l).
- The worker (`_parse_loaded_file`) and the main-thread install (`_apply_loaded_file`) are the Inc 12b split: a worker reads only its request, the session is written only on the main thread (LLR-177.1d/177.1e).
