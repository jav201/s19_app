# Kimi brief — batch-100 Increment 2 · Save project name guards

Read `BRIEF-COMMON.md` first. The orchestrator names your worktree and base commit when it launches you. The base is `main` with Inc 1 merged. The packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-002.md`; copy the template from `increment-001.md`'s seed shape if it is missing, keeping Inc 1's header pattern.

**Design:** `design/design-proposal-b100.md` §5.2 is the authority. The contract is `01-requirements.md`:
- HLR-164;
- LLR-164.1 to LLR-164.4, read with LED .19 and .20 (the worker-census note is Inc 12's business, not yours);
- the token table for refusals (UX-07): grep `refusal token`.

Interfaces: freezes B100-I11 (as amended) and consumes B100-I13 (`place_into_workarea`, landed by Inc 1).

**SOURCE files (2):** `s19_app/tui/app.py` and `s19_app/tui/workspace.py`. Nothing else under `s19_app/`.

**What to build** (§5.2 governs):
- **The name check in `_handle_save_dialog`.** It runs before ANY `mkdir`, in this order:
  1. empty name;
  2. `is_windows_device_name` (NEW in `workspace.py`: one shared predicate, case-folded, with or without an extension or a superscript digit), applied to the RAW typed name, the sanitised name, and every path component;
  3. reserved homes, case-folded;
  4. the 64-character cap (`PROJECT_NAME_MAX_CHARS = 64` in `workspace.py`);
  5. the full-path limit, `len(workarea) + 1 + len(name) + 53 ≤ 259`;
  6. the disguised clash, Q-2: the sanitised name equals an existing project folder case-folded AND the typed name differs from it. The refusal names both and says "choose another name". It never suggests merging (UX-35);
  7. the link/junction target check before `resolve()`.
- **The `OSError` handler.** From the folder's creation on, the whole body runs under one `OSError` handler that calls `_remove_created_project_dir`. Every exit that created the folder removes it; this is an exception census, not a returns census (S-05).
- **An exact-name save into an existing project that is not open** still adds a variant (LLR-005.1). The full merge carry arrives at Inc 8a, so do not write it now.
- **`list_projects`** filters reserved homes case-folded (`Splits` is no longer listed).
- **Every refusal** paints its fixed token and a next step (UX-07).

**Tests** (ids from the contract):
- TC-B100-04, -05 (Inc 2 arms only: refusals, open-project save, exact-name save adding a variant; NOT the merge-carry arm), -06, -07, and AT-B100-02.
- AT-B100-02 drives the CURRENT Save project dialog by keys. Inc 11 replaces that dialog later and re-pins its ids; that is not your concern here.
- Enabler: a work-area base padded to length L = 150 for the path-limit arms.
- RED today:
  - P-14: `reports` and `Splits` are saved and listed;
  - S-04: `CON` is saved;
  - P-13: `RAISED FileNotFoundError` on a long name;
  - S-05: a 262-character path leaves a folder;
  - P-10: `a b` is saved silently into `ab`.

**Re-pins and arm extensions** (contract §5.3/§5.4, PDR C-QA-7):
- `tests/test_tui_variants.py::test_save_second_s19_into_project_appends_variant` must stay GREEN unchanged (A-09).
- Run every test file the reverse census finds and re-validate each hit. Re-pin only where LLR-164.x changes the behaviour, and record each re-pin old → new. Use `grep -rln "_handle_save_dialog\|list_projects\|sanitize_project_name\|_remove_created_project_dir" tests/ --include=*.py`.
- Never touch `#project_parent_path` tests; removing that field is Inc 11's work (D7).

**Snapshot cells:** none should change. If one does, STOP.

Finish with the guards (`guards.txt` + `guards-census.txt`), the packet §1–§7 (§4b `pending — orchestrator`), and `HANDOFF.md` ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
