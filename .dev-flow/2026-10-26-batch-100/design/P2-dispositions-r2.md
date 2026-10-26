# P2 round 2 — orchestrator dispositions (batch-100), bounded round 3

> **Inputs.** The four round-2 reviews of `01-requirements.md` at `0c7ca1d`:
> - `P2-security-r2.md`: 0 HIGH · 3 MAJOR · 6 MINOR, plus S-02/S-08 carried.
> - `P2-ux-r2.md`: 1 · 10 · 7.
> - `P2-qa-r2.md`: 0 · 6 · 8.
> - `P2-architect-r2.md`: 1 · 6 · 7.
>
> **Operator decisions this round:**
> - S-16: the recent list is kept per user (`%APPDATA%\s19_app\recent_sources.json`).
> - The P2 iteration cap was reached. The operator chose the **bounded round 3**: apply these dispositions, then each reviewer verifies only the closure of its own open findings, with no new full review.
>
> **Rule.** As in round 1, every open finding is closed with its reviewer's proposed closure, except where a row below rules otherwise. Overlapping findings close together.

## Rulings

| Finding(s) | Ruling |
|---|---|
| **B-01** (HIGH) + **QA R2-01** | The emit-or-copy decision is made on DATA. The change document's entries are re-derived onto a copy of the source image (B-04's split). If the resulting data differs from the source data, emit; otherwise byte-copy. A **check document never counts**. Only a change document's entries can produce a difference, and a check document is saved to `checks/` per HLR-170 without blocking the save. Add three test arms: check-document-only → byte-copy plus `checks/` written; unchanged change document → byte-copy and no spurious variant; real change → emit. List this rule in §6.3 as a deviation that the round-2 author introduced and round 3 corrected. R-TUI-012's restatement ("otherwise copies byte for byte") holds again. |
| **UX-26** (HIGH) | Record which variant each patched variant derives from. The `project.json` per-variant key `derived_from` (additive, carried by every rewrite per A-02) is set by save-back and by Save project's emit. "N bytes differ" in the P-E panel compares against `derived_from`, never against "the first variant by name". Add an AT arm using the default `firmware-patched.s19` name. |
| **QA R2-03** + **B-02** | Put the unsaved-work question in the **one load seam** that every image-replacing route passes through: the Load dialog, the Workarea Files pick (`_load_from_item` → `load_selected_file`), the variant switch (`v` and the panel's `v` → `_handle_select_variant`) and project load. Add one test arm per route. |
| **QA R2-02** | Loading a MAC or A2L only attaches it. It loses nothing, so it never asks. Correct the 16-cell table. |
| **UX-27** | Save project clears the Patch Editor document's dirty flag, through the existing `mark_saved` path, once the document is written. Add a test cell: patched + entries → Save project → load = no question. |
| **UX-29** + **B-11** | `#status_text` has ONE owner during a busy action: the progress line. At the end, a single final writer applies a stated order: outcome, then the project + file line, then the file state. The start and end states of the bar are stated: hidden when idle, never a stale `100%`. |
| **UX-30** | Per the operator's P-D note ("que la barra realmente haga su trabajo"), the bar shows **progress within a step** wherever it is measurable: bytes copied, bytes read or parsed. It steps only for indivisible steps. The A2L tag-table build stays main-thread and out of scope, with that stated (R-PD). |
| **UX-31** | The P-E panel's problem list is reachable by keyboard. Focus starts on the list (↑/↓/PgUp/PgDn scroll it), `tab` moves to OK, and `enter`/`esc` on OK dismisses. The test reaches the last row. |
| **UX-32** + **QA R2-05** | Define summary rows at the granularity of pc_B: one row per top-level file, one per sub-folder (with its file count), plus `project.json`. Each row carries an action word (new / replace / keep / merge / rewrite). AT-21 compares rows with the written tree at that granularity, by full path and action, read from the plan object, not from the painted (possibly truncated) text. A long summary scrolls, and its buttons stay pinned. Restate "nothing is overwritten silently": every replace or rewrite is a row that says so. |
| **UX-33** + **B-04** | Split `save_patched` into "re-derive onto a copy" and "emit + verify" in the change service, as Inc 5's API. The image digest is computed once per dialog open, not per keystroke. The plan's file names are debounced (≥150 ms) and the plan does no hashing on keystrokes. Inc 5's file list is re-counted. |
| **B-05** | One shared `predict_placement` uses the placement code itself. The handler checks that each landed path equals the planned row, and a mismatch is an error that names both paths. |
| **UX-34** | While a worker runs, every action that replaces the image or the project is refused, and the refusal names the running action: load, unload, `v`, save-back, Save project. Quit asks first; if the user confirms, it waits for the worker to finish or roll back, so no partial folder is left. AT-18 follows the statement. |
| **UX-35** | A disguised clash's refusal tells the user to **choose another name**. It does not suggest merging. Merging only happens when the user types the exact name of an existing project, and the summary then shows it as a merge row. |
| **UX-36** | ● on a file row marks the file plus whatever the session would pair it with: the open project's variant set, or the A2L/MAC already attached. If a project is open, the row says the file becomes its active variant. A recent row shows only what is known without reading the file (path, size, last seen) and says so; there is no preview read before Enter. |
| **UX-05** + **QA R2-06** | Initial focus in the Load dialog is the **path field**, which corrects pa_C's start. The order is path → list → preview → buttons, with `tab`. A printable key while the list has focus jumps to the path field and types there, so it never reaches app bindings. `#load_ok` loads the highlighted row when the list has focus and the typed path otherwise. Recount ATs 01/12 against this. |
| **B-03** | The tightened path check (LLR-169.8) applies to **manifest keys only**. The shared helper gains a mode, and `test_tc_b97_20_hostile_refs_render_literally` stays green. Name it in §5.4. |
| **B-06** | Move each test arm to the increment that makes it possible: LLR-164.2(b) at Inc 8a, TC-B100-59's sub-folder scenario at Inc 8b, and TC-B100-12's modal list split per increment. |
| **B-07** | The ARQ record and `docs/architecture.md` §11 get the B100-I amendments. Rows amended: I2–I9, I12. New rows: the save plan, `contained_in_workarea`, the `save_patched` split, `derived_from`, `predict_placement`. The architect writes them in parallel with the author. |
| **Security R2-01** (S-02 carried) | The this-work-area check lives **inside the single placement function** (`place_into_workarea`) and inside `save_patched`'s emit path. It also runs a reparse-point check on the Save target before `resolve()`. Every writer named by security R2-01 is covered by construction, and each has an arm. |
| **Security R2-02** | Every guard lives in `place_into_workarea`: reparse, containment, size cap, private staging. `copy_into_workarea` returns `place_into_workarea(...).path` and contains no second claim loop (architect's condition). The export uses the placement's `reused`. |
| **Security R2-03** (S-08 carried) | Cap every manifest array (`batch`, `assignments`, `declared_regions`, `gathered`, `files`) at 1 000 entries. The project preview in the Load dialog reads the manifest on a worker, with a bounded read, so a highlight never blocks. |
| **QA R2-04** | AT-B100-20 is written fully, with a surface, an observable and a threshold, the same as the other ATs. |
| **QA R2-09** | Problems are painted in user terms, e.g. "manifest damaged: a file path points outside the project". The internal code goes to the log only. |
| **QA R2-11** | §5.4 gets a row for the 7 `_handle_save_dialog` test files, including AT-B99-05 under the corrected emit rule. |
| **UX-37** | `p` highlights the open project's row, or the first project. The key-bar labels are stated. |
| **All other MINOR** (UX-38..41, UX-07/22 residuals, QA R2-07/08/10/12/13, security R2-04..R2-09, B-08..B-14) | Accept the proposed closures. Specifically:
- device names are checked on the RAW name and on every path component (R2-04/05);
- the recent cap arm uses 1 000 entries (R2-08);
- the free-space walk uses the same link pruning (R2-06);
- a failed merge removes what it placed (R2-07);
- mapped drives are not claimed "local" (R2-08 sec);
- the worker keeps the OSError handler and stays in the census (R2-09 sec). |

## Bounded round 3

After the author applies this file:
- **Each reviewer reads only the rows of its own open findings and marks each one closed or open.** That covers its round-2 new findings plus any carried ones.
- **A new defect the reviewer notices is recorded but does not block the gate.** It goes to the PDR as a condition, unless it is a HIGH.
- **Then PDR.**
