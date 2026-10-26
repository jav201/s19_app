# P2 · UX review · round 3 (bounded verification) — batch-100

- **Reviewer:** `ux-reviewer` (trigger D1). Read-only: no edits, no commit.
- **Under review:** `01-requirements.md`, ledger LED .14–.23 and `02-review.md` "Round 2" rows 184-201, all at `4e9c8f1`.
- **Scope (operator decision after the P2 iteration cap):** only the closure of my open findings, UX-26..UX-41 and the residuals UX-05, UX-07 and UX-22. This is not a new full review. A new defect noticed along the way becomes a PDR condition and blocks only if it is HIGH.

## Verdict

**`approve`.** 18 of the 19 findings are closed. One is still open, **UX-22, MINOR**, and it moves to PDR as a condition. No HIGH is open, and I found no new HIGH. The axis that was unmet in round 2, requirement content, is now met for this lens.

**Open count: 1 (MINOR).** In addition, 3 new MINOR PDR conditions (C-1..C-3 below), none blocking.

## Closure table

| id | r2 sev | state | where it closes | note |
|---|---|---|---|---|
| UX-05 | MAJOR | **closed** | LLR-173.2 (focus starts on `#load_path`; a printable key typed on `#load_list` goes to `#load_path` and never to an app binding; the arm "`p` typed with the list focused → the field holds `p`, 0 app actions"); VS-PA-6 corrected; LED .18 | — |
| UX-07 (residual) | MINOR | **closed** | §3 token table: all 7 problem kinds now carry next-step tokens, and "outside the work area" → `copy the folder into the work area`; LED .22 | — |
| UX-22 (residual) | MINOR | **open → PDR condition** | §3 token row `no data or A2L file` / `load a file and Save project`; LED .22 | The token row exists, but no LLR obliges it. LLR-171.2's threshold still answers "a folder with neither" with the `no project.json` or `missing` tokens. A folder that has a `project.json` recording no missing file, and no data or A2L file, matches neither of those, so the new row is never painted. **PDR:** LLR-171.2 uses `no data or A2L file` for that case, with a TC arm. |
| UX-26 | HIGH | **closed** | LLR-168.4 (`derived_from` per patched variant: base name, base SHA-256, differing byte count, recorded at the write); LLR-178.1 (the relation comes from `derived_from`, never from name order; the `firmware-patched.s19` arm; 0 announcements say "identical"; mutation "compare with the first variant by name" → RED); LED .16 | Recording starts at Inc 7. Projects saved before that, or by older builds, get no relation line. They still show the opened variant and its reason, so nothing is presented as false. Acceptable. |
| UX-27 | MAJOR | **closed** | LLR-167.8 (Save project calls the panel's `mark_saved` and `ChangeService.mark_saved`); LLR-174.1 cell "patched + entries → Save project → project load → load"; LED .17 | — |
| UX-29 | MAJOR | **closed** | LLR-176.1 (`begin_busy` owns `#status_text`; `set_file_status` cannot paint it until `end_busy`; the final lines run in order: outcome, then project + file, then file state; the bar starts at 0 and is hidden at the end and when idle); LLR-178.2 passes its line to `end_busy`; LED .19 | — |
| UX-30 | MAJOR | **closed** | HLR-176, LLR-176.1 (the bar follows `done/total` when a step reports bytes (copy, read, parse), and the step index otherwise; the within-step arm and its mutation); LED .19 | An indivisible step is a declared boundary case. That is consistent with the declared tag-table freeze. |
| UX-31 | MAJOR | **closed** | LLR-178.3 (the focus starts on the problem list; ↑↓ PgUp PgDn Home End scroll it; after `end`, a geometry read finds the last row visible; `tab` → `#result_ok`); LED .16 | **Author's choice — `escape` dismisses from anywhere, `enter` only on OK: acceptable.** It keeps a stray or repeated `enter` from closing the D2 notice unread (this also closes UX-39). `escape` remains a one-key exit from any position, and its mutation arm exists. See C-1 for the button label. |
| UX-32 | MAJOR | **closed** | HLR-175, LLR-175.4, LLR-167.6 (one row per top-level file, one per sub-folder with its count, one for `project.json`; action words `new` / `replace` / `keep` / `merge` / `rewrite`; "nothing is overwritten silently"; a merge paints the active-variant change as its own row; scrolls with Save/Cancel pinned; a 300-row arm at 118×54); §3 preface's declared exception for AT-B100-21 reading `SaveProjectScreen.plan`; LED .15 | The exception is acceptable: it is declared, read-only, and the painted action words are still checked at 220 columns. |
| UX-33 | MAJOR | **closed** | LLR-175.4 (name-dependent rows recomputed at most every 150 ms, 0 digests per keystroke, "20 keystrokes → ≤ 3 recomputations"); LLR-167.6 / LLR-167.7 (digest computed once per dialog open); LED .15 | See C-2 for the cost of opening the dialog. |
| UX-34 | MAJOR | **closed** | LLR-177.1 (refused set: the one load seam, unload, `v`, save-back, Save project, Patch apply and undo, each with `busy`; quit asks with the focus on No and, if confirmed, waits or rolls back; arms for 7 refusals and "0 partial folders after exit"); token rows `busy` and `still working`; LED .19 | — |
| UX-35 | MAJOR | **closed differently, acceptable** | §3 token table: disguised clash → `choose another name`; LLR-175.4 merge row; LED .22 | The merge is no longer suggested at all, rather than offered as the second option. That is the safer direction and fits the operator's P-C note. |
| UX-36 | MAJOR | **closed** | LLR-173.6 (`choose_install_set` marks `●` for project, file and work-area rows, with the note "becomes P's active variant" when a project is open; 6 of 6 arms); LLR-173.4 (a recent row shows path, size, last-seen and "checked when loaded", with 0 filesystem calls); LED .18 | — |
| UX-37 | MINOR | **closed** | LLR-173.2 (`p` highlights the open project's row, else the first); VS-PA-4 (key-bar labels "Load" and "Projects"); LED .18 | — |
| UX-38 | MINOR | **closed** | LLR-178.2 (the summary line ends "details: p"); LED .16 | — |
| UX-39 | MINOR | **closed** | LLR-178.3 (arm "an immediate `enter` → the panel still open"; mutation "focus on `#result_ok`" → RED); LED .16 | — |
| UX-40 | MINOR | **closed** | LLR-178.1 ("latest" means the variant the app's last recorded write made active; a touched file → false); LED .16 | — |
| UX-41 | MINOR | **closed** | §3 token row `not enough free space` / `free disk space or remove files from the project`; LLR-171.1 (refused before the folder is created, with the tokens); LED .22 | — |

## Author's choice on the P-E wording when the base is not in the project

LLR-178.1 says: **"patched from `<base>` (not in this project); N bytes differ from it"** when no project file has the recorded name and digest. A variant that has a `derived_from` record is never called "identical".

**Acceptable.** The wording:
- names the base;
- says plainly that the base cannot be opened from this project;
- keeps the byte count that was recorded when both images were in hand.

That is the honest statement, and it keeps the D2 notice true for a session loaded from outside the project (LLR-168.4 has an arm for that case).

## New, non-blocking (PDR conditions, all MINOR)

- **C-1 — the panel's button label.** `pe_B` labels the button "OK (enter)". With the focus starting on the list, a first `enter` does nothing, so under the §3 rule "every shown key is verified by pressing it" the label claims a key that does not work from the opening state. **PDR:** label the button with `esc` (for example "Close (esc)"), or state that its `enter` applies when it has the focus, and press the shown key in TC-B100-67.
- **C-2 — the cost of opening the Save dialog.** LLR-167.7's digest is computed "once per dialog open". For a large image, emitting and hashing on the main thread delays the dialog's first paint, which is the same freeze class as UX-02. **PDR:** say whether that computation runs on the worker or after the first paint, with a budget, using the case_06-sized fixture.
- **C-3 = UX-22** (above): LLR-171.2 should use the `no data or A2L file` tokens.

## Evidence checklist

| Item | State | How |
|---|---|---|
| Each of the 19 closures | `executed` (inspection) | The cited LLR and HLR text read at `4e9c8f1`; the ledger headings LED .14–.23 located; `02-review.md` rows 184-201 cross-checked. |
| The two author choices | `executed` | LLR-178.3 (keys and focus), LLR-178.1 and LLR-168.4 (base wording). |
| A new full review | `not-run — bounded round by operator decision` | Only the closures were read; C-1 and C-2 were noticed along the way. |
| Live run / captures | `not-run` | No surface ships yet, and no re-capture was made after the verdict. The Phase-4 expert inspection (§5.1) remains the place for the visual claims: the last row visible, the buttons pinned. |
| Evaluation with users | `not performed` | The team is one person and this surface has no user outside it. |
