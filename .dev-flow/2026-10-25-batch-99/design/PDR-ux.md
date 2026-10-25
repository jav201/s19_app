# PDR — ux-reviewer rows — s19_app — Batch 2026-10-25-batch-99

| Field | Value |
|---|---|
| Record | `PDR-2026-10-25-batch-99`, ux lens (trigger D1) |
| Reviews | `design/design-proposal-b99.md` against `01-requirements.md` as of LED-2026-10-25-batch-99.3 |
| Code read at | `b2c4464` (`flow_screens.py`, `app.py`, `a2l.py`, `screens_directionb.py`, `window_help.py`, `screens.py`, `workspace.py`, `flow_execution_service.py`) |
| Reviewer | `ux-reviewer` (read-only; nothing edited but this file) |
| **Verdict** | `approved with conditions` |

**Bottom line.** This batch changes text inside surfaces that already exist. It adds no glyph, status word, column or pane, so **no prototype round is owed**. That holds only while the tripwire in §4 is not crossed. Eleven conditions follow. Four close places where a correct message would be painted and the user still would not see it: it is overwritten, clipped, sent to a panel the user does not read, or checked by a test that cannot fail. Each condition has one owning increment.

Axes: **Coverage** is met, except where HLR-156 asks the lane to list "each non-applied entry" and LLR-156.2 does not carry that (UX-C1), and for the interactive load path (UX-C7). **Certainty** is unmet for UX-C2, UX-C6 and UX-C9 until they close. **Evidence** is owed at the Phase 4 walkthrough.

---

## 1 · Context of use (ISO 9241-210 activity 1)

| | |
|---|---|
| **User** | A calibration engineer. Trusts the status line, the lane marks and the reports. Flashes the written file to an ECU. Reads hex fluently. Is not the author of the tool. |
| **Task** | Load an S19/HEX image (`l`). Patch it from a change document (flow PATCH, chain set) or by hand (Patch Editor). Save it back or export it (Split/Join/Export). Read the result, then flash the file the status names. |
| **Environment** | Windows Terminal, Textual TUI. Width is variable, with an 80×24 floor and 118 as the reference width. The status log is tail-clipped at the screen width, floor 50 (`app.py:13361`). Work area under cloud sync and antivirus, so locked files happen. Files and A2L names come from suppliers and are untrusted text. |
| **Harm model** | The engineer reads something as success that was not one, then flashes an image that is missing entries or has a truncated tail. |

---

## 2 · PDR checklist row 9 — interaction design reviewed

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 9 | UX lens applied (D1 fired): interaction design reviewed | ⚠ | Approved with conditions UX-C1..C11 (§3). Prototype question answered in §4. Evaluation states declared in §6. |

### 2a · Surface-by-surface findings (expert inspection against the code at `b2c4464`)

| Surface (HLR) | What the user reads today → after | Finding |
|---|---|---|
| Flow Execution PATCH card and cable (156) | `▓ done` always → `◇ notices` / `✗ error`. These are the existing `_FX_BLOCK_STYLE` / `FX_CABLE_GLYPHS` entries (`flow_screens.py:2386`, `:2432`). | ✓ Fits the existing pattern: no new glyph and no new word. |
| Lane run-log terminal line (156, 159, 154, 155-D9) | Notices: `◇ <lane> · done with notices · wrote X` (`flow_screens.py:3359`). It does not say *what* was not applied. Error: `· block i/n KIND — <diagnostics[-1] or summary> · chain halted` (`:3311`, `:3330`). | ✗ The notices line says "done … wrote X" with no count. That is the line most likely to be read as "safe to flash" (UX-C1). The error detail is whatever diagnostic comes *last*, so the cause is right only if each arm puts it last (UX-C2). |
| "skipped" on one screen (156) | `░ skipped` = a block that did not run (`skipped (upstream error)`, service `:274`). The PATCH summary will add `skipped-outside` etc. = an entry that was not applied. | ⚠ One word, two meanings, side by side on one lane (UX-C3). |
| Chain-set refusal D7 (155) | none → status line naming the lanes. | Must lead with the outcome. Status is tail-clipped, so names placed first push "nothing written" out of view (UX-C4). |
| Save project, missing source (155) | crash (exit 1) → a "notice". | ✗ LLR-155.4 leaves *no project folder*, so the save did not happen. A notice-severity message risks being read as "saved, with a caveat" (UX-C4). |
| `WorkareaPlacementError` (155) | none → raised. Callers paint `f"…: {exc}"` (`app.py:7996`, `:8428`, `:8450`, `:8554`, `:8624`; `crc_designer_view.py:1255`). | The exception text *is* the user message. It must name the cause (a locked file) and the next step. A containment-class subclass must not read as "outside the work area". 6 `except` sites against 15 `copy_into_workarea(` calls: a reachable caller that does not catch it crashes (UX-C5). |
| Patch Editor save summary (157) | — → status names the entries not applied before the save. | ✗ `on_patch_editor_panel_save_back_decision` calls `_report_change_result(result)` and then `_surface_verify_result()`, which **overwrites** the status with `Saved + verified: {name}` (`app.py:3388-3390`, `:3904`). As designed, the HLR-157 text is painted and then replaced (UX-C6). |
| Loader integrity notices (154) | none → 5 codes in the Issues panel. The flow SOURCE refuses. | ⚠ The interactive path is unchanged. `l` still paints `Loaded X (S19 only)` (`app.py:11013`) for a truncated file, and Patch Editor save-back still writes from it. The status line is the surface the user trusts (UX-C7). |
| A2L window, undecodable RAT_FUNC (158) | blank Physical cell (`app.py:12522`); `conversion_error` is computed (`a2l.py:2638`) but painted nowhere. → `n/a` with a reason. | The design does not say *where* the reason paints. Today a blank cell already means "no raw bytes", so `n/a` must stay distinct from it (UX-C8). |
| Bytes field (161, D1 provisional) | placeholder `DE AD BE EF` (`screens_directionb.py:4941`); the help already reads "a run of hex bytes" (`window_help.py:84`). | ✗ LLR-161.2's oracle ("both texts contain `hex`") already passes for the help on HEAD, so half of TC-B99-33 is vacuous. The help said hex while the parser read decimal: the text was never the defect. It has to state the *rule* (UX-C9). |
| Export (160) | silent overwrite / escape → `_<N>`, refusals, written-or-reused status. | Covered by LLR-160.2/160.4/160.5. The status needs outcome-first wording and the words `wrote` / `reused` (UX-C11). |
| Load project list / Workarea Files (162) | reserved homes listed; list reads the wrong folder → filtered; load folder. | ✓ A content change. ⚠ The empty and vanished-file states stay silent (N2). |

---

## 3 · Conditions — each individually dischargeable, re-read at the DDR

| # | Condition | Owner | Discharged by reading |
|---|---|---|---|
| **UX-C1** | When a lane's PATCH ends `notices` or `error`, the lane's terminal run-log line names the PATCH block and what was not applied. Format: count + first address + disposition, e.g. `· PATCH: 1 of 2 entries not applied (0x00020000 skipped-outside)`, or the refusal code. Clipped at `FX_ERROR_LINE_MAX`. The full list stays in the chain-set and flow reports. HLR-156 says the lane lists *each* entry, but the log is capped at 8 lines (`FX_LOG_MAX_ROWS`). Amend LLR-156.2 through a ledger entry to say "count + first + reports list each", or implement per-entry lines. Either way, write the choice down. | Inc 8 (+ ledger) | the LLR-156.2 text after the ledger entry; an AT-B99-06 assertion on the **painted** log line of the `mix` lane |
| **UX-C2** | For PATCH `error`, CRC empty-region `error`, SOURCE integrity `error` and WRITE-OUT verify `error`, the block result's **last** diagnostic, the one `_failure_detail` paints, is the user-facing cause. That means code plus address or count, e.g. `[S19-NO-TERMINATOR] …`, `applied 0 of 1 entries: 0x00020000 skipped-outside`, `region 0x20000-0x30000 holds no image byte`, `first difference at 0x…`. It is never an incidental line. CRC `notices` names the absent-byte count on the same line. | Inc 3 (D9), Inc 5 (CRC), Inc 8 (PATCH), Inc 9 (SOURCE) | each AT's assertion on the painted lane log line, not on `BlockResult` |
| **UX-C3** | Vocabulary. (a) No new glyph, status word or colour class: `_BLOCK_STATUS_GLYPH`, `_FX_BLOCK_STYLE`, `_FX_STATUS_STYLE`, `FX_CABLE_GLYPHS` and `_FLOW_STATUS_BANNER` are unchanged in the diff. (b) On flow surfaces, the umbrella word for entry-level outcomes is **"not applied"**. Disposition tokens appear verbatim with their address (`0x%08X`). Bare "skipped" stays reserved for a block that did not run. (c) The Patch Editor keeps `applied / skipped / blocked` counts. | Inc 8 | the Inc 8 diff of those maps (empty) and the PATCH summary strings |
| **UX-C4** | Outcome-first messages. Each new refusal or notice puts its outcome inside the first 50 characters, then names the file or lanes, then the next step, and says whether anything was written. Shapes: `Chain set not run: lanes 'A', 'B' both write 'same.s19' — give each lane its own output name. Nothing written.` / `Project NOT saved: source file missing: firmware.s19 — reload it or remove it from the project.` Save project, for both the missing source and the placement failure, is never painted with success or information severity, and never with a "Saved" prefix. | Inc 3 | the three message literals, and a TC asserting the outcome token at index < 50 of the painted status |
| **UX-C5** | The `WorkareaPlacementError` text names the file and the folder, the cause ("still locked after 5 retries, another program may hold it"), the next step ("close it and retry") and "nothing written". It never says "outside the work area" or "containment". The LLR-155.2 caller census adds one column, *the text the user sees*. A user-reachable caller with no handler is fixed, or is declared with its crash. | Inc 3 | the exception message and the census table in the Inc 3 packet |
| **UX-C6** | After a save-back, the **final** painted status line names the entries not applied before the save, together with the verify word, e.g. `Saved + verified: X.s19 — includes 1 entry not applied before this save (0x0000EB40)`. `_surface_verify_result` must not overwrite it. AT-B99-08 reads the status log **after the handler returns**. If this needs `app.py`, it counts against Inc 4's SOURCE budget (`change_service.py` + `models.py` today), and the packet says so. | Inc 4 | AT-B99-08's painted-status assertion; the Inc 4 file list |
| **UX-C7** | When a loaded image carries any of the five integrity codes, the load status line says so, e.g. `Loaded X (S19 only) — S19-NO-TERMINATOR: file may be truncated, see Issues`. Today only the Issues panel shows it, and save-back from a truncated load is unchanged. To discharge, add an LLR-154.4 through a ledger entry and implement it, **or** have the operator decline in writing (then it becomes a declared ⚠). | Inc 9 (+ ledger or operator note) | the ledger entry or the operator's note; the painted status in AT-B99-03 |
| **UX-C8** | A2L `n/a`. The design names *where* the reason paints. Recommended: the Physical cell reads `n/a`, and the characteristic description modal (`render_curve_description`) reads `Scalar value: n/a (<reason>)`, where the reason comes from `conversion_error`, is short and enum-derived, and contains no unsanitised file text. `n/a` (bytes present, not decodable) stays distinct from blank (no raw bytes). At width 118 and at the 80 floor, `n/a` is not clipped. A new column, pane or widget is out of scope: that crosses the §4 tripwire. | Inc 10 | AT-B99-09's painted cell and modal text |
| **UX-C9** | The help states the **rule**: "every token is hex, 1–2 digits, `0x` optional; digit-only tokens such as `10` are hex (0x10); decimal is not accepted". The placeholder says hex, e.g. `hex: DE AD BE EF`, and fits the compact input at width 118 and at 80. The refusal names the token and the rule (`Bytes: '100' is not a hex byte (1–2 hex digits)`). TC-B99-33 asserts a phrase that is **absent on HEAD**, so it is RED at `b2c4464` (today `window_help.py:84` already contains "hex"). | Inc 11 (gated on D1) | TC-B99-33's RED run on HEAD |
| **UX-C10** | Markup safety for every new file-derived sink: D7 lane names, the Save project file name, the placement-error path, export file and segment names, the integrity-notice path, and any A2L text in the reason. Each renders literally (`safe_text`; `notify(..., markup=False)`). Each has one hostile-name TC (`[red]x[/red]`, `[@click=app.quit]`) asserting 0 markup spans. | Inc 3, 6, 8, 9, 10, one per sink | the hostile-name TCs |
| **UX-C11** | The export status leads with the outcome (`Export refused: …` / `Exported 3 files: …`), uses the words `wrote` and `reused`, and names the actual `_<N>` names. On a part-way failure it names the files already written (LLR-160.5). | Inc 6 | AT-B99-11's painted status |

---

## 4 · Prototype round — does any change qualify?

**No round is owed.** Every change is content inside an existing pattern:

- the PATCH card and cable reuse the `◇` and `✗` entries already painted for other blocks;
- the status, log and notice strings go to the existing status log and run log;
- the Bytes placeholder and help are text;
- `n/a` goes in the existing Physical cell and the existing description modal;
- the project and Workarea lists change what they hold, not their layout.

**Tripwire.** Any of the following stops the increment and owes a prototype round with real Windows Terminal captures before implementation:

- a new glyph, status word or colour class;
- a new column, pane, widget or modal;
- a changed card or lane geometry;
- the A2L reason needing more width than its cell or modal gives.

This is also trigger A3 (PDR re-open).

---

## 5 · Proposed UX criteria for the Phase 4 walkthrough (observable, through the real mechanism)

| Criterion | Drive with | Painted result to read |
|---|---|---|
| PATCH outside the image → lane fails, nothing written | Textual pilot: Flow Execution, `#fx_run` | card `✗ error`; log line names `0x00020000 skipped-outside` and `chain halted`; no `wrote`; WRITE-OUT card `░ skipped` |
| One applied, one skipped → notices with the count | pilot, `#fx_run` | card `◇ notices`; log line `1 of 2 entries not applied …` (UX-C1) |
| Duplicate lane outputs → refused, outcome first | pilot, chain-set run | status log line starts `Chain set not run`; 0 files |
| Save project with a missing source → not saved, app alive | pilot, Save project dialog | status `Project NOT saved …`; app still running |
| Save-back after add-without-apply | pilot: Patch Editor Add / Apply / Undo / Add / Save | final status names the entry not applied before the save (UX-C6) |
| Truncated S19 load | pilot, `l` | status names the code (UX-C7, if kept); Issues panel lists it |
| Undecodable RAT_FUNC | pilot, A2L window | Physical cell `n/a`; modal shows the reason |
| Bytes help and refusal | pilot: type `100` in Bytes, then Add | status names `'100'`; help text states the rule |

Visual claims (colour of `✗` / `◇`, the cell not clipped) need a rendered frame, either `export_screenshot` or the widget's rendered strips at width 118 and at 80. A text read alone is `inspected, not exercised` for the visual half.

---

## 6 · Evaluation states (declared, keyed to what happened)

| Act | State |
|---|---|
| Expert inspection (cognitive walkthrough of the §1 tasks against the code at `b2c4464`) | **performed** — this record; method: read each painted string's composer and its overwrite path; evidence: the file:line citations in §2a; limits: no rendering run, widths taken from the code constants, not measured |
| Automated walkthrough through the real mechanism | **not performed — PDR precedes implementation**; planned at Phase 4 (§5) |
| Evaluation with users | **not performed — this team is one person and no user of this surface exists outside it** |

---

## 7 · ⚠ Notices (declared, not blocking)

- **N1** — Three vocabularies for one status already exist. The Builder shows `● ok ◈ notices ✗ error ○ skipped`. Execution shows `▓ done ◇ notices ✗ error ░ skipped`. The chain-set report shows `✓ ok`, and `✓` also means the CHECK kind in the Builder. This batch adds none; it should get a backlog row.
- **N2** — Two states stay silent. The Load project dialog has no empty-state text: once reserved homes are hidden, an install with only those homes shows an empty list. And `_load_from_item` (`app.py:8816`) does nothing when the picked file has vanished. Recommended for Inc 7: one status line each.
- **N3** — Under D1 = hex, a habitual decimal entry `10` is written as `0x10` with no refusal. Recommended: the Add status echoes the parsed bytes in hex. The operator's D1 decision owns this.
- **N4** — RAT_FUNC physical values change on screen with no in-app cue. The release note in the batch close is the only mitigation.
- **N5** — An existing behaviour: when a save-back takes `_<N>`, the status shows the real name but does not say it differs from the typed name. Recommended: `(X.s19 exists with different bytes)`.
- **N6** — The Builder's run panel paints the whole PATCH summary (`flow_screens.py:2337`). With many non-applied entries, cap it at the first N plus `and K more`, and point to the report.

## 8 · Explicitly not covered

- Visual styling and colour choices: these belong to the existing palette.
- The chain-set and flow report layout beyond its words: that is markdown, and QA owns its oracles.
- Whether D1, D5, D6 and D7 are the right decisions: the operator owns those. Only their wording consequences are reviewed here.
- Real-user evaluation: see §6.
