# Inc 12b — E5 review (code + security)

Batch 2026-11-01-batch-101, increment 12b. Reviewer: code-reviewer, one agent with both the code and the security lens (one source file), independent of the implementer (DeepSeek v4 Pro), the testers (Sonnet G-T3, G-T4) and the integrator (Opus). Scope at head `092fffd` of branch `b101-inc12b` (worktree `<HOME>/Github/s19_app-b101-inc12b`): `git diff 2f54c7d -- s19_app` (`s19_app/tui/flow_screens.py` only, −511/+30) and `git diff 2f54c7d -- tests` (the 39 re-pointed nodes in 13 files, `tests/test_id_registry.py` +1, the new `tests/test_b101_flow_shown_widgets.py`, 4 nodes). I read all of it in full against `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc12b.md` (I-2, I-3, I-4), `E1-slice.md` §5, `E1-rulings.md`, `E3-rulings.md` and `../inc-12/E3-rulings.md` (S-1, S-2, S2-2, E3A-05, the round-2 acceptance that tests stop spelling removed names), `E4-impl-notes.md`, `E4-integration-notes.md` (I-D1 … I-D14) and both tester notes. I also read the code the change relies on: `_card_rows`, `_card_annotation`, `_card_lines`, `pipeline_text`, `pipeline_layout`, `ribbon_text`, `clip_head` / `clip_tail`, `_sync_kind_dependent_visibility`, the `flow_add` and `flow_clear` branches, `set_blocks`, `render_quarantine`, the panel's construction in `app.py:3805`, the flow-panel rules of `styles.tcss`, and `tests/b97_probes.is_displayed`.

I ran nothing that imports `s19_app` (operator rule). I did run these:
- `git grep`: the three pinned I-3 commands on this head, all empty; a wider grep of the repository outside `s19_app` and `tests`.
- A stdlib AST pass (`python -I`, a script in my session scratchpad) over `flow_screens.py` at head and at `2f54c7d`. Neither has an unused import. Both have the same set of unread module-level names and private methods: five public names, `ModeToggle._on_click` and `FlowExecutionPanel._source_indices`. All seven were there before this change, so the removal leaves no orphan.

The working tree equals HEAD for `s19_app` and `tests`. Every test-run statement below comes from the integrator's transcripts (`int-00` … `int-08`, `int-07b`) and the testers' base runs.

## Verdict

**PASS-WITH-NOTES.** There is no HIGH finding.
- **Product code:** correct against I-2, I-3 and both rows. No removal leaves a reader. The kind state cannot hold a value outside `_KIND_OPTIONS` on any path. Add, the NUL refusal and the first sync all read it. The module docstring describes the shipped surface.
- **Security:** the S-1 guard sits before any state change. No other removed widget was a guard. Hostile refs reach the cards only as plain text, and the re-pointed security nodes keep their hostile inputs whole.
- **Tests:** I compared the 39 re-pointed nodes with their base versions one by one. All but two are equal or stronger, apart from the drops the E3 ruling accepted. In the remaining two, AT-B94-15 and TC-B94-20, the width bound became a clause that cannot fail (R-1, MEDIUM).
- **Notes:** three LOW test notes (R-2 … R-4) and one LOW doc note (R-5). All five are recommendations; none blocks.

## Checks

| # | Check | Result | Evidence state |
|---|---|---|---|
| 1 | No live reader of a removed name | The I-3 commands on head are empty (×3). A wider grep outside `s19_app` and `tests` (tools, scripts, config) finds nothing either. Under `docs/` the only hits are records: CODE-CHANGES D16-6, S16 D16-6, the legacy LLR-146.1 / .11 text and DOSSIER `:594`, `:744` (carried below). `styles.tcss` has no rule for a removed id, and the `#flow_add_row` rules (`:3333-3341`) do not depend on child position. `app.py` reads none of the removed names. No module imports `LABEL` or an `_S_*` name through `flow_screens`. | executed (grep, read) |
| 2 | No dead helper left by the removal | The AST pass gives the same orphan set on base and head (above). The `LABEL` import went with its last reader. `_binding_label`, `_join_lines`, `_S_RULE` / `_S_DIM` / `_S_OUT` / `_S_ERR`, `RIBBON_NO_SESSION`, `Select` and `safe_text` are still read. | executed (AST, grep) |
| 3 | Kind state closed on every path | There are two writes: `__init__` sets `BLOCK_SOURCE` (`:1342`), and the chip branch writes `self._kind = kind` (`:2050`) only after `if kind not in dict(self._KIND_OPTIONS).values(): return` (`:2048`). That check runs before the write, the sync and the notice, so the bare prefix `flow_palette_` (suffix `""`) returns too. No other `._kind` site exists in `s19_app`, and no test reads `_kind`. **Load of a flow** (`set_blocks`, `:1548-1571`) sets blocks, name and funnel, never the kind; on base it never touched the select either. **Clear** (`:2099-2111`): the kind is untouched, as on base. **Session restore**: `set_session_dir` (`:1396-1401`) refreshes the ribbon only, and nothing else sets a kind. The panel is built once (`app.py:3805`) and never recomposed, so `_kind` cannot outlive a fresh compose that would reset it. | executed (read, grep) |
| 4 | Add paths read the new state | `flow_add` reads `kind = self._kind` (`:2059`). The NUL refusal `nul_add_refusal(kind, {… _ADD_PATH_INPUTS.get(kind, ())})` follows (`:2062-2068`), then the A2B and EXT-STEP branches and `_make_flow_block(kind, …)`. `on_mount`'s first sync reads `self._kind` (`:2131`). The kind is always one of the seven, so `.get(kind, ())` never yields `()` for a kind that has path inputs, and the NUL refusal cannot be skipped by the kind (graph E2-2). | executed (read) |
| 5 | Docstrings describe the code | All of these match the code: the module docstring (`:13-20`: chips, the one-row pipeline of cards, the add form); `KindChip` (`:1089`); the `FlowBuilderPanel` Summary and Data Flow; the rail section header (`:521-523`); `_refresh_blocks` (`:1649`); the `on_select_changed` comment. Leftovers outside the planned hunks: R-5. The "ledger number" wording (`:47`, `:1753`, `:1840`) still has a referent, because each card header paints its number (`_card_lines`, `:864-867`). | executed (read, grep) |
| 6 | Security: was a removed widget a guard? | Only `#flow_kind` gave a check: its options refused any value outside `_KIND_OPTIONS`. The S-1 guard replaces it at the same point, before any state change, and M1 turns R-FB-ADD.1/2 RED (`int-07b`). `#flow_ext_session`, `#flow_canvas` and `#flow_blocks` were `safe_text` sinks; removing a sink removes no check on an input. `#flow_help` and `#fx_help` held constant text. | executed (read) |
| 7 | Security: hostile refs paint literally on the cards | `_card_rows` scrubs each ref through `safe_text(s).plain` (`:737`). `row()` appends the plain string to a `Text` (`:852-856`), never through markup. `#flow_pipeline` receives a `Text` (`:1413`, `:1652`). `_card_annotation` has its own `safe_text` sink (`:819-828`). The ribbon `#flow_name_strip` is `markup=False`, and `ribbon_text` scrubs the session path. | executed (read) |
| 8 | Security nodes: inputs whole (S2-2), I-D4, I-D5 | **Inputs (each node asserts its own):** AT-088b keeps the scrubbed `_HOSTILE` whole in the CHECK card's `in · doc` row. AT-B94-18 keeps the 34-character scrubbed `_HOSTILE_SYMBOL` whole (`:428`); its NUL was already dropped on base (S4-1). The directionb node keeps `evil[red].s19` whole on the `in · file` row. The NUL inputs of TC-B97-62 and AT-B97-08 are unchanged. **I-D4:** "no span cuts the input, exactly one covers it" is the right adaptation of `spans == []`, since cards carry legitimate rule and colour spans, and it kills M3 (`int-07b`); one gap, R-3. **I-D5:** the fix is correct and keeps every clause. **The integrator's "anywhere in the pipeline" note** is answered in R-2: AT-B97-08 is not weaker; AT-B94-18 is not weaker than base, but its kill depends on the card geometry. | executed (read) |
| 9 | The 39 re-pointed nodes against base | **Equal or stronger:** 34 nodes, listed below. **Drops accepted by the E3 ruling:** "hidden widget stays hidden" in TC-B97-13, TC-B97-49 (session) and TC-1804, carried by the walks, which were RED on base; and the canvas-only glyphs in AT-B94-15 and TC-B94-20. **Weakened:** AT-B94-15 and TC-B94-20, the width bound (R-1). **Less discriminating than its docstring claims:** AT-006 REPORT (R-4). Details below the table. | executed (read) |
| 10 | The new file (G-T4) | Each walk asserts its population size before `never == []`. `is_displayed` tests `display` up the chain to the screen, which is the CTX-SHELL "shown widget". Every state is driven through the product's controls. In R-FB-ADD.1/2 the spy proves the stray press reached the panel. Its Add clause (`title == "chain · 1 block"`) also kills a store-then-guard variant: with `self._kind = kind` before the guard, Add shows `Add needs …` and the clause fails. AT-I12b-1 runs on keys only; its ribbon check (≥ 8 characters of the path) is weaker than "the folder name", accepted as I-D6. | executed (read) |
| 11 | Mutant table M1 … M7 | Not run by me; E5's mutant runner runs it on LAN host 2. M4 (`nul_add_refusal` → `None`) has only the G-T3 base run (10 RED). The NUL nodes changed only their kind driver (`set_kind` → `choose_kind`), so I expect the kill to stand; it is still unverified on this head. | not-run |
| 12 | Windows arms | Not run (operator rule): the 4 new nodes, the Windows-only skips of `int-01` … `int-05`, and the Windows half of I-D7. | not-run |

Node-by-node, check 9:
- **`tests/test_b97_flow_builder.py` (13).**
  - The helper `choose_kind` now waits for `selected_kinds(panel) == [kind]`. The base waited for the select's value; the new wait is stronger, because exactly one chip must be marked. The AST maps 11 nodes to `choose_kind` / `selected_kinds`, among them TC-B97-14 (`{k: [k]}`) and TC-B97-51 keyboard.
  - TC-B97-62 swaps its white-box `set_kind` for `choose_kind`; its NUL paste, refusal line and unchanged-chain clauses are unchanged.
  - AT-B97-08's assertions are its base form.
  - TC-B97-13 and TC-B97-49 (session) drop only their hidden-is-hidden clause.
- **`tests/test_tui_flow_builder_b94.py` (5).**
  - AT-B94-15 and TC-B94-20 gain card and cable counts (`╭` ×3, `▶` ×2) and lose the canvas glyphs and the width bound (R-1).
  - AT-B94-16 checks `#2.out` on the A2B card. AT-B94-17 changes its helper only.
  - AT-B94-18 is stronger: it adds the whole-payload and span clauses (R-2).
- **`tests/test_flow_builder_render.py` (3).**
  - AT-088b is anchored on its row (I-D5); R-3 applies.
  - AT-088 gating checks the model, as before.
  - `test_flow_block_label_covers_check` reads the card's title row and ref.
- **`tests/test_tui_flow_persistence_ui.py` (3).** AT-006 quarantine and AT-005 keep their content clauses (`keep.s19`, `other.s19`) plus before/after equality on the pipeline. AT-006 REPORT: R-4.
- **`tests/test_flow_crc_ui.py` (2).**
  - TC-356 reads `⊕ CRC`, `in · tpl` and `crc.json` on the card.
  - AT-128 calls the surviving `_refresh_blocks()` and reads `CRC` / `crc.json`.
- **`tests/test_tui_directionb.py` (2).**
  - The add-and-run node is stronger: it adds the order of the card heads.
  - The markup node is stronger: it gains the row anchor and the span clause.
- **The rest are equal.**
  - `tests/test_flow_crc_ribbon.py` (2): TC-361 uses chip presses with the same display clauses; TC-358 checks `No blocks yet`.
  - `tests/test_b97_chips_help.py` (2), `tests/test_b101_flow_names_ui.py` (3, Inc 9's `_add_load_block`), `tests/test_b102_flow_file_chooser.py` (1) and `tests/test_flow_funnel_b96.py` (1): only the wait or the driver changes.
- **TC-1804** (`tests/test_flow_external_step_b96.py`) is stronger: the project folder's name on the ribbon replaces a `session: ` prefix on a hidden line, and `terminal · human` on the card replaces `TERMINAL` on the canvas.
- **TC-B100-31** (`tests/test_b100_project_homes.py`): the clause "the full path `W/Q` is present" becomes "the ribbon ends with `workarea/Q`, not `workarea/P`". The ribbon's tail clip forces this; it still tells Q from P, and it uses OS separators, as the ribbon paints them.

## Findings

### R-1 — AT-B94-15 and TC-B94-20: the re-pointed width bound can no longer fail  [MEDIUM · test (weakened re-point)]
- **Where:** `tests/test_tui_flow_builder_b94.py:195`, `:200` (AT-B94-15); `:521-522` (TC-B94-20).
- **What:**
  - **Base:** `all(len(line) <= 88 …)` bounded the canvas's fixed paint width, and `canvas_width <= 96` bounded the canvas widget.
  - **Re-pointed:** `all(len(line) <= chain_width …)` with `chain_width = #flow_pipeline.region.width`, plus `rail_width <= 96`.
  - **Why the first clause is always true:** `#flow_panel #flow_pipeline` is `width: auto` (`styles.tcss:3314-3317`), so its region width is its own longest line. G-T3 measured 92 for both.
  - **Why the second clause is always true:** `#flow_pipeline_scroll` scrolls sideways (`overflow-x: auto`, `:3299-3308`). Its width comes from the panel, not from the chain, so `≤ 96` holds whatever the painter emits.
- **Failure scenario:** a `pipeline_layout` mutant that ignores `avail_w` paints the 3-card chain wider than the 92-cell rail. Both clauses stay GREEN, while the comment at `:196-199` still claims "the chain paints inside it (C-23 measured, C-32 painted oracle)".
- **Why it matters:** the two clauses give no evidence for what their comment states. This is MEDIUM, not HIGH, because the behaviour is pinned elsewhere: AT-B97-16's `void` reading (`tests/test_b97_width.py:1660-1665`) and the `pipeline_layout` nodes (`:813`, `:891-918`). No behaviour is left unguarded.
- **Fix:** bound the chain by the rail's content width, which is what the canvas's fixed 88 stood for. Read `rail.scrollable_content_region.width` inside `_drive`, then:
  ```python
  assert all(len(line) <= rail_content_w for line in canvas.splitlines()), (rail_content_w, chain_width)
  ```
  At 120×30 the 3 cards paint exactly 92 = the rail (G-T3's measurement), so this holds. Alternatively, drop the clause and cite AT-B97-16 in the comment.

### R-2 — AT-B94-18 searches the whole pipeline; its kill of S-2 mutant (b) rests on the origin note's clip  [LOW · test robustness]
- **Where:** `tests/test_tui_flow_builder_b94.py:426-434`.
- **What:** the A2B card paints the file binding twice:
  - on its `in · B` value row, through the `_card_rows` sink;
  - in the origin note, through `_card_annotation`'s own `safe_text` sink, as `missing: <head…>` clipped to `card_w − 16` cells.

  The presence clauses (`_SENTINEL`, `"_evil[red]"`, `scrubbed`) and `canvas.index(scrubbed)` all search the whole pipeline.
- **Failure scenario:** under M2 (the value row interprets markup) the node is RED today only because the note clips the payload.
  - **Arithmetic at 120×30 with two cards:** `card_w` = 44, so the note holds 27 characters plus `…`: `b77hostilemark[31m_evil[red…`. That is one character short of `_evil[red]`.
  - **What still kills M2:** the `scrubbed` clause (34 characters) needs a note of at least 34 cells (`card_w` ≥ 50), which the 96-wide box cannot give at two cards. So the kill is real at this node's fixed size.
  - **What would break it:** a larger box, or a change to the note's clip width. Either would let the note alone satisfy every presence clause.
- **Compared with base:** not weaker in what it catches at its size. Base read the canvas, which had one sink, with three clauses. The re-point adds the whole-payload and span clauses, and its control-byte clause now covers both sinks. It is, however, less robust than the form AT-088b got in I-D5.
- **AT-B97-08** (the integrator's other "anywhere" node) is not weaker. Its assertions are its base form; only `choose_kind` changed. Its presence clause `clip_tail(payload, inner)` with a leading `…` (`tests/test_b97_flow_builder.py:1618`) can only come from the card's value row (`_card_lines` uses `clip_tail`). The note keeps the head (`clip_head`), so the clause is effectively anchored to the value row.
- **Fix:** anchor AT-B94-18 as I-D5 anchored AT-088b. Take the row after `in · B`, assert `scrubbed` in that row, and compute `start` from the row's offset. The span and control-byte clauses stay as they are.

### R-3 — the span clause does not check which style covers the input  [LOW · test]
- **Where:** `tests/test_flow_builder_render.py:551-552`, `tests/test_tui_flow_builder_b94.py:433-434`, `tests/test_tui_directionb.py:5859-5860`.
- **What:** `exact` matches on `(start, end)` only. I-D4 says the clause "pins the one covering span to the card's value style"; the code does not do that.
- **Failure scenario:** a sink that keeps the text literal but paints it in another style, as one span exactly over the input, passes all three nodes. Base AT-088b's `spans == []` would have caught it.
- **Why it matters:** the impact is small. Such a mutant is not markup injection (the brackets stay literal), and M2 and M3 are RED, so the S-2 threat is covered. The problem is mainly that the record says more than the clause checks.
- **Fix:** assert that the covering span carries the card's value style: `VALUE`, the default of `row()` in `_card_lines` (`flow_screens.py:852`), in whatever form the rendered `Content` spans hold it. Or correct the I-D4 sentence.

### R-4 — AT-006 REPORT: `"REPORT"` cannot tell the REPORT entry from the fallback  [LOW · test]
- **Where:** `tests/test_tui_flow_persistence_ui.py:241`; the module docstring, `:19-20`.
- **What:**
  - **Base:** the node read `_flow_block_label`'s REPORT arm, whose fallback was `"?"`. So it failed if the arm went missing, which is the AMD-2 "non-vacuous" point.
  - **Now:** the card title comes from `_KIND_LOOK.get(kind, ("·", kind.upper(), …))` (`flow_screens.py:847`), so a report block paints `REPORT` with or without its entry (`≡ REPORT` vs `· REPORT`).

  The node still fails if the report block drops out of the loaded chain, which is its main intent. But the docstring's "the pipeline card's REPORT arm is non-vacuous" no longer holds.
- **Fix:** `assert "≡ REPORT" in blocks_text`, the glyph of `_KIND_LOOK[BLOCK_REPORT]` (`:557`).

### R-5 — four docstrings and comments still describe the removed surfaces  [LOW · impl (doc)]
- **Where, and suggested wording:**

| Site | Says now | Suggested |
|---|---|---|
| `flow_screens.py:1222-1226` (`_KIND_OPTIONS`) | "The dropdown block-kind options … the A2B entry rides the same single-select" | "the kind chips' options (label, kind) …; the A2B entry is one chip" |
| `:1554-1555` (`set_blocks`) | "repaint the canvas + ledger strip + name strip" | "repaint the pipeline and the name strip" |
| `:1601` (`render_quarantine`) | "the canvas + ledger and name strip are unchanged" | "the pipeline and the name strip are unchanged" |
| `:3975` (`_join_lines`) | "Join painted grid lines" | "Join painted lines (cards, lanes)" |

- **Why it matters:** on base the first three were true, because the hidden select, canvas and list existed and were repainted. After 12b they name surfaces that no longer exist. The implementer fixed two such comments beyond the plan (deviation 1, accepted) and missed these four. No behaviour changes.
- **Fix:** reword as in the table.

## Carried, not findings

- DOSSIER `:594` (anatomy row 11, "Kind dropdown (mounted but hidden …)", citing `#flow_kind`) and `:744` (F-35) still describe the removed widget. By E3A-04 + U-1, the DOSSIER is Inc 12's, and anatomy rows stay as found (the precedent in U-5). Inc 12 should know that row 11 describes a removed widget once 12b merges.
- `dict(self._KIND_OPTIONS).values()` (`:2048`) builds a dict on each press and keys it by label. The labels are unique literals, so it equals `{v for _l, v in …}`. The integrator accepted it as deviation 2.
- I-D9 (`label` ids repeated inside Textual composites): the product's own ids are unique, so the rows' population is unaffected.
- The untracked empty file `i12b-e5-mut.md` at the worktree root (18:11, presumably the mutant runner's output) is not in the diff. Keep it out of the commit, or move it under `.dev-flow/`.
- `FlowExecutionPanel._source_indices` and `ModeToggle._on_click` have no reader on base or head alike; they predate 12b and are out of scope.

## Evidence checklist

- [x] Diff read in full: `flow_screens.py` (the whole 695-line diff); the 13 re-pointed test files (diffs, plus the full TC-1804 builder node and AT-B97-08 on head); the new `tests/test_b101_flow_shown_widgets.py` (398 lines); `test_id_registry.py`.
- [x] Correctness pass: the kind's write sites and every path (check 3); the add paths (check 4); no remount; Clear, load and session restore.
- [x] Simplicity pass: removals only, plus a one-line guard. No new abstraction. The `dict(...)` idiom is carried.
- [x] Reuse and duplication: nothing re-implemented. The removal leaves no orphan helper (AST on base and head).
- [x] Tests reviewed for intent: 39 nodes against base; 4 new nodes with their negative controls; R-1 … R-4.
- [x] Verdict explicit: PASS-WITH-NOTES. No HIGH to resolve.

## §4b Independent review cell

`code-reviewer (code + security, E5) · PASS-WITH-NOTES · no HIGH (none to resolve); product = graph I-2/I-3/I-4, kind state closed on chip/load/Clear/restore, S-1 guard before any write, I-3 empty ×3 on head, no orphan (AST base = head), hostile refs plain on the cards; open as recommendations: R-1 MEDIUM AT-B94-15 / TC-B94-20 width bound re-pointed to a clause that cannot fail (property pinned by AT-B97-16); R-2 LOW AT-B94-18 M2 kill rests on the origin note's clip (anchor on the in · B row; AT-B97-08 not weaker); R-3 LOW span clause does not check the covering span's style (I-D4 overstates); R-4 LOW AT-006 "REPORT" passes on the fallback title; R-5 LOW four docstrings still name the canvas, ledger and dropdown`

### Evidence states

- Checks 1–10: `executed` (reading, `git grep`, a stdlib AST pass; no `s19_app` import).
- Every test result cited: `executed` by the integrator and the testers (`int-00` … `int-08`, `int-07b`, `base-01-g-t3`, `red-01-g-t4-base`), not by me.
- Mutant table M1 … M7 on this head: `not-run` by me (E5 runner).
- Windows arms: `not-run`.
- R-1 … R-5: their fixes are `planned`.
