# Review — s19_app — Batch 2026-10-19-batch-97

> **Artifact language:** English. Phase 2 artifact, round 1 (contract at `c83f6fe`).
> Reviewers, in parallel, each spawned as a named agent with its role file: `architect` ∥ `qa-reviewer` ∥ `security-reviewer` (always in `full`; the P1 scan also returned `security_required: true`) ∥ `ux-reviewer` (trigger D1 fired — added by the orchestrator's call, recorded here).

> **Owed in.** `core` ✓ · `full` ✓

## ✅ Verdict (read first)

- **Gate:** `iterate-to-refine` → Phase 1. One blocker (Q-1) forces it (`stations/p2-review.md` §Gate); every lens returned `iterate-to-refine` on its own majors as well.
- **Out-of-scope findings:** 4 named and routed below (S-6 → backlog, U-17 → backlog, A-15 → backlog entry written in this round, Q-13 → security + Flow Builder increment).
- **Findings:** 1 blocker · 33 major · 31 minor (architect 0/5/10 · qa 1/13/9 · security 0/3/5 · ux 0/10/8, by the row severities below; overlapping findings are cross-referenced, not merged, so each lens's record stands).
- **shall/should check:** ✓ clean — architect grep of every `Statement:` line for should/may/will/might/could/can/must → 0.
- **Two-layer (blockers):** ✗ (c) incomplete — story elements without LLR/TC (A-2, Q-8); ✗ (d) — AT-B97-03's hostile file name cannot be built through the surface (Q-1); ✗ (b) partial — the REPORT FIELDS deliverable has no observation (Q-7).
- **Census (change-first):** done — best-effort + gate-confirmed (qa-reviewer, below). Not complete by construction.
- **Security:** ⚠ 8 findings, risk LOW (no network, auth, secret or new execution surface; launches go through the existing argv-list seam).
- **Evidence checklists (architect / qa / security / ux):** ✓ all four returned; ✗ items are the findings below.

**Operator decisions this review surfaces (for PDR, the operator stop):** the waiting-state colour — the operator approved captures painted in the prototype amber `#e8a33d`, the shipped code paints `#f6ff8f`, and burnt orange `#cf6a2d` sits 13.2° from the amber (A-4, U-2); one primary action per screen (U-9); whether cards grow at 220 (U-5); the JSON-tab refresh mechanism (UX recommends live-on-show with a stamp and no button, read-only view).

---

## Detail (reference)

### Findings

Status for every requirement defect: `open → P1 (iterate-to-refine)`. Other classes carry their route.

| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| Q-1 | qa | blocker | HLR-144 AT-B97-03, LLR-144.7, TC-B97-07 (also AT-B97-11) | The hostile file name (`[/]`, `[link=https://…]`, C0/NUL bytes) cannot exist on disk; the C-17 AT is unbuildable through the surface. Probe: `b97[bold]x[/].json` FileNotFoundError, `https://` OSError | Split the payload: filename-legal subset (`[bold]`, `[red]`, `[link=e]`, `[@click=app.quit]`) as a real file through `#patch_doc_load_button`; the full payload through a file-content field | open → P1 |
| A-1 | architect | major | LLR-144.5/144.6, TC-B97-06 | JSON-tab refresh covers 5 of 9 document writers; `add_symbol_entry` `:1154`, `edit_entry_json` `:1344`, `load_text` `:1465` missing | Writer set derived from the census (C-40 limb 2), all nine | open → P1 |
| A-2 | architect | major | US-134/135/136 → LLRs | Story elements never derived: hex strip hero, labelled form, entry chips; REPORT FIELDS content + memory table; copy/paste strip, `Variables (n)`, session ribbon | Add LLRs or move to Not-taken-in with consent | open → P1 |
| A-3 | architect | major | LLR-146.5 only | "Hero + Run, nothing else filled" required only on the Builder; `#fx_confirm_<i>` ships `variant="primary"` | One LLR + TC per screen; Confirm painted in the wait style | open → P1 |
| A-4 | architect | major | LLR-146.6, HLR-146/147 | Colour clause misplaced (HLR-146 has no colour); amber exclusivity never stated; the ≥20° gate conflicts with the approved amber | Colour clause in HLR-147; exclusivity LLR; wait colour back to the operator; CRC derived from it | open → P1 + PDR (operator) |
| A-5 | architect | major | HLR-149 vs LLR-149.2/.4/.5 | LLRs narrow "≥118x54, variable" to two sample points | State over the range; samples 118x54, 220x60, one off-grid (160x56), one above 220 | open → P1 |
| A-6 | architect | minor | IFC `project_dir_to_folder_chip`, `a2l_parameters_to_check_ledger` | Two nodes owned by LLRs that do not state the transform | LLR for press → one seam call per family; owner for `_prefill` | open → P1 |
| A-7 | architect | minor | IFC Part B `set_row`, `entries_ledger`, preamble | `#fx_set_row` consumers wrong; docstring counted as consumer; preamble claim false | Fix consumers; correct preamble | open → P1 |
| A-8 | architect | minor | P-17, LLR-146.7 | Spanish counts do not add up (34 vs 35 vs 26) | One re-run census, one total (see Q-3) | open → P1 |
| A-9 | architect | minor | §1.2, §2.4 | English proven only for flow panels | P-row with the editors + `window_help.py` census (0/0 measured) | open → P1 |
| A-10 | architect | minor | LLR-148.6/148.7 | Help coverage omits keys; `✓` vs shipped `☑`; Builder legend names glyphs it never paints | Keys in coverage set; `☑`; Builder's own vocabulary | open → P1 |
| A-11 | architect | minor | HLR-147 vs LLR-147.3 | Lane numbering 1-based vs 0-based | 0-based everywhere | open → P1 |
| A-12 | architect | minor | HLR-148, HLR-144 (EARS) | Compound "or … or … respectively"; state property behind an event trigger | Split HLR-148; `While displayed` for layout | open → P1 |
| A-13 | architect | minor | §3 acceptance | AT-B97-14 (and -06) tied to no clause | One line per AT (see Q-9) | open → P1 |
| A-14 | architect | minor | ARQ R16 vs §2.4 | `insight_style.py` makes Inc 3 or 4 five files | Re-cut increments | carried → P3 (Inc 3/4 cut, fixed at PDR) |
| A-15 | architect | minor | Not-taken-in | Hex-viewer no-wrap called a backlog item; no entry exists | Write the backlog entry quoting the operator | routed → orchestrator, written in this round |
| Q-2 | qa | major | US-137/R-9, HLR-147, LLR-146.7/147.5 | 7 Spanish strings in `flow_execution_service.py` (`:501, :846, :860, :867, :885`) paint on both flow screens; contract says "no service change" | Service strings in scope (LLR + budget + pins) or OUT with backlog row; painted-surface check over summary/diagnostic paths | open → P1 |
| Q-3 | qa | major | P-17, LLR-146.7/147.5, §5.2 | Spanish census keyed on line spans and an unwritten regex; measured 36 + 12 pins, not 34/11 | AST `ClassDef` keying; committed regex; `>= 36` guard on `9c7beaf` | open → P1 |
| Q-4 | qa | major | LLR-144.1 / TC-B97-01, TC-B97-08 | Id set re-derived from the source it certifies; negative control cannot go RED | Freeze 66 / 31 ids from `9c7beaf` | open → P1 |
| Q-5 | qa | major | §2.4, HLR-149 boundary | Shipped 80x24 floor and 120-col `width-narrow` breakpoint ignored; 13 test files drive these screens at 80x24 | Declare floor superseded (ledger + affected tests) or kept reachable under scroll; name the breakpoint; 119↔120 arm | open → P1 |
| Q-6 | qa | major | C-10/C-11, §5.1 | Mode control, rebind input, Check Editor tabs have no non-default black-box AT | AT arms for parallel, rebind, JSON/Addendum | open → P1 |
| Q-7 | qa | major | US-135 vs HLR-145 | REPORT FIELDS deliverable never observed | Parsed card equals the included parameters | open → P1 |
| Q-8 | qa | major | US-136/137 vs §3–4 | `Variables (n)`, copy/paste strip, variant-scope selector removal, ~13 dead rows: no requirement | Derive or move out (overlaps A-2) | open → P1 |
| Q-9 | qa | major | §3 all HLRs | ATs exist only as ids; AT-B97-14 has no content | Per-AT row: fixture, driver, assertion, RED arm | open → P1 |
| Q-10 | qa | major | HLR-147, AT-B97-09/10, P-24, §5.1 | `flash_q4` is not a file; lanes added through internals; "error lane" does not exist; CRC fixture missing; fixtures without `tests/` paths | Fixture list under `tests/`; lanes via `#fx_import`; deterministic error lane; CRC fixture or drop the clause | open → P1 |
| Q-11 | qa | major | LLR-149.4 / TC-B97-37 | No-wrap set hand-listed; DataTable arm is a pin | Set from the DOM with `len >= K`; per-widget height vs line count + cell length; label the pin | open → P1 |
| Q-12 | qa | major | C-26, §6.3 | Superseded shipped ATs/TCs not declared (census below) | Name each node with owning LLR + increment; retire/rewrite via the ledger | open → P1 |
| Q-13 | qa | major | AT-B97-08 path, `variant_execution_service.py:273` | A flow ref with NUL raises an uncaught `ValueError` on load (pre-existing crash on a hostile file) | Security re-invoked on the existing surface; AT-B97-08 uses a NUL-free payload and records the gap, or expects fail-closed after a fix | routed → security-reviewer + Flow Builder increment |
| Q-14 | qa | major | `tests/test_id_registry.py:124` | `EXPECTED_SCANNED_TEST_FILES = 189` exact; new test files turn it RED | Bump per test-adding increment | carried → P3 (each test-adding increment) |
| Q-15 | qa | minor | HLR-144 threshold | Compares against the service document (internal symbol) | Compare against the fixture file's six addresses | open → P1 |
| Q-16 | qa | minor | LLR-145.5 / TC-B97-12 | Assumption dischargeable now | Paste the executed `parse_a2l_file` result as a premise | open → P1 |
| Q-17 | qa | minor | LLR-148.6/149.2/148.3 | DOM-derived sets with no non-empty guard; chip families hand-listed | `len >= K`; loop over `CHIP_FAMILIES` | open → P1 |
| Q-18 | qa | minor | §5.2 snapshot bound | Every snapshot cell already `xfail(strict=False)`; the bound cannot fail | State it; tie to regen or mark cells | carried → P3 (Patch Editor increment) |
| Q-19 | qa | minor | §5.1 C-12 vs HLR-147 | Load-Set restore, Write `.chk.json`, Run press never driven | Add them to the ATs | open → P1 |
| Q-20 | qa | minor | LLR-144.6 / AT-B97-02 | Stale-then-current not asserted in the AT | Add once PDR picks the mechanism | open → P1 |
| Q-21 | qa | minor | LLR-147.2 negative control | Cannot run on `main` | RED on the first increment's tree | open → P1 |
| Q-22 | qa | minor | P-11 | `#flow_run` y = 48, not 49 | Correct | open → P1 |
| Q-23 | qa | minor | P-24 fixtures | Demo fixtures are copies of tracked examples / frozen serializer output | Use tracked examples; generate JSON in `tmp_path` | open → P1 |
| S-1 | security | major | LLR-148.1/148.2; `folder_open_service.py` Popen; `open_folder_chip.py:118,162-177` | Chip checks only `exists()`; a `flows` file/symlink or a `*.app` project dir is opened/run by the default handler | Real directory (`is_dir()`, not a symlink/junction, inside the project root) or a status refusal and 0 opener calls; TC for file + symlink | open → P1 |
| S-2 | security | minor | PDR item 5 | Create-on-press for new families has no containment constraint | `flows` create via `scoped_home`; `session` never creates | open → P1 (constraint) / PDR |
| S-3 | security | major | LLR-144.2/144.5/144.7 | C-17 gap: inspector pane and JSON tab paint file-derived fields with no LLR/AT | Extend 144.7; hostile arm through inspector + JSON tab | open → P1 |
| S-4 | security | major | LLR-146.8, 147.3, 147.6 | C-17 gap: EXT-STEP `instruction`, `log_ref`, `output_path` on card, pending lines, run log | Add the fields; hostile EXT-STEP arm | open → P1 |
| S-5 | security | minor | LLR-144.5 boundary | JSON tab can receive 256 MB / 100,000 entries synchronously | Display cap + truncation note; boundary arm | open → P1 / PDR |
| S-6 | security | minor | `s19_app/utils.py:30-39` | Bidi / zero-width controls pass `safe_text` (pre-existing, shared module) | Backlog entry | routed → backlog |
| S-7 | security | minor | LLR-144.7 threshold | Counts only bold/link spans; payload has `[red]` | "0 spans originating in the payload" | open → P1 |
| S-8 | security | minor | §6.3 C-17 text | The source scan cannot see implicit markup sinks | Correct the risk text; per-surface ATs are the control | open → P1 |
| U-1 | ux | major | HLR-144..148, §5.1 | No keyboard/focus requirement; every AT clicks | Tab-order LLR per screen; keyboard-only first-task AT; "key" back into help | open → P1 |
| U-2 | ux | major | LLR-146.6, HLR-147 | Amber exclusivity not a requirement; notices / dirty dot share the hue | Exclusivity LLR over renderer-derived spans; PDR picks wait + notices hues | open → P1 + PDR |
| U-3 | ux | major | LLR-149.4, 145.3, 145.5 | Tail-keeping makes picked REPORT FIELDS rows identical | Discriminating truncation; no two painted rows equal unless records equal | open → P1 |
| U-4 | ux | major | LLR-146.4 vs 149.4 | Head vs tail conflict on file lines | Files/paths keep tail, labels keep head | open → P1 |
| U-5 | ux | major | LLR-149.5, TC-B97-38 | Container width passes while fixed cards leave the void | Measure painted extent; PDR decides grow vs more per band | open → P1 + PDR |
| U-6 | ux | major | LLR-147.3, 147.1 | Confirm can be off screen (5+ blocks, lane below fold) | Confirm inside the panel viewport while waiting; 6-block fixture | open → P1 |
| U-7 | ux | major | LLR-148.6, TC-B97-32 | Help check passes on a bare word list; glyph set hand-listed | `label — effect` lines; glyphs from the renderer | open → P1 |
| U-8 | ux | major | LLR-148.7 scope | Many painted vocabularies without legend; issues/notices and `✓` ambiguities | Extend; unify; distinct pending glyph | open → P1 |
| U-9 | ux | major | R-5.2 not carried | Filled-element rule only on Builder (overlaps A-3) | One LLR per screen; PDR names each primary action | open → P1 + PDR |
| U-10 | ux | major | empty/loading/error states | Uncovered region states incl. Flow Execution while running | Clause per region or declared OUT | open → P1 |
| U-11 | ux | minor | LLR-147.1 table | Cable after waiting block: `░` vs approved plain line | Match the approved capture or show the operator | PDR |
| U-12 | ux | minor | LLR-147.1, 146.6 | Visual claims tested only via glyphs/styles | Declare "inspected, not exercised" for the visual half | open → P1 |
| U-13 | ux | minor | HLR-148 | All chips read `Open folder` | Name the folder in the label/tooltip | PDR |
| U-14 | ux | minor | LLR-145 / 149.5 | Fmt column cuts units; column identity unclear | Say what it shows; adaptive if units | open → P1 |
| U-15 | ux | minor | inspector heading | Clipped without ellipsis at 118 | Add to LLR-149.4 row list | open → P1 |
| U-16 | ux | minor | context of use | Input devices and colour capability not stated; strip is colour-only | Environment line; non-colour cue or declared OUT | open → P1 |
| U-17 | ux | minor | cross-screen | Footer key bar clipped at 118 and shows hex keys on these screens | Backlog for the all-screens review | routed → backlog |
| U-18 | ux | minor | §2.6 / 220 voids | Vertical voids not written down | Remaining height to the growing region; assert it | open → P1 |

### shall / should check

✓ clean (architect: 0 modal should/may/will/might/could/can/must in any HLR/LLR statement).

### Two-layer acceptance review (blockers)

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-134 / HLR-144 | yes | yes | no — strip, form, chips underived (A-2) | no — AT-B97-03 unbuildable (Q-1); threshold reads the service document (Q-15) | blocker |
| US-135 / HLR-145 | yes | no — REPORT FIELDS unobserved (Q-7) | no — card content, memory table (A-2) | yes | major |
| US-136 / HLR-146 | yes | yes | no — copy/paste strip, Variables chip, ribbon (A-2, Q-8) | yes | major |
| US-137 / HLR-147 | yes | yes | partial — dead rows (Q-8) | no — lanes added through internals (Q-10) | major |
| US-138 / HLR-148 | yes | yes | partial — press → seam call has no LLR (A-6) | yes | major |
| US-139 / HLR-149 | yes | yes | yes | yes — but the void predicate is a proxy (U-5) | major |

### Supersession census (change-first)

qa-reviewer, best-effort + gate-confirmed, `grep -rl --include='*.py' <symbol> tests/` at `c83f6fe`:

- Patch Editor: union over the 66 ids = 24 files; `test_tui_patch_chips.py` reaches the E-3 grid rules and is not in the IFC; `test_tui_patch_layout.py` 9 tests at fixed sizes (7 at 80x24).
- Check Editor: `check_param_table` 1, `check_write_button` 2; `test_tui_check_editor.py` asserts button height 3 (LLR-145.4).
- Flow Builder: `test_tui_flow_builder_b94.py:144-159, 241, 371, 436-454` (painted canvas, palette, canvas region — AT-B94-15..18) and `test_flow_external_step_b96.py:404` break if the canvas is hidden.
- Flow Execution: `test_tui_flow_execution_b94.py:626, 693` read `#fx_mode` as a `Select`.
- Chips/help: `test_window_usage_help.py:250` (`SHIPPED_WINDOW_KEYS`), `_EXPECTED_KEYS` there and in `test_changes_file_notation_help.py`; `test_open_folder_chips.py:94-98` (`_RAIL_CHIPS`, id scheme).
- Spanish pins: `test_flow_external_step_b96.py:265, 266, 333, 345, 422, 425, 507-509, 514`, `test_flow_funnel_b96.py:331, 475` (four pin service strings, Q-2).
- 80x24 runs in 13 patch/check/flow test files (Q-5); `test_id_registry.py:124` file count (Q-14).
- Goldens / B3: no `tests/goldens/` source touched (C-24 not fired); `test_tui_snapshot.py` patch cells (80x24, 120x30) already `xfail(strict=False)` (Q-18); `#screen_flow_execution` not in the matrix.

What the increment gates must confirm: each superseded node above retired or rewritten through the ledger in its owning increment.

### Security review summary

security-reviewer: risk LOW, 0 blockers, 3 majors (S-1 directory check before launching the opener; S-3/S-4 C-17 coverage of the inspector, JSON tab and EXT-STEP fields), 5 minors. Argument injection into the opener checked and not possible (argv list, absolute resolved paths, no `-` prefix, no `/` switch on Windows). JSON tab: no eval/exec/template; size is the only concern (S-5). External step: display-only, no process launch in the flow code. Q-13 (uncaught `ValueError` on a NUL ref) is a pre-existing hostile-file crash routed back to security as a scope re-invocation at the Flow Builder increment.

### Evidence checklists (full)

**architect** — constraints ✓ (§2.4; budget slip A-14) · alternatives ✓ (PDR §6.2, ARQ R13–R17) · n/a marked ✓ · recommendation tied to constraints ✗ (A-2, A-3, A-4) · risks ✓ (+ stale JSON, draft overwrite on reseed) · cost n/a ✓ · diagram n/a ✓ · what would change it ✓ · two-layer ✗ (A-2, A-13, A-4) · shall/should ✓ · IFC owners/consumers run ✓ (A-6, A-7). About 45 file:line claims spot-verified, all matched.

**qa-reviewer** — mode plan ✓ · acceptance shape ✓ / per-AT GWT ✗ (Q-9) · explicit expected ✗ (Q-9, Q-10) · edge cases ✓ / HLR-144 error arm unbuildable ✗ (Q-1) · regression checklist ✓ / §6.3 incomplete ✗ (Q-12) · exit criteria ✓ / snapshot bound cannot fail ✗ (Q-18) · no PII ✓ · results `planned` ✓ · Layer B through surface ✗ (Q-10, Q-7, Q-1) · reachability ✗ (Q-6, Q-19) · no unfilled template ✓. Re-measured 15 thresholds: 12 match; `#flow_run` y (Q-22), Spanish total and pin count (Q-2, Q-3) do not.

**security-reviewer** — what/where/why/fix ✓ · severity ✓ · no secrets ✓ · verdict explicit ✓ · new surface scoped ✓.

**ux-reviewer** — context of use ✓ user/task, ✗ environment (U-16) · observable criteria ✓ · real mechanism ✗ (U-1) · painted result ✗ (U-5, U-12) · error/empty/slow ✗ (U-10) · help and legends ✓ required, ✗ vacuous/incomplete (U-7, U-8) · folder chips ✓ · width at 118 ✓ · voids at 220 ✗ (U-5, U-18) · round-2 rules partial (U-2, U-4) · captures reviewed ✓ · ISO 9241-210 declaration ✓ (expert inspection performed; automated walkthrough owed at P4; new-engineer persona not evaluated with users).

---

## Round 2 — contract at `55899dd` (after `LED-2026-10-19-batch-97.2`)

### ✅ Verdict (round 2)

- **Gate:** `iterate-to-refine` → Phase 1. One blocker (Q2-1) forces it; all four lenses returned `iterate-to-refine`.
- **Round-1 resolution:** architect 11 resolved · 3 partially (A-4, A-7, A-11) · 1 carried (A-14); qa 17 resolved · 4 partially (Q-2, Q-3, Q-11, Q-12) · 3 carried/routed (Q-13, Q-14, Q-18); security 6 resolved · 2 partially (S-1, S-4); ux 10 resolved · 6 partially (U-1, U-2, U-3, U-5, U-6, U-8; U-10 also partial) · 2 routed to PDR (U-11, U-13).
- **New findings:** 1 blocker · 17 major · 27 minor (architect 0/4/11 · qa 1/5/4 · security 0/1/3 · ux 0/7/9).
- **shall/should check:** ✓ clean (architect, 0 modal words in any Statement).
- **Security:** risk LOW, 0 HIGH. Q-13 ruled: fix in this batch at the Flow Builder increment (S2-2).
- **Operator decisions put to the operator before the round-3 amendment** (they close several requirement gaps at once, so the amendment can be final): hue pair (U-2/A-4; UX proposal `#e8ad3d` waiting / `#c9562b` CRC, 23.0°), primary action per editor (U-9), card growth at 220 (U-5/U2-5), JSON refresh (PDR 1), multi-variant runs once `#flow_scope` leaves the Builder (A2-4), cable after a waiting block (U-11), chip labels name their folder (U-13), Confirm focus on pause (U2-3).

### New findings (round 2)

| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| Q2-1 | qa | blocker | AT-B97-22, -06, -19, -23 | ATs observe internal symbols (`last_run_record.mode`, posted `RunRequested` count, `run_chain_set` wrapper); a synchronous run cannot be pressed mid-flight through the surface | Observe the chain-set report's `**Mode:**` line (`flow_execution_service.py:1598`) and new `reports/*` files / written output; move AT-B97-23's in-flight arm to TC-B97-55 | open → P1 |
| Q2-2 | qa | major | `ES_MARKER`, P-17, LLR-146.7/147.5 | Marker misses 6 painted Spanish constants; true census on `9c7beaf` is 48, not 42 | Freeze the 48 constants as a literal; extend the marker; restate P-17 | open → P1 |
| Q2-3 | qa | major | LLR-149.4 / TC-B97-37 | Neither no-wrap predicate goes RED on a clipped wrapped row (executed) | `get_content_height` vs line count; DataTable content length vs column width + required ellipsis | open → P1 |
| Q2-4 | qa | major | LLR-145.3, 149.4, TC-B97-10/37 | Tail-only mutation cannot go RED on the fixture (74/75 names share `ASAM`); row vs cell ambiguity; Fields parameters unnamed; distinct cells need W ≥ 42 | Head-keeping as the RED mutation or a new fixture pair; per-cell predicate; name the 6; state the minimum Parameter width | open → P1 |
| Q2-5 | qa | major | §6.3 superseded table | New LLRs supersede unnamed nodes (`test_tui_flow_execution_b94.py:277, 345-348, 363, 451-452`; `test_flow_external_step_b96.py:387, 425`) | Add rows; re-run C-26 over the 21 new LLRs | open → P1 |
| Q2-6 | qa | major | LLR-147.6, AT-B97-11 | `#fx_set_select` paints `flowsets/{stem}.json` as raw markup (`flow_screens.py:2566`, executed: spans bold/red/link/@click) | Add the set picker to LLR-147.6 + an AT arm; security re-invoked on the existing surface | open → P1 + security |
| Q2-7 | qa | minor | §5.3 fixtures | `crc_wait_chain` lacks its CRC config (executed); "restart panel" is not a control; widest-values fixtures missing | `examples/crc_config.example.json`; a new `S19TuiApp` on the same `tmp_path`; fixture rows | open → P1 |
| Q2-8 | qa | minor | LLR-146.12 / TC-B97-50 | Scope clause passes on `main` (SINGLE is default) | Set the hidden Select to ALL_VARIANTS first | open → P1 |
| Q2-9 | qa | minor | LLR-147.7, 148.7, 149.2 | Missing non-empty guards on three derived sets | `len >= K` guards | open → P1 |
| Q2-10 | qa | minor | P-35 | Evidence command does not reproduce as written | Paste the real command (`80, ?24`) | open → P1 |
| A2-1 | architect | major | HLR-147, LLR-147.1, AT-B97-09 | Expected `✗ ░ ░` contradicts the truth table (`▓ ✗ ░`) | Correct in all three places | open → P1 |
| A2-2 | architect | major | HLR-144 vs LLR-144.6; HLR-146 vs LLR-149.6 | HLR statements contradict their LLRs (explicit JSON branch; Run without scroll below 118x54) | Qualify both HLR statements | open → P1 |
| A2-3 | architect | major | LLR-144.1/.2/.9/.10; PDR item 2 | Shipped Patch Editor controls (paste buffer + parse, undo/redo, execute, saveback, Refresh) have no home and may be hidden; the PDR option "reseed `#patch_paste_text` read-only" breaks the `load_text` writer | LLR placing the paste area editable; displayed-and-reachable set for shipped controls (Check Editor too); drop or restate the option | open → P1 |
| A2-4 | architect | major | LLR-146.12, PDR item 12, §6.3 | Hiding `#flow_scope` retires LLR-104.6 (multi-variant runs) silently | Requirement for where multi-variant runs live, or a ledger-recorded retirement with operator consent | open → P1 + operator |
| A2-5 | architect | minor | §6.2 items 8, 15 | "Holds for any choice" false for canvas reachability and the cable glyph | Parametrise or decide | open → P1 / PDR |
| A2-6 | architect | minor | derived LLRs | No parent HLR clause for primary action, one run at a time, CRC hue, scope selector; "hero" undefined | Add clauses; define "hero" | open → P1 |
| A2-7 | architect | minor | HLR-144, LLR-147.3, 147.10, 148.1 | Compound EARS | One trigger per statement | open → P1 |
| A2-8 | architect | minor | LLR-147.3 vs §5.3 | Block numbering mixed | 0-based | open → P1 |
| A2-9 | architect | minor | HLR-149, LLR-149.6 | Mixed sizes (220x40) undefined | "width < 118 or height < 54"; 220x40 sample | open → P1 |
| A2-10 | architect | minor | LLR-148.8, §1.2 | The real-directory guard changes the shared chip app-wide; "family root" undefined for non-project families | Declare app-wide scope; census other chips; define roots | open → P1 |
| A2-11 | architect | minor | LLR-144.10 | "≥1 member per group" cannot hold with the JSON tab active | Guard per tab state | open → P1 |
| A2-12 | architect | minor | LLR-147.4, AT-B97-22, IFC | Mis-citation (P-31); consumer errors | Correct | open → P1 |
| A2-13 | architect | minor | IFC JSON-tab flows | One node, two owners | One owner | open → P1 |
| A2-14 | architect | minor | LLR-144.8 | Hex strip vs shipped `#patch_before_after_card`: reuse or replace unstated | Decide | PDR |
| A2-15 | architect | minor | whole file | 178,620 bytes vs 54k budget; normative text ~12% | Move §2.7 evidence, IFC, executed-verification text, id literals to appendices/companion files (check V26/V42 readers first) | open → P1 (hygiene) |
| S2-1 | security | minor | LLR-148.8 | Reparse check covers only the leaf (executed: project dir as junction passes) | Reuse `workspace._path_traverses_reparse_point`; keep `is_dir()`; define roots; junction-project TC arm | open → P1 |
| S2-2 | security | major | `variant_execution_service.py:273`; `flow_persistence_service.py:903-905, 1150-1162` | NUL in a flow ref, chain-set input/template or manifest entry crashes the app (executed) | New LLR under HLR-146: refused with a finding, 0 uncaught exceptions; NUL arms in AT-B97-08/-11 + set load; fix in the Flow Builder increment | open → P1 |
| S2-3 | security | minor | LLR-146.8/147.6, TC-B97-20/26 | `output_path` never exercised; TC text vs fixture table disagree | Slash-free payload arm; align | open → P1 |
| S2-4 | security | minor | LLR-145.6; PDR item 2 | Check Editor JSON tab uncapped; capped view must never be a parse source | Cap or state bound; display-only TC | open → P1 |
| U2-1 | ux | major | LLR-145.3, 149.4 | First-segment + tail cannot distinguish names below ~28 cells; the Fields line has ~17–20 | Geometry clause (≥28 name cells at 118) or another discriminator at PDR | open → P1 |
| U2-2 | ux | major | LLR-148.7, TC-B97-33 | Renderer glyph harvest unbounded; Execution legend ~130 cells cannot fit one line at 118 | Closed vocabulary constant per renderer; painted ⊆ vocab ⊆ legend; two legend lines or kinds to help | open → P1 |
| U2-3 | ux | major | LLR-147.3, AT-B97-20 | Auto-focusing Confirm lets a key repeat attest human work | Scroll + highlight, no focus move; scoped confirm key named in the REQUIRED line and help | open → P1 + operator |
| U2-4 | ux | major | LLR-147.3, 147.1, 149.4 | Lane wider than viewport (6 blocks at 118) has no defined behaviour; Confirm at the right end | State lane overflow; waiting card + Confirm inside the viewport on both axes | open → P1 |
| U2-5 | ux | major | §1.3, LLR-149.5, TC-B97-38 | Painted extent over a bordered region always reads 0 void | Content region minus border/padding; RED arm with fixed 24-cell cards at 220 | open → P1 |
| U2-6 | ux | major | §1.3, LLR-147.7 | Waiting-human list omits the REQUIRED line and the run-log `□` (amber in the approved capture) | Add both | open → P1 |
| U2-7 | ux | major | TC-B97-41/45/51/56 | No completeness check of the focus chain; enter/space only for chips | Every displayed interactive control in the chain; enter arm per button group | open → P1 |
| U2-8 | ux | minor | LLR-146.5, 144.11 | Selected-kind fill vs primary fill | Separate selection fill; arm | open → P1 / PDR |
| U2-9 | ux | minor | AT-B97-18, LLR-145.8 | Include by keyboard has no LLR | `space` on a row toggles include | open → P1 |
| U2-10 | ux | minor | LLR-148.6 | Inputs and selects missing from help coverage | Add | open → P1 |
| U2-11 | ux | minor | lanes / header | `✓` and `▼` carry two meanings | One meaning per glyph | PDR |
| U2-12 | ux | minor | LLR-146.4 | EXT-STEP instruction has no truncation class | Head-kept | open → P1 |
| U2-13 | ux | minor | keyboard LLRs | Focus visibility on one-row chips unstated | Focused spans differ | open → P1 |
| U2-14 | ux | minor | §2.6, PDR 13 | UI-thread run freeze undeclared | Declare OUT with the measured duration or require a worker | open → P1 |
| U2-15 | ux | minor | LLR-145.7 | `Size` label vs `Fmt` column | One term | carried → P3 |
| U2-16 | ux | minor | LLR-147.7 | Grey/white hue undefined in the distance check | Exclude saturation < 0.15 | open → P1 |

### Evidence checklists (round 2)

**architect** — constraints ✓ · alternatives ✓ (3 PDR items are gaps: A2-4, A2-5) · n/a ✓ · recommendation tied ✗ (A2-2, A2-3) · risks ✓ (missing: app-wide chip change A2-10) · cost n/a · diagram n/a · re-open ✓ · two-layer ✗ (A2-6, A2-1) · shall/should ✓ · IFC ✗ (A2-12, A2-13) · 30 new claims spot-verified, 28 match.

**qa-reviewer** — GWT shape ✓ (24/24 rows) · explicit expected ✗ (Q2-4, Q2-7) · edge cases ✓ · regression checklist ✗ (Q2-5) · exit criteria ✓ · no PII ✓ · mode plan ✓ · results planned ✓ · Layer B through surface ✗ (Q2-1) · reachability ✗ (Q2-6) · no unfilled template ✓. 10 thresholds re-measured, 9 match (P-35 command, Q2-10).

**security-reviewer** — what/where/why/fix ✓ · severity ✓ · no secrets ✓ · verdict explicit (BLOCK-UNTIL S2-2, LOW) ✓ · opener surface scoped ✓. Executed: junction probes (leaf, project-dir junction, dangling), two NUL `ValueError` reproductions.

**ux-reviewer** — role file ✓ · read-only ✓ · captures inspected ✓ · executed hue math + truncation simulation over the 75 tags ✓ · walkthrough not driven (no implementation) ✗ · ISO 9241-210: expert inspection performed, automated walkthrough owed at P4, user evaluation not performed.

---

## Round 3 — contract at `b8feb8a` (after `LED-2026-10-19-batch-97.3`)

### ✅ Verdict (round 3)

- **Gate:** `iterate-to-refine` → Phase 1 forced by blocker Q3-1. Lenses: architect `iterate-to-refine` (0/3/5), qa `iterate-to-refine` (1/5/3), security **`approve`** (0/0/3, risk LOW, 0 HIGH), ux `iterate-to-refine` (0/3/4).
- **Round-2 resolution:** every round-2 qa item resolved (Q2-1..Q2-10, most executed); architect 13 resolved · 2 partially (A2-7, A2-15); security S2-2, S2-3, S2-4, Q2-6 resolved, S2-1 partially; ux 11 resolved · 3 partially (U2-3, U2-4, U2-7) · 2 accepted/carried.
- **New findings:** 1 blocker · 11 major · 15 minor. None reopens an operator decision.
- **Convergence:** round 1 = 1 blocker / 33 major; round 2 = 1 / 17; round 3 = 1 / 11. Every round-3 finding is a bounded edit to one clause, one TC or one AT row.
- **Iteration cap:** returning to P1 makes P1's third iteration — the soft cap (`stations/shared-batch.md` §Iteration cap). Stopped and surfaced to the operator before continuing.

### New findings (round 3)

| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| Q3-1 | qa | blocker | AT-B97-23, LLR-148.9 | The "run raises" arm cannot be built through the surface once LLR-146.14 removes the NUL raise (executed: NUL rebind raises at `variant_execution_service.py:273` on HEAD; a `reports` file is swallowed) | Keep the raise arm white-box (TC-B97-58/55); in the AT use NUL pasted into the rebind input → Bind → Run, expecting one English refusal naming `MANIFEST-PATH-ESCAPE`, 0 tracebacks | open → P1 |
| Q3-2 | qa | major | AT-B97-22, LLR-147.2 | Rebind takes effect only on `#fx_bind_<i>_<j>`, which no LLR places (executed: outputs identical without Bind); RED arm not among the assertions | Place Bind in the SOURCE card + focus chain, press it in the driver; honest RED arm | open → P1 |
| Q3-3 | qa | major | AT-B97-19 | Passes on `main` (executed keys-only) | Assert what the change adds: a kind chip new on main by `enter`, `flow_scope` absent from the chain, English banner | open → P1 |
| Q3-4 | qa | major | LLR-148.6 / TC-B97-32 / AT-B97-14 | Help coverage collected from one displayed state; guards fillable by bindings/glyphs | Union over the driven states or composed controls; guards on controls only | open → P1 |
| Q3-5 | qa | major | LLR-144.12 / TC-B97-60 | Requires non-focusable Statics in the focus chain (same as A3-3) | "each displayed focusable control" | open → P1 |
| Q3-6 | qa | major | AT-B97-23 / TC-B97-58 | Read-only-dir write succeeds on Windows (executed) | Directory collision at the target or a read-only existing file (`PermissionError`, executed) | open → P1 |
| Q3-7 | qa | minor | AT-B97-09, LLR-147.3 | Attention observed as a CSS class | Observe painted style | open → P1 |
| Q3-8 | qa | minor | AT-B97-24, TC-B97-59 | `scroll_to_widget` is not a shipped control | `tab` / `pagedown` / wheel | open → P1 |
| Q3-9 | qa | minor | LLR-144.12, 145.10 | Control tables hand-listed, no completeness guard (complete today) | Frozen-literal ⊆ table guard | open → P1 |
| A3-1 | architect | major | HLR-144, LLR-144.6, IFC, TC-B97-06, AT-B97-02 | Stamp refreshes only on document writers; Save (`mark_saved`) and paste-buffer typing change the dirty flag without a document change → stale `saved`/`unsaved` (operator decision 4 unmet) | Trigger on the dirty-flag writers (P-48); Save and typing arms; SOURCE node | open → P1 |
| A3-2 | architect | major | §1.3, HLR-149, LLR-149.2 vs 147.12 | Overflow predicate counts correctly scrolled cards (executed: unclipped regions inside `HorizontalScroll`) | Measure the clipped region; keep a non-scrolling RED arm | open → P1 |
| A3-3 | architect | major | LLR-144.12, 145.10, TC-B97-60/61 | Same as Q3-5 for both editors | Restrict to focusable controls; split tables into controls / read-outs | open → P1 |
| A3-4 | architect | minor | HLR-144, HLR-147, LLR-147.13, 148.10 | Compound EARS residue | One trigger per sentence | open → P1 |
| A3-5 | architect | minor | HLR-146 vs LLR-146.14 | "refuse" vs "skip" for manifest entries | Align | open → P1 |
| A3-6 | architect | minor | §3 preamble vs HLR-148 | `SeamSpy` vs "no wrapped service function" | Allow the OS-boundary seam | open → P1 |
| A3-7 | architect | minor | LLR-148.8, §6.2 item 3 | Node count (11, not 6); guard order after create; create-on-press already shipped | Correct; settle item 3 | open → P1 |
| A3-8 | architect | minor | whole file | 169,152 bytes | Hygiene | open → P1 (hygiene) |
| S3-1 | security | minor | LLR-148.8 | Project-junction arm walks an unresolved path the app never holds (`app.py:8200` resolves) | Walk unresolved workarea projects, or declare the resolved dir the trust anchor | open → P1 |
| S3-2 | security | minor | LLR-146.14 | "Path-bearing field" undefined; `stat()` still catches only `OSError` (`:903-906`, `:1463-1471`) | Enumerate fields; widen to `(OSError, ValueError)` | open → P1 |
| S3-3 | security | minor | LLR-147.13 | `c` confirms the first waiting lane, not necessarily the one looked at | Name the lane in the status line; scope `c` to a focused lane | open → P1 (overlaps U3-1) |
| U3-1 | ux | major | LLR-147.13, AT-B97-20, TC-B97-64 | `c` repeated confirms two waiting lanes / a re-wait | `c` only on the attention lane, once per waiting entry, attention moves after paint + minimum time; arms | open → P1 |
| U3-2 | ux | major | §4 preamble (b), TC-B97-41/45/51/56 | Focus-chain completeness is circular (`focus_chain` is built from the same set) | Reference set by type and id, independent of `can_focus`; mutation on all four screens | open → P1 |
| U3-3 | ux | major | LLR-147.12, 147.11, TC-B97-63 | Horizontal lane scroll has no keyboard path; `#fx_lanes_scroll` not in the order | Name it in the lanes group; `tab` + `right` arm | open → P1 |
| U3-4 | ux | minor | LLR-145.3 | Fields name at 24 clips M/C class; full name shown nowhere at 118; not adaptive at 220 | Full-name line for the highlighted row; Fields name adaptive; risk row | open → P1 |
| U3-5 | ux | minor | LLR-147.3, AT-B97-20 | REQUIRED line names no lane; `c` in a rebind input; scroll hides the focused input; stray `enter` re-runs | Name the chain; assert run count; decide stray-enter behaviour | open → P1 |
| U3-6 | ux | minor | LLR-147.12, US-137 | Overflowed lane gives no at-a-glance status | Lane-header worst-status mark or overflow mark | open → P1 |
| U3-7 | ux | minor | §1.3 selection style | Focused vs selected not required distinct | Three distinct states | open → P1 |

---

## Scoped verification — contract at `217e699` + fold `LED-2026-10-19-batch-97.5` (operator's cap ruling: each lens checks only its own round-3 rows)

### ✅ Verdict (final P2)

- **Gate:** `approve` → PDR. Every blocker and major row of round 3 is closed; all four lenses returned `approve`.
- **architect** — A3-1, A3-2 (probe re-run: clipped-region predicate scroll 0 / no-scroll 4; HEAD 7/2/1/1), A3-3..A3-7 closed; A3-8 (size, 190,495 bytes) left open as hygiene under the operator's no-restructure ruling.
- **qa-reviewer** — Q3-1 (executed: `nul_bind` RED on HEAD with `ValueError` at `variant_execution_service.py:273`), Q3-2 (executed: Bind pressed vs not), Q3-3 (executed: three assertions RED on main), Q3-4, Q3-5 (executed column typing), Q3-6 (executed `PermissionError` at the staging path), Q3-7..Q3-9 (executed subset guard) closed.
- **security-reviewer** — S3-1..S3-3 closed; `permission` scan flag answer adequate; risk LOW, 0 HIGH. S2-2's `stat()` widening is owed RED → GREEN at the Flow Builder increment gate.
- **ux-reviewer** — U3-2, U3-4..U3-7 closed at `217e699`; U3-1 and U3-3 not closed there (each fix contradicted its own text: the burst arms lacked the dwell wait; "every control by enter/space" covered `#fx_lanes_scroll`, which binds arrows only). The orchestrator folded both sentences as `LED-2026-10-19-batch-97.5` (one-line edits, nothing added) and the same reviewer re-checked: both closed.

### Carried to P3 / PDR (named, with owner)

| ID | What | Owner |
|----|------|-------|
| A3-8 | contract size 190,495 bytes vs 54k budget (V26 NOTICE) | P5 lessons (hygiene) |
| S2-2 / S3-2 | `stat()` handlers widened to `(OSError, ValueError)`; NUL arms RED → GREEN | Flow Builder increment |
| Q-14 | `tests/test_id_registry.py:124` file count bumped per test-adding increment | each increment |
| Q-18 | snapshot cells already `xfail(strict=False)` | Patch Editor increment |
| U2-15 | `Size` label vs `Fmt` column term | Check Editor increment |
| qa note | LLR-148.6 patch guard breakdown (19+7 vs 20+5+1) | PDR |
| ux notes | `CONFIRM_DWELL_S` silent swallow feedback; stray-`enter` extra report | PDR |
