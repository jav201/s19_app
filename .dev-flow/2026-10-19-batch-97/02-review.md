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
