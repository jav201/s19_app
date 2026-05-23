# Review — s19_app — 2026-05-20-batch-02

**Phase:** 2 — Cross-agent review
**Iteration:** 1
**Date:** 2026-05-20
**Source artifact under review:** [`.dev-flow/2026-05-20-batch-02/01-requirements.md`](01-requirements.md)
**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Reviewers:** `architect`, `qa-reviewer`, `security-reviewer` (parallel)

---

## Aggregate summary

| Reviewer | Blockers | Majors | Minors | Informational | Verdict |
|---|---|---|---|---|---|
| architect | 0 | 3 | 5 | 1 | pass-with-fixes |
| qa-reviewer | 0 | 6 | 6 | 0 | pass-with-fixes |
| security-reviewer | 0 | 2 | 2 | 1 | pass-with-fixes |
| **Total** | **0** | **11** | **13** | **2** | **pass-with-fixes** |

### Consolidated verdict

**pass-with-fixes (0 blockers).** All three reviewers returned `pass-with-fixes`. No blocker-severity finding was raised, so the dev-flow Phase 2 spec does not force a rollback — the batch may advance once the requirement/TC-text fixes are folded in.

One finding (**A-03**) is an *internal contradiction* in the requirements: the fixed-width pane mandates (LLR-008.1 / 009.1 / 010.1) and the 80×24-no-clip mandate (LLR-007.1 / HLR-007) are mutually unsatisfiable as written. It is rated `major`, not `blocker`, because it is a doc-only inconsistency with several valid resolutions — but it is the **highest-priority fix** and **must be closed before Phase 3 implementation begins**, since the pane layout cannot be coded against contradictory targets. See the Recommended Disposition section.

### `shall` / `should` discipline check

- ✅ **Clean.** Zero `should` found inside any HLR or LLR `Statement:` bullet. The strict normative convention in the document preamble is honored throughout Sections 3 and 4.
- ✅ No stray normative `shall` / `shall not` in informative voice (the `§2.4` issue from batch-01 iter 1 did not recur).
- ⚠️ **One borderline, no action required (A-09).** Appendix §6.2 candidate `R-TUI-029` contains the prose *"`R-TUI-003` should be marked superseded once `R-TUI-029` is accepted."* This is informative future-action text inside an appendix candidate-entry list — **not** an HLR/LLR `Statement` — so it does not violate the convention. Flagged only so it is not mistaken for a discipline breach on a future read.

---

## Architect findings

### Summary
- blockers: 0
- majors: 3
- minors: 5
- informational: 1
- one-line verdict: pass-with-fixes

### Findings

#### A-01 — Module-level freeze conflicts with the A2L Explorer restyle [major]
- **Target:** C-1 / LLR-014.1
- **Observation:** C-1 and LLR-014.1 freeze `tui/a2l.py` and `tui/mac.py` as "behaviorally untouched." But `a2l.py` is the canonical 1.4k-LOC A2L module and contains *view code* (`render_a2l_view`), and `a2l_render.py` is a thin re-export view facade around it. The A2L Explorer restyle (HLR-009 / LLR-009.1) may legitimately need to touch A2L *rendering* helpers while leaving *parse/validate* untouched. As worded, the freeze is over-broad and would block a legitimate restyle edit.
- **Why it matters:** A blanket "do not touch `a2l.py`" reading either blocks the restyle or forces an awkward workaround; the intent (freeze the *engine*, not the *view*) is not stated precisely.
- **Recommended fix:** Scope C-1 / LLR-014.1 to the **parse/validate functions** of `a2l.py` / `mac.py`, and explicitly declare `render_a2l_view` and the `a2l_render.py` facade as view-layer and re-stylable within this batch.

#### A-02 — Retired `#view_bar` and `view_*` actions not marked superseded [major]
- **Target:** HLR-013 / LLR-013.2 / §2.1
- **Observation:** §2.1 and A-7 state Direction B replaces the three-layout toggle, but the retired `#view_bar` button bar and the `view_main` / `view_alt` / `view_mac` actions are never explicitly marked *superseded*. Their disappearance is a silent gap — a Phase 4 keyboard-reachability check (TC-011) could read it as a regression.
- **Why it matters:** Without an explicit supersession note, a deliberate design decision is indistinguishable from an accidental loss of an action at the validation gate.
- **Recommended fix:** Add a note in LLR-004.4 and/or the screen-inventory table that `#view_bar` and the `view_main` / `view_alt` / `view_mac` actions are **superseded by rail items 1/2/3**, not regressions.

#### A-03 — INTERNAL CONTRADICTION: fixed pane widths vs. the 80×24 no-clip mandate [major — HIGHEST PRIORITY]
- **Target:** LLR-008.1 / LLR-009.1 / LLR-010.1 vs. LLR-007.1 (and HLR-007)
- **Observation:** The fixed-width pane mandates are mutually unsatisfiable with the 80-column minimum:
  - Rail width (handoff sketch) = **22 columns**.
  - Workspace (LLR-008.1) = rail 22 + left ranges/sections **22** + right context **40** = **84 columns of fixed chrome** *before the hex pane receives any width at all.*
  - The supported minimum (LLR-007.1, HLR-007, OQ-1) is **80×24** with an explicit "no clip / no overlap" requirement.
  - 84 > 80: the fixed widths and the 80×24 no-clip requirement **cannot both hold**. The center `1fr` hex pane would be allocated a negative remainder at 80 columns.
- **Why it matters:** This is a genuine logical contradiction inside the requirements document. An implementer cannot code a layout against two mutually exclusive targets, and a Phase 4 verdict (TC-016-S snapshot vs. TC-017 width assertions) would be unwinnable — one TC must fail by construction. This is the single fix that must land before any layout code is written.
- **Recommended fix:** Pick one resolution and bake it in:
  1. Make the side panes **proportional** (e.g. `fr`-based or percentage) below a width breakpoint, keeping fixed columns only above it; **or**
  2. **Raise the supported minimum width** above 84 columns (revising OQ-1 / HLR-007 / LLR-007.1); **or**
  3. Apply the fixed 22 / 40 column widths **only at ≥120 columns** and define an explicit **80×24 collapse behavior** (e.g. side panes collapse to a single togglable pane, or scroll).
  Whichever is chosen, LLR-007.1, LLR-008.1, LLR-009.1, LLR-010.1 and TC-016 / TC-016-S / TC-017 / TC-019 / TC-021 must be reconciled to it.

#### A-04 — Rail glyph→screen pairing is only positional [minor]
- **Target:** LLR-001.1 / LLR-001.3
- **Observation:** The eight-item rail order is fixed in LLR-001.1, and the Unicode/ASCII glyph set is fixed in LLR-001.3, but the *pairing* of a specific glyph to a specific screen is implied only by the positional order of two separate LLRs. There is no single explicit glyph→screen table.
- **Recommended fix:** Add an explicit glyph→screen mapping table (Unicode glyph + ASCII fallback per rail item) so the pairing is unambiguous and directly testable by TC-001 / TC-035.

#### A-05 — Project-name / A2L-filename status content loses its container [minor]
- **Target:** G-2 / R-TUI-016
- **Observation:** G-2 already flags that promoting the Issues table out of the Main-view Status tile (HLR-011) orphans the project-name / A2L-filename status content protected by `R-TUI-016` — and §6.1 confirms "its new home is not yet specified." The gap is acknowledged but no LLR closes it.
- **Recommended fix:** Add an LLR specifying where the project-name / A2L-filename status content renders in Direction B (e.g. in the command bar or the status/footer bar).

#### A-06 — Palette "export" command does not exist [minor]
- **Target:** LLR-003.2 / TC-007
- **Observation:** LLR-003.2 lists "export" as one of the existing actions the command palette must surface. There is no `export` action in the pre-batch `BINDINGS`; the only export-like binding is `j` → `dump_a2l_json` (and the matching `R-A2L-003`). "export" is a phantom command.
- **Recommended fix:** Replace "export" with "dump A2L JSON" in the LLR-003.2 action list (consistent with the `dump A2L JSON` wording already used in LLR-004.4).

#### A-07 — `Ctrl+K` / `Ctrl+D` behavior during command-bar input focus is unstated [minor]
- **Target:** LLR-004.5
- **Observation:** LLR-004.5 specifies that *single, unmodified* keys (`g`, `1`–`8`) are routed as text while a command-bar input holds focus. It is silent on *modified* bindings (`Ctrl+K`, `Ctrl+D`) during input focus — leaving it ambiguous whether the command palette / density toggle remain operable while the user is typing in the find or go-to input.
- **Recommended fix:** Add one informative sentence to LLR-004.5: modified-key bindings (`Ctrl+K`, `Ctrl+D`) stay active during input focus; only unmodified single keys are suppressed.

#### A-08 — "placeholder data" for the A↔B Diff screen is undefined [minor]
- **Target:** HLR-012 / LLR-012.3
- **Observation:** LLR-012.3 mandates the three-column A↔B Diff scaffold be "populated with placeholder data only" but never defines what placeholder data *is*. An implementer and a Phase 4 reviewer could disagree on whether empty panes, a single label, or sample rows satisfy it.
- **Recommended fix:** Define the placeholder concretely — e.g. static, clearly-labelled sample hex rows in each of the three columns, visibly marked as placeholder content.

#### A-09 — Appendix supersession prose is informative, not normative [informational]
- **Target:** R-TUI-029 candidate entry, §6.2
- **Observation:** §6.2 candidate `R-TUI-029` says *"`R-TUI-003` should be marked superseded once `R-TUI-029` is accepted."* This `should` is informative future-action text inside an appendix candidate-entry list — it is **not** an HLR/LLR `Statement` and therefore does **not** violate the `shall`/`should` convention.
- **Recommended fix:** None required. Recorded so the borderline `should` is not mistaken for a normative-discipline violation on a later read.

---

## QA-reviewer findings

### Summary
- blockers: 0
- majors: 6
- minors: 6
- one-line verdict: pass-with-fixes

### Findings

#### Q-01 — "three severity colors" is factually wrong [major]
- **Target:** C-6 / HLR-005 / LLR-005.1 / TC-012
- **Observation:** The document repeatedly says the theme uses "the three severity colors." This is factually wrong — `color_policy.SEVERITY_CLASS_MAP` defines **five** classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`), plus `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE`. LLR-005.1's own acceptance criteria already list all five `sev-*` classes, contradicting the "three" wording in C-6 / HLR-005. As worded, TC-012 ("count … three severity colors") could fail a *correct* implementation that defines five classes, or pass an incorrect one that silently dropped `sev-ok` / `sev-neutral`.
- **Why it matters:** A test whose expected value contradicts the source-of-truth code is wrong on its face; the verdict it produces is meaningless.
- **Recommended fix:** Replace "three severity colors" with **"the severity colors defined by `SEVERITY_CLASS_MAP`"** everywhere (C-6, HLR-005, §1.2, §1.3, §2.4, product-functions list). Restate TC-012 to assert the **five** `sev-*` class names are present and that `MAC_ADDRESS_OVERLAY_STYLE` / `FOCUS_HIGHLIGHT_STYLE` are preserved — not a literal count of three.

#### Q-02 — TC-007 spot-checks only one palette entry [major]
- **Target:** TC-007 / LLR-003.2
- **Observation:** LLR-003.2's intent is *parity*: every `BINDINGS` action has a palette entry routing to the same handler. TC-007 as written enumerates `BINDINGS` but then "select **one** entry and assert the bound handler ran" — a single spot-check that cannot verify parity. A palette missing half its entries would still pass.
- **Recommended fix:** Restate TC-007 to iterate the **full** `BINDINGS` set: assert a palette entry exists per action, and that each palette entry dispatches the **same action id** as its key binding.

#### Q-03 — TC-009 asserts `_handle_goto` is "invoked with the address" — not executable [major]
- **Target:** TC-009 / LLR-004.2
- **Observation:** `_handle_goto` (`app.py:4993`) takes **no address argument** — it reads `#goto_input` directly off the widget tree. TC-009's step "submit a valid hex address; assert `_handle_goto` invoked **with it**" describes a call signature that does not exist; the assertion is not executable as written. LLR-004.2's acceptance bullet shares the same imprecise "routes to the existing go-to handler" phrasing.
- **Recommended fix:** Restate TC-009 to assert the **observable effect** rather than the call signature: after submitting an address, the hex view is scrolled to that address and the status line reads `Goto 0x…`. Adjust LLR-004.2's acceptance bullet to match.

#### Q-04 — `1`/`2`/`3` key remap cannot be distinguished from a regression [major]
- **Target:** HLR-004 / LLR-004.4 / TC-011
- **Observation:** The `1` / `2` / `3` keys change meaning under Direction B — from the old view-toggle (`view_main` / `view_alt` / `view_mac`) to rail-item activation. TC-011 verifies *action reachability* but has no way to distinguish a *designed supersession* from an *accidental regression* of the old view actions. (Couples with A-02.)
- **Recommended fix:** Add an explicit note to LLR-004.4 — and a TC-011 assertion — that the `1` / `2` / `3` → rail-item remap is **intended supersession**, and that the underlying screens (Workspace / A2L / MAC) remain keyboard-reachable via the rail.

#### Q-05 — Input-focus suppression ignores the `+ - , .` paging keys [major]
- **Target:** LLR-004.5 / TC-008 / TC-009 / TC-029
- **Observation:** LLR-004.5 and its TC sub-cases suppress only `g` and `1`–`8` while a command-bar input holds focus. The pre-batch `BINDINGS` also include single-key paging bindings (`+`, `-`, `,`, `.`). These are unmodified single keys that would collide with typed search text — typing `,` into the find input would fire a page action. The suppression rule is incomplete.
- **Recommended fix:** Broaden LLR-004.5 to cover **all** single-key bindings (not just `g` and `1`–`8`); extend the TC-008 / TC-009 / TC-029 input-focus sub-cases to include at least one punctuation paging key (e.g. `,` or `+`).

#### Q-06 — Snapshot baseline count (~48) is never stated [major]
- **Target:** TC-016-S / §5.5 / AC-B7
- **Observation:** TC-016-S captures SVG baselines for "every Direction B screen × {compact, comfortable} × {80×24, 120×30, 160×40}." That is ~8 screens × 2 densities × 3 sizes ≈ **48 baseline files**, but the document never states the count. A 48-file snapshot diff in a PR invites rubber-stamping — reviewers cannot meaningfully inspect 48 SVGs and will tend to auto-accept.
- **Recommended fix:** State the explicit baseline count in §5.5 / TC-016-S, and **narrow the matrix**: the full {2 density × 3 size} matrix only for the 4 restyled screens (Workspace, A2L Explorer, MAC View, Issues Report); the 3 additive scaffolds (Memory Map, Patch Editor, A↔B Diff) at the **120×30 primary size only**. This cuts the baseline set to a reviewable size while keeping regression coverage where the risk is.

#### Q-07 — Pane-width assertions need a pinned terminal size [minor]
- **Target:** TC-017 / TC-019 / TC-021
- **Observation:** The pane-width assertions read `region.width` / `size.width` and compare against `22±2` / `40±2` / a `1fr` remainder. The `1fr` remainder is size-dependent, and `App.run_test()` defaults to **80×24** — at which the remainder is ill-defined (see A-03). Without a pinned test size the expected remainder value cannot be computed.
- **Recommended fix:** Pin TC-017 / TC-019 / TC-021 to **120×30**, compute the expected `1fr` remainder at that size, and cross-check the 80×24 no-clip behavior separately. (Couples with A-03 — the 80×24 case only becomes well-defined once A-03 is resolved.)

#### Q-08 — TC-028 AST guard searches for modules that do not exist [minor]
- **Target:** TC-028 / LLR-012.4
- **Observation:** TC-028 AST-walks the new screen modules and asserts they do **not** import a "CRC / patch-undo / bookmark-persistence / diff-compute / PDF-export module." Those modules do not exist anywhere in the repo, so the search can never match — the test can never fail and verifies nothing.
- **Recommended fix:** Reframe TC-028 as a **positive** guard: assert that **no new processing module** is added under `s19_app/` outside the view layer, and assert that `bincopy`, `pya2l`, and `crcmod` are absent from both the new modules' imports and from `pyproject.toml`.

#### Q-09 — TC-030 has no reference binding set to compare against [minor]
- **Target:** TC-030 / LLR-013.2
- **Observation:** TC-030 asserts the footer shows "the active screen's `show=True` bindings." But the new scaffold screens (Memory Map, Patch Editor, A↔B Diff) have **no defined binding set** — OQ-8 explicitly defers the final keymap to Phase 3 increment 1. TC-030 therefore has no reference set to compare the footer against until that increment lands.
- **Recommended fix:** Note in TC-030 that the expected per-screen `show=True` binding set is **pinned in Phase 3 increment 1** (when the implementer proposes the keymap), and TC-030's expected column is filled in at that point.

#### Q-10 — No TC guards the project-name / A2L-filename visibility after the move [minor]
- **Target:** G-2 / R-TUI-016
- **Observation:** Even once A-05 adds an LLR for the relocated project-name / A2L-filename status content, no test case verifies it stays visible after the Issues table moves out of the Status tile. `R-TUI-016` is in the no-regression list but has no TC.
- **Recommended fix:** Add a TC (or extend TC-023) that asserts the project name and A2L filename remain visible in their new Direction B home.

#### Q-11 — `inspection`-method TCs have no written checklist [minor]
- **Target:** TC-012 / TC-031 / TC-033 / §5.1
- **Observation:** §5.1 defines the `inspection` method as "static review … against a written checklist," but no such checklist exists for the inspection TCs (TC-012, TC-016, TC-031, TC-033). The pass/fail verdict is therefore reviewer-subjective. TC-031 ("classify each engine-module change as cosmetic-only or none") especially needs an explicit rubric.
- **Recommended fix:** Either embed the inspection checklists inline in each TC, or commit in §5.1 to producing them at Phase 4 start. For TC-031, add an explicit **cosmetic-only rubric**: whitespace, comments, and import-order changes are cosmetic; changes to logic, constants, or function signatures are not.

#### Q-12 — TC-013 duplicates an existing test, misses the real restyle risk [minor]
- **Target:** TC-013 / LLR-005.2
- **Observation:** TC-013 re-runs the existing `test_color_policy_round_trip.py` pattern. That test already exists and passes — re-running it adds no coverage. The real restyle risk is the **stylesheet ↔ class-name binding**: a new `.tcss` that fails to define a rule for one of the five `sev-*` classes would silently break severity coloring, and TC-013 as written would not catch it.
- **Recommended fix:** Keep the round-trip test as a no-regression anchor, and **add** an assertion that the new stylesheet defines a CSS rule for **each** of the five `sev-*` classes.

---

## Security-reviewer findings

### Summary
- blockers: 0
- majors: 2
- minors: 2
- informational: 1
- one-line verdict: pass-with-fixes

### Findings

#### S-1 — No normative `shall` pins the command-bar inputs to the validated handlers [major]
- **Target:** HLR-003 / HLR-004 / LLR-004.2 / TC-008 / TC-009
- **Observation:** The new command-bar find and go-to inputs are new input surfaces. No normative `shall` clause pins them to the **existing, already-validated** handlers (`_handle_goto`, `find_string_in_mem`). A re-wire during implementation could introduce fresh, unguarded address-parsing or string-decoding code without violating any requirement.
- **Why it matters:** The batch is explicitly "view-layer only" (C-1, C-4). New parsing/decoding logic behind the command bar would be an unscoped, unreviewed input surface — a silent expansion of the attack/defect surface.
- **Recommended fix:** Add a normative `shall` clause (in LLR-004.1 / LLR-004.2 or a new LLR) requiring that submitted command-bar text is **routed to the existing handlers**, that **no new address-parsing or string-decoding code is introduced**, and that invalid input is reported via the existing `set_status` path as it is today. Add malformed-input assertions to TC-008 / TC-009.

#### S-2 — Snapshot SVG baselines can leak proprietary client data [major]
- **Target:** §5.5 / TC-016-S / AC-B7
- **Observation:** `pytest-textual-snapshot` SVG baselines render actual screen content. If a baseline is captured against a real client firmware/A2L/MAC artifact, the committed `.svg` would embed that file's **bytes, addresses, symbol names, and MAC tags** — proprietary client data committed to the repo.
- **Why it matters:** The repo is shared/version-controlled; an SVG baseline is an easily-overlooked exfiltration channel for client IP.
- **Recommended fix:** Add a normative requirement that snapshot baselines are rendered **only** against the public synthetic fixtures (`examples/case_00_public/`, the `tests/conftest.py` generators) — **never** client artifacts. Add an inspection check (extend TC-031 or a new TC) that no committed `.svg` traces back to a non-public fixture.

#### S-3 — No constraint forbids logging typed input or rendered file content [minor]
- **Target:** HLR-003 / HLR-004 / R-TUI-015
- **Observation:** The new command bar accepts typed search / go-to / palette text, and screens render loaded file content. `R-TUI-015` keeps a rotating log under `.s19tool/logs/`. No requirement forbids the new input surfaces from logging typed text or rendered file content into that log.
- **Recommended fix:** Add a one-line clause: the command bar does **not** log typed text or file content beyond the existing `set_status` behavior, and log verbosity does not exceed the pre-batch baseline.

#### S-4 — Path containment correctly preserved [informational — confirm, no action]
- **Target:** C-1 / C-4 / A-5 / LLR-015.2 / AC-B5
- **Observation:** Verified: path containment (`resolve_input_path`, `validate_project_files`, the `.s19tool/` workarea layout) is correctly held unchanged by C-1, C-4, A-5, LLR-015.2 and AC-B5. The modal re-skin does not touch the path-handling surface. **Recorded as verified — no action required.**
- **Recommended fix:** None required. Optional hardening: add a path-traversal assertion to TC-034.

#### S-5 — `pytest-textual-snapshot` lacks a version pin; `project.toml` drift risk [minor]
- **Target:** C-2 / C-8 / R-TUI-032
- **Observation:** The dev-only optional-dependency scoping of `pytest-textual-snapshot` (under `[project.optional-dependencies]`, never under `[project] dependencies`) is correct. But no **version constraint** is specified for it, and the legacy pre-PEP-621 `project.toml` at the repo root must not drift out of sync.
- **Recommended fix:** Specify a version constraint for `pytest-textual-snapshot` (e.g. a `>=` floor consistent with the `textual` floor from OQ-13). Note explicitly that the optional-dependency block lands in `pyproject.toml` **only** — the legacy `project.toml` is not edited.

### Out-of-scope confirmation (per this app's threat model)
- **Auth / authorization:** N/A. Single-user offline desktop TUI; the document correctly omits auth controls.
- **Network egress / DNS / TLS:** N/A. No network surface; the batch adds none.
- **Secrets / credentials:** N/A. No keys, tokens, or `.env` are read or written.

---

## Normative `shall` / `should` discipline — result

**Clean.** No `should` appears inside any HLR or LLR `Statement:` bullet in Sections 3 and 4 — the strict IEEE 830 + EARS convention declared in the document preamble is honored. No stray normative `shall` / `shall not` was found in informative voice.

One borderline use (**A-09**) — *"`R-TUI-003` should be marked superseded …"* in the §6.2 candidate `R-TUI-029` appendix entry — is **informative appendix prose, not an HLR/LLR Statement**, and therefore does not violate the convention. No corrective action is required; it is recorded so it is not later mistaken for a discipline breach.

---

## Verdict

**pass-with-fixes (0 blockers).** All three reviewers independently returned `pass-with-fixes`. The aggregate is **0 blockers · 11 majors · 13 minors · 2 informational**. The dev-flow Phase 2 spec forces a rollback to Phase 1 only when a blocker is open; with zero blockers the batch is **not** forced back.

The 11 majors are not implementation blockers in the security/correctness sense — they are **requirement-text and test-case-text defects**: one internal contradiction (A-03), three "designed-change-vs-regression" ambiguities (A-01, A-02, Q-04), three test cases that cannot verify their stated intent (Q-01, Q-02, Q-03), one incomplete suppression rule (Q-05), one un-bounded snapshot matrix (Q-06), and two missing normative scoping clauses (S-1, S-2). Every one is closable with a focused edit to `01-requirements.md`.

**A-03 is the headline.** It is an outright logical contradiction (84 columns of fixed chrome vs. an 80-column minimum) and **must be resolved before Phase 3 implementation starts** — layout code cannot be written against two mutually exclusive targets.

---

## Recommended Disposition

The findings split cleanly into one must-fix-now item, a single cheap requirement-iteration batch, and two no-action items.

### Must fix before Phase 3 — A-03

**A-03 must be closed before any Phase 3 layout increment begins.** It is the only finding that, if left open, makes implementation impossible — the Workspace pane layout has no satisfiable specification until one of the three resolutions (proportional panes below a breakpoint / raised minimum width / fixed widths only ≥120 cols + defined 80×24 collapse) is chosen and baked into LLR-007.1 / 008.1 / 009.1 / 010.1. This is a product-owner decision (it changes the supported-size contract or the layout behavior), so it needs Javier's sign-off, not just an editorial pass. **Q-07 couples to A-03** — the 80×24 leg of the pane-width TCs only becomes well-defined once A-03 is resolved, so fix them together.

### Fix in one Phase-1 iteration — the remaining 10 majors + most minors

The other **10 majors** and the **13 minors** are inexpensive requirement/TC-text edits with no design uncertainty. They are best handled in **one focused Phase-1 iteration** alongside A-03, rather than spread across phases:

- **Majors (cheap text fixes):** A-01 (scope the freeze to parse/validate functions), A-02 + Q-04 (mark the `#view_bar` / `1`/`2`/`3` remap as intended supersession — single coupled fix), Q-01 (correct "three" → "five `sev-*` classes" everywhere + restate TC-012), Q-02 (TC-007 iterate the full `BINDINGS` set), Q-03 (TC-009 assert observable effect), Q-05 (broaden LLR-004.5 to all single-key bindings), Q-06 (state the baseline count, narrow the matrix), S-1 (add the validated-handler `shall` clause), S-2 (add the public-fixture-only snapshot requirement).
- **Minors:** A-04, A-05, A-06, A-07, A-08, Q-07, Q-08, Q-09, Q-10, Q-11, Q-12, S-3, S-5 — all one-to-few-line edits. Q-09 is partly deferred by nature (TC-030's expected binding set is pinned in Phase 3 increment 1) but the *note saying so* is added now.

Estimated effort: one Phase-1 iteration, well under an hour of editing once A-03's resolution is chosen. No agent re-spawn is required for the text edits; A-03 needs an owner decision first.

### No action required — S-4 and A-09

- **S-4** — path containment is verified correct as-is; recorded only. (The optional TC-034 path-traversal assertion may be folded in opportunistically but is not required.)
- **A-09** — the §6.2 `should` is informative appendix prose, not a normative-discipline violation; recorded only.

### Suggested sequencing

1. Product owner picks the A-03 resolution (proportional / raised-minimum / breakpoint-collapse).
2. One Phase-1 iteration applies A-03's resolution plus all 10 remaining majors and 13 minors to `01-requirements.md`.
3. Optional light re-review (text-diff check that each finding is closed); no full parallel re-review needed given 0 blockers and no design-level disagreement.
4. Advance to Phase 3.

---

*Generated by parallel review pass: `architect` + `qa-reviewer` + `security-reviewer`. Consolidated by `architect`.*

---

## Phase 2 — Iteration 2: Closure Verification

**Date:** 2026-05-20
**Re-checked after:** Phase 1 iteration 4
**Reviewers:** `architect`, `security-reviewer`, `qa-reviewer` (light closure pass)

### Result

All **24** Phase-2 iteration-1 findings (A-01..A-09, Q-01..Q-12, S-1..S-5) were re-checked after Phase 1 iteration 4 and are **CLOSED**.

| Reviewer | Closure verdict |
|---|---|
| architect | `all-closed-clean` |
| security-reviewer | `all-closed-clean` |
| qa-reviewer | `all-closed-new-issues` |

**Consolidated Phase 2 verdict: pass** — 0 blockers, 0 majors.

### New findings surfaced by the closure scan

All are minor / cosmetic — none gate-blocking.

#### CV-01 — LLR-008.1 rationale worked example rounds loose [minor]
- **Target:** LLR-008.1 rationale
- **Observation:** The 80×24 worked example in the rationale (left ~19 / right ~24) rounds slightly looser than the stated proportional values (24% / 30% of body width ≈ 18 / 23). Cosmetic rationale drift; the normative `shall` statement and tolerances are correct.

#### CV-02 — Rail-collapse regime not cross-referenced from the rail LLRs [minor]
- **Target:** LLR-001.1 / LLR-001.2
- **Observation:** The rail-collapse-to-4-cols `<120`-column regime is specified in LLR-008.1 (Workspace layout) but not cross-referenced from the rail LLRs (LLR-001.1 / 001.2). Traceability looseness, not a break — TC-016 / TC-017 do assert the collapsed rail.

#### CV-03 — No-file empty-state layout uncaptured by any snapshot baseline [minor]
- **Target:** TC-016-S / TC-037
- **Observation:** Snapshot baselines render only file-loaded public fixtures, so the no-file empty-state layout (LLR-002.3) is not captured by any snapshot baseline. LLR-002.3 is still functionally covered by TC-037; only empty-state layout *drift* is unguarded.
- **Recommended fix:** Add an optional 120×30 empty-state baseline, or add an explicit note that empty-state layout is functionally-covered only.

#### CV-04 — Proportional layout regime exercised at a single `<120` size [minor]
- **Target:** TC-016 / TC-017
- **Observation:** The proportional layout regime is exercised at a single `<120` size (80×24); a width-responsive bug near the 119/120 breakpoint boundary would not be caught.
- **Recommended fix:** Add a 119-column boundary check.

#### CV-05 — TC-038 / TC-039 label swap in Section 5.1 [cosmetic]
- **Target:** Section 5.1
- **Observation:** Section 5.1 lists TC-038 as an inspection-checklist-bearing TC, but TC-038 is a `test (run_test)` case and TC-039 is the inspection case — a TC-038 / TC-039 label swap.
- **Recommended fix:** One-word editorial fix to Section 5.1.

### Disposition

CV-01..CV-05 are all minor / cosmetic. Recommended: fold them into **Phase 3 increment 1** as opportunistic pickups, or formally accept as-is. **None blocks advancing to Phase 3.**
