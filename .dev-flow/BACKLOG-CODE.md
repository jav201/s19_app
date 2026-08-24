# s19_app — BACKLOG · LANE A: application code + its development flow

> **Canonical open-work queue for the CODE lane.** Split out of [`BACKLOG.md`](BACKLOG.md) on 2026-07-27 by operator ruling; that file is now the router and lineage archive. Scope: the s19_app application code (features, defects, Flow Builder) **and the development flow of that code** (tests, CI, repo hygiene). Engineering process, controls and skills live in [`BACKLOG-PROCESS.md`](BACKLOG-PROCESS.md) — do not add them here.
>
> **Last refresh: 2026-08-24 (batch-87 close — D-II re-author of the pilot IFC contract + IFC surface #3 `workspace_body`, CLOSED COMPLETE; second full batch under flow rev45).** `origin/main` tip at its cut = **`943e54a`** (**unchanged** — the batch rides `claude/batch-87-ifc-reauthor-surface-3`; **7 commits exist, none pushed, no PR open**, merge is an explicit post-close operator grant). **Shipped:** `D-II` **discharged** (operator-ruled re-author) — the batch-85 pilot contract re-authored **in place** under `D-87-A` with the union output **split into six** (`panel_handle`, `slots_container`, `artifact_row_set`, `unload_all_row`, `artifact_slots`, `project_row`, cardinalities re-measured at runtime); the batch-86 `screen_workspace` re-export block **forced** to follow (`LLR-87.5` — a child cannot move while its parent keeps a stale re-export under a balancing rule); **surface #3 `workspace_body` declared with 42 outputs** (11 own + 31 re-export), honest `PARENT : workspace_shell`; canon mirror `R-TUI-113` refreshed **with its not-discharged scope enumerated** + `R-TUI-114` amended + `R-TUI-115` seeded (**13 ids, one id per line**), **V22 289 → 276 of 544**, two under the ≤278 target; **UNPARSED census 2 → 1 — the `[IFC]` class is CLEARED, `[BATCHES]` survives as the negative control**. Validator `0 block · 284 notice · 15 n/a` at every gate; **0 source files** (pin empty at every gate). Gate suite (s19env, one complete 40:43 run): **2702 passed · 6 failed · 3 skipped · 21 deselected · 3 xfailed / 2714 selected**. Detail + cost n=3: `.dev-flow/2026-08-24-batch-87/05-close.md`.
>
> **✅ DONE — closed by batch-87** *(the batch-86 carry text below is left verbatim; the DONE mark lives here, not in that block)*: (a) **carry (2), `workspace_body` = next undeclared PARENT** — DECLARED, surface #3 shipped. (b) **carry (4), the canon mirror packs two ids per line** — ADOPTED: batch-87 seeded **one id per line**, and mutation arm K8 proves the read is sensitive per id (remove one id's clause → that id greps 0, the neighbour still greps 3, V22 moves **+1 exactly**). (c) **`D-II`** — discharged; `R-TUI-113` no longer says KNOWN-DEFECT, but see carry (5) below before reading that as a clean bill.
>
> **New carries from batch-87 (this lane) — 10 items, nothing dropped:**
>
> **(1) ELEVEN flaky suite node ids — ONE family, and batch-86's diagnosis of them was `n = 1` and therefore VACUOUS.** batch-86 recorded *"every one of the 6 passes in isolation on main"* from a **single** isolated run per node. Re-sampled at **N = 10** at the batch-87 gate, one of that very six **fails 4 of 10 alone**, and two nodes no prior record carries fail 4 of 10 and 1 of 10. The "order-dependent suite pollution" classification was an artifact of stopping at the first isolated pass. **The repair batch must not re-run the same check:** any node it declares fixed needs a rate at **N ≥ 10**, and ids 7 through 11 below need their **first real rate measured** before anyone claims they were only order-dependent.
>
> *Observed failing at the batch-87 gate (6), each with its measured isolated rate:*
> 1. `tests/test_tui_flow_persistence_ui.py::test_at006_report_bearing_flow_shows_report_row` — **timing race, 1 of 10**
> 2. `tests/test_tui_flow_persistence_ui.py::test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` — **timing race, 4 of 10**
> 3. `tests/test_tui_map_big.py::test_at072a_bands[size1]` — **order-dependent, 0 of 10**
> 4. `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` — **timing race, 1 of 10**
> 5. `tests/test_tui_patch_editor_v2.py::test_at_batch41_escape_cancels_changeset_json_popup` — **order-dependent, 0 of 10**
> 6. `tests/test_tui_patch_editor_v2.py::test_tc329_popup_seed_and_load_text_apply_seam` — **timing race, 4 of 10**
>
> *Pre-registered at batch-86, did NOT recur at the batch-87 gate (5) — rate **UNMEASURED**, and labelled unmeasured rather than assumed:*
> 7. `tests/test_before_after_report.py::test_at_061a_persistent_control_survives_then_writes_pair_and_clears`
> 8. `tests/test_tui_flow_persistence_ui.py::test_at006_quarantine_card_painted_and_flow_unchanged`
> 9. `tests/test_tui_legend.py::test_at023c_issues_legend_button_opens`
> 10. `tests/test_tui_patch_editor_v2.py::test_at057b_regroup_wiring_and_binding_regression`
> 11. `tests/test_tui_patch_editor_v2.py::test_at064b_json_popup_edit_confirm_cancel_and_geometry`
>
> **Root-cause direction, from the signatures rather than from a guess: a modal push / mount race.** Every failing selector observed across the gate run and the sixty isolated runs is a **modal screen widget id**, and every failure is a `NoMatches` raised at query time (the single exception raises an `AssertionError` about a binding that did not route). The **same node fails on a different selector on different runs** — node 6 above produced three distinct ones across four isolated failures. That is a test querying a child before the modal's `compose()` children are mounted, **not** cross-test state pollution: pollution would fail deterministically once the polluting neighbour ran, and would never fail a node running alone. **The suspect is the seam between pushing a modal screen and its children being mounted.** Transcripts: `.dev-flow/2026-08-24-batch-87/04-validation.md`.
>
> **(2) The bare-stem phantom-id census is WIDER than batch-86 reported: 8 authored feeders across 3 distinct phantom stems**, not 5 across 1. The Atlas id regex (`devflow-validate.py:1575`) reduces a backtick-quoted family wildcard to a bare stem with no allocation, and the Atlas then adopts that stem as an id row. Enumerated: the bare batch-87 LLR stem is fed by the batch-85 record `:500` and by the batch-87 record at `:637`, `:1273`, `:1289` and `:1314` — **four sites in that record, not three** — plus the batch-87 increment packet's own, now removed, leaving **5 pre-existing**; the bare batch-86 HLR stem and the bare batch-86 LLR stem are each fed **once**, both from the batch-86 record `:62`. All three stems are **already adopted** into `ATLAS-TRACE.md` at `:1565`, `:2384` and `:2394` — which is the observable that makes this a real corpus defect and not a typography quibble. **Not fixed at batch-87**: every feeder lives in a frozen record section that increment could not edit. **The general rule worth registering with it — a family wildcard mints a phantom every time it is written, so a family should be named in prose.** (The flow-side half of the fix — the scanner regex — is lane B; see `BACKLOG-PROCESS.md`.) Source: `.dev-flow/2026-08-24-batch-87/03-increments/increment-001.md` §6.
>
> **(3) ⚠ `R-87-2` — the re-export cost COMPOUNDS with depth, and it MUST be ruled before surface #4.** Balancing is transitive set containment, so each ancestor re-declares every id its descendants emit, and V13 greps each declared literal **once per declaration**. Measured across three levels: of the **102** stray pairs in the corpus, **40 exist only because an ancestor re-declares a descendant's address** — 4 at surface #2's lines duplicating the pilot's, 36 at surface #3's lines duplicating surface #2's. **39 % of the corpus-wide V13 census, at depth 3.** The same shape is in V14: 94 of surface #3's 139 consumer entries are re-exports of lists already declared one level down. Named remedies, neither taken unilaterally: grep each literal **once per corpus** and attribute the stray to every declaring component, or allow a **by-reference address** for a re-export (`D-87-C`, a corpus-wide convention question). **Every further surface pays this until it is ruled.** Cite: `.dev-flow/2026-08-24-batch-87/01-requirements.md` §5.6 and §6 (`R-87-2`).
>
> **(4) `R-87-3` — FIVE in-source claims about the shell's arity are FALSE, enumerated exhaustively rather than described by a category.** Measured against ten children (M-6), each site re-read at the P2 iteration: `app.py:1849` ("an 8-child `#workspace_body`") · `app.py:1880` ("the other seven screen containers") · `app.py:1902` ("the 8-screen workspace body") · `app.py:5885` (`action_show_screen`'s docstring, "hiding the other eight") · `styles.tcss:46` ("the 8-screen `#workspace_body`"). **A spec-only batch could not fix them** — batch-87 may not touch source. **Owed by the next batch that edits those files.** This is the `HLR-85.2` defect class alive on a new surface. ⚠ The first version of this survey cited `app.py:1885` — wrong by 4,000 lines, in a finding whose entire value is exactness — and missed `app.py:1902`; both found by review and re-measured per site. A **sixth** candidate was proposed by review and **REFUTED by arithmetic** (`R-87-3b`): `screens_directionb.py:3284` reads *"on all nine screens"* and is **correct** — the comment sits in `MemoryMapPanel`, mounted on `#screen_map`, and quantifies over every rail screen EXCEPT the map: ten minus one is nine. Recorded so it is not re-proposed.
>
> **(5) ⚠ The pilot's other defects are STILL OPEN — `R-TUI-113`'s refreshed status is scoped to the CONTRACT and nothing broader.** `D-II`'s scope was the contract only, and `D-87-A` bounded the edit to the record's contract/IFC sections. Standing open, enumerated at `REQUIREMENTS.md:6069` through `:6090`: (a) **`HLR-85.2` is still unsatisfiable as written** — its Statement quantifies over the whole repository (`.dev-flow/2026-08-21-batch-85/01-requirements.md:164`) while its own threshold requires *"0 edits to frozen batch records"* (`:180`), and a frozen record is a hit; catalogued as pilot defect #7, where the named remedy is **an explicit ruling that has not been made**. batch-87's §5.5 row 7 says that defect class is "not reproduced" **in the new contract** — a statement about batch-87's text, not a repair of `HLR-85.2`. (b) **`R-1` is still Open** (`.dev-flow/2026-08-21-batch-85/01-requirements.md:449`): a `styles.tcss` comment edit drifts a structural parser test, dischargeable only by **`TC-B85-07`**'s differential block parse — which matters because a `{`-in-comment corruption shifts **259 of 284** blocks while both named tests stay GREEN. (c) **batch-85 closed UNFINISHED at P5 with 0 implementation** — frozen historical fact; re-authoring the contract does not retroactively finish the batch.
>
> **(6) Surface #4 candidate: `workspace_shell`.** V12's sole surviving residual notice names it, at `.dev-flow/2026-08-24-batch-87/01-requirements.md:845` — the same V12-liveness criterion that chose surface #2 and surface #3. **Rule `R-87-2` first** (carry 3): #4 is one level higher and pays the whole subtree.
>
> **(7) `R-87-4` — `ScreenScaffold` (`s19_app/tui/screens_directionb.py:182`) is never instantiated.** Five references, all docstrings. It carries a `db-screen` construction site that never fires, which is why the **static** count of `.db-screen` construction sites disagrees with the **runtime** count by one. Registered, not fixed (surgical-change rule).
>
> **(8) `R-87-5` — `.dev-flow/design/C-54-ENCODING-RECORD.md` still asserts the pilot's stale consumer count** (pilot defect #8). Out of batch-87's contract scope; carried unchanged.
>
> **(9) `R-87-6` — the pilot's V13 NOTICE on `slots_container` names the PROVIDER (`screens_directionb.py`) as an undeclared consumer** (pilot F-2, a structural bound of a grep-based rule). It survives the re-author because the provider writes the class name **without** its leading dot for the class addresses and **with** `#loaded_slots` for the id one; the asymmetry is an accident of syntax, not a property of the rule.
>
> **(10) The V22 seeding backlog stands at 276 unreflected ids** (HLR 75 · LLR 193 · US 8 of 544), retired one tranche at a time. batch-87 seeded only its own 13 and lands two under its floor; **no id outside batch-87 was retired**, so the standing tranche obligation for the other 276 is untouched. Also still open from batch-86: **batch-51's `06-docs/traceability-matrix.md:115` dotted-range tokens** (the matrix's own cleanup; the flow-side tokenizer half landed at rev45 but carry (2) above shows a residual class still minting stems).
>
> ⚠ **Housekeeping, REPORTED as found and never swept (C-44):** another session's untracked WIP sits in the primary checkout — `build/`, `prototypes$f.png`, `prototypes/out/`, and seven `prototypes/memmap2*` files. batch-87 neither read nor wrote any of them. Fate is an operator decision, together with the stale worktree `dev-flow-68a67d`.
>
> **Earlier refresh: 2026-08-24 (batch-86 close — IFC surface #2 `screen_workspace`, CLOSED COMPLETE; first batch under flow rev42–rev44).** `origin/main` tip at its cut = **`a112eeb`** (unchanged; batch rides `claude/batch-82-lane-a-scoping`, PR #199). Shipped: the corpus's SECOND IFC record (30 outputs, pair-based census under the M-10 search-width guard, `SURFACE:` field) + canon mirror **`R-TUI-114`** in `REQUIREMENTS.md` (12 ids; V22 seeding debt 288 → **276**, one BELOW the batch-open baseline). **Headline: the pilot's `PARENT` is balanced — V12's "NOT checked" notice at batch-85 `:334` is GONE.** Gate suite (s19env, one complete 39:49 run): **2702 passed · 6 failed · 3 skipped · 21 deselected · 3 xfailed** — the 6 diagnosed by execution as PRE-EXISTING order-dependent flakiness (each passes isolated on pristine `main`; batch touched 0 source files, pin held at every gate). Detail + cost n=2: `.dev-flow/2026-08-24-batch-86/05-close.md`.
>
> **New carries from batch-86 (this lane):** (1) **6 order-dependent flaky suite nodes** — `test_at_061a_persistent_control…` (before_after_report) · `test_at006_quarantine…` + `test_at005_dirty_guard…` (flow_persistence_ui) · `test_at023c_issues_legend…` (legend; fails even in a 6-test group, passes alone — cross-test pollution) · `test_at057b_regroup…` + `test_at064b_json_popup…` (patch_editor_v2); repro transcripts referenced from batch-86 `04-validation.md`. (2) **`workspace_body` is the next undeclared PARENT** — surface #3 candidate by the same V12-liveness criterion that chose #2. (3) **batch-51's `06-docs/traceability-matrix.md:115` carries dotted-range id tokens** (zero-padded -086 LLR family) that the Atlas id-scanner adopts as phantom ids — same class as the batch-86 Inc-1 F2 finding, pre-existing. **Sibling cause found by the final PR pass (LOW): the Atlas tokenizer itself truncates suffixed ids** (a dash- or dot-suffixed AT/TC token yields a bare stem the registry does not know — 8 phantom stems measured in the derived TRACE); the fix is flow-side (the scanner regex), the carry here is that the derived index over-reports until it lands. (4) **The canon mirror packs two ids per line** (measured by M7's refuted prediction) — per-id greps stay the primary predicate; a future seeding tranche may prefer one id per line.
>
> **Earlier refresh: 2026-07-31 (batch-76 close — `R-TUI-102` IMPLEMENTED, PR [#184](https://github.com/jav201/s19_app/pull/184)).** `origin/main` tip at its cut = **`291bb76`**. **The P0 owed by batch-75 is CLOSED**: Inc-0…Inc-3 all landed (`5f60ffe` golden · `9ee848d` HLR-108 document gating · `0b51409` HLR-109 `_format_length` · `660c1b0` HLR-110 attribution), plus `REQUIREMENTS.md`, the `TC-610` amendment and the `RESERVED`→`LIVE` flip of **42 ids** (`AT-250`…`AT-264`, `TC-552`…`TC-578`). Gate suite **2482 passed / 2 skipped / 21 deselected / 3 xfailed**, 29 snapshots, exit 0; ledger reconciles EXACTLY `2428 + 27 + 19 + 8 = 2482`. **The four `R-TUI-101` wording carve-outs are DISCHARGED** — folded into the requirement text, which is where they always lived. ⚠ **A NINTH false premise, and the first from the registry lane rather than batch-75:** the note promising the reserved block *"converts to LIVE when Inc-0…Inc-3 write the nodes"* was forbidden by `TC-610`, the guard that shipped WITH it — while `G4` simultaneously required LIVE. Both limbs executed; mutually unsatisfiable. Resolved by operator ruling: `TC-610` is now *reserved-or-spent-by-its-owner*. **Three requirement amendments** (B76-A1 header exemption — the spec's own sketched fix was rejected by measurement; B76-A2 both-budgets gating; B76-A3 shares cut from the remaining budget). **21 counterfactual mutations, INERT none — and all six defects they found were in ACCEPTANCES or in the mutation HARNESS, never in shipped code.**
>
> **Earlier refresh: 2026-07-31 (D2 re-triage — no batch).** `origin/main` tip = **`038dfd9`**. **D2 dropped MAJOR -> P3 (hardening)** on re-executed measurement: `ChangeSummaryEntry`/`CheckRunEntry` are constructed at **exactly two sites** (`changes/apply.py:342`, `changes/check.py:379`), both from `entry.addressed_range`, so `Length == len(encoded_bytes) <= MF_RUN_LENGTH_CEILING` -> **7 decimal digits vs a 4300 limit**; it is unreachable through any shipped path. **Recommendation is to KEEP it inside the `R-TUI-102` implementation anyway** (ATs already gated in revision 2) - the re-triage changes the counting, not the plan. No other item moved.
>
> **Earlier refresh: 2026-07-31 (AT/TC registry Lane A close — registry file + G1–G7 guard, `/fast-dev-flow`, PR [#181](https://github.com/jav201/s19_app/pull/181)).** `origin/main` tip at its cut = **`232eb0a`**; **rebased onto `1984341` (batch-75) before merge**. Shipped `AT-TC-REGISTRY.jsonl` (**1 370 rows**) + `tests/test_id_registry.py` (**G1–G7**, no `slow` marker) + `tools/id_registry.py` (the tokenizer library **shared** by seeder and guard). high-water **AT-281 / TC-610**; `next_free` **AT-282 / TC-611**. ⚠️ **The reservation mechanism was exercised for real, not hypothetically:** this batch seeded `AT-250…279` + `TC-552…599` as `RESERVED` for batch-75 while batch-75 was in flight, and batch-75 then minted **exactly inside that block** (max `AT-279` / `TC-599`). Because it is SPEC-ONLY those ids stay `RESERVED` — they convert to `LIVE` when its Inc-0…Inc-3 write the nodes. **Three of the item's queued premises were imprecise and the corpus corrected them** (phantoms are **24**, not 11 — the spec's pattern discarded suffixes; the §6.2 residue is **5**, not 73 — form-3 binding IS derivable; `TC-319` was **removed, not renamed**, but C-26's evidentiary basis survives under `AT-063c`). Gate suite **2428 passed / 2 skipped / 21 deselected / 3 xfailed**, 29 snapshots, exit 0 — run twice. ⚠️ **Neither lane half closes the item** (router Amendment A), and marking **C-3** + the batch-62 "16 of 23" carry closed is **owed in `BACKLOG-PROCESS.md`**, the Lane B file this batch was scoped out of.
>
> **Earlier refresh: 2026-07-31 (batch-75 close — SPEC ONLY, `R-TUI-102`).** `origin/main` tip at its cut = **`232eb0a`**. batch-75 shipped its **requirements only** by operator ruling mid-batch; Inc-0…Inc-3 are **owed** and registered as a P0 above. Phase 2 **BLOCKED** on 4 blockers — two of them in clauses batch-75 itself authored, one the house vacuous-fixture defect — and the spec was re-gated as **revision 2**. **Three false premises were executed and killed, two of them originating INSIDE the batch** (a review lane's wire-reachability claim; the batch's own `_hexdump_section` exemption). **The `R-TUI-101` wording carve-outs are declared STILL OPEN, not discharged** (batch-75 never edited `REQUIREMENTS.md`). New Lane-B carry: re-stamp `FLOW-VERSION.md` for the 641-line `dev-flow-lessons/SKILL.md`.
>
> **Earlier refresh: 2026-07-31 (batch-73 close — `_first_intersecting_symbol` soundness, `/fast-dev-flow`).** `origin/main` tip at its cut = **`d81cb3d`** (PRs #168 + #169 merged after the audit line below was written, which is why that line's `6524afd` is stale). Closed the MAJOR linkage-probe defect under "New defects found in passing at batch-65" and **corrected three things that bullet had wrong** (wrong function named; the recommended in-repo fix pattern loses the symbol; the defect also reaches MAC aliases, not just A2L). Amended **`R-CHG-002`** (Amendment A) and added `AT-220`..`AT-223` / `TC-521`..`TC-524`. Returned **two P3 carries** (the rejected innermost-attribution arm; a stale `.fast-dev-flow/spec.md` reported as found). ⚠️ **batch-74 runs in parallel on `report_service.py` and shares only this file** — whoever closed second rebased.
>
> **Earlier refresh: 2026-07-31 (backlog-carry audit — no batch).** `origin/main` tip = **`6524afd`**, unchanged. Registered **six deferrals that were born outside a batch** and had therefore never entered this queue (new section below); three arrived narrower than their source document once re-executed against `6524afd`. **No batch closed** — the two open PRs at the time of writing are [#168](https://github.com/jav201/s19_app/pull/168) (batch-72 vault sync, `state.json` only) and [#165](https://github.com/jav201/s19_app/pull/165) (the `tui-ci` paths-filter bullet). The *mechanism* that let the six leak is a PROCESS item and is routed to [`BACKLOG-PROCESS.md`](BACKLOG-PROCESS.md), not duplicated here.
>
> **Earlier refresh: 2026-07-30 (batch-72 close — P1 design defects: CRC Variant B + Legend two-pane, PR [#166](https://github.com/jav201/s19_app/pull/166) squash `1abda8e`).** `origin/main` tip at its cut = **`31d87d0`** (PR #164, the prototypes + scaffold); at its close = **`1abda8e`**. Closed the four 2026-07-28 operator-flagged defect bullets, **corrected line 153's false snapshot-drift premise** (executed: the CRC screen is not snapshot-captured at all), registered **`R-TUI-100`**, and returned **five** new carries — two of them requirements that did not survive measurement (the Select-height cap **withdrawn**, guard **G-2 retired**). Gate suite `2370 passed / 2 skipped / 21 deselected / 3 xfailed`, 29 snapshots, exit 0; ledger `2379 − 1 + 18 = 2396` exact.
>
> **Earlier refresh: 2026-07-29 (batch-70 close — FB-P2 multi-image + report fusion, PR #159 squash `b457ef8`).** batch-70 shipped `R-TUI-099`, marked FB-P2 DONE below, and added **three P3 carries**. Its own close-out exists because `origin/main` was left asserting a *finished* batch was mid-phase — the same stale-state defect batch-70 had to recover for batch-65 (PR #158) and the one that misled batch-70's own Phase-0 intake.
>
> **Earlier refreshes — 2026-07-28 (batch-67 close — feature slate). TWO batches closed into this lane on the same day, in this order:**
>
> 1. **batch-65** (`origin/main` `b691f21`, PR #149) — `_addendum_lines` producer bounding. `origin/main` tip at its cut = `082ada9`; shipped on `claude/batch-65-code-lane`. **Renumbered 64 → 65 mid-flight**: a parallel session's process-lane batch used the same id, merged first (#144/#145/#146) and keeps the number. Bullets below reading "batch-64 §7.x" belong to THAT batch, not this one. It closed the top D1 item and returned **seven** residuals plus **three** new/cleared items to this lane — each with its executed numbers, none as prose.
> 2. **batch-67** (PR #151) — feature slate. Cut off `73e3fb9` (the `origin/main` tip at ITS cut, before batch-65 landed), RC-1 PASS, then merged `origin/main` `b691f21` in before merging. Shipped **N4 (a+b)**, **Universal paste**, **FB-P2 dual-entry**; three items marked DONE below, two new carries added under P2. **Renumbered 66 → 67** after the parallel PROCESS-lane session was found holding `claude/batch-66-flow-backlog-routing`; its Inc-1/Inc-2 commit subjects still read "batch-66". **Zero file overlap with batch-65** — batch-65 touched `report_service`/`report_addendum`, batch-67 touched the TUI; this file was the only shared edit.
>
> 3. **batch-68** (PR #154, squash `5809822`) — N5's report half: before/after + A2B diff composition moved **off the UI thread** onto workers, with progress at their seams. Cut off `488bf5d`, RC-1 PASS. The carry's premise ("same `set_progress` pattern") was wrong — it was a total UI freeze, not a missing indicator. Closes two of N5's four carries; two remain (CRC coverage progress, A2L intra-parse granularity).
>
> ⚠ **Line numbers in this file are stale in BOTH directions after 2026-07-28.** batch-65 added ~598 lines to `report_service.py`; batch-67 added the `BandSegment` class (~60 lines) to `screens_directionb.py` above `MapRuler`. Re-derive every line number, never copy one.
>
> **RC-1 every batch:** `git fetch`; assert merge-base == `origin/main` tip; cut a fresh branch off it; per-story already-shipped grep before deriving. **Engine-frozen set OFF-LIMITS** (needs an explicit operator unfreeze, re-frozen post-merge PR-B): `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — AND the frozen TEST files (`_ENGINE_TEST_FILES`). ≤5 files/increment; every behavioral change ships a black-box `AT-NNN` shown failing pre-fix. **Standing authorization is NEVER carried across batches — ask at every kickoff.** **All changes go through ≥ `/fast-dev-flow`.**
>
> ⚠ **Every `report_service.py` line number below is as of `031ca8d`.** batch-63 added +47 lines to that module; the file measures 1730 lines at `e347079`. Re-derive line numbers, never copy them.
>

## 🆕 batch-84 close (2026-08-16) — the assembled selector, measured

**Last refresh: 2026-08-16 (batch-84 close, `/fast-dev-flow`).** `origin/main` tip at its cut =
**`1afccb0`** (PR [#196](https://github.com/jav201/s19_app/pull/196), the handoff). Branch
`claude/blind-spot-assembled-selector-c2c117`; **PR not yet opened — this flow runs no git.**
Shipped `tools/address_origin.py` + `tests/test_address_origin.py` (`AT-B84-01`..`AT-B84-07`,
21 arms, PR lane) and `bare_name_candidates()` in `tools/address_census.py`. Gate suite
**2730 passed / 2 skipped / 3 xfailed**, 29 snapshots, exit 0, 31:13 by `python -m pytest -q`, run
on the merged tree. (2725 → 2728 → 2730 as guards were added across Inc-1/Inc-3/Inc-4.)

⚠ **That total is NOT comparable to batch-83's `2684 / 21 deselected`** — the two runs used
different invocations, and a total without its command is not a measurement (handoff §4.2).

**THE RESULT, and it is a negative one:**

> **`A 14 · B 0 · C 14 · D 13 · U 0`** over the 41 candidates. **No bare-name address argument in
> the tree is assembled.** The census's `56` computed addresses is complete **with respect to this
> population** — which is the bound, not a claim about the whole tree. Re-derive with
> `python tools/address_origin.py`; do not cite this line.

**✅ DONE — closed by this batch:**

- **▸ (was P2) The assembled-selector blind spot is MEASURED and EMPTY.** `sel = f"{prefix}{suffix}"`
  and `sel = "#" + wid` escape all three of batch-83's shape-keyed nets — **re-executed at this
  cut, not inherited**: both give `forms=['name'] loose=0 indirect=0`, while the control
  `sel = f"#{x}"` gives `loose=1 indirect=1`, so the probe discriminates. Neither form occurs.
  The escape is now **positively detected** rather than merely declared absent: `AT-B84-04`
  classifies all four assembly forms (f-string, `+`, `%`, `.format`) as **B** on synthetic
  fixtures, so the guard would fail the day one enters the tree. Same argument that justified
  `AT-B83-10`: a blind spot that can be cheaply detected is unwritten code, not a limit of design.
- **▸ (was P2) The 41 non-class-like bare-name arguments are CLASSIFIED, each with its evidence.**
  `A` = 14 (`_B78_RUN_ENTRY` ×12, `_B78_RUN_NOTE` ×2, all `assign->literal`, grep-resolvable).
  `C` = 14 (function or lambda parameters). `D` = 13, each with its sub-kind printed
  (`target` ×2 `[Subscript]` + ×2 `[IfExp,Subscript,call:next]`, `widget_id` `[Tuple]`,
  `note` `[call:list]`, …). `U` = 0 — every candidate binds somewhere in its own file.
- **The stale pointer to batch-83's `.fast-dev-flow/spec.md` §9**, in this file and in
  `.dev-flow/design/BLIND-SPOT-assembled-selector.md` §6. batch-84 archived that spec to
  `.fast-dev-flow/archive/2026-08-15-batch-83-address-census-spec.md`; both references now name
  the archived path, in the same commit that moved it.
- **`EXPECTED_SCANNED_TEST_FILES` 154 → 155**, MEASURED by two paths that share no code:
  `scanned_test_files()` reports 155, and an independent glob (`tests/**/*.py` minus the four
  excluded directories) agrees — 153 `test_*.py` plus `conftest.py` and `generate_large_samples.py`.

**⚠ Carries returned — nothing dropped:**

- **▸ (P2) The residue of the measurement: 27 of the 41 are unresolved at ONE HOP, and that is
  batch-82's to decide.** The 14 `C` sites take their address from a caller; the 13 `D` sites take
  it from a collection whose elements are never read. Neither is a blind spot in batch-83's sense —
  their sites ARE visible — but neither has a resolvable value either. **This is the number the
  Lane A retrofit should size itself from, and it is 27, not 56 and not 41.** The registry proposal
  (a dictionary of ids plus an existence check) is exactly what would collapse `A` + parts of `C`.
- **▸ (P2) A THIRD escape exists and the closure argument does not cover it: the
  attribute-stored selector.** The design doc §3 argues the 41 are the whole population *"because
  both escapes end as a bare-name argument"* — which proves closure over the **two named** escapes
  only. `self._sel = "#" + x; query_one(self._sel)` lands as census form `other:Attribute`: outside
  the 41, outside every shape net, and outside `address_origin` entirely. **Measured empty today** —
  the census forms table is exactly `{literal, name, fstring}`, zero `other:*` — but that emptiness
  is measured, not guarded, and nothing goes red the day one appears. **Belongs with batch-82's
  sizing.** Cheapest fix if it is wanted: assert `set(forms) <= {"literal","name","fstring"}` —
  membership, not a tree count, and it names the new form when it fails. Found by the Inc-3
  adversarial review, reproduced before being accepted.

- **▸ (P3) A value assembled inside a conditional or boolean expression is classified `D`, not
  `B`.** `sel = f"#{x}" if cond else "#y"` reports `D [IfExp]`; `kind_of_value` names the node and
  does not recurse into its branches. **Two distinct** `IfExp` bindings exist
  (`tests/test_tui_directionb.py:6809`, `tests/test_tui_patch_editor_v2.py:3103`), appearing across
  **three** row occurrences; both were read at source and neither branch is one of the four
  assembled forms — 6809's true branch is `ast.unparse(...)`, a call, so **`B 0` is unaffected**.
  *(An earlier draft of this bullet said "all three bindings … literal-or-variable" — wrong on both
  the count and the kind, caught by an adversarial pass. Re-derive, never carry.)* Now **declared**
  in the tool's own "does NOT
  resolve" list rather than left implicit. **Reopen when** recursing into branches is wanted — that
  is a design decision (how deep, and what to do with a mixed branch), not a patch.

- **▸ (P3) `match`/`case` capture patterns are not a binding form `collect_bindings` knows.**
  A candidate bound only by `case sel:` reports no binding and lands in `U`. That is loud, not
  silent — `U` is printed as its own section and `AT-B84-06` now guards that it survives the
  resolver — so the failure mode is "says it cannot resolve this", which is the acceptable
  direction. **Reopen when** a real candidate lands in `U`.

- **✅ CLOSED at Inc-3 — `+=` assembly was classified `D` instead of `B`.** `sel += name` is
  `sel = sel + name`, but the augmented branch reported the right-hand OPERAND, so the assembly was
  invisible and the forward promise (*"the guard fails the day an assembled selector enters the
  tree"*) was false for that form. Unlike `str.join`, it was **not** a declared exclusion — it was
  a gap between the approved rule and the code. The operator now decides the kind
  (`Add → concat`, `Mod → percent-format`); `AT-B84-04` gained escapes 5 and 6 and goes red under
  the reverting mutation. **No real site was affected** — zero `augassign` bindings across the 41,
  so the headline never moved.

- **✅ CLOSED at Inc-3 — `AT-B84-06`'s "never drop it" half was VACUOUS.** It was asserted against
  `classify` only, so `return [r for r in rows if r.bindings]` inside `resolve_origins` passed all
  sixteen guards: it dropped nothing, because the tree holds zero `U` rows today. **A guard that
  holds only because today's tree is empty of the case it names is not a guard.** Now covered by a
  synthetic-tree arm that builds a module with an unbound address argument and asserts the row
  survives. Found by an adversarial review, **reproduced independently before being accepted**.

- **▸ (P3) `str.join` and `str.replace` are NOT in `ASSEMBLED_KINDS`.** The approved rule named
  four forms (f-string, `+`, `%`, `.format`) and the implementation ships exactly those — no silent
  widening. **Verified harmless today:** no candidate binds to either call. **Reopen when** any
  candidate's binding is a `call:.join` or `call:.replace`, which the `D` sub-kind column prints
  by name, so the day it happens the row says so.
- **▸ (P3) The negative result depends on the walk OVER-collecting, and only one guard protects
  that.** `collect_bindings` is scope-insensitive by design: it reports a binding written in an
  unrelated function of the same file. Narrow it and every "no assembled selector found" claim
  weakens while all other guards stay green. `AT-B84-05` is the only thing that goes red.
  **Reopen when** anyone proposes scope-precise resolution — the trade must be argued, not merged.
- **▸ (P3, found in passing — NOT this batch's, reported as found)
  `.fast-dev-flow/ADR-flow-builder-tracer.md:171` points at `.fast-dev-flow/spec.md` for batch-69's
  rationale.** batch-83 archived that spec to
  `.fast-dev-flow/archive/2026-07-28-batch-69-fbp2-design-spec.md`, so the ADR now names a file
  holding a different batch's content. Pre-existing; batch-84 did not create it and did not fold it
  into its own diff. The two `.dev-flow/2026-07-28-batch-70/` references are frozen batch records
  and are left alone deliberately.
- **▸ batch-83's own remaining carries are UNCHANGED and still open in the section below** — the
  `AT-B83-06` registry conflict (P2), the producer side and `.tcss` (P3), and the four by-design
  risks with their reopening criteria. They are not duplicated here; each open item lives in
  exactly one place.

**Unblocked by this batch:** **batch-82's Lane A retrofit can now be scoped on 27 unresolved sites
with their kinds named**, instead of on a `56` known to be an incomplete lower bound. The question
the handoff left open — *"is the 56 materially wrong?"* — is answered **no**, and the sizing that
was waiting on it can proceed.

---

## 🆕 batch-83 close (2026-08-15) — the unresolvable-address detector

**Last refresh: 2026-08-15 (batch-83 close, `/fast-dev-flow`).** `origin/main` tip at its cut =
**`fbbeafc`** (PR [#194](https://github.com/jav201/s19_app/pull/194)). Shipped
`tools/address_census.py` + `tests/test_address_census.py` (`AT-B83-01`..`AT-B83-09`, 19 arms, PR
lane). Gate suite **2684 passed / 2 skipped / 21 deselected / 3 xfailed**, 29 snapshots, exit 0.

**⚠ Six defects were found DURING this batch, and two of them by nothing at all.** Four were caught
by the batch's own guards (`AT-B83-05`, `-07`, `-08`, plus code review). **Two were caught by
neither**: the candidate filter applied in one derivation pass and not the other (surfaced only by
comparing the rule's prediction of 40 against an output of 43), and `AddressSite.shape` left empty
for bare names (which would have printed `0 of 183` — a plausible number from a field nobody
filled). Both now have guards, `AT-B83-11` and `AT-B83-12`, **each shown red under its mutation
before being accepted**. Operator instruction at the Inc-3 gate: *"si esos casos pudieron burlar la
guarda hay que revisarlos"*.

**✅ DONE — closed by this batch:**

- **The stale `.fast-dev-flow/spec.md`** (batch-73 carry, P3): it held batch-69's DESIGN-ONLY spec,
  shipped by batch-70 on 2026-07-29 and never archived. Now at
  `.fast-dev-flow/archive/2026-07-28-batch-69-fbp2-design-spec.md`.
- **`EXPECTED_SCANNED_TEST_FILES` 153 → 154**, measured by `scanned_test_files()` **and**
  re-derived by an independent glob, per `TC-607`'s own instruction.

**⚠ Carries returned — nothing dropped:**

- **▸ (P2) The `AT-B83-06` conflict is registered but NOT resolved, and it is not this batch's to
  resolve.** `BACKLOG-CODE.md:118` calls the registry's blindness to batch-scoped ids a **P1
  defect**; `AT-TC-REGISTRY-SPEC.md:468` records the same blindness as **"✅ Accepted,
  deliberately … zero recorded collisions"**, and §2.3:123 says *"New work should prefer these"*.
  Both citations verified exact by an independent pass. batch-83 followed the spec. **Whoever owns
  that P1 must close it or re-word it** — right now the project asserts both.

- **✅ CLOSED at Inc-3 — the false positives in the derived set.** Resolved by **three rules, each
  a rule and not a list of names**: a selector parameter must be *annotated* as accepting `str`;
  *private* methods are excluded; *reactive hooks* (`watch_`/`validate_`/`compute_`) are excluded.
  Measured: **48 → 40** entries, and **not one of the 8 removed is called anywhere in s19_app**.
  The six that were a hand-maintained list survive all three.

- **✅ CLOSED at Inc-3 — the one-hop indirection blind spot.** `sel = f"#{x}"` then
  `query_one(sel)` is now DETECTED (`AT-B83-10`, `find_indirect_addresses`), not merely declared.
  A blind spot that can be cheaply detected is unwritten code, not a limit of the design.
  Measured today: **0 sites** — the value is that the day one appears, it is visible.

- **✅ CLOSED by batch-84 (2026-08-16) — the assembled selector with no selector shape.**
  `sel = f"{prefix}{suffix}"` matches no selector pattern *and* sits in no address argument, so it
  escapes **both** nets — including the one-hop detector, which keys on selector shape. **Now
  measured: zero occurrences**, and the escape is positively detected by `AT-B84-04` rather than
  declared absent. See the batch-84 section above.

- **✅ CLOSED at Inc-3 — the gating decision now has a written trigger.** *A surface's computed
  addresses become BLOCKING on the day that surface's IFC is written* (spec §8b), per-surface,
  owned by the batch that writes that IFC. Same staging `C-54` chose for `V13`. It was a deferred
  decision with no owner; now it has a condition and an owner.

- **✅ CLOSED by batch-84 (2026-08-16) — 41 of 183 bare-name address arguments are NOT class-like**
  (`selector` ×8, `_B78_RUN_ENTRY` ×12, `select_id`, `widget_id`, `container_id`, `layout_id`).
  Measured by `tools/address_census.py`; the census reports the split but follows no dataflow
  (zero hops, declared). **`tools/address_origin.py` now follows that one hop and classifies all
  41** — `A 14 · B 0 · C 14 · D 13 · U 0`. The retrofit's real population is the **27** `C`+`D`
  sites, carried forward as a P2 in the batch-84 section above.

- **▸ (P3) Out of scope and stated: the producer side and `.tcss`.** `id=f"log_line_{i}"` at widget
  construction, and `add_class`/`set_classes`, are addresses nobody greps and this census does not
  see. Neither does it read stylesheets.

- **▸ (P3) By-design risks, with their reopening criteria, live in
  `.fast-dev-flow/archive/2026-08-15-batch-83-address-census-spec.md` §9** (that spec was archived
  by batch-84; `.fast-dev-flow/spec.md` now holds batch-84's).
  Four of them (guards fail on a Textual bump; the 18 s derivation cost; the three exclusion rules;
  the taint's unbounded false positives). **Each carries a "reopen when" condition** — a by-design
  risk nobody can quote when its scenario fires is not documented, it is buried. Cite §9, not the
  docstrings.

**Unblocked by this batch:** **batch-82's Lane A retrofit can size itself from a command**
(`python tools/address_census.py`) instead of from a figure pasted in a document — which is the
defect this project has now found seven times.

---

## 🆕 Carries returned by batch-79 (2026-08-07, Lane 1 — command-bar deletion)

Registered mid-batch at operator instruction rather than at the close, so they survive a session
boundary. batch-79 status **as of 2026-08-12**: Inc-6…Inc-11 shipped **including `HLR-121`'s three
acceptances and the merge-gate response**; **Inc-12 owed** (the 29-golden snapshot regen, canonical
CI only, its own PR).

- **▸ (P2) `#status_text` silently drops most of a routine load message at 80×24 — batch-79's eighth merge gate, NON-BLOCKING.**
  Measured with ordinary names and the real `_format_coexistence_status` output:

  ```
  BASE 829adc6 @80x24:  |Loaded brake_ecu_app_v12.s19 (S19+MAC: brake_ecu_app_v|   ~76 cols
  HEAD         @80x24:  |Loaded brake_ecu_app_v12.s19 (S19+MAC:|                   38 cols, NO ellipsis
  ```

  **Not blocked, and the reason is load-bearing:** `app.py:9681-9683` sends the *same string* to
  `set_file_status` **and** `_append_log_line`, and the gate verified the log tail two rows below
  carries it in full at 80×24. **Nothing leaves the screen** — it is a legibility regression, not an
  information loss.

  Two related findings, same site:
  - **The stylesheet's stated mechanism does not hold.** `#status_text`'s comment claims *"`1fr` +
    ellipsis makes the transient MESSAGE truncate"*. Executed: `text-overflow: ellipsis` fires only
    when the text has **no wrap point**. Every real coexistence message contains spaces, so the Label
    wraps and rows 2+ are clipped by `#status_line { height: 1 }` — loss with **no ellipsis**. Only an
    unbroken-token probe produced `…`. *A CSS property named in a comment is not evidence it fires.*
  - **No separator between the two cells at 80×24**, so the strip reads as one run-on string.
  - **Nothing asserts the status MESSAGE survives the new sizing.** `AT-B78-08/11` uses a realistic
    message but observes only `#status_context` and the bar height. This gap is why the regression
    reached the gate.

- **▸ (P3) `AT-B78-28` clause 1 asserts the affordance against the RENDERABLE, not the painted strip — batch-79 gate 8, NON-BLOCKING.**
  Measured: the affordance is present in `_b78_run_list_text` at every size but **truncated in the
  painted strip at every regime** — `Keys: Up/Down move the ` at wide (list 26 cols, constant 32).
  `Up`/`Down` stay readable so the requirement is met **in substance**, but this is the exact
  `render()`-vs-painted distinction the batch spent several gates establishing elsewhere, **applied
  inconsistently here**.

- **▸ (P3) Three defects in `TC-B79-05`'s own record — batch-79 gate 8, NON-BLOCKING.**
  - Its docstring pairs **two figures computed under different definitions of the same word**: *"276
    real members against 783 admitted"*. `276` is the class-body-only count; the shipped resolver's
    own count is **337**, because it deliberately includes `self.X` — as the paragraph directly above
    it explains. The honest ratio is **770/337 ≈ 2.3×**, not 783/276 ≈ 2.8×. *Neither figure names its
    commit or its definition.* Same shape as the `F-8` instances the node exists to guard against.
  - It reads `Path("s19_app/tui/app.py")` — **relative**; the only new node with a cwd dependency.
    Fails loudly off-root, so not vacuous.
  - `_CONTEXT_BAR_INSET = 4` is exact at 80/120/160 and **wrong below**: at 20 columns the real inset
    is 6, so the composer budgets 11 against a 9-column cell. Outside the supported set, and
    `TC-B79-02` correctly asserts only the three supported sizes. Related to the carried `N-7`.

- **▸ ✅ (P1 — SHIPPED 2026-08-24 as flow rev42–rev44 + adoption `875cef0`/`0d26e5d`) The HUMAN
  consolidated view of the Information Flow Contract. Operator ruling 2026-08-21.**
  **Delivered:** `--atlas --write` derives `ATLAS-IFC/TRACE/BATCHES/ORPHANS.md` into
  `.dev-flow/_derived/`, guarded by `V20` (digest, both directions, UNPARSED-census rise);
  D-III ruled as the declared selector taxonomy; D-VII hybrid ruled (Atlas derived / canon
  authored + coherence rules `V21`–`V23`). Design record: `.dev-flow/design/ATLAS-FIELD-SET-2026-08-23.md`
  + `CANON-CORPUS-AND-COHERENCE-2026-08-23.md`. Original charter text kept below for the record. The IFC **is** a consolidated view — *for the
  machine*. `_ifc_corpus` merges all 61 `01-requirements.md` at validation time, and that is the canon:
  **it is not to be moved or touched.** What does not exist is the view a *human* reads. Operator:
  *"el IFC es el consolidado para la máquina, tampoco creo que debamos tocarlo, si no más bien debemos
  tener el consolidado para humanos también"*.

  **The measured problem (batch-85 `F-9`, surfaced by an operator question, not by a guard):** after 27
  surfaces the contract lives in **27 batch folders, unified only in memory**. No document exists that a
  person can read to learn how the application is addressed — the reader must assemble a jigsaw.
  Formally C-50 holds (*one home per artifact*), but only by making the home a **corpus** rather than a
  file, which is not what a reader means by "one home".

  **The design invariant, and it is the whole of the decision:** the human view is **DERIVED BY COMMAND
  FROM THE CORPUS, NEVER MAINTAINED BY HAND.** Same relationship `skills/dev-flow/` already has to the
  manifest table via `--sync-bundle` — **a derived artifact is a build output, not a second home**, so
  C-50 is satisfied without an exception. A hand-maintained consolidation would reproduce, at project
  scale, exactly the stale-consumer-list defect this whole programme exists to close.

  **Hard constraint — do not design around it:** `_ifc_corpus` reads **only**
  `.dev-flow/**/01-requirements.md`. Move a record into a standing document and `V10`–`V14` return to
  `SKIP`. That is the blocker that closed the fast-lane spec, one level up.

  **Open decisions, enumerated as decisions rather than prose:** one document or a set? · does it cover
  only the IFC, or requirements + HLR/LLR + test cases + validation as the operator's brief describes? ·
  how do **batch tags, past revisions and checklists** render, since those are the seams that make
  completeness auditable (*"la evidencia de que el tejido está completo, no hay huecos"*) ? · which
  command derives it and in which phase does it run? · how does it relate to `REQUIREMENTS.md`, which is
  already this project's standing consolidated spec at 6,074 lines?

  **Why BEFORE surface #2:** it is a **one-way door**. 26 records authored in the wrong shape is the cost
  of deciding it late.

  ⚠️ **C-45 PUSH obligation attached.** Designed here, in the programme where the need is felt — which
  is the same path `C-54` itself took (discovered in batch-79, encoded to the flow at `rev33`). But the
  portable half **owes an upstream push once proven**, or every project running this flow re-learns it at
  full price. Register the Lane B half in `BACKLOG-PROCESS.md` at that point, not before.

- **▸ 🛑 (P1 — BATCH-82 CHARTER) Author the Information Flow Contract for s19's surfaces — the FULL retrofit. LANE A HALF.**
  ⚠️ **Cross-lane item, split per Amendment A.** The **control** (`C-54`: the global flow, template,
  validator rules, propagation) is the Lane B half in
  [`BACKLOG-PROCESS.md`](BACKLOG-PROCESS.md). **Neither half is complete alone.** Design:
  [`design/C-54-information-flow-contract.md`](design/C-54-information-flow-contract.md).

  **Operator ruling 2026-08-13 — the FULL retrofit, overruling the design's own proposal**, and the
  reason changes what the work IS:

  > *"Aunque me duela, si tenemos que hacer el retrofit… parece que hay mucho potencial para
  > requerimientos ambiguos y comportamientos perfilados a medias."*

  **The deliverable is the FINDINGS, not the file.** Authoring an `address` and a `consumers` list for
  a surface that has never declared one forces the question *"who depends on this, and how do they
  reach it?"* onto ~40 surfaces that have never been asked it. `LLR-120.2` is one instance of that
  question going unasked — found by accident, at the cost of a production regression and eight merge
  gates. **This retrofit is the systematic version of the same search**, and every ambiguity it
  surfaces is the point rather than a side effect.

  **Scope:** 10 screens (`SCREEN_CONTAINER_IDS`) + their panels/views. Part A (flow) for all; Part B
  (boundary decomposition) wherever a consumer addresses a component independently — which, in a TUI
  selected by `query()`, is nearly everywhere.

  **Staged so it cannot block the queue:** the control ships enforcing **NEW and MODIFIED surfaces
  only** (`V13` as NOTICE). Existing surfaces stay NOTICE until their screen's stage lands, then
  BLOCK. A large retrofit must not gate unrelated batches — that failure mode is why the design
  originally proposed skipping it.

  **Expected yield, stated as a prediction so it can be wrong:** ≥1 further address-vs-value
  ambiguity of the `LLR-120.2` shape, and ≥1 surface whose declared behaviour has no owning
  requirement. **If the retrofit finds neither, the control is over-priced and that finding is worth
  recording too.**

- **▸ (P1) The AT/TC registry is BLIND to all 106 batch-78/79 acceptance nodes — the id namespace sits
  outside the project's own grammar.** Found at Inc-11 when two new `TC-B79-*` nodes did **not** trip
  **G1** (*"an id on a test node that nobody registered"*). Executed, not inferred:

  ```
  _FUNC_ID_RE  test_at_b78_09_loaded_panel_names_the_project  -> NO MATCH
               test_tc_b79_01_a_long_project_cannot_evict_... -> NO MATCH
               test_tc489_candidate_consumption_is_r_indep... -> ['_tc489']   ✅
  derive_named_nodes over the corpus : 678 ids, of which B78/B79-shaped = 0
  iter_tokens("AT-B78-12") -> governed=False, conforming=False, key=None
  iter_tokens("TC-489")    -> governed=True,  conforming=True,  key='TC-489'
  test nodes named test_at_b7*/test_tc_b7* : see below      registry rows : 0
  ```

  **The node count is stated with its pattern and its commit, because the first version of this entry
  was already stale in the commit that wrote it** — it said `106`, measured at `4c5aa5d`, while the
  same commit added `TC-B79-03` and made it `107`. *A carried number is re-derived, not copied.*
  Pattern: `grep -rh "^def test_at_b7\|^def test_tc_b7" tests/*.py | wc -l` — **108** at the Inc-11
  close. Restricted to `tests/*.py` deliberately: a recursive grep also matches the 8 tracked `.pyc`
  binaries carried above, which is the same inflation that made an Inc-8 gate figure read 10 for 4.
  The figure that matters is not the count but the **0**, which no edit to the test tree changes.

  `_FUNC_ID_RE` (`tools/id_registry.py:95`) requires **digits immediately after `at`/`tc`**, so
  `at_b78_09` never parses; and because a non-conforming token is classified `governed=False`, **G3
  and G5 skip it too**. batch-78 minted an id namespace outside the grammar and every guard declines
  to police it **silently**. Same vacuous-input-set shape as the `_B78_NON_WRITING_CALLS` defect, two
  layers up: an id form the regex cannot parse is indistinguishable from one that does not exist.
  Lands on the Lane B finding already on record that **the id GRAMMAR is undefined**. **Operator
  decision owed** — extending the regex reclassifies tokens repo-wide and could redden G1/G3/G5
  across 678 existing ids, so it is its own batch. It also qualifies `AT-B78-14`: for this namespace
  the registry never had anything to reconcile.
- **▸ (P2) Eight `subprocess.run(..., text=True)` calls in the test tree decode with the HOST's
  preferred encoding, not UTF-8.** `text=True` alone uses `locale.getpreferredencoding()` — **cp1252**
  on this Windows host — so any non-cp1252 codepoint in the captured output raises
  `UnicodeDecodeError` on a subprocess reader thread, `completed.stdout` becomes `None`, and the
  calling guard dies with `AttributeError: 'NoneType' object has no attribute 'splitlines'` **instead
  of reporting what it was built to report**. A guard that cannot fail loudly fails silently-adjacent:
  the error names the wrong thing entirely.

  **Observed live at batch-79 Inc-11**, killing
  `test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` — a **binding-freeze guard**.

  ⚠️ **The cause first recorded here was FALSE, and the third merge gate caught it.** This entry
  said a CJK fixture added to `tests/test_tui_commandbar.py` put byte `0x8f` into the diff. That is
  **impossible**: the command is `git diff main -- s19_app/tui/app.py`, whose pathspec excludes
  `tests/` entirely. Re-derived on that exact diff:

  ```
  CJK present                : False
  non-ASCII codepoints       : U+00AB U+00BB U+2014 U+2026 U+26A0 U+FE0F
  U+FE0F ("️", VS16) in utf-8 : ef b8 8f   <- the cited 0x8f
  added by                   : the batch's own commit, in `on_resize`'s docstring
  ```

  The trigger was **`⚠️` in a docstring of the very file being diffed** — `U+26A0 U+FE0F`, where the
  variation selector supplies `0x8f`. At base `app.py` held 9× `U+26A0` and **0× `U+FE0F`**; this
  batch added the file's first one.

  **Two consequences.** The lesson previously recorded — *"the blast radius crossed modules through
  git"* — is false; it never left `app.py`. And the risk axis is **not** content-vs-paths but
  *"does the captured output contain any non-cp1252 codepoint"* — and `⚠️` is used liberally in this
  codebase's comments, so the axis is far easier to trip than the original note implied.

  **Fixed at the one site that decodes file CONTENT** (`encoding="utf-8", errors="replace"`; the
  guard greps for `Binding(`, pure ASCII, so `errors="replace"` cannot hide a real hit — verified
  live: 36 089 chars read, 0 replacement characters, an injected `Binding(` line still detected).
  The remaining eight emit paths, SHAs or `--stat` counts and were checked to read no file
  containing `⚠️` today — `test_engine_unchanged.py` (`--name-only`), `test_examples_smoke.py`
  (`git ls-files`), `test_tui_legend.py` ×2 (`rev-parse`, `diff --stat` on `color_policy.py`),
  `test_tui_directionb.py` (generic `["git", *args]` — **risk depends on the caller**),
  `test_a2l_f841_cleanup.py`, `test_flow_persistence.py`, `test_tui_workspace.py`. **Operator
  decision owed:** sweep all eight, or leave them knowing one `⚠️` in a newly-diffed file re-arms it.
  *A narrow patch was taken deliberately; the general control is what is registered here.*
- **▸ (P2) batch-79's increment packets for **Inc-8, Inc-9 and Inc-10 do not exist on disk**, and are
  deliberately NOT being reconstructed.** Only `increment-006.md`, `increment-007.md`,
  `increment-007-entry-gate.md`, `increment-010-entry-gate.md`, `increment-011.md` and
  `increment-011-merge-gate-response.md` were written. The commits exist (`6ed78f9`, `ae71bd6`,
  `aa1aa72`/`1154bd8`) and carry detailed messages with gates, counterfactuals and file-set
  deviations — but the flow's per-increment artifact was never produced.

  **Operator ruling 2026-08-13: leave them absent.** Writing packets now from commit messages would
  manufacture evidence of observations nobody made, which is the exact defect class this batch exists
  to avoid. The second merge gate independently judged the refusal correct.

  ⚠️ **But the gate also named the price, and it is not hypothetical.** `H-3` — a factual error about
  **Inc-9's own work**, shipped into a docstring that then contradicted a comment five lines above it
  — is the one claim a missing Inc-9 packet let through. *An increment with no packet is an increment
  whose later claims have nothing to check them against.* Registered so the cost is on the record,
  not just the decision.
- **▸ (P3) `N-7` from the batch-79 merge gate — degenerate terminal widths breach the context budget.**
  `_compose_context_line` returns the bare 5-column separator when the budget falls under the
  separator's own width (`bar_width <= 7`), and at `avail == 1` returns `"  |  …"` — the project
  evicted entirely, contradicting the method's own *"neither can evict the other"*. **Unreachable at
  the three supported terminal sizes**, which is why it was carried rather than fixed. Registered
  here because the third gate found it recorded in the increment file and **missing from this
  backlog** — a carry that lives only in a batch artifact does not survive the batch close.
- **▸ (P2) `M-4` from the batch-79 merge gate — `_apply_unload` now clears `current_a2l_path`, a
  production behaviour change outside every in-scope requirement.** Landed as an F6 fix at Inc-7. It
  reaches `save_project`, the empty-state guards and `_project_stem` — all resolved **by name**, because
  the line numbers first recorded here were already off by 3 in the commit that wrote them, shifted by
  an insertion the same commit made. Only its **display** effect is tested (`TC-B78-43`).
  Concretely: unload the A2L, then save the project — the A2L is no longer copied into the workarea.
  That is arguably correct and is **untested either way**. Owed: one acceptance on the save path, or
  a descope to its own item. **Carried by operator ruling 2026-08-12** rather than fixed under time
  pressure, because a test written hastily over an untested behaviour change is how vacuous
  acceptances get made.

- **▸ (P2) `git` tracks 8 `.pyc` files that `.gitignore` excludes.** `git ls-files '*.pyc'` returns
  **8** under `s19_app/__pycache__/`, while `.gitignore:4-5` lists `__pycache__/` and `*.pyc` — they
  were committed before the rule, and `.gitignore` does not untrack what is already tracked. They are
  **Python 3.9 / 3.10** bytecode in a project now running **3.14**, so they are stale as well as
  unwanted. **Two live costs, not just tidiness:** they show up as spurious `M` entries in
  `git status` during any test run (batch-79 Inc-7 nearly committed two), and they **inflate greps over
  `tests/`** — Inc-8's gate figure read `10` instead of `4` because six matches were binaries. Removal
  is `git rm --cached` + a commit; **operator decision owed** because it rewrites nothing but does touch
  files no batch has claimed.
- **▸ (P2) `LLR-119.2`'s numeric threshold is NOT MEASURABLE as written — §6.5 amendment owed.** It
  reads *"`len(app.log_lines)` grows by exactly 1 per key on each of the 7 screens"*. `log_lines` is a
  **`deque(maxlen=4)`** (`app.py:1445`), so its LENGTH saturates at 4 and stops growing. Executed
  against a CORRECT implementation across all seven notice screens: `map/issues/patch/diff` report a
  delta of **1**, `flow/checks/crc_designer` report **0**. A node asserting the spec's literal wording
  false-fails on whichever three screens happen to run last. batch-79 `AT-B78-05` counts the **emitted
  notices** instead (the repo's `_statuses` idiom) paired with the rendered `#log_line_4`; the spec text
  still needs the Before/After amendment.
- **▸ (P2) `TC-B78-43`'s project half — §6.5 amendment owed.** The boundary catalog reads *"unload all →
  both surfaces return to `(none)`"*. The **A2L half was right** and batch-79 fixed the defect behind it
  (`current_a2l_path` was written in two places and cleared in none). The **project half is wrong**:
  `_apply_unload` never touches `current_project`, and making it do so would change what unload-all
  *means*, which is nowhere in `HLR-120`. ⚠️ **The lesson, worth the amendment on its own:** measuring
  told the batch that catalog and code disagreed; it did **not** say which was mistaken, and the first
  pass resolved that in favour of the code for *both halves at once*. Ask it per half.
- **▸ (P3) The command palette has NO `escape`-to-close.** `command_bar.py` declares no `BINDINGS` and
  handles no `escape`; re-executed at batch-79 Inc-9, `ctrl+k` then `escape` leaves `palette_is_open`
  **True**. `LLR-119.3`/`AT-B78-07` originally asserted a constraint *"must not shadow the palette's
  escape"* — **against nothing**. ⚠️ **Do not repeat the spec's suggested justification for deferring
  it:** *"the bar is being deleted anyway"* is **FALSE** — `HLR-118` deletes `#command_bar_row` while
  `#command_bar_slot` and `#command_bar` **survive to host the palette**, so the gap outlives Lane 1.
  Deferred at Inc-9 for the reason that does hold: it is a new capability on a different widget, outside
  `HLR-119`'s statement, and it needs its own requirement. Inc-9 pins only that its `escape` handler
  leaves the palette exactly as it found it.
- **▸ (P3) The three painted-Footer-children arms are unasserted.** `LLR-126.1` specifies **8** @80×24 ·
  **13** @120×30 · **15** @160×40 under §1.3's containment rule, as a PIN at the first two sizes and a
  GATE only at 160×40. Inc-6 shipped `AT-B78-28`'s model-key set-equality arm and **not** these. Carried
  from Inc-6 rather than dropped.

## 🆕 Carries returned by batch-76 (2026-07-31, `R-TUI-102`)

- **▸ (P2) `_applied_regions` is STILL the unbounded third producer, and it is now the ONLY thing standing between this repo and a whole-report residency claim.** batch-76 bounded the produced **file**; non-claim (a) states in writing that peak memory is untouched, because every producer is fully evaluated before its gate can refuse it. Operator-fenced for batch-75/76 by explicit ruling. **A residency acceptance stays unsatisfiable until this is bounded** — that is not a wording problem, it is the reason the claim cannot be made.
- **▸ (P3) Pre-existing `ruff F821 Undefined name 'Dict'` at `s19_app/tui/app.py:5682`.** **Reported as found, not fixed** — verified pre-existing by running ruff against a pristine `origin/main` copy of the file, so it is not batch-76's and was out of its scope. Harmless at runtime (`from __future__ import annotations` defers annotation evaluation), which is presumably why CI has never gated on it.
- **▸ (P3) `screens.py:1717-1719` — a NON-INTEGER `context_bytes` makes Generate do nothing.** It logs and returns: no status, dialog left open. An out-of-domain *integer* gives a clear `Report rejected:` (now correctly attributed by `HLR-110`), so this is the one input shape with no operator feedback at all. Inherited from the batch-75 spec §10 m-4.
- **▸ (P3) The disclosure allowance is large relative to a SHRUNKEN test limit.** `_disclosure_allowance(0)` was **47 534 B** when this was recorded and is **63 726 B** on `fd9124a` — batch-76's merge-gate closure raised it via `REPORT_VARIANT_ID_MAX_BYTES`, so **re-derive before citing (C-39)**. At the real 2 MB cap that is 3.0 % and immaterial, but a ceiling AT run against a shrunk budget has real slack, which is measurably why `TC-573` had to assert the hexdump seam **directly** rather than through the ceiling. Not a defect; a property to remember before writing the next ceiling AT — and since the slack **grew**, the point is now slightly stronger than when it was written.

> **Routed to `BACKLOG-PROCESS.md`, not duplicated here:** the mutation-harness control candidate (*a counterfactual must be shown to move the predicate's DECLARED SUBJECT, not merely to modify the file*), evidenced three times in this batch alone.

---

## 🔶 batch-78 — LANE 2 SHIPPED, LANE 1 CHARTERED FORWARD (cut 2026-08-06) — A2B diff master–detail

> **RECONCILED AT THE CUT, not left as written.** The operator cut the batch at the Lane-2/Lane-1
> boundary on token cost. **Handoff: `.dev-flow/2026-08-06-batch-78/HANDOFF.md`** — read it before
> resuming; it carries the open HIGH, the findings that reach into the unbuilt increments, and both
> follow-on charters.
>
> **✅ SHIPPED — Lane 2 in full (Inc-0…Inc-5).** The charter's original defect is **closed**:
> `_render_run_windows` was only ever called with the literal `0`, so runs 1..N were unreachable.
> The panel now has a selectable run list (keyboard **and** mouse), windows that follow the selection
> with context rows derived from pane height, report completeness observed **through the written
> file**, and three width/height regimes with an explicit insufficient-terminal notice that names
> **which axis** failed. Ledger `2607 → 2647`.
>
> **❌ NOT STARTED — Lane 1 (Inc-6…Inc-12).** Fully specified in `01-requirements.md` §7; see the
> charter below. **Do not re-derive the spec — execute it.**
>
> ⚠️ **ONE OPEN HIGH AT THE CUT (Inc-5 F-1).** `_DIFF_MIN_H = 26` declares heights 26–27 deliverable
> while painting **zero hex rows**, because line 0 of each window is the header. Strictly worse than
> 25, where the operator is at least told why. Root cause is a spec conflict resolved silently:
> `D-1`'s *"one visible content row"* → 26 versus **normative `LLR-125.2`**'s *"one **hex row** of
> content"* → **28**. `LLR-125.2` governs. **It blocks rather than carries because Inc-10's file set
> excludes `screens_directionb.py`.** The durable fix is the **height-floor node asserting both
> sides**, which does not exist — `TC-B78-31` does exactly that for the width axis.
>
> **Two defects reached shipped product code across six increments**, both found and fixed inside
> their own increment's gate. Every other finding — roughly thirty — was in an acceptance, a metric,
> a driver, a citation or the requirements document. **23 carries** are in `state.json`
> `phase3_carries`; the ones that changed how the work was done are tabulated in the handoff §5.
>
> Charter INPUT: `prototypes/cmdbar_a2bdiff.HANDOFF.md` (operator-approved 2026-08-06). Branch
> `claude/batch-78-cmdbar-a2bdiff`, cut off `origin/main` @ **`f6ff1d3`**, RC-1 PASS. Plan:
> `.dev-flow/2026-08-06-batch-78/PLAN.md`; measurements: `00-measurements.md`.
>
> **Scope (operator ruling at kickoff): Lane 1 + Lane 2 only — `S-1`…`S-9`.** Lane 3 (operations
> staged removal, `S-10`…`S-13`) is **explicitly out**, and **a handoff charter for it is a required
> deliverable of this batch's close**. `x` does **not** become free this batch.
>
> **Phase-0 premise evaluation: 20 evaluated — 16 TRUE · 1 FALSE · 3 INCOMPLETE · 1 UNVERIFIED.**
> All nine of the charter's cited `app.py` addresses are **exact to the line**. The cost is in what
> it does not say:
>
> - ❌ **Nothing unmounts.** `action_show_screen` (`app.py:5817-5824`) swaps a `hidden` class, so all
>   eight find/goto inputs resolve on **every** screen. `S-2` cannot route by presence — it must key
>   on `_active_screen_key`.
> - 🆕 **The bar acts on the WRONG PANE.** Executed: with A2L active, `CommandBar.Find("BOOT")`
>   writes into the *workspace* `#search_input` and leaves `alt_search_input` empty. The bar inputs
>   are duplicates **that silently act on the wrong pane on 9 of 10 screens** — so `S-2` fixes a
>   latent defect, not just cosmetics.
> - ⚠️ **10 screens exist, not 4**; only 3 own find/goto. `S-2`'s "no local find/goto" notice is the
>   **majority path (7 of 10)**, not an edge case.
> - ⚠️ **`Esc` does not return focus today** (`/` → `find_input`, `escape` → still `find_input`).
>   `S-2`'s Esc clause is **net-new work** and must not be written as a control.
> - ⚠️ **`S-3` reduces availability 10 screens → 1.** `LoadedArtifactsPanel()` is composed at
>   `app.py:2037` inside `#screen_workspace`. Escalated to the operator at the Phase-0 gate.
> - 💣 **29 of 29 snapshot goldens drift** — the bar is app-level chrome in every full-screen
>   capture. **CI-only regen** (textual 8.2.8 pin). Largest mechanical cost in the batch.
> - ✅ **`_PRE_BATCH_BINDINGS` does not pin `/` or `g`** (`tests/test_tui_directionb.py:6058-6074`,
>   14 tuples) — re-homing them cannot trip the frozen keymap guard. Verified, not assumed.
> - ⏳ **The width ceiling is a HYPOTHESIS, not a measurement of this tree.** 81-cell row / ≥130 /
>   120-wrap come from the design prototype; **re-derived at Phase 1** before they may bound `S-7`
>   (C-39 — a carried number is re-derived, not copied).
>
> **Blast radius (C-26 reverse-grep).** Lane 1 → `test_tui_commandbar.py`, `test_tui_directionb.py`,
> `test_loadfilescreen_input.py`. Lane 2 → `test_tui_diff_screen.py`,
> `test_tui_diff_compare_realpath.py`, `test_tui_directionb.py`. **Both lanes share
> `test_tui_directionb.py`.** `command_bar_row`, `set_context_labels`, `focus_find`,
> `diff_columns`, `DISPLAY_CONTEXT_BYTES`, `_render_run_windows` have **zero** test references today.
>
> **Ids: batch-scoped `AT-B78-*` / `TC-B78-*`** — no reservation PR; global `next_free` re-derived
> as `AT-282` / `TC-613` and left untouched.

  - **▸ (P1 — IN FLIGHT) `S-1`…`S-4` command-bar deletion.** Delete `#command_bar_row` (prompt,
    Project/A2L labels, find/goto inputs) app-wide · re-home `/`·`g` to the active screen's local
    inputs with a notice where there are none and a working `Esc` · re-home the context labels ·
    delete the dead surface (`styles.tcss:55-102`, `CommandBar.Find/Goto`, the two adapters,
    `focus_find/goto`). **Ctrl+K must keep working on all 10 screens**; workspace/A2L/MAC search and
    goto behaviour is the byte-identical control.
  - **▸ (P1 — IN FLIGHT) `S-5`…`S-9` A2B diff master–detail (variant A).** `#diff_range_list`
    `Static` → selectable list (every run reachable by keyboard **and** mouse, visible focus,
    scrollable past the viewport) · windows follow selection with context rows derived from pane
    height, retiring the `DISPLAY_CONTEXT_BYTES = 16` constant as a constant · two width regimes with
    a **required 120-col fallback** · compact selection rows · discoverability. G-9 display caps and
    the "showing N of M" notice are preserved; **the persisted report stays complete**.
  - **▸ 🛑 (P0 — BATCH-79 CHARTER) Lane 1: command-bar deletion, `Inc-6`…`Inc-12`. FULLY SPECIFIED — execute, do not re-derive.** `01-requirements.md` §7 carries the file sets, ATs and gates; `HLR-118`…`HLR-121` and `HLR-126` are written, reviewed through **three** Phase-2 rounds and amended. Order and its reason are in the handoff §7. **Findings that reach into these unbuilt increments and must not be rediscovered:**
    1. ❌ **The command palette has NO `escape`-to-close.** `command_bar.py` declares **no `BINDINGS`** and handles no `escape`; executed, `ctrl+k` then `escape` leaves `palette_is_open` **True**. `LLR-119.3`/`AT-B78-07` asserted *"must not shadow the palette's escape"* — **there was nothing to shadow**, and **both Phase-2 lanes accepted it** because it sounded like a property the widget would obviously have. **Inc-9 chooses a disposition in writing rather than inheriting one.**
    2. ⚠️ **`C-78-vi` BLOCKS Inc-10:** §5.1 rule 1's painted-height metric measures the **border box** and does not clip through intermediate ancestors, so `AT-B78-26`'s 120×30 "≥1 hex row" clause would pass with **three rows of border and zero hex**. Use Inc-1's corrected helper (`content_region` through the **full** ancestor chain).
    3. 💣 **29 of 29 snapshot goldens drift** on the bar deletion — app-level chrome in every full-screen capture. **CI-only regen.** This is the largest mechanical cost in Lane 1 and the reason Lane 2 went first.
    4. ⚠️ **Lane-1 blast radius is 6 test files, not 3.** `#cmdbar_project` is the observable for `_project_label()` (**14** call sites) guarding the LLR-005.5 multi-variant form, so **S-3 owes the display FORM, not just the name**. `tests/test_tui_app.py` goes **blind, not red** — it monkeypatches `update_project_labels`, so **its green is not evidence**.
    5. ⚠️ **The bar acts on the WRONG PANE today** — with A2L active, `CommandBar.Find` writes into the *workspace* `#search_input`. Nothing unmounts, so **`/`·`g` must route on `_active_screen_key`**, never on which inputs exist. **10 screens, 3 own find/goto — the notice path is 7 of 10, the majority.** And `set_status` writes the **log tail**, not `#status_text`.
    6. ⚠️ **The deletable CSS span is `:66-102`, not `:55-102`** — `#command_bar_slot` and `#command_bar` survive to host the palette.
    7. **Inc-0's committed artifacts are Inc-10/Inc-11's oracles** and **must be re-read from disk, never regenerated**: `AT-B78-03` was provably inert before Inc-0 because `CommandBar(self._build_palette_entries())` made observed and expected the same producer — GREEN at `36 == 36` with a whole `Binding` removed. **The temporal freeze is what breaks the circularity**, and `TC-B78-44`'s AST census reddens if any test module tries to rebuild one.
  - **▸ 🛑 (P1 — BATCH-81 CHARTER) Lane 3: operations staged removal, `S-10`…`S-13`.** ⚠️ **Renumbered 80 → 81 at batch-79 Phase 0 (operator ruling, 2026-08-07)**, because Lane 1 took 79 and the aggregation carry `C-77-l` moved into 80. Content unchanged. **Never in scope for batch-78** (operator ruling at kickoff); this charter was a **required deliverable of its close**. Source: `prototypes/cmdbar_a2bdiff.HANDOFF.md` §2 Lane 3. **S-10** encode the modal's known CRC as a saved Designer `.crc.json` (width 32, poly `0x04C11DB7`, init/xorout `0xFFFFFFFF`, refin=refout=true) — **open decision, do not silently pick:** op configs allow multiple regions with per-region output addresses while Designer serialization is single-output. **S-11** the Designer gains an execute path, **the first firmware write it performs**, amending `US-V6` with an explicit Before/After. **S-12** equivalence **by test, not by UI** (operator ruling — no KAT surface): byte-identical output between Designer execution and the modal's check+Write CRC path, and **this test must exist BEFORE S-13 deletes the modal**. **S-13** gated on S-10…S-12 merged and green. ⚠️ The deferred `wire-kernel-into-crc.py` item **intersects** S-10…S-12 — Phase 1 states the relationship explicitly rather than absorbing it. **`x` does not become free until S-13.**
  - **▸ (P3, NEW — batch-78 Phase 0) Diff variants B and C are backlog CANDIDATES, not scheduled.**
    Evaluated in the design session and not chosen. **C additionally needs ~190 cols or an 8-byte row
    mode `render_hex_view_text` does not have.** The charter fences both out explicitly.

---

## ✅ batch-77 — DONE (2026-08-01, merged via PR [#186](https://github.com/jav201/s19_app/pull/186)) — Memory Map redesign, Variant A

> **Registered at Phase 0.** Charter INPUT: `prototypes/memmap_variant_a.HANDOFF.md` (operator-approved 2026-08-01, Variant A + the cross-cutting fixes). Branch `claude/batch-77-memmap-variant-a`, cut off `origin/main` @ **`f8747b8`**, RC-1 PASS. Plan: `.dev-flow/2026-08-01-batch-77/PLAN.md`; measurements: `00-measurements.md`.
>
> ⚠️ **This section was written at Phase 0 and stood unreconciled until the merge gate.** It advertised `o` = open-hex as in-scope after ruling **R3 descoped it**, and it carried none of the five carries the batch returned. Both are recorded below rather than silently overwritten: **a section that says `IN FLIGHT` after the PR is open is a queue a reader cannot act on**, and the carries existing only in `01-requirements.md` §6.3 is exactly the condition under which this project has previously dropped an explicitly-addressed action across four consecutive PRs (batch-74).
>
> **Phase-0 premise evaluation: 15 evaluated — 9 TRUE, 4 FALSE, 1 IMPRECISE, 1 NEW defect found.** The charter's engineering direction survived execution; its **acceptance layer** did not — this project's dominant defect class arriving exactly where the charter itself warned it would.
>
> - ❌ **The charter's draft acceptance #1 is VACUOUS.** *"every region ≥1 visible bar column"* measures **TRUE on the pre-change tree**: `screens_directionb.py:2066` floors every run at `max(1, …)`. Invariant under the change it gates (**C-40 limb 1**). Replaced by **width monotonicity**, which IS red today because all five widths are equal.
> - ✅ **S-2 invalidates a shipped acceptance, not a sentence** — the clause is `R-TUI-072` (`:4787`), guarded by the then-live, passing `AT-072b` asserting *exactly 5 ticks*. **That half stands.** ⚠️ **CORRECTED at batch-77 Inc-5 (carry `C-77-i`): the "ZERO definitions in `REQUIREMENTS.md` / dangling reference" half was FALSE.** `LLR-072.3` **is defined** — `.dev-flow/2026-07-15-batch-47/01-requirements.md:508` — and is cited from **four shipped-source sites**, so the citation at `tests/test_tui_map_big.py:118` was never dangling. **The reasoning error, recorded so it is not made a third time:** the check grepped `REQUIREMENTS.md`, and `grep -cE '^\*\*LLR-[0-9]' REQUIREMENTS.md` returns **0** — that document defines **no LLR bodies at all**; LLR bodies live in the owning batch's `01-requirements.md`. **Absence from a corpus that cannot contain the target is evidence of nothing**, and such a search returns "not found" for every LLR id equally. Both ids now carry Before/After amendments (batch-77 §6.5 Amendments A and B). (`LLR-*` is **not** registry-covered — operator scoping ruling 2026-07-31.)
> - 🆕 **NEW, uncharted: the band bar OVERFLOWS its own budget — 64 columns against `_BAND_BAR_WIDTH = 60`**, because all 9 segments independently floor at `max(1, …)`. Identical at 80×24 and 120×30. **Folded into US-77-1** rather than carried (D-2): it is the same expression that story rewrites.
> - ✅ The charter's headline reproduces **exactly**: 5 regions, **1 030 B** mapped, **128.0 MiB** span, **59** gap-hatch columns. Its *"1-column sliver"* wording is imprecise — measured `[1,1,1,1,1]` = 5 columns, one per region. **The defect is non-discrimination** (256/256/256/200/62 B all render at 1 col), **not invisibility**.
>
> ⚠️ **Blast radius centres on `tests/test_tui_map_big.py`** — it hosts `AT-072a`, `AT-072b`, `AT-073`, `AT-074` **and** both `query(RegionRow)` sites. **C-26 reverse-grep** of every touched symbol (`RegionRow`, `.map-band-seg`, `.map-ruler-tick`, `.map-legend-row`, `#map_stats_body`) across all of `tests/` before any increment lands.

  - **▸ (P1 — ✅ SHIPPED) Memory Map Variant A: `US-77-1`…`US-77-7`.** Gap-fold band bar (widths ∝ **mapped** bytes, gaps folded to fixed markers, bar bounded by its column budget; a dense no-gap image renders **byte-identical to today** as the control) · edge-labeled ruler · dual mapped/span stats with a humanized largest gap · legend demotion to the existing `k` LegendScreen · keyboard path (rows focusable, ↑↓/j/k, `Enter` inspect, ~~`o` hex~~ — **descoped by R3, see `C-77-f`**) · auto-select first region · selection styling. **`R-TUI-072` amended in place** (§6.5 Amendment A) with a re-derived `AT-072b`.
  - **▸ (P3, NEW — deferred from batch-77 Phase 0, decision D-4) `US-77-8` — log-scale microbar denominator + column-aligned region rows**, the two ideas ported from Variant C. Ruled **OUT of batch-77**: no measured defect motivates either, the charter explicitly forbids silent absorption, and the batch already carries 7 stories. **Registered, not dropped** — reversible on operator request.
  - **▸ (P3, NEW — batch-77 Phase 0) Variant B (two-lane map) is a backlog CANDIDATE, not scheduled.** Evaluated and not chosen in the design session; the charter fences it out of this batch explicitly. Its own batch if the operator ever wants it.

### 🆕 Carries returned by batch-77 (2026-08-01, `R-TUI-103`)

> Written **inline, not as pointers**. Until the merge gate these lived only in `.dev-flow/2026-08-01-batch-77/01-requirements.md` §6.3 — a file no later batch reads at Phase 0 — which is how this project previously lost an explicitly-addressed one-sentence action across four consecutive batch-74 PRs that each opened this queue. A carry that is not in the live queue is not carried.

- **▸ 🛑 (P1) `C-77-l` — BATCH-80 CHARTER: the aggregation path. This carry is LOAD-BEARING.** It is the **sole** reason ruling **R-10**'s removal of aggregation from batch-77 is a *scope reduction* and not a *silent drop*: the path was descoped on the explicit promise that the next batch inherits it **fully measured**. Losing this carry retroactively converts a recorded descope into an undocumented gap. **Every measurement below is already paid for — the executing batch re-verifies, it does not re-derive.**
  > ⚠️ **RENUMBERED AGAIN, 79 → 80, at batch-79 Phase 0 (operator ruling, 2026-08-07).** batch-78's `HANDOFF.md` **contradicted itself**: its §7 chartered its Lane-1 follow-on as "batch-79" while its own §6 warned that *"79 is taken by the aggregation carry"*. Two claimants, surfaced at batch-79's kickoff rather than silently resolved. **The operator ruled that Lane 1 (command-bar deletion) takes 79**; the aggregation path moves to **80**, and Lane 3 (operations, below) moves to **81**.
  > ⚠️ **Prior renumbering, 78 → 79, at batch-78 Phase 0 (operator ruling, 2026-08-06)** — kept for lineage. This carry named "batch-78" before any batch had claimed that number, and the `prototypes/cmdbar_a2bdiff.HANDOFF.md` charter took **78**.
  > **The carry's content, priority and measurements are unchanged by either renumbering.** ⚠️ **Its own body still says "batch-79 must …" in four places** (the degradation rule, the time budget, the strict-∃ tension, the represented-not-merely-counted clause) — **read those as "batch-80 must …"**. They are left as written rather than rewritten, because editing normative sentences inside a load-bearing carry to chase a number is how measurements get lost; the number is corrected here, once, at the top.
  1. **Onset formula:** aggregation is required when `n_runs + n_gaps·fold > bar_width`, i.e. `2·n_runs − 1 > bar_w`.
  2. **Measured onset:** **26 runs @bar=50** (25 clean, 26 aggregates 1) · **34 runs @bar=66** (33 clean, 34 aggregates 1).
  3. ⭐ **THE ACCEPTANCE FIXTURE, FROM THE START — this is the single most important line in the carry.** `examples/professional_validation/case_08_heavy_fragmentation/firmware.s19` — **801 ranges → 801 runs + 800 gaps = 1601 segments**, ~30× the ceiling. **It is the ONLY shipped fixture past the onset**; every other is ≤ 11 runs. **The aggregation path has now been designed TWICE against fixtures that did not represent the real one** — revision 2's synthetic 35-run fixture was chosen because no shipped fixture was believed to cross, and that premise was false. This is the batch's signature failure recurring, and it is why R-10 descoped rather than patched.
  4. **Out-of-domain behaviour, BOTH producers.** *Pristine + CSS only:* @66 `797/801 (99.5 %)`, outside 1594; @50 `800/801 (99.9 %)`, outside 1600; `gap_w max=60`. *batch-77's producer:* @66 `768/801 (95.9 %)`, outside 1535; @50 `776/801 (96.9 %)`, outside 1551; `gap_w max=1`. Improvement **−29 runs @66, −24 @50**. Region list **801** rows, **no crash**, in every case. **batch-77 improves it at both regimes and fixes it at neither. Quote both figures or neither** — a lone "95.9 %" understates the wide regime. ⚠️ **The degradation rule is UNSPECIFIED** — these are observations of one conforming implementation, not a contract. **batch-79 must specify it.**
  5. **The bound is arithmetically unsatisfiable out of domain:** `avail = bar_w − n_gaps` = **−734** @66, **−750** @50.
  6. **⏱ O(n²) cost — and time is NOT currently a stated cost axis.** Merge-smallest-adjacent on the UI thread: **n=1000 → 975 merges, 31.10 ms**; **n=5000 → 4975 merges, 840.34 ms**, uncapped. `case_08` is n=801. **batch-79 must add a time budget to its constraints** (security M-3r).
  7. **An aggregate has no usable monotonicity subject.** `region_end − region_start` **includes swallowed gaps**, so it is not the aggregate's mapped size. Executed on `case_08`: monotone-by-span **False**, monotone-by-**sum of constituent run bytes** **True**; first span violation `((1988,2),(2150631108,1))`. **The subject must be the summed run bytes, and `BandSegment` does not currently expose it** (arch RB-2).
  8. **"Merge until it fits" dies exactly where strict-∃ dies.** Executed: `regions=18 → 76 runs`, both regimes, **all widths 1, strict False — the strict limb is DEAD**. The stopping rule and the discrimination requirement are in direct tension; **batch-79 must resolve which yields** (arch RB-3).
  9. **The disclosure count is ambiguous three ways on the real fixture.** `case_08` @66: `oracle − TOTAL segments = 768` · `oracle − STANDALONE = 801` · `runs that lost a dedicated segment = 768`. @50: `776` / `801` / `776`. **Pick the definition before writing the AT, not after** (arch RB-4).
  10. **A coverage clause that excludes aggregates is FALSE on correctly-aggregating code.** QA: 2 ranges → 1 aggregate → filtered `emitted` empty → coverage `False`; 26-region fixture leaves **10** uncovered range starts @66, **15** @50. **Coverage must include aggregate spans** (QA N-1).
  11. **The count formula cannot distinguish merged from DROPPED.** `oracle − emitted` is GREEN identically whether runs were merged into an aggregate or **silently discarded**. batch-79 needs a separate clause that every run is *represented*, not merely *counted* (QA N-1).
  - **Scope note.** `LLR-111.7` (floor-1 + largest-remainder bound) **stays shipped in batch-77** — it is verified sound and is what makes **15 of the 16** shipped fixtures work with zero aggregation. batch-79 inherits a working bound and owns only the excess.
- **▸ (P3) `C-77-f` — `o` = open-hex keyboard affordance DESCOPED (ruling R3).** The batch-77 story line above advertised it and it did not ship. Rows are focusable and `↑`/`↓`/`j`/`k`/`Enter` all work; there is **no keyboard route to the hex view from a region row**. Reversible; no measured defect forces it.
- **▸ (P3) `C-77-g` — 2-column fold marker + humanized size label DESCOPED (ruling R-5).** Gaps fold to **exactly one** column carrying `╱`, with no size label. A 2-column marker would carry a legible size at the cost of one column per gap, which on a 10-gap image is 10 columns off the ceiling on visible regions — the batch's whole subject. **Reopening condition:** an operator report that gap magnitude is not readable from the stats line's largest-gap figure.
- **▸ (P3) `C-77-j` — pre-existing 1-column glance-box clip, STILL LIVE at 80×24.** The box is 28 columns; its widest content row is 29 (`'· constant/padding 3 ████ 60%'`). Found by the corrected R-7 sweep. `LLR-111.9` incidentally fixes it **at 120×30 only**, by giving the glance full width; **the 80×24 path is unchanged and still clips**. Pre-existing, not introduced by batch-77. **Distinct from `C-77-k`** — different defect, same screen.
- **▸ (P3) `C-77-k` — the stats line's scroll DEEPENS (ruling R-8, accepted).** `LLR-111.9` moves `#map_stats_body` from `bottom=31/30` to `bottom=33/30` at 120×30. It is **already below the fold at both regimes today** (`bottom=31/30` @120×30, `bottom=35/24` @80×24), so this deepens an existing scroll and **newly hides nothing**; the line stays reachable by scrolling exactly as today. **The widen is deliberately NOT narrowed to protect it** — every column surrendered lowers the ceiling on visible regions. **Distinct from `C-77-j`.**
- **▸ (P3) `AT-B77-19` guards FIRST RENDER ONLY — four correct-but-unguarded paths.** The merge-gate product fix (`BandBar.Measured`) is verified correct on **five** layout paths at both regimes — first render, re-render, terminal resize after settle, screen-away-and-back, and *resize while the map screen is not active* — but the regression node `test_b77_bar_reapportions_without_panel_resize_or_retry` exercises only the **first**. LOW rather than higher because all five ride the single `BandBar.Resize → Measured` mechanism, and first render is the only regime where the two incidental correctors (the panel's own `on_resize`, the bounded retry) were ever load-bearing. If the settle path regresses on any other path, **nothing reddens**.
  ⚠️ **This carry is itself the FIFTH instance of this batch's carry/citation class, and it was live AT CLOSE.** It was raised by the post-gate re-review as F3, written into `REQUIREMENTS.md:6017`, and then existed in **neither** backlog lane — `grep -c AT-B77-19` returned **0** in this file and **0** in `BACKLOG-PROCESS.md`. Found by the Phase-5 postmortem's own reconciliation sweep, i.e. by the mechanism built to catch exactly this, one gate after the close-out repaired instances three and four. **A carry that is not in the live queue is not carried** — this project already has an incident where a one-sentence action survived four consecutive PRs that each read this file.
- **▸ (P3, REGISTRY LANE) Two node-naming corrections in `AT-TC-REGISTRY.jsonl`, both deferred because renaming a node is a registry change, not a test edit.**
  - **`TC-519`'s node name is now inaccurate.** §6.5 **Amendment E** replaced the node's predicate — from `git diff origin/main -- s19_app/tui/legend.py` is empty (file identity) to a two-arm **behavioural** predicate (Arm A: `LegendScreen.compose` splats each helper's return directly into its pane; Arm B: the helpers return `Widget`s, not text). The node is still called `test_tc519_legend_module_unchanged_vs_main` and **nothing about it now asserts that the module is unchanged** — measured, `git diff --stat origin/main -- s19_app/tui/legend.py` is **8 insertions / 5 deletions**. The registry binds `TC-519` to that exact node path (and to `_repo_root`), so a rename must land as a coordinated registry + test change.
  - **`AT-072b`'s registry entry names one node and the observable now spans two.** The entry is `"nodes": ["tests/test_tui_map_big.py::test_at072b_ruler"]` with the seed statement *"Seeded from the existing verifier(s): test_at072b_ruler."* That node survives and was amended in place (its retired 5-tick percentile predicate → labels ⊆ run starts ∪ last mapped byte). But its predicate is **subset-only and therefore GREEN on a ruler that renders ZERO ticks** — which is why `AT-B77-04` (`test_b77_ruler_labels_every_run_start_and_the_last_byte`, `tests/test_tui_map_big.py:362`) exists as the ⊇ lower bound. ⚠️ **Verified at the merge gate: `AT-B77-*` ids are not in the registry at all (`grep -c AT-B77 AT-TC-REGISTRY.jsonl` → 0)**, so this is not a stale-path defect — it is the open question of whether the batch-scoped ⊇ half should be promoted into the registry under `AT-072b` or minted as its own permanent id. **Decide before the next registry sweep.**
    > ⚠️ **STILL OPEN after batch-78 (2026-08-06).** This item's deadline read *"before batch-78's registry sweep"*, written when no batch had claimed 78. **batch-78 performs NO registry sweep** — it mints batch-scoped `AT-B78-*` / `TC-B78-*` ids, which `_meta.governed` places outside the registry's authority by spec §2.3, so the global `next_free` (`AT-282` / `TC-613`) is untouched. The deadline is re-pointed at *the next batch that actually sweeps the registry* rather than allowed to expire against a batch that never had the opportunity to discharge it.

---

## Status legend
`P0` next · `P1` high · `P2` medium · `P3` low · flow ∈ {/dev-flow, /fast-dev-flow, direct}

> ### 🔄 Flow revision — verify currency at Phase 0 (C-45)
> **`flow_version: 2026.07.28-rev1` · `flow_hash: 0127a2767ff11c8a` · controls C-1…C-45.**
> Three controls were encoded from this project on 2026-07-28 and pushed upstream so every project inherits them: **C-43** premise evaluation at every gate (artifact = `req-template` §2.7) · **C-44** session-close working-file reconciliation (artifact = the post-mortem's reconciliation + conditional-gate-discharge tables) · **C-45** the flow is a shared asset (PUSH portable controls upstream; PULL and verify currency before deriving).
>
> **Before deriving anything, re-derive the aggregate and compare** — the command is in `~/.claude/docs/FLOW-VERSION.md` (mirrored at `jav201/claude-skills/dev-flow/`). A mismatch is either uncommitted local work (push it) or staleness (pull it); the per-file rows say which. **Record the revision in `PLAN.md` beside the RC-1 line** — a batch that cannot state its flow revision cannot claim its controls were current.

---

## 🟡 P0 — RE-REVIEW OF batch-65 — **LARGELY RESOLVED at batch-70 (2026-07-28)**, 3 residuals below

> ### ✅ Resolution summary (batch-70, commits `b037186` + `14b8285`; PR [#158](https://github.com/jav201/s19_app/pull/158))
>
> **ROOT CAUSE FOUND, and it was not what the P0 suspected.** The merge-gate re-gate closed **CONDITIONALLY** — *"Once items 1–5 land this is a MERGE"* (`07b-merge-gate-qa-regate.md` §6) — **and the batch merged with 2 of the 5 undischarged.** The record did not decay by neglect; its corrections were written, approved, and never executed.
>
> | Merge-gate item | Status |
> |---|---|
> | 1 — the *"four `batch-64` strings"* false premise at `07-merge-gate-qa.md:153` | ❌ **STILL OPEN** — residual R-1 below |
> | 2 — Phase-4 disposition tally | ✅ had landed (`05-postmortem.md:304-305`) |
> | 3 — deliberate old-number retention disclosure | ✅ discharged batch-70 (`14b8285`) |
> | 4 — unreachable SHA citations in postmortem + traceability matrix | ✅ discharged batch-70 (`b037186`) |
> | 5 — *"and nowhere else"* in `REQUIREMENTS.md:5009` | ✅ had landed |
>
> **① ids/branches — CLEAN.** `REQUIREMENTS.md` R-TUI-098: **0** `batch-64` refs. Of 59 `batch-64` lines in the artifact set, **57 sit in the two merge-gate docs**, where `batch-64` legitimately denotes the *other* batch. The 2 outliers (`06-docs/traceability-matrix.md:10`, `05-postmortem.md:12`) were **accurate** references to the pre-migration backup — but both anchored traceability on `ba5f09a` / `9d21d9a`, verified **NOT reachable from `origin/main` and never will be** (PR #149 was squash-merged). Both now name **`b691f21`** as the auditable commit. ③ **`TC-497` 1 passed** — the guarded residual figures still reproduce.
>
> **⑤ GOVERNANCE QUESTION ANSWERED — the post-mortem's claim is FALSE.** *"All eleven self-corrections WEAKENED a finding, not one strengthened one"* (`05-postmortem.md:274`) has at least two counterexamples: `07b:221` **MED-1 — verdict "worse", ruling "ESCALATE"**, and MED-5 *"unchanged, more false"*. **Both are at the merge-gate re-gate (Phase 6), which ran AFTER the post-mortem (Phase 5)** — the claim was true when written and the corpus outgrew it by one gate, with nothing re-asking. **This tilts the watch-item toward the BENIGN reading:** once a gate ran post-mortem, a reviewer did escalate its own finding, against the interest of a merge it also authorised. **Close the watch-item unless a later batch finds the pattern re-forming.**

### Residuals from the P0 — still open

  - **✅ (P0, R-1) merge-gate item 1 — DISCHARGED batch-70, by re-derivation, NOT by applying the prescribed text.** The re-gate's prescribed replacement was itself wrong on both the arithmetic and the taxonomy: it asserted *"the only **four** … so the other **nine** are this batch mislabelling itself"*, which **contradicted its own parenthetical in the same row** (a stated total of 13), and whose "mislabelling" category is **empty** on today's file. **Re-derived at `dc6aa71`: 9 occurrences on 7 lines = 4 `§7.x` bullet markers (theirs, `:118` `:125` `:126` `:148`) + 1 further legitimate reference to their `D-5` constraint (`:125`) + 3 navigational / backup-branch / renumbering-event references (`:7` `:27` `:28`) + 1 replica of the false claim itself (`:28`). ZERO mislabels.** Both sites corrected — the merge-gate report AND the replica in this file — and both now state the **commit basis**, because *a count without its commit is a claim with an expiry date*. **Live proof of that during the derivation:** the measurement of 9 went stale inside this same session the moment the resolution block above was written (the working copy read 14/10), so the recorded figure had to be re-taken against `origin/main` rather than reused. Original text of this residual preserved below for the record.
    ~~**▸ (P0, R-1) merge-gate item 1 — `07-merge-gate-qa.md:153` still carries the false premise, and it is a DERIVATION, not a text swap.**~~ The re-gate prescribed replacing it with *"the only **four** `batch-64` strings in `origin/main`'s copy are the other batch's §7.x bullets, so the other **nine** are this batch mislabelling itself"* — asserting **13 total**. **Measured 2026-07-28: this file has 9 occurrences across 7 lines**, and batch-67 + batch-69 have edited it since. **Copying the prescribed sentence forward would plant a fresh false figure — the exact defect class the item exists to remove.** Re-classify the 9 occurrences one by one against the current file. *A carried number is re-derived, never copied.*
  - **▸ (P1, R-2) `.dev-flow/state.json`'s `artifacts` map lists 10 of the 21 batch-65 artifacts on disk** — missing the 3 increments, validation, post-mortem, all 4 `06-docs/` files and both merge-gate reports. Deliberately NOT fixed by rewriting another session's commit; apply on top of PR #158.
  - **▸ (P3, R-3) ② the two merge-gate documents — MECHANICAL layer VERIFIED CLEAN batch-70; the PROSE layer remains unread.** Executed against the tree, not read: **21/21** cited file paths exist · **16/16** cited `AT-`/`TC-` nodes are present in `tests/` or `REQUIREMENTS.md` · the double-proven golden matches on **both** axes (**155 702 B** and SHA256 **`327adfb7…688c0a73`**, exactly as recorded) · the recorded **2233**-test figure is correct for batch-65 and today's `-m "not slow"` collection of **2319** differs by **+86**, **fully attributed** (81 nodes from the four test files batch-67/68 created, ~5 added to existing files). **Referential and numeric integrity therefore HOLDS** — the defect this re-review actually found (G-3) was in *commit* references, not file or node references, and it is closed. **What is NOT done:** a prose read of the 741 lines for reasoning defects. Deliberately deferred rather than attempted at the end of a long window — that is the exact condition batch-65's own record identifies as producing bad self-corrections. Downgraded **P2 → P3**: the mechanical layer was where a defect would have been actionable, and it is clean.
    *Method note worth keeping: two attribution attempts for the +86 were WRONG before the third was right (a `+def test_` count gave 20; a "full vs not-slow population mismatch" hypothesis gave the wrong gap). Neither was reported as a finding. **A delta you cannot attribute is not yet a defect** — attribute it or say you could not, never publish the guess.*

  - **✅ (P0 — RESOLVED batch-70, retained for the record) re-review batch-65's RECORD with an intact context window. The code is not what needs checking; the record is.** batch-65 (`R-TUI-098`, PR #149) merged with strong evidence on the product side — correctness re-derived by two independent parties (30 855 exhaustive geometries + 3 000 randomized + 15 hand-built, comparing caller-index lists, **0 mismatches**; plus 4 000 randomized below-bound fixtures byte-identical to a transcription of the pre-batch producer), 2233-passing suite, 0 frozen diff, 0 goldens re-baselined, 6/6 byte-identity shapes. **What is NOT trustworthy at the same level is the batch's own paperwork**, for a specific and measured reason.
    **Why this item exists — the failure is documented, not suspected.** The authoring session's judgement about *its own corrections* failed twice in a row, at the end of a very long context window: (1) it fixed merge-gate `HIGH-1` with a **blanket `batch-64` → `batch-65` replacement over 20 files**, justified by an unverified rationale ("my artifacts predate the collision"); the rationale held for 19 files (66/66 substitutions verified correct by the re-gate, line by line) and **failed on the 20th** — `07-merge-gate-qa.md`, the gate's own report, written *after* the collision and *about* it — producing three false statements about a merged batch, six references to a directory that never existed, and seven evidence lines turned tautological. (2) It then reported `HIGH-3` closed while the metrics row that actually carried the wrong number was still wrong, having corrected a *neighbouring* line. Both were caught by an independent re-gate, not by the author.
    **What to check, in priority order.** ① Every batch-id and branch reference in `.dev-flow/2026-07-28-batch-65/**` and in `REQUIREMENTS.md`'s `R-TUI-098` section — **do not trust any of them**; the file set went through two mechanical passes. `origin/claude/batch-64-addendum-producer-bound` @ `98b5b7a` is the pre-migration backup and the *only* ref containing `9d21d9a` and `ba5f09a`; `claude/batch-65-addendum-producer-bound` @ `374ad90` is **not** a backup, it is a live ancestor pushed by the parallel session. ② The two gate documents `07-merge-gate-qa.md` and `07b-merge-gate-qa-regate.md` — the first was corrupted and hand-restored on 24 named lines, and it also contains a premise the re-gate corrected *about its own earlier report* (`origin/main`'s `BACKLOG-CODE.md` has **four** `batch-64` strings, not zero — ⚠️ **superseded, see R-1**: re-derived at `dc6aa71` it is **9 occurrences on 7 lines**, of which 4 are the other batch's `§7.x` bullet markers and **none is a mislabel**). ③ Whether the Lane-A residuals below still say what `R-TUI-098` says — they were first written with the requirement's `(a)`…`(f)` letters, **three were mis-lettered**, and the letters were removed rather than re-lettered. ④ Whether anything this batch owes is stated twice or lost after a 3-way merge plus four hand-added bullets.
    **What NOT to redo.** Correctness, dual traceability, byte identity, the frozen guards and the suite. Two independent parties established them and the corrective passes touched **no code** — the six files under `s19_app/` and `tests/` are blob-identical to `98b5b7a`. Re-running the 28-minute suite would feed it byte-identical input. Read `07b-merge-gate-qa-regate.md` §6 first: it is the list of what was fixed and how.
    **The governance question worth answering while you are in there**, from batch-65's own post-mortem: across four agents there were **eleven self-corrections and every single one WEAKENED a finding — not one strengthened one**, in a batch running autonomy + self-merge. Two readings fit and that record could not separate them. The cheap test: *did any reviewer, at any point, ESCALATE its own prior finding after executing something?*

## 🔺 MAJOR / HIGH — `report_service` producer bounding + report integrity

  - **✅ (was MAJOR/HIGH — batch-63 D1) `_addendum_lines` producer bounding — DONE, batch-65, `R-TUI-098` / `HLR-103` / `LLR-103.1…6`.** Single pass over a coalesced disjoint half-open cover; `range_index` consumed as a **reject pre-filter only** (it inspects one `bisect_right` candidate, so it is unsound over unmerged overlaps, and returns `bool` so it can never name a region); region identity from a caller-local `bisect` + prefix-max array; **one ordered hit list per region + three admission counters**, NOT per-class buckets — the shipped order interleaves `mod, issue` per summary, so buckets would have broken byte identity. Production blast radius **2 files**; suite `2233 passed / 0 failed`; 29 snapshots; frozen diff 0; **0 goldens re-baselined**. Correctness re-derived independently by the increment reviewer: 30 855 exhaustive geometries + 3 000 randomized + 15 hand-built, comparing caller-index lists, **0 mismatches**; plus 4 000 randomized below-bound fixtures against a verbatim transcription of the old producer, exact line equality. **The batch does NOT close the memory-exhaustion DoS and never claims to** — see the residuals below. Original bullet text preserved in `.dev-flow/2026-07-28-batch-65/`.
  - **✅ PARTIALLY CLOSED by batch-74 (`R-TUI-101`) — the CARDINALITY and PER-CELL WIDTH axes are DONE for both producers, plus the previously unchartered `Address` cell. The EMITTED-BYTES axis (F4, next bullet) is NOT, and is chartered to batch-75.** Corrections batch-74 executed against this bullet's own numbers: its **`988 B/entry`** is **not a constant** — the cost is **`≈ 92 + 6·L`**, linear in the entry's byte-run length, and 988 is its value at `L ≈ 149` (at an 8-byte run: **140.1** / **126.1 B/entry**). Its proposed remedy *"charge them to `_ByteBudget`"* was **falsified**: `emit()` (`:2215-2217`) calls `budget.consume(...)` only — it **accounts, never gates** — and by the time `consume` runs the producer has already been fully evaluated. And its line citations were pinned to `031ca8d`; they are superseded by symbol names. **What actually closed it: bound the PRODUCER on BOTH axes** — a row-count cap alone leaves one row costing ~6 MiB at `MF_RUN_LENGTH_CEILING = 1_048_576`. *(original bullet text follows, unedited, for lineage)* **▸ (MAJOR/HIGH, new — batch-63 sec F2, OB-4) the SAME two functions carry a RESIDENT-MEMORY axis, and the bullet above does NOT close it.** This is a **peer of the twelve document-byte axes, not a subset of them.** The bullet above proposes *"charge them to `_ByteBudget`"* — that remedy bounds the **output** and leaves resident memory untouched, **because the row list is fully materialised before the budget ever sees it**. Measured on `031ca8d` (bounded grid + extrapolation from a printed marginal constant; the declared-domain fixture was never built, since building it is what exhausts host RAM): **988 B/entry marginal** across `_modifications_lines` (`report_service.py:923`) + `_checklist_lines` (`:1095`), ~11× the addendum's 89 B/hit → **~99 MB for ONE change document** at `MF_ENTRY_COUNT_CEILING = 100_000` (`tui/changes/io.py:226`), and **~6.3 GB at 8 change documents × 8 variants**. Independently: even a per-class-capped addendum stays **linear in an unbounded declared-region count** at **6 415 B/region** (`R=50, K=200`), because `options.declared_regions` has **no cardinality cap anywhere** — the only cap is `DECLARED_REGION_NAME_MAX = 80`, which bounds a region's *name*, not the region *count* (`report_addendum.py:26`). **batch-63 does NOT close this:** it shipped D3 (the writer/accounting defect) only; D1 (addendum cost) and D2 (schema-legal address denial) were returned to this backlog at the Phase-2 re-gate. **Operator-confirmed carry 2026-07-27** — recorded as a carry *with its numbers* rather than as a signed risk acceptance, because under the D3-only scope batch-63 makes no memory claim for a residual to be accepted against; the moment any batch re-asserts a memory bound over `report_service`, this is the line it must discharge. **Whoever takes it: bound the PRODUCER — stream or cap rows as they are found — not the emitted document.** That is the same shape as batch-63's D1, whose Phase-2 finding was precisely that *bounding output does not bound traversal*, and it is why the `_ByteBudget` remedy above is insufficient.
  - **🔺 CHARTERED TO batch-75 — the ROW-COUNT half of this bullet is DONE (batch-74, `R-TUI-101`); the EMITTED-BYTES gate is what remains.** See the **batch-75 charter** block below for the measurements batch-74 executed and did not spend. Its closing suggestion *"or charge them to `_ByteBudget`"* is **struck**: that remedy was measured to close nothing (`emit` accounts, never gates). *(original bullet text follows, unedited, for lineage)* **▸ (MAJOR, new — sec F4) the modifications and checklist tables are UNBOUNDED, and the constant's comment used to claim otherwise.** `REPORT_MAX_REGIONS_PER_VARIANT` is consumed by `_hexdump_section` ONLY, so `_modifications_lines` and `_checklist_lines` emit one row per entry with no cap. **Measured:** 5 000 entries → 5 000 rows; ~100 000 rows → **~208 MB, ~99× the declared 2 MiB `REPORT_MAX_TOTAL_BYTES`**; realistic A2L symbols at 100k rows → 7.6 MB (3.6×). The unbounded row count is PRE-EXISTING, but batch-62 raised per-cell cost ~1.4–2× and moved `entry.linkage` from raw to escaped, so it amplified an unbounded path. The false docstring claim was corrected at Inc-6; **the cap itself is this carry** — mirror `MAX_REPORT_ISSUES_PER_VARIANT` on both tables, or charge them to `_ByteBudget`. The 200-issue cap batch-62 added proves the pattern is understood.
  - **🔻 P3 (HARDENING) as of the 2026-07-31 re-triage — NO LONGER PART OF THE MAJOR CLUSTER. Chartered to `R-TUI-102`; ITS HEADLINE IS FALSE — see the batch-75 charter below.** The severity drop is recorded once, in the charter's D2 bullet, with the two-construction-site measurement re-executed on `038dfd9`; this bullet inherits it rather than restating it, so there is exactly one place to correct if it is ever wrong. batch-74 executed this bullet's premise and it did not hold: *"a schema-legal **address** denies the report"* is **FALSE** (**P-20**) — a huge address renders fine; the `raise` keys on **`Length`**'s decimal digits, exactly as this bullet's own body says two sentences later. Worse, the whole item is **unreachable through the shipped ingestion path**: `addressed_range = (address, address + len(encoded_bytes))` bounds `Length` at `MF_RUN_LENGTH_CEILING` → **7 decimal digits** against a 4300-digit limit (`changes/model.py:173-185`). It is constructor-domain hardening, not a wire threat — which is precisely why it was the safest of the three to defer. **The genuinely wire-reachable oversized field was the `Address`, which this bullet mentions only to dismiss, and which no requirement chartered until `R-TUI-101`** (`int('0x'+'F'*100000,16)` **parses** — CPython's `int_max_str_digits` does not apply to base 16 — for a **100,000-character** cell, ceiling `READ_SIZE_CAP_BYTES` = 268 MB). *(original bullet text follows, unedited, for lineage)* **▸ (MAJOR, new — batch-63 D2, RETURNED at the Phase-2 re-gate) a schema-legal address DENIES the report, and the error blames the operator.** `_ADDRESS_RE` is `^0x[0-9A-Fa-f]+$` with **no digit limit** (`changes/io.py`), so an address of ≥ **3572 hex digits** is schema-legal — `_parse_address` accepts every width with **0 issues** — and the decimal `Length` column raises `ValueError: Exceeds the limit (4300 digits)`. **The obvious suspect is innocent:** the address cells are `0x{…:08X}` and hex is exempt from the digit limit; the crash sites are the two **decimal** f-strings, `report_service.py:996` (`_modifications_lines`) and **`:1171`** (`_checklist_lines`) — the exact two-member set derived by AST census, not by reading. **Not a crash at the shipped surface:** `app.py:4034` catches the `ValueError` and reports `Report rejected: <CPython internals string>` in the **operator-input-rejection** branch, the same branch used for genuine domain errors — so an internal failure is presented as though the operator's input were invalid. Fails **closed** today (no partial file); any fix must preserve that. **Three findings for whoever takes it:** the boundary literal is **not stable** (under `-X int_max_str_digits=1000` it moves to 831), so an acceptance must derive the width from `sys.get_int_max_str_digits()`; a **bare-hex** fallback is **forgeable as a decimal numeral** (`int('9'*3572,16)` renders `'9'×3572`, `isdigit()` True, understating the true length by ~10^730× in an evidentiary document) so the alternative form needs a `0x` prefix — and the predicate must be `^-?0x[0-9A-F]+$`, because a **negative** `Length` is constructible (`ChangeSummaryEntry(0x2000, 0x1000)` → −4096) and a bare "starts with `0x`" both rewards the malformed `0x-9999…` and false-fails the correct `-0x9999…`; and the two sites take **disjoint inputs** (`change_summaries[].entries` vs `check_results[].entries`), so a change-only fixture never reaches `:1171` and an AT must bind each site independently. Eliminated by measured output, so it need not be re-argued: "cap the rendered width" **still raises** (the int→str conversion precedes the slice), and "render the column in hex" changes **9/9** in-domain renderings. **All `report_service.py` line numbers in this bullet are as of `031ca8d`** — batch-63 added +47 lines to that module (49 insertions, 2 deletions), so the two crash sites moved; re-derive them rather than copying (the same rule this batch applied to every other carried number).
  - **▸ (MAJOR, REDESIGN NEEDED) host-path exposure in project reports — D-11/R-TUI-078 WITHDRAWN at the batch-62 merge gate (operator ruling 2026-07-26).** batch-62 implemented redaction on `issue.message`, and **three revisions of a shape-inference redactor produced three integrity defects**: it ate URLs (`http://vendor.example/spec` → `httspec`); it consumed to end-of-string on an unclosed quote, deleting a diagnostic's failing address and byte values; and finally it mangled quoted **symbol names**, because every `ValidationIssue` template in `s19_app/validation/` embeds a file-derived symbol in single quotes (`f"MAC symbol '{name}' address 0x…"`) and a path-shaped symbol is indistinguishable from a path — producing ONE report line stating TWO identities for the same symbol. Reverted; `flow_report_service` keeps main's batch-60 redactor untouched. **The correct construction, named so the next attempt does not repeat this:** substitute **KNOWN roots** (`Path.home()`, project root, temp root) by literal replacement — the technique `tests/conftest.py::canonical_report_bytes` already uses — plus at most a conservative whitespace-bounded catch-all. It guesses nothing and deletes nothing, and it covers spaced usernames BETTER than any pattern because the space is part of `Path.home()`. **Acceptance criterion to carry with it (the strongest available here):** *symbol identity is consistent across every field of one report* — for any issue carrying a `symbol`, the value inside `message` must equal the value at `symbol=` and in the Modifications/Checklist row. Black-box, needs no knowledge of the redactor, and fails on a shape-inference implementation.
  - **▸ (superseded by the bullet above — kept one release for lineage)** the batch-62 D-11 "partial fold" bullet said `_redact_absolute_paths` **is** applied to `issue.message` and framed the Mode-B divergence as an accepted ruling. **That is no longer true**: D-11 was withdrawn at the merge gate (Inc-8) and NOTHING in a project report is redacted. Superseded rather than deleted so the reversal is traceable; the live statement is the redesign carry above.

### 🔵 batch-75 — SPEC LANDED, IMPLEMENTATION OWED (2026-07-31, PR pending)

> **batch-75 shipped its SPEC ONLY, by operator ruling mid-batch** ("solo enmiendas, para antes de
> Inc-1"). Phases 0→2 are complete and re-gated; **Inc-0…Inc-3 are NOT implemented.** The spec is
> `R-TUI-102` / `HLR-108`/`109`/`110` in `.dev-flow/2026-07-31-batch-75/01-requirements.md` **revision 2**.
> A fresh session implements it with a full context window — this area hit the 3-iteration cap in b63 and
> b74 partly by running out of room mid-increment.
>
> **What the spec already settles, so the implementing batch does not re-derive it:**
> - **F4 CONFIRMED and sharper than chartered.** Exactly **1** `.fits` gate (`_hexdump_section`'s block
>   loop) vs **2** `.consume` sites. `emit()` accounts and never gates — **and neither does
>   `_hexdump_section`'s `put()`** (`:1748-1750`, consumes unconditionally; **5 ungated sites**,
>   ≈178 B/variant). The charter's own framing missed the second one.
> - **Re-derived floor: `2,097,152 + V × 311,625` B** → **1.15× / 2.49× / 15.86×** at `V = 1/10/100`. The
>   charter's `315,912` and `2.51×`/`16.06×` run ~1.4% high. **Use the re-derived numbers.**
> - 🆕 **`md_safe(limit=N)` bounds INPUT characters, not emitted bytes — measured 2.03× expansion.** Every
>   per-cell cap in the module is input-shaped; any byte arithmetic from `REPORT_CELL_CHARS` is wrong by
>   up to 2.03×. **Not in the charter.**
> - 🆕 **`md_code` refuses truncation deliberately** (a cap would be machine-dependent and poison
>   goldens), so capping the `#### Checklist:` heading is **FORECLOSED**.
> - **OPERATOR RULING (F7 fairness):** the design uses a **per-variant byte reservation**, not first-fit.
>   An attacker controlling content controls emission order; an early 311,625 B variant blanks variants
>   8–100. `AT-254` is the acceptance.
> - **Structural lines per check file are 6/7/8 by ARM, never a flat 7** — the charter's 7 and my own
>   Phase-0 7 were both incomplete.
>
> ⚠ **Two premises came out FALSE from INSIDE batch-75** (not from the backlog): the Phase-1 architect
> lane's *"the D2 `Length` defect is wire-reachable"* (**FALSE** — `end − start == len(encoded_bytes)`
> on both wire paths, ≤ `MF_RUN_LENGTH_CEILING` → **7 decimal digits vs a 4300 limit**; D2 is
> constructor-domain hardening) and my own revision-1 `LLR-102.4` exemption. **Treat every lane's output
> as a starting point, exactly as the charter says to treat itself.**
>
> ⚠ **ID NAMESPACE TRAP, cost a Phase-2 blocker.** `HLR`/`LLR` are a **separate counter** from `R-TUI-`.
> `HLR-102`/`LLR-102.x` are **live** (batch-63, cited at `report_service.py:608`/`:622`). True high-water
> = **`HLR-107`/`LLR-107`**. **Derive every id namespace the batch will write, not only the one the
> charter names.**

  - **▸ (P0 — batch-75 IMPLEMENTATION) implement `R-TUI-102` revision 2: Inc-0…Inc-3.** Inc-0 pre-flight
    golden · Inc-1 `emit`+`put` gating, per-variant reservation, aggregated disclosure, round-robin
    appendix, derived allowance (`AT-250`…`AT-256`, `TC-552`…`TC-561`) · Inc-2 `_format_length` + both
    call sites (`AT-257`…`AT-259`, `TC-562`…`TC-569`) · Inc-3 error re-attribution (`AT-260`…`AT-263`,
    `TC-570`…`TC-572`). **Ids `AT-250`…`AT-279` / `TC-552`…`TC-599` are RESERVED and partly consumed by
    the spec — take the rest from there, and re-derive the HLR/LLR high-water before adding any.**
    Three premises carried as `assumed — verify at Inc-1`: **P-16** can the preamble be refused (if TRUE,
    `HLR-108`'s V-invariance clause must be restated — a requirement-strength change, surface it at the
    gate) · **P-17** does the appendix cap drift a golden · **P-25** does the reservation floor starve a
    legitimate single-variant report.
  - **▸ (P2, NEW — found at batch-75 Phase 2, out of scope there) a non-integer `context_bytes` makes the
    Generate button do NOTHING.** `screens.py:1717-1719` logs and returns with no status, no toast, dialog
    still open — where an out-of-**domain** integer produces a clear `Report rejected:` line. Asymmetric
    and silent.

### 🗒 batch-75 CHARTER (original, superseded by the block above — kept for lineage)

> **Why this block exists.** batch-74 was re-scoped at the 3-iteration cap to **OB-4 + the `Address`
> cell**, and **F4 + D2 were split out**. A split is only honest if the measurements survive it —
> otherwise it is a deletion with better manners. **Everything below was executed during batch-74 and
> is not re-derivable for free.** Whoever opens batch-75 starts here, not from scratch.
>
> ⚠ **Re-derive every number before you gate on it anyway (C-39).** These are batch-74's measurements
> on batch-74's tree. They are a starting point and a cross-check, not a substitute for execution —
> that rule is exactly what turned seven of this area's inherited premises FALSE.

  - **▸ (MAJOR/HIGH — batch-75, F4) the document is NOT budget-bounded, and `_ByteBudget` as currently built cannot bound it.** **The load-bearing finding, executed: `emit()` (`report_service.py:2215-2217`) calls `budget.consume(...)` only — it ACCOUNTS, it never GATES.** `emit(_modifications_lines(...))` at `:2243` has already fully evaluated the producer before `consume` is reached. So "charge the tables to `_ByteBudget`", which this backlog recommended twice, closes **nothing** on either axis. **Five producers stay on that ungated `emit`:** `_modified_files_lines` (`:2242`), `_declaration_error_lines` (`:2244`), `_entropy_lines` (`:2250`), `_addendum_lines` (`:2252`), and the hexdump notes. **Measured:** `_declaration_error_lines` alone = **315,912 B/variant** at 500-char issue fields (capped at 200 *issues*, not at *bytes*); document floor `2,097,152 + V × 315,912` → **1.15× budget at V=1, 2.51× at V=10, 16.06× at V=100**. **This is why batch-74 refused to close F4:** an honest per-row gate on two producers while five siblings stay ungated would be a bound in name only, and batch-74's own `HLR-106`/`AT-227` were withdrawn for exactly that over-claim after all three review lanes found it independently.
  - **▸ (MAJOR — batch-75, F4 companion) the variant count `V` and the per-variant check-file count `F` have NO cap anywhere.** `O(V × F × 7)` structural lines are ungated. `R-TUI-101` caps rows **per variant summed across check files**, which bounds `F × CAP` rows — it does **not** bound the `7` structural lines each check file emits regardless. Any batch-75 document bound must carry a `V`/`F` term or say why it does not.
  - **▸ 🔻 RE-TRIAGED MAJOR → P3 (HARDENING) 2026-07-31 — D2 is NOT reachable through any shipped path, and the severity it carried was inherited from a headline that has now been refuted twice.** Operator-requested re-triage after batch-75 killed **P-14** (*"the D2 `Length` defect is wire-reachable"*, raised by its own Phase-1 architect lane). **Re-executed independently on `038dfd9` rather than taken from the spec:** `ChangeSummaryEntry` and `CheckRunEntry` are constructed at **exactly two sites in the whole package** — `changes/apply.py:342` and `changes/check.py:379` — and **both** pass `address_start=start, address_end=end` unpacked from `entry.addressed_range`, which `ChangeEntry` defines as `(address, address + len(encoded_bytes))`. So `end − start == len(encoded_bytes)` **always**, bounded by `MF_RUN_LENGTH_CEILING = 1_048_576` (`changes/io.py:232`) → **7 decimal digits against a 4300-digit limit**. The negative-`Length` arm is constructor-only for the same reason (`len(...) ≥ 0`). **The architect lane's error was a category error, worth keeping:** it computed `a − b` from two arbitrary huge addresses — a pair ingestion cannot construct — because `addressed_range` belongs to `ChangeEntry`, a *different class* from the two entry types the writers actually hold. **What survives at P3:** the two entry classes take independent endpoints with **no `__post_init__` validation**, so the defect is real in the *constructor domain* — library-contract hardening, not an operator-facing defect. **RECOMMENDATION, not a ruling: keep D2 inside the `R-TUI-102` implementation anyway.** Its ATs are already authored and gated in revision 2, and the cheapest moment to ship hardening is while the file is open; ripping a story out of a gated spec costs a re-gate and risks the split-becomes-deletion failure. **What the re-triage changes is the COUNTING, not the plan** — D2 must stop being carried as one of the MAJOR cluster, because a severity nobody re-derived is how this area accumulated eight false premises. Implementation detail preserved verbatim below.
    **▸ (was MAJOR — batch-75, D2) the inline `Length` cell + the `app.py` error re-attribution.** ⚠ **There is no `_format_length` symbol** — an earlier draft of this charter named one (0 hits in the package, caught at the PR gate). The site is the inline expression `{entry.address_end - entry.address_start}` inside `_modifications_lines` and `_checklist_lines`; whoever takes D2 must CREATE the formatter, not find it. Full statement, and the **correction to its headline**, in the D2 bullet above. Carry these three, all executed: (1) the boundary literal is **not stable** — under `-X int_max_str_digits=1000` it moves from 3572 to 831 — so an acceptance must derive the width from `sys.get_int_max_str_digits()`, never hard-code it; (2) a bare-hex fallback is **forgeable as a decimal numeral**, so the predicate must be `^-?0x[0-9A-F]+$` — and **regex membership is the wrong shape**: `f"0x{abs(n):X}"` renders a positive token for a negative length and satisfies it, and `lambda n: "0"` passes too, so it must be **token EQUALITY against an independently derived string**; (3) the two sites take **disjoint inputs** (`change_summaries[].entries` vs `check_results[].entries`), so one AT cannot bind both. **The `app.py` half is CERTIFIED CLEAN to re-route** — batch-74's architect lane executed the sweep: the only `raise ValueError` in `variant_execution_service.py` is `:650` (unreachable — `app.py:4127` passes the constant), every `ValueError` in `report_service.py` is inside `ReportOptions.__post_init__`, and malformed operator files are **collected** as `ValidationIssue`s, never raised. **No legitimate operator-input `ValueError` is re-routed by the fix.** Bonus already identified: it also fixes the `:4144` tuple-unpack arity error currently surfacing as "Report rejected".
  - **▸ (MAJOR — batch-75 or later) `_applied_regions` (`report_service.py:1288`) is a THIRD unbounded producer.** Peak **16,128 → 160,992 B** at `N = 2000 → 4000`. Fenced out of batch-74 explicitly; it is why a whole-report residency acceptance was **unsatisfiable** there (**P-23**) and would be unsatisfiable in batch-75 too until this is bounded.
  - **▸ (P2 — batch-75 hygiene) truncation notices do not reach `## Truncation appendix`.** `R-TUI-101`'s two new emitters take the count from 3 to **4**, following `_declaration_error_lines`' inline-only convention. Either route all four to the appendix or state in the requirement that the appendix is not the notices' sink.
  - **▸ (P3 — wording carve-outs owed to `R-TUI-101`) — ✅ DISCHARGED at batch-76** (PR #184). All four folded into `REQUIREMENTS.md`'s `R-TUI-101` section, which is where they always lived and which batch-75 never opened: (1) *"the total"* = the **kept** total; (2) `LLR-105.7` gains its non-`None` carve-out, because as written it was **literally false** for `values=None` (`"-"` is in none of the three sets); (3) the *"maximum elided count"* is defined, with its **byte-vs-digit** unit mismatch named as a deliberate upper bound rather than an equality; (4) a per-check-file notice carries **its own** file's numbers. *Historical text follows.* ~~ batch-75 was ruled **spec-only** by the operator and **never edited `REQUIREMENTS.md`**, which is where all four carve-outs live — so there was no honest opportunity to fold them. They are **not** discharged. The batch that implements `R-TUI-102` touches `REQUIREMENTS.md` in all three increments and **is the right place to fold them**. *(Charter non-negotiable #8 required these be discharged **or** declared open; this is the declaration.)* Original text follows.
    **▸ (P3 — wording carve-outs OWED to `R-TUI-101`, found by implementing, not by review.** (1) `LLR-105.5`'s *"the total"* is ambiguous — kept total or pre-filter population? Resolved **in code** as the **kept** total, for consistency with `LLR-105.4′`. (2) `LLR-105.7`'s set-inclusion is **literally false for `values=None`** — `"-"` is in none of the three sets; it needs a non-`None` carve-out. (3) `LLR-106.3`'s derivation contains an **undefined term** — *"len(cue at the maximum elided count)"* never says what that count is; batch-74 defined it as `READ_SIZE_CAP_BYTES − REPORT_ADDRESS_HEX_DIGITS`. (4) `LLR-105.2` mandates a per-check-file notice but never says **whose numbers** it carries; batch-74 ruled per-file. Fold these into the requirement text when this area is next open.

### Residuals OWED by `R-TUI-098` — the requirement states them; they are tracked here

> These were first written with the requirement's `(a)`…`(f)` non-claim letters. **Three of the six were mis-lettered**, so a later batch grepping for a letter would have landed on the wrong residual. The letters are removed deliberately — match these by CONTENT against `REQUIREMENTS.md`'s `R-TUI-098` section, which is the shipped artifact and the one `TC-497` greps.

  - **▸ (MAJOR/HIGH — `R-TUI-098` residual) the `R` multiplier is RELOCATED, not removed.** Recovering region identity for a candidate inside an enclosing declared region costs `O(R)` worst case, because the attribution walk is a prefix-max **array**. Measured under a `huge+tiny` geometry (one enclosing region + `R−1` narrow ones), 500 candidates producing **one** hit: region ops **500 / 4000 / 32000 / 128000** at `R = 1/8/64/256`. `TC-498` pins this as `A == R × N` — deliberately a **disclosure counter, not a pass/fail bound**, because no `R`-independent `c` exists for `A ≤ c(N+hits)`, and a gate that cannot pass is the same defect class as one that cannot fail. **Reversal trigger, already named in spec §15:** a max-segment-tree removes it at `O((1+k) log R)`. The residual is an accepted, reversible implementation choice, not an inherent limit — and `TC-498` fails loudly if a future change alters it, forcing this line to be rewritten.
  - **⚠️ PARTIALLY DISCHARGED by batch-74 — and this is the discharge the bullet demanded.** (`R-TUI-098` residual, was MAJOR/HIGH.) `R-TUI-101` re-asserts a memory bound over `report_service`'s two row producers, so per this bullet's own closing sentence it must state exactly what it closes: **cardinality + per-cell byte-run width, on both producers, plus the `Address` cell**. It does **not** close the emitted-bytes gate (F4), the uncapped `V` and `F`, or `_applied_regions`. Its **`988 B/entry`** figure is corrected to **`≈ 92 + 6·L`** (988 is its value at `L ≈ 149`; **140.1 / 126.1 B/entry** at an 8-byte run) — see `REQUIREMENTS.md` `R-TUI-098` non-claim (a), amended. *(original text)* `_modifications_lines` and `_checklist_lines` remain unbounded at a measured **988 B/entry** and dominate at ordinary `R` and `V`. That is the OB-4/F4 pair below; batch-65 deliberately left them and made no whole-report claim, which is why the security lane cleared it unconditionally. **The moment any batch re-asserts a memory bound over `report_service`, this is the line it must discharge.**
  - **▸ (MAJOR — `R-TUI-098` residual) `B-3(b)` is REDUCED, not eliminated** — from `R×V×E` to `V×E`. One pass is irreducible: the candidates are unsorted lists with no address index, so a zero-match region no longer pays `R` passes but still pays one.
  - **▸ (MAJOR — `R-TUI-098` residual) intra-class and cross-variant eviction are DISCLOSED, not PREVENTED.** All three hit classes are document-derived (`changes/apply.py:363`, `changes/check.py:399`), so the attacker owns every class's cardinality, and within a class first-K in attacker-controlled document order still decides what is shown. The control shipped is the **notice naming the cut classes and the DROPPED variants** — verified to name only variants that actually lost hits, never mere contributors. **Prevention was priced and declined:** severity-priority admission lets an already-admitted hit be evicted later, destroying per-variant contiguity and turning the `O(1)` last-seen sentinel into an `O(V)` membership set — prevention on the severity axis costs the `V`-independence claim on the memory axis.
  - **▸ (P2 — `R-TUI-098` residual) `options.declared_regions` has NO cardinality cap anywhere.** The only cap is `DECLARED_REGION_NAME_MAX = 80`, which bounds a region's NAME, not the region COUNT (`report_addendum.py:26`). `R` is manifest-fed and bounded only by `READ_SIZE_CAP_BYTES` (256 MB). `MAX_DECLARED_REGIONS` genuinely does not exist — verified at Phase 4, not assumed.
  - **▸ (P3 — `R-TUI-098` residual) the notice's variant list is capped at 8 + `+N more`** (`report_service.py:1849`), so the notice never reintroduces a `V` term. The `+N more` count is exact; only the enumeration is bounded.
  - **▸ (P2, batch-65 Phase-4 F-4) the ten mutant arms are NOT re-runnable from the tree.** The harness lived in a scratch export, yet spec §6.3 makes their reproduction a gate condition — so the roster in `REQUIREMENTS.md` is a **record**, not something a later batch can re-execute. Inc-3 showed the alternative by making its head-of-line-guard control permanent (`test_head_of_line_guard_detects_a_planted_violation`). Do the same for the arms whenever this area is next open.

  - **▸ (P3, batch-65 Phase-4 G-1) duplicate / equal-start-nested region geometry is verified WHITE-BOX only.** `TC-487` observes the M-times emission through `_addendum_lines`, not through the written file. Non-gating because it is a *preservation* property whose document-level consequence would break `AT-196`'s byte identity on a golden shape — but the black-box arm does not exist, so that argument is transitive, not direct.
  - **▸ (P3, batch-65 Phase-4 G-2) the addendum's line-count bound is verified WHITE-BOX only.** `TC-483` asserts `addendum 208 lines ≤ bound 607` through `_addendum_text`. The *behavioural* consequence (≤ K hit lines at `K+1` and at 3000) IS observed through the file by `AT-198[K_plus_1]` and `TC-480`, so the gap is the bound itself, not the behaviour.
  - **▸ (P2, batch-65 Phase-4 G-3) three disclosed residual figures sit OUTSIDE `TC-497`'s grep list** — `≈ 11.6 kB/region` among them. `TC-497` is the node that stops the requirement's residual figures decaying silently, so a figure outside its list is exactly the silent-decay path the node exists to close. **Widen the list, or state in `R-TUI-098` which figures are deliberately unguarded.** Related: `TC-497` greps the WHOLE file rather than the `R-TUI-098` section, so a guarded figure can be deleted from the section and stay green if it appears anywhere else (merge-gate MEDIUM, executed mutant).
  - **▸ (MAJOR, NEW — found at batch-74 Inc-3, EXECUTED) `TC-497` cannot tell an ASSERTION from its REFUTATION.** It greps `REQUIREMENTS.md` for residual figures **verbatim**, so *"the two tables cost `988 B/entry`"* and *"the flat `988 B/entry` quoted here is **FALSE**"* satisfy it **identically**. batch-74 rewrote non-claim (a) to say the figure is false — correcting it to `≈ 92 + 6·L` — and **`TC-497` stayed green**, which is the proof, not the hypothesis. A guard that a document can satisfy by stating the opposite of what the guard exists to preserve is the house defect of this area, one level up: *the predicate does not test what its label claims*. **The fix is not a bigger grep list.** A presence-grep can only ever pin a token; pinning a *claim* needs the figure bound to its subject — e.g. assert the figure appears **within the `R-TUI-098` section** (`TC-497` currently greps the whole file — already noted below) **and** that no refutation marker (`FALSE`, `superseded`, `corrected to`) occurs in the same paragraph. Take it together with the two `TC-497` scope defects listed below; they are one node's worth of work.
  - **▸ (P3, batch-65 Phase-4 F-3) an Inc-3 transcript count does not reproduce.** `increment-003.md` §4.1 pastes `4 '988 B/entry'`; the shipped document has **3**. Non-gating — `TC-497` asserts presence, not count — but a pasted number that does not reproduce is the defect class this batch spent two gates removing, and it went missing because `05-postmortem.md`'s metrics row miscounted the Phase-4 tally as "3 folded, 1 carried" when it was 2 folded + 1 carried + 1 undispositioned.

### New defects found in passing at batch-65 — NOT this batch's scope

  - **▸ ~~(MAJOR, NEW — live defect in shipped code) the one-candidate bisect is unsound over overlapping ranges~~ — DONE, batch-73** (PR pending merge; branch `claude/batch-73-linkage-fix-0372a0`, base `d81cb3d`). Fixed by normalizing `_linkage_index` to emit a **disjoint cover** that preserves per-span symbol ownership, so the probe's declared disjointness precondition holds by construction. `R-CHG-002` amended (Amendment A) with a normative **first-by-start** tie-break; `AT-220`..`AT-223` / `TC-521`..`TC-524` in `tests/test_linkage_soundness.py`. **Three corrections to this bullet, all executed at `d81cb3d`:** (1) it named the **wrong function** — `_linkage_index` (`:438`) contains no bisect; the unsound probe is `_first_intersecting_symbol` (`:470`, bisect `:513-518`). (2) The `report_filter.py:737` pattern it recommends **loses the symbol** — `_merge_ranges` coalesces away which symbol owned which span, and this probe returns a name; **not adopted**. (3) The defect was **not** confined to A2L: two MAC records at one address are an overlap too, and `examples/professional_validation/case_07_cross_reference_inconsistencies/firmware.mac:6-7` ships exactly that (`ALIAS_1`/`ALIAS_2` at `0x80200010`) — pre-fix the operator was shown the **last** alias. Measured impact: over randomized overlapping ranges the pre-fix probe answered wrongly on **12 123 / 48 000** probes (25.3%); over disjoint ranges the fix is **bit-identical** across 48 000 probes. **No stored evidence was contaminated** — the four committed goldens carrying a `Linkage` column were instrumented against a ground-truth oracle before any code changed: 490 probe calls, **0** over an overlapping index, **0** divergences.
  - **▸ (CLEARED — recorded so it is not re-audited) the same defect does NOT reach `validation/engine.py` or `tui/hexview.py`.** Ranges in `validation/engine.py` come from `core.py::get_memory_ranges` over a sorted unique-key dict → disjoint by construction (9 real fixtures, 0 overlapping pairs, including `case_03_overlapping_records`); `hexview.py` is a pure re-export facade that builds no range set. `screens_directionb.py:1889` also cleared — its runs are forced disjoint by `compute_entropy`'s tiling and `_merge_band_runs`' exact-adjacency rule (206 fixtures, **89 032 addresses swept, 0 attribution mismatches**). **An earlier claim in this project naming those first two as at-risk was WRONG and is withdrawn.**
  - **▸ (P2, security S5 fold 2 — REJECTED with reasons, carried) a dropped-severity histogram in the truncation notice.** Rejected because **the field does not exist for 1 of the 3 hit classes**: `ChangeSummaryEntry` (`changes/model.py:321-373`) has 8 fields and no severity; only `ValidationIssue` has one. A notice field undefined for a third of what it describes is worse than no field. Revisit only alongside a severity model that also covers modification entries.

## P1 — open features

- **✅ N4 — Memory Map interaction split + clickable bands — DONE (2026-07-28, batch-67 Inc-3/Inc-4, `/fast-dev-flow` autonomous+self-merge).** Single click now INSPECTS a region, double click OPENS IT IN HEX; the entropy band strip is clickable with the same semantics. **The queued premise was imprecise and disk corrected it:** single click ALREADY populated the detail inspector (batch-47 R-TUI-074, `screens_directionb.py::on_region_row_activated`) *and* jumped to hex — so the work was a **split**, not a new details surface, and **no design pass was needed**. Mechanism: `RegionRow.on_click` forwards `events.Click.chain` on `Activated`; the panel navigates only at `chain >= 2`, so the policy lives in ONE place. New `BandSegment` is a deliberate **sibling** of `RegionRow`, not a subclass — Textual's `query(Type)` matches subclasses, so subclassing would have silently widened every existing `app.query(RegionRow)` call site (pinned by an AT). Gap hatches stay inert. `_DETAIL_HINT` updated (it claimed single-click jumps to hex) → 1 snapshot cell regenerated in canonical CI. C-31/C-32 discharged properly: the counterfactual was NOT accepted from the base tree (there it dies on a `TypeError`, proving nothing) but from **reverting the guard on a copy of the fixed tree in an isolated worktree**, where AC-3 and AC-5 both fail on their assertions. ATs `tests/test_map_click_chain.py` (8).
- **✅ Universal paste — DONE (2026-07-28, batch-67 Inc-1/Inc-2).** All **16** stock `Input` constructions across 5 modules converted to `OsClipboardInput` (`app.py` 8, `command_bar.py` 3, `screens.py` 3, `screens_directionb.py` 1, `crc_designer_view.py` 1 — the last is `_field_row`, the shared helper behind every CRC Designer field). `Input` stays imported for `query_one(..., Input)` and `Input.Changed`, which keep working because `OsClipboardInput` is a subclass — zero call sites changed. Guarded by an **AST census swept over the whole package** (not a hand-kept list), so a NEW module reintroducing a stock `Input` fails without anyone registering it, plus a synthetic positive control proving the census discriminates constructions from references. `tests/test_universal_paste.py`.
- **Issues Report v2 — filter (name/type) + sort.** PARKED — operator never picked a tier in the v2 prototype verdict. Data (`symbol`/`code`/`severity`) already on each row; only a 3-way severity filter today. `app.py:6564`, `issues_view.py:173`. *(B1 PgUp/PgDn no-op ✅ FIXED batch-49 #94.)*
- **CRC Algorithm Designer** — keel (batch-57 #110) + **Variant B VIEW + engine E4/E5/E6 (batch-58) DONE** (see DONE section). **DEFERRED follow-up (operator 2026-07-21): wire the width-general kernel into the shipped `crc.py` operation** — a result-identical `crc32_stream` refactor (E1 wrapper). The preview-only view uses the kernel directly; the shipped 32-bit operation is untouched. `/fast-dev-flow` when picked up.
- **🟩 N5 — Long-running actions have NO progress/load-bar status — PARTIAL/DONE (report-gen) (2026-07-23, `/fast-dev-flow`, branch `fix/n5-progress-indicators` off `d1d0285`).** **Phase-A disk finding:** the file **load** path ALREADY drives the persistent `#progress_bar` (`set_progress` 10/50/100) — a load indicator would be redundant. The real gap was **report generation**: the off-thread worker used only `set_status` and left the bar at its prior value (e.g. `100` from the last load → read as "done" mid-report). **Shipped:** `set_progress` at the 4 report seams — kickoff `_trigger_generate_report`→15, worker-mid→55, success `_finish_generate_report`→100, reject/crash→0 (reset, never stuck). Reuses the existing determinate bar (no new widget); load progress unchanged. 4 tests (`tests/test_report_progress.py`), RED-verified; 37 report-related regression green. **Carries (N5 follow-ups):** ▸ **✅ before/after + diff report — DONE 2026-07-28, batch-68 (PR #154, squash `5809822`).** ⚠ **The carry's own framing was WRONG and the correction is the reusable part:** it said "same `set_progress` pattern", but `app.py` had exactly **three** `@work` methods and neither report handler was among them — `compose_before_after_report`, `generate_diff_report` and `generate_diff_report_html` all ran **on the Textual event loop**, so the TUI froze outright for the whole composition. *You cannot drive a progress bar from the thread you are blocking*, so the threading fix was upstream of the progress work, not parallel to it. Both handlers now dispatch to `@work(thread=True, exclusive=True)` workers matching the shipped `_start_generate_report_worker` template; progress at 3 seams (before/after: 15/100/0) and 4 seams (diff: 15/55/100/0, with **each** of the three failure arms resetting — the HTML-refused-after-md-succeeded arm parks the bar at 55 if forgotten). **The AT oracle is THREAD IDENTITY, not a progress value**: a handler that sets 15, blocks the loop, then sets 100 satisfies every progress assertion while still freezing the UI. `tests/test_report_off_ui_thread.py` (4), all RED on the base each on its own assertion (`assert 48008 != 48008`). ▸ CRC compute-over-large-coverage progress — **still open**. ▸ A2L enrichment/validation progress — **still open but SMALLER than written**: the A2L **load** path already drives 10/50/100 (`app.py` `load_a2l_from_path`, measured at the batch-67 review); only intra-parse granularity is missing. ▸ (optional) an "active vs idle" visual state / true-percent signal if a step-count becomes available.

## Flow Builder (rail-8, multi-batch)

> **Reconciled 2026-07-21** against the operator's original `/prototype` request (2026-07-19 session) + the memory batch plan (`project_flow_builder_batch_plan.md`). Items 4-6 below were only in memory/ADR and had NOT been written into this canonical queue — now captured + prioritized. ADR: `.fast-dev-flow/ADR-flow-builder-tracer.md`. Prototype artifacts: `prototypes/flow_builder.*`. TUI direction chosen = **"Pipeline Ledger"** (Direction A).
>
> **SHIPPED so far (do NOT redo):**
> - **batch-44 tracer**: `SOURCE → PATCH → WRITE-OUT` runnable vertical (`flow_model.py` + `flow_execution_service.py`, `FlowBuilderPanel`).
> - **batch-51** ([#101](https://github.com/jav201/s19_app/pull/101) `640de1b`): **LOAD** block (external image → saved to project; integrity findings as WARN **notices**, never aborts) + **CHECK** block (read-only, passes image through) + `completed-with-issues` amber status (surfaces in reports) + "Pipeline Ledger" render + per-block gating selector. NEW global control **C-36**.
> - **batch-52** (`3022abd`/`ba9e138`/`71c7f13`): **CRC** block (compute/inject over post-patch image, address-space growth, ordering WARN, fail-close) + before/after twin ribbon + F3 + G-1. Detail in FB-P0 (DONE) below.

### Flow Builder — shipped (do NOT redo; carries noted inline)

**✅ FB-P0 — batch-52 = CRC block — DONE (2026-07-23, `/dev-flow` autonomous+self-merge, off `6e64c48`).** Template-driven CRC block as the 4th typed Flow Builder block (`SOURCE→PATCH→CRC→WRITE-OUT/CHECK`): computes over the post-patch threaded image via the reused kernel (`parse_crc_config`→`check_regions`→`inject_crcs`), **grows** `(mem_map,ranges)` when the output window is outside loaded ranges, threads the extended image forward; CRC-before-PATCH (or no-PATCH) = non-blocking WARN; malformed/unsafe `config_ref` = fail-close (containment via reused `_resolve_manifest_entry`). Ships the §6.5 AMD-1 before/after **twin ribbon** (shared-axis `pre_crc_ranges`→`image_ranges`), F3 gating-hide-for-non-CHECK, G-1 empty-flow. **NO crc.py refactor** — the ADR §7 seam was already split (`inject_crcs` is the pure grow-stage); crc.py/crc_config.py byte-unchanged (frozen-safe). 3 incs (`3022abd`/`ba9e138`/`71c7f13`), 19 ATs/TCs (AT-123..129 + TC-346..361), full suite **1840 passed** (0 regression; 19 tc016s snapshot fails = pre-existing batch-58/59 drift, not batch-52). Artifacts `.dev-flow/2026-07-22-batch-52/`. **Carries:** ▸ **FB-P3** CRC-as-subflow (deferred — single block proved the contract) ▸ R-2 one-ribbon-pair-per-flow (accepted, reversible) ▸ `/dev-flow-sync` for b52.
**✅ FB-P1 — batch-53 = `flow.json` persistence — DONE + MERGED (2026-07-24, `/dev-flow` autonomous+self-merge, RESUMED fresh session from the Phase-3 pause checkpoint; PR [#129](https://github.com/jav201/s19_app/pull/129)).** Save/load/import a Flow to `.s19tool/workarea/<project>/flows/<name>.json` (multiple named flows, reusable across a file + its variants). New Textual-free `flow_persistence_service.py`: `flow_to_dict`/`dict_to_flow`/`load_flow_json` (hardened untrusted loader — size-cap-before-parse, type-strict schema + strict-keys, fail-closed WHOLE-flow, every READ ref re-validated through the REUSED `_resolve_manifest_entry` never forked, `FLOW-UNSAFE-REF` drive-relative pre-reject, reject-arm census `REJECTING_CODES`) + `save_flow_json` (`sanitize_project_name` = write-side containment) + `list_saved_flows` + `import_flow_file` (thin seam binding `copy_into_workarea(..., max_size_bytes=FLOW_SIZE_CAP_BYTES)` — copy-not-execute, C-12). UI: `FlowBuilderPanel` name-strip (glyph `●`/`✓` dirty tracking, C-10) + Save…/Load… row + `SaveFlowScreen`/`LoadFlowScreen`/`ConfirmDiscardScreen` modals + quarantine card (C-32 painted, C-17 `safe_text`) + `_flow_block_label` REPORT arm + dirty-guard confirm-discard. NEW ref-less **`ReportBlock`** (model+persist+run_flow no-op only). 5 incs (`b056036`/`2f9607b`/`a749054`/`637dc9d`/`87283db`), 47 new tests (data + UI pilots), C-34 full directionb 185 pass, C-38 union sweep, **0 batch-53 regressions** (full non-slow 1914 pass; the 19 tc016s snapshot fails PROVEN pre-existing by base differential @ 4f4f20f — the batch-58/59+#128 CRC-snapshot-drift carry below). FINAL gates 0-HIGH (security + qa). Artifacts `.dev-flow/2026-07-24-batch-53/`. **Carries:** ▸ **FB-P1b (NEW, P1) = report GENERATION** — batch-53 ships the `ReportBlock` model+persist+no-op ONLY; generating report content (report_service→flow_execution_service wire + the "every flow generates its report" invariant) is a NEW batch (operator RB-model decision). ▸ qa M-3 (static `from_markup` scanner over `render_quarantine`, defense-in-depth; behaviourally covered by AT-006 `spans==[]`). ▸ `/dev-flow-sync` for b53. ▸ RISK: `LoadProjectScreen`'s `label_widget.text` stem-recovery is latently fragile (fixed here for `LoadFlowScreen` via `ListItem.name`).
**✅ FB-P1b — batch-60 = flow-run report GENERATION — DONE + MERGED (2026-07-24, `/dev-flow` autonomous+self-merge, plan/prototype-first; PR [#131](https://github.com/jav201/s19_app/pull/131)).** A flow containing a `ReportBlock` now GENERATES content (batch-53 shipped the block as model+persist+no-op). New Textual-free `flow_report_service.py`: `compose_flow_report` (header + Pipeline ledger + Findings **and diagnostics** + Image footprint incl. the before/after CRC growth + Written files) + `write_flow_report` (REUSES `report_service._report_filename` + `REPORTS_DIR_NAME`, so the file matches `REPORT_FILENAME_REGEX` and the SHIPPED `list_project_reports`/`ReportViewerScreen` surface it with **no new viewer**). Wired at the `run_flow` ReportBlock branch; the `if aborted:` skip guard now EXEMPTS ReportBlock so a broken run still writes its FAILED record. Semantics: **explicit** trigger (only with a ReportBlock) + **positional** (state up to the block) + N blocks allowed + path shown in the panel ledger. 3 incs (`e0521cb`/`3c2f80f`/`e8ef802`) + 2 gate-hardening commits (`b617b50`/`e172fb3`); 53 tests; **1970 passed / 0 batch-60 regressions** (19 tc016s = the pre-existing drift below; C-34 gate confirmed **0 NEW drift** from the viewer change). Artifacts `.dev-flow/2026-07-24-batch-60/`.
>
> **Phase-2 gate FAILED then resolved (AMD-1..14) — the batch's main value.** Two independent reviewers found the approved prototype escaped for the WRONG GRAMMAR: the sink is `MarkdownIt("gfm-like")` with **linkify enabled**, so a bare `http://…` autolinked and `~~x~~` struck a ledger row through (forgery in an audit record). Plus: operator decision D-6 was **unimplementable** at the specified wire point, and the status rollup keyed on a string matching **1 of 9** real abort sites. All three fixed in the CONTRACT before any code existed. The AT was rebuilt to assert the REAL parser's **token stream** instead of a character list.
>
> **Carries:** ▸ **`report_service` markdown escaping (P1, own batch)** — `generate_project_report` embeds file-derived text (variant ids, filenames, declaration errors) with **NO escaping at all** against the same linkify sink. batch-60's hardened viewer parser blunts it at render time, but the shared `.md` is still unescaped. Same class as the hole batch-60 just closed. ▸ strikethrough survives the hardened parser (a gfm-like plugin, not an option) — rides with the above. ▸ AT-002 could drive `ReportViewerScreen` end-to-end (partially done as AT-002b, which renders through the viewer's parser). ▸ `report_service` renders no `diagnostics` either (the same gap batch-60 fixed for flow reports).

### Flow Builder — open

**✅ FB-P2 — PATCH dual-entry — DONE (2026-07-28, batch-67 Inc-5).** **The premise was half-wrong and disk said so before any code was written:** the change-doc input WAS already surfaced in the Flow Builder (block-kind option "Patch (change doc)" + the project-relative ref box, since the batch-44 tracer), and the Patch Editor has the richer `#patch_doc_file_select` picker. So "confirm it is surfaced" was already YES. **The real gap was that nothing PINNED the two surfaces to the same behaviour** — they could drift silently. Closed with a convergence oracle (`tests/test_patch_dual_entry.py`, 4 tests, **zero production code**): the emitted `.s19` read back from disk must be byte-identical from both paths (not the summary object — two paths can agree on counts while writing different bytes); a positive control proving the patch is not a no-op (**it earned its place — the first run had both paths agreeing perfectly on nothing**, because the fixture used a guessed format id); a structural identity check that both modules reach the SAME `apply_change_document`; and a pin on the one asymmetry found (`ChangeService.apply` refreshes `collision_issues` first, the flow path does not — equal for a disk-parsed document, asserted so a future editor rule change fails loudly). Documented in **ADR §11** (`.fast-dev-flow/ADR-flow-builder-tracer.md`).
**✅ FB-P2 — multi-image scope + report fusion — DONE + MERGED 2026-07-29 (batch-70, PR [#159](https://github.com/jav201/s19_app/pull/159) squash `b457ef8`; pre-squash `ebca4cc` · `4573d43` · `2b6c3a5`). CI green at merge: `tui-ci` + `snapshot` both pass.** Shipped as **R-TUI-099 / HLR-104 / LLR-104.1…104.7**, all seven ACs observed (`AT-205`…`AT-211`) plus D-4 as an artifact-on-disk count and LLR-104.6 through the real Run button. Branch `claude/fb-p2-batch-70-impl-92b3cd` — the Phase-0 branch `claude/fb-p2-batch-70-bfc118` was fast-forwarded into it, so all nine Phase-0 commits are in the PR. **+36 collected** (35 new nodes + 1 auto-parametrised — `test_universal_paste.py::test_ac1_…[flow_fused_report_service.py]`, a pre-existing per-module guard that adopted the new module by itself).

> **The two things worth carrying from the implementation:**
> - **Premise P-2 came out FALSE and it was the load-bearing one.** The design said "`SourceBlock.image_ref` is overridden per variant by the planned image" without saying in what FORM. `VariantDescriptor.path` is **absolute** and `_resolve_manifest_entry` **rejects absolute refs by design** (`variant_execution_service.py:263-272`, executed) — so the obvious binding fails 100% of variants, and the tempting "fix" is to bypass the seam, which is precisely the containment fork §7 forbids. `_bound_source_ref` derives a project-**relative** POSIX ref instead. This is also what makes AC-7 reachable: *a path that will not relativise IS the containment rejection*.
> - **D-4's second half had no owning increment.** The inherited increment table assigned "one fused report, per-variant sections" to Inc-2 but never assigned "**no per-variant files**" to anyone — and with a REPORT block each variant's `run_flow` would have written its own, i.e. V files, the exact manual collation FB-P2 exists to remove. Every composer-level test would still have passed, because the defect is a **count of FILES**. Closed with `FlowContext.defer_report` + an artifact-on-disk acceptance.

**New carries from batch-70 (both P3, both stated in `REQUIREMENTS.md` R-TUI-099 as non-claims):**
- **✅ (was P3) AC-6 has no byte-golden — DONE + MERGED 2026-07-30 (batch-71, PR [#161](https://github.com/jav201/s19_app/pull/161) squash `4753589`)** (`AT-212` / `TC-509` / `TC-509b`, golden `tests/goldens/batch71/ac6-unscoped-flow-report.md`). ⚠️ **The carry as written would have produced a VACUOUS test and disk said so first:** it proposed a golden "captured from `origin/main`", which for the *composer* cannot fail — `git diff f1f3987 origin/main -- flow_report_service.py` is **0 lines**. The edited surface is `flow_execution_service.py` (**+263 / −5**, two deletions on the unscoped SOURCE path), so the golden is taken **end-to-end through `run_flow`** over a flow exercising every block kind, and the baseline is **`f1f3987`** — the commit *before* FB-P2 merged, not `origin/main`, which now contains the very change under test. Driven RED on a copy of the fixed tree by leaking the variant into the default path.
- **▸ (P3) the fused document's `O(V × ~6 lines)` heading overshoot is unbounded by the byte budget.** Each variant's heading/status/footprint/cut-notice is emitted **outside** the budget gate so no variant can vanish (AC-5) — deliberate, but it means a project with very many variants can exceed `FLOW_REPORT_MAX_TOTAL_BYTES` by that margin. No node drives V high enough to observe it.
- **▸ (P3, extends the existing AST column-0 guard carry below)** that carry already says the guard should run over `flow_report_service.py` as well as `report_service.py`; **`flow_fused_report_service.py` is now a third composer** and belongs in the same sweep.

*Superseded planning entry (kept for lineage):*

> **batch-70 Phase 0 corrected the inherited design TWICE — both folded into ADR §12 / spec (`b037186`).** Ten design premises were executed against disk; eight held exactly (including the `971`/`531` line counts and the `:343` address). Two did not:
> - **F-1 ❌ the "seam marker" is FALSE as characterized.** ADR §12 and spec §2 read `flow_execution_service.py:343`'s `variant_id=None` as *"the single-variant assumption is explicit in the code"* and concluded FB-P2 is *"mostly threading an existing dimension, not building one"*. The line is real at that address but sits in the **CRC block handler**'s `OperationInput` (`:339-346`); `OperationInput.variant_id` is operations-kernel reporting metadata (`operations/model.py:44-46`). Only three "variant" occurrences exist in the 531-line module: docstring `:7`, the import `:66`, that CRC line. **`run_flow` takes no variant and `FlowContext` has no variant field (`flow_model.py:226-228`) — Inc-1 BUILDS the flow-layer dimension.** Genuinely reused: `_resolve_manifest_entry` (4 sites `:135/:190/:250/:309`) + `plan_variant_executions`. **Real Inc-1 binding points: `run_flow`'s signature, `FlowContext`, and the SOURCE `image_ref` override at `:135` — NOT `:343`.** An implementer trusting the old text wires the variant into the CRC `OperationInput` and believes Inc-1 closed.
> - **F-2 ❓ incompleteness → AC-7 added (operator-approved).** §7 declares the containment constraint **mandatory**, yet no AC-1..AC-6 observed it — AC-2 covers *"variant k aborts"*, and an abort is not a containment rejection. Folding into AC-2 was **rejected**: an AC with two distinct subjects is where batch-65's `AT-197` lost its threshold. AC-7 consumes the **existing** C-31 census `REJECTING_CODES` (`flow_persistence_service.py:117`) rather than building a new oracle. Spec §5 re-cut per **C-21** so AC-7 has an owning increment (Inc-1).
>
> **D-1..D-8 unchanged** — the corrections move the *effort/risk* premise, not any decision.

Original entry (batch-69 design) follows: Run a saved flow across multiple images/variants and fuse the per-image results into one report. **The design batch is DONE and closed every open question** — decisions D-1..D-8 are recorded in **ADR §12** (`.fast-dev-flow/ADR-flow-builder-tracer.md`) with full rationale + 6 observable ACs + a 4-increment plan in the batch-69 spec. **Whoever implements it inherits decisions, not questions — do not re-open them without a reason.** Headlines: the image set is the project's **variant set** (`plan_variant_executions`), never a path list (a list escapes project containment); `SourceBlock.image_ref` is overridden **per run**, the flow file is untouched; **per-variant isolation** (one abort does not kill the run); **one fused report** with per-variant sections; status = worst-across-variants **plus** explicit `n_ok/n_issues/n_error`, because a rollup that cannot be inverted is a summary that lies by omission. **D-7 is non-negotiable and is the reason this got a design pass at all:** the fused report must be bounded **by construction, per variant, in the PRODUCER** — this project has spent batches 62/63/65 on unbounded report producers and one of them exhausted the operator's machine; fusion multiplies row cardinality by the variant count, so shipping it unbounded would be re-committing a measured failure, not discovering one. Scope note (measured): `flow_execution_service` **already** imports `_resolve_manifest_entry` from the variant service and marks the single-variant assumption explicitly at `variant_id=None` — this threads an existing dimension rather than building one. ⚠ Security constraint carried forward: every per-variant ref resolves through the **reused** containment seam, never a fork, and D-3 must not become a containment bypass.
**FB-P2 — 🔐 PKI binary-region extraction from S19 (NEW capability) — ⛔ BLOCKED: awaiting operator definition.** *(`/dev-flow` or `/fast-dev-flow` — needs a design pass first; DO NOT build yet)*. Functions to **extract binaries from specific address regions** of an S19 (its hex content) so the output can feed **PKI / signing infrastructure** (get signatures for the S19 / HEX files). Operator-defined cybersecurity workflow. As a flow block: input = S19 + region spec (JSON), output = raw binary of that region (written to project). Reuses the sparse `mem_map` + `range_index` membership primitive. **⛔ Operator is investigating the exact extraction functions / region-spec format / PKI hand-off — HOLD until operator supplies the definition.** Carry forward every batch until unblocked. Record in ADR §7 roadmap on pickup.
**FB-P3 — 🧩 CRC as a configurable SUB-FLOW of blocks (revisit)** *(`/prototype` first, then `/dev-flow`)*. Re-decompose CRC: the standard CRC steps are fixed, but **fill-of-gaps, memory addresses, polynomial, big/little-endianness** are configurable → model these as their own blocks for flexibility (vs the single template-driven block in FB-P0/batch-52). Bigger design; **deferred until the simple CRC block (batch-52) ships and proves the block contract**. Overlaps the standalone **CRC Algorithm Designer** (batch-57/58/59) — reconcile the two CRC surfaces during the design pass so they share the width-general kernel + template model, not fork.

## ✅ CLOSED by batch-72 (PR [#166](https://github.com/jav201/s19_app/pull/166), squash `1abda8e`) — the four operator-flagged 2026-07-28 TUI design defects

> **ALL FOUR CLOSED by batch-72** (prototypes PR [#164](https://github.com/jav201/s19_app/pull/164) `31d87d0`; implementation PR [#166](https://github.com/jav201/s19_app/pull/166) squash `1abda8e`). Shipped: the paired `Reflection` row, the KAT verdict **demoted** to a `Self-test` row under Check, the `Switch`-separability guard (`AT-214`), and the Legend two-pane body with a key-first floor regime. Registered as **`R-TUI-100`** — which puts the CRC Designer into `REQUIREMENTS.md` for the *first* time; batch-59's bench layout was never registered.
>
> ⚠️ **Line 153's snapshot claim below was FALSE and is corrected here rather than left to mislead a third batch.** It asserts any change "will drift the CRC snapshot cells". Executed probe (batch-72 §2.7 P-2): `tests/test_tui_snapshot.py:109-110` lists `workspace/a2l/mac/issues` + `map/patch/diff` — **the CRC screen is in neither list, and 0 CRC snapshots exist on disk**. Confirmed twice more in execution: 29 snapshots passed at every gate, none regenerated, and `git diff origin/main -- '*__snapshots__*'` is empty. **No snapshot-regen follow-up was needed for either story.** The bullet's *other* premise — that AT-B59-03/08 must be preserved — held exactly; they survive unedited.
>
> Two requirements did **not** survive contact with measurement, and are carried below rather than buried: the Select-height cap (**withdrawn**) and design guard **G-2** (**retired**).
>
> Original capture note: from operator user-testing on 2026-07-28, after batch-67/68. **Premises verified on disk at capture** — each bullet carries its measured mechanism. **The companion skill-side item (why `/tui-design` did not catch these) lives in [`BACKLOG-PROCESS.md`](BACKLOG-PROCESS.md) — routed there, not copied.**

- **▸ (P1, NEW) CRC Designer: two adjacent switches render as ONE control.** Operator: *"hay switches que parecen uno sólo"*. **Root cause measured, not guessed:** `crc_designer_view.py:301-302` stacks two `_switch_row` calls (`Reflect in` `#crc_field_refin`, `Reflect out` `#crc_field_refout`) and `styles.tcss:1952` sets `.crc-field-switch { border: none; height: 1; }` while `.crc-field-row` is `height: auto` with **no row margin or separator**. `border: none` removes the only visual boundary Textual's `Switch` would otherwise draw, so two 1-row borderless switches abut and read as a single wider control. Fix is CSS-level (row margin / restore a boundary / group them under one labelled fieldset), but **it needs a design pass, not a one-line patch** — see the redesign bullet below. ⚠ Touches the batch-59 Variant-B bench layout, so any change must preserve the AT-B59-03/08 signature assertions (`len(distinct bench-column ancestors) == 3`) and will drift the CRC snapshot cells.
- **▸ (P2, NEW) CRC Designer: the known-answer (KAT) verdict field may not earn its place.** Operator: *"existe un campo de CRC known value match. Eso no le veo uso a menos que se conozca el resultado de antemano… nos sirve para revisar contra algún otro programa que genere CRC, pero no como general. Si es así recomiendo que se elimine y se contemple en el rediseño de la pantalla."* **Measured nuance the decision should weigh, recorded so the redesign is not made on a half-premise:** `#crc_kat_verdict` (`crc_designer_view.py:397`, computed `:693` from `CrcAlgorithm.kat_ok`) is not a check against the operator's *data* — it validates the **algorithm definition** by reproducing the published check value for the ASCII string `123456789`, the standard CRC self-test convention. So it does have one real use the report's framing does not cover: confirming a hand-built polynomial/init/reflect combination actually matches the standard it claims to be. **That is still close to the operator's own reading** ("revisar contra otro programa"), and it is a *designer-bench* affordance, not an operational one. **Operator recommendation stands: remove it, or demote it, as part of the screen redesign** — do not delete it piecemeal ahead of that pass, because the verdict is currently load-bearing for AT-058-08 and the batch-58/59 preview-gating tests.
- **▸ (P1, NEW) CRC Designer needs a design pass with explicit design guards.** Operator: *"faltan agregar guardas de diseño"*. The two bullets above are symptoms of the same gap — the screen shipped functional (batch-58) then visually rebuilt (batch-59) with fidelity ATs that assert **structure** (3 bench columns, a rendered hero) but nothing about **control separability or affordance density**. Take `/tui-design` (PROTOTYPE mode) first, then `/fast-dev-flow`. Fold the KAT-field decision into this pass rather than shipping it alone.
- **▸ (P1, NEW) Legend pop-up screens need reorganization and, in places, reimplementation.** Operator: *"las pop up screens con la leyenda necesitan mejor reorganización y otras mejor implementación. Necesitamos checar de nuevo con tui-design."* Scope note: `LegendScreen` has been extended twice without a layout pass — **N1/batch-49** added per-screen filtering (`_SCREEN_LEGEND_SECTIONS`) and **N8/batch-125** added per-view annotated example cards (`LEGEND_EXAMPLES`, `legend.py`) above the colour key, with key rows changed `Label`→`Static` to wrap rather than truncate. Two additive passes, no reorganisation between them. Needs `/tui-design` before code. ⚠ N8 established that the Legend modal is **NOT** `tc016s`-captured (verified at batch-125), so a layout change here does **not** drift snapshots — the cheapest surface in the app to redesign.

## 🆕 New carries from batch-72 (P1 design-defect implementation)

> Every item below is **measured, not proposed** — each carries the executed number that produced it.

- **▸ (P2, new — batch-72 §6.5 W-1) CRC Designer Select chrome density — the `height: 3` cap was WITHDRAWN on measurement; the lever is WIDTH.** The batch specced `#crc_designer_panel Select { height: 3 }` to stop Selects eating 4-6 rows. **Executed on a private tree copy (M-4): at `height: 3` the preset renders `CRC-32/I` — 8 of 15 characters of `CRC-32/ISO-HDLC`, with no ellipsis and no overflow marker — and 4 of the 6 Selects lose their bottom border.** Minimum legible height at the measured 12-col pane width is **5** for the text and **6** for text + intact box, i.e. exactly what `height: auto` already produces. Measured heights today: `6/4/4/4/3/3`. **A cap that makes a control lie about its value is worse than the density it fixes** — so the density finding is real and open, but the fix is a bench-column **width** change (15 chars need ~19 cols inside this Select's padding + arrow), which redistributes batch-59 geometry and needs its own design pass. Do NOT re-attempt a height cap without re-reading M-4.
- **▸ (P3, new — batch-72 §6.5 R-1) Switch state legibility — design guard G-2 was RETIRED, and this is what was dropped.** G-2 asserted *"a control's state renders as a glyph/word, not slider position alone"*. The rendered state word was **Variant A's** mechanism (`NOTES.md:66`); the operator chose **Variant B**, whose verdict row records "Steals from: —". Encoding A's guarantee against B's design is a category error, and the batch's own discharge for it proved handler *wiring* (already covered at `test_crc_designer_view.py:414-415`), not legibility. **The dropped guarantee, stated so it is recoverable: a `Switch`'s own state is not readable without relying on slider position.** Separability (G-1) is closed by `AT-214`; legibility is not, and no test asserts it.
- **▸ (P3, new — batch-72 §6.4 / M-8) The CRC hero row already violates the 6:1 hero-extent law, and did so before this batch.** Guard G-3 was **not encoded**, and the first reason given for that was a rationalisation which the re-gate refuted by measurement. Executed (M-8): `#crc_coverage_window` area **305** vs `#crc_live_verify` and `#crc_warnings_group` at **30x4 = 120 each** — identical boxes, so retiring one tile and giving its space to the other changes the bounded quantity by **zero**. The measured ratio on `main` is **2.54:1** against a 6:1 law. **Pre-existing, unrelated to batch-72, and this batch neither caused nor worsened it** — encoding G-3 here would have failed batch-72's gate on batch-59's geometry. Whoever takes hero-extent work owns re-deriving the ratio first.
- **▸ (P3, new — batch-72 §10 G-004) The CRC Designer screen is UNMEASURED and UNPINNED at the 80x24 floor.** `00-measurements.md` measured the Legend at both regimes but the CRC screen only at 120x30, and no node pins its floor behaviour. The new `Self-test` row is tight even at 120x30 — label 13 cols + `123456789` 10 + the verdict, where `○ NO-EXPECTED` is 13 chars and the `Invalid parameters: …` fault string is much longer. **Bounded, and this is why it is P3 not P2:** the verdict is a `height: auto` `Static` inside a `.crc-field-row`, so an overlong string **wraps** rather than truncating — the silent-truncation failure mode measured in M-4 does *not* apply here. Owed: one floor measurement + a pin.
- **▸ (P3, new — batch-72 §10 G-001, review finding F5) `AT-218`'s clause 4 is discharged but not LABELLED as out-of-node.** The requirement gives AT-218 four clauses; the node implements 1-3. Clause 4 (*"the three legend test files stay green"*) is a **gate-run property**, and it was genuinely discharged four times (Inc-1 239 passed, Inc-2 242, Inc-4 108, plus the Phase-4 run) — but the node's docstring (`tests/test_legend_two_pane.py:420-430`) does not say the clause lives outside the node. **The clause is satisfied; only its labelling is missing** — one sentence. Left open rather than fixed post-review so the merge-gate record stays accurate.
- **▸ (P3, new — batch-72 Inc-1/2 code review, findings F3/F4/F6) Three LOW review findings not folded.** **F6** is the one that nearly escaped — the post-mortem's C-44 sweep found it *neither discharged nor carried*, falling between the fold and the carry: `screens.py:1287`'s `on_resize` docstring does not state why the handler ignores its `event` argument (the reason lives only in the increment packet). **F4**: `#legend_body`'s `overflow: hidden` is unpinned by any test. **F3**: `on_mount`'s width argument is masked by the subsequent `Resize`, so the code is correct but only half-pinned.
- **▸ (P3, new — batch-72 Phase-6) Two unrelated `G-` numbering schemes now coexist in one batch's artifacts.** `04-validation.md` §10 uses `G-001…G-008` for validation gaps while `01-requirements.md` §6.4 uses `G-1…G-4` for the *design guards*. The docs-writer used a third prefix (`G-072-NN`) with a cross-reference column rather than add ambiguity. Cosmetic, but resolve it before it is inherited as a convention.

## 🆕 Registered 2026-07-31 — deferrals born OUTSIDE a batch (backlog-carry audit)

> **How these got here, because the mechanism matters more than the six items.** `feedback_backlog_carryover_enforced` fires at **batch close** and reconciles what a *batch* produced. All six below were deferred in artifacts that are **not batch artifacts** — a `/prototype` verdict's "Non-goals" section and an audit's findings list — so nothing ever swept them into this queue. **This project has already paid for this exact hole once:** line 108's Flow Builder note records *"Items 4-6 below were only in memory/ADR and had NOT been written into this canonical queue"* (2026-07-21), fixed by hand, for one section, without closing the mechanism.
>
> **Every premise below was re-executed against `6524afd` on 2026-07-31, not carried from the source document** — and three of them came back narrower than the source claimed. The source's 15-day-old wording is NOT reproduced where measurement disagreed with it. Sources: `prototypes/screen_upgrades.HANDOFF-PLAN.md` §9 (Non-goals) · the 2026-07-15 screens audit · the 2026-07-14 patch-editor prototype verdict. **The process-side item (a control so deferral lists get swept into the queue) belongs in [`BACKLOG-PROCESS.md`](BACKLOG-PROCESS.md) — route it there, do not copy it here.**

  - **▸ (P2, NEW) raising the 120-column layout cap is an UNMADE operator decision, not an unbuilt feature.** `HANDOFF-PLAN.md` §9 lists it as an explicit non-goal with a reason that survives today — *"the 160×42 exports argue for it — separate decision"*. The cap is a **breakpoint, not a ceiling**: `app.py:6202` sets `narrow = width < 120` and `styles.tcss:305` opens the *">= 120-column fixed-width regime"* (LLR-008.1), so above 120 the side panes are **fixed** (left 22, right 40) and only the centre takes `1fr` — i.e. a 160- or 200-column terminal spends every extra column on one pane. Related and already registered: batch-72's Select-width finding (P2 above) is a *symptom* of the same fixed geometry, and batch-67's clipped entropy band is pinned against `_BAND_BAR_WIDTH = 60`. **Whoever takes this owns re-deriving the regime first** — it redistributes batch-59 bench geometry and will drift map/patch snapshot baselines. Needs `/tui-design` before code.
  - **▸ (P2, NEW) `LoadedFile.errors` carries per-line loader detail that NO surface renders — only its count.** The 2026-07-15 screens audit called this its biggest gap. **Measured 2026-07-31 and the scope is narrower than the audit's wording:** batch-47 *did* ship the count — `build_loader_facts_text` (LLR-066.4/066.6) renders `Loader N err · ⚠K OOO · Entry 0x…` into `#ws_stats` — so "the TUI never shows it" is **FALSE for the count and TRUE for the detail**. All ten consumers of the field take `len()` (`app.py:929/10072`, `compare_service.py:575/582`, the rest are constructor pass-throughs); the per-record dicts are built by `core.py`/`hexfile.py` and then only counted. So the open work is **one table of the existing records**, not new parsing — the engine already collects them and is frozen, which makes this additive by construction. Ties to the parked V2 Workspace MID tier.
  - **▸ (P3, NEW) identity-header residue: the S0 header text and the autodetected endian are computed and never displayed.** **Scope corrected by measurement — most of the original bundle SHIPPED.** The audit's identity header was *S0 · endian · entry point · out-of-order*; batch-47 shipped **entry point and out-of-order** in the loader-facts line above. What is left: (a) `LoadedFile.source_s0_header` is carried and preserved through patching (`app.py:2711`, `_synth_s0_header_from_filename`) but rendered **nowhere** — grep for a display site returns 0; (b) `S19File.endian` is autodetected at `core.py:232` and goes **only to the log** (`logger.info`) — the only `endian` in `s19_app/tui/` is A2L `byte_order` decoding, an unrelated axis. **The "curated footer" half of the v1 chrome idea is deliberately NOT registered here** — footer truncation is already tracked in the A2L discoverability item below, and the `?` help overlay shipped at batch-49 #95; registering them again would duplicate live work.
  - **▸ (P3, NEW) omni-search / linked workbench (prototype variant V3) was never built and is not tracked.** `HANDOFF-PLAN.md` §9 non-goal. V3 = omni-search + unified navigator + selection-synced hex + inspector. **It is a direction, not a defect** — registered so the decision is visible rather than lost, not because anything is broken. It overlaps the 120-col item above (a linked workbench is what the extra columns would be *for*), so the two should be decided together or V3 will be re-proposed against a geometry that cannot host it.
  - **▸ (P3, NEW) `ScreenScaffold` is dead code, flagged 2026-07-15 and still live.** `s19_app/tui/screens_directionb.py:179`. **Verified 2026-07-31:** the only occurrence of `ScreenScaffold(` outside the class statement is the **docstring example at `:211`** — zero instantiations in `s19_app/` or `tests/`. Deleting it is a `/fast-dev-flow` one-liner **plus** the two docstring references at `:8` and `:162` that advertise it as part of the module's public shape. ⚠ Not free: `screens_directionb.py` is **not** in the engine-frozen set, but it is the module batch-67 and batch-72 both edited, so check for an in-flight branch first.
  - **▸ (P3, NEW) app start width/height + font scale — DEFERRED at the 2026-07-14 patch-editor prototype verdict and never registered.** The verdict recorded *"DEFERRED: app start width/height + font scale"* beside the chosen responsive-3-column layout. **Measured: nothing in `app.py` sets an initial window size or font scale** — no such control exists today. Worth stating plainly for whoever picks it up: **Textual cannot set the host terminal's font size**, and start geometry is only settable where the app owns the window (a terminal emulator invocation or `textual serve`), so this may resolve to *"document the recommended terminal size"* rather than code. **Decide the framing before opening a batch** — it is the cheapest of the six to close and the easiest to over-build.

## P2 — A2L discoverability follow-ups (core '?' help SHIPPED batch-49 #95)

- Settings-surfacing · footer-truncation · CRC-modal-depth · only 14 of 30 A2L fields shown. In-app hints / onboarding pass.

## P2 — new carries from batch-67 (feature slate)

  - **▸ (P2, new — batch-67 Inc-4) the entropy band strip is CLIPPED at 120x30, and N4b inherits the limitation.** Segments are positioned against the module constant `_BAND_BAR_WIDTH = 60` (`screens_directionb.py`) while their container `.map-band-bar` is `width: 1fr`. **Measured** on the batch-67 fixture: at **120x30 the bar renders 21 columns**, so the second band segment is laid out at **x=87 — 40 columns outside its own container** — and `get_widget_at(87,10)` returns `#map_detail_body`, i.e. the segment is not drawn there at all. At 160x48 (63 cols) and 80x24 (68 cols, narrow mode = `width: 100%`) both segments fit. **Pre-existing since batch-45, NOT introduced by batch-67** — `_BAND_BAR_WIDTH` is byte-identical on the base `73e3fb9` — and it was invisible while the strip was inert decoration. Making the bands clickable did not cause it but does make it *matter*: a clipped segment is also an unclickable one, so at the 120x30 regime the new feature reaches only the runs inside the first 21 columns. **NOT fixed in batch-67 deliberately:** the constant's own docstring states the fixed width is a geometry-purity decision (LLR-041.2, "independent of live layout geometry") that keeps segment widths deterministic for testing, so reconciling it against the live container is an **operator design call** — it redistributes every segment width and drifts the map snapshot baselines. **Pinned executably** by `tests/test_map_click_chain.py::test_ac6_clipped_segments_are_a_known_layout_limitation`, which asserts the DISAGREEMENT and instructs its own deletion when the layout is reconciled (so the fixer cannot leave a stale claim behind). Whoever takes it must also drop the 160x48 note from the two AC-6 pointer tests.
  - **▸ (P3, new — batch-67 Inc-5) the Flow Builder's ref box is free text where the Patch Editor offers a picker.** `#flow_ref` is one shared `Input` serving all four ref-taking block kinds (`image_ref` / `change_doc_ref` / `check_doc_ref` / `config_ref`), so a Flow Builder user types a filename blind while the Patch Editor user picks from `#patch_doc_file_select`. **A discoverability gap, not a capability gap** — both entry points are proven behaviourally equivalent (ADR §11). A per-kind picker would have to stay correct for all four kinds and re-validate every ref through the REUSED `_resolve_manifest_entry` seam (never fork it — that seam is the containment boundary batch-53 hardened). batch-67 paste-enabled the box, so at least a copied path can now be pasted.

## P3 — code carries / hygiene (fold opportunistically into a themed fast-flow)

  - **▸ (P3, new — batch-73 D-2 rejected arm) linkage over nested ranges reports the OUTER symbol, not the most specific one.**
    batch-73 made the probe sound and fixed the tie-break to **first-by-start**, which is what
    `_first_intersecting_symbol`'s name and contract already promised. The operator explicitly chose that over
    **innermost / most-specific** attribution. So for a genuinely nested pair the operator is now shown
    `BIG_ARRAY` where `INNER` may be the more informative answer — executed:
    `[(0x1000,0x9000,'BIG_ARRAY'),(0x2000,0x2010,'INNER')]`, addr `0x2008` → `BIG_ARRAY`.
    **This is correct-per-contract, not a defect** — it is registered so the choice is re-openable rather than
    forgotten. Revisiting it is a *semantic* change to what linkage means, needs its own operator ruling, and
    would move `R-CHG-002` Amendment A's normative clause. The disjoint-cover mechanism can express it (emit the
    narrowest covering range per span instead of the earliest), so the cost is in the decision, not the code.
  - **▸ (P3, new — batch-73 merge-gate review F7) doctest `Example` blocks are never executed by CI, so they rot silently.**
    `[tool.pytest.ini_options]` in `pyproject.toml` carries no `addopts`, and both CI jobs run bare
    `pytest -q` / `pytest -q -m "not slow"` — so `--doctest-modules` is never applied. PROJECT_RULES.md
    makes `Example` a docstring section, and the codebase has accumulated many; batch-73 added two
    (`apply.py::_linkage_index`, `tests/test_linkage_soundness.py::_pre_fix_probe`), **both verified
    passing by hand** (`python -m pytest --doctest-modules s19_app/tui/changes/apply.py -q` → 3 passed,
    1 skipped). The gap is repo-wide, not batch-73's to close: enabling `--doctest-modules` globally
    would collect every `Example` in the tree at once and is its own batch. **Scope it before enabling.**
  - **▸ (P3, new — batch-73) `.fast-dev-flow/spec.md` still holds batch-69's design-only spec.**
    batch-69 merged 2026-07-28 (#157) and was superseded by batch-70; recent fast-flows
    (batch-71, batch-73) write `.dev-flow/<date>-batch-NN/SPEC.md` instead, so the `/fast-dev-flow`
    pre-check that asks whether to resume "an unclosed prior spec" now fires on a stale file every
    run. Either archive it to `.fast-dev-flow/archive/2026-07-28-batch-69-spec.md` (26 specs already
    live there) or record the convention change in `docs/engineering-rules.md`. **Reported as found,
    not folded in** — batch-73 did not touch it.
  - **▸ (P3, new — batch-64 §7.15) `prototypes/out/` is untracked AND not gitignored.**
    The five prototype SOURCES were committed in PR #147 after a backup audit found them versioned nowhere;
    `prototypes/out/` (32 generated SVGs, ~4 MB) was deliberately excluded as derived. It now sits untracked
    and unignored forever, so it clutters every `git status` and is one careless `git add -A` away from
    landing. One `.gitignore` line closes it. **Also here:** the batch-65 branch still carries
    `tests/goldens/batch64/` under the old batch number — renaming it would break that batch's tests, so it
    is that batch's call, not this backlog's.
  - **▸ (P2, new — batch-64 §7.1) FOUR vacuous predicates live on `main`, one carry.** `V-6`/`AT-172b` (`tests/test_report_document_bytes.py:208-221`) — on the merge-gate platform **BOTH** clauses are inert, not only the named one, and `REQUIREMENTS.md:4849` cites `AT-172` as covering **R-TUI-097**, so the requirement record carries a **false coverage claim**; `V-7` (`tests/test_flow_report_service.py:496`), the same round-trip tautology one line above the sound `:497`; `S-6`'s second assert (`tests/test_report_document_bytes.py:266`), dead by entailment behind a docstring (`:250-252`) whose stated justification is measurably false. **Fix shape for all: compare the file against an INDEPENDENTLY COMPOSED document, not against its own decode.** batch-64 was forbidden to touch `tests/` (D-5).
  - **▸ (P2, new — batch-64 §7.2) a FALSE COUNTERFACTUAL in batch-63's VALIDATION RECORD.** `.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34` records a pre-fix **RED** for an observable measured **GREEN** in all four cells; the adjacent rows qualify where the authors knew, these two carry no qualifier. Squarely inside C-40's *"any measurement probe whose number a gate is keyed on"* — **and the gate layer had never been audited by any lane.**
  - **▸ (P2) RR-1 — reader extensions out of the modelled grammar.** `:x:`, `$…$` math and `==highlight==` are inert under `markdown-it` `gfm-like` and live on GitHub / VS Code / Obsidian, so a filename containing `:x:` can put a red ❌ beside a PASSED row while every token stays `text`. Escape-set extension **declined** (D-22 — `:` appears in every address-bearing string); declared out-of-model and written into R-TUI-077 instead.
  - **▸ (P2) RR-4 / D-8 — `diff_report_service._md_cell` / `._md_table_cell` remain un-promoted** (own goldens, own un-audited HTML sink). The exclusion now lives **inside HLR-097** rather than only in a deferral ruling. Three batch-62 test re-baselines assert the divergence explicitly, so it is visible rather than latent.
  - **▸ (P3, new — batch-63 OB-3) `diff_report_service`'s two writers use text mode too** (`:1393`, `:2063`, `Path.write_text`). **Not D3:** `grep -c "_ByteBudget\|_line_bytes"` on that module returns **0**, so it has no accounting a newline expansion could contradict — it self-documents "no run cap, no byte budget" at `:1129`/`:1693`. Excluded from R-TUI-097 deliberately and by measurement, not by oversight. Carried as a **consistency** follow-up only: routing it through `document_bytes` would make report bytes platform-independent everywhere, at the cost of touching two writers and their goldens to close zero defects. Do it when that module is open for another reason.
  - **▸ (P3, new — sec F7) in-band markers are forgeable.** `md_safe("… (truncated)")` returns `… (truncated)` unchanged; same for `(empty)` and the U+FFFD loss marker — none of their characters is in `MD_ESCAPE`. In an evidentiary document a field whose own text IS the marker is indistinguishable from a genuine cap or loss event. Low blast radius; a distinguishable encoding (or a note in R-TUI-077) would close it.
  - **batch-58 LOW carries (code/security-review, non-blocking):** Inc-3 — add a public `build_target(raw)` wrapper (view imports loader-private `_build_target`) + strip "target 1" wording for the single-target designer; document the intentional `parse_job` vs `parse_crc_config` loader asymmetry; a flat config missing `polynomial` gives a misleading error. Inc-5 — preset-select recompute fan-out (~9×, wasteful not wrong); `_current_algorithm` carries the preset name after edits. Inc-6 — redundant `#crc_field_name` write in `_apply_template`; Save silently overwrites a same-name template (add an "overwrote <name>" note); sanitize collision maps distinct names to one file (accept, pre-existing convention). Inc-7 — conflict-address "first 8" formatting duplicated between `evaluate_target` and the view. All in `s19_app/tui/crc_designer_view.py` / `crc_designer_model.py`.
- **P-3 (A2L)** — reason-string precision on the address branch. BLOCKED by frozen `tc032` (needs the unfreeze). `validate_a2l_tags`.
- **report_service:1091** — raw `check.source_path` heading; sanitize/relabel (batch-39 carry).
- **P-1** — 1-based index convention for the axis-count / inline-axis surface (DEFERRED; no concrete defect).
- **Unload cosmetic** — a MAC-only state (after unloading the S19 spine) keeps the S19 `path` for the window title; the Loaded panel labels correctly from `mac_path`. Re-title on unload. (#107 follow-up.)
- **Throwaway prototype cleanup** — `prototypes/unload_state.*` (logic absorbed into the shipped unload feature). `prototypes/screen_upgrades.*` KEPT by operator decision 2026-07-17 (Batch A/B design source).

## Needs-repro

- **A2L address "two extra chars"** — the >32-bit case is handled (batch-38 `A2L_ADDRESS_EXCEEDS_32BIT` warning). If a DIFFERENT case, needs a concrete repro (symbol + value). `app.py`, `a2l.py`.

## 🆕 Arrived 2026-07-31 by the router's Amendment A — Lane A halves of cross-lane items

> **Transferred here from `BACKLOG-PROCESS.md`, verbatim, on 2026-07-31.** Router
> [Amendment A](BACKLOG.md) splits an item spanning both lanes into one entry per lane; these are the
> **Lane A halves**. They were staged in the PROCESS lane while `BACKLOG-CODE.md` was owned by in-flight
> batch-74, and the move is now executed — batch-74 is fully closed and no batch holds this file.
> **Their Lane B counterparts stay in `BACKLOG-PROCESS.md`; neither half closes its item.**
>
> ⚠ **`R-*` / `LLR-*` / `US-*` are NOT covered by the AT/TC registry** (operator scoping ruling
> 2026-07-31) and have demonstrably collided — that gap is registered separately in the PROCESS lane.

  - **✅ (MAJOR → Lane A) build the AT/TC registry file + its guard test — DONE 2026-07-31**
    (`/fast-dev-flow`, autonomous-to-PR; artifacts
    [`.fast-dev-flow/archive/2026-07-31-at-tc-registry-lane-a-spec.md`](../.fast-dev-flow/archive/2026-07-31-at-tc-registry-lane-a-spec.md)).
    Shipped `AT-TC-REGISTRY.jsonl` (**1 370 rows** — 849 LIVE · 422 BURNED · 78 RESERVED · 21 RETIRED),
    `tools/id_registry.py` (the tokenizer/corpus library **shared** by seeder and guard, so the two
    cannot disagree), `tools/seed_id_registry.py`, `tests/test_id_registry.py` (**G1–G7** + cost bound
    + well-formedness, 13 tests, **no `slow` marker**), `tools/counterfactual_id_registry.py`,
    a repaired `REQUIREMENTS.md` (21 stale verifier assertions + a new `## Retired ids` section), and
    the allocation-authority pointer in `CLAUDE.md` + `docs/engineering-rules.md`.
    **Re-derived at the seed commit `232eb0a`, nothing copied:** high-water **AT-281 / TC-610**,
    `next_free` **AT-282 / TC-611**. `AT-250…279` + `TC-552…599` seeded `RESERVED` for **batch-75**,
    which may be running concurrently — this batch minted from **above** that block (`AT-280/281`,
    `TC-600…610`).
    **Three of the queued premises were imprecise and the corpus corrected them.** (a) The phantom
    population is **24**, not 11 — the spec's figure used a pattern that discards suffixes, so its own
    §1.1 finding (*"the figure measures the grep"*) reproduced one level down; the spec's 11 all
    reproduce inside the 24. (b) The §6.2 residue is **5**, not 73: form-3 binding IS derivable in two
    attested shapes (docstring-enclosing, and the banner comment above a node), leaving only
    module-docstring citations unbound — and those are deliberately left unbound, because binding a
    file-level summary to whichever function comes first invents a relationship the source never made.
    (c) **`TC-319` was REMOVED, not renamed** (`2a647d1` → `19bf1eb`), *but* **C-26's evidentiary basis
    survives**, re-homed as `_MUST_PRESERVE_IDS` (`tests/test_tui_patch_layout.py:67`, consumed at
    `:353`) under **AT-063c**. The id is dead; the evidence is not.
    **One recorded premise correction on the spec itself:** G4 as worded fires on 28 citations, 11 of
    which are honest history *already saying* the verifier was deleted. G4 is scoped to the
    **verifier-asserting** line — which is how §6.1 describes the defect — so history keeps its ids.
    All 7 phantoms the item cites are in `- Validation:` bullets, so nothing cited escapes. Exempt
    anchors used: **2 of the 5** the spec allows.
    **✅ Closes C-3 and the batch-62 "16 of 23" carry** — the `nodes` field is N:M in both directions
    (212 ids bound that way; `TC-24.3` → five nodes is the worked consolidated-battery case), which is
    what batch-62's accepted resolution required, and **G2 enforces it**. ⚠ The C-3 row itself lives at
    `.dev-flow/BACKLOG-PROCESS.md:135` — the Lane B file this batch was instructed not to touch — so
    **marking that row is owed to the next Lane B reconciliation.**
    ⚠ **This half does NOT close the item** (router Amendment A); the Lane B design half does not
    either. `R-*` / `LLR-*` / `US-*` remain out of scope and still collide — that gap stays in Lane B.
    **Carries:** ▸ **(P3)** `TC-355` advertises a "no-raise" arm in `tests/test_flow_crc_block.py:10`
    that **no node asserts** and that never had one (`git log -S tc355` over all refs is empty) —
    seeded `BURNED` so it reads as *no claim was ever made* rather than *coverage was lost*; write the
    verifier or drop the claim. ▸ **(P3)** `EXPECTED_SCANNED_TEST_FILES` is a manual constant every
    test-adding PR must bump — deliberate (it makes corpus growth a decision), but someone will want to
    automate it, and automating it deletes the bound. ▸ **(P3)** `statement` for the ~1 000
    mechanically-bound ids is generated boilerplate, so §3.5's *"is my TC-410 your TC-410?"* is only
    answerable for hand-dispositioned and newly-minted ids; filling these in is incremental work, not a
    batch.
    *(Original entry, retained for lineage:)* ✅ UNBLOCKED 2026-07-31 — both
    preconditions are met. (i) The Lane B spec exists and is merged: [`AT-TC-REGISTRY-SPEC.md`](AT-TC-REGISTRY-SPEC.md),
    PR #174. **Its §9 is the ordered build contract with executable done-conditions — build from §9, not from
    this bullet.** (ii) batch-74 **merged** (`537f27d`, #173), so the id set has stopped moving under the seed.
    ⚠ **Seed figures are already stale**: the high-water mark went **`TC-524` → `TC-551`** in that one batch
    (re-derived on `origin/main` 2026-07-31, not copied from batch-74's own text, which cites `TC-549`).
    **Re-derive at the seed commit** (spec §1.3, §9 Inc-1) — the spec's numbers justify the design, they do not
    seed the file. batch-74 also shipped `TC-549b`, a suffixed id, which is exactly the shape spec §2.2 rules on. The guard lives in `tests/` and must fail in **both** directions — but note §5.2:
    two-way is **not** sufficient to catch the phantoms, so build G1–G7, not G1–G2. **Closes C-3 and the
    batch-62 "16 of 23" carry** — state that explicitly at close rather than letting them lapse.
    *(Original blocking rationale, now discharged, retained for lineage: "Blocked until batch-74 merges:
    batch-74 is renumbering the live AT/TC set (`96bcbd7`, third collision in two days), so a registry
    snapshotted now is born stale and its guard reddens the day batch-74 lands." The prediction held —
    `TC-524` → `TC-549` in one batch.)*
  - **▸ (P2 → Lane A) the 1c CI staleness guard.** Every `R-*`/`LLR-*` code tag must name a live
    requirement. Half-built already: 25 back-refs in `screens_directionb.py`, and `REQUIREMENTS.md` maps
    `R-*` → files. Consumes 1c's Lane B control definition.
  - **▸ (P2 → Lane A) the 1d markup-sink sweep assertions.** Over the 4 known surfaces (`screens.py`,
    tooltips, DataTable, Select), asserting `plain` verbatim **and** `spans == []`. Consumes 1d's Lane B rule.
    Note this is the **assert-the-emitted-form** family (C-42), so the assertions must be written against
    what the widget emits, not against the rendered text.

## Development flow OF the code — tests · CI · repo hygiene

  - **▸ (P3, operator-requested 2026-07-30) `tui-ci` runs the full ~35-min pytest suite on docs-only PRs — add a paths filter.** Measured on PR #164 (diff = `prototypes/` + `.dev-flow/` only): `.github/workflows/tui-ci.yml` triggers on every `pull_request`/`push` to `main`/`main-tui` with **no `paths` filter**, so a prototypes/backlog/docs-only change costs a full suite run. Candidate fix: `paths-ignore` for `prototypes/**`, `.dev-flow/**`, `docs/**`, `**/*.md` (audit the exact set — `REQUIREMENTS.md` edits ride code batches anyway). ⚠ **Known GitHub gotcha to handle in the same change:** if `tui-ci` is a *required* status check, a path-skipped run leaves the PR stuck `pending` — either pair the filter with a no-op success job for skipped paths, or verify the check is not branch-protection-required before filtering. Route: `/fast-dev-flow`, CI-only, 1 file.

  - **▸ (P2, new 2026-07-30) `examples/case_04_bad_checksums/` is the ONLY example case with no `.mac` file** — 7 of the 8 cases carry one. A `firmware.mac` for it exists on the unmerged `web/flask-viewer` branch and nowhere else. Measured: `ls examples/*/ | grep -c '\.mac$'` → 1 for every case except `case_04` → 0. Either the fixture is genuinely missing (and every MAC-view pilot frame for that case is exercising an empty linkage source), or its absence is deliberate and undocumented. **Decide which before that branch is deleted** — see `.dev-flow/BRANCH-AUDIT-2026-07-30.md`.
  - **▸ (P3, new 2026-07-30) an unmerged Flask web viewer exists and is referenced nowhere.** `web/flask-viewer`, last commit **2026-04-13** (predating batch-01), holds **1 187 lines**: `s19_app/web/` (app/routes/loader/session_store/a2l_utils/mac_display/cli + templates + CSS) and `tests/test_web_app.py`. No backlog item, no requirement, no vault note mentions it. **Revive as a batch, archive, or delete knowingly — but not unknowingly.** Full characterisation in `.dev-flow/BRANCH-AUDIT-2026-07-30.md`.

  - **▸ (P3, new at batch-70 sync) a vault-sync step copies pilot SVGs RECURSIVELY instead of using the §5 flattening helper — and that is why batch-47's prune did not hold.** batch-47 removed the legacy nested `assets/pilot/svgs/<case>/frame_*.svg` layout under an operator-approved prune (46 files). It is **back**: 16 directories / 80 files, dated 2026-07-27, re-created by some sync between batch-47 and batch-63. **Operator ruling 2026-07-29: KEEP them as historical context**, now classified in the vault's `visual-evidence.md` §6 with an explicit sync contract so the freshness reject-check stops flagging them. **The residual is the CAUSE, not the files:** whatever step copies recursively will keep re-creating the layout, so a future prune would be undone again. Fix the copying step first; only then is deletion even a question. *(Evidence: `find assets/pilot/svgs -mindepth 2 -name "*.svg" | wc -l` → 80, all `2026-07-27`, while the §5 helper writes only flattened `pilot_<case>_<frame>.svg`.)*
  - **▸ (P3, new at batch-70 sync) batch-66 has a `.dev-flow/` folder in the repo and NO vault counterpart.** `.dev-flow/2026-07-28-batch-66/` exists; `dev-flow-batches/` in the vault jumps 65 → 70. Either that batch was never synced or it deliberately produced no syncable artifacts — undetermined, and stated as undetermined rather than guessed.

  - **▸ (P3) Known-flaky TUI case** — `tests/test_tui_flow_persistence_ui.py::test_at002_name_strip_glyph_dirty_then_saved` failed once with `NoMatches: '#flow_panel'` and passed alone (7/7), beside every neighbouring suite, and on an identical-tree identical-order re-run. `#flow_panel` is queried at `app.py:2313/2354/2394`, mounted at `screens_directionb.py:2672` — a Textual mount-timing path in the batch-53 rail, untouched by batch-62. Same family as the earlier `setup_logging` handler-leak flake; deserves a root-cause pass rather than a retry, because a flaky gate erodes every "CI green" claim built on it.
  - **▸ (P3, new — sec F8 / qa m-3) the AST column-0 guard is narrower than the rule it protects.** `test_no_escaped_field_is_emitted_at_the_head_of_its_line` only matches a DIRECT `md_safe(...)`/`md_code(...)` as `JoinedStr.values[0]`, and only in `report_service.py`. The assign-then-interpolate shape the module itself already uses (`name = md_safe(region.name, …)` then `f"### {name} …"`) is invisible to it, as is the same hazard in `flow_report_service.py`. Fix: follow local assignments one level, and run the guard over both composers.
  - **▸ (P3, new — qa m-1/m-2/m-6/m-7) four small test-integrity items.** `CheckRunEntry.result`'s escape has no failing test of its own (closed-domain token, low risk); `test_tc382_a_large_value_is_bounded_*` cannot see the `limit * 8` entry clamp it names (truncation bounds the output regardless — assert the clamp or rename); AT-160 reads the committed golden rather than driving the shipped surface (coverage is transitive via the seam byte-identity test, so sound, but it is not black-box as `04-validation.md` §2 implies); and `report_service.py`'s per-element-join comment is wrong about `,` being escaped.
  - **▸ (PROCESS, new — sec F5) do not run counterfactuals in a worktree a reviewer is reading.** batch-62 mutated `report_service.py` in the live worktree while the independent security review was in progress, costing it four spurious failures and forcing a re-run against a pristine `git archive` export. The committed tip was always clean, but **gate evidence must never be taken from a tree another session is editing.** Run mutation experiments in an export.
  - **▸ (P3, new — batch-64 §7.8) the worktree-mutation hygiene rule carried at `.dev-flow/BACKLOG-CODE.md` as **(PROCESS, new — sec F5)** is now a DEPENDENCY of an encoded control.** C-40's discharge mandates executing a reddening mutation, and its bound (*run where no other session is reading; RESTORE before the next gate*) is exactly that rule. Close the standing candidate or retire it explicitly — do not leave it open beneath a control that depends on it.
  - **▸ (P3) `ruff check s19_app/` is RED on `main`** — pre-existing, verified with batch-62's changes stashed. Every batch-62 packet's "ruff clean" means *the touched files*, not the package.
- **Repo/worktree hygiene — PARTIAL.** `direct`. State 2026-07-21: **(a)** git worktree REGISTRY cleaned for the 4 project worktrees; 3 left inert **directory shells** on disk (locked — deletable after reboot); rail-8 dir fully removed. **(b)** the PRIMARY checkout is on `ef5145b` (detached) — **restore primary→`main` (now `7954652`)** as an RC-1 closeout. **(c)** 5 stray `.cursor/worktrees/` (dyl/fkp/fmi/kxu/lyi) — **NOT pruned: `.cursor/` are the operator's IDE worktrees → need explicit operator ok.** **(d)** `backlog-consolidado-prioridad-f37dfb` NOT pruned (its PR #111 merged; other session's worktree).

---

## Lineage — shipped code work whose carries are listed above

### ✅ batch-59 — CRC Designer view-fidelity rebuild — DONE + MERGED #113 `7954652` (2026-07-21)
> Shipped the approved **Variant-B coverage-first bench**: a wide LIVE-rendered coverage-window hero + verdict/warnings hero row + 3-column bench (algorithm+serialization · coverage+vector · roomy JSON+template+load/save). Merged as [#113](https://github.com/jav201/s19_app/pull/113) `7954652`. Commits `3ffbf85` (bench+CSS) / `266dae6` (live window) / `41f5a87` (abort-gate fix + fidelity/security ATs). **0 engine change, 0 frozen diffs.** 11 AT (AT-B59-01..11) + F2 + 20 batch-58 preservation tests green; gate suite **1772 passed**. **Root cause fixed:** the `crc-*` CSS classes were UNDEFINED in `styles.tcss` (→ Textual default stacking = the flat form). Design-fidelity ATs with TEETH (AT-B59-03/08: `len(distinct bench-column ancestors)==3`, provably `==1` on the flat form). Live window honors `on_gap_conflict="abort"`. Artifacts `.dev-flow/2026-07-21-batch-59/`. **dev-flow tail (minimal close, operator 2026-07-21):** postmortem/docs light; `/dev-flow-sync` PENDING (vault upload, batched b57+b58+b59).
>
> **Carries from batch-59:** **F4 (P3, `/fast-dev-flow`):** window-level warn/ignore branch test (mirror AT-058-08 for the window; the abort/refuse path is pinned, warn/ignore isn't). **F3 (accepted design):** the window shows labeled concat/fill comparison hexes under abort-refusal (store word IS gated) — revisit only if strict display-parity with the preview (hide the comparison hex too) is ever wanted (one-line guard). **CONTROL CANDIDATE (needs its own AskUserQuestion before encoding):** *design-fidelity AT* — when a prototype is operator-approved, an AT must assert the shipped layout matches the prototype's SIGNATURE elements (a rendered hero, a multi-column container), not merely functional widget presence (extends C-32); this is the exact gap that let batch-58 ship a functional-but-off-design view. Encoded ad-hoc as US-L5/AT-B59-03 this batch. **`/tui-design` refined (this session):** new `PROTOTYPE.md` mode — deploy N runnable TUI variants (mount-in-real-app / standalone) + headless SVG capture — now part of the global skill (backup `SKILL.md.bak`).
### 🆕 Operator-flagged 2026-07-21 — new asks (proposed priority, awaiting operator triage)
> Captured from operator on 2026-07-21. All go through ≥ `/fast-dev-flow` (`feedback_all_changes_tracked_min_fast_dev_flow`). Priorities below are PROPOSED — operator to confirm before they migrate into the P1/P2/P3 tiers.
- **✅ N1 — Legend scoping: per-SCREEN — DONE (2026-07-23, `/fast-dev-flow`, branch `feat/n1-n2-legend-tasklog` off `5ec46b3`).** `LegendScreen(sections=…)` filter + `_SCREEN_LEGEND_SECTIONS` map (a2l→A2L, mac→MAC, issues→Issues, map/patch/diff→Hex, checks→Issues) driven from a new `_active_screen_key` (set in `action_show_screen`); unmapped screens (workspace/flow/crc) fall back to the full table (never empty). Row colours still round-trip through the frozen `SEVERITY_CLASS_MAP` (read-only). 3 tests + 14 legend regression green; RED-verified. **Note:** legend was keyed to the FULL table (not per-file as the item guessed) — the real fix was per-screen filtering.
- **✅ N2 — activity-log full width at fullscreen — DONE (2026-07-23, `/fast-dev-flow`, same batch as N1).** **Root cause was NOT CSS** (the item guessed a `width`/`max-width`): the truncation was a hard code cap `_append_log_line` → `line = trimmed[:50]` (`app.py`). Fixed to `max(50, self.size.width)` so long `.s19tool/workarea/…` paths use the full viewport span at fullscreen and stay bounded (never unbounded) at narrow. `styles.tcss` needed no change — the `#workspace_status_bar` Labels already span full width. 2 tests (untruncated @200-wide, bounded @80-wide); RED-verified.
- **✅ N3 — Report generation is NOT logged (observability BUG) — DONE (2026-07-21, `/fast-dev-flow`, branch `fix/n3-report-logging` off `9bb50f2`).** Added `format_report_log_line()` + `S19TuiApp._log_report_event()` (INFO ok / WARNING fail) wired at the 3 `app.py` orchestration call sites — project worker (success + `ValueError` reject + crash), `action_before_after_report` (success + refusal, was fully silent), diff handler (md+html success + both refusals, was fully silent). Metadata-only line (kind · source · output · outcome); no logging inside the pure emitter services (design-intent honored). **Scoping correction:** the "ZERO logger calls" claim was true for the pure `report_service.py` module, but the project **app call site** already logged thinly (path-only + crash) — the truly silent surfaces were before/after + diff + the project reject branch. 6 tests (`tests/test_report_logging.py`) incl. a **driven gold-standard AT** (real `b` action → reads `s19tui.log`, RED-verified). Full suite **1821 passed** (the 19 `test_tc016s` failures are the pre-existing batch-58/59 snapshot drift below, not N3 — logging renders nothing). **Carry:** ▸ **P3 follow-up** — AC-1 (project) + AC-3 (diff) are unit-covered (formatter + level routing + file-landing) but NOT driven end-to-end through the app; a follow-up can add driven ATs mirroring the before/after one (low risk, mechanism proven, call sites straight-line).
### 🆕 Operator-flagged 2026-07-23 — user-test asks (N6–N8)
> Captured from operator user-testing on 2026-07-23. All go through ≥ `/fast-dev-flow`. Priorities PROPOSED. **Phase-A disk-verified at capture** (two of three premises were more precise than the user-test wording — the recurring "verify the premise first" lesson).
- **✅ N6 — Help panel `?` TOGGLE (show AND hide) — DONE (2026-07-23, `/fast-dev-flow` autonomous+self-merge, branch `fix/n6-n7-help-toggle-a2l-panel` off `235923f`).** Root cause: `Binding("question_mark", "show_help_panel", …)` routed to Textual's stock `action_show_help_panel`, which only MOUNTS the panel — no keyboard dismiss. **Fix (surgical):** overrode `S19TuiApp.action_show_help_panel` to TOGGLE (`self.query(HelpPanel)` present → stock `action_hide_help_panel`, else `super().action_show_help_panel()`); binding action name kept as `show_help_panel` so the discoverability contract (`test_discoverability.py` AC-1/AC-2: key `?`, footer-visible, label "Help") stays green. 1 black-box AT (`test_help_panel_toggle_hides_on_second_press`), RED-verified. Shipped with N7 in one batch.
- **✅ N7 — Workspace A2L filename shown at top on load (no screen-switch) — DONE (2026-07-23, same batch as N6).** Root cause confirmed: [`load_a2l_from_path`](../s19_app/tui/app.py) set `current_file.a2l_path` but never called `_refresh_loaded_panel()` → the top `LoadedArtifactsPanel` only redrew on the next `action_show_screen`. **Fix:** one line — `self._refresh_loaded_panel()` at the end of the A2L load path. **C-15.1 sweep result:** A2L is the ONLY orphaned load site — S19/HEX + MAC both go through `_apply_loaded_file` (already refreshes at app.py:9118); no `load_mac_from_path` exists. 1 black-box AT (`test_a2l_load_refreshes_loaded_panel_without_screen_switch`), RED-verified (slot `(none)` pre-fix). Full suite: **1851 passed** / 2 skipped / 3 xfailed; the only 19 failures are the pre-existing batch-58/59 `tc016s` snapshot drift (advisory `continue-on-error` in CI), zero new.
- **✅ N8 — Legend per-view explanatory snippets — DONE + MERGED (2026-07-24, full `/dev-flow`, PR [#125](https://github.com/jav201/s19_app/pull/125) squash `a6f2d6ff`, branch `feat/n8-comprehensive-legend` off `f56cf48`; resumed from the Phase-3 pause checkpoint; authorization CHANGED at resume supervised→autonomous+self-merge; final qa gate PASS 0-HIGH).** Encoded **C-37** (render-layer probe: colour lives in `render().spans` not `render_line`) + **C-38** (widget-type-swap query sweep) in `docs/engineering-rules.md`. Extends **N1** (`7ba2631`). Shipped: each rail view's `LegendScreen` renders an annotated example card (`LEGEND_EXAMPLES`, `legend.py`) above the real colour/entropy key. Workspace now mapped to `()` (example-only); Map renders the entropy band key + both Hex overlays (not the `LEGEND_TABLE["Hex"]` severity rows); MAC has the orange↔pale-yellow reconciliation; key rows `Label`→`Static` (wrap not truncate). 3 increments (Inc-1 data / Inc-2 render / Inc-3 CSS+ATs), AT-N8-01..07 + TC-N8-*. **NO snapshot regen needed** (design note's premise was wrong — the Legend modal is NOT `tc016s`-captured; verified). Full suite **1869 passed / 0 regressions** (19 pre-existing snapshot fails proven pre-existing via base-render diff). **Carries:** the 2 general controls are now encoded (C-37/C-38, operator-approved). Detail: `.dev-flow/2026-07-23-batch-n8/`.

## 🆕 Registered by batch-76's merge-gate closure (2026-07-31)

  - **▸ (P3, NEW — hardening, NOT a live defect) `REPORT_VARIANT_RESERVATION_FLOOR_BYTES` carries the same character-cap-as-byte-bound pattern H-3 named, and its guard measures a 2-character variant id.** `report_service.py:412` derives the floor as `len("## Variant: ") + REPORT_CELL_CHARS + 1`. `REPORT_CELL_CHARS` is `md_safe`'s **INPUT-CHARACTER** cap, and batch-76 measured its emitted output at **2.03×** that cap for escaped ASCII and **4.03×** for unescaped non-BMP code points (`TC-611` pins both). This is the identical defect H-3 closed in `_disclosure_allowance`'s `note` and `headings` terms, which now derive from `REPORT_VARIANT_ID_MAX_BYTES = 3 × 255 = 765` — the reachable filename bound — instead.
    **Why it is registered rather than patched: scope, and the guard does hold.** `TC-556` asserts a *relation* (`floor >= measured marginal`) rather than a number, and it passes. **But the fixture it measures the marginal against uses variant ids `"v0"`/`"v1"` — two characters.** At the widest id the shipped surface can deliver (255 × U+4E00, measured **777 B** emitted) the marginal would be far larger, so `TC-556` is the **narrow-fixture** class — a correct predicate whose fixture never exercises what it asserts, which is precisely the class that blocked batch-75 revision 1 and that `TC-552` exists to guard. **No code mutation can reveal it**; only widening the fixture can.
    **Not claimed to be reachable-broken:** the floor governs the per-variant *reservation*, and a reservation that under-provisions produces a heading with thin content (non-claim (d), an accepted outcome), not a ceiling violation. So this is hardening. **Suggested fix:** derive the floor from `REPORT_VARIANT_ID_MAX_BYTES` and re-measure `TC-556`'s marginal with the widest reachable id, in one increment with a per-arm counterfactual via `tools/mutation_harness.py`.
    **Whoever takes this owns a decision, not just an edit:** `REPORT_CELL_CHARS` is cited as a byte bound at **~20 further `md_safe(..., limit=REPORT_CELL_CHARS)` call sites**. Deciding whether the general rule is "every byte budget derives from an emitted-byte constant" — versus two constants for two purposes — is the actual work. Per `feedback_general-controls-not-narrow-patches`, prefer the general form; per surgical-changes, do not widen this into a module-wide refactor without approval.

  - **▸ (P3, NEW — raised by the batch-76 merge gate round 1, DROPPED by me at first reconciliation, registered here after round 2 caught the omission) `AT-253`'s dict equality has the FORM of per-kind verification and a fixture that exercises 1 of 8 kinds.** `AT-253` (`tests/test_report_document_bound.py`) now parses the rendered disclosure into `{kind: bytes}` and asserts equality against refused bytes weighed independently at the seam — which is what closed merge-gate finding H-4, and that half is sound. **But its fixture refuses exactly one member of the 8-element `REPORT_SECTION_KINDS`**, so both sides of the equality are single-entry dicts: `rendered == independent == {'checklists': 19356}`. The dict shape advertises an attribution check the fixture cannot perform.
    **Executed, per-arm, on a throwaway worktree** — substituting `_EmissionGate.emit`'s `self._refusals.record(kind, batch, cost, self._variant)` for `record("checklists", batch, cost, self._variant)`, i.e. mis-attributing **every** refusal to a single kind:
    | node | verdict |
    |---|---|
    | `AT-253` | **GREEN** |
    | `TC-560` | RED |
    | `TC-561` | **GREEN** |
    So a report that mislabels which sections were dropped — while stating the correct total — is caught only by `TC-560`, at the accumulator, and never through the rendering an auditor reads. **This is the vacuous-FIXTURE class, not the vacuous-predicate class: the predicate is right and no code mutation of the renderer reveals it; only widening the fixture does.**
    **Not a re-open of H-4.** H-4 as worded is byte EQUALITY on the rendered total, and that is satisfied and counterfactually guarded (M3 RED). This is the adjacent property — per-kind attribution — that the dict form implies and the fixture does not reach. **Suggested fix:** drive the fixture until refusals land in ≥3 distinct kinds (memory-regions and modifications are the easy additions alongside checklists), then re-run the mutation above and require `AT-253` RED. One increment, one counterfactual.
    **Process note, which is the more useful half.** This item was raised, understood, and then **left out of the first backlog reconciliation** — against the operator's standing *"drop nothing"* rule — and it took a second independent pass to notice. It is evidence for the input-side carry-over control already registered in `BACKLOG-PROCESS.md`: **a finding surfaced by a reviewer needs a named owner at a named gate, or it evaporates between the review and the close.**
