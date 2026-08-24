# Requirements — s19_app — 2026-08-24-batch-87 · D-II re-author of the pilot IFC record + IFC surface #3 (`workspace_body`)

> **Station state.** Authored at P1 to the batch-86 exemplar
> (`.dev-flow/2026-08-24-batch-86/01-requirements.md`) under the execute-first discipline: **every
> threshold in this document was derived from a probe that ran first, and the probe's transcript is
> in §2.8.** The pilot's method finding is the reason — seven orchestrator defects, all of them a
> threshold written before the thing it measures was executed (`HANDOFF-batch85-ifc-pilot-2026-08-21.md`
> §4). Where a figure here disagrees with what the command prints, the command is right.

## 1 · Context

Second batch under flow rev45. Two objectives, one record:

1. **Discharge D-II** — the batch-85 pilot's IFC contract is RE-AUTHORED, not patched, to the
   exemplar format, with the D-A six-output split. The contract's home stays the pilot's own file
   (decision **D-87-A**, ruled by executed probe, §2.8 M-4).
2. **Declare IFC surface #3** — `workspace_body`, the shell above `screen_workspace` and the only
   undeclared `PARENT` the validator named at batch open.

Zero product code planned. The batch also produced the retrofit's first measured **compounding**
figure: balancing is transitive set containment, so an ancestor must re-declare every id its
descendants emit, and the cost of the re-export grows with depth × width (§5.4 D-87-C, §5.6).

## 2.6 · Story intake & refinement (Definition of Ready)

### US-87-1 — Re-author the batch-85 pilot IFC record (D-II discharge)

**As** the IFC retrofit programme, **the contract** for `loaded_panel` (the batch-85 pilot surface)
**is re-authored** to the batch-86 exemplar format — SIX outputs per the D-A analysis (split
`slot_rows` into `artifact_row_set`, `query(".loaded-slot")`, cardinality 4, and `unload_all_row`,
`query(".loaded-allrow")`, cardinality 1; `HANDOFF-atlas-ifc-2026-08-22.md` §8), pair-based
thresholds, scoped statements, no absorbed `owner` field — **so that** the UNPARSED census clears to
pure BATCHES entries and the D-86-E verbatim re-export duplication is resolved under
`screen_workspace`'s already-declared parent boundary.

- **D-II ruling (operator, 2026-08-24, this session):** re-author — chosen over patching the 15
  catalogued defects (`HANDOFF-batch85-ifc-pilot-2026-08-21.md` §5). The pilot's MEASUREMENTS
  (census, cost figures) stay valid history; re-authoring replaces the CONTRACT, not the record of
  what was measured.
- **Observable outcome (black-box, through the shipped validator):** the `[IFC]` UNPARSED entry at
  `2026-08-21-batch-85/01-requirements.md:372` (field `owner` absorbed 801 chars) is GONE from the
  regenerated `ATLAS-ORPHANS.md`; the BATCHES dir-name census entry remains (negative control);
  `loaded_panel` balancing stays CHECKED under V12; 0 new BLOCKs.
- **INVEST:** Independent of US-87-2 in authoring order (but shares the batch record — see D-87-A).
  Valuable: clears the last IFC parse debt + one contract, one declaration. Estimable: bounded by
  the exemplar + the D-A prescription. Small: one record section. Testable: the validator/Atlas
  observables above.
- **Open design question `D-87-A` (P1, decided by executed probe, not by reading):** where the
  re-authored contract LIVES — (a) corrected in place in the batch-85 record vs (b) declared fresh
  in batch-87's record. Deciding evidence owed: `_ifc_corpus`'s merge semantics when two batches
  declare the SAME `COMPONENT` id (named UNARMED by the pilot handoff §7.2 — the probe must be run,
  and D-86-E's rationale "correcting it elsewhere while the pilot stands forks the contract" weighs
  toward (a) for the contract body).
- **DoR: READY** — outcome observable through the shipped surface (validator + Atlas), acceptance
  criterion stated at behavior level, path known (exemplar + D-A), no unresolved dependency
  (D-87-A is a bounded in-batch decision with a named probe).

### US-87-2 — Declare IFC surface #3: `workspace_body` (the shell)

**As** the IFC retrofit programme, **the shell component** `workspace_body` (`#workspace_body`,
`app.py:1917` — the container above `screen_workspace`, the only undeclared `PARENT` V12 names)
**gets its IFC Part B contract declared** in the batch-87 record, **so that** the standing V12
NOTICE naming `screen_workspace/workspace_body` is replaced by a checked balancing verdict, and the
`.db-pane` / `.db-screen` couplings measured at batch-86 M-6 become contract-visible (D-86-A
discharge path).

- **Selection criterion:** the SAME V12-liveness criterion that chose surface #2 — it is the only
  undeclared PARENT the validator names (probe executed this session: the sole V12 finding names
  `screen_workspace/workspace_body`; validator run 2026-08-24, `0 block · 254 notice`).
- **Observable outcome (black-box):** post-state validator run shows 0 V12 findings naming
  `screen_workspace/workspace_body` as unchecked; `workspace_body`'s own PARENT question is answered
  honestly (SYSTEM if it is truly the root — to be MEASURED at P1, `app.py` compose tree — else one
  standing NOTICE one level up, the staged-retrofit pattern of pilot D-B / D-86-B).
- **Consumer-census input (measured this session, to be re-derived at P1):** `workspace_body`
  appears in 24 test files / 40 occurrences; `loaded_panel` in 12 test files.
- **INVEST:** Independent: declarable given screen_workspace's record (merged, on `main`).
  Valuable: retires the last named undeclared PARENT; per-surface cost point n=3 (dispersion series
  continues). Estimable/Small: one Part B contract; the shell is plausibly LARGE (composes three
  panes) — cost measured, not assumed (batch-86 non-extrapolation caveat honored). Testable: V12
  observable above.
- **DoR: READY** — same bar as US-87-1, all criteria evidenced by executed probes.

### Batch premise (both stories)

Spec-only batch: **0 source files** planned (pin verified at every gate, as batch-86). Canon mirror
edits in `REQUIREMENTS.md` only (R-TUI-113 refresh to re-authored status + new-id seeding per the
corpus rules; V22 debt must not grow — batch-86 closed at 276).

### P1 corrections to this intake, recorded rather than rewritten

The intake above is kept verbatim; three of its expectations were REFUTED by the P1 probes, and
saying so here is cheaper than a reader discovering it in §2.7:

| Intake claim | P1 verdict | Where |
|---|---|---|
| "the D-86-E verbatim re-export duplication is resolved" | **REFUTED.** The duplication is STRUCTURAL, not a defect of the pilot's authoring: balancing requires the parent to re-declare the child's ids, and V13 then greps the same literal once per declaration. Re-authoring cannot remove it; only a rule change can | P-6, D-87-C |
| "`workspace_body`'s own PARENT … SYSTEM if it is truly the root" | **REFUTED.** It is not the root — `#workspace_shell` sits above it | P-8, M-6 |
| "V22 debt must not grow — batch-86 closed at 276" | **REFUTED as a baseline.** The live baseline at this station is **278**: this batch's own scaffold put `US-87-1` and `US-87-2` into the corpus before P1 opened | P-12, M-1 |

## 2.7 · Premise evaluation (C-43)

> Every row's evidence is a command this session RAN, or a file:line this session READ. A premise
> whose only support is another document is UNDECIDABLE, not TRUE — citing the pilot handoff or the
> Atlas handoff is not evidence, and each of their claims below was re-executed.

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-1** | The validator's baseline at this station is `0 block` | AXIOM | ✅ TRUE | M-1: `python ~/.claude/docs/tools/devflow-validate.py .` → tail `0 block · 254 notice · 15 not applicable`; V20 `atlas current (4 files, census 2)` | every later BLOCK in this batch is attributable to this batch |
| **P-2** | `_ifc_corpus` MERGES declarations by list extension, so a second declaration of one COMPONENT id does not replace the first — and the two halves of the corpus then judge different components under one id | HYPOTHESIS | ✅ TRUE | M-4 arm 1 (synthetic two-batch corpus, temp dir): V11 counted **7** OUTPUTs over a 5-output truth, V19 NOTICE named both declarations, V12 resolved the parent to the LAST. Rule source read at `devflow-validate.py:452` (`by_id = {c["id"]: c for c in components}`) and `:617-626` (`components.extend`) | **decides D-87-A against option (b)** |
| **P-3** | The `[IFC]` UNPARSED census entry is keyed to the batch-85 file and line, so no document other than that file can clear it | PREMISE | ✅ TRUE | M-2: `.dev-flow/_derived/ATLAS-ORPHANS.md:17` reads `[IFC] .dev-flow/2026-08-21-batch-85/01-requirements.md:372 — field 'owner' absorbed 801 chars` | **decides D-87-A for option (a)**, independently of P-2 |
| **P-4** | The absorption is caused by a missing block terminator in `_parse_ifc`, not by anything the pilot wrote inside its block | PREMISE | ✅ TRUE | M-3: executing `_parse_ifc` over the pilot file printed the field's value — **801 chars over 11 lines**, whose content is §5.5's INDENTED pre-state transcript plus five indented continuation lines from §6.3. Rule read at `devflow-validate.py:338-340`: `if last_key and indent:` appends ANY later indented line; the closing fence is not recognised | gives LLR-87.4 its positive authoring constraint |
| **P-5** | The D-A prescription is arithmetically right about the populations: `.loaded-slot` selects 4 rows and `.loaded-allrow` selects 1 | PREMISE | ✅ TRUE | M-6 (runtime, `run_test()` under conda `s19env`): `.loaded-slot -> 4`, `.loaded-allrow -> 1`, `.loaded-detail -> 3`, `.loaded-project-detail -> 1`. Provider read at `screens_directionb.py:1926-1930` — `render_slots` mounts the project row, then one row per `_SLOTS` (3), then the footer | the split is declared at the measured arities |
| **P-6** | Re-authoring the pilot RESOLVES the D-86-E duplication (4 duplicate V13 stray pairs, 15 duplicate consumer entries) | HYPOTHESIS | ❌ **FALSE** | M-4 arms 2–4: with the child's ids changed and the parent's re-export left alone, V12 BLOCKs (`emits artifact_row_set, unload_all_row`); with the parent updated, balancing holds — but the parent must still name every child id, and V13 greps each declared literal ONCE PER DECLARATION. The duplication is a consequence of the balancing rule, not of the pilot's authoring | the intake's second goal observable is **withdrawn and replaced** by a measured cost figure (D-87-C); registered as finding R-87-2 |
| **P-7** | `INDEXED POSITIONALLY` is FALSE for `slot_rows`' declared consumer | PREMISE | ✅ TRUE | M-5: `tests/test_tui_variants.py:96-99` — `for row in app.query("#loaded_slots > Horizontal")` then `if cells and str(cells[0].render()).strip() == LoadedArtifactsPanel._PROJECT_KIND`. A linear sweep with a content predicate; reordering rows does not break it. What breaks it is the index WITHIN a row and the VALUE of `_PROJECT_KIND`, a class attribute — outside the contract by §1.3's definition of address (pilot F-8) | the re-authored `artifact_row_set` carries NO positional annotation and states the real coupling |
| **P-8** | `PARENT : SYSTEM` is TRUE for `workspace_body` — it is the top of the boundary | HYPOTHESIS | ❌ **FALSE** | M-6 (runtime): `workspace_body.parent -> workspace_shell (Horizontal)`. Source read at `app.py:1904-1920`: `yield Horizontal(Container(Rail(...), id="rail_slot"), Container(..., id="workspace_body"), id="workspace_shell")` | `PARENT : workspace_shell`, undeclared — **one standing V12 NOTICE**, the staged-retrofit pattern of D-B / D-86-B, one level up |
| **P-9** | `workspace_body` has exactly ten addressable children, and they are exactly the `.db-screen` population | PREMISE | ✅ TRUE | M-6 (runtime): `.db-screen -> 10`; `workspace_body children -> ['screen_workspace', 'screen_a2l', 'screen_mac', 'screen_map', 'screen_issues', 'screen_patch', 'screen_diff', 'screen_flow', 'screen_checks', 'screen_crc_designer']` — the same ten, in compose order, and the same ten values `SCREEN_CONTAINER_IDS` maps (`app.py:5748-5759`) | **`.db-screen` IS an output of this component** — unlike `.db-pane`; see P-10 |
| **P-10** | D-86-A's exclusion still holds for `.db-pane` at this level: it selects a population `workspace_body` does not own as a unit | PREMISE | ✅ TRUE | M-6 (runtime): `.db-pane -> 7`, re-deriving batch-86's figure independently; construction sites at `app.py:2017, 2033, 2044` (this screen) and `5196, 5219, 5279, 5297` (A2L and MAC screens) — grandchildren of three different screens, never a boundary of the shell | `.db-pane` is NOT declared; `.db-screen` is. One address = one population, applied in both directions |
| **P-11** | A parent that declares NO outputs still balances its children's outputs | PREMISE | ❌ **FALSE — and it is the sharper finding** | M-4 arm 5: with `workspace_body` declared carrying zero OUTPUTS, `screen_workspace`'s emits BLOCK **vanished entirely** — V12 printed no finding for it at all. Rule read at `devflow-validate.py:484`: `if child_out and parent_out:` — the emits half is skipped when either side is empty | declaring an output-less parent is a check that cannot fail (C-55 shape); **D-87-B rejects it**, and it is registered for the flow repo as R-87-1 |
| **P-12** | The V22 unreflected-id baseline for this batch is 276 (batch-86's close figure) | PREMISE | ❌ **FALSE** | M-1: the live line reads `278 of 533 batch-declared ids are not reflected in the living canon (HLR 75 · LLR 193 · US 10; e.g. HLR-007a, LLR-001.6, US-87-1)` — and it names `US-87-1`, this batch's own scaffold id | baseline for this batch is **278**; the target is stated against 278, not against 276 |
| **P-13** | `AT-B87-*` / `TC-B87-*` are letter-initial and therefore ungoverned by the id registry, so no reservation is owed | PREMISE | ✅ TRUE | M-1 tail: `grep -c "AT-B86" AT-TC-REGISTRY.jsonl` → **0** and `grep -c "AT-B85" AT-TC-REGISTRY.jsonl` → **0**; `_meta.next_free.AT` reads **282** and is untouched by either predecessor batch | precedent is consistent across batch-85, batch-86 and this batch; the registration question is recorded as D-87-F rather than silently decided |
| **P-14** | `ScreenScaffold` (`screens_directionb.py:182`) contributes an eleventh `.db-screen` instance | PREMISE | ❌ **FALSE** | M-6 tail: `grep -rn "ScreenScaffold" s19_app/ tests/ tools/` excluding its own `class` line returns **5 hits, all docstrings** — the class is never instantiated. Its `classes = "db-screen hidden"` line (`:220`) is a construction site that never fires | cardinality 10 stands; the dead scaffold is registered as R-87-4, not fixed here |
| **P-15** | The in-source claims about the shell's arity are still true | PREMISE | ❌ **FALSE — five stale claims in two files, measured; count corrected at the P2 iteration (R2-04)** | M-6, **re-executed line by line at the P2 iteration**: the compose body yields **ten** children (`app.py:1907-1916`), against which `app.py:1849` says *"an 8-child `#workspace_body`"*, `app.py:1880` says *"the other seven screen containers"*, `app.py:1902` says *"the 8-screen workspace body"*, `app.py:5885` (`action_show_screen`'s docstring) says *"hiding the other eight"*, and `styles.tcss:46` repeats *"the 8-screen `#workspace_body`"`. **Five sites, two files.** The first version cited `app.py:1885` — which holds the line `Used by:` and is wrong by 4,000 lines — and missed `app.py:1902` entirely | the HLR-85.2 defect class, alive on this surface. **NOT fixed here — this is a spec-only batch and they live in source.** Registered as R-87-3 with the exact sites, so the next batch that touches `app.py` inherits the enumeration rather than the category |

**Verdict counts: 9 TRUE · 6 FALSE · 0 UNDECIDABLE.**

**Gate rule:** no ❌ premise blocks this batch. P-6 withdraws a goal observable and replaces it with a
measured cost; P-8 and P-11 together fix the shape of the surface-#3 declaration; P-12 corrects a
baseline; P-14 and P-15 are findings registered, not scope.

## 2.8 · Probe transcripts (C-39 / C-56)

> **These transcripts are corpus input** (C-56). Every line below is pasted, not retyped; no
> mutated or corrupted token appears anywhere in this document — where a probe mutated something,
> the mutation is described by position and operation and the mutated text is not reproduced.
> All synthetic corpora were built under `C:\Users\jjgh8\.claude\jobs\4783ea0a\tmp\`. **The real
> tree was never mutated** (C-40).

### M-1 — validator baseline, Atlas census, registry state

```
0 block - 254 notice - 15 not applicable
[-] V20  .dev-flow/_derived/: atlas current (4 files, census 2)
[!] V12  .dev-flow/2026-08-24-batch-86/01-requirements.md:386: COMPONENT screen_workspace: parent `workspace_body` is not declared in this document, so balancing was NOT checked; this is not a pass
[!] V22  REQUIREMENTS.md: 278 of 533 batch-declared ids are not reflected in the living canon (HLR 75 - LLR 193 - US 10; e.g. HLR-007a, LLR-001.6, US-87-1)
grep -c "AT-B86" AT-TC-REGISTRY.jsonl -> 0
grep -c "AT-B85" AT-TC-REGISTRY.jsonl -> 0
"next_free": {"AT": 282
```

The V12 line is the surface-selection criterion, executed: exactly one undeclared PARENT, and it is
`workspace_body`.

### M-2 — the UNPARSED census entry, read at its own line

```
.dev-flow/_derived/ATLAS-ORPHANS.md:15  UNPARSED census: 2 item(s)
.dev-flow/_derived/ATLAS-ORPHANS.md:17  - [IFC] .dev-flow/2026-08-21-batch-85/01-requirements.md:372 - field `owner` absorbed 801 chars of trailing prose (the IFC parser has no block terminator)
```

The entry names a file and a line. Nothing declared in another file can clear it.

### M-3 — what the parser actually did, by running the parser

`_parse_ifc` was imported from the shipped validator and run over the pilot file. For the LAST
output of the LAST block it printed the `owner` field at **801 chars over 11 lines**:

```
owner value, 801 chars, 11 lines:
   | LLR-85.3
   | [-] V10  01-requirements.md: no FLOW blocks declared - nothing to check
   | [-] V11  01-requirements.md: no COMPONENT blocks declared - Part B is conditional, so this may be correct
   | [-] V12  01-requirements.md: no COMPONENT blocks declared - nothing to balance
   | [-] V13  01-requirements.md: no COMPONENT blocks declared - nothing to search
   | [-] V14  01-requirements.md: no COMPONENT blocks declared - nothing to resolve
   | `python tools/statement_modal_check.py .dev-flow/2026-08-21-batch-85/01-requirements.md`
   | reports **0** modal `should`/`deberia` inside any line beginning `- **Statement:**`, and **0**
   | unfilled placeholders. This probe **can** go RED: inject one `should` into a Statement.
   | (**never a finding count** - see `HLR-85.1`).
   | (`TC-B85-07`, `TC-B85-08`, `TC-B85-09`, `TC-B85-09b`).
```

Two lines of that transcript were re-rendered here with their non-ASCII characters folded to ASCII
so this document does not re-feed a mangled token into the corpus; the character counts above are
the parser's, unmodified. The mechanism is `devflow-validate.py:338-340` — an indented line with no
`key : value` shape is appended to the last field, and a fenced-block close is not a terminator.
**The absorbed content is the pilot's own pasted evidence.** C-56 named this class; here is its
first measured instance in the IFC plane.

### M-4 — `_ifc_corpus` under a duplicate COMPONENT id, six arms, all executed

Arms 1 through 4 run on synthetic corpora; arms 5 and 6 run on a copy of the real corpus at its
as-shipped state plus one synthetic component. Arms 1 and 4 answer D-87-A; arms 2 and 3 answer
D-87-D; **arms 5 and 6 are an A/B pair** and together answer D-87-B. Each arm has its own verdict
line; no figure below is shared between two arms.

```
ARM 1 - two batches declare one COMPONENT id, parent untouched
  [-] V11  01-requirements.md: 7 OUTPUT(s), each with an address and a declared consumer list
  [x] V12  ...childnew/01-requirements.md:6: COMPONENT child_panel: emits artifact_row_set, unload_all_row, which `parent_screen` does not declare - unbalanced
  [!] V19  ...childnew/01-requirements.md:6: COMPONENT child_panel is declared 2 times (...childold:6, ...childnew:6) - balancing resolves it to the LAST and ignores the rest, while the OUTPUT contract counts all of them, so the two rules judge different components under one id

ARM 2 - one re-authored child, parent re-export NOT updated (the "edit one file" hypothesis)
  [-] V11  01-requirements.md: 5 OUTPUT(s), each with an address and a declared consumer list
  [x] V12  ...childnew/01-requirements.md:6: COMPONENT child_panel: emits artifact_row_set, unload_all_row, which `parent_screen` does not declare - unbalanced
  [-] V19  01-requirements.md: 2 COMPONENT id(s), each declared exactly once

ARM 3 - one re-authored child, parent re-export UPDATED
  [-] V11  01-requirements.md: 6 OUTPUT(s), each with an address and a declared consumer list
  [-] V12  01-requirements.md: balancing holds on 1 parented component(s)
  [-] V19  01-requirements.md: 2 COMPONENT id(s), each declared exactly once

ARM 4 - duplicate child on the UPDATED parent (option (b) at its best)
  [-] V11  01-requirements.md: 8 OUTPUT(s), each with an address and a declared consumer list
  [x] V12  ...childold/01-requirements.md:6: COMPONENT child_panel: emits slot_rows, which `parent_screen` does not declare - unbalanced
  [!] V19  ...childnew/01-requirements.md:6: COMPONENT child_panel is declared 2 times ...

ARM 5 - the parent declares ZERO outputs (batch-85 and batch-86 as shipped, plus a synthetic workspace_body carrying PARENT and INPUTS but no OUTPUTS block)
  [-] V11  01-requirements.md: 35 OUTPUT(s), each with an address and a declared consumer list
  [!] V12  ...batch-87/01-requirements.md:6: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
  [-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once

ARM 6 - same corpus, same synthetic component, but the parent declares ONE output (non-empty and incomplete)
  [-] V11  01-requirements.md: 36 OUTPUT(s), each with an address and a declared consumer list
  [x] V12  .dev-flow/2026-08-24-batch-86/01-requirements.md:386: COMPONENT screen_workspace: emits a2l_scroll, a2l_title, a2l_view, artifact_slots, center_pane, empty_state, files_list, files_title, goto_button, goto_input, hex_controls, hex_scroll, hex_title, hex_view, left_pane, load_project_button, memstrip_band, panel_handle, panes_container, project_row, right_pane, screen_root, search_button, search_input, sections_list, sections_title, slot_rows, slots_container, ws_stats, ws_stats_title, which `workspace_body` does not declare - unbalanced
  [!] V12  ...batch-87/01-requirements.md:6: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
  [-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once
```

**Arm 4 is the one that settles D-87-A.** There is no parent output set that balances the old and
the re-authored declaration at once: name the old id and the new declaration BLOCKs (arm 2 shape);
name the new ids and the old declaration BLOCKs (arm 4); name all three and the parent declares an
output no child emits. Two declarations of one contract cannot both be true, and the validator says
so in two directions.

**Arms 5 and 6 together settle D-87-B, and they are ONE A/B pair — the corpus is identical, the
only difference is whether the parent's OUTPUTS block exists.** In arm 6 the child's emits BLOCK
fires and enumerates thirty ids. In arm 5 — same corpus, same child, same parent id — **it is not
merely weaker, it is absent**: V12 prints no finding for `screen_workspace` at all. That is the
C-55 shape, and it is why D-87-B rejects the cheap form.

> ⚠️ **Corrected at the P2 iteration (R2-08).** As first written this section declared "five arms"
> and attributed arm 6's thirty-id BLOCK to arm 5 — two mutually exclusive configurations under one
> label, since a BLOCK enumerating thirty ids requires a non-empty parent output set while P-11's
> whole point is that arm 5's set is empty. Both transcripts were real; the attribution was not.
> Re-derived at the iteration by running each configuration separately, and both are pasted above
> with their own verdict lines.

Arm 6's list is thirty ids, printed by the rule rather than assembled by hand — the re-export set of
§5.3, measured against batch-86 **as it shipped** (`slot_rows` still present, hence thirty; after the
split it is thirty-one).

### M-5 — the real coupling of the pilot's only row-set consumer

`tests/test_tui_variants.py:96-99`, read this session:

```
    for row in app.query("#loaded_slots > Horizontal"):
        cells = list(row.children)
        if cells and str(cells[0].render()).strip() == LoadedArtifactsPanel._PROJECT_KIND:
            return str(cells[1].render())
```

A linear sweep, a content predicate on `cells[0]`, and a positional read of `cells[1]`. Not an index
over rows. `_PROJECT_KIND` is a class attribute (`screens_directionb.py:1813`), so its VALUE is
outside the contract by definition — pilot F-8, still a declared bound and now stated on the output.

By contrast, `.loaded-detail` IS indexed positionally, and that annotation was re-verified rather
than inherited: `tests/test_help_toggle_and_a2l_panel.py:72-73` does `cells = list(panel.query(".loaded-detail"))`
then `cells[2].render()`; `tests/test_unload_feature.py:260-272` builds the ordered list documented
as `_SLOTS` order; `tests/test_tui_commandbar.py:1300` asserts the query selects exactly three.

### M-6 — runtime probe: cardinalities and the compose tree

Run under conda `s19env` through Textual's `run_test()` — the app itself, not a reading of it:

```
#workspace_shell         -> 1
#workspace_body          -> 1
.db-screen               -> 10
.db-pane                 -> 7
#rail_slot               -> 1
#screen_workspace        -> 1
#loaded_panel            -> 1
#loaded_slots            -> 1
.loaded-slot             -> 4
.loaded-allrow           -> 1
.loaded-detail           -> 3
.loaded-project-detail   -> 1
workspace_body parent  -> workspace_shell Horizontal
workspace_body gparent -> _default Screen
workspace_body children -> ['screen_workspace', 'screen_a2l', 'screen_mac', 'screen_map', 'screen_issues', 'screen_patch', 'screen_diff', 'screen_flow', 'screen_checks', 'screen_crc_designer']
loaded rows -> [('loaded-slot-absent','loaded-slot',2), ('loaded-slot-absent','loaded-slot',2), ('loaded-slot-absent','loaded-slot',2), ('loaded-slot-absent','loaded-slot',2), ('loaded-allrow',1)]
```

The last line is the empty state: four `.loaded-slot` rows of two cells each plus one
`.loaded-allrow` of one. The row COUNT is state-invariant (four rows are always mounted); the CELL
count inside a row is not, which is exactly why the two populations are two outputs.

The `frozenset(...)` wrappers Textual prints around each row's class set were flattened to plain
tuples above for readability; the class names and the child counts are verbatim.

### M-7 — the per-(output_id, file) reacher census, at V13's own search width

The census script re-implements V13's walk exactly — the same `_V13_SKIP_DIRS` (which excludes
`.dev-flow/` and `build/`, and does NOT exclude `.fast-dev-flow/` or `prototypes/`) and the same
`_V13_EXT` extension set — so a pair it reports is a pair the rule will report.

```
LITERAL '#loaded_panel' -> 7 file(s)
    .fast-dev-flow/archive/2026-07-23-n6-n7-spec.md
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    s19_app/tui/styles.tcss
    tests/test_help_toggle_and_a2l_panel.py
    tests/test_tui_commandbar.py
    tests/test_unload_feature.py
LITERAL '#loaded_slots' -> 4 file(s)
    s19_app/tui/screens_directionb.py
    s19_app/tui/styles.tcss
    tests/test_tui_commandbar.py
    tests/test_tui_variants.py
LITERAL '.loaded-slot' -> 1 file(s)
    s19_app/tui/styles.tcss
LITERAL '.loaded-allrow' -> 1 file(s)
    s19_app/tui/styles.tcss
LITERAL '.loaded-detail' -> 5 file(s)
    .fast-dev-flow/archive/2026-08-21-batch-85-ifc-pilot-promoted-spec.md
    s19_app/tui/styles.tcss
    tests/test_help_toggle_and_a2l_panel.py
    tests/test_tui_commandbar.py
    tests/test_unload_feature.py
LITERAL '.loaded-project-detail' -> 2 file(s)
    s19_app/tui/styles.tcss
    tests/test_tui_commandbar.py
LITERAL '#loaded_slots > Horizontal' -> 1 file(s)
    tests/test_tui_variants.py
LITERAL '#workspace_body' -> 12 file(s)
    .fast-dev-flow/ADR-flow-builder-tracer.md
    REQUIREMENTS.md
    s19_app/tui/app.py
    s19_app/tui/screens.py
    s19_app/tui/screens_directionb.py
    s19_app/tui/styles.tcss
    tests/test_crc_designer_view.py
    tests/test_tui_directionb.py
    tests/test_tui_mac_layout.py
    tests/test_tui_patch_layout.py
    tests/test_tui_snapshot.py
    tests/test_tui_workspace_layout.py
LITERAL '.db-screen' -> 1 file(s)
    s19_app/tui/styles.tcss
LITERAL '#screen_a2l' -> 4 file(s)
    docs/architecture.md
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    tests/test_tui_directionb.py
LITERAL '#screen_mac' -> 4 file(s)
    docs/architecture.md
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    tests/test_tui_directionb.py
LITERAL '#screen_map' -> 5 file(s)
    REQUIREMENTS.md
    docs/architecture.md
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    tests/test_tui_directionb.py
LITERAL '#screen_issues' -> 7 file(s)
    REQUIREMENTS.md
    docs/architecture.md
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    s19_app/tui/styles.tcss
    tests/test_tui_directionb.py
    tests/test_tui_issues_view.py
LITERAL '#screen_patch' -> 2 file(s)
    docs/architecture.md
    s19_app/tui/app.py
LITERAL '#screen_diff' -> 5 file(s)
    docs/architecture.md
    s19_app/tui/app.py
    tests/test_tui_commandbar.py
    tests/test_tui_diff_screen.py
    tests/test_tui_directionb.py
LITERAL '#screen_flow' -> 6 file(s)
    .fast-dev-flow/ADR-flow-builder-tracer.md
    .fast-dev-flow/archive/2026-07-14-batch44-flow-builder-spec.md
    REQUIREMENTS.md
    s19_app/tui/app.py
    tests/test_flow_builder_render.py
    tests/test_tui_directionb.py
LITERAL '#screen_checks' -> 4 file(s)
    prototypes/legend_n8.INVENTORY.md
    s19_app/tui/app.py
    s19_app/tui/styles.tcss
    tests/test_tui_checks_screen.py
LITERAL '#screen_crc_designer' -> 4 file(s)
    docs/crc-algorithm-designer/01-requirements.md
    s19_app/tui/app.py
    s19_app/tui/crc_designer_view.py
    tests/test_crc_designer_view.py
```

### M-8 — the bare-name channel, swept at DECLARED width (the C-55 search-width guard)

Batch-86's blocker B86-R2-01 measured that sweeping the bare channel in `app.py` alone missed four
dependant pairs. This sweep covers **both `s19_app/` and `tests/`, for all eleven ids** of surface
#3. What it found, and every one of these is a coupling whose grep hit is not a `#`-literal:

| Site | Couples to | Why it is a dependant |
|---|---|---|
| `s19_app/tui/app.py::SCREEN_CONTAINER_IDS` (`:5748-5759`) | all ten screen container ids, bare | `action_show_screen` reads `self.SCREEN_CONTAINER_IDS[screen_key]` (`:5923`) and iterates `.values()` (`:5924`); rename a container id and rail routing stops resolving |
| `s19_app/tui/app.py::_EMPTY_STATE_SCREENS` (`:6008-6013`) | `screen_workspace`, `screen_issues`, `screen_map`, `screen_checks`, bare | pairs each screen id with its real-content child id for the empty-state swap |
| `tests/test_tui_directionb.py` (`:137-146`) | all ten, bare, as a module-level tuple | the rail-screen inventory the Direction-B suite asserts over |
| `tests/test_tui_commandbar.py` (`:135, :306, :316, :481`) | `screen_workspace`, `screen_a2l`, `screen_mac`, `screen_issues`, `screen_map`, bare | visibility assertions written against bare ids (`assert visible == ["screen_workspace"]`) |
| `tests/test_tui_directionb.py` (`:5434`, `:6458`) | `screen_flow`, `screen_mac`, bare | `assert visible == ["screen_flow"]` / `["screen_mac"]` |

**Declared width is the guarantee.** The sweep covered `s19_app/**` and `tests/**` for eleven bare
ids; it did NOT cover `prototypes/`, `docs/` or the archives, because a bare id in prose is not a
coupling. That bound is stated so nobody reads the empty remainder as coverage.

### M-9 — classification evidence for the pairs a reader would most likely dispute

| Pair | Class | Evidence |
|---|---|---|
| `body_root` × `s19_app/tui/app.py` | DEPENDANT | `query_one("#workspace_body")` at `:5311` (`on_mount`), `:6341` (`action_cycle_density`), `:6379` (`_apply_width_regime`) |
| `body_root` × `s19_app/tui/screens.py` | mention | `:1033`, a `#:` comment |
| `body_root` × `tests/test_tui_patch_layout.py` | DEPENDANT | `:669` asserts the literal selector string is present in the compiled CSS — it breaks if the address moves |
| `issues_screen` × `s19_app/tui/styles.tcss` | mention | `:740` is inside a `/* ... */` comment; the rule that follows selects `#issues_content`, not `#screen_issues` |
| `checks_screen` × `s19_app/tui/styles.tcss` | mention | `:1356`, same shape; the rule selects `#checks_content` |
| `map_screen` / `flow_screen` / `diff_screen` × `s19_app/tui/app.py` | DEPENDANT via the bare channel | their `#`-literal hits in `app.py` are compose docstrings (the provider accident, pilot F-2); the real coupling is `SCREEN_CONTAINER_IDS` — M-8 |
| `screen_slot_set` × `s19_app/tui/styles.tcss` | DEPENDANT | `:125` `.db-screen {` is a live rule. `:130` `.db-screen-title` is a DIFFERENT class whose name contains the first as a substring — the `#ws_stats`/`#ws_stats_title` collision shape of batch-86 P-6, checked here and harmless: the same file carries a bare hit, so the pair is genuine either way |

## 3 · Acceptance (black-box) — the user-verified outcomes

> Layer B. The "user" is the operator auditing addressability; the shipped surface is the validator
> + Atlas toolchain reading the authored records (trigger B4: the acceptance runs the REAL consumers
> over the real records, never a hand-fed copy). `AT-B87-*` ids are letter-initial ⇒ ungoverned by
> the registry (P-13), provisional-until-Phase-3 per V-5. **No new pytest files**
> (`EXPECTED_SCANNED_TEST_FILES` stays pinned); these acceptances are operator-local validator runs,
> and saying so is the honest form.

### AT-B87-01 — the UNPARSED census loses its only IFC entry

- **Observable outcome:** after `--atlas --write`, `.dev-flow/_derived/ATLAS-ORPHANS.md` carries no
  line beginning `- [IFC]`, and the census total drops from 2 to 1; the surviving entry is the
  BATCHES dir-name item, which is the **negative control** — a census that emptied completely would
  mean the census stopped counting, not that the debt cleared.
- **Shipped surface:** `python ~/.claude/docs/tools/devflow-validate.py --atlas --write`, then a
  plain run.
- **Deliverable + observation:** §5.6 carries the pre-state (M-2) and the post-state verbatim.
- **Boundary catalog:** ☑ empty — M-2 is the recorded RED arm · ☑ boundary — the census is compared
  as a COUNT and as the surviving entry's TEXT, because a count alone cannot tell "the IFC entry
  cleared" from "a different entry cleared" · ☑ invalid — re-indenting any line after the block
  restores the absorption, which is what LLR-87.4 forbids · ☐ error — N/A: the census has no
  file-resolution failure mode.

### AT-B87-02 — the re-authored pilot contract balances, and its own parent stays checked

- **Observable outcome:** V12 reports `loaded_panel` balanced against `screen_workspace` (0 findings
  naming `loaded_panel`), and V19 reports each COMPONENT id declared exactly once — no fork.
- **Shipped surface:** the same validator run.
- **Deliverable + observation:** §5.6 post-state; both failing directions demonstrated by M-4 arms 2
  and 4, and by a LIVE pre-fix run over the real corpus that printed
  `COMPONENT loaded_panel: emits artifact_row_set, unload_all_row, which screen_workspace does not
  declare` before the batch-86 re-export was updated (§5.6).
- **Boundary catalog:** ☑ empty — the live pre-fix BLOCK is the RED arm, on the real corpus, not a
  synthetic one · ☑ boundary — the split changes the emitted id set by exactly one removal and two
  additions, and each direction was executed · ☑ invalid — a second declaration of the same id
  yields the V19 NOTICE and the arm-4 BLOCK · ☐ error — N/A: V12 is a set-containment rule.

### AT-B87-03 — surface #3 is declared, and the last named undeclared PARENT moves one level up

- **Observable outcome:** V12 prints **exactly one** finding, and it names `workspace_body` and
  `workspace_shell` — not `screen_workspace` and `workspace_body`. The retrofit's boundary moved; it
  did not vanish, and a threshold of "0 V12 findings" would have been a lie about a staged retrofit.
- **Shipped surface:** the same validator run.
- **Deliverable + observation:** §5.6 post-state, stated as an ENUMERATED RESIDUAL (the one finding
  named), never as a count alone.
- **Boundary catalog:** ☑ empty — M-1's pre-state finding is the RED arm · ☑ boundary — the INPUTS
  superset is exact: `workspace_body.INPUTS` must contain all five of `screen_workspace`'s, and
  M-4 arm 5 ran with exactly that set · ☑ invalid — declaring `PARENT : SYSTEM` would be false and
  is refuted by M-6 · ☑ error — a consumers entry naming an absent file is a V14 BLOCK, evidenced by
  the shipped selftest arm `V14 BLOCK-nofile` (`devflow-validate.py:2667`).

### AT-B87-04 — the Atlas RENDERS surface #3 as its own declaration, not as a mention

- **Observable outcome:** after `--atlas --write`, `.dev-flow/_derived/ATLAS-IFC.md` contains
  **exactly one** line matching the heading form `### COMPONENT` followed by the id `workspace_body`
  in backticks, where the pre-state file contained **zero**; the total count of `### COMPONENT`
  headings goes **2 → 3**; and no `{id: component}` collapse appears (each declaration keeps its own
  row set — the failure shape the Atlas handoff §5.4 names).
- **Shipped surface:** `python ~/.claude/docs/tools/devflow-validate.py . --atlas --write`, then the
  bytes of the regenerated file.
- **Deliverable + observation:** §5.6 carries both measurements.
- **Negative control, in the same probe:** the heading grep for `screen_workspace` returns **1** in
  the pre-state file and **1** in the post-state file — proof that the grep and the file both work
  before the change, so a post-state `1` for `workspace_body` is a change and not an artifact of the
  predicate.
- **Boundary catalog:** ☑ empty — pre-state 0 is the RED arm, measured on the committed file ·
  ☑ boundary — the predicate is the HEADING form, not a bare substring: a bare
  `grep -c "workspace_body"` returns **2** in the pre-state (batch-86's `parent : workspace_body`
  row and V12's own finding text), so a "≥ 1" threshold on it is GREEN before any work · ☑ invalid —
  a duplicate declaration renders two rows and is caught by V19 (M-4 arms 1 and 4) · ☐ error — N/A:
  the generator either writes the file or V20 BLOCKs.

> ⚠️ **This acceptance exists because of R2-06 and R2-07, and the reviewer was right twice.** The
> qa plan's `AT-B87-06` was the only acceptance observing `ATLAS-IFC.md` bytes, and it was dropped
> from the first fold with no disposition — a coverage hole (R2-07). Its stated pre-state
> measurement was also FALSE (R2-06): I re-measured the committed pre-state file myself and the
> bare grep returns **2**, not 0, so its own RED arm never existed. Both defects are fixed here by
> a predicate that discriminates, re-measured in both states rather than carried over.

### AT-B87-05 (PIN) — the batch's source diff is empty

- **Observable outcome:**
  `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml`
  reports 0 files / 0 insertions / 0 deletions at the gate.
- **Shipped surface:** git.
- **Deliverable + observation:** the increment gate record.
- **Negative control (qa plan §4):** the same command with `.dev-flow/` added to its scope returns
  NON-empty — proof the diff command is not silently a no-op.
- **Boundary catalog:** ☑ empty — trivially observable · ☑ boundary — the diff scope names the four
  source paths explicitly, in merge-base form · ☐ invalid / ☐ error — N/A: a one-command structural
  check.
- **Labelled a PIN, not a gate:** it is green before any work and invariant under every edit this
  batch makes.

### AT-B87-06 (PIN) — the suite ledger holds

- **Observable outcome:** the whole-suite run matches the recorded base ledger,
  `post = base - 0 + 0`.
- **Shipped surface:** the orchestrator's gate suite run under conda `s19env` (the orchestrator owns
  suite runs — C-25; this document does not execute pytest, because a second run is a second truth).
- **Deliverable + observation:** `PLAN.md` test ledger, per the qa plan §7 protocol — whole run
  redirected to a file, never piped through `tail` (C-19), ANSI stripped before grepping FAILED.
- **Boundary catalog:** ☑ empty — `D = A = 0` is structural, proved by AT-B87-05's empty diff over
  `tests/` rather than assumed · ☑ boundary — the six pre-existing flaky nodes are dispositioned in
  advance in the qa plan §7, by exact node id · ☐ invalid / ☐ error — N/A.
- **Not executable at authoring**, and separated from AT-B87-05 for exactly that reason (R2-12):
  merging an executable structural check with a gate-time suite run into one AT lets the executable
  half report green for both.

### Behavioral traceability (US → AT → outcome)

| US | Observable outcome | Shipped surface | AT | Observed? |
|----|--------------------|-----------------|----|-----------|
| US-87-1 | The `[IFC]` UNPARSED entry is gone; the BATCHES control remains | `--atlas --write` + V20 | `AT-B87-01` | pre-state ✅ M-2 |
| US-87-1 | `loaded_panel` balances at six outputs; one declaration, not two | `devflow-validate.py` | `AT-B87-02` | RED arm ✅ state A (§5.6) |
| US-87-2 | The single V12 finding names `workspace_body`/`workspace_shell` | `devflow-validate.py` | `AT-B87-03` | pre-state ✅ M-1 |
| US-87-2 | The Atlas renders surface #3 as its own declaration | `--atlas --write` + the file's bytes | `AT-B87-04` | pre-state ✅ 0 headings (§5.6) |
| US-87-1 + US-87-2 | 0 product files touched | git | `AT-B87-05` (pin) | measured at gate |
| US-87-1 + US-87-2 | Suite-neutral | gate suite | `AT-B87-06` (pin) | measured at gate |

### Batch acceptance criteria

- **3** HLRs and **8** LLRs covered by **8** inspection/analysis TCs (`TC-B87-01` … `TC-B87-08`); the
  two stories by **6** ATs — four gating acceptances and two labelled pins (`AT-B87-01` … `AT-B87-06`,
  the id space reconciled with `01b-qa-validation-plan.md` by the mapping table below).
- **0 BLOCK attributable to this batch** in the post-state run — stated WITH its scope, **per run
  rather than summed** (R2-01): the batch's own edits passed through two transient states, **state A
  at `11 block`** (1 V12 emits + 6 V21 owner + 4 V20 drift) and **state B at `12 block`** (8 V21
  owner + 4 V20 drift, zero V12), both re-derived at the P2 iteration and pasted in §5.6. Thirteen
  distinct RED instances in three families were observed across the sequence; **no state carried all
  thirteen at once**. All are discharged. A criterion without that scope would be the unfalsifiable
  batch-85 §6.3 shape; a criterion that sums two mutually exclusive runs into one number is the
  spliced-evidence shape this iteration removed.
- V12's finding count is **1** and it is ENUMERATED: `workspace_body` / `workspace_shell`. V19
  reports **3** COMPONENT ids, each declared exactly once.
- Every V13 figure is stated over the **(output_id, file) PAIR set** of §5.6 — never a finding count,
  never a file-set union.
- Ledger: `post = base - 0 + 0` (0 test files added or removed).
- **V22's unreflected aggregate at CLOSE is ≤ 278**, the measured baseline at this station (P-12,
  M-1) — not 276, which was batch-86's close figure and had already been overtaken by this batch's
  own scaffold ids. The Phase-3 canon-seeding increment owes the shrink-back.
- **Expected unowned-LLR notices, enumerated:** `LLR-87.4` and `LLR-87.8` from this document (both
  constrain without transforming), plus `LLR-85.4`, `LLR-85.5`, `LLR-85.6`, `LLR-85.7` from batch-85
  (the last three lost their owner citations when the `ifc_pilot_authoring` pseudo-FLOW was deleted
  — D-87-E) and `LLR-86.7`, `LLR-86.8` from batch-86. Threshold = **0 UNEXPECTED** unowned-LLR ids,
  never "0 notices".

### Reconciliation with `01b-qa-validation-plan.md` (R2-02)

> **The two Phase-1 artifacts forked the `AT-B87-*` id space**: the qa plan defines six ATs plus two
> pins, this record originally defined four, and the same id did not mean the same acceptance in
> both. That is a real defect — an id is a promise that two readers are discussing one thing — and
> it is fixed by mapping, not by renaming one side into silence. **`01b-qa-validation-plan.md` is
> the SOURCE; this record is where its rows are realized.** Where an id is reused with a different
> meaning, the table says so explicitly. **Nothing is dropped without a stated reason** (C-40 limb 2).

| `01b` id | Realized in this record as | Same observable? | Note |
|---|---|---|---|
| `AT-B87-01` (ORPHANS bytes: `[IFC]` absent, `[BATCHES]` present) | `AT-B87-01` + **G1** | ✅ identical | id and meaning agree |
| `AT-B87-02` (zero V12 rows containing `loaded_panel`) | `AT-B87-02` + **G3** | ✅ identical | id and meaning agree |
| `AT-B87-03` (counted V11/V14/V19/V21 messages; pilot 5 → 6 outputs) | **G5** + the thresholds of HLR-87.1 and HLR-87.2 | ⚠️ **re-homed** | realized as a GATE, not an AT. The id `AT-B87-03` is REUSED in this record for the V12 residual — see the next row. Reader beware: `AT-B87-03` does not mean the same thing in the two files |
| `AT-B87-04` (V13 enumerated PAIR set) | **G6** + §5.6's per-record pair census | ⚠️ **re-homed** | realized as a GATE. The id `AT-B87-04` is REUSED here for the Atlas-rendering acceptance |
| `AT-B87-05` (V12: 0 naming `screen_workspace`/`workspace_body`, exactly 1 enumerated residual) | `AT-B87-03` + **G2** | ⚠️ **renumbered** | same observable, different id |
| `AT-B87-06` (`ATLAS-IFC.md` bytes: `### COMPONENT` heading for the new id) | `AT-B87-04` + **G10** | ⚠️ **renumbered AND its predicate corrected** | R2-07: it had been dropped entirely from the first fold. R2-06: its stated pre-state (`grep -c "workspace_body"` = 0) is FALSE — re-measured at **2** — so the predicate is now the heading form, re-measured in both states |
| `P-src` (source-scope diff, merge-base form) | `AT-B87-05` (pin) + **G9** | ✅ identical | promoted from an unnumbered pin to a numbered one |
| `P-ledger` (suite ledger) | `AT-B87-06` (pin) + **G11** | ✅ identical | split out of the old combined pin per R2-12 |
| `01b` G1 · G2 · G3 · G4 · G5 · G7 · G8 · G9 | **G1** · **G2** · **G3** · **G5** · **G6** · **G8** · **G9** · **G11** | ✅ | one-for-one; this record adds **G4** (V19 single-declaration) and **G7** (V20 currency), which `01b` folded into its G4 and G6 |
| `01b` G6 (Atlas rows AND V20 currency) | **G7** (currency) + **G10** (rendering) | ⚠️ **split** | the two halves are independent: V20 can report the Atlas current while the rendering is wrong, which is precisely the hole R2-07 found |

**Retired without realization: none.** Every `01b` row above is realized as an AT, a gate, or both.

**Consequence for D-87-F, recorded rather than left standing.** That decision's cost line read
"none today". This fork refutes it: two artifacts of one phase minted overlapping `AT-B87-*` ids
with different meanings, and nothing mechanical caught it, precisely because letter-initial ids are
outside the registry's authority. The cost of staying outside the registry is therefore **not zero**
— it is that id collisions inside a batch are caught by review or not at all. D-87-F's cost cell is
amended accordingly, and the decision itself stands.

### Gate criterion set G-87

| Gate | Criterion (pre-state → required post-state) | Status at P1 |
|---|---|---|
| **G1** (headline) | `ATLAS-ORPHANS.md` UNPARSED census `2 → 1` item, and the surviving item is the BATCHES entry, not an `[IFC]` one | **GREEN** (§5.6) |
| **G2** | V12 prints exactly **1** finding, naming `workspace_body` / `workspace_shell`; **0** findings name `loaded_panel` or `screen_workspace` | **GREEN** (§5.6) |
| **G3** | the batch-86 re-export block declares `artifact_row_set` + `unload_all_row` and no longer declares `slot_rows`; the live pre-fix run's `emits` BLOCK is absent from the post-state | **GREEN** — the RED arm is a real run, pasted in §5.6 |
| **G4** | V19 reports **3** COMPONENT id(s), each declared exactly once — no forked contract | **GREEN** |
| **G5** | counted messages, corpus-wide: V10 · V11 · V14 · V21 at the §5.6 figures; final line `0 block`; no BLOCK located under `.dev-flow/2026-08-24-batch-87/`, `.dev-flow/2026-08-21-batch-85/`, `.dev-flow/2026-08-24-batch-86/` or `.dev-flow/_derived/` | **GREEN** (§5.6) |
| **G6** | V13's stray census equals the enumerated §5.6 PAIR set, stated as an addition of disjoint per-line sets (batch-85's pairs at its lines PLUS batch-86's at its lines PLUS batch-87's at its lines), never a union and never a count alone | **GREEN** (§5.6) |
| **G7** | V20 reports the Atlas current at every gate, `4 files`, census as in G1 | **GREEN** |
| **G8** | per-id canon greps ≥ 1 for every batch-87 heading id — **executed AT THE P3 INCREMENT GATE**, one grep per id, one id per line (the batch-86 M7 lesson), with CLOSE as the confirming re-measurement | **GREEN** — discharged by increment 001 (`03-increments/increment-001.md` §4). All **thirteen** declared ids grep ≥ 1 in `REQUIREMENTS.md`, one grep per id: `US-87-1` 2 · `US-87-2` 1 · `HLR-87.1` 2 · `HLR-87.2` 1 · `HLR-87.3` 1 · `LLR-87.1` 2 · `LLR-87.2` 1 · `LLR-87.3` 1 · `LLR-87.4` 1 · `LLR-87.5` 3 · `LLR-87.6` 1 · `LLR-87.7` 1 · `LLR-87.8` 1. Validator, same tree: `[!] V22  REQUIREMENTS.md: 276 of 544 batch-declared ids are not reflected in the living canon (HLR 75 · LLR 193 · US 8)` against a pre-edit `289 of 544 (HLR 78 · LLR 201 · US 10)` — a shrink of exactly the 13 seeded, final line `0 block · 284 notice · 15 not applicable`. ⚠ **§7 says eleven and the record declares thirteen**: eleven is what P1 authoring ADDED (278 → 289), the other two being this batch's own scaffold ids, which the census retires alike. Found by counting ids one at a time, which is the M7 lesson working |
| **G9** (PIN) | source-scope diff empty — labelled a pin, not a gate | GREEN (pin) |
| **G10** | `ATLAS-IFC.md` on disk carries exactly **1** `### COMPONENT` heading naming `workspace_body` where the committed pre-state carried **0**, and the heading total goes 2 → 3; the `screen_workspace` heading returns 1 in BOTH states (negative control). Currency alone (G7 / V20) does not imply rendering, which is why this is a separate gate | **GREEN** (§5.6) — added at the P2 iteration, R2-07 |
| **G11** (PIN) | ledger `post = base - 0 + 0`, measured by the orchestrator's gate suite run — separated from G9 because it is not executable at authoring (R2-12) | measured at gate (pin) |

**Kill-mutation disposition.** M2/M3/M6/M8 of the standing protocol are discharged by CITATION of
the shipped `--selftest` arms (192 arms, exit 0). **This batch additionally carries LIVE RED arms
taken on the REAL corpus rather than in memory**, which is stronger evidence than batch-86 had.
Stated per state, since the states are mutually exclusive (R2-01):

| Family | Instances | Observed in | Went green by |
|---|---|---|---|
| V12 `emits artifact_row_set, unload_all_row` | 1 | state A only | LLR-87.5's re-export update — this transition is G3's evidence |
| V21 owner not defined in the corpus | 6 in state A, 8 in state B | both | this document declaring the `LLR-87.*` headings |
| V20 derived-file drift | 4 | both | the Atlas regeneration at the gate |

Thirteen distinct instances across three families; **11 in state A, 12 in state B, never 13 at
once**. Each family went green by the intended change and by nothing else. **Still OWED batch-local
at Phase 4, on a copy:** the consumers-entry mutation (remove one entry → the V13 PAIR count moves
+1 while the file-set union may not) and the canon-mirror grep mutation. Never the live tree (C-40).

## 4 · Requirements (HLR / LLR)

> Scope-rule convention (batch-85 defect #7 closed): **every Statement names the population it
> quantifies over.** No repo-wide predicate appears anywhere in this section, and `should` appears
> in no normative statement.

### HLR-87.1 — the pilot's contract is re-authored, parses whole, and exists exactly once

- **Traceability:** US-87-1
- **Statement:** When the flow validator and the Atlas generator run against this repository, the system shall report the `loaded_panel` component as a single declaration of six outputs whose every field parses to its written value — the quantified population being the `COMPONENT loaded_panel` block of `.dev-flow/2026-08-21-batch-85/01-requirements.md` §8 and the UNPARSED census of `.dev-flow/_derived/ATLAS-ORPHANS.md`.
- **Validation:** `inspection` (the validator lives outside the repository and is operator-local — batch-85 §6.2 precedent; a `test` label would assert a pytest node that cannot exist)
- **Executed verification:** `python ~/.claude/docs/tools/devflow-validate.py .` and `--atlas --write` at the worktree root; pre-state M-1/M-2, post-state §5.6.
- **Numeric pass threshold:** V19 reports **3** COMPONENT ids, each declared exactly once; the UNPARSED census reports **1** item and **0** items whose class tag is `[IFC]`; the `loaded_panel` block declares **6** outputs; **0** parsed field of that block exceeds the length of the text written for it.
- **Priority:** high
- **Acceptance (black-box):** `AT-B87-01`, `AT-B87-02` (§3).

### HLR-87.2 — surface #3 is contractually addressable, and the retrofit's residual is named

- **Traceability:** US-87-2
- **Statement:** When V10 through V21 run over the merged IFC corpus, the system shall report counted verdicts that include the `workspace_body` component declared in §5.3 of this document, and V12 shall confine its not-checked notice to `workspace_body`'s own undeclared parent — the quantified population being the complete finding set of one validator run over the merged corpus.
- **Validation:** `inspection`
- **Executed verification:** the V10/V11/V12/V13/V14/V19/V21 lines of the post-state run (§5.6); the balancing arms executed on synthetic corpora (M-4) and the enumeration of the owed re-export taken from the rule's own BLOCK text.
- **Numeric pass threshold:** exactly **1** V12 finding, naming `workspace_body` and `workspace_shell`; **0** V12 findings name `screen_workspace` or `loaded_panel`; V11, V14 and V21 report the §5.6 figures with **0** BLOCK.
- **Priority:** high
- **Acceptance (black-box):** `AT-B87-03` and `AT-B87-04` (§3) — the V12 residual and the Atlas rendering; declaring a component and RENDERING it are two observables, and G7's currency check proves neither (R2-07).

### HLR-87.3 — the per-surface cost gains a third point, and the re-export compounding is measured

- **Traceability:** US-87-1, US-87-2
- **Statement:** When this batch closes, the close record shall report the per-surface figures for surface #3 beside those of surfaces #1 and #2, each figure either cited to an executed M-id measurement or carrying a declared capture/absence disposition, together with a dispersion statement over the three measured surfaces, the measured re-export duplication figure, and zero extrapolated retrofit totals — the quantified population being the figure table of `05-close.md` compared against §5.6, batch-86 §5.6 and batch-85 §7.4.
- **Validation:** `analysis`
- **Executed verification:** re-read of `05-close.md` against §5.6's figure table; effort span from `git log --format='%h %ad' --date=iso` over this batch's commits.
- **Numeric pass threshold:** **6** of 6 figures non-null at n=**3**; **1** dispersion statement in range form (no mean); **1** stated duplication figure derived from the post-state V13 pair census; **0** totals computed from the still-unmeasured surface count (batch-85 P-9 stands).
- **Priority:** medium
- **Acceptance (black-box):** `AT-B87-05` and `AT-B87-06` (the two pins) cover the neutrality half; the figure half is Layer-A analysis by design (partially unobservable, declared — pilot HLR-85.4 precedent: a green check never means "the cost is correct").

### LLR-87.1 — the pilot's structural handles are re-declared with measured consumer sets

- **Traceability:** HLR-87.1
- **Statement:** The re-authored `loaded_panel` record shall declare `panel_handle` and `slots_container` with their addresses, cardinality 1, and the consumer sets measured in M-7 and M-9 — the quantified population being those two OUTPUT entries of the §8 block in the batch-85 record.
- **Validation:** `inspection`
- **Executed verification:** the V11/V13/V14 lines of the post-state run; census M-7.
- **Numeric pass threshold:** V11 reports **0** BLOCK over these two; V14 resolves their **8** consumer entries; V13's stray pairs for them are exactly **3** — `panel_handle` 2 (`.fast-dev-flow/archive/2026-07-23-n6-n7-spec.md`, `prototypes/legend_n8.INVENTORY.md`, both mentions) and `slots_container` 1 (`s19_app/tui/screens_directionb.py`, the provider — pilot F-2, a structural bound of the rule, not a dependant).
- **Acceptance criteria (informative):** `slots_container` gains `tests/test_tui_variants.py::_project_label` as a declared consumer even though the helper's own selector is `#loaded_slots > Horizontal`: that literal contains `#loaded_slots`, the file is a measured reacher, and after the split this is where the row-set coupling stays visible.

### LLR-87.2 — the D-A split replaces the union output, at measured arities

- **Traceability:** HLR-87.1
- **Statement:** The re-authored record shall declare `artifact_row_set` at `query(".loaded-slot")` with cardinality 4 and `unload_all_row` at `query(".loaded-allrow")` with cardinality 1, shall declare no output whose address is `query("#loaded_slots > Horizontal")`, and shall attach no positional-index annotation to either — the quantified population being the OUTPUT entries of the §8 block.
- **Validation:** `inspection`
- **Executed verification:** M-6 (runtime cardinalities, 4 and 1); M-5 (the only row-set consumer sweeps linearly with a content predicate); the V11/V13/V14 lines of the post-state run.
- **Numeric pass threshold:** **2** outputs replace **1**; cardinalities **4** and **1**, each equal to the runtime count M-6 printed; V13 stray pairs for both are exactly **0** (each address has exactly one reacher, `s19_app/tui/styles.tcss`, and it is declared); **0** occurrences of the phrase `INDEXED POSITIONALLY` on either output.
- **Acceptance criteria (informative):** the reason the union was wrong is not that it was imprecise — `cardinality : 5` collapsed two independent invariants, *"1 + len(_SLOTS)"*, which moves the day a fourth artifact is added (the origin defect of `LLR-120.2`), and *"exactly one footer"*, which never moves. A single number cannot say which one moved.

### LLR-87.3 — the cell-level outputs keep annotations that were RE-VERIFIED, not inherited

- **Traceability:** HLR-87.1
- **Statement:** The re-authored record shall declare `artifact_slots` at `query(".loaded-detail")` with cardinality 3 and the annotation `INDEXED POSITIONALLY`, and `project_row` at `query(".loaded-project-detail")` with cardinality 1 — the quantified population being those two OUTPUT entries of the §8 block, with the positional annotation carried only where a consumer was measured to index.
- **Validation:** `inspection`
- **Executed verification:** M-5's second half — `tests/test_help_toggle_and_a2l_panel.py:73` indexes `cells[2]`; `tests/test_unload_feature.py:260-272` builds the `_SLOTS`-ordered list; `tests/test_tui_commandbar.py:1300` asserts the query selects exactly three. M-6 gives both cardinalities at runtime.
- **Numeric pass threshold:** cardinality **3** and **1**, both equal to M-6's runtime counts; V14 resolves **7** consumer entries across the two; V13 stray pairs exactly **1** (`artifact_slots` × the archived promoted spec, a mention) and **0** for `project_row`.
- **Acceptance criteria (informative):** `INDEXED POSITIONALLY` is TRUE here and FALSE one level up, on the same panel. The pilot wrote it on both; batch-87 writes it on one, and the difference is a measurement, not a judgement.

### LLR-87.4 — the contract block is placed where the parser can terminate it

- **Traceability:** HLR-87.1
- **Statement:** The re-authored `COMPONENT loaded_panel` block shall be the last IFC block in `.dev-flow/2026-08-21-batch-85/01-requirements.md`, and no line following that block in that file shall begin with whitespace — the quantified population being every line of that file after the block's closing fence.
- **Validation:** `inspection`
- **Executed verification:** M-3 (the mechanism, by running `_parse_ifc`); the post-state UNPARSED census (§5.6) is the outcome.
- **Numeric pass threshold:** **0** indented lines after the block; the parsed length of every field of every output in the block is **≤** the length of the text written for it; the UNPARSED census reports **0** `[IFC]` items.
- **Acceptance criteria (informative):** this LLR owns no FLOW node deliberately — it constrains placement, not a transform, and it is one of the two expected V22 unowned-LLR notices. The positive form matters: *"do not write a defective owner"* is unenforceable, while *"no indented line follows the block"* is a property of the file that anyone can check.

### LLR-87.5 — the parent boundary follows the split

- **Traceability:** HLR-87.1
- **Statement:** The `screen_workspace` re-export block in `.dev-flow/2026-08-24-batch-86/01-requirements.md` §5.3 shall declare `artifact_row_set` and `unload_all_row` with the same addresses, cardinalities and consumer sets as the child's declaration, shall declare no output named `slot_rows`, and shall leave every other section of that document unedited — the quantified population being the six re-export OUTPUT entries of that block.
- **Validation:** `inspection`
- **Executed verification:** the live pre-fix run over the real corpus, which BLOCKed naming exactly these two ids, and the post-fix run in which that BLOCK is absent (§5.6); field-by-field comparison against the child block.
- **Numeric pass threshold:** **6** re-exported ids; **0** V12 emits BLOCKs; **0** sections of the batch-86 document other than the §5.3 block and its appended amendment note are modified.
- **Acceptance criteria (informative):** this edit was not planned — it was forced. It is what P-6 refutes: the parent cannot keep a stale re-export while the child moves, so a "re-author one file" batch is arithmetically impossible under a balancing rule.

### LLR-87.6 — surface #3's own outputs are declared with measured consumer sets

- **Traceability:** HLR-87.2
- **Statement:** The `workspace_body` component record shall declare eleven own outputs — `body_root`, `screen_slot_set`, and one per rail screen container other than the workspace screen — each with its address, its cardinality, and the consumer set measured in M-7, M-8 and M-9, and shall declare two FLOW blocks whose every node names an owner defined as a heading in this document; the quantified population is those eleven OUTPUT entries and those FLOW nodes of §5.2 and §5.3.
- **Validation:** `inspection`
- **Executed verification:** the V10/V11/V13/V14 lines of the post-state run; M-6 (cardinalities and the child list), M-7 (literal census), M-8 (bare channel), M-9 (classification).
- **Numeric pass threshold:** **11** own outputs; `screen_slot_set` cardinality **10**, equal to M-6's runtime `.db-screen` count and to the length of `SCREEN_CONTAINER_IDS`; every other own output cardinality **1**; V13's stray pairs over the eleven are exactly the **26** enumerated in §5.6 (`body_root` 4 · `screen_slot_set` 0 · `a2l_screen` 2 · `mac_screen` 2 · `map_screen` 3 · `issues_screen` 5 · `patch_screen` 1 · `diff_screen` 1 · `flow_screen` 4 · `checks_screen` 2 · `crc_designer_screen` 2), every one classified mention or provider, **0** undeclared dependants, and that emptiness is guarded by M-8's declared-width bare sweep, not asserted.
- **Symbol citations (all EXISTING, measured):** `on_rail_selected` `app.py:6057` · `action_show_screen` `app.py:5881` · `on_resize` `app.py:6413` · `_apply_width_regime` `app.py:6351` · `action_cycle_density` `app.py:6314` · `on_mount` `app.py:5308` · `_active_view_name` `app.py:1751` · `SCREEN_CONTAINER_IDS` `app.py:5748` · `_EMPTY_STATE_SCREENS` `app.py:6008`.

### LLR-87.7 — surface #3 re-exports the child boundary in full, and its PARENT is honest

- **Traceability:** HLR-87.2
- **Statement:** The `workspace_body` record shall declare `PARENT : workspace_shell`, shall declare `INPUTS` as a named list containing every input `screen_workspace` declares, and shall re-export every output id `screen_workspace` emits with that child's address, cardinality and consumer set — the quantified population being the COMPONENT header fields and the thirty-one re-export OUTPUT entries of §5.3.
- **Validation:** `inspection`
- **Executed verification:** M-4 arm 5, whose V12 BLOCK enumerated the thirty ids owed before the split (thirty-one after it); M-6 for the parent identity; the post-state V12 line.
- **Numeric pass threshold:** **31** re-exported ids, equal to the count of outputs `screen_workspace` declares; **0** V12 emits BLOCKs and **0** V12 consumes BLOCKs; exactly **1** V12 NOTICE, naming `workspace_body` and `workspace_shell`; the declared `PARENT` reads `workspace_shell`, and the string `PARENT : SYSTEM` appears **0** times **inside the §5.3 `COMPONENT: workspace_body` fenced block** (measured: 0; the same string appears **3** times elsewhere in this document — in P-8's row, in AT-B87-03's boundary catalog, and in this threshold — because naming a rejected value is how a record shows it was considered).
- **⚠ Scope corrected at the P2 iteration (R2-03), and the defect was the pilot's #4 shape.** As first written this threshold said `PARENT : SYSTEM` appears **0 times in this document** — a predicate RED on arrival, since one of its own occurrences is the threshold sentence. A criterion that its own text falsifies is not a strict criterion, it is an unrunnable one, and §5.5 row 4 (which claims that defect is "not reproduced") is corrected to say so.
- **Acceptance criteria (informative):** `PARENT : workspace_shell` is true and undeclared, mirroring pilot D-B and D-86-B one level up. `SYSTEM` was the intake's hypothesis and M-6 refuted it by asking the running app. The honest cost is one standing NOTICE; the dishonest alternative buys silence with a false claim.

### LLR-87.8 — the cost record at n=3, with the compounding measured rather than argued

- **Traceability:** HLR-87.3
- **Statement:** Section 5.6 of this document shall carry the per-surface figures for surface #3, each either cited to an executed M-id measurement or carrying a declared capture/absence disposition, together with the measured duplication figure — the count of V13 stray pairs that exist only because an ancestor re-declares a descendant's address — and the close record shall restate them beside surfaces #1 and #2 with a range-form dispersion statement; the quantified population is §5.6's figure table, its M-citations and its declared disposition rows.
- **Validation:** `analysis`
- **Executed verification:** the figure table of §5.6 against M-1 through M-9 and the post-state run, each count re-derivable by re-running the cited command.
- **Numeric pass threshold:** **6** figures non-null; the duplication figure derived from the post-state V13 pair census by subtraction of the per-declaration sets, never estimated; dispersion stated as the measured range over outputs and consumer entries across the three surfaces; **0** extrapolated totals.

### Functional traceability (US → HLR → LLR → TC)

| Requirement | Method | Test case | Notes |
|---|---|---|---|
| HLR-87.1 | inspection | `TC-B87-01` — census + V19 single-declaration check | operator-local |
| HLR-87.2 | inspection | `TC-B87-02` — V12 finding-set check, enumerated residual | + M-4 arms |
| HLR-87.3 | analysis | `TC-B87-03` — close-record figure audit | at Phase 5 |
| LLR-87.1 | inspection | `TC-B87-04` — per-output pair census, pilot handles | M-7/M-9 |
| LLR-87.2 | inspection | `TC-B87-05` — split arity + annotation-absence check | M-5/M-6 |
| LLR-87.3 | inspection | `TC-B87-05` | same check, cell-level rows |
| LLR-87.4 | inspection | `TC-B87-06` — placement + field-length check | M-3 |
| LLR-87.5 | inspection | `TC-B87-07` — parent re-export field comparison | live RED arm |
| LLR-87.6 | inspection | `TC-B87-08` — surface-#3 pair census | M-7/M-8/M-9 |
| LLR-87.7 | inspection | `TC-B87-02` | shared with HLR-87.2 |
| LLR-87.8 | analysis | `TC-B87-03` | shared with HLR-87.3 |

`TC-B87-*` are letter-initial ⇒ ungoverned by the registry (P-13); all are operator-local
inspection/analysis procedures, **not** pytest nodes — 0 test files added, and saying so is the
honest form.

## 5 · Information Flow Contract (C-54) — surface #3: `workspace_body`

> Syntax per the rev45 template. One field per line; the validator anchors on the block keywords.
> **Format lessons applied:** (1) every reacher threshold is stated over `(output_id, file)` PAIRS;
> (2) one address = one population — `.db-screen` is declared because this component owns all ten of
> its members, `.db-pane` is excluded because it does not (D-87-G); (3) every §4 Statement carries an
> explicit scope rule; (4) `INDEXED POSITIONALLY` appears only where a consumer was measured to
> index; (5) `consumers : none` is written explicitly wherever it is true.

### 5.1 The surface, confirmed by execution

`#workspace_body` is the ten-screen shell of the Direction-B app: a Textual `Container` yielded by
`S19TuiApp.compose` (`s19_app/tui/app.py:1906-1918`), child of the `Horizontal` `#workspace_shell`
(`app.py:1919`) and sibling of `#rail_slot`. Its ten children are the rail screen containers, in
compose order, and they are exactly the `.db-screen` population (M-6). It carries the app's density
and width-regime classes, and it is the component `screen_workspace` names as its parent.

### 5.2 Part A — the shell's information flows

```
FLOW: rail_screen_activation
  SOURCE : the operator's rail selection, entering S19TuiApp as a Rail.Selected message or as a numeric key binding
  NODES  :
    - fn    : on_rail_selected
      owner : LLR-87.6
      in    : Rail.Selected carrying a screen key
      out   : a call to action_show_screen with that key
    - fn    : action_show_screen
      owner : LLR-87.6
      in    : one key of SCREEN_CONTAINER_IDS
      out   : exactly one visible screen container among the ten, the other nine carrying the hidden class
    - fn    : _active_view_name
      owner : LLR-87.6
      in    : the hidden-class state of the screen containers
      out   : the name of the screen currently visible, for the key routers that ask
  SINK   : the visibility state of the screen slot set declared in 5.3

FLOW: shell_regime
  SOURCE : terminal geometry events and the density keybinding, entering S19TuiApp
  NODES  :
    - fn    : on_mount
      owner : LLR-87.6
      in    : app start
      out   : the comfortable density class on the body root
    - fn    : on_resize
      owner : LLR-87.6
      in    : the terminal width
      out   : a width-regime application
    - fn    : _apply_width_regime
      owner : LLR-87.6
      in    : the terminal width
      out   : the narrow-width class set on the shell and on the body root
    - fn    : action_cycle_density
      owner : LLR-87.6
      in    : the density class currently on the body root
      out   : the swapped density class on the body root
  SINK   : the class state of the body root declared in 5.3, which the stylesheet's cascade reads
```

### 5.3 Part B — boundary decomposition

**Trigger question: does the system's boundary have components a consumer can address
independently?** Yes — measured: ten screen containers, each reachable by its own id and all ten
selectable as one class population (M-6, M-7).

**Why thirty-one of the forty-two outputs are re-exports.** Balancing is set containment over output
ids (`devflow-validate.py:482-489`), so a parent must declare every id its child emits. M-4 arm 5
printed the owed list from the rule itself. The alternative — a parent with no OUTPUTS — is refuted
by P-11: it does not weaken the check, it switches it off. The cost of the honest form is measured
in §5.6 and registered as R-87-2.

```
COMPONENT: workspace_body
  PARENT : workspace_shell
  SURFACE: the Direction-B app shell — the ten-screen body composed by S19TuiApp.compose (s19_app/tui/app.py:1906)
  INPUTS : loaded: Optional[LoadedFile] ; project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str ; active_screen_key: str
  OUTPUTS:
    - id          : body_root
      value       : the shell container itself, carrying the density and width-regime classes the whole stylesheet cascade keys on
      address     : query_one("#workspace_body")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_mount
                    s19_app/tui/app.py::action_cycle_density
                    s19_app/tui/app.py::_apply_width_regime
                    s19_app/tui/styles.tcss
                    tests/test_crc_designer_view.py
                    tests/test_tui_directionb.py
                    tests/test_tui_mac_layout.py
                    tests/test_tui_patch_layout.py
                    tests/test_tui_snapshot.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.6
    - id          : screen_slot_set
      value       : the ten rail screen containers as one population, exactly one of which lacks the hidden class at any time
      address     : query(".db-screen")
      cardinality : 10
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.6
    - id          : a2l_screen
      value       : the A2L Explorer rail screen container
      address     : query_one("#screen_a2l")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_active_view_name
                    s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : mac_screen
      value       : the MAC View rail screen container
      address     : query_one("#screen_mac")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_active_view_name
                    s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : map_screen
      value       : the Memory Map rail screen container
      address     : query_one("#screen_map")
      cardinality : 1
      consumers   : s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    s19_app/tui/app.py::_EMPTY_STATE_SCREENS
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : issues_screen
      value       : the Issues Report rail screen container
      address     : query_one("#screen_issues")
      cardinality : 1
      consumers   : s19_app/tui/app.py::action_page_down_context
                    s19_app/tui/app.py::action_page_up_context
                    s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    s19_app/tui/app.py::_EMPTY_STATE_SCREENS
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : patch_screen
      value       : the Patch Editor rail screen container
      address     : query_one("#screen_patch")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_patch_history_action_allowed
                    s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : diff_screen
      value       : the A2B Diff rail screen container
      address     : query_one("#screen_diff")
      cardinality : 1
      consumers   : s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_commandbar.py
                    tests/test_tui_diff_screen.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : flow_screen
      value       : the Flow Builder rail screen container
      address     : query_one("#screen_flow")
      cardinality : 1
      consumers   : s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : checks_screen
      value       : the Checks rail screen container
      address     : query_one("#screen_checks")
      cardinality : 1
      consumers   : s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    s19_app/tui/app.py::_EMPTY_STATE_SCREENS
                    tests/test_tui_checks_screen.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : crc_designer_screen
      value       : the CRC Designer rail screen container
      address     : query_one("#screen_crc_designer")
      cardinality : 1
      consumers   : s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_crc_designer_view.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.6
    - id          : screen_root
      value       : re-export of screen_workspace's screen_root at this boundary (balancing); this is also how the workspace screen container itself is addressed, which is why it is not declared twice
      address     : query_one("#screen_workspace")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    s19_app/tui/app.py::SCREEN_CONTAINER_IDS
                    tests/test_tui_checks_screen.py
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : memstrip_band
      value       : re-export of screen_workspace's memstrip_band (balancing)
      address     : query_one("#ws_memstrip")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_memory_strip
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_insight.py
      owner       : LLR-87.7
    - id          : panes_container
      value       : re-export of screen_workspace's panes_container (balancing)
      address     : query_one("#workspace_panes")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : left_pane
      value       : re-export of screen_workspace's left_pane (balancing)
      address     : query_one("#ws_left")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.7
    - id          : center_pane
      value       : re-export of screen_workspace's center_pane (balancing)
      address     : query_one("#ws_center")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.7
    - id          : right_pane
      value       : re-export of screen_workspace's right_pane (balancing)
      address     : query_one("#ws_right")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.7
    - id          : empty_state
      value       : re-export of screen_workspace's empty_state (balancing); type-addressed by measured necessity, the widget sets no id
      address     : query_one(EmptyStatePanel) scoped to the workspace screen subtree — type selector, computed, carries no quoted literal by design
      cardinality : 1
      consumers   : s19_app/tui/app.py::_apply_empty_state
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : load_project_button
      value       : re-export of screen_workspace's load_project_button (balancing)
      address     : query_one("#ws_load_project_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : files_title
      value       : re-export of screen_workspace's files_title (balancing)
      address     : query_one("#files_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : files_list
      value       : re-export of screen_workspace's files_list (balancing)
      address     : query_one("#files_list")
      cardinality : 1
      consumers   : s19_app/tui/app.py::refresh_files
                    s19_app/tui/app.py::on_list_view_selected
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : sections_title
      value       : re-export of screen_workspace's sections_title (balancing)
      address     : query_one("#sections_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : sections_list
      value       : re-export of screen_workspace's sections_list (balancing)
      address     : query_one("#sections_list")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_sections
                    s19_app/tui/app.py::on_list_view_selected
                    s19_app/tui/styles.tcss
                    tests/test_tui_app.py
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : hex_title
      value       : re-export of screen_workspace's hex_title (balancing)
      address     : query_one("#hex_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : hex_controls
      value       : re-export of screen_workspace's hex_controls (balancing)
      address     : query_one("#hex_controls")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : search_input
      value       : re-export of screen_workspace's search_input (balancing)
      address     : query_one("#search_input")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_search
                    s19_app/tui/app.py::_FIND_GOTO_INPUTS
                    s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
                    tests/test_tui_goto_marker.py
                    tests/test_tui_search_pagination.py
                    tests/test_universal_paste.py
      owner       : LLR-87.7
    - id          : search_button
      value       : re-export of screen_workspace's search_button (balancing)
      address     : query_one("#search_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
                    tests/test_tui_commandbar.py::_B78_SEARCH_SURFACES
      owner       : LLR-87.7
    - id          : goto_input
      value       : re-export of screen_workspace's goto_input (balancing)
      address     : query_one("#goto_input")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_handle_goto
                    s19_app/tui/app.py::_FIND_GOTO_INPUTS
                    s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_directionb.py
                    tests/test_tui_goto_marker.py
      owner       : LLR-87.7
    - id          : goto_button
      value       : re-export of screen_workspace's goto_button (balancing)
      address     : query_one("#goto_button")
      cardinality : 1
      consumers   : s19_app/tui/app.py::on_button_pressed
                    tests/test_tui_commandbar.py::_B78_SEARCH_SURFACES
      owner       : LLR-87.7
    - id          : hex_scroll
      value       : re-export of screen_workspace's hex_scroll (balancing)
      address     : query_one("#hex_scroll")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.7
    - id          : hex_view
      value       : re-export of screen_workspace's hex_view (balancing)
      address     : query_one("#hex_view")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_hex_view
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_patch_variant.py
                    tests/test_tui_workspace_layout.py
      owner       : LLR-87.7
    - id          : ws_stats_title
      value       : re-export of screen_workspace's ws_stats_title (balancing)
      address     : query_one("#ws_stats_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : ws_stats
      value       : re-export of screen_workspace's ws_stats (balancing)
      address     : query_one("#ws_stats")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_workspace_stats
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
                    tests/test_tui_workspace_insight.py
      owner       : LLR-87.7
    - id          : a2l_title
      value       : re-export of screen_workspace's a2l_title (balancing)
      address     : query_one("#a2l_title")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : a2l_view
      value       : re-export of screen_workspace's a2l_view (balancing)
      address     : query_one("#a2l_view")
      cardinality : 1
      consumers   : s19_app/tui/app.py::update_a2l_view
                    s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : a2l_scroll
      value       : re-export of screen_workspace's a2l_scroll (balancing)
      address     : query_one("#a2l_scroll")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_directionb.py
      owner       : LLR-87.7
    - id          : panel_handle
      value       : re-export of loaded_panel's panel_handle, carried through screen_workspace (balancing)
      address     : query_one("#loaded_panel")
      cardinality : 1
      consumers   : s19_app/tui/app.py::_refresh_loaded_panel
                    s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-87.7
    - id          : slots_container
      value       : re-export of loaded_panel's slots_container (balancing)
      address     : query_one("#loaded_slots")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py
                    tests/test_tui_variants.py::_project_label
      owner       : LLR-87.7
    - id          : artifact_row_set
      value       : re-export of loaded_panel's artifact_row_set (balancing) — the four loaded-slot rows
      address     : query(".loaded-slot")
      cardinality : 4
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_variants.py::_project_label
      owner       : LLR-87.7
    - id          : unload_all_row
      value       : re-export of loaded_panel's unload_all_row (balancing) — the footer row
      address     : query(".loaded-allrow")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
      owner       : LLR-87.7
    - id          : artifact_slots
      value       : re-export of loaded_panel's artifact_slots (balancing)
      address     : query(".loaded-detail"), INDEXED POSITIONALLY
      cardinality : 3
      consumers   : s19_app/tui/styles.tcss
                    tests/test_help_toggle_and_a2l_panel.py::_a2l_slot_text
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_unload_feature.py::_detail_texts
      owner       : LLR-87.7
    - id          : project_row
      value       : re-export of loaded_panel's project_row (balancing)
      address     : query(".loaded-project-detail")
      cardinality : 1
      consumers   : s19_app/tui/styles.tcss
                    tests/test_tui_commandbar.py::test_at_b78_09_loaded_panel_names_the_project
                    tests/test_tui_variants.py::_project_label
      owner       : LLR-87.7
```

**On `consumers : none`.** It is written nowhere in this block, and that is a measured fact rather
than an omission: every declared address has at least one reacher (M-7; the minimum is the
stylesheet). The obligation to write it explicitly stands and simply has no instance on this
surface, exactly as on surface #2.

**On `INDEXED POSITIONALLY`.** It appears on exactly one output of this component — `artifact_slots`,
carried from the child, where M-5 measured a consumer that indexes `cells[2]`. It appears on no own
output: every own address is either a singleton id reached by `query_one` or a class population whose
only consumer is a stylesheet rule (M-7, M-9). The pilot's mistake was writing it where no consumer
indexed; the correction is not to stop writing it but to measure before writing it.

### 5.4 Design decisions inside the record, and what each costs

| # | Decision | Alternative rejected | Why (executed evidence) | Cost |
|---|---|---|---|---|
| **D-87-A** | The re-authored `loaded_panel` contract lives **in place**, in `.dev-flow/2026-08-21-batch-85/01-requirements.md` §8 | declare it fresh in the batch-87 record and leave the pilot's block standing | Two independent measurements, either sufficient. **(1)** M-4 arms 1 and 4: `_ifc_corpus` merges by list extension, so both declarations survive — V11 counts the outputs of both, V19 raises a collision NOTICE, V12 resolves the parent to the LAST, and there is no parent output set that balances the old and the new declaration at once. **(2)** M-2: the UNPARSED census entry is keyed to the pilot's own file and line, so nothing declared elsewhere can clear it. D-86-E's argument ("correcting it elsewhere forks one contract into two disagreeing declarations") is no longer a rationale — it is a measurement | Edits to a closed batch's record. Bounded by rule: contract/IFC sections only, every edit cited from here, §5.5/§6/§7 of that document untouched and its superseded figures left standing rather than rewritten |
| **D-87-B** | `workspace_body` declares its **full** output set — eleven own plus thirty-one re-exports | declare it with no OUTPUTS, which parses and passes | M-4 arm 5: with the parent's OUTPUTS empty, `screen_workspace`'s emits BLOCK **disappeared** — `devflow-validate.py:484` skips the emits half when either side is empty. The cheap form does not weaken balancing; it switches it off for every child, which is the exact "check that cannot fail" this programme exists to kill | 42 outputs, **139** consumer entries (measured — §5.6; the first version of this cell wrote a rounded estimate in a document whose own header rule is that the command is right, R2-13), and the duplication measured in §5.6 |
| **D-87-C** | The re-export declares the child's **literal** address verbatim | declare the re-export by reference, with no quoted literal, so V13 greps each literal once per corpus instead of once per declaration | Consistency with the one existing exemplar (D-86-E) and with the template's rule that `address` says how a consumer reaches the value. **The cost is measured, not waved at:** every re-exported literal is grepped again at the ancestor's lines, so the stray-pair census grows by the child's whole set at each level. The by-reference form is a corpus-wide convention change that one batch may not make alone | the duplication figure in §5.6; registered as **R-87-2** with the by-reference remedy named, for the flow repo and for operator ruling |
| **D-87-D** | The `screen_workspace` re-export block is edited in the same batch | split it into a follow-up batch | Not a preference: M-4 arm 2 and a LIVE run over the real corpus both BLOCK. A batch that re-authors the child and stops leaves the corpus unbalanced at its own gate | one contract-section edit to a closed batch's record, cited and bounded exactly as D-87-A |
| **D-87-E** | The pilot's `ifc_pilot_authoring` FLOW block is **deleted** | keep it verbatim; or restate it with real symbols | Catalogued defect #11: its four `fn` entries are process verbs with no `def` anywhere, and it supplied 4 of V10's 9 nodes. Batch-86 already declined to author one (D-86-C); a re-author that kept it would reproduce a defect the re-author exists to remove | V10's corpus node count drops; three batch-85 LLRs lose their only owner citation and appear in V22's unowned census — enumerated in §3 so they are expected, not discovered. Batch-85 §4's LLR-85.1 threshold now names a superseded figure, declared in that file rather than silently corrected |
| **D-87-F** | `AT-B87-*` / `TC-B87-*` take no registry reservation | reserve them in `AT-TC-REGISTRY.jsonl` | P-13: letter-initial bodies are outside the registry's authority, `_meta.next_free.AT` is untouched, and neither batch-85 nor batch-86 registered theirs (measured: 0 rows each). **Recorded as a decision rather than assumed**, because comparability across the three IFC batches is the only argument holding it, and that argument would change the day the registry's grammar does | **Not zero, and the first version of this cell said "none today" — refuted at the P2 iteration (R2-02).** This batch's two Phase-1 artifacts minted overlapping `AT-B87-*` ids with DIFFERENT meanings and nothing mechanical caught it, because letter-initial ids are outside the registry's authority. The standing cost is that an id collision INSIDE a batch is caught by review or not at all; the reconciliation table in §3 is this batch's manual discharge. If the convention flips, three batches migrate together |
| **D-87-G** | `.db-screen` IS declared as an output; `.db-pane` is NOT | declare both, or neither | M-6 and M-9: the ten `.db-screen` instances are exactly this component's ten children, so one address selects one population that this component owns. The seven `.db-pane` instances are grandchildren of three different screens (`app.py:2017, 2033, 2044, 5196, 5219, 5279, 5297`), so declaring it here would unite foreign members under one component — batch-85 defect #12, which D-86-A refused at the level below | the `.db-pane` couplings in `styles.tcss` and `tests/test_tui_theme.py` stay contract-invisible until each screen declares its own panes; D-86-A's cost, unchanged and re-stated rather than re-litigated |

### 5.5 Defect-catalogue discharge — the pilot's fifteen, re-executed

Each row was treated as a claim to re-execute, per the pilot handoff's own instruction. "Not
reproduced" means the re-authored contract does not contain it; "out of contract scope" means it
lives in a section this batch is not permitted to edit and is therefore declared, not fixed.

| # | Pilot defect | Disposition in the re-authored contract |
|---|---|---|
| 1 | V13 threshold stated over FILES | **Not reproduced** — every threshold in §4 is a `(output_id, file)` PAIR set, enumerated (LLR-87.1, LLR-87.2, LLR-87.3, LLR-87.6) |
| 2 | two cited tools do not exist | **Not reproduced** — every command in this document was run this session; §2.8 carries the transcripts |
| 3 | `pytest -k "b85"` selects 0 tests | **Not reproduced** — this document names no pytest node; all TCs are labelled inspection/analysis |
| 4 | a TC invariant RED on arrival | ⚠️ **REPRODUCED ONCE, then fixed — and the honest entry is this one, not the "not reproduced" the first fold claimed.** LLR-87.4's invariant ("no indented line follows the block") was measured on the file before it was written, and is clean. But `LLR-87.7`'s threshold *"`PARENT : SYSTEM` appears 0 times in this document"* was RED the moment it was written, because the sentence stating it contains the string — found by the P2 review (R2-03), re-measured at **3** occurrences document-wide and **0** inside the block, and re-scoped to the block. The pilot's defect #4 is a threshold written before it was executed; this batch wrote fifteen thresholds from probes and one from a sentence |
| 5 | reacher union stated as 3 in one place and 4 in another | **Not reproduced** — one census (M-7), cited by id everywhere |
| 6 | site population stated six ways | **Not reproduced** — the populations here are M-6's runtime counts, cited once |
| 7 | repo-wide Statement vs a scoped threshold, unsatisfiable | **Not reproduced** — every Statement names its quantified population |
| 8 | a third design record asserts a stale count | **Out of contract scope** — `C-54-ENCODING-RECORD.md` is a design document, not an IFC section; registered as R-87-5 |
| 9 | the document self-hits its own census | **Not reproduced** — `.dev-flow/` is in `_V13_SKIP_DIRS` (`devflow-validate.py:524`), verified by the census script sharing that set |
| 10 | a dangling "the named false positive" reference | **Not reproduced** — no reference in this document is resolvable only by leaving it |
| 11 | the authoring pseudo-FLOW | **Deleted** — D-87-E |
| 12 | `slot_rows`' positional annotation false for row 5 | **Not reproduced** — the output is split (LLR-87.2) and neither half carries a positional annotation; M-5 is why |
| 13 | `F-10` marked folded but appearing in no site list | **Out of contract scope** — a §7.3 status row; not edited |
| 14 | premise names a superseded flow revision | **Not reproduced** — the flow revision is not asserted in this document; the validator's own output is |
| 15 | the "0 BLOCK attributable" criterion dropped | **Restored, with scope** — §3's batch acceptance criteria state it and enumerate the twelve BLOCKs this batch raised and discharged |

### 5.6 Measured validator verdicts, the stray-pair census, and the cost record

**Pre-state (M-1, before any edit):** V10 `20 FLOW node(s)` · V11 `35 OUTPUT(s)` · V12 one NOTICE
naming `screen_workspace` / `workspace_body` · V14 `106 declared consumer(s)` · V19 `2 COMPONENT
id(s)` · V21 `35 OUTPUT owner(s)` · V20 `atlas current (4 files, census 2)` · tail
`0 block · 254 notice · 15 not applicable`.

**Live RED arms, taken on the real corpus during authoring** (not synthetic, not in memory):

> **Every line of the transcripts below is written flush left.** Inside this document that is a
> requirement, not a style: §5.3's block precedes it, and an indented line after a block's last
> field is appended to that field (M-3). LLR-87.4 states the rule for the batch-85 record; the same
> rule governs this one, and §5.3 is this file's last IFC block.
>
> ⚠️ **Corrected at the P2 iteration (R2-01, found independently by both reviewers).** As first
> written, ONE fence carried the V12 line of state A above the tail line of state B — an artifact
> no single command has ever produced. The two states are **mutually exclusive**: the V12 emits
> BLOCK exists only while the batch-86 re-export still says `slot_rows`, and the two extra V21 rows
> exist only after it stops. The states below were **re-derived at the iteration**, not recovered
> from notes: a copy of the worktree was rebuilt at the pre-P1 commit, verified to reproduce the
> batch-open baseline `0 block · 254 notice · 15 not applicable` exactly, and then advanced one
> file at a time. **The re-derivation reproduced both states byte-for-byte on the BLOCK lines**,
> which is why the defect is an evidence-artifact defect and not a false claim.

```
STATE A - batch-85 re-authored; batch-86 re-export NOT yet updated; LLR-87.* not yet declared
[x] V12  .dev-flow/2026-08-21-batch-85/01-requirements.md:504: COMPONENT loaded_panel: emits artifact_row_set, unload_all_row, which `screen_workspace` does not declare - unbalanced
[x] V20  .dev-flow/_derived/ATLAS-BATCHES.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-IFC.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-ORPHANS.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-TRACE.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:509: COMPONENT loaded_panel: output `panel_handle` names owner `LLR-87.1`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:519: COMPONENT loaded_panel: output `slots_container` names owner `LLR-87.1`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:527: COMPONENT loaded_panel: output `artifact_row_set` names owner `LLR-87.2`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:534: COMPONENT loaded_panel: output `unload_all_row` names owner `LLR-87.2`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:540: COMPONENT loaded_panel: output `artifact_slots` names owner `LLR-87.3`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:549: COMPONENT loaded_panel: output `project_row` names owner `LLR-87.3`, which no document in the corpus defines
11 block - 254 notice - 13 not applicable
```

```
STATE B - batch-86 re-export now follows the split; LLR-87.* still not declared
[x] V20  .dev-flow/_derived/ATLAS-BATCHES.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-IFC.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-ORPHANS.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V20  .dev-flow/_derived/ATLAS-TRACE.md: committed copy differs from what the corpus derives - regenerate (--atlas --write), or find who edited a DERIVED file
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:509: COMPONENT loaded_panel: output `panel_handle` names owner `LLR-87.1`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:519: COMPONENT loaded_panel: output `slots_container` names owner `LLR-87.1`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:527: COMPONENT loaded_panel: output `artifact_row_set` names owner `LLR-87.2`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:534: COMPONENT loaded_panel: output `unload_all_row` names owner `LLR-87.2`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:540: COMPONENT loaded_panel: output `artifact_slots` names owner `LLR-87.3`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-21-batch-85/01-requirements.md:549: COMPONENT loaded_panel: output `project_row` names owner `LLR-87.3`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-24-batch-86/01-requirements.md:610: COMPONENT screen_workspace: output `artifact_row_set` names owner `LLR-87.5`, which no document in the corpus defines
[x] V21  .dev-flow/2026-08-24-batch-86/01-requirements.md:617: COMPONENT screen_workspace: output `unload_all_row` names owner `LLR-87.5`, which no document in the corpus defines
12 block - 254 notice - 13 not applicable
```

**The ledger, per run rather than summed.** State A is `11 block`: **1** V12 emits + **6** V21 owner
+ **4** V20 drift. State B is `12 block`: **8** V21 owner + **4** V20 drift, and **zero** V12 — the
V12 arm went green at exactly the edit LLR-87.5 mandates, which is why that transition is G3's
evidence rather than an assertion. Across the sequence **13 distinct RED instances** were observed
in **three families**, and no state ever carried all thirteen at once: saying "thirteen" without
saying "never simultaneously" is the arithmetic the first version of this section performed by
accident.

Each family went green by the intended change and by nothing else: the V12 instance by LLR-87.5's
re-export update, the eight V21 instances by this document declaring the `LLR-87.*` headings, the
four V20 instances by the Atlas regeneration.

**Post-state** — recorded at this station's gate by running the shipped validator over the merged
corpus after all three records landed, then regenerating the Atlas and re-running. Figures are
pasted, not edited:

```
[-] V10  01-requirements.md: 23 FLOW node(s), every one owned
[-] V11  01-requirements.md: 79 OUTPUT(s), each with an address and a declared consumer list
[!] V12  .dev-flow/2026-08-24-batch-87/01-requirements.md:845: COMPONENT workspace_body: parent `workspace_shell` is not declared in this document, so balancing was NOT checked; this is not a pass
[-] V14  01-requirements.md: 251 declared consumer(s), every one resolved
[-] V19  01-requirements.md: 3 COMPONENT id(s), each declared exactly once
[-] V20  .dev-flow/_derived/: atlas current (4 files, census 1)
[-] V21  01-requirements.md: 79 OUTPUT owner(s), every one declared
[!] V22  .dev-flow/2026-08-21-batch-85/01-requirements.md: LLR(s) never used as an owner - LLR-85.4, LLR-85.5, LLR-85.6, LLR-85.7
[!] V22  .dev-flow/2026-08-24-batch-86/01-requirements.md: LLR(s) never used as an owner - LLR-86.7, LLR-86.8
[!] V22  .dev-flow/2026-08-24-batch-87/01-requirements.md: LLR(s) never used as an owner - LLR-87.4, LLR-87.8
[!] V22  REQUIREMENTS.md: 289 of 544 batch-declared ids are not reflected in the living canon (HLR 78 - LLR 201 - US 10)
0 block - 284 notice - 15 not applicable
```

and the Atlas regeneration, which is what discharges G1:

```
UNPARSED census: 1 item(s)
- [BATCHES] .dev-flow/2026-07-23-batch-n8 - dated dir does not match the batch pattern - census, not silence
```

**G1 discharged, with its negative control intact.** The census fell from 2 items to 1; the item
that survived is the BATCHES one. A census that had emptied completely would have meant the census
stopped counting.

**G10 discharged — the Atlas RENDERS surface #3, which currency alone does not prove** (added at the
P2 iteration, R2-07). Measured on the committed pre-state file and on the regenerated one:

```
predicate                                        PRE (committed)   POST (regenerated)
grep -c '^### COMPONENT `workspace_body`'                      0                    1
grep -c '^### COMPONENT `screen_workspace`'                    1                    1     <- negative control
grep -c '^### COMPONENT '                                      2                    3
grep -c 'workspace_body'   (bare substring)                    2                   34     <- NOT a usable predicate
```

**The bare-substring row is why this gate needed re-deriving.** The qa plan's `AT-B87-06` proposed
`grep -c "workspace_body" ATLAS-IFC.md` with a stated pre-state of 0 and a threshold of ≥ 1. The
pre-state is **2** — batch-86's `- parent : workspace_body` row at `ATLAS-IFC.md:53` and V12's own
finding text at `:93` — so that threshold was GREEN before any work, and its "own RED arm" did not
exist (R2-06). The heading form discriminates: 0 before, 1 after, while the `screen_workspace`
heading returns 1 in both states, proving the predicate and the file both worked beforehand.

**The notice delta is fully accounted for**, which is the difference between a measured figure and a
number that merely appeared: 254 → 284 is **+29** V13 findings (surface #3 declares 29 addresses
that draw at least one undeclared reacher) and **+1** V22 line (this document's own unowned-LLR
census row). No other rule moved.

**Re-measured after the P2 iteration: the tail is unchanged at `0 block · 284 notice · 15 not
applicable`.** The twelve R2 fixes touched prose, tables and one line number — no declaration, no
address, no consumer entry — so no rule's count could move, and none did. The iteration did produce
four transient V20 BLOCKs, because this record is itself Atlas input and editing it drifts the
derived digest; they are the qa plan's K9 "free RED", discharged by the regeneration below.

> ⚠️ **One figure in the transcript above is self-referential and will drift again.** The V12 line
> number `845` is a line of THIS file, so any edit above §5.3 moves it. It was re-measured after the
> P2 iteration (it had read `740` before the iteration added ~105 lines above the block). Treat it
> as a measurement at a moment, like every line-keyed figure in this corpus; the stable part of the
> assertion is the component pair it names, `workspace_body` / `workspace_shell`.

**V22's canon aggregate rose 278 → 289**, which is **+11**, exactly the heading ids this document
declares (3 HLR + 8 LLR). US-87-1 and US-87-2 were already counted at the scaffold (P-12). The
shrink-back is the Phase-3 seeding increment's deliverable, gated at G8; the target at CLOSE is
**≤ 278**, the measured baseline of this station.

**V13's stray PAIR census, stated as an addition of disjoint per-line sets** (never a union, never a
count alone):

| Declaring record | Findings | Stray PAIRS |
|---|---|---|
| `.dev-flow/2026-08-21-batch-85/01-requirements.md` (the re-authored pilot) | 3 | **4** |
| `.dev-flow/2026-08-24-batch-86/01-requirements.md` (`screen_workspace`) | 19 | **36** |
| `.dev-flow/2026-08-24-batch-87/01-requirements.md` (`workspace_body`) | 29 | **62** |
| **Σ** | 51 | **102** — plus **1** no-literal V13 notice NAMING **2** addresses (`screen_workspace/empty_state` and `workspace_body/empty_state`, the same type-addressed widget reported once per declaration). One notice, two addresses: the first version wrote "2 notices", which counts the things named instead of the rows printed (R2-09) |

Surface #3's 62 pairs split exactly along the decision that produced them:

| Class | Pairs | Detail |
|---|---|---|
| own outputs | **26** | `body_root` 4 · `screen_slot_set` 0 · `a2l_screen` 2 · `mac_screen` 2 · `map_screen` 3 · `issues_screen` 5 · `patch_screen` 1 · `diff_screen` 1 · `flow_screen` 4 · `checks_screen` 2 · `crc_designer_screen` 2 |
| re-export | **36** | the same 36 pairs `screen_workspace` already reports, re-reported at this document's lines because V13 greps a declared literal once per declaration |

Every one of the 26 own pairs is a mention (an archived spec, a prototype note, a canon citation, a
doc, a tcss comment, a test docstring) or the provider's own docstring. **0 undeclared dependants**
— and that emptiness is guarded by M-8's declared-width bare-name sweep, not asserted from the
absence of `#`-literal hits, which is the guard batch-86's blocker B86-R2-01 had to add after the
fact.

**The compounding figure — the number this batch exists to produce (LLR-87.8, R-87-2).** Of the 102
stray pairs in the corpus, **40 exist only because an ancestor re-declares a descendant's address**:
4 at `screen_workspace`'s lines that duplicate the pilot's, and 36 at `workspace_body`'s lines that
duplicate `screen_workspace`'s. That is **39 % of the corpus-wide V13 census, at depth 3**, and it
grows by the whole subtree at every further level, because balancing is transitive. The same shape
appears in the no-literal notice (2 entries, 1 widget) and in V14 (139 of this surface's consumer
entries, of which 94 are re-exports of lists already declared one level down). **No projection was
taken to make this smaller** — the alternative shapes are D-87-B's zero-output parent, which is a
check that cannot fail, and D-87-C's by-reference address, which is a corpus-wide convention this
batch may not change alone.

**Per-surface cost figures (surface #3, measured now; effort captured at close):**

| # | Figure | Surface #3 `workspace_body` | Surface #2 `screen_workspace` | Surface #1 `loaded_panel` | M-cite |
|---|---|---|---|---|---|
| 1 | Declared OUTPUTS | **42** (11 own + 31 re-export) | **31** (as batch-86 shipped: 30 — the split turned its `slot_rows` re-export into two) | 6 (as the pilot shipped: 5) | M-6/M-7 + the post-state V11; both predecessor columns re-measured at the P2 iteration by parsing each record at its as-shipped revision |
| 2 | Consumer entries · distinct dependant files | **139** entries (45 of them on own outputs) · **20** files (11 on own outputs) | **94** · 15 (as batch-86 shipped: 91 · 15) | **18** · 6 | M-7/M-8/M-9 + a direct parse of each block, cross-checked against the post-state V14 total of 251 = 18 + 94 + 139 |
| 3 | Addresses literal-greppable | **41 of 42** (`empty_state` type-only) | **30 of 31** (as batch-86 shipped: 29 of 30) | 6 of 6 | M-7 |
| 4 | V13 stray pairs, classified | **62 pairs · 0 undeclared dependants** (26 own + 36 duplicated) | 36 · 0 | 4 · 0 | post-state census above |
| 5 | Stale in-repo claims found | **5 sites in 2 files** — SURVEYED, not declared-absent: `app.py:1849`, `app.py:1880`, `app.py:1902`, `app.py:5885`, `styles.tcss:46` (R-87-3) | not surveyed — declared absence | 5 sites / 4 files | M-6, re-executed per site at the P2 iteration |
| 6 | Authoring effort | captured at close | captured at close | captured at close | disposition, not M-cited |

**Dispersion (n = 3, range form — no mean, no total), stated on ONE plane.** All three figures are the
**post-state** of each record as the corpus now stands: outputs **6 → 31 → 42**; consumer entries
**18 → 94 → 139**; stray pairs **4 → 36 → 62**. *(As the three records SHIPPED before this batch, the
first two columns read 5 and 30 outputs and 15 and 91 consumer entries; the first version of this line
mixed the planes, taking surface #2's outputs from the pre-split record and its consumer entries from the
post-split one — R2-05, re-measured at both revisions rather than edited.)* The spread is a factor of seven on outputs and
nearly eight on consumer entries across the three surfaces measured so far, and the growth is not
the surface's own size — surface #3 declares only **11** outputs of its own, fewer than half of
surface #2's 25, and is the most expensive record in the corpus because of what it must re-export.
**That is the finding, and it is why no per-surface average may be multiplied by the still-undefined
surface count** (batch-85 P-9 stands unmeasured): the cost of surface N depends on where N sits in
the tree, not on how large it is.

## 6 · Open findings registered by this batch

| id | Finding | Status |
|---|---|---|
| **R-87-1** | **A parent component declaring no OUTPUTS silently switches off the emits half of balancing for every child it has** (`devflow-validate.py:484`, `if child_out and parent_out:`). Measured: M-4 arm 5, where a real BLOCK disappeared. The rule cannot distinguish "this component emits nothing" from "this component did not say" — the same `None`-versus-empty distinction `_ifc_consumers` was written to preserve for `consumers`, absent for `OUTPUTS` | New, for the flow repo. A candidate fix exists and is cheap: treat an omitted `OUTPUTS` as unknown (NOTICE, balancing not checked) and an explicit empty one as a claim |
| **R-87-2** | **The re-export cost compounds with depth.** Balancing is transitive set containment, so each ancestor re-declares every id its descendants emit, and V13 greps each declared literal once per declaration. Measured across three levels in §5.6 | New. The named remedy — grep each literal once per corpus and attribute the stray to every declaring component, or allow a by-reference address for a re-export — is a flow-side change and a corpus-wide convention question (D-87-C). **It should be ruled before surface #4**, because every further surface pays it |
| **R-87-3** | **Five in-source claims about the shell's arity are false**, and they are the HLR-85.2 defect class alive on this surface. Measured against ten children (M-6), each site re-read at the P2 iteration: `app.py:1849` ("an 8-child `#workspace_body`") · `app.py:1880` ("the other seven screen containers") · `app.py:1902` ("the 8-screen workspace body") · `app.py:5885` ("hiding the other eight", `action_show_screen`'s docstring) · `styles.tcss:46` ("the 8-screen `#workspace_body`") | New, enumerated exhaustively rather than described by a category. **Not fixed here** — spec-only batch. Owed by the next batch that edits those files. ⚠️ **Corrected at the P2 iteration (R2-04):** the first version cited `app.py:1885`, which holds `Used by:` — a citation wrong by 4,000 lines, in a finding whose entire value is exactness — and missed `app.py:1902`. Both found by review, both re-measured here per site |
| **R-87-3b** | **A sixth candidate site was proposed by review and REFUTED by execution**, recorded so it is not re-proposed: `screens_directionb.py:3284` reads *"on every load, on all nine screens"*. It is **correct**, not stale. The comment sits in `MemoryMapPanel` (`screens_directionb.py:2163`), which is mounted on `#screen_map` (`app.py:2203`), and it describes the screens on which an unguarded focus would land invisibly — that is every rail screen EXCEPT the map. With ten rail screens (`SCREEN_CONTAINER_IDS`, ten values), the non-map count is **nine**. Under the stale eight-screen model the sentence would have read *seven* | Closed as NOT-A-DEFECT, with the arithmetic stated. The general lesson is the one this batch keeps re-learning: a number that looks stale beside a corrected count may be counting a different set, and the way to tell is to read what the sentence quantifies over |
| **R-87-4** | `ScreenScaffold` (`s19_app/tui/screens_directionb.py:182`) is never instantiated — five references, all docstrings (M-6 tail). It carries a `db-screen` construction site that never fires | New. Registered, not fixed (surgical-change rule). It is why the static count of `.db-screen` construction sites disagrees with the runtime count by one |
| **R-87-5** | `C-54-ENCODING-RECORD.md` still asserts the pilot's stale consumer count (pilot defect #8). Out of this batch's contract scope | Carried, unchanged |
| **R-87-6** | The pilot's `V13` NOTICE on `slots_container` names the PROVIDER (`screens_directionb.py`) as an undeclared consumer — pilot F-2, a structural bound of a grep-based rule, still standing after the re-author | Carried. It survives because the provider writes the class name without its leading dot for the class addresses and with `#loaded_slots` for the id one; the asymmetry is an accident of syntax, not a property of the rule |

## 7 · The canon-mirror increment (P3), planned but not executed here

The living canon (`REQUIREMENTS.md`) is the AUTHORED plane of the D-VII hybrid; the Atlas is the
derived one. This batch regenerated the derived plane at its gate and owes the authored plane a
separate increment, scheduled for **Phase 3** so that P3 carries a live gate attributable to its own
deliverable (G8, the batch-86 QA-F2 lesson).

**Scope of that increment — three edits, one file:**

| # | Edit | Target |
|---|---|---|
| 1 | Refresh `R-TUI-113` (`REQUIREMENTS.md:6033`, the batch-85 pilot row) from its honest KNOWN-DEFECT status to RE-AUTHORED, citing `.dev-flow/2026-08-21-batch-85/01-requirements.md` §8 and this batch's D-87-A. Its own §Allocation note stays as written | the pilot's canon row |
| 2 | Amend `R-TUI-114` (`REQUIREMENTS.md:6062`, the `screen_workspace` row) for the re-export change, so the canon does not carry `slot_rows` after the corpus has stopped declaring it | surface #2's canon row |
| 3 | Seed a new `R-TUI-115` row for surface #3, mirroring the eleven batch-87 heading ids the way `R-TUI-114` seeded batch-86's twelve — **one grep per id, one id per line**, never a single grep over a pattern (the M7 lesson: a pattern grep reported +2 where the truth was +1) | surface #3's canon row |

**Id allocation for edit 3.** `R-TUI-115` is the monotonic next: `R-TUI-113` was defined by the
batch-85 canon seeding and `R-TUI-114` by batch-86's. No gap-filling, no reuse — the same rule the
`AT`/`TC` registry enforces, applied by hand because `R-*` ids are not registry-governed.

**The debt target, stated against the MEASURED baseline.** V22's unreflected-id aggregate was
**278** when this batch opened (P-12, M-1) — not 276, which was batch-86's close figure and had
already been overtaken by this batch's own scaffold ids. Authoring this document raised it to
**289** (+11, the heading ids declared here). **The target at CLOSE is ≤ 278.** The seeding
increment therefore owes a net retirement of at least eleven ids, and the eleven it retires first
are its own — a batch that seeds only its own ids ends level, which is the floor, not the goal.

**What this increment is NOT permitted to do.** It touches `REQUIREMENTS.md` and nothing else. The
derived plane is regenerated by command (`--atlas --write`), never hand-edited — rev43 exists
because the Atlas once read its own output, and §10.2 of the Atlas handoff records what happens when
a generated file is edited on the generated side.
