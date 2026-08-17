# Quick Spec — s19_app · batch-83 · unresolvable-address detector

- **Branch:** `claude/batch-83-address-detector` (base = `origin/main` `fbbeafc`; RC-1 PASS)
- **Flow:** `/fast-dev-flow` · supervised, no self-merge
- **Flow revision (C-45 PULL):** `2026.08.15-rev33` · `flow_hash d851576cfe8f60b3` · 24/24 tabled
  files agree · all 3 declared checkouts clean and `0/0` against `origin`, refs refreshed at cut.
  Verified, not assumed — a batch run on a stale flow inherits a solved problem as an open one.

> **Revision 2**, rewritten after a triple check (three independent adversarial passes plus my
> own). Revision 1 carried **4 blocking defects and 5 major ones**; every one is listed at §10
> with what it was, because the defects are the evidence for the criteria that replaced them.
>
> Cut against `origin/main` = `b5c3245`. **All Textual figures are pinned to `textual 8.2.8`.**

---

## 1. Objective

Give s19_app a detector that names every widget address no static analysis can resolve, so
`C-54`'s IFC declares or waives them explicitly instead of omitting them without knowing.

---

## 2. User stories

- As an **IFC author**, I want a list of the addresses on a surface that no static search can
  resolve, so that I declare or waive each one instead of silently omitting it.
- As a **batch reviewer**, I want to run one command and see every computed address in the tree
  with its `file:line`, so that a new one is visible to me during review.
  *(Revision 1 said "cannot enter the tree without an owner" — that is a gate, and gating is
  non-goal 3. The story now says what this batch actually delivers: a report a human runs.)*
- As an **IFC author**, I want the report to state plainly which sites require human judgement
  because no tool can resolve them, so that I do not mistake a tool's silence for an absence.

⚠ **The `V13` story was WITHDRAWN at Inc-3, and this is the honest version of why.** Revisions 1
and 2 both claimed something about `V13` — first that it was "structurally blind", then that the
report would mark what it "can neither confirm nor rule out". **`V13` lives in `claude-config`,
and I could not measure either claim**: my attempt to size whether `V13` would reach a given
computed site used a heuristic too loose to conclude (it answered "56 of 56 might", on a criterion
that proved nothing). A batch does not get to assert properties of another repo's rule that it
did not execute. What survives is verifiable and about this code alone: **these sites cannot be
resolved by reading the call.**

---

## 3. Acceptance criteria

> Every criterion names the exact mutation that puts it in red. Phase B owes the **executed**
> mutation transcript for each; a green arm alone proves nothing.
> *(Revision 1's preamble promised this and then delivered it for 3 of 8 criteria.)*

- [ ] **`AT-B83-01` · the site is recognised.** A module containing `query_one(f"#{var}")` yields
      a row with its `file:line` and form `fstring`.
      *Kill:* drop `JoinedStr` from the classifier → row disappears.

- [ ] **`AT-B83-02` · a format spec is not a selector.** A module containing `f"{value:#x}"`
      yields no row.
      *Kill:* remove the `format_spec` exclusion → 12 phantom `#x` rows appear tree-wide.

- [ ] **`AT-B83-03` · prose is not a selector.** `f"## Variant: {n}"` and `f"... {n} more"` yield
      no rows.
      *Kill:* relax the criterion to bare `startswith("#")` → the selector-shaped population goes
      **72 → 98**, both sides holding the format-spec and length exclusions constant.

- [ ] **`AT-B83-04` · the taxonomy does not collapse the hard cases.** The partition is
      `strict f"#{name}"` / `non-Name interpolation` / `extra literal in the selector`, and
      `f"#legend_key_pane .{cls}"` lands in the third.
      *Kill:* group by `shape` alone, dropping the interpolation-kind check → the 2 `Subscript`
      rows merge into `strict` and the partition reads 46/0/8 instead of 44/2/8.

- [ ] **`AT-B83-05` · `ADDRESS_PARAMS` IS the live derivation — set equality, both directions,
      parameters included.** The snapshot must equal what `derive_address_params()` returns, and
      `FIRST_POSITIONAL_SELECTOR` likewise.
      *Kill:* add `query_exactly` to the snapshot → the second limb goes red.
      ⚠ **Revision 1 asserted only `derived ⊆ set`, and a phantom name walked straight through**:
      that limb says nothing about a member of `set` that is neither derived nor declared.

      **The predicate, written out because "17 qualify" was never reproducible** — three
      implementations gave 13, 16 and 17. Two passes compose:
      1. **annotation shape** — a parameter whose annotation admits `str` in union with a
         `type[...]` or `Widget` form. Finds the query family.
      2. **taint, seeded by pass 1** — a parameter counts when its value reaches a sink through
         an f-string or a local assignment, sinks grown by fixed point.

      Three rules narrow it, **each a rule, not a list of names**: the parameter must be
      *annotated*; *private* methods are out; *reactive hooks* (`watch_`/`validate_`/`compute_`)
      are out. Result at `textual 8.2.8`: **40 methods**. Measured: the rules remove 8, and
      **not one of the 8 is called anywhere in s19_app**.

- [ ] **`AT-B83-06` · the six that used to be a hand-maintained list stay DERIVABLE.**
      `get_child_by_id`, `get_widget_by_id`, `action_add_class/remove/toggle`, `action_focus`
      annotate their parameter as a plain `str`, so annotation alone finds none of them.
      *Kill:* seed taint from the raw sinks only → 5 of the 6 vanish (measured: 1 of 6 derived).
      ✅ **The Inc-1 experiment was run and the hypothesis HELD, with a correction**: seeding from
      `parse_selectors`/`DOMQuery` alone reaches **1 of 6**; seeding from the annotation pass
      reaches **6 of 6** plus 23 per-id APIs nobody watched. Not circular — the seeds are
      themselves derived. **`DECLARED_ADDRESS_APIS` is gone.**
      ⚠ `get_child_by_type` must never enter: its parameter is `type[ExpectType]`. It was got
      wrong twice — called nonexistent (it exists) and called a plain-`str` API (it is not).

- [ ] **`AT-B83-07` · positional AND keyword arguments are scanned.** `query_one(selector=f"#{x}")`
      and `pilot.click(widget=f"#{id}")` yield rows.
      *Kill:* scan `node.args` only → both fixtures vanish.
      ⚠ **The current tool has exactly this defect** (`address_census.py:370` iterates `node.args`
      alone). Tree-wide there are **0** such calls today, which is why nothing revealed it and why
      only a fixture can.

- [ ] **`AT-B83-08` · the no-flow-tracking premise fails loudly, proven on a fixture first.**
      A synthetic module containing `query_one("#" + name)`, `query_one("#%s" % n)` and
      `query_one("#{}".format(n))` must put the guard in **red**. Only then is the tree-wide
      assertion — that address arguments are exclusively `{literal, name, fstring}` — meaningful.
      ⚠ **Revision 1 asserted only the tree-wide invariant, over a tree with 0 violations.** That
      is the canonical vacuous shape: it passes identically with the detection logic correct,
      broken, or unwritten. The fixture is what makes it a test.

- [ ] **`AT-B83-09` · `name` arguments are split by measurement, not by adverb.** The report
      partitions bare-name arguments into *resolves to an imported class* (type-addressing) and
      *everything else*, and prints both.
      *Kill:* return a single `name` bucket → the split disappears.
      **Why it earns a criterion:** measured today, of 183 first-arguments that are bare names,
      **142 resolve to a class-like name and 41 do not** (`selector` ×8, `_B78_RUN_ENTRY` ×12,
      `select_id`, `widget_id`, `container_id`, `layout_id`, …). Revision 1's report called this
      bucket "overwhelmingly type-addressing" — an adverb standing in for a number, and the 41 are
      the population most likely to hold a computed selector one assignment away.

- [ ] **`AT-B83-10` · the one-hop indirection is DETECTED, not merely declared.**
      `sel = f"#{x}"` followed by `query_one(sel)` in the same function yields a row of form
      `fstring-via-name`. The tree-wide arm asserts there are none.
      *Kill:* drop the assignment lookup → the fixture row vanishes and the pattern is invisible.
      **Why it was added at Inc-3:** revision 2 listed this as a declared blind spot. A blind spot
      that can be cheaply detected is not a limit of the design, it is unwritten code — and a
      declared one cannot tell you the day it starts to matter. Measured today: **0 sites**.

- [ ] **`AT-B83-11` · no derived name may violate the exclusion rules.** Every entry in the
      snapshot AND in the live derivation satisfies `is_candidate_method`.
      *Kill:* drop the filter from the annotation pass → 3 private names reappear. **Executed
      at Inc-4: the mutation was applied and this arm went red.**
      ⚠ **Added because its absence let a real defect through.** The filter ran in one of two
      passes and three private methods walked back in. Nothing failed; it surfaced only because
      the rule predicted 40 and the output showed 43 — an arithmetic check done once, by hand.

- [ ] **`AT-B83-12` · a bare-name row records WHICH name.** `shape` is populated for `name`
      arguments, on a fixture and tree-wide.
      *Kill:* stop assigning `site.shape = arg.id` → red. **Executed at Inc-4.**
      ⚠ **Added because its absence would have shipped a plausible lie.** The report's class-like
      split computed `resolves_to_class_like("")` for all 183 rows and would have printed
      `0 of 183` — a number produced by a field nobody filled. It was caught by writing the line
      that prints it, not by any assertion.

---

## 3b. Information Flow Contract — Part A (C-54)

**Part B is not owed here** (`/fast-dev-flow` scope). **Escalation check, run and negative:** this
batch alters *what is carried* (a new report), never *how a consumer reaches* anything — it adds
no selector, index, channel or offset, and modifies no existing address. The `/dev-flow` trigger
in Phase A §5 does **not** fire. Stated explicitly because addressing is this batch's subject
matter, which makes "it doesn't change any address" a claim worth writing down rather than
assuming.

```
SOURCE   s19_app/**/*.py + tests/**/*.py  (228 files)   ·   installed `textual` 8.2.8
   |
   v
N1  iter_python_files      enumerate + sort for determinism        owner: AT-B83-08 (tree invariant)
N2  derive_address_apis    introspect textual -> the API set       owner: AT-B83-05, AT-B83-06
N3  census                 parse AST; classify every arg of an     owner: AT-B83-01, 07, 08, 09
                           address call (args AND keywords)
N4  is_selector            the shape criterion                     owner: AT-B83-02, AT-B83-03
    + format_spec_nodes
N5  interpolation_kinds    strict / non-Name / extra-literal       owner: AT-B83-04
N6  report | --json        emit                                    owner: AT-B83-09 (the name split)
   |
   v
SINK     stdout table  ·  --json  ·  tests/test_address_census.py
```

**Consumers of the SINK, named:** (1) `tests/test_address_census.py`, which imports `census()` and
asserts on shape, never on counts; (2) the IFC author in batch-82, who reads the report to size the
retrofit; (3) a batch reviewer running the command by hand. **No automated consumer gates on it** —
that is non-goal 3, and it is why no node above emits a severity.

---

## 3c. Premise table (C-43)

| Premise | Tier | Verdict | Executed evidence |
|---|---|---|---|
| `tools/address_census.py` exists, uncommitted, 495 lines | PREMISE | ✅ TRUE | `git status --porcelain` → `?? tools/address_census.py`; `wc -l` → 495 |
| …and its `ADDRESS_APIS` holds a name that is not a Textual API | PREMISE | ✅ TRUE | `hasattr` sweep over 233 `textual.*` modules → `query_exactly` found on 0 of 564 classes |
| …and `get_child_by_type` takes a type, not a selector | PREMISE | ✅ TRUE | `inspect.signature(Widget.get_child_by_type)` → `(self, expect_type: 'type[ExpectType]')` |
| …and keyword arguments are never scanned | PREMISE | ✅ TRUE | `address_census.py:370` iterates `node.args` only |
| 0 address calls pass the selector as a keyword today | PREMISE | ✅ TRUE | AST sweep over 228 files → 0 |
| 56 computed addresses (f-string in an address argument) | PREMISE | ✅ TRUE | 5 independent measurements, 4 different API sets (9/23/24/+9 per-id) → 56 every time |
| 0 address arguments outside `{literal, name, fstring}` | PREMISE | ✅ TRUE | AST sweep, 24-API set → `literal 1335 · name 1112 · fstring 56 · other 0` |
| 183 bare-name first-args split 142 class-like / 41 not | PREMISE | ✅ TRUE | AST sweep; the 41 include `selector`×8, `_B78_RUN_ENTRY`×12 |
| `textual` is 8.2.8 | PREMISE | ✅ TRUE | `textual.__version__` |
| Batch-scoped ids owe no registry reservation | PREMISE | ✅ TRUE | `AT-TC-REGISTRY-SPEC.md:123` + `:468`; `_meta.next_free` unchanged at `AT-282`/`TC-613` |
| The prior `.fast-dev-flow/spec.md` was stale (batch-69, shipped by batch-70) | PREMISE | ✅ TRUE | header dated 2026-07-28; last touched by `b457ef8` (batch-70, 2026-07-29). Archived this session |
| `tools/` is the right home — the flow must not measure the product | AXIOM | ✅ TRUE | `main` tip `cf11319` titled *"encoding the flow is NOT s19_app work"*; `id_registry.py` precedent |
| The frozen engine set is untouched by this batch | AXIOM | ✅ TRUE | no file in `_ENGINE_PATHS` appears in §8 deliverables |
| **AST taint analysis can derive the 6 non-derivable APIs** | **HYPOTHESIS** | ❓ **UNDECIDABLE** | reported by an independent pass as executed; **I have not verified it.** Does not block: declared in writing at `AT-B83-06` as an Inc-1 experiment, and the maintained list stands if it fails |
| `V13` would or would not reach a given computed site | PREMISE | ❓ **UNDECIDABLE** | my heuristic was too loose to conclude. Declared out of scope in writing at §9.4 — reported as *ambiguous*, never as *blind* |

**Two ❓ verdicts, both declared out of scope in writing rather than left open** — which is the
escape the control allows, and the reason each names where it is declared.

---

## 4. Validation strategy

**Synthetic fixtures** (`01`–`04`, `07`, `08`, `09`) — Python source in test strings, parsed
in-memory. They never go stale and every one of them is shown red before green.

**Introspection guards** (`05`, `06`) — run against the installed Textual, **pinned and printed**:
`textual 8.2.8`. They fail on a dependency bump **by design**; §8 names the owner of that failure.

**Explicitly not asserted: any count.** No `== 56`, no `== 2503`. A count assertion breaks on every
legitimate change and proves nothing.

**Standing rule, earned twice.** No figure enters an artifact unless re-derived by a path
different from the one that produced it, **and no figure is quoted without the definition that
makes it reproducible.** `2503` and `2499` are both correct — they differ by 4 `double_click`
arguments, because they were measured under different API sets. A total without its API set is
not a measurement.

---

## 5. Non-goals

- **Authoring the IFC.** batch-82's charter.
- **Touching `claude-config`.** `V13` stays in the flow; the detector measures the product.
- **Gating anything.** The detector reports. No user story may imply otherwise.
- **Any flow tracking — zero hops, not one.** `sel = f"#{x}"; query_one(sel)` is reported as form
  `name`, and the f-string separately as `loose`. Neither is joined to the other.
  *(Revision 1 said "deeper than one hop", implying one hop was followed. None is.)*
- **Selectors in `.tcss`**, and the **producer** side (`id=f"log_line_{i}"` at construction,
  `add_class`/`set_classes`). Out of scope, and listed in §9 rather than left unsaid.
- **Resolving the address VALUE.** Recognising the *site* is the whole claim.

---

## 6. Security flags

All unchecked. **`security_required: false`** — read-only AST over files already in the repo, plus
introspection of an installed package. No network, no writes, no new surface.

---

## 7. Ids

Batch-scoped `AT-B83-*`, per `AT-TC-REGISTRY-SPEC.md` §2.3 and `CLAUDE.md`. **No reservation is
owed**; `next_free` stays `AT-282` / `TC-613`.

⚠ **Conflict surfaced, not averaged, and verified by an independent pass:** `BACKLOG-CODE.md:118`
registers as **P1** that the registry is "BLIND" to batch-scoped ids; `AT-TC-REGISTRY-SPEC.md:468`
records that same blindness as **"✅ Accepted, deliberately"**, and §2.3 line 123 says *"New work
should prefer these"*. Both citations confirmed exact. This batch follows the spec; the backlog
item needs closing or re-wording by its owner.

---

## 7b. Defects this batch's own guards found — six, and the source of each

`tools/address_census.py` (495 lines, uncommitted) is a starting point that **carries the defects
its own criteria exist to catch**, which is why Inc-1 writes guards first and fixes second:

| Defect | Caught by | Status |
|---|---|---|
| `ADDRESS_APIS` held `query_exactly` (not a Textual API) and `get_child_by_type` (takes a type) | `AT-B83-05` | ✅ fixed Inc-1 |
| keyword arguments never scanned | `AT-B83-07` | ✅ fixed Inc-1 |
| `_argument_form` docstring said `'type'`, returned `'name'` | code review | ✅ fixed Inc-1 |
| census read ARGUMENTS where it should read PARAMETERS (`mount(*widgets)`) | `AT-B83-08` | ✅ fixed Inc-1 — **found by the invariant, not by review** |
| the candidate filter was applied in the collection pass but NOT in the annotation pass, so 3 private methods walked back in through the second door | none — found by comparing the rule's prediction (40) against the output (43) | ✅ fixed Inc-3 via `is_candidate_method`, now the single definition |
| `shape` never populated for bare-name arguments, so the class-like split would have silently read 0 of 183 | none | ✅ fixed Inc-3 |

---

## 8. Deliverables and where they live

| Deliverable | Path | Lane |
|---|---|---|
| the tool | `tools/address_census.py` | — |
| the guards | `tests/test_address_census.py` | PR lane, **not** `slow` |
| ~~traceability row in `REQUIREMENTS.md`~~ | **WITHDRAWN at Inc-2** | — |

⚠ **The `REQUIREMENTS.md` row was withdrawn on measurement, not on preference.** That file
documents PRODUCT requirements (`R-TUI-*`, one section per behavioural surface). Executed:
`tools/id_registry.py` — the analogous instrument, with its own guard, landed through this same
flow — has **no entry there**. Instrumentation is not product, and adding a row would have
invented a convention rather than followed one. Traceability for this batch lives where the
precedent puts it: this spec, and the `AT-B83-*` ids on the guards. *This was a premise in
revision 2's §8 that I wrote without executing — the same class of defect §10 lists twelve of.*

**Report columns:** `file`, `line`, `api`, `form`, `shape`, `interp`, `note`.

⚠ **`v13_ambiguous` withdrawn at Inc-2 — it would have been a vacuous column.** Every computed
address IS a site `V13` cannot resolve; a boolean that holds the same value on every row of the
section carries no information. Story 3's deliverable is the *"computed addresses"* section
itself, and the report now says so in a closing line rather than in a constant column.

**Dependency-drift owner:** when `AT-B83-05`/`06` fail on a Textual bump, the batch that bumps
Textual owns re-deriving the set. Recorded here because a guard that fails with no named owner
becomes a guard someone disables.

**`census()` propagates `SyntaxError` deliberately** — a census that silently skips a file it
could not read is the vacuous shape. Consequence, declared: any unparseable scratch `.py` under
`tests/` fails the suite.

---

## 8b. When this detector starts to gate — the trigger, written now (B5)

The detector reports and does not block. That is non-goal 3, and leaving it at *"some day"*
turns a deliberate decision into a forgotten one. **The activation condition, decided now:**

> **A surface's computed addresses become BLOCKING on the day that surface's IFC is written.**
> Until then, per-surface, they are reportable only.

This is the same staging `C-54` already chose for `V13` (NOTICE until a screen's stage lands,
BLOCK after). Two consequences worth stating so nobody has to re-derive them:

- **A gate before the IFC exists would mean "no new computed addresses", period** — blocking
  legitimate work with no criterion to judge it by. A control priced before it has a corpus is
  priced blind, which is the criticism `C-54` levelled at itself.
- **The trigger is per-surface, not global.** batch-82 lands screens one at a time; the detector
  hardens with each, and a large retrofit never gates unrelated batches.

**Owner of the transition:** the batch that writes a surface's IFC also flips that surface.

---

## 9. Declared risks and blind spots — each with its reopening criterion (A5)

> These live here, not only in docstrings, so they can be **cited from outside the code** when the
> scenario appears. A by-design risk that nobody can quote when it fires is not documented; it is
> buried.

| Risk | Why it is accepted | **Reopen when** |
|---|---|---|
| The introspection guards fail on a Textual upgrade | That IS the mechanism — a guard that stays green when its subject changes is worthless | Never "fix" it; the batch that bumps Textual re-derives the snapshot. If that becomes frequent enough to be friction, revisit the snapshot-vs-live-call tradeoff |
| The derivation costs ~18 s in the PR lane | Operator decision, measured: 0.9 % of suite wall clock, 4th slowest test behind three unrelated ones at 42/29/20 s | Suite time becomes a real constraint, or this test enters the top 2 |
| 3 exclusion rules (annotated / non-private / non-hook) could hide a real API | Measured: removes 8, **none called anywhere in s19_app** | Any of the 8 becomes reachable from s19_app, or a new address API matches one of the exclusions |
| The taint pass has no upper bound on false positives | Its output is a *set of APIs*, and a spurious entry only costs if s19_app calls it with an f-string | A derived API with no plausible selector semantics appears AND is called by s19_app |

### Blind spots — what this batch does NOT see

1. **Assembled selectors with no selector shape.** `sel = f"{prefix}{suffix}"` matches no selector
   pattern *and* sits in no address argument. It escapes both nets. **UNMEASURED** — size it
   before quoting the 56 as complete. *(Note: the one-hop case IS now covered — see `AT-B83-10`.)*
2. **The producer side and `.tcss`** — `id=f"log_line_{i}"` at construction,
   `add_class`/`set_classes`, and selectors inside stylesheets.
3. **Chains longer than one hop.** `AT-B83-10` catches assign-then-use inside one function.
   Helper-calls-helper is not followed.

## 10. What revision 1 got wrong

Recorded because these are the evidence for the criteria above, not an apology.

| # | Defect | Now |
|---|---|---|
| B1 | `AT-B83-05` asserted one inclusion; a phantom name walked through the guard | set equality, 3 limbs |
| B2 | claimed the 7 non-derivables annotate plain `str`; `get_child_by_type` takes a **type** | 6, listed |
| B3 | story 2 implied a gate, contradicting non-goal 3; stories 2 and 3 had no `AT` | both rewritten to what ships |
| B4 | preamble promised a kill mutation for every criterion; 3 of 8 had one. `AT-B83-06` was vacuous | all 9 name one; the invariant gets a red fixture |
| M1 | "17 derivable" — three implementations gave 13, 16, 17 | predicate written out; no number quoted |
| M2 | no figure named the Textual version | pinned to `8.2.8`, drift owner named |
| M3 | `2503`/`1112` not reproducible by any committed artifact | rule added: no total without its API set |
| M4 | keyword arguments unscanned, and `AT-B83-06` could not have caught it | `AT-B83-07` |
| M5 | "one hop" implied flow tracking that does not exist | zero hops; assembled-selector escape declared |
| m1 | "overwhelmingly type-addressing" | `AT-B83-09`: 142 vs 41, measured |
| — | `LLR-120.2` called "the exact address form" of the computed class selector | it is not — different surface, inherited from the handoff unchecked |
| — | `V13` called "structurally blind" | it is noisy, not blind; its own docstring says so |

**None of these was caught by reading. Every one was caught by executing** — a second
implementation, an introspection pass, a fixture, or an adversarial reader told to refute.

---

## 11. Batch status

| Field | Value |
|-------|-------|
| Current phase | **CLOSED** |
| Cut against | `origin/main` `b5c3245` · `textual 8.2.8` |
| Started | 2026-08-15 |
| Promoted to /dev-flow | no |
