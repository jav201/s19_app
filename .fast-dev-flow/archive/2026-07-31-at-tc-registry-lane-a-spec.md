# AT/TC id registry — Lane A build (registry file + guard)

| Field | Value |
|---|---|
| Flow | `/fast-dev-flow` — autonomous to PR, operator-approved 2026-07-31 |
| Lane | **A (code)** of the cross-lane item *"MAJOR — there is no AT/TC registry"* |
| Built from | [`.dev-flow/AT-TC-REGISTRY-SPEC.md`](../../.dev-flow/AT-TC-REGISTRY-SPEC.md) **§9**, the ordered build contract |
| Seed commit | `origin/main` @ **`232eb0a`** — every figure below re-derived here, none copied from the spec |
| Backlog item | `.dev-flow/BACKLOG-CODE.md` — *"(MAJOR → Lane A) build the AT/TC registry file + its guard test"* |
| Scope | The registry file + its guard. `R-*` / `LLR-*` / `US-*` are **out** (operator ruling); their gap stays registered in Lane B |
| Artifact language | English |

> ⚠ **This half does not close the item, and neither does Lane B.** Router Amendment A splits a
> cross-lane item into one entry per lane; a batch reporting "AT/TC registry DONE" on either half
> alone has shipped the defect the item describes.

---

## 1 · What shipped

| # | Deliverable | §9 |
|---|---|---|
| 1 | `AT-TC-REGISTRY.jsonl` — 1 370 rows, one JSON object per line, sorted by `(space, stem, suffix)` | Inc-1 |
| 2 | `tools/id_registry.py` — the **shared** grammar/corpus library | Inc-1 |
| 3 | `tools/seed_id_registry.py` — the one-time seeder + §6.4 outlier report, carrying the per-id dispositions | Inc-1/2/3 |
| 4 | `tests/test_id_registry.py` — G1–G7 + cost bound + well-formedness, **13 tests, no `slow` marker** | Inc-4 |
| 5 | `tools/counterfactual_id_registry.py` — the recorded 7-mutation evidence run | Inc-5 |
| 6 | `REQUIREMENTS.md` — 21 stale verifier assertions repaired + a new `## Retired ids` section | Inc-6 |
| 7 | `CLAUDE.md` + `docs/engineering-rules.md` — the allocation authority pointer | Inc-7 |

**Seeder and guard share one tokenizer.** Two private copies of the pattern would reproduce, inside
the fix, the exact defect the item names: *an unstated grep pattern is an unstated definition*.

---

## 2 · Re-derived at the seed commit

The spec's figures are stale by design (§1.3 says so). These are measured on `232eb0a`.

| Quantity | Spec's figure (`093ff8e`) | Re-derived (`232eb0a`) |
|---|---|---|
| High-water `TC` | 525 | **610** — 551 from batch-74, then this batch's own mints |
| High-water `AT` | — | **281** |
| `next_free` | — | **AT-282 / TC-611** |
| Registry rows | ~167 BURNED expected | **1 370** total: 849 LIVE · 422 BURNED · 78 RESERVED · 21 RETIRED |
| Phantoms (cited, no node) | 7 TC + 4 AT | **24** (13 TC + 11 AT) — the spec's 11 reproduce *inside* this set |
| §6.2 residue (tests-cited, no name-bearing node) | 73 TC | **5**, then individually dispositioned |
| Scanned files | 147 + 1 | **149 + 1** |

**Why the phantom count more than doubled.** The spec measured with a pattern that discards
suffixes; under the §2.1 grammar the same corpus yields `AT-033a/b/c`, `AT-034a/b`, `TC-019a/d/h`,
`TC-027a/b` and others besides. This is §1.1's own finding — *the figure measures the grep* —
reproduced one level down.

**Why the §6.2 residue collapsed from 73 to 5.** The spec calls form-3 binding "not derivable". It is,
in two attested shapes: the id in a node's **docstring** (enclosing binding), and the id in the
**banner comment** immediately above the node it labels — a form this repo uses consistently:

```
# ---------------------------------------------------------------------------
# AT-220 / TC-521 — the overlap counterexample
# ---------------------------------------------------------------------------
def test_at220_tc521_overlap_counterexample_resolves_enclosing_symbol() -> None:
```

Module-docstring citations are deliberately **not** bound: a docstring enumerating a file's ids is a
summary, not a binding, and binding it to whichever function happens to come first would invent a
relationship the source never asserted. That exclusion needs no window constant, and it is what
leaves exactly 5 for hand disposition.

---

## 3 · Per-id dispositions (Inc-2/Inc-3) — a bulk relabel was forbidden

`TC-319` was the one the spec singled out: *"if it is silently retired, C-26's evidentiary basis is
gone and nothing announces it."* Determined from git history, not assumed:

> `test_tc319_regroup_section_structure_census` was added at `2a647d1` (batch-35) and **removed** at
> `19bf1eb` (batch-46) — removed, not renamed. Its census assertion **survives**, re-homed as the
> module-level `_MUST_PRESERVE_IDS` tuple (`tests/test_tui_patch_layout.py:67`) consumed at `:353`
> by `_drive_reparent_safety`, feeding `test_at063c_reparent_safety_at_80/_at_120`.
> **C-26's evidentiary basis is intact but now carried by AT-063c.** The id is dead; the evidence
> is not. Anyone tracing C-26 through `TC-319` finds nothing and must follow AT-063c.

Other groups, each with its own recorded evidence: the deleted `tests/test_tui_entropy_viewer.py`
(`AT-062a/b`, `TC-324..327`); the retired `cdfx` suite (`TC-019a/d/h`, `TC-027a/b`); the batch-46 2×2
supersession (`AT-033a/b/c`, retired by `REQUIREMENTS.md:3525` itself); `AT-195`/`TC-496`
transcribed from the existing prose; `AT-058a` removed and replaced by `TC-46.2` **in the same
commit**. Four ids that looked like phantoms are **LIVE** — `AT-030a-R2` (node exists; the id is
non-conforming so no derivation rule reaches it) and `AT-034a/b` (bound to a *parametrised* node,
and §2.4 forbids brackets in a node ref).

**One coverage gap surfaced rather than papered over.** `TC-355` is advertised in
`tests/test_flow_crc_block.py:10` as the file's "no-raise" arm; no node asserts it and
`git log -S tc355` over all refs returns nothing. Recorded `BURNED`, not `RETIRED`, precisely so it
reads as *no coverage claim ever existed* rather than *coverage was lost*.

**The §6.4 outlier rule ran and mattered.** The gap report flags three stems; two (`TC-201`,
`TC-301`) are deliberate block starts and keep `conforming: true`. `TC-1728` is forced
`conforming: false`, which is what holds `next_free(TC)` at **611 instead of 1729**.

---

## 4 · The guard, and one recorded premise correction

Seven rules, each naming every offender with its locus rather than asserting a count.

> **RECORDED PREMISE CORRECTION — G4's scope.** The spec words G4 over *every* citation, escaped
> only by an exempt heading anchor. Implemented literally it fires on **28** citations, which split
> into two populations: **17** in `- Validation:` bullets — a document advertising a test that does
> not exist, i.e. the phantom — and **11** in `- Status:` / `**SUPERSEDED**` prose that *already
> says* the verifier was deleted (line 3839: "`tests/test_tui_entropy_viewer.py` (AT-062a/b,
> TC-324/325) **is deleted**"). Firing on the second would force honest history to be stripped of
> its ids to stay green. Anchors cannot rescue it either: those notes sit inside ordinary feature
> sections, so exempting their headings would exempt the live citations beside them, and the spec's
> own trigger caps the anchor list at five. **G4 is therefore scoped to the verifier-asserting
> line** — which is what §6.1 already describes the defect as: prose saying "is deleted" *"while the
> verifier column keeps citing the ids"*. All seven phantoms the item cites live in `- Validation:`
> bullets, so nothing in the cited evidence escapes. The anchor mechanism is retained on top, at
> **2** anchors of the 5 allowed.

### The guard is shown able to fail — four ways

1. **In CI, forever.** `AT-281` mutates a deep copy of the *green* state once per rule and asserts
   each goes red. It refuses to run at all from a non-green baseline.
2. **Recorded run**, `tools/counterfactual_id_registry.py` — 7/7 RED, each row naming **the
   substituted value**, not a deleted operator:

   | Rule | Substituted value | Verdict |
   |---|---|---|
   | G1 | registry entry `'AT-001'` → absent | RED (1) |
   | G2 | `AT-001.nodes[0]` → `'tests/test_flow_persistence.py::test_this_node_does_not_exist_anywhere'` | RED (1) |
   | G3 | registry entry for cited id `'AT-043-c17'` → absent | RED (1) |
   | G4 | `AT-015.1.status` → `'RETIRED'` (was `'LIVE'`) | RED (1) |
   | G5 | `AT-030a-R2.conforming` → `True` (was `False`) | RED (1) |
   | G6 | appended row id → `'AT-0000'` (padding alias of `'AT-0'`) | RED (1) |
   | G7 | `_meta.high_water['TC']` → `1` (was `610`) | RED (736) |

3. **Planted unregistered node** — `tests/test_planted_counterfactual.py` carrying
   `def test_at999_planted_unregistered_node`. G1 **and** G3 went red naming it. Reverted.
4. **Planted registered id with no node** — a `LIVE` row `TC-611` naming
   `::test_this_planted_node_does_not_exist`. G2 went red; **G7 also fired**, catching the
   out-of-band stem as a bonus. Reverted; tree verified clean and 13/13 green after.

---

## 5 · Reservations the registry was born knowing

`AT-250…279` and `TC-552…599` are seeded `RESERVED`, `reserved_by: batch-75`, and pinned by
`TC-610`. batch-75 is chartered and may be executing concurrently; a registry seeded without its
block would put `next_free` **below work already in flight** and then redden against it. A guard
that fires on legitimate work is worse than no guard — it teaches everyone to wave it through.

This batch therefore minted from **above** the reservation: `AT-280/281`, `TC-600…610`.

---

## 6 · What this closes, and what it does not

| Item | State |
|---|---|
| **C-3** — *16 of 23 TC ids not traceable to any node* | ✅ **CLOSED.** The `nodes` field is N:M in both directions, which the accepted batch-62 resolution required (consolidated batteries, N ids → 1 node). `TC-24.3` is the worked case: one id, five nodes in `tests/test_report_addendum.py`. G2 enforces it. 212 ids are bound this way. |
| **batch-62 "16 of 23" carry** | ✅ **CLOSED** by the same mechanism. |
| The 134-id "next free TC" spread | ✅ Made **inexpressible** — `_meta.next_free` is the only consultable answer. |
| The phantoms | ✅ All 24 dispositioned; G4 keeps `REQUIREMENTS.md` from re-acquiring one. |
| **The item as a whole** | ❌ **NOT closed.** This is the Lane A half only. |
| `R-*` / `LLR-*` / `US-*` | ❌ Out of scope by ruling; still colliding; registered in Lane B. |

⚠ **The C-3 row itself lives at `.dev-flow/BACKLOG-PROCESS.md:135`, which is the Lane B file this
batch was instructed not to touch.** The closure is stated here and in `BACKLOG-CODE.md`; marking
that row is owed to whoever next reconciles Lane B.

---

## 7 · Carries

- **▸ (P3) `TC-355` names a no-raise arm that no node asserts** — `tests/test_flow_crc_block.py`.
  Either write the verifier or drop the claim from the module docstring.
- **▸ (P3) `EXPECTED_SCANNED_TEST_FILES` is a manual constant.** Every PR adding a test module must
  bump it. That is deliberate — it makes corpus growth a decision — but it will feel like friction
  and someone will want to automate it. Automating it would delete the bound.
- **▸ (P3) the seed's `statement` for mechanically-bound ids is generated**, of the form *"Seeded
  from the existing verifier(s): …"*. It satisfies the schema but carries no semantics, so
  §3.5's *"is my TC-410 your TC-410?"* is only answerable for hand-dispositioned and newly-minted
  ids. Filling these in is a slow, incremental job, not a batch.
- **▸ (P2, Lane B) mark C-3 and the batch-62 "16 of 23" carry closed** in `BACKLOG-PROCESS.md`,
  citing this batch's guard run.
