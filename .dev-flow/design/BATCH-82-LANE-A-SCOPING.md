# batch-82 · Lane A retrofit — SCOPING

**Status:** SCOPING ONLY — no batch opened, no IFC authored, no code touched
**Date:** 2026-08-21 · **Lane:** A (code) · **Charter:** `BACKLOG-CODE.md` § *"BATCH-82 CHARTER … LANE A HALF"*
**Design it implements:** [`C-54-information-flow-contract.md`](C-54-information-flow-contract.md)

> Every figure below carries the command that produced it. Where a figure disagrees with a prior
> artifact, both are shown and the disagreement is named rather than silently resolved.

---

## 1 · The prerequisite is satisfied — Lane B is landed

`BACKLOG-PROCESS.md:9` records `C-54` **ENCODED 2026-08-15** at flow `rev33`, `V10`–`V14` each
demonstrating RED, selftest 85 → 136 arms. Verified by execution here:

```bash
python ~/.claude/docs/tools/devflow-validate.py --map
```

`V10`–`V14` print **no verdict line at all** — they appear in the COVERAGE list and nowhere in the
EXECUTION block. That is the documented `SKIP`, because **s19_app has authored no IFC**. That is
exactly what this retrofit is, and it is now unblocked on both counts (batch-84 closed the sizing
question, batch-82 Lane B shipped the control).

---

## 2 · There are TWO populations, and they have been conflated

This is the finding that most changes the shape of the work.

| Population | What it sizes | Count |
|---|---|---|
| **Reachers** — address-argument call sites the census cannot resolve at one hop (`C`+`D`) | *can `V13` tell who reaches a surface?* | **27** |
| **Surfaces** — classes that emit an addressable widget tree | *how many IFC records must be authored?* | **27** |

> ⚠️ **The two 27s are a coincidence and nothing else.** They share no member and measure unrelated
> things. Recorded loudly because a reader who sees one number twice will assume one population, and
> the 2026-08-18 handoff's *"the sizing number is 27"* is a claim about the **first** while the
> charter's deliverable is the **second**.

```bash
python tools/address_origin.py                       # C 14 + D 13 = 27 reachers
grep -rc "def compose(" --include=*.py s19_app/      # 27 surfaces
```

**The design doc's own estimate was `~40` surfaces** (§D-2). It is **27** by `compose()` and **31** by
direct widget-base. None of the three agree, because **"surface" has never been given a definition
that a command can evaluate.** Settling that is the retrofit's first increment, not an aside.

---

## 3 · Only 6 of the 27 reachers are product code

```
group  total  s19_app/  tests/
  A       14        0       14      literal-bound; resolvable by grep, not a blind spot
  B        0        0        0      the assembled selector -- confirmed empty
  C       14        5        9      caller decides
  D       13        1       12      other; sub-kind named per row
  U        0        0        0
TOTAL     41        6       35
```

The 6 product sites, in full:

```
s19_app/tui/app.py:1749                query_one(layout_id)     param
s19_app/tui/app.py:6380                query_one(widget_id)     [Tuple]
s19_app/tui/app.py:10627               query_one(container_id)  param + .values()
s19_app/tui/crc_designer_view.py:674   query_one(selector)      param
s19_app/tui/screens_directionb.py:7217 query_one(select_id)     param + Tuple
s19_app/tui/screens_directionb.py:7246 query_one(select_id)     param + Tuple
```

**All 21 test-side reachers sit in 9 files**, 14 of them in three (`test_map_click_chain` 5,
`test_tui_diff_screen` 5, `test_tui_directionb` 4).

**Why this matters for sizing:** `V13`'s subject is *who reaches a declared literal address*. A test
that reaches a surface through a parameter is still a consumer, so the 21 do not vanish — but they
are **9 files of test-helper indirection**, not 21 independent problems, and are likely cheaper
per-site than the 6 in the product tree. *Likely* — this is argued, not measured (see §7).

---

## 4 · The findings the retrofit is FOR already exist — three of them, measured today

`BACKLOG-PROCESS.md:33` registers **two** stale consumer lists. There are **three**.

| Copy | Says | Registered? |
|---|---|---|
| `s19_app/tui/screens_directionb.py:1953` | "two shipped readers" | ✅ yes |
| `C-54-information-flow-contract.md` §4 worked example | "two" | ✅ yes |
| **`s19_app/tui/styles.tcss:252`** | **"Two shipped"** | ❌ **NO — found here** |

Re-derived reader count for `.loaded-detail`:

```
tests/test_help_toggle_and_a2l_panel.py:72
tests/test_tui_commandbar.py:1285
tests/test_unload_feature.py:270
```

**Three Python readers, plus one `.tcss` selector at `styles.tcss:258`.** That reconciles with the
backlog's *"the tree has four"* **only if a stylesheet counts as a consumer** — and that is an open
question, not a detail:

> ⚠️ **`V14` requires every declared consumer to "resolve to a file, and its `::symbol` is in it".
> A `.tcss` selector has no `::symbol`.** The contract as encoded cannot express the CSS consumer
> that a class-based address demonstrably has. Either CSS is out of scope (and the count is three),
> or `V14` needs a second consumer kind. **Settle this before the first record is authored**, or
> every subsequent record inherits the wrong answer.

---

## 5 · Recommended shape — pilot first, then decide the flow

**The per-surface cost is unknown, and 27 × unknown is not a plan.** The charter's own staging rule
(*"the retrofit lands per-screen … a big retrofit does not gate unrelated work"*) already says this
work is a sequence of small stages, not one batch.

**Increment 1 — the pilot, one surface: `LoadedArtifactsPanel`.** The right pilot because it is the
surface `LLR-120.2` broke, its consumers are already enumerated, and it carries **three known stale
copies** to correct. Deliverables:

1. a definition of "surface" a command can evaluate — which of 27 / 31 / ~40 is right, and why
2. the CSS-consumer ruling of §4
3. one authored IFC record, with `V10`–`V14` moving off `SKIP` for it
4. **the measured cost and finding-yield of one surface**

Then size the remaining 26 from a real number.

**Flow: `/fast-dev-flow` for the pilot.** The design work `/dev-flow` exists to force — ARQ, PDR, the
design artifact — is **already paid for** in `C-54-information-flow-contract.md` and
`C-54-ENCODING-RECORD.md`; re-running it would re-derive an approved design. Re-evaluate at the
pilot's close: if the findings reopen the design (likely if §4's CSS question needs a `V14` change),
promote to `/dev-flow` — `mode` is a field in `state.json` and promotion is writing one field (C-50).

**Pair it with a hand-run adversarial pass over the batch's own guards**, recording what it finds and
what it false-flags. That is the measurement the 2026-08-18 handoff §2.2 asks for, and this is the
batch to start it on.

---

## 6 · D3 rides along

`BACKLOG-CODE.md` § *"A THIRD escape exists … the attribute-stored selector"* (P2) is registered as
*"belongs with batch-82's sizing"*, and it does. `self._sel = "#" + x` lands as census form
`other:Attribute` — outside the 41, outside every shape net. **Measured empty today; not guarded.**
Cheapest fix, unchanged from its registration:

```python
assert set(forms) <= {"literal", "name", "fstring"}
```

Membership, not a tree count — it names the new form when it fails. One assertion; it belongs in the
pilot rather than in a batch of its own.

---

## 7 · What this scoping does NOT establish

- **The per-surface cost.** That is the pilot's whole point; nothing here estimates it.
- **That 27 surfaces is the right number.** It is one of three live figures (§2), and the definition
  that would settle it does not exist yet.
- **That the 21 test reachers are cheap.** Argued as likely in §3, measured nowhere.
- **Anything about D1.** The public-repo question is untouched and stays open.
