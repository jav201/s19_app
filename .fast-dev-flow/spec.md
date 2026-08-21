# Quick Spec — s19_app · batch-85 · IFC pilot, one surface (`LoadedArtifactsPanel`)

- **Branch:** `claude/batch-82-lane-a-scoping` (base = `origin/main` `a112eeb`)
- **Flow:** `/fast-dev-flow` · supervised, no self-merge · artifact language English
- **Flow revision (C-45 PULL):** `2026.08.18-rev37` · `flow_hash ee21531d2c8372b4` · `V7` `V15`
  `V16` `V17` all green, refs refreshed with `--fetch`. Verified by execution, not assumed.
- **Entry document:** [`.dev-flow/design/BATCH-82-LANE-A-SCOPING.md`](../.dev-flow/design/BATCH-82-LANE-A-SCOPING.md)
  (PR #199). **Two of its claims are corrected below — see §6.**
- **Predecessor spec:** batch-84, CLOSED, archived to
  `.fast-dev-flow/archive/2026-08-17-batch-84-assembled-selector-census-spec.md`.

---

## 0 · ⛔ GATE VERDICT — BLOCKED AT PHASE A. Do not implement.

**The batch's headline deliverable is unachievable as specified, and the reason is a defect in the
control itself.** Found before any code was written, by the adversarial pass over the guards that
this batch was told to pair with. Stated first because everything below is detail.

> **`V10`–`V14` read exactly ONE file named `01-requirements.md`, chosen by `os.walk` order.
> There are 61. The one they read is `.dev-flow/2026-05-05-batch-01/01-requirements.md` — a frozen
> batch record from May. The other 60 are silently ignored.**

Authoring an IFC record for `LoadedArtifactsPanel` in a new batch folder would therefore leave
`V10`–`V14` on `SKIP` **forever**, and the suite would stay green while doing it. Per C-43 this is a
❌ FALSE premise, and a FALSE premise **blocks**.

---

## 1 · Objective (as briefed)

Author the Information Flow Contract record for one surface, `LoadedArtifactsPanel`, as the pilot
for batch-82's Lane A retrofit — establishing the per-surface cost so the remaining surfaces can be
sized from a measured number rather than an estimate.

## 2 · Out of scope

- The other surfaces. This is one, deliberately.
- Any change to `_FUNC_ID_RE`, the AT/TC registry, or its guards (D4's open half).
- **D1** — the public-repo question. Untouched.
- Changing any address. This batch *declares* how consumers reach surfaces; it moves nothing.

## 3 · Acceptance criteria

> Written before the block was found. **AC-3 is the one that cannot be met**; the rest survive and
> are the basis of the re-scope options in §7.

| id | Criterion | Status |
|---|---|---|
| **AC-1** | When `tools/address_origin.py` runs, the census asserts `set(forms) ⊆ {"literal","name","fstring"}` and names the offending form when it fails (D3). | ✅ achievable |
| **AC-2** | When the three stale "two shipped readers" copies are read, each names the measured consumer set of `.loaded-detail` rather than a count that was accurate when written. | ✅ achievable |
| **AC-3** | When `devflow-validate.py` runs against this repo, `V10`–`V14` report a verdict for `LoadedArtifactsPanel` instead of `SKIP`. | ⛔ **BLOCKED — see §0** |
| **AC-4** | When the pilot closes, the per-surface cost and finding-yield are reported as measured figures. | ⚠️ partially — findings yes, cost only for what was executed |

## 4 · Information Flow Contract — Part A (this change's own flow)

```
FLOW: ifc-pilot-authoring
  SOURCE : the shipped tree (s19_app/**, tests/**, s19_app/tui/styles.tcss)
  NODES  :
    - fn    : measure_consumers_of_address
      owner : AC-2
      in    : a declared literal address
      out   : the set of files that reach it
    - fn    : assert_census_forms_membership
      owner : AC-1
      in    : the census's form column
      out   : pass, or the name of the unexpected form
  SINK   : the IFC record + the corrected consumer lists
```

**Part B is deliberately absent from this spec, and that is itself the routing finding — see §5.**

## 5 · ⚠️ Routing conflict — this batch does not belong in `/fast-dev-flow`

Three independent confirmations, none of which is an opinion:

| Source | What it says |
|---|---|
| `/fast-dev-flow` Phase A step 5 | *"Part B — addresses, `cardinality`, `consumers` — is **NOT owed here**; it belongs to the full flow."* |
| `templates/dev-flow/ifc-template.md` §placement | Part B lives *"Inside `.dev-flow/01-requirements.md`, authored in **Phase 1** with the HLR/LLR set"* — a `/dev-flow` artifact |
| `devflow-validate.py::_artifacts` | walks **`.dev-flow/` only**. `/fast-dev-flow` writes `.fast-dev-flow/spec.md` and nothing under `.dev-flow/` |

**This batch's entire product IS a Part B record.** `/fast-dev-flow` structurally cannot produce the
artifact in the place the validator reads. The scoping doc recommended this lane on the grounds that
the design work was pre-paid — **true, and not sufficient**: the design being done does not give the
fast lane a Phase 1 to write into.

## 6 · Premise table (C-43) — evaluated before any code

| Premise | Tier | Verdict | Executed evidence |
|---|---|---|---|
| Lane B is encoded; the control exists to be applied | AXIOM | ✅ TRUE | `BACKLOG-PROCESS.md:9` + `devflow-validate.py --map`: `V10`–`V14` present in COVERAGE, absent from EXECUTION = the documented SKIP |
| The flow is current; this batch is not run on a stale flow | PREMISE | ✅ TRUE | `V7` green, `flow_hash ee21531d2c8372b4`; `V15` 21/21; `V16` both repos `0/0` after `--fetch` |
| **Authoring an IFC record in this batch moves `V10`–`V14` off SKIP** | **HYPOTHESIS** | ❌ **FALSE** | `_artifacts()` executed against this repo: `art["01-requirements.md"]` = **59,998 chars, 0 COMPONENT blocks**, resolving to `.dev-flow/2026-05-05-batch-01/01-requirements.md`. **61 such files exist; 60 are ignored.** No `state.json` read, no active-batch selection anywhere in the validator |
| **`V14` blocks a consumer with no `::symbol`, so a `.tcss` entry is illegal** | PREMISE | ❌ **FALSE — this was MY claim in the scoping doc, and it is wrong** | `devflow-validate.py:512` — `elif symbol and not contains(...)`. The symbol check is **conditional**. The template's §3 states the rule directly: a consumer entry is *"a path, **optionally** with `::symbol`"* |
| **A stylesheet counts as a consumer — genuinely open** | PREMISE | ❌ **FALSE — also already settled, also mine** | `_V13_EXT` includes `.tcss` and `.css`; the template's worked example lists `s19_app/tui/styles.tcss` as a consumer and states *"a dependant is … anything that would break if the address moved"* |
| `.loaded-detail` has 4 consumers, not 2 | PREMISE | ✅ TRUE | 3 `query(".loaded-detail")` sites (`test_help_toggle_and_a2l_panel.py:72`, `test_tui_commandbar.py:1285`, `test_unload_feature.py:270`) + `styles.tcss:258`. Matches the template's own corrected list exactly |
| A **third** stale copy exists, unregistered | PREMISE | ✅ TRUE | `styles.tcss:252` reads "Two shipped"; backlog registers only `screens_directionb.py:1953` and the design doc |
| The census's `other:Attribute` form is empty today (D3) | PREMISE | ✅ TRUE | `tools/address_origin.py`: forms are exactly `{literal, name, fstring}`, zero `other:*` |

### C-55 — the load-bearing emptiness in this batch

`AC-1`'s assertion is green **only because the tree contains no `other:Attribute` binding today**.
That emptiness is load-bearing: the guard is a no-op on the current tree and mutating it changes
nothing. **Discharge owed: a synthetic module with `self._sel = "#" + x`, asserting the guard goes
RED.** "There are none today" is why the guard is needed, never a reason to skip its red arm.

## 7 · Security flags

**`security_required: false`.** Scanned objective + criteria + description against the full pattern
list. No match: this batch authors documentation and one membership assertion, adds no route, no
input surface, no integration, no credential path, no destructive DB operation. The word *"address"*
throughout means a widget selector, not a network or memory address.

## 8 · Options — operator decision owed

| # | Option | Cost | What it buys |
|---|---|---|---|
| **A** | **Fix the validator first**, then pilot. Make `_artifacts` aggregate all `01-requirements.md`, or select by the active batch. | A flow-repo batch: `devflow-validate.py` + selftest arms + rev bump + `--sync-bundle` + C-45 PUSH. **Not this repo.** | Unblocks the whole retrofit, not just the pilot. Without it, **no** staged per-screen retrofit can ever accumulate |
| **B** | **Re-scope the pilot to AC-1 + AC-2 + AC-4** and drop AC-3. | Small; stays in `/fast-dev-flow`. | Real value (D3's guard, three corrected stale lists, measured findings) with the headline deliverable openly unmet |
| **C** | **Promote to `/dev-flow`** and author the record in a proper Phase-1 `01-requirements.md`. | Full V-model. | Correct home for Part B — **but AC-3 still fails**, because batch-01's file still wins the walk. Option A is a prerequisite, not an alternative |

**Recommendation: A, then B.** Option A is the only one that unblocks the retrofit as a programme,
and it is a flow-repo change that does not touch this repo. B can run in parallel here and is
genuinely useful on its own. **C without A does not achieve AC-3** — worth stating plainly, because
"promote to the heavier flow" is the intuitive answer and it does not work here.

---

## 9 · Status

| | |
|---|---|
| Current phase | **A — BLOCKED at the gate, awaiting operator decision on §8** |
| Implementation | **none.** No code, no IFC record, no correction applied |
| Files changed | this spec + the batch-84 archive move |
