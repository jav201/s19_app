# AT/TC Id Registry — Design Specification

> **Lane B (process) half of the `BACKLOG-PROCESS.md` item *"MAJOR — there is no AT/TC registry"*.**
> This document is the **design only**. It builds nothing. The registry file and its guard test are the
> **Lane A** half, staged in `BACKLOG-PROCESS.md` under *PENDING MOVE TO LANE A* and blocked until
> batch-74 merges.
>
> **Neither half closes the item.** A batch that ships the registry file and reports "AT/TC registry DONE"
> has shipped the half without enforcement — a document that drifts silently, i.e. the defect itself.

| Field | Value |
|---|---|
| Status | **DRAFT — awaiting operator review** (done-condition for the Lane B half: *the spec exists and is reviewed*) |
| Authored against | `origin/main` @ **`093ff8e`** (batch-73 merged; router Amendment A landed) |
| Measurement refs | `031ca8d` (the backlog's own basis) and `093ff8e` (today) — **both stated, never mixed** |
| Governs | the **AT** and **TC** global numeric id spaces |
| Does **not** govern | `R-*`, `LLR-*`, `US-*`, `C-*` — see §0.2. Operator-scoped 2026-07-31 |
| Batch identity | **none** — deliberately not a numbered batch (§0.3) |
| Artifact language | English (engineering-artifact convention) |

---

## §0 Scope

### 0.1 What the registry is

**One file that is the single authority for AT/TC id allocation, and one test that fails when the file and
the repository disagree — in both directions.** Everything below is the detail needed to build that without
inventing semantics at implementation time.

### 0.2 Non-goals, named rather than omitted

| Out of scope | Why | Residual exposure |
|---|---|---|
| `R-*` / `LLR-*` / `US-*` id spaces | Operator ruling 2026-07-31: literal scope of the backlog item | ⚠️ **Real and measured.** The item's own cost evidence includes batch-63 re-using *live* `R-TUI-079/080/081` from batch-48 — an `R-*` collision, not an AT/TC one. Shipping this spec does **not** make that class impossible. §8.2 records it as a fresh backlog entry rather than letting it lapse |
| `C-*` control ids | Governed by the cross-project lineage in `~/.claude`, outside this repo's PR flow | Low — control minting is rare and already gated by an AskUserQuestion |
| Retroactive disambiguation of `.dev-flow/` prose | Burning an id (§6.3) stops *future* ambiguity; it cannot repair a batch-63 document that already used `TC-410` to mean something else | Accepted. The archive stays as-written; the registry records that the id is spent |
| The `state.json` concurrency hazard | Sibling defect, separately registered in `BACKLOG-PROCESS.md` | §4.3 borrows its lesson but does not fix it |

### 0.3 Why this has no batch number

Three id-numbering collisions in two days (batch-64/65, batch-66/67, and batch-74's `96bcbd7`). This
document would have to reserve a batch number from the same uncoordinated pool whose failure it exists to
describe. It is a **standing design artifact** consumed by a future build batch, not a record of one, so it
takes a name instead: `.dev-flow/AT-TC-REGISTRY-SPEC.md`.

---

## §1 Why — the measurements, re-derived

The backlog item carries four figures measured on `031ca8d`. **Three do not reproduce.** They are corrected
here rather than repeated, per this project's standing rule that *a carried number is re-derived, never
copied*.

### 1.1 Reproduction table

| Claim (`BACKLOG-PROCESS.md`, measured on `031ca8d`) | Re-derived on `031ca8d` | Verdict |
|---|---|---|
| 6 phantom TC ids: `TC-319/320/324/325/326/327` | exactly those six | ✅ **CONFIRMED**, id-for-id |
| TC: registers 97 of 188 live → **52 %** unregistered | 97 ids in `REQUIREMENTS.md`, of which **91** are live; 188 live in `tests/` → 97 unregistered → **52 %** | ⚠️ **percentage right, sentence wrong.** It registers **91** of 188, not 97. The two 97s are different quantities that coincide: `97 registered ids − 6 phantoms = 91`, and `188 − 91 = 97 unregistered` |
| AT: registers 20 of 73 live → **73 %** unregistered | with `\bAT-(\d+)`: 60 of 119 live registered → **50 %** unregistered | ❌ **DOES NOT REPRODUCE.** 20/73 is reproducible only with `\bAT-(\d{3})\b`, a pattern that silently discards every suffixed id (`AT-065b`). The figure measures the grep, not the corpus |
| "next free TC" = **345 / 398 / 479**, a **134**-id spread | 345 ✅ · 398 ✅ · **479 has zero occurrences anywhere in the repo**. Max TC stem in `.dev-flow/` is **398** — except the outlier `TC-1728`, which pushes a naive max-scan to **1729** | ❌ **DOES NOT REPRODUCE.** The third term and therefore the spread are unsupported |
| 75 AT / 119 TC exist only in `.dev-flow/` | on `031ca8d`: **30 AT / 65 TC** (excluding `tests/` and `REQUIREMENTS.md`). No exclusion variant reaches 75/119. On `093ff8e`: **54 AT / 113 TC** | ❌ **DOES NOT REPRODUCE at the stated ref.** The TC figure is close to today's, suggesting a different corpus date |

**Derivations used, stated so they can be refuted:** id tokens matched with `\bAT-(\d+)` / `\bTC-(\d+)` over
`git ls-tree -r <ref>` file sets; *live* = appears in `tests/`; *registered* = appears in `REQUIREMENTS.md`;
*phantom* = registered with no occurrence in `tests/` in either `TC-NNN` text or `def test_tcNNN` form.

### 1.2 What the reproduction failures actually tell us

**None of the four figures declared its grep pattern or its corpus.** That is not carelessness — it is the
item's own thesis one level up. *If "an id" is undefined, every measurement invents a definition, and two
honest measurements disagree.* The 73 % vs 50 % divergence **is** that ambiguity, measured: two defensible
patterns, two universes, a 46-id gap.

**Consequence for this design, and it is the reason §2 exists:** the root cause sits one layer above
allocation. A registry that assigns ids without first defining what an id *is* inherits the bug it was
built to fix. The backlog item does not ask for a grammar. It needs one.

### 1.3 The problem is growing

| Quantity | `031ca8d` (2026-07-26) | `093ff8e` (2026-07-31) | Δ |
|---|---|---|---|
| AT ids live in `tests/` | 119 | 153 | +34 |
| TC ids live in `tests/` | 188 | 240 | +52 |
| Phantoms (registered, no node) | 6 TC + 3 AT | **7 TC + 4 AT** | +2 |
| Ids existing only in `.dev-flow/` | 30 AT / 65 TC | **54 AT / 113 TC** | +72 |
| TC ids cited in `tests/` with no name-bearing node | 57 | **73** | +16 |

> ⚠️ **Every number in this section is stale the moment batch-74 merges.** Lane A **re-derives at its own
> seed commit**; it does not copy from here. These figures exist to justify the design, not to seed the file.

---

## §2 The id grammar

### 2.1 Governed space

```
id      ::= space "-" stem [ suffix ]
space   ::= "AT" | "TC"
stem    ::= digit+ [ "." digit+ ]
suffix  ::= lowercase-letter+
```

Corpus-attested examples: `AT-065b`, `AT-193b`, `TC-46.1`, `TC-021.1`, `AT-063c`, `AT-079c`.
Suffix letters observed in node names go well past `c` — `u`, `s`, `h` all occur — so `suffix` is
`[a-z]+`, not an enumeration.

### 2.2 Rulings the grammar must make, and the ruling

| Question | Ruling | Rationale |
|---|---|---|
| Is `AT-065b` a distinct id from `AT-065`? | ✅ **Yes. The full token is the id.** | The corpus already uses them as distinct assertions. Any other rule requires rewriting history. **This single ruling closes the 73 %/50 % ambiguity by decree** |
| What does allocation range over, then? | The **stem**. Minting `AT-224` consumes the entire `AT-224*` family | Prevents a second author minting `AT-224b` against a different observable. Only the stem's owner mints its suffixes |
| Zero-padding (`AT-065` vs `AT-65`) | **New ids are unpadded.** Comparison is done on a **normalized key** with leading zeros stripped, so legacy `AT-065b` and `AT-65b` are the *same* id and cannot both be allocated | Padding to 3 digits is already broken — `TC-524` exists. One normalization function, defined once in the guard, used everywhere |
| `TC-46.1` ↔ node `test_tc46_1_...` | The dotted stem maps to `_` in node names. Normalization handles both directions | Attested: `tests/test_tui_patch_layout.py::test_tc46_1_window_structure_layout_agnostic` |

### 2.3 Declared but ungoverned id shapes

| Shape | Example | Treatment | Why |
|---|---|---|---|
| Batch-scoped | `AT-B64-04`, `AT-N8-07` | **Outside** the allocation authority and outside the guard | Cannot collide across batches by construction — the batch tag is the namespace. **New work should prefer these**; every batch-scoped id is one the global pool never has to carry |
| Named subspace | `AT-CRC-*` | Same as above | Same |
| Non-conforming legacy | `TC-024-color`, `TC-1728` | Seeded once with `conforming: false` (§6.4); **any NEW non-conforming token is a guard failure** | Freezes the legacy mess at its current size instead of letting it grow |

### 2.4 What counts as a node

Three forms exist in `tests/` today. The first two are machine-derivable; the third is why C-3 is still open.

| # | Form | Example | Registry treatment |
|---|---|---|---|
| 1 | id in the **function** name | `def test_at065b_sev_semantics` | Derived automatically by the guard |
| 2 | id in a **class** name, methods unnamed | `class TestTc307ValidRoundTrip` (`tests/test_report_filter.py:57`) | Derived automatically by the guard. Note `TC-310` is carried by **four** classes — cardinality is N:M, not 1:1 |
| 3 | **text citation only**, no name-bearing node | 73 TC ids at `093ff8e` | ❌ Not derivable. **Must be declared explicitly** in the registry's `nodes` field. This is exactly the C-3 / batch-62 "16 of 23" gap, and declaring it is what closes it |

A **node reference** is a pytest-style locator: `tests/<file>.py::<function>` or `tests/<file>.py::<Class>`.
Parametrization brackets are **never** part of a node reference — the guard checks that the *name* exists,
not that a particular parametrized case does.

---

## §3 The registry file

### 3.1 Format — JSONL

**One JSON object per line, one line per id, sorted by `(space, normalized stem, suffix)`.**

> **⚠️ RECORDED PREMISE CORRECTION.** At the design gate this section recommended **TOML**, on the premise
> that `tomllib` is available as stdlib. `pyproject.toml:15` declares **`requires-python = ">=3.8"`**, which
> refutes it: `tomllib` landed in 3.11. Adopting TOML would need either a new test dependency (forcing an
> edit to `.github/workflows/tui-ci.yml`, which §7.3 exists to avoid) or a `requires-python` bump.
> **Cost to override back to TOML: one line in the workflow's pip-install step, plus a `tomli` pin.**

| Option | Verdict |
|---|---|
| **JSONL** ✅ | stdlib `json` on every supported Python · **append-only, line-granular merges** — the property §4.3 depends on · one line per id makes `git diff` name exactly which ids changed · greppable (`grep '"id": "TC-410"'`), which is the actual consultation pattern |
| Markdown table ❌ | Reintroduces the `\|`-escaping hazard — batch-62's exact defect class. A description containing a pipe forges a column, and the guard's parse silently shifts |
| TOML ⚠️ | Prettier for multi-field records, but see the premise correction. Merge conflicts span whole `[[table]]` blocks rather than single lines |
| JSON (single array) ❌ | Every append rewrites the closing bracket → guaranteed conflict on every concurrent edit, with no information about which id caused it |

### 3.2 Location — `AT-TC-REGISTRY.jsonl`, repository root

Beside `REQUIREMENTS.md` and `PROJECT_RULES.md`, the project's other governance documents. The decisive
criterion is **discoverability by the party about to mint an id**: a registry no one trips over before
minting is not an authority. `docs/` and `tests/` were considered; `tests/` additionally miscategorizes the
file as test data when its authors are requirement writers.

### 3.3 Schema

| Key | Type | Required for | Meaning |
|---|---|---|---|
| `id` | string | all | The verbatim canonical token, e.g. `"TC-046.1"` |
| `space` | `"AT"` \| `"TC"` | all | Redundant with `id`; present so the file is filterable without parsing |
| `status` | enum, §3.4 | all | |
| `statement` | string | `LIVE`, `RESERVED` | **What the id asserts, in one sentence.** Not decoration — see §3.5 |
| `nodes` | list of node refs | `LIVE` | ≥1. N:M permitted in both directions (§2.4) |
| `origin` | string | all | Minting batch or `"seed"` |
| `conforming` | bool | all | `false` only for §2.3 legacy tokens |
| `reserved_by` | string | `RESERVED` | Owning batch id |
| `retired_reason` | string | `RETIRED` | Free text; must say what happened to the verifier |
| `provenance` | string | `BURNED` | Where the spent id was found |

### 3.4 Status values

| Status | Means | Has a node? | Reusable? |
|---|---|---|---|
| `LIVE` | Bound to ≥1 existing node | ✅ required | ❌ never |
| `RESERVED` | Allocated to a batch, node not yet written | ❌ not yet | ❌ never |
| `RETIRED` | **Was** live; its verifier was removed or renamed | ❌ | ❌ never |
| `BURNED` | **Never** had a node in this repo; consumed by a superseded design | ❌ | ❌ never |

**`RETIRED` and `BURNED` are deliberately not merged.** `RETIRED` means a verifier that once existed is
gone — a coverage regression someone should see. `BURNED` means no coverage claim ever existed. Collapsing
them would bury every future coverage regression inside a ~167-row bulk import (§6.3). The distinction costs
one enum value and is the only thing that keeps the seed honest.

**Precedent, not invention:** `REQUIREMENTS.md:5068` already declares *"`AT-195` and `TC-496` are **retired
ids and are not reused**"*. The project has been maintaining a `status` field by hand, in prose, without a
schema. This formalizes what already exists.

### 3.5 Why `statement` is mandatory

Fixing id **ranges** before dispatch prevented range overlap in batch-63 and did **not** prevent per-id
semantic collision: **9–10 of 12 AT ids bound to different observables**, found independently by all three
Phase-2 lanes. A registry that records only *"TC-410 is taken"* leaves that half of the measured cost
untouched. `statement` is what makes *"is my TC-410 your TC-410?"* answerable before the lanes converge.

---

## §4 Allocation

### 4.1 The rule that closes the spread

> **The registry is the only consultable corpus. `next_free(space) = max(stem of every entry with
> `conforming: true`) + 1`. Allocation is monotonic: no gap-filling, no reuse, ever — regardless of status.**

Nobody greps anything again. The 345 / 398 / *479* disagreement does not get documented, reconciled, or
mitigated — **it ceases to be expressible**, because there is exactly one place to look and it contains
every id ever spent (§6).

**Why `conforming: true` is in the formula:** a naive max over the corpus returns **1729**, because
`TC-1728` (`.dev-flow/2026-07-08-batch-29/_qa-acceptance-validation.md:252`) parses as a stem and is 1330
above its neighbour. Excluding non-conforming entries from the high-water mark keeps the mark at 525 while
leaving `TC-1728` permanently spent. **This is measured, not hypothetical** — it is the failure a max-scan
actually produces today.

**Why no gap-filling.** Gaps are the mechanism by which "free space" becomes a matter of opinion. A
monotonic counter is the only rule with a unique answer.

### 4.2 Reservation protocol

| Step | When | What |
|---|---|---|
| 1 | Batch Phase 1 (requirements), **before** any AT id is written into a spec | Append a contiguous block as `RESERVED` with `reserved_by` and a `statement` per id |
| 2 | Immediately | **Merge the reservation to `main` on its own small PR**, ahead of the batch's work |
| 3 | Batch Phase 3/4 | Convert `RESERVED` → `LIVE`, filling `nodes` |
| 4 | Batch close | Any unconsumed reservation → `RETIRED` or left `RESERVED`; **never** released back to the pool |

**Step 2 is load-bearing.** A reservation only prevents a collision if a concurrent session can see it.
A reservation living on an unmerged branch prevents nothing — which is precisely the batch-64/65 failure.

### 4.3 Concurrency — the conflict is the feature

⚠️ **A scalar `next_id` counter in a mutable file would reproduce the `state.json` hazard verbatim**:
one file, last-writer-wins, no owner field, three collisions in two days. The design avoids it structurally:

- The file is **append-only and sorted**, so a block reservation is a contiguous run of new lines.
- Two concurrent batches reserving overlapping ranges append at the same position → **git merge conflict**.
- A merge conflict is **loud, blocking, and names the exact lines**. A silent overwrite is none of those.

**Deliberately not built: reservation expiry.** A leaked reservation costs *ids*, not *correctness* — the
id stays spent and nothing breaks. A time-based expiry check fails on unrelated PRs on an arbitrary day,
which is how a gate becomes something everyone learns to wave through (`BACKLOG-PROCESS.md` §7.7 registers
that exact failure mode against the R-c length check). No machinery for a hygiene issue with no correctness
impact.

---

## §5 Guard semantics

Lives in `tests/test_id_registry.py`. Modelled on `tests/test_engine_unchanged.py`, the repo's existing
hygiene guard: fails **loud** and **names every offender** rather than asserting a count.

### 5.1 The rules

| # | Direction | Rule | Closes |
|---|---|---|---|
| **G1** | node → registry | Every id derivable from a node name (§2.4 forms 1–2) is registered | unregistered node |
| **G2** | registry → node | Every `LIVE` entry's `nodes` all exist. `RESERVED`/`RETIRED`/`BURNED` are exempt **by status, not by absence** | registered id with no node · **C-3** · batch-62 "16 of 23" |
| **G3** | citation → registry | Every id token cited anywhere in `tests/` or `REQUIREMENTS.md` is registered in *some* status | ids in circulation that the registry never saw |
| **G4** | citation → liveness | An id cited in `REQUIREMENTS.md` must be `LIVE`, **unless** the citation falls under a declared exempt anchor (§5.3) | **the 6+1 phantoms** |
| **G5** | grammar | Every token matching `\b(AT\|TC)-\S` either parses per §2.1 or is a registered `conforming: false` entry | new legacy-shaped tokens |
| **G6** | uniqueness | No two entries share a normalized key (§2.2) | zero-padding aliases |
| **G7** | monotonicity | No entry's stem exceeds the recorded high-water mark for its space | out-of-band minting |

### 5.2 ⚠️ The item under-specifies its own guard

The backlog item asks for a guard that *"FAILS when the registry and `tests/` diverge in either
direction"* — that is **G1 + G2 only**. The six phantoms it presents as headline evidence are a
`REQUIREMENTS.md` ↔ `tests/` divergence: `TC-324..327` are cited in `REQUIREMENTS.md` as verifiers while
`tests/test_tui_entropy_viewer.py` **does not exist**. A registry↔`tests/` guard never looks at
`REQUIREMENTS.md` and **would not detect a single one of them.**

**G3 and G4 are therefore not scope creep — they are the minimum that closes the evidence the item cites.**

### 5.3 G4's exempt anchors

`REQUIREMENTS.md` legitimately names non-live ids in history sections (`## History / superseded`, line
1108) and in the retirement note at line 5068. The exemption is **structural, not keyword-based**: the
registry carries a top-of-file metadata line listing exempt heading anchors, and a non-live citation is
permitted only under one of them.

**The exempt list is data, reviewable in the PR diff, not logic buried in the guard.** It starts with the
history section plus a new `## Retired ids` section Lane A creates as the sanctioned home for
retirement notes.

> **Refutation trigger, stated in advance:** if the exempt list needs **more than 5** anchors, G4's model of
> `REQUIREMENTS.md` is wrong and the rule should be weakened to G3-only rather than grown. Written here so
> the fallback is a designed decision instead of an implementation-time improvisation.

### 5.4 Failure output

Each rule emits its own assertion, naming every offending id **and its locus**. A single aggregate
`assert not problems` reporting a count would leave the reader to re-derive the diff by hand — the same
defect as a phantom: an assertion that claims coverage without delivering locatability.

### 5.5 The guard must be shown able to fail

Per the standing project rule that a guard firing nowhere on install is indistinguishable from one that
cannot fire, Lane A ships a **counterfactual per rule G1–G7**: seven mutations executed against a **copy of
the fixed tree** (never against the pre-fix tree — an error on the old tree proves nothing), each recorded
with **the substituted value**, not the deleted operator.

---

## §6 Legacy corpus disposition

Seeding is a **one-time** operation. Its cost never appears in CI (§7).

### 6.1 The three phantom sub-cases — re-derivation per id, bulk relabel FORBIDDEN

The seven phantoms at `093ff8e` are **not one class**. Marking all seven `RETIRED` would be fast, wrong,
and undetectable.

| Ids | Situation, verified on disk | Required disposition |
|---|---|---|
| `TC-324/325/326/327` | Cite `tests/test_tui_entropy_viewer.py`, which **does not exist**. `REQUIREMENTS.md:3839` and `:3879` already say *"is deleted"* in prose while the verifier column keeps citing the ids | `RETIRED`, `retired_reason` naming the deleted file. **Lane A must also repair the `REQUIREMENTS.md` citations** so the doc stops asserting live verifiers — otherwise G4 fails on merge, correctly |
| `TC-319/320` | Cite `tests/test_tui_patch_layout.py`, which **exists** — but contains no `test_tc319_*`. The file's live nodes are `test_at063*`, `test_at064*`, `test_tc46_1*`, `test_tc46_2*` | ❓ **Renamed or removed — must be determined, not assumed.** If renamed → `LIVE`, re-bound to the current node. If removed → `RETIRED`, and the requirement it verified **loses its verifier**, which is a coverage regression to surface, not to paper over |
| `AT-195` / `TC-496` | `REQUIREMENTS.md:5068` already declares them *"retired ids and are not reused"* | `RETIRED`, transcribed. Zero judgement required |

> **`TC-319` is the loudest of the seven.** It is cited as `test_tc319_regroup_section_structure_census`,
> the census node that control **C-26** rests on. If it is silently retired, C-26's evidentiary basis is
> gone and nothing announces it.
>
> **Correction to the item's own text:** it states *"`TC-319` is the exact node `CLAUDE.md` cites as the
> origin of control C-26."* In this repo, `CLAUDE.md` contains **neither** `TC-319` **nor** `C-26`. `TC-319`
> is cited 3× in `REQUIREMENTS.md` (`:3656`, `:3694`, `:3902`) and C-26 5× in `REQUIREMENTS.md`. The
> substance stands — a control's cited node has no implementation — but the locus in the item is wrong, and
> anyone who greps `CLAUDE.md` to check will find nothing and may conclude the finding was withdrawn.

### 6.2 Ids cited in `tests/` with no name-bearing node

**73 TC ids at `093ff8e`** (was 57 at `031ca8d`). Each is either bound to a battery node — which the
registry expresses natively via `nodes: [...]`, §2.4 form 3 — or is a citation of something that does not
exist, which is a phantom by another route. **Lane A resolves each; this is the population C-3 and the
batch-62 "16 of 23" carry both name.**

### 6.3 Ids existing only in `.dev-flow/`

**~54 AT / ~113 TC at `093ff8e`, re-derive at the seed commit.** Bulk-seeded as `BURNED`, `provenance:
".dev-flow"`, unaudited, `statement` omitted.

| Option | Consequence |
|---|---|
| **Burn them** ✅ | ~167 rows, one script. The `.dev-flow/` archive stays unambiguously readable forever |
| Leave them free ❌ | A future batch mints `TC-410` while a batch-63 document already uses `TC-410` for something else. **The archive becomes permanently ambiguous, and no guard can detect it** because both uses are legitimate in their own file |
| Audit each before burning ❌ | ~167 manual judgements to establish facts nobody will consult. Burning is cheap precisely *because* it asserts nothing about meaning |

Burning is explicitly **not** a claim that the id meant something coherent — only that it is **spent**.
That is what `BURNED` vs `RETIRED` (§3.4) keeps honest.

### 6.4 Outliers

The seed script emits the sorted stem list per space and **flags every gap greater than 25**. Each flagged
token gets an individual disposition line. At `093ff8e` this flags exactly one: `TC-1728`, → `BURNED` with
`conforming: false`, keeping the high-water mark at 525 instead of 1729 (§4.1).

**This is the "re-derive, never copy" rule applied to seeding itself.** A blind bulk import would have
imported `TC-1728` as an ordinary id and broken the allocation rule on day one.

---

## §7 CI cost

### 7.1 Corpus bounds

| Scanned | Not scanned | Why not |
|---|---|---|
| `AT-TC-REGISTRY.jsonl` (1 file) | **`.dev-flow/`** (865 files, 17 MB) | Not just expensive — **incorrect**. Re-scanning it would make the guard's verdict depend on batch prose, so editing a postmortem could redden CI |
| `tests/**/*.py` (**147** tracked at `093ff8e`, of 181 tracked under `tests/`) | `tests/goldens/`, `tests/__snapshots__/` | Binary/large fixtures carry no ids |
| `REQUIREMENTS.md` (5 269 lines) | `s19_app/`, `docs/`, `prototypes/` | Ids appear there but those are **citations of** requirements, not allocations. Adding them is a later widening, not a day-one cost |

### 7.2 Implementation

- **Node names** via `ast.parse` — precise, and immune to ids appearing inside strings or comments.
- **Citations** via a compiled regex over file text.
- **No pytest collection, no app import, no subprocess, no network.** 147 small `ast.parse` calls.

### 7.3 Budget as an executable threshold

A wall-clock assertion is flaky and would fail on unrelated PRs. The guard instead asserts the **number of
files it scanned** against a declared constant.

That threshold is executable, deterministic, and **can go RED**: pointing the guard at `.dev-flow/` or
adding a directory moves the count immediately. It bounds the thing that actually drives cost.

### 7.4 No workflow change

⚠️ `.github/workflows/tui-ci.yml` has **no `paths-ignore`** — verified, not assumed. Every PR runs
`pytest -q -m "not slow"` and every push to `main` runs the full suite. A plain test file in `tests/` is
therefore gated automatically.

**The guard must NOT carry the `slow` marker**, or it silently vanishes from the PR lane — which is the one
that matters, since PRs are where ids get minted.

---

## §8 What this closes

### 8.1 Explicit closures — and the precise condition for each

| Item | Closed by | ⚠️ Condition |
|---|---|---|
| **C-3** — *16 of 23 TC ids are not traceable to any node* | The `nodes` field (§3.3) + **G2** | Closes **only if `nodes` is N:M**. Batch-62's accepted resolution was *consolidated batteries with the mapping in `04-validation.md` §3* — N ids → 1 node. **A 1:1 schema would contradict the accepted resolution of the very carry it claims to subsume.** §2.4 permits N:M in both directions specifically for this |
| **batch-62 "16 of 23" carry** | Same mechanism | Same |
| The 134-id spread | §4.1 | Closes by making the disagreement inexpressible, not by reconciling it |
| The 6+1 phantoms | **G4** | Does **not** close under the guard as the item words it (§5.2) |

> **Neither C-3 nor the "16 of 23" carry is closed by this document.** They close when Lane A's guard is
> green on `main`. **State that explicitly at Lane A's close rather than letting them lapse** — the item
> warns that a batch reporting "AT/TC registry DONE" on the file alone has shipped the defect.

### 8.2 New backlog entries this design creates

To be added to `BACKLOG-PROCESS.md` **as a separate reviewed edit**, not folded silently into this file:

1. **(P2) `R-*` / `LLR-*` / `US-*` are unregistered and demonstrably collide.** batch-63 re-used live
   `R-TUI-079/080/081`. Scoped out by operator ruling; registered so the exposure is a decision, not an
   oversight.
2. **(P3) Four of the five figures in the AT/TC registry item do not reproduce.** Corrected in §1; the
   backlog text still carries them.
3. **(P3) The item mislocates `TC-319`'s citation** as `CLAUDE.md`; it is `REQUIREMENTS.md` (§6.1).

---

## §9 Lane A build contract

**Do not start before batch-74 merges.** It is renumbering the live AT/TC set (`96bcbd7`), so a registry
seeded now is born stale and its guard reddens the day batch-74 lands.

| Inc | Deliverable | Done-condition (executable) |
|---|---|---|
| 1 | Seed script + `AT-TC-REGISTRY.jsonl` | Every id in `REQUIREMENTS.md` ∪ `tests/` ∪ `.dev-flow/` at the seed commit appears exactly once. Outlier report emitted per §6.4 |
| 2 | Phantom disposition | All phantoms dispositioned per §6.1, **each with a per-id rationale**. `TC-319`'s outcome states what happens to C-26's evidentiary basis |
| 3 | §6.2 resolution | Every `tests/`-cited id with no name-bearing node is either bound via `nodes` or dispositioned |
| 4 | `tests/test_id_registry.py` (G1–G7) | Green on `main`; **no `slow` marker**; scanned-file-count threshold asserted |
| 5 | Counterfactuals | 7 executed mutations on a copy of the fixed tree, each recording the **substituted value** |
| 6 | `REQUIREMENTS.md` repair + `## Retired ids` section | G4 green without exceeding 5 exempt anchors (§5.3) |
| 7 | `CLAUDE.md` + `docs/engineering-rules.md` point at the registry as the allocation authority | An author reading either arrives at §4 without reading this spec |
| 8 | Close | C-3 and the batch-62 carry **named as closed, with the guard run as evidence** |

**Ordering constraint:** Inc 4 must not precede Inc 1–3, or the guard is authored against a corpus it
cannot yet be green on and its thresholds get tuned to make it pass — the failure mode this whole item
exists to prevent.

---

## §10 Risks and rejected alternatives

| Risk | Mitigation, or accepted |
|---|---|
| The registry becomes a file people edit *after* minting, restoring the status quo | §4.2 step 2 puts the reservation on `main` **before** the work. If reservations are routinely retrofitted, the protocol has failed and that is observable in PR order |
| G4's exempt-anchor list grows without bound | §5.3's refutation trigger: >5 anchors ⇒ weaken to G3-only |
| ~167 `BURNED` rows make the file unreadable | Sorted + one line per id + greppable. `BURNED` rows carry no `statement`, so they are visibly inert |
| Batch-scoped ids (§2.3) escape the guard entirely | ✅ Accepted, deliberately. They cannot collide across batches. Widening the guard to cover them doubles its complexity for a class with **zero** recorded collisions |
| The spec's own numbers go stale | ⚠️ **They already are** (batch-74 in flight). §1.3 and §9 Inc 1 both require re-derivation at the seed commit |

**Rejected: mint ids from a hash / UUID.** Kills collisions outright and destroys the ordering and
human legibility every existing artifact depends on. The problem is not that integers collide; it is that
nobody agreed where the integers live.

**Rejected: generate the registry from `tests/` on every run.** Then it cannot hold `RESERVED` (no node
yet), `RETIRED` (node gone) or `BURNED` (never a node) — i.e. it cannot represent allocation at all, only
current occupancy. Occupancy is exactly the view that produced 345 / 398 / *479*.
