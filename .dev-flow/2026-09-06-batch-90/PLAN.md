# PLAN — s19_app — 2026-09-06-batch-90

> **Living plan.** Updated at every gate and every significant checkpoint. The machine-readable
> mirror is `state.json.decisions_log`; this file is the human-readable half.

---

## 0 · BLUF

**batch-90 closes the two falsified-green-signal defects that survive an already-shipped check:
the AT/TC registry's blindness to batch-scoped ids, and `TC-497`'s inability to tell an assertion
from its refutation.** A third item entered scope by operator ruling — `report_service` markdown
escaping — and is **dropped at P0 as `SATISFIED-EXTERNALLY`**: it shipped at `fbc9f2a`, six weeks
before the brief that re-confirmed it open.

**THIS BATCH STOPS AT P1 IN THIS WAVE, AND THAT IS THE PLAN, NOT AN INTERRUPTION.** The parallel
lane is shipping flow **rev59**; **rev60**, immediately after it, adds declared fields to the
increment-packet template. Writing batch-90's first packet now would make it the last exhibit of
the superseded template and the first violation of the new one. Held at P1, the same packet becomes
the **first live exhibit of rev60's fields**. No increment, no source edit, no `03-increments/` is
opened in this wave.

**Order is load-bearing.** Requirement 1 (registry) precedes requirement 2 (`TC-497`) because
batch-90's own id reservation is unsound until it lands: 127 batch-scoped ids live in `tests/` and
**0** of them are visible to the authority that exists to stop id collisions.

---

## 1 · Station status

| Station | Status | Artifact |
|---|---|---|
| **P0 — intake** | ✅ done | this file · `state.json` · `AT-TC-REGISTRY.jsonl` reservation |
| **P1 — requirements** | ✅ done | `01-requirements.md` (live contract) · `01-requirements-ledger.md` (append-only) |
| P3 — implementation | ⏸ **HELD FOR rev60** | *(not opened)* |
| P4 — validation | not started | |
| P5 — close | not started | |

---

## 2 · RC-1 — base currency and flow currency

```
flow: 2026.09.06-rev58 (hash verified)
```

**Flow.** The manifest recipe (`~/.claude/docs/FLOW-VERSION.md` §"Verify the local flow") derived
**24 files** from the table and aggregated to **`50d1c2d0191432bf`**, identical to the declared
`flow_hash` at `docs/FLOW-VERSION.md` line 20. `~/.claude` had **no** dirty files at the moment of
measurement, so the local flow is exactly rev58 with nothing uncommitted. `V7` was green in the
baseline gate run, and is RED in the after-P1 run because rev59 landed in between — see §7.

⚠ **The forward divergence was predicted here and then OCCURRED during this wave.** rev59 landed in
`~/.claude` between the P0 measurement and the after-P1 gate: the aggregate moved to
`45eac0f2f6345fe3` and `V7`, `V15` and `V16` all went red. That is the other lane's in-flight work,
not a batch-90 finding, and §7 proves the attribution on a clean export rather than asserting it.
Family **F** did not fire *at evaluation time*, which is why this verdict is timestamped rather
than standing — and this is what a timestamped verdict is for.

**Base currency.** Measured in this worktree:

```
main         006d9635cbac832fcc4c054a1206a33243c7bfaa
origin/main  006d9635cbac832fcc4c054a1206a33243c7bfaa
merge-base   006d9635cbac832fcc4c054a1206a33243c7bfaa
HEAD         006d9635cbac832fcc4c054a1206a33243c7bfaa
```

`main` == `origin/main` == merge-base == HEAD. Nothing to rebase; requirements are derived against
the `origin/main` tip, not a stale tree.

**Worktree, and the proof that it is the tree under measurement.** The editable install points at
the main checkout, so the import was proven rather than assumed:

```
C:\Users\jjgh8\Github\s19_app-wt-batch90\s19_app\__init__.py
3.11.15 | packaged by Anaconda, Inc.
```

Note also that git cannot materialise an empty directory, so this worktree lacks any empty directory
the main checkout carries. That is correct behaviour, not a defect.

---

## 3 · Already-shipped check (RC-1, per item, against `origin/main`)

**Run fresh, not inherited.** The brief that proposed this scope supplied its own commands; each was
re-run here, and one of the three verdicts does not reproduce.

### Item 1 — AT/TC registry blindness · **OPEN**

```
$ git show origin/main:AT-TC-REGISTRY.jsonl | grep -cE '"(AT|TC)-B[0-9]+'
0
$ git show origin/main:AT-TC-REGISTRY.jsonl | wc -l
1373
$ git grep -hE "^def test_(at|tc)_b[0-9]+_" origin/main -- 'tests/*.py' | wc -l
141
$ git grep -hoE "^def test_(at|tc)_b[0-9]+_[0-9]+" origin/main -- 'tests/*.py' | sed 's/^def test_//' | sort -u | wc -l
127
```

Executed against the shipped tool, not inferred:

```
AT-B78-12 -> IdToken(space='AT', body='B78-12', governed=False, conforming=False, key=None)
TC-B79-01 -> IdToken(space='TC', body='B79-01', governed=False, conforming=False, key=None)
TC-489    -> IdToken(space='TC', body='489',    governed=True,  conforming=True,  key='TC-489')
```

**1373 registry rows · 0 batch-scoped rows · 127 batch-scoped ids live on test nodes.** OPEN.

⚠ **Two figures in the record do not survive re-measurement, and both under-report.**
The backlog item is titled *"BLIND to all 106 batch-78/79 acceptance nodes"* and the brief measured
**83** unique ids. Re-derived here: **127** unique ids over **141** node definitions, and the
namespace is **not** confined to batch-78/79 — it spans **five** batch tags:

```
b77: 30   b78: 74   b79: 5   b83: 18   b84: 14
```

The count drifts with every batch; **the `0` does not**, which is why the `0` is the figure the
requirement is keyed on.

### Item 2 — `report_service` markdown escaping · **SATISFIED-EXTERNALLY — `fbc9f2a`, 2026-07-26, PR #136. DROPPED FROM SCOPE.**

The brief's command reproduces, and its verdict does not follow from it:

```
$ git show origin/main:s19_app/tui/services/report_service.py | grep -cE "_md_escape|_escape_md|markdown_escape"
0
```

Those three helper names were never the shipped spelling. The escaper is a **leaf module**, and
`report_service` imports it:

```
s19_app/tui/services/report_service.py:61
    from .markdown_safety import md_safe, md_code
$ grep -cE "\bmd_safe\(|\bmd_code\(" s19_app/tui/services/report_service.py
28
$ git log --oneline -3 origin/main -- s19_app/tui/services/markdown_safety.py
fbc9f2a feat(report): batch-62 — escape file-derived text in project reports at the composer (#136)
$ git merge-base --is-ancestor fbc9f2a origin/main && echo YES
YES
```

All three classes the item names are escaped at the composer:

| class the item names | site |
|---|---|
| variant ids | `report_service.py:1735`, `:1791`, `:2355`, `:2373` — `md_safe(…variant_id, limit=REPORT_CELL_CHARS)` |
| filenames / paths | `:1736` `descriptor.path.name` · `:1822` / `:2116` `md_code(…source_path)` |
| declaration errors | `:2008`–`:2015` `issue.code` / `issue.message` / `issue.symbol` · `:2934` |

The item's rider — *"strikethrough survives the hardened parser — rides with the above"* — is
covered too. Executed against the shipped escaper:

```
strikethrough  '~~struck~~'                -> '\~\~struck\~\~'
linkify        'see http://evil.example/x' -> 'see http:\/\/evil\.example\/x'
heading        '# forged heading'          -> '\# forged heading'
table pipe     'a|b'                       -> 'a\|b'
```

`MD_ESCAPE` is `\ & | * _ [ ] < > # ~ / . @ \``. The requirement is on the living canon at
`REQUIREMENTS.md:5095` and is pinned by `tests/test_report_markup_safety.py` and
`tests/test_report_field_census.py`.

**Why the carry was stale.** It was written at the batch-60 close (2026-07-24). The fix merged at
batch-62 (2026-07-26), **two days later**, and nothing reconciled the carry. This is the exact case
RC-1's already-shipped check exists for, and it was caught at P0 rather than at P3.

### Item 3 — `TC-497` cannot tell an assertion from its refutation · **OPEN**

Node live on `origin/main` at
`tests/test_report_addendum_bound.py::test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers`.
Its figure loop is a whole-document membership test — the seven residual strings are searched in
`REQUIREMENTS.md` **in full**, while only the later `does NOT claim` and lettered-non-claim
assertions use a slice.

**Counterfactual EXECUTED, not argued** (own worktree, no other reader; C-40):

```
baseline                                       1 passed, 28 deselected
mutation applied (git diff --stat)             REQUIREMENTS.md | 3 +++
same node under the refutation                 1 passed, 28 deselected
restore: git checkout -- REQUIREMENTS.md
sha256 before   fc37480bfb6dad943d61b9921ab0888bad4ef3a1b34c211deb1f981a7f43b554
sha256 after    fc37480bfb6dad943d61b9921ab0888bad4ef3a1b34c211deb1f981a7f43b554
git status --porcelain                         (empty)
```

**The mutation is described by position and operation, never pasted (C-56):** into the `R-TUI-098`
section, on the line following the one carrying the first residual figure, one block-quoted sentence
was inserted declaring that figure false and superseded, with the figure token itself unchanged.
The node stayed green. It cannot distinguish the claim from its denial.

**Populations measured before the requirement was written (R-88-17):**

| measurement | value |
|---|---|
| what the node slices for its non-claim checks | **86,129** chars — the anchor to end-of-file |
| the true `R-TUI-098` section (anchor → next `##`) | **13,394** chars |
| over-slice factor | **6.4×** |
| residual figures present inside the true section | **7 of 7** |
| residual figures with an occurrence OUTSIDE the section | **1** (`988 B/entry`, one occurrence before the anchor) |

The last row matters: the whole-file grep is satisfiable today by a copy living outside the section,
so the section-binding defect is live rather than hypothetical. The 7-of-7 row matters too — it is
the evidence that binding to the section can be done **without editing `REQUIREMENTS.md`**, so the
fix stays test-only and cannot false-fail a correct document.

---

## 4 · `state.json` rollover — field by field, with the table row that justified it

**Ruling applied:** `~/.claude/commands/dev-flow.md` §*Batch rollover — `state.json` is SINGLE-SLOT*.
Every field was dispositioned; *"carried"* is recorded as a decision, not as an omission.

**The archive first, because it is one-way.** Before `batch_id` changed, batch-89's `decisions_log`
was written verbatim to `.dev-flow/2026-08-28-batch-89/decisions-log.json` and read back:

```
entries in state.json : 9
entries in archive    : 9
round-trip identical  : True
archive bytes         : 30559
archive sha256        : 0ace956c807f9382a52aae9b04693bab…
```

Only then was `state.json.decisions_log` set to `[]`.

| Field | Table row | Disposition for batch-90 |
|---|---|---|
| `decisions_log` | **MOVED**, then `[]` | Archived to `.dev-flow/2026-08-28-batch-89/decisions-log.json` (9 entries, round-trip verified), then cleared and re-opened with this batch's own entries |
| `batch_id` | replaced | `2026-08-28-batch-89` → **`2026-09-06-batch-90`** |
| `batch_objective` | replaced | Rewritten for batch-90; carries the P1 stop and its reason |
| `batch_objective_superseded` | *"Never park the old objective under an invented key"* | **DELETED.** It was added by hand at batch-89 and no rule or command reads it. Removing it is the rollover discharging the exact residual the table names |
| `current_station` | reset to the opening station | `P5` → **`P1`** (opened at `P0`, advanced when P0 completed; the batch is at P1 at this commit) |
| `phase_status` | reset to `not-started` | `awaiting-sync` → **`awaiting-gate`** (opened `not-started`; P1 is authored and awaiting the operator) |
| `iterations_per_station` | reset to zero over the stations THIS batch activates | Re-cut to `{P0:1, P1:1, P3:0, P4:0, P5:0}`. batch-89's map still carried `ARQ` and `PDR` keys for stations it never activated |
| `stations_active` | re-evaluated | `["P1","P3","P4","P5"]` → **`["P0","P1","P3","P4","P5"]`**. batch-89 omitted `P0` while running an intake; batch-90 runs one and declares it. `ARQ`/`PDR`/`DDR` stay off — see the trigger table |
| `triggers` | re-evaluated; a carried block asserts an evaluation that never ran | **RE-EVALUATED 2026-09-06** with executed probes (§5). batch-89 carried batch-88's block verbatim, `evaluated_at: 2026-08-24T21:30` and a `record` pointing at batch-88's PLAN — an evaluation stamped with someone else's timestamp |
| `artifact_homes` | every `<batch_id>`-templated path re-pointed | `requirements` and `increments` still named **batch-88** — two batches back — so batch-89's writes were declared into a closed batch's record. Both re-pointed at `2026-09-06-batch-90`. The non-templated homes (`traceability`, `tests`, `module_map`, `backlog`, `derived_atlas`, `design_ddr`) are carried unchanged; `design_pdr` is carried with its seal-rule note |
| `artifacts` | cleared, then re-pointed as created | Cleared, then re-pointed at `P0` (this file), `P1` and `P1-ledger`. No `P4`/`P5` key is written for files that do not exist |
| `mode` | re-declared | **`core`**, re-declared for batch-90 (dual traceability + RED counterfactual + `code-reviewer` as a gate are all wanted here) |
| `mode_history` | append-only PROJECT history, **CARRIED** | Carried unchanged, one entry. No entry appended: `core` → `core` is not a mode change, and an entry recording a non-change would make the history lie about what it is for |
| `standing_authorization` | **re-asked**, never carried | **NOT CARRIED.** batch-89's block was itself batch-88's, stamped `asked_on: 2026-08-24`. Replaced with an explicit not-asked record: this wave was dispatched with a bounded charter and no operator was available to ask, so the flow's stated default applies — the operator approves every gate and merges. `autonomous: false`, `merge: false` |
| `obsidian_synced` | `false` | `true` → **`false`** |
| `project` · `language` | carried | `s19_app` · `en` |
| `created_at` | re-stamped | **`2026-09-06T…-06:00`** |

**Landed in one commit** with the batch directory, `PLAN.md` and the two requirements files, so there
is no window in which `state.json` names a batch whose record does not exist.

**Read back, not assumed.** `V18`, `V27`, `V28` and `V29` results are in §7.

---

## 5 · Trigger evaluation — 2026-09-06, with probes

Evaluated over the batch's **planned** diff surface: `tools/id_registry.py` ·
`AT-TC-REGISTRY.jsonl` · `tests/test_id_registry.py` · `tests/test_report_addendum_bound.py`.

| id | Verdict | Probe and its output |
|---|---|---|
| **A — structure** | **FIRED** | The token-classification interface is consumed outside its module: `grep -rl "_FUNC_ID_RE\|iter_tokens\|derive_named_nodes" tests/ tools/` → `tests/test_id_registry.py`, `tools/id_registry.py`, **`tools/seed_id_registry.py`**. Widening the grammar changes what a second consumer sees |
| **B1 — shared surface** | **FIRED** | Same probe: `tools/seed_id_registry.py` asserts on these symbols and belongs to no story here. Reverse census owed |
| **B2 — file moves** | not fired | No move planned; both edits are in place |
| **B3 — golden drift** | not fired | `grep -rl "id_registry\|AT-TC-REGISTRY\|report_addendum" tests/goldens/` → `tests/goldens/batch64/addendum-below-bound.md`. **That is a golden of the report PRODUCER's output**, and this batch touches no producer — the hit is a substring match on `report_addendum`, not a captured source. Named rather than silently dismissed |
| **B4 — output-then-consume** | **FIRED** | `AT-TC-REGISTRY.jsonl` is read by `tools/seed_id_registry.py`, `tests/test_id_registry.py` and `.dev-flow/_derived/ATLAS-TRACE.md`. A change to what the guard admits is consumed downstream; C-12 AT owed |
| **C — security** | not fired | No auth, secrets, external integration, sensitive data, destructive DB, input surface or network exposure in the planned diff; and no render mode is flipped over file-derived text (C-17). Re-run over the real diff at every later gate |
| **D — interaction** | not fired | Nothing the user sees or touches changes. No prototype involved (C-16 n/a) |
| **E — size and risk** | **FIRED** | Not on the story/increment limb (2 stories, 2 planned increments) but on **high risk declared at intake**: the backlog item states that widening the regex reclassifies tokens repo-wide and *"could redden G1/G3/G5 across 678 existing ids"* — its own reason for demanding a dedicated batch |
| **F — flow currency** | not fired **at evaluation time** | `flow_hash` verified equal at rev58 (§2); the backlog was reconciled at `006d963`, today. ⚠ Timestamped, not standing — the parallel rev59 bump will invalidate it |

`ARQ`, `PDR` and `DDR` remain **off**: A fired, and A's controls are the reverse census and the
design review at the increment gate, not a module-map station — this batch moves no module boundary
and creates no module. Recorded as a judgement, and it is re-openable at the Inc-1 gate.

---

## 6 · Id reservation — what the registry actually governs, and what was reserved

**Read the authority before using it.** `AT-TC-REGISTRY-SPEC.md` §2.3 and the registry's own
`_meta.governed` field agree, verbatim:

> `_meta.governed`: *"A token whose body starts with a digit. Letter-initial bodies (AT-B64-04,
> AT-CRC-DSN-010, the AT-NNN placeholder) are batch-scoped / named-subspace ids, **outside this
> authority by spec 2.3**."*

> §2.3, *Declared but ungoverned id shapes* — batch-scoped ids are *"**Outside** the allocation
> authority and outside the guard"*, and *"⚠ **Outside the guard is also outside the GRAMMAR, which
> this cell alone does not say** — see §10: no guard reports a batch-scoped id at all, including one
> nobody registered."*

**So the registry governs global numeric `AT-NNN` / `TC-NNN` ids and nothing else today.** That has
a direct consequence for this batch's own reservation, and it is the reason requirement 1 is first:

- `CLAUDE.md` tells new work to *"Prefer batch-scoped ids (`AT-B76-01`)"*. Those are precisely the
  ids nothing polices. Minting `AT-B90-*` here would put batch-90's own acceptance ids outside the
  authority — reserving nothing, protecting nothing.
- Therefore batch-90 reserves **governed global ids** from `_meta.next_free`, which are the ids the
  registry can actually hold, and requirement 1 is the change that brings the batch-scoped space
  under the same authority so a later batch is not forced to choose between the convention and the
  guard.

**Reserved from `_meta.next_free` (`AT-282` / `TC-613`), appended as `RESERVED` with
`reserved_by: batch-90`, allocation monotonic — no gap-filling, no reuse:**

| id | reserved for |
|---|---|
| `AT-282` | a batch-scoped id carried by a test node is reported by the registry guard rather than silently ignored |
| `AT-283` | a residual figure the living canon refutes is not accepted by the guard as the figure being asserted |
| `TC-613` | the token grammar resolves a batch-scoped id to a comparable key instead of `None` |
| `TC-614` | `G1` names an unregistered batch-scoped node |
| `TC-615` | the residual-figure search is bound to the `R-TUI-098` section |
| `TC-616` | a refutation marker in the figure's own paragraph reddens the node |

`_meta.high_water` moved to `AT: 283` / `TC: 616` and `_meta.next_free` to `AT: 284` / `TC: 617`,
because **G7** fails any entry whose stem exceeds the recorded high-water mark.

⚠ **THE RESERVATION IS NOT MERGED, AND §4.2 STEP 2 SAYS THAT MEANS IT PREVENTS NOTHING.** The
protocol requires the reservation to reach `main` on its own small PR *ahead of the batch's work*;
this lane is forbidden to push or merge. Until the operator merges `claude/batch-90-green-signals`
(or cherry-picks the registry lines), a concurrent session can allocate `AT-282`/`TC-613` and the
collision is real. **Flagged, not worked around.** G1–G7 are green on this branch (§7), which
proves the reservation is well-formed — not that it is visible.

---

## 7 · Executed gates

### `tests/test_id_registry.py` (G1-G7) — after the reservation

```
tests/test_id_registry.py::test_tc600_g1_every_named_node_id_is_registered            PASSED
tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes             PASSED
tests/test_id_registry.py::test_tc602_g3_every_citation_is_registered                 PASSED
tests/test_id_registry.py::test_tc603_g4_requirements_citations_are_live              PASSED
tests/test_id_registry.py::test_tc604_g5_grammar_holds_or_is_registered_legacy        PASSED
tests/test_id_registry.py::test_tc605_g6_normalized_keys_are_unique                   PASSED
tests/test_id_registry.py::test_tc606_g7_no_stem_exceeds_the_high_water_mark          PASSED
tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound       PASSED
tests/test_id_registry.py::test_tc608_tokenizer_and_normalizer_edge_cases             PASSED
tests/test_id_registry.py::test_tc609_registry_file_is_well_formed                    PASSED
tests/test_id_registry.py::test_tc610_reservations_are_recorded_and_respected         PASSED
tests/test_id_registry.py::test_at280_registry_and_repository_agree_in_both_directions PASSED
tests/test_id_registry.py::test_at281_every_guard_rule_can_fail                       PASSED
13 passed
```

### `devflow-validate.py`

| run | tool | tree | result |
|---|---|---|---|
| baseline | rev58 | untouched worktree | **0 block** · 293 notice · 29 n/a |
| control | in-flight (rev59) | clean `git archive` export of `origin/main` | **5 block** · 290 notice · 28 n/a |
| after P1 | in-flight (rev59) | this worktree | **9 block** · 292 notice · 26 n/a |

**The baseline and the after-P1 run were made with DIFFERENT TOOLS, so they are not comparable and
the control run exists for that reason.** The parallel lane edited `devflow-validate.py` between
them: `V7` moved from `50d1c2d0191432bf` to `45eac0f2f6345fe3`, which is rev59 landing mid-wave
exactly as this wave anticipated.

**Attribution of all 9 blocks, measured rather than assumed:**

| block | attributed to | evidence |
|---|---|---|
| `V7` ×1 · `V15` ×2 · `V16` ×2 | **the parallel lane** | All five reproduce on a clean `origin/main` export that contains no batch-90 record. Not this batch's work, not chased |
| `V20` ×4 (`ATLAS-BATCHES`, `ATLAS-IFC`, `ATLAS-ORPHANS`, `ATLAS-TRACE`) | **batch-90's own record** | `V20` is GREEN on that same clean export under the same in-flight tool, so it is NOT the rev59 bump — it is this batch's directory entering the derived corpus |

**`V20` is reported and NOT regenerated, and the reason is not only the charter.** Regenerating now
would derive the Atlas with a validator that has uncommitted changes, baking unshipped tooling into
this batch's commit. The regeneration belongs after rev59 and rev60 settle — which is when the batch
resumes anyway.

**Named `[-]` results that are not passes:**

```
[-] V2   01-requirements.md: no AT ids declared
```

True and blind, and the rule's own docstring names this case. `V2` strips code spans on the declared
side, so `AT-282` and `AT-283` — written as citations of the reservation, with the field carrying the
`owed at <increment>` declared empty — are invisible to it. Writing them bare would make `V2` resolve
them against `tests/`, where neither node exists yet, and BLOCK. Recorded in the contract's §7 so the
`[-]` marker is not read as coverage.

**Gate lines the batch is judged on:**

```
[-] V6   01-requirements.md: 9 statement block(s) scanned, no modal inside any statement
[-] V26  01-requirements.md: the live contract is 26160 characters, inside the 54000-character budget
[-] V26  01-requirements.md: no strikethrough delimiter found in the live contract
[-] V26  01-requirements.md: every requirement declares a `**Ledger:**` field, `none` included
[-] V26  01-requirements-ledger.md: every ledger entry names at least one requirement
[-] V26  01-requirements-ledger.md: 12 (requirement, entry) pairing(s) declared on both sides and identical in both directions
[-] V18  .dev-flow/state.json: active batch `2026-09-06-batch-90` declared and on disk
[-] V27  .dev-flow/state.json: all 0 increment packet(s) on disk are named by a `decisions_log` decision
[-] V27  .dev-flow/state.json: the newest `decisions_log` entry is dated 2026-09-06 and the newest commit touching the batch directory is dated 2026-09-06
[-] V28  .dev-flow/2026-08-28-batch-89/: the batch `2026-09-06-batch-90` superseded holds `04-validation.md` and a close artifact
[-] V29  .dev-flow/state.json: all 6 `decisions_log` entry(ies) belong to `2026-09-06-batch-90` ... This is the strong pass -- both witnesses were available
```

**`V29`'s strong pass is a direct product of the rollover being done properly.** batch-89's own
record measured the WEAK pass, because batch-88 held no archived log for the rule to cross-check
against. Writing the archive before clearing the slot is what turned that into the strong form.

**Other notices, attributed:** `V8`, `V9`, `V13`, `V22`, `V23` findings are historical batches'
records. The validator is correct to light up on batches closed before those rules existed, and that
is not a backlog. `V16`'s stale-local-ref notices concern `~/.claude`, `~/.claude/skills` and
`~/kimi/agent-skills`, none of which is this lane's tree.

## 8 · Decision log (human-readable mirror of `state.json.decisions_log`)

| # | Station | Date | Decision | Why |
|---|---|---|---|---|
| D-1 | P0 | 2026-09-06 | **`report_service` markdown escaping dropped as `SATISFIED-EXTERNALLY`** at `fbc9f2a` | Taken without asking, because RC-1 mandates the reclassification at Phase 0 and the evidence is unambiguous: the escaper is imported at `report_service.py:61` with 28 call sites, and all three classes the item named are escaped |
| D-2 | P0 | 2026-09-06 | **Governed global ids reserved instead of batch-scoped ids** | The registry does not govern batch-scoped ids (§6). Reserving `AT-B90-*` would reserve nothing. Recorded because it deviates from `CLAUDE.md`'s stated preference, and requirement 1 is what removes the conflict |
| D-3 | P0 | 2026-09-06 | **`batch_objective_superseded` deleted rather than migrated** | The rollover table names it as an invented key nothing reads. Migrating it would preserve the defect under a new name |
| D-4 | P0 | 2026-09-06 | **`standing_authorization` recorded as NOT ASKED, with the flow's default applied** | The field is re-asked per batch and never carried. No operator was reachable in this wave, and inventing an authorization would be worse than declaring the default. `autonomous: false`, `merge: false` |
| D-5 | P1 | 2026-09-06 | **The `TC-497` requirement is written about what the node must DISTINGUISH, not about editing `REQUIREMENTS.md`** | Measured: all 7 figures already sit inside the true section, so the fix is test-only and cannot false-fail a correct document |
| D-6 | P1 | 2026-09-06 | **The batch is held at P1 in this wave** | rev60 adds declared fields to the increment-packet template. Held, batch-90's Inc-1 packet is that template's first exhibit; unheld, it is its first violation |

---

## 9 · Risks and watch items

| # | Risk | Disposition |
|---|---|---|
| R-1 | The unmerged reservation prevents no collision (§6) | **Open, and it is the operator's to close.** This lane cannot push |
| R-2 | Widening the id grammar reclassifies tokens repo-wide and could redden `G1`/`G3`/`G5` across 678 existing ids | The reason the item demanded its own batch. Requirement 1's threshold is written as a *measured* delta over the current tree, so the blast radius is a number produced before the change, not predicted (C-39) |
| R-3 | rev59/rev60 land mid-batch and move the flow hash | Expected and planned for; it is why the batch stops here |
| R-4 | The `TC-497` fix could be written so that it pins the section slice rather than the claim binding | Requirement 2 states two clauses and each owes its own negative control (C-55 limb 1: one mutation per conjunct) |
| R-5 | Item 2's stale carry is still open in `BACKLOG-CODE.md` and will be re-proposed by the next reader | The `SATISFIED-EXTERNALLY` verdict is recorded here with its SHA; reconciling the backlog line is a P5 close obligation, not a P1 edit |

---

## 10 · Out of scope, named

- **`TC-497`'s third defect** — three disclosed residual figures sit outside the node's 7-string
  list (`BACKLOG-CODE.md`, P2). That is *widening the list*; this batch fixes *what the list is
  compared against*. Deliberately separate.
- **Item 2 in every form.** Dropped at P0.
- Every other row of the code lane's prioritised index.
- Regenerating the Atlas, and anything under `~/.claude`.
