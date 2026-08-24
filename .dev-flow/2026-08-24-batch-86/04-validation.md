# Validation — s19_app — Batch `2026-08-24-batch-86`

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in Phase 1
> (`01b-qa-validation-plan.md` §1/§2, folded into `01-requirements.md` §3 as `AT-B86-01`…`04`
> and the G-86 gate table).
>
> **Zero-source-code batch — the template is adapted honestly, not zero-filled.** No product
> function was authored, so Layer 0 (unit/mutation-on-code) and the UX walkthrough have no
> population; each is marked `n/a` with its reason, never with a fabricated row. The shipped
> surface this batch actually ships against is the **`devflow-validate` toolchain + the
> derived Atlas + the living canon** — an operator-local surface, so every method label below
> is `inspection (executed)` and never `test`, which would assert a pytest node that cannot
> exist (C-18).

## ✅ Verdict (read first)

- **Result:** **PASS.** *(Fold retraction 2026-08-24, final PR pass MEDIUM: this bullet
  originally read "with one half of one pin BLOCKED-ON-BASELINE" — superseded when the
  ledger was folded; see the ledger table.)* (G7's
  ledger comparison — see below; it is not counted green).
- **Requirements:** `11`/`11` pass (3 HLR + 8 LLR) · `0` blocker fails
- **Black-box acceptance (Layer B):** ✓ all four `AT-B86-*` observe their outcome through the
  shipped surface, each with the deliverable observed on disk (validator stdout, the derived
  `ATLAS-IFC.md`, the canon file) and boundary + negative arms **executed on a copy** this
  phase, not predicted
- **Surface-reachability (bidirectional):** ✓ 5 named input dimensions and 5 named
  outputs/deliverables — all reached/observed through the real handler (a validator process
  reading files off disk), 0 gaps
- **Supersession inspection:** ✓ the one superseded marker of this batch (the pilot's
  "parent … NOT checked" NOTICE for `loaded_panel`) has 0 surviving live references; its only
  surviving assertion is a **negative** one (an absence claim, with its positive control)
- **Test ledger:** ✓ **FOLDED at the gate** — `2702 passed · 6 failed · 3 skipped · 3 xfailed`
  of 2714 selected, one complete run; the 6 diagnosed by execution as pre-existing
  order-dependent flakiness (each passes isolated on pristine `main`), carried to the
  backlog at close. Ledger `post = 2714 − 0 + 0` reconciles; the pin's diff half was
  already green. Full disposition in the ledger table below.
- **Evidence checklist (qa-reviewer):** ✓ complete — 11/11 items cited below
- **Kill mutations owed at Phase 4 (M4 · M5 · M7):** ✓ **all three executed on disposable
  copies**, live tree never mutated (`git status --porcelain` empty after the run)

> Two findings worth the reader's time even though neither blocks:
> **(1)** M4 reproduced batch-85 **defect #1 exactly** — the stray census moved **+1 pair while
> the corpus-wide file-set union did not move at all**. A file-set-based census would have
> been blind to the deleted declaration.
> **(2)** M7's predicted delta was **wrong by one**, and the mutation is what found it: the
> canon's mirror line packs **two** ids, so deleting the line moves V22 by **+2**, not +1.
> The prediction is repaired by a second, surgical arm that isolates one id and lands on the
> predicted 277. Both arms are transcribed; the wrong prediction is not quietly overwritten.

---

## Detail (reference)

### Kill-mutation transcripts (the Phase-4 debt from `01-requirements.md` §3)

**Protocol executed verbatim** (`01b` §2): `T=$(mktemp -d); cp -r <worktree>/. "$T";
rm -rf "$T/.git"`, then `python ~/.claude/docs/tools/devflow-validate.py "$T"`. One copy per
mutation; each copy **discarded** at the end of its arm (`rm -rf "$T"`). *No restore step is
recorded because none is owed — that is the point of the copy protocol, and it is strictly
stronger than the increment's sed-on-the-live-tree arm, which needed a sha256 to prove the
CRLF normalisation had been undone.* The live tree was re-checked after all three:
`git status --porcelain` → empty, and the two ids M7 touched still grep 1 each.

Neither M7 arm creates a corrupted id token — both are pure deletions — so, unlike the
increment's RED arm, there is nothing here the Atlas could adopt as a phantom id. Mutations
are described by **position and operation**, never by pasting a mangled token.

---

#### M4 — remove one `consumers` entry from a `screen_workspace` OUTPUT

**Mutation (on copy):** in the record's IFC block, the `memstrip_band` OUTPUT's consumer list
loses its **first** entry (the `s19_app/tui/app.py::update_memory_strip` binding); the list
goes from 4 declared entries to 3. The address literal, the owner and every other output are
untouched. `app.py` was chosen deliberately: it carries the address literal 6 times, and it
**already appears** in four other outputs' stray sets — which is what makes the file-union
blindness observable.

**Confirm the mutation applied** (copy differs from live):

```
live    : V14  01-requirements.md: 106 declared consumer(s), every one resolved
mutated : V14  01-requirements.md: 105 declared consumer(s), every one resolved
```

**Targeted V13 line — live vs copy:**

```
live    : [!] V13 …/batch-86/01-requirements.md:401: COMPONENT screen_workspace/memstrip_band:
              reached by 4 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md,
              prototypes/screen_upgrades.HANDOFF-PLAN.md, tests/test_tui_snapshot.py

mutated : [!] V13 …/batch-86/01-requirements.md:401: COMPONENT screen_workspace/memstrip_band:
              reached by 5 undeclared file(s) — REQUIREMENTS.md, prototypes/legend_n8.INVENTORY.md,
              prototypes/screen_upgrades.HANDOFF-PLAN.md, s19_app/tui/app.py, tests/test_tui_snapshot.py
```

**The census, both ways** (both figures derived from the same two runs by parsing every V13
line, not by eyeballing one row):

```
LIVE : stray PAIRS = 40  file-set UNION = 15
M4   : stray PAIRS = 41  file-set UNION = 15
delta pairs = 1  |  delta file-union = 0
new pair(s)         : [('screen_workspace/memstrip_band', 's19_app/tui/app.py')]
new file(s) in union: []
```

**Verdict: KILLED — and this transcript IS batch-85 defect #1's demonstration.** The rule is
sensitive at pair granularity (**40 → 41**, matching G4's stated `4 + 36` corpus set) and
**completely blind at file granularity** (15 → 15). Had G4 been stated over a file-set union —
the shape batch-85 used — deleting a real declaration would have produced **no signal at all**.
This is why `01-requirements.md` §3 forbids stating any V13 figure as a finding count or a
file-set union. The `01b` §2 disposition ("no selftest arm asserts pair-vs-file over a real
corpus") is now discharged with a real corpus behind it.

*Copy discarded.*

---

#### M5 — remove one INPUT name from the `screen_workspace` COMPONENT

This is the **decided-deviation discharge** recorded in `01-requirements.md` §3 against review
finding **QA-F3**: M-9's arms proved rule sensitivity by feeding **pre-parsed dicts** to
`_v12_outcome`, bypassing the parse path. This arm runs the same mutation through the **full**
path — a real file on disk, the real header parser, the real containment rule, one real
validator process.

**Mutation (on copy):** the COMPONENT's `INPUTS` line drops its **first** declared name (the
one the pilot consumes), leaving the other four types intact and the line structurally valid:

```
live    :   INPUTS : loaded: Optional[LoadedFile] ; project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str
mutated :   INPUTS : project: str ; workarea_files: list[Path] ; search_query: str ; goto_addr: str
```

**Targeted V12 lines — live vs copy:**

```
live    : [!] V12 …/batch-86/01-requirements.md:386: COMPONENT screen_workspace: parent `workspace_body`
              is not declared in this document, so balancing was NOT checked; this is not a pass
          (no [x] V12 row anywhere; tail 0 block)

mutated : [x] V12 …/batch-85/01-requirements.md:334: COMPONENT loaded_panel: consumes loaded,
              which `screen_workspace` does not declare — unbalanced
          [!] V12 …/batch-86/01-requirements.md:386: COMPONENT screen_workspace: parent `workspace_body`
              is not declared in this document, so balancing was NOT checked; this is not a pass
```

**Verdict: KILLED, through the full parse path.** `[x]` is BLOCK. The BLOCK names
`loaded_panel`, quotes the dropped name, names `screen_workspace` as the failing parent, and
lands at the pilot's own `:334` — the exact line whose "NOT checked" notice this batch exists
to retire. Two things are proved at once, and only a real parse can prove the second:
(i) the containment rule is sensitive to a one-name deletion; (ii) the record's blocks **do
actually parse**, since a rule that never reached the header could not report the header's
contents. The residual `screen_workspace / workspace_body` NOTICE is the declared-honest
D-86-B cost and is expected in both runs.

*Copy discarded.*

---

#### M7 — delete the canon line mirroring one batch-86 LLR id

Two arms. The first is the mutation as specified; it **refuted its own prediction**, so a
second arm was run to isolate the effect. Both are reported.

**M7a — whole-line deletion (as specified).** The canon's R-TUI-114 mirror section has exactly
one line mentioning `LLR-86.3` (`REQUIREMENTS.md:6079`); that whole line is deleted.

```
live line (CRLF file) :   `LLR-86.3` left-pane content outputs likewise · `LLR-86.4` center hex-pane outputs
mutated               :   (line deleted)

per-id greps on the copy:  LLR-86.3 → 0    LLR-86.4 → 0    LLR-86.2 → 1
V22 (copy)  : [!] V22 REQUIREMENTS.md: 278 of 531 batch-declared ids are not reflected … (HLR 75 · LLR 195 · US 8)
V22 (live)  : [!] V22 REQUIREMENTS.md: 276 of 531 batch-declared ids are not reflected … (HLR 75 · LLR 193 · US 8)
```

**Verdict: KILLED — and the stated prediction was wrong by one.** The per-id grep goes to 0 as
predicted, but the aggregate moves **276 → 278 (+2)**, not the predicted +1, because the mirror
line **packs two ids on one line**. The prediction silently assumed one id per line. The LLR
sub-count moving 193 → 195 confirms both ids were lost, so this is a property of the canon's
formatting, not of the rule. **This is exactly the class of error a kill mutation exists to
find, and it is recorded here rather than repaired in place.**

**M7b — surgical single-id deletion (the repaired arm).** Same copy, canon file restored from
live first; then only the `LLR-86.3` clause is removed and the `LLR-86.4` clause kept verbatim
— no token is corrupted, nothing renamed:

```
live    :   `LLR-86.3` left-pane content outputs likewise · `LLR-86.4` center hex-pane outputs
mutated :   `LLR-86.4` center hex-pane outputs

per-id greps on the copy:  LLR-86.3 → 0    LLR-86.4 → 1   ← the inert arm, named
V22 (copy) : [!] V22 REQUIREMENTS.md: 277 of 531 batch-declared ids are not reflected … (HLR 75 · LLR 194 · US 8)
```

**Verdict: KILLED, at the predicted magnitude.** Per-id grep → 0; aggregate **276 → 277
exactly (+1)**; LLR sub-count 193 → 194. The neighbouring id stays at 1 under the mutation, as
it must — the **inert arm is named** per the C-40 rider, so the RED is attributable to the one
id and not to having disturbed the line.

Together the two arms establish what the G6 gate needs: the per-id grep is the **primary**
predicate (it is exact and attributable), and the V22 aggregate is **secondary and
informational** (its magnitude depends on canon line packing, which no requirement governs).
That ordering was already the `01b` §1 AC-c decision; M7 is now its executed justification
rather than its assertion.

*Copy discarded. Live canon re-verified: both ids grep 1.*

---

### Layer 0 — unit

**n/a — no population.** The increment authored **0 source files** (`increment-001.md` §2:
"0 / 4 SOURCE files"), so no unit meets either criterion (cyclomatic complexity ≥ 3, or
transforming data across an `ARCHITECTURE.md` boundary). Stating "n/a" here is the honest
form; a table of invented rows would be worse than an empty one. The mutation discipline the
layer exists to enforce is **not** skipped — it is relocated to the record itself and
discharged by M4/M5/M7 above, which redden the real rules over the real corpus.

### UX walkthrough — trigger family D

**Did not fire.** No change alters anything a TUI user sees or touches: the source-scope diff
over `s19_app/ tests/ tools/ pyproject.toml` is empty (below), and the two files this batch
writes are a `.dev-flow/` record and a canon markdown section. **Mechanism used: none — and
no inspection is claimed either**, because there is no interaction to inspect.
**Evaluation with real users was NOT performed** (ISO 9241-210), and nothing here implies it
was needed.

### Layer A — functional (white-box): per-requirement results

Method is `inspection (executed)` for every row: the validator is operator-local and outside
the repository, so a `test` label would be C-18. `TC-B86-01`…`08` are the record's inspection
cases; each row names the executed verification that discharges it.

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-86.1 | inspection (executed) | live `devflow-validate .` (this phase, final run) | V10 = 20 · V11 = 35 · V14 = 106 · V19 = 2 · V21 = 35 · V13 = 36 pairs + 1 no-literal notice | **pass** | final-run block below; all six counted MESSAGES match §5.6's re-measured post-fix figures verbatim |
| HLR-86.2 | inspection (executed) | same run, V12 filter | exactly 1 V12 finding, naming `screen_workspace`/`workspace_body`; the pilot's `:334` "NOT checked" notice ABSENT | **pass** | live V12 shows one `[!]` row at `…batch-86/…:386`; nothing at `…batch-85/…:334`. **Sensitivity proved by M5**, which makes `:334` speak again as a BLOCK |
| HLR-86.3 | analysis | §5.6 per-surface cost table + dispersion paragraph | 6/6 figures non-null · 1 unmeasured-surface caveat · 0 totals/means | **pass** | §5.6 rows 1–6 all carry a value or an explicit declared-absence disposition (row 5 "not surveyed", row 6 "captured at close") — neither zero-filled; dispersion stated as a range (5 → 30 outputs, 15 → 91 consumer entries, "factor of about 6") with the no-multiplication caveat intact |
| LLR-86.1 | inspection (executed) | V10 line | 20 FLOW nodes, **every one owned** | **pass** | `[-] V10 … 20 FLOW node(s), every one owned` |
| LLR-86.2 | inspection (executed) | V11 + V21 lines | 35 OUTPUTs each with address + consumer list; 35 owners, every one declared | **pass** | `[-] V11 … 35 OUTPUT(s), each with an address and a declared consumer list` · `[-] V21 … 35 OUTPUT owner(s), every one declared` |
| LLR-86.3 | inspection (executed) | V13 per-output rows for the left-pane outputs | the enumerated §5.6 pair rows, unchanged | **pass** | live V13 rows for `left_pane` (3), `files_list` (2), `sections_list` (2), `load_project_button` (1) match §5.6 row-for-row |
| LLR-86.4 | inspection (executed) | V13 per-output rows for the centre-pane outputs | §5.6's 10-pair figure for this LLR | **pass** | live rows `hex_controls` 1 · `search_input` 1 · `search_button` 1 · `goto_input` 1 · `goto_button` 1 · `hex_scroll` 3 · `hex_view` 2 = 10; `hex_title` absent from V13 = its 0 |
| LLR-86.5 | inspection (executed) | V13 rows for the right-pane outputs | `ws_stats` 2 pairs; no phantom `_title` pollution (P-6) | **pass** | live `ws_stats` row lists exactly `REQUIREMENTS.md, tests/test_tui_snapshot.py` |
| LLR-86.6 | inspection (executed) | V13 re-export rows + V12 GREEN direction | the pilot's 5 ids re-exported; 3 of them re-report at this record's lines | **pass** | live rows `panel_handle` 2 · `slots_container` 1 · `artifact_slots` 1 at the batch-86 lines, alongside the pilot's own at the batch-85 lines — the "addition of disjoint per-line sets" G4 demands, not a union |
| LLR-86.7 | inspection (executed) | V12 + the V22 unowned-LLR notice | INPUTS list + `PARENT : workspace_body` present; appears in the **expected** unowned-LLR notice | **pass** | header read at the record's COMPONENT block; `[!] V22 …batch-86…: LLR(s) never used as an owner — LLR-86.7, LLR-86.8` = **exactly** the pair §3 pre-enumerated (R2-06). Threshold is 0 **unexpected**, and 0 unexpected is what ran. **M5 is this row's RED arm** |
| LLR-86.8 | analysis | §5.6 cost table, dispersion form | no mean, no total, n = 2 stated | **pass** | same evidence as HLR-86.3; the unowned-LLR notice above is expected for this id too |

**Note on LLR-86.7/86.8's notice:** it is a NOTICE by design — an LLR may constrain without
transforming. It is counted here as *expected and enumerated in advance*, which is the only
form in which a standing notice may be called green.

### Layer B — behavioral (black-box) acceptance

The "user" is the operator auditing addressability. The shipped surface is the real
`devflow-validate` toolchain run over the merged corpus — the **real consumer executed against
the handler-produced record**, never a hand-fed copy (trigger B4).

| US | AT | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----|----------------|---------------------------------------|----------------------------|--------|
| US-86-1 | `AT-B86-01` | `python ~/.claude/docs/tools/devflow-validate.py .` at the worktree root | validator stdout: six counted MESSAGES (V10/V11/V13/V14/V19/V21) whose figures include this component — non-empty and matching §5.6 | ✓ · ✓ · ✓ | **pass** |
| US-86-1 | `AT-B86-02` | same run, V12 | stdout: exactly one V12 finding, and it names this record's own undeclared parent — the pilot's `:334` line silent | ✓ · ✓ · ✓ | **pass** |
| US-86-1 | `AT-B86-03` | `--atlas --write` (increment gate) then a plain run | **`.dev-flow/_derived/ATLAS-IFC.md` on disk**: `### COMPONENT \`screen_workspace\`` at line 50 with **30 declaration rows** (one per OUTPUT, no `{id: component}` collapse); V20 `atlas current (4 files, census 2)` | ✓ · ✓ · n/a | **pass** |
| US-86-1 | `AT-B86-04` | `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` + the orchestrator's suite run | empty diff (0 files / 0 insertions / 0 deletions), exit 0 | ✓ · ✓ · n/a | **diff half pass · ledger half FOLDED at the gate (2702/6/3/3 of 2714, dispositioned)** |

**Arm provenance — where each boundary/negative arm was actually executed** (this is the
column that stops an AT from being a claim):

| AT | representative | boundary | negative / error |
|---|---|---|---|
| `AT-B86-01` | live final run, six counted messages | **M4 (this phase, copy):** a consumer entry deleted → V14 105, V13 pair +1 | selftest arm `V14 BLOCK-nofile` (`devflow-validate.py:2667`, 189 arms exit 0) for the absent-file error mode — re-cited per QA-F4; the earlier "carried pilot transcript" does not exist |
| `AT-B86-02` | live V12, single finding | **M5 (this phase, copy):** one INPUT name dropped → `[x]` BLOCK naming `loaded_panel` at `:334`, through the full parse path | same M5 transcript — V12 has no file-resolution error mode; it is a set-containment rule, and saying so beats inventing an arm |
| `AT-B86-03` | live V20 `atlas current`, 30 Atlas rows | V20's own census comparison against the committed Atlas (`census 2`) | the **observed** RED: the increment's first post-edit run read `2 block`, both V20 staleness, cleared by `--atlas --write` (`increment-001.md` §4 Gate 2) — a free RED, recorded rather than manufactured |
| `AT-B86-04` | empty diff, executed above | the scope names four source paths explicitly | n/a — a one-command structural check with no input space beyond the diff scope |
| G6 (canon) | increment gate: 12/12 ids grep ≥ 1 | **M7b (this phase, copy):** one id removed → that id 0, neighbour still 1, V22 +1 | **M7a (this phase, copy):** whole line removed → both its ids 0, V22 +2 — the over-shoot that corrected the prediction |

### Bidirectional surface-reachability matrix

Every named INPUT dimension and every named OUTPUT/deliverable, exercised or observed through
the real surface — a validator process reading files off disk — not through an in-memory API.
(This is precisely the gap QA-F3 named in M-9's arms, and M5 closes it.)

| Direction | US dimension / deliverable | Producer / consumer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|---------------------|------------------------------|---------|--------|
| input | COMPONENT header fields (`PARENT`, `SURFACE`, `INPUTS`) | the record's IFC block, parsed by the validator's header parser | **yes** — V12 quotes `workspace_body` back, and M5 proves the `INPUTS` list is read name-by-name | `AT-B86-02` | ✓ |
| input | OUTPUT declarations (id + address literal) | same block; V11/V19/V13 | **yes** — V11 counts 35 and V13 greps each address literal across the corpus | `AT-B86-01` | ✓ |
| input | consumer entries | same block; V14 resolution + V13 stray classification | **yes** — V14 resolves 106; M4 shows a single deleted entry changes both V14 and V13 | `AT-B86-01` | ✓ |
| input | owner ids on each OUTPUT | same block; V21 + V22's unowned-LLR check | **yes** — V21 counts 35 owners "every one declared"; V22 names the two intentionally unowned LLRs | `AT-B86-01` | ✓ |
| input | canon mirror id lines | `REQUIREMENTS.md` R-TUI-114 section, read by V22 and by the G6 grep loop | **yes** — 12/12 per-id greps at the increment gate; M7a/M7b prove the read is per-id sensitive | G6 · `AT-B86-04` | ✓ |
| output | counted validator verdicts | `devflow-validate` stdout | **yes** — pasted from one complete run below | `AT-B86-01` | ✓ |
| output | the balancing verdict for the pilot | V12 | **yes** — observed as a specific single finding, with M5 as its counterfactual | `AT-B86-02` | ✓ |
| output | the derived Atlas | **`.dev-flow/_derived/ATLAS-IFC.md` on disk** — 30 rows under the component heading at `:50` | **yes** — read off disk, not inferred from V20 | `AT-B86-03` | ✓ |
| output | the living-canon reflection | `REQUIREMENTS.md` R-TUI-114 section + V22 aggregate | **yes** — greps on the file, V22 at 276 of 531 | G6 | ✓ |
| output | source-scope neutrality | `git diff --stat` over the four declared paths | **yes** — empty output, exit 0 | `AT-B86-04` | ✓ |

**0 gaps.** Note every output row observes a **thing** (a stdout line, a file's content), never
only "the command exited 0" — an exit code is not a deliverable.

### Supersession-completeness inspection

| Superseded marker | grep result | All surviving refs negative? | Evidence |
|-------------------|-------------|------------------------------|----------|
| the pilot's V12 "parent `screen_workspace` is not declared … NOT checked" NOTICE at `…batch-85/01-requirements.md:334` | 0 occurrences in the live validator output (it was present in the M-8 pre-state) | **yes** — the only surviving references are the batch's own **absence assertions** (`01-requirements.md` §5.6 pre-state, `AT-B86-02`, and this row). No artifact depends on the notice still firing | live V12 filter shows a single `[!]` row, at `…batch-86/…:386`. **Positive control:** that surviving row proves V12 still emits NOT-checked notices where they apply, so the absence is a real retirement and not a silenced rule. **Second control:** M5 makes `:334` speak again — as a BLOCK — which is what a live dependency would have looked like |

The `01-requirements.md` §3 reasoning is confirmed rather than repeated: V12's affirmative
summary is suppressed when another notice fires, so "CHECKED" is provable **only** by this
absence, and an absence claim needs exactly the two controls above.

### Signed-balance test ledger

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| 2714 selected (2735 − 21 deselected) | 0 | 0 | 2714 | 2714 | **2702 passed · 6 failed · 3 skipped · 3 xfailed** (one complete run, 39:49, its own output at the orchestrator's `batch86_baseline.txt`) | **✓ with the 6 dispositioned below** |

**FOLDED AT THE GATE by the orchestrator (C-25/C-19 — one complete `s19env` run, evidence
read from that run's own output file).** The 6 failures were DIAGNOSED before acceptance,
by execution on pristine `main` (`a112eeb`, same env): **every one of the 6 passes in
isolation on main** (`at057b` 1.82 s · `at023c` 1.55 s · the remaining 4 in the 6-test
group run, `1 failed 5 passed in 16.28 s` — and that one, `at023c`, then passed alone,
so even a 6-test group exhibits the cross-test pollution). Verdict: **order/state-dependent
suite flakiness, pre-existing, reproduced entirely OUTSIDE this batch's changes** — the
batch's source-scope diff is empty and `tests/` is byte-identical to merge-base. The 6
node ids and both repro transcripts are carried to `BACKLOG-CODE.md` at close (test-hygiene
carry: order-dependent TUI pilots — `test_at_061a…`, `test_at006…`, `test_at005…`,
`test_at023c…`, `test_at057b…`, `test_at064b…`). The pin's subject — "this batch changed
no behavior" — is discharged by the empty diff; the flaky 6 are a property of the base,
recorded and carried, never swept.

Per C-25 the orchestrator owns the suite run and it is in flight; this phase deliberately did
**not** run `pytest`. What *is* established here, executed:

- `D = 0` and `A = 0` — the increment added and deleted **zero** test nodes
  (`increment-001.md` §2: "Test files 0 (uncapped) — tests untouched").
- The `tests/` tree is byte-identical to merge-base, proved by the source-scope pin below —
  so `post = base` is guaranteed *structurally*, whatever number `base` turns out to be.

**RETRACTED at the fold (final PR pass MEDIUM):** the paragraph below described the pre-fold
state; the ledger row above now carries the folded figures and disposition. Original text,
kept for the record: QA-F6 stood while the ledger half of the
G7 pin is checkable only once the baseline figure lands in `PLAN.md` (currently: "Base: pending
the in-flight s19env baseline run (2714 selected)"). The orchestrator completes this row.

### Gate criterion set G-86 — status at Phase 4

| Gate | Status now | Pointer (executed) |
|---|---|---|
| **G1** (headline) | **GREEN** | live V12: one `[!]` row, at this record's `:386`, naming `workspace_body`; the pilot's `:334` silent. Counterfactual: **M5** |
| **G2** | **GREEN** | `[-] V19 … 2 COMPONENT id(s), each declared exactly once` (was 1) |
| **G3** | **GREEN** | `[-] V10 … 20` · `[-] V11 … 35` · `[-] V14 … 106` · `[-] V21 … 35`; final line `0 block`; **0** BLOCK located under `.dev-flow/2026-08-24-batch-86/` or `.dev-flow/_derived/` (the tail is `0 block` outright, so the attribution clause is satisfied trivially and honestly) |
| **G4** | **GREEN** | V13 corpus census parsed from the live run: **40 pairs** = the pilot's 4 at their `…batch-85/…` lines **plus** this record's 36 at its `…batch-86/…` lines (stated as an addition of disjoint per-line sets, per R2-08), plus the 1 no-literal notice for the type-addressed output. Counterfactual: **M4**, which also demonstrates why the file-set form (15, unmoved) would have been vacuous |
| **G5** | **GREEN** | `grep -c "screen_workspace" .dev-flow/_derived/ATLAS-IFC.md` → **25** (pre-state 0) and the component renders **30 declaration rows** under its own heading at `:50`; `[-] V20 … atlas current (4 files, census 2)` |
| **G6** | **GREEN at the increment gate** (QA-F2 discharged: P3 carried a live gate attributable to its own deliverable) — **CLOSE re-measurement still owed** | `increment-001.md` §4 Gate 1: the loop's twelve ids (the story id plus the batch's eleven HLR/LLR heading ids) each grep ≥ 1, 12/12. Secondary: V22 **276** of 531 ≤ the 277 batch-open baseline — the P-8 transient has already shrunk back **below** baseline, one id further than owed. Counterfactuals: **M7a/M7b**. CLOSE must re-measure, because V22 moves whenever any batch adds ids |
| **G7** (PIN) | **diff half GREEN · ledger half FOLDED (reconciles, 6 pre-existing flaky dispositioned)** | `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` → empty output, exit 0 (the VERBATIM §2.6(d) command, R2-02's correction applied: merge-base, and `pyproject.toml` in scope). Ledger: see the row above |

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G4-01 | `AT-B86-04` / G7 | The suite-ledger half of the pin had no baseline at authoring; FOLDED at the gate (retraction record) | minor (declared, then closed) | Orchestrator folds the `s19env` figure into the ledger row at the gate. `D = 0`/`A = 0` and the byte-identical `tests/` tree are already proved, so only the number is missing |
| G4-02 | G6 / P-8 | V22's aggregate is a **corpus-wide** figure: it moves when *any* batch declares ids, so today's 276 is not by itself proof that this batch's tranche is seeded | minor | Already mitigated by design — the per-id grep loop is the primary predicate and the aggregate is explicitly secondary. **M7a is the executed reason** for that ordering. CLOSE re-measures both |
| G4-03 | canon formatting | The canon mirror packs two ids per line in at least one place, so V22 deltas are not 1-per-id | minor (finding, not a defect in this batch) | Recorded for the postmortem: any future prediction of a V22 delta must count **ids**, not lines. No repair proposed — the packing is compact and harmless once the primary predicate is per-id |

### Escaped-bug regression

**None — no defect escaped the suite.** Nothing to record: this batch ships no product code, so
there is no shipped-surface regression to write and no QC-2 counterfactual to owe. The nearest
analogue is review blocker **B86-R2-01** (the app.py-only bare-name sweep), which was caught
**at Phase 2, before the record shipped**, and is guarded going forward by M-10's declared
search width — cited in §5.6 and re-verified in the Layer A `LLR-86.4` row above.

### Final live validator run (Phase 4, at the end of this artifact's authoring)

Fixpoint procedure per the increment's F1/F2 lesson (`.dev-flow/**` is corpus input, so this
artifact perturbs the corpus it measures): write → run → regenerate the Atlas if V20 blocks →
re-run → confirm the tail is stable **with this file present at its shipped content**. Ids are
described rather than enumerated wherever describing suffices ("the batch's eleven heading
ids"), so this file adds no id the Atlas could adopt.

**Observed, and it fired:** the first run with this file present read
`1 block · 254 notice · 14 not applicable` — one `[x] V20` on `ATLAS-BATCHES.md`, the batch
**file inventory**, because this artifact is a new file in the batch directory. `--atlas
--write` cleared it and the re-run reached the fixpoint below. Every counted figure (V10 20 ·
V11 35 · V14 106 · V19 2 · V21 35 · V22 276 of 531 · UNPARSED census 2) is **identical either
side of the regeneration**, which is the evidence that this artifact perturbed only the file
inventory and not the id-space — the describe-don't-enumerate discipline held. The two
`_derived/` files the regeneration rewrote are uncommitted by design: this phase does not
commit.

```
  [-] V20  .dev-flow/_derived/: atlas current (4 files, census 2)
0 block · 254 notice · 15 not applicable
```

Full V10–V22 block from that same run:

```
  [-] V10  01-requirements.md: 20 FLOW node(s), every one owned
  [-] V11  01-requirements.md: 35 OUTPUT(s), each with an address and a declared consumer list
  [!] V12  .dev-flow/2026-08-24-batch-86/01-requirements.md:386: COMPONENT screen_workspace: parent
           `workspace_body` is not declared in this document, so balancing was NOT checked; this is not a pass
  [-] V14  01-requirements.md: 106 declared consumer(s), every one resolved
  [-] V19  01-requirements.md: 2 COMPONENT id(s), each declared exactly once
  [-] V20  .dev-flow/_derived/: atlas current (4 files, census 2)
  [-] V21  01-requirements.md: 35 OUTPUT owner(s), every one declared
  [!] V22  …/batch-85/01-requirements.md: LLR(s) never used as an owner — LLR-85.4
  [!] V22  …/batch-86/01-requirements.md: LLR(s) never used as an owner — LLR-86.7, LLR-86.8
  [!] V22  REQUIREMENTS.md: 276 of 531 batch-declared ids are not reflected in the living canon
           (HLR 75 · LLR 193 · US 8; e.g. HLR-007a, LLR-001.6, US-B63-1)
```

V13's 36 + 4 pair rows are not re-pasted here — they are enumerated row-for-row in
`01-requirements.md` §5.6 and were re-verified against this run by parsing every V13 line
(the 40/15 census in the M4 transcript is that parse).

### Evidence checklist — qa-reviewer (full)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✓ | `01-requirements.md` §3 uses the batch's fixed **Observable outcome / Shipped surface / Deliverable + observation / Boundary catalog** form — the project's Given/When/Then equivalent, and the one its gate table indexes. Conforming to the codebase's convention over the template's wording (global rule 11); flagged here rather than forked silently |
| 2 | Test cases have explicit Expected, not vague "works" | ✓ | Every Layer A row carries a numeric threshold (20 · 35 · 106 · 2 · 35 · 36+1) and every mutation states its expected line before its transcript |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | empty = the M-8 pre-state (`5 OUTPUT(s)`, before this record existed) · boundary = **M4/M5** executed this phase · invalid = **M7a/M7b** · error = selftest `V14 BLOCK-nofile` (`devflow-validate.py:2667`) |
| 4 | Regression checklist exists | ✓ | the "Supersession-completeness inspection" table (the retired pilot notice, with two positive controls) + G-86's seven rows re-executed at this gate |
| 5 | Exit criteria stated | ✓ | the Verdict block: all four ATs observed with arm provenance, 0 blocker fails, 0 reachability gaps, ledger folded at the gate |
| 6 | No real PII / secrets | ✓ | artifact contains only repo-relative paths, validator output and git metadata; no credentials, no personal data, and no fixture invented that could carry any |
| 7 | Results left blank unless actually run | ✓ | the pytest suite was run ONCE by the orchestrator (C-25) and folded with its own output; at this artifact's authoring the row was `PENDING`, never blank-asserted |
| 8 | **Layer B (black-box)** — every output-producing story's deliverable observed through the SHIPPED surface, with boundary + negative evidence | ✓ | Layer B table + the arm-provenance table: `AT-B86-03` observes `ATLAS-IFC.md` **on disk** (30 rows at `:50`), not merely V20's word for it; boundary/negative arms are M4/M5/M7 executed this phase on copies |
| 9 | **Bidirectional surface-reachability** — every named input AND every named output reached through the handler | ✓ | the 10-row matrix, 0 gaps; the input rows are validated by mutation (M4/M5/M7 each redden a different input dimension), which is what distinguishes "reached" from "present" |
| 10 | **No unfilled template** | ✓ | 0 `<...>` placeholders, 0 `TC-NNN` stubs, 0 empty required rows. The rows that are `n/a` (Layer 0, UX walkthrough, escaped-bug) say **why** the population is empty; the one `PENDING` row says **who** completes it |
| 11 | Kill mutations owed at Phase 4 executed on copies, live tree never mutated | ✓ | three transcripts above, each with its `COPY=` path, its live-vs-copy diff line, and its discard; `git status --porcelain` on the live tree → empty after all three |

**An item without a citation is not satisfied — it is asserted.**
