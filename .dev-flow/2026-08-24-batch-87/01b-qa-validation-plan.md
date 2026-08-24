# QA validation-methods plan — batch-87 Phase 1 (qa-reviewer deliverable, 2026-08-24)

> ## ⚠️ SUPERSESSION NOTE — added at the P2 iteration (R2-02), 2026-08-24
>
> **This file is the SOURCE for batch-87's acceptance layer; `01-requirements.md` is where its rows
> are REALIZED. Where the two disagree on an id, the record's reconciliation table governs.**
>
> The two Phase-1 artifacts forked the `AT-B87-*` id space: this plan defines `AT-B87-01` through
> `AT-B87-06` plus two named pins, while the record's first fold defined only `AT-B87-01` through
> `AT-B87-04` — and **the same id does not mean the same acceptance in both files.** Specifically:
> this plan's `AT-B87-03` (counted messages) and `AT-B87-04` (the V13 pair set) are realized in the
> record as **gates G5 and G6**, and the record REUSES those two id numbers for different
> acceptances; this plan's `AT-B87-05` and `AT-B87-06` are realized as the record's `AT-B87-03` and
> `AT-B87-04`; and `P-src` / `P-ledger` become the record's `AT-B87-05` / `AT-B87-06` pins.
>
> **Read the mapping table in `01-requirements.md` §3 ("Reconciliation with 01b") before citing any
> `AT-B87-*` id from this file.** Every row of §2 and §6 here is realized somewhere in the record;
> none was retired. Two of this file's own measurements were also refuted on re-execution and are
> corrected in the record rather than here — see the inline markers at §2's `AT-B87-06` row and §6's
> G6, both of which rest on a pre-state grep that measures **2**, not 0.
>
> This file is otherwise **unmodified** — it is the record of what the qa lens returned, and it is
> not rewritten to agree with what was later measured.

> Returned by the Phase-1 `qa-reviewer` dispatch; persisted verbatim by the orchestrator.
> To be FOLDED into `01-requirements.md` §3/§4 at the Phase-1 fold, together with the F1–F3
> corrections to §2.6. **Every threshold below is marked `DERIVE-AT-AUTHORING` and names WHICH
> probe prints the number (C-39). No figure in §1/§6 is to be copied from this file into the
> record — re-execute and paste the transcript.** The pre-state in §0 is a measurement at a
> moment, recorded so the deltas have a floor; it is not a threshold.

**Notation.** `W` = this worktree (`C:\Users\jjgh8\Github\s19_app`, branch
`claude/batch-87-ifc-reauthor-surface-3`) · `VAL = python ~/.claude/docs/tools/devflow-validate.py`
· `T` = a `mktemp -d` COPY of `W` with `.git` removed. Method label for every criterion is
**inspection (operator-local executed verification)**, never `test (integration)` — the validator
lives outside the repository, so a `test` label asserting a pytest node that cannot exist is C-18.
The one exception is §7, the suite gate, which is a real pytest run owned by the orchestrator.

---

## 0 · Pre-state, measured on `W` this session (re-derive; do not cite)

Executed: `VAL .` at the worktree root, `.dev-flow/_derived/` at flow_version
`2026.08.24-rev45`, flow_hash `09bea075fc183f8b`, corpus digest `525c7a6d8e24682e`.

| Probe | Value as measured | Note |
|---|---|---|
| tail | `0 block · 254 notice · 15 not applicable` | the attribution floor |
| V10 | `20 FLOW node(s), every one owned` | |
| V11 | `35 OUTPUT(s), each with an address and a declared consumer list` | 5 pilot + 30 batch-86 |
| V12 | **exactly 1 finding** — `…batch-86/01-requirements.md:386`, `screen_workspace`: parent `workspace_body` not declared, balancing NOT checked | US-87-2's target |
| V13 | **22 per-output NOTICE rows = 40 (output_id, file) PAIRS** (pilot 3 rows / 4 pairs; batch-86 19 rows / 36 pairs) **+ 1 no-literal notice** naming `screen_workspace/empty_state` | census stated over PAIRS, never over a file-set union (batch-86 M4) |
| V14 | `106 declared consumer(s), every one resolved` | |
| V18 | active batch `2026-08-24-batch-87` declared and on disk | V1–V9 judge this batch's copies |
| V19 | `2 COMPONENT id(s), each declared exactly once` | US-87-1 option (b) would move this |
| V20 | `atlas current (4 files, census 2)` | |
| V21 | `35 OUTPUT owner(s), every one declared` | |
| V22 | unowned-LLR: `LLR-85.4` · `LLR-86.7, LLR-86.8`; canon: `278 of 533` (HLR 75 · LLR 193 · US 10), **sample names `US-87-1`** | the batch's two US ids are already in the corpus and unmirrored |
| V23 | no PDR/DDR citations anywhere | a fact, not a pass |
| UNPARSED census (`ATLAS-ORPHANS.md`) | **2 items** — `[BATCHES] .dev-flow/2026-07-23-batch-n8` (dir-name; the **negative control**, must SURVIVE) and `[IFC] .dev-flow/2026-08-21-batch-85/01-requirements.md:372` (field `owner` absorbed 801 chars) | US-87-1's target is the second only |
| `--selftest` | `SELFTEST PASSED`, exit 0 | arm count printed by the run — re-derive it, this plan does not cite one |

---

## 1 · Three findings on §2.6's framing (P2 candidates if unaddressed)

These are not stylistic. Each names a §2.6 clause that is **not satisfiable as written**, or that
is satisfiable only by work §2.6 does not put in scope. All three were found by reading the
shipped validator's own code and by executing it — not by inference.

### F1 — `D-87-A` is not an open question; the stated observable already decides it (C-10)

§2.6 offers `D-87-A` as "(a) corrected in place in batch-85 vs (b) declared fresh in batch-87",
to be decided by an executed probe on `_ifc_corpus`'s merge semantics. But the story's own
observable outcome is *"the `[IFC]` UNPARSED entry at `2026-08-21-batch-85/01-requirements.md:372`
is GONE"*. That entry is emitted by `_atlas_scalar` while rendering **the batch-85 file's own
block**, keyed to that file's path and line. `_ifc_corpus` **merges by extension into a list** —
no declaration ever removes another — so authoring a fresh block in batch-87 leaves the batch-85
block parsed, rendered, and still absorbing. **Option (b) cannot clear the entry. Only editing
`.dev-flow/2026-08-21-batch-85/01-requirements.md` can.**

The genuinely open sub-question that survives is narrower and should replace `D-87-A`: *does the
corrected contract body live in the batch-85 file (in-place), or is the batch-85 block reduced to a
pointer while the body lives in batch-87?* Both edit batch-85; they differ in what is left behind.
**Probe owed (P1, executed):** on a copy, apply each shape and read V19 (`2` vs a duplicate NOTICE
naming both `file:line`) and the census (`2` vs `1`). Decide from that transcript.

*Mechanism, so the fix is authorable rather than guessed:* `_parse_ifc` has **no block
terminator** and no dedent rule for continuation lines — `if last_key and indent:` appends **any**
indented, non-field, non-anchor line to the block's last key, until the next `FLOW:`/`COMPONENT:`
anchor or EOF. batch-85's block is followed by a fenced §5.5 transcript whose lines are indented,
so they glue onto the last `owner`. The re-authored record must therefore satisfy a positive
authoring constraint, and §3 must state it as one: **no indented line may follow the block's last
field before the next anchor or EOF.**

### F2 — The pilot's six-output split forces an edit to the batch-86 record that §2.6 does not scope (C-10)

V12 checks `child_out ⊆ parent_out` whenever **both** sets are non-empty
(`_v12_outcome`). batch-86's `screen_workspace` re-exports the pilot's five ids **verbatim**,
including `slot_rows`, with its own note that *"the six-output split is D-II territory, inherited
with citation, not fixed here"*. The moment the pilot declares `artifact_row_set` and
`unload_all_row` in place of `slot_rows`, those two ids are in `child_out` and absent from
`parent_out` → **a V12 BLOCK naming `loaded_panel`**, produced by this batch's own work.

So the batch's real file set is **three** records, not two: batch-87's, batch-85's, and
batch-86's. §2.6's "0 new BLOCKs" is unachievable without the third. This must be declared as
scope at the fold, not discovered at the P3 gate. **Threshold:** `DERIVE-AT-AUTHORING` — after the
batch-86 re-export is updated, `VAL` prints **zero** V12 rows whose message contains
`loaded_panel`; the probe is `VAL "$W" | grep "V12"`.

### F3 — `workspace_body`'s parent is measured, and it is not `SYSTEM` (C-31)

§2.6 says *"`workspace_body`'s own PARENT question is answered honestly (SYSTEM if it is truly the
root — to be MEASURED at P1)"*. **It was measured this session and the hypothesis is refuted:**
`s19_app/tui/app.py:1917` mounts `id="workspace_body"` as a child of the `Horizontal` at
`app.py:1919` carrying `id="workspace_shell"`, which is itself a top-level `compose()` yield.
`PARENT : SYSTEM` would be the pilot's rejected D-B lie one level up. The honest declaration is
`PARENT : workspace_shell`, and its cost is **one new standing V12 NOTICE** naming
`workspace_body`/`workspace_shell` — the staged-retrofit pattern, expected and enumerated in
advance. Any criterion phrased as "0 V12 findings" is therefore either unsatisfiable or an
incentive to write the lie; §3 must phrase it as **"0 V12 findings naming
`screen_workspace`/`workspace_body`, and exactly one expected residual naming
`workspace_body`/`workspace_shell`."**

**F3's rider — the bimodal output problem, owed as `D-87-B`.** Because the containment check is
gated on `if child_out and parent_out`, `workspace_body` has exactly two legal shapes: declare
**zero** OUTPUTs (the check is skipped; but a container composing ten screen roots that emits
nothing is a false contract), or declare a superset of **all** of `screen_workspace`'s 30 ids
(D-86-E duplication, tripled). There is no middle. `D-87-B` must be decided at P1 by executing
both shapes on a copy and reading the V12/V11/V21 lines, with the chosen cost written into the
record — not assumed.

---

## 2 · Black-box acceptance (C-12, trigger B4 fired)

**The consumer of the record is the shipped `devflow-validate.py` (V10–V23) plus the Atlas
scanner/builder it drives under `--atlas --write`.** The AT drives that real consumer over the
authored record as it sits on disk and asserts post-state findings. No AT reads a hand-fed dict,
and no AT observes only an exit code — every row observes a **thing**: a stdout line, or bytes in
a derived file.

> **Id note (honesty, not a blocker):** `AT-B86-01…04` are **absent from
> `AT-TC-REGISTRY.jsonl`** (measured: `grep -c "AT-B86" AT-TC-REGISTRY.jsonl` → `0`). The
> registry guard does not trip because these ATs have no pytest node to bind. `AT-B87-*` below
> follows the same precedent so the batches stay comparable, and the gap is **named here rather
> than silently repeated** — the orchestrator decides at the fold whether to register the batch-86
> and batch-87 blocks together.

### US-87-1 — re-authored pilot contract

| AT | Surface driven (shipped) | Deliverable observed | Threshold | Derivation |
|---|---|---|---|---|
| `AT-B87-01` | `VAL "$W"`, Atlas regenerated first | **`.dev-flow/_derived/ATLAS-ORPHANS.md` bytes on disk**: the `[IFC]` line for `…batch-85/01-requirements.md:372` is ABSENT; the `[BATCHES]` `2026-07-23-batch-n8` line is PRESENT | census `2 → 1`, and the surviving item is the BATCHES one | `DERIVE-AT-AUTHORING` — probe: `VAL "$W" --atlas --write` then read the file's `UNPARSED census:` line and its bullet list. **Never assert the count alone: assert the surviving bullet's text.** |
| `AT-B87-02` | same run, V12 filter | stdout: **zero** V12 rows whose message contains `loaded_panel` | 0 | `DERIVE-AT-AUTHORING` — probe: `VAL "$W" \| grep "V12"`. Discharges F2. |
| `AT-B87-03` | same run, V11 / V14 / V19 / V21 counted MESSAGES | stdout: the pilot contributes **6** OUTPUTs where it contributed 5; V19 still reports each COMPONENT id declared exactly once | V11 = pre + `+1` (the split is 1→2) · V14 = pre + `ΔC` · V21 = pre + `+1` · V19 message unchanged in FORM | `DERIVE-AT-AUTHORING` — probe: the same `VAL` run's V11/V14/V19/V21 lines. `ΔC` is whatever the authored consumer lists sum to; it is **counted from the record, not chosen**. |
| `AT-B87-04` | `VAL "$W"` V13 filter, parsed line-by-line | stdout: the enumerated post-state `(output_id, file)` PAIR set, written out in §3 row-for-row | the pilot's post-state pairs, ENUMERATED; a sum is printed alongside but is never the criterion | `DERIVE-AT-AUTHORING` — probe: parse **every** V13 line of one run into pairs (the batch-86 M4 method). Splitting one output into two redistributes its stray files; the new pair set is a measurement. |

### US-87-2 — `workspace_body` declared

| AT | Surface driven (shipped) | Deliverable observed | Threshold | Derivation |
|---|---|---|---|---|
| `AT-B87-05` | `VAL "$W"`, V12 filter | stdout: **zero** V12 rows naming `screen_workspace`/`workspace_body`; **exactly one** expected residual naming `workspace_body`/`workspace_shell`; **zero** V12 BLOCK rows | 0 / 1 / 0 — the residual is **enumerated in advance**, which is the only form in which a standing notice may be called green | `DERIVE-AT-AUTHORING` — probe: `VAL "$W" \| grep "V12"`. Depends on F3's ruling and on `D-87-B`. |
| `AT-B87-06` | `VAL "$W" --atlas --write` then a plain `VAL "$W"` | **`ATLAS-IFC.md` bytes on disk**: a `### COMPONENT \`workspace_body\`` heading with one declaration row per declared field/output, no `{id: component}` collapse; V20 line `atlas current (4 files, census N)` with `N ≤` the committed census | rows ≥ 1 for the new id (pre-state grep = 0, so the grep is its own RED arm); `N` from `AT-B87-01` | `DERIVE-AT-AUTHORING` — probes: `grep -c "workspace_body" .dev-flow/_derived/ATLAS-IFC.md` (pre-state **0**, measured) and the V20 line of the re-run. |

> ⚠️ **`AT-B87-06`'s pre-state is REFUTED (batch-87 R2-06), and the row above is left as written.**
> Re-measured on the committed pre-state file at the P2 iteration: `grep -c "workspace_body"
> .dev-flow/_derived/ATLAS-IFC.md` returns **2**, not 0 — batch-86's `- parent : workspace_body` row
> (`ATLAS-IFC.md:53`) and V12's own finding text (`:93`). A threshold of "rows ≥ 1 for the new id" over
> that grep is therefore GREEN before any work, and the "pre-state grep = 0, so the grep is its own RED
> arm" clause describes an arm that does not exist. The discriminating predicate — the `### COMPONENT`
> heading form, **0** pre / **1** post, with the `screen_workspace` heading returning 1 in BOTH states as
> the negative control — is measured in `01-requirements.md` §5.6 and realized as its `AT-B87-04` + G10.

### Cross-story pins (constrain; they do not gate)

- **P-src** — source neutrality: `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml` → **empty output, exit 0**. Verbatim command, merge-base form, `pyproject.toml` in scope (batch-86 R2-02's correction).
- **P-ledger** — §7. A pin, labelled one.

---

## 3 · Kill mutations (C-40)

**Protocol, executed verbatim.** `T=$(mktemp -d); cp -r "$W"/. "$T"; rm -rf "$T/.git"`, then
`VAL "$T"` asserting the **one targeted line**. One copy per mutation; each copy `rm -rf`'d at the
end of its arm. Restore is proven by construction — the live tree is never touched — and is
**verified after every arm** by `git status --porcelain` on `W` → empty, plus a re-read of the one
figure the arm moved. `~/.claude` is frozen for the duration (the validator is in every reader's
read-set); each transcript is stamped with the re-derived flow hash.

**C-56 compliance.** Every mutation below is described by **POSITION + OPERATION only**. No
mangled, renamed, or corrupted token is spelled anywhere in this plan or in the transcripts it
governs — this file is itself scanner corpus, and a phantom id written here would be adopted by the
Atlas id-scanner. Where an arm needs a "wrong" value, the operation is a **deletion** or an
**indent change**, never a substitution that invents a token.

| # | Mutation (on copy) — position + operation | Rule / expected flip | Verdict owed | Disposition |
|---|---|---|---|---|
| **K1** | In the re-authored pilot block, take the **first prose line following the block's LAST field** and increase its indentation to depth ≥ 1 | `_atlas_scalar` re-flags that field; **UNPARSED census RISES**, and `V20` BLOCKs with `census rose N -> N+1` | per-arm: census before/after **and** the V20 severity | **batch-local, MANDATORY.** This is the only proof the census entry was cleared by removing the *cause* rather than by the parser going quiet. The selftest's `BLOCK-census-rise` arm runs on a synthetic pair map, never over this record. |
| **K2** | Delete the **first declared name** from `workspace_body`'s `INPUTS` line, leaving the remaining names and the line's structure intact | `V12` **BLOCK** naming `screen_workspace` and quoting the deleted name as unbalanced against `workspace_body` | one verdict; name the **inert arm** (the sibling names still resolve) | **batch-local, MANDATORY.** Proves the new parent declaration is **BLOCK-capable**, not merely notice-silencing — the distinction §2.6's wording cannot make. Mirrors batch-86 M5 through the full parse path. |
| **K3** | Delete the **first consumer entry** of the re-authored pilot's `artifact_row_set` OUTPUT — choosing at authoring time an entry whose file is *proven by the same V13 grep* to contain that output's address literal | `V14` counted message −1; **`V13` stray PAIR count +1**, with the new pair named; the file-set **union** may or may not move — record which | per-arm: V14 delta, pair delta, union delta, the new pair | **batch-local, MANDATORY.** No selftest arm asserts pair-vs-file over a real corpus. If the union does not move, that transcript is batch-85 defect #1 reproduced on the *re-authored* record. |
| **K4** | Delete the whole `owner :` line of one re-authored pilot OUTPUT | `V21` BLOCK naming component + output | one verdict | Selftest covers the core; run **one** batch-local execution anyway — it is the only proof the parse path over THIS record reaches the core. |
| **K5** | Delete the `consumers :` line (not its value) of one re-authored pilot OUTPUT | `V11` BLOCK — omitted field, distinguished from `consumers : none` | one verdict | Selftest arms cover both limbs; **cite, do not re-execute**. |
| **K6** | Duplicate the `COMPONENT: workspace_body` anchor line and its header | `V19` NOTICE naming **both** `file:line`, and stating that balancing keeps the LAST while the OUTPUT contract counts all | one verdict | **batch-local if `D-87-A` resolves toward any shape that re-declares an id**; otherwise cite selftest `V19 DUP-red` + `NAMES-both` + `ATL DUP-both-render`. Decide at the fold, from F1's probe. |
| **K7** | Delete the `PARENT :` line of `workspace_body` | `V12` BLOCK — *no PARENT declared* — proving the field is read rather than defaulted | one verdict | **batch-local, MANDATORY.** Directly refutes the C-31 reading that F3's honest declaration could be omitted and still pass. |
| **K8** | Remove the single canon clause mirroring **one** batch-87 heading id, keeping its line-mates verbatim (batch-86 M7b's surgical shape, not M7a's whole-line shape) | that id's per-id `grep -cF` → **0**; `V22` aggregate **+1**; the neighbouring id on the same line still greps 1 | two figures + the named inert arm | **batch-local, MANDATORY.** batch-86 measured that the canon **packs two ids per line**, so the whole-line shape moves the aggregate by +2. Predict per **id**, never per line. |
| **K9** | Append one byte to the committed `ATLAS-IFC.md` | `V20` BLOCK — drift | — | Cite selftest `V20 E2E-drift`. **Free RED available:** at the P3 gate, V20's BLOCK after authoring but *before* `--atlas --write` **is** an observed RED — record that transcript instead of manufacturing one. |

**Every mutation gets its own resolved arm and its own verdict line.** An arm that fails to flip
its rule is reported as a **refuted prediction with its transcript**, repaired by a second surgical
arm, and **not quietly overwritten** — batch-86's M7 is the precedent and the reason.

---

## 4 · Negative-control register (C-55 rider)

Every absence claim in §2 is paired here with a probe over a known-present case, run in the **same
invocation**. An absence with no positive control is a silenced rule, not a retirement.

| Absence claimed | Positive control (same probe, same run) | Counterfactual (mutation) |
|---|---|---|
| `AT-B87-01`: the `[IFC]` census line for `…batch-85/…:372` is gone | the `[BATCHES]` `2026-07-23-batch-n8` line is **still present and still counted** in the same census block — proof the census renderer still emits | **K1** makes an `[IFC]` line appear again |
| `AT-B87-02`: zero V12 rows naming `loaded_panel` | the **expected residual** V12 row naming `workspace_body`/`workspace_shell` is present in the same output — proof V12 still emits NOT-checked notices where they apply | **K2** makes `loaded_panel`'s parent speak again, as a BLOCK |
| `AT-B87-05`: zero V12 rows naming `screen_workspace`/`workspace_body` | same residual row, one level up | **K2** and **K7** |
| `AT-B87-05`: zero V12 **BLOCK** rows | the tail's `N block` figure is read from the same run **and** `VAL` is shown BLOCK-capable on this corpus by K2/K4/K7 in this phase | K2 · K4 · K7 |
| `AT-B87-06`: pre-state `grep -c "workspace_body" ATLAS-IFC.md` = 0 | the same grep for `screen_workspace` returns ≥ 1 **in the pre-state file** — proof the grep and the file both work before the change | the grep's own pre/post pair is the RED/GREEN arm |
| P-src: empty diff | the same command with `.dev-flow/` added to its scope returns **non-empty** — proof the diff command is not silently no-op | — |

---

## 5 · C-10 / C-31 audit — what would pass on a default or on a hand-listed set

Flagged now so §3 cannot inherit them:

1. **`0 block` alone is a default-pass.** The pre-state tail already reads `0 block` (measured).
   A criterion of "final line `0 block`" is GREEN before any work is done. It is admissible only
   in its two-part attributed form: `0 block` **AND** no BLOCK located under
   `.dev-flow/2026-08-21-batch-85/`, `.dev-flow/2026-08-24-batch-86/`,
   `.dev-flow/2026-08-24-batch-87/`, or `.dev-flow/_derived/`.
2. **"The UNPARSED census is 1"** is a count, and a count can be reached by the wrong item
   disappearing. The criterion is the **surviving bullet's text** (§4 row 1), with the count as
   secondary.
3. **"0 V12 findings"** (§2.6's wording for US-87-2) is C-31: it is satisfiable only by writing
   `PARENT : SYSTEM`, which F3 measured to be false. Replaced by the enumerated-residual form.
4. **"loaded_panel balancing CHECKED"** is not directly observable: `_v12_outcome` suppresses its
   affirmative summary the moment any other finding fires, and the batch will carry F3's residual
   by design. CHECKED is provable **only** as an absence — which is why §4 row 2 exists and why
   K2 is mandatory rather than cited.
5. **Every quantified set must name its derivation.** The V13 pair set (`AT-B87-04`) is derived
   by parsing **every** V13 line of one run — never hand-listed, never stated as a finding count,
   never stated as a file-set union (batch-86 M4 measured the union blind at 15 → 15 while a real
   declaration was deleted). The consumer census for `workspace_body` quoted in §2.6 ("24 test
   files / 40 occurrences") is a **grep** figure, not a validator figure: it may seed the authored
   list but must never be a threshold — the threshold is V14's own resolved count.
6. **V22's aggregate is corpus-wide** and moves whenever *any* batch declares ids (it already
   moved 276 → 278 when batch-87's two US ids landed). Primary predicate is the **per-id
   `grep -cF` loop** over every batch-87 heading id; the aggregate is explicitly secondary and
   informational.
7. **The `--selftest` arm count is not this batch's evidence.** Citing it for a rule whose
   batch-local behaviour was never executed is the vacuous-check shape. §3's "cite, do not
   re-execute" dispositions are limited to K5 and K9, and each says why.

---

## 6 · Gate criterion set G-87

Every gate is RED on today's tree (measured in §0) except the pins; each names the validator line
or file byte that flips it; none is a repo-wide statement.

- **G1 (LIVE, headline — US-87-1)** — `ATLAS-ORPHANS.md` on disk: `[IFC]` bullet for
  `…batch-85/…:372` ABSENT, `[BATCHES]` bullet PRESENT. Counterfactual **K1**.
- **G2 (LIVE, headline — US-87-2)** — V12: 0 rows naming `screen_workspace`/`workspace_body`;
  exactly the enumerated residual naming `workspace_body`/`workspace_shell`; 0 V12 BLOCK.
  Counterfactuals **K2**, **K7**.
- **G3 (LIVE — F2 discharge)** — V12: 0 rows whose message contains `loaded_panel`. This gate
  exists only because the six-output split reaches into batch-86's re-export; it is the gate that
  catches F2 being forgotten.
- **G4 (LIVE)** — counted messages V10/V11/V14/V19/V21 equal pre-state + the authored deltas,
  each delta counted from the record; V19's message form unchanged (or, if `D-87-A` resolves
  toward a re-declaring shape, the duplicate NOTICE is **enumerated in advance**, never
  discovered). Attribution per §5 item 1.
- **G5 (LIVE)** — V13 post-state stated as an **enumerated PAIR set** (pilot pairs redistributed
  by the split, ∪ the new `workspace_body` pairs), written out row-for-row in §3 of the record,
  never a count alone and never a union. Counterfactual **K3**.
- **G6 (LIVE)** — ⚠️ *its grep predicate is refuted; see the note above §2's pins and the record's G7/G10 split.* Atlas: `grep -c "workspace_body" .dev-flow/_derived/ATLAS-IFC.md` ≥ 1 (today
  **0**) and a `### COMPONENT` heading with per-declaration rows; V20 `atlas current (4 files,
  census N)` with `N` ≤ committed, **re-checked at EVERY gate** (this artifact and the record are
  themselves corpus input, so the Atlas must reach a fixpoint with them present at shipped
  content).
- **G7 (LIVE)** — canon: per-id `grep -cF "<id>" REQUIREMENTS.md` ≥ 1 for **every** batch-87
  heading id (today `US-87-1` is in V22's own missing sample, so this is measured RED);
  secondary V22 aggregate ≤ the batch-open baseline re-measured at P1. Counterfactual **K8**.
  **CLOSE must re-measure**, because V22 moves whenever any batch adds ids.
- **G8 (PIN, labelled)** — P-src: source-scope diff empty. Green before work; it constrains, it
  does not gate.
- **G9 (PIN, labelled)** — P-ledger: §7. `D = 0`, `A = 0` expected for a spec-only batch; the
  `tests/` tree byte-identical to merge-base makes `post = base` structural.

---

## 7 · P4 gate-run protocol (the suite)

**One complete run, owned by the orchestrator (C-25).** This phase does **not** run `pytest`; a
qa-authored figure would be a second run and a second truth.

```
conda run -n s19env python -m pytest -q -m "not slow"
```

- **Redirect the whole run to a file** (`batch87_gate.txt`) and read evidence **from that file**.
  **Never pipe the run through `tail`** (C-19) — a truncated stream is not the run's own output,
  and the summary line is not a substitute for the FAILED lines.
- **Strip ANSI before grepping**: `sed -r 's/\x1b\[[0-9;]*[mK]//g' batch87_gate.txt > batch87_gate.clean.txt`,
  then grep `^FAILED` / `^ERROR` on the clean file. Colour codes split node ids and make a grep
  silently under-report.
- **Ledger form**: `post = base − D + A`, with `base` the batch-open selected count, `D`/`A` the
  nodes this batch deleted/added. For a spec-only batch `D = A = 0`, and that is **proved**, not
  assumed, by the empty source-scope diff over `tests/` (P-src).

**Pre-existing flaky nodes — dispositioned IN ADVANCE.** These six are the batch-86 carry recorded
in the `BACKLOG-CODE.md` header ("New carries from batch-86", item 1). Each was diagnosed by
execution on pristine `main` (`a112eeb`) and passes in isolation; they are order/state-dependent
suite pollution, not this batch's product. Exact node ids, read from the backlog header and
resolved to their definitions in `tests/`:

| # | Node id | File:line of definition |
|---|---|---|
| 1 | `tests/test_before_after_report.py::test_at_061a_persistent_control_survives_then_writes_pair_and_clears` | `tests/test_before_after_report.py:1078` |
| 2 | `tests/test_tui_flow_persistence_ui.py::test_at006_quarantine_card_painted_and_flow_unchanged` | `tests/test_tui_flow_persistence_ui.py:190` |
| 3 | `tests/test_tui_flow_persistence_ui.py::test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` | `tests/test_tui_flow_persistence_ui.py:295` |
| 4 | `tests/test_tui_legend.py::test_at023c_issues_legend_button_opens` | `tests/test_tui_legend.py:197` |
| 5 | `tests/test_tui_patch_editor_v2.py::test_at057b_regroup_wiring_and_binding_regression` | `tests/test_tui_patch_editor_v2.py:2361` |
| 6 | `tests/test_tui_patch_editor_v2.py::test_at064b_json_popup_edit_confirm_cancel_and_geometry` | `tests/test_tui_patch_editor_v2.py:2766` |

> **Disambiguation, because the backlog abbreviates:** `test_at006…` is the **quarantine** node in
> `test_tui_flow_persistence_ui.py`. Two other `test_at006*` nodes exist
> (`tests/test_flow_report_wire.py:160`, `tests/test_tui_flow_persistence_ui.py:158`) and are
> **not** on this list. Likewise `test_at064b_reachable_under_scroll_at_120`
> (`tests/test_tui_patch_layout.py:495`) is a different node and is **not** carried.

**Disposition rule — stated before the run, so it cannot be fitted to the result:**

- A FAILED node **on this list** → recorded as **pre-existing**, with (i) the node id, (ii) an
  isolated re-run on the same env showing it passes alone, and (iii) the empty source-scope diff.
  It does not block.
- A FAILED node **not on this list** → **BLOCKER**, regardless of how flaky it looks. A
  spec-only batch has no mechanism by which it could redden a new node, so a new failure means
  either the premise (0 source files) is false or the base moved — and both are findings.
- **Zero failures is also a result**, not a licence to skip the disposition table. State that the
  six did not recur.

---

## 8 · §2.6 corrections owed at the fold

| # | §2.6 clause | Defect | Fix |
|---|---|---|---|
| **F1** | `D-87-A` "(a) in place vs (b) fresh in batch-87" | Not open — option (b) cannot clear the census entry, since `_ifc_corpus` merges by extension and the entry is keyed to the batch-85 file's own line | Replace with the narrower in-place-body-vs-pointer question; declare `.dev-flow/2026-08-21-batch-85/01-requirements.md` as an edit target; add the "no indented line after the block's last field" authoring constraint |
| **F2** | "0 new BLOCKs" + "Small: one record section" | The six-output split makes `child_out ⊄ parent_out` against batch-86's verbatim re-export → a self-inflicted V12 BLOCK; the batch edits **three** records | Scope the batch-86 re-export update; add gate **G3** |
| **F3** | "SYSTEM if it is truly the root — to be MEASURED at P1" | Measured: `app.py:1917` mounts it inside `#workspace_shell` (`app.py:1919`). Hypothesis refuted | Declare `PARENT : workspace_shell`; state the one expected residual V12 NOTICE; rewrite "0 V12 findings" into the enumerated-residual form |
| **F4** | "the `.db-pane` / `.db-screen` couplings become contract-visible" | No oracle — "visible" is not observable | Bind it to a named V13 pair row per coupling, or drop the claim |
| **F5** | (implied by F3) | `workspace_body` has only two legal OUTPUT shapes — zero, or a superset of `screen_workspace`'s 30 ids | Register `D-87-B`; decide by executing both shapes on a copy; write the chosen cost into the record |
| **F6** | "V22 debt must not grow — batch-86 closed at 276" | Already false as a comparison: measured **278 of 533** this session, because batch-87's own two US ids entered the corpus | Restate as: per-id greps ≥ 1 primary; aggregate ≤ the **re-measured batch-open baseline**, secondary |
| **F7** | "per-surface cost point n=3" | Needs a §3 row or it is a claim | Method **analysis**: the six labelled figures per LLR-85.7's schema, dispersion across n=3 stated as a **range**, the unmeasured-surface caveat restated. Threshold: 6/6 non-null, 1 caveat, **0 totals and 0 means** |

---

## 9 · Evidence checklist (qa-reviewer, Phase 1)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria in the project's Given/When/Then equivalent | ✓ | §2's fixed **Surface driven / Deliverable observed / Threshold / Derivation** form — the batch-86 convention this record's gate table indexes (global rule 11) |
| 2 | Explicit Expected, never "works" | ✓ | Every §2 row carries a threshold **and** the probe that prints it; every §3 arm states its expected flip before execution |
| 3 | Edge cases: empty, boundary, invalid, error | ✓ | empty = `consumers` omitted (K5) · boundary = the one-name / one-entry deletions (K2, K3) · invalid = the re-absorbed indent (K1) and the missing PARENT (K7) · error = selftest `V14 BLOCK-nofile` |
| 4 | Regression checklist | ✓ | §4's negative-control register + §6's nine gates, re-executed at every gate; §7's pre-declared flaky disposition |
| 5 | Exit criteria | ✓ | §6 G1–G9 with G1/G2 as the two headline LIVE gates |
| 6 | No real PII / secrets | ✓ | repo-relative paths, validator stdout, git metadata only |
| 7 | Results left blank unless actually run | ✓ | §0 is a **measured pre-state**, labelled as a measurement at a moment; every §2/§6 threshold is `DERIVE-AT-AUTHORING`. No post-state figure is asserted anywhere in this file |
| 8 | Layer B — deliverable observed through the SHIPPED surface with boundary + negative evidence | ✓ | §2: every row observes stdout text or file bytes (never an exit code); boundary/negative arms are §3's K1–K8, each with a named verdict owner |
| 9 | Bidirectional surface-reachability | ✓ | inputs — `PARENT`/`INPUTS`/`OUTPUTS`/`consumers`/`owner`/canon mirror lines are each reddened by a distinct arm (K7 · K2 · K1 · K3 · K4 · K8); outputs — census bullet, V12 rows, counted messages, V13 pair set, `ATLAS-IFC.md` rows, `ATLAS-ORPHANS.md` bullet, canon greps, source diff — each observed as a **thing** in §2/§6 |
| 10 | No unfilled template | ✓ | 0 `<...>` placeholders, 0 `TC-NNN` stubs. The `DERIVE-AT-AUTHORING` markers are **deliberate C-39 obligations with a named probe each**, not blanks |
| 11 | C-56: no mangled token spelled | ✓ | §3 describes every mutation by position + operation; the only operations are deletion and indent change |

**An item without a citation is not satisfied — it is asserted.**
