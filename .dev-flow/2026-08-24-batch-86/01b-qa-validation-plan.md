# QA validation-methods plan — batch-86 Phase 1 (qa-reviewer deliverable, 2026-08-24)

> Returned by the Phase-1 `qa-reviewer` dispatch; persisted verbatim by the orchestrator.
> To be FOLDED into `01-requirements.md` §3/§4 at the Phase-1 fold, together with the D1–D6
> corrections to §2.6. Pre-state figures below were measured by the reviewer on the live
> worktree at rev44 — re-derive rather than cite.

**Pre-state at measurement:** `0 block · 233 notice · 15 n/a`; V10 **9** nodes · V11 **5**
outputs · V12 **1** NOTICE (`…batch-85/01-requirements.md:334`, "parent `screen_workspace`
is not declared … NOT checked") · V13 **3 findings / 4 files / 4 stray pairs** · V14 **15**
consumers · V19 **1** id · V20 `atlas current (4 files, census 2)` · V21 **5** owners ·
V22 `277 of 520` unreflected (sample names **US-86-1**) + 1 unowned-LLR notice ·
`--selftest` exit 0, **189** arms.

**Notation.** `W` = this worktree · `VAL = python ~/.claude/docs/tools/devflow-validate.py`
· K/M/C = the new record's flow-node / OUTPUT / consumer-entry counts, frozen as numbers in
§3 at authoring (pilot analogues 9/5/15). Method labels: the validator lives outside the
repo ⇒ these are **inspection (operator-local executed verification)**, never
`test (integration)` — a `test` label with no pytest node is C-18.

## 1 · Per-criterion methods, commands, thresholds

- **AC-a — counted verdicts, 0 BLOCK attributable.** Inspection (executed). `VAL "$W"`
  pre/post filtered to V10–V14/V19/V21. Thresholds counted by MESSAGE, never severity (D1):
  V10 = 9+K nodes every one owned · V11 = 5+M OUTPUTs · V14 = 15+C consumers resolved ·
  V21 = 5+M owners declared · V19 message = `2 COMPONENT id(s), each declared exactly once`
  · V12 `:334` NOT-checked notice ABSENT post, replaced by a CHECKED outcome (D5), 0 V12
  BLOCK · V13 per G4. Attribution: final line `0 block` AND no BLOCK located under
  `.dev-flow/2026-08-24-batch-86/` or `.dev-flow/_derived/`.
- **AC-b — Atlas renders the component, V20 current.** Inspection (executed).
  `grep -c "screen_workspace" .dev-flow/_derived/ATLAS-IFC.md` ≥ 1 (pre-state **0** — this
  grep is its own RED arm); V20 line = `atlas current (4 files, census N)`, N ≤ 2.
  Regenerate + re-check at EVERY gate.
- **AC-c — canon mirrors the batch's ids.** Inspection (executed). PRIMARY (scoped, per
  defect #7): for EVERY heading id in batch-86's doc, `grep -cF "<id>" REQUIREMENTS.md` ≥ 1
  each (V22's own predicate executed per id; measured RED today — US-86-1 is in V22's
  missing sample). SECONDARY (informational): V22 aggregate ≤ 277 of (520 + N₈₆). Also
  enumerate expected unowned-LLR notices ("0 unexpected" is the threshold, not "0 notices").
- **AC-d — suite/source neutrality.** Inspection (executed).
  `git diff --stat $(git merge-base HEAD origin/main) -- s19_app/ tests/ tools/ pyproject.toml`
  → 0 files / 0 insertions / 0 deletions. Ledger post = base − 0 + A, A declared (A = 0
  legitimate ⇒ the pytest ledger is a PIN and is labelled one). Drop "byte-neutral on
  product behavior" wording (D4).
- **Per-surface cost n=2** (needs a §3 row): method **analysis** — six labelled figures per
  LLR-85.7's schema + dispersion vs the pilot's row (ratio or range per figure) + the
  unmeasured-surface-count caveat restated. Threshold: 6/6 non-null, 1 caveat, 0 totals.

## 2 · Kill-mutation table (C-10/C-40)

Protocol: mutations ONLY on a copy (`mktemp -d`, copy the worktree, drop `.git`), then
`VAL "$T"` asserting the one targeted line. Freeze `~/.claude` for the duration (handoff
§10: the validator is in every reader's read-set); stamp transcripts with the re-derived
flow hash.

| # | Mutation (on copy) | Rule / expected | Discharged by |
|---|---|---|---|
| M1 | delete one workspace OUTPUT's `owner :` line | V21 BLOCK naming component+output | selftest arms cover the CORE; run ONE batch-local execution anyway — only proof the parse path over THIS record reaches the core |
| M2 | owner → `LLR-99.9` | V21 BLOCK "no document defines" | cite selftest `V21 BLOCK-ghost`; do not re-execute |
| M3 | append one byte to committed `ATLAS-IFC.md` | V20 BLOCK drift | cite selftest `V20 E2E-drift` + siblings. Free RED: at Phase 3, V20's BLOCK after authoring but before `--atlas --write` IS the observed RED — record that transcript |
| M4 | remove one `consumers` entry from a workspace OUTPUT | V13 stray PAIR count +1; record whether the file-set union moved — when it does NOT, that transcript is defect #1's demonstration | **batch-local, MANDATORY** — no selftest arm asserts pair-vs-file over a real corpus |
| M5 | remove one input name (or child-output id) from `screen_workspace` | V12 BLOCK `consumes/emits … unbalanced` naming `loaded_panel` | **batch-local, MANDATORY** — the batch's headline live verdict (G1); no arm exercises THIS record's containment sets |
| M6 | duplicate `COMPONENT: screen_workspace` | V19 NOTICE naming BOTH file:line | cite selftest `V19 DUP-red` + `NAMES-both` + `ATL DUP-both-render` |
| M7 | delete one batch-86 mirror line from the REQUIREMENTS.md copy | per-id grep → 0; V22 aggregate +1 | core cited; the grep mutation costs one command — execute batch-local |
| M8 | FLOW node owner names an undefined requirement | V10 BLOCK | cite P-10 (pilot, executed) + V10 arms |

## 3 · Gate criterion set G-86 (the zero-live-gates fix, defect #15)

Every gate is currently RED on today's tree (measured) except the pin G7; each names the
validator line/value that flips it; none is a repo-wide statement.

- **G1 (LIVE, headline)** — V12: the `:334` notice ABSENT post-state; balancing for
  `loaded_panel` CHECKED; only batch-86's record can flip it (editing batch-85 = D-II, out
  of scope).
- **G2 (LIVE)** — V19 = `2 COMPONENT id(s), each declared exactly once` (today: 1).
- **G3 (LIVE)** — V10/V11/V14/V21 counted messages = pre-state + exactly K/M/C/M; final
  line `0 block`; no BLOCK under the batch's paths. Since rev39 `_artifacts()` prefers the
  declared batch, V1–V9 judge THIS document too — "0 block" is live over §3/§4 prose,
  unlike batch-85's F-7.
- **G4 (LIVE)** — V13 stray census stated over (output_id, file) PAIRS: post set = the 4
  enumerated batch-85 pairs (unchanged) ∪ the enumerated new-workspace pairs; sum =
  4 + P_new exactly; the pair set written out in §3, never a count alone.
- **G5 (LIVE)** — Atlas grep ≥ 1 row for the new id (today 0) AND V20
  `atlas current (4 files, census ≤ 2)` at every gate.
- **G6 (LIVE)** — per-id canon greps ≥ 1 for every batch-86 heading id (today: US-86-1 =
  0); secondary V22 aggregate ≤ 277.
- **G7 (PIN, labelled)** — source-diff empty + ledger unchanged. Green before work; it
  constrains, it does not gate.

## 4 · §2.6 defects found (to correct at the fold)

- **D1** — "verdicts — not SKIP" unsatisfiable: passing rules also print `[-]`. Fix:
  counted-message deltas vs recorded pre-state.
- **D2** — "0 BLOCK attributable" lacked an attribution rule. Fix: G3's two-part rule.
- **D3** — V22-aggregate criterion unscoped (defect-#7 shape; vacuous at 0 declared ids).
  Fix: per-id grep primary, explicit-number aggregate secondary.
- **D4** — "byte-neutral on product behavior" has no oracle. Fix: G7's diff-scope command +
  ledger arithmetic.
- **D5** — "V12 verdict instead of NOT checked" hides two authoring preconditions: (i) both
  INPUTS must be parseable `name: type` lists covering `loaded` and `project`, else the
  outcome is a different NOTICE that still satisfies the sloppy wording — demand the
  CHECKED outcome; (ii) V12 also balances child OUTPUT ids against parent OUTPUT ids when
  both are non-empty — a workspace OUTPUTS set not covering the panel's 5 ids produces a
  BLOCK from the batch's own record. §3 must enumerate expected residual V12 notices (the
  workspace's own PARENT, unless honestly `SYSTEM`).
- **D6** — "selected by measured evidence" had no refutation threshold. Fix: freeze the
  falsifier as Part B's trigger question — no selector literal by which a consumer
  independently addresses the workspace ⇒ hypothesis refuted, fallback + reason recorded.
