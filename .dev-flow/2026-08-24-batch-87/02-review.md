# 02 — Cross-review · batch-87 · P1 record + 01b plan (two independent Opus 5 lenses)

**Verdict (both reviewers, independently): `iterate` with named gaps.** Findings consolidated
below; every one carries executed evidence (reviewer probe scripts + replay corpora preserved
under the job temp dir at review time; key transcripts `val_redarm.txt` / `val_redarm2.txt`).
The substance SURVIVED adversarial attack (see §3); the defects are in the **evidence
artifacts**, which is the failure class this batch exists to eliminate — and the reason the
gate forces the iteration.

**Convergence note:** R2-01 was found by BOTH reviewers independently, by different methods
(git-state replay; the author's own saved run files) — the batch-51 double-derivation pattern.

## 1 · Findings

| id | Sev | Lens | Finding (evidence executed by the reviewer) | Fix direction | Axis |
|---|---|---|---|---|---|
| R2-01 | **blocker** | both | §5.6 "live RED arms" fence splices TWO mutually exclusive runs (state A: `11 block`, 1 V12 + 6 V21 + 4 V20; state B: `12 block`, 8 V21 + 4 V20, zero V12). No single command produces the pasted artifact. Propagates to §3:500 (12-BLOCK decomposition omits the V12 arm) and §3:532-536 ("three LIVE RED arms" summed to 13, a count no state produced). | Split into two LABELLED transcripts — both already captured (fix hypothesis executed by arch reviewer, byte-consistent). Re-derive the §3 ledger per run (11-then-12, or 13 distinct instances across the sequence, stated as such). | Evidence |
| R2-02 | **blocker** | arch | `AT-B87-*` id space FORKED between the two P1 artifacts: same id ≠ same acceptance (01b's -03/-04/-05/-06 vs record's -01…-04); record never references 01b; no supersession note; record claims "4 ATs" while 01b defines 6. D-87-F's "cost: none today" is refuted by this live fork. | ONE mapping table (01b id → record id/gate or explicit retirement with reason, per C-40 limb 2 no-dropped-observables); supersession note in 01b; amend D-87-F's cost line. | Coverage + Certainty |
| R2-03 | major | arch | `LLR-87.7` threshold RED on arrival: "`PARENT : SYSTEM` appears 0 times in this document" — executed: 3 (one hit is the threshold itself). Pilot defect #4 shape, which §5.5 row 4 claims "Not reproduced". | Scope to the §5.3 COMPONENT block (executed: 0 inside block). Update §5.5 row 4 honestly. | Certainty |
| R2-04 | major | both | R-87-3 / P-15 survey: `app.py:1885` wrong by 4000 lines (real site `app.py:5885`, cited twice); 2 sites missed in the surveyed files (`app.py:1902`, `screens_directionb.py:3284`); P-15 says "two in-source claims", enumerates four. | Correct the line, add the 2 sites, reconcile the count. A carried finding whose value is exactness must be exact. | Evidence + Coverage |
| R2-05 | major | both | §5.6 cost table mixes pre/post planes in surface #2's column (outputs 30 = pre-split; consumer entries 94 = post; "29 of 30" = pre) while its own M-cite requires 31; dispersion line "6 → 30 → 42" inherits it. Surface #1's cell IS annotated — convention known, not applied. | Annotate like #1 (post value + "(as batch-86 shipped: …)"), propagate to the dispersion line. Re-MEASURE, never edit (C-39 rider). | Certainty |
| R2-06 | major | qa | 01b `AT-B87-06` pre-state measurement FALSE: `grep -c "workspace_body" ATLAS-IFC.md` at both candidate pre-states → **2**, not 0 (batch-86's `PARENT : workspace_body` + V12's own finding). Threshold "≥1" was GREEN before any work; the §4 negative-control contrast does not exist. | Re-derive a discriminating predicate (e.g. `### COMPONENT \`workspace_body\`` heading presence — pre 0 / post 1, verified by qa) and re-measure both states. | Certainty |
| R2-07 | major | qa | The only acceptance observing `ATLAS-IFC.md` BYTES was dropped without disposition (01b AT-B87-06 has no counterpart in §3/G-87; G7/V20 check currency, not rendering). The artifact happens to be correct (qa verified `### COMPONENT \`workspace_body\`` at ATLAS-IFC.md:96, no `{id: component}` collapse) — a coverage hole, not a defect. | Realize it as a gate/AT per R2-06's corrected predicate, or retire it with a stated reason. | Coverage |
| R2-08 | major | qa | §2.8 M-4 header says "five arms" but line ~230 attributes a SIXTH arm's output to arm 5: arm 5's own transcript shows a `[!]` V12 NOTICE and no BLOCK (P-11 depends on that absence), while the quoted 30-id `[x]` BLOCK requires a non-empty output set — mutually exclusive configs under one label. Both facts true; attribution wrong. | Name the sixth arm, fix the header count. Per-arm verdicts (C-40 rider). | Evidence |
| R2-09 | minor | qa | §5.6 "plus 2 no-literal notices" — measured: **1** V13 notice naming 2 addresses (01b §0 has it right). Count-vs-thing distinction. | One notice, two addresses. | Evidence |
| R2-10 | minor | qa | batch-86 amendment note scope one clause too narrow: "figures that count outputs and consumer entries" doesn't reach LLR-86.6's Statement naming `slot_rows` and its "VERBATIM" carry clause. | Widen the note's scope clause to name the superseded non-count assertions. | Evidence |
| R2-11 | minor | arch | Malformed markdown in P-13's evidence cell (bold opened, closed with a backtick). | Fix the cell. | Evidence |
| R2-12 | minor | qa | `AT-B87-04` merges 01b's two independent pins (source-diff + suite ledger), one not executable at authoring ("measured at gate"). | Prefer 01b's split (C-18 one-AT-one-node direction). | Coverage |
| R2-13 | minor | arch | D-87-B rationale says "~120 consumer entries"; §5.6 measures 139, in a document whose header rule is "the command is right". | 139. | Evidence |

## 2 · Kill mutations executed by the reviewers (all on discarded copies; real tree verified untouched by both)

K1 (owner re-absorption → census 1→2, V20 BLOCK, Atlas re-emits the `[IFC]` bullet — G1 non-vacuous,
GONE-probe reports PRESENT) · K7 (PARENT deletion → V12 BLOCK — G2 not a default-pass) · G3 live
arm (pre-P1 batch-86 restore → `emits` BLOCK returns verbatim at `batch-85/01-requirements.md:504`)
· Arm-5 A/B (zero-output parent → child's BLOCK VANISHES / non-empty incomplete → 30-id BLOCK —
P-11/R-87-1 confirmed, D-87-B's rejection of the cheap form upheld with a live kill) · plus the
arch reviewer's re-derivations: 42 outputs = derived (wb−sw = 11 own, sw−wb = ∅), V13 census
3/4 · 19/36 · 29/62 · Σ 51/102 exact, +29/+1 delta exact, V22 baseline arithmetic 276→278→289
verified, INPUTS containment live (dropped input → BLOCK).

## 3 · Attacked and survived (so §1 reads as a result, not a reading)

D-87-A (both measurements reproduce) · D-87-B/P-11/R-87-1 (the batch's best finding — holds under
kill-mutation) · D-87-E/D-87-F measurements (registry 0 rows for all six prefixes, `next_free.AT`
282 untouched) · frozen-history line (per-hunk diff judged correct; supersession declarations
present at batch-85:313 and the batch-86 note; declaring-not-rewriting upheld) · pilot defect
discharges #1/#11/#12 · 9/9 LLR-87.6 symbol citations · M-6 reproduced verbatim under s19env
run_test() · shall/should 11/11-0 · no C-56 shorthand in new text (2 corpus hits are frozen
history, barred from edit) · 01b's P4 protocol incl. all six flaky-node ids resolved and the
pre-registered disposition rule · V13 census reproducible despite the foreign untracked WIP
(`build/` in `_V13_SKIP_DIRS`; memmap2 files carry no declared literal).

## 4 · Gate decision

Blockers exist → **`iterate` forced back to the P1 author** (per flow rule). Iteration order:
R2-01 and R2-02 first (they gate G3/G5 evidence and the AT layer), then R2-03…R2-08, minors last.
Every moved figure is RE-MEASURED by command, never edited (C-39 rider); the corrected §5.6
transcripts come from re-running the two states, not from editing the fence. The fold is owned by
ONE writer (the P1 record author) across all three touched files + 01b, to prevent a second fork.
Re-review at the orchestrator: re-run validator, re-execute the corrected predicates R2-01/05/06,
then decide.
