# HANDOFF — 2026-09-03 — CONSOLIDATED PLAN: rev56 intake + backlog, one ordered sequence

> ## ⚠ WHICH HANDOFF THIS IS
>
> **This is the PLAN — the file the next session reads and executes.** Its input is
> `HANDOFF-devflow-session-2026-09-03-rev56-intake-PLAN-INPUT.md` (same directory), which holds the
> measurements and per-proposal verdicts. **This file orders the work; that file proves the claims.**
> When a figure here needs its evidence, follow the §-pointer into the input — nothing is re-argued
> here that the input already settled, and nothing here contradicts it without saying so (§6).
>
> Written by the consolidating reviewer, 2026-09-03. Nothing was committed, pushed, or edited
> outside this one file. Verification ledger: §7 says exactly which input claims were re-measured
> today and which are taken on trust.

---

## ✅ STATUS — appended 2026-09-03, later the same day. The plan below is UNCHANGED; this says what has since shipped.

**Steps 1 and 2a are DONE.** Read this block before the plan, or you will execute work that is already merged.

| step | state | evidence |
|---|---|---|
| **1 — rev56, tranche 1** | **SHIPPED** | `claude-config` `1fd6748` · `agent-skills` `e825ffd`. 565 arms, 0 FAIL under 3.11.15 **and** 3.12.7 · `--map` 24/24/0/0 · `flow_hash 7ebb49bee3b82839` |
| **+ the vault leak** | **CLOSED** | `dev-flow-sync.md` no longer names any Drive. `vault:` resolves against a `vault_root` row in `~/.claude/docs/deployment.md`. **`artifact_homes` was rejected as the home** — it is circular (its values *contain* the prefix) and per-project-and-tracked, so N projects would hold N copies of one machine fact. Argued in the tranche-1 packet |
| **2a — close batch-89** | **DONE, MERGED, SYNCED** | `04-validation.md` + `05-close.md` written **with the gate run before the record**, not after. PRs #207, #208. `main` at `cd2fc00`, then `4beed6e` |
| **the sync** | **PASSED — a first** | ACTIVE case, `mode: core → P5`. **The first `core` batch ever to clear pre-requisite 2**, which demanded `P6` until rev56. `obsidian_synced: true` verified **on `origin/main`**, not just on disk (the C-44 half) |
| **housekeeping** | done | primary checkout moved to `main`; `claude/batch-89-lean-contract` pruned local + remote after verifying **0 branch-only objects**; `V20` then caught a stale Atlas over the merged corpus and it was regenerated (`4beed6e`) |
| **2b — rev57, tranche 2** | **SHIPPED** *(appended 2026-09-03, later the same day)* | `~/.claude` **`68e27aa`** · `~/.claude/skills` **`7524a77`** · `s19_app` **`2f574a1`**. `flow_hash 943054294e1ff9de`. **565 arms, 0 FAIL** under 3.11.15 **and** 3.12.7 — a **carried baseline, not a new result**: `devflow-validate.py` is byte-untouched, exactly as this plan predicted for a doc-only tranche. Gate over `s19_app`: **0 block · 291 notice · 29 not applicable**. Closes **`R-89-3`** in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) |

**Two things the execution changed about the plan's own content:**

- **The `core`-mode sync condition shipped as the INPUT's §1.6 correction, not the candidate's.** It derives `P6`/`P5` from `mode` and states in terms why `stations_active` is not consulted. The plan's own note that `stations_active[-1]` is "already the authority" was **over-read**: `dev-flow.md:575` calls it the authority on *which optional stations exist* (`ARQ`/`PDR`/`DDR`), never on which is terminal.
- **The input's third reason against `stations_active` — "it is not reset at rollover" — is FALSE as a property.** Traced through the state ledger's git history: batch-88 opened at `['P0']` and grew, so the 87→88 rollover reset it correctly and **only** 88→89 did not. The accurate form shipped in the command.

**What remains, unchanged from the plan below:** step **2b** (tranche 2 — P3's remainder, P7's severity sentence, the origin-parenthetical rule) · step **3** (the rev58+ validator series, whose head is the `P0`) · step **4** (decisions **D2, D3, D5** — D1 is executed, D4(iii) is closed by the vault fix, D6 is executed).

---

### ➕ APPENDED 2026-09-03, later the same day — **step 2b is DONE.** Three things it changed about the plan, and one it did not.

**Read the row added to the table above first.** The sentence *“What remains … step **2b**”* immediately above is **superseded**: 2b shipped as flow **`rev57`**. It is left standing rather than edited, because the plan body is frozen and a struck prediction is more useful than a tidy one.

**(1) P3's population was LARGER than this plan carried, and the correction is the reusable part.** §3.2 (b) instructs *“extract the **remaining 6 origin markers in 3 files**… 5 of 5 files, not 3 of 5.”* **The executed population was 72 sites across 6 files.** Enumerated before anything was touched: **61 `(Origin:` markers in five files** (`dev-flow.md` 41 · `req-template.md` 13 · `dev-flow-sync.md` **4**, not the 3 the input listed · `fast-dev-flow.md` 2 · `validation-template.md` 1) **plus 11 unmarked narrative blocks** (3 · 6 · 2) that carry **no marker at all** — which is how `ifc-template.md`, a **sixth** file at **zero** markers, still held 2.4 KB of origin story. **A marker census is not a population census**, and this is the second time in two passes that the intake’s enumeration came in short.

**(2) P7 was resolved by REWORDING, not by a `--map` change** — which is a real narrowing of step 3, not a rescheduling. The hand-kept `V1`–`V9` table (9 of 28 rules, stale eight revisions) is gone, replaced by documentation-by-reference to `--map`; and the severity sentence was **rewritten in the command** rather than made satisfiable by a tool change. So **step 3's item 4, *“`--map` prints per-rule severity”*, no longer “completes P7” — P7 is complete without it.** ⚠ **And as item 4 is specified, it must not ship:** severity is a property of a **finding**, not of a rule — measured over all 28 registered rules, **10 can only BLOCK**, **11 can only NOTICE**, and **7 raise BOTH** (`V7` `V12` `V15` `V16` `V17` `V26` `V30`; `_v26_outcome` NOTICEs an over-budget live contract and BLOCKs a one-sided pairing). A single-valued column cannot be true for those seven. **Re-filed as a `P3` (`map-severity-column`) in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) §*Opened 2026-09-03 (post-`rev57`)*, with the closing condition rewritten:** print the **set** a rule can raise and disclaim per-finding severity, or retire the item.

**(3) One site of the 72 was deliberately NOT extracted**, and it is filed rather than hidden: `(Origin: batch-06 B-1.)` in `req-template.md` resolves to no `dev-flow-lessons` heading, so `rev57` left it verbatim rather than invent an origin story. New `P3`, `origin-batch-06-b-1-unresolved`.

**What this did NOT change:** step **3**'s head is still the `P0` — `R-89-6`/`R-89-7`, `V2`'s vacuity — untouched by a doc-only tranche. ⚠ **But step 3's *other* framing did move:** this plan's `§0` table calls the batch-79 charter the code lane's `P0`; **it shipped 2026-08-13 (`f198447`, PR #192)** and both backlog indexes have been corrected. **The instrument-blindness law and the other two portable lessons are still unencoded** and each still owes its AskUserQuestion — `7524a77` touched the catalog, which is not the same as paying the `C-45` debt.

**⚠ The hard guard is still in force: no batch-90 directory exists and none may be opened** until the plan says so. `V28`'s window is one batch wide.

---

### ➕ APPENDED 2026-09-06 — Wave A landed, and the operator RULED on the four briefs

**Wave A (four parallel Opus 5 lanes, 2026-09-03 → 06) shipped:** the post-`rev57` backlog reconciliation (`a13c079`) · flow **rev58** — `V2`'s node corpus declared via `artifact_homes.tests`, 565 → 585 arms, 19/19 mutants killed, `_V2_DECLARED` untouched (`~/.claude` `82a4a20`, bundle `21d3ee4`, `flow_hash 50d1c2d0191432bf`) · the Atlas regenerated on a clone-reproducible tree (`ed859d1`) · four measured briefs at `C:/Users/jjgh8/.claude/docs/analysis/briefs-2026-09-03/`.

**The code lane's `P0` was already shipped** (batch-79 Lane 1, `f198447` / PR #192, 2026-08-13) and its `IN FLIGHT` twins with it; batch-90 was therefore NOT opened, and the guard in §0 above is moot — its condition (2a complete) was met on 2026-09-03.

**Rulings, 2026-09-06 — "Aprobado", following each brief's recommendation:**

| # | question | ruling | executes as |
|---|---|---|---|
| 1 | id grammar (§3.2-1) | **(A)** widen `_V2_DECLARED` to the batch-scoped form, grandfather global-numeric ids, **and ship `_strip_code` on the declared side in the same increment** — widening alone raises 2 BLOCKs over this repo and both are backtick-quoted false positives | step 3, `V2` limb 1 — now unblocked |
| 2 | instrument-blindness law | **encode as (b)+(c)**: a declared field in the increment packet plus a `V9`-shaped validator rule keyed on that field, never on a phrase; the law is absent from the catalog and 11 of 13 recent packets would go RED today | a flow rev (template + rule + catalog entry) — its own increment |
| 3 | population rule | **extend `C-14`** (trigger: a path move OR a correction to a multi-artifact claim) rather than mint a control; add the declared field to the increment template; **re-point the supersession-completeness inspection from P4 to P3**; `V9`-shaped rule on the field | a flow rev — its own increment; shares the template edit with ruling 2 |
| 4 | batch-90 scope | `report_service` markdown escaping · AT/TC registry blindness to batch-scoped ids · `TC-497` cannot tell an assertion from its refutation — three falsified-green-signal items, ~2 source files, no cross-row dependency; **the registry item goes first because batch-90's own id reservation is unsound until it lands** | batch-90, `core` mode |

**Sequencing consequence:** rulings 2 and 3 both edit the increment template, so they ship as ONE flow rev (rev59 or later), after ruling 1's limb-1 rev — the flow repo stays serial. Batch-90 (ruling 4) is independent and may open in parallel; it runs under whatever rev is current at its P0 and records it.

**The four briefs are the arguments; this table is only the verdicts.** Each brief ends with what it could not measure, and none of those gaps was waived.

**➕ 2026-09-06, later — Wave B lanes 1 and 2 landed.** **rev59** shipped (`~/.claude` `9d95647`, bundle `0bf7005`, `flow_hash 45eac0f2f6345fe3`, 592 arms): ruling 1 executed — `_V2_DECLARED` widened to `AT-(B<batch>-)?<n>`, `_strip_code` on the declared side, `WORDING-declared` re-frozen; **`R-89-6` closed** (on a batch-88-active copy `V2` names all nine ids, as nine BLOCKs — none has a node). `TC-B<batch>-<n>` ruled OUT by the operator on measurement (0 of 66 contracts differ). **batch-90 opened through P1** on `claude/batch-90-green-signals`, **PR #209** — the `report_service` item was SATISFIED-EXTERNALLY at `fbc9f2a` (2026-07-26) and dropped at P0; two requirements remain (registry blindness, `TC-497`); the batch stops at P1 until **rev60** (rulings 2+3) lands, so its first packet carries the new declared fields. **Next flow increment = rev60.**

### ➕ APPENDED 2026-09-07 — **rev60 SHIPPED, and every open PROCESS item now has a written disposition.** The flow is not finished; the QUEUE is.

**Read this row before the four-rev plan below.** This append does not change the plan; it records what shipped, what the six readiness checks measure today, and what the backlog now says.

| what | state | evidence |
|---|---|---|
| **rev60** | **SHIPPED 2026-09-06** | `claude-config` **`99b77fc`** · `agent-skills` **`0609e46`** · `flow_hash f0f12b04652cfd75` · **623 arms**. **Verified here by reading the shipped files, not the changelog:** the `Instrument RED-proof` and `Correction population` sections, declaration rows and gate-checklist rows 12/13 are in `increment-template.md`; `--map` registers `V31` and `V32` at `[S1]` with `(rev60)` origins; `C-57` and the widened `C-14` carry their own headings in `dev-flow-lessons/SKILL.md`; the supersession-completeness inspection reads **P3** in `validation-template.md` and in the catalog; rev59's `SyntaxWarning` is gone (the file compiles under `-W error::SyntaxWarning` on 3.12.7 while a planted bare-escape docstring **raises** on the same command) and two arms hold it, `INT SOURCE-no-warning` and `INT SOURCE-probe-sees-one`; and `FLOW-VERSION.md`'s `controls:` derivation is repaired — re-run here it returns **25** at heading depths 1–3 against **38** under the old published `#{1,6}` command, with the three planted injections scoring **0 / 1 / 0**. |
| **the disposition pass** | **DONE 2026-09-07** | [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) and [`BACKLOG-CODE.md`](../BACKLOG-CODE.md). **51 open markers in, 34 out**, every one of the 51 carrying a dated disposition. |

**The six readiness checks, as they measure TODAY.** Two are green, one was green already, three are red and each red one is assigned.

| # | check | today | who closes it |
|---|---|---|---|
| **1** | `--selftest` from a clone, both interpreters, byte-identical twice under default `PYTHONHASHSEED`, and the file compiles clean under `-W error::SyntaxWarning` | **◑ half green.** The compile half is **CLOSED at rev60** and re-verified here with a discriminating planted control. The byte-identical half is still open — three `--selftest` arms print an unsorted `set` repr. | **rev61** |
| **2** | a project scaffolded by following `/dev-flow-init` literally gates at 0 block / 0 flow notice, and its `state.json` carries every field a rule reads | **❌ RED, and it is the only check red for the user who matters — a project starting today.** | **rev62** (4 items filed) |
| **3** | no registered rule is known-vacuous; every rule with declared blindness prints that blindness in its own finding | **✅ GREEN, and it moved.** This lane's `P0` — the last known-vacuous rule — **closed at rev58 + rev59** and had never been recorded as closed; the closure and the two-day gap are both written at the item now. `V2` and `V30` both print their declared blindness. | closed |
| **4** | every template field the flow declares mandatory has a rule that reads it, or a written exemption | **❌ RED.** Re-verified: `Negative control` returns 6 hits in the validator and `Boundary catalog` 3, **all comments about the validator's own arms**; `Acceptance test(s)` returns 0; `Independent review` returns 2, both comments. | **rev63** (2 items) |
| **5** | no hand-kept inventory sits beside a derived one | **❌ RED, one duplicate.** The ten-key `artifact_homes` default block is written out in full in two command files and **has already drifted** between them. | **rev62** |
| **6** | every portable lesson from batches 86–89 is encoded with its measured origin or retired with a dated reason | **❌ RED, six remain.** rev60 encoded one of them (instrument-blindness → `C-57`); the counter moves 7 → 6 and does not reset. | **no revision — an operator sitting.** Amended at the `C-45` decision. |

**The dispositions actually written, which differ from the triage that proposed them and the difference is the point.**

| disposition | this pass wrote | the 2026-09-06 triage proposed |
|---|---:|---:|
| **CLOSED** | **5** | 2 (as *closing-at-rev60*) |
| **RETIRED** | **6** | 6 |
| **MOVED** to the code lane | **13** (12 routed + 1 prior move recorded) | 21 |
| **DEFERRED** to the operator | **23** markers / **19** questions | 13 rows |
| **assigned to a flow revision** | **4** existing + **7** newly opened = **11** | 9 |

**Eight of the twenty-one proposed moves were overturned**, each on a measurement or on a standing ruling the triage had not read: three closed instead (a contiguity claim already struck in its own plan; two figure-corrections already delivered in this lane's own registry spec) · three deferred instead (`C-33`, whose normative text is a **flow** file and appears zero times in this project's rules; both `/tui-design` rows, which this file's own scope sentence names as this lane's and which the receiving lane's scope excludes) · one deferred on the receiving file's own words (the unregistered id spaces, which `BACKLOG-CODE.md` already states are *"registered separately in the PROCESS lane"*) · and one re-routed to **rev62** (a `~/.claude` template, which no project-lane batch can edit). **Both are correct classifications of their own reading; the difference is that these were re-measured.**

**Two items the triage dispositioned NOWHERE** were found and disposed of: `map-severity-column` and the vacuous-FIXTURES control candidate — the second of which **carries no band marker and is therefore invisible to every count either backlog publishes**, including the triage's own five bands, whose prose names it.

**The closing plan, unchanged in order and now with its items filed as items:**

- **rev61** — *the instrument prints what it measured*: `ifc-set-repr` · the stale rule census in `commands/dev-flow.md`. ⚠ **The census figure did not survive re-measurement:** the sentence says 28 registered rules and the commissioning brief said 32; `--map` returns **30** today (`V3` and `V24` do not exist). **Verify the reproducibility half under DEFAULT `PYTHONHASHSEED` — pinning it is the vacuous form.**
- **rev62** — *a project born today passes its own gate*: `init-schema-8-fields` · `init-ledger-blocks` · `init-no-batch-dir` · `req-template-v23-example` · `artifact-homes-duplicated`, plus `origin-batch-06-b-1-unresolved` and two one-line derivations in files it already opens. **The arm must plant the OLD seed and reproduce the ghost, or it is a tautology.**
- **rev63** — *a mandate nothing reads is a paragraph*: `R-89-8` · `code-reviewer-absent`, both as a declared field plus a rule, on rev60's own pattern. **Four arms, two of them negative controls.**
- **rev64** — **deferred: it is gated on operator question `Q1`**, which rules the mutation harness's address and, in the same sitting, the named-mutation mandate and the per-node-counterfactual property. **No files are assigned to it here, because assigning them would presume the ruling.**

**The exit criterion is unchanged and is now checkable in one place: the six checks green, re-run from a fresh clone.** Checks 1, 2, 4 and 5 close in revs 61–63. Check 3 is green. **Check 6 closes in no revision at all** — it needs six AskUserQuestions, which is the same sitting as the nineteen questions at the head of [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md). **A queue with a disposition on every row is what “ready” looks like from this side; the operator's list is what stands between it and “finished”.**

⚠ **What this append could NOT verify.** The gate over this project still reports **1 block**, and it is `V16 ~/.claude/skills: uncommitted changes` — a parallel agent mid-edit, an environment fact and not a defect of either repository. **Nothing here was committed**, and rev61's landing is another lane's to confirm.


**➕ 2026-09-07 — rev61 and rev62 shipped; readiness checks 1b and 2 are green.** **rev61** (`~/.claude` `3ec2826`, bundle `0d14241`, `flow_hash ee5715dc55cb4a97`, 629 arms): the selftest transcript is byte-reproducible under the DEFAULT hash seed (`ifc-set-repr` closed); the rule-severity sentence re-measured at **30 registered rules** (V3/V24 do not exist). **rev62** (`e4ba398`, bundle `427e284`, `afb4a237ea0a2a21`, 637 arms): `/dev-flow-init` seeds the 17-key schema, the batch DIRECTORY, a `V26`-clean ledger, a conforming `V23` example; `config.json` retired (3 canon sites, 0 elsewhere); eight `DFI` arms scaffold a project from the command's OWN text and gate it — the RED baseline was 2 BLOCK + 3 NOTICE (one BLOCK more than BRIEF-5 found: `V1` on the seeded `<YYYY-MM-DD>`), now `{V27/NOTICE}` only. Existing projects see nothing (batch-90 worktree byte-identical over every non-S0 rule). Both revs committed as separate, recipe-verified revisions. **rev63 in flight** (check 4: `R-89-8`'s three fields + `Independent review` become read fields). After it, what remains for the flow is the operator's: **rev64 (Q1)** and the **`C-45` sitting** (six lessons) — see `BACKLOG-PROCESS.md` §⏸ Operator questions.

**➕ 2026-09-07 — rev63 shipped; the closing plan's non-ruling revs are DONE. Exit criterion measured from fresh clones.** **rev63** (`claude-config d41447d`, bundle `f7b4f7f`, `flow_hash d1a24a6a3731819f`, **747 arms**): `R-89-8`'s three fields and the independent review are read fields (`V33`–`V36`, NOTICE, S1), `C-58` minted, `dev-flow.md` §Severity re-measured at 34 rules; independent review PASS-WITH-NOTES with all five MEDIUMs folded in. **Readiness, BRIEF-5's six checks, run from a fresh clone of both repos over a clean `git archive` of `s19_app` `origin/main`:** 1a ✅ 747 arms · 1b ✅ (rev61) · 1c ✅ **`0 block`** · 2 ✅ (rev62; its wording must now read *"0 block, every notice typed"* — six rev63 notices are true of a fresh scaffold and `DFI SCAFFOLD-clean` types them) · 3 ✅ · 4 ✅ for the four obligations (remaining unread sections listed in rev63's packet for the D3 sitting) · 5 ✅ · **6 ⏸ — six portable lessons still owe their AskUserQuestion: the operator's sitting.** **What the flow still owes, and only the operator can give:** rev64 (`Q1`, the mutation harness's home; `Q20`, the reviewer-identity refusal), the `C-45` sitting, the D3 classification sitting, and the 20 questions in `BACKLOG-PROCESS.md` §⏸. batch-90 resumes at Inc-1 under rev63 (PR #209).

**➕ 2026-09-07 — THE OPERATOR ANSWERED `Q1`–`Q20` IN ONE SITTING. Every ruling is now a dated disposition at the item it rules in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md); this line is the grouping, not the record.** ⚠ **`rev64`–`rev66` below are PROPOSED GROUPINGS OF THE RULINGS, AWAITING THE OPERATOR'S GO — they are not approved work, not scheduled revisions, and each control in them still owes its own AskUserQuestion under the control-encode rule.** They group by shared mechanism so a reader can see what would land together:

- **`rev64` — the executed-counterfactual group.** `Q1`: the mutation harness enters the FLOW's canon table under `docs/tools/`, hashed by `V7` — Python because its subject is the validator, and **projects keep their own**; it rules three items (the harness, the named-mutation mandate, per-resolved-node-id reporting). `Q20`: `V36` refuses a review cell that names no reviewer identity (`code-reviewer` / `security-reviewer` / a human / `WAIVED-BY-OPERATOR`) instead of a negation blocklist that is incomplete by construction. `Q16`: vacuous FIXTURES folds into `C-57` as a named sub-case, and is **banded `P3` at the same edit** so it stops being invisible to every count. **`Q4`: MEASURED, then ruled** — `C-40` fired **12** times and `C-42` **2**, across six live batches, so the operator's own 0/>0 rule selects **field + rule**: attribute `V33` to `C-40` in the catalog and the rule's docstring, decide whether `V33`'s scope widens beyond `test`/`analysis` requirements, give the increment template's **gate row 11** a reader (a `grep` over the validator returns 0 for it today), and give `C-42` a declared emitted-form field read by a `V9`-shaped rule. Two catalog corrections ride with it: `C-40`'s corpus is **batch-64, not batch-63** (batch-63 cites it zero times), and BRIEF-2's standing *"`C-40` is a paragraph"* is **refuted** — corrected in the backlog and the catalog, **not** by editing the dated brief.
- **`rev65` — the state/derived-artifact group.** `Q7`: a **BLOCK** rule — `current_station` must have that station's artifact family (`01-*` / `02-*` / `04-*` / `05-*`) on disk **and not be the empty template**; this closes the PROCESS lane's only remaining `MAJOR`, whose count is **left at 1 until rev65 lands**. `Q8`: a written convention (one active batch per checkout; parallel work takes a worktree) plus an `owner` field in `state.json` compared by a NOTICE rule with the tree the gate runs in — **no lock**, because the convention says there are no concurrent writers. `Q18`: a rule guarding a derived artifact depends **only on versioned content** (empty directories ignored, existence via `git ls-files`), plus an arm that plants an empty directory.
- **`rev66` — the evidence-and-deferral group.** `Q5` + `Q19` as **ONE control with two exhibits**: evidence bytes live at a home declared in `artifact_homes` (`repo:` / `vault:`), stored verbatim, hash-verified at close, with a NOTICE rule requiring the declared home. `Q6`: a declared `⏸ DEFER` marker valid in `.dev-flow/design/` and ADRs, plus a NOTICE census counting markers absent from the backlog.
- **Measurement in flight:** **BRIEF-6** for `Q11`, the D3 classification sitting — the brief first, then an interview; its four items are marked ⏳ **AWAITING BRIEF-6** and their bands are unmoved. *(`Q4`'s sweep was also in flight at the sitting and **landed**; it is folded into `rev64` above rather than left pending.)*
- **Retired:** `Q2` (`V31`'s per-instrument field is the mechanism) · `Q3` (`F-8` subsumed by `C-14` widened + `V32`, rev60) · `Q9` (`C-55` declined permanently — no exhibit since 2026-08-15, `C-57` covers the sweep) · `Q10` (all three limbs — multi-artifact corrections, recorded as `C-14` exhibits) · `Q12` (`--map` keeps rev57's wording) · `Q13` (`C-33` — **0** occurrences in the project's engineering rules, no executable discharge) · `Q17` (one identity; two hashes are two inventories).
- **Moved:** `Q14`, both `/tui-design` rows — to `~/.claude/skills/tui-design/` in the `agent-skills` repo. ⚠ **Outside `s19_app`: no landing bullet in either lane file, and not verifiable from this repository.** `Q15` — to [`BACKLOG-CODE.md`](../BACKLOG-CODE.md) as a **dated charter for batch-91** (extend the registry's `space` to the requirement / low-level-requirement / user-story spaces **after batch-90 lands**), deliberately not filed into a band.

**The PROCESS lane's queue, re-derived rather than decremented: `P0` 0 · `P1` 8 · `MAJOR` 1 · `P2` 6 · `P3` 7 = 22 open**, from 32 — **8 retired, 3 moved, and 1 arriving by being BANDED rather than opened.** ⚠ **The re-derivation found a defect the published figure hid:** the pre-sitting `P1` of 11 was correct as a total and wrong as a membership — a filtering counter reads `code-reviewer-absent` as open (its closure verdict sits on the line *above* the banded bullet) and misses `per-node-counterfactual`, two errors of one each that cancelled. `R-89-8` in `P2` is the second instance. **The counter now carries a fifth drop class for it and was shown red on planted decoys before its 22 was believed.**

**➕ 2026-09-07 — D3 SITTING HELD ON BRIEF-6: 18 CONFIRMED (6 retire, 12 re-scope), REVS A–D JOIN THE CLOSING SERIES AFTER `rev64`–`rev66`, E/F ARE NEXT STAGE; `rev64` IS IN FLIGHT.** The operator ruled BRIEF-6 row by row in an interview on 2026-09-07. **Every ruling is now a dated disposition at the item it rules in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md); this block is the ordering and the residue, not the record.** The brief's population was **33 rows / 34 dispositions** — **16 execute · 6 retire · 12 re-scope** — and **the operator confirmed the 6 retires and the 12 re-scopes in bloc.** ⚠ **Only SEVEN of the thirty-three rows are backlog items**; the rest are template sections and orphan controls that have never had a bullet in either lane, and they are listed below rather than minted — a row whose disposition is *“nothing to do”* does not become queue work by being ruled.

**THE SERIAL ORDER, AND IT IS SERIAL BECAUSE `~/.claude` ADMITS EXACTLY ONE AUTHOR AT A TIME:** `rev64` → `rev65` → `rev66` → **A** → **B** → **C** → **D**, then **E** and **F**. Each is ≤5 authored files. ⚠ **None of this is approved work** — the groupings are the rulings' shape, and every control in them still owes its own AskUserQuestion under the control-encode rule.

| # | what it ships | which readiness check it serves |
|---|---|---|
| **`rev64`** *(in flight)* | the mutation harness into the flow's canon under `docs/tools/`, hashed by `V7` (`Q1`, three items) · `V36` refuses a review cell naming no reviewer identity (`Q20`) · vacuous FIXTURES folds into `C-57` and is banded (`Q16`) · **`Q4`'s field + rule: `C-42`'s emitted-form assertion and gate row 11's per-arm verdicts** | **check 4** (a mandate nothing reads is a paragraph) and **check 1** — a canonical harness is what makes an executed counterfactual re-runnable instead of a throwaway |
| **`rev65`** | `current_station` must have its station's artifact family on disk and not be the empty template, as a **BLOCK** (`Q7`) · the one-active-batch convention + an `owner` field read by a NOTICE rule (`Q8`) · a derived-artifact rule that depends only on versioned content (`Q18`) | **check 2** (a project born today passes its own gate) — and it is the revision that takes the PROCESS lane's last `MAJOR` from **1 → 0**, when it lands and not before |
| **`rev66`** | evidence bytes at a home declared in `artifact_homes`, verbatim, hash-verified at close (`Q5`+`Q19`, one control) · a declared `⏸ DEFER` marker + a NOTICE census of markers absent from the backlog (`Q6`) | **check 6's neighbourhood** — it does not encode the six lessons, but it is the pair of controls that stop a deferral or an evidence blob leaving the record unread |
| **Rev A** | `increment-template.md`: the **`Reverse census`** section (**0 of 6** batch-89 packets, **7 of 246** overall) **and gate row 4** (`RED counterfactual captured and restored by hash`), extending `_v60_field`'s row grammar that already reads rows 12 and 13 | **check 4.** ⚠ **NARROWED BY THE OPERATOR:** BRIEF-6 §3 also put `C-42`'s emitted-form row and gate row 11 in Rev A; both stay at **`rev64`**, where `Q4` already ruled them, so **Rev A is `Reverse census` + gate row 4 only** |
| **Rev B** | `req-template.md`: **`Premise evaluation`** — the section whose own control the flow calls MANDATORY AT EVERY GATE and which is the **most-cited control in the catalog**, while **69 of 81** requirement documents lack the section · the **`Dual traceability` heading deleted** (its body is already a retirement notice; **14 of 81** copied it forward) · the **four fork preconditions**, gated on `stations_active`, **14 of 17** lane/fork batches naming none of them | **check 4** — and the deletion is what pays for the two additions in reading cost |
| **Rev C** | `validation-template.md`: the keyed **`- **Result:**`** line with the alternation moved out of the value position (**55 of 64** records state no readable verdict) · **`Evidence checklist`** · **`Layer 0` — unit** (**62 of 64** records absent) · the **supersession line**, free inside the same block | **check 4** — the batch verdict is the single most load-bearing fact the flow produces, and 86% of validation records do not state it in a form anything can read |
| **Rev D** | `close-template.md` + the catalog: **`Conditional-gate discharge`** · the **`C-45` landing row** (catalog/command/project as keyed cells) · the **owed catalog entry for the vacuous-check shape** · the **lineage strike of the control registered with no encoded text** · the **origin tag on `V9`** for the increment-budget control | **check 4**, and the one revision that touches **check 6**: the landing row is the instrument that counts the `C-45` debt **without a sitting**. ⚠ It does not encode the six lessons and discharges no AskUserQuestion |
| **Rev E** ⏭ | **the forward-applicability control, alone (3 files)** — that table's reader. **0 of 949** files in the record have ever contained one, against a template section, two checklist rows and a command paragraph that all demand it | **next stage.** The row is now an item: [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) §*Opened 2026-09-07 by the D3 sitting on BRIEF-6* |
| **Rev F** ⏭ | **the `::symbol` resolver, alone (2 files, no template edit)** — **41 of 589** resolved symbol anchors name a symbol that is not in the file they name | **next stage.** ⚠ **The line-anchor half is NOT built:** 69% of the 9079 line anchors cannot be resolved to a file at all, so that check cannot be written honestly, and the ruling says so rather than minting a gate everyone waves through |

**THE OPERATOR'S RULING ON HOW THE SERIES RUNS: per-rev REPORTS, no per-rev STOP.** Each revision reports when it lands — what shipped, what the gate read, what the selftest returned — and the next one starts without waiting for an approval turn. **The stop is at the end of the series, not inside it.** ⚠ This does **not** relax the control-encode rule: a revision that would mint or amend a control still owes its own AskUserQuestion before that edit, and the series' freedom to run is a freedom about **sequencing**, not about approvals.

**RULED IN BRIEF-6, NO BACKLOG ITEM — the twenty-six rows that took a disposition in the brief and correctly have no bullet in either lane.** *(Listed here so the classification is complete without the queue growing to hold it.)*

- **Orphan controls (4), named by SUBJECT rather than by id** — see the note below: **the increment-budget control (b)**, retired as *orphan status only*, since it is already the loudest rule in the gate at **231 `V9` notices standing** and what it lacks is a one-line origin tag, which rides Rev D · **the Layer-0 unit control (a)** — **62 of 64** validation records absent, and it is the **same decision** as Rev C's `Layer 0` row, not a second one · **the fork-preconditions control (a)** — **14 of 17** lane/fork batches name none of the four; ships in Rev B · **`C-46` (c)** — a paragraph, correctly: **the plan's claim that it is an orphan is struck**, `increment-template.md` §4 cites it.
- **`increment-template.md` (4 rows):** `Reverse census` **(a)** · gate row 4 **(a)** · gate row 11 **(a)**, at `rev64` · **gate rows 1, 2, 3, 5, 7, 8, 9, 10 (c) for this sitting only** — ⚠ **they were outside the commissioned population and are UNMEASURED**; BRIEF-6's own recommendation is one follow-up measurement **before** Rev A, not a ruling today, and leaving eight rows of the same table unclassified would re-create the gap this sitting exists to close.
- **`req-template.md` (6 rows, 7 dispositions):** `Premise evaluation` **(a)** · `Dual traceability` **(b)** · §7 the ledger **(c)** — **the positive control**, already read by `V26`, included to prove the other zeros are readings · the IEEE-830 container sections §1.1–§1.5 / §2.1–§2.5 / §6.1–§6.3 **(c)** — no field can be minted over them that could fail for a substantive reason · §6.4 **(c)** / §6.5 **(b, subsumed by `V26`)** — the row that splits · `Refinement log` **(c)**, never declared mandatory.
- **`validation-template.md` (6 rows, 7 dispositions):** `✅ Verdict` **(a)** · `Evidence checklist` **(a)** · `Layer 0` **(a, = the Layer-0 unit control above — one decision, not two)** · the supersession line **(a, free)** · `UX walkthrough` **(c) for now** — ⚠ its precondition corpus **does not exist yet**: `triggers` was seeded by `rev62` and no closed batch carries one, so the retroactive number is not computable · the four minor sections — `Signed-balance test ledger` **(b, subsumed by `V5`)**, `Bidirectional` / `Gaps detected` / `Escaped-bug` **(c)**, the second row that splits.
- **`close-template.md` (4 rows):** `Conditional-gate discharge` **(a)** · the `C-45` landing row **(a)** · §5 `Batch metrics` **(c)** — and **the plan's `31-key schema` is not a contradiction of the template's `12 keys of core`**: `dev-flow.md`'s mode table splits them · §3 `Working-file reconciliation (C-44)` **(c)** — a rule reading a markdown section can only verify that a sentence claims the reconciliation happened, which is a vacuous check by construction.

**AND THE SEVEN THAT ARE ITEMS, with where their dated disposition now sits in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) — addressed the way that file addresses its own rows, by section and opening words:** the **batch-88 per-rule enumeration** ▶ **EXECUTE**, no rev — its *cannot be re-derived* premise is **false**, the `rev47` validator being on disk at `52866e6` · the **owed vacuous-shape catalog entry** 🕒 **rev D** · **`R-88-8`** ↔ **RE-SCOPED** to the project's own rules · **`R-88-3`** ↔ **RE-SCOPED** to [`BACKLOG-CODE.md`](../BACKLOG-CODE.md), where it now has a live entry · the **symbol-anchor row** ⏭ **NEXT STAGE** (rev F, narrowed to `::symbol`) · the **`R-c` length check** ♻ **RETIRED** · the **lineage entry with no encoded text** ♻ **RETIRED**. All seven live under §*Routed from batch-88 and batch-89*, §*Routed from batch-79* and §*SHIPPED — control encoding*. **That lane's queue re-derives to `P0` 0 · `P1` 8 · `MAJOR` 1 · `P2` 6 · `P3` 6 = 21**, from 22, by the filtering counter shown red on planted decoys — **and the counter cannot see a re-scope**, which that lane's index now states rather than leaves for the next pass to find.

⚠ **SIX OF THESE ROWS ARE NAMED BY SUBJECT AND NOT BY ID, DELIBERATELY** (`C-56`: writing an id under `.dev-flow/` declares it to the id scanners, and six of the controls and carries this sitting rules — four orphan controls and the two batch-88 gap carries — appear **nowhere** in this file, so naming them here in order to summarise them would **mint** them here). **Their ids are in BRIEF-6 and at their items in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md), where they were already declared.** Same posture as [`BACKLOG-CODE.md`](../BACKLOG-CODE.md) §*Received from the PROCESS lane*.

⚠ **WHAT DID NOT SURVIVE MEASUREMENT AND IS RECORDED RATHER THAN CARRIED.** The plan's *“11 orphan controls”* is **5**, and it is 5 at `rev55`, `rev56` and `rev63` — no definition returns 11 · `C-46` was **never** an orphan · the batch-88 enumeration carry's unrecoverability is **false** · `R-88-8`'s remedy is **already true** of the flow (0 line-phrased thresholds in `commands/` + `templates/`) · the `R-c` check **does not exist in `~/.claude` at all** · and the owed catalog entry's *“ELEVENTH shape”* has no list of ten behind it, so the ordinal is fixed or dropped in the same increment that writes the entry.

**➕ 2026-09-10 — RESUMED AFTER THE WEEKLY API LIMIT CUT `rev65` MID-REVIEW-7 ON 2026-09-08; AN EXTERNAL CODEX-SESSION REVIEW CONTRIBUTED FOUR VERIFIED DEFECTS, TWO QUESTIONS AND ONE NEXT-STAGE ITEM; **Rev G** IS ADDED TO THE SERIAL ORDER; THE CODEX ADAPTER IS SET ASIDE BY THE OPERATOR.** `rev65` was in flight when the limit hit and resumed on 2026-09-10; **its `V7` / `V15` / `V16` / `V20` gate footprint is expected and is not a defect of either repository.** In the gap, a Codex session reviewed `/dev-flow` on 2026-09-08 and **wrote a handoff instead of executing anything** — which is the right shape for an outside reading of a flow it had no authorization to change.

**The handoff is on the record, verbatim.** It is copied byte-identically (SHA-256 equal) into the flow repo at `docs/analysis/briefs-2026-09-03/HANDOFF-codex-review-2026-09-08.md`, beside the six briefs of 2026-09-03 and the `Q4` brief. ⚠ **Its references are LINE numbers dated 2026-09-08 and are deliberately NOT carried forward** into the backlog: every item it produced cites a symbol or a §section → *“opening words”*, re-measured at `~/.claude` HEAD (`405c083`, flow `rev64`) on 2026-09-10.

**Seven findings in, four dispositions out — stated by disposition, because the shape of the intake is the interesting part.**

| the finding | disposition | where it now lives |
|---|---|---|
| the invocation steps read the pre-station field pair `/dev-flow-init` is forbidden to write | **item, `P1`**, 🕒 **Rev G** | [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) §*Opened 2026-09-10 by an EXTERNAL review* |
| the phase instructions still write flat `.dev-flow/NN-name.md` paths — the *ghost* shape `V18` reports | **item, `P1`**, 🕒 **Rev G** | same section — **same population as the row above**: `rev62` repaired `/dev-flow-init` and never swept `/dev-flow` |
| the command's ≤4 SOURCE budget against the invoked skill's ≤5 TOTAL, with no precedence declared | **item, `P2`**, 🕒 **Rev G** | same section. ⚠ **The diagnosis PREDATES the handoff** — it was made here on 2026-09-06 in the `rev57` overflow analysis and **was never executed**, which is recorded at the item |
| *“p90 = 6 source files”* and *“95.3 % of increments touch ≤4”* cannot both describe one population | **item, `P2`**, 🕒 **Rev G** | same section. **Neither the review nor this pass reproduced the calculation**, and the item says so; the derivation script exists at `~/.claude/docs/analysis/increment-file-history.py` |
| precedence between per-batch `standing_authorization` and per-gate approval is unstated | **`Q21`**, UNANSWERED | [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) §⏸ *Operator questions*. **Measured 2026-09-10: *precedence* and *overrides* occur 0 times in `commands/dev-flow.md`** |
| `artifact_homes.postmortem` is `vault:` while init also creates `05-postmortem.md` locally, and PDR/DDR demand vault writes the hard rules forbid | **`Q22`**, UNANSWERED | same table — *who writes PDR / DDR / postmortem, when, and which copy is canonical per mode* |
| package `/dev-flow` as a skill a second runtime can discover | **item, `P3`**, ⏭ **NEXT STAGE** | §*Opened 2026-09-07 by the D3 sitting on BRIEF-6*, with Revs **E** and **F**. **The operator set it aside on 2026-09-10** |

**Two observations correctly produced NO item and are recorded here instead.** *(a)* The review ran `--map` at `rev65` and read **2 of 26 files differing, 5 blocks, ~2,249 uncommitted lines**, and called it **a revision in flight** rather than a defect — which is exactly right, and is the reading this plan would want an outside reviewer to make. *(b)* `--help` is not a validator option: passing it runs a **normal validation**. Verified here on 2026-09-10 — the transcript of `--help` over this project is **byte-identical** to the plain run and exits **1**. That is one line of **Rev G**, not an item.

⚠ **AND ONE ASSERTION OF THE HANDOFF DID NOT SURVIVE RE-MEASUREMENT, which is written before its findings are used.** It reports that the command's own `artifact_homes` **defaults** are flat as well. **They are not, and have not been since `rev62`:** `/dev-flow` §`state.json` schema carries a **pointer** where the block used to be (*“the ten default homes are declared ONCE, in /dev-flow-init step 3…”*) and the single surviving inventory is **batch-scoped in every `repo:` value**. That is `artifact-homes-duplicated`, closed at `rev62`, and readiness check 5's one duplicate. **The flat-path defect is real anyway and is larger than the handoff's single example** — **13** flat artifact paths, **10** of them operative phase instructions — so the correction narrows the cause and retires nothing, and **no fifth item was opened for it**.

**THE SERIAL ORDER, AMENDED 2026-09-10 — `rev64` → `rev65` → `rev66` → **Rev G** → **A** → **B** → **C** → **D**, then **E** and **F**.** **Rev G** enters **after `rev66` and before Rev A**, and it is still serial for the reason the rest of the series is serial: `~/.claude` admits exactly one author at a time. **It is tagged `rev G` at its items** in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md). ⚠ **None of this is approved work**, and the control-encode rule is untouched — though **Rev G** mints no control, which is part of why it is cheap.

| # | what it ships | which readiness check it serves |
|---|---|---|
| **Rev G** *(added 2026-09-10)* | **command reconciliation** — the retired schema pair removed from the invocation steps so the compatibility rule has a reader · the flat artifact paths replaced in the phase instructions and in the schema's own example · the file-budget precedence with `supervised-incremental-development` settled in one direction and named once · the `p90` / `95.3 %` figures **re-measured with the derivation script** or struck · `--help` given a real behaviour or a stated absence | **check 5** — *no hand-kept inventory sits beside a derived one*: the budget paragraph's figures sit beside a script that derives them, and the budget itself sits in two documents that disagree — **and check 2's other half.** Check 2 reads *a project scaffolded by following `/dev-flow-init` gates clean*; `rev62` closed that. **A project born today is RUN by `/dev-flow`, not only seeded by `/dev-flow-init`**, and the running half is what these two command-side items measure |

**Rev G's files, ≤5 as every revision of this series is:** `commands/dev-flow.md` · the skill's `SKILL.md` · `docs/FLOW-VERSION.md` · the validator — for **one arm that greps the command for the retired pair outside the rollover table and the schema sentence, and for flat artifact paths, proven RED on a planted occurrence of each** — · and a catalog line **if** the reconciliation turns out to owe one. ⚠ **The arm is the half that makes this checkable:** two of the four defects are *a sweep must return 0*, which is the shape that goes vacuous unless the plant is shown first. **`C-14`'s lesson is the reason Rev G exists at all** — `rev62` corrected `/dev-flow-init` and left the population's other member, `/dev-flow`, unswept for two revisions.

**What this append could NOT verify.** The gate over this project reads **10 block · 321 notice · 31 not applicable** before and after this documentation pass, unchanged — the blocks are `V15` / `V16` / `V7` on a flow repository mid-revision, which is `rev65` in flight and another lane's to resolve. **Nothing here was committed or staged**, no flow file was edited, and **Rev G is a plan, not a landing**: no count in either backlog moves on its account.


**2026-09-10 — TWO MORE EXTERNAL HANDOFFS INTEGRATED, AND A THIRD, AND THE SERIAL ORDER GAINS TWO REVISIONS AT ITS TAIL.** Three handoffs arrived the same day, each written by a session that read something and executed nothing, and each is copied **verbatim** into the flow repo at `docs/analysis/briefs-2026-09-03/`. **(a) A templates audit** of all fourteen `templates/dev-flow/` files against `/dev-flow-init`, both commands and the validator's own functions — **ten findings, all ten survived re-measurement at `~/.claude` HEAD (`51bfebf`), all ten are items** in [`BACKLOG-PROCESS.md`](../BACKLOG-PROCESS.md) §*Opened 2026-09-10 by an EXTERNAL templates audit*, grouped by the FILE each corrects: **4 → Rev B** (`req-template.md`), **1 → Rev C** (`validation-template.md`), **1 → Rev D** (`close-template.md` + the catalog), and **4 that belong to no single file → Rev H**. **(b) Five candidate controls** from OUTSIDE this flow's corpus — a course verification harness, an agent-rewritten skill, a commercial tool and the handoff author's own VCS misdiagnosis — which are **NOT items**: they are input for the `C-45` catalog sitting, written as **`Q23`**, one row with a rule and an assessment per candidate, so five can be answered at once. **(c) An agents reconciliation** of the seven technical agents against both commands — **one item**, `P2`, 🕒 **Rev I**, because its seven verified contradictions are one population with one closure, plus **`Q24`**, whether `agents/tester.md` is created and `tester` joins `V36`'s reviewer-identity set.

**THE SERIAL ORDER, AMENDED AGAIN 2026-09-10 — `rev64` → `rev65` → `rev66` → Rev G → A → B → C → D → **H** → **I**, then E and F.** **Rev H** is **minted by the templates audit** rather than assigned from the D3 sitting, and it enters **after Rev D**: *cross-template contract — the reserved vocabulary the parsers read literally; mode applicability across the shared templates; the IFC promise of a detection `V11` does not perform; and the Phase-2 return path.* **Rev I** enters after it: *agents reconciliation.* ⚠ **Rev A is in flight on `increment-template.md` as this was written**, which is why one Rev H finding that touches that file is filed for H rather than folded into A — a revision already being authored is the wrong place to add scope. ⚠ **None of this is approved work,** and **Rev I is not closing-series work by default:** five of the seven agent files sit outside `V7`'s hashed canon (`agents/ux-reviewer.md` since `rev12` and `agents/software-dev.md` since `rev67` are the two inside), so nothing in the manifest reddens while they disagree — whether it joins the series at all is part of `Q24`'s answer.

**WHAT THIS APPEND RE-MEASURED, AND THE TWO CLAIMS THAT DID NOT SURVIVE.** Every verdict was re-verified against `~/.claude` **HEAD** and never against the working tree, which was mid-`rev68`. *(i)* The ledger finding is argued in its source from *“real batches (89, 90)”*; **batch-90 does not exist** — `state.json` still names `2026-08-28-batch-89`, and the only ledger on disk is that batch's, **24 entries, all of the short form** — so the conclusion holds and is narrower than written: what is broken is the template's recommendation, not a live record. *(ii)* The agents handoff reports `/code-review` as *not found as a skill in the two installations nor as a local command* and recommends replacing the reference; **`/code-review` is a Claude Code BUILT-IN skill**, so both absences are correct and the finding is a **portability note** — it resolves for Claude Code and does not resolve for Codex. **And two readings came out stronger than their source:** `cardinality` is read by **no rule at all** in the validator (6 occurrences, every one an Atlas column, a fixture string, an arm name or a test dictionary), and **two templates ORDER** the translation of labels the parsers read literally, which the audit did not say.

**BACKLOG EFFECT, AND WHAT THIS APPEND COULD NOT VERIFY.** The process lane moves **26 → 37 open** (`P0` 0 · `P1` **13** · `MAJOR` 1 · `P2` **14** · `P3` **9**), re-derived by the same filtering counter and **shown red on planted decoys before the figure was believed** — a raw marker sweep moves **84 → 86** on a decoyed copy while the filtering counter moves **37 → 38** and names the struck decoy in its drop list. **Nothing arrives in the code lane:** all eleven items are flow-side, and [`BACKLOG-CODE.md`](../BACKLOG-CODE.md)'s cross-lane top carries the mirror. The gate over this project is **unchanged before and after this documentation pass**; its standing blocks are `V7` / `V15` / `V16` / `V20` against a flow repository mid-revision, which is another lane's to resolve. **Nothing was committed or staged**, no flow file was edited, and **Rev H and Rev I are plans, not landings**: no count moves on their account.

**2026-09-10 — rev64…rev68 closures written into the backlog (14 items), remaining open by rev: B/C/D/H/I = 4/1/1/4/1 (11 total).** Every backlog item tagged `🕒 CLOSING AT flow rev64`, `rev65`, `rev66` or `rev G` (`= rev67`) found its subject named in that rev's own `docs/FLOW-VERSION.md` changelog row and was closed in place with a `✅ CLOSED` line, a `~/.claude` + `~/.claude/skills` SHA pair, `flow_hash` and arm count, one line of quoted evidence, and the item's band marker converted to its `was`-form — none deleted, per this file's no-deletion rule. **No item was tagged `🕒 CLOSING AT flow rev A` (`= rev68`) anywhere in either backlog file** — rev68's own two rules (`V43` Reverse census, `V44` RED counterfactual) close BRIEF-6's own two rows directly and mint no separate backlog item, so rev A's closure count is **0 of 0**, not a miss. `revs B/C/D/H/I` stay tagged and untouched, exactly as scoped: **Rev B 4** (`req-template.md`'s four defects), **Rev C 1** (`validation-template.md`), **Rev D 1** (`close-template.md` + the catalog), **Rev H 4** (the cross-template contract), **Rev I 1** (agents reconciliation, seven contradictions as one item) — **11 items**, matching this file's own "THE SERIAL ORDER" paragraph above. `BACKLOG-PROCESS.md`'s re-derived index: `P0` **0** · `P1` **13 → 5** · `MAJOR` **1 → 0** · `P2` **14 → 11** · `P3` **9** = **37 → 25 open**, by the filtering counter of rule 6, shown discriminating on a planted open/closed decoy pair before being believed (open decoy `P1` 5 → 6; closed `was`-form decoy stayed 6). `BACKLOG-CODE.md`'s cross-lane mirror rows for the four closed items carrying a code-lane twin were updated to match, CRLF preserved (`file` reports CRLF unchanged; `BACKLOG-PROCESS.md` stays pure LF, 0 CRLF bytes). Gate over this project, before/after this pass: **5 block · 344 notice · 34 not applicable → 6 block · 344 notice · 34 not applicable** — the sole diff is `V7`'s reported local-flow hash (changed because `~/.claude` moved under the parallel rev69 session between the two runs, not because of this pass) and one new `V15` bundle-mismatch BLOCK, both the parallel session's declared footprint; **zero new `V22`/`V23` findings and zero findings naming `BACKLOG-*`** (diffed line-for-line). **Current flow identity: rev68, `5a71ebb829aeaaac`, 1106 arms, 27 manifest files.**

**2026-09-11 — the `C-45` sitting held on BRIEF-7: 10 confirmed in bloc, two mints (subject-named — see below), four work items routed (the `V12` OUTPUTS bug and three others → `rev74`; the conda-run project half → `batch-91`). Series extended: `rev73` (Rev I, in flight) → `rev74` (three flow fixes) → `rev75` (the catalog sitting) → final backlog pass → exit criterion from a fresh clone.**

⚠ **ONE OF BRIEF-7'S OWN PROPOSALS DID NOT SURVIVE THIS PASS'S VERIFICATION, AND IT IS SAID BEFORE THE FIGURE IS USED.** BRIEF-7 proposes minting the census-over-axis candidate as `C-63` and the flaky-class candidate as `C-64`. **Both ids were already taken, the same day, by flow `rev71`** (`4d5da2c`, `Q23`, committed *before* this sitting): `C-60`/`C-62` minted, `C-63` folded into `C-57`, `C-64` a rider on `C-44`, over a five-candidate corpus BRIEF-7 never read (verified by reading `dev-flow-lessons/SKILL.md` at `~/.claude/skills` HEAD `82c6c5c`, headings `#### C-60` and `#### C-62`). **Both mints are therefore transcribed by subject** ("the census-over-axis candidate," "the flaky-class candidate") **rather than by number**, per this project's own `C-56` id-collision rule — the real numbers land wherever the catalog's `controls:` derivation puts them at `rev75`.

**Also verified rather than assumed, at this pass:** the P0-scaffold candidate's `🕒 CLOSING AT flow rev62` marker in `BACKLOG-PROCESS.md` was stale in the other direction — `rev62` (`e4ba398`) DID ship it (*"the batch record is `.dev-flow/<batch_id>/` in all ten step-4 destinations"*), and the marker had simply never been converted to `✅ CLOSED`; the evidence-transcript candidate's marker was similarly stale, still reading *"needs its AskUserQuestion"* seven weeks after it shipped as `C-56` (`02238d4`, 2026-08-24). Both confirmed at their items rather than re-opened.

**BACKLOG EFFECT.** `BACKLOG-PROCESS.md`'s index moves `P3` **9 → 10** (one work item opened, `c58-severity-census-arm`, 🕒 flow `rev74`); `P0`/`P1`/`P2`/`MAJOR` unmoved — the sitting's other three work items (the `V12` OUTPUTS balancing bug at `P1`, the Atlas phantom-stem code fix at `P2`, the conda-run project half at `P2`) are recorded in the batch-87/86 sections' own narrative-blockquote style, matching how the six lessons themselves are carried, rather than as new live queue markers; the ten FOLD/RIDER/MINT dispositions carry no band at all, on the same convention. Re-derived: `P0` **0** · `P1` **5** · `P2` **11** · `P3` **10** · `MAJOR` **0** = **26 open**, by the filtering counter of rule 6, shown discriminating on a planted open/struck decoy pair before being believed (struck `P3` decoy dropped, stayed 10; open `P2` decoy counted, 11 → 12). `BACKLOG-CODE.md`'s own count is **unchanged at 108** (`P0` 0 · `P1` 6 · `P2` 35 · `P3` 60 · `MAJOR` 7) — the two batch-91 charter arrivals are deliberately unbanded, on the same not-workable-until-batch-90 rule the registry-`space` charter already uses — and its cross-lane top carries the PROCESS-lane mirror. Line endings verified: `BACKLOG-PROCESS.md` and this file stay pure LF; `BACKLOG-CODE.md` stays CRLF, unchanged by the added text. Gate over this project, before this pass: **11 block · 348 notice · 35 not applicable**; the eleven blocks are `V38`–`V51`-family "no such field in the active batch's artifact" findings against the ACTIVE batch (`2026-08-28-batch-89`, long closed) rather than anything this pass touched — verified unmoved after this pass, same eleven, byte-identical finding text. **Zero new `V22`/`V23` findings and zero findings naming `BACKLOG-*`**, diffed line-for-line against the before transcript. **Nothing was committed or staged**, no flow file was edited. **Current flow identity, unchanged by this documentation-only pass: rev72, `859fc46a70a3eb95`, 1358 arms, 27 manifest files.**

**2026-09-11 — rev61…rev63 leftover tags + rev68…rev73 closures written (19 items: rev61 2 · rev62 5 · rev68/A 0 of 0 — no item was ever tagged for it, rev68's own two rules close `BRIEF-6`'s two rows directly · rev69/B 4 · rev70/C 1 · rev71/D 2 · rev72/H 4 · rev73/I 1); the closing series 61–73 is SHIPPED except three rev62 items left tagged and unclosed — `origin-batch-06-b-1-unresolved`, `next-session-controls-stale`, `flow-version-unnumbered-hand-kept` — none names its subject in rev62's own changelog row or commit message, checked against every one of the nine revs in scope, not rev62 alone. `Q21`/`Q22` marked ✅ **EXECUTED at flow rev72** (`730e63e`), `Q23` at flow `rev71` (`4d5da2c`), `Q24` at flow `rev73` (`718f7b6`) — all four were `⏸ UNANSWERED` before this pass. `BACKLOG-PROCESS.md`'s re-derived index (rule-6 filtering counter, decoy-verified on a planted open/closed pair — open decoy counted, closed `was`-form decoy dropped): `P0` **0** · `P1` **5 → 0** · `P2` **11 → 3** · `P3` **10 → 6** · `MAJOR` **0** = **26 → 9 open**. `BACKLOG-CODE.md` needed no mirror edit — none of the nineteen closed items carries a code-lane twin (all nine revs in scope are flow-side: `~/.claude/templates/`, `~/.claude/commands/`, `~/.claude/docs/tools/devflow-validate.py`, `dev-flow-lessons/SKILL.md`). Gate over this project, before/after this pass: **5 block · 348 notice · 34 not applicable → 6 block · 348 notice · 34 not applicable** — the sole diff is one new `V20` BLOCK on `.dev-flow/_derived/ATLAS-ORPHANS.md` (the derived-atlas cache is now stale against ids this pass's closures reference; regenerating it is `--atlas --write`, outside this lane's editable-files list, so it is reported rather than fixed). **Zero new `V22`/`V23` findings and zero findings naming `BACKLOG-*`**, diffed line-for-line against the before transcript. **Nothing was committed or staged.** Line endings verified: `BACKLOG-PROCESS.md` stays pure LF, 0 CRLF bytes. **Current flow identity, unchanged by this documentation-only pass: rev73, `1330ed31b54fa01d`, 1369 arms, 34 manifest files.**
**2026-09-11 — SERIES CLOSED at rev75 (final closure pass).** rev74 = 3 fixes (V12 OUTPUTS guard, Atlas wildcard code-half, severity-census arm; canon `29da5f6` / skills `671dd8d`, 1395 arms) and rev75 = catalog sitting on BRIEF-7 (C-65 census-over-axis, C-66 flaky class, C-40/C-58 riders, C-19 conda-run global half; canon `4f59a3d` / skills `145f135`, `flow_hash 6b971eaeca008392`, 1399 arms, 34 files, 31 numbered controls C-10…C-66). Exit criterion re-measured from fresh clones: selftest ×2 and two runs 0 diff, recipe = declared hash, `--map` 34/34 + 31/31, gate over `git archive origin/main` = 1 block (V16, other sessions' uncommitted skills work, since landed as skills `3d8a11e`). `~/kimi/agent-skills` fast-forwarded to the same tree. Batch-90 P0+P1 merged (PR #209, `b37e9a8`). `BACKLOG-PROCESS.md` open after this pass: **8** (P2 3 · P3 5); `BACKLOG-CODE.md` charter rows for C-19 / C-66 corrected to rev75. Remaining, next stage: Javier's `CLAUDE.md` file-cap line (his to update), batch-90 Inc-1 under rev75, batch-91 charter, E (C-49), F (`::symbol` resolver), Codex adapter, `--flag` silently absorbed.



## 0 · The plan at a glance

**The critical path is: rev56 (small, verified repairs) → close batch-89 → everything else.**
The one hard coupling in the whole intake is that `/dev-flow-sync`'s pre-requisite 2 cannot pass for
a `core` batch (verified today: `~/.claude/commands/dev-flow-sync.md:39` hardcodes "`P6`, or `6`";
`state.json` declares `mode: core`, `current_station: P3`), and batch-89 — merged, built, unclosed —
is the first batch that will ever hit it. `V28`'s hole becomes permanent only when batch-90's
directory opens, and no such directory exists today, so **the window is under our control: nothing
opens batch-90 until step 2a completes.**

| # | step | repo | depends on | closes (by id) |
|---|---|---|---|---|
| 0 | Operator rules D1–D6 (proposed rulings: §2) | — | — | — |
| 1 | **rev56 — tranche 1**: the verified repairs, with P1c corrected per input §1.6 | `claude-config` | ruling D1 | fixes the `sync-P6` defect (closure proven at 2a) |
| 2a | **Close batch-89**: `04-validation.md` + `05-close.md` + backlog reconciliation + merge + `/dev-flow-sync` | `s19_app` | step 1 pushed | `batch-89-unclosed` (P1) · proves `sync-P6` (P1) closed |
| 2b | **rev57 — tranche 2**: P3 completed to its full population + P7 with the severity sentence fixed + the origin-parenthetical rule (+ the instrument-blindness law, if its AskUserQuestion is approved) | `claude-config` | step 1 (serial in the flow repo); **parallel with 2a by file ownership** | `R-89-3` (P2) |
| 3 | **rev58+ — validator series**: V2 limbs 1+2 · `mode`↔`stations_active` NOTICE · `--map` prints severity · `ifc-set-repr` | `claude-config` | 2b (serial in the flow repo) | `R-89-6`+`R-89-7` (**P0**) · `ifc-set-repr` (P3) · completes P7 |
| 4 | **Decision executions**: P8 init seeding (+ P0-scaffold candidate) · D3 classification pass · D4(i) git-authority table · D5 traceability authority · redone holds (P1d, P4d, id grammar) | both | rulings D2–D5 | see §3.4 |
| 5 | **Resume the backlog by its own index order** (both lanes' heads, tiebreaks as declared) | both | — | per index |

**Parallelism criterion — file ownership**, the input's own (§4.1): the flow repo's canon table
re-hashes on every edit, so **exactly one author inside `claude-config` at a time**; 2a (`s19_app`
only) and 2b (`claude-config` only) share no files and may run concurrently. The validator is
byte-untouched by tranches 1–2 (doc-only), so 2a's gate numbers are comparable to rev55's
(565 arms · 0 FAIL · 0 block on s19_app).

**Standing guards for every step:** `export PYTHONIOENCODING=utf-8` in every shell · gate suite via
`C:\Users\jjgh8\anaconda3\envs\s19env\python.exe -m pytest` directly, **never `conda run`**
(batch-87 harness rule) · never touch `prototypes\` or `build\` in `s19_app` (parallel session,
`C-44`) · when applying candidate files, diff after `tr -d '\r'` and write in canon's line-ending
convention (the 16 author-touched files are LF, canon is CRLF — input §1.1).

---

## 1 · The ordered sequence, in full

### Step 1 — rev56, tranche 1: the verified repairs (flow repo, doc-only, one author)

**Contents, by proposal id** (verdicts and evidence: input §1.4):

- **P1a** — selftest-exemption claim becomes derived (the hand-list `(V7, V8)` has been stale since
  rev47; measured `{}` over 28).
- **P1b** — `core` sync step list `1→2→3→6→7→8→9`. Verified today: canon's `mode: core` bullet
  (`dev-flow-sync.md:66`) says "generate only the README … then jump to step 7", bypassing step 6's
  full frontmatter contract — the only artifact `core` produces. Keep the 12-key core subset
  explicit when rerouting through step 6 (the 12-vs-31-key split is the mode table's,
  `dev-flow.md` mode rows).
- **P1c — with the input's §1.6 correction, not the candidate's text.** The condition reads:
  read `mode`; closing station is **`P6` for `full`, `P5` for `core`** (derived from
  `dev-flow.md`'s mode table + "`core` closes with `05-close.md`"), `fast` → command does not
  apply; read whichever of `current_station` / `current_phase` is present (numeric maps `6`/`5`);
  **neither key present is an ERROR, not a pass**; `stations_active` is **not consulted**, and the
  sentence says why (absent from all 20 close snapshots · trigger-shaped order · not reset at
  rollover).
- **P2** — fast-lane promotion, **plus** repairing its one cross-file inconsistency: the
  `dev-flow.md` side must say `V7/V15/V16` (matching `fast-dev-flow.md:119`), not `V15/V16/V17`.
- **P4a** — `RC-1 → RC-S1` disambiguation (verified 9-vs-2 site split; validator carries 0 of
  either).
- **P4b** — verdict tokens incl. `PASS-WITH-NOTES`.
- **P5** — example rows marked, **plus one sentence** noting the disarmed trap: deleting the marked
  row from a required table trips `dev-flow-sync.md:87`'s header+separator BLOCK.
- **P12a** — the 7-sentence collapse (best-executed change in the bundle; all sites moved).
- **P12b** — postmortem station grammar.
- **P12c — with fix**: phrase as the blocking rule + *"may seal more than once per batch, one record
  per seal"* (batch-88 held two PDRs; do not harden a position the live record violates).
- **P12d — with fix**: delete the second clause that restates the unscoped claim.
- **Housekeeping in the same rev:** fix the candidate README's stale mirror-commit line;
  `FLOW-VERSION.md` census — adopt the verified **range** `C-55 → C-56`, and either derive the
  count or drop it (`dev-flow.md` cites 33 distinct `C-` ids; "numbered" is undefined — input §1.12).

**Explicitly NOT in tranche 1:** P3, P7 (tranche 2 — see §4.4 for why P3 must not land partially),
P1d, P1e, P4c, P4d, P12e (held/rejected — §2.1, §4).

**Gate for the rev:** `--selftest` exit 0 on **both** 3.11.15 and 3.12.7 · gate over `s19_app`
0 BLOCK · `--map` 24/24 agree · bump `FLOW-VERSION.md` → rev56, regenerate the
`skills/dev-flow/` mirror bundle, push `claude-config` + `agent-skills`.

**RED evidence for P1c** (a fix to a gate needs a demonstrated failure first): before editing,
walk pre-requisite 2 as written against batch-89's live `state.json` and record the refusal
(`P3 ≠ P6`); after editing, the same walk passes with `mode: core` → `P5` **once batch-89's close
sets `current_station` to its closing station**. Record both in the rev56 notes.

### Step 2a — close batch-89 (project repo; MUST complete before any batch-90 directory exists)

Order within the step, each item the standing close contract (`dev-flow.md:544`):

1. **Gate run** for `04-validation.md`: validator (rev56) over the repo — expect 0 BLOCK; the suite
   via `s19env` python directly. **Known confound to state, not hide:** the suite's failure count
   depends on gitignored state (`suite-gitignored-state`, P2, CODE lane) and carries the known
   flaky family with measured rates (batch-87 carry (1)). Record figures and cite those items;
   do not re-diagnose them inside the close.
2. Write `04-validation.md` and `05-close.md` (mini postmortem — `core` mode). The close narrative
   should note the close is late and why, the same honesty batch-88's retroactive close used.
3. **Backlog reconciliation** (the three mandatory moves). The 2026-08-30 hand-routing already
   filed batch-88/89 findings — **reference it, do not redo it.** Mark shipped what this close
   ships: `batch-89-unclosed`; and `sync-P6` once step 4 below proves it. This is the first
   sanctioned edit to the fresh `BACKLOG-*.md` files.
4. Set `current_station` to the `core` closing station, commit, merge (per whatever merge authority
   the operator grants — `core` mode has no autonomous merge), then run **`/dev-flow-sync`** — the
   first live execution of the repaired pre-requisite 2 — and land the `obsidian_synced` edit on
   `origin/main` per the sync's own step 9 (C-44).
5. **Rollover hygiene while closing:** `stations_active` is known-stale (byte-identical to
   batch-88's — input §1.6, verified today in `state.json`). Do not hand-edit it to satisfy
   anything; the step-3 NOTICE rule will police rollovers mechanically. If the rollover into
   batch-90 later resets it correctly, that is the fix's proof.

### Step 2b — rev57, tranche 2 (flow repo; parallel with 2a by file ownership)

- **P3, completed to its full population — or not at all.** The two defects (input §1.5) plus the
  population completion, in one rev:
  (a) reinsert the dependant-definition at **both** normative homes (`dev-flow.md`,
  `ifc-template.md`) — it is the rule `V13`/`V14`'s `consumers` parsing depends on — and re-point
  `ifc-template.md:17`'s use of "misaddressed-observable" to wherever its definition now lives;
  (b) extract the **remaining 6 origin markers in 3 files**: `fast-dev-flow.md:145`, `:174`;
  `dev-flow-sync.md:90`, `:148`, `:234`; `validation-template.md` (1) — 5 of 5 files, not 3 of 5;
  (c) add the missing `SKILL.md` heading for "Golden double-proof (batch-24)" (`dev-flow.md:504`
  resolves to nothing today);
  (d) restore the ≤4 source-file cap's **derivation** next to the surviving constant.
- **Mint the origin-parenthetical rule** into `dev-flow-lessons`: *a parenthetical may carry
  provenance, never a definition* (the root cause of P3's defect (a) was canon's, not the
  candidate's).
- **P7 — with the severity sentence fixed.** Delete the hand-kept `V1–V9` table (9 of 28 rules
  documented, stale ≥8 revisions), document by reference to `--map`, and reword: severity is
  **per-finding on a real run**, not derivable from `--map` today (5 of 28 COVERAGE lines carry
  one; the 23 that don't include five documented-NOTICE rules — input §1.9). Add the one line
  saying what a reader without the tool loses: the rule list and the severities. The complete fix
  (`--map` printing severity) is validator work → step 3.
- **The instrument-blindness law** (input §2.3 — the session's largest finding, unencoded): *a
  verification instrument must demonstrate it can report FAILURE before a single PASS is
  believed.* Its home is `dev-flow-lessons`, whose `SKILL.md` this very rev has open — **but the
  control-encode rule requires its own AskUserQuestion first.** Ask at this rev's kickoff; encode
  here if approved, else it stays a named candidate. One control, not five fixes.

**Closure this rev claims:** `R-89-3` (P2, PROCESS lane) — the template's forensic-register
preamble is exactly this reform; verify by the item's own clause (V26-style budget over the
template, or an explicit exemption row).

### Step 3 — rev58+ validator series (flow repo, serial after 2b)

Grouped because all four live in `devflow-validate.py` and each needs an executed RED arm:

1. **V2 limb 1** — widen `_V2_DECLARED` to the batch-scoped form, **in its own increment**: the
   constant is frozen by the `WORDING-declared` arm and that freeze was earned. Verify per the
   item: the gate over batch-88's record names all nine ids instead of "no AT ids declared".
2. **V2 limb 2** — the node corpus becomes **declared** rather than hardcoded to `tests/`
   ("the real fix", per `R-89-7`). Verify: a `--selftest`-homed acceptance id resolves; an id with
   no node anywhere still BLOCKs.
3. **The `mode` ↔ `stations_active` NOTICE** (new — input §1.6's exposed rule, which the candidate
   did not propose): *the last station must equal the mode's closing station, or the rollover did
   not run.* It would have caught `R-89-9` at the gate instead of at the sync.
4. **`--map` prints per-rule severity** — completes P7's documenting-by-reference.
5. **`ifc-set-repr`** (P3) — three arms print `sorted(...)` renderings; verify with two consecutive
   `--selftest` runs under **default** `PYTHONHASHSEED` diffing to 0 lines (the item itself warns:
   verifying under a pinned seed is the vacuous form).

**Closures:** `R-89-6` + `R-89-7` (**the P0**, both limbs) — which also absorbs `G5-02` per the
item's own text: do not re-register it — and `ifc-set-repr`.

### Step 4 — decision executions (after rulings D2–D5; §2 proposes the rulings)

- **P8 / D2:** `/dev-flow-init` seeds `current_station` schema + the rev48 two-file lean contract
  for **new** batches only. **Bundle the P0-scaffold candidate** (batch-86 carry (2): a batch born
  without its own `01-requirements.md` is judged on batch-01's frozen doc) — same file, same
  concern, one rev.
- **D3:** one classification sitting over the 11 orphan controls + `PLAN.md` template + sealed
  baseline + 31-key metrics schema, producing a disposition table (control → bucket a/b/c →
  landing site) and the AskUserQuestion list; then execute all moves in a single rev. `C-46` is
  bucket (b) already (0 citations in `dev-flow.md`).
- **D4(i):** the station × git-operation authority table, one small design increment. It subsumes
  P12e's intent and P1's step-9 rewrite.
- **D5:** the Atlas is the traceability authority; land the ruling at **all three homes**
  (`artifact_homes.traceability` declaration · the hand template, re-headed "rendering — do not
  hand-edit" · the V20/Atlas doc) or it mints a fourth opinion.
- **Redone holds:** P1d as a **single-home** fix (pick the ledger, delete §6.4/§6.5 at
  `req-template.md:326`/`:329` and the citation at `dev-flow.md:164` — one obligation, one home,
  and no invented ledger column) · P4d as a distinct prefix for the three id-less lesson rules ·
  the id grammar **derived from the corpus** with the grandfathering statement (D-item in §3.3).

### Step 5 — resume the backlog by its own index

Both lanes' indexes are well-ordered and state their tiebreaks; follow them. After steps 1–3 the
remaining top of the PROCESS lane is `R-88-19`, `R-88-12`, `no-canonical-mutation-harness`,
`code-reviewer-absent` (a process change for future batches — every increment gets an independent
reviewer pass; encode where the increment contract lives), `R-88-17` (the population rule — a
strong candidate to encode alongside the instrument-blindness law, since steps 1–4 of this plan
are themselves an exhibit of it), and `F-8`. CODE lane: the batch-79 charter P0 ("execute, do not
re-derive") and its P1s per the index.

---

## 2 · Rulings on D1–D6 (proposed, with the argument)

### D1 — adoption shape: **three tranches, contents pinned by id (§1), holds converted to decision items**

The input's suggested shape is right; what it lacked was the pin. Tranche 1 is *only* what is both
verified and on or near the close path — small enough to gate cleanly, and it unblocks 2a.
Tranche 2 is the two ADOPT-WITH-FIX items whose fixes are known and bounded, landed **complete**
(P3's population, P7's sentence). Everything held or rejected becomes a named decision item
(§3.3) rather than a "tranche 3" that would invite wholesale application later. **Argument:** the
bundle is not atomic — 6 of its 17 applied proposals fail review — and the only coupling that
matters (P1b/P1c → batch-89 close) involves exactly two proposals; so ship the coupling first and
smallest.

### D2 — P8: **yes — and it is scaffolding, not a decision**

The candidate left `dev-flow-init.md` byte-identical (LF delta 0), the never-migrate rule already
protects old batches, and every argument for the current-station schema and lean contract was
settled when rev48/rev51 shipped them. The only judgment call is bundling the P0-scaffold
candidate, which I recommend: same file, and it closes a known green-gate-for-nothing hole in the
same stroke.

### D3 — P9: **one classification pass, one sitting, one rev of moves — never piecemeal**

The policy already exists (`dev-flow.md`, "Control placement (standing policy)" — verified today).
Eleven controls moved one at a time across revisions is eleven chances for the 1-of-N landing that
is `R-88-17`. The sitting produces the disposition table and the AskUserQuestion batch for Javier
(the control-encode rule is per-control and is not waived by the policy); the moves then execute
together and the census (§1 housekeeping) is re-derived once, after.

### D4 — P10: **adopt part (i) now as its own small increment; (ii) is D3's bucket-(c) machinery; (iii) is a one-line ruling**

(i) pays twice immediately — it retires P12e and P1's step-9 rewrite as ad-hoc edits and replaces
them with a table that can be cited. (ii) needs no new decision: the standing placement policy
already says stack-specific content leaves the global files; executing it is D3. (iii): rule that
`vault:` resolves through the batch's `artifact_homes` block and nothing else — that is already
the sync command's own "never write a path not declared there" discipline; one sentence makes it
the definition.

### D5 — P11: **the Atlas. The template is a rendering; Phase-6 generation is the author**

The argument is structural, not preferential: of the three claimants, only the V20-derived Atlas
is enforced against the corpus in both directions, so it is the only one that *cannot* drift; a
hand template and a config key can. Consequences to encode: hand-edits to the template become
findings, and the sync contract copies renderings but never authors them. Must land at all three
homes at once (§1, step 4).

### D6 — **close batch-89 immediately after tranche 1 lands, before anything else opens batch-90**

Not before tranche 1: closing triggers the sync, the sync fails pre-requisite 2 for `core`
(verified), and the choice would be forcing a failing gate or leaving the batch half-closed a
second time — the exact state `V28` exists to forbid. Not after tranches 2–3: they touch nothing
on the close path, and every day the batch stays open is a day some session might scaffold
batch-90 and make the hole permanent. The plan therefore pins the guard as an instruction, not a
hope: **no batch-90 directory until 2a's artifacts exist and its reconciliation is merged.**

---

## 3 · Bookkeeping: closures, additions, and the checkable map

### 3.1 Backlog items closed, by step

| step | closes | lane · band | verified how |
|---|---|---|---|
| 1 + 2a | `sync-P6` | PROCESS · P1 | the live sync run in 2a passes pre-req 2 for `core`; RED recorded pre-fix |
| 2a | `batch-89-unclosed` | PROCESS · P1 | `04-validation.md` + `05-close.md` exist; reconciliation merged; `V28` green for batch-89's directory |
| 2b | `R-89-3` | PROCESS · P2 | the item's own clause: V26-style budget over the template, or an exemption row |
| 3 | `R-89-6` + `R-89-7` (absorbing `G5-02`) | PROCESS · **P0** | each limb's executed RED arm, per the item |
| 3 | `ifc-set-repr` | PROCESS · P3 | two runs, default hash seed, 0-line diff |
| 4 | P0-scaffold candidate (batch-86 carry (2)) | PROCESS · candidate | init seeds `01-requirements.md`; a scaffolded batch no longer inherits batch-01's doc |

`R-88-17` and the instrument-blindness law are **encode candidates**, not closures — each owes its
AskUserQuestion (step 2b kickoff and step 5 respectively).

### 3.2 What the candidate ADDS to the backlog (new items, none previously filed)

1. **Grandfathered-id question** (opened by P4c's rejection): which id form is canonical going
   forward vs grandfathered. The corpus says batch-scoped (`AT-B<batch>-<n>`, 23 unique vs 2
   numeric; `CLAUDE.md` recommends it); the validator holds two disagreeing grammars
   (`_ATLAS_ID_ATTC` accepts `(?:B\d+-)?`, `_V2_DECLARED` does not — the divergence is even
   documented as deliberate in `v2_at_without_node`'s docstring). Ruling wanted before step 3's
   V2 limb 1 lands, since the widened grammar *is* the going-forward statement.
2. **Origin-parenthetical rule** — provenance yes, definition no (rides step 2b).
3. **`mode` ↔ `stations_active` NOTICE** (rides step 3).
4. **P1e's population record**: if `deliverable + observation` is ever retired, the retirement has
   a five-site population — `req-template.md:82` (blocker class b) · `review-template.md:11`,
   `:33`, the §checklist table column · `validation-template.md`'s AT table — filed so a future
   attempt cannot repeat the half-migration.
5. **`--map` severity printing** (from P7's unsatisfiable sentence; rides step 3).
6. **FLOW-VERSION "numbered controls"** — define the term or derive the count (33 distinct `C-`
   ids cited vs a hand count of 25).
7. **One lesson for the candidate's author** — all five of its defects are single-source
   enumeration over a larger population (`R-88-17`'s shape, reproduced while fixing other
   instances of it). One lesson, not five; the input §1.10 already drafted it.

### 3.3 Decision items minted by this plan (Javier's queue)

D2–D5 rulings (§2) · the grandfathered-id ruling (3.2-1) · the two control-encode
AskUserQuestions (instrument-blindness; `R-88-17`/population) · D3's per-control question batch.

---

## 4 · What NOT to do, and why

1. **Do not apply the candidate wholesale.** Six of seventeen applied proposals fail review; the
   bundle is a quarry, not a patch.
2. **Do not write the sync condition as `stations_active`-derived** (the candidate's P1c text).
   The array is absent from all 20 close snapshots, trigger-shaped in order, and not reset at
   rollover — deriving from it reintroduces the "silently unevaluable" defect inside the sentence
   that repairs it (input §1.6, re-verified against live `state.json` today).
3. **Do not adopt P4c's id grammar.** It makes 23 live AT ids, 24 TC ids, and all 67 `R-` findings
   ungrammatical and hands `V23` a grammar RED on correct history. Any grammar ships only from the
   corpus, after the grandfathering ruling (3.2-1).
4. **Do not land P3 partially.** 3-of-5-files extraction leaves two registers alive — the exact
   disease `R-89-3` names, installed by the cure. Tranche 2 lands the full population or P3 waits.
5. **Do not delete `deliverable + observation` (P1e).** Canon is coherent; the candidate's
   deletion leaves four gating sites pointing at a retired field (nuance in §6.1 — the rejection
   stands, on slightly different ground than the input states).
6. **Do not open batch-90's directory — or let any parallel session scaffold it — before 2a
   completes.** `V28`'s hole becomes permanent at that moment and cannot be repaired after.
7. **Do not hand-edit `stations_active` to make anything pass.** It is stale data; the fix is the
   condition (step 1) and the rollover NOTICE (step 3).
8. **Do not run the gate suite through `conda run`.** It destroyed a 40-minute run's evidence once
   already (batch-87). Direct interpreter, `PYTHONIOENCODING=utf-8`.
9. **Do not mint rival backlog ids.** The flaky-suite finding amends batch-87's entry (the input
   says so itself); both indexes forbid new id schemes; `G5-02` is absorbed by the P0, not
   re-registered.
10. **Do not put two authors in the flow repo concurrently.** The canon table re-hashes on every
    edit; two writers corrupt the aggregate — this is the parallelism criterion, stated as its
    own prohibition.
11. **Do not rename `close batch` (P12e).** No defect named; 15 historical artifacts carry the
    token; if the intent is "the agent may not close unilaterally," that is D4(i)'s table.
12. **Do not verify `ifc-set-repr` under a pinned `PYTHONHASHSEED`** — that is the vacuous form of
    its own check, and the item warns against it by name.

---

## 5 · Risks this plan carries (named, not hedged)

- **The 2a gate may not reproduce rev55's suite figures** — the failure count is known to depend
  on gitignored state (`suite-gitignored-state`). Mitigation: record figures with the tree state
  named; cite the open item; do not block the close on a delta that item already explains.
- **2b touches `dev-flow-lessons/SKILL.md` while it is P3's landing zone** — a merge hazard only
  if step 3 starts early; the serial-in-repo rule covers it, but it is the likeliest place for an
  ordering mistake.
- **The grandfathering ruling (3.2-1) gates step 3's V2 limb 1.** If unruled by then, land limb 2
  (declared corpus) first — the limbs are orthogonal by the item's own words.
- **This plan was produced without an independent reviewer pass** — the same `code-reviewer-absent`
  observation the input records about its own session. The mitigation is §7: every load-bearing
  claim is either re-measured or explicitly flagged as trusted.

## 6 · Where the input does not survive re-measurement (contract §4.6)

1. **P1e is overstated, though the verdict stands.** The input says *"Author writes nothing,
   Phase 2 blocks them for it."* Measured today: the candidate DOES leave a retirement mapping
   note — `req-template.md:211`: *"`Deliverable + observation` — covered by `Validation` plus
   `Executed verification`"* — so it is not a naked deletion. What is true and decisive: the four
   gating sites survive un-re-pointed (verified at candidate `req-template.md:82`,
   `review-template.md:11`/`:33` + the checklist table, `validation-template.md`'s AT table), so
   the obligation now has five homes where canon has one field. REJECT holds — on
   "half-migrated obligation," not "field deleted, nothing given back."
2. **Minor line drift:** the input cites `validation-template.md:22` as a deliverable-gating site;
   in the candidate the live sites measure at `:23–:24` and `:73`/`:75`. Substance unaffected.
3. **A phrasing trap worth defusing:** "R-89-3 is exactly its P3" — the *candidate's proposal*
   P3, not priority P3. The backlog files `R-89-3` at **P2**. Anyone triaging by band should not
   read that sentence as a demotion.

Everything else checked today survived — see §7.

## 7 · Verification ledger — measured vs trusted

**Re-measured today (this reviewer, 2026-09-03):**
- `dev-flow-sync.md:37-39` hardcodes "`P6`, or `6`" in ACTIVE pre-req 2 ✓ · `:66` `core` branch
  jumps to step 7 past step 6's README contract ✓ (step 6 = `:148`).
- `s19_app/.dev-flow/2026-08-28-batch-89/`: no `04-validation.md`, no `05-close.md` ✓;
  `state.json`: `mode: core`, `current_station: P3`,
  `stations_active = ['P0','ARQ','P1','PDR','P3']` ✓.
- Candidate at `C:\Users\jjgh8\kimi\dev-flow-rev56-candidate\` = exactly 25 files ✓.
- `R-89-3` filed at P2 in `BACKLOG-PROCESS.md:212`, subject = forensic-register preamble ✓.
- Validator (`C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py`): `_ATLAS_ID_ATTC:2096`
  accepts `(?:B\d+-)?` ✓; `_V2_DECLARED` divergence documented as deliberate in
  `v2_at_without_node`'s docstring ✓; `_LEAN_OWNER:2694` English-only `**Requirement:**` ✓;
  `_V6_MARKER:377` `**Statement` ✓; `V28` requires `04-validation.md` + (`05-close.md` |
  `05-postmortem.md`) per batch directory ✓.
- `dev-flow.md`: control-placement standing policy present ✓; `:544` backlog reconciliation is a
  mandatory close step ✓; `core` closes with `05-close.md`, no `06-docs/` → closing station `P5`
  derivable ✓.
- P1e's five candidate sites and the `:211` mapping note ✓ (→ §6.1).
- Both backlog indexes read in full; the P0 item (`R-89-6`+`R-89-7`) and `sync-P6` item read at
  their bodies, not just the index ✓.

**Taken on trust from the input** (it declares them measured; none is load-bearing for the
ordering): the LF-normalized byte deltas (§1.2) · P3's 119/121 span count and the 6-marker/3-file
un-extracted census (§1.5) · P4a's 9-vs-2 site split · §1.8's Spanish-alternate parse results ·
§1.9's 5-of-28 severity census · the 20 close-snapshots-lack-`stations_active` figure · batch-88's
snapshot equality with batch-89's array (today's array matches the quoted value; the batch-88 side
is the input's measurement) · candidate-validator byte-identity (the input marks provenance
settled and instructs not to re-check).

---

*Deliverable of the consolidating review, 2026-09-03. One file written; nothing else changed;
nothing committed. Input: `HANDOFF-devflow-session-2026-09-03-rev56-intake-PLAN-INPUT.md`.*
