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

**Two things the execution changed about the plan's own content:**

- **The `core`-mode sync condition shipped as the INPUT's §1.6 correction, not the candidate's.** It derives `P6`/`P5` from `mode` and states in terms why `stations_active` is not consulted. The plan's own note that `stations_active[-1]` is "already the authority" was **over-read**: `dev-flow.md:575` calls it the authority on *which optional stations exist* (`ARQ`/`PDR`/`DDR`), never on which is terminal.
- **The input's third reason against `stations_active` — "it is not reset at rollover" — is FALSE as a property.** Traced through the state ledger's git history: batch-88 opened at `['P0']` and grew, so the 87→88 rollover reset it correctly and **only** 88→89 did not. The accurate form shipped in the command.

**What remains, unchanged from the plan below:** step **2b** (tranche 2 — P3's remainder, P7's severity sentence, the origin-parenthetical rule) · step **3** (the rev58+ validator series, whose head is the `P0`) · step **4** (decisions **D2, D3, D5** — D1 is executed, D4(iii) is closed by the vault fix, D6 is executed).

**⚠ The hard guard is still in force: no batch-90 directory exists and none may be opened** until the plan says so. `V28`'s window is one batch wide.

---

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
