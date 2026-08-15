# C-54 / batch-82 — session handoff, 2026-08-13

> **HISTORICAL RECORD — frozen at `rev16`, 2026-08-13.** The flow is at `rev33`; this document
> predates it by seventeen revisions, and not one of the nine `flow_hash` values it cites is
> current. **Do not read §0, §1, §5 or §7 as current state.** The live state has one source and
> it is a command, not a file:
> `python ~/.claude/docs/tools/devflow-validate.py --map --fetch`.
>
> **§6 is mixed — do not read it either way.** Most of its `❌` debt was paid between `rev17` and
> `rev33`; some was not. Which is which is deliberately not recorded here: a debt list maintained
> beside the debt is the defect this very document diagnoses. The current register is
> `~/.claude/docs/NEXT-SESSION.md` §4.
>
> **What survives re-reading unchanged is §2, §3, §4 and §8** — they measure s19_app's code and
> this session's reasoning, neither of which the flow's revisions age. §3's AST address census is
> the sizing input for the batch-82 retrofit.

**Supersedes nothing.** Read alongside, not instead of:

| Document | What it holds |
|---|---|
| [`C-54-information-flow-contract.md`](C-54-information-flow-contract.md) | the design: schema, worked examples, D-1…D-8 |
| [`C-54-FLOW-REPO-HANDOFF.md`](C-54-FLOW-REPO-HANDOFF.md) | scope correction — the flow work belongs to `claude-config`, not s19_app |
| [`BATCH-82-ENTRY.md`](BATCH-82-ENTRY.md) | the charter, the exit criteria, the falsifiable prediction |

**Two of those documents now contain a claim this session measured and refuted.** See §4.

---

## 0 · What this session actually shipped

**Not `C-54`.** `C-54` is still unencoded — that has not moved and §5 says so with its grep.

What shipped is the **flow-sync guard**, which was the operator's second item and turned out to
be a prerequisite: `C-54`'s encoding will touch both commands, a new template, the validator, the
manifest and every packaged counterpart, in one session, under pressure to close eight exit
criteria. That is precisely the condition under which the drift being guarded against happens.

**Four revisions, not one.** Each was caused by a defect found in the previous one, and every one
of those was found by *measuring* rather than by review.

| Rev | claude-config | agent-skills | What it closed |
|---|---|---|---|
| **rev13** | `b57f58b` | `31a1298` | `V15` (the guard) · validator into the aggregate · `flow_hash` made reproducible |
| **rev14** | `27b9870` | `139bc92` | `V15` reported a pass and a no-op with the same severity |
| **rev15** | `43d4322` | `4fe0d0e` | three inventories → one; bundle becomes **derived**; mirror finally ships the mechanism |
| **rev16** | `e49229c` | `9df1244` | `V7` had `V15`'s defect, and rev15's "one inventory" claim was still false |

**All eight are pushed**, each verified 0/0 with `HEAD == origin/main` **after** the push, per
`C-44`'s wording. The commit messages carry the reasoning; it is not repeated here.

**The cost rev13 predicted arrived immediately and kept arriving:** rev13 recorded that folding
the validator into the aggregate means *"every future edit to the validator now obliges a manifest
bump."* Every rev since has been that bump. That is the friction working, not failing — each one
is a version a consumer can pull.

**And they are one defect wearing four masks.** Stated once here because it is the transferable
part: *every* finding was either **a check whose expected value is written by the same hand as the
change**, or **a list maintained beside the list it was meant to guard.**

---

## 1 · Before / after of the out-of-repo files — exit criterion 8

The global flow lives outside this repo and is not covered by its PR flow. This is that record.

```
                    BEFORE (rev12)          AFTER (rev16)
flow_version        2026.08.10-rev12        2026.08.13-rev16
flow_hash           41144ca54e8b944a        677cd8cb43b320d9
hashing scheme      raw working-tree bytes  CR-normalised content
hash membership     hardcoded in V7         DERIVED from the manifest table, in table order
validator rules     V1,V2,V4…V9             + V15
files in aggregate  19                      20 (+ devflow-validate.py)
the bundle          hand-maintained copy    generated: --sync-bundle
inventories         3 (none agreeing)       1 — the table
what the mirror     18 of 20 declared       all 20, incl. the validator and ux-reviewer
  actually ships      (no validator)
selftest arms       12/12                   32/32
rules unprovable    V7 and V8               V8 only
  synthetically
```

Intermediate hashes, for anyone reading a `PLAN.md` that cites one:
`rev13 d6f3d1d814e4c04f` · `rev14 4f5ba10d3ce6b104` · `rev15 9798daa71763c02e`.

**One tabled per-file hash moved for reasons other than an edit:**
`commands/dev-flow.md` `57c6605ee4dfb419` → `73b54e9b1826cb73`. The file is byte-unchanged; it
was the only file carrying CRLF in the authoring working tree, so normalisation moved it. Every
other per-file hash is unchanged, which is itself the evidence that normalisation was a no-op on
files an editor had already written.

---

## 2 · The three findings, in the order of severity they turned out to have

### F-1 · `flow_hash` was irreproducible outside one working tree — the severe one

`V7` exists to make `C-45`'s PULL obligation mechanical: *prove in one command that the flow you
are about to run is current.* It hashed **raw working-tree bytes** while `core.autocrlf=true`, so
a file `git` wrote at checkout carried CRLF and a file an editor wrote carried LF.

Measured against a fresh clone of both repos:

```
declared (rev12)                41144ca54e8b944a
aggregate on a fresh clone      bfb37780aa0fa43f
per-file mismatches             18 of 19
the single match                commands/dev-flow.md — by the accident of being CRLF on both sides
```

**So the rule whose entire job is the PULL check was RED on every fresh checkout, for reasons
with nothing to do with drift.** That is `C-53`'s own lesson at the scale of the whole manifest:
a rule that false-fails correct work is more corrosive than one that passes wrong work, because
it teaches everyone to ignore the checker.

Fixed by hashing CR-normalised content in **both** implementations — `_norm()` in the tool,
`tr -d '\r'` in the manifest's verify command. Verified by execution:

```
same file set, local worktree AND fresh clone   ->  10c98fbd5d32590c   MATCH
rev13 set, fresh clone (3630 CR bytes present)  ->  d6f3d1d814e4c04f   MATCH
rev13 set, fresh clone, WITHOUT normalisation   ->  does NOT match     (old scheme confirmed broken)
```

The 3630 CR bytes matter: the verification clone is maximally *unlike* the authoring tree in line
endings, and the hash still agrees.

> ⚠️ **One piece of evidence offered for this during the session was weaker than it sounded.**
> "Three implementations agree" — the rehash script, `V7`, and the manifest's shell one-liner — is
> **one algorithm wearing three hats**: the tool's own docstring says `_norm` matches `tr -d '\r'`
> *by construction*. That is the coincidence-oracle pattern this project's catalogue already logs
> (rev3, unnumbered). **The only genuinely independent evidence is fresh-clone vs local**, and the
> without-normalisation control above. Cite those, not the three-way agreement.

**Found only because F-2 forced a re-hash.** Nobody was looking for it.

### F-2 · The validator was outside the identity of the flow it validates

`docs/tools/devflow-validate.py` was tabled nowhere and hashed nowhere, so **a rule could be
added or relaxed and the flow would still declare `rev12`**. Same defect as rev12(c)'s
`ux-reviewer.md`, one layer in — the mechanism that makes the controls mechanical was the one
file not under them. Now in the table, the verify command and `V7`'s aggregate.

**Cost accepted deliberately:** every future edit to the validator now obliges a manifest bump.

### F-3 · The packaged copy had no oracle — the operator's original alert

`skills/dev-flow/` (18 files) is a **duplicate** of the live flow, and it is what feeds the mirror
Kimi runs. The obvious fix does not work, and this is the part worth carrying forward:

> **Folding the packaged copy into the aggregate does NOT close the hole.** An aggregate answers
> *"did somebody forget to re-hash?"*. Edit `commands/` only, bump the manifest correctly, and
> `V7` goes GREEN AGAIN with the packaged copy stale — **the bump records the drifted state as
> canonical.** Summing N files discards the *pairing*, which is exactly where the failure lives.

`V15` is therefore a separate rule using an **equality** oracle, pairing **by directory** so a
newly added template with no packaged counterpart is drift too. Its comparison core is separated
from its I/O so it can demonstrate RED synthetically — three distinct shapes, edited · missing ·
orphan — which `V7` and `V8` still cannot, and still say so out loud.

### The unifying root — worth stating once, because it recurs

Every one of these, plus the `LLR-120.2` defect that produced `C-54`, is **an oracle that
normalises applied to a property whose failure lives in what the normalisation discarded**:

| Oracle | Discards | Where the failure lived |
|---|---|---|
| set equality over 3 rows | order | order (`LLR-120.2`) |
| sha256 aggregate over N files | the pairing | the pairing (F-3) |
| `cardinality: 3` | order | order — **still open, see §6** |

It recurs for a structural reason, not carelessness: **aggregation is what makes a check cheap.**
The pressure toward a cheap oracle *is* the pressure toward a normalising one.

There is a second axis, useful for judging any future rule — **who writes the expected value?**

| Reference written by | What the check actually is |
|---|---|
| the author of the change | memory — catches only forgetting |
| a second, independent artifact | **correctness** |
| derived from the running system | correctness, strongest |

`V7` is the first kind, which is why it could go green over drift. `V15` is the second.

---

## 3 · Decisions taken this session

### `D-6` — RESOLVED: provider declares, **validator discovers**

Neither of the two options in the design. The operator selected a third:

- the **provider** declares its `consumers` (authorship stays where the retrofit's value is);
- a validator rule **greps the declared `address` literal** across the tree and BLOCKs on any
  node that reaches it and is not listed.

**Why not Pact's inversion:** Pact solves *"a provider never learns when a new consumer
appears"* for separately-deployed, separately-owned services. Here provider and consumer land in
the same commit and the same CI run, so the property is obtainable without moving authorship —
and consumer-declares would destroy the retrofit's actual deliverable, which per `D-2` is **the
findings**, i.e. forcing *"who depends on this, and how do they reach it?"* onto ~40 surfaces.

**The correction that matters more than the decision** — discovery is *not* the guard:

| | Needs to know the consumers? |
|---|---|
| (a) discovery — who reaches this address | yes; grep is incomplete here |
| **(b) detection — did the address move** | **NO** |
| (c) attribution — who breaks | yes |

`LLR-120.2` is (b). A fourth `.loaded-detail` cell violates `cardinality: 3`, a property of the
provider measured against its own declaration. **Even a total grep failure could not let the
batch-79 defect through.** Grep incompleteness degrades the reported blast radius, never the
detection.

### The computed-address hole — measured by AST, and the first census was wrong

An earlier grep-based census in this session put the total at 1586 sites with 53 computed ones "all
of one shape". **An independent AST pass refuted all three of those figures.** The corrected census:

| Address form | Sites | Statically resolvable |
|---|---:|---|
| literal selector | 1290 | yes — grep verbatim |
| type-addressed `query_one(Rail)` | ~179 | yes — by symbol |
| **f-string in query-argument position** | **54** | **no** |
| **API total** | **1558** = `query_one` 1272 + `query` 286 | `query_exactly(` has **zero** occurrences |

**The 54 are NOT one shape.** 44 match the strict `f"#{var}"`; **ten do not**, across 7 files, and
one of them is in `s19_app/` itself rather than only in tests:

| Shape | Count | Example |
|---|---:|---|
| prefix + interpolated index | 6 | `query_one(f"#assign_{index}")`, `f"#log_line_{i}"` |
| interpolated dict subscript | 2 | `query_one(f"#{_WINDOW_BODY[win_id]}")` |
| **descendant combinator** | 1 | `query_one(f"#flow_result {selector}")` |
| **computed CLASS selector** | 1 | `query(f"#legend_key_pane .{cls}")` |

**The last two are the ones that matter.** They are not id selectors at all — the selector *grammar*
differs. And a computed **class** selector is the exact address form of `LLR-120.2`. A detector keyed
on the single shape `f"#{var}"` would have silently skipped the hardest case it exists to catch.

**Second refutation, and it roughly doubles the surface:** the 54 are only those f-strings sitting
*directly* in a query argument. Tree-wide there are **105** selector-shaped f-strings; the other 51
are built elsewhere — assigned to a variable, or passed into helpers such as `_static_plain`,
`_b78_window_text`, `_b79_painted_strip`. **Whether those reach a query site indirectly is
UNMEASURED.** Anyone sizing this work should measure it before quoting 54.

**What survives:** the control is still an **unresolvable-address detector** (BLOCK or
NOTICE-with-owner), not "grep and hope" — a validator cannot resolve a value but can recognise the
*site*. What does not survive is the claim that recognising it is a one-regex job. It needs the
shape taxonomy above, and the two grammar outliers are its acceptance tests.

Sites computing an id from *data* (config, file contents) remain **zero**; if one appears it
declares the id set it can produce, or takes a waiver with an owner and an expiry. **A waiver is
visible in the file; a grep miss is not.**

Helper indirection (`_detail_texts` and its six callers) is not a hole either: under `D-7`,
already adopted, **the helper is the port.** One consumer is declared, not six.

### `D-5`, `D-7`, `D-8` — unchanged, adopt-and-go, as the design has them.

---

## 4 · Claims in the prior handoffs that this session refuted

**Both must be corrected before the next session acts on them.**

1. > *"There is NO local checkout of the mirror. `agent-skills` exists only on the remote."*
   — `C-54-FLOW-REPO-HANDOFF.md` §1

   **False.** `~/.claude/skills/` **is** the `agent-skills` checkout, nested and gitignored by
   `claude-config` (`.gitignore` line 3, `/*` whitelist, with the comment *"skills/ is its own
   repo, kept nested"*). That is why its changes never appear in `claude-config`'s `git status`,
   which is what made it look unreachable. **Consequence:** the planned mirror check collapses
   from a network comparison to `git -C ~/.claude/skills status` clean and 0/0.

2. > *"Hoy están las tres en sync (medido)"*

   What had been measured was **the two local surfaces**. The mirror had never been compared to
   anything. It was measured this session — via `gh api` blob shas, then via a fresh clone —
   and was in fact clean, 18/18. The claim was true; **its evidence did not exist.**

---

## 5 · State at handoff — measured, not asserted

```
C-54 grep across commands/, FLOW-VERSION.md, devflow-validate.py,
     templates/dev-flow/, skills/dev-flow/                     ZERO hits
templates/dev-flow/ifc-template.md                             DOES NOT EXIST
manifest controls line                                         C-10…C-53  (NOT C-54)
validator rules                                                V1,V2,V4…V9,V15  (NO V10–V14, NO V16)

devflow-validate.py --selftest                                 32/32 PASSED
V7  against the real tree                                      flow current (677cd8cb43b320d9)
V15 against the real tree                                      20 files derived from the manifest table,
                                                               bundle identical
full run against s19_app                                       14 block / 227 notice
                                                               = unchanged from the recorded baseline
```

**The consumer case, measured rather than reasoned about** — a standalone `agent-skills` clone,
run with a foreign `HOME`, i.e. what a Kimi install actually looks like:

```
[!] V7   no ~/.claude/docs/FLOW-VERSION.md — the flow revision was NOT checked; this is not a pass
[!] V15  no skills/dev-flow/ on this machine — the bundle was NOT checked; this is not a pass
```

Before rev16 that first line read `[-] no manifest found` — **rendered identically to its success
line** `[-] flow current (…)`. This scenario is why rev16 exists: rev15 shipped the validator, and
shipping it is what turned a registered defect into one a consumer would hit.

The 14 blocks are the pre-existing batch-01 (May 2026) set. **No regression was introduced.**

**Independently re-verified** — 45 claims CONFIRMED by a separate measurement pass that re-cloned
both repos and re-ran every command, including the negative control (*without* normalisation the
aggregate does **not** match, so the old scheme is confirmed broken rather than merely asserted).
Four claims were REFUTED; all four were in the address census, all four are corrected in §3 above.

### What is on `origin` — verified AFTER each push, not before

```
~/.claude          e49229c  0/0, clean, HEAD == origin/main    -> origin serves rev16
~/.claude/skills   9df1244  0/0, clean, HEAD == origin/main    -> mirror serves rev16
s19_app            claude/flow-version-sync-fix-8d7086, pushed with this commit
```

Both remotes were read back through the GitHub API, not from local refs, and both declare
`2026.08.13-rev16`. **A `git pull` of the flow gets the fixed guards and the validator.**

The wording *"verified after the push"* is not ceremony: this project has already shipped a change
asserted locally that never reached `origin`, which is why `C-44` exists and why batch-78 needed
`#190` purely to land a flag.

**What `31a1298` actually contains:** one file, `dev-flow/FLOW-VERSION.md`, +32/−10. The mirror's
`commands/` and `templates/` were **not** re-pushed this rev because they did not change — verified
identical to live, 17/17, CR-normalised. Stated explicitly because "the mirror is at rev13" and "the
mirror's every file was re-pushed" are different sentences and only the first is true.

---

## 6 · Owed — nothing silent

### The open risk that outranks the rest

> **`C-55` is not encoded, and `C-54` without it has a hole shaped like the defect `C-54` exists
> to prevent.**

`cardinality: 3` does not catch a **reorder**: the count holds, set equality holds, and a
positional consumer breaks anyway. To close it the `address` must carry the ordering commitment
(`INDEXED POSITIONALLY`, which the design's own worked example already writes) and the oracle must
compare a **sequence**, not a set.

`D-3` deferred `C-55` to "after the retrofit, its best evidence generator". **That ordering is now
questionable**: this session produced two further instances without any retrofit, and closing
`C-54` while declaring it sufficient would repeat, with irony, the error `C-54` was written to
prevent. **Re-litigate before encoding, not after.**

### Everything else

### Defects in what this session shipped — found by the verification pass

| | Defect | |
|---|---|---|
| **`V15` reported a pass and a no-op identically** | `SKIP` for *"packaged copy identical"* **and** for *"no `skills/dev-flow/` on this machine"*; both rendered `[-]`. A consumer mounting the mirror elsewhere got a silent green **from the rule written to stop silent greens**. A second defect sat below it: `_pair_drift({}, {})` is empty, so a tree with nothing to compare would have reported "identical" — **zero files compared is never a pass**. | ✅ **FIXED in rev14** — `_v15_outcome()` pure core, NOTICE on both no-op cases, selftest asserts **exact severity** per arm plus an explicit `PASS != NOOP` arm. 12 → 19 arms |
| **`V7` had the identical shape** | `[-] flow current` and `[-] no manifest found` rendered alike. **Theoretical until rev15 shipped the validator; then a consumer would read a no-op as a pass.** | ✅ **FIXED in rev16** — `_v7_outcome()`, NOTICE on not-checked, re-measured in the foreign-`HOME` scenario |
| **`V7` kept its own hardcoded file list** | A **fourth** inventory beside the three rev15 collapsed — so rev15's own changelog claim (*"the table is the only inventory"*) was **false when written**. A new table row would have stayed outside the flow's identity. | ✅ **FIXED in rev16** — membership *and* order derived from the table |
| **A misdiagnosis in `V7`** | A file declared but missing on disk fed the literal `None` into the aggregate; the mismatch was reported as *"you have unpushed edits, or you are behind"* — sending you to `git pull` for a missing file. | ✅ **FIXED in rev16** — own BLOCK, with an arm asserting the wording |
| **`skills/dev-flow/README.md` was unguarded** | In no inventory; could drift indefinitely. | ✅ **rev15** — now a *declared exclusion*, named rather than absent |
| **The table was verified only inward** | Nothing could notice a file that *should* have been listed. A self-consistent manifest is exactly the vacuous shape. | ⚠️ **half-fixed in rev15** — `V15` now BLOCKs on a bundle file in no inventory, so the *bundle* direction is covered. Nothing still checks that the **table** itself is complete against the authoring tree |
| **No mutation test on the wired rules** | Nobody perturbed a byte and confirmed the aggregate goes red end-to-end. The pure cores have 20 arms between them; the wired rules have none. | ❌ |
| **Nothing enforces either rule** | No CI job, no hook, no pre-commit. `V7` and `V15` run **only when a human types the command.** A control that depends on someone remembering is the thing `C-53` exists to replace. | ❌ **now the largest open item in this file** |

### Everything else

| Item | Status |
|---|---|
| `C-54` encoding — both commands, `ifc-template.md`, `V10`–`V14` | not started; `D-6` now resolved so it is unblocked |
| `V16` — `git -C ~/.claude/skills` clean and 0/0 | collapsed from network to local; not written |
| unresolvable-address detector | proposed, not written — and **re-size it first**, see §3 |
| `BACKLOG-PROCESS.md` Lane B → pointer | untouched; still carries the half that moved to `claude-config` |
| this handoff | committed and pushed on `claude/flow-version-sync-fix-8d7086`; **no PR opened** |
| exit criteria 1, 2, 3 (for `V10`–`V14`) | belong to the `C-54` batch, not to this one |

### Carried forward unchanged from `BATCH-82-ENTRY.md` §6

Lane A's eight gate-8 observations, `M-4`, `F-6`, `N-7`, the eight `subprocess.run(text=True)`
siblings, the Inc-8/9/10 packet gap; Lane B's `F-8` and the symbol-anchor control. **Not
re-litigated here** — that document remains their register.

---

## 7 · First moves for the next session

1. **`cd ~/.claude`** — that is the working directory for the flow work, not this repo.
   Re-run `devflow-validate.py --selftest` and the manifest's verify command; both should be
   green before anything is edited. **They are now reproducible, so a red is real.**
2. **Ask for authorization — per-batch AND per-session, never inherited.**
3. **Settle `C-55` first** (§6). It changes what `V11` has to check.
4. Encode `C-54` against the eight exit criteria in `C-54-FLOW-REPO-HANDOFF.md` §2, with `D-6`
   as resolved in §3 above.
5. **Every edit under `~/.claude` now owes: the packaged copy, the manifest bump, and BOTH
   pushes.** `V15` will block if the first is skipped; nothing blocks if the third is.
6. Reduce `BACKLOG-PROCESS.md`'s Lane B entry to a pointer at `C-54-FLOW-REPO-HANDOFF.md`.
   **Reduce, not delete** — the finding and its evidence originated there.
7. **Never hand-copy into `skills/dev-flow/` again** — run `--sync-bundle`. The bundle is a build
   output; editing it directly is the drift this whole arc removed.

### ⚠️ Before anything else

**Confirm the flow you are about to run is `rev16`** — `git -C ~/.claude pull`, then the verify
command in `docs/FLOW-VERSION.md`. It is reproducible on any checkout, so a mismatch is real.

`claude/flow-version-sync-fix-8d7086` is on `origin` with **no PR opened**. Decide whether this
handoff merges to `main` on its own or rides with the `BACKLOG-PROCESS.md` pointer edit (§7.6).

### Suggested skills

| Skill | Why |
|---|---|
| `dev-flow-lessons` | the control catalogue; `C-53`, `C-40`, `C-45`, `C-47` all bind this work |
| `supervised-incremental-development` | ≤4 SOURCE files per increment, stop at the boundary |
| `review-packet` | the 7-section packet at each increment gate |
| `dev-flow` | only once `C-55` is settled and authorization is granted |

---

## 8 · Process notes this session paid for

- **`~/.claude` is two nested repos.** `git status` in the parent is blind to `skills/`.
  A change can be "committed and clean" and half-shipped.
- **A manifest bump can certify drift.** Recomputing the reference is not verification when the
  reference is written by the same hand as the change.
- **Hash working-tree bytes and you hash the checkout, not the content.** `git` and editors
  disagree about line endings; the disagreement is invisible until someone clones.
- **The measurement that mattered was the one nobody had run.** Three surfaces were declared in
  sync; the third had never been compared to anything. *Assumed-clean and verified-clean are
  different states and they look identical in a handoff.* This document tries to mark which is
  which — §5 is measured, §6 is owed.
- **A grep census is not a census.** The address figures in §3 were produced by regex, stated with
  three significant figures, and used to argue that a hole was bounded and one-shaped. An AST pass
  refuted the total, the count, the shape claim, and the scope. **The regex over-counted the API by
  28, invented a method that does not exist here, and missed roughly half the computed selectors by
  only looking at call sites.** Nothing about the conclusion changed; everything about its size did.
- **A rule can ship with the defect it was written to prevent.** `V15` guards against a green that
  means nothing — and reported its own pass with the same `[-]` it uses for "not applicable". It was
  not caught by writing it, nor by its own selftest, but by an independent pass asking *what would a
  fresh reader misread here?* **Budget for that pass; it is not optional on control code.**
- **Shipping a control changes who its defects hurt.** `V7`'s ambiguous `[-]` was registered as a
  known, tolerable flaw for two revisions. rev15 put the validator in the mirror, and the same flaw
  became something a consumer would hit on their first run — measured, not predicted, by cloning
  the mirror and running it with a foreign `HOME`. **Re-triage every registered defect at the moment
  distribution widens.**
- **A changelog claim is a testable assertion.** rev15's entry said *"the table is the only
  inventory"*. `V7` still held a hardcoded list of the same 20 files, so the sentence was false when
  it was written and pushed. It was caught by opening `V7` for an unrelated fix. **When a rev claims
  to have unified something, grep for the other copies before writing the sentence** — and if one
  turns up later, correcting the code is cheaper than leaving the record wrong.
- **A generated artifact ends the argument.** Three inventories were reconciled twice by hand in one
  session. Neither reconciliation held, because both left the *maintenance* manual. Deriving the
  bundle from the canon removed the failure mode instead of re-detecting it — which is what `C-50`
  meant by *nothing is copied*.
