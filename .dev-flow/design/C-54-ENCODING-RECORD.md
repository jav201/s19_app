# C-54 — encoding record (exit criterion 8)

**Written 2026-08-15.** The flow lives in `jav201/claude-config`, **outside this repo and outside
its PR flow**, so a merged PR here is not evidence that the control landed. This is that evidence.

Companion documents, none superseded: [`C-54-information-flow-contract.md`](C-54-information-flow-contract.md)
(the design), [`C-54-FLOW-REPO-HANDOFF.md`](C-54-FLOW-REPO-HANDOFF.md) (the scope correction and the
eight exit criteria), [`BATCH-82-ENTRY.md`](BATCH-82-ENTRY.md) (the charter).

---

## 1 · Before / after of the out-of-repo files

```
                       BEFORE (rev27)              AFTER (rev33)
flow_version           2026.08.14-rev27            2026.08.15-rev33
flow_hash              656591c996355452            d851576cfe8f60b3
controls               22 numbered, C-10…C-53      23 numbered, C-10…C-54
tabled files           23                          24  (+ ifc-template.md)
validator rules        V1,V2,V4…V9,V15,V16,V17     + V10, V11, V12, V13, V14
selftest arms          85                          136
commands carrying      none                        dev-flow.md · fast-dev-flow.md
  the obligation
```

Repositories, verified 0/0 **after** each push, per `C-44`'s wording:

```
jav201/claude-config   32f6b11
jav201/agent-skills    f8e237d
~/kimi/agent-skills    advanced by --sync-checkouts
```

Intermediate hashes, for anyone reading an artifact that cites one:
`rev28 4d33731c6d18caef` · `rev29 bf4fed1fcb85a56d` · `rev30 18eae2f3fa25cf4c` ·
`rev31 685c563b0323aa60` · `rev32 2f3caa33ffa64e8e`.

---

## 2 · The eight exit criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | **both** commands carry the obligation; fast owes Part A only, written in it | rev33 — `/fast-dev-flow` step 5 states Part A only, and its Part B trigger is written as that phase's **escalation signal** to the full flow |
| 2 | `templates/dev-flow/ifc-template.md` exists | rev28, tabled and mirrored; corrected at rev29, rev31, rev32 |
| 3 | `V10`–`V14`, **each demonstrating RED in `--selftest`**, output pasted | §3 below |
| 4 | manifest bumped — version, `flow_hash`, `controls` → `C-10…C-54` | rev33; the verify command derives from the table, so it needed no separate edit |
| 5 | packaged copy updated and re-measured IN SYNC | `--sync-bundle` per rev; `V15` reports 21 pairs identical |
| 6 | pushed to `claude-config`, 0/0 verified **after** the push | §1 |
| 7 | `agent-skills` mirror reconciled | §1 — and the third checkout advanced, see §5 |
| 8 | a before/after record in the batch artifacts | this file |

---

## 3 · `V10`–`V14` demonstrating RED — pasted transcript

`--selftest` at rev33, filtered to the `C-54` arms. `SELFTEST PASSED`, 136 arms total.

```
  V10 BLOCK-noowner     expected BLOCK  · got BLOCK  · ok
  V10 BLOCK-ghostowner  expected BLOCK  · got BLOCK  · ok
  V10 PASS-owned        expected SKIP   · got SKIP   · ok
  V10 NOOP-noflows      expected SKIP   · got SKIP   · ok
  V10 NOOP-reads-apart  expected distinct wording    · ok
  V11 BLOCK-noaddress   expected BLOCK  · got BLOCK  · ok
  V11 BLOCK-consumers-omitted  expected BLOCK · got BLOCK · ok
  V11 PASS-consumers-none      expected SKIP  · got SKIP  · ok
  V11 PASS-consumers-list      expected SKIP  · got SKIP  · ok
  V11 NOOP-nocomponents        expected SKIP  · got SKIP  · ok
  V11 SILENCE!=ANSWER   expected BLOCK vs SKIP · got BLOCK vs SKIP · ok
  V12 BLOCK-noparent    expected BLOCK  · got BLOCK  · ok
  V12 BLOCK-unbalanced-in      expected BLOCK · got BLOCK · ok
  V12 NOTICE-parent-absent     expected NOTICE · got NOTICE · ok
  V12 NOTICE-prose-inputs      expected NOTICE · got NOTICE · ok
  V12 PASS-contained    expected SKIP   · got SKIP   · ok
  V12 THREE-STATES      expected SKIP/BLOCK/NOTICE distinct · ok
  V13 NOTICE-undeclared expected NOTICE · got NOTICE · ok
  V13 NOTICE-nolteral   expected NOTICE · got NOTICE · ok
  V13 PASS-all-declared expected SKIP   · got SKIP   · ok
  V13 PASS-symbol-form  expected SKIP   · got SKIP   · ok
  V13 SYMBOL-strips     expected path::symbol matches the path · ok
  V13 UNSEARCHED!=CLEAN expected NOTICE vs SKIP · ok
  V14 BLOCK-nofile      expected BLOCK  · got BLOCK  · ok
  V14 BLOCK-nosymbol    expected BLOCK  · got BLOCK  · ok
  V14 PASS-resolves     expected SKIP   · got SKIP   · ok
  V14 PASS-none-declared       expected SKIP  · got SKIP  · ok
  V14 SYMBOL-counts     expected file-ok+symbol-missing != both-ok · ok
```

**The arms that carry weight are not the BLOCK ones.** Any rule can BLOCK. These are the pairs
that prove the rule measures the thing it claims:

| Arm | What it forbids |
|---|---|
| `V11 SILENCE!=ANSWER` | an **omitted** `consumers` passing as if it said `none` — silence accepted as a contract, which is what `LLR-120.2` did |
| `V12 THREE-STATES` | *could not be tested* rendering like *holds* — which would make the rule agree with every document that declares nothing |
| `V13 UNSEARCHED!=CLEAN` | an address nobody can grep reading like an address with no undeclared readers — a bound turning into a lie |
| `V14 SYMBOL-counts` | a present file with an absent symbol passing, which would make `::symbol` decoration |
| `V10 NOOP-reads-apart` | *nothing here* and *checked and clean* wearing the same words |

---

## 4 · What the encoding measured, and what it refuted

**The design's syntax did not survive contact, twice, and both were found by building the rule
rather than by reading the document.**

- **rev29** — the worked example's `consumers` list was copied from a comment in
  `s19_app/tui/screens_directionb.py:1953`, which the design copied, which the template copied.
  **Three copies of one list, and a grep of the tree contradicts all three.**
- **rev31** — writing `V12` found `INPUTS` written as prose (`loaded-file state`). **Containment is
  a set operation and free text has no members**; nothing could ever have been compared.
- **rev32** — running `V13` against the shipped tree found a **fourth** consumer the corrected list
  still missed: `s19_app/tui/styles.tcss`. It reads nothing and breaks silently if the class is
  renamed, which produced the definition the design lacked: **a dependant is not only something
  that reads the value; it is anything that would break if the address moved.**

**Two decisions the design left ambiguous, now closed in the template:** one field per line (its
schema and its own worked example disagreed), and **consumers are paths, not acceptance ids** —
`V13` compares that list against what a grep returns, so an entry must be the kind of thing grep
returns.

**`V13` was redefined before a line of it was written.** The design specified *"a requirement of
type `test` touching a declared surface"*, but *what counts as a surface* is stack vocabulary and
the design's own §5 puts vocabulary in the project. The agnostic core was already in `D-6`: the
provider declares, the validator **discovers by grepping the declared literal**. Grepping a literal
is stack-free — it serves a CSS selector, a register name and a channel key identically.

---

## 5 · Found while encoding, unrelated to `C-54`, recorded because it was severe

Asking how Kimi actually loads the flow — a question put to the machine rather than to the
manifest — produced **a third checkout nobody had declared**: `~/kimi/agent-skills`, the directory
Kimi is run from, **21 commits and nineteen flow revisions behind since 2026-08-09**. Bringing it
current moved **15 files and +2346 lines, eight of which did not exist in it at all**, including
`devflow-validate.py` itself and six of the thirteen templates. It was not a stale flow; it was a
flow with **no mechanical verification and half its templates**.

`V16`'s BLOCK arm reads *"N commit(s) behind"* and would have caught it on day one. It did not,
because its list of checkouts was hardcoded and held **two of the three**. Fixed at rev24 by
declaring the list in `docs/deployment.md`; rev26 added `--sync-checkouts` to advance them.

---

## 6 · Registered for the retrofit — NOT fixed here

**Two copies of the consumer list are still short**, and correcting them belongs to the Lane A
retrofit, not to the control:

1. `s19_app/tui/screens_directionb.py:1953` — the source comment naming two readers of
   `.loaded-detail`. The tree has four.
2. `design/C-54-information-flow-contract.md` §4 — the design's worked example, same two names.

Both were accurate when written. **`V13` is now the thing that notices when they stop being**, and
running it over the retrofit's declarations is what will surface them mechanically instead of by
somebody remembering this paragraph.

Also carried, unchanged: **`C-55`** stays registered-not-encoded — operator ruling 2026-08-14,
*decide it when `V11` is written*, and `V11` now exists, so it is live. `cardinality` alone does
not catch a **reorder**: the count holds, set equality holds, and a positional consumer breaks
anyway. `INDEXED POSITIONALLY` is written from today so that control lands against a corpus.

---

## 7 · The honest limit of what this closes

**None of the five rules can fail against this project yet.** All five report SKIP, because s19_app
has not authored an IFC — that is the Lane A retrofit, a different batch. What is demonstrated is
that the rules **run, and that they can go red**, plus one thing better than a synthetic arm: `V13`
found a real defect in the documentation of the control it belongs to, three times.

What is **not** demonstrated is that the contract is correct over s19_app's surfaces. The retrofit
is where that gets tested, and the ~40 surfaces it will ask *"who depends on this, and how do they
reach it?"* are, per `D-2`, its actual deliverable.
