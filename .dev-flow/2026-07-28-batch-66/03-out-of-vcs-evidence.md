# batch-66 — out-of-VCS evidence

Four of the five edited files live **outside this repo**, so no PR diff covers them. This file plus
`pre-bytes/` **is** their diff and their rollback. The PRE bytes are committed here deliberately —
batch-64 §7.10 recorded that keeping `.PRE` copies only in a session-scoped `Temp` directory means
the rollback does not survive the session. That carry is *not* closed by this batch (it asks for a
durable location as a general rule); this batch simply does not repeat the mistake for its own files.

## Ledger

| File | PRE SHA256 | PRE bytes | POST SHA256 | POST bytes |
|---|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | `e103af29…58fd8d5` | 68 391 | `f484a117…cdd53814` | 69 469 |
| `~/.claude/commands/fast-dev-flow.md` | `babb461f…19a34b7d5` | 9 469 | `d3fec103…525a0b2` | 10 200 |
| `~/.claude/skills/dev-flow-lessons/SKILL.md` | `8485f6c2…db76b4502` | 33 872 | `a5ef55fe…f132dc548290` | 34 533 |
| `G:/My Drive/Courses/textual/PENDING-UPDATES.md` | `da15d710…93e545e41` | 7 546 | `e8c2280b…5281a0690c5` | 7 926 |

Full PRE hashes are reproducible from the committed bytes: `sha256sum pre-bytes/*.PRE`.

**Rollback:** `cp pre-bytes/<name>.PRE <destination>`, then confirm the destination's hash returns to
the PRE column above. The hash is the check — `git status` cannot see these files at all.

### ⚠ The first commit of these bytes was CORRUPT, and the ledger above is what caught it

`core.autocrlf=true` on this host. Committing the `.PRE` files as ordinary text normalised them, so
**the stored blob was not the file it claimed to be**: `dev-flow.md.PRE` went in as `d46bb314…`
against a recorded `e103af29…`. A rollback from that commit would have written LF where the original
had CRLF — restoring a file that hashes differently from the thing it is supposed to restore, while
looking perfectly healthy in `git log`.

Both directions are broken and it is worth stating separately, because the second is invisible at
commit time: `dev-flow.md.PRE` was **CRLF on disk** and was normalised **to LF on the way in**, while
`fast-dev-flow.md.PRE` was **LF on disk**, stored unchanged, and would have been converted **to CRLF
on the way out** at the next checkout. Same corruption, opposite direction, and only the first one
produces a mismatch you can see without checking out.

Fixed by `.gitattributes`: `.dev-flow/**/pre-bytes/** -text`. **`text eol=lf` — the pattern this repo
already uses for snapshot and golden fixtures — would NOT have worked here**, because these four files
carry *mixed* line endings by nature and `eol=lf` corrupts the CRLF one just as surely. Verbatim
storage is the only correct setting for bytes whose hash is the contract.

Verified after the fix, index blob vs working copy, all four: `MATCH`.

This is batch-63's own lesson (text-mode writers and CRLF hosts) reappearing one layer up, in the
*evidence* mechanism of a batch that cites it — which is the honest reason it is written here at
length rather than fixed quietly.

## What changed, per file

### 1. `~/.claude/commands/dev-flow.md` — 4 sites
The command instructed every batch to read and reconcile *"the SINGLE canonical cross-batch backlog
`.dev-flow/BACKLOG.md`"*. Now delegates: *"the file, or lane files, that the project's
`docs/engineering-rules.md` designates; absent such a designation, `.dev-flow/BACKLOG.md`"*.

- **:122** Phase-0 input — adds *resolve the routing first, then read the file it names*, and names the
  failure mode: a partitioned queue keeps no open work in the original file, so reading it alone
  returns an empty queue indistinguishable from "nothing pending".
- **:231** Phase-6 close — reconcile **the lane the batch belongs to**; the router only at batch close.
- **:235** the gate sentence — "until the canonical backlog reflects it", no longer file-named.
- **:252** the standing rule — the anti-drift invariant is **preserved and restated generically**:
  *every open item lives in exactly ONE canonical file*; a partition is a split, not a copy, so items
  MOVE between lane files. What stays forbidden is a second *de-facto* source drifting alongside.

### 2. `~/.claude/commands/fast-dev-flow.md` — 2 sites (:102 Phase C step 6, :126 standing rule)
**Not registered in the backlog.** Batch-64 §7.9 named only `dev-flow.md`, so the item as written
would have shipped a half-fix leaving `/fast-dev-flow` pointing at the router. Same treatment.

### 3. `~/.claude/skills/dev-flow-lessons/SKILL.md` — 4 sites
The catalog cited controls earned as late as `b64` (C-39, C-40, C-42) while its description, intro,
honesty note and provenance all claimed **38** post-mortems: an index understating its own coverage.
Corrected to the **measured 54** (`ls .dev-flow/*/05-postmortem.md | wc -l`), and the provenance now
records *how* the number is obtained so the next extension re-measures instead of carrying it.

> **Why this is not a find-replace.** Of the 16 occurrences of "38" in that file, **11 are batch
> citations** (`b38`, `35-38`) and **one is a hue value** (`38.44°`, inside the C-31 origin story).
> Only 5 were corpus-size claims. A blind substitution corrupts 12 unrelated facts, including a
> control's own worked example. Sites were selected by reading each match.

Also note the count is **not** the highest batch number — 56 batch directories exist and the
numbering has gaps, so `batch-64` implies neither 64 nor 56 post-mortems.

### 4. `G:/My Drive/Courses/textual/PENDING-UPDATES.md` — 1 site (header cross-reference)
Doubly stale. It pointed readers at `.dev-flow/BACKLOG.md` (now the router) **and** described the
other three P-3 legs as still queued when batch-64 shipped all three. Corrected on both axes, and it
now states plainly that the course leg is the only outstanding one.

## Executed counterfactual — the predicates, and the one that caught me

Two predicates, run against the committed PRE bytes and the POST files. Both are RED on PRE by
construction, which is the point: they are not presence checks.

```
P1  count of "single canonical"                  P2  count of "until `.dev-flow/BACKLOG.md`"
dev-flow.md        PRE=(2,2)  POST=(0,0)
fast-dev-flow.md   PRE=(1,1)  POST=(0,0)
```

**The first POST run read `fast-dev-flow.md POST=(0,1)`** — P2 was RED on my own incomplete
increment, because I had fixed `:102` and missed the standing rule at `:126`. The miss was found by
executing the predicate, not by re-reading the edit. Recorded because a clean final table otherwise
implies a clean first pass.

A third predicate closes the obvious hole in the first two — deleting the mentions would also satisfy
P1/P2, so: **every surviving `.dev-flow/BACKLOG.md` mention must be framed as the named default.**
`mentions=3, framed-as-default=3`.

## In-repo side (covered by the PR)

`docs/engineering-rules.md` gains a **`## Backlog routing`** section — deliberately **not** numbered
`C-NN`. It is a routing fact, not a discipline, and minting a control id needs its own operator
AskUserQuestion (`feedback_devflow_control_encode_approval`). **`C-41` remains FREE** (batch-64 §7.6);
this batch did not consume it.

Verified: `grep -rln engineering-rules tests/ s19_app/` → no hits, so no test is coupled to that
document; `git diff --stat origin/main` over the engine-frozen set → empty.
