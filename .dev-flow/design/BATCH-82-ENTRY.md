# batch-82 — entry point for a fresh session

**Written:** 2026-08-13, at the end of the session that closed batch-79 · **Status:** CHARTERED, not started

---

## 0 · Read this first — one thing is repeatedly misunderstood

> ### ⛔ `C-54` IS NOT IMPLEMENTED. Nothing was encoded into any flow.

Verified at the close of the session, not asserted:

```
grep "C-54|Information Flow Contract|IFC" in
  ~/.claude/commands/dev-flow.md
  ~/.claude/commands/fast-dev-flow.md
  ~/.claude/docs/FLOW-VERSION.md          ->  ZERO hits
~/.claude/docs/FLOW-VERSION.md declares   ->  controls C-10…C-53   (NOT C-54)
~/.claude/docs/tools/devflow-validate.py  ->  rules V1…V9          (NOT V10–V14)
~/.claude vs jav201/claude-config         ->  0/0, clean
```

**`~/.claude` being "in sync" means it matches `rev12` — which PREDATES this design.** What was pushed
to `jav201/s19_app` is the **design document and the charter**, both under `.dev-flow/`. The control
itself does not exist anywhere. Encoding it is batch-82's entire job.

*(This was misread twice in one session. If you find yourself assuming the flow already has it, run
the grep above.)*

---

## 1 · What batch-82 is

**`C-54` — the Information Flow Contract.** Full design:
[`C-54-information-flow-contract.md`](C-54-information-flow-contract.md). Charter split across both
lanes per Amendment A:

| Lane | Owns | Entry |
|---|---|---|
| **B** (process) | the control: global flow, template, validator rules, propagation | `BACKLOG-PROCESS.md`, first section |
| **A** (code) | the s19 retrofit of ~40 surfaces | `BACKLOG-CODE.md`, `BATCH-82 CHARTER` |

**Neither half is complete alone.** Both say so.

### The one-sentence framing, which is the operator's and not negotiable

> *A structure for modeling the input and output of information to a system. Then UI/UX is a system.*

A UI-scoped framing was proposed and **rejected** — it would have made the global flow stack-aware,
violating the project-agnostic rule, and missed data acquisition and sensor arrays. The generalisation
is what keeps the flow agnostic **by construction** rather than by discipline.

---

## 2 · ⚠️ `D-6` must be decided BEFORE any encoding

Four prior-art decisions are registered. Three are adopt-and-go. **`D-6` is open and changes the
schema's shape:**

- **As designed:** the *provider* lists its consumers.
- **Pact / Consumer-Driven Contracts:** each *consumer* declares what it needs; the provider verifies
  against the union.

**Why it matters structurally:** *a provider never learns when a new consumer appears.* Inverting
moves authorship from ~40 surfaces to N consumers and changes **who the validator holds responsible**.

**Do not start encoding with this open.** The other three: `D-5` adopt "balancing" (DFD, ~1979);
`D-7` separate *port* from *item flow* (SysML); `D-8` name the concern (42010) — *"who breaks if I
change this?"*.

⚠️ Standards were named from working knowledge. **Concepts firm, clause-level detail NOT verified.**
*A cited standard is a figure like any other.*

---

## 3 · The six exit criteria — the flow lives OUTSIDE this repo

The operator emphasised this twice. **batch-82 does not close until all six are verified by
execution:**

1. **BOTH** `dev-flow.md` **and** `fast-dev-flow.md` carry the obligation — the fast flow owes
   **Part A only**, and that difference must be written *in* it;
2. `templates/dev-flow/ifc-template.md` exists;
3. `V10`–`V14` in `devflow-validate.py`, **each demonstrating RED in `--selftest`**, output pasted
   into the batch record — *a rule that cannot go red is a vacuous check with CI authority*;
4. `FLOW-VERSION.md` bumped — version, `flow_hash`, controls → `C-10…C-54` — and the manifest's own
   `sha256` command recomputed to match;
5. **pushed to `jav201/claude-config`**, mirror `jav201/agent-skills` reconciled, with
   `git -C ~/.claude status` clean **and 0/0 vs origin verified AFTER the push**;
6. before/after of the out-of-repo files recorded **in this repo's batch artifacts**.

**Criterion 5 is worded that way for cause:** this project has shipped a change asserted locally that
never reached `origin`. `C-44` exists because of it, and batch-78 needed PR #190 purely to land a
flag. **A local edit to `~/.claude` is not a shipped control.**

---

## 4 · The retrofit — operator ruled FULL, and the framing is the point

> *"Aunque me duela, si tenemos que hacer el retrofit… parece que hay mucho potencial para
> requerimientos ambiguos y comportamientos perfilados a medias."*

**The deliverable is the FINDINGS, not the file.** Authoring `address` and `consumers` for a surface
that never declared one forces *"who depends on this, and how do they reach it?"* onto ~40 surfaces
that have never been asked. `LLR-120.2` is one instance of that question going unasked — found by
accident, at the cost of a production regression and eight merge gates.

**Staged so it cannot gate the queue:** the control ships enforcing NEW and MODIFIED surfaces only
(`V13` as NOTICE); existing surfaces stay NOTICE until their screen's stage lands.

**Falsifiable prediction, recorded so it can be wrong:** ≥1 further address-vs-value ambiguity of the
`LLR-120.2` shape, and ≥1 surface whose declared behaviour has no owning requirement. **If the
retrofit finds neither, the control is over-priced and that finding is worth recording too.**

---

## 5 · State at handoff — everything below is CLOSED

| | |
|---|---|
| batch-79 | **MERGED** `f198447` (PR #192) · merge record `a68d2eb` · sync `8372382` |
| `origin/main` tip | `8372382`, asserts `obsidian_synced: true` **verified on origin/main itself** |
| Vault | synced, `Dashboard.md` untouched, operator confirmed Obsidian OK |
| Suite | 2691 collected, **0 unexplained failures** after Inc-12's regen |
| CI | `snapshot` pass · `tui-ci` pass |
| Local repo | on `main`, clean apart from a PARALLEL session's untracked `prototypes/`, `build/` |

**Batch numbering:** 80 = `C-77-l` aggregation · 81 = Lane 3 operations · **82 = this** · next free 83.
Verified against disk, `git ls-remote` and both backlogs. *This project has had two collisions.*

---

## 6 · Owed, all registered — none silent

**Lane A:** the 8 gate-8 observations (the substantive one: `#status_text` drops part of a load
message at 80×24 — **not** an information loss, the log tail carries it) · `M-4` · `F-6` (the registry
is blind to 108 nodes) · `N-7` · the 8 `subprocess.run(text=True)` siblings · the Inc-8/9/10 packet
gap, **with its price recorded**.

**Lane B:** `F-8` (P1, thirteen instances) · the symbol-anchor control (P2) · `C-55` — *a threshold
whose oracle NORMALISES something must state that the failure mode does not live in what it
discarded* — **registered, NOT encoded**, per the operator's control-encode ruling. Re-litigate after
the retrofit, which is its best evidence generator.

---

## 7 · Process notes that cost time this session

- **Authorization is per-batch AND per-session.** Ask again.
- **Run `devflow-validate.py` at every gate** — flow rev12 requires it. Current: 14 BLOCK / 227
  NOTICE, **all 14 from batch-01 (May 2026)**, none from 78/79.
- **`C-47`:** the cap is **≤4 SOURCE files**; tests uncapped; `.dev-flow/**` outside the count.
- **PowerShell here-strings mangle embedded quotes** — write commit messages to a file, `git commit -F`.
- **PowerShell pipes and redirects ADD a BOM.** A `git show ... | python` check reported a phantom BOM
  in `state.json`. **Compare `git hash-object` against the blob sha — never bytes read through a
  re-encoding pipe.**
- **Verify a restored mutation by CONTENT (`git diff`)**, not by `sha256` of a file Python rewrote —
  `write_text` translates newlines on Windows.
- **`state.json` is single-batch, last-writer-wins.** Re-read immediately before every edit.
- **A monitor's exit condition is a predicate like any other.** A waiter that exited on *"output does
  not contain `pending`"* fired on `no checks reported` and declared CI complete before it started.
