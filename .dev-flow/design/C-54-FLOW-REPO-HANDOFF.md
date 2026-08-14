# C-54 — handoff for the FLOW repo, not for s19_app

**Written:** 2026-08-13 · **Working directory for this work:** `~/.claude` (a checkout of
`jav201/claude-config`) — **NOT** the s19_app repo.

---

## 0 · The scope correction that produced this file

An earlier charter put the `C-54` encoding into **s19_app's batch-82 as "Lane B"**. **That was wrong,
and the operator caught it:**

> *"Encodear las nuevas reglas para dev-flow y fast-dev-flow no es batch-82, porque no son de proyecto
> s19_app — los flows son agnósticos."*

**s19_app does not own the flow. It is one consumer of it.** Putting the provider's work in the
consumer's backlog is — with some irony — the exact confusion `C-54` exists to prevent.

| | Correct owner |
|---|---|
| **Encoding `C-54`** into the flow, template, validator, manifest | **`jav201/claude-config`**, its own repo and cycle |
| **batch-82** in s19_app | **the retrofit ONLY** — authoring s19's contracts, consuming the control |

⚠️ **`BACKLOG-PROCESS.md` in s19_app still carries the Lane B half. It needs to be reduced to a
pointer at this work, not deleted** — the finding and its evidence originated there.

---

## 1 · Status: the flow asset's real shape, measured

```
~/.claude  ──push──▶  jav201/claude-config   (CANONICAL)
                              └──mirror──▶  jav201/agent-skills   ← what Kimi consumes
```

**There is NO local checkout of the mirror.** `agent-skills` exists only on the remote.

### THREE surfaces inside `~/.claude`, not one

| Surface | Path | Role |
|---|---|---|
| **LIVE command** | `commands/dev-flow.md`, `commands/fast-dev-flow.md` | what Claude Code loads |
| **LIVE templates + manifest** | `templates/dev-flow/` (13 `.md`), `docs/FLOW-VERSION.md` | authored here |
| **PACKAGED copy** | `skills/dev-flow/{commands,templates,FLOW-VERSION.md,README.md}` | the bundle mirrored to `agent-skills` |

`skills/dev-flow/` is **not** a skill — it has no `SKILL.md`. It is a **packaged duplicate** of the
flow carrying its own `commands/`, `templates/` and `FLOW-VERSION.md`.

### Drift check, measured 2026-08-13 — currently CLEAN

```
commands/dev-flow.md        vs  skills/dev-flow/commands/dev-flow.md        IN SYNC
commands/fast-dev-flow.md   vs  skills/dev-flow/commands/fast-dev-flow.md   IN SYNC
docs/FLOW-VERSION.md        vs  skills/dev-flow/FLOW-VERSION.md             IN SYNC
templates: 13 live          vs  13 packaged                                 IN SYNC
```

> ⚠️ **This is the drift hazard nobody has a guard for.** Editing only `commands/` leaves the packaged
> copy stale, `agent-skills` ships the old flow, and **Kimi silently runs a different flow than
> Claude Code.** `FLOW-VERSION.md`'s hash covers the LIVE files only — it would still verify green
> while the packaged copy rotted. **Any C-54 edit must touch both, and the sync must be re-measured
> after.**

### Current version, both copies

```
flow_version : 2026.08.10-rev12
flow_hash    : 41144ca54e8b944a
controls     : C-10…C-53 (22 numbered) + 5 unnumbered + META
validator    : V1…V9
~/.claude    : clean, 0/0 vs origin
```

**`C-54` appears NOWHERE.** Verified by grep across all three surfaces.

---

## 2 · The work

Design: **s19_app** `.dev-flow/design/C-54-information-flow-contract.md` — it lives there because the
defect that produced it did. **Read it first.** Framing, non-negotiable and the operator's:

> *A structure for modeling the input and output of information to a system. Then UI/UX is a system.*

**Part A (Flow)** always owed; **Part B (boundary decomposition)** conditional on one agnostic
trigger: *does the system's boundary have components a consumer can address independently?*

### ⚠️ `D-6` must be decided BEFORE encoding

Provider-lists-consumers (as designed) vs **consumer-declares / provider-verifies** (Pact). *A
provider never learns when a new consumer appears.* Inverting moves authorship and changes **who the
validator holds responsible**. `D-5` (call it *balancing*), `D-7` (port vs item flow), `D-8` (name the
concern) are adopt-and-go.

⚠️ Standards named from working knowledge — **concepts firm, clause-level detail NOT verified.**

### Exit criteria — all verified by execution

1. **BOTH** `dev-flow.md` **and** `fast-dev-flow.md` — the fast flow owes **Part A only**, written in it;
2. `templates/dev-flow/ifc-template.md`;
3. `V10`–`V14` in `docs/tools/devflow-validate.py`, **each demonstrating RED in `--selftest`**, output pasted;
4. `docs/FLOW-VERSION.md` bumped — version, `flow_hash`, controls → `C-10…C-54` — manifest's own `sha256` recomputed;
5. **`skills/dev-flow/` packaged copy updated and re-measured IN SYNC** ← the surface that gets forgotten;
6. **pushed to `jav201/claude-config`**, `git -C ~/.claude status` clean **and 0/0 vs origin verified AFTER the push**;
7. **`jav201/agent-skills` mirror reconciled** — otherwise Kimi keeps the old flow;
8. a before/after record, since the flow is outside every project's PR flow.

**Why 6 is worded that way:** this project has shipped a change asserted locally that never reached
`origin`. `C-44` exists because of it. **A local edit to `~/.claude` is not a shipped control.**

---

## 3 · What is already done, and closed

- **batch-79 MERGED and synced** — `f198447`, record `a68d2eb`, sync `8372382`, `origin/main` asserts
  `obsidian_synced: true` verified on `origin/main` itself. Vault confirmed by the operator.
- **The design and the charter are committed** to s19_app under `.dev-flow/design/`.
- **batch-82 is chartered** — after this correction it should be **retrofit-only**.

## 4 · First moves for the fresh session

1. `cd ~/.claude` — **that is the working directory**, not s19_app.
2. Re-run the drift check in §1; confirm still IN SYNC before editing anything.
3. Resolve **`D-6`** with the operator.
4. Ask authorization — **per-session, never inherited**.
5. Then encode, against the eight exit criteria.
6. Reduce s19_app's `BACKLOG-PROCESS.md` Lane B entry to a pointer here.
