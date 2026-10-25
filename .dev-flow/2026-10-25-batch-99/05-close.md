# Batch close — s19_app — Batch 2026-10-25-batch-99

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language — the **prose**,
> and never a label.

> **Owed in.** `core` ✓ · `full` —

> **Field guide:** `templates/guides/close-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Conditional-gate discharge` · `New controls` · `Human perimeter` · `Human review ledger` · `Gated tree` · `Found before the batch` · `⏸ DEFER`
> **And the §6 DEPTH tokens — cell VALUES rather than field names, reserved for the same reason:**
> `light` · `rigorous` · `spot-check` · `none` · `✅` · `❌`. A CLOSED set, declared closed by the first
> revision that ships it — so the vocabulary a later promotion of `V54` to BLOCK will need already exists,
> instead of being introduced over a free-text field that six authors have by then written six ways.
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Notice convention.** `⚠` yellow = declare and continue · `✗` red = block · `✓` green = satisfied
> **with its citation**.

---

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `<the validator command, the exit code THAT run printed, and 0 block · date>` |
| Gated tree | `<the 40-hex HEAD at the gate · clean — or: dirty — the files>` |
| Requirements canon | `<the canon path `artifact_homes.requirements_canon` declares — every id this batch's `01-requirements.md` declares as a heading is a token in it>` |

---

## 1 · What changed

*(BLUF. What the user can now do that they could not before, and through which surface. Then the mechanism.)*

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| `R-NNN` | `vN` | `AT-NNN` · `TC-NNN` | |

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|

**The four landings — record which ones actually happened. Command-but-not-template is *half-encoded*, and the missing half is the enforceable one:**

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** (`commands/…`) — the rule itself | | |
| 2 | its **artifact** (a template section) — a control with no output degrades to "I thought about it" | | |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | | |
| 4 | **committed and pushed**, manifest re-hashed and bumped | | |

- **New controls:** `<N control(s) minted → C-NN, C-NN | none — the reason this batch minted none>`

---

## 3 · Working-file reconciliation (C-44)

| File | State | Evidence |
|---|---|---|
| `<path>` | ✅ committed **and landed** (PR / merge named; with no `origin` remote, the local branch and the no-origin premise) · 🗑️ deliberately reverted · 📋 left on purpose, path + remaining work in the backlog | |

- **Found before the batch:** `none — no tracked file was modified when the batch began`

### Conditional-gate discharge

- **Conditional-gate discharge:** `<N condition(s) · ✅ all discharged | N condition(s) · ⚠ M outstanding, named below | none — no gate closed conditionally>`

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|

---

## 4 · Backlog reconciliation — the carry-over contract

| Item | Move | Reference |
|---|---|---|

---

## 5 · Batch metrics — the 13 keys of `core`

Extract, do not invent: a key the artifacts did not record goes `null`, and the key is never dropped.

```yaml
type: dev-flow-batch
project: <str>
batch_id: <str>
mode: core
verdict: pass | iterate
increments: <int>
source_files_max: <int>          # highest source-file count in any one increment
notices_raised: <int>            # distinct NOTICE ids declared in PLAN.md
rework_returns: <int>            # items that came back, per QA's phase checklists
triggers_fired: <str>            # e.g. "B1,B4,C3"
tests_base_to_post: "<base> -> <post>"
new_control: <str | none>
open_items_next: <int>
```

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| `<one row per human-auditable artifact this batch produced>` | | | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that
nothing has to be deleted: a row copied out of it would claim a reading that did not happen.
Write your own rows in the table above, one per artifact.

```text
| *(example)* `01-requirements.md` | gate §4 ✓ · `V26` green | ✅ | `rigorous` | |
| *(example)* Test cases / ATs | `V37` 12/12 · mutants 9/9 KILLED | ✅ | `light` | the fixture matrix behind `AT-007` |
| *(example)* Evidence view | `V41` — every cited file resolved | ❌ | `none — read the packet summaries instead` | |
| *(example)* Code | gates + reviewer verdict `PASS` | ✅ | `spot-check` | not audited line by line |
```

- **Human perimeter:** `<what this flow does NOT cover and the operator owns — e.g. personnel selection, organisational environment, business judgement | none — why nothing lies outside>`
- **Human review ledger:** `<human:NAME — N artifact(s) reviewed, M rigorous · K declared not-reviewed | none — why this batch recorded no human review>`
