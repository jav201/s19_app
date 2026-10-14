# Increment 001 — <REQ-ID> · `<Short title>`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/increment-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `SOURCE files` · `Instrument RED-proof` · `Correction population` · `Mutation verdicts` · `Emitted-form assertion` · `Reverse census` · `RED counterfactual` · `Independent review` · `Evidence files` · `Traces to` · `File` · `Kind` · `source` · `test` · `doc` · `config` · `generated` · `fixture` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Where this lives:** the **repo**, next to the diff it describes —
> `.dev-flow/2026-10-13-batch-95/03-increments/increment-001.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

> **A table you may delete.** A table whose `| **Field** |` row reads `none — <reason>`, or whose question one line of the gate checklist answers, may be deleted, its field row kept: `stations/core-runbook.md` §*A minimal increment packet* is a one-function change written that way.

| Field | Value |
|---|---|
| Batch | `2026-10-13-batch-95` |
| Increment | `001` |
| Lane (if the batch forked) | `<lane name>` · `<modules owned by this lane>` |
| Requirement(s) | `<R-NNN vN / LLR-NNN.n>` |
| Acceptance | `<AT-NNN>` · white-box `<TC-NNN>` · unit `<layer-0 nodes>` |
| Agent | `software-dev` |
| Date | `2026-10-13` |

---

## 1 · What changed

*(BLUF: state the outcome first, then the mechanism. Name the shipped surface the user reaches.)*

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|

| Count | Value |
|---|---|
| **SOURCE files** | **`<N>` / 4** |
| Test files | `<N>` (uncapped) |
| Doc files | `<N>` (outside the count) |

- ⚠ **At exactly 4 source files:** state here why this increment could not be cut smaller.
- ⚠ **Above 4:** this does not auto-block, but the reason goes here **and** the design/close review looks at it.
- ✗ If a file belongs to another lane's file set, stop: lanes may not share a file.

---

## 3 · How to test

```bash
<the exact commands, copy-pasteable>
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | `<nodes>` | <N passed> |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `<nodes>` | <N passed> |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | `<nodes>` | <N passed> |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | `<what was changed to make the assertion fail>` |
| Instrument | project code: your own hand or a script in the project's stack, the restore checked by hash · a batch whose subject is the flow: `python scripts/devflow-mutate.py --select ID,ID`, run from the bundle root — field guide §`Mutation verdicts` |
| Where it ran | **the tree, and who ran it** — the orchestrator when a spawned sub-agent wrote the code (`stations/p3-implementation.md` §Phase 3); never a tree another lane or session is reading |
| Transcript | `<paste: the RED output, plus confirmation the mutation actually applied>` |
| Restore proven by | **file hash returned to its pre-mutation value** (`git status` alone is insufficient, and vacuous for an untracked file) |
| Bytecode cache | cleared / run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | `<N>` — **assert the expected count.** An arm the harness cannot see is an arm it cannot report inert; a whitespace-delimited node pattern silently drops every *parametrized* arm |
| Verdict granularity | **per resolved node id**, never the process exit code — a runner exits non-zero if ANY arm fails, so an inert arm hides behind a sibling that failed |
| Arms that stayed GREEN | `<name them, or 'none'>` — `3 passed` unread in a transcript is how four arms once survived a fully removed gate |

| Field | Value |
|---|---|
| **RED counterfactual** | `<the mutation that made THIS increment's OWN new assertion fail, by position and operation · where its transcript is stored · the restore digest that returned the file to its pre-mutation bytes — or: none — no new assertion in this increment>` |

| Field | Value |
|---|---|
| **Mutation verdicts** | `<per resolved node: the mutation by position and operation · KILLED / CRASH / SURVIVED / BAD (the mutation's anchor did not apply) · the arms that stayed GREEN, named · the transcript's path under artifact_homes.evidence and the restore digest — or: none — no mutation battery in this increment>` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `<test / counter / mutation harness / grep / parser>` | `<the corruption planted in its MECHANISM, not in its verdict>` | `<the failure it printed, verbatim — and where>` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | `<N instruments, each shown RED before its first PASS was believed — or: none — no instrument beyond the suite>` |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| `<the file / report / screen / record>` | `<the command or predicate, pasted>` | `<its actual output, verbatim>` |

| Field | Value |
|---|---|
| **Emitted-form assertion** | `<N artifacts, each asserted against the form its producer emitted — or: none — this increment emits no artifact>` |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| `<the transcript / capture / snapshot / .PRE copy>` | `<the path, as stored>` | `<the 64-hex digest of the bytes AT THAT PATH>` |

| Field | Value |
|---|---|
| **Evidence files** | `<N artifacts, each at the declared home and cited with the digest of its stored bytes — or: none — this increment cites no evidence file>` |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | `<yes: name it / no>` |
| If the result is an ABSENCE, what made the search wide enough | `<the over-broad property — and the guard that protects it>` |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `<node id — else the next reader "improves" it away>` |
| Conjunctive criteria: one mutation per conjunct | `<per-conjunct verdicts, or 'no conjunctive criterion'>` |
| Synthetic instance of the absent case | `<fixture / in-memory module that contains what the tree lacks>` |
| **Positive control for every probe that returned an ABSENCE** | `<the known-present case, and the NON-absent output the same unmodified probe returned on it>` — uniformity over heterogeneous inputs (N-of-N) is one failure repeated, not a measurement |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl <symbol> tests/` | `<files, and whose they are>` |
| B2 file moved on disk | `<glob probe over the old path>` | `<readers found>` |
| B3 byte-identical golden captures this source | `grep <source> tests/goldens/**` | `<hits>` |
| B4 artifact produced here is consumed elsewhere | `<who reads the path/format written>` | `<consumers>` |
| A3 interface consumed by another module changed | `grep <symbol>` outside its owning module | `<hits>` |

| Field | Value |
|---|---|
| **Reverse census** | `<N probes run of B1 · B2 · B3 · B4 · A3, each with its command and its verdict — N hits, and where every hit was re-validated — or: none — this increment touches no code symbol or shared surface>` |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| `<the claim being corrected>` | `<what kind of thing must be true everywhere>` | `<the command, pasted>` | `<N>` | `<…>` | `<…>` |

| Field | Value |
|---|---|
| **Correction population** | `<N corrections, each enumerated with its method before its first site was edited — or: none — no correction>` |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `<marker>` | `<N hits>` | yes/no | `<…>` |

### Signed-balance test ledger

`post = base − deleted + added` → `<post> = <base> − <D> + <A>`  ✓ reconciles

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `<who reviewed · the verdict · how every HIGH was resolved — or: WAIVED-BY-OPERATOR — and the reason, in the operator's own words>` |

*Example of a filled cell:* `` `code-reviewer` · PASS-WITH-NOTES, 0 HIGH / 5 MEDIUM · all five
folded into this increment — F1 severity census, F2 block truncation, F3 blocklist, F4 scope
state, F5 this table ``

---

## 5 · Risks

*(What could break that this increment does not cover. Be specific enough to act on.)*

---

## 6 · Pending items / spec deviations

*(Anything surfaced and not closed here. Every line lands in the canonical backlog at batch close —
if the increment surfaced it, the backlog owns it.)*

---

## 7 · Suggested next task

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | | |
| 2 | Tests written in this same increment | all | | |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | | |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | | |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | | |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | | |
| 7 | No file from another lane touched | all | | |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | | |
| 9 | Coverage claims verified **on disk**, not from intent | all | | |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | | |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | | |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | | |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | | |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | | |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | | |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | | |
