# Increment plan — batch `2026-08-24-batch-88` — seven increments, each with its gate

> **This is a PLAN, not an executed packet.** It is named `00-increment-plan.md` so it is not
> mistaken for an `increment-00N.md` post-execution record. Each increment ships its own packet
> under this directory when it runs; this file is what those packets are measured against.
>
> **Authored to discharge condition C8** of the station-4 design review, which withheld **every**
> increment until it existed: *"seven increments enumerated, each with its source-file set, its
> pre-state, its post-state and its gate."* See `PDR-2026-08-25-batch-88#D8`.
>
> **Every pre-state below was executed on 2026-08-25**, on branch `claude/batch-88-audit-closures`.
> Re-derive before starting an increment — a pre-state is a reading, not a constant, and this batch
> has already watched four of its headline figures expire between stations.

## 0 · The invariants every increment carries

| # | Invariant | Source |
|---|---|---|
| I-1 | **Every new or patched rule owes a `PASS != NOOP` arm, and its GREEN arm asserts the pass SENTENCE, not the absence of a BLOCK.** | operator, non-negotiable; `HLR-88.1` |
| I-2 | Each increment records **its own** pre-state and post-state gate line. The batch-wide gate value moves inside the batch, so a single batch-wide number would splice mutually exclusive states. | batch criterion 3 |
| I-3 | `LLR-88.4` applies to **all seven**, not to one: the arm floor is stated per rule with a named kill mutation each. **The QA plan rejected 5 of 29 proposed arms and three independent lenses confirmed those rejections** — do not adopt the proposed arms without reading `01b-qa-validation-plan.md`'s audit. | `LLR-88.4` |
| I-4 | The derived Atlas re-stales on every `.dev-flow/**` write, including writing the increment's own packet. Regenerate with `--atlas --write` **after** the packet exists, not before, or you buy a second staleness. | batch-86 F1 lesson; V20 |
| I-5 | Source-file budget **≤ 4 per increment**. Max here is **3** (Inc 7). Derived Atlas files and `.dev-flow/**` are outside the count. | `AT-B88-08`; PLAN §4 |
| I-6 | The operator's parallel session holds untracked work under `prototypes/`, `build/` and in `~/.claude`. **Never swept, never counted, never committed** by this batch. | C-44 |

## 1 · Sequencing, and what forces it

Three orderings are **binding**; the rest is free.

1. **Inc 1 lands FIRST** — operator ruling: the census re-baseline is recorded before any
   canon-seeding evidence exists. Story E is in batch-89 and will measure against it.
2. **Inc 7's flow-version bump is LAST** — `LLR-88.16` re-declares the flow's identity *after* the
   final edit. A bump before the last edit is a hash that lies.
3. ~~Inc 6 is withheld until the `security-reviewer` lens runs.~~ **DISCHARGED 2026-08-26** — the
   lens ran over both files and its record is `02-review-security.md`: verdict `safe with
   conditions`, 0 blocker, 2 medium, **both dispositioned by operator ruling**. Inc 6 is released.

Inc 2 needs no sequencing guard: its oracle was **stilled** by the C-56 de-minting already landed
in this batch's Phase-1 re-work, so it moves no live verdict. That is why the oracle table now
counts five moves and finds only two still moving.

---

## 2 · The seven

### Inc 1 — the census oracle becomes token membership, and says what it counted

| Field | Value |
|---|---|
| Requirements | `LLR-88.6` (oracle) · `LLR-88.7` (the message names its population) · `LLR-88.8` (the re-baseline, already recorded in Phase 1) |
| Source files | `~/.claude/docs/tools/devflow-validate.py` — **1** |
| Pre-state (executed 2026-08-25) | `V22` reports **302 of 570** unreflected ids. Membership is `rid not in canon` — a **substring** test over the whole canon text |
| Post-state | **306 of 570**. Delta **+4**, and the four are named, not sampled: `HLR-053`, `HLR-056`, `US-064`, `US-068` — each reads as present today only because a longer id sharing its prefix exists |
| Gate | The census line moves 302 → 306 **and** the four named ids appear in the missing set, checked one id at a time. **A total alone is not the gate** — a substring→token change that moved the count by +4 for the wrong four ids would pass a total and fail this |
| ⚠ | Reverting the oracle leaves **221 arms with zero verdict changes** while moving the live census — measured by the reviewer. The arm set is blind to this fix, so the live census **is** the discriminating evidence and must be in the packet |

### Inc 2 — the design-review grammar, strict, and the harvester that feeds it

| Field | Value |
|---|---|
| Requirements | `LLR-88.9` (both halves: grammar **and** citation harvester) |
| Source files | `devflow-validate.py` — **1** |
| Pre-state | `V23` reports **48 citations, every one conforming** — the corpus was cleaned by the Phase-1 de-minting. Harvester probe M-11: **8 of 12** ordinary Markdown contexts turn a *conforming* citation into a notice |
| Post-state | Grammar expresses a record, a `.md` filename, a `-v<n>` version and a decision inside either, and rejects a hyphenated batch-directory name. Harvester discards trailing characters by a **character class derived from the grammar**, not by an enumeration of Markdown delimiters |
| Gate | Non-conforming set stays **∅** over a population ≥ 48; **≥ 11** grammar arms (≥ 2 reject the hyphenated dir, ≥ 2 accept a version, ≥ 4 preserve shipped rejections); **≥ 8** harvester arms, one per failing context of M-11; **≥ 1** arm asserting a bare-hash form still FAILS after the widening |
| ⚠ | **The live corpus cannot discriminate the candidate grammars** — all three score 48/48 — so the arms are the only evidence this increment has. A criterion phrased as "the live citations still conform" is green under the grammar the operator rejected |

### Inc 3 — the sentence family: three rules that pass and could-not-check in one voice

| Field | Value |
|---|---|
| Requirements | `LLR-88.1` (V5 ledger) · `LLR-88.10` (V8 map resolver) · `LLR-88.11` (V8 root file) |
| Source files | `devflow-validate.py` — **1** |
| Pre-state | V5 prints `SKIP: no ledger expression found` for **57 of 61** validation records — **byte-identical** for a correct ledger and for a file with none; the 4 that parse are batches **09, 10, 11, 74**, and **36** of the 57 mention a ledger in prose. V8 opens `docs/ARCHITECTURE.md` while git tracks `docs/architecture.md`. `setup.py` raises *"under no declared module — the map is stale"* |
| Post-state | V5's two outcomes carry distinct sentences. The map resolves case-insensitively over its parent directory, **preferring an exact name when one exists**. A repository-root file reads as *unexpressible by the rule*, not as a stale map |
| Gate | V5's sentences differ under both branches; **57** records change what V5 says about them; the resolver returns the on-disk casing, the exact name when present, and nothing for an absent file **and** an absent directory; the root-file and real-orphan notices are two different sentences |
| ⚠ | **The casing fix is LATENT, not active** — no CI job, git hook or settings entry runs the validator, measured. Its arm therefore asserts the **resolver's return value**, which is platform-independent. **The QA plan's proposed `CASE-adopted` and `CASE-exact-wins` arms were REJECTED and the rejection independently confirmed**: both stay green when the fix is reverted |

### Inc 4 — the scope family: two rules that read a line where they mean a block

| Field | Value |
|---|---|
| Requirements | `LLR-88.2` (V2 acceptance ids) · `LLR-88.3` (V6 modal, **and its new pass sentence**) |
| Source files | `devflow-validate.py` — **1** |
| Pre-state | V2 tests **substring** membership against one concatenated `tests/` text; **989** distinct acceptance/test-case tokens (`_ATLAS_ID_ATTC`, `devflow-validate.py:1574` — the tokenizer M-6 names; a briefly-published 915 was withdrawn as undefined) on disk. V2 **SKIPs in this repository** — its pattern needs a digit right after the prefix and this project's ids are letter-initial. V6 requires the marker and the modal on the **same physical line**, and **emits nothing at all on success** |
| Post-state | V2 resolves by token. V6 evaluates the whole statement block and **emits a pass sentence naming the blocks it scanned** |
| Gate | V2: a short id no longer resolves through a longer sibling — **synthetic, and the acceptance says so**, since the rule has no live instance here. V6: a wrapped statement with the modal on a continuation line yields **1** BLOCK where the shipped rule yields **0** findings; a modal in the rationale yields **0**; **≥ 2** arms over the new pass sentence, one asserting it differs from the no-document sentence |
| ⚠ | V6's hole is real and **0 instances have fallen through it**: 930 statements, 207 wrap, 5 carry a modal, V6 caught all 5. Do not let the packet imply a live escape was found |

### Inc 5 — the loader stops handing the gate someone else's document

| Field | Value |
|---|---|
| Requirements | `LLR-88.5` · **the docstring correction travels here, in the same increment as the body** (`PDR-2026-08-25-batch-88#D9`) |
| Source files | `devflow-validate.py` — **1** |
| Pre-state | `_artifacts` prefills every basename first-wins across all batch dirs, then overrides **only** basenames present in the active dir. **Today the window is CLOSED**: the loader resolves `01-requirements.md` to the active batch-88 copy, byte-identical, and not to batch-01's May document. The gate is **0 block** both shipped and patched |
| Post-state | The declared batch's copies are **preferred**, and an artifact absent from the active batch reads as **absent** rather than silently resolving to another batch's file. The docstring stops promising preference while the body implements exclusion |
| Gate | With the active dir holding a partial artifact set, every present basename resolves to the active copy and every absent one reports absence. **The `14 block → 0` demonstration no longer reproduces** — the window closed when P1 authored — so the gate is the **resolution**, not the block count |
| ⚠ | **This increment's original justification has expired and must not be re-cited.** The honest subject is the **window** every batch passes through before authoring its record, bounded independently at **10 of the 14** blocks. Cite the window; the count is gone |

### Inc 6 — the imaging dependency reaches the job that needs it

| Field | Value |
|---|---|
| Requirements | `LLR-88.12` · `HLR-88.6` |
| Source files | `pyproject.toml` · `.github/workflows/tui-ci.yml` — **2** |
| **Withheld until** | ~~the `security-reviewer` lens~~ — **RELEASED 2026-08-26**, `02-review-security.md`. Two rulings travel with it: the entry is **floored at `>= 10`**, and F2's silent-failure risk is **accepted with its mitigation declined** to hold the edit at 4 lines |
| Pre-state (M-12) | Manifest declares the library **nowhere**; one ad-hoc `pip install pillow` at `tui-ci.yml:42`. `[project].dependencies` holds **3** entries; the `dev` extra holds **2**, one of which pins `textual==8.2.8`. The `tui-ci` job installs bare `-e .` at `:43` and runs the **full** suite on push; the `snapshot` job already installs `.[dev]` at `:76` |
| Post-state | A new `evidence` extra holds **1** entry, **floored at `>= 10`** with a rationale comment (operator ruling 2026-08-26); `tui-ci`'s install is routed through it and the three ad-hoc lines removed; `[project].dependencies`, the `dev` extra and the `snapshot` job's install are **byte-identical** |
| Gate | `AT-B88-09`: installing `.[evidence]` yields an importable imaging library **and** a `textual` that is `>= 8.0.2` and **not** the `8.2.8` pin; `.[dev]` yields the pin; **bare `-e .` must FAIL** the import. `.github/` shows exactly **1** file and **5** lines (the fifth is the import guard) |
| ⚠ | **The negative control is not optional.** The imaging library is already installed on the authoring machine, so the positive check passes **before the fix exists**. Without the bare-`-e .` arm this gate is green on a defect. **Second, an ACCEPTED RISK the operator ruled on 2026-08-26:** a mistyped or renamed extra exits **0** silently (measured, pip 24.2), and because the GIF test is `slow` while PRs run `-m "not slow"`, a broken extra would keep every PR green and break `main` after merge. The one-line import guard was declined to hold the edit at 4 lines. **RULING REVISED the same day: the guard IS adopted** and the edit is **5** lines. The declined version is kept in `AT-B88-09` and `02-review-security.md` as superseded |

### Inc 7 — Story C, the derived exemption set, and the flow's re-declared identity

| Field | Value |
|---|---|
| Requirements | `LLR-88.13` (V25's checks and four outcomes) · `LLR-88.14` (its arms **and the COMPUTED exemption set**) · `LLR-88.15` (INTAKE row) · `LLR-88.16` (rev47 bump + re-hash) |
| Source files | `devflow-validate.py` · `~/.claude/templates/dev-flow/phase-checklists.md` · `~/.claude/docs/FLOW-VERSION.md` — **3** |
| Pre-state | `V24` and `V25` occur **0** times in the flow repo; no "Layer C" text exists. `phase-checklists.md` has **no** RC-2 row and RC-1 is INTAKE row 4 of 8. Flow is `2026.08.24-rev46` · `9c1449ed815d267c`; selftest **192** arms, exit 0. **The synthetic-exemption "list" is a hardcoded `print()`; nothing computes membership and `ok` is never influenced by it** |
| Post-state | V25 exists with four distinguishable outcomes. RC-2 lands as INTAKE **row 5**, shifting nothing. The exemption set is **derived** as `CHECKS` minus the emitted arm labels, printed, and drives `ok` against a declared expected set. Flow re-declared at rev47 with a fresh hash |
| Gate | Selftest exit **0**, arm lines **≥ 240**; **≥ 6** V25 arms with **2** threshold-boundary arms at 30 and 31 days; the derived set is exactly `{V8}`; **≥ 1** arm feeds the derivation a corpus where a rule has no arms and asserts the set is **non-empty**; V7 and V20 green on both sides of the bump |
| ⚠ | **Without the non-empty arm the vacuity has only moved.** A derivation that always returned `∅` would pass every check written over it — which is precisely the defect being repaired, one layer up. Bump **last**, and pay step 4 (re-hash) or V7 reports drift that does not exist |

---

## 3 · What this plan does NOT authorise

- **Batch-89 work**: Stories A (Layer C, `V24`), B (assurance limits + the review-debt marker) and
  E (canon seeding). The interface freeze at `docs/architecture.md:226-236` names batch-88 **by
  literal string** and must be amended when batch-89 opens, or `V24` debuts with zero real
  consumers.
- **`R-88-6`**, the `requirements.txt` third declaration surface found while measuring Inc 6. It
  disagrees with the manifest twice and is harmless **by install ordering alone**. Batch-89.
- **`R-88-4`**, the example-GIF test's zero import-skip guards: a `tests/` edit this batch's pin
  forbids.
- **`_ATLAS_ID_REQ`'s 129 non-ids** — 97 range notations, 32 prose compounds. Inherited, not
  re-measured, and it re-baselines with Story E.

## 4 · Condition status at the time this plan was authored

| Condition | State |
|---|---|
| C1 · C2 · C3 · C4 · C5 · C6 · C10-b | **discharged** in the Phase-1 re-work |
| C7 | **discharged** — `HLR-88.6` / `LLR-88.12` re-authored, criterion 8 and `AT-B88-08` widened, `AT-B88-09` minted |
| **C8** | **discharged by this file** |
| C9 | **DISCHARGED 2026-08-26** — `02-review-security.md`; Inc 6 released |
| C10-a | **open by design** — travels inside Inc 5, per the review's own instruction |
