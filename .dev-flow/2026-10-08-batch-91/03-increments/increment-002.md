# Increment 002 — `HLR-123` — the docs catch-up: README and `docs/` describe the shipped 10-screen app

> **Agent note.** Same substitution as increment 001, declared once more because each
> packet stands alone: the opencode route failed at the provider
> (`inc002-run.log`: `Error: Incorrect API key provided`); the increment ran on a
> **Kimi coder subagent** under the coordinator's brief (`inc002-brief.md`).

| Field | Value |
|---|---|
| Batch | `2026-10-08-batch-91` |
| Increment | `002` |
| Lane (if the batch forked) | none — one lane; this increment owns `README.md` + `docs/` and nothing else |
| Requirement(s) | `HLR-123` |
| Acceptance | `AT-285` — **stays RESERVED, declared**: no acceptance harness was minted for the docs (the brief scoped the work to the four documents and the verification to grep-driven inspection); see §6 |
| Agent | `kimi-k2.7-code` (coder subagent), coordinator-briefed |
| Date | `2026-10-11` |

---

## 1 · What changed

**A new reader now learns the shipped app, not a superseded one.** Four documents,
223 insertions / 122 deletions, zero code:

- **README.md** (+127 lines touched): the **CDFX promise is killed with its
  replacement named** — the v2 change-set JSON plus the patched S19/HEX image emit
  (the `tui/cdfx/` package is deleted; every line that named it as live is gone).
  The shipped surfaces it omitted are documented: the **variants system**
  (`project.json` manifest, per-variant assignments, variant-scoped execution, the
  fused report), the **Flow Builder**, the **CRC Designer**, the **Operations
  modal**, and the previously undocumented global keys (`U` unload-all, `r`
  refresh, `o` open workarea, `v` variant, `j` A2L JSON dump, `t` report viewer,
  `b` before/after, the `+`/`-`/`,`/`.`/PgUp/PgDn` paging keys, `Ctrl+Z`/`Ctrl+Y`
  undo/redo). The key tables were reconciled against the shipped keymap — the
  README now says the full set lives in `S19TuiApp.BINDINGS` and documents every
  bound key or deliberately marks it (measured at close-out: **31 app-level
  bindings** at `s19_app/tui/app.py:1339`, 40 `Binding(` sites across
  `s19_app/tui/*.py`). The CLI section records `s19tool` as the library's **legacy
  module-only CLI** (`python -m s19_app.cli`), not a console script — measured:
  `pyproject.toml` registers only `s19tui`. The test count reads **2760** (the P0
  post-repair measurement).
- **docs/overview.md** (66 lines touched): 8 → **10 rail screens** (Workspace, A2L
  Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Flow
  Builder, Checks, CRC Designer) + the fourteen modals; the engines list (the
  parsers, the validation engine's issue codes, the change-set engine v2, the CRC
  family, the entropy service); superseded history marked as such (the Bookmarks
  placeholder superseded; the CDFX row reads *"the CDFX exchange surface itself
  was removed"*).
- **docs/architecture.md** (145 lines touched): the module tables corrected to the
  shipped tree, the dead test citations dropped, the **29 SVG baselines** measured;
  the batch-03 CDFX XML reader kept as a *Historic:* note.
- **docs/crc-algorithm-designer/01-requirements.md** (+7): a header marking it the
  designer's **pre-ship design record** — the shipped behavior is the CRC Designer
  screen's contract in the canon.

The genre was kept: structure and voice untouched, content corrected — the brief's
own rule ("a doc naming a thing that does not exist is the exact defect this batch
closes") was enforced by reading every named surface against the code.

---

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `README.md` | `doc` | | CDFX promise killed (replacement named); variants / Flow Builder / CRC Designer / Operations documented; key tables reconciled with `S19TuiApp.BINDINGS`; CLI = module-only legacy; test count 2760 |
| `docs/overview.md` | `doc` | | 8 → 10 screens; engines list; superseded history marked |
| `docs/architecture.md` | `doc` | | module tables corrected; dead test citations dropped; 29 SVG baselines measured |
| `docs/crc-algorithm-designer/01-requirements.md` | `doc` | | pre-ship design-record header |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 |
| Test files | 0 (uncapped) |
| Doc files | 4 (outside the count) |

---

## 3 · How to test

```bash
# the batch's own sanity gate for a docs-only increment
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest tests/test_id_registry.py -q -p no:cacheprovider

# the inspection arms (run at close-out against the emitted files)
grep -n "CDFX" README.md docs/overview.md docs/architecture.md docs/crc-algorithm-designer/01-requirements.md
grep -rn "s19tool" README.md docs/overview.md docs/architecture.md
grep -c "Binding(" s19_app/tui/app.py   # plus the screen-level Binding( census over s19_app/tui/*.py
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — no code moved | n/a |
| **A · white-box** | `core` · `full` | none minted | n/a |
| **B · black-box** `AT-285` ↔ US-103 | `core` · `full` | **0 arms — the id stays RESERVED** | the outcome was verified by inspection (the greps below); the missing harness is a declared deviation, §6 |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| **RED counterfactual** | none — no new assertion in this increment. The negative control the contract names (*"the CDFX/`s19tool` mentions must be gone or clearly historic"*) was executed as an inspection: both greps below return **only** sentences that name the removal |

| Field | Value |
|---|---|
| **Mutation verdicts** | none — no mutation battery in this increment (docs-only; no assertion to mutate against) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Field | Value |
|---|---|
| **Instrument RED-proof** | none — no instrument beyond the suite and grep. The two greps are self-proving as instruments: each DID return rows (the historic mentions), so a silent-empty pass was impossible to mistake for coverage |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the four documents | `grep -n "CDFX" README.md docs/overview.md docs/architecture.md docs/crc-algorithm-designer/01-requirements.md` | 2 hits, both historic-marked: `docs/overview.md:87` (*"the CDFX exchange surface itself was removed"*) and `docs/architecture.md:134` (*"Historic: the batch-03 CDFX XML reader … removed with the `cdfx/` package"*) — zero live promises |
| the four documents | `grep -rn "s19tool" README.md docs/overview.md docs/architecture.md` | distribution name, `.s19tool/` workarea paths, and `README.md:405` **"No `s19tool` console script. `pyproject.toml` registers only `s19tui`"** — zero live console-script claims |
| the key tables | keymap census: 31 `Binding(` in `S19TuiApp.BINDINGS` (`s19_app/tui/app.py:1339`), 40 across `s19_app/tui/*.py` | the README's two key tables cover the rail (`1`–`0`) and every other bound global key, and name `?` as the in-app discovery surface for the hidden ones |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 assertions, each run against the emitted document bytes at close-out, outputs pasted above |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — *"no doc names the removed CDFX package or the `s19tool` console script as live"* |
| If the result is an ABSENCE, what made the search wide enough | the grep is over the exact tokens (`CDFX`, `s19tool`) across exactly the four shipped documents — the over-broad property is *any* occurrence, with the two surviving hits inspected by eye and quoted above |
| Guard labelled as protecting a CONCLUSION, not a behaviour | none minted — declared as the gap §6 owns |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion |
| Synthetic instance of the absent case | not planted — the positive control below is what keeps the absence honest |
| **Positive control for every probe that returned an ABSENCE** | the same `grep -n "CDFX" …` probe returned **2** NON-absent rows (the historic mentions) — the probe demonstrably sees the token when present, so its zero-live-promise verdict is a measurement, not silence |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "overview.md\|architecture.md" tests/ tools/ s19_app/` | 0 test asserts over these documents' content — nothing to re-validate |
| B2 file moved on disk | `git diff --name-status HEAD -- README.md docs/ \| grep -c "^R"` | 0 renames |
| B3 byte-identical golden captures this source | `grep -rl "README" tests/__snapshots__/ tests/goldens/ 2>/dev/null` | 0 hits — no golden captures a doc |
| B4 artifact produced here is consumed elsewhere | `grep -rln "docs/overview\|docs/architecture" README.md docs/ .dev-flow/state.json` | consumers are human readers plus `artifact_homes.module_map` (`docs/ARCHITECTURE.md` — note: the state value's casing predates the batch; declared, not repaired here) |
| A3 interface consumed by another module changed | n/a — docs export no interface | — |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes (B1 · B2 · B3 · B4 · A3) with commands and verdicts; B1/B2/B3 returned zero with their commands printed; A3 not applicable — no code symbol touched |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| doc drift: the docs describe a superseded app | every live claim about a removed surface | the P0 survey measured the drift (README:91/222 promising a deleted package; docs at the batch-02..04 state); the agent re-verified each named surface against the code before writing | 4 documents | 4 | 0 — the survey's drift list is closed; `docs/` beyond these three carried no measured drift |

| Field | Value |
|---|---|
| **Correction population** | 1 correction, enumerated from the P0 survey's measured drift list before the first edit |

### Signed-balance test ledger

`post = base − deleted + added` → `2762 = 2762 − 0 + 0` ✓ reconciles (docs-only).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — spot-checked the four diffs against the shipped surfaces (the rail screens against `s19_app/tui/app.py`, the CLI claim against `pyproject.toml`, the CDFX mentions against the deleted package) and ran the two greps above as the negative control. No HIGH. The lens is the same human who owns the gate run — declared |

---

## 5 · Risks

- **Docs drift again the day a surface moves.** Nothing machine-readable binds the
  README's key tables to `S19TuiApp.BINDINGS` — the reconciliation was manual and
  will rot. That is precisely the harness `AT-285` would be (§6).
- **Screenshots age.** The README embeds `docs/images/*.png`; their currency is not
  re-measured by this increment.

## 6 · Pending items / spec deviations

- **`AT-285` stays RESERVED.** HLR-123's acceptance names it; the increment shipped
  the documents and the inspection evidence but no harness. Mint it (a docs-canon
  guard: every README-named key greps to a `Binding(`, no live CDFX/`s19tool`
  token) or retire the reservation with its reason — carried at close.

## 7 · Suggested next task

Increment 003 — the registry hygiene (`HLR-124`).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **0** source files — docs only |
| 2 | Tests written in this same increment | all | ⚠ | none — and that is the declared deviation: `AT-285` un-minted, §6; the batch is adoption/documentation, and this increment's verification is inspection with executed greps |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | criterion does not apply — no unit of code |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | `none — no new assertion in this increment`; the contract's negative control executed as inspection |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes above, commands and verdicts |
| 6 | `code-reviewer` passed — declared in **§4b** | `core` · `full` | ⚠ | no agent lens; `human:coordinator`, declared in §4b |
| 7 | No file from another lane touched | all | ✓ | owns README + docs/ only; increments 001/003 disjoint |
| 8 | Frozen interfaces untouched | all | ✓ | no `s19_app/` file in the diff |
| 9 | Coverage claims verified **on disk** | all | ✓ | every named surface read against the code before writing; close-out greps pasted above |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | the absence claim carries its positive control (2 non-absent CDFX rows from the same probe) |
| 11 | **Mutation verdicts** declared | all | ✓ | `none — no mutation battery in this increment` |
| 12 | **Instrument RED-proof** declared | all | ✓ | `none — no instrument beyond the suite`; the greps self-prove by returning rows |
| 13 | **Correction population** declared | all | ✓ | 1 correction, enumerated from the survey before the first edit |
| 14 | **Emitted-form assertion** declared | all | ✓ | 3 assertions over the emitted bytes, outputs pasted |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared | all | ✓ | 2 artifacts below, digests of the stored bytes |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-08-batch-91/evidence/inc002-brief.md` | `75170b8457558910ec2cd09a8b7687f3b60f4cdd5f5673ad6016b337c339f9f8` |
| the failed opencode launch | `.dev-flow/2026-10-08-batch-91/evidence/inc002-run.log` | `418935dfa1cad1f8eacca319ae4e5ae7c80adc3ee16ec66509a62d85933b9021` |

| Field | Value |
|---|---|
| **Evidence files** | 2 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes (the grep outputs live inline above — they are two-line pastes, not files) |
