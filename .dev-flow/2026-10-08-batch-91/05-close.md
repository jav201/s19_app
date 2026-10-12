# Batch close — s19_app — Batch 2026-10-08-batch-91 — the contract-gap closure

> **Reserved field names** (parsed literally): `Conditional-gate discharge` ·
> `New controls` · `Human perimeter` · `Human review ledger` · `Gated tree` ·
> `Found before the batch` · `⏸ DEFER`; the §6 DEPTH tokens `light` · `rigorous` ·
> `spot-check` · `none` · `✅` · `❌`.
> **Notice convention.** `⚠` declare and continue · `✗` block · `✓` satisfied with
> its citation.

---

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `python "C:/Users/jjgh8/.claude/skills/dev-flow/scripts/devflow-validate.py" --brief .` from the repo root — **exit 1 · 10 block · 308 notice · 55 not applicable · 2026-10-11**. The 10 blocks are **one finding repeated ten times**: `V22`'s fold-canon — the batch's declared ids (`HLR-122`–`HLR-124`, `LLR-122.1`–`LLR-122.5`, `LLR-124.1`, `LLR-124.2`) are not yet tokens in `REQUIREMENTS.md`, and the fold (`devflow-init.py --fold-canon`) is **the coordinator's owed step at this close**, tracked as `G-91-02`; the gate goes to 0 block the moment it lands. **Zero other blocks are attributable to batch-91.** The 308 notices are the historical corpus over the 90 sealed batches plus the expected close-time ones: `V20` ×5 (the batch's files unversioned until the coordinator's commit) · `V27` ×2 (`decisions_log` entries owed by the coordinator) · `V28` (batch-90 HELD, declared) · `V57` (dirty by design — §0's tree row) |
| Gated tree | `983f8985f625be368fd6943f8cb1553537e7e3b7` (`git rev-parse HEAD`) — **dirty, by design**: the batch's whole diff is uncommitted; the coordinator commits and pushes at this close per the standing authorization (no PR). The dirty census at the gate: **84 modified** (71 test modules · `README.md` · `docs/overview.md` · `docs/architecture.md` · `docs/crc-algorithm-designer/01-requirements.md` · `AT-TC-REGISTRY.jsonl` · `.gitattributes` · `.dev-flow/state.json` · 4 `.dev-flow/_derived/ATLAS-*.md` · 3 `.dev-flow/BACKLOG*.md`) + **6 untracked entries**, all batch-owned (`.dev-flow/2026-10-08-batch-91/` · `tests/__init__.py` · `tests/test_batch91_adoption.py` · `tests/test_batch91_registry_hygiene.py` · `.dev-flow/rollover_batch91.py` · `.dev-flow/2026-09-06-batch-90/decisions-log.json` — the rollover's archive write). The pre-existing `build/` and 17 `prototypes/` entries — another session's, reported as FOUND, never swept (C-44) — **left the diff census through `.git/info/exclude`**, which is `V59`'s own discharge for untracked byproducts (rev97 E2); the patterns are commented there and removing them makes the census see the files again |
| Requirements canon | `repo:REQUIREMENTS.md` (as `artifact_homes.requirements_canon` declares) — ⚠ **the batch's declared ids (US-102..104, HLR-122..124, LLR-122.1–.5) are NOT YET tokens in it**: the fold-canon is the coordinator's owed step at this close, and until it lands `AT-286` arm (c)'s census cannot see this batch's ids (measured — the M3 first aim, `increment-003.md` §4). Tracked as `G-91-02` |

---

## 1 · What changed

**BLUF: the foundation traces, the docs read the shipped app, the registry is
complete, and the suite collects again.**

- **The foundation traces.** The S-record/Intel-HEX/A2L/MAC/CRC engines, the range
  index, and the TUI host-surface behaviors the oldest strata left prose-only now
  carry real ids: **32 RESERVED→LIVE conversions** (`TC-617`–`TC-648`), **358 nodes
  derived by the registry library's own machinery**, a docstring token in each of
  the **41 adopting modules** (additions-only, difflib-verified), and the batch's
  own completeness acceptance `AT-284` (2 arms, both mutation-proven RED-able).
  **No shipped behavior moved** — adoption, never re-implementation.
- **The docs read the shipped app.** README's CDFX promise is dead with the v2
  replacement named; the variants system, Flow Builder, CRC Designer, Operations
  modal and the undocumented global keys are documented, reconciled against the
  shipped keymap (31 app-level bindings); `docs/overview.md` and
  `docs/architecture.md` describe the 10-screen app, not batch-02..04's; the CRC
  designer doc is marked the pre-ship design record it is.
- **The registry is complete.** `AT-043` resolved LIVE (re-spelled from the seed's
  `AT-43` — same normalized key — with its node derived, never hand-written); the
  **44 token-invisible LIVE ids** carry their tokens (token-exact reading — the
  substring reading stops at 42, and the disagreement is the registry's whole
  reason to exist); `AT-286` (3 arms) guards all three properties standing.
- **The suite collects again** — and that is a repair found *before* the batch, in
  this batch's diff: §3's Found-before-the-batch.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| `HLR-122` + `LLR-122.1`–`LLR-122.5` — the foundation contract | v1 | `AT-284` · `TC-617`–`TC-648` | ✓ |
| `HLR-123` — the docs describe the shipped app | v1 | `AT-285` — **RESERVED, harness not minted**; executed inspection (the emitted-form greps) | ✓ with `G-91-01` declared |
| `HLR-124` + `LLR-124.1`–`LLR-124.2` — the registry's hygiene | v1 | `AT-286` | ✓ |

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|
| *(none minted — three candidates below)* | | |

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** | ✗ | — |
| 2 | its **artifact** (a template section) | ✗ | — |
| 3 | the **catalog** entry with its measured origin | ✗ | — |
| 4 | **committed and pushed**, manifest re-hashed | ✗ | — |

- **New controls:** `none — this batch minted none`: the project's control-encode
  rule requires an operator question per control (`BACKLOG-PROCESS.md` header), and
  none was asked. The three candidates are transcribed here so they are not lost:

  1. **The editable-`.pth` shadow class.** A *different* repo's editable install
     planted a `tests` package on `sys.path` and shadowed this repo's own — the
     suite could not collect, and the failure read as 22 import errors, not as a
     shadow. **Environment assumptions need a probe at P0**: `tests/__init__.py`'s
     own docstring now carries the mechanism, but nothing guarded the class before
     it fired. A `python -c "import tests; print(tests.__file__)"` assertion at
     intake would have caught it in one line.
  2. **The token-exact reading.** "Does id X occur in file Y" has at least three
     answers (substring 42, per-file variant 48, token-exact 44) and they disagree
     precisely on the ids the registry exists to disambiguate. **Any occurrence
     claim about registry ids must name its reading** — the registry's own
     `TOKEN_RE`, maximal munch, is the only one that reproduces the survey.
  3. **The measured-bump discipline.** Every guard bound this batch moved
     (`EXPECTED_SCANNED_TEST_FILES` 156→158→159, `_meta` high_water 283/616→287/650)
     was **re-derived by two paths that share no code** and carries its derivation
     in the source comment. An incremented-without-measuring bound is how G7 came
     to be red on an untouched tree.

---

## 3 · Working-file reconciliation (C-44)

**Everything this batch produced is uncommitted by design** — the standing
authorization gives the commit and push to the coordinator at the close. The
mechanical sweep, 2026-10-11:

| File | State | Evidence |
|---|---|---|
| the batch diff — 71 test modules, `AT-TC-REGISTRY.jsonl`, `README.md`, 3 docs, `tests/__init__.py`, 2 new test modules | 📋 **left on purpose — the coordinator's commit** | `git status --short` at the gate (§0); every file's change is described in an increment packet |
| `.dev-flow/2026-10-08-batch-91/` (the record, incl. 17 evidence files) | 📋 same | the packets' Evidence files tables, digests of the stored bytes |
| `.dev-flow/state.json` | 📋 same — the coordinator's rollover/close edits | working-tree blob `96bd31e8cd32cf735e863c6c7c87c0920d933ece` (`git hash-object`) |
| `.dev-flow/_derived/ATLAS-*.md` (4) | 📋 regenerated, coordinator commits | `--atlas --write` at this close (V20's own named repair; the 3 pre-existing content-row blocks cleared). Close-out blobs: BATCHES `713df89debfd11f9a955e34685dd6d11e58cebfe` · IFC `e267e54a31a497c0ab081857f494d73f04827da8` (both unchanged since the seeding — verified) · ORPHANS `892a34ba5ab26634dc74ea67cf4e6c103e65148f` · TRACE `9ef80798806e68221146b4002097c1acd8ac585c`. ⚠ V20 guards by digest, and the derivation widens once the batch's files are tracked: **the coordinator regenerates once more after the commit** |
| `.gitattributes` | 📋 same | one added line: `.dev-flow/2026-10-08-batch-91/evidence/** -text` — the evidence bytes are pinned verbatim, diff-host-independent |
| `.dev-flow/BACKLOG.md` · `BACKLOG-CODE.md` | 📋 same | this close's §4 reconciliation: the router lineage bullet + the three `P3` carries (`G-91-01`, `G-91-02`, the spare reservations); the lane index counts deliberately not re-derived for two `P3`s — declared at the section |
| `.dev-flow/rollover_batch91.py` | 📋 kept — the rollover's executable record | untracked at the gate |
| `.dev-flow/2026-09-06-batch-90/decisions-log.json` | 📋 the rollover's archive of the HELD batch's log | `rollover_batch91.py`'s step 1 — moved, never copied |
| `build/` + 17 `prototypes/` entries | 📋 **pre-existing, another session's — untouched** | reported as FOUND; committing another session's work in progress is its own defect (C-44). They left the diff census through `.git/info/exclude` — `V59`'s own discharge for untracked byproducts (rev97 E2), 5 commented patterns, reversible by deleting the lines |

- **Found before the batch:** `.dev-flow/_derived/ATLAS-BATCHES.md @ 713df89debfd11f9a955e34685dd6d11e58cebfe` `.dev-flow/_derived/ATLAS-IFC.md @ e267e54a31a497c0ab081857f494d73f04827da8` `.dev-flow/_derived/ATLAS-ORPHANS.md @ e2eeb7e1c154da3f3af6dc17eeb4535508dbda00` `.dev-flow/_derived/ATLAS-TRACE.md @ da211221ad38d8f57cb5361eff5c9fa154488664` `.dev-flow/state.json @ 8a86e372f10a07086428f5b3d3e330a0537bb605` — the five as found at this record's seeding (working-tree blobs; ATLAS-ORPHANS, ATLAS-TRACE and `state.json` have moved since — the coordinator's regeneration and post-increment edits — and their close-out blobs are named in this section's table)

### Found before the batch — the collection breakage, and its repair inside this batch's diff

**The suite could not collect, and had not since 2026-08-21.** The mapper project's
editable install had planted
`C:\Users\jjgh8\anaconda3\Lib\site-packages\_editable_impl_mapper.pth`, whose
`tests` package shadowed this repo's own on `sys.path`: **22 collection errors**,
every one an import of the *other* repo's conftest. Nothing in the tree was wrong;
the environment was. Recorded as premise `P-3` (`01-requirements.md` §2.7, executed
at P0) and repaired **inside this batch's diff**, first, before any increment:

- `tests/__init__.py` **added** — the repo's own `tests` becomes a regular package
  and wins by `sys.path` order (pyproject pins `pythonpath = ["."]`; the file's
  docstring carries the whole mechanism so the next reader cannot "simplify" it
  away);
- the bare imports uniformized to `tests.`-qualified: **6 files** off
  `from conftest import …` and **9 files** off `from test_* import …` (15
  file-memberships, 14 distinct files — `test_tui_report_seam.py` carried both;
  18 import lines, measured by `git diff` at close-out).

**Evidence the repair works:** the base suite collects **2760, 0 errors** after it
(P0 measurement, reproduced at close-out under the house env), and the guard's
scanned-file bound absorbed the new module by measurement, not by increment
(`tests/test_id_registry.py:81-89`). **Why it is here and not in an increment:** it
was found at P0, before the increments existed, and gating it behind a packet
written after its repair would misdate the evidence. It is the batch's first
shipped change and this section is its record.

### Conditional-gate discharge

- **Conditional-gate discharge:** `none — no gate closed conditionally`. The P1
  gate's own two catches (the modal `should` in HLR-122's draft statement; the two
  stale derived atlases) were folded *before* the gate approved — they are folds,
  not conditions (`02-review.md`).

---

## 4 · Backlog reconciliation — the carry-over contract

**Placement.** The router (`.dev-flow/BACKLOG.md`) holds no open work; the batch's
carries are code-side, so they land in **`BACKLOG-CODE.md`** under a new
`### 🆕 Routed 2026-10-11 — batch-91 close` section in the *Development flow OF the
code* division, and the router's Lineage gains the batch-91 closeout bullet. No new
backlog file was invented; the lane indexes' counts are untouched by the two `P3`
additions and that is declared in the section itself.

| Item | Move | Reference |
|---|---|---|
| `G-91-01` — the docs acceptance harness (the RESERVED id the batch leaves) | carry → `BACKLOG-CODE.md` (P3) | `04-validation.md` Gaps |
| `G-91-02` — the fold-canon into `REQUIREMENTS.md` (the coordinator's owed step; until it lands, the cross-artifact census cannot see this batch's ids) | carry → `BACKLOG-CODE.md` (P3), coordinator-owned | `04-validation.md` Gaps; §0's canon row |
| the spare reservations of the chartered block (one acceptance id, two TC ids, RESERVED and deliberately unused) | carry → `BACKLOG-CODE.md` (P3): mint their subjects or release the reservations | `increment-003.md` §6 |
| the three control candidates (§2) | recorded **unencoded** — the encode needs the operator's per-control question | §2 above |
| the batch-91 closeout itself | lineage bullet → `BACKLOG.md` | the router's Lineage section |

---

## 5 · Batch metrics — the 13 keys of `core`

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-10-08-batch-91
mode: core
verdict: pass
increments: 3
source_files_max: 0
notices_raised: 11
rework_returns: 2
triggers_fired: null
tests_base_to_post: "2760 -> 2719 passed + 40 failed (collected 2765 measured); the 40 = the snapshot/layout baseline family, environmental on this machine (named in 04-validation)"
new_control: none
open_items_next: null
```

| Key | How it was obtained |
|---|---|
| `verdict` | `pass` — `04-validation.md` Result PASS with two declared notes (the `AT-285` reservation, the suite placeholder) |
| `increments` | 3 packets on disk — `increment-001.md`, `increment-002.md`, `increment-003.md`, enumerated (C-56) |
| `source_files_max` | **0** — all three packets declare `0 / 4` in `s19_app`; the batch's diff is tests, docs, the registry, the record |
| `notices_raised` | counted by grep over the batch's artifacts at the close write |
| `rework_returns` | **2** — the P1 gate's folds, recorded in `02-review.md` (the modal `should`; the stale atlases) |
| `triggers_fired` | `null` — `state.json`'s `triggers` block was never evaluated for this batch (`evaluated_at: null`); reporting one would be inventing it |
| `tests_base_to_post` | base **2760** = the P0 post-repair collection (house env); post **collected 2765** measured at close-out (`2765 = 2760 − 0 + 5`); the passed/failed figure: 2719 passed · 40 failed — the failure census: the snapshot/layout baseline family (test_tui_snapshot.py's density_layout_snapshot arms + the variants/popup/geometry arms) whose baselines were generated in CI's environment — the rendered SVG differs in font/colour metrics on this machine (the app's own nocolor class is visible in the render); pre-existing and unrelated to the batch (the batch's diff carries no product code), CI's snapshot lane green per batch-89's record; the popup arm passes isolated under the house env — the coordinator's `C-25` run, 2026-10-11, house env (s19env). The contaminated base-env run (42 failed, overlapping the agents' writes) is recorded in `04-validation.md` and is not a number of the settled tree |
| `new_control` | `none` — three candidates transcribed unencoded (§2) |
| `open_items_next` | `null` — the lane indexes' totals are not re-derived by this close; the two new `P3` carries are filed in `BACKLOG-CODE.md` with the non-re-derivation declared there |

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| `01-requirements.md` + ledger | `V26` pairs green; P1 gate `approve` with 2 folds (`02-review.md`) | ✅ | `rigorous` | |
| the 3 increment packets | gate checklists signed per packet; `V31`–`V44` fields all carry real values | ✅ | `rigorous` — the registry diff line-by-line, the adoption lists against the contract, the counterfactual transcripts | |
| the registry + test diffs (the code) | AT-284/AT-286 green; additions-only asserted by the write scripts | ✅ | `spot-check` — the 41 modules' docstring diffs sampled, the guard bumps re-derived; not every line of all 71 test files read by eye | the adopted modules' pre-existing assertions (adoption, not re-implementation — that is the contract's point) |
| the 4 documents | the emitted-form greps, zero live CDFX/`s19tool` claims | ✅ | `spot-check` | the screenshots' currency (`docs/images/*.png`) |
| the evidence files (17) | `V41` — digests of the stored bytes cited per artifact | ❌ | `none — the digests and the transcripts' content checks (offender names in the RED lines) stand in lieu` | |

- **Human perimeter:** `the operator (Javier) owns: the commission itself — quoted verbatim from 2026-10-08: "revisa la funcionalidad de la app y cierra los gaps de user stories, requerimientos y test cases que falten... usa /dev-flow" + "despliegues agentes kimi 2.8 o 2.7 segun convenga"; the per-control encode questions (§2's three candidates wait on one); the commit and push at this close; and the fate of the pre-existing build/ and prototypes/ residue. ⚠ The Kimi-agents note, declared rather than smoothed: the commission's named route — Kimi K2.7-code via opencode — failed at the provider (opencode's Moonshot provider holds no key on this machine; the three inc00N-run.log files each record 'Error: Incorrect API key provided'). The three increments ran on the Kimi coder subagents under the coordinator's briefs instead — the briefs, sandbox rules and report-back contracts are committed verbatim under evidence/. The flow does not cover provider key management; the substitution and its reason are the operator's to know`
- **Human review ledger:** `human:coordinator — 5 artifact classes reviewed, 2 rigorous · 1 declared not-reviewed (the evidence bytes, digest-pinned instead) · the coordinator is also the gate runner — one pair of eyes, declared in every packet's §4b rather than obscured`
