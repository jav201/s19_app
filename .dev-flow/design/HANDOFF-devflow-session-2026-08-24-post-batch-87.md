# Handoff — after batch-87: D-II discharged, surface #3 declared, and the 4 BLOCKs left on `main` are batch-88's opening move

> **Written 2026-08-24 (evening, local -06:00), session "batch-87 landing + batch-88 scoping" (background job, operator Javier).**
> **Supersedes** [[HANDOFF-devflow-session-2026-08-24]] — that document's §1, §4, §5 and §6 were
> written before batch-87 and are now FALSE in named ways (D-II is ruled AND discharged; surface #3
> shipped; the flaky diagnosis it records was refuted by measurement). It is kept, not edited.
>
> **Re-derive every figure below; if a command disagrees, the command is right.** Everything here was
> measured on 2026-08-24 against `main` at `3e96794`.
>
> ⚠ **Read §5 before you panic at §0.** A clean `main` reports **4 block** — all four are V20, all
> four are one cause, none is corruption, and none was caused by batch-87. They are the first thing
> batch-88's P0 clears.
>
> **Reading order:** §0 (verify ground) → §5 (the two blocks) → §6 (next actions) → §7 (what
> batch-88's proposal gets wrong). §2/§3/§4 are reference.

## 0 · Verify the ground before trusting anything here

```bash
cd <repo-root>                                            # C:\Users\jjgh8\Github\s19_app, branch main
python ~/.claude/docs/tools/devflow-validate.py .         # expect: 4 block · 284 notice · 14 n/a  ← see §5
#   V20 lines: 4 × "committed copy differs" — the flow rev bumped, NOT a corpus change
#   V22 line : "276 of 544 batch-declared ids are not reflected in the living canon"
python ~/.claude/docs/tools/devflow-validate.py --selftest # expect exit 0, SELFTEST PASSED, 192 arms
grep -E "flow_version|flow_hash" ~/.claude/docs/FLOW-VERSION.md | head -2
#   expect 2026.08.24-rev46 · 9c1449ed815d267c
conda run -n s19env python -m pytest --collect-only -q -m "not slow" 2>&1 | tail -1
#   expect 2714/2735 collected (21 deselected) — s19env is the GATE ENV (see §4)
git log --oneline -2                                      # expect 3e96794 (sync) over 5f49e85 (batch-87)
```

**Two path facts worth knowing.** The validator exists at `~/.claude/docs/tools/devflow-validate.py`
AND `~/.claude/skills/dev-flow/scripts/devflow-validate.py`. Measured 2026-08-24: **byte-identical**
(`sha256` both `f3fe00cc7dc41140…`). It is a deploy, not a fork — `docs/` is the bundle, `skills/` is
the source repo. `FLOW-VERSION.md` doubles the same way. **`close-template.md` also doubles**
(`~/.claude/skills/dev-flow/templates/` and `~/.claude/templates/dev-flow/`) — that pair has NOT
been verified identical, and any batch that edits the close template must settle which is canonical
first.

## 1 · State at the cut

| | |
|---|---|
| `main` | **`3e96794`** — batch-87 sync (`obsidian_synced: true`, verified by reading `origin/main`'s copy, not the local one) over **`5f49e85`** (PR #202, batch-87 squash-merged, CI green: `snapshot` pass · `tui-ci` pass 56m04s) |
| flow | **`2026.08.24-rev46`**, `flow_hash 9c1449ed815d267c`. Selftest **192 arms, exit 0**. rev46 was documentation + manifest re-hash (IEEE 829/29119-3 collapse rationale in `validation-template`) — **no new rules**, arm count unchanged from rev45 |
| batch-87 | **CLOSED COMPLETE, merged, vault-synced.** D-II ruled *re-author* and discharged; surface #3 `workspace_body` declared (42 outputs); UNPARSED census **2 → 1** (`[IFC]` cleared, `[BATCHES]` survives as the negative control); V22 **289 → 276** of 544; **0 source files** |
| batch-86 | CLOSED COMPLETE, merged, vault-synced. Still the **FORMAT EXEMPLAR** for every IFC record |
| PRs | **#198 still OPEN, deliberate, operator's** (batch-83 D4 contradiction). #199/#200/#201/#202 merged |
| vault | `dev-flow-batches/2026-08-24-batch-87/` (core light-sync README, 35/35 frontmatter keys). `Dashboard.md` picks it up automatically. ⚠ **batch-85 still never synced** — a gap, not an error |
| hygiene | **9 extra worktrees**, 4 on `claude/*` branches (`batch-82-lane-a-scoping` — MERGED, `flow-diagrams-rescued-11aacc`, `flow-version-sync-fix-8d7086`, `blind-spot-assembled-selector-c2c117`) + 5 detached Cursor worktrees. **The primary checkout still holds foreign untracked WIP** (memmap2 prototype with its own HANDOFF, `prototypes/out/*.svg`, `build/`) — another session's work: REPORT, never sweep (C-44) |

## 2 · What shipped since the last handoff

| Piece | Where |
|---|---|
| **batch-87** — D-II discharge (batch-85 pilot IFC re-authored to the exemplar: SIX outputs, pair thresholds, scoped statements, no absorbed `owner`) + IFC surface #3 `workspace_body` (42 outputs, PARENT `workspace_shell`, SYSTEM refuted at `app.py:1919`) | `.dev-flow/2026-08-24-batch-87/` — read `05-close.md` §5 for the n=3 cost table |
| **rev46** — IEEE 829/29119-3 collapse rationale documented in `validation-template`; manifest re-hash via `--sync-bundle` | flow repo `2e8d774` + `1883152` |
| **Canon seeded** — 13 ids, ONE PER LINE (the M7 lesson adopted), V22 **289 → 276**, two under the ≤278 target | `REQUIREMENTS.md` mirror section |
| **Vault sync** — batch-87 README with the 12 core keys; artifacts stay in the repo and cross **by id**, never copied (mode `core` light sync) | `01 - Proyectos/s19_app/dev-flow-batches/2026-08-24-batch-87/` |

**The two batch-87 results worth a new reader's time.**
1. **K1 is the only proof the census entry was cleared by removing its CAUSE.** Re-absorbing one line
   back into the pilot block makes the validator print `UNPARSED census rose 1 -> 2` as a V20 BLOCK.
   Without that arm, "the census fell to 1" is equally consistent with the parser having gone quiet.
2. **K3's first arm refuted its own prediction** — deleting a `consumers` header line moved V14 by
   **−2**, not −1, because the orphaned continuation line was absorbed by the field above (mechanism
   M-3). The wrong prediction is **not overwritten**; it is repaired by the surgical arm K3b, and the
   refutation is itself a measurement of the parser defect the batch existed to fix.

## 3 · Standing operator directives

1. **Subagents on Opus 5** — every Agent dispatch passes `model: "opus"`. Re-stated at batch-87 P0.
2. **Authorization is PER BATCH — re-ask at every batch open.** batch-86 and batch-87 both ran:
   autonomous, gates self-approved WITH evidence, **merge granted explicitly by the operator at
   close**. batch-87's merge was granted 2026-08-24 (verbatim: *"mergea el #202 y sincroniza"*).
3. Artifact language English for dev-flow; conversation Spanish.
4. **batch-88 scope already declared by the operator** (2026-08-24, verbatim: *"alcance A+B+C+E"*) —
   see §6/§7. The US-E numeric ceiling is explicitly deferred to Phase 0.

## 4 · Environment facts the next session needs

- **Gate env = conda `s19env`** (Python 3.11.15). Anaconda base CANNOT collect the suite (22
  pre-existing `tests.conftest` import errors).
- ⚠ **`conda run` destroys gate evidence on this machine.** batch-87's first gate run died on a
  `cp1252 UnicodeEncodeError` through `conda run`; the run that produced the record used the env's
  python **directly**. Recorded as harness finding G4-03. Use direct env-python for gate runs.
- ⚠ **CORRECTION to the previous handoff.** It recorded "6 order-dependent flaky nodes, each passes
  ISOLATED on pristine `main`". **That diagnosis was REFUTED by measurement at batch-87 P4.**
  Re-sampled at **N = 10**: three of them fail *in isolation* (rates 1/10 to 4/10); overlap with the
  batch-86 pre-registered list is **1 node**, not 6. batch-86's `n = 1` "passes isolated" reading is
  now recorded as **vacuous (C-53)**. The adopted disposition is by **CLASS MEMBERSHIP** (empty
  source diff AND N≥10 rates-as-figures AND modal push/mount race family), not by node whitelist —
  a whitelist under-covers because the failing population resamples every run. **11 distinct node
  ids** carried to close, 5 of them with unmeasured rates.
- Probe discipline paid for in blood: never pipe a gate run through `tail` (C-19 — evidence destroyed
  once); pytest FAILED lines carry ANSI codes (a `grep "^FAILED"` silently returns nothing — strip
  first).

## 5 · Why `main` blocks — both causes named, one already cleared, neither corruption

Measured 2026-08-24 on `main` at `3e96794`: **5 block · 284 notice · 13 not applicable**.
**Update, same session: V16 was CLEARED** — the `tui-design/` work was verified complete (all six cited targets resolve, zero broken links, the gallery really holds its twenty-one
frames), committed as `33e1114` and **pushed** (V16 has a second arm: committed-but-unpushed
still blocks, which is the C-44 state). **`main` now reports 4 block · 284 notice · 14 n/a** —
the four V20 only, which belong to batch-88's P0.

**(a) V16 × 1 — `~/.claude/skills: uncommitted changes`.** The FLOW repo's working tree is dirty:
three modified files, **all under `tui-design/`** (`HIERARCHY.md`, `SKILL.md`,
`assets/gallery/INDEX.md`) — a different skill entirely, unrelated to dev-flow. V16 is repo-wide, so
any dirty file in the flow repo trips it. **Not caused by batch-87, not dev-flow's WIP.** Someone
must decide: commit, stash, or keep. **This will block batch-88's P0 until settled.**

**(b) V20 × 4 — every Atlas file "committed copy differs from what the corpus derives".** Diagnosed
by regenerating and reading the diff: **the ONLY change is the stamp line.**

```
- <!-- flow_version: 2026.08.24-rev45 | flow_hash: 09bea075fc183f8b | corpus: 64 files | corpus digest: 2a35037db2b5abd9 -->
+ <!-- flow_version: 2026.08.24-rev46 | flow_hash: 9c1449ed815d267c | corpus: 64 files | corpus digest: 2a35037db2b5abd9 -->
```

**The corpus digest is IDENTICAL** (`2a35037db2b5abd9`), the file count is identical (64), and no
content line moved in any of the four files. The cause is the **flow rev bump rev45 → rev46 after
batch-87 closed** — the Atlas header stamps the flow that derived it, so V20's digest guard trips on
a version stamp, not on drift.

> **The generalisable fact, worth recording as a lesson candidate:** *V20 is coupled to the flow
> revision, not only to the corpus.* **Every flow rev bump orphans every project's committed Atlas
> until it is regenerated.** "0 block" is therefore not stable across a flow bump. batch-87's own P0
> already paid this tax once (it opened with a V20-driven Atlas regen commit); **batch-88 plans a
> rev47 bump at Inc 4 and will pay it again.** Budget the regen + re-hash step, don't rediscover it.

**Deliberately NOT fixed here.** The regeneration was executed to diagnose, then **reverted**
(`git checkout -- .dev-flow/_derived/`; tree clean). Committing a derived-plane change outside any
batch is exactly the shape C-56 exists to catch. **The regen belongs to batch-88's P0**, recorded
under its own gate — the pattern batch-87's P0 already followed.

## 6 · Suggested next actions, in order

1. **Settle V16** — decide what happens to the three uncommitted `tui-design/` files in the flow
   repo. P0 of batch-88 cannot pass a clean gate until this is resolved.
2. **Open batch-88** with RC-1 against `origin/main` = `3e96794`; first act of P0 is the **V20 Atlas
   regen + commit** (see §5b). Scope is operator-declared: **US-A + US-B + US-C + US-E**, US-D
   (C-45 reconciliation of 15 half-encoded controls) deferred. **Read §7 first** — the proposal has
   three defects.
3. **Refresh the vault visual-evidence gallery — BLOCKED, and the root cause is new (2026-08-24).**
   Newest asset is **2026-08-07**; the last commit touching `s19_app/tui/` is **`f198447`
   (2026-08-13, batch-79)**, so every live asset predates the last UI change. **The refresh was
   attempted and could not run:**

   ```
   pytest -m slow tests/test_examples_pilot_gifs.py   (s19env, direct env-python per G4-03)
   → 15 failed in 32.39s — ModuleNotFoundError: No module named 'PIL'
   ```

   **`Pillow` is not declared anywhere in `pyproject.toml`** — neither in `[project] dependencies`
   nor in the `dev` extra — and `test_examples_pilot_gifs.py` imports it **lazily inside a function**
   (`from PIL import Image, ImageDraw, ImageFont`, `:111`). That combination is why nothing ever
   shouted: the suite **collects** clean and fails only at run time. Measured both ways:
   **`s19env` has no PIL; Anaconda base has PIL 12.2.0 but cannot collect the suite** (22
   pre-existing `tests.conftest` import errors). **Neither env can run the evidence suite today** —
   that, not neglect, is why the gallery froze.

   **Deliberately not fixed by `pip install pillow`**: papering an undeclared dependency makes the
   next silence quieter. The fix is to **declare it** (an evidence/dev extra in `pyproject.toml`)
   and then install — a dependency-contract change that wants an owner and a gate, not a side-effect
   of a sync.

   Asset decomposition, measured, for whoever does the refresh: **176 total = 90 live**
   (75 flattened frames + 15 gifs) **+ 80 nested** (16 dirs, historical context, operator ruling
   2026-07-29 KEEP, 75 @ 2026-08-03 + 5 @ 2026-07-08) **+ 6 retired**
   (`pv__case_06_large_nested_a2l`: 5 frames + 1 gif). ⚠ The §5 GIF helper is a **blanket glob** and
   will re-stamp the retired case as fresh unless excluded **by name**; the §5 SVG helper must be the
   **flattening** loop, never `-Recurse` (a recursive copy already destroyed the nested set once —
   see `visual-evidence.md` §6's correction block).

4. ✅ **batch-85 vault sync gap — CLOSED 2026-08-24.** Synced retroactively as
   `dev-flow-batches/2026-08-21-batch-85/`, `verdict: iterate` with 8 honest `null`s (no
   `02-review.md`, no `03-increments/`, no `04-validation.md` exist — P3/P4/P5 were never reached).
   Recorded as CLOSED UNFINISHED in the body rather than dressed up: an absent Dashboard row reads
   as *"this batch never happened"*, a stronger false claim than an honest `iterate` row.
5. **PDR/DDR id rule** — V23 still reports "no PDR/DDR citations anywhere; the id glue is unused".
   Needs a first real PDR to exist before more machinery is worth building.
6. **Test-hygiene batch** for the flaky family — now with real rate figures at N=10 (see §4) and the
   class-membership criterion instead of a whitelist.
7. **The Dex Horthy questioning session** (operator-declared pending) — now with two full trial
   batches as evidence for/against the flow's cost.
8. Housekeeping: 9 stale worktrees (§1); the foreign memmap2 WIP's fate (its own HANDOFF is in
   `prototypes/`).

## 7 · What batch-88's proposal gets wrong — measured 2026-08-24

The proposal lives at
`…/Claude Templates and Flows/Propuesta batch-87 — cierres de auditoría (2026-08-24).md`.
Three defects, all verified against disk:

1. **It calls itself batch-87. That id is taken and closed.** It is **batch-88**.
2. **Its sequencing premise is void.** It says *"before surface #3, so V24 debuts on a real consumer
   in the following batch"*. Surface #3 already shipped. The effect is favourable, not harmful: the
   frozen interfaces exist **now**, so V24 can take a real consumer **inside** batch-88 (Inc 4).
3. **US-A is not implementable as written — this is the load-bearing one.** It anchors rule V24 on
   *"every interface marked `Frozen?` in `ARCHITECTURE.md §4`"*. Measured: the `Frozen?` column
   exists **only** in the flow's `architecture-template.md:63`
   (`| Interface | Owner module | Consumers | Shape | Frozen? |`). **s19_app never adopted that
   section** — its `docs/ARCHITECTURE.md` §4 is "Patch Editor flow", a prose diagram with no
   interface table and no `Frozen?` marker (the only "frozen" string in the file is *"Byte-frozen
   post-batch-03"* about `writer.py`, an unrelated use). The file is untouched since 2026-07-11.
   **Consequence:** acceptance criterion #2 (*"V24 active over ≥1 real frozen interface"*) is
   **unreachable today**. Inc 4 must first adopt the template's §4 interface table into s19_app and
   mark the real frozen interfaces from surfaces #2/#3. This also **confirms** the proposed
   NOTICE/BLOCK adoption pattern — NOTICE where the table does not exist is precisely s19_app's
   state today.

**Premises that DID verify** (do not re-litigate these):
- `close-template.md:108` carries the ISO 9241-210 "declare what was NOT done" line — US-B's new
  assurance-limits section is a legitimate sibling. ✅
- **The V8 side-finding is real.** `_RULE_COVERS["V8"]` (`devflow-validate.py:1946`) reads
  *"requirements name modules the project map declares"*; the implementation `v8_module_map`
  (`:243`) does the inverse — *"every tracked source file falls under a declared module"*. Catalogue
  and code point in opposite directions. One-line fix, correctly scoped into Inc 3. ✅
- `Layer C` appears nowhere in the flow repo — net-new, no collision. ✅
- RC-1 sits at `phase-checklists.md:29` (row 4); RC-2 slots in as row 5. ✅
- V22 census is **276 of 544**, matching batch-87's close. ✅
- **The selftest's synthetic-exemption list currently names exactly one rule: V8** (it needs a
  project map on disk). Acceptance criterion #1 — *"no new rule on the synthetic exemption list"* —
  is therefore a real, checkable constraint for V24/V25, not a formality. ✅

## 8 · The first PDR exists — the third traceability lane is now exercised

**Sealed 2026-08-24 in the vault**, in the folder `dev-flow-init` declares for design records
(`vault:<project>/design/`), in the file named for the record id bound below. It is the project's
**first design review record**; before it, `V23` reported *"no PDR/DDR citations anywhere — the id
glue is unused, which is a fact about this project, not a pass."*

> 🛑 **The file is deliberately named by its folder and id above, never written out as a path
> — and that is a DEFECT in V23, not a style choice.** See the grammar box below.

**Verdict: `approved with conditions`**, and the conditions are measured, not ceremonial. It
authorises **Inc 1 and Inc 2 to start** (neither depends on the frozen-interface table) and
**withholds Inc 3 and Inc 4** until `PDR-2026-08-24-batch-88#D1` has landed. A conditional verdict
is not an authorisation.

| Decision | Id to cite from the repo | Lands in |
|---|---|---|
| Adopt the §4 interface table, mark `Frozen?` | `PDR-2026-08-24-batch-88#D1` | `docs/ARCHITECTURE.md` §4 |
| V24 severity: NOTICE without the table, BLOCK with it | `PDR-2026-08-24-batch-88#D2` | `devflow-validate.py` · `validation-template.md` |
| V25 threshold `N = 30` days since last push | `PDR-2026-08-24-batch-88#D3` | `devflow-validate.py` · `phase-checklists.md` row 5 |
| `_RULE_COVERS` description must equal implementation | `PDR-2026-08-24-batch-88#D4` | `devflow-validate.py` `_RULE_COVERS` |
| One canonical `close-template.md` | `PDR-2026-08-24-batch-88#D5` | the copy declared canonical |
| `Pillow` declared as a dependency | `PDR-2026-08-24-batch-88#D6` | `pyproject.toml` |
| US-E tranche = the ids of the batches touching US-A's frozen interfaces | `PDR-2026-08-24-batch-88#D7` | `REQUIREMENTS.md` canon mirror |
| The V20 flow-rev tax, budgeted at P0 and at Inc 4 | `PDR-2026-08-24-batch-88#D8` | `.dev-flow/_derived/` · `FLOW-VERSION.md` |

> 🛑 **V23 cannot tell a citation from a FILENAME — found by tripping it, twice, in this very
> section.** The token matcher is `(?:PDR|DDR)-\S+`, which happily swallows a path. So writing the
> record's own file path in any repo document raises a NOTICE **against the flow's own declared
> convention**: `dev-flow-init` puts design records at `vault:<project>/design/` under a name that
> begins with the record id, and naming that file is therefore unrepresentable in the repo. There is
> no escape — the scan reads every line of every `.md` with **no fence awareness**, so a code block
> does not protect it either. **Registered as a batch-88 finding**, adjacent to `PDR-2026-08-24-batch-88#D4`
> (description must equal implementation): a rule whose grammar forbids the convention its own
> command prescribes is the same class of defect as a `_RULE_COVERS` line that contradicts its code.
>
> ⚠ **A grammar fact worth knowing before you cite anything.** `V23`'s token matcher is
> `\b(?:PDR|DDR)-\S+` and its conformance test is
> `^(?:PDR|DDR)-\d{4}-\d{2}-\d{2}-batch-[A-Za-z0-9]+#D\d+$`. **The record's own id — without a
> `#D<n>` suffix — does NOT conform.** Writing the bare record name anywhere under `.dev-flow/` or in
> `REQUIREMENTS.md` raises a NOTICE against itself. The grammar can express *a decision inside a
> record*, never *the record*. That is arguably correct (a citation should bind to a decision, not a
> document) but it is undocumented, and it is the first thing a second reader will trip on. Cite
> decisions; name the file by **path** when you mean the document.

**`artifact_homes` gap this surfaced:** `state.json` declares no design homes. batch-88 must add
`"design_pdr"` and `"design_ddr"` — otherwise the record has no declared home and `/dev-flow-sync`
has no path for it.
