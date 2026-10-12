# Post-mortem — s19_app — Batch 2026-10-11-batch-92

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Structured for cross-batch sweeping — keep the section order.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Gated tree` · `Found before the batch` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe C:\Users\jjgh8\.claude\docs\tools\devflow-validate.py --brief` (mode `full`), run at the close, 2026-10-12. First close run: **exit 1 · 8 block · 345 notice**; **final, after this pass's reconciliations: exit 1 · 2 block · 359 notice · 60 n/a**. The 8 → 2 fall: **2× `V20`** (the ATLAS derivations went stale after the batch's own artifact writes — regenerated at the close, `--atlas --write`, exit 0, "commit these; V20 guards them by digest", verified gone on the re-run) **+ 6× `V59`** (six touched files no increment packet's §2 table named — three station-gate writes + three AT-290/291 test docstrings — reconciled by declared §2 addenda in both packets, true authorship stated; see Process findings). **The 2 standing blocks are both `V16` over `~/.claude` and `~/.claude/skills`** — uncommitted changes in the FLOW repos, found at the close, made by other lanes during the batch window (the same command returned **exit 0 · 0 block · 321 notice** at the batch's first gate, 2026-10-11). This batch never wrote either repo (C-44 below) and they cannot be discharged repo-side — reported, not foldable. |
| Gated tree | `410cde57c99094b89500ab890f919478d39ea999` (branch `kimi/batch-92-layer-inversions`, the batch's base) — dirty with exactly the batch's own diff (111 paths: 37 tracked modified · 1 tracked deleted · 73 new files), which the orchestrator commits at this close immediately after this pass. No foreign content in the dirty set (see `Found before the batch`). |

## 🔑 At a glance (read first)

- **Outcome:** closed with carry-over — 6 backlog entries routed (1 `P2` defect · 1 `P2` charter · 3 `P3` · 3 named flake nodes folded into the first), **0 HIGH open at close**
- **Top 3:** ① executed review simulations — not design argument — caught the render-first import cycle before any code existed (C1/C2) ② the local suite's noise floor (36–40 failures per run on identical base code) made the GATE RULE, not the moves, the batch's hardest deliverable ③ the PDR's tester lens caught AT-288's undriveable charter before implementation (QA-PDR-1)
- **New control this batch:** none minted catalog-side; the flaky-tolerant union-corpus gate rule is recorded project-side in the contract (§5.2) with its falsifiability warning attached — a gate whose reference grows every run is a debt, and the sharpening is carried to the backlog, not absorbed
- **Open items → next batch:** 6 — biggest: **the local full-suite gate is not sharp on this machine** (52-node known-unstable corpus; 5-run characterization + inventory at `evidence/baseline-failing-set.txt`)
- **Metrics:** iterations 12 station-passes (`P1`×2 · `P2`×2 · `P3`×2 increments — true re-works: P1, P2) · findings **17 closed / 0 opened at close** · ledger none → `LED-2026-10-11-batch-92.1`–`.15`

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What shipped (the 4 HLRs and how each validated)

- **HLR-001 — `tui/hexview.py` relocated to `s19_app/render/hexview.py`.** Validated by: the moved body hash `fe6921c7…` recomputed independently three times (implementer, increment reviewer, DDR analyst); **AT-288** — report bytes byte-identical to the pinned pre-move capture (sha256 `061ee94c…4c39`, re-verified at P4); the 43-node repointed suite absent from every failing set; TC-651 (live-tree AST import-census of the 8 consumer modules, set-equality) green with reviewer-run RED mutations.
- **HLR-002 — the `range_index` re-exports are gone.** Validated by: TC-652 (wrapper absence from the moved module, the `tui/__init__` import surface and `__all__`, and `app.py` sourcing the frozen engine directly); the engine suite `tests/test_range_index.py` unchanged and green; the frozen engine itself at 0 diff under the dual-guard.
- **HLR-003 — `safe_text` canonical at `s19_app/utils.py`, C-17 preserved.** Validated by: the transfer hash `103da220…2974` recomputed by the Inc-B reviewer; `_CONTROL_SCRUB` moved with the function; the hostile probe `safe_text("a\x9b31mb[red]")` → `a31mb[red]` executed in a cold interpreter; a `from_markup` mutation at the new address reddening 5 b77 nodes; TC-653 (live-tree census, ~96 internal call sites repointed) green.
- **HLR-004 — `microbar` + style constants in the presentation-neutral `render/format.py`.** Validated by: TC-654 (canonical-address census + `is`-identity arms), TC-655 (the `render/format` copies pinned value-equal to the frozen `tui/color_policy.py`/`insight_style.py` origins — the freeze respected by data copies, not edits), the 8-symbol `insight_style` shim `is`-identical 8/8, and AT-291's 14/14 strip family through the shipped app surface.

### What worked
- **Executed probes over design argument.** P2's cold-import simulations converted C1/C2 from opinions into demonstrated `ImportError`s with three priced dispositions each; the P1 gate then chose the root-cause one on evidence, not taste.
- **Third-party recomputation as the load-bearing habit.** Every critical number (body hash, transfer hash, pinned-capture sha256) was recomputed by an independent reviewer; every census TC was reddened by the reviewer's own mutation battery, in both increments.
- **The PDR earned its keep.** QA-PDR-1 was found by reading the real report-service signature and call chain — before any implementation existed. The re-charter cost one ledger entry; a discovered undriveable oracle at P4 would have cost an increment.
- **The deterministic evidence set closed the batch honestly.** With the local suite non-sharp, the no-functionality-loss claim rested on hashes, a pinned pre-move capture, and cross-tree standalone identity — evidence that does not flake.

### What didn't / friction
- **Five full-suite executions (~38–61 min each, >3 h of gate time) went to characterizing noise, not testing the diff.** The baseline the contract inherited was a count from a different checkout ("40", then measured 38); the corrected pin itself moved (36/38/40 across runs). That is the batch's real cost center.
- **The close gate cannot go green repo-side.** Two `V16` blocks stand over `~/.claude` + `~/.claude/skills`, dirtied mid-batch by other lanes (flow rev102 work and a benchmark handoff, measured at the close). Reported at C-44, not foldable into this batch.
- **Station checklist tables (`00-checklists.md`) went unsigned.** The discipline they catalog lived in the increment packets' 16-row gate checklists and the review artifacts; the station tables were dead paper. Declared, not retro-filled.
- **One gate-relevant transcript first landed outside the artifact home** (`~/kimi/batch92/base-full-suite.txt`, the base-control run) — relocated into `evidence/` at this close so the committed record is self-contained.
- **The record itself owed a close-time repair.** `V59` found six touched files no packet's §2 table named — three station-gate writes and three AT-290/291 test docstrings. All six are now named by declared §2 addenda with their true authorship (see Process findings); the sealed Count blocks stay as written.

### Scope drift (planned vs actual)
| Planned | Actual | Note |
|---------|--------|------|
| 6 inversions killed; `render/` keeps 2 declared residual tui edges | 6 inversions killed **and both residual edges killed** — `render/` is fully tui-free | P2 finding C1-(c), operator-ratified at the P1 gate: the style constants moved DOWN into `render/format.py` instead of patching the cycle's symptoms |
| 3 increments (roadmap Inc-1…Inc-3) | 2 increments (Inc-A/Inc-B; format-module creation folded into Inc-A) | closure finding N1 — the import graph, not the story boundaries, decides increment content |
| US-92-5 in scope if the operator unfreezes `color_policy.py` | OUT — freeze stands | operator ruling 2026-10-11 ("si haz el freeze de color policy") → backlog carry |
| AT-288 drives 4 non-default parameters | AT-288 drives the 2 parameters that are actually driveable (≥2 disjoint `row_bases` windows + non-default `context_bytes`) | QA-PDR-1 — the other 3 are undriveable through the report surface (executed evidence); the undriveable trio is explicitly excluded in the contract |

### Metrics (full)
| Metric | Value |
|--------|-------|
| Iterations per station | `{P0:1,ARQ:1,P1:2,P2:2,PDR:1,P3:2,DDR:1,P4:1,P5:1}` |
| Findings opened / closed | 17 / 17 (0 opened at close; 17 = C1–C5 · F-QA-1..7 · N1–N2 · QA-PDR-1..3) |
| Findings by severity (blocker/major/minor) | blocker 0 · major 4 (F-QA-2, F-QA-3, F-QA-6, QA-PDR-1) · minor 13 (3 HIGH: C1, C2, F-QA-1 · 2 MEDIUM: C3, N1 · 8 LOW/MINOR: C4, C5, F-QA-4/5/7, N2, QA-PDR-2/3) |
| Where caught (P2 / P3 gate / P4) | 14 at P2 incl. its closure pass (C1–C5, F-QA-1..7, N1–N2) · 3 at the PDR (QA-PDR-1..3) · 0 at the P3 increment gates · 0 at P4 |
| Test ledger (base − D + A = post) | 2765 − 0 + 5 = **2770** (A = TC-651/652, TC-653/654, TC-655 across the 3 new modules; 0 nodes deleted — the 43-node repointed suite keeps its ids) |
| Files touched · increments (cap trips) | 37 tracked modified + 1 tracked deleted + 73 new (67 batch artifacts incl. this record · 3 `render/` modules · 3 test modules) · 2 increments · 0 cap trips (≤5-files convention waived at P1, ratified: mechanical repoints, 1–2 lines each) |

> **Severity legend, stated because this file mixes two vocabularies:** the batch's reviews graded HIGH/MAJOR/MEDIUM/LOW/MINOR; this table maps them onto the template's blocker/major/minor as blocker=HIGH, major=MAJOR, minor=everything below. 3 + 4 + 10 = 17.

### Root causes (only if a phase took ≥2 iterations)
- **P1 ×2 → `iterate-to-refine` at P2.** Root cause: the design's import-graph claims were argued in prose, not executed — P2's cold-import simulations demonstrated the render-first partial-init `ImportError` (C1) and the self-import `ModuleNotFoundError` (C2). Both were contract amendments; no product code existed yet, which is exactly why the probes were cheap.
- **P2 ×2 → the same `iterate-to-refine` edge requires a closure pass.** After the amendment package, the code lens re-executed the C1-(c) transform (PASS) and the qa lens found F-QA-6/7 inside the *evidence artifact* itself (truncated union ids, unanchored path) — fixed at the gate.
- **P3 ×2 → not re-work.** The chartered sequential split (Inc-A → Inc-B), with N1 (format module folds into Inc-A) applied before any gate ran.

### The three hard problems (this batch's load-bearing fights)
- **(a) The render-first import cycle — found by P2 review (C1, HIGH), fixed by moving the design, not the symptoms.** Any cold `import s19_app.render.hexview` raised `ImportError` from the partially-initialized module: the move inverted the initialization order the old `tui.hexview` address had relied on. Three dispositions were priced — (a) tui-priming first imports in the new tests, (b) a module-level tui import in `tests/conftest.py`, (c) kill the cycle root. The batch chose (c): the style constants moved DOWN into `render/format.py`, pinned value-equal to the frozen origins by TC-655 — `render/` became tui-free by construction, protecting every future render-first consumer, not just this one. *Lesson: review simulations beat design argument.*
- **(b) The baseline flakiness — 5 full-suite executions to characterize, union methodology, and the honest limitation that the local suite is not a sharp gate.** Identical base code failed 36, 38, 39 and 40 nodes across runs — the failing set moving run to run, widening under load (the 61-minute loaded run produced the widest cloud), while CI is green on the same code. The gate rule became flaky-tolerant over the union corpus (44 → 52 known-unstable nodes at `evidence/baseline-failing-set.txt`), strict only in the functionality-loss direction (stable-pass → fail), with TC-651..TC-655 required green and AT-288 as the sole byte-identity oracle. Recorded as a limitation, not hidden: the batch's no-functionality-loss claim rests on the deterministic evidence set (3× body hash, pinned capture, cross-tree standalone identity), and the suite-flakiness defect itself is carried to the backlog as its own item. *Lesson: gate rules must declare their noise floor.*
- **(c) The AT-288 undriveable charter — caught by the PDR's tester lens before implementation (QA-PDR-1, MAJOR).** Three of the four chartered non-default parameters (`focus_address`, `highlight`, `mac_highlight_addresses`) cannot be driven through the report-service surface — the report path is charter-*forbidden* from touching the `Text` variant that carries them, and the one code path the move changes (the import block) is invisible to a report-only capture. An oracle that cannot be driven verifies nothing (C-10). The PDR read the real signature and call chain; the re-charter to the driveable set (≥2 disjoint `row_bases` windows + non-default `context_bytes`) landed as LED-…92.13 *before* Inc-A authored its capture. *Lesson: charter driveability must be executed, not asserted.*

### Process / workflow findings
> About the dev-flow itself (phases, gates, templates, agents, controls). Feeds workflow improvement — keep separate from product.
- **Station checklist tables went unsigned; sign them at the gates or retire the duplication.** `00-checklists.md`'s per-station tables were dead paper this batch — the real discipline lived in the increment packets' 16-row gate checklists (C-50's one home) and the review artifacts. Either the station tables get signed at each gate or they go.
- **A gate whose reference grows every run risks unfalsifiability.** The union-corpus extension (44 → 52) was legitimate — every added node carries executed evidence in both trees and pre-existence proven at base (LED-…92.15 states the bar) — but the bar must survive the next batch or the gate becomes a rubber stamp. The sharpening (quarantine the corpus or fix the harness-level races; never retry/sleep/xfail) is carried, not absorbed.
- **Name evidence by its anchored artifact home as soon as it exists.** The base-control run first landed at `~/kimi/batch92/base-full-suite.txt`, outside `.dev-flow/`; the contract cited it by the unanchored relative path (QA-PDR-2's one-line lesson, applied one station late). Relocated into `evidence/` at this close.
- **`decisions_log` texts carry cp1252 transliteration artifacts** (`�` where em-dashes and accents were written) — cosmetic, but this record is the next batch's memory. The C-19 lesson met again: write gate evidence with `PYTHONIOENCODING=utf-8` set first.
- **Close-time reconciliation rules earn their blocks; keep the remedy in the open, not in a rewrite.** `V59` saw six touched files the increment tables alone could not — three station-gate writes (registry chartering at P1, the guard bound at the DDR, the architecture map at ARQ) and three AT-290/291 docstring bindings. Batch-91's precedent is the sanctioned home (registry/guard rows carried in a packet table as `config`/`test`); this batch named all six via **declared §2 addenda** in both packets, true authorship stated, sealed Count blocks untouched. An unmarked retro-edit of a sealed packet would have laundered the omission; the addendum format keeps it visible.

### Product findings
> About the code/product under development.
- **The local suite's flakiness is a project defect, pre-existing this batch.** Proven at the untouched base: `at064b` fails there; 36–40 failures per run on identical code. This batch's 5-run characterization + the 52-node inventory are the sharpening starting point. Carried to BACKLOG-CODE.md lane A (with `tc024`/`tc058b`/`at064b` as named members), per the 2026-09-03 family's own closure bar.
- **`css_class_for_severity` in frozen `tui/color_policy.py` is the last service→tui presentation edge.** Killing it (US-92-5) is chartered work blocked on explicit operator unfreeze words — the freeze demands them by design.
- **4 stale `s19_app.tui.hexview` prose mentions** (frozen `range_index.py` docstrings :29/:60/:94 · `tests/test_tui_workspace_layout.py:37` · `diff_report_service.py:35`) — the address no longer exists; cosmetic, routed to the backlog.

### Control lineage
- **New control proposed this batch:** none minted catalog-side. The flaky-tolerant union-corpus gate rule is project-side gate mechanics, recorded in the contract §5.2 with its falsifiability warning; catalog-side `C-66` (flaky is a CLASS with a measured rate, never a name on a list) already exists — this batch's 52-node inventory is that class's project-side home. *(Status: propose — none.)*
- **Prior controls exercised:** `C-17` (safe_text hostile scrub — moved with the function, `_CONTROL_SCRUB` intact, cold-verified by the Inc-B reviewer) · `C-18` (AT↔node binding — AT-289 re-pointed at its realized node at the DDR; AT-290's canonical node named) · `C-31` (input-set oracle — the censuses derive their sets from the live tree; the `insight_style` shim made a missed consumer *silently* green by design, which is why the live-tree derivation matters) · `C-10` (non-vacuous acceptance — QA-PDR-1) · `C-25` (orchestrator-owned gate runs — all 5 full-suite runs) · `C-44` (this sweep). **Near-miss:** the render-first cycle was one un-executed review away from becoming a Phase-3 `ImportError` on the contract's own isolated verification commands.

### Open / deferred items → next batch
| Item | Type (process/product) | Reason deferred | Trigger / owner |
|------|------------------------|-----------------|-----------------|
| SUITE-FLAKINESS — sharpen the local gate (quarantine/mark the 52-node corpus or fix the harness-level timing races) | product | characterization done; the sharpening is its own batch and must not ride a behavior-preserving move | next batch / operator triage — BACKLOG-CODE.md lane A, batch-92 close §1 |
| US-92-5 — `css_class_for_severity` out of frozen `color_policy.py` | product | operator freeze ruling 2026-10-11 stands; lifting it demands explicit words | operator ruling → BACKLOG lane A, batch-92 close §2 |
| C3 — TC-027 `_ENGINE_PATHS` gains `tui/color_policy.py` | product | harmless while the freeze pins the file (a ruling, not a guard) | any batch touching the frozen set — BACKLOG lane A, batch-92 close §3 |
| C4 — 4 stale `tui.hexview` prose mentions | product | cosmetic; the frozen `range_index.py` docstrings want a batch that owns them | cleanup batch — BACKLOG lane A, batch-92 close §4 |
| AT-290/AT-291 registry re-binding (RESERVED → LIVE, canonical nodes already named) | process | pure bookkeeping against the canonical nodes named in `04-validation.md` Layer B | coordinator / next gate over the registry — BACKLOG lane A, batch-92 close §6 |
| batch-93 (memmap2) coordination | process | agreed sequencing: batch-92 lands first; batch-93 runs its contract (P0–P2) now and **holds its source increments (P3+) until batch-92 merges**, then rebases onto the refactored tree; file-set rule — 93 owns the Memory Map surface only, overlap in `screens_directionb.py` resolved by the sequencing | batch-93 coordinator — `.dev-flow/2026-10-11-batch-92/COORDINATION-batch93-memmap.md` |

### Working-file reconciliation (C-44) — MANDATORY, every file this batch touched
> **Run as a sweep, never from memory:** `git status --short` in **every repository touched, auxiliary repos outside the project tree included** · `git log @{u}..HEAD` for commits that exist but were never pushed · an open-PR check. **Pre-existing uncommitted changes are reported as FOUND, never folded into this batch's commit.** A tracked file already modified when the batch began goes in the `Found before the batch` field below the table, not in it.
>
> **A commit that never lands is NOT a terminal state.** Work that is finished but unlanded is indistinguishable from work never done — and it makes the state files the next batch reads assert something false, which that batch then inherits as a premise (**C-43 §2.7**).

| Repo | File(s) | Terminal state | Landing / backlog ref |
|------|---------|----------------|-----------------------|
| `s19_app-b92` | 37 tracked modified (incl. `.dev-flow/state.json`, `AT-TC-REGISTRY.jsonl`, `REQUIREMENTS.md`, `docs/architecture.md`, the repointed consumers/tests, `.gitattributes`) + 1 tracked deleted (`s19_app/tui/hexview.py`) | ✅ committed — the batch's full diff, at the orchestrator's close commit on `410cde5` | this close |
| `s19_app-b92` | `s19_app/render/{__init__,format,hexview}.py` · `tests/{test_render_hexview,test_render_format,test_import_census}.py` (1 237 new lines) | ✅ committed — the moved module, the new tui-free format module, the 5 census/pin nodes | this close |
| `s19_app-b92` | `.dev-flow/2026-10-11-batch-92/` — 67 files (14 top-level incl. this record · 3 increments · 6 design · 3 docs · 39 evidence + `evidence/base-full-suite.txt`, the base-control transcript relocated in at this close) | ✅ committed — the batch record, self-contained | this close |
| `s19_app-b92` | `.dev-flow/_derived/ATLAS-{BATCHES,IFC,ORPHANS,TRACE}.md` | ✅ committed — regenerated at this close (`--atlas --write`); V20 guards them by digest | this close |
| `s19_app-b92` | (anything reverted) | 🗑️ **none — no batch work was discarded; nothing was reverted** | — |
| `~/.claude` · `~/.claude/skills` | uncommitted changes from OTHER lanes (measured at the close: e.g. `docs/analysis/benchmark-2026-09-25/HANDOFF-one-mode-kimi28.md`, rev102 packet work at `35f6c0a`) | 📋 **FOUND at the close — NOT this batch's, must NOT be committed by it**; the two standing `V16` blocks ride the flow coordinator's lane | flow coordinator |
| `s19_app-b92` | `stash@{0}: WIP on claude/batch-77-memmap-variant-a (fffb299)` | 📋 **FOUND before the batch — a foreign branch's WIP, left untouched; must NOT be committed or dropped by this batch** | batch-77 lane |

- **Found before the batch:** `stash@{0}` (batch-77 WIP — predates the batch; this batch never checked out `claude/batch-77-memmap-variant-a`). The `~/.claude` / `~/.claude/skills` dirt **appeared during the batch window** from other lanes' flow work (the first gate, 2026-10-11, ran 0-block with both repos clean) — reported above, not folded. No tracked file was modified when the batch began; the working tree at open contained exactly the batch's own changes.

**Hygiene checks, executed:** no `__pycache__`/`.pytest_cache` noise (`.gitignore:3-4` cover them; the on-disk `s19_app/render/__pycache__` is ignored — `git status` clean of it) · no editor temp files · no secrets (the `evidence/*.bin` files are report-byte captures + their `.PRE` backup and `.sha256`, per the standing PRE-bytes convention) · both increment packets carry **declared §2 addenda** (close V59 reconciliation — six touched files named with true authorship, sealed tables untouched) · **total diff stat: 37 files changed, 620 insertions(+), 773 deletions(-) tracked; +73 new files (67 artifacts · 6 code/test, 1 237 lines)**.

**Conditional gate verdicts:** if any gate this batch ran closed as *"once items 1–N land this is a PASS/MERGE"*, list each item and its discharge **verified by re-reading the artifact** — not by trusting that the corrective pass ran.

| Conditional item | Discharged? | Verified how |
|---|---|---|
| PDR C2 — `docs/architecture.md` carries the KILLED residual rows | ✅ | decisions_log DDR entry (2026-10-12) — "C2 architecture.md KILLED rows landed"; file in the close diff |
| PDR C3 — TC-027 `_ENGINE_PATHS` carry | ✅ as carry | BACKLOG-CODE.md lane A, batch-92 close §3 (this pass) |
| QA-PDR-1 — AT-288 re-charter to the driveable set | ✅ | LED-…92.13; `04-validation.md` Layer B — AT-288 byte-equal to the pinned capture at P4 |
| QA-PDR-2 — evidence path anchored | ✅ | contract refs anchored; base transcript relocated into `evidence/` at this close |
| QA-PDR-3 — run3 per-run ids re-derived in full | ✅ | LED-…92.14 — union file holds 44 full ids; run3 lines rewritten |
| DDR C-1 — scanned-corpus bound 159 → 162 | ✅ | `tests/test_id_registry.py:70`; registry guard 13/13 (LED-…92.14) |
| DDR C-2 — AT-289 re-pointed at its realized node | ✅ | `04-validation.md` Layer B — `test_tc652_wrapper_absence_and_renderer_surface` (LED-…92.14) |

### Evidence checklist — architect + qa-reviewer
> Attach both co-authors' completed evidence checklists (items in their agent files), each ✓/✗ with one-line evidence.
- **qa-reviewer (full):** ✓ complete in `review-p4-qa.md` — per-result Layer A/B attribution (who executed each result), the AT-290 C-18 judgment, the gate-rule application over the 52-node corpus, and the provisional verdict `04-validation.md` finalizes.
- **architect / increment gates:** ✓ the two increment packets' 16-row gate checklists are signed in-packet (C-50's one home), each with its independent code-reviewer verdict (Inc-A: OK to advance, 0 HIGH · Inc-B: OK, 0 findings) and reviewer-run mutation transcripts in `evidence/`.
- **Station tables (`00-checklists.md`):** ✗ not maintained this batch — declared under Process findings rather than retro-filled; the re-work counter they feed is reported above from `state.json` `decisions_log` and `iterations_per_station`.
