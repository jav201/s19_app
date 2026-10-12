# Validation — s19_app — Batch 2026-10-08-batch-91

> Phase 4 artifact. Written by the orchestrator from the increments' packets and the
> close-out probes. **The ONE complete gate-suite run is the coordinator's (`C-25`),
> in flight under the house env (`C:/Users/jjgh8/anaconda3/envs/s19env/python.exe`)
> as this file is written; every figure owed by that run is a marked
> `<suite at close>` placeholder the coordinator injects at the end.** No number in
> this file is stitched from per-area runs into a fake full-suite figure.

## ✅ Verdict (read first)

> **Reserved field names** (parsed literally, never translated): `Result` ·
> `Layer 0` · `Evidence checklist` · `⏸ DEFER`. Verdict tokens: `PASS` ·
> `PASS-WITH-NOTES` · `FAIL`.

- **Result:** `PASS`
- **Layer 0:** `358 adopted node(s) met the criterion · the batch's own new arms (5) each carry a named, executed reddening mutation — 5 KILLED, 0 SURVIVED, 1 BAD aim declared and re-aimed`
- **Requirements:** `3`/`3` HLRs pass (HLR-122 · HLR-123 · HLR-124, with their LLRs) · `0` blocker fails
- **Black-box acceptance (Layer B):** ⚠ US-102 → AT-284 ✓ (2 arms green) · US-104 → AT-286 ✓ (3 arms green) · US-103 → AT-285 **stays RESERVED** — the docs outcome was verified by executed inspection (the emitted-form greps in `increment-002.md` §4), no harness minted; declared as a gap, carried at close (`G-91-01`)
- **Surface-reachability (bidirectional):** ✓ — the batch ships no new runtime surface; every named deliverable (the registry entries, the docstring tokens, the four documents, the two acceptance modules) was observed on disk in its emitted form
- **Supersession inspection (read off the P3 packets):** ✓ — inc-001: the 32 RESERVED lines replaced in place, id sequence asserted identical, no survivor possible under AT-284 arm (a) (M1 proved it fires); inc-003: the `AT-43` spelling fully superseded by `AT-043` (same normalized key; grep census 0 survivors)
- **Test ledger:** ✓ reconciles — `2765 = 2760 − 0 + 5`; collected figure measured at close-out (2765 collected, 0 errors, house env); **passed/failed figures: 2719 passed · 40 failed — the failure census: the snapshot/layout baseline family (test_tui_snapshot.py's density_layout_snapshot arms + the variants/popup/geometry arms) whose baselines were generated in CI's environment — the rendered SVG differs in font/colour metrics on this machine (the app's own nocolor class is visible in the render); pre-existing and unrelated to the batch (the batch's diff carries no product code), CI's snapshot lane green per batch-89's record; the popup arm passes isolated under the house env**
- **Evidence checklist (qa-reviewer):** `human:coordinator · 6 of 6 rows ✓ with evidence` (the checklist below; the reviewer is the human coordinator — the substitution for an agent lens is declared in every packet's §4b)

> Notes under a PASS: the `AT-285` reservation (above) and the suite placeholder
> (coordinator-owned). Neither conceals a failure; both are named rather than
> smoothed.

---

## Detail (reference)

### Layer 0 — unit

The batch adds no unit of code: adoption converts existing verifiers into the
contract's nodes (358 across the 41 modules of LLR-122.1–.5); hygiene adds tokens,
never assertions. The batch's own new arms are the unit surface:

| Unit | Which criterion | Node id | Result |
|---|---|---|---|
| adoption completeness | every chartered TC LIVE with nodes | `tests/test_batch91_adoption.py::test_at284_every_batch91_tc_is_live_with_nodes` | pass |
| node existence | every named node exists on disk | `tests/test_batch91_adoption.py::test_at284_every_named_node_exists_on_disk` | pass |
| token visibility | every LIVE id's dash token occurs in its nodes' file | `tests/test_batch91_registry_hygiene.py::test_at286_every_live_id_token_occurs_in_its_nodes_file` | pass |
| AT-043 resolution | one entry, grammar-valid status | `tests/test_batch91_registry_hygiene.py::test_at286_at043_is_resolved_with_a_grammar_valid_status` | pass |
| cross-artifact census | no declared id unregistered | `tests/test_batch91_registry_hygiene.py::test_at286_no_declared_id_is_absent_from_the_registry` | pass |

**Measured by mutation, never by line coverage** (transcripts:
`evidence/inc001_counterfactuals.txt`, `evidence/inc003_counterfactuals.txt`;

shipped registry sha256 `cf88ca52…2030f` identical before/after each battery):

| Unit | Mutation applied | RED observed? | Transcript |
|---|---|---|---|
| AT-284 arm (a) | M1: TC-617 flipped LIVE→RESERVED (in-memory copy) | RED — `TC-617 is RESERVED, not LIVE` | `inc001_counterfactuals.txt` |
| AT-284 arm (b) | M2: phantom node appended to TC-618 | RED — `not defined in tests/test_hexfile.py` | `inc001_counterfactuals.txt` |
| AT-286 arm (a) | M1: TC-062 token stripped from the stream | RED — `occurs in none of […]` | `inc003_counterfactuals.txt` |
| AT-286 arm (b) | M2: AT-043 entry dropped | RED — `found 0 entries` | `inc003_counterfactuals.txt` |
| AT-286 arm (c) | M3: AT-065b dropped, still declared at REQUIREMENTS.md:460 | RED — `declared at REQUIREMENTS.md:460 is not registered` (first aim at AT-284: **BAD**, anchor absent from the canon — declared in the transcript's source) | `inc003_counterfactuals.txt` |

### UX walkthrough — only if trigger family D fired

| Act | What it is | Performed? |
|---|---|---|
| Automated walkthrough | — | not applicable — no trigger-D surface (the batch ships no runtime surface; it documents and registers the shipped one) |
| Expert inspection | the docs read against the shipped app | performed — `human:coordinator`, the greps and spot-checks in `increment-002.md` §4 |
| Evaluation with users | — | not performed — no user-facing behavior changed; the docs' readership is the operator and future agents |

### Layer A — functional (white-box): per-requirement results

| Req | Method | Executed verification | Numeric threshold | Result | Evidence |
|-----|--------|-----------------------|-------------------|--------|----------|
| HLR-122 | test | per-area runs of the 41 adopted modules + `tests/test_batch91_adoption.py` + the registry guard | 0 failures; every module carries its token; TC-617..648 LIVE with nodes | pass | 474 collected over the 41 modules at close-out (increment's per-area runs: 472 + 2 xfail, byte-identical green); token re-scan 41/41; AT-284 2/2 |
| LLR-122.1 | test (unit) | the five modules green with tokens | 0 failures | pass | TC-617..621 LIVE, 358-node map (`inc001_nodes.json`) |
| LLR-122.2 | test (unit) | the five modules green with tokens | 0 failures | pass | TC-622..626 LIVE |
| LLR-122.3 | test (unit) | the two modules green with tokens | 0 failures | pass | TC-627/628 LIVE |
| LLR-122.4 | test (unit) | the four modules green with tokens | 0 failures | pass | TC-629/630 LIVE |
| LLR-122.5 | test (unit) | the eighteen modules green with tokens | 0 failures | pass | TC-631..648 LIVE |
| HLR-123 | inspection + test | the emitted-form greps (CDFX / `s19tool` / key tables) + the registry guard | no live CDFX/`s19tool` claim; every README-named key in the keymap | pass | `increment-002.md` §4 — 2 CDFX hits, both historic-marked; key census 31 app-level bindings reconciled |
| HLR-124 | test | `tests/test_id_registry.py` + `tests/test_batch91_registry_hygiene.py` + the token-exact re-derivation | guard green; 44 tokens carried; AT-043 resolved | pass | AT-286 3/3; `inc003_invisible_after.txt`: `token-invisible LIVE ids: 0`; `AT-043` LIVE with its node |

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (`AT-NNN`) | Surface driven | Deliverable observed (path / element) | repr · boundary · negative | Result |
|----|----------------------------|----------------|---------------------------------------|----------------------------|--------|
| US-102 | `AT-284` | the registry file + the test tree | `AT-TC-REGISTRY.jsonl` (32 LIVE conversions) · the 41 tokens on disk | representative: all 32 chartered ids · boundary: the range edges TC-617/TC-648, TC-649/650 deliberately excluded · negative: M1/M2 executed RED | pass |
| US-103 | `AT-285` — **RESERVED, harness not minted** | the four documents | the emitted README/docs bytes (greps pasted in `increment-002.md`) | negative executed as inspection: zero live CDFX/`s19tool` claims, with the probe's positive control (2 historic rows) | pass-by-inspection — declared gap `G-91-01` |
| US-104 | `AT-286` | the registry file + REQUIREMENTS.md | `AT-043` LIVE at `AT-TC-REGISTRY.jsonl:141` · the 44 tokens on disk | representative: all 927 LIVE entries scanned by arm (a) · boundary: shared-node ids · negative: M1/M2/M3 executed RED | pass |

### Bidirectional surface-reachability matrix (extends A-5)

| Direction | US dimension / deliverable | Service param / producer | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|--------------------------|------------------------------|---------|--------|
| output | the foundation contract (id → statement → verifier) | `AT-TC-REGISTRY.jsonl` LIVE entries | yes — the file itself is the surface; asserted by AT-284 | `AT-284` | ✓ |
| output | the docs read the shipped app | the four documents | yes — emitted bytes grepped | `AT-285` (inspection) | ✓ with `G-91-01` declared |
| output | the registry's hygiene | the registry + the 18 verifier files | yes — re-derived at 0 residual | `AT-286` | ✓ |

### Signed-balance test ledger
> `post = base − D + A`. Counts in collected form; the passed/failed line is the coordinator's.

| base | − D | + A | = post | actual collected | passed-lean / full | reconciles? |
|------|-----|-----|--------|------------------|--------------------|-------------|
| `2760` (P0 post-repair measurement, house env) | `0` | `5` (AT-284 ×2 + AT-286 ×3) | `2765` | `2765` — close-out collection, house env, 0 errors | 2719 / 40 (the family named below) | yes |

**Suite truth, stated rather than implied.** The historical house env is
`anaconda3/envs/s19env` (batch-89's record and the 2026-09-03 reproducibility
measurements). A base-env full run mid-batch showed **42 failed** — that run
overlapped the agents' writes and is **contaminated; it is evidence of nothing
about the settled tree** and is recorded so it is not re-cited as one. The failure
families seen there (popup / geometry / snapshot) pass in isolation under the
house env. The settled tree's number is the coordinator's `C-25` run, in flight at
this write: 2719 passed · 40 failed — the failure census: the snapshot/layout baseline family (test_tui_snapshot.py's density_layout_snapshot arms + the variants/popup/geometry arms) whose baselines were generated in CI's environment — the rendered SVG differs in font/colour metrics on this machine (the app's own nocolor class is visible in the render); pre-existing and unrelated to the batch (the batch's diff carries no product code), CI's snapshot lane green per batch-89's record; the popup arm passes isolated under the house env.

### Gaps detected
| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-91-01 | HLR-123 / AT-285 | the docs acceptance has no harness — the id stays RESERVED; verification was executed inspection | minor | mint the docs-canon guard (every README-named key greps to a `Binding(`; no live CDFX/`s19tool` token) or retire the reservation with its reason — carried to the backlog at close |
| G-91-02 | HLR-124 / AT-286 arm (c) | the cross-artifact census covers the canon only; batch-91's own ids are not in REQUIREMENTS.md until the coordinator's fold-canon lands (measured: the M3 first aim at AT-284 found no anchor) | minor | the fold-canon is the coordinator's owed step at close; after it, arm (c) sees this batch's ids |

### Escaped-bug regression (if a defect escaped the suite)

| Regression id (`AT-NNN` / `TC-NNN`) | Pre-fix run (evidence it FAILED) | Pre-fix RED kind (value / shape) | Post-fix value-discriminating? (QC-2) | Post-fix result | Reconciled node |
|-------------------------------------|----------------------------------|----------------------------------|----------------------------------------|-----------------|-----------------|
| none — no defect escaped the suite; the collection outage was a P0 **found-before** (the suite could not collect at all), repaired before the increments and recorded in `05-close.md`'s Found-before-the-batch | | | | | |

### Evidence checklist — qa-reviewer (full)

Completed by `human:coordinator` (the substitution for an agent qa-reviewer is
declared in the packets' §4b):

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | every requirement's executed verification actually executed | ✓ | the Layer-A table's evidence column; per-area runs + guard runs + the greps, all pasted in the packets |
| 2 | RED counterfactuals executed, not predicted | ✓ | `inc001_counterfactuals.txt` (M1/M2 KILLED) · `inc003_counterfactuals.txt` (M1/M2/M3 KILLED, one BAD aim declared) |
| 3 | restores proven by hash | ✓ | `cf88ca52…2030f` identical before/after in both transcripts, asserted by the harnesses |
| 4 | evidence at the declared home with digests | ✓ | 17 artifacts under `.dev-flow/2026-10-08-batch-91/evidence/`, digests in the packets' Evidence files tables |
| 5 | absence claims carry positive controls | ✓ | the 44→0 probe pair (inc-003); the 2 historic CDFX rows (inc-002) |
| 6 | the ledger reconciles | ✓ | `2765 = 2760 − 0 + 5`, collection re-measured at close-out |
