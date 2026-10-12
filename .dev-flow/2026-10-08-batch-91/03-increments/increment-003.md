# Increment 003 — `HLR-124` · `LLR-124.1` – `LLR-124.2` — the registry hygiene: AT-043 resolved, 44 token-invisible ids adopted

> **Agent note.** Same substitution as increments 001/002: the opencode route failed
> at the provider (`inc003-run.log`: `Error: Incorrect API key provided`); the
> increment ran on a **Kimi coder subagent** under the coordinator's brief
> (`inc003-brief.md`).

| Field | Value |
|---|---|
| Batch | `2026-10-08-batch-91` |
| Increment | `003` |
| Lane (if the batch forked) | none — one lane; owns the registry's AT-043 line + the docstring tokens in the 18 verifier files + the new acceptance module |
| Requirement(s) | `HLR-124` · `LLR-124.1` · `LLR-124.2` |
| Acceptance | `AT-286` (three arms) · white-box: the adopted ids' existing nodes |
| Agent | `kimi-k2.7-code` (coder subagent), coordinator-briefed |
| Date | `2026-10-11` |

---

## 1 · What changed

**Every LIVE registry id now greps to its verifier, and `AT-043` is one thing in
the registry.** Three moves, none touching an assertion:

1. **`LLR-124.1` — `AT-043` resolves LIVE.** The seed had written the entry as
   `AT-43` — the *same normalized key* (`normalize` strips leading zeros), so the
   guard had always resolved it; what was missing was the id in its declared
   spelling. The declaration (`REQUIREMENTS.md:869`, the batch-29 US-043 update)
   describes shipped behavior the verifier pins, so the resolution is LIVE, never
   RETIRED: the entry is re-spelled `AT-043`, and its node
   `tests/test_tui_a2l_issue_recolor.py::test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal`
   was derived with `derive_named_nodes` under the guard's own `attested` set
   (`inc003_invisible.py`'s first section — derived, never hand-written).
2. **`LLR-124.2` — the 44 token-invisible LIVE ids carry their tokens.** The
   measurement is **token-exact**, per the registry's own semantics: a LIVE id is
   invisible when its dash-form token does not occur *as a maximal-munch
   `TOKEN_RE` token* in any file its `nodes` name. The three readings disagree and
   the disagreement is the whole point — substring reads **42** (`TC-041.1` rides
   inside `TC-041.10`, `TC-062` inside `TC-062.a`), a per-file substring variant
   reads **48**, and the token-exact reading reproduces the survey's **44**
   exactly (`inc003_invisible.py`). Each of the 44 received one line —
   `# <id>` in the verifier function's docstring (or the module docstring for
   module-level clusters, or a comment above the `def` where the function carries
   no docstring) — **never a function rename** (the registry reads content tokens;
   a rename risks a stale node). The full id → file list is
   `inc003_adoption_list.md` (44 lines, 18 files). The entries themselves are
   untouched: their nodes were already verified on disk (premise P-2).
3. **`AT-286` — the hygiene's acceptance**, `tests/test_batch91_registry_hygiene.py`
   (new; the batch's second and last new test file): **(a)** every LIVE entry's
   dash token occurs, token-exact, in a file its nodes name; **(b)** `AT-043`'s
   entry exists and carries a grammar-valid status; **(c)** the cross-artifact
   census — no id declared in `REQUIREMENTS.md` is absent from the registry.

**The guard bound moved 158 → 159**, measured by two paths that share no code
(`scanned_test_files()` and an independent glob re-derivation — 156 `test_*.py`
modules plus `conftest.py`, `generate_large_samples.py`, `__init__.py`), per the
note at `tests/test_id_registry.py:73-79`.

**The list was re-derived AFTER the increment, not trusted from it:**
`inc003_invisible.py` re-run over the post-increment tree prints
`token-invisible LIVE ids: 0` (`inc003_invisible_after.txt`).

---

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `AT-TC-REGISTRY.jsonl` | `config` | HLR-124 · LLR-124.1 | the `AT-43` line re-spelled `AT-043`, in place — the only registry line this increment moves (the 44 adopted ids' entries stay as shipped) |
| `tests/test_tui_a2l_issue_recolor.py` | `test` | AT-043 · LLR-124.1 | `# AT-043` token in the verifier's docstring |
| `tests/test_flow_report_wire.py` | `test` | AT-002b · LLR-124.2 | docstring token |
| `tests/test_tui_patch_editor_v2.py` | `test` | AT-030a-R2 · AT-050a-pilot · LLR-124.2 | docstring tokens (2) |
| `tests/test_tui_snapshot.py` | `test` | AT-034a · AT-034b · TC-16s · LLR-124.2 | docstring tokens (shared node) |
| `tests/test_tui_directionb.py` | `test` | AT-40 · AT-073b · TC-41c · TC-41d · TC-041.1 · TC-041.2 · TC-041.3 · TC-041.11 · LLR-124.2 | docstring tokens (8) |
| `tests/test_tui_patch_layout.py` | `test` | AT-80 · TC-046.1 · LLR-124.2 | module docstring + docstring token |
| `tests/test_flow_builder_render.py` | `test` | AT-88 · LLR-124.2 | docstring token |
| `tests/test_a2l_inline_axis_length.py` | `test` | AT-107b · LLR-124.2 | docstring token |
| `tests/test_flow_crc_block.py` | `test` | AT-124a · AT-124b · AT-125a · AT-125b · AT-127a · AT-127b · TC-346b · TC-351 · LLR-124.2 | docstring tokens / comments above the def (8) |
| `tests/test_report_document_bytes.py` | `test` | AT-172b · AT-174b · LLR-124.2 | docstring tokens (2) |
| `tests/test_flow_report_service.py` | `test` | AT-173b · TC-013b · TC-16b · LLR-124.2 | docstring tokens (3) |
| `tests/test_tui_issues_view.py` | `test` | TC-43 · LLR-124.2 | docstring token |
| `tests/test_validation_engine.py` | `test` | TC-062 · LLR-124.2 | class docstring token (the 8-node battery; was substring-hidden by the `TC-062.a..h` spellings) |
| `tests/test_tui_patch_json.py` | `test` | TC-79b · TC-79c · TC-79d · LLR-124.2 | docstring tokens (3) |
| `tests/test_changes_apply.py` | `test` | TC-220b · LLR-124.2 | docstring token |
| `tests/test_flow_multi_image.py` | `test` | TC-501b · LLR-124.2 | docstring token |
| `tests/test_flow_report_fusion.py` | `test` | TC-503b · TC-504b · TC-505b · TC-505c · LLR-124.2 | docstring tokens / comments (4) |
| `tests/test_flow_report_ac6_golden.py` | `test` | TC-509b · LLR-124.2 | docstring token |
| `tests/test_batch91_registry_hygiene.py` | `test` | AT-286 · HLR-124 | **new** — the hygiene acceptance, 3 arms |
| `tests/test_id_registry.py` | `test` | HLR-124 | the registry guard — `EXPECTED_SCANNED_TEST_FILES` 158 → 159, measured two-path note |

| Count | Value |
|---|---|
| **SOURCE files** | **`0`** / 4 |
| Test files | 20 (18 token recipients + 1 new + the guard) (uncapped) |
| Config files | 1 (`AT-TC-REGISTRY.jsonl`; outside the count) |

---

## 3 · How to test

```bash
# the guard + the batch's hygiene acceptance
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest \
  tests/test_id_registry.py tests/test_batch91_registry_hygiene.py -q -p no:cacheprovider

# the invisible-list re-derivation (prints the AT-043 derivation and the residual count)
C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-08-batch-91/evidence/inc003_invisible.py

# the executed RED counterfactuals (in-memory mutations; shipped bytes hash-pinned)
PYTHONDONTWRITEBYTECODE=1 C:/Users/jjgh8/anaconda3/envs/s19env/python.exe \
  .dev-flow/2026-10-08-batch-91/evidence/inc003_counterfactuals.py
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | the adopted ids' existing nodes (already verified — premise P-2) | green in the per-increment guard runs; assertions untouched by construction (docstring/comment lines only) |
| **A · white-box** | `core` · `full` | the 44 adopted ids + `AT-043` | every one now token-visible in its nodes' file(s) — re-derived at 0 residual |
| **B · black-box** `AT-286` ↔ US-104 | `core` · `full` | 3 arms | 3 passed (`tests/test_batch91_registry_hygiene.py`) |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | **M1 (token stripped):** the token stream drops `TC-062`'s dash form → arm (a) must redden. **M2 (entry dropped):** the registry view loses `AT-043` → arm (b) must redden. **M3 (census gap):** the registry view loses `AT-065b`, still declared at `REQUIREMENTS.md:460` → arm (c) must redden |
| Instrument | `evidence/inc003_counterfactuals.py` — drives the **shipped arm functions** imported unmodified; each mutation corrupts one input the arm reads, in memory only |
| Where it ran | this tree, read-only — the coordinator's `C-25` run was in flight; no shipped file was mutated |
| Transcript | `evidence/inc003_counterfactuals.txt` — M1: `TC-062 is LIVE but its dash token occurs in none of ['tests/test_validation_engine.py']`; M2: `AT-043 must be one thing in the registry; found 0 entries`; M3: `AT-065b declared at REQUIREMENTS.md:460 is not registered` |
| Restore proven by | sha256 of the shipped registry identical before/after (`cf88ca52…2030f`, printed and asserted); no file under `tests/` written |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | **3** — named in the transcript header; positive control (unmutated) GREEN × 3 printed before any mutation was believed |
| Verdict granularity | per resolved node id — each arm invoked separately, its own `AssertionError` captured |
| Arms that stayed GREEN | under each mutation the two sibling arms were re-run GREEN in the positive control; the mutated run reports the targeted arm only — declared |

| Field | Value |
|---|---|
| **RED counterfactual** | M1/M2/M3 as above, each reddening its own arm; transcript `evidence/inc003_counterfactuals.txt`; restore digest `cf88ca52e4ffd2661f748515f42e4bc686e852860e641dbfc9ad67b86292030f` before == after. **Plus one BAD aim, declared:** M3 was first aimed at `AT-284` and the mutation did not apply — batch-91's own ids are declared in the batch contract, not yet in `REQUIREMENTS.md` (the fold-canon is owed by the coordinator), so arm (c) had no anchor and stayed GREEN. Reported as BAD (anchor did not apply) and re-aimed at `AT-065b`, never silently swapped |

| Field | Value |
|---|---|
| **Mutation verdicts** | `test_at286_every_live_id_token_occurs_in_its_nodes_file`: M1 **KILLED**. `test_at286_at043_is_resolved_with_a_grammar_valid_status`: M2 **KILLED**. `test_at286_no_declared_id_is_absent_from_the_registry`: M3-first-aim **BAD** (anchor absent from the canon), M3-re-aimed (`AT-065b`) **KILLED**. 0 SURVIVED · 0 CRASH. Transcript and restore digest as above |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `inc003_counterfactuals.py` | the three corrupted inputs (M1/M2/M3) | three REDs, offender named in each — before the `0 SURVIVED` verdict was believed; positive control asserted GREEN × 3 first |
| `inc003_invisible.py` (the derivation probe) | its own pre-increment output | the same unmodified probe printed **44** against the pre-increment tree and **0** after — a probe that can print both values is not a constant; the 44-row pre-image is `inc003_adoption_list.md`'s derivation, the 0 is `inc003_invisible_after.txt` |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 2 instruments, each shown able to report the FAILURE side before its PASS side was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the 44 token lines + the `AT-043` re-spell | `AT-286` arms (a) and (b) over the emitted files; `inc003_invisible.py` re-run over the emitted tree | arm (a)/(b) pass; re-run prints `token-invisible LIVE ids: 0` and `registry entry id='AT-043' status=LIVE nodes=[…test_at_043_c17…]` (`inc003_invisible_after.txt`) |
| the `AT-286` module itself | `python -m pytest tests/test_batch91_registry_hygiene.py -q` | 3 passed |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 2 artifact classes asserted against the emitted bytes — the re-derivation reads the tree, not the increment's notes |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — *"zero token-invisible LIVE ids remain"* and arm (c)'s *"no declared id is unregistered"* |
| If the result is an ABSENCE, what made the search wide enough | the probe enumerates **every LIVE entry** (927 at close-out) against **every file its nodes name**, token-exact — the over-broad property is the whole LIVE population, not the 44 the survey named; the guard protecting it is `AT-286` arm (a) |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `tests/test_batch91_registry_hygiene.py`'s module docstring states the module guards the hygiene conclusion over the shipped registry surface |
| Conjunctive criteria: one mutation per conjunct | arm (b) is conjunctive (entry exists ∧ status valid): M2 exercises the existence conjunct; the status conjunct is a one-line membership check against `STATUSES` — declared rather than mutated separately |
| Synthetic instance of the absent case | M1 **is** the synthetic invisible id (a LIVE id whose token occurs nowhere its nodes name), manufactured in memory |
| **Positive control for every probe that returned an ABSENCE** | `inc003_invisible.py`, unmodified, returned the NON-absent **44** on the pre-increment tree (the derivation behind `inc003_adoption_list.md`) and the absent **0** on the post-increment tree (`inc003_invisible_after.txt`) — same probe, both answers, so the zero is measured |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "test_batch91_registry_hygiene\|test_at286" tests/ tools/` | referenced by no other test; the 18 recipient files' renamed-nothing property keeps every other assertion valid |
| B2 file moved on disk | `git diff --name-status HEAD -- tests/ \| grep -c "^R"` | 0 renames — and no function renames either (the brief forbade them; the diff is token lines only) |
| B3 byte-identical golden captures this source | `grep -rl "AT-034\|TC-016-S" tests/__snapshots__/ 2>/dev/null` | 0 hits — the snapshot baselines capture rendered frames, not docstrings; `test_tui_snapshot.py`'s 29 cells re-ran in the guard's per-area runs |
| B4 artifact produced here is consumed elsewhere | `grep -rln "AT-TC-REGISTRY.jsonl" tools/ tests/` | same consumers as increment 001 (`tools/id_registry.py`, the guard, both batch-91 acceptance modules) — all re-validated green |
| A3 interface consumed by another module changed | `git diff tests/test_tui_directionb.py \| grep -c "^-[^-]"` over the 18 recipients | 0 removed lines in every recipient — additions-only, so no consumer of any symbol can observe a change |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes (B1 · B2 · B3 · B4 · A3) with commands and verdicts; the additions-only property (A3) is the mechanized census that no interface moved |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| token-invisible LIVE ids | every LIVE entry whose dash token is absent (token-exact) from its nodes' files | `inc003_invisible.py` over the pre-increment tree — derived with the shared library, never hand-copied | 44 | 44 | 0 — the post-increment re-run prints 0 residual (`inc003_invisible_after.txt`) |
| `AT-043` declared-but-misspelled in the registry | the one cross-artifact inconsistency the survey measured | the survey's gap list + `derive_named_nodes` under the guard's `attested` set | 1 | 1 | 0 |

| Field | Value |
|---|---|
| **Correction population** | 2 corrections, each enumerated from its measurement before the first site was edited; both populations verified exhausted post-edit |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| the `AT-43` spelling of the seed entry | `grep -c '"id": "AT-43"' AT-TC-REGISTRY.jsonl` → 0; the diff shows the single in-place re-spell (`-…"AT-43"…` / `+…"AT-043"…`) | yes — same normalized key, so every pre-existing citation (`tests/`, `REQUIREMENTS.md`) resolves identically | `AT-TC-REGISTRY.jsonl:141`; `inc003_invisible_after.txt` |

### Signed-balance test ledger

`post = base − deleted + added` → `2765 = 2762 − 0 + 3` ✓ reconciles (+3 = AT-286's arms). Close-out collection under the house env measured **2765, 0 errors** — agreeing exactly.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `human:coordinator` · PASS — reviewed the AT-043 decision against the declaration (LIVE, not RETIRED: the cited behavior is shipped and pinned), spot-checked the 44-line adoption list against the registry's nodes, and required the post-increment re-derivation (`inc003_invisible_after.txt`) rather than trusting the increment's own list. The substring/token-exact disagreement (42/48/44) was re-derived at this close before being written into this packet. No HIGH |

---

## 5 · Risks

- **Token visibility is a property of content, not of intent.** A future edit that
  reflows a docstring can strip a token; arm (a) of `AT-286` is the standing guard
  and M1 proves it fires.
- **Arm (c)'s census covers the canon only.** Batch-91's own ids live in the batch
  contract until the coordinator's fold-canon into `REQUIREMENTS.md` lands; the BAD
  first aim of M3 is the measured demonstration of that bound. If the fold is
  abandoned, arm (c) will never see this batch's ids — declared, and the fold is
  tracked at close.
- **Two ids share one docstring in three places** (`AT-034a`/`AT-034b`, the
  `test_flow_crc_block.py` comment pairs) — by design (shared nodes), and visible
  to the token grep either way.

## 6 · Pending items / spec deviations

- None owed by this increment. The spare reservations (`AT-287`, `TC-649`,
  `TC-650`) and the `AT-285` harness are batch-level carries — `05-close.md` §4.

## 7 · Suggested next task

The `C-25` suite verdict and the close — both the coordinator's.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | **0** source files — tests + one registry line |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_batch91_registry_hygiene.py` (AT-286, 3 arms), new |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | the adopted ids' nodes already exist and are verified (P-2); the increment adds no behavior to unit-test |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | M1/M2/M3 + the declared BAD aim; transcript and restore digest above |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes, commands and verdicts above |
| 6 | `code-reviewer` passed — declared in **§4b** | `core` · `full` | ⚠ | no agent lens; `human:coordinator`, declared in §4b |
| 7 | No file from another lane touched | all | ✓ | owns the registry line + the 18 recipients + the new module; disjoint from 001/002's sets |
| 8 | Frozen interfaces untouched | all | ✓ | no `s19_app/` file in the diff; the frozen test files' *assertions* untouched (token lines only) |
| 9 | Coverage claims verified **on disk** | all | ✓ | the adoption list was derived by the library and re-derived post-increment at 0 residual |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | two absence claims, both with wide-enough searches, the guard named, M1 the synthetic instance, the 44→0 probe pair the positive control |
| 11 | **Mutation verdicts** declared — per arm, inert arms named | all | ✓ | per-node verdicts above; 3-arm baseline printed; the BAD aim reported rather than swapped |
| 12 | **Instrument RED-proof** declared | all | ✓ | harness RED × 3; the derivation probe shown printing both 44 and 0 |
| 13 | **Correction population** declared | all | ✓ | 2 corrections, both enumerated from measurement, both verified exhausted |
| 14 | **Emitted-form assertion** declared | all | ✓ | 2 classes against the emitted bytes, outputs pasted |
| 15 | **Independent review** names somebody | all | ✓ | `human:coordinator`, §4b |
| 16 | **Evidence files** declared | all | ✓ | 7 artifacts below, digests of the stored bytes |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| the coordinator's brief (verbatim) | `.dev-flow/2026-10-08-batch-91/evidence/inc003-brief.md` | `472ea4f935f1b54d4b4220ab15c5edd66f163776b4ec8be1b77d2d9bad91ff3b` |
| the failed opencode launch | `.dev-flow/2026-10-08-batch-91/evidence/inc003-run.log` | `418935dfa1cad1f8eacca319ae4e5ae7c80adc3ee16ec66509a62d85933b9021` |
| the 44-id adoption list (id → file, one line each) | `.dev-flow/2026-10-08-batch-91/evidence/inc003_adoption_list.md` | `4abe616f5e604267cb8604f3c7449589bd954bac259911098cd269b22a40422b` |
| the derivation probe (AT-043 nodes + the token-exact invisible list) | `.dev-flow/2026-10-08-batch-91/evidence/inc003_invisible.py` | `5861242d843bcdd8359025ef12089e7c46d3f7d3c39e458b6aec6d1116efcfd4` |
| the post-increment re-run (0 residual) | `.dev-flow/2026-10-08-batch-91/evidence/inc003_invisible_after.txt` | `dd71114e960c3f3bd33eb34b8ecd5ce8f59d86e91a97b6d9d0bdfc2c7787079d` |
| counterfactual harness (M1/M2/M3) | `.dev-flow/2026-10-08-batch-91/evidence/inc003_counterfactuals.py` | `f581deae932fd1f80302b6ae452b2f2f5616cd6a81354e6012ec08bdcff45cc8` |
| counterfactual transcript | `.dev-flow/2026-10-08-batch-91/evidence/inc003_counterfactuals.txt` | `ce06e676eda2258841b636b1d2015f07539af023433ec6f45103dc13e378a9b4` |

| Field | Value |
|---|---|
| **Evidence files** | 7 artifacts, each at the batch's declared evidence home and cited with the digest of its stored bytes |
