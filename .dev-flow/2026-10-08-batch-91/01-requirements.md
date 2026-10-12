# Requirements Document — s19_app — Batch 2026-10-08-batch-91

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
*(Informative text. Describes the document's objective.)*

### 1.2 Scope
*(What this batch covers and what it does NOT cover.)*

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| | |

### 1.4 References
*(Related documents, standards, external tickets.)*

### 1.5 Document overview
*(How this document is structured.)*

---

## 2. Overall description

### 2.1 Product perspective
*(How the change fits into the larger system.)*

### 2.2 Product functions
*(High-level list of functional capabilities.)*

### 2.3 User characteristics
*(Roles, permissions, expected experience levels.)*

### 2.4 Constraints
*(Technological, regulatory, business.)*

### 2.5 Assumptions and dependencies
*(What we take for granted. If an assumption fails, the batch is invalidated.)*

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-102 | As a maintainer, I want the foundation engines contracted with real ids and their existing tests adopted as the verifiers, so that every shipped behavior traces id → statement → test. | operator commission 2026-10-08 | READY |
| US-103 | As a new reader, I want the README and docs to describe the shipped 10-screen app, so that I learn the real product. | operator commission 2026-10-08 (the doc drift measured in the survey) | READY |
| US-104 | As a maintainer, I want every LIVE registry id to grep to its verifier and no declared id unregistered, so that the authority is complete. | operator commission 2026-10-08 | READY |

#### Refinement log (one block per story)

**US-001 — `<short title>`**
- **INVEST:** I · N · V · E · S · T  (mark ✓/✗ each)
- **Functionality (V, N):** user = … · outcome = … · why = … · out of scope = …
- **Feasibility (E, S):** implementation path = … · dependencies/unknowns = … · fits one batch? = yes/no (split or spike if no)
- **Evaluability (T) — behavioral, black-box:** ≥1 observable acceptance criterion at the behavior level = "When `<input>`, the user observes `<outcome through the shipped surface>`" (becomes an `AT-NNN` in Phase 1). A story phrased as a mechanism (implementation spec) is mis-captured → REFINE.
- **Open questions:** …
- **Classification:** `READY` / `REFINE` / `SPIKE` / `OUT` — `<reason / next action>`

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| P-1 | The 41 unpinned test modules pin real shipped behavior (each module's tests pass on the current tree) — adoption, not re-implementation, is the honest move | measured at P0 | TRUE | the coordinator's survey: the 41 modules listed with their counts; the base suite collects 2760 and runs green | the adoption law is the contract's (HLR-122) |
| P-2 | The registry's LIVE nodes are already verified on disk — the 44 renames are orthographic only | measured | TRUE | the coverage survey (893/893 LIVE ids have their nodes present) | LLR-124.2 is a rename, never an assertion edit |
| P-3 | The repo's own tests package must win the `tests` import over any editable install's stray `tests` package — the base suite could not collect before the repair (22 collection errors from another repo's .pth) | found at P0 | TRUE — repaired at P0 (`tests/__init__.py` + the uniformized `tests.conftest` imports) | the base suite collects 2760 after the repair | recorded in the close's Found-before-the-batch |

- **Premise evaluation:** 3 premise(s) · ✅ TRUE / ✅ TRUE / ✅ TRUE

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

- **Fork preconditions:** none — one lane on the main checkout. (The increments take disjoint file sets: 001 owns the foundation modules' docstrings + the registry entries; 002 owns README.md + docs/; 003 owns the renamed test functions + AT-043. No two live briefs share a file; batch-90 stays HELD and untouched.)

---

## 3. High-level requirements (HLR)

### HLR-122 — The parsing engines carry the contract they never had
- **Traceability:** US-102
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** The shipped foundation — the S-record/Intel-HEX parser and emitters, the A2L engine, the MAC parser, the CRC engines, the range index, and the TUI host-surface behaviors the oldest strata left prose-only — shall carry real requirements with real test ids: every LLR below names its TC range, and each TC ADOPTS the existing test modules that already pin the behavior (the 41 unpinned modules stay byte-identical except for the docstring token that names its TC — adoption, never re-implementation); where a module pins behavior no contract section covers, the requirement is written from the code's own shipped law (the characterization discipline: the statement says what the code provably does, never an intention).
- **Rationale (informative):** the operator's commission 2026-10-08 — the foundation was built while dev-flow was in development; the stable flow owes it its contract.
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests -q` + the registry's guard (`tests/test_id_registry.py`)
- **Numeric pass threshold:** the suite stays green (0 new failures vs the base run); every adopted module carries its TC token; the registry's LIVE entries for TC-617..650 carry their `nodes`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the foundation's behaviors trace: id → statement → verifier, every one of them.
  - **Shipped surface:** the engines' shipped behavior (unchanged — this batch documents, it does not alter).
  - **Acceptance test(s):** AT-284 (the registry guard passes over the adopted tokens; the suite runs every adopted module).
  - **Boundary catalog (QC-3):** none new (adoption adds no behavior).
  - **Negative control:** a module without its TC token — the registry guard/report shows it unadopted (the adoption completeness is greppable).

### LLR-122.1 — S19/Intel-HEX parse and emit
- **Traceability:** HLR-122
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** the S-record parser shall parse S0–S9 with per-record checksum validation, overlap and out-of-order detection, and contiguous-range/gap computation; the Intel HEX parser shall handle record types 00–05 with checksums and the memory map; the emitters shall round-trip a parsed image back to records; the range index shall answer membership in sorted ranges. Pinned by TC-617 (tests/test_core_srecord_validation.py), TC-618 (tests/test_hexfile.py), TC-619 (tests/test_hex_emit.py), TC-620 (tests/test_range_index.py), TC-621 (tests/test_address_census.py + tests/test_address_origin.py).
- **Validation:** `test (unit)`
- **Executed verification:** the five modules run green in the suite; each carries its TC token in its docstring.
- **Numeric pass threshold:** 0 failures in the five modules; the registry lists TC-617..621 as LIVE with their nodes.
- **Negative control:** a module missing its token (the adoption greppable law).
- **Boundary catalog:** the parsers' own boundary arms already live in the modules (empty files, junk records, the wrap-around).

### LLR-122.2 — the A2L engine
- **Traceability:** HLR-122
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** the A2L engine shall parse ASAP2 structure, extract tags, enrich raw+physical values via datatype/COMPU_METHOD, and validate internally (the viewer's 19-field filter and per-row severity are §37's surface contract — the ENGINE's contract here is the parse/enrich/validate law). Pinned by TC-622 (tests/test_a2l_enriched.py), TC-623 (tests/test_a2l_missing_length_fix.py), TC-624 (tests/test_a2l_record_layout_length.py), TC-625 (tests/test_tui_a2l.py), TC-626 (tests/test_validation_a2l.py).
- **Validation:** `test (unit)`
- **Executed verification:** the five modules green, each carrying its token.
- **Numeric pass threshold:** 0 failures in the five modules; TC-622..626 LIVE with nodes.
- **Negative control:** the adoption greppable law.
- **Boundary catalog:** the modules' own missing-length/record-layout arms stand.

### LLR-122.3 — the MAC parser
- **Traceability:** HLR-122
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** the MAC parser shall read `TAG=hexaddr` lines with collect-don't-abort diagnostics (malformed lines kept and flagged — the MAC View's per-row status vocabulary rides §37). Pinned by TC-627 (tests/test_tui_mac.py), TC-628 (tests/test_validation_mac.py).
- **Validation:** `test (unit)`
- **Executed verification:** the two modules green, tokens carried.
- **Numeric pass threshold:** 0 failures; TC-627/628 LIVE with nodes.
- **Negative control:** the adoption greppable law.
- **Boundary catalog:** the malformed-line arms stand.

### LLR-122.4 — the CRC engines
- **Traceability:** HLR-122
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** the CRC family shall compute the parameterized Rocksoft kernel (width 8–64) with its catalogue presets, load/save `*.crc.json` templates with the collect-don't-abort loader, and encode/decode the check word per its store width/endianness. Pinned by TC-629 (tests/test_crc_kernel.py), TC-630 (tests/test_crc_designer_model.py + tests/test_crc_template_loader.py + tests/test_crc_word_codec.py).
- **Validation:** `test (unit)`
- **Executed verification:** the four modules green, tokens carried.
- **Numeric pass threshold:** 0 failures; TC-629/630 LIVE with nodes.
- **Negative control:** the adoption greppable law.
- **Boundary catalog:** the kernel's width/pad arms stand.

### LLR-122.5 — the TUI host-surface behaviors the strata left prose-only
- **Traceability:** HLR-122
- **Ledger:** LED-2026-10-08-batch-91.1
- **Statement:** the unpinned host-surface modules shall carry their contract: unload (U), undo/redo UX, universal paste, the capped text area, filename markup safety, the hostile map arms, the tui helpers/services seams, the map click chain, the memory-map entropy merge, the patch dual entry, the flow execution and multi-image UI arms, the N8 legend and logwidth scope, the report logging/progress/off-thread behaviors, the workspace variants, the evidence packs and sync-evidence tooling, the pilot GIFs example. Pinned by TC-631 (test_unload_feature.py), TC-632 (test_undo_redo_ux.py), TC-633 (test_universal_paste.py), TC-634 (test_capped_text_area.py), TC-635 (test_discoverability.py), TC-636 (test_filename_markup_safety.py), TC-637 (test_tui_hostile_map.py), TC-638 (test_tui_helpers.py + test_tui_services.py), TC-639 (test_map_click_chain.py), TC-640 (test_memmap_entropy_merge.py), TC-641 (test_patch_dual_entry.py), TC-642 (test_flow_execution.py + test_flow_multi_image_ui.py), TC-643 (test_legend_n8.py + test_legend_scope_and_logwidth.py), TC-644 (test_report_logging.py + test_report_progress.py + test_report_off_ui_thread.py), TC-645 (test_workspace_variants.py), TC-646 (test_tui_evidence_packs.py + test_examples_pilot_gifs.py), TC-647 (test_sync_evidence.py), TC-648 (test_cli.py).
- **Validation:** `test (unit)`
- **Executed verification:** the modules green, tokens carried.
- **Numeric pass threshold:** 0 failures; TC-631..648 LIVE with nodes.
- **Negative control:** the adoption greppable law.
- **Boundary catalog:** each module's own boundary arms stand.

### HLR-123 — The docs describe the shipped app
- **Traceability:** US-103
- **Ledger:** LED-2026-10-08-batch-91.2 · LED-2026-10-08-batch-91.4
- **Statement:** README.md shall stop promising the removed CDFX export (the shipped replacement is the v2 change-set JSON + patched S19/HEX image emit) and shall document the shipped surfaces it omits today (the variants system, the Flow Builder, the CRC Designer, the Operations modal, the undocumented global keys — U/r/o/v/j/t/b, the paging keys, Ctrl+Z/Y); `docs/overview.md` and `docs/architecture.md` shall stop describing the batch-02..04 state (8 screens, the A↔B Diff placeholder, the `s19tool` script) and read the current 10-screen app; `docs/crc-algorithm-designer/01-requirements.md` shall be marked as the designer's design record (it is a draft dated before the designer shipped).
- **Rationale (informative):** the survey measured the drift: README:91/222 promise a deleted package; the docs describe a superseded app.
- **Validation:** `inspection` + `test`
- **Executed verification:** the docs' key tables against the shipped keymap (grep-driven); `python -m pytest tests -q` stays green.
- **Numeric pass threshold:** every key the README tables name exists in the keymap; no docs line names the removed CDFX package or the `s19tool` console script as live.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** a new reader learns the shipped app, not a superseded one.
  - **Shipped surface:** README.md, docs/overview.md, docs/architecture.md, the CRC designer doc's header.
  - **Acceptance test(s):** none minted — the outcome was verified by executed inspection at the increment (`increment-002.md` §4: the emitted-form greps with their positive control). The reservation for the docs-canon guard is held RESERVED (cited, not declared: `AT-285`); the amendment and its reason are LED-2026-10-08-batch-91.4.
  - **Boundary catalog (QC-3):** none new.
  - **Negative control:** the CDFX/`s19tool` mentions must be gone or clearly historic.

### HLR-124 — The registry's hygiene
- **Traceability:** US-104
- **Ledger:** LED-2026-10-08-batch-91.3
- **Statement:** `AT-043` (declared in REQUIREMENTS.md, absent from the registry) shall resolve — registered LIVE with its verifier node, or RETIRED with its reason, per the registry's grammar; the 44 LIVE ids whose verifiers are token-invisible shall be renamed to carry their tokens (the registry's nodes are already verified; the rename is orthographic, assertions untouched); the reserved block for this batch's new ids (AT-284..287, TC-617..650) lands at P0 as RESERVED entries.
- **Rationale (informative):** the survey: 44 LIVE ids verified-but-invisible to the token grep; one declared-but-unregistered id.
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/test_id_registry.py -q` + the token grep.
- **Numeric pass threshold:** the guard green; the 44 renames carry their tokens; AT-043 resolved one way.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** every LIVE id greps to its verifier; AT-043 is one thing in the registry.
  - **Shipped surface:** the registry, the renamed test functions.
  - **Acceptance test(s):** AT-286.
  - **Boundary catalog (QC-3):** none new.
  - **Negative control:** a rename that loses its assertion — the suite reddens.

### LLR-124.1 — AT-043 resolves
- **Traceability:** HLR-124
- **Ledger:** LED-2026-10-08-batch-91.4
- **Statement:** `AT-043` — declared in REQUIREMENTS.md (the batch-29 US-043 update) and verified by `tests/test_tui_a2l_issue_recolor.py` — shall be exactly one thing in the registry: a LIVE entry in its declared spelling, its verifier node derived with `tools/id_registry.py`'s `derive_named_nodes` (the seed had written the id as `AT-43`, the same normalized key; the resolution re-spells it, never duplicates it). RETIRED with a real reason was the alternative the grammar admits, and the declaration describes shipped behavior the verifier pins, so LIVE is the resolution.
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/test_id_registry.py tests/test_batch91_registry_hygiene.py -q` (arm (b)).
- **Numeric pass threshold:** exactly one `AT-043` entry; its status is grammar-valid; its node exists on disk.
- **Negative control:** arm (b) reddens when the entry is dropped (executed — M2, `inc003_counterfactuals.txt`).

### LLR-124.2 — the token-invisible LIVE ids carry their tokens
- **Traceability:** HLR-124
- **Ledger:** LED-2026-10-08-batch-91.4
- **Statement:** every LIVE registry id whose dash-form token did not occur — token-exact, per the library's maximal-munch `TOKEN_RE`, in any file its `nodes` name — shall carry its token in a verifier docstring or comment (never a function rename; the registry reads content tokens and a rename risks a stale node). The population is derived, not hand-copied: 44 ids (the substring reading stops at 42, the per-file variant at 48 — the token reading reproduces the survey's figure), enumerated in `evidence/inc003_adoption_list.md`.
- **Validation:** `test`
- **Executed verification:** arm (a) of AT-286 + the post-increment re-derivation (`inc003_invisible_after.txt`: 0 residual).
- **Numeric pass threshold:** 0 token-invisible LIVE ids; the registry entries themselves untouched (their nodes were already verified — premise P-2).
- **Negative control:** arm (a) reddens when a token is stripped from the stream (executed — M1, `inc003_counterfactuals.txt`).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:** `<one fenced FLOW block per information flow: SOURCE, NODES (each node with exactly one owner, an LLR above — split a node two LLRs own), SINK>`
- **Part B — boundary decomposition:** `<yes — one fenced COMPONENT block per component | no — and why no component of the boundary is addressable on its own>`

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

### 5.2 Batch acceptance criteria
- every adopted module carries its TC token and stays green; the registry's LIVE entries for the batch's ids carry nodes; AT-043 resolved.
- full suite: 0 failures vs the base run's count (the base run's number is the P0 measurement).
- the docs name the shipped app; no doc names a removed package or script as live.

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
### 6.3 Open risks
### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-08-batch-91

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
