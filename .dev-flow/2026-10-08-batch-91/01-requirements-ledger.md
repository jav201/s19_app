# Requirements ledger — s19_app — Batch 2026-10-08-batch-91

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
### LED-2026-10-08-batch-91.1 — the foundation contract (P1)
- **Requirement:** HLR-122, LLR-122.1, LLR-122.2, LLR-122.3, LLR-122.4, LLR-122.5
- **Date:** 2026-10-08
- **What changed:** new requirements: the parsing engines (S19/HEX, A2L, MAC, CRC) and the prose-only TUI host-surface modules carry real TC ids, each ADOPTING the existing unpinned test module(s) that already pin the behavior (adoption, never re-implementation; a docstring token per module, the registry LIVE entries with nodes). The reserved block AT-284..287 + TC-617..650 was written at P0.
- **Why:** the operator's commission 2026-10-08 (the foundation was built while dev-flow was in development).
- **Evidence:** the coverage survey (the 41 unpinned modules with counts; 893/893 LIVE nodes verified) · the P0 suite collection (2760 tests after the tests/__init__.py repair — 22 collection errors from a stray editable .pth before it).

### LED-2026-10-08-batch-91.2 — the docs describe the shipped app (P1)
- **Requirement:** HLR-123
- **Date:** 2026-10-08
- **What changed:** new requirement: README.md, docs/overview.md, docs/architecture.md catch up to the shipped app (no CDFX promise, the variants system, the Flow Builder, the CRC Designer, the Operations modal, the undocumented global keys, the 10 screens); docs/crc-algorithm-designer/01-requirements.md marked as the design record.
- **Why:** the survey measured the drift (README:91/222 promise a deleted package; docs describe the batch-02..04 state).
- **Evidence:** the inventory survey's doc-drift section.

### LED-2026-10-08-batch-91.3 — the registry's hygiene (P1)
- **Requirement:** HLR-124
- **Date:** 2026-10-08
- **What changed:** new requirements: AT-043 resolves (registered LIVE with its verifier node, or RETIRED with its reason, per the registry's grammar); the 44 LIVE ids whose verifiers are token-invisible get renamed to carry their tokens (orthographic only — the registry's nodes are already verified).
- **Why:** the survey's registry findings (the 44 token-invisible; the one cross-artifact inconsistency).
- **Evidence:** the coverage survey's gap lists (a)/(b).

### LED-2026-10-08-batch-91.4 — close-out amendments: the LLR-124 pair declared, HLR-123's acceptance re-planned (P5)
- **Requirement:** LLR-124.1, LLR-124.2, HLR-123
- **Date:** 2026-10-11
- **What changed:** two repairs found by the close-out record, both in the live contract. (1) **The LLR-124 pair is declared.** The increments' briefs and packets trace to LLR-124.1/LLR-124.2, but the gated contract had written both limbs only inside HLR-124's statement — a trace to an id no block declares is a claim, not a trace (the close gate said so). The two LLR blocks are now written, with the same content HLR-124 already stated, and with their executed negative controls named. (2) **HLR-123's acceptance is re-planned from harness to executed inspection.** The P1 contract named a minted acceptance id for the docs catch-up; increment 002 shipped the documents and verified them by inspection (the emitted-form greps, with their positive control), and no harness was minted — so the field now says so, the reservation stays RESERVED and is cited rather than declared (a declared acceptance id with no node is the vacancy the guard exists to forbid), and minting that harness or retiring the reservation is carried to the backlog at close. Also folded: LLR-122.5's statement gained its `shall` — it read as descriptive prose where every sibling block is normative, and the gate's phantom check reads exactly that line.
- **Why:** the close-out's validator pass found the two defects (the phantom traces; the declared-but-nodeless acceptance id); the `shall` fold is the same pass's catch on LLR-122.5.
- **Evidence:** the validator's V59/V22 findings over the batch's own packets before this entry; `increment-002.md` §4 (the inspection evidence); `inc003_counterfactuals.txt` (the executed negative controls the new LLR blocks name).
