# Requirements ledger — s19_app — Batch 2026-10-19-batch-97

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-19-batch-97.1 — Phase-1 derivation of HLR-144..HLR-149 and their LLRs
- **Requirement:** HLR-144, HLR-145, HLR-146, HLR-147, HLR-148, HLR-149, LLR-144.1, LLR-144.2, LLR-144.3, LLR-144.4, LLR-144.5, LLR-144.6, LLR-144.7, LLR-145.1, LLR-145.2, LLR-145.3, LLR-145.4, LLR-145.5, LLR-146.1, LLR-146.2, LLR-146.3, LLR-146.4, LLR-146.5, LLR-146.6, LLR-146.7, LLR-146.8, LLR-147.1, LLR-147.2, LLR-147.3, LLR-147.4, LLR-147.5, LLR-147.6, LLR-148.1, LLR-148.2, LLR-148.3, LLR-148.4, LLR-148.5, LLR-148.6, LLR-148.7, LLR-149.1, LLR-149.2, LLR-149.3, LLR-149.4, LLR-149.5
- **Date:** 2026-10-20
- **What changed:** the live contract gained its first requirement set: six HLRs (HLR-144..HLR-149, one per READY story US-134..US-139), 38 LLRs, 16 acceptance tests (AT-B97-01..16), 38 white-box tests (TC-B97-01..38), the IFC (10 flows, 5 components), the §2.7 premise table (26 rows, all TRUE) and the declared-empty §2.8.
- **Why:** the operator commissioned the port of the prototype round `prototypes/b94_polish/` with the verdict **A on all four screens** ("Sí, cambié de opinión"; "Me gustan bastante"), the binding JSON condition on the Patch Editor (consultable document, live or explicit update, Load keeps populating), the round-2 answers (Run as the second bright element; CRC burnt orange, amber only for the waiting state; variable terminal size, 118x54 minimum and ≈220x60 reference, no wrapped rows; folder chips on every screen "sobre todo para usuarios nuevos"), as written in `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md` §1 and §3, and the ARQ declarations in `docs/architecture.md` (batch-97 section). Three brief claims were corrected against the code before they became requirements: E-1's column doubling is a prototype artefact (§2.7 P-7), the palette gap is 4 of 7 kinds, not 3 of 6 (P-13), and no demo flow holds a CRC block, so the CRC-beside-paused capture needs a new fixture (P-16).
- **Evidence:** §2.7 rows P-1..P-26 (executed 2026-10-20 on `9c7beaf`): the id census of the four panels, the `probe_b97.py` / `probe_overflow.py` runs of the real tree through the harness scenarios at 118x54 and 220x60, the serialiser run over `calib_hotfix.json` (706 bytes, 6 entries), the writer censuses of `ChangeService.document` and `record.outcomes`, the AST census of Spanish strings (34), the help-coverage probe (6/19 · 0/6 · 2/13 · 0/4), and the hue computation for the CRC token (42.2° from the shipped waiting colour).
