# 02 — Phase-2 cross-agent review · batch-n8 (comprehensive per-view Legend)

**BLUF:** No design blocker; the spec is structurally sound. ONE testability BLOCKER
(qa B-1, empirically verified) on the load-bearing fold-in AT + 4 architect majors,
all resolved by folding the §6.5 amendments (AMD-2 corrected → AMD-5..12) into the
executable predicate with a "§6.5 overrides §3/§4" precedence line. Security: OK to
ship, 0 HIGH/MEDIUM. Gate: `iterate-to-refine` on B-1 applied inline; ready for Phase 3.

## Reviewers + verdicts
- **architect** (a62c): no hard blocker; 4 MAJOR, 5 minor. Theme: §6.5 amendments documented but NOT folded into executable HLR/LLR/AT bodies → vacuous ATs if implemented literally.
- **qa** (ae22): 1 BLOCKER (B-1), 0 major, 4 minor. Empirically probed Textual 8.2.8.
- **security** (a84d): OK to ship. 0 HIGH/MEDIUM. 1 LOW (F3 markup-guard). All card content static author literals; no untrusted-file data path (markup-safety-for-file-data LLR does NOT apply).

## Findings → resolutions (all folded into §6.5)
| # | Sev | Finding | Resolution |
|---|-----|---------|-----------|
| B-1 | BLOCKER | AT-N8-06 vacuous: `Label{width:auto}`=139×1, `render_line` reads widget buffer not compositor clip → tail present on BOTH Label & Static (AMD-2 premise empirically false) | **AMD-5**: pass = `type(row) is Static AND size.height >= 2` (wrap occurred); tail = secondary. Counterfactual restored (Label h=1 RED, Static h=2 GREEN). |
| MAJOR-1 | major | AMD-2 painted-method not in HLR-N8-6/LLR-N8-6.1/LLR-N8-4.3 bodies | subsumed by AMD-5 + precedence line |
| MAJOR-2 | major | AMD-3 Map Hex overlays not in LLR-N8-3.1/AT-N8-03 | **AMD-6**: map card threshold 4/4→6/6 incl. both overlay meanings |
| MAJOR-3 | major | MAC sample colour `#d9a35b` ≠ `MAC_ADDRESS_OVERLAY_STYLE` (=`bold orange3`); real warning row paints `orange3` | **AMD-7**: paint sample `orange3`, couple AT-N8-07 to the real inline WARNING style, not a hex |
| MAJOR-4 | major | C-31 live A2L-column oracle lost (6 hand substrings) | **AMD-8**: derive from live `#a2l_tags_list.columns`, guard len>=16 |
| F3 | LOW | N8 introduces markup into legend lines; unescaped `[` → MarkupError crash, no tripwire | **AMD-9**: NEW TC-N8-11 markup round-trip guard over every LEGEND_EXAMPLES line |
| m-1/M-7 | minor | cutoff `8.000001`→`8` format seam / hand-list | **AMD-10a**: single format helper from ENTROPY_BANDS |
| m-3 | minor | workspace glyphs hand-listed | **AMD-10b**: derive from `band_style` |
| m-2 | minor | orange read needs stable hook | **AMD-11**: id `#legend_mac_warning_sample` |
| M-5 | minor | entropy path missing `services/` | **AMD-12a** |
| M-8 | minor | `may` inside LLR statement | **AMD-12b**: move to acceptance line |
| M-9 | minor | AMD-4 lacks N1 test file:line | **AMD-12c** |
| M-6 | minor | TC crosswalk incomplete | **AMD-12d** |

## Confirmed SOUND (no action)
- Per-story ATs drive the shipped modal + assert content (presence use of `.plain`/`render_line` is fine — F-1 only bites truncation).
- C-10 differential riders present (AMD-1 fold of qa AT-156); AT-N8-07 asserts BOTH pale-yellow word + orange sample.
- C-31 sets derived/guarded (columns, bands, meanings, code families).
- Boundary + negative evidence per HLR; no unobservable outcome.
- No frozen-engine edit, no external-write/output surface, no secrets, no new dependency (security F4).

## Axis check (gate)
- **Coverage** OK — dual traceability complete; every US→AT, LLR→TC.
- **Certainty** — was UNMET (B-1 vacuous counterfactual); RESTORED by AMD-5 (height/type discriminator, empirically verified).
- **Evidence** OK — all citations file:line; qa's empirical probe recorded.

## Gate recommendation
`iterate-to-refine` on B-1 applied inline (AMD-5); majors+minors+F3 folded (AMD-6..12). No residual blocker/major. Ready to advance to Phase 3 on operator approval.
