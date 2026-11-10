# Inc 2b E3 re-review brief

Base: branch `batch-103`, commit `4828e4ce`. Inc 2a, 3a, 11 and 12 are merged. Inc 2b has 19 requirements, 109 cases and 11 graph nodes already designed. Do not restart E1/E2 and do not implement code.

Read selectively:
- `01-requirements.md:190-218,243-345` (encode rows, AT and split).
- `02-test-cases.md:170-244,284-305,345-390` (2b and mixed cases).
- `codewire/graph-inc2.md:302-314,611-752` (span index and encode graph).
- `E3-rulings.md:138-167` (all open 2b findings and split ruling).
- `E3-security.md:200-272` (round 5, especially E3S-36 through E3S-44 and their fixes).
- `E1-rulings.md:101-136` (I-2) and `E1-slice.md:87-116`.
- `../inc-11/04-validation.md` and the current `../../../s19_app/tui/a2l.py` reader implementation as needed.
- Current `../../../s19_app/tui/a2l_definition.py`: Definition at 113-153, describe at 521-839, scalar decode at 2545-2647 and 2912-3121. It now also contains Inc 3a; no encode exists.

Authority: the requirements are the contract, not the old implementation. Resolve every E3S-36…44 as closed-by-Inc-11 / accept-fix / reject-with-evidence / superseded. Check the fixed reader premise against current code and existing Inc 11 evidence; citing a document alone is not an executed probe. Do not run pytest or probes on Windows. Read-only review except your assigned report. Do not edit requirements, cases, graph, source, tests, steps.log, or another reviewer's files. Do not run git mutations.

Pay particular attention to:
- span-index safety for hostile lengths, declared addresses including 0x0, INSTANCE/BLOB and `/include` (E3S-37 option a vs b), AXIS_PTS ownership, and current Inc 3a interactions;
- mask exemption correctness by actual selected bytes and byte order; a mask counts only from a definition with no refusal;
- exact encode order, text-kind overlap, precision and limit checks, immutability, fail-closed behaviour and message caps;
- every requirement needs concrete cases, a numeric threshold and a discriminating negative control. Identify vacuous or stale cases after Inc 11 and Inc 3a.

Return a report with verdict PASS / PASS-WITH-NOTES / FAIL; findings tagged design-gap or impl, severity, exact requirement/graph/case references, a concrete correction for each, and explicit disposition of E3S-36…44. MAJOR/HIGH blocks E4. State what was executed versus only read. Keep the report concise and do not paste large file contents.
