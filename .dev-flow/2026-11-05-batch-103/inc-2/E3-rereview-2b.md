# Inc 2b E3 narrow re-review

Read the final `E3-rulings.md` section "Inc 2b re-review against the fixed reader" and its "Inc 2b correction completion addendum". Review the corrected `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc2.md`, `E1-rulings.md` and `E1-slice.md`. Also read your previous `E3-architect-2b.md` or `E3-security-2b.md` and the executed premise transcripts `evidence-e3/e3-2b-reader-premise-transcript.txt` and `e3-2b-residual-premise-transcript.txt`.

Scope: only the former blockers and changed rows/cases/nodes. Confirm E3S-36 through E3S-44 dispositions, the completed BLOB/INSTANCE and unknown-length index, cross-kind file order, CLEAN mask semantics without a whole-file second describe, the two live residual .19 guards, R-A2L-DEF.152 and its reachable fixtures, exact expected values, text-kind overlap, the 256-character operator echo that preserves spaces and Unicode, current Inc 3a fields, and active counts (73 requirements; 318 cases = 216 + 102).

Check for vacuous new cases and conflicts between PARSE, definition refusals and OVERLAP. `.138/13` deliberately checks PARSE on the original payload and OVERLAP on a copy with errors cleared. AT-B103-I2-1 applies only UNKNOWN. AXIS_PTS stays Inc 3b before Inc 8/9.

Read-only except your assigned report. Do not edit any artifact, source or test; no git mutations, no pytest or probes on Windows. Return PASS / PASS-WITH-NOTES / FAIL, findings tagged design-gap or impl with severity and exact references, and explicit closure of the former blockers. MAJOR/HIGH blocks E4. State what was read versus executed.
