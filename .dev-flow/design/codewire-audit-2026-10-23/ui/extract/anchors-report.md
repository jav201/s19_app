# Anchor check of the UI threads (C16 analogue)

| Status | Source | Missing anchors / count | Line |
|---|---|---|---|
| ok | U1.1 | 3 anchors | examples: (U1.1) `Load` with the probe path ext\firmware.s19 → screen `Screen` (dialog clo |
| ok | U1.6 | 3 anchors | examples: (U1.6) `Load` with an empty input → dialog still `LoadFileScreen`; no log line,  |
| ok | U6.3 | 2 anchors | examples: (U6.3) `escape` on the dialog → still `LoadFileScreen` |
| ok | U1.7 | 1 anchors | examples: (U1.7) missing path → "File not found: …\nope.s19" |
| ok | U1.8 | 1 anchors | examples: (U1.8) a folder path → "Unsupported file type: " (empty suffix; the line does no |
| ok | U1.1 | 3 anchors | examples: (U1.1) probe path ext\firmware.s19 (case_01) → temp [`firmware.s19`]; log "Copyi |
| ok | U1.3 | 3 anchors | examples: (U1.3) the same source path with case_02 bytes → temp [`firmware.s19`, `firmware |
| ok | U1.5 | 3 anchors | examples: (U1.5) the work copy temp\firmware_1.s19 itself → temp still [`firmware.s19`, `f |
| ok | U1.2 | 2 anchors | examples: (U1.2) same bytes again → copied `firmware.s19` (reused); temp has `1` file |
| ok | U1.4 | 3 anchors | examples: (U1.4) source back to the case_01 bytes → copied `firmware.s19` (reused); temp s |
| ok | U1.1 | 3 anchors | examples: (U1.1) → file status "Loaded firmware.s19 (S19 only)"; the log gets "Loaded firm |
| ok | U3.9 | 5 anchors | examples: (U3.9) a load over an image with an applied, unsaved patch (`0B 16 BE EF` at `0x |
| ok | U2.7 | 1 anchors | examples: (U2.7) project P2 over P1 → file status "Loaded prg.s19 (S19+MAC: firmware.mac)" |
| ok | U1.1 | 2 anchors | examples: (U1.1) after the load → list `[]`; temp holds `firmware.s19` |
| ok | U1.9 | 4 anchors | examples: (U1.9) after 5 loads → list `[]`; work-area root files `[]`, dirs [`patches`, `t |
| skip | U1.9, inferred | inferred | examples: (U1.9, inferred) no row exists to select, so the node never runs; its name looku |
| ok | U6.2 | 2 anchors | examples: (U6.2) after a load on the Workspace → focused `_SegTable sje_table`; window hid |
| ok | U6.1, U6.2 | 7 anchors | examples: (U6.1, U6.2) then `p` → screen stays `Screen` (no Load project dialog); `a` → lo |
| ok | U5.4 | 1 anchors | examples: (U5.4) on the Check Editor after a load → focused `_SegTable sje_table` |
| ok | U2.1 | 2 anchors | examples: (U2.1) name "P1" → payload; log "Saved project to …\P1 (variant 'firmware')" |
| ok | U2.8 | 1 anchors | examples: (U2.8) empty name → still `SaveProjectScreen`; nothing recorded |
| ok | U2.1 | 2 anchors | examples: (U2.1) → "Project saved + manifest verified"; the painted file status still read |
| ok | U2.4 | 3 anchors | examples: (U2.4) listed projects [`P1`, `P2`, `patches`] |
| ok | U2.4 | 4 anchors | examples: (U2.4) `P1` highlighted, `Load` clicked → dismiss value `Label()`; log "Project  |
| ok | U2.5 | 2 anchors | examples: (U2.5) `P1` highlighted, `enter` on the list → dismiss value none; the dialog st |
| ok | U6.3 | 2 anchors | examples: (U6.3) `escape` → still `LoadProjectScreen` |
| ok | U2.6 | 3 anchors | examples: (U2.6) direct call with "P1" (the dialog cannot send it) → "Loaded project 'P1'  |
| ok | U2.7 | 3 anchors | examples: (U2.7) "P2" over P1 → "Loaded project 'P2' -> prg.s19"; context "P2  \|  firmware |
| ok | U2.2 | 3 anchors | examples: (U2.2) `U` → "Unloaded all artifacts."; no question; the project stays: context  |
| ok | U2.3 | 4 anchors | examples: (U2.3) after `U`, a loose load of `prg.s19` → "Added variant 'prg' to project 'P |
| ok | U3.2 | 4 anchors | examples: (U3.2) Apply → "Apply: 1 applied, 0 skipped, 0 blocked"; image `DE AD BE EF` at  |
| ok | U3.6 | 2 anchors | examples: (U3.6) an entry at `0x80000080` → "Apply: 0 applied, 1 skipped, 0 blocked"; the  |
| ok | U5.7 | 3 anchors | examples: (U5.7) "11 22" → [`0B`, `16`] |
| ok | U5.7 | 4 anchors | examples: (U5.7) "10 1A 08" → [`0A`, `1A`, `08`]: three bases rules in one run |
| ok | U3.9 | 1 anchors | examples: (U3.9) probe Bytes field 11 22 → ledger row "0x8000007C \| 0B 16" |
| ok | U5.7 | 2 anchors | examples: (U5.7) paste JSON with bytes 11 22 → entries [(`0x8000007c`, "11 22")] |
| ok | U3.1 | 3 anchors | examples: (U3.1) before the apply → "was    38 39 3A 3B 3C 3D 3E 3F", "now    38 39 3A 3B  |
| ok | U3.2 | 2 anchors | examples: (U3.2) after the apply → "was    38 39 3A 3B DE AD BE EF", "· 0 changed": the ca |
| ok | U3.6 | 3 anchors | examples: (U3.6) an entry outside the image → "2 B @ 0x80000080 · 2 changed" while the led |
| ok | U3.4 | 4 anchors | examples: (U3.4) `ctrl+z` after Apply → table `[]`, card "No entry yet: Add one or Load a  |
| ok | U3.3 | 1 anchors | examples: (U3.3) Decline → "Patch Editor: save-back declined"; the image stays patched; no |
| ok | U3.7 | 3 anchors | examples: (U3.7) Confirm → "Saved + verified: firmware-patched.s19"; an independent read o |
| ok | U4.1 | 5 anchors | examples: (U4.1) lane `outside_chain` → head "▓ outside_chain · done · … · wrote out_outsi |
| ok | U4.1 | 2 anchors | examples: (U4.1) lane `malformed_chain` (its change doc is not JSON) → "▓ malformed_chain  |
| ok | U4.2 | 2 anchors | examples: (U4.2) → "… 3 earlier lines — the full log is in the run report"; the two chain- |
| ok | U4.2 | 2 anchors | examples: (U4.2) Confirm with no evidence files → "flash_chain failed at block 3/4 — log ' |
| ok | U4.3 | 2 anchors | examples: (U4.3) evidence written, then `c` → "c: no lane is waiting for confirmation." |
| ok | U5.1 | 2 anchors | examples: (U5.1) `prg.s19` loaded, no field changed → "Load an image to preview coverage C |
| ok | U5.2 | 4 anchors | examples: (U5.2) range "20000-30000" (no bytes) → "concat: 0x00000000", "fill:   0x0000000 |
| ok | U5.3 | 2 anchors | examples: (U5.3) case_02 loaded over case_01 → the same "0x6EC3F848" as for case_01; a for |
| ok | U5.5 | 3 anchors | examples: (U5.5) a field at `0x8000007C`, size 4 (probe input), after an unsaved Patch Edi |
| ok | U5.4 | 1 anchors | examples: (U5.4) Validate on the clean image → "Checks: 1 passed, 0 failed, 0 uncheckable" |
| ok | U5.5 | 2 anchors | examples: (U5.5) Validate on the patched, unsaved image → "Checks: 1 passed, 0 failed, 0 u |

lines: 53 · ok: 52 · drift: 0 · no_anchor: 0 · inferred: 1
