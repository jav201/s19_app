# Inc 2 — orchestrator rulings on the E2 graph (2026-11-06T18:03:39-06:00, Opus 5.5)

| Item | Ruling | Consequence |
|---|---|---|
| P-1 `Definition.bit_mask_text` | **accepted** | I-2 gains the field (after `bit_mask`); R-A2L-DEF.47's `<mask>` is the file's text. |
| E2-1 (header words fill the tag) | **accepted** | The model reads the MEASUREMENT/CHARACTERISTIC header itself when the tag lacks the fields; R-A2L-014 becomes a cited row; BL-I2-17 (the tag table drops commented header lines) joins the batch backlog. |
| E2-4 … E2-8 (cases that cannot pass on a correct model) | **accepted** | `02-test-cases.md` takes the graph's corrected inputs (correction pass, records only). |
| E2-10 … E2-14 | **to E3** | E3 rules: describe cost for Inc 6 (E2-10), non-numeric BIT_MASK word (E2-12), `<kind>` text with no header kind (E2-13), slice deviations (E2-14), the mask-merge reading (E2-11). |
| Inc 3 D-1 (I-2 extension) | **pinned** | `decode_values` / `encode_values` (one span, the whole record), `element_name`, new `Definition` fields with defaults. Inc 2's graph keeps every field it defines; Inc 3 only adds. |
