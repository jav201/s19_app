# E1 test cases — Inc 4 — bulk add

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-BULK-01 | Verify that the bulk-add control opens the designed modal. | normal | Check Editor mounted with picker. | Activate `#check_param_bulk_button`. | Modal contains a multiline input, exact instruction, include action and close action; focus starts in the text area. | R-B102-BULK-001, full | Open a one-line filter or omit instruction. | not_run |
| TC-B102-BULK-02 | Verify all list separators. | normal | Source parameters `Alpha`, `Beta`, `Gamma`, `Delta`. | Paste `Alpha\nBeta, Gamma; Delta   Alpha`. | Parsed names are `Alpha`, `Beta`, `Gamma`, `Delta`, `Alpha`; no empty token is included. | R-B102-BULK-002, full | Parse only newlines. | not_run |
| TC-B102-BULK-03 | Verify inclusion semantics and duplicate controls. | normal | Existing pick `Alpha`; source also has `Beta`. | Paste `Beta\nBeta\nAlpha\nGamma`. | Picks become `Alpha`,`Beta`; duplicate tokens and pre-existing pick add no duplicates; order preserves existing picks then first new occurrence. | R-B102-BULK-003, full | Replace picks or append duplicates. | not_run |
| TC-B102-BULK-04 | Verify the completion summary with missing names. | normal | Source has `Alpha`; list has `Alpha`, `MissingOne`, `MissingTwo`. | Confirm list. | Summary is `Included 1 · already included 0 · not found 2 — first missing: MissingOne`. | R-B102-BULK-004, full | Omit first-missing detail. | not_run |
| TC-B102-BULK-05 | Verify the empty-list arm and missing-names summary boundary. | robustness | `Alpha` already picked. | Confirm buffer `  \n,;`; then confirm `Nope1 Nope2`. | Empty buffer paints exactly `No listed parameters found.`; missing names paint `Included 0 · already included 0 · not found 2 — first missing: Nope1`; picks unchanged. | R-B102-BULK-005/.004, full | Clear existing picks or suppress missing summary. | not_run |
| TC-B102-BULK-06 | Verify hostile pasted names render literally. | robustness | A source parameter contains markup/control bytes; list references its exact name plus `[red]` missing token. | Confirm list. | Hostile source name is included; `[red]` appears literal in missing detail; zero markup spans/control bytes are rendered. | R-B102-BULK-006, full | Paint summary as markup. | not_run |
| TC-B102-BULK-07 | Verify close/apply does not rebuild the ledger unnecessarily. | normal | 10 000-parameter picker mounted; spy on `_rebuild_ledger`. | Include valid list then close; reopen modal and close without changes. | Picked count/preview update after include; ledger rebuild count does not increase on either close. | R-B102-BULK-007, full | Rebuild ledger on modal close. | not_run |

## Notas de ejecución

- RED: TC-01..05/.07 deben fallar en base por ausencia de modal/bulk; TC-06 puede permanecer verde si los contratos seguros existentes ya cubren el renderer, pero el caso nuevo debe ejercitar el modal.
- GREEN: repetir en rama tras Inc 4.
