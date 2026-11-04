# E1 test cases — Inc 6 — Flow block edit/remove

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-FB-01 | Verify edit opens an initialized modal for each block kind. | normal | Flow contains one block of every kind. | Enter each ledger number and activate Edit. | Modal kind/fields match the selected block and carry current values. | R-B102-FB-001, full | Open empty/default modal. | verified |
| TC-B102-FB-02 | Verify save replaces only the selected block. | normal | Three-block flow; edit middle SOURCE ref. | Save modal with `new_image.s19`. | Middle block ref changes; other block objects equal originals; pipeline/ribbon repaint; dirty true. | R-B102-FB-002, full | Replace whole flow or skip dirty. | verified |
| TC-B102-FB-03 | Verify invalid edit is refused and original remains. | robustness | A2B block references downstream flow; edited binding invalid; external-step block missing log. | Save each invalid modal. | Modal paints refusal; original block list unchanged; flow dirty state unchanged by failed edit. | R-B102-FB-003, full | Accept invalid replacement. | verified |
| TC-B102-FB-04 | Verify remove affects only the selected block. | normal | Flow has variables, clipboard and 3 blocks. | Remove first, then middle, then last with confirmation. | Only selected index disappears each time; variables and clipboard remain; dirty true. | R-B102-FB-004, full | Clear variables/clipboard or whole chain. | verified |
| TC-B102-FB-05 | Verify invalid pick handling for edit/remove. | robustness | Flow has 2 blocks. | Try empty, `x`, `9` for both actions. | Exact notice with `1 and 2`; no modal opens and no block is removed. | R-B102-FB-005, full | Invalid input mutates flow. | verified |
| TC-B102-FB-06 | Verify hostile block fields render literally in edit modal and notices. | robustness | Block ref contains markup/control bytes. | Open edit and read painted modal; trigger refusal. | Sentinel remains literal; zero markup spans/control bytes. | R-B102-FB-006, full | Use markup rendering. | verified |

## Notas de ejecución

- RED: todos los TC deben fallar en base por ausencia de acciones Edit/Remove por bloque.
- GREEN: validar contra la rama tras Inc 6.
