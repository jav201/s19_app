# Inc 9b — E1 orchestrator rulings (Q1–Q10)

Ruled on `E1-rulings-proposed.md`. Rule: prefer removing a feature over guarding it, keep 3 source files, and never change an operator verdict without the operator.

| Id | Ruling | Effect on the draft |
|---|---|---|
| Q1 (CR9-1) | **Accept: do not record** a source found only through the fallback (LLR-172.1n). | as drafted |
| Q2 | **Accept: keep** preview problems with the worker, the stale discard and the 150 ms rest timer. Removing them would change the operator's approved UX-36 / `pa_C` verdict, which only the operator can change. | as drafted |
| Q3 | **Accept: keep the entry**, and paint `not found` / `check the path`. | as drafted |
| Q4 | **Accept**: the row shows file name + kind, and the preview shows the full path. | as drafted |
| Q5 | **Accept** both store-problem token pairs. No per-user path is painted. | as drafted |
| Q6 | **Accept for the Load dialog** (LLR-173.2e). The Save-dialog exposure goes to the backlog for Inc 11. | as drafted; backlog row at close |
| Q7 | **Accept**: the §1.3 content test lives in `list_projects` (LLR-173.4a). E2 owes the reverse census of tests that list an empty folder. | as drafted |
| Q8 | **Defer to Inc 12a**: the binding labels "Load" / "Projects" and the 35 snapshot rebaselines. Snapshot regeneration needs the CI-matching environment, and the operator asked to finish as soon as possible. **Remove LLR-173.2m** from 9b. | LLR-173.2m removed; the §5.4 census row moves to Inc 12a |
| Q9 | **Accept: delete both screens**; the new class is `LoadDialog`. The re-pins are mechanical. | as drafted |
| Q10 | **Accept `OptionList`.** | as drafted |

Seams S-a … S-g: fixed in `codewire/interfaces-9b.md`.
