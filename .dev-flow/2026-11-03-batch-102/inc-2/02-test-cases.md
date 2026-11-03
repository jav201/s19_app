# E1 test cases — Inc 2 — A2L load/reload refresh

| TC | Objective | Class | Preconditions | Inputs | Expected result | Covers | Mutant control | Status |
|---|---|---|---|---|---|---|---|---|
| TC-B102-A2L-01 | Verify that a successful direct A2L attach refreshes enriched and filtered rows before the success outcome. | normal | No A2L attached; fixture A has tags `Alpha` and `Beta`. | Attach fixture A. | Summary count is `2`; the table renders both names; the status/outcome says A2L loaded; no manual refresh is sent. | R-B102-A2L-001, full | Remove the install's `update_a2l_view()` call. | not_run |
| TC-B102-A2L-02 | Verify that loading/reloading a primary image refreshes A2L memory state automatically. | normal | Fixture A and S19 image are loaded. | Load a different image whose memory contains/drops one mapped address. | The corresponding A2L row's in-memory display/severity changes on the final painted table. | R-B102-A2L-002, full | Make `_apply_prepared_load` skip `_step_a2l`. | not_run |
| TC-B102-A2L-03 | Verify that an active filter is applied to a newly attached A2L. | normal | Filter input already contains `Alpha`; fixture B contains `Alpha` and `Gamma`. | Attach fixture B. | Only `Alpha` is visible; summary reports 1 matching tag. | R-B102-A2L-003, full | Ignore the filter after attach. | not_run |
| TC-B102-A2L-04 | Verify that an active filter with no matches names the filter instead of showing a generic empty A2L message. | normal | Filter input contains `Missing`; fixture B contains `Alpha` and `Gamma`. | Attach fixture B. | Summary is exactly `No A2L tags match 'Missing'.`; zero tag rows are painted. | R-B102-A2L-003, full | Paint `No A2L tags.` | not_run |
| TC-B102-A2L-05 | Verify that equal cache-key shape cannot return stale enrichment. | robustness | A stale enriched list is installed; the new payload is different but `id(new_payload)` and memory size equal the old key. | Attach/call the view refresh path with the colliding payload. | New tags are computed and rendered; the stale list is not returned. | R-B102-A2L-001/.004, full | Restore the `(id(payload), mem_size)` key. | not_run |
| TC-B102-A2L-06 | Verify the no-A2L state after clear/unload. | robustness | Fixture A was attached and visible. | Clear/unload A2L. | Summary is `No A2L loaded.`; the tag table has zero rows; stale row-key mapping is empty. | R-B102-A2L-005, full | Keep the previous rows after clear. | not_run |

## Notas de ejecución

- RED en base: TC-B102-A2L-05 está diseñado para fallar con la clave `id()` actual cuando se fuerza la colisión; los demás deben ejecutarse y registrar cualquier fallo real adicional.
- GREEN: repetir en el worktree del incremento con el mismo fixture y tamaño de terminal.
