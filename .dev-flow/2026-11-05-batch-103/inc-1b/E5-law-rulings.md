# E5 — disposición de leyes y fallos heredados

Base del entregable: `305e5892` más el working tree E5. Las ejecuciones se hicieron en un clon construido desde esa rama y `origin/main` locales, con el diff y los untracked del worktree. El clon anterior `pre-ci2` contenía módulos ajenos y no se usa como veredicto del entregable.

## Resultados comprobados

- Seis familias, clon exacto: **160 passed, 96 skipped en 1480.54 s**, exit 0. Evidencia: `evidence-e5/full-six-families-final.txt`.
- Selección final E5, incluidos outer 14/14, censo AST del escáner y B97: **246 passed, 2 skipped en 143.84 s**. Evidencia redactada: `evidence-e5/final-targeted.txt` y `final-targeted-junit.xml`.
- Comparación de los seis fallos de leyes:
  - `e2e93548` (base previa a E4): **5 failed, 1 passed**; B97 pasó.
  - `305e5892`: **6 failed**; B97 falló.
  - Recheck del árbol corregido: **5 failed, 1 passed**; B97 volvió a pasar.

## Regresión Inc 1b corregida

`tests/test_b97_key_bar.py::test_tc_b97_72_clicks_run_the_action_and_type_nothing` esperaba la acción antigua `quit` al hacer clic en `q Quit`. La base E4 cambió el binding aprobado de `q` a `help_quit` (R-COPY.23); `KeyBar.run_token()` ejecuta precisamente la acción del binding. El test se actualizó para exigir una llamada a `action_help_quit`, cero a `action_quit`, input vacío y ninguna conversión del clic en `simulate_key`. No se cambió el comportamiento de producto ni la distinción R-COPY.24 para Ctrl+Q/palette Quit.

## Cinco fallos heredados, no regresiones E5

Los mismos cinco nodos fallan en `e2e93548`, en `305e5892` y en el recheck E5; no se modifican en este incremento:

- `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`;
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once`;
- `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors`;
- `test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach`;
- `test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go`.

La disposición se basa en ejecución real de la misma selección sobre la base, no en una lista de «flaky» ni en una inferencia por proximidad. Los transcript de comparación están en el runner remoto y se conservarán redactados con la evidencia final.

## Redacción Inc 1b

El fallo heredado de redacción se conserva; no se alteran registros E3/E4 para ocultarlo. El recheck fue inspeccionado específicamente para `inc-1b/E5*` e `inc-1b/evidence-e5/**`: **0 hits nuevos**. El redactor E5 informa `residual=0` fuera de ocho excepciones declaradas en controles ejecutables y los seis manifests verifican los bytes almacenados. La corrida completa final de leyes queda registrada por separado; este documento no la anticipa.

WinCI, los mutantes de producto y AT-I1b-8 no se declaran ejecutados por este ruling.
