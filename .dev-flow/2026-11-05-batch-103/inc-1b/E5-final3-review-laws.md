# E5 — Revisión independiente FINAL3 de leyes, B97 y evidencia final

Base revisada: `305e5892` más el working tree actual. Alcance: `E5-law-rulings.md`, el oráculo B97 y su concordancia con `KeyBar.run_token` y R-COPY.23/24, los cinco fallos heredados restantes, el censo `303 + 4 = 307`, las referencias de `E5-artifact-ruling.md` y los artefactos finales citados por el ruling.

Revisión exclusivamente estática mediante lecturas acotadas, búsquedas y `git diff/status` de sólo lectura. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow, WinCI, mutantes, redactor ni verificadores de manifests. No hice mutaciones Git ni modifiqué producto, tests, workflow, ledger, canon o evidencia. La única escritura es este informe.

## Veredicto

**GO para la disposición técnica de leyes/B97.** El nuevo oráculo B97 exige exactamente `help_quit=1`, `quit=0` e input vacío; concuerda con la acción del binding y con R-COPY.23 sin convertir palette Quit en `help_quit`, por lo que preserva la distinción R-COPY.24. Los otros cinco fallos quedan documentados como heredados y abiertos, no como verdes ni como «flaky», y no encontré arreglos fuera de alcance en sus módulos de ley. El censo 307 y su comentario corregido son coherentes. Las referencias del addendum señaladas por FINAL2 ya son actuales.

**NO-GO para certificar que la evidencia final está redactada e íntegra en su estado actual.** Los dos transcripts finales añadidos después de la última pasada de redacción contienen rutas personales sin redactar y no están cubiertos por el manifest raíz. Por tanto, la frase de `E5-law-rulings.md:32` que combina `0 hits nuevos`, `residual=0` y manifests verificados **no describe los bytes actuales**. Este es un defecto de incorporación de evidencia, no un sexto fallo de leyes ni una regresión de producto/B97.

**NO-GO para un cierre global de E5** mientras WinCI y los mutantes de producto sigan sin ejecutarse y AT-I1b-8 siga manual. El GO limitado de leyes no sustituye ninguno de esos desbloqueos.

## Resultados ejecutados comunicados, no repetidos por esta revisión

Acepto como datos del orquestador los resultados siguientes. Las referencias comprueban que los artefactos citados existen y contienen el tally; no constituyen una ejecución propia ni una validación independiente del proceso del clon.

| Ejecución comunicada | Resultado aceptado | Artefacto local contrastado |
|---|---|---|
| Seis familias en clon exacto | **160 passed / 96 skipped**, exit 0, **1480.54 s** | `evidence-e5/full-six-families-final.txt:14` contiene el tally y `:13` seis bounds reportados; el exit 0 es dato comunicado. |
| Selección final E5, incluidos outer 14/14, censo AST y B97 | **246 passed / 2 skipped**, **143.84 s** | `evidence-e5/final-targeted.txt:7`; `final-targeted-junit.xml` está presente. El launcher incluye TC-607 y B97 (`run_e5_final_targeted.py:25,31`). |
| Recheck de seis nodos de leyes | **5 failed / 1 passed**, B97 verde, **46.41 s** | `evidence-e5/law-recheck.txt:2,785-791`; el launcher enumera los cinco fallos y B97 (`run_e5_law_failures.py:18-23`). |

También acepto, conforme al encargo, que `e2e93548` produjo los mismos **5 failed / 1 passed**, con B97 verde. `E5-law-rulings.md:11` registra además **6 failed** en `305e5892`, con B97 rojo. No localicé bajo `evidence-e5` los transcripts de esas dos bases: no afirmo haber comparado independientemente sus nodeids. El GO de disposición depende del resultado base explícitamente aceptado, no de una inferencia por proximidad ni de una supuesta flakiness.

## 1. B97: oráculo correcto y discrimante

La cadena estática completa es consistente:

1. `S19TuiApp.BINDINGS` contiene `("q", "help_quit", "Quit")` (`s19_app/tui/app.py:3030`). El texto visible sigue siendo `q Quit`.
2. `_token()` copia `binding.action` al `KeyToken` (`s19_app/tui/window_help.py:985-991`) y `global_tokens()` construye los tokens desde los bindings de la app (`:1017-1025`).
3. Para un token sin owner, `KeyBar.run_token()` ejecuta `await self.app.run_action(token.action)`; no llama a `simulate_key` (`s19_app/tui/window_help.py:1250-1257`).
4. B97 instala espías independientes para `action_help_quit` y `action_quit` (`tests/test_b97_key_bar.py:1252-1254`), hace clic en `q Quit` (`:1292`) y recoge el valor del input y ambos contadores (`:1294-1299`).
5. La aserción final es exactamente `("checks", "", 1, 0)` (`tests/test_b97_key_bar.py:1307`): pantalla Checks, **input vacío, una llamada a `action_help_quit` y cero a `action_quit`**. El docstring y la mutación declarada describen la misma distinción (`:1237-1247`).

El diff de B97 frente a HEAD sólo endurece ese oráculo y su documentación: sustituye la antigua tupla que sólo contaba `quit` por la tupla de cuatro valores. No relaja la condición ni permite que el clic se convierta en escritura.

Concordancia con las leyes:

- R-COPY.23 exige que `q` abra una única confirmación y no salga inmediatamente (`01-requirements.md:125`); sus pruebas comportamentales están en `tests/test_b103_copy_quit_dialog.py:812-858`. Contar `help_quit=1` y `quit=0` es el oráculo B97 coherente con ese binding.
- R-COPY.24 mantiene Ctrl+Q y palette Quit en salida inmediata (`01-requirements.md:126`; `tests/test_b103_copy_quit_dialog.py:861-897`). La proyección de palette conserva `PaletteEntry("Quit", "quit")` (`s19_app/tui/app.py:10358-10376`), de modo que el cambio de B97 no propaga `help_quit` a palette Quit.

Conclusión: la corrección cierra la expectativa obsoleta de B97 sin reabrir la separación R-COPY.23/24.

## 2. Cinco fallos restantes: disposición aceptable, siguen abiertos

`law-recheck.txt:786-791` enumera exactamente los cinco nodeids documentados en `E5-law-rulings.md:22-26`:

- `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`;
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once`;
- `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors`;
- `test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach`;
- `test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go`.

La comparación read-only frente a `305e5892` no muestra cambios en `tests/test_suite_hygiene.py`, `tests/test_requirements_canon.py`, `tests/test_address_census.py`, `tests/test_b101_reach_and_reports_escape.py` ni `tools/address_census.py`. Tampoco el ruling propone alterar canon, evidencia histórica E3/E4 o esas leyes para ocultar los fallos.

Aceptada la ejecución equivalente sobre `e2e93548`, la disposición «cinco heredados + regresión B97 corregida» es razonable y no encubre arreglos fuera de alcance. **No significa que esos cinco nodos estén verdes ni resueltos.**

## 3. Censo 307 y comentario 303+4: coherentes

- `EXPECTED_SCANNED_TEST_FILES = 307` está en `tests/test_id_registry.py:214`; el total derivado añade `REQUIREMENTS.md` en `:318`.
- El comentario `:211-213` identifica cuatro módulos nuevos: `tests/test_b103_e5_safety.py`, `tests/test_b103_winci_gate.py`, `tests/support/b103_winci_gate.py` y `tests/support/b103_artifact_safety.py`.
- El diff de nombres frente a `305e5892` muestra exactamente esos cuatro `.py` nuevos bajo `tests`, más `tests/support/b103_winci_manifest.json`; no muestra otra adición o eliminación de módulos.
- `scanned_test_files()` recorre `tests/**/*.py` y sólo excluye `goldens`, `__snapshots__`, `_artifacts` y `__pycache__` (`tools/id_registry.py:259,295-323`). Por tanto, los dos módulos de `tests/support` sí cuentan y el JSON no cuenta.

El diff de la constante es `299 -> 307`, mientras el comentario habla del **censo real** de HEAD, 303, medido y documentado en `E5-final2-review-gate-laws.md:85-89`; no afirma que la antigua constante fuera 303. Con ese significado, la procedencia escrita y el delta de archivos son coherentes: **303 + 4 = 307**. El antiguo hallazgo documental DOC-01 queda cerrado estáticamente.

## 4. Referencias de `E5-artifact-ruling`: actuales

Las referencias cuestionadas por DOC-02 ya coinciden con el workflow actual:

- escáner: `.github/workflows/clipboard-windows.yml:100-111`;
- upload condicionado: `:113-123`;
- preservación del exit: `:125-133`.

Son exactamente los rangos citados por `E5-artifact-ruling.md:25` y `E5-fix2-workflow-law.md:31`. La condición literal `always() && steps.artifact_safety.outcome == 'success'`, `actions/upload-artifact@v4` e `if-no-files-found: error` están presentes (`clipboard-windows.yml:113-123`). Los oráculos enlazados existen en `tests/test_b103_clipboard_core.py:1752-1758` y `tests/test_b103_winci_gate.py:679-685`.

La trazabilidad también sigue sincronizada en `01-requirements.md:131`, `02-test-cases.md:127,206` y `codewire/graph-inc1b.md:203`: upload sólo tras escáner exitoso, known-bad sin upload y conservación del fallo funcional. DOC-02 queda cerrado estáticamente. Esto no ejecuta el escáner ni demuestra el comportamiento real de GitHub Actions/WinCI.

## 5. Hallazgo restante: la última incorporación de evidencia no está cerrada

### EV-FINAL-01 — bloqueante para llamar «final» a la evidencia; no cambia los tallies ni la herencia

Hay dos hechos directamente observables, sin ejecutar el redactor ni el verificador:

1. `evidence-e5/full-six-families-final.txt:1` y `evidence-e5/law-recheck.txt:1` contienen una ruta hogar Unix personal sin sustituir; el segundo también reproduce rutas/identidades personales en el detalle del fallo heredado. No repito esos valores aquí. El detector escrito reconoce esta clase como `unix_home` (`redact_e5.py:56-60`) y el recorrido recursivo no exceptúa estos archivos (`:247-258`).
2. `evidence-e5/SHA256SUMS.txt:1-20` no contiene entradas para `full-six-families-final.txt` ni `law-recheck.txt`. El verificador exige una entrada para **cada** archivo directo y bytes exactamente iguales al conjunto esperado (`refresh_manifests.py:24-37,68-104`); por tanto, el manifest almacenado no describe el directorio actual.

El censo archivado sigue siendo el de la pasada anterior: `redaction-census.json:31,37-50` registra 156 archivos y modificaciones sólo en `final-targeted.txt` y `final-targeted-junit.xml`. Coherentemente, `E5-redaction-final.md:78-88` dejó escrito que los transcripts full/leyes adicionales aún no estaban copiados y que había que repetir redacción y manifests al incorporarlos. No hay un informe posterior que cierre esa operación para los dos archivos ahora presentes.

En consecuencia, `E5-law-rulings.md:32` no puede usar el `residual=0` y los seis manifests de aquella pasada como descripción del árbol final actual. Tampoco convierto este hallazgo en una afirmación sobre qué detectó la ejecución histórica de R-TST.070.2: es una conclusión estática sobre los artefactos locales y sus reglas de redacción/integridad.

**Desbloqueo sin repetir pruebas:** conservar los resultados ya aceptados, aplicar el proceso de redacción establecido a los bytes ahora incorporados, reconstruir y verificar los seis manifests, archivar esos resultados y actualizar `E5-law-rulings.md:32` para que describa esa pasada final. No se requiere cambiar producto, tests, workflow, canon ni los cinco fallos heredados.

## 6. Lo que permanece no verificado

- **WinCI:** sin ejecución real, artefactos reales ni veredicto; ningún GREEN Linux se promueve a Windows.
- **Mutantes de producto:** sin ejecución ni mortalidad demostrada; los controles del harness no los sustituyen.
- **AT-I1b-8:** sigue manual y pendiente de aceptación del operador.
- **Comparación base:** los resultados `e2e93548` y `305e5892` se aceptan según el encargo/ruling, pero sus transcripts no están archivados localmente para una comparación independiente.
- **Redacción e integridad finales:** no ejecuté los verificadores; la conclusión EV-FINAL-01 se deriva de los bytes y reglas actuales. El PASS anterior cubre 156 archivos, no demuestra la incorporación posterior de los dos transcripts.

Nada en este informe declara verdes los cinco fallos heredados, resuelta AT-I1b-8, ejecutado WinCI o ejecutados los mutantes de producto.
