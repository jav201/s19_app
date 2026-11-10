# E5 coverage audit — Inc 2b, R3

**Veredicto: PASS-WITH-NOTES.** Los dos hallazgos de `E5-coverage-audit-2b-r2.md` están resueltos y el nuevo `.138/23` tiene oráculo funcional para BLOB e INSTANCE. Los conteos, nombres, columnas y RED citados cierran: **321 casos = 216 + 105**, **322 tests = 310 main + 12 synth**, y **125 RED citados = 125 `FAILED` reales**. No quedan sobreafirmaciones bloqueantes en los cambios revisados. Persisten notas de trazabilidad y granularidad de evidencia, detalladas abajo.

## Alcance y método

Base declarada: worktree final HEAD `57b69214`. Revisé las **105 filas 2b y 21 mixtas** de `02-test-cases.md`, los requisitos y tests actuales, y las evidencias `int2b-run14-main.txt`, `int2b-red-stub-final9-main.txt` e `int2b-red-homonym-guard.txt`. Partí de los hallazgos de R2 y comprobé los brazos ejecutados, no solo los nombres.

No ejecuté pytest en Windows ni invoqué git. La revisión fue estática con censos de texto/AST de solo lectura; las ejecuciones citadas se leyeron como evidencias existentes.

## Totales e integridad

- **Casos:** 321 activos = 216 de 2a + 105 de 2b. Requisitos: 285 = S2.7a 99 + S2.7b 54 + **S2.7c 124** + S2.7d 8; más 33 canon + 3 aceptación = 321 (`02-test-cases.md:364`). 2b = 4 de S2.7a + 3 de S2.7b + 98 de S2.7c (`:400-401`).
- **Alcance:** 126 filas = 105 2b + 21 mixtas, sin intersección ni IDs ausentes. Las 105 de 2b figuran `covered/full`; las mixtas conservan 20 `covered/full` y `.136/1` `partial`.
- **Nombres:** las 127 referencias de las 126 filas existen (`.136/1` referencia dos nodos), incluida la prueba de rendimiento de `.136/1`. No hay referencias rotas.
- **Columnas:** las 336 filas de casos —321 activas y 15 retiradas— tienen 9 columnas bajo lectura con escapes; las 16 filas de split tienen 3.
- **Tests:** 310 `def test_` en `test_b103_a2l_definition.py` + 12 en `test_b103_synth_definitions.py` = **322**, coincidente con `int2b-run14-main.txt:6` (**322 passed**) y con `int2b-red-stub-final9-main.txt:2446` (**125 failed, 197 passed**).
- **RED:** 105 citas de 2b + 20 mixtas = 125. Los 125 nombres citados y los 125 `FAILED` de `final9` coinciden exactamente, sin ausentes ni extras. `.136/1` es correctamente la única mixta sin cita `final9`.
- **Cobertura funcional:** **105/105 filas 2b sin sobreafirmación restante**; 20 mixtas full y `.136/1` parcial según su marca. Total del alcance sin hallazgo bloqueante: **126/126**.

## Descarga de los hallazgos de R2

### E5R2-1 — decode de `.152/1`–`.152/5` — RESUELTO

Los cinco nodos comparan ahora exactamente:

`decode_definition(d, a2l, {0x10: 7, 0x11: 0}) == Decoded(7, 7, "7")`

antes del refusal `A2L-DEF-PARSE` de encode: `tests/test_b103_a2l_definition.py:3431-3439`, `:3442-3449`, `:3452-3459`, `:3462-3469` y `:3472-3480`. Esto cubre el “describe and decode are unchanged” de `01-requirements.md:215` y de `.152/1` en `02-test-cases.md:309`. El código fuente incluido en `final9` contiene esas afirmaciones (`int2b-red-stub-final9-main.txt:1644-1730`), por lo que no son añadidos posteriores a la evidencia.

### E5R2-2 — overlap inicial de `.46/2` y `.48/2` — RESUELTO

- `.46/2` ejecuta `_enc(d, ...)` y exige `A2L-DEF-OVERLAP` con el mensaje exacto antes de `_enc(_clear(d), ...) == Encoded(...35 12...)` (`tests/test_b103_a2l_definition.py:2780-2786`).
- `.48/2` hace lo propio antes del `Encoded(...04 00...)` (`:2831-2837`).

Ambos brazos coinciden ahora con `02-test-cases.md:186,193`; ya no hay Expected results más amplios que el oráculo.

## Nuevo `.138/23`

La fila exige, para BLOB y sized INSTANCE homónimos de un tag enmascarado pero no solapado, `MW.shared_with == "B"` y `A2L-DEF-OVERLAP` (`02-test-cases.md:308`; `01-requirements.md:210`, 23/23).

`test_r_a2l_def_138_23_cross_kind_name_collision_has_no_mask_exemption` construye **las dos formas** y, para cada una, afirma `shared_with` y el refusal exacto de encode (`tests/test_b103_a2l_definition.py:3394-3413`). La guarda de producto devuelve `False` antes de consultar `mask_of` cuando `entry[2]` es BLOB o INSTANCE (`s19_app/tui/a2l_definition.py:3511-3513`), por lo que ninguna de las dos puede heredar la máscara del tag homónimo. El caso está correctamente marcado `covered/full` y añade un nodo main: 310 en vez de 309.

La evidencia sin guarda es real y discrimina el defecto: `int2b-red-homonym-guard.txt:24-30` obtiene `None` en vez de `"B"` y termina en 1 failed, 309 deselected. `final9` también contiene el nodo (`int2b-red-stub-final9-main.txt:2417`), y `run14` prueba el conjunto GREEN completo.

## Notas restantes, no bloqueantes

1. **Los RED son por nodo, no por cada brazo.** En `.46/2` y `.48/2`, `final9` falla primero en `shared_with` (`int2b-red-stub-final9-main.txt:694,787`), antes del overlap inicial añadido. En `.138/23`, tanto `final9` como `int2b-red-homonym-guard.txt` se detienen en la primera forma, BLOB (`final9:1638-1643`; `int2b-red-homonym-guard.txt:23-28`), así que el RED específico no ejecuta la rama INSTANCE. `run14` cubre en GREEN todos esos brazos y el código fuente de la guarda cubre ambos tipos; no hay afirmación falsa a nivel de fila, pero no debe describirse la evidencia como un RED independiente por brazo o por forma.
2. **Trazabilidad incompleta en 17 mixtas.** `.58.1/1`-`/2` y las quince `.58.2` siguen citando solo sus nuevos nodos encode (`02-test-cases.md:220-238`). Los nodos antiguos describe/decode siguen existiendo y participan en los 310 tests main (`tests/test_b103_a2l_definition.py:1109-1271`). La suite cubre ambos brazos, pero las celdas Tests deberían citar ambos nodos para que `full` sea trazable desde la fila sola.
3. **Docstring residual de `.43/4`.** `tests/test_b103_a2l_definition.py:2715` aún dice “first the overlap”, aunque el test y el ledger solo afirman `shared_with` y el refusal de límites sobre la definición limpiada. No afecta al oráculo.
4. **Censo futuro de DEFC.** Los cuatro escalares actuales están cubiertos, pero `_SCALAR_DEFC` sigue siendo una lista manual sin afirmación de igualdad contra los escalares de `defc["objs"]` (`tests/test_b103_synth_definitions.py:313,351`). Un nuevo escalar del generador podría quedar fuera sin hacer RED el AT. Es robustez futura del oráculo, no una omisión actual.

## Cierre

R2 queda descargada en su totalidad y `.138/23` cierra la colisión cross-kind con prueba GREEN de ambas formas y RED específico de la guarda. No encontré nuevas sobreafirmaciones en los cambios ni RED citados ausentes. El veredicto es **PASS-WITH-NOTES** por las cuatro limitaciones documentadas, no por cobertura funcional pendiente.
