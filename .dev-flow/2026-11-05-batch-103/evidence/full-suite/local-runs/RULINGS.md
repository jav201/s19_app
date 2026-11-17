# Batch-103 G3 — rulings de evidencia local y corridas 33028542/85ed7210

## Alcance y estado

Este documento clasifica evidencia local y no cierra G3. La tercera corrida sobre `3302854210a8a62637c37f9d59745d70ae8c8a2a` fue INVALID/infra por `OSError: [Errno 22]` durante el flush de terminal y quedó parcial; sus JUnit no se usan como full-suite final. La cuarta corrida sobre 330 completó main/serial y está archivada como RED clasificada.

La corrida completa `85ed72102479585728b7dd8210b98b8d7639eef9` también está archivada en `run-85ed7210/`: es **RED clasificada**, no PASS. La full-suite de cierre corre actualmente sobre `13b1e52257b381a4a091e253b49dd9b58aaf0fcd` como task `bash-1an26qz7` en un clon separado. No tiene veredicto en este record; G3 sigue abierto.

## Censo reconciliado de las corridas

| Ejecución | Commit | Main failed | Serial failed | Total failed |
|---|---|---:|---:|---:|
| Primera | `35fabb25c42d752216433c095eb0d29024027294` | 428 | 94 | **522** |
| Segunda | `795779add81875976ac3651f8862498426d45abf` | 304 | 68 | **372** |
| Completa 330 | `3302854210a8a62637c37f9d59745d70ae8c8a2a` | 306 | 66 | **372** |
| Completa 85ed | `85ed72102479585728b7dd8210b98b8d7639eef9` | 294 | 69 | **363** |

`comparison-35fabb25-795779ad.tsv` registra 170 fixed, 352 persistent y 20 new: `522 = 170 + 352`; `372 = 20 + 352`.

`comparison-795779ad-33028542.tsv` registra 23 resolved, 349 persistent y 23 new. Ambos failed-sets tienen 372 casos, pero no el mismo conjunto de nodeids.

`comparison-33028542-85ed7210.tsv` registra la transición a 85ed:

- **22 resolved** respecto al failed-set de 330.
- **350 persistent**.
- **13 new** en 85ed, antes de su A/B.
- Reconciliación: `372 = 22 + 350`; `363 = 13 + 350`.

Los cuatro targets de `final-fixes` `8f979651` tienen evidencia dirigida PASS. En 85ed, los objetivos **project_check, LoadGuard, refresh same_path y OSC52** quedaron PASS según sus carriles y la corrida. Saveback S0/TC-024 se corrigió después en `fba4aa25`. Ninguno se anticipa a la suite de cierre 13b1e522.

## Guards de clipboard, excepciones y WinCI

- Primera suite: **271 = 238 main + 33 serial**.
- Segunda suite: **269 guards literales + 2 excepciones**; las excepciones no son censos.
- Corrida 330: **270 guards literales + 1 excepción OSC52**, corregida posteriormente en `ba819252`.
- Corrida 85ed: **269 guards literales = 236 main + 33 serial**.

Los guards literales representan **indisponibilidad local**, no cobertura ni pases. No se contabilizan como PASS ni como pruebas ejecutadas. Las selecciones y exclusiones permanecen en `probes/residual/`; OSC52 tiene evidencia separada en `../b103-g3-osc52/`.

El WinCI histórico **10/10** pertenece al árbol `b2d6`; no es una ejecución del árbol de cierre ni evidencia de que la suite actual pase.

## Instrumentos, plataforma y heredados

La evidencia incremental previa conserva 21 instrumentos sin veredicto Windows: 10 `process_time`, 7 `/proc` y 4 usos puros de `getloadavg`. La evidencia Linux no se reclama como cobertura Windows actual.

Para 330, la auditoría histórica usa 30 firmas de instrumentos/plataforma con 18 solapamientos heredados y 68 atribuciones heredadas. **Estos conteos no se reutilizan para 85ed.**

Para 85ed, el censo específico es **21 plataforma, 60 residuales y 13 nuevos antes del A/B**. Los 13 nuevos se clasifican en `probes/last13/`, sin copiar conteos de corridas anteriores.

Los cuatro casos `getloadavg` con assertions propias permanecen en `probes/final-timing/`: B29/2, B82/1 y B97/3 PASS head/control; B95/1 conserva la misma falla head/control y no es regresión respecto a ese control.

Referencias exactas por nodeid:

- `probes/residual/comparison.tsv` y `comparison-summary.json`: estados y firmas base/head.
- `probes/functional/comparison.tsv`, `probes/visual/signature-comparison.txt` y `probes/a2l/comparison.tsv`: comparaciones especializadas y sus JUnit.
- `probes/new2/comparison.tsv`: los 20 nuevos de la segunda corrida.
- `probes/last23/comparison.tsv`, `classification.tsv` y `results.tsv`: los 23 nuevos de 330.
- `probes/last13/comparison.tsv`, `classification.tsv` y `results.tsv`: los 13 nuevos de 85ed y su A/B.
- `probes/final-timing/comparison.md`: casos antiguos base/head y nuevos head/control.

Las atribuciones heredadas siguen **RED / no PASS**; la aprobación provisional no las cierra.

## A/B de los últimos 23 de 330

`probes/last23/` contiene 15 contexto no reproducido, 5 instrumentos/portabilidad Windows y 3 regresiones reales: project_check, LoadGuard y refresh same_path. Estas tres fueron corregidas por `045cc707` y `0f190ecb`.

Para `test_r_a2l_def_149_2_scaling_enum_table`, el base aislado también falla con `{256: 0.0, 512: 0.0, 2048: 0.0}`. `windows-process-time-probe.txt` registra 2000/2000 muestras `process_time` en cero: evidencia de cuantización, no afirmación de regresión.

## A/B de los últimos 13 de 85ed

`probes/last13/` contiene 13 head, 11 base y 2 control, con JUnit/log/exit y comparaciones:

- **10 contexto:** no reproducido aislado; no se promociona como regresión ni cobertura de suite.
- **1 heredado de instrumento:** `test_r_a2l_def_148_3_shared_layout_first_line_value`, misma firma ZeroDivisionError head/base por denominador `process_time` cero.
- **1 instrumento:** `test_r_a2l_def_150_arr_6_long_matched_range_text_referenced`, ZeroDivisionError por el mismo instrumento; no evidencia de regresión funcional.
- **1 regresión real:** saveback S0 `test_saveback_width_32_preserves_source_s0_header`, `written=None` antes de las aserciones S0. Fue corregida posteriormente por `fba4aa25`; sus oráculos de anchura, S0 y payload permanecen intactos.

### Adjudicación TC-024 `#diff_status`

`../saveback-s0/RESULT.md` documenta que la firma contextual de 85ed fue `WorkerFailed: NoMatches("#diff_status")` durante el cierre de la app. El driver consultaba workers antes de que el botón creara el worker y salía antes del callback `call_from_thread` que instalaba el estado final.

El driver corregido espera el estado observable con ambos nombres `.md` y `.html`. Los probes aislados 85ed/base y last23 head330/base pasaron; no se relajaron las expresiones regulares ni la aserción de ambas rutas. Es una carrera real del driver expuesta por contexto, no una regresión persistente del generador de reportes.

## Hygiene heredado y runner

Se conservan los **60 hits hygiene heredados**; no se reescriben records históricos. Tras el fix estático, el runner aporta **0 nuevos hits**, según `../fix-g3-static/RESULT.md`.

## Regresiones previas ya integradas

Las regresiones `new2` apply_doc settled y undo/redo real key, junto con B100 load question e Inc10 long written name, están integradas por `8f979651`. La evidencia dirigida y hashes están en `../final-fixes/`.

## AT y decisión del operador

AT-I1b-8 permanece **deferred-to-user-validation / not_run**: no ejecutada por agentes y no convertida en cobertura. La aprobación provisional del operador cubre decisiones/página y su validación continúa durante uso/pruebas de usuario. No equivale a G3 cerrado ni full-suite PASS.

## Regla de cierre pendiente

G3 permanece abierto hasta disponer del resultado de la full-suite actual sobre `13b1e522` y clasificar cualquier diferencia por nodeid. Cada diferencia nueva, persistente o corregida deberá enlazar JUnit/transcript y comparación. Ningún conteo de este documento sustituye esa ejecución final.
