# Batch-103 G3 — rulings finales y evidencia local

## Decisión final: PASS-WITH-NOTES, no full-suite GREEN

La full-suite `13b1e52257b381a4a091e253b49dd9b58aaf0fcd` completó main/serial y quedó archivada en `run-13b1e522/`: **RED clasificada**, con **0 regresiones abiertas** tras el A/B de `last18`. Los fallos heredados, contextuales y de instrumentos siguen **RED / no PASS**; no se convierten en pases.

G3 se cierra **PASS-WITH-NOTES** porque la corrida está completa y clasificada, los 346 persistentes están reglados y no queda una regresión abierta. No es una declaración de full-suite GREEN. No se ejecuta otra full-suite porque desde 13b1e522 sólo cambiaron records, no producto/tests.

La aprobación provisional del operador cubre decisiones/página y se mantiene su validación durante uso/pruebas de usuario. AT-I1b-8 permanece **deferred-to-user-validation / not_run**, no ejecutada por agentes.

## Censo de corridas

| Ejecución | Commit | Main failed | Serial failed | Total failed |
|---|---|---:|---:|---:|
| Primera | `35fabb25c42d752216433c095eb0d29024027294` | 428 | 94 | **522** |
| Segunda | `795779add81875976ac3651f8862498426d45abf` | 304 | 68 | **372** |
| Completa 330 | `3302854210a8a62637c37f9d59745d70ae8c8a2a` | 306 | 66 | **372** |
| Completa 85ed | `85ed72102479585728b7dd8210b98b8d7639eef9` | 294 | 69 | **363** |
| Cierre 13b1e522 | `13b1e52257b381a4a091e253b49dd9b58aaf0fcd` | 298 | 66 | **364** |

La descomposición final independiente es **269 guards literales + 19 plataforma + 58 residuales + 18 nuevos antes del A/B = 364**.

`comparison-35fabb25-795779ad.tsv` registra 170 fixed, 352 persistent y 20 new.

`comparison-795779ad-33028542.tsv` registra 23 resolved, 349 persistent y 23 new.

`comparison-33028542-85ed7210.tsv` registra 22 resolved, 350 persistent y 13 new.

`comparison-85ed7210-13b1e522.tsv` registra el cierre:

- **17 resolved** respecto a 85ed.
- **346 persistent**, todos reglados.
- **18 new** antes del A/B.
- Reconciliación: `363 = 17 + 346`; `364 = 346 + 18`.

## Last18: cero regresiones reales

`probes/last18/` contiene 18 head, 15 base y 3 control, con repetición head/base adicional:

- **16 contexto no reproducido:** no son regresiones ni cobertura de suite.
- **2 instrumento:** cuantización Windows de `process_time`, sin regresión funcional.
- **0 regresiones reales abiertas.**

Para `test_r_a2l_def_148_13_long_type_word`, la corrida inicial head falló por cuantización, pero la repetición head/base pasó con ratio 1.0 y tiempo absoluto dentro de límites. Para `test_r_a2l_def_150_arr_2_enum_table_decode_val_blk`, head/base pasaron y el ZeroDivisionError del instrumento quedó documentado sin afirmar regresión. Los archivos `comparison.tsv`, `classification.tsv`, `results.tsv`, `repeat-results.tsv` y JUnit/logs contienen los nodeids y firmas.

Los contextos y heredados no se declaran PASS; simplemente no constituyen una regresión abierta atribuible a la integración.

## Doce objetivos integrados PASS

Los doce objetivos integrados quedan enlazados a su evidencia dirigida:

1. Inc15/TC-051 settled.
2. Undo/redo real key.
3. Inc10 long written name.
4. B100 project-load question.

Los cuatro anteriores están en `../final-fixes/`.

5. Project_check / SEC6-5 (`../b103-g3-project-check/`).
6. LoadGuard (`../b103-g3-loadguard-refresh/`).
7. Refresh same_path (`../b103-g3-loadguard-refresh/`).
8. OSC52 (`../b103-g3-osc52/`).
9. Saveback S0 (`../saveback-s0/`).
10. TC-024 `#diff_status` (`../saveback-s0/`).
11. Censo OsClipboardInput (`../fix-g3-static/RESULT.md`).
12. Censo total de text boxes (`../fix-g3-static/RESULT.md`).

Estos PASS son dirigidos y no sustituyen el censo RED de la full-suite; sí cierran sus regresiones específicas.

### Adjudicación TC-024 `#diff_status`

`../saveback-s0/RESULT.md` documenta `WorkerFailed: NoMatches("#diff_status")` durante cierre de app: consulta de workers antes de creación del worker y salida antes del callback `call_from_thread`. El driver corregido espera ambos nombres `.md` y `.html`. Probes aislados 85ed/base y last23 head330/base pasaron; oráculos y rutas no se relajaron. Es carrera del driver, no regresión persistente del generador.

## Guards, plataforma y heredados

- Primera suite: 271 = 238 main + 33 serial.
- Segunda suite: 269 guards literales + 2 excepciones, no censos.
- Corrida 330: 270 guards literales + 1 excepción OSC52 corregida por `ba819252`.
- Corrida 85ed: 269 guards literales = 236 main + 33 serial.
- Cierre 13b1e522: **269 guards literales**; son indisponibilidad local, no cobertura ni PASS.

El WinCI histórico 10/10 pertenece al árbol `b2d6`, no al árbol final.

La evidencia incremental previa conserva 21 instrumentos sin veredicto Windows. Para 330 se usaron 30 firmas con 18 solapamientos y 68 atribuciones heredadas; para 85ed, 21 plataforma y 60 residuales; para el cierre, 19 plataforma y 58 residuales. No se copian esos conteos hacia atrás ni se intercambian entre corridas.

Los cuatro `getloadavg` con assertions están en `probes/final-timing/`: B29/2, B82/1 y B97/3 PASS head/control; B95/1 misma falla head/control, no regresión.

Referencias exactas por nodeid: `probes/residual/comparison.tsv`, `probes/functional/comparison.tsv`, `probes/visual/signature-comparison.txt`, `probes/a2l/comparison.tsv`, `probes/new2/comparison.tsv`, `probes/last23/comparison.tsv`, `probes/last13/comparison.tsv`, `probes/last18/comparison.tsv` y `probes/final-timing/comparison.md`.

## A/B anteriores

`last23`: 15 contexto, 5 instrumentos Windows y 3 regresiones posteriores corregidas. `149_2` falla también en base aislado por cuantización, no regresión.

`last13`: 10 contexto, 1 heredado de instrumento, 1 instrumento y 1 regresión saveback S0 corregida por `fba4aa25`.

Las regresiones apply_doc settled, undo/redo, B100 load question, Inc10 long name, project_check, LoadGuard, refresh same_path, OSC52 y saveback S0 están integradas en sus carriles y no quedan abiertas.

## Hygiene heredado y runner

Se conservan los **60 hits hygiene heredados**; no se reescriben records históricos. Tras el fix estático, el runner aporta **0 nuevos hits**, según `../fix-g3-static/RESULT.md`.

## Regla de promoción

El estado es **listo para promoción a main**, no merge a main realizado. La promoción usa PASS-WITH-NOTES con: full-suite completa clasificada, 0 regresiones abiertas, 12 objetivos PASS, aprobación provisional registrada y AT-I1b-8 diferida a validación de usuario. Los RED heredados/contextuales permanecen visibles como notas y no como cobertura.
