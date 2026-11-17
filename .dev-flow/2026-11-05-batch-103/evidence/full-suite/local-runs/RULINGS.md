# Batch-103 G3 — rulings de evidencia local previa y corrida 33028542

## Alcance y estado

Este documento clasifica evidencia local y no cierra G3. La tercera corrida sobre `3302854210a8a62637c37f9d59745d70ae8c8a2a` fue INVALID/infra por `OSError: [Errno 22]` durante el flush de terminal y quedó parcial; sus JUnit no se usan como full-suite final. La cuarta corrida sobre el mismo commit sí completó main/serial y está archivada en `run-33028542/`: es **RED clasificada**, no PASS.

Una nueva full-suite corre actualmente sobre `85ed72102479585728b7dd8210b98b8d7639eef9` en un clon separado, con salida directa a archivos. No tiene veredicto en este record y no se anticipa su resultado. G3 sigue abierto.

## Censo reconciliado de las corridas

La fuente mecánica son los JUnit main/serial almacenados en `run-35fabb25/`, `run-795779ad/` y `run-33028542/`.

| Ejecución | Commit | Main failed | Serial failed | Total failed |
|---|---|---:|---:|---:|
| Primera | `35fabb25c42d752216433c095eb0d29024027294` | 428 | 94 | **522** |
| Segunda | `795779add81875976ac3651f8862498426d45abf` | 304 | 68 | **372** |
| Completa 330 | `3302854210a8a62637c37f9d59745d70ae8c8a2a` | 306 | 66 | **372** |

`comparison-35fabb25-795779ad.tsv` registra la primera transición:

- **170** nodeids salieron del failed-set.
- **352** permanecieron.
- **20** nodeids entraron como nuevos.
- Reconciliación: `522 = 170 + 352`; `372 = 20 + 352`.

`comparison-795779ad-33028542.tsv` registra la transición a la corrida completa 330:

- **23 resolved** respecto al failed-set de `795779ad`.
- **349 persistent**.
- **23 new** en `33028542`.
- Reconciliación: `372 = 23 + 349` para la corrida previa y `372 = 23 + 349` para la nueva, con conjuntos de nodeids distintos.

Los cuatro targets de `final-fixes` `8f9796517cc17c33495778792504ee87c2666429` quedaron posteriormente **GREEN** en evidencia dirigida. Los fixes posteriores project-check, LoadGuard y refresh same_path también tienen sus carriles GO integrados. Ninguno se mezcla con el censo 330 ni se anticipa a la suite actual `85ed7210`.

## Guards de clipboard, excepciones y WinCI

Se corrige la nota histórica:

- Primera suite: **271 = 238 main + 33 serial**.
- Segunda suite: **269 guards literales + 2 excepciones**; las dos excepciones no son censos.
- Corrida completa 330: **270 guards literales + 1 excepción OSC52**. Esa excepción fue corregida posteriormente en `b103-g3-osc52` `ba819252`, sin cambiar retrospectivamente el censo 330.

Los guards literales representan **indisponibilidad local**, no cobertura ni pases. No se contabilizan como PASS ni como pruebas ejecutadas. Las selecciones y listas de exclusión permanecen en `probes/residual/`; el caso OSC52 y su corrección tienen evidencia separada en `../b103-g3-osc52/`.

El WinCI histórico **10/10** pertenece al árbol `b2d6` citado por records históricos. No es una ejecución del árbol final ni evidencia de que la full-suite actual pase.

## Instrumentos, plataforma y heredados

La evidencia incremental previa conserva **21 instrumentos sin veredicto Windows**: 10 `process_time`, 7 `/proc` y 4 usos puros de `getloadavg`. Esa evidencia Linux no se reclama como cobertura Windows actual.

Para la corrida 330, la auditoría actual usa **30 firmas de instrumentos/plataforma con 18 solapamientos heredados** y **68 atribuciones heredadas**. No se reutilizan los antiguos conteos **61/25** como si fueran el censo final.

Los cuatro casos `getloadavg` con assertions propias fueron medidos en `probes/final-timing/`:

- **B29/2:** PASS en head y control; margen head bajo visible.
- **B82/1:** PASS en head y control.
- **B97/3:** PASS en head y control.
- **B95/1:** misma falla head/control; no regresión respecto a ese control y no PASS.

Las referencias exactas por nodeid y evidencia son:

- `probes/residual/comparison.tsv` y `comparison-summary.json`: estados, categorías y firmas base/head.
- `probes/functional/comparison.tsv` y `probes/visual/signature-comparison.txt`: comparaciones funcionales/visuales y sus JUnit.
- `probes/a2l/comparison.tsv`: estado por nodeid para cada JUnit head/base/control A2L.
- `probes/new2/comparison.tsv`: los 20 nuevos de la segunda corrida.
- `probes/last23/comparison.tsv`, `classification.tsv` y `results.tsv`: los 23 nuevos de 330 con su A/B y clasificación.
- `probes/final-timing/comparison.md`: los ocho casos antiguos con misma firma base/head, `focus[map]` separado y los cuatro nuevos head/control.

Las atribuciones heredadas siguen **RED / no PASS**. La aprobación provisional no las cierra.

## A/B de los últimos 23

`probes/last23/` contiene 23 casos finales, 20 base y 3 control, con JUnit/log/exit y comparaciones:

- **15 contexto no reproducido**: no se promocionan como regresiones ni como cobertura de la suite.
- **5 instrumentos/portabilidad Windows**: fallan también en el comparador según las filas `heredado_portabilidad`.
- **3 regresiones reales:** project_check, LoadGuard y A2L refresh same_path. Fueron corregidas en carriles posteriores `045cc707` y `0f190ecb`; su resultado no se anticipa a la suite `85ed7210`.

Para `test_r_a2l_def_149_2_scaling_enum_table`, el **base aislado también falla** con `{256: 0.0, 512: 0.0, 2048: 0.0}`, igual que final. `windows-process-time-probe.txt` registra 2000/2000 muestras `process_time` en cero. Esta nueva evidencia documenta cuantización del instrumento y **no afirma una regresión**.

## Hygiene heredado y runner

Se conservan los **60 hits hygiene heredados**; no se reescriben records históricos para ocultarlos. Tras el fix estático, el runner aporta **0 nuevos hits**, según `../fix-g3-static/RESULT.md`, incluida la ausencia de hits para `run_distributed.py` y las formas removidas `isolation/home/...`.

## Regresiones previas ya integradas

Las dos regresiones nuevas de `new2` fueron:

1. `tests/test_suite_hygiene.py::test_r_tst_154_155_inc15_arms_wait_through_settled` — espera settled después de `apply_doc`.
2. `tests/test_undo_redo_ux.py::test_ac2_1_ctrl_z_y_undo_redo_via_real_key` — Add real no visible antes de undo/redo.

Esas correcciones y las otras dos de final-fixes —B100 load question e Inc10 long written name— están integradas por `8f979651`. Su evidencia dirigida y hashes están en `../final-fixes/`.

## AT y decisión del operador

AT-I1b-8 permanece **deferred-to-user-validation / not_run**: no ejecutada por agentes y no convertida en cobertura. La aprobación provisional del operador cubre decisiones/página y su validación continúa durante el uso/pruebas de usuario. No equivale a G3 cerrado ni a full-suite PASS.

## Regla de cierre pendiente

G3 permanece abierto hasta disponer del resultado de la full-suite actual sobre `85ed7210` y clasificar cualquier diferencia por nodeid contra esta evidencia. Cada diferencia nueva, persistente o corregida deberá enlazar su JUnit/transcript y comparación. Ningún conteo de este documento sustituye esa ejecución final.
