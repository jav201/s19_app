# Batch-103 G3 — rulings de evidencia local previa

## Alcance y estado

Este documento clasifica evidencia **previa** a la full-suite final. No es un verdict agregado ni cierra G3. La tercera corrida sobre `3302854210a8a62637c37f9d59745d70ae8c8a2a` fue **INVALID / infraestructura** por `OSError: [Errno 22]` durante el flush de terminal de pytest y quedó parcial; sus JUnit no se usan ni se archivan como full-suite final. Una cuarta corrida corre actualmente en un clon separado del mismo commit, con salida directa a archivos que este paquete no toca. Mientras no termine y toda diferencia quede clasificada, G3 sigue abierto y no hay G3 PASS.

Las dos ejecuciones archivadas son anteriores a los últimos fixes. Ambas terminaron con `main_exit=1`, `serial_exit=1` y `full_suite_exit=1`; ninguna es GREEN.

## Censo reconciliado de las dos corridas

La fuente mecánica son los JUnit main/serial almacenados en `run-35fabb25/` y `run-795779ad/`. `comparison-35fabb25-795779ad.tsv` contiene la unión de failed-sets, una fila por nodeid, con categoría `fixed`, `persistent` o `new`.

| Ejecución | Commit | Main failed | Serial failed | Total failed |
|---|---|---:|---:|---:|
| Primera | `35fabb25c42d752216433c095eb0d29024027294` | 428 | 94 | **522** |
| Segunda | `795779add81875976ac3651f8862498426d45abf` | 304 | 68 | **372** |

- **170** nodeids salieron del failed-set en la segunda ejecución.
- **352** permanecieron en él.
- **20** nodeids entraron como nuevos en la segunda ejecución.
- Reconciliación: `522 = 170 + 352`; `372 = 20 + 352`.

Los cuatro targets de `final-fixes` `8f9796517cc17c33495778792504ee87c2666429` quedaron posteriormente GREEN en su evidencia dirigida. Esto no se anticipa ni se mezcla con una tercera suite: la full-suite final sobre `33028542` todavía no tiene veredicto en este record.

## Guards de clipboard y WinCI

El antiguo conteo **271** se reconcilia como **269 guards literales de clipboard + 2 censos ya corregidos**. Los 269 son 238 exclusiones main y 31 seriales documentadas en `probes/residual/selection-summary.json` y las listas `main-excluded-clipboard.txt` / `serial-excluded-clipboard.txt`.

Estos guards representan **indisponibilidad local**, no cobertura ni pases. No se contabilizan como PASS ni como pruebas ejecutadas. Los dos censos fueron corregidos y su evidencia está en el carril estático; no se reutiliza el antiguo 271 como si siguiera vigente.

El WinCI histórico **10/10** pertenece al árbol `b2d6` citado por los records históricos. No es una ejecución del árbol final ni evidencia de que la full-suite final pase.

## Instrumentos y evidencia incremental

Hay **21 instrumentos sin veredicto Windows**: 10 basados en `process_time`, 7 dependientes de `/proc` y 4 usos puros de `getloadavg`. La evidencia Linux incremental existente no se reclama como cobertura Windows actual ni como PASS de esos instrumentos en esta corrida.

Los cuatro casos `getloadavg` que tienen assertions propias fueron medidos en `probes/final-timing/`:

- **B29/2:** PASS en head y control; el margen head bajo permanece visible en `comparison.md`.
- **B82/1:** PASS en head y control.
- **B97/3:** PASS en head y control.
- **B95/1:** la misma falla aparece en head y control; no es una regresión respecto a ese control y no se convierte en PASS.

Los cuatro nodos no existen en la base `0c3a6bd4`; por eso el contraste es head/control. `comparison.md`, los tres JUnit y las listas `nodes-*.txt` contienen los nodeids completos y las condiciones de ejecución.

## Heredados que siguen RED

El censo reconciliado conserva **38 heredados previos + 23 vigentes**, atribuidos mediante comparación base/head del mismo oráculo. Siguen **RED / no PASS**; la aprobación provisional no los cierra.

Referencias exactas por nodeid y evidencia:

- `probes/residual/comparison.tsv`: columnas `nodeid`, categoría, estados y firmas base/head; `comparison-summary.json` conserva el censo y mensajes asociados.
- `probes/functional/comparison.tsv`: comparación funcional base/head por nodeid y firma.
- `probes/visual/signature-comparison.txt` y los JUnit base/head del mismo paquete: diferencias visuales y clipboard clasificadas sin ocultar fallos.
- `probes/a2l/comparison.tsv`: estado por nodeid para cada JUnit head/base/control del probe A2L.
- `probes/new2/comparison.tsv`: los 20 nodeids nuevos de la segunda corrida, con clasificación y evidencia head/base/control.
- `probes/final-timing/comparison.md`: los ocho casos antiguos con la misma firma base/head y el cambio `focus[map]` separado, además de los cuatro casos nuevos head/control.

Estas referencias mantienen separados heredados, contexto no reproducido, regresiones y diferencias de firma; ninguna fila heredada se promueve a PASS.

## Hygiene heredado y runner

Se conservan los **60 hits hygiene heredados**; no se reescriben records históricos para ocultarlos. Tras el fix estático, el runner aporta **0 nuevos hits**: el detalle está en `../fix-g3-static/RESULT.md`, incluida la ausencia de hits para `run_distributed.py` y las formas removidas `isolation/home/...`.

## Regresiones y correcciones integradas

Las dos regresiones nuevas explícitamente clasificadas son:

1. `tests/test_suite_hygiene.py::test_r_tst_154_155_inc15_arms_wait_through_settled` — espera settled después de `apply_doc`.
2. `tests/test_undo_redo_ux.py::test_ac2_1_ctrl_z_y_undo_redo_via_real_key` — el Add real no aparecía antes de undo/redo.

Sus firmas head/control están en `probes/new2/comparison.tsv`. Esas dos correcciones y las otras dos —sincronización de B100 load question y escritura Inc10 del nombre largo— están integradas por `8f979651`. La evidencia dirigida y sus hashes están en `../final-fixes/`; no se afirma aquí el resultado de la tercera suite.

## AT y decisión del operador

AT-I1b-8 permanece **deferred-to-user-validation / not_run**: no ejecutada por agentes y no convertida en cobertura. Queda registrada la aprobación provisional del operador de las decisiones/página, cuya validación continúa durante el uso y las pruebas de usuario. Esto no equivale a G3 cerrado ni a full-suite PASS.

## Regla de cierre pendiente

G3 permanece abierto hasta disponer del resultado de la full-suite final sobre `33028542` y clasificar cualquier diferencia por nodeid contra esta evidencia previa. Cada diferencia nueva, persistente o corregida deberá enlazar su JUnit/transcript y su comparación; ningún conteo de este documento sustituye esa ejecución final.
