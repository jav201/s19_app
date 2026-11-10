# E5 coverage audit — Inc 2b, R2

**Veredicto: FAIL.** Los cuatro issues de `E5-coverage-audit-2b.md` están resueltos y la integridad mecánica es correcta: 320 = 216 + 104, 125 filas en alcance, 124 RED citados = 124 `FAILED` reales de `int2b-red-stub-final8-main.txt`, y 321 tests = 309 + 12 en `int2b-run13-main.txt`. No obstante, la revisión de los oráculos encuentra **siete filas 2b cuya marca `full` aún sobreafirma lo ejecutado**: `.152/1`–`.152/5` no comprueban el `decode` exigido, y `.46/2` y `.48/2` no ejecutan el rechazo de solape que sus resultados esperados todavía prometen.

## Alcance y método

Se compararon las **104 filas 2b** y las **21 mixtas** de `02-test-cases.md` con `01-requirements.md`, `tests/test_b103_a2l_definition.py`, `tests/test_b103_synth_definitions.py` y las evidencias `evidence-e4/int2b-run13-main.txt` e `int2b-red-stub-final8-main.txt`. Se partió de `E5-coverage-audit-2b.md` y se revisaron los valores y brazos afirmados, no solo la existencia de nombres.

No ejecuté pytest en Windows ni mutaciones git. Hice revisión estática y censos de texto/AST de solo lectura; las dos ejecuciones citadas se verificaron como evidencias existentes, no como corridas nuevas.

## Totales e integridad

- **Casos:** 320 activos = 216 de 2a + 104 de 2b. La composición 2b es 4 de S2.7a + 3 de S2.7b + 97 de S2.7c; el total general es 284 de requisitos (99 + 54 + 123 + 8) + 33 canon + 3 aceptación (`02-test-cases.md:363,397-400`).
- **Alcance efectivo:** 125 filas, sin solape entre las 104 de 2b y las 21 mixtas. Las mixtas son `.21/3`, `.136/1`, `.58.1/1`, `.58.1/2`, quince de `.58.2`, `AT-B103-I2-1` y `AT-B103-I2-2`.
- **Marcas:** las 104 de 2b figuran `covered` y `(full)`; en las mixtas, 20 figuran `covered`/`full` y `.136/1` conserva correctamente `partial` con sus dos nodos (`02-test-cases.md:254`).
- **Nombres:** las 126 referencias de esas 125 filas existen (`.136/1` tiene dos). Esto incluye `test_r_a2l_def_136_1_describing_every_object_is_fast` en `tests/test_b103_a2l_definition_perf.py:34`; no hay referencia rota.
- **Columnas:** las 335 filas de casos —320 activas y 15 retiradas— tienen 9 columnas bajo lectura con escapes; las 16 filas de la tabla de split tienen 3. No hay malformación en las 125 filas del alcance.
- **Tests recogidos:** 309 `def test_` en `test_b103_a2l_definition.py` + 12 en `test_b103_synth_definitions.py` = **321**, coincidente con `int2b-run13-main.txt:6` (**321 passed**) y con `int2b-red-stub-final8-main.txt:2414` (**124 failed, 197 passed**).
- **RED:** hay 104 citas RED de 2b y 20 de mixtas. `.136/1` es la única mixta que no cita `final8`, coherentemente. Los 124 nombres citados y los 124 `FAILED` de `final8:2290-2413` coinciden exactamente, sin ausentes ni extras.
- **Resultado semántico:** **97/104 filas 2b sin hallazgo**, 7/104 con sobreafirmación; las 21 mixtas ejecutan sus brazos GREEN, con las notas de trazabilidad indicadas abajo. Total sin discrepancia fila-test: **118/125**.

## Los cuatro issues anteriores

### 1. RED vacuos o ausentes — RESUELTO

Las seis filas anteriormente falsas ya aparecen en `final8`: `.19/7`, `.58.1/1`, `.58.1/2`, `.58.2/12`, `.58.2/14` y `.58.2/15`.

- `.19/7` ahora exige también `encode_definition(...) == d.refusal` (`tests/test_b103_a2l_definition.py:2480-2482`); el RED muestra `Encoded(...STUB...)` frente al `A2L-DEF-MASK` esperado (`int2b-red-stub-final8-main.txt:23-39`). Ya no es solo una comprobación de describe.
- `_no_exception_encode` rechaza el cuerpo del stub (`res.data != b"STUB"`) además de exigir `Encoded | Refusal` (`tests/test_b103_a2l_definition.py:3476-3481`). Por ejemplo, `.58.2/12` falla realmente en esa afirmación (`int2b-red-stub-final8-main.txt:1985-2011`). El criterio amplio sigue siendo adecuado para `.58.2`, cuyo contrato es “valor o refusal, 0 excepciones”, no un byte exacto.
- `_encode_unchanged` aplica el mismo control anti-stub y exige refusal cuando `shared_with` existe (`tests/test_b103_a2l_definition.py:3587-3597`); `.58.1/1` falla en `b'STUB' != b'STUB'` (`int2b-red-stub-final8-main.txt:2106-2134`). Las copias profundas de payload e imagen siguen siendo el oráculo de no mutación (`:3600-3614`).

Los demás RED citados también están presentes. Ningún RED del alcance queda apoyado únicamente en una afirmación que acepta el stub.

### 2. Rejilla `.55/1` — RESUELTO

`test_r_a2l_def_55_1_number_round_trip` ya construye:

- las seis conversiones —none, IDENTICAL, LINEAR, RAT_FUNC, TAB_NOINTP, TAB_INTP— por cinco datatypes, dos órdenes y cuatro formatos (`tests/test_b103_a2l_definition.py:2992-3029`);
- el texto de display, el texto `.17g` y decimales escritos para cada valor no enmascarado (`:3030-3050`);
- UBYTE/SWORD/ULONG con máscaras multi-bit y one-bit, dos órdenes y cuatro formatos (`:3053-3077`).

El contador estático es **1 152 valores aceptados** (960 sin máscara + 192 con máscara), y `accepted >= 300` está afirmado en `:3078`. En la rama enmascarada, `dec.text` es también el texto de 17 cifras significativas y el decimal escrito: al ser enteros sin conversión, ambos son la misma cadena entera, con cero decimales. Por tanto una sola codificación basta para esos dos inputs coincidentes; no hay un brazo numérico distinto omitido. Los valores crudos aparentemente fuera de una máscara de un bit no invalidan la rejilla: antes de codificar, el decode selecciona el bit y produce `0` o `1`, que sí caben.

### 3. `AT-B103-I2-2` limitado a escalares — RESUELTO

La fila dice ahora “each scalar object” (`02-test-cases.md:360`), alineada con `01-requirements.md:248`. El nodo ejecuta build → decode → encode del planned text → apply → decode y después un segundo valor para los cuatro escalares, conservando los bytes fuera de los spans (`tests/test_b103_synth_definitions.py:340-371`). `_SCALAR_DEFC` contiene `ENUM_0001`, `MASK_BIT_0001`, `MASK_FIELD_0001` y `DISPLAY_0001` (`:313`), que son los cuatro VALUE del caso; AXIS_PTS, CURVE, MAP y VAL_BLK quedan fuera por diseño. La marca `full` ya no afirma arrays ni ejes.

### 4. Detalles de ledger — RESUELTO en `02-test-cases.md`

- `.26/4` usa el nombre rederivado `ASAM.C.ASCII.UBYTE.NUMBER_42` y sus 42 bytes (`02-test-cases.md:113`; test `:2510-2514`).
- `.43/4` ya no promete un encode de solape; exige `shared_with` y el refusal de límites sobre la definición limpiada (`02-test-cases.md:179`; test `:2714-2720`).
- `.44/1` y `.44/2` usan `0x810001` y ambos ejecutan primero `A2L-DEF-OVERLAP` y después bytes + notice (`02-test-cases.md:180-181`; tests `:2723-2741`).
- `.45/1` y `.45/2` describen exactamente `shared_with` + refusal de extended limits sobre la definición limpiada (`02-test-cases.md:182-183`; tests `:2744-2755`).
- `.56/1` limita correctamente el control previo al **primer** entry text de cada una de las tres tablas (`02-test-cases.md:214`), exactamente lo que hace el test (`tests/test_b103_a2l_definition.py:3091-3107`).

## Hallazgo bloqueante nuevo

### E5R2-1 — `.152/1`–`.152/5`: `full` sin el brazo `decode`

R-A2L-DEF.152 exige para sus cinco formas: refusal `A2L-DEF-PARSE` al codificar, **“describe and decode are unchanged”** y orden del chequeo (`01-requirements.md:215`). La propia fila `.152/1` lo repite explícitamente (`02-test-cases.md:308`).

Los cinco tests comprueban `d.refusal is None`, el primer error cuando aplica y el refusal exacto de encode, pero **ninguno llama a `decode_definition`**:

- `.152/1`: `tests/test_b103_a2l_definition.py:3404-3411`;
- `.152/2`: `:3414-3420`;
- `.152/3`: `:3423-3429`;
- `.152/4`: `:3432-3438`;
- `.152/5`: `:3441-3448`.

El RED de encode presente en `final8:2386-2390` no demuestra que decode permanezca inalterado. Tampoco hay otro nodo citado que ejercite decode sobre estos cinco payloads. Por tanto `covered/full` no está justificado para las cinco filas. Deben añadirse afirmaciones exactas de decode antes del encode o corregirse la cobertura; después hace falta una nueva evidencia GREEN completa.

## Otras discrepancias fila-test

### E5R2-2 — `.46/2` y `.48/2` prometen un solape que no ejecutan

- `.46/2` espera primero `A2L-DEF-OVERLAP`, cero bytes, y luego `35 12` (`02-test-cases.md:186`). El test afirma `shared_with` y ejecuta únicamente `_enc(_clear(d), ...)`; nunca codifica con `d` sin limpiar (`tests/test_b103_a2l_definition.py:2780-2784`).
- `.48/2` tiene la misma discrepancia: la fila espera refusal y luego `04 00` (`02-test-cases.md:193`), pero el test solo ejecuta la definición limpiada (`tests/test_b103_a2l_definition.py:2829-2832`).

El comportamiento de solape está cubierto en otros casos, por lo que esto no demuestra un defecto de producto; sí son dos Expected results más amplios que sus oráculos. Como se hizo con `.43/4`/`.45`, puede recortarse el texto a `shared_with` + encode limpiado, o añadirse el primer encode exacto. Mientras tanto esas dos marcas `full` son sobreafirmaciones.

## Notas no bloqueantes

- **Trazabilidad incompleta en 17 mixtas, no pérdida de ejecución.** `.58.1/1`-`/2` y las quince `.58.2` citan ahora solo sus nuevos nodos encode (`02-test-cases.md:220-236,238`). Los nodos antiguos de describe/decode siguen existiendo y forman parte de los 309 tests (`tests/test_b103_a2l_definition.py:1109-1125,1143-1150,1153-1169,1178-1271`). La suite cubre ambos brazos, pero las celdas Tests ya no enumeran el nodo 2a necesario para sostener `full`; deberían citar ambos o unificarse los brazos en un nodo.
- **Docstring residual.** `.43/4` está corregido en el ledger y en el código, pero su docstring aún dice “first the overlap” (`tests/test_b103_a2l_definition.py:2715`), aunque ya no hay ese encode. No altera el oráculo.
- **Censo futuro de DEFC.** Los cuatro escalares actuales sí están cubiertos, pero `_SCALAR_DEFC` es una lista manual y no se afirma contra los objetos escalares de `defc["objs"]` (`tests/test_b103_synth_definitions.py:313,351`). Si el generador añade otro escalar, el AT puede seguir verde sin incluirlo; una guarda de igualdad de conjuntos haría robusta la universalidad. Es una mejora de oráculo, no una omisión en el caso actual.

## Cierre

Los cuatro issues originales están cerrados, `.138/22` está realmente `covered/full` y tiene un oráculo discriminante de orden global (`02-test-cases.md:307`; `tests/test_b103_a2l_definition.py:3376-3386`; RED en `int2b-red-stub-final8-main.txt:1601-1617,2385`). Los conteos, nombres, columnas, marcas declaradas y los 124 RED son coherentes.

El FAIL se limita a la cobertura todavía sobreafirmada de **siete filas 2b**: cinco de `.152` por el decode ausente y dos por el solape no ejecutado. No se verificó una nueva corrida posterior a esas correcciones porque siguen pendientes; `run13` y `final8` solo prueban los brazos que efectivamente contienen sus nodos.
