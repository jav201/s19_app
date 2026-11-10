# Inc 3b — E3 seguridad, re-revisión R2 tras correction 1

**Veredicto: FAIL.** Queda **1 MAJOR**, **3 MEDIUM** y **2 MINOR**. El MAJOR bloquea E4: la regla de materialización limitada no define un superset seguro de candidatos y puede seguir perdiendo un solape cuyo registro empieza en una página anterior. S-02, S-03, S-04, S-06, S-07 y S-10 están cerrados; S-05 y S-08 quedan parciales; S-09 conserva un caso no alcanzable y una inconsistencia de mensaje.

Revisión de diseño y cobertura sobre `E3-rulings.md:197-213`, requirements/cases/graph/slice corregidos. No se exige ni se ejecuta producto nuevo.

## Bloqueo restante

### E3B3-R2-01 — MAJOR — design-gap — la materialización por páginas tocadas no garantiza descubrir el candidato solapado

**Ubicación:** `codewire/graph-inc3.md:282`; casos `.140/5-6` en `02-test-cases.md:336-337` y `codewire/graph-inc3.md:342`.

La corrección fija correctamente el uso de la `Definition.byte_length` final en índice y `_entry_overlaps`. Sin embargo, después de construir las definiciones solicitadas, prescribe materializar «only candidates on pages they touch». Si la selección previa usa las entradas provisionales del tag, todavía no existe una relación segura entre «el tag está en esta página» y «su registro final puede tocar esta página».

Ejemplo que el texto no resuelve: una CURVE C en `0x10`, con `tag.length is None` y longitud final `0x40`, y un VALUE V en `0x41`. C empieza en la página 1; V está en la página 4. Si solo se materializan candidatos de las páginas de V, C nunca se describe, nunca recibe su span final y no llega al índice: V vuelve a quedar sin `shared_with` aunque C cubra `0x41`. El mismo hueco aparece con un tag que tenga una longitud provisional corta.

`.140/5` no lo discrimina: C8 en `0x20` y V en `0x21` están en la **misma página** de 16 bytes, por lo que el candidato sí está disponible bajo esa lectura. `/6` repite exactamente el mismo emplazamiento con máscaras.

**Corrección requerida:** definir un superset conservador de candidatos antes de materializar, incluidos registros que empiezan antes de la primera página solicitada y pueden alcanzarla (hasta el límite de span), o materializar todas las definiciones una vez por walk y construir después el índice final. La caché debe evitar toda segunda descripción sin sustituir esa garantía de completitud. Añadir un caso cross-page con dirección inicial fuera de las páginas del VALUE, tanto con `tag.length=None` como con longitud provisional corta, conservando orden global de archivo y conteos de materialización.

## Otros hallazgos

### E3B3-R2-02 — MEDIUM — design-gap / cobertura — la inversión O(log M) no fija todavía la semántica exacta del oracle

**Ubicación:** `codewire/graph-inc3.md:154`, `:832`, `:873`; `02-test-cases.md:330`; oracle real `s19_app/tui/a2l.py:2884-2937`.

Las formas compartidas, inmutables y construidas una vez por walk sí cierran el problema de coste estructural de S-05. El hueco restante es semántico. «Indexed by physical value for bisect» no basta para especificar:

- la **primera raw en file order** entre todas las entradas dentro de `abs_tol=1e-9`, que el oracle devuelve en TAB_NOINTP y TAB_INTP (`a2l.py:2891-2894`, `:2913-2915`);
- endpoints, empates de distancia y los dos valores usados en el mensaje de error (`:2895-2904`);
- entradas no numéricas, NaN y la forma en que afectan al orden usado por el oracle;
- la interpolación, el redondeo de raw y el flag basado en volver a decodificar el raw escrito (`:2916-2941`).

Una bisect convencional puede elegir otra raw dentro de la tolerancia o asumir un orden que NaN rompe. `.131/2` no fija tipo TAB_INTP/TAB_NOINTP, entradas de la tabla, textos del operador ni resultados concretos por alternativa; «compare every inverse result with frozen `_reverse_table_lookup`» no proporciona inputs que discriminen esas ramas. Tampoco hay un caso de textos enum duplicados que pruebe «first raw in file order».

**Corrección requerida:** especificar el algoritmo de consulta para cada rama, incluida la selección del primer match en file order y el comportamiento con no finitos, manteniendo O(log M) por consulta. Fijar una matriz de entradas y textos: ambos tipos TAB, dentro/fuera de rango, tolerancia, empates, duplicados, no numéricos/NaN y flag de written value; añadir el texto enum duplicado. La comprobación de coste puede conservar la tabla de 256 KiB y el límite de 0,500 s.

### E3B3-R2-03 — MEDIUM — design-gap / sincronía — CTX conserva el orden antiguo sin PARSE

**Ubicación:** `01-requirements.md:123-125`, frente a `E3-rulings.md:208` y `codewire/graph-inc3.md:390`, `:832`.

El grafo ya prescribe `definition.refusal → PARSE → decode/ELEMENTS`, y `.120/3`, `.130/4-5` lo cubren. Pero CTX *array encode order* sigue empezando por «the record's decode», sin PARSE ni las nuevas reglas de monotonía desconocida/punto no evaluable. Es la misma contradicción documental que S-08 pedía eliminar: un implementador que siga CTX vuelve a producir BYTES/INDEX antes de PARSE.

**Corrección requerida:** escribir en CTX la secuencia común `definition refusal → PARSE → decode/ELEMENTS → positions → edits → monotony`, con OVERLAP tardío, y referenciar desde ella las reglas .154/.155. No cambiar el grafo ya corregido.

### E3B3-R2-04 — MEDIUM — cobertura — `.155/1` espera DECODE donde PRECISION ocurre antes

**Ubicación:** `02-test-cases.md:342`; orden de `codewire/graph-inc3.md:832`; `s19_app/tui/a2l_definition.py:3764-3772`.

El caso edita el mismo punto cuya conversión RAT_FUNC falla y espera su exacto `A2L-DEF-DECODE` desde la comprobación de monotonía. Pero antes de llegar a monotonía, el paso 4 delega ese punto en `encode_definition`. Su round trip convierte cualquier refusal de decode en `A2L-DEF-PRECISION` con «the nearest stored value is (none)» (`a2l_definition.py:3766-3772`). Por tanto, el camino que el caso pretende probar no se alcanza con ese input.

**Corrección requerida:** hacer que el punto con conversión inválida sea **no editado** y que otro punto editado lo convierta en necesario para la comprobación, o cambiar la expectativa a PRECISION si se pretende probar el fallo del punto editado. Mantener `.155/2` para el texto enum acotado.

### E3B3-R2-05 — MINOR — sincronía — `.154` alterna `<axis name>` y nombre de punto

**Ubicación:** `01-requirements.md:246`, frente a `02-test-cases.md:341` y `codewire/graph-inc3.md:832`, `:880`.

La fila y el nodo escriben `<axis name>: the monotony rule …`, que bajo CTX es `C.X`; el caso y el ejemplo esperan `C.X[0]: …`. No es una cuestión cosmética para el oracle: son dos mensajes distintos.

**Corrección requerida:** elegir `<axis point name>` (`C.X[0]`), coherente con la regla aplicada al punto editado y con S-06, y alinear fila, nodo y caso.

### E3B3-R2-06 — MINOR — sincronía de conteos/trazas y oracle de posiciones

**Ubicación:**

- `01-requirements.md:315`: sigue diciendo **3b 12 rows / total 83**, contradiciendo el recuento correcto de `:292` (15 / 86).
- `02-test-cases.md:433`: sigue diciendo que `.120` tiene «1 of 2 cases in 3a»; ahora son 1 de 3.
- `E3-rulings.md:213`: pide ejecutar «all 55 cases», pero el split correcto son 56 (`02-test-cases.md:453-456`).
- `codewire/graph-inc3.md:829`: el `req:` de `encode_values` omite .153, .154 y .155, aunque la cobertura `:246-247` y el nodo sí los incluyen.
- `E1-slice.md:9`: el resumen de filas termina en .147 y omite .153 … .155; la entrada detallada `#21` de `:41` sí está corregida.
- `02-test-cases.md:309`: `.125/4` exige solo «the object's bounded position text», sin fijar el texto de cada forma malformada. Prueba no excepción y longitud, pero no que el formatter conserve la posición ni el mensaje exacto de R-A2L-DEF.125.

**Corrección requerida:** actualizar esas trazas y fijar un expected message por posición, o un esquema exacto de rendering con longitud máxima y escaping.

## Disposición de S-01 … S-10

| Hallazgo previo | Estado R2 | Evidencia |
|---|---|---|
| S-01 final span / índice | **ABIERTO — R2-01** | La longitud final está reglada en `graph-inc3.md:282`; falta garantizar el descubrimiento cross-page. `.140/5-6` solo cubre misma página. |
| S-02 STD `shared_with` | **CERRADO** | `graph-inc3.md:284`, `:692`; `.140/7` (`02-test-cases.md:338`) exige herencia del padre, OVERLAP y cero bytes. |
| S-03 exención array/curve/map | **CERRADO** | `graph-inc3.md:282` prohíbe la exención en cualquier lado; `.140/8` (`02-test-cases.md:339`) cubre ambos sentidos, endianess, segundo elemento y CURVE con puntos. |
| S-04 AXIS_PTS homónimo | **CERRADO** | CLEAN queda limitado a MEASUREMENT/CHARACTERISTIC en `graph-inc3.md:282`; `.140/4` (`02-test-cases.md:335`) tiene máscaras aparentemente disjuntas y exige OVERLAP. BLOB/INSTANCE quedan igualmente excluidos. |
| S-05 formas inversas / coste | **PARCIAL — R2-02** | Formas inmutables por walk y sin rebuild/sort por celda (`graph-inc3.md:154`, `:832`), con límite `.131/2`; falta fijar semántica exacta e inputs discriminantes. |
| S-06 `_name_echo`, layout/ref | **CERRADO** | `graph-inc3.md:284`, `:692`, `:832`: eco + sufijo en nombre, refusals, notices e INDEX; `<layout>`/`<ref>` con `_echo`. |
| S-07 posiciones totales | **CERRADO**, con nota R2-06 | `graph-inc3.md:146`, `:832` valida antes de desempaquetar/offsets; `.125/4` (`02-test-cases.md:309`) cubre todas las formas pedidas y cero excepciones. Falta precisar el texto esperado. |
| S-08 refusal/PARSE/decode/ELEMENTS | **PARCIAL — R2-03** | Grafo y casos corregidos (`graph-inc3.md:390`, `:832`; `.120/3`, `.130/4-5`); CTX sigue sin actualizar (`01-requirements.md:123-125`). |
| S-09 monotonía / breaking point | **PARCIAL — R2-04, R2-05** | .154 y .155 existen, pero `.155/1` es interceptado antes por PRECISION y .154 no fija un único nombre. |
| S-10 scalar `encode_values` | **CERRADO** | Rama explícita en `graph-inc3.md:150`, `:832`; fila .153 (`01-requirements.md:245`) y caso `.153/1` (`02-test-cases.md:340`) cubren number/enum/text, `(0,)` y rechazo de otra posición. |

## Conteos y checks

- **86 rows:** confirmado en `01-requirements.md:292`: S2.7e 19 + S2.7f 29 + S2.7g 20 + S2.7h 15 + S2.7i 3.
- **336 casos:** `02-test-cases.md:429`, `:453-456`: **280 3a + 56 3b**.
- **S2.7g 46:** los 40 3a anteriores más seis 3b (`.120/2-3`, `.121/1-2`, `.130/4-5`).
- **S2.7h 50:** 39 anteriores + `.125/4` + `.131/2` + cinco `.140/4-8` + `.153/1` + `.154/1` + dos `.155/1-2`.
- Se añaden **14** casos 3b sobre los 42 previos; los cinco brazos edit mixtos permanecen pendientes hasta E4, sin que esta revisión exija su ejecución.

**Leído:** ruling correction 1 completo; requisitos CTX, S2.7h y counts/split; los 14 casos nuevos y split/counts; grafo I-2, split, `describe_definitions`, `encode_definition`, `_element_definition`, `encode_values`, `_breaking_point` y entidades; slice `#21-23`, split y resumen; helpers reales `_reverse_table_lookup` y el round trip de `encode_definition` solo para contrastar la semántica diseñada.

**Ejecutado:** ningún test ni sonda, por decisión del encargo: esta R2 evalúa diseño y cobertura, no producto nuevo. Sin pytest en Windows y sin mutaciones Git.
