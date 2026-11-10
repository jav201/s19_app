# Inc 3b — E3 seguridad

**Veredicto: FAIL.** Hay **5 MAJOR**, **4 MEDIUM** y **1 MINOR**; los MAJOR bloquean E4. Cuatro riesgos de escritura fuera del objeto o de omisión de solape están confirmados sobre el producto actual, no solo inferidos del grafo. La falta de `encode_values` y `_breaking_point` es el estado esperado antes de E4 y se registra como cobertura no ejecutable, no como otro hallazgo.

Base: `8cb8f479ece7279eb635794160dde01f55eee1c2`, con Inc 2b integrado. Alcance: las 12 filas de escritura de `01-requirements.md:229-244`, los 42 casos 3b y los 5 casos mixtos de `02-test-cases.md`, el split y los nodos `encode_definition`, `encode_values` y `_breaking_point` de `codewire/graph-inc3.md`, contrastados con `s19_app/tui/a2l_definition.py` y las rutas reutilizadas de `s19_app/tui/a2l.py`.

## Hallazgos

### E3B3-S-01 — MAJOR — impl + design-gap — el índice usa `tag.length`, no el span calculado por 3a

**Ubicación:** `codewire/graph-inc3.md:279`; `s19_app/tui/a2l_definition.py:627-636`, `:3535-3542`, `:3516-3520`, `:3485-3495`.

El grafo ordena conservar en el índice la longitud del tag incluso para los nuevos tipos. La implementación hace exactamente eso al crear `span_entries`, mientras `_describe_array` calcula después otra `Definition.byte_length`. `_entry_overlaps` reduce una longitud `None` a un punto en la dirección inicial, aunque 3a sí pueda colocar el registro completo. Por tanto, un objeto interior al registro no ve al array/curve/map como vecino.

**Confirmación ejecutada:** una CURVE COM de cuatro valores UWORD en `0x20` tenía `tag.length is None` y `Definition.byte_length == 8`; un VALUE en `0x21`, dentro de ese registro, obtuvo `shared_with is None`. Además, al poner máscaras CLEAN en ambos, la propia descripción terminó en `TypeError: 'NoneType' object cannot be interpreted as an integer`: `mask_of("C")` obtiene una máscara de la definición calculada, pero `_selected_bits` recibe la longitud `None` de la entrada del tag y ejecuta `range(None)`.

Esto reabre tanto una escritura sobre otro objeto como la promesa de no lanzar ante contenido del A2L. Los casos `.140/1-3` solo cubren AXIS_PTS y no detectan ninguna de las dos variantes.

**Corrección requerida:** construir el índice con la misma `Definition.byte_length` final que gobierna decode/encode, y usar ese mismo span en `_selected_bits`; no mezclar la definición CLEAN calculada con la longitud del tag. Añadir: (a) VALUE no enmascarado dentro de una CURVE cuyo tag carece de longitud → OVERLAP; (b) la variante enmascarada → resultado sin excepción y sin exención espuria. Mantener el punto fail-closed solo cuando ni el reader ni 3a pueden calcular longitud.

### E3B3-S-02 — MAJOR — impl + design-gap — un punto STD pierde el `shared_with` del objeto

**Ubicación:** `codewire/graph-inc3.md:281`, `:684`, `:824`; `s19_app/tui/a2l_definition.py:1882-1908`, `:2852-2866`.

El camino de valores hace `replace(definition, …)` y hereda el solape del objeto. El de puntos hace `replace(points, …)`, pero `AxisDefinition.points` se construye con `shared_with=None`. COM y FIX se rechazan antes; STD llega a `encode_definition` sin la guarda aunque el `Encoded` final contenga el registro completo de la CURVE/MAP.

**Confirmación ejecutada:** una CURVE STD de 12 bytes en `0x10`, con otro objeto en `0x12`, tenía `C.shared_with == "OTHER"`; su punto `X[0]` tenía `point.shared_with is None` y `encode_definition(point, …, "5", image)` devolvió `Encoded(address=0x10, data=b"\x05")`.

**Corrección requerida:** propagar `shared_with=definition.shared_with` también en el `replace` de puntos. Añadir un punto STD de una CURVE solapada: OVERLAP y ningún byte, aunque el punto concreto no toque al otro objeto, pues se devuelve el registro entero.

### E3B3-S-03 — MAJOR — impl + design-gap — CLEAN aplica una máscara una sola vez al registro completo de un array

**Ubicación:** `s19_app/tui/a2l_definition.py:2867-2884`, `:3475-3495`, `:3498-3523`; el grafo solo cita `_selected_bits` de 2b y no adapta su modelo a arrays.

Cada elemento hereda `bit_mask` y lo aplica a su propio datatype. En cambio, la exención calcula los bits del objeto con `_selected_bits(address, byte_length, byte_order, mask)` sobre el registro completo. Para un array, la máscara debe repetirse por elemento; para CURVE/MAP solo corresponde a FNC_VALUES, no a puntos ni contadores. La fórmula actual la coloca una vez sobre `byte_length`, produciendo bits distintos y exenciones falsas.

**Confirmación ejecutada:** un VAL_BLK de dos UWORD en `0x10`, `BIT_MASK 0x000F`, y un UBYTE en `0x12`, `BIT_MASK 0x0F`, quedaron ambos con `shared_with is None`; el escalar aceptó `Encoded(address=0x12, data=b"\x01")`. Sin embargo, `0x12` es el segundo elemento del VAL_BLK y su máscara selecciona allí los mismos bits.

**Corrección requerida:** la opción segura inmediata es no conceder exención cuando cualquiera de los lados sea array/curve/map. Si se conserva la funcionalidad, calcular los bits por componente y por elemento con la definición final, nunca una única máscara sobre todo el registro. Añadir los dos sentidos del par y las variantes little/big endian, segundo elemento y CURVE con puntos.

### E3B3-S-04 — MAJOR — design-gap — AXIS_PTS puede heredar la máscara CLEAN de un tag homónimo

**Ubicación:** `codewire/graph-inc3.md:279`, `:336-337`; `s19_app/tui/a2l_definition.py:697-715`, `:3498-3523`.

El grafo añade entradas AXIS_PTS al índice, pero `_pair_exempt` solo impide consultar `mask_of` para BLOB e INSTANCE. Para una futura entrada AXIS_PTS, `mask_of(entry[1])` describe un MEASUREMENT/CHARACTERISTIC homónimo y le presta su máscara al AXIS_PTS. Un AXIS_PTS no tiene una máscara CLEAN propia y R-A2L-DEF.140 no admite exención.

**Confirmación ejecutada:** con una entrada `(name="AX", kind="AXIS_PTS", address=0x10, length=5)`, un UWORD `MW` con máscara `0x0F00` y un UBYTE homónimo `AX` en `0x100` con máscara `0x0F`, `_pair_exempt` devolvió `True`. El mismo mecanismo queda correctamente bloqueado para BLOB/INSTANCE por `:3511-3512`.

**Corrección requerida:** permitir la consulta de máscara únicamente para entradas MEASUREMENT/CHARACTERISTIC; AXIS_PTS, BLOB e INSTANCE nunca se eximen. Añadir el caso homónimo a `.140`, conservando `shared_with` y OVERLAP.

### E3B3-S-05 — MAJOR — design-gap — el coste de encode crece como ediciones × tamaño de tabla

**Ubicación:** `codewire/graph-inc3.md:824`; `s19_app/tui/a2l_definition.py:3346-3385`, `:3422-3437`; `s19_app/tui/a2l.py:2870-2937`.

Cada posición delega en `encode_definition`. Para TAB_INTP/TAB_NOINTP, `_encode_number` llama a `_reverse_table_lookup`, que reconstruye `numeric`, lo ordena y puede volver a recorrer la tabla en cada edición: O(M log M) por celda, seguido en TAB_INTP de otra búsqueda lineal. `_encode_enum` también recorre las entradas por texto en cada celda. N posiciones sobre una tabla de M entradas cuestan O(N·M log M), sin que los 42 casos fijen un límite de encode ni una forma reducida inversa. El decode previo ya puede recorrer hasta 1.048.576 elementos; el encode no debe multiplicar además el trabajo por el tamaño de una tabla compartida hostil.

**Corrección requerida:** reutilizar formas reducidas inversas construidas una vez por walk (texto enum → primera entrada; tabla numérica ordenada para inversión), con una consulta O(log M) por celda y sin copiar/ordenar la tabla por edición. Añadir un caso de escala con tabla grande y múltiples posiciones, y su control negativo que reintroduce la reconstrucción por celda. Este hallazgo es de complejidad leída; no se ejecutó benchmark.

### E3B3-S-06 — MEDIUM — impl + design-gap — los mensajes de encode pierden el sufijo del elemento/punto

**Ubicación:** `codewire/graph-inc3.md:85`, `:824`; `s19_app/tui/a2l_definition.py:2766-2772`, `:2865-2884`, `:3290-3297`, `:3693-3695`.

`_element_definition` cambia `name` a `V[1,2]` o `C.X[1]`, pero conserva `_name_echo` del objeto (`V`) o del eje (`C.X`). Todos los helpers de encode prefieren `_name_echo`, por lo que límites, enum, precisión, extended limits, overlap y notices no nombran la celda. El nodo además prescribe `element_name` para `<position>`, reintroduciendo el nombre completo que E3S3-37 había retirado y dejando sin el límite R-A2L-DEF.151 ese mensaje.

**Confirmación ejecutada:** para `AR[1]`, `encode_definition` con `abc` devolvió `A2L-DEF-NUMBER` con `AR: 'abc' is not a number`, no `AR[1]: …`.

**Corrección requerida:** fijar `_name_echo` al eco del objeto/eje más `[i,j]` o `[k]` al construir cada definición elemental; componer igual `<position>` y notices. Aplicar `_echo` también a `<layout>` y `<ref>` en AXIS-NONE/SHARED. Alinea `.121`, `.122/3,5-7` y la regla de mensajes acotados.

### E3B3-S-07 — MEDIUM — design-gap — posiciones malformadas pueden lanzar antes de A2L-DEF-INDEX

**Ubicación:** `codewire/graph-inc3.md:146-147`, `:696`, `:824`; `s19_app/tui/a2l_definition.py:2766-2772`.

El contrato exige A2L-DEF-INDEX para cualquier posición que no sea un índice válido y el grafo añade «any other form». Sin embargo, `element_name` desempaqueta `letter, k = position` cuando el primer elemento es `str`, e itera `position` en el otro camino. `("X",)`, `("X",0,1)`, `None` o un entero lanzan antes de que la validación pueda devolver el refusal. Los tres casos `.125` solo prueban índices enteros fuera de rango, longitud incorrecta y un eje en un array.

**Confirmación ejecutada:** `element_name(definition, ("X",))` lanzó `ValueError: not enough values to unpack`.

**Corrección requerida:** validar la forma antes de calcular offsets y usar un formateador total y acotado para toda posición rechazada, sin destructuración previa. Añadir tuplas de eje cortas/largas, índice no entero, `None`, escalar no iterable, negativos y letra desconocida; todos → A2L-DEF-INDEX, cero excepciones y ningún byte.

### E3B3-S-08 — MEDIUM — design-gap — PARSE no tiene un orden consistente con decode/ELEMENTS

**Ubicación:** `codewire/graph-inc3.md:383`, `:824`; `s19_app/tui/a2l_definition.py:3693-3710`; R-A2L-DEF.152 y el orden de Inc 2 en `../inc-2/01-requirements.md:108-110`, `:215`.

El código integrado de `encode_definition` aplica `refusal → PARSE → ELEMENTS`, mientras el grafo dice `refusal → ELEMENTS → pasos 2…10`. Más importante: `encode_values` empieza por `decode_values`, que comprueba bytes de imagen antes de que cualquier elemento alcance la guarda PARSE. Con errores de parseo y bytes ausentes devolvería BYTES; con errores y posición inválida podría devolver decode/INDEX en lugar de PARSE. R-A2L-DEF.152 no contiene una excepción para arrays.

**Corrección requerida:** fijar una única secuencia `definition.refusal → PARSE → decode/ELEMENTS → posiciones → edits → monotonía`, manteniendo OVERLAP en el paso tardío de cada elemento. Alinear el nodo y CTX con esa decisión; añadir PARSE + bytes ausentes, PARSE + posición inválida y PARSE + single encode de array. No cambiar el orden en código sin corregir antes la contradicción documental.

### E3B3-S-09 — MEDIUM — design-gap — monotonía no cierra reglas desconocidas ni textos de punto no decodificables/acotados

**Ubicación:** `s19_app/tui/a2l_definition.py:1912-1916`, `:2965-2973`; `codewire/graph-inc3.md:824`, `:869-879`.

`_read_axis` acepta cualquier palabra tras MONOTONY, mientras `_breaking_point` solo define siete reglas. No se prescribe si una palabra desconocida rechaza o si se comporta como NOT_MON; una lectura permisiva aceptaría cualquier orden. Además, decode conserva refusals por punto, de modo que el paso 1 no necesariamente devuelve un `Refusal` global. Si el punto que rompe el prefijo tiene un refusal de conversión, el paso 4 no tiene definido de dónde obtener su `<point text>`. Para un eje enum, ese texto puede ser además una entrada compartida de tamaño arbitrario; el nodo no aplica la regla de eco acotado al construir el refusal.

**Corrección requerida:** fail closed para una regla desconocida antes de escribir; propagar un refusal de un punto necesario para monotonía (o definir explícitamente su prioridad bajo `.124`), y escribir el texto del punto con el límite aplicable, conservando los textos numéricos exactos de `.129/1-9`. Añadir MONOTONY desconocida, un breaking point con conversión inválida y una entrada enum larga; ninguno puede terminar en bytes, excepción o mensaje ilimitado.

### E3B3-S-10 — MINOR — design-gap — la rama scalar de `encode_values` no existe en el algoritmo

**Ubicación:** `codewire/graph-inc3.md:150`, frente a `:822-824`; `01-requirements.md:300`.

I-2 promete para number/enum/text la posición `(0,)` delegando en `encode_definition`. El algoritmo operativo solo valida contra `definition.shape`, que es `()` en un scalar, por lo que `(0,)` cae en INDEX. El propio split reconoce que esta mitad todavía no tiene fila ni caso.

**Corrección requerida:** escribir la rama scalar explícita y sus casos aceptado/rechazado para los tres tipos, o retirar scalar de I-2. No derivar el contrato scalar de la validación de arrays.

## Comprobado sin otro hallazgo

- BLOB e INSTANCE ya entran desde `declared_spans` (`a2l_definition.py:643-658`) y nunca reciben exención por máscara (`:3511-3512`); para tags, CLEAN exige definición sin refusal (`:697-715`). Estas dos guardas no se rebajan: S-04 las extiende a AXIS_PTS.
- Las longitudes del reader se acotan con `_bounded_length` (`a2l.py:354-360`, `:3803-3811`), evitando el antiguo llenado de páginas por una longitud hostil. S-01 es otra divergencia: longitud del tag frente a longitud final del modelo.
- El diseño rechaza FIX/COM/ejes sin puntos antes de delegar, decodifica antes incluso para COM y comprueba monotonía después de todos los edits (`graph-inc3.md:824`). Los offsets ROW/COLUMN e INDEX_INCR/DECR existen y coinciden con el decode (`a2l_definition.py:2789-2813`).
- La copia local del registro y la sustitución solo de celdas editadas preservan contadores y demás bytes; no se reencodea desde display texts. Las formas compartidas leídas son tuplas, frozen dataclasses o `MappingProxyType`, sin alias mutable nuevo exigido por 3b. Los brazos edit de `.58.1/arr-1,2` siguen siendo la prueba necesaria de que image y `a2l_data` no cambian.

## Checks leídos vs ejecutados

**Leídos, no ejecutados como tests:** los 42 casos 3b (`02-test-cases.md:285-329`) están `gap/not_run`; los cinco mixtos (`.58.1/arr-1,2`, `AT-B103-I3-1,2,3`) están `partial`, con el brazo edit pendiente. Se leyeron además `01-requirements.md:70-134`, `:229-246`, `:258-273`, split `:291-312`; `codewire/graph-inc3.md:114-160`, `:262-293`, `:379-387`, `:680-879`; y las rutas actuales de describe/índice/decode/encode citadas arriba.

**Ejecutado por este revisor:** sondas directas `python -B` sobre el parser y el modelo reales, con temporales fuera del repo, `PYTHONDONTWRITEBYTECODE=1`, sin pytest ni mutaciones Git. Confirmaron: (1) `encode_values` y `_breaking_point` ausentes; (2) `tag.length=None` frente a span 8 y `shared_with=None` dentro de CURVE; (3) VALUE en el último byte de AXIS_PTS aceptando `data=b"#"`; (4) exención falsa por máscara repetida con `Encoded(data=b"\x01")`; (5) `TypeError` con máscara y longitud de tag `None`; (6) punto STD aceptando bytes pese al solape del padre; (7) `_pair_exempt(AXIS_PTS)` verdadero por homónimo; (8) mensaje `AR:` en lugar de `AR[1]:`; (9) `ValueError` en posición `("X",)`.

**No ejecutado:** pytest, los 42 casos/5 brazos edit, benchmarks de complejidad ni una llamada end-to-end a `encode_values` (la API todavía no existe). Las conclusiones de S-05 son análisis de complejidad del código, no medidas de tiempo.
