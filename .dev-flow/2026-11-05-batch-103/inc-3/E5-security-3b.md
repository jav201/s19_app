# Inc 3b — E5 seguridad

## Veredicto: FAIL

**0 HIGH, 3 MAJOR, 4 MEDIUM y 1 MINOR.** Los tres MAJOR bloquean el cierre de E5 y la integración: la optimización lazy permite una escritura dentro de un span over-cap, una tabla con `±inf` lanza una excepción y las formas inversas vuelven a hacer búsquedas lineales con matches aceptados.

Producto revisado: `s19_app/tui/a2l_definition.py`, HEAD `c88cd029829a241fccbc319e5e35022e2c817363` más la optimización actual sin commit. Contratos contrastados: `codewire/graph-inc3.md`, las correcciones 1–2 de `E3-rulings.md` y su nota E4 «lazy candidate materialization» (`E3-rulings.md:239-243`).

La evidencia existente registra **75 passed**, **662 passed** y `.142/5` en **0,103 s**. No se repitió pytest en Windows ni se hicieron mutaciones Git. Las sondas citadas abajo se ejecutaron directamente con `PYTHONDONTWRITEBYTECODE=1 python -B`, en memoria y sin archivos temporales. Los suites verdes no ejercitan los contraejemplos de este informe.

## Hallazgos bloqueantes

### E5S-3B-01 — MAJOR — impl + design-gap — el superset lazy omite spans over-cap y permite escribir dentro de ellos

**Ubicación:** `s19_app/tui/a2l_definition.py:856-870`, `:1002-1012`, `:1057-1064`, `:3856-3872`; `codewire/graph-inc3.md:282`; `E3-rulings.md:239-243`.

El filtro solo conserva candidatos que empiezan en `address - MAX_A2L_DECODE_BYTES + 1` o después. La nota E4 justifica ese corte porque todos los spans cabrían bajo el cap de 1 MiB. Eso no es cierto para MEASUREMENT/CHARACTERISTIC rechazados por longitud: `_describe_one` devuelve `A2L-DEF-ADDRESS` pero conserva su `byte_length` por encima del cap, y `_entry_overlaps` usa esa longitud como intervalo. Es deliberado: R-A2L-DEF.138/10 exige que un vecino length-refused siga bloqueando.

Consecuencia: un span over-cap que empieza antes de la ventana desaparece antes de `materialize`, aunque cubra la dirección editada. **Sonda sobre la API real:** `BIG` en `0x0`, longitud `1048577`, recibe `A2L-DEF-ADDRESS` y conserva `byte_length=1048577`; para `V` en `0x100000`, `describe_definition` devolvió `shared_with is None` y `encode_definition` devolvió `Encoded(address=1048576, data=b'\x07')`. `V` está dentro del último byte de `BIG`: es una escritura fuera del objeto, no un falso positivo.

**Corrección requerida:** retirar la premisa global de 1 MiB del lower bound. El superset debe incluir todo candidato cuya longitud final desconocida o superior al cap pueda alcanzar la dirección, sin convertir una longitud ilegible en un intervalo: el punto fail-closed sigue limitado a su dirección declarada. Añadir el caso over-cap anterior a la ventana y comprobar `shared_with == "BIG"`, OVERLAP y cero bytes. Actualizar también la nota lazy, cuya garantía de completitud es actualmente falsa.

### E5S-3B-02 — MAJOR — impl + design-gap — la interpolación con `±inf` rompe la garantía de no excepciones

**Ubicación:** `s19_app/tui/a2l_definition.py:3623-3644`, `:3667-3675`; contrato de totalidad `:11-14`; oráculo heredado `s19_app/tui/a2l.py:2919-2933`.

Con una tabla TAB_INTP `(0, -inf), (1, inf)` y valor físico `0`, la fórmula de interpolación produce `raw_fraction=nan` y se ejecuta `round(nan)`. La sonda a través de `_encode_number`, con la forma construida por `_build_tab_form`, lanzó `ValueError: cannot convert float NaN to integer`. El oráculo congelado lanza el mismo error; por eso también hace falta una decisión de diseño, no copiar literalmente su excepción.

La tabla llega de contenido A2L y el módulo promete devolver `Refusal` en lugar de lanzar por contenido del archivo o imagen. La matriz `.131/3` cubre NaN como entrada del operador, pero no esta combinación de extremos físicos.

**Corrección requerida:** antes de redondear, rechazar una fracción no finita como tabla no invertible, devolviendo `A2L-DEF-ENCODE` y ningún byte. Registrar la enmienda respecto al oráculo y añadir pruebas de encode con combinaciones `±inf`, NaN y endpoints, además de la comparación de equivalencia para entradas finitas.

### E5S-3B-03 — MAJOR — impl — las formas inversas reintroducen O(M) por match aceptado

**Ubicación:** `s19_app/tui/a2l_definition.py:3557-3584`, especialmente `:3563-3571` y `:3573-3584`; requisito de complejidad `E3-security-3b.md:51-57`; `codewire/graph-inc3.md:154`, `:833`.

La corrección de E3 exigía consulta **O(log M)** por celda. Dos ramas vuelven a recorrer la tabla o una racha completa en cada consulta que sí encuentra raw:

- `inverse_y_nan` hace que `_table_match` recorra `inverse_file`/`inverse_sorted`; una sola entrada NaN envenena todas las consultas.
- En TAB_NOINTP, la búsqueda entre `lo` y `hi` recorre toda la racha dentro de tolerancia para hallar la primera raw en file order. Con muchas entradas del mismo valor físico, un match aceptado vuelve a ser O(M).

Sonda de 64 matches sobre 20.000 entradas: match único, por debajo de la resolución del temporizador; NaN con match tardío, **0,078125 s CPU**; racha duplicada con match, **0,109375 s CPU**. Las raws devueltas eran correctas; el hallazgo es de complejidad y disponibilidad. `.131/2` usa TAB_INTP con valores crecientes y no ejercita ninguna de las dos ramas.

**Corrección requerida:** guardar en la forma inmutable los índices necesarios para obtener el primer match en file order sin recorrer la racha y separar las entradas NaN de la estructura de búsqueda, conservando la semántica del oráculo. Añadir controles de escala TAB_NOINTP con rachas duplicadas y con una entrada NaN, no solo la tabla creciente TAB_INTP actual.

## Otros hallazgos

### E5S-3B-04 — MEDIUM — impl — la vía rápida escalar da longitud provisional a definiciones cuyo span final es un punto

**Ubicación:** `s19_app/tui/a2l_definition.py:796-811`, `:820-826`, `:986-997`, `:1063`, `:3914-3926`.

`is_array_entry` excluye todo VALUE y, en MEASUREMENT, exige que `matrix[1]` sea válido. Sin embargo, un VALUE con MATRIX_DIM múltiple recibe `.145` y `byte_length=None`; una MEASUREMENT con MATRIX_DIM múltiple malformada se clasifica como array y también termina sin longitud. La vía rápida usa entonces `tag.length` en lugar del punto fail-closed final.

Sonda: VALUE `VMD` en `0x10`, longitud provisional 2 y `MATRIX_DIM 2 2` terminó con `A2L-DEF-MATRIX` y `byte_length=None`; el VALUE limpio `V` en `0x11` obtuvo `shared_with == "VMD"` y OVERLAP, aunque el span final de `VMD` solo cubre `0x10`. La discrepancia también impide reconocer la entrada propia en `_shared_with`, pudiendo producir un autónombre en el objeto rechazado. No se observó escritura insegura en esta variante: el impacto es denegar una edición válida y romper la invariante de span final.

**Corrección requerida:** usar la vía rápida solo cuando se garantiza que la longitud final es la del tag. Pasar por `describe_name` todo VALUE con MATRIX_DIM múltiple y toda MEASUREMENT con MATRIX_DIM múltiple, válida o malformada. Añadir ambos vecinos fuera del punto final, comprobando ausencia de OVERLAP.

### E5S-3B-05 — MEDIUM — impl — `element_name` no es total ni aplica el echo acotado

**Ubicación:** `s19_app/tui/a2l_definition.py:2905-2911`; contrato `codewire/graph-inc3.md:146`, `:701-708`; camino seguro separado `s19_app/tui/a2l_definition.py:4160-4232`.

La función pública sigue usando `definition.name` crudo, desempaqueta `letter, k` antes de validar e itera cualquier posición. Sonda: un nombre de 300 caracteres produjo una salida de 303, no el echo de 256 más `…` y sufijo; `("X",)` y `("X",0,1)` lanzaron `ValueError`; `None` y `0` lanzaron `TypeError`.

`encode_values` sí valida con los helpers totales posteriores, por lo que este hallazgo no reabre su escritura; queda expuesta la API pública I-2 y su contrato explícito de formatter total y acotado.

**Corrección requerida:** unificar `element_name` con `_position_label`, `_name_echo_of` y `_position_repr`, manteniendo los nombres válidos ya fijados. Añadir pruebas directas de la función pública para nombre largo/controlado y todas las formas de `.125/4`.

### E5S-3B-06 — MEDIUM — impl — TAB_NOINTP no reproduce los dos valores más próximos del oráculo

**Ubicación:** `s19_app/tui/a2l_definition.py:3506-3554`, `:3595-3609`; oráculo `s19_app/tui/a2l.py:2891-2904`.

La ventana alrededor de la bisección no conserva necesariamente los dos mejores globales ni el desempate por file order. En particular, al recortar la racha anterior puede conservar solo un duplicado tardío y perder la primera entrada a igual distancia. Con entradas `(2, -1e-9), (5, 0.5), (7, 2.0)` y físico `1e308`, el oráculo devuelve vecinos `-1e-09 and 0.5`; la forma optimizada devuelve `0.5 and 2.0`.

Una sonda determinista de 20.000 tablas finitas encontró **82 diferencias, todas de texto/reason y ninguna de raw, aceptación o flag**. Otra muestra con NaN/infinitos también mostró razones distintas. No se encontró escritura distinta en esa muestra, pero `.131/3` y el grafo exigen el comportamiento exacto del oráculo.

**Corrección requerida:** conservar la bisección para matches aceptados y reglar por separado la selección de vecinos en el rechazo, incluyendo duplicados, distancias redondeadas y no finitos. Añadir el contraejemplo finito y un diferencial que distinga raw/flag de reason.

### E5S-3B-07 — MEDIUM — impl — los límites se copian sin echo y superan el máximo de mensaje

**Ubicación:** `s19_app/tui/a2l_definition.py:558-568`, `:3470-3502`; R-A2L-DEF.151 y su alcance sobre `<lower>/<upper>` en `.dev-flow/2026-11-05-batch-103/inc-2/01-requirements.md:165`, `:291`.

`_read_limits` conserva `lower_text`/`upper_text` con `str(word)` y `_check_limits` los inserta literalmente en refusals y notices. Una palabra numérica larga puede ser válida y producir un mensaje arbitrariamente grande, pese a la regla de 256 caracteres por palabra y 1.024 por mensaje.

Sonda: límite inferior formado por 2.000 ceros y un `1`, al codificar `0`, produjo `A2L-DEF-LIMITS` con **2.031 caracteres**. El camino se reutiliza para cada elemento/punto de Inc 3b.

**Corrección requerida:** aplicar `_echo` a los cuatro textos de límites en el punto de lectura o al componer el mensaje, sin cambiar los valores numéricos usados en comparaciones. Añadir palabras largas y caracteres no imprimibles a límites normales y extendidos, comprobando el máximo de 1.024 caracteres.

### E5S-3B-08 — MINOR — impl — el docstring conserva el diseño eager retirado

**Ubicación:** `s19_app/tui/a2l_definition.py:593-600`, frente a `:848-875` y `E3-rulings.md:239-243`.

El docstring afirma que todo candidato se materializa y que su span final se indexa en cada página. El código ya no construye ese índice: filtra direcciones por cada solicitado y materializa bajo demanda. El grafo y la nota E4 sí describen el mecanismo nuevo. Actualizar el docstring al corregir E5S-3B-01 para no volver a legitimar una garantía equivocada.

## Comprobaciones sin hallazgo adicional

- **CLEAN, arrays y homónimos:** `_pair_exempt` limita la exención a escalares number/enum limpios de MEASUREMENT/CHARACTERISTIC y la excluye para arrays, CURVE/MAP, AXIS_PTS, BLOB e INSTANCE (`a2l_definition.py:3824-3853`). `mask_of` exige la definición limpia y los homónimos duplicados quedan sin exención.
- **AXIS_PTS, BLOB e INSTANCE:** se conserva el orden global de secciones y dirección `0x0`; los spans BLOB/INSTANCE sí pasan por `_bounded_length` (`a2l.py:354-360`, `:3894-3993`). El caso cross-page normal `.140/9` queda cubierto, pero no invalida el over-cap de E5S-3B-01.
- **Orden de encode:** definition refusal → PARSE → decode/ELEMENTS → posiciones → ediciones → monotonía; OVERLAP permanece tardío dentro de `encode_definition` (`a2l_definition.py:4029-4144`, `:4307-4438`).
- **Posiciones hostiles en encode:** validación antes de offsets, `repr` acotado y rama escalar `(0,)` correctos. El hallazgo E5S-3B-05 se limita a la función pública separada.
- **Monotonía:** regla desconocida rechazada antes de bytes, comparación sobre stored values y propagación del refusal de un punto necesario; los textos de ruptura usan `_operator_echo`.
- **Escritura de arrays:** posiciones validadas antes de `_element_offset`/`_point_offset`, registro copiado de la imagen y solo las celdas aceptadas sustituidas; los bytes no editados se conservan.
- **Aliases:** las formas compartidas usan tuplas, dataclasses congelados y `MappingProxyType`; no se encontró una nueva mutación de `a2l_data` o `image` en las rutas revisadas.
- **Duplicate-describe oracle:** `.140/9` instrumenta `_describe_one` y exige una construcción de `V` y una de `CX` para `describe_definitions(["V", "V"])` (`tests/test_b103_a2l_definition_arrays_write.py:900-922`), incluido en la familia verde.

## Evidencia y límites de la revisión

- `evidence-e4/write3b-run4-int.txt`: **75 passed in 47.97s**.
- `evidence-e4/write3b-family-run5.txt`: **662 passed in 76.22s**; `.142/5` **0,103 s / 1,000 s** y `.142/6` 0,522 s / 5,000 s.
- `evidence-e4/write3b-perf-142-5-direct.txt`: **1 passed**, `.142/5` 0,103 s; las aserciones del test incluyen el pico de memoria.
- Como comprobación informativa, no como sustituto del oracle serial de tres ejecuciones, una llamada directa a `describe_definitions` sobre los **13.990** nombres de `software_a` terminó en **1,224 s** y devolvió 13.990 definiciones. El filtro lazy es O(nombres solicitados × spans con dirección), por lo que conviene conservar una medida de escala con todos los objetos direccionados; el fixture contiene 3.452 tags con dirección.
- `steps.log:45` deja scale/perf/law/mutants pendientes tras la última optimización. Las transcripciones intermedias RED o de versiones anteriores no se usaron como evidencia del estado final.

Para cerrar: corregir primero E5S-3B-01 … -03, añadir sus contraejemplos como pruebas discriminating RED/GREEN y repetir la familia funcional, `.140`, `.131`, `.142/5`, escala, law guards y mutantes sobre el árbol final. Los MEDIUM también tienen reproducción directa y deben quedar cubiertos antes de dar por sincronizados implementación y contratos.
