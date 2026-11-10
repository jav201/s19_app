# Inc 2b E5 — revisión de código R3

**Veredicto: FAIL.** Hay un hallazgo **HIGH de implementación** que permite omitir
`A2L-DEF-OVERLAP` frente a un BLOB o INSTANCE; bloquea la integración. El último cambio de
`_shared_with` sí corrige el orden global multipágina señalado en R2 y no se le encontró una
regresión propia. El hallazgo bloqueante ya existía en la forma revisada en R2: no fue
introducido por la restauración del orden global.

Base revisada: HEAD `1147a6e9e2292a423330fab33071338b67958bec` y los cambios de
documentación presentes en el árbol. Los archivos de producto y pruebas del alcance están
limpios respecto de HEAD. El cambio de producto posterior a R2 procede de `4ab76337`.

## Ejecutado frente a leído

- **Ejecutado por este revisor:** nada. Revisión estática en Windows, sin pytest, probes ni
  mutaciones git.
- **Evidencia ejecutada por el orquestador, solo leída aquí:**
  `evidence-e4/int2b-run13-main.txt`: **321 passed in 15.55s**;
  `evidence-e4/int2b-red-stub-final8-main.txt`: **124 failed, 197 passed in 28.91s**.
  La lista RED incluye `.138/22` y los demás casos `.138` del alcance. Estas ejecuciones no
  cubren el contraejemplo del hallazgo E5R3-1.
- **Leído:** `s19_app/tui/a2l_definition.py` (índice de spans y `mask_of` :585-738; helpers
  CLEAN :3475-3589; `encode_definition` y helpers :3241-3472, :3592-3806),
  `tests/test_b103_a2l_definition.py` (:2404-3670),
  `tests/test_b103_synth_definitions.py` (completo), los contratos indicados de
  `01-requirements.md` y `codewire/graph-inc2.md`, R2, y el diff `ce1aa0ec..HEAD` del alcance.
  Para la alineación y acotación de BLOB/INSTANCE se leyó también
  `s19_app/tui/a2l.py:354-360,3894-4009,4050-4056`.

## Hallazgo bloqueante

### E5R3-1 — HIGH · implementación · BLOB/INSTANCE puede tomar la máscara de un tag homónimo y quedar exento

`_pair_exempt` obtiene la máscara del vecino únicamente con `mask_of(entry[1])`
(`s19_app/tui/a2l_definition.py:3511`), sin mirar el tipo guardado en `entry[2]`. A su vez,
`mask_of` describe ese nombre como MEASUREMENT/CHARACTERISTIC y devuelve su `bit_mask` cuando
esa definición está limpia (`s19_app/tui/a2l_definition.py:697-714`). Las entradas BLOB e
INSTANCE sí llevan su tipo en el índice (`s19_app/tui/a2l_definition.py:643-657`), pero ese
tipo nunca impide la exención.

Esto contradice directamente el diseño: **“BLOB and INSTANCE have no mask exemption”**
(`codewire/graph-inc2.md:450`). También viola R-A2L-DEF.138 (`01-requirements.md:210`), cuya
excepción exige que las máscaras de **ambos objetos** hayan sido leídas y que ambas
definiciones estén limpias; un BLOB/INSTANCE no adquiere una máscara por compartir nombre con
otro objeto.

Contraejemplo estático válido para la tubería leída:

- `MW`: UWORD VALUE big-endian en `0x10`, `BIT_MASK 0x000F`;
- BLOB `B`: span `0x10..0x11`;
- UBYTE VALUE `B`: en otra dirección, por ejemplo `0x100`, definición limpia con
  `BIT_MASK 0x0F`.

Para `MW`, `_pair_exempt` toma `0x0F` del tag `B` como si fuese máscara del BLOB. Los bits
calculados son `{0x11: 0x0F}` para `MW` y `{0x10: 0x0F}` para el BLOB; como no comparten bit,
la pareja queda exenta. El BLOB real no tiene máscara y su span incluye `0x11`, byte que `MW`
sí escribe. Después, el tag `B` en `0x100` no solapa, por lo que `MW.shared_with` resulta
`None` y `encode_definition` puede devolver `Encoded` (`a2l_definition.py:3800-3806`) en lugar
del obligatorio `A2L-DEF-OVERLAP` que nombra `B`. La misma traza aplica a INSTANCE.

La colisión cross-kind no queda bloqueada por el gate de parseo: la construcción del payload
extrae tags y declared spans por separado (`s19_app/tui/a2l.py:4050-4056`) y R-A2L-DEF.139
solo rechaza duplicados entre tags o secciones MEASUREMENT/CHARACTERISTIC
(`a2l_definition.py:996-1009`). Las pruebas `.138/2`-`.138/4`
(`tests/test_b103_a2l_definition.py:3180-3202`) usan nombres distintos para el tag y el
BLOB/INSTANCE, por lo que no discriminan esta rama.

**Corrección necesaria:** hacer fail-closed la exención cuando `entry[2]` sea `BLOB` o
`INSTANCE`, antes de consultar `mask_of`, y añadir casos con colisión de nombre cross-kind que
verifiquen tanto `shared_with` como el rechazo exacto de encode. Como mínimo, el ejemplo
anterior debe producir `MW.shared_with == "B"` y
`MW: its bytes at 0x10 are shared with B`.

## Comprobación del último cambio de `_shared_with`

El diff posterior a R2 reúne candidatos y, solo para un span multipágina, los deduplica por
`entry[0]` y los ordena por esa posición (`a2l_definition.py:3561-3575`). La posición procede
de un único recorrido preorden (`a2l_definition.py:601-670`), por lo que es estable y única por
sección. Así se restaura el orden global cross-kind, no el orden página-mayor de R2.

- La lista de una sola página conserva el orden de archivo y evita set/ordenación, como antes.
- En multipágina, cada entrada replicada en varias páginas aparece una sola vez y la primera
  ocurrencia tras la ordenación es la de archivo.
- La exclusión propia sigue ejecutándose una única vez con los cinco campos
  (`a2l_definition.py:3574-3584`), ahora sobre el orden global; la deduplicación previa no la
  rompe.
- `.138/22` (`tests/test_b103_a2l_definition.py:3376-3386`) es discriminariedad correcta:
  `LATE` se declara antes pero está en una página posterior a `EARLY`; exige `LATE` tanto en
  `shared_with` como en el mensaje. La variante página-mayor devolvería `EARLY`.
- R-1 de R2 queda resuelto. R-2 de R2 también quedó corregido en documentación: el BLOB hostil
  se describe como indexado fuera del alcance del span.
- No se encontró una regresión de corrección introducida por este cambio. La evidencia de
  rendimiento ya ejecutada `int2b-perf-fix-136-multipage.txt` registra `.136` en **1.453 s /
  2.000 s, 1 passed**; este revisor no la repitió.

## Resto del alcance, sin hallazgos adicionales

Lectura estática y de las pruebas, no nuevas ejecuciones:

- **CLEAN y duplicados entre tags:** la exención exige definición propia limpia, longitudes
  legibles y ambas máscaras no nulas (`a2l_definition.py:3498-3521`). Un vecino con rechazo de
  longitud, byte order o nombre duplicado recibe `None` de `mask_of`; `.138/10`-`.138/13` lo
  fijan. El único escape encontrado es la homonimia cross-kind de E5R3-1.
- **Byte order:** `_selected_bits` coloca el byte bajo de la máscara según endianness
  (`a2l_definition.py:3484-3495`); `.138/17` y las escrituras big/little de `.46`, `.53` y el
  caso sintético fijan el comportamiento.
- **BLOB/INSTANCE fuera de E5R3-1:** el recorrido de `extract_declared_spans` y el consumo por
  `ds_index` son ambos preorden; las longitudes se acotan con `_bounded_length`, y una longitud
  ilegible queda como punto fail-closed. `.138/2`-`.138/9` y `.138/21` cubren sized, unsized y
  números hostiles.
- **Precisión numérica frente a enum:** el round-trip y la comprobación decimal exacta solo se
  ejecutan en la rama `kind == "number"` (`a2l_definition.py:3762-3798`); enum codifica el raw
  de la primera entrada textual y no pasa por ese guard. `.54`, `.55`, `.48` y `.56` son
  coherentes con esta separación.
- **Orden parse/overlap:** rechazo propio, errores de parseo, validación del valor, límites,
  conversión, bytes de imagen, máscara, precisión/límites escritos y solape al final
  (`a2l_definition.py:3691-3806`); texto usa la misma colocación del solape tras validar texto e
  imagen. `.57` y `.152` fijan los controles negativos relevantes.
- **Inmutabilidad:** encode construye vistas nuevas de tag/método, una imagen temporal para el
  round-trip y bytes nuevos; no escribe en `a2l_data` ni en `image`. Las pruebas `.58.1`
  comparan deep copies antes/después.
- **Textos acotados:** nombres/tablas/vecinos usan `_echo`, texto del operador `_operator_echo`
  y números potencialmente enormes `_number_text`; `.151/7` y los casos hostiles comprueban
  truncado, sanitización y ausencia de excepciones.
- **Caso sintético:** las pruebas de escritura ejercitan enum, máscaras disjuntas y conservación
  de bits, byte order big-endian, segundo valor y no alteración de los demás bytes
  (`tests/test_b103_synth_definitions.py:316-371`).
