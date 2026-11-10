# E3 architect — Inc 3b, re-review r2

## Veredicto: FAIL

A-01…A-05 están cerrados en el diseño corregido. Queda **1 hallazgo MAJOR nuevo** en la materialización bajo demanda del índice de spans; bloquea E4 porque vuelve a permitir una escritura sobre otro objeto. No se exige GREEN: esta revisión evalúa únicamente registros y diseño, sin producto nuevo.

## Bloqueo restante

### E3B3R2-A-01 — MAJOR — design-gap — la selección por páginas provisionales no descubre todos los spans finales

**Ubicación:** `codewire/graph-inc3.md:282`, con el caso insuficiente en `:342` y `02-test-cases.md:336`; contrato R-A2L-DEF.138 y la ampliación final de `01-requirements.md:244`; ruling S-01 en `E3-rulings.md:204`.

La corrección usa acertadamente `Definition.byte_length` como span final, pero ordena materializar un candidato no solicitado únicamente cuando ya aparece en una página tocada por una definición solicitada. Antes de materializarlo, su archivo provisional puede ser solo el punto de su dirección declarada, precisamente cuando `tag.length` es `None`. Así, el algoritmo no puede descubrir que el span final alcanza otra página.

Contraejemplo directo: una CURVE no solicitada empieza en `0x20`, su tag no tiene longitud y su definición final calcula 64 bytes (`0x20…0x5F`); un VALUE solicitado está en `0x40`. La CURVE queda archivada provisionalmente solo en la página `0x2`, mientras el VALUE toca la página `0x4`; la CURVE nunca se materializa y el VALUE obtiene `shared_with=None`, pese a estar dentro de su registro. El mismo falso negativo aparece con una longitud provisional corta que no llega a la página del objeto solicitado.

`.140/5` no discrimina esta rama: CURVE y VALUE están en `0x20…0x27` y `0x21`, ambos en la página `0x2`. Por eso el caso nuevo pasa por la selección provisional sin demostrar descubrimiento entre páginas.

**Corrección requerida:** hacer completa la selección de candidatos antes de calcular `shared_with`; no basta consultar las páginas del span provisional. Una estrategia válida debe localizar también candidatos cuya dirección inicial pueda comenzar un registro que alcance el span solicitado, materializarlos una vez con caché y archivar después el span final en todas sus páginas. Añadir un caso con tag sin longitud o longitud provisional corta, vecino en otra página y resultado `A2L-DEF-OVERLAP`; conservar el punto fail-closed solo cuando el modelo final tampoco calcula longitud.

## Notas no bloqueantes

### E3B3R2-N-01 — MINOR — bookkeeping — quedan conteos y listas secundarias sin rebasar

Los totales principales sí son correctos: **86 rows** (`01-requirements.md:292`), **336 = 280 + 56 casos** y **S2.7g 46 / S2.7h 50** (`02-test-cases.md:429`, `:454-456`). Los 14 casos añadidos son exactamente `.120/3`, `.125/4`, `.130/4-5`, `.131/2`, `.140/4-8`, `.153/1`, `.154/1` y `.155/1-2`.

Quedan estas inconsistencias concretas:

- `01-requirements.md:315` todavía declara **3b 12 rows / total 83**; debe decir **3b 15 rows / total 86**. En `:304`, la cláusula pendiente de `.120` menciona solo `/2` y omite el nuevo `/3`.
- `02-test-cases.md:433` dice que `.120` tiene **1 de 2** casos en 3a; ahora es **1 de 3**, con `/1` en 3a y `/2-3` en 3b, como sí recoge `:440`.
- `E1-slice.md:135` mantiene la lista anterior de casos 3b y omite los cuatro nuevos de S2.7g (`.120/3`, `.125/4`, `.130/4-5`). Los contratos funcionales sí están actualizados en `E1-slice.md:41-43`, `:122-123`.

## Cierre verificado de A-01…A-05 y de los invariantes solicitados

- **A-01:** `_name_echo` y `name` reciben el eco acotado más sufijo; la misma composición gobierna INDEX, refusals, notices y overlap, con `_echo` para layout/ref (`codewire/graph-inc3.md:284`, `:704`, `:832`, `:390`).
- **A-02:** todo punto STD hereda el `shared_with` del padre (`codewire/graph-inc3.md:284`, `:343`; `02-test-cases.md:338`).
- **A-03:** CLEAN solo aplica a scalars number/enum limpios de MEASUREMENT/CHARACTERISTIC, nunca a AXIS_PTS ni cuando cualquiera de los lados es array/curve/map (`codewire/graph-inc3.md:282`; `02-test-cases.md:335`, `:337-339`).
- **A-04:** `encode_values` tiene rama scalar explícita, exactamente `(0,)`, con `.153` y sus tres tipos (`codewire/graph-inc3.md:150`, `:832`; `01-requirements.md:245`; `02-test-cases.md:340`).
- **A-05:** el orden es refusal → PARSE → decode/ELEMENTS → posiciones → edits → monotonía, con OVERLAP tardío (`codewire/graph-inc3.md:390`, `:832`; `02-test-cases.md:287`, `:327-328`).
- **Posiciones totales y monotonía fail-closed:** validación antes de unpack/offsets y formatter total/acotado (`codewire/graph-inc3.md:146`, `:704`); regla desconocida rechazada, refusal de cualquier punto necesario propagado y texto del breaking point acotado (`:832`, `:888`; `01-requirements.md:246-247`).
- **Formas inversas:** índices inmutables compartidos por walk, first-text para enum y bisect para valores numéricos, sin reconstruir ni ordenar por celda; equivalencia con el oracle y control de coste en `.131/2` (`codewire/graph-inc3.md:154`, `:832`, `:873`; `01-requirements.md:242`; `02-test-cases.md:330`).

## Checks

Revisión estática de `E3-rulings.md:197-211`, `01-requirements.md:229-247`, `:290-315`, `02-test-cases.md:285-343`, `:429-456`, `codewire/graph-inc3.md:140-160`, `:240-247`, `:281-284`, `:339-344`, `:386-395`, `:701-708`, `:828-894` y `E1-slice.md:41-43`, `:118-135`. No se ejecutó pytest ni producto; no hay implementación nueva que deba presentarse como GREEN.
