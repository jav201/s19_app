# Inc 3b — E3 seguridad, re-revisión R3 tras correction 2

**Veredicto: PASS-WITH-NOTES.** No queda ningún HIGH ni MAJOR y, por tanto, ningún bloqueo de seguridad para E4. R2-01 está cerrado: la materialización provisional por páginas se retira y todos los candidatos se describen una vez por walk, con su span final indexado en todas las páginas. R2-03, R2-04 y R2-05 están cerrados; R2-06 queda corregido salvo una CTX de `<position>` aún antigua. Persisten **1 MEDIUM** y **2 MINOR** de precisión de diseño/cobertura, sin exigir producto nuevo.

## Notas

### E3B3-R3-01 — MEDIUM — diseño/cobertura — la semántica inversa queda nombrada, pero no completamente determinada

**Ubicación:** `codewire/graph-inc3.md:154`, `:833`, `:875`; `02-test-cases.md:330-331`; `E3-rulings.md:220`; oracle `s19_app/tui/a2l.py:2884-2937`.

La corrección nombra TAB_INTP, TAB_NOINTP, tolerancia, endpoints, empates, no numéricos, NaN, missing/empty y written flag, y exige igualdad con el frozen oracle. Esto cierra la mayor parte de R2-02, pero dos precisiones siguen abiertas:

- «Indexed by physical value for bisect» no define cómo se obtiene la **primera raw en file order** cuando varias entradas físicas distintas caen dentro de `abs_tol=1e-9`. El frozen recorre el archivo y devuelve la primera (`a2l.py:2891-2894`, `:2913-2915`); una bisect que elija una entrada arbitraria del intervalo puede devolver otra. Tampoco se define la ruta para NaN en `y`, cuyo orden no es una ordenación total apta para bisect.
- `.131/3` enumera categorías, pero no fija entradas concretas, textos del operador ni resultados raw/reason/flag por input. El oráculo congelado es correcto, pero hacen falta datos que distingan tolerancia de igualdad exacta, empate de file order y NaN. Además, `.131/2` (`02-test-cases.md:330`) no declara TAB_INTP, aunque el ruling (`E3-rulings.md:220`) sí lo fija.

**Recomendación:** precisar la estructura de consulta para el primer match en file order y la ruta NaN/no finita, sin reconstruir ni ordenar por celda. Fijar la matriz concreta de entradas/textos/resultados y declarar TAB_INTP en `.131/2`. No es un bloqueo nuevo: las formas inmutables compartidas y el límite de coste ya están reglados; es una nota para que E4 no implemente una bisect solo aparentemente equivalente.

### E3B3-R3-02 — MINOR — cobertura — `.140/9` no contiene el oráculo de materialización pedido por el ruling

**Ubicación:** `E3-rulings.md:219`, frente a `02-test-cases.md:341` y `codewire/graph-inc3.md:282`, `:345`.

El diseño ya garantiza la completitud: «every span candidate is materialised once per walk», reutilizando definiciones existentes y archivando el span final en todas sus páginas. `.140/9` prueba el caso cross-page `0x20 … 0x5F` frente a `0x40` y exige OVERLAP.

Sin embargo, el ruling también exige comparar contra el camino anterior y demostrar que no hay describes repetidos por candidato. El caso solo comprueba `shared_with` y el refusal; no fija conteos ni una comparación de coste. Así, una implementación que describa dos veces al mismo candidato podría pasar el caso sin cumplir la regla de una materialización por walk.

**Recomendación:** añadir a `.140/9`, o a su cobertura asociada, un instrumento que cuente describes por nombre/candidato, compruebe reutilización de los ya solicitados y una sola descripción de cada no solicitado, y compare con el camino anterior. No cambia el veredicto porque la regla de diseño sí es completa y segura.

### E3B3-R3-03 — MINOR — sincronía — CTX `<position>` conserva la definición anterior a `repr`

**Ubicación:** `01-requirements.md:140`, frente a `codewire/graph-inc3.md:146`, `:705` y `02-test-cases.md:309`.

CTX todavía define `<position>` como «the element name or axis point name the position would have». La corrección 2 establece otra regla para posiciones malformadas: eco acotado del objeto + `: ` + `repr(position)` acotado. El caso ya fija exactamente `('X',)`, `('X', 0, 1)`, `(0.5,)`, `None`, `0`, `(-1,)` y `('Z', 0)`.

**Recomendación:** actualizar CTX para distinguir posiciones válidas, que conservan sus element/axis-point names, de malformadas, que usan el `repr` acotado. El algoritmo y los expected texts ya coinciden entre grafo y casos.

## Disposición de R2-01 … R2-06

| Hallazgo R2 | Estado R3 | Evidencia |
|---|---|---|
| R2-01 cross-page | **CERRADO** | `E3-rulings.md:219`; `codewire/graph-inc3.md:282`: todos los candidatos una vez por walk, reutilización/caché y span final en todas las páginas, en orden global. `.140/9` (`02-test-cases.md:341`) cubre inicio en página anterior. Nota R3-02 solo para el conteo de materialización. |
| R2-02 semántica inversa | **NOTA — R3-01** | Las ramas y categorías están en `graph-inc3.md:154` y `.131/3` (`02-test-cases.md:331`); `.131/2` conserva el oráculo de escala. Falta fijar la selección exacta bajo tolerancia/NaN y datos concretos. |
| R2-03 CTX orden | **CERRADO** | `01-requirements.md:123-127`: refusal → PARSE → decode/ELEMENTS → positions → edits, unknown monotony → Inc 2 encode → monotony X/Y, OVERLAP tardío. |
| R2-04 `.155/1` enmascarado por PRECISION | **CERRADO** | `02-test-cases.md:344` y `graph-inc3.md:883`: el punto RAT_FUNC inválido es **no editado** y otro punto se edita, por lo que el refusal necesario llega desde monotonía y no desde scalar PRECISION. |
| R2-05 axis point name | **CERRADO** | `01-requirements.md:248`, `codewire/graph-inc3.md:833`, `:882` y `02-test-cases.md:343` usan todos `<axis point name>` / `C.X[0]`. |
| R2-06 conteos, req, slice, repr | **CERRADO**, salvo nota R3-03 | Totales secundarios corregidos (`01-requirements.md:317`; `02-test-cases.md:435`, `:457-458`); `encode_values.req` incluye .120, .153-.155 (`graph-inc3.md:830`); resumen del slice incluye .153-.155 (`E1-slice.md:9`); `.125/4` fija cada `repr` (`02-test-cases.md:309`). |

## Conteos y checks

- **86 rows:** S2.7e 19 + S2.7f 29 + S2.7g 20 + S2.7h 15 + S2.7i 3 (`01-requirements.md:294`, `:317`).
- **338 casos = 280 3a + 58 3b:** `02-test-cases.md:431`, `:457-458`.
- **S2.7g 46:** 40 3a + 6 3b.
- **S2.7h 52:** los 50 de correction 1 + `.131/3` + `.140/9`.
- Los 58 casos 3b comprenden los 42 originales y 16 añadidos por corrections 1 y 2; los cinco brazos mixtos edit siguen pendientes para E4.

**Leído:** `E3-rulings.md:215-227`; CTX y filas .125, .131, .140, .154, .155 y counts de requirements; `.125/4`, `.131/2-3`, `.140/9`, `.154/1`, `.155/1-2` y split/counts de cases; I-2, split, `describe_definitions`, `_element_definition`, `element_name`, `encode_values` y ejemplos del grafo; resumen y #21-23 del slice; `_reverse_table_lookup` real para contrastar tolerancia, file order, endpoints, NaN, errores y flag.

**Ejecutado:** nada. Esta R3 evalúa diseño y cobertura, sin exigir producto nuevo, sin pytest en Windows y sin mutaciones Git.
