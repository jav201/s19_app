# E3 architect — Inc 3b, re-review r3

## Veredicto: PASS-WITH-NOTES

E3B3R2-A-01 y E3B3R2-N-01 están cerrados. No queda ningún bloqueo MAJOR/HIGH en correction 2. Persiste una nota MINOR de cobertura del oráculo de materialización. La revisión es de diseño y registros; no se exige producto ni evidencia GREEN.

## Cierre verificado

- **Cross-page completo:** todos los candidatos se materializan una vez por walk, reutilizando definiciones ya construidas y el mismo `reads`; cada span final se archiva en todas sus páginas, sin subconjunto provisional (`codewire/graph-inc3.md:282`). `.140/9` reproduce exactamente el contraejemplo R2: CURVE en `0x20`, tag sin longitud, span final `0x20…0x5F` y VALUE en `0x40`, con `shared_with="CX"` y OVERLAP (`02-test-cases.md:341`; `codewire/graph-inc3.md:345`; `01-requirements.md:246`). Ya no existe la dependencia de descubrimiento por la página provisional que motivó R2-A-01.
- **Sincronización R2-N-01:** los conteos secundarios quedaron corregidos en `01-requirements.md:306`, `:317`, `02-test-cases.md:435` y `E1-slice.md:9`, `:135`. Los totales finales son coherentes: **86 rows** (`01-requirements.md:294`, `:317`), **338 = 280 + 58** (`02-test-cases.md:431`, `:456-458`) y **S2.7g 46 / S2.7h 52** (`02-test-cases.md:431`, `:457`).
- **Semántica inversa:** `.131/3` compara raw, reason y written-value flag con el frozen oracle para TAB_INTP/TAB_NOINTP, tolerancia, ties, endpoints, entradas no numéricas, NaN, tablas ausentes/vacías y textos enum duplicados (`02-test-cases.md:331`). Las ramas escritas en `codewire/graph-inc3.md:154` coinciden con `_reverse_table_lookup`: primer match estable con tolerancia `1e-9`, orden de archivo en ties, interpolación y redondeo, rango y flag (`s19_app/tui/a2l.py:2884-2942`). `.131/2` conserva el oráculo de escalado (`02-test-cases.md:330`).
- **Orden y nombres:** CTX fija refusal → PARSE → decode/ELEMENTS → posiciones → edits → monotonía, con OVERLAP tardío (`01-requirements.md:123-127`). `.154` usa `<axis point name>` y espera `C.X[0]` (`01-requirements.md:248`; `02-test-cases.md:343`; `codewire/graph-inc3.md:833`, `:882`).
- **Punto no editado:** `.155/1` sitúa el fallo RAT_FUNC en un punto no editado que se vuelve necesario al editar otro, evitando que scalar PRECISION enmascare el decode refusal (`02-test-cases.md:344`; `codewire/graph-inc3.md:883`).
- **Posiciones:** las formas malformadas usan el nombre acotado + `: ` + `repr(position)` acotado; las válidas conservan sus nombres (`codewire/graph-inc3.md:146`, `:705`). Los siete textos exactos están fijados en `codewire/graph-inc3.md:858`, y `encode_values.req` ya incluye `.120` y `.153…155` (`:830`).

## Nota restante

### E3B3R3-N-01 — MINOR — coverage-gap — falta el oráculo de materialización única y comparación de coste

**Ubicación:** exigencia en `E3-rulings.md:219`; diseño en `codewire/graph-inc3.md:282`; caso en `02-test-cases.md:341` y ejemplo en `codewire/graph-inc3.md:345`.

El ruling exige que el oráculo de rendimiento compare contra el camino anterior y demuestre que no hay descripciones repetidas por candidato. `.140/9` verifica correctamente `shared_with` y OVERLAP, pero no instrumenta el número de descripciones, la reutilización de una definición solicitada ni la comparación de coste. El texto del grafo prescribe una vez por walk, así que no es un defecto funcional del diseño; es una cobertura pendiente que permitiría aprobar una implementación con describe duplicado.

**Corrección concreta:** ampliar `.140/9`, sin cambiar los conteos, con un contador alrededor de la descripción/materialización: cada candidato una vez por walk, la definición solicitada reutilizada, y comparación de coste contra el camino anterior; describe repetido o nueva descripción del objeto ya construido → RED.

## Checks

Lectura estática de `E3-rulings.md:215-227`, `01-requirements.md:96-130`, `:236-249`, `:292-317`, `02-test-cases.md:325-345`, `:431-458`, `codewire/graph-inc3.md:140-155`, `:281-345`, `:701-708`, `:829-896`, `E1-slice.md:1-45`, `:118-135` y `s19_app/tui/a2l.py:2870-2942`. No se ejecutó pytest, producto ni comandos Git.
