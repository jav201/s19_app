# Batch-103 G3 — carril `b103-g3-osc52`

**Veredicto: driver/contexto; no hubo cambio de producto.** El oráculo conserva exactamente un OSC52 y el payload íntegro, y añade la comprobación de un único tail con ese mismo payload.

## Causa y corrección

- La evidencia existente de la full-suite final completada `33028542` ejecutó el brazo `multi` y falló con `AssertionError: (0, None)`. Se archiva un extracto mecánico de ese único caso, más el entorno y completion redactados, con los SHA-256 de las fuentes originales completas y de los extractos en `MANIFEST.tsv`.
- Las reproducciones seriales en head `12238830` y base `0c3a6bd4` terminaron ambas en el guard de aislamiento para `single` y `multi`; no se forzó CI ni se abrió el clipboard real.
- En `multi`, las cuatro pausas de `show_patch_paste` permitían leer una región obsoleta. El hit-test del clic caía en `#patch_inspector` y otros controles, no en `#patch_paste_text`. Una vez asentado el layout, el hit correcto produce un OSC52 con el texto esperado.
- `right_click_app_route` acepta ahora `offset` y `wait_for_hit` como opciones; el default conserva el comportamiento previo. El caso objetivo usa `(2, 1)` y espera acotadamente el hit correcto, luego espera el fin del tail.
- El caso objetivo sustituye solo `write_os_clipboard` por un seam local que devuelve `False`, registra el payload y no toca el OS. Esto hace válida la comprobación OSC52 en Windows sin convertir un guard de aislamiento en un PASS de cobertura OS.

## Ejecuciones

- `red-final-33028542.{junit.xml,log}`: RED existente del full final, un caso, firma `(0, None)`; `red-final-33028542.{environment.txt,completion.txt,full-suite-exit.txt}` conserva su procedencia y finalización.
- `red-head-before.{junit.xml,log}` y `red-base-before.{junit.xml,log}`: 2 failed en cada árbol, guard `OS clipboard not isolated`, `-n0`, stdin cerrado, caches off.
- `green-focused.{junit.xml,log}`: **2 passed en 4.92 s**, ambos brazos, un OSC52 y payload exacto por brazo.
- `red-non-os-initial.{junit.xml,log}`: 30 passed, 2 skipped, 1 failed. El fallo fue `test_r_paste_35_4_right_click_paste_multi_line_strips`, ya clasificado por los probes archivados head/base como acceso OS; quedó fuera del alcance y no se editó.
- `green-non-os.{junit.xml,log}`: **30 passed, 2 skipped, 55 deselected en 61.12 s**. Se usó la lista histórica de guards, reincorporando los dos brazos objetivo ahora aislados, y se excluyó también el acceso OS anterior.
- `ruff.log`: cinco hallazgos `F401/F841` preexistentes fuera de las líneas cambiadas; no se corrigieron por ser otras familias. No se usa como PASS.

No se ejecutó de nuevo la full-suite `33028542`; este carril no cambia el veredicto global RED372 ni reclama cierre G3. Los logs/XML almacenados fueron decodificados como UTF-8, despojados de ANSI, normalizados a LF y redactados; todos los XML almacenados se parsearon durante el empaquetado. `MANIFEST.tsv` registra SHA-256 de origen y almacenado; `SHA256SUMS` verifica los bytes finales del carril.
