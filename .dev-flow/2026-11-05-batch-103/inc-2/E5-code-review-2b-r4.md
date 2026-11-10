# Inc 2b E5 — revisión final de código R4

**Veredicto: PASS.** E5R3-1 está corregido. No se encontraron hallazgos HIGH/MAJOR ni otros
hallazgos en la revisión final acotada del delta de producto y de las pruebas añadidas.

Base revisada: HEAD `57b69214a6ea9e06d85ad9a2643016694ad62e64`. El diff
`1147a6e9..HEAD` del alcance contiene dos líneas de producto en `_pair_exempt` y cambios de
pruebas; no modifica `_shared_with`, `encode_definition` ni el generador sintético. Producto y
pruebas están limpios respecto de HEAD en el worktree.

## Ejecutado frente a leído

- **Ejecutado por este revisor:** nada. Revisión estática en Windows, sin pytest, probes ni
  mutaciones git.
- **Evidencia ejecutada por el orquestador, solo leída aquí:**
  - `evidence-e4/int2b-run14-main.txt`: **322 passed in 15.50s**.
  - `evidence-e4/int2b-red-homonym-guard.txt`: **1 failed, 309 deselected**, al quitar solo la
    guarda; falla `.138/23` con `MW.shared_with is None` frente al esperado `"B"`, exactamente
    la regresión de E5R3-1.
  - `evidence-e4/int2b-red-stub-final9-main.txt`: **125 failed, 197 passed in 29.24s**; la lista
    incluye `.138/23` y los cinco casos `.152`.
- **Leído:** diff completo `1147a6e9..HEAD` para `s19_app/tui/a2l_definition.py`,
  `tests/test_b103_a2l_definition.py` y `tests/test_b103_synth_definitions.py`; implementación
  actual de `_pair_exempt` / `_shared_with` (`a2l_definition.py:3498-3591`); pruebas `.46/2`,
  `.48/2`, `.138/20`-`.138/23` y `.152/1`-`.152/5`.

## E5R3-1 — RESUELTO

La nueva guarda (`s19_app/tui/a2l_definition.py:3511-3512`) devuelve `False` cuando la entrada
es `BLOB` o `INSTANCE`, antes de llamar a `mask_of(entry[1])`. Por tanto, una colisión de nombre
con un MEASUREMENT/CHARACTERISTIC limpio y enmascarado ya no puede prestar su máscara al
BLOB/INSTANCE. El camino de MEASUREMENT/CHARACTERISTIC conserva la consulta `mask_of` y la
exención por máscaras disjuntas sin cambios.

`.138/23` (`tests/test_b103_a2l_definition.py:3394-3413`) reproduce el contraejemplo de R3 con
`MW` big-endian, máscara `0x000F`, span `0x10..0x11` y un tag homónimo `B` limpio en `0x100`.
Ejercita dos formas, BLOB e INSTANCE de dos bytes en `0x10`, y exige en ambas `shared_with ==
"B"` y el mensaje exacto `A2L-DEF-OVERLAP`. Sin la guarda, la máscara prestada hacía disjuntos
los mapas de bits y devolvía `None`; la evidencia RED confirma esa discriminación.

Nota de evidencia, no hallazgo: al ser un bucle fail-fast, el mutante RED se detiene en el
primer shape (BLOB) y no llega al shape INSTANCE. El GREEN ejecuta ambos y la misma guarda
explícita cubre los dos tipos; no queda una rama de producto sin revisar.

## Brazos añadidos

- `.46/2` (`tests/test_b103_a2l_definition.py:2780-2786`) comprueba primero el rechazo de
  solape sobre la definición original y después conserva la escritura esperada `35 12` solo en
  la copia de prueba con `shared_with` limpiado.
- `.48/2` (`tests/test_b103_a2l_definition.py:2831-2837`) hace lo mismo para el enum de rango:
  `A2L-DEF-OVERLAP` original y luego `04 00` en la copia limpiada. Los mensajes y bytes son los
  del contrato.
- `.152/1`-`.152/5` (`tests/test_b103_a2l_definition.py:3431-3480`) añaden en cada caso
  `Decoded(7, 7, "7")` con errores de parseo presentes, seguido del mismo rechazo
  `A2L-DEF-PARSE` al codificar. Las nuevas aserciones fijan correctamente “describe y decode
  unchanged” sin alterar el orden del gate de escritura.

El último algoritmo de orden global multipágina y la exclusión propia permanecen sin cambios en
este delta; no aparece una regresión asociada a la corrección.
