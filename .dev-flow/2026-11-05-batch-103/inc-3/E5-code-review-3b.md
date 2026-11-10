# E5 — revisión de código de Inc 3b

## Veredicto: FAIL

Producto revisado: `s19_app/tui/a2l_definition.py`, HEAD `c88cd029829a241fccbc319e5e35022e2c817363` más la optimización perezosa sin commit. Contratos contrastados: `codewire/graph-inc3.md`, las correcciones 1–2 y el addendum de materialización perezosa de `E3-rulings.md`.

La evidencia aportada registra 75 pruebas de integración y 662 pruebas de familia verdes, con `.142/5` en 0,103 s; no se repitió pytest en Windows. Esta revisión ejecutó únicamente sondas directas con `python -B`, en memoria y sin archivos temporales. Esas pruebas verdes no cubren los cuatro MAJOR siguientes.

## Hallazgos

### E5-3B-01 — MAJOR — impl: la vía rápida de spans no conserva la longitud final en contenido hostil

`s19_app/tui/a2l_definition.py:796-826` decide qué candidatos necesitan `describe_name`. En MEASUREMENT exige `matrix[1] is not None` (`:805-810`), de modo que una `MATRIX_DIM` múltiple pero malformada se clasifica como escalar y conserva la longitud provisional del tag. Sin embargo, el modelo final la clasifica como array y deja `byte_length=None` al fallar `.71`. Tampoco entra en la vía final un VALUE rechazado por `.145`, cuya longitud final se anula expresamente en `:986-997` y `:1063`.

Esto rompe la regla de `.140` de usar el span final y también la detección de la entrada propia en `:3914-3926`. Sonda directa: MEASUREMENT `M` en `0x10`, longitud provisional 4 y `MATRIX_DIM x 2` produjo `kind=array`, `byte_length=None`, `A2L-DEF-MATRIX`, pero `shared_with="M"`; un MEASUREMENT escalar limpio `V` en `0x12` obtuvo `shared_with="M"` y `encode_definition` devolvió `A2L-DEF-OVERLAP`, aunque el span final de `M` es sólo el punto fail-closed `0x10` y no toca a `V`.

**Corrección acotada:** la vía rápida escalar sólo debe usarse cuando se garantiza que la longitud final es la del tag. En MEASUREMENT, toda línea `MATRIX_DIM` múltiple debe pasar por `describe_name`, incluso si `_matrix_shape` devolvió `None`; en CHARACTERISTIC, también debe pasar el VALUE con `MATRIX_DIM` múltiple de `.145`. Añadir casos `.140` para ambos, comprobando `shared_with is None` en el propio objeto rechazado y ausencia de OVERLAP en el vecino fuera del punto final.

### E5-3B-02 — MAJOR — impl: TAB_NOINTP no reproduce los dos valores más próximos del oráculo

`_nearest_table_entries`, `s19_app/tui/a2l_definition.py:3518-3553`, reduce los candidatos a los alrededores del punto de bisección. El oráculo congelado calcula la distancia de **todas** las entradas y estabiliza los empates por orden de archivo (`s19_app/tui/a2l.py:2895-2903`). Las distancias redondeadas no son monótonas, por lo que los dos primeros globales pueden quedar fuera de esa ventana.

Contraejemplo completamente finito: entradas `(2, -1e-9)`, `(5, 0.5)`, `(7, 2.0)` y valor físico `1e308`. El oráculo devuelve como vecinos `-1e-09 and 0.5`; la forma optimizada devuelve `0.5 and 2.0`. Una comparación directa de 81.600 casos con semilla 104 encontró 2.830 divergencias, todas en este mensaje de TAB_NOINTP; no observó divergencias de interpolación en esa muestra. `.131/3` exige equivalencia exacta, no sólo el mismo raw.

**Corrección acotada:** conservar la bisección para la coincidencia dentro de tolerancia, pero, sólo cuando TAB_NOINTP ya va a rechazar, seleccionar los dos mejores mediante un recorrido en orden de archivo de `inverse_file`, con el comparador de distancia y desempate del oráculo. Esto evita copiar, reconstruir u ordenar la tabla por celda y mantiene la vía rápida de los encodes aceptados. Añadir el contraejemplo finito y casos con `±inf`.

### E5-3B-03 — MAJOR — design-gap: la interpolación con `±inf` físicos escapa una excepción del contenido del archivo

En `s19_app/tui/a2l_definition.py:3633-3644`, una tabla TAB_INTP con entradas físicas `(0, -inf)` y `(1, inf)`, al codificar el valor físico `0`, calcula `raw_fraction=nan` y ejecuta `round(nan)`. La sonda directa produjo `ValueError: cannot convert float NaN to integer`. El oráculo congelado comparte el defecto en `s19_app/tui/a2l.py:2919-2933`; por eso no es una divergencia de la optimización, sino una brecha heredada frente a la interfaz «never raises on file or image content».

**Corrección acotada:** antes de redondear, tratar una fracción no finita igual que una tabla no invertible y devolver `A2L-DEF-ENCODE` con la razón ya usada para esa rama, sin escribir bytes. Registrar la corrección como enmienda del oráculo congelado y añadir una prueba de encode con `±inf` en y, no sólo una comparación de equivalencia con él.

### E5-3B-04 — MAJOR — impl: `element_name` no es total ni aplica el echo acotado

La interfaz pública `element_name`, `s19_app/tui/a2l_definition.py:2905-2911`, sigue usando `definition.name` crudo, desempaqueta `letter, k` antes de validar la forma e itera cualquier posición. En la sonda directa, un nombre de 300 caracteres produjo un nombre de 303 en lugar del echo de 256 más `…` y sufijo; `("X",)` y `("X",0,1)` lanzaron `ValueError`, y `None` y `0` lanzaron `TypeError`. Incumple el contrato total y acotado de `graph-inc3.md:146` y `:701-708`, aunque la ruta separada de validación de `encode_values` sí supera sus casos `.125/4`.

**Corrección acotada:** implementar `element_name` delegando en el ya total `_position_label` (`:4217-4224`), o reutilizar exactamente sus validadores, `_name_echo_of` y `_position_repr`; no mantener dos composiciones distintas de sufijos. Añadir pruebas directas de la función pública para nombre largo/controlado y todas las formas malformadas de `.125/4`.

## Alcance de la verificación

Por lectura no aparecieron otros HIGH/MAJOR en caché por posición, orden global y cross-page, máscaras CLEAN, monotonía, sufijos de encode ni inmutabilidad de las formas inversas. Como comprobación informativa, no como sustituto del oracle serial de tres ejecuciones, una llamada directa a `describe_definitions` sobre los 13.990 nombres de `software_a` terminó en 1,227 s. Los hallazgos E5-3B-01 … -04 sí están reproducidos por ejecución directa; el carácter heredado de E5-3B-03 está además confirmado contra el oráculo congelado.
