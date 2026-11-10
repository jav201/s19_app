# E5 — re-revisión de código Inc 3b

## Veredicto: PASS

Revisiones independientes Kimi, sobre el árbol posterior a `a2295311` y antes del commit de cierre NaN. No quedan HIGH/MAJOR abiertos en el alcance revisado.

La primera re-revisión encontró E5R-3B-01 (exact-first alteraba tolerancia/file order) y E5R-3B-02 (cuatro límites largos superaban 1.024). La seguridad añadió RR-03 (fallback no exacto lineal). La corrección retiró exact-first, introdujo un range-minimum tree y `_bounded_message`; las pruebas `.131/5-6` discriminan esos defectos.

Una segunda revisión aisló dos defectos NaN: el centinela RMQ usaba el tamaño filtrado y NaN-y se eliminaba también de la interpolación. Se corrigió el centinela con `len(numeric)` / `len(inverse_file)` y se regló TAB_INTP con cualquier NaN-y como no invertible, sin bytes. Requisitos `.131/4`, grafo y ruling declaran la enmienda al oráculo.

Comprobaciones finales de los revisores:

- RMQ conserva primer file-order en TAB_NOINTP y primer physical-sorted en TAB_INTP; O(log M) también en matches no exactos.
- 500 tablas finitas deterministas, 0 divergencias informado por el revisor de código.
- NaN-y en TAB_INTP falla cerrado; dos NaNs antes de un match TAB_NOINTP conservan raw.
- Mensajes de límites normales/extendidos y notice combinado ≤1.024 caracteres.
- Spans over-cap/final-point, `element_name`, vecinos globales y docstring permanecen cerrados.

Evidencia: `write3b-nan-fixes.txt` 5 passed; `write3b-run9-int.txt` 81 passed; `write3b-family-final-a2295311.txt` 668 passed en el commit anterior (la familia se repite en el commit de cierre). Los revisores no editaron archivos ni ejecutaron pytest en Windows.
