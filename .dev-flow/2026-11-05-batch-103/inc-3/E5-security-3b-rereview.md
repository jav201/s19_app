# E5 — re-revisión de seguridad Inc 3b

## Veredicto: PASS

Revisor independiente Kimi. **0 MAJOR restantes** en el alcance final; los HIGH/MAJOR previos quedan cerrados.

RR-01, RR-03 y RR-04 están cerrados: no hay exact-first, todo match de tolerancia usa bisect + RMQ en O(log M), y las tres salidas de `_check_limits` están acotadas. RR-02 fue retirado por el revisor porque el oráculo ordena `numeric` antes del match TAB_INTP (`a2l.py:2905`).

RR-05 se cierra por una enmienda explícita: NaN-y hace TAB_INTP no invertible antes de rango, match o interpolación, sin interpolar a través del NaN ni escribir bytes. Python NaN sort no ofrece un dominio de interpolación ordenado sólido. La prueba `0 0`, `1 nan`, `2 1`, físico 0.5 exige A2L-DEF-ENCODE.

El centinela RMQ usa el tamaño original sin filtrar; toda posición real gana al centinela y un rango vacío devuelve `None`. La escala con dos NaNs y match tardío no exacto conserva el raw y realiza 0 escaneos de tolerancia.

Evidencia de las correcciones: `write3b-nan-fixes.txt` (5 passed) y `write3b-run9-int.txt` (81 passed). Leyes, escala, rendimiento y mutantes se validan aparte; la ley de redacción tiene un fallo heredado reproducido en `8cb8f479` por evidencia Inc 12 que el operador ordenó no modificar.
