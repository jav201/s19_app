# E4 VIEWS/GESTURES — RED Linux

## Alcance y base

- Familia exclusiva: R-COPY.1, .2, .4, .10, .11, .12, .13, .14, .15, .21 y .22; 54 casos y 54 nodos pytest. No se diseñaron casos de tail/quit.
- Oráculos derivados de `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc1b.md` y `E2-interfaces.md`, no del worktree de implementación de DeepSeek.
- Clone Linux: `<HOME>/work/b103-e4-views-JP7rJz/tree`.
- HEAD verificado: `e2e935482646553a34242e524af5ac5bc57af82b` (`e2e93548`). El repositorio compartido de origen no contenía ese objeto; se transfirió el commit base ya existente desde el worktree independiente mediante un bundle temporal, sin crear commits ni usar producto de DeepSeek. El bundle y los probes temporales se eliminaron.
- Producto sin modificaciones; el único overlay fue `tests/test_b103_copy_views.py`.
- SHA-256 del archivo de tests, idéntico en el worktree y en el clone: `f8127c7d5acc3d2266302cd33a61633141ea9884a809f545984cbcb2cb6f2a79`.
- Transcript completo: `red-linux-e2e93548.txt`. Su SHA-256 se registra en `SHA256SUMS.txt` después de copiarlo sin truncar.

## Aislamiento ejecutado

Runner `<USER>@<HOST>`, Python `<HOME>/miniconda3/envs/s19ci/bin/python` 3.11.18, `-I -B`, stdin cerrado, pytest sin cache y `sys.path.insert(0, ".")` antes de importar pytest. La primera línea del transcript identifica el `s19_app.__file__` del clone; a continuación se imprimen HEAD y el entorno.

`TMPDIR`, `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` y `LOCALAPPDATA` apuntan a directorios neutrales dentro de `<HOME>/work/b103-e4-views-JP7rJz`. `DISPLAY` y `WAYLAND_DISPLAY` se quitaron del entorno. `PYTHONDONTWRITEBYTECODE=1` y `PYTHONIOENCODING=utf-8`.

Linux usa un escritor registrador que no abre clipboard y devuelve éxito, salvo el brazo de fallo R-COPY.2/4, que devuelve `False`. También se neutralizaron el lector OS y el arranque Tk antes de iniciar la app. OSC 52 se observa en el driver real; las notificaciones se leen de la lista asentada de la app. No se accedió al clipboard del PC operador. Las lecturas OS separadas solo están programadas para la ruta WinCI aislada existente.

## Resultado RED

- `collected=54`; `FAILED=25`; `PASSED=29`; `SKIPPED=0`; exit de pytest `1`; duración `431.61 s` (`0:07:11`). El transcript tiene 1,770 líneas y 54 líneas de estado, una por nodo.
- Los 25 RED se descomponen en: R-COPY.1 (6), R-COPY.2 (4), R-COPY.4 (3), R-COPY.10/2–3 (2), R-COPY.12 (8), R-COPY.13/9 (1) y R-COPY.22/1 (1).
- Los 29 pases base se descomponen en: R-COPY.10/1 (1), R-COPY.11 (5), R-COPY.13/1–8 (8), R-COPY.14 (9), R-COPY.15 (3), R-COPY.21 (2) y R-COPY.22/2 (1).
- No hubo errores de colección ni fixtures en la corrida final. Los RED observados son: ausencia del writer OS y del nuevo tail/cardinalidad; ausencia de copia right-click de selecciones y nombres completos; OSC 52 ausente en right-click; padding `out_of_bounds=True` que mueve el cursor A2L; y salto hex A2L.

Un resultado `pass-base` en `per-case.csv` significa únicamente que el oráculo ya se cumple en la base, no GREEN de Inc1b. Un resultado `red` es una aserción conductual por comportamiento Inc1b ausente. No hay afirmación GREEN ni cobertura WinCI inferida desde skips.

## Cobertura y estados por caso

`per-case.csv` contiene una fila por cada uno de los 54 casos, con nodo pytest, cobertura Linux, estado WinCI, resultado RED y observación concreta.

- `full-linux`: todos los oráculos aplicables al brazo LinuxH se ejecutaron; no implica cobertura WinCI.
- `partial-writer-proxy`: se ejecutó el gesto y se comprobó el payload/ausencia en el escritor y demás sinks, pero la lectura OS separada exigida sigue pendiente de WinCI.
- 32 casos `full-linux`; 22 `partial-writer-proxy` (R-COPY.1, .4, .11 y .12).
- WinCI `not_run` para 46 casos que lo requieren; `not_required` para R-COPY.2/4, .15, .21 y .22 (8 casos). Ningún skip Linux se contabilizó como verificación.
- Las lecturas OS separadas de R-COPY.1, .4, .11 y .12, y los brazos WinCI de R-COPY.2/1–3, .10, .13 y .14, quedan pendientes de la ruta aislada Windows CI.

## Mutantes que deben quedar detectados (no ejecutados en E4)

- R-COPY.1: eliminar la escritura executor o no programar el tail → escritor separado sin el texto/selección y seed intacto.
- R-COPY.2: escribir solo OS u omitir la llamada base → `app.clipboard` conserva seed; el brazo de fallo debe conservar el mirror del nombre de fila.
- R-COPY.4: usar fila resaltada en vez de clicada, key interna, celda abreviada, glyph/tab, truncado o borrado arbitrario de caracteres; rechazar `out_of_bounds=False`; ignorar `.plain` del Rich `Text` MAC o acortar el nombre largo.
- R-COPY.10: omitir la base → 0 OSC 52; llamar base dos veces/reentrar desde el tail → 2 solicitudes.
- R-COPY.11: copiar al seleccionar, mover highlight, pulsar F7, hacer click o en `MouseDown(3)` → escritor/OSC 52 distintos de cero.
- R-COPY.12: leer selección después del dispatch, copiar solo el fragmento clicado, copiar al press, aceptar movimiento, no consumir candidate/replay, no reemplazar candidate en reentry o duplicar base/writer/OSC 52/noticia.
- R-COPY.13: usar selección global al hacer click fuera, copiar en right-drag, revalidar al volver, aceptar padding por índice válido o copiar cadena vacía.
- R-COPY.14: emitir copy/cut/refusal/write-failure/nothing notice en gesto vacío o cancelado.
- R-COPY.15: conservar selección hex/stats/JSON tras el right-click.
- R-COPY.21: dejar cursor en fila anterior, no actualizar detail card o emitir `RowSelected` en vez de solo highlight.
- R-COPY.22: delegar el right-click a la selección estándar de DataTable → `RowSelected` y salto de la primera fila hex.

## Bloqueos y trabajo pendiente

- **Bloqueo de plataforma:** no se ejecutó WinCI ni ninguna lectura OS separada; 46 casos conservan `winci=not_run`. Esto no se sustituyó por skips ni se declaró verificado. Los otros 8 casos son Linux-only según el ledger.
- **Brazos posteriores no alcanzados tras el primer RED:** R-COPY.4/2 no llegó al nombre largo MAC `.plain`; R-COPY.12/7 no llegó al replay posterior; R-COPY.12/8 no llegó a los brazos A2L/MAC ni a sus cardinalidades; R-COPY.13/9 no llegó al padding MAC. Quedan implementados en los nodos y deben ejecutarse en integración/GREEN.
- **Sin bloqueo Linux restante:** los 54 nodos se recolectaron y ejecutaron en la corrida final sobre la base correcta. No se editaron producto, otros tests, ledger compartido ni git refs del worktree; no hubo commits ni push.
