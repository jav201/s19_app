# Batch 103 — correcciones de drivers CI

## Revisión y alcance

- Rama: `b103-ci-driver-fixes`.
- `main` de referencia: `65fcaa3f2a58ab6dd78152c4b6af596a01e2d1d6`.
- Base con higiene temporal: `b5968f2348206f90fd4c3269d2829c566886a526`; contiene a `main` y a `chore: finalize batch 103 CI hygiene`.
- Árbol de código verificado antes de archivar esta evidencia: `4fc56ffae6d513739a80702dab700eb827ee1949`.
- Sólo se modificaron `tests/test_b103_inc9b_s.py` y `tests/test_b103_clipboard_matrix.py`; no hubo cambios de producto ni de oráculos.

## Justificación de auditoría agente62

La auditoría reportó cero regresiones de producto y tres drivers de prueba por corregir.

1. Los dos casos R-PE-BENCH.98/2 llamaban `monkeypatch.setattr` y después eliminaban manualmente los mismos atributos en `finally`. Así, el `undo()` posterior del fixture intentaba restaurar atributos que ya no existían, causando los errores de teardown observados con pytest 9.2. Se eliminó únicamente esa doble limpieza: el fixture vuelve a ser el único responsable de restaurar. Los cuerpos, llamadas y aserciones conservan su comportamiento.
2. En el caso `[patch]`, una pausa fija no garantizaba que el clic derecho hubiera terminado la copia; `rc_copied` podía leer el valor anterior `W1`. Ahora el clic espera un hit real (`wait_for_hit=True`) y una espera acotada existente (`_poll_until`) confirma `app.clipboard == f"R1-{P1}"` antes de borrar y pegar. Se conservan los payloads, las cuatro aserciones y la cardinalidad de la matriz.

El ContextVar posterior pertenece al cierre señalado por la auditoría; no se trató como otro defecto ni se modificó.

## Resultados locales

Entorno: Windows, Python 3.12.7, pytest 8.3.4. No se accedió al clipboard real ni se definió o alteró `GITHUB_ACTIONS`.

- `scheduler-focused.txt`: los dos nodos R-PE-BENCH.98/2 pasaron, `2 passed in 8.25s`, sin errores de teardown.
- `scheduler-full-file.txt`: archivo completo, `8 passed, 2 failed in 79.50s`. Los dos fallos no son los nodos modificados: R-PE-BENCH.101/3 y .101/4, ambos `serial_timing`, agotaron 5 s esperando la señal visual de ocupado. No se cambiaron esos tests ni sus oráculos.
- `scheduler-non-timing.txt`: el mismo archivo excluyendo sólo esos dos casos de timing, `8 passed, 2 deselected in 51.98s`.
- `clipboard-static-and-windows.txt`: `37 tests collected`; se conserva el nodo `[patch]`. Su ejecución local terminó en `1 skipped` por el guard Windows/LinuxH, antes de crear la app o usar clipboard.
- `static-checks.txt`: `py_compile` PASS para ambos archivos; comprobación AST PASS del orden hit → actualización de clipboard → borrado; `git diff --check` PASS.

## Límites y validación pendiente

No se pudo ejecutar localmente el cuerpo LinuxH del caso clipboard `[patch]`: la plataforma es Windows y no se forzó el guard ni se usó clipboard real. La recolección y la comprobación AST son verificaciones estáticas, no evidencia end-to-end de ese cuerpo. CI debe validarlo.

El entorno local tiene pytest 8.3.4, no pytest 9.2; los dos nodos de teardown pasan localmente, pero CI debe confirmar específicamente la versión donde se observó el fallo. Los dos timeouts `serial_timing` del archivo completo quedan reportados como fallos locales no relacionados, sin reclamar suite completa verde.
