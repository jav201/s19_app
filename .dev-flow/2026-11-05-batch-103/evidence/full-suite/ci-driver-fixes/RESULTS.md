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

## Clasificación del run completo 44229060057

El run `tui-ci` [`44229060057`](https://github.com/jav201/s19_app/actions/runs/44229060057), ejecutado sobre `main` `65fcaa3f2a58ab6dd78152c4b6af596a01e2d1d6`, terminó en **failure**, no GREEN:

- Full lane: `56 failed, 9256 passed, 293 skipped, 4 xfailed, 2 errors in 16082.31s (4:28:02)`.
- Serial lane: `4 failed, 198 passed, 23 skipped, 9609 deselected in 4541.51s (1:15:41)`.
- Los dos casos R-PE-BENCH.98/2 pasaron sus cuerpos y produjeron los dos errores de teardown que corrige esta rama.

La clasificación y procedencia se conservan en `run-44229060057-tally.txt`. La auditoría agente62 encontró cero regresiones de producto y limitó la intervención a los tres drivers descritos arriba; esa conclusión y los pases locales no convierten el run completo ni esta rama en GREEN.

## Redacción de evidencia — revisión agente64

La revisión independiente agente64 dio NO-GO a `a12a30065` por evidencia, no por los drivers. El guard inicial encontró nueve rutas con cuenta local: dos en `clipboard-static-and-windows.txt`, una en `scheduler-focused.txt`, cinco en `scheduler-full-file.txt` y una en `scheduler-non-timing.txt`.

- ORIGINAL local: seis capturas almacenadas en el commit `a12a30065`, con hashes registrados en `ORIGINAL-SHA256SUMS`. No se duplican aquí sin redactar.
- ORIGINAL Windows: los cuatro archivos descargados del artefacto `b103-winci-outcomes` (id `14418330558`) del run `44276970151`; sus hashes originales también están en `ORIGINAL-SHA256SUMS`.
- Stored: las copias publicadas sustituyen la cuenta local por `<user>` y el hostname del runner por `<host>` (`&lt;host&gt;` en el XML), usan LF y no tienen espacios/tabuladores finales. `static-checks.txt` también se normalizó. No se alteraron tallies, aserciones, nodeids ni oráculos; cada copia fue comparada byte a byte con `redact(normalize(ORIGINAL))`.
- `SHA256SUMS` identifica las copias redactadas y los demás artefactos almacenados; sus hashes difieren de ORIGINAL por la redacción/normalización documentada.
- Los dos archivos de tests permanecen byte-idénticos a `a12a30065`; este cambio sólo afecta a evidencia.

## Run clipboard-windows 44276970151

Se esperó el run existente [`44276970151`](https://github.com/jav201/s19_app/actions/runs/44276970151), disparado por push sobre `a12a30065`; no se lanzó otro. Terminó **completed / success** en 37 min 9 s, con watcher exit 0.

- Pytest: **216 passed, 44 skipped, 2 warnings in 2175.42s**.
- Gate: **108/108 obligations; AT 28/28 (P1 14/14, P2 14/14)**; `WINCI_GATE_RESULT PASS violations=0 pytest_exit=0 gate_exit=0`.
- Artifact safety: `ARTIFACT_SAFETY_RESULT PASS violations=0`.
- Los 44 skips son 37 LinuxH, seis linux-only y una aceptación manual de Windows Terminal; no se reclama aceptación manual.
- Los cuatro artefactos redactados están en `run-44276970151/`; tally y metadata tienen referencias explícitas. `validation.txt` documenta parse XML PASS (260 casos, cero failures/errors), gate independiente PASS y artifact-safety PASS sobre las copias almacenadas.

Este éxito es específico del workflow Windows sobre `a12a30065`; no equivale a full-suite GREEN ni a la validación `tui-ci` pytest 9.2/LinuxH pendiente tras `main`.

## Comprobaciones de higiene posteriores

- `python -m pytest -q tests/test_no_private_tokens.py`: **2 passed in 49.06s**, cero hits nuevos tras redacción y con la evidencia nueva indexada.
- Escaneo directo de `ci-driver-fixes`: cero tokens prohibidos; copias `.txt` LF y sin trailing whitespace.
- `ORIGINAL-SHA256SUMS` contrastado con los blobs de `a12a30065`: PASS, seis archivos.
- `git diff --check b5968f23`: PASS; los dos archivos de tests no cambiaron desde `a12a30065`.
- Registro literal en `privacy-and-diff-checks.txt`. La validación de `SHA256SUMS` y el parse XML se documentan junto al artefacto Windows correspondiente.

## Límites y validación pendiente

No se pudo ejecutar localmente el cuerpo LinuxH del caso clipboard `[patch]`: la plataforma es Windows y no se forzó el guard ni se usó clipboard real. La recolección y la comprobación AST son verificaciones estáticas, no evidencia end-to-end de ese cuerpo.

El entorno local tiene pytest 8.3.4, no pytest 9.2; los dos nodos de teardown pasan localmente, pero eso no confirma la versión donde se observó el fallo. **`tui-ci` validará pytest 9.2/LinuxH tras integrar en `main`; esa validación queda pendiente y no se presenta como completada.** Los dos timeouts `serial_timing` del archivo completo local quedan reportados como fallos no relacionados, sin reclamar suite completa verde.
