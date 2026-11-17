# Batch-103 G3 — saveback S0 y TC-024

Base de integración: `0ddd27700d78cd8435dfb6bd3d1411843285555e`. Rama: `b103-g3-saveback-s0`. Ejecución Windows local con Python 3.12.7, `-I -B -n0`, stdin cerrado, bytecode y pytest cache desactivados, HOME/XDG/LOCALAPPDATA/TMPDIR aislados y temporales cortos. Cada `environment.txt` registra las variables de clipboard y color. No se cambió código de producto ni se usó el clipboard real.

## Veredicto

Los dos síntomas eran sincronización de drivers. Se corrigieron únicamente `tests/test_tui_patch_editor_v2.py` y `tests/test_tui_diff_screen.py`; los oráculos de anchura, S0, bytes y rutas Markdown/HTML permanecen intactos.

- **GREEN dirigido:** 3/3 passed en 7.32 s (`green-targeted/`): los dos saveback width32 y TC-024.
- **GREEN de archivos completos:** 105/105 passed en 350.13 s (`green-full-files/`): 52 de `test_tui_patch_editor_v2.py` y 53 de `test_tui_diff_screen.py`. Incluye los dos width32 y el width16 que comparte el driver.
- **Ruff:** PASS (`ruff.log`). **JUnit:** 12 archivos parseados (`summary.json`). **Redacción:** 0 hallazgos con el scanner del proyecto (`redaction-check.txt`).
- No se repitió la full-suite global. Este cambio **sí obliga a una nueva full-suite**, porque modifica archivos.

## RED y diagnóstico de saveback

`red-full85/` conserva los dos casos seleccionados de la full-suite `85ed72102479585728b7dd8210b98b8d7639eef9`: 2/2 failed. Saveback falla con `written=None` y el mensaje `the 32-byte confirm must write a file`; el otro width32 no está en ese extracto porque pasó.

`red-last13-head/` conserva el A/B de contexto: head 13 tests, 10 passed y 3 failed; el preserve-S0 falla con la misma firma mientras el otro width32 pasa. `repro-last13-base/` registra base 11 tests, 10 passed y 1 failed; ambos saveback width32 pasan. Los fallos A2L ajenos se conservan en los JUnit y no se reclaman como verde.

El archivo producido durante el RED se archiva en `red-last13-head/wide_s0-patched.s19`. Su comprobación mecánica (`product-oracle.json`) demuestra:

- S0 source exacto: `SRCHDR_PRESERVE_ME`.
- Anchuras de datos S3: `[32, 8]`.
- Secuencia parcheada `DE AD BE EF` presente y 40 bytes de datos en total.

Por tanto, el producto escribió el archivo correcto y el driver leyó `last_summary.saved_path` antes de despacharse `SaveBackDecision`. El driver compartido ahora espera el dock realmente visible tras Apply y su clase `hidden` tras Confirm; después conserva la aserción original `written is not None` y todas las comprobaciones de contenido.

Los probes aislados anteriores al cambio también pasaron (`probe-isolated-saveback-before/`, 2/2; `repro-base-saveback/`, 2/2), coherente con una carrera de sincronización y no con una pérdida determinista de S0.

## Adjudicación de TC-024

La firma nueva de full85 es `WorkerFailed: NoMatches("#diff_status")`, originada en `AbDiffPanel.set_status` durante el cierre de la app. El evento del botón puede crear el worker después de que `wait_for_complete()` consulte el conjunto de workers; además, la instalación del estado final llega por `call_from_thread`. Salir del contexto antes de ese callback desmonta el DOM y produce el `NoMatches`.

El driver ahora espera el estado observable final que contiene **ambos** nombres `.md` y `.html`. No se relajaron `DIFF_REPORT_FILENAME_REGEX`, `DIFF_REPORT_HTML_FILENAME_REGEX` ni la aserción de ambas rutas.

La reproducción queda reconciliada, sin ocultar los pases aislados:

- Full85 contextual: RED en `red-full85/junit.xml`.
- Mismo `85ed7210` aislado: 1/1 PASS en `repro-85ed-tc024/`.
- Base `0c3a6bd4` aislado: 1/1 PASS en `repro-base-tc024/`.
- Probe last23: head330 y base, 1/1 PASS cada uno en `repro-last23-head330-tc024/` y `repro-last23-base-tc024/`.

La firma es una carrera real del driver expuesta por contexto, no una regresión persistente del generador de reportes.

## Integridad y seguimiento

`SHA256SUMS` cubre los artefactos finales. Los transcript externos fueron seleccionados/normalizados con `archive_external.py`; las ejecuciones nuevas usan `run_focused.py`. Las fechas de `steps.log` proceden de reloj real. La siguiente full-suite debe ejecutarse sobre el commit resultante; este paquete no sustituye ese gate.
