# E5 review rulings — batch-102

Fecha: 2026-11-03 (cierre E5: 2026-11-04)

## Revisiones

- Code review: PASS-WITH-NOTES (0 blocker / 0 high / 2 major / 5 minor).
- Security review: PASS-WITH-NOTES (0 blocker / 0 high / 2 minor).
- Test-case audit: PASS-WITH-NOTES (cobertura 1:1 por incremento; discrepancias menores).

## Cierre E5 — suite completa local y correcciones de guardas

La suite completa (`pytest tests`, 5403 tests) corrió localmente con xdist (72F/5331P/12S/4X). Clasificación completa en `04-validation.md`. Los 72 fallos se repartieron en: regresiones del batch (9 grupos, corregidos y verificados en verde), preexistentes/de entorno (48, confirmados en el commit base `2f2f932` vía worktree) y paralelo-flaky (verdes en serie).

Correcciones aplicadas en el cierre:

1. `tests/test_b102_clipboard.py`: el test renombrado a `test_tc_b102_01_over_cap_paste_is_capped_at_write_cap` — el nombre previo derivaba `AT-65536` (spec §2.4) y rompía G1 del registry.
2. `tests/test_id_registry.py`: `EXPECTED_SCANNED_TEST_FILES` 239 → 246, medido (los 7 módulos `test_b102_*`).
3. `tests/test_import_census.py`: `MEASURED_SAFE_TEXT_CONSUMERS` + `a2l_parameter_picker` y `MEASURED_SAFE_TEXT_TEST_IMPORTERS` + `test_b102_flow_file_chooser`, medidos.
4. `styles.tcss`: los dos `#969aad` del modal bulk (dentro del bloque Calm Dark) pasan a `$fg-base` (el conjunto Calm Dark no tiene token dim).
5. `screens.py` + `test_b102_clipboard.py`: argumentos de `query_one` en forma Name (AT-B83-08).
6. `tests/test_b99_staging.py`: `import_external_ref` entra al allow-list de escritura final de LLR-155.3 — staging confinado en el workarea, claim exclusivo `O_CREAT|O_EXCL`, `os.replace` atómico, unlinks solo de archivos propios en fallos.
7. `tests/test_b97_flow_execution.py`: 4 superposiciones nombradas registradas en la guarda de CSS (dc55e56 ×2, db1a8f7, 7a3e536).
8. `window_help.py`: líneas `Filter`/`Prev`/`Next` agregadas a la sección `patch` (TC-B97-32 / AT-B97-14).
9. `tests/test_b97_width.py`: superposición nombrada para TC-B97-38 (ver ruling 1 abajo).

## Rulings del cierre E5 — pendientes de ratificación del operador

1. **TC-B97-38 (LLR-149.5) relajación del brazo after_run a 118x54.** La fila de anotación de origen que Inc 7 pinta en las tarjetas con ref de archivo crece el marco del pipeline una fila — por diseño, el marco es exactamente tarjetas + borde. A 118x54 el área de resultado queda una fila más corta: su contenido corre 1 fila (`max_scroll <= 1` en ese brazo), la columna del scrollbar estrecha el contenido 2 columnas y la fila `wrote` de ruta larga se lee haciendo scroll al final, aserción por stem (`fw_app_patched`). El resto de cláusulas (geometría, separadores, cabezales de avisos) quedan intactas. Alternativa rechazada en E5: inlinear la anotación (rompería las expectativas de `test_b102_flow_file_chooser` sobre la tarjeta).
2. **TC-B100-64 (LLR-173.6l) movimiento del congelado de imports.** `SCREENS_MODULES_AT_BASE` se congeló en la cabeza del batch-102 (5 imports nuevos en `screens.py`, todos sirviendo los modales/pantallas del propio batch). La redacción "allows 0 new ones" de LLR-173.6l necesita la misma enmienda para que la guarda vuelva a ser un tripwire y no un obstáculo.

## Correcciones aplicadas en E5 (ronda anterior)

1. `os_clipboard_input.py`: el comando PowerShell de escritura fija `[Console]::InputEncoding=[System.Text.Encoding]::UTF8` antes de leer stdin, cerrando la corrupción Unicode de la capa rescate.
2. `pyproject.toml`: la dependencia runtime de Textual sube a `>=8.2.8,<9`, acorde con los seams privados que usa `CappedTextArea`.
3. `a2l_parameter_picker.py`: `on_mount` reconstruye el ledger para poblaciones pre-mount; la normalización de direcciones rechaza `bool`.
4. `app.py`: la clave A2L precalculada tolera `mem_map=None` y la documentación ya no promete `len(mem_map)` sin guard.

## Hallazgos abiertos aceptados / backlog

- MINOR: el aviso de truncado de 64 KiB del modal bulk puede dispararse también por tipeo largo, no solo por paste; se acepta porque el contrato visible es el buffer acotado.
- MINOR: `powershell.exe` se resuelve por PATH; hardening futuro: ruta absoluta System32/sysnative.
- MINOR/informativo: TOCTOU source-side residual en `import_external_ref`; el destino sigue confinado y endurecido, la integridad de contenido queda documentada como riesgo residual.
- Evidencia: la primera full-suite sin ámbito falló por `prototypes/load_projects/appcopy/tests/conftest.py` (preexistente); la suite batch-102 se acotó a `tests/`.
- Auditoría: TC-SEL-04 podría espiar `set_parameters` además del estado; FB-04 podría releer pipeline tras remove; ambos mutantes principales ya están cubiertos.
- `trace_check.py` no reconoce los ids `R-B102-*` en formato de lista numerada ni los TC batch-scoped como casos `<req>/<n>`; se conserva trazabilidad en los artefactos del batch y se deja la integración al canon estricto para un batch de canon, no para este hot-fix.
- Entorno (fuera del alcance del batch): 23 snapshots de densidad y ~25 aserciones de color/perf fallan en este host por exportación SVG con tema neutro y bounds de <1 s medidos en host más rápido; se reproducen en el commit base. Se deben re-fijar las baselines o investigar el tema de exportación en un host sano, en un batch de entorno separado.

