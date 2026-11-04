# E5 review rulings — batch-102

Fecha: 2026-11-03

## Revisiones

- Code review: PASS-WITH-NOTES (0 blocker / 0 high / 2 major / 5 minor).
- Security review: PASS-WITH-NOTES (0 blocker / 0 high / 2 minor).
- Test-case audit: PASS-WITH-NOTES (cobertura 1:1 por incremento; discrepancias menores).

## Correcciones aplicadas en E5

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
