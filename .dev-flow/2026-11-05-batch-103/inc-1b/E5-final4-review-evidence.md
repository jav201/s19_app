# E5 revisión final 4 — F3-01 y D-04

Revisión limitada a los dos bloqueos anteriores, actualizada tras la corrección de `pytest_temp_account`. Este texto sustituye el NO-GO anterior de este informe. No ejecuté tests ni verificadores dinámicos; sólo lectura estática y búsquedas. La única escritura es este informe.

## Veredicto

- **F3-01: GO, cerrado.**
- **D-04: GO, cerrado.**

**Resultado conjunto: GO para F3-01 y D-04.** Este veredicto no evalúa ni reabre otras puertas.

## F3-01 — redacción corregida y verificada estáticamente

`pytest_temp_account` está incorporado a `GENERAL_RULES` y sustituye la cuenta por `pytest-of-<USER>` (`redact_e5.py:64-69`). Su known-present está registrado en `:217-223`; el bucle de `:236-250` exige una sustitución efectiva y que el patrón no vuelva a detectar el resultado. El censo archiva **16/16** (`redaction-census.json:33-36`).

La pasada registra 139 sustituciones en `law-recheck.txt`, 43 en `previous-winci-failures.txt` y la corrección de dos identidades en `matrix/post-fix-contract.txt` (`redaction-census.json:37-49`). El estado almacenado es 159 archivos, `post_hits_outside_exceptions={}` y ocho excepciones declaradas (`:31,51-69`).

Las búsquedas independientes sobre esos tres archivos no encontraron las cuentas conocidas, rutas personales, IP concreta ni formas `pytest-of-` seguidas de un identificador crudo. `law-recheck.txt:11,138-176` conserva ahora `pytest-of-<USER>`; `matrix/post-fix-contract.txt:249,299` contiene `<USER>`. `full-six-families-final.txt:1` mantiene `<HOME>`. El bloqueo concreto anterior queda resuelto.

## D-04 — cobertura e integridad actuales

El manifest raíz tiene **23 entradas**, incluidos `law-recheck.txt`, `previous-winci-failures.txt`, el redactor y el censo actualizados (`evidence-e5/SHA256SUMS.txt:6,11-13`). Junto con las 58 entradas de los otros cinco manifests, la cobertura es **81**, coherente con el PASS comunicado `manifests=6 files=81`.

La construcción de entradas conserva la ordenación explícita por `path.name` y la serialización desde ese orden (`refresh_manifests.py:24-37`). No queda la discrepancia de cobertura que motivó D-04.
