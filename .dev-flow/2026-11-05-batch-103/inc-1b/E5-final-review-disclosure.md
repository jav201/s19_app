# E5 revisión final independiente — divulgación y evidencia

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. Revisión independiente de D-01…D-05 y de los defectos introducidos directamente por sus correcciones.

No ejecuté pytest, colección, probes, producto, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto, tests, workflow o evidencia. Las comprobaciones dinámicas se limitaron a verificadores read-only de hashes/manifests y búsquedas acotadas. La única escritura es este informe.

## Veredicto

**NO-GO para divulgación/evidencia.**

Queda un **HIGH de implementación** en la barrera previa a publicación: el escáner no reconoce una familia de canarios realmente usada por los tests Windows. Además persisten dos **MEDIUM** —la evidencia ejecutada final no está archivada y el detector de tail conserva una laguna de formas XML— y el **MINOR** D-05. No encontré un BLOCKER o MAJOR adicional dentro del alcance permitido.

| ID | Severidad | Clase | Estado | Resumen |
|---|---|---|---|---|
| D-06 | HIGH | impl | NUEVO, ABIERTO | El escáner fail-closed omite la familia `SECRET-TEXT-` usada en WinCI. |
| D-03 | MEDIUM | design-gap | PARCIAL | El outer está bien escrito y el orquestador comunica su PASS, pero no hay transcript/JUnit archivado de la selección final; la batería archivada tampoco es la última comunicada. |
| D-02 | MEDIUM | impl | PARCIAL | `LogRecord` ya cubre excepciones/stacks, pero `_no_secret()` de tail sigue sin las formas XML exigidas. |
| D-05 | MINOR | impl | ABIERTO | El mismatch real usa coma y el clasificador exige punto y coma; los controles nuevos reproducen sólo este último. |
| D-01 | — | — | CERRADO | El agregador ya no serializa `str(exc)` ni el ledger. |
| D-04 | — | — | CERRADO para los bytes actualmente almacenados | Cero residuos fuera de excepciones declaradas; manifests íntegros. |

El HIGH y los restos anteriores impiden un GO aun aceptando como comunicados los resultados Linux `160 passed / 96 skipped` y `44 passed / 2 skipped`. Ninguno es un veredicto WinCI ni una ejecución de mutantes de producto.

## D-06 — HIGH · impl · la barrera de publicación tiene un censo incompleto

`tests/support/b103_artifact_safety.py:14-26` enumera los canarios que reconoce. Incluye el prefijo `SECRET-COPY-` y la familia de selección, pero ninguna entrada de la familia `SECRET-TEXT-`. Esa familia sí aparece en las llamadas WinCI de `tests/test_b103_clipboard_windows.py:1105` y `:2037`; una búsqueda acotada encontró cuatro líneas con ella en ese archivo y cero en el escáner y en sus tests.

Los known-bad del escáner usan exclusivamente `HOSTILE_CANARY` (`tests/test_b103_winci_gate.py:277-311`). Por tanto, el PASS comunicado de esos controles no demuestra detección de toda la población real de las seis familias.

Hay una ruta concreta de divulgación: si el oráculo de logs falla en una de esas llamadas, el traceback puede incluir la línea fuente con el literal, además de cualquier aparición del payload en logging. El workflow conserva stdout+stderr y JUnit (`.github/workflows/clipboard-windows.yml:77-92`); el escáner no marca esa familia y el upload está permitido cuando su outcome es success (`:94-117`). Un fallo funcional se publica deliberadamente si el escáner queda verde, de modo que este falso negativo llega exactamente a los artefactos que la barrera debía proteger.

**Cierre requerido:** censo completo de los literales/canarios de las seis familias, incorporación de los ausentes y known-bad del escáner para cada familia y para las formas directa, prefijo, `repr`, escape y XML. Añadir un brazo que atraviese un fallo real de la llamada WinCI, no sólo un canario synthetic aislado. No reproduzco aquí ningún canario completo.

## D-03 — MEDIUM · design-gap · la ejecución comunicada no está archivada

### Lo que el código outer sí demuestra si pasa

La ruta escrita es sólida en los puntos solicitados:

- `tests/test_b103_e5_safety.py:425-438` enumera exactamente 12 nodeids known-bad.
- `:458-467` ejecuta un pytest hijo y exige retorno no cero.
- `:469-484` exige 12 casos, el conjunto exacto de 12 fallos y cero errores. Por tanto, un PASS del outer demuestra **12/12 RED**, no sólo un hijo genéricamente fallido.
- `:486-494` audita stdout, stderr, JUnit crudo y una superficie parseada que incluye tags, nombres/valores de atributos, texto y tails (`:441-447`). `_assert_no_canary()` aplica las formas derivadas de Windows (`:37-42`).
- Los 12 brazos incluyen probe, round-trip, encadenamiento de lectura/escritura, mensaje/`exc_info`/`stack_info`, `_counts()` dentro de `_run_arms()` y cardinalidad/argv/cwd/input hostile (`:213-421`). Los marcadores seguros esperados están en `:496-507`.

El orquestador comunica **44 passed / 2 skipped** para la selección correctiva. Si ese resultado corresponde a este working tree —como se ha indicado—, el PASS del nodo outer implica que sus assertions 12/12 y de no divulgación pasaron. Esto es un **resultado ejecutado comunicado**, no una ejecución realizada por esta revisión.

### Lo que no se puede auditar en `evidence-e5`

No hay ningún transcript o JUnit de la selección 44/2 ni un resumen archivado del outer 12/12. `evidence-e5/run_e5_corrective.py:11-25` es solamente la ruta de ejecución; no es su resultado y no solicita un JUnit padre. Las búsquedas de `44 passed`, `12 failed`, del nodeid outer y de `test_b103_e5_safety.py` sólo localizan el launcher/código, no evidencia de ejecución.

Además, `evidence-e5/full-six-families.txt:14` conserva `160 passed, 96 skipped in 1449.12s`, mientras el resultado final comunicado es el mismo tally en **1863.17 s**. El archivo almacenado corresponde por tanto a una ejecución anterior; no lo presento como el resultado final ni como una ejecución nueva de esta revisión.

**Cierre requerido:** archivar, redactar y cubrir con manifests los bytes originales de la selección 44/2 y evidencia suficiente del outer 12/12 y sus cuatro superficies, junto con el transcript final 160/96 de 1863.17 s. No hace falta repetir una ejecución si el orquestador conserva esos bytes; si no los conserva, la repetición queda para la fase autorizada. Este informe no convierte la ausencia de archivo en una afirmación de que los tests no se ejecutaron.

## D-02 — MEDIUM · impl · excepciones/stacks corregidos; formas XML de tail aún no

La corrección principal sí está presente:

- `_LogCapture.emit()` guarda `self.format(record)` (`tests/support/b103_clipboard.py:486-494`), que incorpora mensaje, exception text y stack text.
- Windows formatea `LogRecord` completos y busca full/prefijo/`repr`/escape/XML (`tests/test_b103_clipboard_windows.py:143-185`). El control directo recorre mensaje, excepción y stack para todas las formas (`tests/test_b103_e5_safety.py:57-91`). El outer exige que ambos detectores reconozcan los tres canales (`:254-324`).
- Las dos conversiones de excepciones encontradas en el helper usan `raise AssertionError(...) from None`: proceso PowerShell (`tests/support/b103_clipboard.py:647-650`) y decodificación Base64/UTF-8 (`:703-706`). Así se evita republicar la causa/contexto original en los brazos de lectura/escritura.

El resto es que `_no_secret()` de tail sigue buscando únicamente valor, prefijo, escape, prefijo escapado y `repr` (`tests/test_b103_clipboard_tail.py:367-374`). No incorpora las formas XML que D-03 exige auditar y que la corrección Windows sí centraliza. El control directo de formas derivadas ejercita sólo `windows._assert_log_excludes()` (`tests/test_b103_e5_safety.py:83-91`); los known-bad del outer pasan el canario sin transformar a ambos detectores (`:295-312`).

No afirmo que el producto haya emitido un payload por esta vía. El defecto restante es que el oráculo de tail no detectaría una aparición exclusivamente XML-escapada y el outer no ejercita ese caso en el canal de log. Debe reutilizar el censo común de formas y añadirse el known-bad correspondiente.

## D-05 — MINOR · impl · el mismatch real sigue cayendo en `unclassified`

El helper real construye el mismatch con **coma** tras `win32 write ok` (`tests/support/b103_clipboard.py:246-252`). El clasificador exige **punto y coma** en esa posición (`tests/test_b103_clipboard_windows.py:188-198`). El consumidor real entrega precisamente ese `result` a `_probe_failure_metadata()` (`:220-231`), por lo que un mismatch real aún se clasifica como `unclassified`.

Los dos controles nuevos no detectan la discrepancia porque fabrican el detalle con punto y coma: prueba directa (`tests/test_b103_e5_safety.py:45-54`) y brazo outer (`:213-220`). Tampoco aprovechan `result.stage`, aunque `_ProbeDetail` ya proporciona metadata estructurada (`tests/support/b103_clipboard.py:186-210`).

No hay divulgación de clipboard en este camino; el impacto es diagnóstico/evidencia. Deben alinearse productor y clasificador —preferiblemente mediante `stage`— y el control debe obtener el detalle del productor real o de un `_ProbeDetail` equivalente, no repetir manualmente el formato que se desea probar.

## D-01 — cerrado

`_counts()` emite mensajes fijos y ya no incluye `actual`/`obs` (`tests/test_b103_clipboard_tail.py:308-316`). `_run_arms()` captura `AssertionError` sin leer su texto y agrega únicamente labels (`:377-386`). En la ruta hostile, el fallo de `_success()` se sustituye por un mensaje genérico con `from None`, y cardinalidad, argv, cwd e input usan diagnósticos fijos (`:1186-1216`). El outer cubre tanto `_counts()` agregado como los cuatro fallos hostile y audita todas las superficies.

Con la ruta escrita y el PASS outer comunicado, cierro la vía concreta D-01. Esto no absorbe el falso negativo independiente del escáner descrito en D-06.

## D-04 — cerrado para la evidencia almacenada

Leí `E5-evidence-redaction.md` y contrasté sus excepciones sin ejecutar el redactor ni reproducir canarios:

- Búsqueda acotada de hogares Windows/MSYS/WSL/Unix/macOS: **0 archivos con residuos**.
- Cuentas mediante `USER/USERNAME/LOGNAME/GITHUB_ACTOR/HOSTNAME`: **0 residuos**; los `hostname` XML localizados están con placeholders, aparte de las definiciones del redactor.
- IPv4 RFC1918: ninguna coincidencia fuera del detector del propio redactor.
- Familias de canarios/nonces: 13 líneas coincidentes en total; cinco pertenecen al self-census/definiciones del `redact_e5.py` excluido y ocho a los tres controles declarados. No hubo hits fuera de esos archivos.

Las ocho retenciones coinciden con `redaction-census.json:3-29,80-88`: cinco en `matrix/contract_probe.py`, dos en `quit/validate_routes.py` y una en `legacy/redaction_runtime_probe.py`. Son excepciones explícitas de controles ejecutables, no un `0 hits` absoluto. Los dos patches están marcados como copias históricas no aplicables (`integration-pre-ci.patch:1-4` y `matrix/integration-e5-fix.patch:1-4`). Se conserva el placeholder de kernel declarado en `legacy/REPORT.md:50`; no alteré ese fallo heredado ni ningún verdict.

Verificación read-only de manifests:

- `python -B refresh_manifests.py --check`: **PASS**, seis manifests, 74 archivos; cobertura exacta y hashes de los bytes almacenados.
- `sha256sum -c --quiet SHA256SUMS.txt` desde raíz, `legacy`, `matrix`, `mutants`, `quit` y `tail`: exit 0 en los seis.

Esto cierra D-04 únicamente para los archivos actuales. Los transcripts finales ausentes de D-03 deberán pasar por la misma redacción y reconstrucción de manifests al incorporarse; su ausencia no se cuenta como evidencia limpia.

## Límites y puertas separadas

- Acepto como datos del orquestador los resultados Linux finales 160/96 y 44/2; no los ejecuté ni encontré sus bytes finales archivados.
- No hay veredicto WinCI ni ejecución de mutantes de producto que esta revisión pueda declarar.
- AT-I1b-8 sigue manual y no se cierra: el manifiesto conserva su nodo, razón y categoría `manual` (`tests/support/b103_winci_manifest.json:359-363`), y el gate admite exactamente esa excepción (`tests/support/b103_winci_gate.py:260-264`).
- No cambié el fallo heredado, evidencia histórica, producto, tests, workflow ni manifests. Para cambiar este veredicto deben cerrarse D-06, D-02, D-03 y D-05 sobre el árbol resultante, manteniendo separadas las puertas WinCI y de mutantes.
