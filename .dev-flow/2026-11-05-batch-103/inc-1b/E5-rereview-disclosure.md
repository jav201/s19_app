# E5 re-review — Alcance D: divulgación de secretos y evidencia

Base inspeccionada: rama `b103-inc1b-integration`, HEAD `305e5892`, con los cambios E5 sin commit presentes en el working tree. Las revisiones anteriores describen bases anteriores; aquí sólo se usa su SEC-03 como lista de comprobación, no como descripción del código actual.

Revisión exclusivamente estática. No ejecuté pytest, colección, probes, producto, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git. No modifiqué producto, tests, workflow, ledger ni evidencia preexistente. La única escritura es este informe.

## Veredicto

**NO-GO para Alcance D y para publicar/ejecutar WinCI como una batería cuyos fallos no divulgan contenido.**

Persisten **tres HIGH, un MEDIUM y un MINOR**. Los dos primeros HIGH dejan respectivamente una vía concreta de republicación en el fallo agregado y una captura de logs ciega a `exc_info`/`stack_info`. El tercero es la ausencia del control outer obligatorio sobre stdout, stderr y JUnit. El GREEN Linux `160 passed / 96 skipped` no demuestra ninguna de esas propiedades y no es evidencia WinCI.

| ID | Severidad | Clase | Estado | Resumen |
|---|---|---|---|---|
| D-01 | HIGH | impl | ABIERTO | `_run_arms()` puede copiar el ledger con payload al mensaje final de pytest/JUnit. |
| D-02 | HIGH | impl | ABIERTO | La captura examina sólo `getMessage()` y omite excepciones y stacks. |
| D-03 | HIGH | design-gap | ABIERTO | No hay controles outer/pytester known-bad sobre stdout, stderr y JUnit; el workflow conserva y publica esos bytes en bruto. |
| D-04 | MEDIUM | impl | ABIERTO | Hay rutas personales sin redactar en evidencia E5 y canarios de control conservados en patches de evidencia. |
| D-05 | MINOR | impl | ABIERTO | El clasificador del fallo del probe no reconoce el mismatch real y lo etiqueta `unclassified`. |

No encontré un BLOCKER o MAJOR adicional en el alcance acotado. Esto no reduce los HIGH anteriores.

## Hallazgos abiertos

### D-01 — HIGH · impl — el agregador de fallos puede republicar payload

Ubicaciones actuales:

- `tests/test_b103_clipboard_tail.py:302-310`: `_counts()` usa `(key, actual, obs)` como mensaje; `obs` contiene app/OS, payloads, OSC y procesos con `kwargs`.
- `tests/test_b103_clipboard_tail.py:324-333` y `:336-343`: otras aserciones conservan listas o valores observados como diagnóstico.
- `tests/test_b103_clipboard_tail.py:365-374`: `_run_arms()` agrega `str(exc)` y vuelve a usar el texto agregado como mensaje de la aserción exterior.
- `tests/test_b103_clipboard_tail.py:1004-1045`: R-TUI-043.13/101 llama a `_success()`/`_failure()` con un canario dentro de brazos gestionados por `_run_arms()`.

Si cambia una cardinalidad antes de llegar a `_no_secret()`, el `AssertionError` de `_counts()` contiene el ledger completo. `_run_arms()` lo serializa otra vez y la aserción exterior lo entrega a pytest. No es sólo una preocupación sobre mensajes futuros: la cadena concreta `_counts()` → `_run_arms()` → aserción exterior existe en la ruta de no-divulgación actual.

La corrección local de R-TUI-043.13/102 no cubre esta ruta /101 ni el resto de consumidores de `_run_arms()`. Tampoco basta cambiar el mensaje de `_no_secret()`: el fallo puede ocurrir antes de llamarla.

Impacto: `.github/workflows/clipboard-windows.yml:78-86` combina stderr con stdout, escribe el transcript y genera JUnit; `:88-97` sube ambos con `if: always()`. El gate posterior no puede retirar bytes ya emitidos en consola.

**Cierre requerido:** impedir que cualquier `AssertionError` de estos brazos contenga payload, prefijos o representaciones derivadas; aplicarlo a todo el censo de `_run_arms()`, no sólo al nodo hostile /102. Conservar oráculos exactos mediante diagnósticos estructurados y genéricos, y demostrar el fallo mediante D-03.

### D-02 — HIGH · impl — `exc_info` y `stack_info` quedan fuera del oráculo

Ubicaciones actuales:

- `tests/support/b103_clipboard.py:438-446`: `_LogCapture.emit()` guarda únicamente `(name, levelname, record.getMessage())`.
- `tests/test_b103_clipboard_tail.py:355-362`: `_no_secret()` busca formas completas, prefijo, escape y `repr`, pero sólo dentro del tercer elemento de esas tuplas.
- `tests/test_b103_clipboard_windows.py:141-146` y `:728-758`: el brazo Windows igualmente reduce los records a mensajes y sólo busca el payload completo.
- `s19_app/tui/os_clipboard_input.py:824-827`: la ruta real de copia usa `logger.debug(..., exc_info=True)` al fallar el mirror de clipboard.

Por tanto, un canario presente sólo en el texto de una excepción o en `stack_info` no llega a la estructura examinada por los tests, aunque otro handler sí pueda formatearlo y pytest/logging pueda imprimirlo. El uso real de `exc_info=True` hace que la laguna no sea hipotética como superficie de logging. **No afirmo que el producto actual haya emitido un secreto por esta vía; afirmo que el oráculo actual no podría detectarlo.**

La cobertura también es incompleta en Windows porque `_assert_log_excludes()` no comprueba prefijo, `repr` ni forma escapada, a diferencia de `_no_secret()`.

**Cierre requerido:** capturar la forma formateada completa del `LogRecord` —incluidos exception text y stack text— y ejercitar un record known-bad para cada canal. Unificar las formas buscadas: valor completo, prefijo discriminante, `repr`, escape y la forma serializada en XML. No basta añadir más assertions sobre `getMessage()`.

### D-03 — HIGH · design-gap — falta la prueba outer de que el propio fallo no filtra

Lo que sí existe:

- `evidence-e5/matrix/contract_probe.py:95-148` fuerza mismatch de escritura y probe, pero inspecciona directamente `str(exc)` o la metadata devuelta dentro del mismo proceso.
- `evidence-e5/matrix/contract_probe.py:238-280` crea JUnit sintético para el gate; `:250-256` comprueba que la **salida del gate** no copie un motivo de skip.
- `evidence-e5/tail/redaction-e5-fixes.txt:1-2` declara el resultado de comprobaciones sobre `str(AssertionError)` y ausencia de ciertos asserts hostile.
- `tests/test_b103_clipboard_windows.py:1968-2002` contiene un pytester, pero es un control de aislamiento Win32, no de divulgación.

Lo que falta es ejecutar un pytest hijo que falle de forma deliberada y auditar el resultado completo. No hay en los archivos revisados un `runpytest` que fuerce los fallos SEC-03 y lea stdout, stderr y el JUnit generado por ese mismo proceso. Tampoco hay un control que inyecte `exc_info`/`stack_info`, ni brazos outer para cardinalidad hostile, cwd, argv o `kwargs["input"]` incorrectos.

El contraste es importante:

- `tests/support/b103_winci_gate.py:81-105` y `:139-154` imprimen nodeids/conteos y no copian cuerpos de failure/error ni motivos de skip. Ésa es una corrección válida del **gate transcript**.
- `.github/workflows/clipboard-windows.yml:75-97`, sin embargo, conserva y publica el pytest transcript y el JUnit originales, sin escáner de divulgación ni redacción previa al upload.

El control negativo del gate en `evidence-e5/matrix/linux-junit-gate-negative.txt` demuestra clasificación de outcomes, no ausencia de payload en el propio pytest/JUnit. La batería verde tampoco puede demostrar el comportamiento de un fallo que no ocurrió.

**Cierre requerido:** añadir controles outer/pytester con una aserción de resultado esperado —el hijo debe fallar— y, sobre stdout, stderr y JUnit crudo y parseado, exigir ausencia de payload, prefijo, `repr`, escape y variantes XML. Cubrir como mínimo:

1. mismatch del probe que atraviese `test_runner_clipboard_probe`;
2. mismatch del round-trip y excepciones encadenadas de lectura/escritura;
3. canario en mensaje, exception traceback y `stack_info`;
4. cardinalidad hostile incorrecta y fallo de `_counts()` dentro de `_run_arms()`;
5. argv/cwd/`kwargs["input"]` incorrectos en R-TUI-043.13/102;
6. evidencia archivada equivalente a la que sube el workflow.

Redactar el artefacto después del upload no cierra la consola: la prevención en tests/logging es primaria; un escáner previo a publicación debe ser defensa adicional fail-closed.

### D-04 — MEDIUM · impl — redacción incompleta de los artefactos E5

Hay rutas personales todavía almacenadas en artefactos nuevos. No las reproduzco aquí:

- `evidence-e5/tail/E5-FIXES.md:41`;
- `evidence-e5/tail/run_linux_tail_e5_fixes.sh:4` y `:19`;
- `evidence-e5/tail/linux-tail-e5-fixes.txt:1`;
- `evidence-e5/tail/linux-tail-e5-fixes-transport1.txt:1`;
- `evidence-e5/tail/linux-tail-e5-fixes-transport4.txt:1`.

`evidence-e5/redact_e5.py:5-15` cubre ciertas formas Windows, `/home/...` e identidades sueltas, pero no la forma `/mnt/c/Users/<...>` ni la cuenta WSL usada por ese runner. Su propio archivo contiene las identidades reconstruibles y se excluye de la transformación (`:17-19`). `evidence-e5/redaction.txt:29` registra una sustitución en `transport1`, pero la ruta personal inicial permanece.

El redactor de matrix sí incorpora las dos formas faltantes (`evidence-e5/matrix/redact_and_hash.py:8-18`), pero sólo recorre el directorio matrix (`:24-25`); es una corrección parcial que no alcanza `tail/`.

Además, la familia de canarios buscada produjo diez hits en patches, no en transcripts/JUnit:

- `evidence-e5/integration-pre-ci.patch:349`;
- `evidence-e5/matrix/integration-e5-fix.patch:517`, `:1342-1345` y `:1587-1590`.

Esos valores son literales de fixtures dentro del diff fuente, **no salida capturada de WinCI ni credenciales reales identificadas**. Aun así, son los payloads de control que la regla escrita de publicación dice no registrar en evidencia. Con esa regla vigente, los patches no pueden contarse como artefactos redactados a `0 hits`; excluirlos de publicación o cambiar la regla sería una decisión explícita, no algo que esta revisión pueda asumir.

**Cierre requerido:** aplicar un único censo de identidades/rutas/canarios a todos los artefactos E5, incluidos patches, scripts, históricos y fallos de transporte; publicar sólo los resultados redactados y recalcular los manifests desde los bytes almacenados. No alterar registros antiguos para ocultar un fallo heredado.

### D-05 — MINOR · impl — mismatch seguro, pero mal clasificado

`tests/support/b103_clipboard.py:204-206` devuelve el mismatch con el prefijo `win32 write ok; PowerShell read ...`. En cambio, `tests/test_b103_clipboard_windows.py:149-159`, especialmente `:155`, busca `win32 write ok, PowerShell read ...` con coma. El mismatch real cae por tanto en `stage=unclassified` en `:157-158`, no en `round-trip-mismatch`.

Ya no se divulga clipboard en este camino; el defecto restante es de diagnóstico/evidencia, no una fuga. Debe corregirse el acoplamiento de strings —preferiblemente con metadata estructurada— y quedar cubierto por el control outer de D-03.

## Bloqueos SEC-03 anteriores que sí están corregidos

Estas correcciones son estáticas y acotadas; no se elevan a resultado WinCI ni cierran D-01 a D-03:

| Control | Estado actual y ubicación |
|---|---|
| Mismatch del probe sin clipboard/nonce | **CORREGIDO en contenido.** `_probe_once()` informa tipo/resultado y longitudes (`tests/support/b103_clipboard.py:188-207`); `test_runner_clipboard_probe()` vuelve a reducirlo a stage/longitud (`tests/test_b103_clipboard_windows.py:181-192`). Queda D-05. |
| Round-trip de escritura | **CORREGIDO en contenido.** El mismatch informa `expected_chars`/`actual_chars`, no fragmentos (`tests/support/b103_clipboard.py:600-626`). El contrato interno lo fuerza en `evidence-e5/matrix/contract_probe.py:95-117`; falta el outer. |
| Mensaje de `_no_secret()` | **CORREGIDO.** Ya no devuelve las coincidencias y comprueba valor/prefijo/escape/`repr` (`tests/test_b103_clipboard_tail.py:355-362`). La cobertura de exception/stack sigue abierta en D-02. |
| Aserciones hostile de proceso/kwargs/input | **CORREGIDO en /102.** `_success()` se convierte a un fallo genérico y cardinalidad, argv, shell, cwd e input usan mensajes fijos o numéricos (`tests/test_b103_clipboard_tail.py:1162-1196`). La ruta agregada /101 sigue abierta en D-01. |
| Diagnósticos de QUIT | **CORREGIDO en los caminos revisados.** Probe, PowerShell, Base64 y seed usan fallos genéricos (`tests/test_b103_copy_quit_dialog.py:83-90`, `:154-185`); la comprobación de seed sin copia también evita imprimir el contenido (`:408-413`). |
| Diagnósticos heredados Windows | **CORREGIDO parcialmente.** Hay formas/longitudes en vez de contenido (`tests/test_b103_clipboard_windows.py:122-138`) y el assert de logs da índices/conteos (`:141-146`). Falta la superficie completa de logging de D-02. |
| Salida del gate JUnit | **CORREGIDO para su propio transcript.** No replica cuerpos ni motivos (`tests/support/b103_winci_gate.py:81-105`, `:139-154`). No es redacción del pytest transcript/JUnit original ni prueba outer. |

## Evidencia: qué se comprobó y qué no

- `evidence-e5/full-six-families.txt:1-14` conserva el tally `160 passed, 96 skipped`. Se acepta como el resultado Linux ya entregado y **no se repitió**. No prueba WinCI, fallos seguros ni mutantes.
- `evidence-e5/mutants/VALIDATION.md:16` declara `0/71` mutantes de producto y cero tests de producto en esa validación. Los self-tests del harness no matan mutantes de las aserciones de redacción.
- `evidence-e5/matrix/post-fix-contract-v3.txt:1-9` registra siete PASS de contratos internos. Son evidencia de los chequeos directos descritos allí, no de stdout/stderr/JUnit de un pytest fallido.
- Las búsquedas acotadas de tokens GitHub/AWS/JWT, claves privadas, Bearer, nonces concretos y la familia de canarios no dieron hits en `evidence-e5/**/*.txt` o `**/*.xml`. Los hits de canarios localizados en patches se detallan en D-04. Esto no es una prueba exhaustiva de ausencia de todo secreto.
- No encontré un veredicto WinCI ni resultados de mutantes de producto en los artefactos revisados. Las rutas WinCI escritas en tests y los patches conservados siguen siendo rutas/artefactos, no ejecución.

## Condiciones mínimas para cambiar Alcance D a GO

1. Cerrar D-01 en todo el censo de agregadores y aserciones con observation ledgers.
2. Cerrar D-02 para mensaje, `exc_info` y `stack_info`, con formas derivadas incluidas.
3. Añadir y ejecutar en el entorno autorizado los controles outer known-bad de D-03; archivar resultados que prueben simultáneamente que el hijo falló y que sus tres superficies no contienen el canario.
4. Mantener el gate de outcomes, pero añadir una barrera fail-closed de divulgación antes de publicar artefactos; no usar la redacción posterior como sustituto de una consola segura.
5. Regenerar/redactar la evidencia afectada por D-04 y recalcular hashes desde los bytes almacenados.
6. Corregir D-05 y repetir la revisión estática sobre el árbol resultante. El veredicto WinCI funcional y los mutantes de producto siguen siendo puertas separadas que esta revisión no declara.
