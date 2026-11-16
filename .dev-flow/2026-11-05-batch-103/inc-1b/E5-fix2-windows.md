# Batch-103 Inc1b E5 — Carril B fix2 Windows

Base: `305e5892` más el working tree recibido, preservando las correcciones previas y las de los demás carriles. Alcance de escritura de esta intervención: `tests/test_b103_clipboard_windows.py` y este informe nuevo. No se editaron producto, support, workflow, ledger, canon, evidencia previa ni otros tests.

## Disposición de hallazgos

### TR-01 — cleanup del holder

- `tests/test_b103_clipboard_windows.py:394`: `_reap_holder()` ejecuta, sin salida anticipada, kill inicial si sigue vivo, `wait(timeout=3.0)`, kill final si sigue vivo, `wait(timeout=1.0)`, cierre de stdout y poll de muerte. Todas las etapas se intentan aunque fallen las anteriores; el primer error se relanza y los posteriores se añaden como notas por etapa/tipo. Un proceso vivo nunca es cleanup exitoso.
- `tests/test_b103_clipboard_windows.py:432`: `_release_clipboard()` intenta independientemente `release.set()`, join de 5 s, reap completo, join final de 1 s, comprobación del supervisor y poll del holder. Captura también el error publicado por el supervisor después de cada acción y conserva el primer fallo observado.
- `tests/test_b103_clipboard_windows.py:474`: el `try` de adquisición empieza inmediatamente después de `Popen`; construcción e inicio del reader y del supervisor quedan cubiertos. La salida por error intenta reap, join/comprobación del reader y join/comprobación del supervisor sin reemplazar el fallo primario. El supervisor reapsa incluso si falla su propia espera de release.
- Los docstrings de holder y del nodo de controles se actualizaron para describir este comportamiento.

### TR-03 — dobles y oráculos de fallo

`tests/test_b103_clipboard_windows.py:650` conserva los controles dentro del nodeid ya existente, ahora en siete grupos con diez escenarios: muerte tras readiness, timeout de readiness con fallo de join, fallo de `reader.start`, fallo de kill con reintento, timeout de wait con kill/wait final, proceso imposible de matar detectado por el poll final, error primario del supervisor, supervisor vivo tras ambos joins, fallo de `release.set` y fallo de ambos joins.

El doble ya no mata espuriamente en `wait()` ni acepta `dead=False`: un timeout conserva `returncode=None`; sólo un wait posterior a un kill efectivo completa la muerte. Los oráculos exigen dos waits acotados, kills/reintentos exactos, cierre único, polls, muerte en el kill/wait final cuando el doble es matable y nota explícita de `death check` cuando no lo es. Cada grupo conserva el deadline externo de 2 s.

### Transporte binario de todos los mocks del archivo

El único transporte de proceso doblado en este archivo es el `Popen` del holder. Su stream y readiness usan ahora `bytes` (`b"HOLDING\n"`); el `Popen` real y su doble no llevan `text`, `encoding` ni `errors`, y stderr permanece redirigido a stdout binario. El doble registra los kwargs y el oráculo rechaza cualquier reintroducción del modo texto. No hay dobles de `subprocess.run`, stdin `input`, stdout de `CompletedProcess` o stderr separado en este archivo; los spies instalados son pass-through del proceso real y no se alteraron.

El `text=True` restante pertenece a la invocación real del compilador `csc.exe` usado para construir el decoy, no a un mock ni al transporte PowerShell de producto. El contraste estático con el carril de producto integrado confirma stdin codificado a bytes y stdout decodificado explícitamente en `s19_app/tui/os_clipboard_input.py:307-339,454-476`.

### TR-05 — exactitud del reader separada del pegado

`tests/test_b103_clipboard_windows.py:2303` mantiene el nodeid R-PASTE.16/1 y ahora:

1. siembra `PS-READ-Ñ\rL2\r\nL3\n`;
2. fuerza PowerShell y compara directamente `read_os_clipboard()` con ese payload exacto, incluidos Unicode, CR, CRLF y LF final;
3. recorre el `Input` real por separado y exige únicamente `PS-READ-Ñ`, su primera línea contractual;
4. exige exactamente dos arranques, ambos por la ruta PowerShell del sistema.

Ya no se exige al widget de una línea que conserve saltos que su contrato elimina, y tampoco se debilita la comprobación directa del reader.

### D-05 — metadata estructurada del probe

`tests/test_b103_clipboard_windows.py:188` usa preferentemente `result.stage`, que es la metadata expuesta por el `_ProbeDetail` real. Si no existe un stage estructurado válido, conserva la compatibilidad para write failure/read exception y reconoce tanto el mismatch real con coma como la forma heredada con punto y coma. La salida sigue limitada a stage y longitud, sin copiar el detalle ni inventar otro formato de diagnóstico.

## Nodeids y `serial_timing`

- Los 51 nombres `test_*` se conservan. La derivación AST con IDs parametrizados da **77/77 nodeids**, sin faltantes ni extras y en el mismo orden que `tests/support/b103_winci_manifest.json`.
- No se añadieron, eliminaron ni reordenaron tests o parametrizaciones.
- El requisito de marcas ya estaba satisfecho en el árbol recibido: este archivo tiene **12/12 brazos timing marcados**. El censo estático de la ley sobre todo `tests/` encontró **150 brazos AST + 2 sampled arms, 0 sin `serial_timing`**. Por tanto no añadí decoradores redundantes; marcar cualquier no-brazo habría introducido una violación de `test_r_tst_004_a_marked_non_arm_is_named`.

## Verificación estática realizada

- `compile()` y `ast.parse()` mediante `python -B` sobre `tests/test_b103_clipboard_windows.py`: correcto; 51 funciones de test y 12 marcas.
- Contraste estructural: `Popen` seguido inmediatamente por el `try` exterior; readiness bytes; no quedan `die_on_kill`, `dead=False` ni streams de readiness `str` en los dobles.
- Censo `tests.support.suite_census.timing_arms` + inspección AST de decoradores, sin importar los tests: 0 brazos desmarcados; los dos aparentes marked-non-arm del chequeo simple son exactamente los `SAMPLED_TIMING_ARMS` admitidos por la ley.
- Nodeids WinCI: `WINCI_NODEIDS 77`, `EXPECTED 77`, `MISSING []`, `EXTRA []`, `ORDER_MATCH True`.
- `git diff --check -- tests/test_b103_clipboard_windows.py`: exit 0.

## No ejecutado y puertas pendientes

No ejecuté pytest, colección pytest, probes, aplicación, PowerShell, clipboard, workflows, baterías, leyes pytest ni mutantes; tampoco hice commits ni otras mutaciones Git. Las comprobaciones anteriores fueron sólo lectura, AST/compilación y diff.

TR-01, TR-03, TR-05 y D-05 quedan **corregidos en implementación escrita**, no declarados verificados por ejecución. El orquestador debe ejecutar el clon Linux exacto y las selecciones previstas; WinCI real sigue siendo necesario para los holders, PowerShell y la exactitud extremo a extremo. No se declara WinCI GREEN, mortalidad de mutantes ni cierre de AT-I1b-8, que permanece manual.
