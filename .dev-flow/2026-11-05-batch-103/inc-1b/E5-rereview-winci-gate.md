# E5 — Re-review alcance B: cobertura funcional y gate WinCI

Base revisada: rama `b103-inc1b-integration`, HEAD `305e5892`, más los cambios E5 actuales sin commit. Se contrastaron el handoff y las tres revisiones indicadas con el working tree actual; las líneas y ausencias descritas en revisiones sobre HEAD antiguos no se dieron por vigentes sin volver a comprobarlas.

Alcance: `.github/workflows/clipboard-windows.yml`, `tests/support/b103_winci_gate.py`, `tests/test_b103_copy_paste_matrix.py`, `tests/test_b103_copy_quit_dialog.py`, las rutas relevantes de `tests/test_b103_clipboard_tail.py` y los helpers de clipboard necesarios para seguir seed/read/skips. Revisión exclusivamente estática, con lecturas acotadas y `git diff`/`git show` de sólo lectura. No ejecuté pytest, colección, probes, PowerShell, clipboard, workflow, WinCI ni mutantes. Todos los conteos siguientes son de código escrito, no resultados de ejecución.

## Veredicto

**NO-GO para aprobar el gate como puerta fiable de cobertura WinCI o para interpretar un eventual `WINCI_GATE_RESULT PASS` como evidencia de las 108 obligaciones.** B3 de `E5-pre-ci-review.md` está corregido para las vías concretas de seed/read/probe revisadas, pero B4 sólo está parcialmente corregido. Permanecen dos hallazgos **HIGH** y uno **MAJOR** que admiten falsos GREEN.

Las dos rutas tail, las nueve rutas quit y las 28 celdas P1/P2 ya tienen implementación estática. **No hay ejecución ni veredicto WinCI en esta revisión.** El GREEN Linux `160 passed / 96 skipped`, los skips Linux y el mero código de las rutas no se promueven a evidencia Windows. AT-I1b-8 sigue correctamente manual y fuera de las obligaciones automatizadas; no se exige automatizarlo ni cerrarlo mediante este gate.

## Hallazgos abiertos

### WG-01 — HIGH · design-gap — El censo JUnit no exige las 108 obligaciones ni siquiera las 2 rutas tail + 9 quit

Ubicaciones actuales:

- `tests/support/b103_winci_gate.py:76-80` sólo rechaza un XML sin ningún `testcase`;
- `tests/support/b103_winci_gate.py:81-105` clasifica los casos presentes, pero no contrasta la población con un manifiesto esperado;
- `tests/support/b103_winci_gate.py:104-113` únicamente impone 28 nodeids AT únicos;
- `.github/workflows/clipboard-windows.yml:75-86` selecciona seis archivos y audita el XML resultante, pero seleccionar archivos no demuestra resultados para cada obligación.

La población de diseño es **108 obligaciones automatizadas WinCI —46 views, 25 tail, 9 quit y 28 AT—** (`E5-coverage-plan.md:34-37,192-196`). Esas 108 obligaciones no equivalen necesariamente a 108 `testcase` JUnit: varias se agrupan en un mismo nodo pytest y varias tienen brazos internos. Precisamente por eso hace falta una correspondencia explícita obligación → nodeid/brazo, no un total agregado.

En el estado actual, un JUnit no vacío que contenga únicamente las 28 celdas AT passed puede terminar verde sin ninguno de los dos nodos R-TUI-043.13/101…102, sin los nueve nodos R-COPY.16/1…6 y R-COPY.20/1…3 y sin el resto de views/tail. Borrar, renombrar o dejar de recolectar uno de esos nodos no crea por sí mismo un `failure`, `error` o `skipped` que el gate actual pueda detectar. Los brazos internos de `test_r_tui_043_13_101…`, `test_r_copy_16_1…` y `test_r_copy_20_1…` tampoco tienen censo JUnit independiente.

**Desbloqueo:** definir el manifiesto exacto de nodeids pytest esperados para los seis archivos y su correspondencia con las 108 obligaciones y brazos internos. Exigir resultado terminal passed para cada obligación automatizada y fallo ante ausencia, duplicado o resultado inesperado. Mantener AT-I1b-8 fuera del conjunto required-passed y conservar por separado su evidencia manual.

### WG-02 — HIGH · impl — La lista blanca de skips depende del texto de la razón y se aplica a cualquier nodo

Ubicaciones actuales:

- `tests/support/b103_winci_gate.py:15-17` define un prefijo regex genérico para razones `Linux…`;
- `tests/support/b103_winci_gate.py:38-50` autoriza ese prefijo sin comprobar qué nodo lo emite;
- `tests/support/b103_winci_gate.py:94-105` registra el skip como permitido y aun así incluye el nodo en el censo AT;
- `tests/support/b103_winci_gate.py:107-113,149-155` no exige 28 AT passed y devuelve 0 cuando no hay violaciones.

Traza de falso GREEN derivada directamente del código, no ejecutada: con `pytest_exit=0`, 28 `testcase` AT distintos, todos con `<skipped message="Linux-only …">`, cero failures/errors declarados y ningún otro testcase, el gate obtiene `JUNIT_EMPTY` ausente, 28 AT únicos, 28 skips permitidos y ninguna violación; `main()` devuelve **0**. Lo mismo permite que una rama tail/quit obligatoria se omita con una razón que empiece por `Linux…`.

Sí existe una población pequeña y concreta que justifica una lista blanca por nodeid: `test_r_copy_2_app_clipboard[R-COPY.2/4]` (`tests/test_b103_copy_views.py:486-489`) y los cinco nodos de `tests/test_b103_clipboard_tail.py:803-806,967-970,975-978,983-986,991-994`. El skip manual de `test_manual_windows_terminal_operator_acceptance` (`tests/test_b103_copy_paste_matrix.py:437-444`) es una exención separada y correctamente condicionada por nombre/razón en `tests/support/b103_winci_gate.py:41-49`.

**Desbloqueo:** reemplazar la autorización global por regex con una lista exacta nodeid + razón para esos seis brazos Linux-only y otra entrada específica para el centinela manual AT-I1b-8. Todo skip de una obligación required-passed debe ser violación independientemente de su texto. El censo AT debe contar passed, no meras entradas presentes.

### WG-03 — MAJOR · impl — El censo AT y las comprobaciones de integridad JUnit siguen siendo parciales

Ubicaciones actuales:

- `.github/workflows/clipboard-windows.yml:71-73` y `tests/support/b103_winci_gate.py:12-14,104-113` reconocen AT por subcadena/prefijo y cuentan 28, pero no comparan con los 28 identificadores canónicos ni con la partición 14 P1 + 14 P2;
- `tests/support/b103_winci_gate.py:107-113` detecta duplicados sólo dentro de AT, no en tail, quit, views ni los archivos heredados;
- `tests/support/b103_winci_gate.py:53-67,115-124` reconcilia únicamente `failures` y `errors`; no contrasta los atributos JUnit `tests` y `skipped` con los `testcase` observados.

Las 28 entradas escritas sí son únicas en `AT_CELLS` (`tests/test_b103_copy_paste_matrix.py:391-422`), pero el gate aceptaría igualmente 28 identificadores distintos de los canónicos si conservan el prefijo. También aceptaría una población AT sin las 14 rutas P2 mientras mantenga 28 nombres únicos. Esto no es un resultado WinCI observado: es un agujero estático de validación ante renombrados, pérdida de parámetros o XML incompleto.

**Desbloqueo:** comparar contra un `frozenset` de los 28 nodeids canónicos completos y contra sus subconjuntos P1/P2; rechazar duplicados de cualquier nodeid requerido; reconciliar `tests`, `skipped`, `failures` y `errors`, además del manifiesto por archivo/obligación de WG-01.

## Bloqueos y omisiones corregidos en el árbol actual

### B3 de `E5-pre-ci-review.md` — corregido para las vías concretas; no confundir con WG-02

- Matrix ya delega seed/read en helpers comunes (`tests/test_b103_copy_paste_matrix.py:12-18,30-57`). El helper falla si falta PowerShell o si la ruta no es absoluta (`tests/support/b103_clipboard.py:553-562`), convierte errores de invocación en `AssertionError` (`:565-597`) y hace fallar seed/read/Base64 incorrectos (`:600-653`); ya no convierte esos fallos en skips de las 28 celdas.
- Quit convierte probe no usable en fallo (`tests/test_b103_copy_quit_dialog.py:83-90`), y sus rutas PowerShell/seed/read fallan en vez de hacer skip (`:122-185`).
- Tail todavía contiene skips de infraestructura en `tests/test_b103_clipboard_tail.py:229-231,1199-1206`, pero sus razones `not_run…`/`runner clipboard unusable…` no cumplen la exención Linux/manual y se convierten en `DISALLOWED_SKIP` en `tests/support/b103_winci_gate.py:94-100`. Por tanto, esos skips concretos ya no producen un GREEN aceptado.
- Los seis skips Linux-only actuales y el skip manual son los únicos que el código escrito justifica eximir. WG-02 permanece abierto porque la implementación no restringe la exención a esos nodos.

### B4 de `E5-pre-ci-review.md` — parcialmente corregido; WG-01/WG-02/WG-03 siguen abiertos

El workflow ya no se limita a colección. Ahora genera JUnit y ejecuta el gate (`.github/workflows/clipboard-windows.yml:75-86`). El gate rechaza XML vacío (`tests/support/b103_winci_gate.py:76-80`), failures/errors (`:85-103`), skips clasificados como no permitidos (`:94-100`), censo AT distinto de 28 y duplicados AT (`:104-113`), e inconsistencias de failures/errors declarados (`:115-124`). Son mejoras reales, pero no sustituyen el censo completo ni la lista blanca exacta.

La preservación de `pytest_exit` sí está cableada: el workflow captura `$LASTEXITCODE` inmediatamente después de pytest, lo pasa al gate y termina con el código del gate (`.github/workflows/clipboard-windows.yml:81-86`). El gate registra un pytest exit distinto de cero como violación (`tests/support/b103_winci_gate.py:70-74`) y devuelve `args.pytest_exit or …` tanto al auditar como al rechazar XML ilegible (`:133-137,149-155`). No encontré en esta ruta una conversión de fallo de pytest en éxito.

### Las 2 rutas tail — ruta real escrita, ejecución pendiente

- R-TUI-043.13/101 ya no tiene el antiguo skip WinCI. `tests/test_b103_clipboard_tail.py:1004-1045` enumera cuatro brazos WinCI: view-key, view-right-click, row-success y row-held. `_instrument` exige guarda/probe, siembra externa y usa writer real (`:128-133,174-187`); `_success` exige app/writer/OSC/OS exactos (`:313-333`), y `_run_arms` agrega fallos en vez de ignorarlos (`:365-374`).
- R-TUI-043.13/102 fuerza sólo el writer PowerShell real en WinCI (`tests/test_b103_clipboard_tail.py:1058-1067`), espera el tail antes de observar (`:1092-1095`) y exige payload exacto, una invocación, argv/stdin/cwd y logs limpios (`:1153-1196`). El antiguo skip de ruta ausente ya no existe.

Esto cierra la **ausencia de implementación** señalada antes. No demuestra que esos brazos hayan pasado ni subsana WG-01 si sus nodos desaparecen del JUnit.

### Las 9 rutas quit — seeds y lecturas OS escritas, ejecución pendiente

- Los seis nodos R-COPY.16/1…6 activan `winci_seed=True` en `tests/test_b103_copy_quit_dialog.py:556-664`; R-COPY.20/1…3 hacen lo propio en `:748-816`.
- La fixture exige aislamiento/probe y conserva writer/reader reales en Windows (`:77-110`). `_run` siembra antes del escenario (`:303-325`); `_seed_os_clipboard` escribe desde PowerShell separado y verifica read-back (`:131-185`).
- `_assert_no_copy_effects` realiza la lectura OS exacta cuando la seed WinCI está armada (`:400-418`). Las observaciones con body B abierto y después de `n` están en `:459-487`; R-COPY.20/1…2 añade comprobaciones antes/después de Ctrl+C y tras Escape (`:748-799`), y R-COPY.20/3 cierra con Stay y vuelve a comprobar (`:802-816`).

Las nueve ausencias funcionales antiguas están corregidas en código. Ninguna se cuenta aquí como pasada, y el gate todavía no detecta su ausencia del XML.

### Las 28 celdas P1/P2 — cadena funcional escrita y doble guarda de cantidad, sin censo canónico completo

- Hay 28 `pytest.param` con ids únicos y aserciones estáticas de cantidad/unicidad (`tests/test_b103_copy_paste_matrix.py:391-422`), parametrizados en `:425-434`. El workflow conserva una guarda de colección de 28 líneas únicas (`.github/workflows/clipboard-windows.yml:71-73`) y el gate otra de 28 entradas JUnit únicas (`tests/support/b103_winci_gate.py:104-113`).
- En WinCI, cada celda siembra (`tests/test_b103_copy_paste_matrix.py:330-332`), copia por right-click y espera el tail (`:353-357`), exige notice/app y separate read iguales al texto capturado (`:361-372`). P1 ejecuta Ctrl+V (`:374-375`); P2 publica `events.Paste(os_artifact)`, no `expected` (`:376-378`). T1/T2 comprueban el contenido exacto (`:380-388`).

La cadena requerida está escrita para las 14 P1 y 14 P2. No hay resultados WinCI que la confirmen, y WG-02/WG-03 impiden aceptar el actual contador AT como prueba suficiente.

### B3/B4 homónimos de `E5-winci-review.md` — corregidos estáticamente

- El antiguo B3 de LF final: el reader común transporta Base64 UTF-8 y ya no aplica `rstrip` (`tests/support/b103_clipboard.py:629-653`); el reader específico de tail hace lo mismo (`tests/test_b103_clipboard_tail.py:226-263`). Los brazos sin y con LF final siguen presentes en `:740-751`. La transformación que destruía el LF final está corregida en código; su comportamiento Windows sigue pendiente de ejecución.
- El antiguo B4 de guarda/origen PowerShell en matrix: matrix usa `clipboard_isolated` y `require_isolated_clipboard` (`tests/test_b103_copy_paste_matrix.py:26-33`), cuya guarda incluye plataforma, GitHub hosted y `runneradmin` (`tests/support/b103_clipboard.py:134-143`). PowerShell se obtiene del sistema y debe ser absoluto (`:553-562`). No queda en matrix el antiguo resolver basado en PATH.

## Condiciones para cambiar el veredicto

1. Cerrar WG-01, WG-02 y WG-03 sin reducir la población ni convertir las 108 obligaciones en un simple total de testcases.
2. Someter el propio gate a controles negativos: XML vacío/ilegible, nodo tail o quit ausente, AT renombrado, P2 ausente, duplicado no AT, skip obligatorio con prefijo `Linux…`, los seis skips permitidos y el manual, conteos JUnit inconsistentes y pytest exit no cero. Los controles deben demostrar rechazo/aceptación según corresponda; esta revisión no los ejecutó.
3. Ejecutar después el workflow real en el runner aislado y conservar JUnit, transcript y salida del gate. Sólo esa ejecución puede producir un veredicto WinCI; el GREEN Linux y las rutas escritas no lo sustituyen.
4. Mantener AT-I1b-8 como aceptación manual separada del operador, sin añadirla al conjunto required-passed ni usar automatización sobre su clipboard.

Hasta entonces el veredicto del alcance B permanece **NO-GO**.
