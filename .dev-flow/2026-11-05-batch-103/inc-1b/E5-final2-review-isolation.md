# Inc 1b — E5 final2 review: aislamiento y procesos

Base revisada: HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` más el working tree actual. Revisión independiente posterior a `fix2`, limitada a los bloqueos C-01…C-04, su cobertura de aislamiento/procesos y los defectos directamente introducidos por esas correcciones. Se contrastó la interacción con los holders sin reabrir el alcance general de transporte.

Revisión estática mediante lecturas acotadas, búsquedas y `git diff/status` de sólo lectura. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow ni mutantes; no hice mutaciones Git ni modifiqué producto, tests, workflow, ledger, canon o evidencia. La única escritura de esta revisión es este informe.

Resultados comunicados, **no repetidos ni verificados dinámicamente por esta revisión**: selección exacta Linux `164 passed / 2 skipped`; full de seis familias y leyes todavía en ejecución en otro clon exacto al recibir el encargo. **No hay resultado WinCI ni mutantes de producto ejecutados que pueda reclamar.** Ninguna ruta escrita se promueve aquí a ejecución Windows.

## Veredicto del área

**GO para aislamiento/procesos, limitado a implementación y cobertura escrita.** Los bloqueos anteriores C-01…C-04, incluido C-01R, están cerrados en el árbol revisado. No encontré defectos nuevos directamente introducidos por estas correcciones dentro del alcance asignado.

- Hallazgos `impl` abiertos: **ninguno**.
- Hallazgos `design-gap` abiertos: **ninguno**.
- Severidad de hallazgos nuevos o persistentes en este alcance: **ninguna; cero BLOCKER/MEDIUM/MINOR**.

Este GO no es un veredicto de release ni sustituye las puertas dinámicas pendientes enumeradas al final.

## Disposición de los bloqueos anteriores

| Control | Estado actual | Evidencia principal |
|---|---|---|
| C-01 / SEC-02, assembly; antiguo BLOCKER `impl` | **Cerrado en implementación escrita** | `PresentationCore` precede a `Windows.Clipboard.SetText` en `tests/support/b103_clipboard.py:650-665`. |
| C-01R; antiguo MINOR `design-gap` | **Cerrado en cobertura escrita** | El oracle captura el comando real, exige orden de assembly y excluye `System.Windows.Forms` en `tests/test_b103_e5_safety.py:246-258`. |
| C-02 / SEC-02, exactitud externa; antiguo MEDIUM `design-gap` | **Cerrado en rutas escritas para shared y tail** | `tests/test_b103_copy_quit_dialog.py:132-146,1038-1039`; `tests/test_b103_clipboard_tail.py:1253-1259,1420-1427`. |
| C-03 / SEC-04, decoy de cada launcher; antiguo MEDIUM `design-gap` | **Cerrado en rutas escritas** | Producto/shared en `tests/test_b103_clipboard_windows.py:2365-2477`; tail en `tests/test_b103_clipboard_tail.py:1366-1440`. |
| C-04 / SEC-05, guards y cero recursos; antiguo MEDIUM `impl` | **Cerrado en implementación y controles escritos** | Guarda de tail en `tests/test_b103_clipboard_tail.py:1559-1562`; control negativo en `:1861-1894`; censo Windows/shared en `tests/test_b103_e5_safety.py:139-189`. |

## Evidencia de cierre

### C-01/C-01R: helper binario y assembly fijado

- `_run_system_powershell()` guarda antes de resolver o lanzar, codifica stdin como UTF-8 explícito y no pasa `text`, `encoding`, `errors` ni `newline`; stdout/stderr permanecen binarios (`tests/support/b103_clipboard.py:615-647`).
- El writer compartido conserva el payload fuera de argv, transporta Base64 de UTF-16LE y ejecuta `Add-Type -AssemblyName PresentationCore` antes de `[Windows.Clipboard]::SetText($text)` (`tests/support/b103_clipboard.py:650-670`). Ya no aparece la dependencia incompatible anterior.
- El reader compartido decodifica Base64 estricto desde bytes y después UTF-8, sin `rstrip` sobre el payload (`tests/support/b103_clipboard.py:679-703`).
- `test_e5_external_seed_writer_loads_presentation_core_before_set_text` selecciona exactamente la llamada de escritura, busca ambos tokens en el comando efectivamente emitido, exige su orden y rechaza `System.Windows.Forms` (`tests/test_b103_e5_safety.py:246-258`). La ausencia o reordenación del assembly haría fallar ese oracle; no depende del round-trip simulado para afirmar la dependencia.

Esto cierra el defecto estático señalado. La resolución real del tipo en Windows PowerShell sigue siendo una puerta WinCI, no un fallo observado ni una ejecución reclamada aquí.

### C-02: valores conocidos por cada implementación externa conservada

- El control compartido con proceso simulado recorre Unicode, CR, CRLF, LF y LF final, con igualdad exacta de writer/reader, stdin binario y payload fuera de argv (`tests/test_b103_e5_safety.py:192-258`). Es un control Linux escrito, no evidencia Windows.
- La ruta WinCI compartida de quit recorre Unicode, CR, LF y LF final mediante `other_program_write()` y `other_program_read()`, con igualdad exacta (`tests/test_b103_copy_quit_dialog.py:132-146`), llamada sólo en Windows desde `:1038-1039`. Su fixture exige aislamiento y convierte un probe WinCI no usable en fallo, no en un skip que oculte la ruta (`tests/test_b103_copy_quit_dialog.py:77-90`).
- Tail conserva su reader separado en `tests/test_b103_clipboard_tail.py:228-265`. Su brazo WinCI ahora recorre cinco valores —hostile con LF, hostile con LF final, Unicode, CR y CRLF— definidos en `:1251-1259`. Para cada uno siembra con el writer externo, lee con producto y con el reader local de tail y exige ambas igualdades exactas (`:1420-1427`). Por tanto Unicode y CR ya atraviesan el reader que antes quedaba descubierto, y se conservan LF/LF final.

No afirmo que estos round-trips WinCI hayan corrido; afirmo que la laguna de cobertura C-02 ya no existe en el código escrito.

### C-03: decoy efectivo en los launchers conservados

- **Producto, lectura y escritura:** el test compila un `powershell.exe` real con marcador, lo instala en cwd y al frente de PATH, fuerza ambos rescates y exige resultados exactos, arranques no vacíos, todos los `argv[0]` del sistema y marcador ausente (`tests/test_b103_clipboard_windows.py:2365-2477`).
- **Launcher compartido:** writer y reader convergen en `_run_system_powershell()` (`tests/support/b103_clipboard.py:615-643,650-690`). Quit y matrix delegan en esos entry points (`tests/test_b103_copy_quit_dialog.py:122-140`; `tests/test_b103_copy_paste_matrix.py:52-57`). El reader compartido se invoca con cwd/PATH todavía hostiles tras restaurar el spy (`tests/test_b103_clipboard_windows.py:2457-2466`), y el marcador final se exige ausente en `:2477`.
- **Reader local de tail:** el brazo crea sus propios decoys en cwd/PATH (`tests/test_b103_clipboard_tail.py:1366-1411`). Bajo ese entorno siembra cada payload, fuerza el reader de producto, invoca el reader local, exige exactamente dos arranques por el PowerShell del sistema y valores exactos (`:1412-1439`), y finalmente exige marcador ausente en `:1440`.

El censo acotado de las seis familias no mostró launchers PowerShell propios en `clipboard_matrix` ni `copy_views`; quit y matrix delegan en el helper compartido, y `copy_views` también lo consume. Los procesos de compilación del decoy y los holders no son launchers PowerShell y se revisan por sus propios controles. En Linux, `forced_reader()` retorna en `tests/test_b103_clipboard_tail.py:1322-1364`, antes del ataque WinCI: los GREEN Linux comunicados no cierran esta ejecución.

### C-04: guarda intrínseca y cero recursos antes del boundary

- La guarda de `_hold_clipboard()` de tail es su primera sentencia (`tests/test_b103_clipboard_tail.py:1559-1562`), antes de construir el script, de `subprocess.Popen` (`:1610-1618`) y de cualquier Win32 del padre (`:1643-1651`). Ya no depende de las barreras de sus callers.
- El control `guard_rejected()` sustituye la referencia de guarda efectivamente usada por tail, instala un `Popen` prohibido y un `ctypes.windll` prohibido, exige la excepción primaria de aislamiento y termina con `resources == []` (`tests/test_b103_clipboard_tail.py:1861-1894`). El control está registrado en la batería de `:2131-2145`, invocada desde el nodeid existente en `:1442-1446`.
- El censo independiente de Windows/shared inyecta rechazo y comprueba una sola guarda, cero `Popen`/`run`, cero user32 y cero kernel32 para los nueve entry points censados (`tests/test_b103_e5_safety.py:139-189`). El holder de Windows también tiene la guarda antes de `Popen` (`tests/test_b103_clipboard_windows.py:474-485,534-541`), y el launcher/shared y helpers Win32 conservan las suyas (`tests/support/b103_clipboard.py:601-620,650-653,679-682,706-715,746-754,781-787`).

No encontré una ruta nueva que alcance proceso o clipboard antes del rechazo en estos helpers. Los controles son oráculos escritos; su ejecución real pertenece a las selecciones externas y WinCI.

## Interacción con holders

No encontré una regresión de procesos introducida por `fix2` en la interacción revisada:

- En tail, el `try` de adquisición comienza inmediatamente después de un `Popen` exitoso (`tests/test_b103_clipboard_tail.py:1610-1619`). `_reap_holder()` intenta kill/wait inicial, kill/wait final acotados, cierre y poll final, conserva el primer fallo y rechaza un proceso vivo (`:1468-1504`). `_release_clipboard()` intenta señal, ambos joins, reap y comprobaciones finales de supervisor/holder sin aceptar vivos (`:1507-1556`).
- Los dobles de tail cubren rechazo de guarda, fallo de `reader.start`, readiness ausente, muerte tras HOLDING, timeout, reintento de kill, holder imposible de matar, supervisor colgado, fallos de release/join y holder vivo durante release (`tests/test_b103_clipboard_tail.py:1744-2145`). Los callers held conservan `try/finally` alrededor del uso y `_release_clipboard()` (`:2169-2180`, `:2214-2232`).
- En Windows, reap/release ejecutan etapas independientes, conservan errores y hacen comprobaciones finales de muerte (`tests/test_b103_clipboard_windows.py:394-471`). La adquisición cubre reader, supervisor y Win32 tras `Popen` (`:474-624`), con controles inertes y deadlines en `:650-1036`.

Estas conclusiones son de estructura y dobles escritos, no una afirmación de cleanup WinCI observado ni de cero holders vivos en un runner real.

## Puertas dinámicas que permanecen abiertas

1. Completar y revisar el full de seis familias y leyes en el clon exacto; al recibir el encargo estaba corriendo y esta revisión no esperó ni adjudicó su resultado.
2. Ejecutar WinCI sobre assembly/seed externa exacta, decoys, guards y holders con cleanup real verificado. Las rutas escritas y el `164 passed / 2 skipped` Linux comunicado no sustituyen esa evidencia.
3. Ejecutar los mutantes de producto previstos; esta revisión no ejecutó ninguno y no les asigna mortalidad.
4. Mantener AT-I1b-8 como aceptación manual separada: continúa marcada `skip` y excluida de automatización en `tests/test_b103_copy_paste_matrix.py:437-444`. No queda verificada por este GO estático.

Verificación auxiliar realizada: `git diff --check` sobre los archivos de producto/tests comprendidos en esta revisión terminó con exit 0 y sin errores de whitespace. No se ejecutó ninguna suite ni sonda.
