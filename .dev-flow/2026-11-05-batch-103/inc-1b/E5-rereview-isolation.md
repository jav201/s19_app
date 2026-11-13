# Inc 1b — E5 re-review C: aislamiento y ejecución

Base revisada: rama `b103-inc1b-integration`, HEAD `305e5892adb4fb109ea204b5eb7c5d8beff151a4` y los cambios E5 sin commit presentes ahora en el working tree. Las líneas siguientes describen ese estado actual, no las bases antiguas de las revisiones previas.

Alcance: `tests/support/b103_clipboard.py`, `tests/test_b103_copy_paste_matrix.py`, `tests/test_b103_clipboard_windows.py`, `tests/test_b103_copy_quit_dialog.py` y las rutas necesarias de `s19_app/tui/os_clipboard_input.py`. Para cerrar el call graph también se inspeccionaron las guardas de `tests/conftest.py` y los consumos puntuales de `tests/test_b103_clipboard_tail.py` y `tests/test_b103_copy_views.py`. Se contrastaron selectivamente el handoff y las tres revisiones E5 indicadas.

Revisión sólo estática, con lecturas y `git diff/show` de sólo lectura. No ejecuté pytest, colección, probes, aplicación, PowerShell, clipboard, workflow ni mutantes; tampoco hice mutaciones Git. El tally **160 passed / 96 skipped** pertenece a Linux y no se repitió. **No hay veredicto WinCI ni mutantes de producto ejecutados que esta revisión pueda reclamar.**

## Veredicto

**NO-GO para el alcance C.** La separación de procesos y el ataque decoy principal fueron corregidos, pero la seed compartida tiene un bloqueo de implementación que impide su escritura PowerShell. Además quedan lagunas de cobertura exacta, de censo del decoy y de guards intrínsecos.

| Control anterior | Estado actual |
|---|---|
| SEC-02, seed en otro proceso | La separación estructural está corregida; sigue **abierto** por C-01 y C-02. |
| SEC-04, PowerShell absoluto y decoy vacuo | La implementación absoluta y el decoy de lectura/escritura de producto están corregidos; queda **parcial** por C-03. |
| SEC-05, guards intrínsecos | Hay guards nuevos en las rutas PowerShell públicas, pero el censo sigue **abierto** por C-04. |

## Hallazgos abiertos

### C-01 — BLOCKER — `impl` — SEC-02: la seed compartida carga un assembly incompatible con el tipo que invoca

`other_program_write()` construye correctamente una entrada Base64 y la envía por stdin a un proceso externo (`tests/support/b103_clipboard.py:600-615`). Sin embargo, su comando hace:

- `Add-Type -AssemblyName System.Windows.Forms` en `tests/support/b103_clipboard.py:612`;
- `[Windows.Clipboard]::SetText($text)` en `tests/support/b103_clipboard.py:613`.

`Windows.Clipboard` es el tipo WPF de `PresentationCore`, no el clipboard de Windows Forms. El writer de producto muestra la dependencia correcta al cargar `PresentationCore` antes de invocar el mismo tipo (`s19_app/tui/os_clipboard_input.py:130-137`). La seed compartida no carga ese assembly.

Cada seed usa un proceso nuevo con `-NoProfile` (`tests/support/b103_clipboard.py:583-593`), de modo que una carga de assemblies en pytest o en otro hijo no puede hacer resoluble el tipo en éste. En Windows PowerShell, la resolución de `[Windows.Clipboard]` falla antes de escribir y `$ErrorActionPreference='Stop'` convierte ese fallo en salida no exitosa; el rechazo está en `tests/support/b103_clipboard.py:616-620`. Esto bloquea la seed compartida usada por matrix (`tests/test_b103_copy_paste_matrix.py:52-57`), views, tail y numerosos casos de Windows.

**Desbloqueo:** cargar `PresentationCore` en este writer, o usar deliberadamente el tipo y assembly de Windows Forms con la misma semántica exacta. Mantener payload fuera de argv, la comparación exacta y el fallo ante cualquier error. Añadir una comprobación estática de la dependencia y una ejecución WinCI posterior; esta revisión no afirma haber observado el fallo en ejecución.

### C-02 — MEDIUM — `design-gap` — SEC-02: falta el censo discriminating del transporte exacto

La implementación compartida sí tiene los elementos estructurales adecuados: UTF-16LE transportado como Base64 por stdin (`tests/support/b103_clipboard.py:604-615`) y una segunda ejecución PowerShell que devuelve Base64 UTF-8 sin BOM, con `validate=True` y sin `rstrip` sobre el payload (`tests/support/b103_clipboard.py:629-653`). Writer y reader son procesos distintos de pytest y entre sí.

La cobertura escrita no cierra todo el dominio exigido por la corrección anterior:

- Unicode tiene llamadores concretos (`tests/test_b103_clipboard_windows.py:673-677`, `:1605-1607`) y LF no final tiene otros (`:608-631`), pero no hay un round-trip de esta seed externa con CR ni con LF final.
- Quit siembra únicamente el literal ASCII `SEED-1b` mediante su implementación local (`tests/test_b103_copy_quit_dialog.py:44`, `:176-185`); no prueba los límites del transporte genérico.
- `test_e5_powershell_preserves_lf_and_emits_bom_free_readers` examina el writer de producto y el reader local de tail (`tests/test_b103_clipboard_tail.py:1112-1150`). No inspecciona el writer/reader compartidos ni el reader local de quit, y por diseño no detecta la dependencia de assembly de C-01.

La prueba estática no es vacua para los tokens de producto/tail que sí examina, pero **no es una prueba de transporte de la seed compartida ni evidencia Windows**. Hacen falta valores conocidos con Unicode, CR, LF y LF final para cada implementación externa conservada, además de sus controles de salida inválida.

### C-03 — MEDIUM — `design-gap` — SEC-04: el decoy efectivo no cubre todos los separate readers

El antiguo decoy vacuo está corregido para producto. El test actual compila un `powershell.exe` real con marcador, lo coloca tanto en cwd como en un directorio prependido a `PATH` (`tests/test_b103_clipboard_windows.py:1821-1867`), fuerza los rescates de lectura y escritura (`:1869-1880`) y exige valores exactos, al menos un arranque, todos los `argv[0]` iguales al PowerShell del sistema y ausencia del marcador (`:1902-1922`). Las cascades se resuelven en tiempo de llamada (`s19_app/tui/os_clipboard_input.py:625-628`, `:692-697`), por lo que esas sustituciones sí alcanzan las rutas reales.

La lectura compartida posterior (`tests/test_b103_clipboard_windows.py:1908`) también se ejecuta antes de deshacer cwd/PATH hostiles; su igualdad exacta y el marcador final hacen que ese brazo no sea vacuo. Matrix usa esa lectura compartida (`tests/test_b103_copy_paste_matrix.py:56-57`).

Queda fuera del ataque la implementación PowerShell local de quit (`tests/test_b103_copy_quit_dialog.py:131-185`) y la implementación local de tail (`tests/test_b103_clipboard_tail.py:226-263`). La corrección SEC-04 anterior pedía repetir el control con matrix/quit/tail, no sólo con producto y el reader compartido. Ambas rutas derivan actualmente su ejecutable de `_system_powershell()`, por lo que **no encontré un PATH hijack implementado**; la laguna es de protección frente a regresiones en esos call sites.

**Desbloqueo:** ejercitar esos readers bajo los mismos decoys, o consolidarlos en el helper compartido guardado y hacer que su único punto de lanzamiento quede cubierto por el ataque.

### C-04 — MEDIUM — `impl` — SEC-05: la guarda intrínseca sigue sin cubrir todos los helpers antes de clipboard/proceso

Hay correcciones reales: `other_program_write()` y `other_program_read()` llaman a `require_isolated_clipboard` antes de resolver/ejecutar PowerShell (`tests/support/b103_clipboard.py:600-603`, `:629-632`), y el launcher local de quit también lo hace antes de `subprocess.run` (`tests/test_b103_copy_quit_dialog.py:131-153`). Matrix exige la guarda completa al entrar en Windows (`tests/test_b103_copy_paste_matrix.py:26-33`).

El invariante documentado de que todo helper del módulo llama primero a la guarda (`tests/support/b103_clipboard.py:156-179`) todavía es falso para este censo:

- `_run_system_powershell()` puede llegar a `subprocess.run` sin una guarda propia (`tests/support/b103_clipboard.py:565-593`). Sus dos llamadores actuales sí están guardados, pero el launcher no impone el invariante por sí mismo.
- `_own_write()` sólo comprueba plataforma antes de `OpenClipboard`, `EmptyClipboard` y `SetClipboardData` (`tests/support/b103_clipboard.py:656-692`). `own_read()` está igual antes de `OpenClipboard` (`:695-726`), y `clipboard_sequence_number()` también carece de guarda (`:729-734`).
- Los helpers directos del archivo Windows no tienen guarda intrínseca: escritura no textual (`tests/test_b103_clipboard_windows.py:265-296`), holder que crea un proceso hijo (`:361-424`), probe `OpenClipboard` (`:477-494`), escritura Unicode vacía (`:572-600`) y escritura sin terminador (`:805-835`).

`test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails` ejercita las capas ctypes **de producto** dentro de un pytester no aislado (`tests/test_b103_clipboard_windows.py:1968-2002`). No invoca los helpers anteriores ni demuestra que cada uno falle antes de cualquier `OpenClipboard`, `EmptyClipboard` o proceso. Es un control útil para producto, pero no cierra SEC-05.

En el call graph ordinario actual, las fixtures `os_clipboard_ready`, las fixtures autouse y el stand-in global (`tests/conftest.py:65-183`) impiden llegar al clipboard real del operador antes de que estos tests fallen. No encontré una ruta de ejecución pytest normal que omita esas barreras. El hallazgo conserva severidad MEDIUM porque sigue siendo defensa en profundidad, no una escritura desprotegida ya alcanzada; no obstante, reutilizar los helpers fuera de esas fixtures sí puede abrir clipboard o lanzar el holder sin imponer aislamiento.

**Desbloqueo:** colocar la guarda al inicio de cada entry point que pueda tocar clipboard o crear proceso, incluido el launcher y el holder, y añadir controles negativos por helper que prueben cero llamadas OS/proceso en Windows no aislado.

## Controles corregidos y ausencia de vacuidad

- **Proceso realmente separado:** la antigua escritura ctypes dentro de pytest fue sustituida en el helper compartido por dos `subprocess.run` reales, uno para escribir y otro para leer (`tests/support/b103_clipboard.py:565-653`). Quit tiene igualmente una escritura y una lectura PowerShell separadas (`tests/test_b103_copy_quit_dialog.py:131-185`). C-01 impide promover la ruta compartida a ejecutable, pero ya no se trata de una seed fabricada dentro de pytest.
- **PowerShell absoluto:** producto deriva el directorio con `GetSystemDirectoryW`, sin `SystemRoot` ni `PATH`, y exige que el ejecutable exista (`s19_app/tui/os_clipboard_input.py:164-203`). Sus rescates usan esa ruta y cwd del sistema (`:278-327`, `:425-470`). El helper compartido además exige `ntpath.isabs` (`tests/support/b103_clipboard.py:553-562`).
- **Decoy lectura/escritura:** ya no se acepta `started=[]`, los rescates están forzados y el marcador es un oráculo negativo real (`tests/test_b103_clipboard_windows.py:1872-1922`). La prueba es discriminating para producto; C-03 limita su censo.
- **Quit:** las nueve rutas R-COPY.16/1…6 y R-COPY.20/1…3 activan `winci_seed=True` (`tests/test_b103_copy_quit_dialog.py:556-664`, `:748-816`). Con la seed armada, `_assert_no_copy_effects` hace una lectura OS exacta (`:400-418`) con el diálogo abierto y después de Stay/cierre modal. No es el antiguo recorder vacuo.
- **Matrix P2:** el paste usa `os_artifact` obtenido por separate read, no `expected` (`tests/test_b103_copy_paste_matrix.py:361-378`). Esto no elimina el bloqueo previo de C-01.
- **Aceptación manual:** AT-I1b-8 permanece excluida de automatización (`tests/test_b103_copy_paste_matrix.py:437-444`); ninguna ruta revisada la convierte en permiso para tocar el clipboard del operador.

## Puerta para cambiar el veredicto C

1. Corregir C-01 y demostrar en WinCI la seed compartida real, sin convertir errores en skips aceptados.
2. Cerrar C-02 con round-trips conocidos Unicode/CR/LF/LF final para todas las implementaciones externas conservadas.
3. Cerrar C-03 para quit y tail, o eliminar sus launchers duplicados mediante un único helper guardado cubierto por el decoy.
4. Cerrar C-04 con guards intrínsecos y controles negativos de cero clipboard/proceso para cada helper.
5. Ejecutar después la evidencia WinCI y los mutantes previstos por el batch. El GREEN Linux, las rutas escritas y esta revisión estática no sustituyen ninguno de esos resultados.
