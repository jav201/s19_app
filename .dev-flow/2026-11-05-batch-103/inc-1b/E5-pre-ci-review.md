# Inc 1b — E5 pre-CI functional review

Base: HEAD `0d4d4e7c` más los cambios E5 sin commit presentes en el working tree. Se revisaron el diff actual, `E5-winci-review.md`, `E5-coverage-plan.md`, el workflow, los helpers/tests y las rutas de producto necesarias para seguir clipboard, PowerShell, tail y quit.

Revisión sólo estática. No ejecuté tests, colección de pytest, aplicación, probes, clipboard, mutantes ni CI. Tampoco ejecuté el paso de colección del workflow. Los conteos siguientes describen rutas escritas, no resultados. Como comprobación mecánica del diff, `git diff --check` terminó sin errores.

## Veredicto

**NO-GO.** Hay cuatro bloqueos de implementación y uno de diseño de evidencia:

1. los readers PowerShell/Base64 no tienen un protocolo stdout válido en Windows PowerShell 5.1 por el BOM de `Encoding.UTF8`; el reader PowerShell de producto comparte el defecto;
2. la ruta PowerShell real fuerza una conversión LF → CRLF en el payload hostile, por lo que su oráculo exacto debe fallar;
3. rutas WinCI obligatorias todavía convierten fallos de seed/read/probe en `skip`;
4. el workflow cuenta 28 nodos recolectados, pero no exige sus resultados ni rechaza skips obligatorios;
5. tres observaciones de tail todavía omiten la barrera de finalización antes de leer/assertar.

Las 11 rutas señaladas como ausentes por la revisión anterior —2 tail y 9 quit— ya tienen implementación estática. Las 28 celdas P1/P2 también tienen la cadena escrita copy → wait → separate read → paste. Esto no las promueve a cobertura mientras permanezcan los bloqueos siguientes.

## Hallazgos bloqueantes

### B1 — BLOCKER · impl — `Encoding.UTF8` contamina stdout con BOM y Base64 lo rechaza

Ubicaciones:

- `tests/support/b103_clipboard.py:594-615`;
- `tests/test_b103_clipboard_tail.py:240-263`;
- `tests/test_b103_copy_quit_dialog.py:153-162`;
- la misma elección de encoding en producto: `s19_app/tui/os_clipboard_input.py:296-332`.

Los tres readers de prueba establecen `[Console]::OutputEncoding=[Text.Encoding]::UTF8` y después aplican `base64.b64decode(..., validate=True)` a stdout. `Encoding.UTF8` es la variante con preamble. En Windows PowerShell 5.1/.NET Framework, con stdout redirigido, el writer puede anteponer `EF BB BF`; Python `encoding="utf-8"` lo expone como `\ufeff`, y `"".join(stdout.split())` no lo elimina. Ese carácter no pertenece al alfabeto Base64 y `validate=True` lo rechaza. Es el comportamiento documentado/medido en [dotnet/runtime#28929](https://github.com/dotnet/runtime/issues/28929) y [mono/mono#6901](https://github.com/mono/mono/issues/6901), no una pérdida de LF que se pueda arreglar relajando el decoder.

El efecto se propaga por rutas distintas:

- `_probe_once()` convierte la excepción del reader compartido en `usable=False` (`tests/support/b103_clipboard.py:187-203`), y las fixtures la transforman en skip (`:217-226`; `tests/test_b103_clipboard_tail.py:1133-1140`; `tests/test_b103_copy_quit_dialog.py:85-89`).
- Matrix llama al reader compartido directamente (`tests/test_b103_copy_paste_matrix.py:88-99`), por lo que sus celdas pueden fallar antes de copiar.
- Quit convierte el mismo fallo de decodificación en skip (`tests/test_b103_copy_quit_dialog.py:159-162`), ocultando las nueve rutas obligatorias.
- El reader de rescate de producto usa el mismo encoding (`s19_app/tui/os_clipboard_input.py:312-313`) y sólo recorta CR/LF (`:331`). En el brazo PowerShell forzado, `test_r_paste_16_1...` puede recibir `\ufeffPS-READ` en vez del valor exigido en `tests/test_b103_clipboard_windows.py:1691-1695`.

**Desbloqueo:** emitir stdout con UTF-8 sin BOM en todos los readers, incluido producto, y mantener el fallo ante cualquier salida no Base64. No convertir este defecto en skip ni quitar CR/LF del payload decodificado. Una vez eliminado el BOM, la estrategia Base64 sí conserva el LF final de R-COPY.7/5; el antiguo `rstrip("\r\n")` ya no está en el reader compartido.

### B2 — BLOCKER · impl — `$input | Set-Clipboard` no conserva el LF hostile

Ubicaciones: `s19_app/tui/os_clipboard_input.py:120-130`, payload en `tests/test_b103_clipboard_tail.py:52`, estrategia forzada en `:1055-1062` y oráculo exacto en `:1116-1127` / `:329-331`.

`HOSTILE_NAME` contiene exactamente un LF entre su primera línea y `SUFFIX`. El nuevo brazo WinCI sí fuerza el writer PowerShell real, pero ése ejecuta `$input | Set-Clipboard`. `$input` entrega las líneas de stdin como elementos; `Set-Clipboard` acepta `String[]` y los recompone con `Environment.NewLine`, que en Windows es CRLF. La implementación upstream hace explícitamente `string.Join(Environment.NewLine, contentList...)`: [SetClipboardCommand.cs](https://raw.githubusercontent.com/PowerShell/PowerShell/v7.0.0/src/Microsoft.PowerShell.Commands.Management/commands/management/SetClipboardCommand.cs).

Por tanto, el brazo real puede dejar app/OSC 52 con `HOSTILE_NAME` y Windows con `primera línea + "\r\n" + "SUFFIX"`. `_success()` exige `obs["os"] == capped`, así que el resultado esperado es RED aunque argv, stdin, proceso y logs sean correctos. El brazo de una sola línea `PS-WRITE` no discrimina este defecto.

**Desbloqueo:** cambiar la implementación PowerShell para leer stdin como una única cadena completa y escribir ese único valor sin reconstruir sus saltos, manteniendo payload fuera de argv. Por ejemplo, la forma `Console.In.ReadToEnd()` evita la división por líneas de `$input`. No relajar la comparación exacta: el test está exponiendo un defecto de producto exigido por R-TUI-043.13/102.

### B3 — BLOCKER · impl — skips todavía pueden sustituir evidencia WinCI obligatoria

Ubicaciones:

- Matrix: `tests/test_b103_copy_paste_matrix.py:58-85`. `OSError`, `UnicodeError`, timeout y exit distinto de cero durante la seed terminan en `pytest.skip`; las 28 celdas obligatorias pueden omitirse antes de la copia.
- Quit: `tests/test_b103_copy_quit_dialog.py:121-162`. Los mismos fallos y una salida Base64 inválida terminan en skip en las nueve rutas R-COPY.16/.20 que este diff pretende cerrar.
- Probe común: `tests/support/b103_clipboard.py:217-226` y `tests/test_b103_clipboard_tail.py:1133-1140`; también se usa desde quit en `tests/test_b103_copy_quit_dialog.py:85-89`.
- Resolver: `tests/support/b103_clipboard.py:549-556` hace skip si falta PowerShell del sistema, incluso cuando la ruta que lo requiere es obligatoria.

Un probe o una infraestructura no disponible puede quedar registrado como `not_run`, pero no puede producir un job verde de cobertura completa. Los únicos skips que no deben contar como deuda son los brazos deliberadamente asignados a otra plataforma y AT-I1b-8 manual.

**Desbloqueo:** en brazos WinCI obligatorios, fallar la ejecución o marcar el gate como fallido, nunca aceptar el skip como resultado terminal. Mantener los skips de plataforma/manual expresamente separados.

### B4 — HIGH · design-gap — el workflow verifica colección, no ejecución ni cobertura

Ubicación: `.github/workflows/clipboard-windows.yml:71-77`.

El paso `Validate exactly 28 acceptance-matrix nodes` sólo ejecuta `--collect-only` y comprueba 28 líneas únicas. Está bien como guarda de colección, y coincide estáticamente con las 28 entradas únicas de `AT_CELLS` (`tests/test_b103_copy_paste_matrix.py:433-476`). No prueba que ninguna haya corrido.

Después, `pytest -v -rs ...` lista skips pero no los convierte en fallo. No hay un censo posterior por nodeid/brazo que exija las 108 obligaciones WinCI identificadas en `E5-coverage-plan.md`, ni siquiera una aserción de que las 28 celdas de matrix y las nueve rutas quit terminaron passed. Por eso B3 puede elevar cobertura falsamente aunque la colección sea exactamente 28.

**Desbloqueo:** conservar la guarda de colección y añadir un resultado estructurado por nodeid que falle ante todo skip/fallo/error de una obligación WinCI. AT-I1b-8 debe quedar fuera de ese censo automatizado y con evidencia manual separada. Esta revisión no declara ejecutado ninguno de esos pasos.

### B5 — HIGH · impl — tres rutas todavía leen/observan sin esperar el tail

Ubicaciones:

- `tests/test_b103_clipboard_tail.py:576-590`, `_injected_hex_key_observation`;
- `tests/test_b103_clipboard_tail.py:1390-1401`, `_line_cut_observation`;
- `tests/test_b103_clipboard_tail.py:1405-1433`, `_unrelated_view_box_observation`.

El nuevo `tail_done` se escribe en `finally` (`:166-187`) y `_wait_copy_tail()` lo espera en view/box/row (`:89-91`, `:503-510`, `:527-539`, `:565-571`). Eso corrige la carrera principal. Sin embargo, los tres helpers anteriores llaman a `_observe()` después sólo de pausas fijas.

En Windows `_instrument(..., writer_result=True)` se convierte deliberadamente en writer real (`:128-133`). Por ello, line-cut y unrelated-view pueden lanzar el separate read mientras el writer real sigue reintentando; el resultado depende del tiempo de arranque de PowerShell. El brazo inyectado de NUL también puede capturar notice/logs antes de que termine el tail. No hay una barrera que distinga «efectos completos» de «todavía no ocurrieron».

**Desbloqueo:** aplicar la misma espera de `tail_done` antes de `_observe()` en los tres helpers. El `finally` ya evita que una salida temprana del tail deje el marcador sin escribir, pero sólo es útil donde realmente se espera.

## Comprobaciones que el diff sí cierra estáticamente

- **Holder:** `Sleep` pertenece ahora a `kernel32` y los prototipos Win32 están declarados (`tests/test_b103_clipboard_tail.py:1167-1204`). Readiness usa cola con timeout y limpieza en error (`:1216-1266`); reap/release tienen esperas acotadas (`:1143-1157`). No encontré en este diff el antiguo `user32.Sleep` ni el `readline()` bloqueante sin cota.
- **R-PASTE.13:** espera `writer_done` y `tail_done`, mide después de ambos, libera/reapa y sólo entonces hace `_observe()` (`:1291-1306`). Ya no lee el clipboard retenido ni mide únicamente el gesto.
- **R-PASTE.14:** espera writer y tail antes de liberar y leer (`:1344-1353`), conservando writer fuera del hilo UI, ticks y bound (`:1357-1363`).
- **PowerShell absoluto:** matrix, tail, quit y el helper compartido usan `_system_powershell()`/`_system_powershell_path()`, no `PATH` (`s19_app/tui/os_clipboard_input.py:184-196`; `tests/support/b103_clipboard.py:549-556`; `tests/test_b103_copy_paste_matrix.py:54-55`; `tests/test_b103_clipboard_tail.py:229-233`; `tests/test_b103_copy_quit_dialog.py:124-141`).
- **Matrix P1/P2:** las 28 celdas esperan el tail, comprueban notice/app/separate read y después pegan (`tests/test_b103_copy_paste_matrix.py:397-429`). P1 usa Ctrl+V; P2 publica `events.Paste(os_artifact)`, no `expected`. El aislamiento incluye la cuenta mediante `clipboard_isolated()` (`:28-35`).
- **R-TUI-043.13/101:** los cuatro brazos WinCI están escritos (`tests/test_b103_clipboard_tail.py:1001-1042`). La conversión `writer_result=True → None` en Windows (`:129-133`) hace que incluso `row-success-real-writer` use el writer real; no es ya un recorder oculto. La captura DEBUG se retira y el nivel se restaura en `finally` (`:878-888`).
- **R-TUI-043.13/102:** el wrapper pass-through fuerza sólo PowerShell (`:1055-1062`), conserva proceso real y exige cardinalidad/argv/stdin/logs (`:1116-1130`). Su bloqueo restante es la transformación LF de B2, no una ruta simulada.
- **Quit 9:** las seis rutas R-COPY.16 y las tres R-COPY.20 reciben `winci_seed=True` (`tests/test_b103_copy_quit_dialog.py:537-645`, `:729-797`). `_assert_no_copy_effects()` lee el OS real cuando la seed está armada (`:382-399`), con lecturas abiertas/después de Stay o del cierre modal correspondiente.
- **Workflow:** las dependencias de paths se ampliaron, Textual queda fijado a 8.2.8 y hay timeout de step (`.github/workflows/clipboard-windows.yml:9-41`, `:61-77`). La colección de 28 está cableada, pero no se afirma ejecutada y no sustituye B4.

## Cobertura que sigue sin ruta completa

Estas lagunas ya estaban en `E5-coverage-plan.md:152-186`; el diff no las cierra. Son **MEDIUM · design-gap** y no deben promoverse por una pasada WinCI de los nodos vecinos:

- **R-COPY.1/4 y R-COPY.12/3:** el drag real de detail-card produce y exige cinco líneas, no las dos del grafo; el propio comentario mantiene el brazo parcial (`tests/test_b103_copy_views.py:404-418`).
- **R-COPY.25/1, arming view-key:** sigue sustituyendo `app.screen.get_selected_text` por un lambda (`tests/test_b103_clipboard_tail.py:576-590`). Prueba el tail con NUL, no una selección hex real más Ctrl+C.
- **Controles E3-01:** replacement/replay de R-COPY.12/7 no arma el MouseUp forwarded sin candidato (`tests/test_b103_copy_views.py:666-688`); los brazos /7…/8 siguen limitados a hex (`:748-805`). Siguen sin ruta completa los drags A2L/MAC con `out_of_bounds=False`, release al mismo offset en otro widget/screen y la cardinalidad directa de forwarding descritos en el plan.
- **R-COPY.4/2 y help:** MAC sigue usando siempre Rich `Text`, sin brazo non-`Text` → `str(cell)` (`tests/test_b103_copy_views.py:550-564`). Help comprueba dos líneas no vacías, pero no que sean las dos primeras (`:429-434`).
- **Quit/grafo:** R-DLG.12/101…102 ejercita una respuesta por nodo, no una segunda respuesta ignorada por `_dismissed` (`tests/test_b103_copy_quit_dialog.py:993-1019`). La ruta palette elige `Quit`, pero no fija por sí misma el token visible `q Quit`, una única entrada y su acción (`:894-920`).

**Manual pendiente, no defecto de automatización:** AT-I1b-8 sigue correctamente excluido (`tests/test_b103_copy_paste_matrix.py:479-486`) y requiere los seis pasos del operador en Windows Terminal (`01-requirements.md:138`). WinCI no cierra esa aceptación.

## Condiciones mínimas para cambiar el veredicto

1. Eliminar BOM de todos los readers PowerShell y corregir el reader de producto; conservar LF final mediante Base64.
2. Hacer que el writer PowerShell real transporte el payload multilínea sin normalizar LF a CRLF.
3. Impedir skips terminales en obligaciones WinCI y añadir al workflow un censo de resultados por nodeid/brazo.
4. Esperar `tail_done` en los tres helpers restantes.
5. Después de esas correcciones, ejecutar la batería estándar en Linux y la selección WinCI, conservando resultados reales por nodo; ningún resultado se anticipa aquí.
6. Resolver o declarar explícitamente fuera del gate las lagunas de grafo anteriores, y obtener por separado AT-I1b-8 manual.

Hasta entonces no procede declarar Windows CI listo, cobertura completa, CI ejecutado ni mutantes ejecutados.
