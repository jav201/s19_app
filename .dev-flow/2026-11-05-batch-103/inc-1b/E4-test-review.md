# Inc 1b — E4 test quality review

Commit revisado: `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`.

Alcance: revisión estática de los cuatro tests nuevos, sus reportes/transcripts RED, `codewire/graph-inc1b.md`, `01-requirements.md`, `02-test-cases.md` y `E3-rulings.md`. No ejecuté tests ni mutantes en Windows; tampoco ejecuté el GREEN Linux. El GREEN Linux comunicado por integración no sustituye las comprobaciones WinCI ni demuestra los mutantes descritos abajo.

## Veredicto

**FAIL — NO PASS.**

La correspondencia numérica y la identidad de las evidencias RED son correctas, y los reportes generalmente declaran con honestidad sus estados `partial`, `not_run` y `pass-base`. No obstante:

- 30 nodos marcados `partial` (21 tail + 9 quit) no contienen el brazo WinCI que podría cerrar esa cobertura: seguirían usando recorders, o se saltarían, incluso en Windows.
- R-COPY.15/1–3 pueden pasar sin que se produzca la copia cuya consecuencia pretenden verificar; de hecho pasan en el base sin right-click copy.
- Dos casos de detail-card reescriben manualmente la selección después del drag, y faltan controles explícitos del grafo para text box y para el límite de imports.
- Hay debilidades adicionales en skips multi-brazo, cardinalidad de NUL y aplicación de `timing_bound`.

No encontré una laguna del diseño que justificara estas omisiones: los comportamientos y controles ya están exigidos por los artefactos normativos. Los hallazgos son, por tanto, `impl` de tests/evidencia, no `design-gap`.

## Correspondencia de nodos y estados RED

| Familia | Cobertura nominal | Nodos esperados | RED registrado |
|---|---|---:|---|
| `test_b103_copy_views.py` | 54 casos de requisitos | 54 | 25 failed, 29 passed, 0 skipped |
| `test_b103_clipboard_tail.py` | 30 casos de requisitos | 30 | 21 failed, 5 passed, 4 skipped |
| `test_b103_copy_quit_dialog.py` | 28 casos de requisitos | 28 | 25 failed, 3 passed, 0 skipped |
| `test_b103_copy_paste_matrix.py` | 28 celdas AT-I1b-1…7 + AT-I1b-8 manual | 29 | 14 failed, 15 skipped |
| **Total** | **112 requisitos + 28 AT + 1 manual** | **141 = 54+30+28+29** | **85 failed, 37 passed, 19 skipped** |

Los nodeids parametrizados cubren una y sólo una vez cada caso asignado. Los transcripts confirman `collected=54/30/28/29` y los totales anteriores. Los hashes SHA-256 de los cuatro blobs de Git en `29ce6448` coinciden con los hashes de test publicados en los cuatro reportes RED; una comparación inicial con el working tree sólo mostró la diferencia CRLF/LF, no otra versión de los tests.

La lectura de cobertura debe ser más estricta que el recuento:

- **views:** 32 `full-linux` y 22 `partial-writer-proxy`; 46 casos conservan WinCI `not_run`. Sus ramas WinCI sí contienen `other_program_read`, por lo que la brecha es de ejecución pendiente, salvo los defectos concretos señalados abajo.
- **tail:** 21 nodos `partial`, 4 WinCI-only `not_run` y 5 casos Linux completos. Los 21 `partial` no tienen una rama de lectura OS separada.
- **quit:** 19 `full` Linux y 9 `partial`; esos 9 conservan el recorder incluso en WinCI.
- **matrix:** 0/28 cadenas copy → separate read → paste verificadas en RED; 14 P1 llegan sólo al assert de copia, 14 P2 quedan `not_run` y AT-I1b-8 queda manual `not_run`. El código WinCI de estas celdas sí implementa la cadena real.

Por tanto, **141 nodos nominales no equivalen a 141 comportamientos verificados**. Los reportes no ocultan casi ninguna de estas brechas; el problema es que varias son estructurales del test on-disk, no meramente ejecuciones pendientes.

## Hallazgos

### TQR-01 — HIGH — `impl` — los 21 casos `partial` de tail no pueden verificar WinCI

**Ubicación:** `tests/test_b103_clipboard_tail.py:118-197`, `tests/test_b103_clipboard_tail.py:599-950`, `tests/test_b103_clipboard_tail.py:900-950`.

`_instrument` instala `writer_spy`; con `writer_result=True` no llama al writer real y copia directamente `text` en `ledger.os_clipboard` (`:153-163`). `_success` luego comprueba ese valor de recorder (`:249-250`). No existe ninguna llamada a `other_program_read` ni a otra lectura OS separada en este archivo. Esto afecta a:

- R-COPY.6/1–5;
- R-COPY.7/1–7;
- R-COPY.8/1–2 y R-COPY.9/1–2;
- R-COPY.25/1–3;
- R-TUI-043.13/101–102.

El caso hostile es especialmente claro: `:909-928` sustituye `subprocess.run` por `fake_run` y vuelve a asignar `ledger.os_clipboard = text`. Es un buen ensayo unitario de argv/stdin, pero no satisface R-TUI-043.13/102, exigido en WinCI con app/OSC 52/Windows iguales al `HOSTILE_NAME` real. Tampoco las fronteras de 65.536 caracteres ni la conservación de seeds de R-COPY.6/.25 obtienen aquí una lectura Windows independiente.

El reporte `evidence-e4/tail/RED-REPORT.md:19-50` marca estos nodos `partial`, lo cual es correcto; la cobertura no está oculta. El defecto es que ejecutar ese mismo archivo en WinCI no la cerraría. Un GREEN Linux puede pasar con writer, transporte PowerShell, clipboard Windows y separate read rotos.

**Propuesta:** dentro de los nodos existentes, añadir una rama WinCI que use `require_isolated_clipboard`, seed mediante otro proceso, writer real y `other_program_read()`/PowerShell separado, con lecturas antes/después y después de `n` donde el ledger lo exige. No presentar `ledger.os_clipboard = text` como evidencia OS. Para hostile, conservar el proceso simulado sólo como brazo unitario Linux; en WinCI usar un spy pass-through y una lectura separada del resultado real de PowerShell. Mantener `partial/not_run` hasta ejecutar esa rama.

### TQR-02 — MAJOR — `impl` — los 9 casos `partial` de quit sustituyen permanentemente la lectura WinCI por un recorder

**Ubicación:** `tests/test_b103_copy_quit_dialog.py:64-92`, `tests/test_b103_copy_quit_dialog.py:434-541`, `tests/test_b103_copy_quit_dialog.py:625-688`.

El fixture autouse reemplaza `write_os_clipboard` y `read_os_clipboard` en todas las plataformas. `write` actualiza `recorder.os_value = text` y `_assert_no_copy_effects` lee ese recorder (`:285-299`). No hay guarda WinCI, seed por otro programa ni `Get-Clipboard -Raw` en el archivo.

Así, R-COPY.16/1–6 y R-COPY.20/1–3 pueden comprobar diálogo y estado interno, pero no la mitad WinCI que sus precondiciones heredadas exigen. El reporte `evidence-e4/quit/report.md:9-11` los declara `partial`; de nuevo, no es sólo una ejecución WinCI pendiente: falta el brazo de test.

**Propuesta:** hacer condicional el recorder: en WinCI, sembrar y releer mediante procesos separados, sin reemplazar el writer/reader real; comprobar ambas seeds mientras el diálogo está abierto y después de `n`, además de los contadores internos ya presentes. Reservar el recorder para Linux.

### TQR-03 — MAJOR — `impl` — R-COPY.15/1–3 son oráculos condicionales vacuos sin copia

**Ubicación:** `tests/test_b103_copy_views.py:809-822`; cobertura publicada en `evidence-e4/views/per-case.csv:49-51`.

Después de armar una selección y hacer right-click, el test sólo comprueba que la selección queda vacía. No comprueba `entry`, tail, writer, OSC 52 ni `app.clipboard`. Por eso los tres nodos pasan en el base, donde la copia right-click todavía no existe; el reporte los clasifica `pass-base` y `full-linux`.

Esto no satisface el antecedente de R-COPY.15 («when the system has copied…») ni los ejemplos integrados del grafo (`graph-inc1b.md:213-215`), que exigen una copia y después selección vacía. Mutante concreto: eliminar la llamada de copia del release right-button pero conservar el forwarding de Textual; estos tres nodos siguen en verde porque Textual limpia la selección.

**Propuesta:** capturar el texto independiente antes del gesto y, en cada nodo, exigir primero una copia válida (`_assert_single_copy` o, como mínimo, writer/app/OSC 52 con el payload esperado) y sólo después la selección vacía. El nodo debe volverse RED si desaparece la copia, no sólo si deja de limpiarse la selección.

### TQR-04 — MAJOR — `impl` — el drag de detail-card se corrige manualmente antes de definir el expected

**Ubicación:** `tests/test_b103_copy_views.py:372-390`.

En `source == "detail"` se ejecuta un drag real, pero después se reemplaza el final de la selección en `screen.selections` (`:385-388`) y se exige que el texto resultante sea `painted[1:3]`. El oráculo ya no es únicamente «el texto seleccionado tras el drag», como fijan `02-test-cases.md:12` y los casos R-COPY.1/4 y R-COPY.12/3.

Un defecto en hover/mouse-up o en la materialización del final de selección puede quedar oculto por esta escritura directa. Además, el reporte describe un drag ejecutado sin revelar esta sustitución, a diferencia de la inyección NUL que tail sí declara explícitamente como parcial.

**Propuesta:** elegir coordenadas reales que produzcan dos líneas no vacías y distinguibles, leer `get_selected_text()` después del drag sin modificar `screen.selections`, y comparar contra esa selección. Si la versión de Textual impide materializar el ejemplo, separar el ensayo de tail del ensayo driver y mantener explícitamente `partial` la cobertura del gesto.

### TQR-05 — MAJOR — `impl` — un skip dentro de R-COPY.9/1 invalida todos sus brazos WinCI

**Ubicación:** `tests/test_b103_clipboard_tail.py:723-744` y `tests/test_b103_clipboard_tail.py:284-293`.

R-COPY.9/1 agrega cuatro brazos en un solo nodo: longitud original 75.210, exactamente 65.536, 65.537 y writer failure. En Windows, el cuarto brazo ejecuta `pytest.skip` (`:734-736`). `pytest.skip` no es una `AssertionError` capturada por `_run_arms`; termina el nodo completo, aunque los tres brazos anteriores ya se hayan ejecutado. El resultado del nodo queda skipped/not_run y no aporta un pase WinCI de los brazos de cap/longitud.

**Propuesta:** no usar `pytest.skip` dentro de un nodo multi-brazo. Ejecutar condicionalmente el brazo Linux sin omitir los demás, o implementar en WinCI el writer failure mediante el holder aislado ya previsto. El reporte por brazo debe distinguir resultados; un skip del brazo de fallo no debe borrar la evidencia de los otros tres.

### TQR-06 — MAJOR — `impl` — faltan dos controles discriminating exigidos por el grafo

**Ubicación:** `tests/test_b103_clipboard_tail.py:667-678` y `tests/test_b103_clipboard_tail.py:118-197`; contratos en `codewire/graph-inc1b.md:130`, `:204` y `:340`.

1. R-COPY.7/7 prueba right-click directo en input y textarea, pero no crea la selección hex ajena de tres filas exigida por E3A-24(c). Sin esa selección competitiva, un mutant que introduzca una copia de vista adicional o prefiera el texto hex en este contexto no queda ejercitado por el ejemplo diseñado para detectarlo.
2. El gate E4 exige también un chequeo estático que rechace cualquier import de `s19_app.tui.app` en `os_clipboard_input.py`. El instrumento dinámico de tail no contiene ese chequeo AST; un import circular añadido al producto puede escapar a estos oráculos según el orden de importación.

**Propuesta:** en R-COPY.7/7, armar primero S3 hex y después `abc` en el input; al hacer right-click en `abc`, exigir override de vista 0, una sola ruta directa y ausencia de texto hex en todos los sinks. Añadir en un nodo existente una inspección AST de imports del módulo clipboard que rechaze tanto `import s19_app.tui.app` como `from s19_app.tui.app import …`.

### TQR-07 — MINOR — `impl` — la cardinalidad de avisos NUL admite efectos adicionales

**Ubicación:** `tests/test_b103_clipboard_tail.py:265-274` y `tests/test_b103_clipboard_tail.py:762-765`.

`_refusal` comprueba que hay exactamente una fila con el texto NUL esperado, pero permite otras notificaciones/warnings. `_assert_nul_log` exige que el WARNING fijo aparezca una vez, no que sea el único WARNING del gesto. Un mutant que añada una segunda warning distinta, o una warning de writer aunque el writer no se haya llamado, puede conservar estos asserts en verde pese a la regla fail-closed de un único aviso/WARNING y cero efectos adicionales.

**Propuesta:** aislar el intervalo del gesto y exigir la lista completa de notificaciones de warning y la lista completa de WARNING, además de los contadores ya existentes. Como mínimo: una sola warning total con mensaje/severity/timeout exactos y un único WARNING total con el texto fijo; mantener la ausencia de payload en todos los niveles.

### TQR-08 — MINOR — `impl` — los límites de salida de quit no usan `timing_bound`

**Ubicación:** `tests/test_b103_copy_quit_dialog.py:371-378`, usado en `:547-585`, `:770-804` y `:897-904`.

`_answer_and_time` impone siempre 1,0 s. Los casos R-COPY.17 y R-COPY.24 remiten a `timing_bound`; en CI el helper del proyecto duplica el límite local para no convertir ruido del runner en un fallo de producto. La medición sí empieza antes de la entrada y comprueba return code 0, por lo que el oráculo no es vacuo, pero puede generar falsos fallos en CI.

**Propuesta:** usar `tests.support.timing.timing_bound(1.0)` y `report_margin`, como ya hacen los tests held-clipboard de tail. Conservar la medición wall-clock desde la entrada y el return code.

## Controles que sí resultan discriminating en la revisión estática

- **Oráculos independientes:** S3 hex exige tres líneas distintas; cross-view exige dos fragmentos distintos y ordenados; A2L usa el nombre canónico del modelo y no la celda abreviada; `J75210` valida longitud y marcadores kept/discarded antes de copiar; NUL_AFTER fija el único NUL en índice 65.536.
- **Right-event real:** views, tail y matrix construyen `MouseDown`/`MouseUp` (y `MouseMove` en negativos) y los envían mediante `App.post_message`, no `Pilot.click(button=3)`. Hay controles back-to-back, reentry, exit-return y `out_of_bounds` positivo/negativo.
- **Acceptance sin shim de paste:** en WinCI, matrix siembra y relee con PowerShell separado, codifica la salida en Base64 y alimenta P2 exclusivamente con `_read_os_clipboard()`; publica `events.Paste(os_artifact)`, no `events.Paste(expected)` ni `_on_paste(expected)`. T1/T2 comparan el contenido exacto una vez. La ejecución sigue pendiente; el diseño del nodo no es el shim prohibido.
- **Skips RED:** los 15 skips de matrix son exactamente 14 P2 WinCI + AT-I1b-8; los 4 de tail son exactamente R-PASTE.13/101 y R-PASTE.14/101–103. Ninguno se cuenta como verificado en su reporte.
- **Timing held-clipboard:** tail comprueba writer fuera del hilo UI, al menos diez ticks y latencia máxima contra `timing_bound(0.1)`; R-PASTE.13 mide wall-clock y una sola cascada. No se limita a afirmar terminación eventual.
- **Mutantes cubiertos por el código on-disk:** cap eliminado/off-by-one, pérdida del N original, LF final contado como línea extra, copia de fila destacada en vez de clicada, copia en MouseDown, revalidación tras exit-return y copia por encima del cap con NUL sólo después del límite tienen aserciones concretas. Esto no reemplaza ejecutar mutantes en una fase posterior.

## Condiciones para una nueva evaluación

1. Cerrar TQR-01…TQR-08 en los tests y actualizar los reportes sin convertir skips o recorders en cobertura WinCI.
2. Ejecutar en la ruta aislada WinCI las lecturas OS, los 28 enlaces acceptance, hostile/PowerShell y held-clipboard; conservar `not_run` hasta tener evidencia real.
3. Ejecutar AT-I1b-8 únicamente por el operador, como exige el diseño; su skip automatizado actual no es un defecto impl, pero sigue siendo un gate manual abierto.
4. Repetir el GREEN Linux y el suite estándar tras los cambios, y ejecutar los mutantes prioritarios: no-copy en R-COPY.15, selección competitiva en text box, writer Windows roto, cap off-by-one y aviso NUL adicional.

Hasta entonces, el conteo 54+30+28+29 es una asignación nominal completa, no evidencia suficiente para PASS.
