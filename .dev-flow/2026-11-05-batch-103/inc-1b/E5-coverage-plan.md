# Inc 1b — E5 coverage plan

Commit revisado estáticamente: `e8f8e3d189ab60eb24b05e7d917b7cd32311468e`.

Alcance: `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc1b.md`, `E3-rulings.md` y los cuatro tests actuales. También se leyó el helper `tests/support/b103_clipboard.py` para comprobar si una supuesta lectura OS es realmente un proceso PowerShell separado. No se ejecutaron tests, aplicación, probes, mutantes ni clipboard; no se modificaron producto, tests, requirements ni ledger. Este documento no declara GREEN ni ejecución WinCI.

## 1. Definiciones y censo total

La población canónica es **112 casos activos de requisitos + 28 celdas AT + AT-I1b-8 = 141 nodos**. Los 112 se descomponen en 93 R-COPY + 10 citados de clipboard/seguridad + 9 citados de diálogo/quit (`02-test-cases.md:158`; `E3-rulings.md:18`). Los 9 casos retirados R-COPY.3/1…5 y R-COPY.5/1…4 no se cuentan. AT-I1b-8 es un nodo manual de seis pasos, no una vigésimo novena celda automatizada (`02-test-cases.md:154`).

Estados usados aquí, siempre como clasificación estática y no como resultado de ejecución:

- **FL-L**: oráculo Linux completo en el nodo asignado a Linux por `02-test-cases.md`. Esto no elimina un complemento WinCI compartido con otro nodo: R-COPY.7/8 depende de la ejecución held de R-PASTE.13/101 para su observación Windows.
- **FL-D**: oráculo de la parte Linux completo, pero el mismo caso también exige WinCI. No es cobertura global completa.
- **P-R**: `partial`; ya existe una rama WinCI con writer/artefacto real, pero falta ejecutarla y registrar su evidencia.
- **P-N**: `partial`; incluso en Windows el nodo hace skip o conserva un recorder, por lo que todavía no tiene la rama WinCI real necesaria.
- **NR-R**: `not_run` en Linux por ser WinCI-only; la rama real sí está implementada.
- **M**: aceptación manual del operador.

| Población / archivo | FL-L + FL-D | P-R | P-N | NR-R | M | Total |
|---|---:|---:|---:|---:|---:|---:|
| Requisitos — `test_b103_copy_views.py` | 8 + 24 = 32 | 22 | 0 | 0 | 0 | 54 |
| Requisitos — `test_b103_clipboard_tail.py` | 5 + 0 = 5 | 19 | 2 | 4 | 0 | 30 |
| Requisitos — `test_b103_copy_quit_dialog.py` | 19 + 0 = 19 | 0 | 9 | 0 | 0 | 28 |
| **Subtotal requisitos** | **32 + 24 = 56** | **41** | **11** | **4** | **0** | **112** |
| AT-I1b-1…7 — `test_b103_copy_paste_matrix.py` | 0 | 14 | 0 | 14 | 0 | 28 |
| AT-I1b-8 | 0 | 0 | 0 | 0 | 1 | 1 |
| **Total** | **56** | **55** | **11** | **18** | **1** | **141** |

En la lectura convencional hay, por tanto, **56 `full-linux`, 66 `partial` (55 P-R + 11 P-N), 18 `not_run` y 1 manual**. `full-linux` no significa que las 24 piezas FL-D hayan cerrado WinCI.

La partición operativa, también sin contar ejecuciones inexistentes, es:

- **32** casos de requisitos Linux-only (8 views + 5 tail + 19 quit).
- **108** obligaciones automatizadas WinCI: 80 de requisitos + 28 AT.
- De esas 108, **97 ya tienen ruta real implementada** (69 requisitos + 28 AT) y **11 no la tienen** (2 tail + 9 quit).
- **1** aceptación manual independiente de WinCI: AT-I1b-8.

La existencia de una rama se comprobó en código. En views y tail, `other_program_read()` termina en un `subprocess.run` separado, con `Get-Clipboard -Raw`, `shell=False` y ruta de PowerShell (`tests/support/b103_clipboard.py:584-595`). En matrix, la lectura equivalente está en `tests/test_b103_copy_paste_matrix.py:49-108`. Nada de esto se presenta como evidencia de que esas rutas hayan corrido.

## 2. Censo por archivo y nodo

### 2.1 Views/gestures — 54 casos

La fixture usa el writer real en WinCI y conserva recorder solamente fuera de Windows (`tests/test_b103_copy_views.py:65-112`). Siembra mediante otro programa en `_arm` (`:181-188`) y dispone de lecturas OS separadas para copia y para ausencia de escritura (`:221-256`).

| Casos | N. | Estado | Nodo/oráculo actual y rama WinCI que falta ejecutar |
|---|---:|---|---|
| R-COPY.1/1…6 | 6 | P-R | `test_r_copy_1_ctrl_c_writes_each_view` (`tests/test_b103_copy_views.py:469-483`): writer real + separate read de las seis selecciones. `/4` conserva además la laguna geométrica de §4.1. |
| R-COPY.2/1…3 | 3 | FL-D | `test_r_copy_2_app_clipboard` (`:487-524`): falta el brazo WinCI de app/base/OSC/writer para key, right-view y right-row; este requisito no añade una lectura OS propia. |
| R-COPY.2/4 | 1 | FL-L | Mismo nodo; fallo de writer Linux y app clipboard con nombre de fila (`:503-523`). El skip WinCI de `:488-489` corresponde a este brazo Linux-only, no a `/1…3`. |
| R-COPY.4/1…3 | 3 | P-R | `test_r_copy_4_full_row_names` (`:528-566`): separate read de A2L fila 3, MAC fila 3 + segundo arming Rich largo, y A2L fila 5 con otra fila destacada. |
| R-COPY.10/1…3 | 3 | FL-D | `test_r_copy_10_one_osc52_request` (`:570-590`): falta repetir en WinCI la cardinalidad/decodificación OSC 52 de key, right-view y right-row. |
| R-COPY.11/1…5 | 5 | P-R | `test_r_copy_11_selection_and_highlight_do_not_copy` (`:594-645`): seed OS real, cero writers/OSC; incluye right-drag con MouseMove forwarded y no forwarded (`:625-643`). Controles de grafo aún dudosos en §4.3. |
| R-COPY.12/1…8 | 8 | P-R | `test_r_copy_12_right_click_selection`, `_7_back_to_back_and_reentry`, `_8_positive_bounds_and_cardinality` (`:653-726`): separate read del snapshot en las ocho rutas, cardinalidad y bounds. `/3` conserva la laguna de §4.1; `/7` la de §4.3. |
| R-COPY.13/1…9 | 9 | FL-D | `test_r_copy_13_empty_and_cancelled_gestures` (`:821-841`): en WinCI lee el seed tras cada conjunto de gestos y exige entry/tail/base/writer/OSC vacíos; `/9` además cursor, `RowSelected` y primera línea hex. |
| R-COPY.14/1…9 | 9 | FL-D | `test_r_copy_14_empty_and_cancelled_gestures_have_no_notice` (`:845-854`): mismos gestos reales y cero notices. La lectura OS asociada está en R-COPY.13; no se la inventa como aserción duplicada de R-COPY.14. |
| R-COPY.15/1…3 | 3 | FL-L | `test_r_copy_15_right_click_clears_selection` (`:858-871`): ya exige primero una copia completa y después selección vacía; el antecedente ya no es vacuo. |
| R-COPY.21/1…2 | 2 | FL-L | `test_r_copy_21_valid_right_click_highlights_without_selection` (`:875-891`): fila destacada y cero `RowSelected`. |
| R-COPY.22/1…2 | 2 | FL-L | `test_r_copy_22_right_click_does_not_jump_hex` (`:895-909`): primeras líneas hex antes/después y cero `RowSelected`. |

WinCI pendiente en este archivo: **46 casos = 22 P-R + 24 FL-D**. Los otros 8 son FL-L. Los 46 tienen ruta real implementada; esto no cierra las dudas independientes de §4.

### 2.2 Clipboard/tail — 30 casos

Tras los fixes, `_instrument` sí tiene una rama WinCI: guarda de aislamiento/probe, seed externo y conversión de `writer_result=True` a writer real (`tests/test_b103_clipboard_tail.py:120-125`). El spy delega en el writer original cuando `writer_result is None` (`:161-171`) y `_read_os` restaura el proceso original y llama a `other_program_read()` (`:210-218`). Las lecturas ordinarias posteriores salen en `_observe` (`:221-243`).

| Casos | N. | Estado | Nodo/oráculo actual y rama WinCI que falta ejecutar |
|---|---:|---|---|
| R-COPY.6/1…5 | 5 | P-R | `test_r_copy_06_1…5` (`tests/test_b103_clipboard_tail.py:524-637`): ya lee OS **mientras el diálogo está abierto** (`:535,556,581,603,630`) y otra vez **después de `n`/Stay** en `_observe`; `_observe` también exige la primera lectura = seed (`:239-241`). Faltan esas cinco ejecuciones reales, no el código de lectura. |
| R-COPY.7/1…7 | 7 | P-R | `test_r_copy_07_1…7` (`:640-726`): writer real + separate read + un notice para fila, stats, hex y rutas directas de input/textarea, incluida la selección ajena competitiva de `/7` (`:716-725,1227-1264`). |
| R-COPY.7/8 | 1 | FL-L | `test_r_copy_07_8_failed_write_has_no_success_notice` (`:729-734`): brazo Linux de writer fallido. Su skip WinCI no debe ocultar que el control held equivalente está en R-PASTE.13/101, donde `_failure` exige cero `Copied…` y una warning (`:1105-1129`). |
| R-COPY.8/1…2 | 2 | P-R | `test_r_copy_08_1…2` (`:737-768`): app/OSC/OS = prefijo de 65.536 para JSON key/right y brazos directos adicionales. |
| R-COPY.9/1…2 | 2 | P-R | `test_r_copy_09_1…2` (`:771-804`): cut notice con N original y fronteras. El brazo de fallo de `/1` ya no aborta el nodo en Windows: usa `held=True` (`:782-797`) y el holder real de `_view_observation` (`:442-453`). |
| R-COPY.25/1…3 | 3 | P-R | `test_r_copy_25_1…3` (`:822-886`): seeds OS reales, cero sinks en rechazo, lista completa de notices/WARNING (`:290-296,816-819`) y NUL después del cap con OS/cut notice. El brazo key inyectado de `/1` queda dudoso en §4.2. |
| R-PASTE.9/101…103 | 3 | FL-L | `test_r_paste_09_101…103` (`:889-910`): writer fallido Linux para view-key, view-right y row-right; skips WinCI deliberados. |
| R-PASTE.10/101 | 1 | FL-L | `test_r_paste_10_101_exact_tail_warning_without_payload` (`:913-923`): WARNING Linux y ausencia de payload. |
| R-PASTE.13/101 | 1 | NR-R | `test_r_paste_13_101_held_row_copy_warns_within_bound` (`:1105-1129`): ruta real con guarda/probe, seed externo, holder de 8 s, una cascada y elapsed contra `timing_bound(2.5)`. Falta ejecutar y medir WinCI; el bound no se da por cumplido. |
| R-PASTE.14/101…103 | 3 | NR-R | `test_r_paste_14_101…103` (`:1188-1209`), con `_responsive_copy`/`_assert_responsive` (`:1132-1185`): holder real, writer fuera del hilo UI, al menos diez ticks y `max(lateness) <= timing_bound(0.1)` para key/right/row. Rutas presentes; timing real pendiente. |
| R-TUI-043.13/101 | 1 | **P-N** | `test_r_tui_043_13_101_no_copied_text_or_prefix_in_logs` (`:926-951`): **skip en todo WinCI** en `:928-929`. No existe en otro nodo el “successful WinCI arm” anunciado por ese skip. Falta la rama descrita en §3.1. |
| R-TUI-043.13/102 | 1 | **P-N** | `test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs` (`:1008-1027`): PowerShell simulado Linux y skip explícito en `:1011-1012` porque la lectura WinCI no está implementada. Falta la rama real de §3.2. |

WinCI pendiente en este archivo: **25 casos = 19 P-R + 2 P-N + 4 NR-R**. Solo 23 tienen actualmente ruta real. R-PASTE.9/101…103 y R-PASTE.10/101 son Linux-only; R-COPY.7/8 tiene su complemento held en R-PASTE.13/101.

### 2.3 Quit/dialog — 28 casos

| Casos | N. | Estado | Nodo/oráculo actual y rama WinCI que falta |
|---|---:|---|---|
| R-COPY.16/1…6 | 6 | **P-N** | `test_r_copy_16_1…6` (`tests/test_b103_copy_quit_dialog.py:452-559`): diálogo, SkipAction, geometría y cierre con `n` sí están; **no hay rama OS real** para las seeds mientras está abierto/después de Stay. Ver §3.3. |
| R-COPY.17/1…3 | 3 | FL-L | `test_r_copy_17_1…3` (`:565-603`): y, Tab+Enter y click, return code 0 y `_answer_and_time`. |
| R-COPY.18/1 | 1 | FL-L | `test_r_copy_18_1_stay_has_confirm_emphasis` (`:606-616`). |
| R-COPY.19/1 | 1 | FL-L | `test_r_copy_19_1_busy_ctrl_c_opens_busy_question` (`:622-640`): held load y pregunta busy, sin body B. |
| R-COPY.20/1…3 | 3 | **P-N** | `test_r_copy_20_1…3` (`:643-706`): modal/stack/seeds sólo con recorder. Falta la rama OS real de §3.3; `/4` es Linux-only. |
| R-COPY.20/4 | 1 | FL-L | `test_r_copy_20_4_busy_question_stays_top` (`:709-733`). |
| R-COPY.23/1…2 | 2 | FL-L | `test_r_copy_23_1…2` (`:739-785`): q idle con/sin selección y segunda q sin duplicar. Dudas de grafo en §4.4. |
| R-COPY.24/1…2 | 2 | FL-L | `test_r_copy_24_1…2` (`:788-822`): Ctrl+Q/palette, salida inmediata y timing. |
| R-DLG.1/101, .2/101, .6/101, .9/101, .11/101, .12/101…102, .14/101 | 8 | FL-L | Nodos `test_r_dlg_*` (`:828-957`): modalidad, Escape/Stay, foco, labels, y/n y censo de opener. Segunda respuesta heredada no comprobada; ver §4.4. |
| R-QUIT.8/101 | 1 | FL-L | `test_r_quit_8_101_confirmed_busy_quit_waits_for_load` (`:960-981`): no sale antes de liberar la carga; después return code 0. |

Los tiempos de salida usan `timing_bound(1.0)` y `report_margin` en `_answer_and_time` (`tests/test_b103_copy_quit_dialog.py:386-395`). Esto es cobertura del oráculo Linux, no una medición WinCI.

### 2.4 Acceptance matrix y AT manual — 29 nodos

| Casos | N. | Estado | Ruta actual y lo pendiente |
|---|---:|---|---|
| AT-I1b-1…7 `/1` y `/3` (T1/T2 por P1) | 14 | P-R | En Linux, `_coverage_or_skip` sólo permite P1 headless y lo declara `partial` (`tests/test_b103_copy_paste_matrix.py:28-46`). En WinCI el mismo `_run_cell` siembra, copia por right-click real, lee OS por PowerShell y hace Ctrl+V (`:365-413`). Falta la cadena WinCI copy → separate read → P1 → contenido exacto en las 14 celdas. |
| AT-I1b-1…7 `/2` y `/4` (T1/T2 por P2) | 14 | NR-R | P2 hace skip en Linux (`:31-36`). La rama WinCI ya publica `events.Paste(os_artifact)`, donde `os_artifact = _read_os_clipboard()` y se exige igual a `expected` (`:386-403`); no inyecta `expected` ni llama directamente `_on_paste`. Faltan las 14 cadenas reales copy → separate read → terminal paste. |
| AT-I1b-8 | 1 | M | Skip automatizado obligatorio (`:456-463`). Los seis pasos manuales de `02-test-cases.md:154` siguen `not_run`: right-click/Notepad, Shift+drag del terminal, fila + Ctrl+V, Ctrl+C con selección y q, Ctrl+C sin selección + q duplicada, y salida con y. Sólo el operador en Windows Terminal puede cerrarlos; WinCI no sustituye P-1/P-2 de pass-through ni este AT. |

Las 28 celdas tienen ruta real implementada. En WinCI todas comprueban también el notice antes de preparar el target (`tests/test_b103_copy_paste_matrix.py:386-397`), T1 recibe exactamente la primera línea y T2 todo el texto una vez (`:405-413`). No se afirma que esa ruta haya ejecutado.

## 3. Los 11 partial que todavía no tienen ruta WinCI real

### 3.1 R-TUI-043.13/101 — 1 nodo, tail

El skip de `tests/test_b103_clipboard_tail.py:928-929` impide cualquier lectura WinCI. La rama que falta dentro del nodo existente debe:

1. Usar guarda/probe y seeds externos, writer real y captura DEBUG.
2. Ejecutar view-key, view-right-click y row-right-click con `SECRET-COPY-43`, exigir el payload exacto una vez en writer y separate read, y cero apariciones del payload/prefijo en logs; es el brazo WinCI explícito de `graph-inc1b.md:434`.
3. Ejecutar también en WinCI el brazo de fallo del ledger (`02-test-cases.md:124`) con holder real, seed intacto y captura de logs; no convertir el writer simulado en evidencia OS.

### 3.2 R-TUI-043.13/102 — 1 nodo, hostile/forced PowerShell

El ensayo actual es un buen unitario de transporte, pero parchea `clipboard_module.sys`, `_system_powershell`, `_system_directory` y `subprocess.run`, y copia el texto a `ledger.os_clipboard` (`tests/test_b103_clipboard_tail.py:954-991`). El propio nodo reconoce el skip y la ausencia WinCI (`:1008-1016`). No satisface E3-03 (`E3-rulings.md:14`) ni `graph-inc1b.md:414-415`.

La rama que falta debe conservar el unitario Linux como brazo separado y, en WinCI:

- Forzar la estrategia real mediante un wrapper pass-through al writer original con `strategies=(("powershell", _write_via_powershell),)`, sin falsificar `sys`, executable, directorio ni proceso.
- Registrar proceso con spy pass-through: Win32=0, PowerShell/proceso=1, writer=1, ejecutable absoluto del sistema, argv estático, `shell=False`, payload sólo en stdin y ausente de argv.
- Exigir `app.clipboard`, OSC 52 decodificado y `other_program_read()` = `HOSTILE_NAME` exacto; una OSC 52/notice de dos líneas, ninguna secuencia terminal adicional, ninguna negativa NUL y cero payload/prefijo/escape en logs.

La lectura PowerShell separada genérica de tail no sustituye esta rama: aquí también debe probarse **PowerShell real como writer**.

### 3.3 R-COPY.16/1…6 y R-COPY.20/1…3 — 9 nodos, quit

La fixture autouse sustituye `write_os_clipboard` y `read_os_clipboard` en todas las plataformas; `write` cambia `recorder.os_value` (`tests/test_b103_copy_quit_dialog.py:68-96`). `_assert_no_copy_effects` comprueba ese recorder (`:300-314`). El archivo no tiene guarda WinCI, seed externo ni `other_program_read`; su docstring todavía dice que ningún test abre clipboard real (`:1-7`). Por tanto, ejecutar este archivo en Windows no cerraría ninguno de los 9 partial.

| Nodo | Referencia | Lecturas/estado real que faltan |
|---|---|---|
| R-COPY.16/1 | `tests/test_b103_copy_quit_dialog.py:452-474` | En los cuatro armings (dos tamaños × selección ausente/materializada): seed externo, OS=seed con body B abierto y después de `n`; conservar SkipAction, geometría y cero workers/base/writer/OSC/notices. |
| R-COPY.16/2 | `:477-487` | OS=seed abierto/después de `n`, sin foco. |
| R-COPY.16/3 | `:490-504` | OS=seed abierto/después de `n`, fila destacada sin copiarla. |
| R-COPY.16/4 | `:507-522` | OS=seed abierto/después de `n`, input vacío. |
| R-COPY.16/5 | `:525-539` | OS=seed abierto/después de `n`, selección JSON vacía. |
| R-COPY.16/6 | `:542-559` | OS=seed abierto/después de `n`, textarea no vacía sin selección. |
| R-COPY.20/1 | `:643-667` | En ambos armings del help modal: seed externo y OS=seed antes/después de Ctrl+C y tras el Escape ya ejercitado; stack/modal inalterados y SkipAction en el arming materializado. |
| R-COPY.20/2 | `:670-690` | Load modal: OS=seed antes/después de Ctrl+C y tras Escape; sin body B ni cambios de stack. |
| R-COPY.20/3 | `:693-706` | OS=seed con el único body B existente antes/después del segundo Ctrl+C; cerrar después con `n`/Stay y repetir la lectura OS=seed, conservando una sola instancia y cero efectos. |

Implementación de prueba requerida, sin crear nuevos casos: hacer condicional la fixture; en WinCI ejecutar `require_isolated_clipboard` + probe, sembrar con `other_program_write`, dejar writer/reader de producto sin sustituir y observar con `other_program_read`. Mantener recorder para Linux y los contadores internos actuales. La lectura independiente no puede ser `read_os_clipboard` del producto. R-COPY.16 hereda las dos observaciones antes/después de Stay de `02-test-cases.md:90-95` y `graph-inc1b.md:278-281`; R-COPY.20 conserva sus propios puntos de cierre modal (`02-test-cases.md:101-103`).

## 4. Cobertura dudosa que WinCI por sí solo no cierra

Estas lagunas no añaden casos al censo 112/28/1, pero impiden tratar “ruta OS implementada” o “full-linux” como cierre exhaustivo del grafo.

### 4.1 Detail-card: el driver actual materializa cinco líneas, no dos — 2 nodos

`_make_view_selection("detail")` ejecuta el drag sin reescribir `screen.selections`, pero exige cinco líneas (`tests/test_b103_copy_views.py:404-418`). El grafo exige exactamente dos para R-COPY.1/4 y R-COPY.12/3 (`graph-inc1b.md:172,197`), y el propio comentario del test conserva ese brazo como partial (`tests/test_b103_copy_views.py:415`).

Plan: conseguir coordenadas reales que produzcan dos líneas no vacías y distinguibles, tomar el expected sólo de `get_selected_text()` después del drag y exigir copia/separate read de esas dos. Si Textual no lo permite, separar explícitamente tail y driver y mantener el driver partial; no editar la selección para fabricar el oracle. Ejecutar WinCI sobre la selección actual de cinco líneas no cierra este ejemplo.

### 4.2 R-COPY.25/1: el arming view-key sustituye la selección — 1 nodo

`_injected_hex_key_observation` reemplaza `app.screen.get_selected_text` por `lambda: text` (`tests/test_b103_clipboard_tail.py:505-519`), y ese helper alimenta el brazo `view-key` de `test_r_copy_25_1` (`:822-841`). El ledger pide una selección hex `A\x00B` copiada con Ctrl+C (`02-test-cases.md:113`). Los brazos view-right y row-right sí construyen fuentes reales.

Plan: materializar una selección de vista real con NUL para el brazo key o declarar ese sub-brazo como prueba de tail, no como cobertura del gesto; no promover R-COPY.25/1 a cobertura driver completa sólo porque la lectura OS WinCI exista.

### 4.3 Controles E3-01 no representados completamente en views

El fix actual prueba MouseMove forwarded y no forwarded en hex (`tests/test_b103_copy_views.py:308-332,625-643,780-797`), pero el grafo también exige:

- right-drag con `out_of_bounds=False` en filas A2L y MAC, sin copia (`graph-inc1b.md:220`); `_empty_gesture` `/7…8` sólo arma `#hex_view` (`tests/test_b103_copy_views.py:780-797`);
- release al mismo offset pero con widget o screen distinto (`graph-inc1b.md:221`); R-COPY.13/4 pulsa directamente en una vista no seleccionada y no crea el candidato válido previo, por lo que no es equivalente (`tests/test_b103_copy_views.py:765-768`);
- release forwarded sin candidato (`graph-inc1b.md:222`); R-COPY.12/7 prueba reemplazo y replay no forwarded, pero ningún MouseUp recibe `_set_forwarded()` (`tests/test_b103_copy_views.py:666-688`).

Plan: añadir estos controles como brazos de los nodos negativos ya existentes R-COPY.13/7…8 y R-COPY.14/7…8, y el release forwarded en R-COPY.12/7, sin alterar el conteo canónico. Conservar seeds y cero entry/tail/base/writer/OSC/notices. La cardinalidad “cada evento se reenvía exactamente una vez” de `graph-inc1b.md:212-224` tampoco tiene un contador directo en estos tests; las comprobaciones de efectos no deben describirse como prueba completa de ese invariante.

### 4.4 Quit: ejemplos de grafo no afirmados por los nodos FL-L

- `graph-inc1b.md:306` exige que una segunda respuesta sea ignorada por `_dismissed`; R-DLG.12/101…102 sólo envían una respuesta (`tests/test_b103_copy_quit_dialog.py:902-922`). Añadir el segundo `n`/`y` al nodo correspondiente y exigir ausencia de efectos adicionales.
- `graph-inc1b.md:319` fija el token visible `q Quit`, una sola entrada palette `Quit` con acción `quit` y ningún comando adicional. R-COPY.23 comprueba diálogo/instancia y R-COPY.24/2 elige Quit, pero ninguno inspecciona key-bar o cardinalidad/acción de entradas (`tests/test_b103_copy_quit_dialog.py:739-822`). Añadir esas aserciones a los nodos existentes antes de llamar completa la cobertura del grafo.

### 4.5 Dos conversiones/selecciones que conviene no dar por cerradas

- R-COPY.4/2 prueba Rich `Text` normal y largo (`tests/test_b103_copy_views.py:550-564`), pero no el brazo non-`Text` → `str(cell)` mencionado por `graph-inc1b.md:193` y E3A-04 (`E3-rulings.md:10`). Debe añadirse como arming del mismo caso si E5 toma todo el contrato de conversión como gate.
- Para help, views exige dos líneas **no vacías**, no necesariamente las dos primeras (`tests/test_b103_copy_views.py:429-434`), mientras el grafo dice “first two lines” (`graph-inc1b.md:173,199`). La geometría exacta debe verificarse antes de marcar R-COPY.1/6 y R-COPY.12/5 como ejemplos completos; no se afirma aquí que sea un defecto confirmado, sólo cobertura dudosa.

## 5. Orden E5 propuesto y criterio de cierre

1. **Cerrar primero las rutas ausentes y dudas de oracle**: 2 nodos tail de §3.1–3.2, 9 quit de §3.3 y los brazos de §4 que se acepten como gate del grafo. No aumentar el censo ni renumerar casos.
2. **Revalidar Linux después de cualquier cambio de tests** con la batería estándar del proyecto. Esta planificación no ejecuta ni anticipa su resultado.
3. **Ejecutar en el runner aislado WinCI las 108 obligaciones automatizadas**, conservando resultados por nodeid y por brazo multi-arming:
   - 46 views, incluidas las 24 FL-D;
   - 25 tail, con las dos nuevas ramas de logging/hostile;
   - 9 quit, con lecturas OS abiertas/después de Stay o del cierre modal correspondiente;
   - 28 AT, con P2 alimentado exclusivamente por el separate read.
4. **Registrar por separado los artefactos de riesgo**:
   - hostile: argv/stdin/proceso real, app/OSC/Windows idénticos y logs limpios;
   - R-PASTE.13: elapsed real contra `timing_bound(2.5)` y una sola cascada;
   - R-PASTE.14: writer thread distinto, ≥10 ticks y latencia máxima contra `timing_bound(0.1)`;
   - R-COPY.9/1 failure y R-COPY.25: seeds reales y cero sinks cuando corresponda.
5. **No convertir skips en evidencia**. Los skips legítimos son los brazos Linux-only fuera de Linux, P2 fuera de WinCI y AT-I1b-8 en automatización. Un skip de una rama obligatoria WinCI deja el caso `not_run`/`partial`, nunca `full`.
6. **Ejecutar AT-I1b-8 aparte, sólo por el operador**, registrando versión/settings de Windows Terminal y 6/6 pasos (`02-test-cases.md:154`). No usar el clipboard del operador desde automatización.
7. Sólo hablar de cobertura completa cuando los 112 casos tengan evidencia en todas las plataformas que su ledger exige, las 28 celdas tengan la cadena OS real, AT-I1b-8 tenga constancia manual y las dudas aceptadas como gate estén cerradas. Las rutas actualmente implementadas y los resultados Linux comunicados no sustituyen ninguna de esas evidencias.
