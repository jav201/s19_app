# E4 QUIT/DIALOG — RED Linux

## Resultado y alcance

- Familia: 19 casos R-COPY (.16, .17, .18, .19, .20, .23, .24) + 9 casos citados R-DLG/R-QUIT.
- Archivo: `tests/test_b103_copy_quit_dialog.py`; 28 funciones pytest, una por caso del ledger.
- RED final: **28 collected, 25 failed, 3 passed, 0 skipped**, en 268.83 s.
- Los 25 fallos son esperados por comportamiento Inc1b ausente en el base. Los 3 passes son comportamiento ya existente y **no son GREEN de Inc1b**: R-COPY.20/2, R-COPY.24/1 y R-COPY.24/2.
- `full`: el nodo implementa todas las acciones y aserciones del caso para Linux; no implica que un RED temprano alcance las siguientes aserciones ni que el requisito esté implementado.
- `partial`: el caso también tiene una mitad WinCI/semilla del clipboard OS. Linux se ejecutó con un recorder aislado; la lectura OS separada/WinCI queda **not_run**. No se infiere cobertura WinCI de skips ni de passes Linux.
- Cobertura: **19 full Linux, 9 partial por WinCI pendiente** (R-COPY.16/1…/6 y R-COPY.20/1…/3). No hay casos WinCI-only convertidos en skips.
- No se usó el worktree ni el producto de DeepSeek. No se ejecutó GREEN, mutantes ni WinCI.

## Base, aislamiento y transcript

- Base HEAD verificado: `e2e935482646553a34242e524af5ac5bc57af82b`.
- `git diff --exit-code c062293b e2e93548 -- s19_app tests`: 0; producto/tests del base coinciden.
- Scratch final: `<HOME>/work/b103-e4-quit-final-CBcgBm/tree`.
- Linux x86_64, Python 3.11.18, Textual 8.2.8, pytest 8.4.2.
- `/tmp/b103-inc6-merge-final` clonaba HEAD `c062293b` y no contenía el objeto `e2e93548`. Se transfirió un bundle incremental del base local y se hizo fetch/checkout **solo dentro del scratch**. Después se repitió la verificación anterior; `git status --short` en el scratch mostró únicamente `?? tests/test_b103_copy_quit_dialog.py`.
- Overlay: solamente `tests/test_b103_copy_quit_dialog.py`.
- Entorno neutral bajo `<HOME>/work/b103-e4-quit-final-CBcgBm/`: `TMPDIR=tmp`, `HOME=home`, `XDG_CONFIG_HOME=xdg-config`, `XDG_DATA_HOME=xdg-data`, `XDG_CACHE_HOME=xdg-cache`, `LOCALAPPDATA=localappdata`; `DISPLAY` y `WAYLAND_DISPLAY` eliminados.
- `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, stdin desde `/dev/null`, pytest `-p no:cacheprovider`.
- El runner insertó `.` en `sys.path` antes de importar y la primera línea del transcript es `s19_app.__file__ = <HOME>/work/b103-e4-quit-final-CBcgBm/tree/s19_app/__init__.py`.
- Comando de pytest ejecutado por `<HOME>/miniconda3/envs/s19ci/bin/python -I -B -c`: `pytest.main(["-p", "no:cacheprovider", "-vv", "--tb=short", "--durations=0", "tests/test_b103_copy_quit_dialog.py"])`.
- Clipboard: semilla y recorder en memoria, writers/readers del producto reemplazados en el fixture; 0 accesos al clipboard real del operador. Las selecciones, workers, base copy, OSC 52 y notices se observaron mediante el driver/estado de la app.
- Transcript completo: `red-linux.txt`, 988 líneas, 70,208 bytes.
- SHA-256 del test: `6669bbeec0f4848bceb9f85688922f579d449b5baf27634565d249e5d3a2d1da`.
- SHA-256 del transcript: `14f3cfc98917c769098c7f86bb2c26ec48f161e0f03b0c32cd5f55b0d00ae6cb`.
- El hash remoto del test coincide con el local. No quedan bloqueos de fixture ni de ejecución Linux.

## Reporte por caso

El prefijo común de los nodos es `tests/test_b103_copy_quit_dialog.py::`.

| Caso | Nodo pytest | Cobertura | Resultado | Mutation target y observación RED/base |
|---|---|---|---|---|
| R-COPY.16/1 | `test_r_copy_16_1_button_and_materialized_empty_selection` | partial | FAIL (RED esperado) | Sustituir `SkipAction` por `return`; body/markup/geometría. Los cuatro armings (118×54 y 220×60, normal/materializado) ejecutados: normales sin `_CopyQuitScreen` y con hint; materializados `entries=['']`, `skips=[]`. WinCI not_run. |
| R-COPY.16/2 | `test_r_copy_16_2_no_widget_focused` | partial | FAIL (RED esperado) | Exigir foco para el fallback. Sin foco, 0 diálogos y hint `Do you want to quit?`; WinCI not_run. |
| R-COPY.16/3 | `test_r_copy_16_3_highlighted_table_row_is_not_selection` | partial | FAIL (RED esperado) | Tratar la fila resaltada como selección/copiar `""`. Cursor en tercera fila armado; 0 diálogos y hint; WinCI not_run. |
| R-COPY.16/4 | `test_r_copy_16_4_empty_single_line_input` | partial | FAIL (RED esperado) | Tragar el `SkipAction` del input o copiar `""`. `#a2l_tags_filter_input` vacío y enfocado; 0 diálogos y hint; WinCI not_run. |
| R-COPY.16/5 | `test_r_copy_16_5_empty_json_selection` | partial | FAIL (RED esperado) | Consumir la selección JSON vacía sin fallback. Vista JSON enfocada, selección `""`; 0 diálogos y hint; WinCI not_run. |
| R-COPY.16/6 | `test_r_copy_16_6_multiline_text_without_selection` | partial | FAIL (RED esperado) | Confundir documento no vacío con selección. `#patch_paste_text='L1'`, selección `""`; 0 diálogos y hint; WinCI not_run. |
| R-COPY.17/1 | `test_r_copy_17_1_y_quits_within_one_second` | full | FAIL (RED esperado) | `dismiss(True)` sin exit, código distinto de 0 o >1 s. Falta el diálogo previo; base muestra hint. |
| R-COPY.17/2 | `test_r_copy_17_2_tab_enter_on_quit` | full | FAIL (RED esperado) | Tab no mueve Stay→Quit o Enter responde Stay. Falta el diálogo previo; base muestra hint. |
| R-COPY.17/3 | `test_r_copy_17_3_click_quit` | full | FAIL (RED esperado) | Botón Quit pintado sin respuesta True. Falta el diálogo previo; base muestra hint. |
| R-COPY.18/1 | `test_r_copy_18_1_stay_has_confirm_emphasis` | full | FAIL (RED esperado) | `modal-confirm` en Quit en vez de Stay. No existe N9 donde medir clases; base muestra hint. |
| R-COPY.19/1 | `test_r_copy_19_1_busy_ctrl_c_opens_busy_question` | full | FAIL (RED esperado) | Abrir body B o permitir exit durante carga retenida. Worker `Loading held.s19` retenido correctamente; Ctrl+C produce hint, 0 busy questions; carga liberada en `finally`. |
| R-COPY.20/1 | `test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection` | partial | FAIL (RED esperado) | Retorno normal para `""` modal, cambio de stack/semillas. Arming ordinario conserva Help; materializado llega a `entries=['']`, `skips=[]`; WinCI not_run. |
| R-COPY.20/2 | `test_r_copy_20_2_load_dialog_stays_top` | partial | PASS base (no GREEN) | Apilar body B sobre Load. El binding modal ya existente conserva el mismo `LoadDialog`, stack y semillas, sin efectos; mitad WinCI not_run. |
| R-COPY.20/3 | `test_r_copy_20_3_existing_copy_quit_stays_single` | partial | FAIL (RED esperado) | Apilar una segunda N9. No puede abrirse la primera en el base; hint y 0 N9; WinCI not_run. |
| R-COPY.20/4 | `test_r_copy_20_4_busy_question_stays_top` | full | FAIL (RED esperado) | Apilar body B sobre la busy question. La primera Ctrl+C no abre busy question, solo hint; carga liberada. |
| R-COPY.23/1 | `test_r_copy_23_1_idle_q_asks_without_selection` | full | FAIL (RED esperado) | Conservar `q -> quit` y salir sin confirmación. `q` termina la app (`running=False`), 0 diálogos. |
| R-COPY.23/2 | `test_r_copy_23_2_q_with_selection_and_second_q_stays_single` | full | FAIL (RED esperado) | Copiar con q, suprimir el diálogo, duplicar/salir con segunda q. Tres filas seleccionadas; primera q sale, por lo que la segunda no puede ejercitarse en base; nodo sí contiene su guardia. |
| R-COPY.24/1 | `test_r_copy_24_1_ctrl_q_quits_immediately` | full | PASS base (no GREEN) | Confirmar Ctrl+Q, código no 0 o salida >1 s. Base idle existente: return code 0 ≤1 s, 0 pushes N9/busy. |
| R-COPY.24/2 | `test_r_copy_24_2_palette_quit_quits_immediately` | full | PASS base (no GREEN) | Proyectar palette Quit a `help_quit`, duplicarla o confirmar. Ruta real Ctrl+K, `Quit`, Enter: return code 0 ≤1 s, 0 pushes N9/busy. |
| R-DLG.1/101 | `test_r_dlg_1_101_window_keys_do_not_act_behind_dialog` | full | FAIL (RED esperado) | Dejar actuar 1/2/`/`/q detrás de N9. Falta N9; base muestra hint. |
| R-DLG.2/101 | `test_r_dlg_2_101_escape_answers_stay` | full | FAIL (RED esperado) | Escape sale, no restaura foco o altera semillas. Falta N9; base muestra hint. |
| R-DLG.6/101 | `test_r_dlg_6_101_initial_focus_is_stay` | full | FAIL (RED esperado) | `AUTO_FOCUS=#confirm_yes`. Falta N9; base muestra hint. |
| R-DLG.9/101 | `test_r_dlg_9_101_click_stay_preserves_window_scroll_and_state` | full | FAIL (RED esperado) | Stay cambia ventana, scroll o `_quit_pending`. Falta N9; base muestra hint. |
| R-DLG.11/101 | `test_r_dlg_11_101_buttons_expose_exact_keys` | full | FAIL (RED esperado) | Etiquetas sin y/n, renombradas o con markup. Falta N9; base muestra hint. |
| R-DLG.12/101 | `test_r_dlg_12_101_n_presses_stay` | full | FAIL (RED esperado) | n sale o deja quit pendiente. Falta N9; base muestra hint. |
| R-DLG.12/102 | `test_r_dlg_12_102_y_presses_quit` | full | FAIL (RED esperado) | y responde Stay. Falta N9; base muestra hint. |
| R-DLG.14/101 | `test_r_dlg_14_101_copy_quit_has_reachable_shared_opener` | full | FAIL (RED esperado) | N9 huérfana, censo distinto de 22 u opener inalcanzable. Censo AST b101: 21 != 22, sin `_CopyQuitScreen`; 0 huérfanos en los 21 existentes. |
| R-QUIT.8/101 | `test_r_quit_8_101_confirmed_busy_quit_waits_for_load` | full | FAIL (RED esperado) | Exit inmediato con y durante carga o ausencia de exit al completar. La carga retenida funciona; Ctrl+C no abre busy question, por lo que el brazo diferido no se alcanza en base; liberación en `finally`. |

## Discriminación incorporada

- Body B literal `Quit the app? Nothing is selected to copy.`, título/botones literales, `markup=False`, cero spans y geometría a 118×54/220×60.
- Selección materializada con `screen.selections` y extracción `""`; se registra la llamada `copy_to_clipboard('')` y se exige `textual.actions.SkipAction`, tanto idle como modal.
- Semillas de app/OS recorder antes y después de `n`; cero workers/base writes/OS writes/OSC 52/notices en los caminos vacíos.
- Respuestas y/Tab+Enter/click, foco inicial/restaurado, énfasis `modal-confirm` en Stay, teclas de fondo bloqueadas y segunda q sin duplicar.
- Ctrl+Q y palette Quit reales con tiempo medido desde la entrada; busy file load retenido en worker y quit diferido hasta su finalización.
- Censo AST existente de b101 Inc 12, exigiendo 22 diálogos, N9 presente, cero huérfanos y `S19TuiApp.action_help_quit` alcanzable por `string` y `toolkit`.

No se afirma GREEN ni cobertura WinCI. Integración debe ejecutar la fase GREEN y las mitades WinCI/separate OS read marcadas `partial`.
