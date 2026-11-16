# E4 QUIT/DIALOG — verificación Linux de integración 29ce6448

## Resultado actual

- Integración verificada: `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c` (`Merge branch 'b103-inc1b-tests' into batch-103`).
- Archivo corregido: únicamente `tests/test_b103_copy_quit_dialog.py`; no se cambió producto.
- Ejecución final: **28 collected, 28 passed, 0 failed, 0 skipped**, en **264.12 s**.
- Cobertura: **19 full Linux, 9 partial por WinCI pendiente** (R-COPY.16/1…/6 y R-COPY.20/1…/3).
- Se conserva `partial` deliberadamente: no se añadieron ramas WinCI ni lecturas OS separadas en esta corrección. **No se afirma cierre WinCI** ni cobertura del clipboard real. Los 28 passes prueban la familia en Linux, no WinCI.
- El RED histórico del base permanece en `red-linux.txt` y `report.md`; no se sobrescribió.

## Correcciones del oráculo

- Plain text: `_plain_and_spans` lee `label`, `renderable` o `render()` y usa un Rich `Text` o los valores `plain` y `spans` reales del renderable/Content. Se eliminó por completo el acceso inexistente `Label.markup`; las aserciones comprueban texto exacto y cero spans reales.
- Geometría: la visibilidad usa el helper existente `tests.b97_probes.is_displayed`, no el atributo inexistente `Button.is_displayed`; se conservan las comprobaciones de región, contención y operabilidad.
- Timing: las respuestas usan `timing_bound(1.0)` —1 s local, 2 s con `CI` truthy— y registran `report_margin` con el nodeid antes de las aserciones. `_wait_exit` también obtiene su default de `timing_bound(1.0)`; no quedan comparaciones absolutas de 1 s.
- WinCI: se mantiene el recorder aislado y la clasificación `partial`; no se presentó una lectura simulada como lectura OS separada.

## Aislamiento y transcript

- Scratch final: `<HOME>/work/b103-e4-quit-29ce-final-F6v3jK/tree`.
- Linux x86_64, Python 3.11.18, Textual 8.2.8, pytest 8.4.2.
- `/tmp/b103-inc6-merge-final` no contenía los 9 commits posteriores a `c062293b`; se transfirió la ref `b103-inc1b-integration` en un bundle verificado y se hizo fetch/checkout solo en scratch. HEAD remoto comprobado = `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`.
- `git status --short` en el scratch final muestra únicamente ` M tests/test_b103_copy_quit_dialog.py`; el hash local/remoto coincide.
- Overlay: solamente `tests/test_b103_copy_quit_dialog.py`.
- Entorno neutral bajo `<HOME>/work/b103-e4-quit-29ce-final-F6v3jK/`: `TMPDIR=tmp`, `HOME=home`, `XDG_CONFIG_HOME=xdg-config`, `XDG_DATA_HOME=xdg-data`, `XDG_CACHE_HOME=xdg-cache`, `LOCALAPPDATA=localappdata`; `DISPLAY` y `WAYLAND_DISPLAY` eliminados.
- `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, stdin desde `/dev/null`, pytest `-p no:cacheprovider`.
- Primera línea del transcript: `s19_app.__file__ = <HOME>/work/b103-e4-quit-29ce-final-F6v3jK/tree/s19_app/__init__.py`.
- Comando: `<HOME>/miniconda3/envs/s19ci/bin/python -I -B -c` con `sys.path.insert(0, ".")` y `pytest.main(["-p", "no:cacheprovider", "-vv", "--tb=short", "--durations=0", "tests/test_b103_copy_quit_dialog.py"])`.
- Clipboard: recorder en memoria; 0 accesos al clipboard real del operador.
- Transcript final: `integration-linux.txt`, 131 líneas, 12,535 bytes.
- SHA-256 del test: `348aefb36d840f013f815f31fca74d4843b0891993637d138d4ed46c97489c6a`.
- SHA-256 del transcript final: `bb50accc25c0ae7516adc42cf3dd3cefdebcb93203dfb781139be62b581d67f7`.
- Intento anterior del oráculo, conservado como `integration-linux-oracle-error.txt`: 27 passed, 1 failed por `Button.is_displayed`; 160 líneas, 14,133 bytes; SHA-256 `cc90faececfc9124a37bdd3522b3291d54a955730fbc71f98882ef7f9854fd38`. No es el resultado final.

## Márgenes QC-TM de la ejecución final

| Caso | Medido | Bound | Margen |
|---|---:|---:|---:|
| R-COPY.17/1 | 0.151 s | 1.000 s | 84.9 % |
| R-COPY.17/2 | 0.148 s | 1.000 s | 85.2 % |
| R-COPY.17/3 | 0.156 s | 1.000 s | 84.4 % |
| R-COPY.24/1 | 0.108 s | 1.000 s | 89.2 % |
| R-COPY.24/2 | 0.127 s | 1.000 s | 87.3 % |
| R-DLG.12/102 | 0.153 s | 1.000 s | 84.7 % |

`QC-TM: 6 bounds, 0 under 20 % margin`.

## Resultado por caso

El prefijo común es `tests/test_b103_copy_quit_dialog.py::`. `full` significa cobertura completa del oráculo Linux; `partial` deja WinCI/separate OS read en **not_run**, sin skips convertidos en evidencia.

| Caso | Nodo pytest | Cobertura | Resultado Linux 29ce6448 |
|---|---|---|---|
| R-COPY.16/1 | `test_r_copy_16_1_button_and_materialized_empty_selection` | partial | PASS; cuatro armings, body/plain text/SkipAction/geometría; WinCI not_run |
| R-COPY.16/2 | `test_r_copy_16_2_no_widget_focused` | partial | PASS; WinCI not_run |
| R-COPY.16/3 | `test_r_copy_16_3_highlighted_table_row_is_not_selection` | partial | PASS; WinCI not_run |
| R-COPY.16/4 | `test_r_copy_16_4_empty_single_line_input` | partial | PASS; WinCI not_run |
| R-COPY.16/5 | `test_r_copy_16_5_empty_json_selection` | partial | PASS; WinCI not_run |
| R-COPY.16/6 | `test_r_copy_16_6_multiline_text_without_selection` | partial | PASS; WinCI not_run |
| R-COPY.17/1 | `test_r_copy_17_1_y_quits_within_one_second` | full | PASS; timing_bound + report_margin |
| R-COPY.17/2 | `test_r_copy_17_2_tab_enter_on_quit` | full | PASS; timing_bound + report_margin |
| R-COPY.17/3 | `test_r_copy_17_3_click_quit` | full | PASS; timing_bound + report_margin |
| R-COPY.18/1 | `test_r_copy_18_1_stay_has_confirm_emphasis` | full | PASS |
| R-COPY.19/1 | `test_r_copy_19_1_busy_ctrl_c_opens_busy_question` | full | PASS |
| R-COPY.20/1 | `test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection` | partial | PASS; ambos armings y SkipAction modal; WinCI not_run |
| R-COPY.20/2 | `test_r_copy_20_2_load_dialog_stays_top` | partial | PASS; WinCI not_run |
| R-COPY.20/3 | `test_r_copy_20_3_existing_copy_quit_stays_single` | partial | PASS; WinCI not_run |
| R-COPY.20/4 | `test_r_copy_20_4_busy_question_stays_top` | full | PASS |
| R-COPY.23/1 | `test_r_copy_23_1_idle_q_asks_without_selection` | full | PASS |
| R-COPY.23/2 | `test_r_copy_23_2_q_with_selection_and_second_q_stays_single` | full | PASS; segunda q sin duplicar |
| R-COPY.24/1 | `test_r_copy_24_1_ctrl_q_quits_immediately` | full | PASS; timing_bound + report_margin |
| R-COPY.24/2 | `test_r_copy_24_2_palette_quit_quits_immediately` | full | PASS; timing_bound + report_margin |
| R-DLG.1/101 | `test_r_dlg_1_101_window_keys_do_not_act_behind_dialog` | full | PASS |
| R-DLG.2/101 | `test_r_dlg_2_101_escape_answers_stay` | full | PASS |
| R-DLG.6/101 | `test_r_dlg_6_101_initial_focus_is_stay` | full | PASS |
| R-DLG.9/101 | `test_r_dlg_9_101_click_stay_preserves_window_scroll_and_state` | full | PASS |
| R-DLG.11/101 | `test_r_dlg_11_101_buttons_expose_exact_keys` | full | PASS; etiquetas exactas y spans reales |
| R-DLG.12/101 | `test_r_dlg_12_101_n_presses_stay` | full | PASS |
| R-DLG.12/102 | `test_r_dlg_12_102_y_presses_quit` | full | PASS; timing_bound + report_margin |
| R-DLG.14/101 | `test_r_dlg_14_101_copy_quit_has_reachable_shared_opener` | full | PASS; censo 22, N9 y opener alcanzable |
| R-QUIT.8/101 | `test_r_quit_8_101_confirmed_busy_quit_waits_for_load` | full | PASS; quit diferido hasta completar la carga |

No quedan bloqueos Linux en esta familia. Queda pendiente, sin afirmar cierre, la ejecución WinCI con semillas y lecturas OS separadas —incluida la lectura después de `n`— para los 9 casos `partial`.
