# E5 QUIT — corrección post NO-GO y validación Linux

## Resultado y alcance

- Base: `0d4d4e7c800b27040769a1a10117e62884cc7326` más los cambios E5 sin commit.
- Código modificado por este rol: únicamente `tests/test_b103_copy_quit_dialog.py`. Evidencia y oráculo auxiliar: únicamente `evidence-e5/quit/**`.
- Linux WSL: **28 collected, 28 passed, 0 failed, 0 skipped**, en **218.03 s**. Transcript final: `linux-28.txt`.
- Cobertura sin elevar: **19 full Linux + 9 partial**. Los nueve brazos WinCI están escritos y auditados estática/dinámicamente con procesos simulados, pero **WinCI queda `not_run`**. Los 28 passes Linux no son evidencia WinCI ni un GO global.
- No se cambiaron requisitos, producto, soporte, workflow, tail, matrix ni otros tests. No se repitió la batería combinada 122/19 porque la validación asignada era QUIT.

## Correcciones

- `_read_os_clipboard_exact` establece `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)` y transporta Base64 UTF-8. Sólo elimina whitespace del transporte; no recorta CR/LF del payload decodificado. El oráculo simulado conserva Unicode, CR, CRLF y LF final.
- `_seed_os_clipboard` decodifica la seed dentro de un PowerShell separado y ejecuta `Set-Clipboard -Value $text`; una segunda invocación realiza la lectura independiente. Ya no usa `other_program_write` dentro del proceso pytest.
- `_winci_powershell_path` usa el PowerShell absoluto de producto y falla si no existe; no delega en el resolver compartido que podía producir skip.
- Probe inutilizable, `Skipped` lanzado por el probe compartido, seed/read fuera de aislamiento, PowerShell ausente, `OSError`/`UnicodeError`/timeout, exit no cero y Base64/UTF-8 inválido producen fallo, nunca skip. La guarda de aislamiento precede a cualquier proceso.
- Los mensajes nuevos no incluyen stdout/stderr, contenido leído ni el detalle del probe. Las comparaciones de seed siguen siendo exactas.
- Linux conserva el recorder en memoria y no ejecuta los brazos WinCI; su estado de cobertura WinCI permanece `not_run`.

## Auditoría de exactamente nueve rutas

`route-audit-final.txt` contiene exactamente nueve líneas `ROUTE PASS`, una por ruta, y comprueba que no haya otra llamada `_run(..., winci_seed=True)`:

| Ruta | Nodo | Linux | WinCI |
|---|---|---|---|
| R-COPY.16/1 | `test_r_copy_16_1_button_and_materialized_empty_selection` | PASS | not_run |
| R-COPY.16/2 | `test_r_copy_16_2_no_widget_focused` | PASS | not_run |
| R-COPY.16/3 | `test_r_copy_16_3_highlighted_table_row_is_not_selection` | PASS | not_run |
| R-COPY.16/4 | `test_r_copy_16_4_empty_single_line_input` | PASS | not_run |
| R-COPY.16/5 | `test_r_copy_16_5_empty_json_selection` | PASS | not_run |
| R-COPY.16/6 | `test_r_copy_16_6_multiline_text_without_selection` | PASS | not_run |
| R-COPY.20/1 | `test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection` | PASS | not_run |
| R-COPY.20/2 | `test_r_copy_20_2_load_dialog_stays_top` | PASS | not_run |
| R-COPY.20/3 | `test_r_copy_20_3_existing_copy_quit_stays_single` | PASS | not_run |

El oráculo también conserva las tres observaciones de `.20/1–2`, el cierre con `n` de `.20/3`, dos procesos para seed/read, `shell=False`, `check=False` y ausencia de llamadas `pytest.skip` en el test QUIT.

## Validación ejecutada

1. **RED previo:** `route-audit-pre-fix-red.txt` registra `AssertionError: [146, 89, 144, 162]` al detectar los cuatro skips del código previo.
2. **Auditoría final:** `run_linux.py audit` terminó 0. Resultados: reader sin BOM y LF exacto, errores de infraestructura como fallo, seed externa simulada y exactamente nueve rutas. No ejecutó Windows, PowerShell real ni clipboard real.
3. **Batería final:** `run_linux.py pytest` terminó 0 con `collected 28 items` y `28 passed in 218.03s (0:03:38)`. Hay exactamente 28 líneas `PASSED` y ninguna línea `SKIPPED`, `FAILED` o `ERROR` en el transcript.
4. **QC-TM:** 6 bounds, 0 bajo 20 % de margen; márgenes medidos 87.3–92.0 %.
5. **Diff:** `git diff --check -- tests/test_b103_copy_quit_dialog.py` terminó 0.

## Entorno e identidad

- Scratch construido con `git archive HEAD` y únicamente los overlays del test QUIT, `validate_routes.py` y `run_linux.py`; los cambios concurrentes de otros roles no entraron en la ejecución.
- Linux x86_64 WSL2, Python 3.12.3, Textual 8.2.8, pytest 9.2.0, pluggy 1.7.0, platformdirs 4.14.5.
- Auditoría y tests usaron el mismo scratch `/tmp/b103-quit-e5-final-26tD1o`; la primera línea de ambos transcripts sitúa `s19_app.__file__` dentro de ese árbol.
- `DISPLAY` y `WAYLAND_DISPLAY` eliminados; `HOME`, `TMPDIR`, `XDG_*` y `LOCALAPPDATA` aislados; stdin desde `/dev/null`; `PYTHONDONTWRITEBYTECODE=1`; pytest con `-p no:cacheprovider`.
- SHA-256 del test local copiado como overlay: `8db6bfbf342298ac62f62b839b5fcf745a67a4d3f71c41ed2e85f3a62f4301b1`.
- No se ejecutó clipboard en el PC del operador, ni WinCI, ni commits/push. Los mensajes `Set-Clipboard`/`Get-Clipboard` de la auditoría estaban detrás de `subprocess.run` simulado.

## Artefactos

- `linux-28.txt`: 131 líneas, 12 436 bytes; SHA-256 `291359017c79898fbe5d41abfba97d30bc32b4215c1dc96d335c55f7f79d2cf3`.
- `route-audit-final.txt`: 16 líneas, 1 308 bytes; SHA-256 `76eecbc6dd3b6283427f1ef3e553d4642d27c9546bcda9419ada0df6aa606156`.
- `route-audit-pre-fix-red.txt`: 9 líneas, 399 bytes; SHA-256 `814486e0bead65cd9447d4b627f217c007f44efa1838eefd2afda57ce962a64e`.
- `validate_routes.py`: SHA-256 `4c996280dccbcac55ddbbe49ec338323515a91d7cbb6c86057709327344b07b2`.
- `run_linux.py`: SHA-256 `eaa56297929502f5c3ced79d0ba3f789686eb657acac9ea8ea6532caf15f8177`.
- `route-audit-setup-error.txt` se conserva como histórico y no sustenta este resultado. `SHA256SUMS.txt` cubre todos los artefactos del directorio excepto sí mismo.

## Bloqueos y riesgos

- **WinCI no ejecutado:** faltan CI real y resultados por nodeid/brazo. Las nueve rutas siguen `partial; WinCI not_run`; no se afirma WinCI GREEN ni cobertura completa.
- La corrección de soporte compartido, workflow, tail y matrix pertenece a otros roles y no se evalúa como resuelta aquí. En particular, QUIT convierte el skip del probe compartido en fallo, pero no cambia ese soporte.
- La preservación LF y la seed externa se verificaron con procesos simulados en Linux, no con PowerShell real. Un defecto específico de Windows PowerShell 5.1 sólo puede descartarse en la pasada WinCI aislada.
- No quedan bloqueos Linux conocidos en la familia QUIT validada.
