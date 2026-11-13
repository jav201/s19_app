# E4 CLIPBOARD/TAIL — corrección sobre integración 29ce6448

## Resultado

- HEAD ejecutado: `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`, comprobado antes de pytest. El bundle `integration-29ce.bundle` permitió fetch/checkout real en el scratch Linux; no se usó el worktree de DeepSeek.
- Scratch: `<HOME>/work/e4-tail-29ce-green-1794501691-1965/tree`; único overlay modificado: `tests/test_b103_clipboard_tail.py`.
- Targeted Linux del archivo completo: **30 collected; 26 passed; 4 skipped; 0 failed/errors; 329.07 s; TARGETED_30_EXIT_STATUS=0**.
- Los cuatro skips son R-PASTE.13/101 y R-PASTE.14/101…103: **WinCI-only, not_run**. No se ejecutó WinCI y no se afirma cobertura Windows.
- Transcript: `integration-29ce-linux.txt`, SHA-256 `7598f1b0a14ea0ae06940122a23259c3306e4990e58472b91753ca1b8b953da9`.
- Test local/remoto: SHA-256 `30524402b42ccf2dd1deb0a57a2a6898447af2bbbea749ea4ca7eaa46b3a783d`.
- Aislamiento: `s19_app.__file__` en la primera línea, Python 3.11.18 con `-I -B`, stdin cerrado, cache/bytecode desactivados, DISPLAY/WAYLAND_DISPLAY/PYTHONPATH sin definir y TMPDIR/HOME/XDG/LOCALAPPDATA neutrales. No se tocó el clipboard del operador.

## Correcciones

### HOSTILE / R-TUI-043.13/102 — GREEN Linux simulado

`_hostile_powershell_observation` instala antes del gesto, sólo en `clipboard_module`:

- `sys = SimpleNamespace(platform="win32")`, sin cambiar `sys.platform` del proceso;
- `_system_powershell() -> /usr/bin/pwsh` y `_system_directory() -> /usr/bin`;
- `subprocess.run = fake_run`, que devuelve `returncode=0`, stdout/stderr vacíos y registra argv/stdin reales.

El `write_os_clipboard` original conserva la estrategia real `_write_via_powershell`; por tanto atraviesa su guarda y construye el comando en llamada. El test comprueba:

- una invocación exacta, `process == 1`;
- `argv == ["/usr/bin/pwsh", "-NonInteractive", *_POWERSHELL_WRITE_COMMAND]`;
- `cwd == "/usr/bin"`, `shell is False`, `input == HOSTILE_NAME`;
- HOSTILE_NAME y su prefijo ausentes de argv y logs, un OSC52, una escritura y un notice de dos líneas.

La observación está marcada `linux-simulated-powershell`. En Windows el caso hace skip con razón `partial`: no se presenta como WinCI ni como lectura OS real. El AST de `os_clipboard_input.py` rechaza `import s19_app.tui.app`, `from s19_app.tui.app` y `from .app`; pasó en integración.

### R-COPY.9/1 y ramas WinCI

Se eliminó el `pytest.skip` interior del brazo `failed-over-cap-write`, que abortaba `_run_arms` y podía ocultar fallos de los otros brazos en Windows. Ese brazo usa ahora `held=True`: writer fallido existente en Linux y holder externo real en WinCI. Los cuatro brazos pasaron en Linux.

Las rutas normales tienen ahora una rama WinCI real, no simulada:

- `_winci_ready_or_skip` antes de abrir clipboard, `other_program_write(SEED_OS)` para seed y writer real (`writer_result=True` se convierte en `None` sólo en Windows);
- procesos reales permitidos y registrados sólo en WinCI; Linux conserva recorders/fail-closed;
- `_read_os` usa `other_program_read()` por proceso separado, restaurando temporalmente el `subprocess.run` original para no contar la lectura del harness como proceso del producto;
- R-COPY.6 lee OS mientras el fallback está abierto y otra vez después de `n`; los otros casos leen después del gesto;
- los fallos comprueban también que el seed OS permanece intacto.

Estas ramas están implementadas, pero **no verificadas aquí** porque WinCI no se ejecutó. Los casos Linux-only y HOSTILE conservan partial explícito.

### E3A-24(c) / R-COPY.7/7

Nuevo brazo con selección real de tres líneas en `#alt_hex_view` y `abc` seleccionado/enfocado en `#a2l_tags_filter_input`. Preparar la caja borra el mapa de selección ajena, por eso el fixture guarda `screen.selections` y lo rearma después del focus, antes del gesto, verificando ambas selecciones.

MouseDown/MouseUp se envían por `App.post_message`. El oráculo exige exactamente `abc` en app/base/writer/OSC52, override 0, tail/base/writer/OSC52/helper 1, un solo notice y caja intacta; el texto hex no aparece en los sinks. El brazo y el archivo completo pasaron. `integration-29ce-e3a.txt` conserva el targeted individual final (`1 passed`, 21.45 s).

### NUL / R-COPY.25

- `_refusal` exige ahora la lista completa `notices == [(NUL_REFUSAL, "warning", 6.0)]`, no sólo filtrar `Copied` o el mensaje esperado.
- `_assert_nul_log` exige la lista completa `WARNING == [NUL_WARNING]`, seguida de ausencia de payload/prefix/escape.
- R-COPY.25/1…3 pasaron con esas aserciones; el brazo 65,537 conserva el prefijo cap y el N original.

## Evidencia y alcance

- `integration-29ce-linux.txt`: targeted 30 final, 26 passed/4 skipped.
- `integration-29ce-e3a.txt`: targeted E3A-24(c) final.
- `integration-29ce-setup.txt`: clone, fetch del bundle y checkout de 29ce6448.
- `integration-29ce.bundle`: objeto Git de integración usado; SHA-256 `8b8f743137e2a09b0d50080908aa4d4596affaf5d1702cf7a58f12b805135c82`.
- `integration-29ce-SHA256SUMS`: hashes de test y evidencia.

No se modificó producto, otros tests, otros archivos de evidencia ni refs compartidas; no hubo commits/push. Los artefactos RED anteriores se conservan como historia y no se reutilizan como prueba de este GREEN Linux.
