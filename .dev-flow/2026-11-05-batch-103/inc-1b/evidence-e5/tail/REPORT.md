# E5 TAIL readiness

## Alcance y entrega

- Fuente base: `0d4d4e7c800b27040769a1a10117e62884cc7326`.
- Test entregado: `tests/test_b103_clipboard_tail.py`, blob `5ab8c60887b0ebd222fddd8dad8caaf928b1dd9e`.
- Censo conservado: 30 nodos pytest; no se añadieron casos ni se cambiaron umbrales.
- Esta propiedad no editó producto, ledger, workflow ni helpers compartidos. La lectura externa exacta es local al test TAIL.

## Correcciones implementadas

- Holder Win32: prototipos de `CreateWindowExW`/`GetModuleHandleW`, `kernel32.Sleep`, anuncio y comprobación de vida, `readline` acotado mediante hilo/cola, kill/wait acotado y join del supervisor antes de leer.
- R-PASTE.13/.14: esperan writer y tail finalizados; R-PASTE.13 mide después de esa finalización; ambos liberan y reapsan el holder antes de `_observe`/separate read.
- `other_program_read` de TAIL: sistema PowerShell absoluto, `Get-Clipboard -Raw`, salida Base64 estricta, UTF-8 estricto, `stdin=DEVNULL`, comprobación de exit/stderr y sin `rstrip` ni reemplazo destructivo. Conserva CR/LF finales, incluido el brazo R-COPY.7/5.
- R-TUI-043.13/101: rama WinCI con cuatro copias reales (key, right-click, fila y fila con clipboard retenido), separate read y captura `s19_app` a DEBUG.
- R-TUI-043.13/102: rama WinCI que fuerza sólo `powershell` en el writer real, sin parchear plataforma, resolvedor ni proceso en Windows. Exige argv estático, `shell=False`, stdin exactamente `HOSTILE_NAME`, un proceso y app/OSC52/Windows exactos.
- Los brazos Linux existentes, incluido PowerShell simulado en Linux, se conservaron.

## Validación Linux ejecutada

Runner `s19ci`, Python 3.11.18. Se creó un árbol limpio mediante `git archive HEAD` y se copiaron únicamente el test TAIL modificado y `run_linux_tail.py`. HOME, TMPDIR, XDG y LOCALAPPDATA neutros; `DISPLAY`/`WAYLAND_DISPLAY` eliminados; stdin cerrado; `-I -B`; bytecode y pytest cache desactivados. El scratch remoto se eliminó al terminar.

Comando de pytest dentro de `run_linux_tail.py`:

```text
-q -rs -p no:cacheprovider tests/test_b103_clipboard_tail.py
```

Resultado en `linux-tail.txt` (blob del runner `af2cefa337dc40618c3f8ec8e9ef5a05c7d8c82f`):

```text
26 passed, 4 skipped in 379.32s (0:06:19)
```

Exit status 0. Este resultado reemplaza únicamente la validación Linux TAIL de esta entrega; no reejecuta ni altera el 122/19 E4 ni el ledger.

## Skips Linux documentados

Los cuatro skips comparten la razón WinCI-only registrada en `linux-tail.txt`:

1. `tests/test_b103_clipboard_tail.py::test_r_paste_13_101_held_row_copy_warns_within_bound` — R-PASTE.13/101, `not_run`.
2. `tests/test_b103_clipboard_tail.py::test_r_paste_14_101_view_key_write_stays_responsive` — R-PASTE.14/101, `not_run`.
3. `tests/test_b103_clipboard_tail.py::test_r_paste_14_102_view_right_write_stays_responsive` — R-PASTE.14/102, `not_run`.
4. `tests/test_b103_clipboard_tail.py::test_r_paste_14_103_row_right_write_stays_responsive` — R-PASTE.14/103, `not_run`.

No se midieron sus thresholds WinCI. No hay skips nuevos para R-TUI-043.13/101 o /102: sus brazos Linux pasaron dentro de los 26.

## WinCI `not_run` y bloqueo residual

No se ejecutó Windows ni WinCI, conforme a la instrucción de ejecutar sólo validación Linux. Por tanto permanecen sin evidencia de ejecución real:

- El holder Win32 corregido y los cuatro nodos R-PASTE.13/.14 anteriores.
- La rama WinCI de R-TUI-043.13/101: cuatro copias reales + separate read + DEBUG.
- La rama WinCI de R-TUI-043.13/102: PowerShell real forzado y payload hostile exacto en app/OSC52/Windows.
- La lectura Windows Base64 y el brazo WinCI con LF final de R-COPY.7/5, además de las demás repeticiones WinCI ya pendientes.

Esas rutas están escritas, pero no se afirma que hayan pasado. Falta una ejecución WinCI aislada posterior; no se disparó el workflow ni se afirmó cobertura nueva. No quedan bloqueos en la regresión Linux ejecutada.

## Intento de transporte conservado

`linux-transport-run1.txt` conserva un fallo inicial de quoting del `python -c` remoto. Ocurrió antes de colección/pytest y no produjo conteo ni evidencia RED/GREEN. Se corrigió usando el runner archivado en esta carpeta; `linux-tail.txt` es la ejecución válida posterior.
