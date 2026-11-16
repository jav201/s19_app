# E4 CLIPBOARD/TAIL — RED Linux

## Alcance y resultado

- Archivo propio: `tests/test_b103_clipboard_tail.py`; 30 nodeids, uno por cada caso asignado. No se editó producto, ledger, views/quit/matrix ni otros tests; no hubo commits/push.
- Scratch final: `<HOME>/work/e4-tail-final-1794495765-535`; árbol `/tree`; único overlay `tests/test_b103_clipboard_tail.py`.
- Base requerido: `e2e935482646553a34242e524af5ac5bc57af82b`. Base ejecutado: `c062293be6c122ecceca5701ea8afd0c6700f008`. `git diff --exit-code e2e93548 c062293b -- s19_app tests` devolvió 0; detalles en `base-equivalence.txt`. No se usó el worktree de DeepSeek.
- Linux `set-<HOST>`, Python 3.11.18, pytest 8.4.2, Textual 8.2.8; `-I -B`, stdin `/dev/null`, bytecode y pytest cache desactivados, `DISPLAY`/`WAYLAND_DISPLAY`/`PYTHONPATH` sin definir, y TMPDIR/HOME/XDG_CONFIG_HOME/XDG_DATA_HOME/XDG_CACHE_HOME/LOCALAPPDATA neutrales.
- `s19_app.__file__` aparece en la primera línea del transcript. La importación inserta `.` en `sys.path` antes de importar.
- Resultado: **30 collected; 21 failed; 5 passed; 4 skipped; 0 errors; 320.29 s; RED_EXIT_STATUS=1**. No es una ejecución GREEN ni una verificación de integración.
- Transcript completo: `red-final.txt` (1,420,169 bytes), SHA-256 `ab686026d62899a7b4e54525cbcf3967737c0eb505341add8d5dc33c504789da`.
- Test SHA-256 local y remoto: `af36aea7f9b43c71f27e53b01688d0f257213bb6fd2a5fc64dc91d258c1b1c59`. Hashes del producto base en `SHA256SUMS`.
- Los cuatro skips son exclusivamente WinCI y quedan **not_run**. Ninguna cobertura Windows se infiere de skips, recorders o procesos simulados. Ningún test tocó el clipboard del operador.

`Tests` indica si el nodo en disco contiene todos los brazos del ambiente especificado. `Cobertura` distingue lo efectivamente ejercitado en Linux de la brecha WinCI. `FAIL_RED` es el fallo esperado sobre el base; `PASS_BASE` es conformidad ya presente, no GREEN de Inc1b.

## Reporte por caso

| Caso | Tests | Cobertura | Resultado | Evidencia y motivo exacto |
|---|---|---|---|---|
| R-COPY.6/1 | partial | Linux seeds/recorder; WinCI gap | PASS_BASE | Botón: seed app/OS intacto antes y después de `n`; 0 sinks. El ledger ya marca el base conforme. |
| R-COPY.6/2 | partial | Linux seeds/recorder; WinCI gap | PASS_BASE | Sin foco: seeds intactos y 0 override/tail/base/writer/OSC52. |
| R-COPY.6/3 | partial | Linux seeds/recorder; WinCI gap | PASS_BASE | Tercera fila resaltada no se copia; seeds intactos. |
| R-COPY.6/4 | partial | Linux seeds/recorder; WinCI gap | PASS_BASE | Input vacío: comprobación con fallback abierto y tras `n`; 0 sinks. |
| R-COPY.6/5 | partial | Linux seeds/recorder; WinCI gap | PASS_BASE | JSON sin selección: seeds intactos; 0 sinks. |
| R-COPY.7/1 | partial | Linux recorder; WinCI not_run | FAIL_RED | Right-click de fila: override `0!=1`; falta productor right-click, tail y notice singular. |
| R-COPY.7/2 | partial | Linux recorder; WinCI not_run | FAIL_RED | Selección stats de 5 líneas construida; override `0!=1` en right-click. |
| R-COPY.7/3 | partial | Linux recorder; WinCI not_run | FAIL_RED | Hex de 3 líneas por Ctrl+C: override `1`, tail `0!=1`; base sólo espejo toolkit. |
| R-COPY.7/4 | partial | Linux direct-box recorder; WinCI not_run | FAIL_RED | Input `abc`: base/writer/OSC52 existentes, helper `0!=1`; no notice de éxito. Override esperado 0. |
| R-COPY.7/5 | partial | Ambos LF ejecutados; WinCI not_run | FAIL_RED | Textarea con y sin LF final: helper `0!=1` en ambos; se discrimina `3`, nunca `4` líneas. |
| R-COPY.7/6 | partial | 5 cuts ejecutados; WinCI not_run | FAIL_RED | Input/textarea selección, line-cut y ambos P70000: helper `0!=1`; faltan notices/cut original N. Cortes locales sí ocurren. |
| R-COPY.7/7 | partial | Ambos right-click directos; WinCI not_run | FAIL_RED | Input y textarea: helper `0!=1`; falta exactamente un notice, sin override de vista. |
| R-COPY.7/8 | full | Linux failing writer | FAIL_RED | Fila right-click: override `0!=1`; no se alcanza writer/notice porque falta la nueva ruta. |
| R-COPY.8/1 | partial | JSON + 2 boxes; WinCI not_run | FAIL_RED | JSON key: tail `0!=1`; input/textarea P70000: helper `0!=1`. Cap base de caja existe, falta cap/notice de la nueva vista. |
| R-COPY.8/2 | partial | JSON + 2 right-click boxes; WinCI not_run | FAIL_RED | JSON right: override `0!=1`; ambas cajas: helper `0!=1`. |
| R-COPY.9/1 | partial | 4 brazos; WinCI not_run | FAIL_RED | J75210 key: tail 0; exact 65536 y 65537 en caja: helper 0; over-cap failing writer: tail 0. N original no se deriva del notice. |
| R-COPY.9/2 | partial | Linux right-click; WinCI not_run | FAIL_RED | JSON right-click: override `0!=1`; no cut notice `(75,210 in all)`. |
| R-COPY.25/1 | partial | 3 rutas; sustitución NUL explícita; WinCI not_run | FAIL_RED | Hex key con `get_selected_text` inyectado: tail 0; JSON right y fila raw: override 0. Se requería fail-closed antes de sinks. |
| R-COPY.25/2 | partial | 6 rutas directas ejecutadas; WinCI not_run | FAIL_RED | Input/textarea × copy/cut/right-click: base `1!=0` en todos; seeds no protegidos. Cut local permanece borrado. |
| R-COPY.25/3 | partial | Vista + 2 cajas; WinCI not_run | FAIL_RED | NUL sólo en índice 65536 (carácter 65,537): vista tail 0; cajas helper 0. Se esperaba P65536 y N=65,537, no refusal. |
| R-PASTE.9/101 | full | Linux failing writer | FAIL_RED | Hex key: override 1, tail `0!=1`; no warning de escritura de la nueva ruta. |
| R-PASTE.9/102 | full | Linux failing writer | FAIL_RED | Hex right-click: override `0!=1`. |
| R-PASTE.9/103 | full | Linux failing writer | FAIL_RED | Fila A2L right-click: override `0!=1`. |
| R-PASTE.10/101 | full | Linux failing writer/log capture | FAIL_RED | Fila `SECRET-COPY-43`: override `0!=1`; falta ruta que debe emitir exact tail WARNING sin secreto. |
| R-PASTE.13/101 | full (WinCI) | not_run | SKIP/not_run | Requiere clipboard Windows aislado, holder externo de 8 s y bound 2.5 s; no se sustituyó por sleep Linux. |
| R-PASTE.14/101 | full (WinCI) | not_run | SKIP/not_run | Requiere holder WinCI y ticks de 50 ms; no se afirma responsividad desde Linux. |
| R-PASTE.14/102 | full (WinCI) | not_run | SKIP/not_run | Igual para right-click de selección de vista. |
| R-PASTE.14/103 | full (WinCI) | not_run | SKIP/not_run | Igual para right-click de fila. |
| R-TUI-043.13/101 | partial | 4 rutas Linux; WinCI success gap | FAIL_RED | View key tail 0; view right y ambas filas override 0. Las cuatro rutas se ejecutaron agregadamente; no se cuenta ausencia de log sin copia como éxito. |
| R-TUI-043.13/102 | partial | Fila hostile intentada; transporte posterior no alcanzado; WinCI not_run | FAIL_RED | `HOSTILE_NAME` exacto en modelo, override `0!=1`. Base no llega a app/OSC52/PowerShell/argv/stdin/log assertions; cobertura parcial, no verificada. |

Los 21 fallos son por comportamiento Inc1b ausente: override/right-click/tail/helper/notice/NUL fail-closed. No hubo `ERROR`, timeout de fixture, widget de área cero ni selección vacía accidental. Los cinco pases son sólo los controles R-COPY.6 que el propio ledger identifica como ya conformes en base.

## R-PASTE.12 — regresión sin nodo adicional

El ledger Inc1b no asigna un caso nuevo R-PASTE.12; añadirlo habría producido 31 nodos. Sus regresiones quedan dentro de:

- R-COPY.7/6: Ctrl+X en ambas clases, selección y line-cut, más P70000 en ambas clases; direct tail/override `1/0`, un writer/OSC52 y cut notice con N=70,000.
- R-COPY.8/1: Ctrl+C P70000 en ambas clases, comprobando app/base/writer/OSC52 = `P70000[:65536]`.
- R-COPY.8/2: lo mismo por right-click directo en ambas clases.
- R-COPY.9/1 y R-COPY.25/3: fronteras exactas 65,536/65,537 y N original independiente.

Los brazos Linux se ejecutaron y cayeron en helper/override/tail ausente. La lectura Windows separada de R-PASTE.12 queda **not_run**, no verificada.

## Oráculos y aislamiento

- Selecciones hex/stats/JSON capturadas antes del gesto; JSON J75210 tiene 75,210 caracteres y marcadores distintos en índices 65,535/65,536.
- Nombres de fila leídos del modelo `_a2l_row_key_to_tag`, nunca de la celda pintada. `HOSTILE_NAME` se construye literalmente con `[red]`, ESC, BEL, OSC-like y LF, sin NUL.
- Call ledger independiente para override/tail/base/writer/helper/process/thread y payload; notices leídos de `app._notifications` tras asentar; OSC52 decodificado del driver y también contado en crudo.
- Linux success usa recorders; failure usa el writer base fallido. HOSTILE fuerza la estrategia PowerShell con proceso simulado para inspección estática de argv/stdin, pero el base falla antes de ese tramo; no se afirma transporte verificado.
- R-COPY.25/1 usa texto seleccionado inyectado para el brazo hex Ctrl+C, JSON para right-click y nombre A2L raw para fila. Esta sustitución se declara y es parte de por qué su cobertura es parcial.

## Mutation targets y bloqueos

Los mutation targets están en `MUTATION-TARGETS.md`; E4 no ejecutó mutantes.

Bloqueos/pendientes exactos:

1. El object store compartido remoto no tenía `e2e93548`; se ejecutó el equivalente `c062293b`, con igualdad producto/tests demostrada localmente (status 0). No es un checkout literal del hash requerido.
2. WinCI no se ejecutó: R-PASTE.13/101 y R-PASTE.14/101…103 quedan not_run; todas las lecturas OS separadas, held clipboard, ticks y transporte PowerShell real quedan pendientes de la ruta aislada Windows existente.
3. El base carece de right-click/override/tail nuevo, por lo que las aserciones posteriores a la primera cardinalidad fallida (incluidas PowerShell real y algunas de logs) no constituyen cobertura verificada. El reporte las marca parcial.
4. No se ejecutó GREEN, integración ni mutantes; su propiedad queda fuera de E4. No hay fallos de fixture abiertos en el RED Linux final.
