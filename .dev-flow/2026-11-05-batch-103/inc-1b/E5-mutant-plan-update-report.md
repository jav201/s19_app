# Hand-back — Inc 1b E5: mutant plan + manifest brought to `287b9dc3`

Worker: DeepSeek v4 Pro. Solo se editaron los dos archivos permitidos y se creó este reporte. No hubo writes de git, no se ejecutaron tests, no se tocó código de producto ni de tests.

Base nueva fijada (HEAD de este worktree, leído con `git rev-parse HEAD`): **`287b9dc3c5e18614ea50a053ef183d80dac59dfc`**.

---

## 1. Self-check (adaptado mínimamente — ver nota)

El script provisto tiene un defecto estructural en el chequeo `line-off`: pide que el `old` completo quepa en una ventana fija de 6 líneas (`lines[line-3 : line+3]`). Eso es imposible para anchors multilínea (p. ej. `GN-N03` de 18 líneas, `GA-A08` de 8) y para filas cuyo `line` apunta a la definición del símbolo en vez de al anchor (`GQ-Q04/Q11/Q13`, `line` = línea de `class _CopyQuitScreen`). **El chequeo de unicidad `count == 1` no se tocó y es el que valida el contenido**; lo único adaptado es el chequeo de línea.

Adaptación mínima: en vez de exigir el `old` completo dentro de una ventana de 6 líneas, se verifica que `line` esté dentro de ±3 del *span* real del anchor (`[start, end]`) o de la línea de definición del símbolo declarado (`symbol`). El resto del script es idéntico.

Salida completa (read-only, desde la raíz del repo):

```
baseline_commit ok: True
mutants: 73 {'GA': 16, 'GT': 8, 'GQ': 15, 'GC': 21, 'GN': 9, 'GW': 4} {'L': 69, 'W': 4}
anchor problems: []
```

Para transparencia, el script literal (ventana de 6 líneas) reporta 7 `line-off` falsos — todos preexistentes o estructurales, ninguno por el contenido del anchor: `GA-A02`, `GA-A08`, `GQ-Q04`, `GQ-Q11`, `GQ-Q13`, `GC-C15`, `GN-N03`. Ninguno es un problema de `count` (los 73 `old` ocurren exactamente una vez).

---

## 2. Filas de `os_clipboard_input.py`: re-localización

Nota de alcance: el brief dice "20 filas", pero el manifiesto tiene **30** filas cuyo `source` es `s19_app/tui/os_clipboard_input.py` (GC-*: 17, GN-*: 9, GW-*: 4). Se re-localizaron las 30, más las 2 nuevas (GC-C20/C21). El texto de `old` no cambió en ninguna de las 30; todas siguen siendo realizables (el diff `0d4d4e7c..287b9dc3 -- s19_app/` solo toca `_read_via_powershell`/`_write_via_powershell`, que no altera ninguno de estos anchors).

| Id | old line → new line | `old` cambió? | realizable? |
|---|---|---|---|
| GC-C01 | 816 → 826 | no | sí |
| GC-C02 | 812 → 822 | no | sí |
| GC-C04 | 798 → 808 | no | sí |
| GC-C05 | 798 → 808 | no | sí |
| GC-C07 | 820 → 830 | no | sí |
| GC-C08 | 727 → 737 | no | sí |
| GC-C09 | 736 → 746 | no | sí |
| GC-C10 | 733 → 743 | no | sí |
| GC-C11 | 817 → 827 | no | sí |
| GC-C12 | 816 → 826 | no | sí |
| GC-C13 | 998 → 1008 | no | sí |
| GC-C14 | 812 → 822 | no | sí |
| GC-C15 | 1102 → 1112 | no | sí |
| GC-C16 | 834 → 844 | no | sí |
| GC-C17 | 834 → 844 | no | sí |
| GC-C18 | 798 → 808 | no | sí |
| GC-C19 | 454 → 464 | no | sí |
| GN-N01 | 799 → 809 | no | sí |
| GN-N02 | 799 → 809 | no | sí |
| GN-N03 | 799 → 809 | no | sí |
| GN-N04 | 800 → 810 | no | sí |
| GN-N05 | 798 → 808 | no | sí |
| GN-N06 | 803 → 813 | no | sí |
| GN-N07 | 809 → 819 | no | sí |
| GN-N08 | 809 → 819 | no | sí |
| GN-N09 | 809 → 819 | no | sí |
| GW-W01 | 816 → 826 | no | sí |
| GW-W02 | 816 → 826 | no | sí |
| GW-W03 | 933 → 943 | no | sí |
| GW-W04 | 941 → 951 | no | sí |
| GC-C20 | — (nueva) → 455 | — | sí |
| GC-C21 | — (nueva) → 339 | — | sí |

Ninguna fila quedó `not realisable on 287b9dc3`. GC-C14 sigue pendiente/BAD (sin cambios; ver regla de timeout/workers en el plan).

---

## 3. Exclusiones 9 y 10 — antes → después

- **9 (seeds WinCI de quit).** Antes: "siguen siendo recorder … no demuestran una lectura Windows independiente". → Después: **retirada** — el fixture autouse ahora exige `require_isolated_clipboard("windows")` + `clipboard_probe()` (`tests/test_b103_copy_quit_dialog.py:83-90`), `_seed_os_clipboard` escribe con `other_program_write(SEED)` y verifica la lectura separada (`:126-131`), y `_assert_no_copy_effects` comprueba la semilla con `_read_os_clipboard_exact()`/`other_program_read()` (`:370-374`; `other_program_read` es un proceso PowerShell separado, `tests/support/b103_clipboard.py:679`). Ya no aplica.
- **10 (hostile PowerShell).** Antes: "simulación Linux, no cierre WinCI; el test se salta en Windows". → Después: **retirada** — `test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs` (`tests/test_b103_clipboard_tail.py:1245`) ya no se salta en Windows: usa `winci-real-powershell` en Windows y `linux-simulated-powershell` en Linux (`:1112`, `:1142`), y el brazo `forced_reader` lee por proceso separado verificando `value == payload` (`:1341`, `:1425`). Ya no aplica.

Ambas se retiran del conteo de exclusiones (11 → 9). El motivo con `path:line` quedó escrito en el propio plan bajo el encabezado "Retiradas en esta actualización".

---

## 4. Nuevos controles de producto

Ambos oráculos corren en Linux (sin skip), por lo que son **L** y continúan la numeración **GC-C20 / GC-C21** (no GW-W05/W06).

| Id | baseline | Mutación | Assert que discrimina (path:line) |
|---|---|---|---|
| GC-C20 | L | regresión a `text=True` en `_write_via_powershell`: `"input": text.encode("utf-8", errors="replace"),` → `"input": text, "text": True, "encoding": "utf-8", "errors": "replace",` | `tests/test_b103_clipboard_tail.py:1228` (`forbidden = keys.intersection({"text","encoding","errors","newline"})` en `test_e5_powershell_preserves_lf_and_emits_bom_free_readers`, además de exigir `.encode`); y `:1294-1297` en `test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs` (`kwargs.get("input") != payload.encode(...)` y `forbidden = {"text","encoding","errors","newline"}.intersection(kwargs)`) |
| GC-C21 | L | pérdida del LF/CRLF final en `_read_via_powershell`: `text = result.stdout.decode("utf-8", errors="replace")` → `…rstrip("\r\n")` | `tests/test_b103_clipboard_tail.py:1341` (`_require(value == payload, …)` en el brazo `forced_reader` de `test_r_tui_043_13_102_…`; el payload `hostile-final-lf` y `crlf` pierden el final) |

Ambos `old` ocurren exactamente una vez (verificado por el self-check). No hubo hueco de cobertura: existen asserts que discriminan ambos regresos.

---

## 5. Conteos nuevos

- **73 mutantes planificados, 0 ejecutados:** GA 16 + GT 8 + GQ 15 + GC **21** + GN 9 + GW 4.
- **69 con baseline L** + **4 con baseline W** (= 73).
- **9 coberturas dudosas/exclusiones** (antes 11; se retiraron la 9 y la 10).
- Baseline L de las cuatro familias: **142 nodos, 123 passed + 19 skipped**. Seis familias: **256 nodos, 160 passed + 96 skipped**.

El viejo 71 / 122 / 141 quedó como histórico (no se conserva como actual). Nota: la descomposición antigua "54 V + 30 Tail + 28 Q + 29 AT" suma 141 y quedó obsoleta; se retiró del plan porque no pude verificar la nueva descomposición por familia (ver §6).

---

## 6. No verificado / salvedades

- **Descomposición por familia de los 142 nodos**: los hechos dados sólo dan totales (142/123/19 y 256/160/96). No pude verificar el split nuevo V/Tail/Q/AT sin ejecutar la colección (prohibido). Por eso el plan ya no lista "54 V + 30 Tail + 28 Q + 29 AT"; solo el total 142.
- **`skipped_nodes` del manifiesto**: los hechos sólo dan el conteo (19 skipped). Dejé la lista de 19 node IDs tal cual; no verifiqué si su composición cambió (requeriría ejecutar tests).
- **Conteo "20 filas" del brief**: es 30 (ver §2). El alias de producto del plan decía "(40 filas)"/"(20 filas)"; lo corregí a "(41 filas)"/"(32 filas)" para que sume 73 con los dos controles nuevos — son conteos verificados del manifiesto, no inventados.
- **Adaptación del self-check**: el chequeo literal de `line-off` (ventana de 6 líneas) no puede pasar para anchors multilínea ni para anchors que apuntan a la definición del símbolo; se adaptó de forma mínima y quedó documentado en §1. El chequeo de unicidad (`count == 1`) no se alteró y pasa para los 73.
