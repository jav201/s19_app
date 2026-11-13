# E4 — auditoría independiente del ledger tras DeepSeek

## Veredicto

**PASS.** No se encontraron errores concretos en la reconciliación de `02-test-cases.md`. Los 112 casos activos, sus node IDs, los estados `full`/`partial`, las excepciones pendientes, la matriz de aceptación y todos los conteos son coherentes entre sí, con los archivos on-disk y con el GREEN `e8f8e3d1`.

Este PASS certifica la reconciliación del ledger y el oráculo Linux ejecutado; **no** convierte en cubiertas las ejecuciones WinCI/PowerShell, los brazos de grafo ni la aceptación manual que el propio ledger deja abiertos en `02-test-cases.md:181-204`.

## Alcance y método

- HEAD comprobado: `25563883f24ad96ee52881628bb06d56b4e0c597`.
- GREEN comprobado: `e8f8e3d189ab60eb24b05e7d917b7cd32311468e`, ancestro de HEAD.
- Se comparó el ledger modificado con su versión en HEAD y se inspeccionaron estáticamente, mediante parsing/AST y sin importar ni ejecutar la suite, los cuatro archivos de tests citados.
- Los cuatro archivos de tests son idénticos entre `e8f8e3d1` y el worktree; por tanto, los node IDs auditados son los mismos a los que se refiere el GREEN.
- `01-requirements.md` no tiene diff respecto de HEAD. No se ejecutaron tests ni se hicieron commits.

## 1. IDs y nodos on-disk

La expansión de los extremos de `R-COPY.14/1 … /6`, `R-COPY.14/7 … /9` y de las siete filas de matriz produce:

- **112 IDs activos únicos**, exactamente el inventario declarado en `01-requirements.md:130-142`: 93 R-COPY, 10 clipboard/security y 9 dialog/quit. No faltan IDs, no sobran y no hay duplicados.
- **9 casos withdrawn**, conservados en las dos filas `R-COPY.3/1 … /5` y `R-COPY.5/1 … /4` (`02-test-cases.md:40,44`), sin elevarlos a ejecución o cobertura.
- **28 celdas de aceptación + AT-I1b-8**, de modo que el universo es 112 + 28 + 1 = **141 nodos**.

Las 141 referencias del ledger son únicas y tienen correspondencia uno-a-uno con los 141 nodos estáticos on-disk; no hay referencias inexistentes, nodos sin referenciar ni duplicados:

| Archivo | Nodos ledger | Nodos on-disk |
|---|---:|---:|
| `tests/test_b103_copy_views.py` | 54 | 54 |
| `tests/test_b103_clipboard_tail.py` | 30 | 30 |
| `tests/test_b103_copy_quit_dialog.py` | 28 | 28 |
| `tests/test_b103_copy_paste_matrix.py` | 29 (28 + manual) | 29 (28 + manual) |
| **Total** | **141** | **141** |

Las parametrizaciones de views (`tests/test_b103_copy_views.py:464-468,486-487,527-528,569-570,593-594,648-653,820-821,844-845,857-858,874-875,894-895`) y los 28 IDs explícitos de matriz (`tests/test_b103_copy_paste_matrix.py:416-449`) confirman los IDs parametrizados, no solamente los nombres de función.

## 2. GREEN y contabilidad de ejecución

`evidence-e4/green-final-e8f8e3d1.txt:2-3` contiene literalmente **122 puntos y 19 marcadores `s`**, 141 resultados en total; su resumen en `:12` confirma **122 passed, 19 skipped**. El `green-run1.txt` anterior contiene fallos y no se usó como evidencia del estado final.

La asignación del ledger reproduce ese resultado sin residuo:

- Pasados: 108 requisitos `verified` + 14 celdas P1 `verified` = **122**.
- Skips: 4 requisitos WinCI-only `not_run` + 14 celdas P2 `not_run` + AT-I1b-8 = **19**.
- Requisitos: `covered + partial = 32 + 76 = 108 = verified`; `gap = 4 = not_run`.
- Los seis tiempos registrados son 0.108–0.349 s frente a 1.000 s, coherentes con `02-test-cases.md:179`; no se reclama ninguno de los cuatro límites WinCI no ejecutados.

El censo expandido independiente coincide con `02-test-cases.md:168-177`:

| Población | covered | partial | gap | verified | not_run |
|---|---:|---:|---:|---:|---:|
| 93 R-COPY | 19 | 74 | 0 | 93 | 0 |
| 10 clipboard/security | 4 | 2 | 4 | 6 | 4 |
| 9 dialog/quit | 9 | 0 | 0 | 9 | 0 |
| **112 requisitos** | **32** | **76** | **4** | **108** | **4** |
| 28 celdas de aceptación | 0 | 14 | 14 | 14 | 14 |

También coincide el desglose por archivo: views 54 = 8 covered + 46 partial; tail 30 = 5 covered + 21 partial + 4 gap; quit 28 = 19 covered + 9 partial.

## 3. Cobertura full/partial y skips/recorders

No se encontró ninguna fila `covered` cuyas precondiciones o resultados exijan WinCI, separate read o PowerShell real. Las 32 filas `covered` son brazos Linux/app-side completos; los brazos con recorder, proxy, PowerShell simulado o ejecución OS pendiente permanecen `partial`, y los cuatro nodos WinCI-only saltados permanecen `gap`.

Comprobaciones específicas:

- El fixture de views registra el writer en Linux y solo delega al writer real en Win32 (`tests/test_b103_copy_views.py:65-112`). Las 22 filas recorder-writer de R-COPY.1/.4/.11/.12 y los demás brazos que deben repetirse en WinCI están correctamente en `partial`, como explican `02-test-cases.md:196-204`.
- **R-COPY.16/1…/6 y R-COPY.20/1…/3** son las nueve filas `partial + verified` de `02-test-cases.md:92-97,103-105`. El fixture de quit sustituye `write_os_clipboard` y `read_os_clipboard` en toda plataforma (`tests/test_b103_copy_quit_dialog.py:68-96`), sin seed/read externos; la pendiente WinCI de `02-test-cases.md:198` es correcta. **R-COPY.20/4** queda correctamente `full + covered + verified`: su precondición heredada es Linux y no exige lectura OS (`02-test-cases.md:106`).
- **R-TUI-043.13/101** está `partial + verified`, no covered: su nodo se salta en WinCI y la variante successful-WinCI sigue separada (`tests/test_b103_clipboard_tail.py:926-951`; pendiente en `02-test-cases.md:199`).
- **R-TUI-043.13/102** está `partial + verified`, no covered: el pase Linux parchea plataforma/rutas/`subprocess.run` y declara transporte `linux-simulated-powershell` (`tests/test_b103_clipboard_tail.py:954-1027`). La pendiente de writer/transporte PowerShell real en `02-test-cases.md:200` es correcta.
- **R-PASTE.13/101 y R-PASTE.14/101…/103** son exactamente los cuatro `gap + not_run` (`02-test-cases.md:122-125`). Sus nodos llaman a `_winci_ready_or_skip`, que se salta fuera de Win32 (`tests/test_b103_clipboard_tail.py:1030-1037,1105-1107,1188-1209`). Ninguno se eleva a cobertura ni a timing medido.

Los 19 skips quedan así completamente explicados: 14 P2 + 4 WinCI-only + 1 manual; ninguno aparece como `covered` o `verified`.

## 4. Matriz P1/P2 y AT-I1b-8

En las 28 celdas de `02-test-cases.md:146-152`:

- `/1` y `/3` = P1: **14 `partial + verified`**.
- `/2` y `/4` = P2: **14 `gap + not_run`**, cada una marcada `none executed`.
- La guarda on-disk salta P2 en Linux y solo permite P1 parcial en el host Linux headless (`tests/test_b103_copy_paste_matrix.py:28-46`), coherente con el ledger.

AT-I1b-8 conserva sus seis pasos y criterios de aceptación. Su estado es **Coverage `not-testable`, Result `not_run`** (`02-test-cases.md:156`), y su nodo tiene skip obligatorio (`tests/test_b103_copy_paste_matrix.py:456-463`). Frente a HEAD solo cambió el estado anterior `gap` a `not-testable`, se añadió la explicación del skip y se ajustó la conjunción de esa misma frase; no cambió el diseño de aceptación.

## 5. Thresholds, requirements y withdrawn

La comparación contra HEAD no encontró cambios de diseño:

- Las **seis primeras celdas** de las 105 filas físicas de requisitos activos —ID, objetivo, clase, precondiciones, inputs y resultado esperado, incluidos thresholds— son idénticas.
- Las **tres primeras celdas** de las siete filas de matriz son idénticas.
- Las dos filas withdrawn son idénticas completas (`02-test-cases.md:40,44`).
- El orden y el conjunto de IDs de todas las filas de diseño son idénticos.
- Fuera de las columnas E4, los cambios se limitan al nuevo párrafo de reconciliación, al estado de AT-I1b-8 descrito arriba y a las secciones E4 añadidas. `01-requirements.md` permanece sin cambios.

La línea 205, blank-at-EOF pendiente de corrección por el orquestador, quedó explícitamente excluida de esta auditoría de fondo y no afecta al PASS.

## Defectos

**Ninguno.** No hay defectos concretos `file:line` que señalar en la reconciliación auditada.
