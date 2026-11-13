# Inc 1b — E3 ARCHITECT, re-review round 2

Revisión independiente de las correcciones E3 sobre HEAD `6adb633711661f072113ffd601cf90ac34d2c26c` y el working tree indicado. Alcance: `E3-architect.md` (E3A-01…05), `E3-rulings.md`, `E3-security.md` (E3-01…03), `01-requirements.md`, `02-test-cases.md`, `E1-slice.md`, `E2-interfaces.md`, `graph-app.md`, `graph-clipboard.md`, `graph-inc1b.md`, `evidence-e2/lint-transcript.txt` y `evidence-e2/deepseek-census-final.txt`.

Contraste estático con `s19_app/tui/app.py`, `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/capped_text_area.py` y Textual 8.2.8. No ejecuté tests, probes ni la aplicación; todos los casos continúan `not_run`. El PASS mecánico se usa como índice de comprobación, no como sustituto de la revisión semántica. En las citas, los artefactos por nombre simple están en este `inc-1b/` y `graph-inc1b.md` en `inc-1b/codewire/`.

## Veredicto

**PASS-WITH-NOTES.** No queda ningún **BLOCKER, HIGH o MAJOR** abierto. E3A-01…05 y E3-01…03 tienen cierre comportamental y ejemplos discriminantes. Quedan **4 minor** de alineación documental/implementación, todos con propietario E4 explícito abajo; ninguno reabre los defectos de comportamiento corregidos ni impide continuar el diseño a E4 con esas instrucciones.

## Disposición de los hallazgos originales

| Hallazgo | Disposición R2 y evidencia comprobada |
|---|---|
| E3A-01 — selección vacía | **Cerrado.** N1 eleva `textual.actions.SkipAction` antes de construir coroutine/worker (`graph-inc1b.md:160-168`). Las armadas idle y modal fijan body B/seeds/cero efectos y conservación del modal (`graph-inc1b.md:167-168,277-281`; `01-requirements.md:118,122`; `02-test-cases.md:90,101`). El mutante `return` queda explícitamente RED. La importación necesaria se precisa en E3R2-04. |
| E3A-02 — `out_of_bounds` | **Cerrado.** N2 exige `not meta.get("out_of_bounds", False)` antes de resolver fila/celda (`graph-inc1b.md:189`). N5 hace `prevent_default()` y retorna sin cursor/`RowSelected` para padding (`graph-inc1b.md:240-243`). Los mismos fixtures cambian sólo el flag para el control positivo (`graph-inc1b.md:194-195,242-243`; `02-test-cases.md:75,84`). La semántica coincide con el meta que Textual emite en `widgets/_data_table.py:2350-2390`. |
| E3A-03 — ejemplos E4 | **Cerrado.** Las seis fuentes Ctrl+C están asignadas (`graph-inc1b.md:169-173,328`); detail-card right-click, left-drag/F7 sin copia y seeds en dos observaciones están en `graph-inc1b.md:197,223-224,278-279,329`. R-COPY.2/4 es ahora fila + writer fallido (`graph-inc1b.md:175`; `02-test-cases.md:37`). El addendum los enumera sin crear requisitos redundantes (`02-test-cases.md:136`). |
| E3A-04 — MAC Rich `Text` | **Cerrado, con nota de fixture E3R2-03.** N2 fija `.plain` para `Text`, `str(cell)` en el otro caso, un único prefijo productor conocido, nombre completo y `None` si falta prefijo/nombre (`graph-inc1b.md:189`; `E2-interfaces.md:22`; `E1-slice.md:29`). La segunda armada larga está en requirements y ledger (`01-requirements.md:106`; `02-test-cases.md:40`), y no aumenta R-COPY.4 de tres a cuatro casos. |
| E3A-05 — provenance/censo | **Cerrado en el grafo; nota residual E3R2-01 en interfaces.** El grafo distingue 17 entradas del fragmento A y 16 tras ceder C1, total integrado 24/2 archivos (`graph-inc1b.md:9,140,783-785`). Body B/q=B están alineados y las notas viejas son históricas (`graph-inc1b.md:36-39,649,774`; `E2-interfaces.md:34,40,45`). La interfaz conserva una cifra A=17 sin el calificador de fragmento. |
| E3-01 — copia prematura en right-drag | **Cerrado comportamentalmente; nota estructural E3R2-02.** N3 captura en press sin N1, invalida definitivamente al cambiar offset, exige release con mismo offset/screen/widget y consume antes de una única llamada N1 (`graph-inc1b.md:206-224`). Hay controles right-drag, exit-return, fila, contexto y reentry (`:218-222`), más R-COPY.11/5 y R-COPY.13/7–9 (`02-test-cases.md:67,82-84`). La entidad `_right_gesture` no añade nodo (`graph-inc1b.md:502-509`). |
| E3-02 — NUL | **Cerrado.** El guard examina `capped_text` antes de base/writer/helper y fija cero sinks/procesos/helper/success, seeds intactos, una warning de 6 s y un WARNING fijo sin payload (`graph-inc1b.md:81-83,405,424-427`; `01-requirements.md:127`; `02-test-cases.md:113-115`). La rama after-cap conserva la longitud original para la cut notice. La fuente confirma la necesidad: Win32 codifica UTF-16LE + terminador (`os_clipboard_input.py:335-374`) y el lector corta en el primer NUL (`:261-264`). |
| E3-03 — fixture hostil | **Cerrado.** El literal es byte-idéntico en `02-test-cases.md:20`, `graph-clipboard.md:37` y `graph-inc1b.md:102`: markup + ESC + BEL + OSC-like + un LF, sin NUL. El caso exige payload raw en app/OSC 52/Windows, cardinalidad, PowerShell stdin/static argv, cero secuencias extra y ausencia de nombre/prefijo en logs (`02-test-cases.md:125`; `graph-inc1b.md:203`). La ruta real usa `shell=False`, comando estático y `input=text` (`os_clipboard_input.py:120-131,441-471`). |

## Censo independiente y compatibilidad del diseño

### Requisitos y casos

La enumeración activa R-COPY.1, .2, .4 y .6–.25 da **23 requisitos**. La suma por filas da **93 R-COPY**: 6 + 4 + 3 + 5 + 8 + 2 + 2 + 3 + 5 + 8 + 9 + 9 + 3 + 6 + 3 + 1 + 1 + 4 + 2 + 2 + 2 + 2 + 3. Con **10 cited clipboard/security** y **9 dialog/quit**, el total es **112 casos**, igual a `01-requirements.md:142` y `02-test-cases.md:158`. Los 9 withdrawn se conservan. AT permanece en **7 fuentes × 4 = 28 celdas + AT-I1b-8 manual** (`02-test-cases.md:140-158`).

Los incrementos respecto de R1 se reconcilian: R-COPY.11 +1, R-COPY.12 +1, R-COPY.13 +3, R-COPY.14 +3, R-COPY.25 +3 = +11 R-COPY; R-TUI-043.13/102 = +1 cited. No hay un R-COPY.4/4 oculto.

### Grafo, fragmentos e integración

- `evidence-e2/lint-transcript.txt:1` confirma **24 nodes / 7 entities / 16 edges / 41 findings / 0 unread**. Las 41 findings se explican como 23 R-COPY + 13 cited + 2 regression pins + E2-1 + E2-2 + COVERAGE.
- La aritmética fragmento/integrado es coherente en el grafo: A tiene 17 entradas (10 implementation + 7 context); al retirar el contexto C1 duplicado queda con 16 (10 + 6); B aporta 8 (2 + 6); total **24 = 12 implementation + 12 context** (`graph-inc1b.md:9,72,140`).
- La séptima entidad es `_right_gesture`; no se convirtió en función ni en una séptima fuente de escritura (`graph-inc1b.md:502-509`). Las 16 edges conservan el tail como único dueño de mirror/write/helper y añaden la exclusión NUL en sus condiciones (`graph-inc1b.md:550-576`).
- El contenido integrado conserva el delta B: `_copy_notice_text`, `_mirror_and_write_os_clipboard` cambiado, HOSTILE y todos los controles NUL (`graph-inc1b.md:386-427`). No hay pérdida por first-node-wins.
- La propiedad del slice es correcta: tail y helper pertenecen a `os_clipboard_input.py` (`E1-slice.md:31-32`), `_compose_screen_a2l` es unchanged (#8) y sólo `_compose_screen_mac` cambia (#9) (`E1-slice.md:35-36`). La observación de DeepSeek sobre “2 changed functions” ya está corregida a **1 changed function** (`E1-slice.md:11`).

### Contratos Textual y transporte

La solución N1/N2/N3/N5 sigue siendo implementable: `SkipAction` continúa la cadena de acciones, App recibe press antes del toolkit y sintetiza Click tras release, el snapshot sobrevive a la limpieza de selección, y `prevent_default` suprime el handler base de DataTable. El nuevo estado no introduce un segundo writer ni un worker adicional. NUL se rechaza antes de cualquier sink; otros C0/markup siguen raw. OSC 52 codifica Base64 y PowerShell recibe stdin con argv estático, por lo que el fixture hostil no se convierte en comando (`os_clipboard_input.py:120-131,441-456`; Textual `app.py:1780-1786`).

## Notas menores abiertas y asignadas

### E3R2-01 — minor — documentación/censo: interfaz A=17 sin distinguir fragmento de integrado

**Evidencia.** `E2-interfaces.md:39` dice “Group A remains 17 function nodes”, mientras el contrato integrado correcto es 17 entradas de fragmento menos C1 = 16 nodos A integrados (`graph-inc1b.md:9,783-785`). El total 24 sí es correcto.

**Propuesta y propietario E4.** En la próxima alineación documental, escribir “17 fragment entries / 16 integrated group-A nodes; 24 total”. Para implementación y censo E4 usar la fórmula del grafo, no 17 + 8 = 25. Es minor porque el grafo canónico ya es inequívoco y el lint cuenta los nodos reales correctamente.

### E3R2-02 — minor — design-gap documental: `E1-slice` describe otro récord de gesto

**Evidencia.** `E1-slice.md:38` exige “exactly four fields” y un snapshot no vacío. `E2-interfaces.md:28-30` y `graph-inc1b.md:212,502-509` fijan cinco campos: `text`, `screen_offset`, `screen`, `widget`, `valid`; el texto puede ser `None` hasta consumir el candidato vacío. El comportamiento previsto sí coincide.

**Propuesta y propietario E4.** Alinear `E1-slice.md` #3c/gesture-state con la interfaz: cinco campos, `Optional[str] text`, `valid=True` en captura y `valid=False` permanente tras movimiento. El implementador N3 debe seguir el grafo pinned; no reinterpretar “cuatro campos” como otra máquina de estados. Es minor porque no hay ambigüedad en el comportamiento canónico ni en los oráculos.

### E3R2-03 — minor — oracle-alignment: dos fixtures alternativos no son idénticos al ledger

**Evidencia.** La segunda armada R-COPY.4/2 usa `Long record name with spaces beyond the painted column width` (`01-requirements.md:106`; `02-test-cases.md:40`; `E1-slice.md:29`), mientras el ejemplo etiquetado R-COPY.4/2 del grafo usa `Curve External Axis With A Very Long Full Name` (`graph-inc1b.md:193`). R-COPY.25/3 fija exactamente 65,537 caracteres (`02-test-cases.md:115`; `graph-app.md:238`), mientras el fixture adicional `NUL_AFTER` del tail contiene 65,541 y anuncia ese total (`graph-inc1b.md:101,426`).

**Propuesta y propietario E4.** Para los casos nombrados, usar los valores del ledger y sus expected exactos. Los otros strings son armadas adicionales válidas, no sustitutos silenciosos: alinearlos en la próxima edición o etiquetarlos expresamente como extras. No crear casos nuevos ni cambiar los conteos. Ambos pares conservan discriminación; la nota evita que E4 elija un fixture y copie el expected del otro.

### E3R2-04 — minor — design-gap de implementación: falta fijar el import de `SkipAction`

**Evidencia.** N1 prescribe literalmente `raise textual.actions.SkipAction` (`graph-inc1b.md:166`; `E2-interfaces.md:9`). El producto actual importa `events` y `work` desde `textual`, pero no `textual.actions` ni `SkipAction` (`s19_app/tui/app.py:18-20`; búsqueda estática de símbolos en todo el archivo sin otra importación). Una transcripción literal sin añadir el import produciría `NameError` justamente en la ruta corregida.

**Propuesta y propietario E4.** Añadir `from textual.actions import SkipAction` y usar `raise SkipAction`, o añadir `import textual.actions` y conservar la forma calificada. Fijarlo en la receta N1 y en la implementación E4; no requiere nodo, requisito o caso adicional. Es minor de integración, no una reapertura del contrato comportamental E3A-01.

## Cobertura final para E4

Los 23 requisitos y 112 casos tienen propietario y oráculo. Los 24 nodos/7 entidades/16 edges/41 findings son coherentes con el grafo integrado. Los ejemplos críticos no son vacuos: `return` frente a `SkipAction`; `out_of_bounds` True/False sobre la misma fila; movimiento/exit-return frente a release válido; NUL dentro/fuera del cap con helper y logs observados; HOSTILE raw frente a proyección pintada; y MAC corto/largo con `.plain`.

Las cuatro notas son explícitamente E4-addenda con dueño y no esconden trabajo de arquitectura pendiente. Si E4 cambia el comportamiento N1/N2/N3/N5/tail en vez de limitarse a estas alineaciones, esa modificación sí necesitará otra revisión de diseño.
