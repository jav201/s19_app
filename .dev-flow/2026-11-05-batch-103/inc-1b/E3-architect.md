# Inc 1b — E3 ARCHITECT: factibilidad y contratos Textual

Revisión independiente en `6adb633711661f072113ffd601cf90ac34d2c26c`. Alcance: `codewire/graph-inc1b.md` integrado (24 nodos), `01-requirements.md`, `02-test-cases.md`, `E2-interfaces.md`, `E1-rulings.md` finales y el veredicto G2 vigente. Contraste estático con `s19_app/tui/app.py`, `os_clipboard_input.py`, `capped_text_area.py` y Textual 8.2.8 instalado en `C:/Users/<user>/anaconda3/envs/s19env/Lib/site-packages/textual/`.

En las citas, `.../textual/` abrevia ese directorio de Textual; los artefactos citados por nombre simple están en este `inc-1b/`, y `graph-inc1b.md` está en `inc-1b/codewire/`.

No ejecuté pytest, probes ni la aplicación; no hago afirmaciones de ejecución. El lint aporta sólo parseo (`nodes=24`, `edges=16`, `findings=40`), no evidencia de corrección. No edité producto, tests, grafos, requirements, interfaces, rulings ni steps.

## Veredicto

**FAIL.** Hay **1 HIGH, 1 MAJOR y 3 minor** abiertos. E3A-01 rompe la ruta Ctrl+C sin selección exigida por R-COPY.16; E3A-02 deja una ruta de copia en espacio vacío que el propio grafo dice excluir. No procede PASS-WITH-NOTES mientras esos dos hallazgos permanezcan abiertos.

El diseño es mayoritariamente implementable: la integración sí conserva el delta de clipboard, la cadena de tablas es viable, el tail no se reentra y las rutas q/Ctrl+Q/paleta pueden convivir. El fallo no es de viabilidad global, sino de dos contratos incompletos y de cobertura/provenance que debe corregirse antes de dar el diseño por apto.

G2 comprobado en `.dev-flow/2026-11-05-batch-103/evidence/G2/veredicto-b103-r2.json:6-18`: body **B**, q=**B**, q5/q6=`approve`, `notes={}` y nota general vacía. El SHA-256 recalculado es `6eb12681c82727cfbbe5a21f6d88719b6ff3815ca0bd4d974c2f1274423ae6bf`, igual al fijado por `E2-interfaces.md:3`. La reconciliación final de `E1-rulings.md:301-311`, no sus secciones históricas, es la que rige.

## Hallazgos

### E3A-01 — HIGH — design-gap: `copy_to_clipboard("")` consume Ctrl+C y suprime el diálogo

**Evidencia.**

- N1 ordena retornar sin efectos cuando `text == ""`: `.dev-flow/2026-11-05-batch-103/inc-1b/codewire/graph-inc1b.md:149-156`.
- Textual no eleva `SkipAction` para ese valor: `Screen.action_copy_text` sólo lo eleva para `None` y después llama al override con el resultado, incluida la cadena vacía (`C:/Users/<user>/anaconda3/envs/s19env/Lib/site-packages/textual/screen.py:985-991`). `get_selected_text` puede devolver `""` tras unir y aplicar `rstrip("\n")` (`.../textual/screen.py:963-983`).
- La ruta vacía no es sólo teórica: una selección de un contenido sin líneas produce `""` (`.../textual/selection.py:34-45`), y el ratón puede crear estado de selección en un widget seleccionable (`.../textual/screen.py:1885-1920`; `.../textual/widget.py:4213-4232`).
- R-COPY.16 exige abrir exactamente un body-B cuando no hay selección y la aplicación está idle (`.dev-flow/2026-11-05-batch-103/inc-1b/01-requirements.md:98`). R-COPY.6 exige además preservar ambos clipboards (`01-requirements.md:88`). Los seis casos actuales cubren widgets sin selección, pero no una selección de pantalla materializada cuyo texto sea vacío (`02-test-cases.md:82-87`).

**Defecto.** Con `screen.selections` no vacío pero `get_selected_text() == ""`, N1 retorna normalmente. `Screen.action_copy_text` termina como acción atendida, de modo que Ctrl+C no continúa hasta N8: no hay copia, pero tampoco quit dialog. Es una contradicción observable con R-COPY.16, no un matiz interno. El ejemplo negativo actual de N1 sólo comprueba clipboards/workers y, por tanto, deja pasar el defecto (`graph-inc1b.md:156`).

**Propuesta concreta.** En N1, sustituir el retorno vacío por `raise SkipAction` antes de crear coroutine/worker. Textual captura esa excepción en el dispatcher y devuelve `False` para continuar la cadena (`.../textual/app.py:4272-4289`); la cadena modal seguirá impidiendo llegar al fallback de App cuando corresponda (`.../textual/screen.py:448-455`). N3 debe seguir llamando N1 únicamente con texto no vacío.

Añadir al ejemplo de R-COPY.16/1 una segunda armada con selección de pantalla presente y texto extraído vacío: idle, sin sesión, resultado exacto = un body-B, ambos seeds intactos y cero workers/writes/OSC 52/notices. Repetir el negativo dentro de la ayuda modal para R-COPY.20: permanece la ayuda original, sin N9 ni efectos. Fijar el mutante `return` como RED por ausencia del diálogo idle, no sólo por cardinalidad de copia.

### E3A-02 — MAJOR — design-gap: el relleno de fila lleva `out_of_bounds`, pero N2/N5 no lo evalúan

**Evidencia.**

- N2 promete “empty space … return `None`”, pero sólo valida tipos, rango de fila y columna; no lee `out_of_bounds` (`.dev-flow/2026-11-05-batch-103/inc-1b/codewire/graph-inc1b.md:168-173`). N5 repite la omisión al decidir el desplazamiento del cursor (`graph-inc1b.md:207-213`).
- Textual marca el relleno horizontal con una fila válida, `column=0` y `out_of_bounds=True` (`C:/Users/<user>/anaconda3/envs/s19env/Lib/site-packages/textual/widgets/_data_table.py:2350-2390`). Su handler estándar rechaza ese flag sólo cuando `cursor_type != "row"`; nuestras dos tablas usan `cursor_type="row"` (`.../textual/widgets/_data_table.py:2669-2702`; `s19_app/tui/app.py:8764-8770,8860`).
- R-COPY.13/.14 exigen seed y ausencia de notices en un empty right-click (`01-requirements.md:95-96`). Los casos actuales prueban header y tabla con cero filas, no el relleno horizontal de una fila válida (`02-test-cases.md:72-78`).

**Defecto.** Un clic en el espacio sobrante a la derecha de las celdas puede tener `0 <= row < row_count` y `column >= 0`; N2 copiará el nombre aunque su propio contrato diga que ese espacio devuelve `None`. Esto puede reemplazar el clipboard en un gesto clasificado como vacío y no tiene un ejemplo E4 que lo distinga.

**Propuesta concreta.** Mantener la semántica ya escrita (“empty space → None”): exigir `not meta.get("out_of_bounds", False)` en N2 antes de resolver la row key o leer MAC. En N5, tratar ese clic como no-row y evitar también la selección por defecto: `prevent_default()` y retorno sin `move_cursor`, para que el relleno no produzca `RowSelected` ni salto. Si se prefiere que el relleno cuente como fila, hay que cambiar explícitamente la definición y los requisitos; no dejar la contradicción implícita.

Añadir ejemplos A2L y MAC con fila válida y `out_of_bounds=True`: N1=0, ambos seeds intactos, cero notices/writes/OSC 52, cursor y primera línea hex sin cambio, cero `RowSelected`. Conservar como control positivo una celda real de la misma fila, cuyo único cambio de fixture sea `out_of_bounds=False`, que sí debe copiar y resaltar.

### E3A-03 — minor — design-gap: la cobertura de ejemplos E4 está sobredeclarada

**Evidencia.**

- El finding de R-COPY.1 presenta hex y JSON y generaliza las otras cuatro fuentes por tener la misma ruta (`.dev-flow/2026-11-05-batch-103/inc-1b/codewire/graph-inc1b.md:532-535`); el censo global afirma después cobertura por “concrete design examples” (`graph-inc1b.md:727-730`). Los seis casos tienen fuentes y oráculos diferentes en `02-test-cases.md:26-31`.
- No hay ejemplos específicos para R-COPY.1/2 (stats con Ctrl+C), /3 (summary), /4 (detail card) y /6 (help modal con Ctrl+C); R-COPY.11/1 (drag sin copia) y /3 (F7 sin copia) (`02-test-cases.md:61-64`); ni R-COPY.12/3 (detail card con right-click) (`02-test-cases.md:67`). En R-COPY.6/1, /2 y /4 falta fijar el seed tanto con el diálogo abierto como después de `n`, aunque el diálogo sí está ejemplificado (`02-test-cases.md:41-45`; `graph-inc1b.md:248-249`).
- La descripción de N1 para R-COPY.2/4 habla de repetir una selección right-click con fallo, pero el caso /4 es un right-click de fila (`graph-inc1b.md:158`; `02-test-cases.md:35`). El tail sí contiene el ejemplo correcto de las tres rutas (`graph-inc1b.md:385`).

**Defecto.** Los 100 casos del ledger sí están especificados, pero no todos tienen el ejemplo de integración que E2 promete a E4. La equivalencia de ruta permite no repetir todo; no permite afirmar que las fuentes modal/detail, los negativos drag/F7 y los seeds antes/después de Stay ya fueron ejemplificados. Es minor porque `02-test-cases.md` sí da pasos y resultados utilizables, pero el sobreclaim facilita omitirlos al implementar E4.

**Propuesta concreta.** Añadir ejemplos breves para los casos enumerados, con entrada no vacía y oráculo independiente. En particular, help modal + Ctrl+C debe probar copia sin abrir N9; drag y F7 sin tecla de copia deben probar seed y cero workers; detail card debe probar su selección exacta; y las tres rutas R-COPY.6 deben comprobar seed antes y después de `n`. Corregir la descripción de R-COPY.2/4 para que sea fila + fallo. No hace falta duplicar el resto de ejemplos equivalentes.

### E3A-04 — minor — design-gap: falta fijar la conversión de la celda MAC a `str`

**Evidencia.**

- N2 declara `Optional[str]` y dice leer columna 0 y quitar glyph+espacio, pero no define la conversión del valor devuelto por `get_row_at` (`.dev-flow/2026-11-05-batch-103/inc-1b/codewire/graph-inc1b.md:170-176`).
- El productor MAC construye esa celda como Rich `Text`, concatenando glyph y nombre (`s19_app/tui/app.py:21059-21078`). `DataTable.get_row_at` devuelve los objetos celda almacenados, no una proyección `str` (`C:/Users/<user>/anaconda3/envs/s19env/Lib/site-packages/textual/widgets/_data_table.py:1011-1028`).
- A2L ya evita correctamente el `Text` pintado mediante `_a2l_row_key_to_tag` (`s19_app/tui/app.py:21490-21507,21806-21809`), por lo que el problema no se resuelve por simetría.

**Defecto.** Sin fijar `.plain`/`str`, una implementación puede devolver un objeto celda o aplicar operaciones de `str` a un tipo que no las tiene. También debe quedar claro que se retira el prefijo del productor, no dos caracteres arbitrarios de un nombre. Es un hueco de contrato, no una afirmación de que ya exista un fallo en producto.

**Propuesta concreta.** Fijar en N2: `painted = cell.plain if isinstance(cell, Text) else str(cell)`; comprobar uno de los prefijos glyph+espacio emitidos por `_populate_mac_datatable`; retirar exactamente ese prefijo y conservar el resto completo, incluidos espacios internos. Devolver `None` si el prefijo o el nombre final no cumplen el contrato. Añadir un ejemplo MAC de nombre largo (mayor que el ancho pintado) y con espacios, para demostrar que `get_row_at` conserva el nombre completo y que el resultado es `str`, sin glyph ni truncamiento.

### E3A-05 — minor — documentación/provenance: quedan referencias históricas presentadas como vigentes

**Evidencia.**

- El grafo dice que `E2-interfaces.md:28` conserva decisiones anteriores y las sustituye (`.dev-flow/2026-11-05-batch-103/inc-1b/codewire/graph-inc1b.md:3,31-35`), pero la interfaz final ya fija q=`help_quit` y body B en `E2-interfaces.md:27-29`.
- `E2-interfaces.md:34,39` atribuye geometría y la nota A2L al “second G2 export’s note” / export vigente. El export vigente tiene `notes={}` y `general_note=""` (`.dev-flow/2026-11-05-batch-103/evidence/G2/veredicto-b103-r2.json:17-18`), y la reconciliación final declara históricas esas notas (`E1-rulings.md:301-310`).
- El finding COVERAGE final vuelve a “17 nodes” y “1 app source file” (`graph-inc1b.md:727-730`), aunque el censo integrado es 24 nodos y dos archivos fuente, uno por grupo (`graph-inc1b.md:127-129`).

**Defecto.** No cambia el comportamiento, pero sí la autoridad que E4 puede citar y el alcance del censo integrado. En particular, una medida local de geometría puede conservarse como objetivo E4, pero no como nota vigente del segundo export.

**Propuesta concreta.** Eliminar la supuesta supersession de la interfaz final; describir body B/O-1=B como contratos ya alineados. Reetiquetar las notas G2 como históricas y no vigentes. Cambiar el cierre a “24 nodos integrados; 2 archivos fuente (1 por grupo)”, dejando el 17/1 sólo como subcenso del grupo A si resulta útil.

## Contratos Textual revisados y aceptados

- **`App.on_event`, press/release/click.** La lectura N3 antes de `await super().on_event(event)` está en el punto correcto: Textual procesa un `MouseDown` no forwardado antes de `screen._forward_event` (`C:/Users/<user>/anaconda3/envs/s19env/Lib/site-packages/textual/app.py:4060-4082`). El `Click` se sintetiza después del `MouseUp` (`.../textual/app.py:4084-4117`). Snapshot en N3 y posterior `Click` en N5 no compiten por la misma acción. La restricción E4 de postear press/release por el driver, sin Pilot ni pausa, es necesaria y está bien fijada en `02-test-cases.md:18`.
- **Selección de Screen y stock TextArea.** La separación es correcta: `Screen.selections` + `get_selected_text` para Static/RichLog/Label y `selected_text` para el stock JSON (`.../textual/screen.py:963-991`; `.../textual/widgets/_text_area.py:1647-1651`). El press de TextArea restablece su selección (`.../textual/widgets/_text_area.py:1948-1955`), de modo que la captura previa de N3 es imprescindible. La excepción de cadena vacía es E3A-01.
- **`get_widget_at`, style meta y row keys.** Las APIs usan coordenadas de pantalla y el compositor recupera el estilo/meta de la celda (`.../textual/_compositor.py:829-848,866-898`). `coordinate_to_cell_key` resuelve la row key actual y es válido mirar columna 0 aunque Tag esté en otra columna (`.../textual/widgets/_data_table.py:1278-1295`). Falta únicamente el guard de E3A-02.
- **`_CopyRowTable` MRO y A2L resize/highlight.** La cadena propuesta no desplaza `A2LTagTable.on_resize` ni `_highlight_row` (`s19_app/tui/app.py:1456-1515`). El dispatcher recorre la MRO y detiene handlers base cuando `prevent_default` está activo (`.../textual/message_pump.py:743-800`; `.../textual/message.py:131-148`). Por tanto, left-click puede continuar a `DataTable._on_click` y non-left puede suprimir sólo ese default.
- **DataTable click/RowSelected/no-jump.** El salto producto está en `on_data_table_row_selected`, no en `RowHighlighted` (`s19_app/tui/app.py:17089-17178`). `move_cursor` no llama `_post_selected_message` (`.../textual/widgets/_data_table.py:1214-1259`), mientras que el click estándar sobre una fila ya destacada sí selecciona (`.../textual/widgets/_data_table.py:2694-2702`). El diseño no-jump es viable, con la salvedad E3A-02.
- **Full-name A2L frente a MAC.** A2L toma el nombre del mapa canónico, no del `Text` recortado (`s19_app/tui/app.py:21490-21507,21806-21809`). MAC almacena el nombre completo en un Rich `Text`, por lo que la fuente es suficiente; falta la normalización de E3A-04.
- **`run_worker` y cardinalidad del tail.** No hay override `run_worker` en `S19TuiApp` (búsqueda estática sobre todo `s19_app/tui/app.py`). El método heredado acepta el awaitable y por defecto `start=True`, `exclusive=False`, `group="default"` (`.../textual/dom.py:496-542`): no cancela copias independientes. El tail actual es único (`s19_app/tui/os_clipboard_input.py:698-754`) y el integrado conserva su cambio a mirror cap + una executor write + un resultado (`graph-inc1b.md:368-398`). La llamada base desligada evita reentrar en N1; boxes siguen directos (`os_clipboard_input.py:891-944`; `capped_text_area.py:242-308`).
- **q=`help_quit`, Ctrl+Q y palette Quit.** App aporta Ctrl+C no prioritario a `help_quit` y Ctrl+Q prioritario a `quit` (`.../textual/app.py:454-464`). El binding q actual está en `s19_app/tui/app.py:2895-2903`; el builder proyecta cada binding a una entrada y deduplica por acción (`app.py:10191-10232`), así que N10 sí necesita la proyección especial `PaletteEntry("Quit", "quit")`, no una entrada añadida. `action_quit` y `_answer_quit` permanecen aptos para idle/busy (`app.py:23017-23045`).
- **Busy/modal/duplicate quit.** La cadena modal corta antes del fallback App (`.../textual/screen.py:448-455`), por lo que q y Ctrl+C no apilan N9. Ctrl+Q sigue prioritario y `action_quit` ya reconoce `_QuitQuestionScreen` en todo el stack (`s19_app/tui/app.py:23023-23035`). No hace falta un binding prioritario nuevo.
- **Body B y herencia.** `_CopyQuitScreen(_QuitQuestionScreen)` hereda el constructor y `PRIMARY_BUTTON="confirm_no"`; la subclase existente está en `s19_app/tui/app.py:456-470`. Reutilizar `_answer_quit` mantiene Stay/Quit y pending quit coherentes (`app.py:23037-23045`). Los textos de graph, requirements e interfaces coinciden exactamente con body B.
- **Integración clipboard.** El grafo contiene 12 implementation + 12 context = 24 nodos (`graph-inc1b.md:127-129`), el helper nuevo y el tail cambiado (`graph-inc1b.md:353-398`), y sus 16 edges (`graph-inc1b.md:499-526`). El viejo context block del tail fue sustituido por el delta B, no ocultado por first-node-wins. R-PASTE.12 tiene ejemplos de regresión cap para ambas clases de box (`graph-inc1b.md:390-393`); R-PASTE.1 queda unido al artifact real de copia en AT (`graph-inc1b.md:398,441-447`).

## Cobertura revisada: 22 requisitos, 100 casos y AT

El aritmética del ledger es **82 R-COPY + 9 clipboard/security citados + 9 dialog/quit citados = 100 casos activos** (`02-test-cases.md:144`). Las 22 filas activas son R-COPY.1, .2, .4 y .6–.24; R-COPY.3 y .5 permanecen retiradas (`01-requirements.md:83-106,119-123`). La cobertura siguiente distingue especificación de ejemplos: no atribuyo PASS de ejecución a ninguno.

| Ámbito | Casos | Cobertura de diseño revisada |
|---|---:|---|
| R-COPY.1 | 6 | Ruta N1 válida; ejemplos explícitos hex/JSON y cuatro fuentes pendientes de E3A-03. |
| R-COPY.2 | 4 | Cubierta por N1+tail en key/right-click/row/fallo; corregir la descripción /4 de E3A-03. |
| R-COPY.4 | 3 | Cubierta con clicked-row distinto de highlighted-row, A2L completo y MAC; precisar E3A-04. |
| R-COPY.6 | 5 | Seeds y diálogo heredado son viables; faltan brazos de E3A-03 y la selección vacía de E3A-01. |
| R-COPY.7, .8, .9, .10 | 15 | Cubiertos con textos exactos, LF final, cap 65,536/65,537, total original y cardinalidad base/write/OSC 52/notice (`graph-inc1b.md:353-397`). |
| R-COPY.11 | 4 | Highlight y left-click sí; drag y F7 sin copia pendientes de E3A-03. |
| R-COPY.12, .13, .14, .15 | 22 | Cobertura representativa fuerte para whole/cross-view selection, JSON/modal, press+release, header/empty y clearing; detail card pendiente de E3A-03 y relleno de fila de E3A-02. |
| R-COPY.16, .17, .18, .19, .20, .21, .22, .23, .24 | 23 | Ejemplos para body B, respuestas, énfasis, busy/modal, highlight/no-jump, q, Ctrl+Q y paleta. R-COPY.16/.20 quedan abiertos por E3A-01. |
| R-PASTE.9, .10, .13, .14 y R-TUI-043.13 | 9 | Cubiertos por warning único, WARNING sin payload, timing/executor y tres rutas de copia (`graph-inc1b.md:385-397`). |
| R-DLG.1, .2, .6, .9, .11, .12 (dos), .14 y R-QUIT.8 | 9 | Cubiertos por modal heredado, foco Stay, labels, respuestas, opener y quit diferido (`graph-inc1b.md:248-274`). |

**AT.** Las siete fuentes × cuatro celdas = **28 celdas** están definidas con T1=primera línea una vez y T2=todo una vez, por P1/P2 (`02-test-cases.md:124-138`). El grafo repite esa regla para todas y exige copia real + separate read + terminal paste (`graph-inc1b.md:131-143`). Los ejemplos explícitos de artifact emitido cubren T1/P2 (`graph-inc1b.md:398,441-447`); al escribir E4 debe materializarse también al menos un T2/P2 multilínea no uniforme, porque el ledger ya identifica el riesgo histórico de duplicación (`02-test-cases.md:142`). Esto es una precisión de implementación de E4, no un nuevo requisito.

**AT-I1b-8** queda correctamente manual y `not_run`, con seis pasos Windows Terminal y sin acceso del agente al clipboard del operador (`02-test-cases.md:140`). No lo computo como evidencia superada.

## Condiciones de cierre para una nueva revisión

1. Corregir N1 para propagar la selección vacía mediante `SkipAction` y agregar las armadas idle/modal de E3A-01.
2. Decidir y fijar `out_of_bounds` coherentemente en N2/N5, con control positivo/negativo sobre la misma fila de E3A-02.
3. Cerrar las omisiones de ejemplos y la descripción errónea de E3A-03; precisar MAC `Text → str` de E3A-04.
4. Alinear provenance y censo integrado de E3A-05.

Con E3A-01 y E3A-02 abiertos, el entregable para E4 no está aprobado. Una vez corregidos y revisados esos dos contratos, los tres minor restantes sí podrían evaluarse como notas si reciben disposición explícita; no los doy por cerrados en este informe.
