# Inc 1b — revisión de ejecutabilidad de E5-mutant-plan

## Alcance y veredicto

Revisión **sólo estática** sobre HEAD `25563883f24ad96ee52881628bb06d56b4e0c597`. Se contrastó `inc-1b/E5-mutant-plan.md` con `s19_app/tui/app.py`, `s19_app/tui/os_clipboard_input.py`, `s19_app/tui/screens.py`, los cuatro tests nombrados y `.github/workflows/clipboard-windows.yml`. No se leyó ni modificó `02-test-cases.md`; no se ejecutaron tests, mutantes ni WinCI.

**Veredicto: no ejecutar el plan tal cual.** La estructura de mutantes es en general sólida, pero hay que corregir antes:

1. la revisión usada para las copias;
2. ocho selectores pytest que no existen como node IDs;
3. los alias de rutas de producto, si la aplicación será mecánica;
4. la repetición innecesaria del baseline completo y el riesgo sin cota de GC-C14.

Conteos de la inspección:

- **71 filas:** GA 16 + GT 8 + GQ 15 + GC 19 + GN 9 + GW 4; **67 L + 4 W**.
- **0 IDs duplicados** y ninguna pareja de filas con el mismo cambio sobre el mismo anchor.
- **97 referencias a tests en las filas, 55 funciones distintas; 0 funciones inexistentes** según inspección AST de los cuatro archivos.
- **8 filas con selectores parametrizados inexistentes**, que deben expandirse a **23 node IDs** reales. Las otras 63 no tienen este defecto.
- **0 mutantes demostrablemente equivalentes por inspección** entre las 71 filas. Esto no predice kills ni permite declarar equivalencia de futuros supervivientes.
- Las 11 exclusiones de `inc-1b/E5-mutant-plan.md:121-135` correctamente no se contabilizan como mutantes prometibles; no deben reincorporarse sin nuevos oráculos.

## 1. Bloqueo: las copias no parten del HEAD revisado

El plan declara `e8f8e3d189ab60eb24b05e7d917b7cd32311468e` y ordena usar esa revisión en cada copia (`inc-1b/E5-mutant-plan.md:3`, `:7`). El HEAD solicitado es `25563883`.

El diff entre ambas revisiones **no cambia los cuatro tests ni los archivos de producto citados**, por lo que los anchors y los oráculos revisados siguen siendo los mismos. Sin embargo, sí cambia `.github/workflows/clipboard-windows.yml`:

- la revisión actual incluye `app.py`, los cuatro tests nuevos y sus rutas en los disparadores (`.github/workflows/clipboard-windows.yml:9-20`, `:23-33`);
- la batería actual ejecuta explícitamente Tail y `test_b103_copy_paste_matrix.py` (`:63-64`);
- el timeout de job es ahora 60 minutos (`:39-41`).

En la base antigua, el workflow no ejecutaba Tail ni la matriz. Por tanto, las cuatro filas GW no pueden apoyarse en ese workflow antiguo sin otro mecanismo explícito.

**Corrección previa:** fijar `25563883f24ad96ee52881628bb06d56b4e0c597` como único baseline de producto/tests/workflow y origen de todas las copias. Registrar ese hash en cada manifiesto. Si se decide conservar deliberadamente `e8f8e3d`, hay que definir otro ejecutor para GW y dejar de presentar las copias como baseline del HEAD actual.

## 2. Bloqueo: ocho selectores no son node IDs de pytest

Los parámetros reales se declaran individualmente, por ejemplo en `tests/test_b103_copy_views.py:464-469`, `:527-528`, `:569-570`, `:648-653`, `:857-858`, `:874-875` y `:894-895`. Una coma, `y` o `…` dentro de un único par de corchetes no selecciona esos casos. Tampoco vale presentar el texto compuesto como si fuera un node ID literal.

Cada fila siguiente debe sustituirse por varios node IDs completos, uno por caso, o por una expansión mecánica explícitamente definida:

| Fila del plan | Test actual | IDs que deben invocarse por separado |
|---|---|---|
| GA-A04 (`inc-1b/E5-mutant-plan.md:23`) | `tests/test_b103_copy_views.py:528` | `[R-COPY.4/1]`, `[R-COPY.4/3]` |
| GA-A06 (`:25`) | `tests/test_b103_copy_views.py:528` | `[R-COPY.4/1]`, `[R-COPY.4/3]` |
| GA-A14 (`:33`) | `tests/test_b103_copy_views.py:858` | `[R-COPY.15/1]`, `[R-COPY.15/2]`, `[R-COPY.15/3]` |
| GT-T03 (`:43`) | `tests/test_b103_copy_views.py:875` | `[R-COPY.21/1]`, `[R-COPY.21/2]` |
| GT-T04 (`:44`) | `tests/test_b103_copy_views.py:895` | `[R-COPY.22/1]`, `[R-COPY.22/2]` |
| GT-T08 (`:48`) | `tests/test_b103_copy_views.py:528` | `[R-COPY.4/1]`, `[R-COPY.4/2]`, `[R-COPY.4/3]` |
| GC-C01 (`:74`) | `tests/test_b103_copy_views.py:469` | `[R-COPY.1/1]`, `[R-COPY.1/2]`, `[R-COPY.1/3]`, `[R-COPY.1/4]`, `[R-COPY.1/5]`, `[R-COPY.1/6]` |
| GC-C03 (`:76`) | `tests/test_b103_copy_views.py:570` | `[R-COPY.10/1]`, `[R-COPY.10/2]`, `[R-COPY.10/3]` |

Ejemplo de forma válida, sin abreviar el archivo:

`tests/test_b103_copy_views.py::test_r_copy_4_full_row_names[R-COPY.4/1]`

y, como otro argumento/node ID independiente:

`tests/test_b103_copy_views.py::test_r_copy_4_full_row_names[R-COPY.4/3]`

Los alias V/Tail/Q/AT sí están definidos (`inc-1b/E5-mutant-plan.md:14`) y NUL-1/2/3 también (`:96`), pero el ejecutor debe expandirlos a rutas reales; no son comandos pytest por sí mismos. GA-A04 conserva además su oráculo Tail, ya válido como función.

## 3. Anchors: las líneas existen, pero faltan alias de producto

Las ubicaciones con línea y símbolo revisadas existen en HEAD. Entre otras:

- extracción/gesto: `s19_app/tui/app.py:23161-23200`, `:23202-23294`, `:23296-23368`;
- tabla: `s19_app/tui/app.py:1504-1584` y MAC en `:8993-8995`;
- quit/palette: `s19_app/tui/app.py:3023-3031`, `:10358-10376`, `:23370-23445`;
- tail/NUL: `s19_app/tui/os_clipboard_input.py:698-836`;
- paste directo: `s19_app/tui/os_clipboard_input.py:916-941`;
- PowerShell: `s19_app/tui/os_clipboard_input.py:415-457`.

Los anchors repetidos quedan desambiguados por símbolo y línea. Por ejemplo, los dos `if meta.get("out_of_bounds", False)` son sitios distintos y correctamente identificados en `s19_app/tui/app.py:1569` y `:23259`; GT-T01 y GT-T08 no son duplicados porque aplican cambios opuestos en `_right_click_text`.

El defecto está en la regla de rutas: el plan dice que toda ruta de producto es relativa a la raíz (`inc-1b/E5-mutant-plan.md:14`), pero después usa `app.py` en **40 filas** y `os_clipboard_input.py` en **20** (incluida GC-C15, sin `:línea`). Literalmente, esos archivos no están en la raíz.

**Corrección previa para automatización:** declarar en las reglas:

- `app.py` = `s19_app/tui/app.py`;
- `os_clipboard_input.py` = `s19_app/tui/os_clipboard_input.py`.

Con esos dos alias no hace falta reescribir las 60 filas. Conviene también fijar la posición de inserción de GQ-Q10 dentro de `S19TuiApp.BINDINGS` (`s19_app/tui/app.py:3023-3031`) para que el parche sea reproducible; el anchor de la lista sí existe.

## 4. Alcanzabilidad y observabilidad de los mutantes

No encontré una fila cuyo cambio esté muerto por construcción ni un mock que oculte sistemáticamente el sitio mutado:

- **GA/GT:** los tests construyen la app real y envuelven entrada, tail, base, writer y OSC 52 (`tests/test_b103_copy_views.py:65-112`); los gestos se inyectan en `app.on_event` (`:259-332`) y los asserts comprueban payload/cardinalidad (`:241-251`). Los anchors de extracción y eventos están en el camino ejecutado.
- **GQ:** los recorders envuelven el método real de copia, workers y `push_screen` (`tests/test_b103_copy_quit_dialog.py:175-211`). Los tests de respuesta, modal y foco comprueban estado observable (`:565-616`, `:643-733`, `:739-822`, `:848-922`). GQ-Q15 tiene además un oráculo AST explícito de una construcción N9 (`:925-957`).
- **GC/GN:** `_instrument` registra override/tail/base/writer/helper/proceso y OSC 52 (`tests/test_b103_clipboard_tail.py:120-207`). Los oráculos `_success`, `_failure` y `_refusal` fijan cardinalidades, payloads y notices (`:246-297`). Los cambios de cap, NUL, logging y transporte alcanzan esos asserts; el transporte hostile es una simulación Linux declarada, no evidencia Windows (`:954-1027`).
- **GW-W01:** exige writer fuera del hilo UI y ticks acotados (`tests/test_b103_clipboard_tail.py:1179-1209`).
- **GW-W02:** el segundo writer ya cambia el contador determinista, aunque el tiempo quede dentro del límite (`:1125-1129`).
- **GW-W03/W04:** la matriz compara el contenido final exacto de T1 (`tests/test_b103_copy_paste_matrix.py:398-413`), por lo que concatenar líneas o insertar dos veces es observable.

Las repeticiones de oracle no son filas duplicadas: por ejemplo, GA-A15 cambia un retorno normal, GA-A16 agenda un worker antes de volver a lanzar `SkipAction`, y GC-C04/GC-C05 distinguen ausencia de cap de off-by-one. Sus efectos son diferentes.

### Excepción de coste/seguridad: GC-C14

Cambiar la llamada no ligada `App.copy_to_clipboard(...)` por `app.copy_to_clipboard(...)` reintroduce recursión de workers (`s19_app/tui/os_clipboard_input.py:812`, `s19_app/tui/app.py:23200`). Los conteos de `tests/test_b103_clipboard_tail.py:246-255` permiten observar la cardinalidad, pero un timeout sin límite de recursos no es un oráculo suficiente y puede generar mucho trabajo antes de abortar.

**Corrección previa:** conservar la regla especial de `inc-1b/E5-mutant-plan.md:12`, pero añadir una cota externa concreta de tiempo y workers/iteraciones, capturar `override/tail` al alcanzarla y cancelar el árbol aislado. Si no se puede imponer esa cota, dejar GC-C14 pendiente; no usar el timeout desnudo como kill. No hace falta ejecutar toda la batería para observar este mutante.

## 5. Baseline Linux 122/19 y agrupación de copias

La aritmética del baseline es consistente con la parametrización y los skips estáticos:

| Archivo | Nodos | Criterio Linux |
|---|---:|---:|
| `tests/test_b103_copy_views.py` | 54 | 54 passed, 0 skipped |
| `tests/test_b103_clipboard_tail.py` | 30 | 26 passed, 4 skipped |
| `tests/test_b103_copy_quit_dialog.py` | 28 | 28 passed, 0 skipped |
| `tests/test_b103_copy_paste_matrix.py` | 29 | 14 passed, 15 skipped |
| **Total** | **141** | **122 passed, 19 skipped** |

Desglose de los 19 skips:

- 14 P2 de la matriz, uno por cada par source/target (`tests/test_b103_copy_paste_matrix.py:416-447`), omitidos fuera de WinCI por `_coverage_or_skip` (`:28-46`);
- AT-I1b-8 manual (`:456-463`);
- R-PASTE.13/101 y R-PASTE.14/101–103, que llaman a `_winci_ready_or_skip` (`tests/test_b103_clipboard_tail.py:1030-1037`, `:1105-1107`, `:1188-1207`).

Esto valida **el criterio nominal**, no el resultado de una ejecución. Deben conservarse las condiciones de admisión de `inc-1b/E5-mutant-plan.md:9-12`: cualquier fallo, skip adicional o colección distinta invalida el baseline.

La separación **67 L / 4 W** es correcta. W01/W02 dependen de holder/reader y writer Windows; W03/W04 usan P2, que Linux omite. No deben trasladarse a L ni interpretarse sus skips como muertes.

### Evitar 67 baselines completos redundantes

Si «antes de mutar» se interpreta como ejecutar los 141 nodos en cada una de las 67 copias L, serían **9.447 nodos recolectados: 8.174 passed + 1.273 skipped**, antes de los pases previos y posteriores de cada test objetivo. Es un coste evitable sin relajar el criterio.

Procedimiento recomendado:

1. Ejecutar una sola vez la batería completa en una copia pristine del hash fijado y del mismo entorno L; archivar recuento, hash y manifiesto.
2. Crear desde esa copia verificada los 67 árboles independientes, uno por `<grupo>/<id>`, con HOME/tmp aislados y `DISPLAY`/`WAYLAND_DISPLAY` sin definir.
3. Verificar hash/contenido pristine en cada árbol y ejecutar allí el objetivo antes del cambio, como ya exige el plan.
4. Aplicar exactamente una fila por árbol y ejecutar después sus node IDs corregidos. Nunca reutilizar un árbol ya mutado ni compartir estado de clipboard.

Si se exige deliberadamente un baseline completo por árbol, el coste anterior debe presupuestarse; no es necesario para demostrar que todos parten del mismo baseline inmutable.

## 6. Correcciones mínimas antes de autorizar ejecución

- [ ] Cambiar el hash de las copias a `25563883f24ad96ee52881628bb06d56b4e0c597` o especificar otro ejecutor para GW.
- [ ] Expandir los ocho selectores compuestos a 23 node IDs reales y expandir también los alias documentados.
- [ ] Declarar los dos alias de producto para las 60 rutas abreviadas; precisar la inserción de GQ-Q10.
- [ ] Fijar una cota de recursos y evidencia de cardinalidad para GC-C14, o dejarlo pendiente.
- [ ] Ejecutar y registrar una única admisión Linux pristine de **122 passed + 19 skipped** por hash/entorno, sin convertir los 19 skips en comportamiento verificado.
- [ ] Mantener GW separado, con probe y holder/reader sin skip; ningún skip, timeout desnudo o fallo de colección cuenta como kill.

Tras esas correcciones, las 71 filas tienen anchors y oráculos estáticamente identificables. Esta revisión no afirma que vayan a morir: sólo que los cambios son alcanzables y que los tests nombrados contienen observables capaces de discriminarlos.

## Addendum de disposición — baseline actual `0d4d4e7c`

La revisión anterior se conserva como evidencia histórica; este addendum no la reescribe ni declara una nueva revisión independiente. Para el HEAD solicitado en esta corrección, `0d4d4e7c800b27040769a1a10117e62884cc7326`:

- Plan y `evidence-e5/mutants/manifest.json` fijan ese hash completo. La diferencia `25563883..0d4d4e7c` sólo afecta al ledger/documentación, no a producto, tests ni workflow.
- Las ocho filas GA-A04, GA-A06, GA-A14, GT-T03, GT-T04, GT-T08, GC-C01 y GC-C03 contienen **23 expansiones por fila (19 node IDs distintos)**, todos completos. La colección Linux estática de los cuatro archivos dio **141 node IDs** y todos los seleccionados existen. Esto no es una ejecución del baseline 122/19.
- Los alias `app.py`/`os_clipboard_input.py` cubren exactamente **40+20=60 rutas abreviadas**; el manifiesto usa siempre rutas completas. Q10 fija su inserción entre los bindings `g` y `q`.
- El recuento mecánico, incluyendo NUL y todas las referencias separadas por comas o «y», es **129 referencias de tests, 76 node IDs distintos y 57 funciones**. La comparación con el plan original del commit no añade ni elimina funciones.
- Hay **66 mutantes L ejecutables**. GC-C14 queda deliberadamente pendiente/BAD sin aplicar, porque todavía no existe la cota externa de workers/iteraciones con captura de cardinalidad exigida. GW-W01–W04 permanecen fuera del runner Linux.
- `run_mutants.py` implementa baseline completo una vez por grupo, copias independientes, un reemplazo y `applied_count=1`, pre/post/post-restore de node IDs específicos, KILLED/SURVIVED/CRASH/BAD, timeout con cancelación del grupo de procesos, hash de restore, bytecode deshabilitado y skips exactos del baseline.
- La validación estática final y el self-test de fixtures son PASS. Los fallos previos del propio harness (import aislado, censo erróneo de 23/19 y colección global, y clasificación del exit 4 de pytest) se conservan en `evidence-e5/mutants/linux/` junto con los transcripts finales.

**Ejecutados en esta corrección: 0/71 mutantes de producto y 0 tests de producto.** Sólo hubo lectura estática, `pytest --collect-only` de los cuatro archivos y tests de fixtures desechables del harness. La admisión 122/19 por grupo sigue pendiente para la ejecución futura; los cuatro GW dependen además del NO-GO WinCI independiente.
