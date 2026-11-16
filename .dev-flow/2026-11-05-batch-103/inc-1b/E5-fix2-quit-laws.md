# E5 fix 2 — Carril D: leyes de timing en quit

Base: `305e5892` más el working tree recibido. Se conservó todo el trabajo previo. Esta pasada sólo editó `tests/test_b103_copy_quit_dialog.py` y añadió este informe; no modificó `tests/test_suite_hygiene.py`, `tests/support/timing.py`, rutas quit, producto, evidencia ni archivos de otros carriles.

## Cierre acotado de los dos fallos propios

### Marcas del carril serial

Se añadió el decorador directo `@pytest.mark.serial_timing`, sin `pytestmark` de módulo o clase y sin parametrizaciones nuevas, a estos seis nodeids ya existentes:

- `tests/test_b103_copy_quit_dialog.py::test_r_copy_17_1_y_quits_within_one_second`
- `tests/test_b103_copy_quit_dialog.py::test_r_copy_17_2_tab_enter_on_quit`
- `tests/test_b103_copy_quit_dialog.py::test_r_copy_17_3_click_quit`
- `tests/test_b103_copy_quit_dialog.py::test_r_copy_24_1_ctrl_q_quits_immediately`
- `tests/test_b103_copy_quit_dialog.py::test_r_copy_24_2_palette_quit_quits_immediately`
- `tests/test_b103_copy_quit_dialog.py::test_r_dlg_12_102_y_presses_quit`

Los decoradores están inmediatamente antes de las definiciones actuales en `tests/test_b103_copy_quit_dialog.py:631`, `:642`, `:657`, `:862`, `:878` y `:991`. No se añadió la marca a ningún otro test del módulo.

### Límite superior con margen registrado

El árbol recibido ya calculaba `allowed = report_margin(label, elapsed, bound)`, pero el contrato AST de R-TST-040/041 exige que `report_margin(...)` sea directamente la expresión del límite en la comparación; el alias `allowed` seguía siendo detectado como bound sin reportar.

En `_answer_and_time` (`tests/test_b103_copy_quit_dialog.py:451-460`) se sustituyó ese alias por:

```python
assert elapsed <= report_margin(label, elapsed, bound), (elapsed, bound)
```

Así el helper compartido se invoca exactamente una vez y registra el margen con el label estable ya existente, derivado del nombre del nodo en `PYTEST_CURRENT_TEST` y con fallback `quit_answer`. Se conservan `bound = timing_bound(1.0)`, su uso en `_wait_exit`, el factor CI del helper compartido, la comparación `<=`, el assert de salida y el retorno de `elapsed`. `report_margin` devuelve el mismo `bound`, por lo que el umbral y el comportamiento temporal no cambian.

No hubo docstrings que describieran el alias o el carril paralelo anterior; los docstrings existentes de los seis tests y del módulo siguen siendo exactos y se conservaron.

## Verificación estática realizada

No se ejecutó pytest, colección pytest, probes, aplicación, PowerShell, clipboard, WinCI, mutantes, AT manual ni baterías. Tampoco hubo mutaciones Git.

1. `git diff --check -- tests/test_b103_copy_quit_dialog.py` — exit 0.
2. Script `python -B` de sólo lectura, con AST y el censo puro `tests.support.suite_census`, sin importar aplicación ni tests — exit 0:
   - las 28 definiciones `test_*` del módulo conservan exactamente nombres y orden frente a `HEAD`; los seis decoradores no alteran nodeids;
   - el conjunto de marcas `serial_timing` del módulo es exactamente los seis tests solicitados;
   - `_answer_and_time` contiene una sola llamada `report_margin(label, elapsed, bound)`, situada directamente en el bound del assert, y conserva `timing_bound(1.0)`;
   - `suite_census.timing_arms(Path("tests"))` reconoce los seis brazos;
   - `suite_census.unreported_upper_bounds(...)` ya no devuelve ningún sitio de `tests/test_b103_copy_quit_dialog.py`.

Estas comprobaciones cierran estáticamente las dos infracciones propias descritas; no equivalen a una ejecución GREEN de las leyes ni de las seis familias.

## Pendiente para el orquestador

Ejecutar en el clon Linux EXACTO del árbol local las dos leyes afectadas y la selección dinámica prevista, incluidos los seis tests en el carril `serial_timing`. Quedan fuera de este cierre cualquier veredicto WinCI, mutantes y AT manual, conforme a la instrucción recibida.
