# E5 fix2 — Carril C: divulgación, censo y outer

Base: HEAD `305e5892` más el working tree recibido y las correcciones integradas por los demás carriles. Se conservó el trabajo previo. Este carril escribió únicamente los tres archivos asignados y este informe; no editó producto, helper compartido, Windows, tail ni los nodeids de las seis familias WinCI.

## 1. Qué cambió

- **D-02:** el control directo recorre mensaje, excepción y stack para todas las formas de divulgación en Windows y tail, incluidas XML textual, prefijos XML, CR numérico y atributos. El outer añade un caso XML para ambos detectores y un brazo `log-xml` que atraviesa la llamada WinCI real `/102` con mocks. El hijo conserva las cuatro auditorías: stdout, stderr, JUnit crudo y JUnit parseado.
- **D-05:** el mismatch se obtiene ejecutando `_probe_once()` con boundaries inertes. El known-bad conserva el `stage` del `_ProbeDetail` real y sustituye sólo su texto por el canario; ya no fabrica puntuación para obtener la clasificación deseada.
- **D-06:** el escáner censa las diez categorías `copy-secret`, `text-secret`, `right-click-secret`, `selection-secret`, `nul-suffix`, `seed`, `hostile`, `matrix-p1`, `matrix-p2` y `control-payload`. Incluye todos los secretos señalados, las seis variantes de control compartidas y las familias anteriores. `_forms()` deriva también prefijos de las representaciones. Los known-bad cubren las diez categorías × raw/prefix/repr/escape/XML × transcript/JUnit, con diagnósticos que no reproducen los valores inyectados.
- **C-01R:** un oracle captura el comando real producido por `other_program_write()` y exige `PresentationCore` antes de `[Windows.Clipboard]::SetText($text)`, además de excluir `System.Windows.Forms`.
- **Transporte:** los mocks de `subprocess.run` y los resultados simulados usan stdin/stdout/stderr binarios, Base64 estricto y rechazo del modo texto. El outer sigue la costura actual de tail: cinco brazos —dos hostile, Unicode, CR y CRLF—, UTF-8 con `errors="replace"`, aviso calculado por el producto y marcadores diferenciados para fallo de transporte y fallo XML de logs.

El outer espera ahora **14 fallos deliberados**, incluidos `test_log_xml` y `test_hostile_log_xml`, sin convertirlos en errores de colección.

## 2. Archivos modificados

- `tests/test_b103_e5_safety.py` — detalle real del probe, controles XML, outer WinCI, mocks binarios y oracle C-01R.
- `tests/support/b103_artifact_safety.py` — censo completo de canarios y formas con prefijo.
- `tests/test_b103_winci_gate.py` — censo independiente y known-bad de cada familia/forma/superficie sin diagnósticos sensibles.
- `.dev-flow/2026-11-05-batch-103/inc-1b/E5-fix2-disclosure.md` — este informe.

## 3. Cómo probar

En el clon Linux EXACTO del árbol integrado, el orquestador puede ejecutar la selección acotada:

```bash
python -m pytest -q tests/test_b103_e5_safety.py tests/test_b103_winci_gate.py
```

El outer debe conservar su hijo rojo y terminar verde el padre: 14 fallos esperados en el hijo, cero errores y ausencia del canario en las cuatro superficies. Las puertas WinCI y de mutantes son ejecuciones separadas; AT-I1b-8 permanece manual.

## 4. Resultados de verificación

No ejecuté pytest, colección pytest, probes, aplicación, PowerShell, clipboard, workflow, baterías ni mutantes en Windows. Tampoco hice mutaciones Git.

Comprobaciones estáticas realizadas:

```text
tests/test_b103_e5_safety.py: static compile OK
tests/support/b103_artifact_safety.py: static compile OK
tests/test_b103_winci_gate.py: static compile OK
Outer census OK: 14 deliberate failures, including log XML and real hostile WinCI call
SECRET census OK: 7 distinct tokens; missing=[]
Shared payload census OK: P1, P2 and all six control variants
Manifest test-name surfaces OK: [51, 8, 13, 31, 28, 2]
git diff --check -- <tres archivos asignados>: exit 0
```

El censo estático usó exactamente las seis rutas del manifiesto: `clipboard_windows`, `clipboard_matrix`, `copy_views`, `clipboard_tail`, `copy_quit_dialog` y `copy_paste_matrix`, más los payloads del helper. Una comparación inicial contra HEAD no se usó como veredicto de nodeids porque el working tree recibido ya contenía el test E5 de tail ausente en HEAD; la comprobación aplicable contra el manifiesto congelado conservó los 133 nombres `test_*` y su orden.

Estos resultados son compilación, AST, censos y whitespace; **no son un GREEN dinámico**.

## 5. Riesgos

- Al cerrar esta intervención, `tests/support/b103_clipboard.py` todavía presenta `text=True`, `encoding` y `errors` en `_run_system_powershell`. Es un archivo fuera de alcance. Los mocks nuevos lo rechazan deliberadamente: la selección dinámica requiere que su propietario integre stdin/stdout binarios y decodificación explícita antes de declarar PASS.
- Los payloads de control con caracteres XML inválidos pueden producir también `JUNIT_XML_UNREADABLE`; es un resultado fail-closed adicional y no sustituye la violación `CONTROL_CANARY` exigida por cada known-bad.
- La ejecución outer con mocks demuestra la ruta escrita y la redacción de artefactos, no el comportamiento del clipboard ni de PowerShell reales.

## 6. Pendientes

- Integrar la corrección binaria del helper compartido por su carril propietario y ejecutar la selección anterior en el clon Linux EXACTO.
- Ejecutar posteriormente WinCI real y los mutantes previstos; este informe no cierra esas puertas ni la aceptación manual AT-I1b-8.
- D-03 y el archivo/redacción de evidencia final permanecen bajo su orquestación; no se declara su cierre por estas comprobaciones estáticas.

## 7. Siguiente tarea

**Orquestación de integración E5-fix2:** completar el contrato binario del helper en su carril correspondiente y ejecutar `tests/test_b103_e5_safety.py` + `tests/test_b103_winci_gate.py` en el clon Linux EXACTO, archivando stdout, stderr y JUnit para revisión.
