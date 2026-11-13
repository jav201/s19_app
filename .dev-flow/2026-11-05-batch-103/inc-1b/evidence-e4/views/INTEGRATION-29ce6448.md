# VIEWS/GESTURES — corrección E4 sobre integration 29ce6448

## Alcance

- Worktree: `<LOCAL_HOME>/Github/s19_app-b103-inc1b-integration`, HEAD `29ce6448e49cc8a67ecf7a5a7c38a4f31833368c`.
- Solo se modificó `tests/test_b103_copy_views.py` y esta carpeta de evidencia. No se cambió producto, otros tests, ledger ni git refs; no hubo commits ni push.
- Clone Linux de ejecución: `<HOME>/work/b103-e4-views-29ce-MPzaTc/tree`, con el mismo HEAD y solo el test superpuesto.
- SHA-256 del test final: `4fd621a0d51e2b690fda6d3f5483805d65a1e2c31bdd7a4a7c13fb3ec4dc6b06`.
- La evidencia RED previa en `e2e93548` se conserva sin reescribir. Este reporte y sus transcripts son evidencia adicional sobre integration.

## Diagnóstico de run1: espera e instrumentación del tail

Run1 observó `entry == [expected]` y `tail == []` en R-COPY.12/7 y .12/8. Había dos problemas de test:

1. `_right_click` terminaba con un número fijo de pausas, que no garantizaba entrada y finalización del worker asíncrono.
2. `S19TuiApp.copy_to_clipboard` resuelve el tail mediante el alias global de `s19_app.tui.app`. El fixture solo envolvía `os_clipboard_input._mirror_and_write_os_clipboard`, por lo que podía no registrar la llamada aunque el tail real avanzara.

Corrección:

- El wrapper del tail registra `tail` al entrar y `tail_done` en `finally`.
- El fixture también envuelve `original_entry.__globals__["_mirror_and_write_os_clipboard"]` únicamente cuando ese alias es idéntico al tail original; no importa símbolos nuevos de producto.
- `_wait_copy_tail` se ejecuta tras right-click/right-drag solo si existe `entry`, espera condicionadamente `tail_done` mediante `_wait` y después hace dos pausas para asentar las notices.
- Las aserciones siguen exigiendo los valores exactos de entry/tail/base/writer/OSC 52/app clipboard/cardinalidad. La espera no sustituye ningún oráculo.

## TQR-03: R-COPY.15 exige primero la copia

R-COPY.15/1–3 captura la selección antes del gesto y llama `_assert_single_copy(session, expected)` antes de comprobar que la selección quedó vacía. Por tanto, eliminar la copia del release pero conservar el clearing de Textual ya no puede producir un falso pase.

## TQR-04: detail-card, cobertura parcial explícita

Se eliminaron la escritura directa de `screen.selections`, `ScreenSelection`/`Offset` y el expected basado en `render()[1:3]`.

El test ejecuta el drag real y toma expected exclusivamente de `screen.get_selected_text()` después del drag. En esta versión de Textual el gesto disponible produce cinco líneas no vacías y distinguibles, no las dos del ejemplo. La copia/tail se verifica con esa selección real, pero **el brazo driver de dos líneas queda `partial` para R-COPY.1/4 y R-COPY.12/3**. No se declara que ese ejemplo geométrico esté cubierto ni se fabrica una selección para cerrarlo.

## E4CR-01: `MouseMove.is_forwarded=True`

R-COPY.11/5, .13/7–8 y .14/7–8 ejecutan ahora el control no reenviado y un brazo con cada `MouseMove` marcado `_set_forwarded()`. `MouseDown` y `MouseUp` siguen no reenviados. Las aserciones conservan seeds y exigen entry/tail/base/writer/OSC 52/notices en cero.

Targeted Linux final, `forwarded-red-29ce6448.txt`:

- 12 collected, 2 failed, 10 passed, 0 skipped; exit 1; 119.27 s.
- R-COPY.13/8 falla porque el brazo forwarded de salida/regreso copia `SECRET-SELECTION-MARKER row 0\nsecond row\nthird row`.
- R-COPY.14/8 falla porque ese mismo gesto emite `Copied 3 lines to the clipboard.`.
- R-COPY.11/5, .13/7 y .14/7 pasan: al release en B, la diferencia de offset ya bloquea la copia incluso en este producto; no son evidencia de que salida/regreso esté corregido.
- R-COPY.12/7, .12/8, R-COPY.15/1–3, R-COPY.1/4 y .12/3 pasan, verificando la espera, la copia previa al clearing y la extracción desde el drag no reescrito.

## Familia completa Linux

`family-linux-29ce6448.txt` contiene la corrida completa final: **54 collected, 52 passed, 2 failed, 0 skipped**, exit 1, 458.91 s. Los únicos RED vuelven a ser R-COPY.13/8 y .14/8 por la copia/notice del brazo `MouseMove.is_forwarded=True` de salida/regreso. R-COPY.12/7 y .12/8 completan sus copias y cardinalidades; R-COPY.15/1–3 completan primero una copia válida y después comprueban selección vacía; R-COPY.1/4 y .12/3 copian la selección real no reescrita, con el brazo de dos líneas declarado parcial arriba.

SHA-256: test `4fd621a0d51e2b690fda6d3f5483805d65a1e2c31bdd7a4a7c13fb3ec4dc6b06`; targeted `338f4b40f0b25a6fde0d61e92ce992fe75c086655880e00fb3f6f94dd635cbc2`; familia `594e2da9b9514432f1682e7cd33bb9dced297473715de3f7d9751e68cf29e376`. Los hashes remotos y locales coinciden.

## Límites

No se ejecutó WinCI ni lectura OS separada. No se declara GREEN de la familia mientras los brazos forwarded de salida/regreso sigan RED. El producto no fue modificado para obtener estos resultados.
