# Batch-96 — pendientes del PDF del operador (2026-10-18)

Fuente: `G:/My Drive/Scan_20261018_153449.pdf` (scan 4 páginas, doodles ignorados).

## ESTADO (2026-10-18, features completas)

- **Fixes (mergeados a main, `bd42d8d`)**: B8 copias duplicadas (TC-1800),
  B7 guard mismo-path (TC-1801) + ayuda notación JSON (TC-1802) +
  B6 salvage kind extendido (TC-1803).
- **Bloque paso externo**: IMPLEMENTADO en el árbol real (port del prototipo
  aprobado `prototypes/external-step-block/`, TC-1804) — modelo, persistencia
  V5, builder (palette EXT-STEP + fila de config + strip de sesión), ejecución
  (pausa "ESPERANDO HUMANO" + confirmación + copia de la salida a la sesión).
  `set_session_dir` cableado desde `_handle_load_project` (app.py) — el strip
  muestra el dir real del proyecto activo. Incluye el fix del glifo de cable
  `_wire_drop` (└→┌ en el aterrizaje, revisión del operador).
- **Funnel**: IMPLEMENTADO (TC-1816/1817) — tabla nombre→valor a nivel Flow,
  persistencia V4b, sustitución `${NAME}` en change-docs al ejecutar el brazo
  PATCH (placeholder exacto, mayúsculas; no declarado → intacto + notice
  nombrada, nunca error); CHECK fuera de scope deliberado.
- **Copy/paste de bloques**: IMPLEMENTADO (TC-1818/1819) — pick por nº de
  ledger, clipboard interno por wire format real (nunca instancia), paste
  re-valida contra los bloques actuales; refs A2B verbatim (documentado).
- **R5 walker**: IMPLEMENTADO (TC-1810/1811) — walker por-componente con
  offsets+alineación, DIRECT standalone tolerado, ejes externos vía
  max_axis_points de la CHARACTERISTIC referenciada, encode de curvas.
  Límites: encode de ejes externos no resuelto, un solo COMPU_METHOD para
  eje+valores, MAP COL_DIR consume en orden de componentes.
- **E9 descripción de curvas**: IMPLEMENTADO (TC-1820..1822) — tecla `d` en la
  vista A2L, modal con tabla x→y física (COMPU_METHOD punto a punto, eje con su
  propia conversión), descripción larga del COMPU_METHOD extraída, puntos
  fuera de límites marcados. Límites: MAP 2-D aplanado con nota, FLOAT16 sin
  decode.
- **E singleton Tk**: IMPLEMENTADO (TC-1815) — root lazy creado una vez en el
  main thread, destrucción única, fallback a ctypes/PowerShell intacto.

Supersessiones registradas: TC-035 y AT-B94-24 actualizados a la doctrina B8
(reuso por contenido idéntico; `_1` solo para bytes divergentes).

Follow-ups declarados: picker de archivos real en el diálogo de confirmación
del paso externo; documentar la acción `d` en la ayuda por ventana; MAP 2-D
como grid; encode de ejes externos.

## Historial de la spec (las secciones siguientes quedan como registro)

Los 4 fixes ejecutables sin interferir con el batch-94 ya están en esta rama
(commit `041bb84`: B8 copias duplicadas TC-1800, B7 guard mismo-path TC-1801,
ayuda notación JSON TC-1802, B6 salvage kind extendido A2L TC-1803).

## 1. Bloque "paso externo" (terminal o manual) — spec v2 del operador

Un SOLO bloque, DOS modos:
- **Modo terminal**: texto exacto pasado al terminal (el usuario es responsable
  del texto, como en el pedido original del PDF).
- **Modo manual**: el bloque le muestra una instrucción al usuario ("haz X
  fuera de la app") y espera. Hay operaciones que lo requieren; esta dualidad
  hace el bloque más robusto.

En AMBOS modos el bloque lleva tres piezas de datos:
1. **Instrucción/comando** — el texto del paso.
2. **Log OBLIGATORIO** — al terminar, el bloque SIEMPRE pide un texto: qué se
   hizo / información a dejar constancia. Nunca opcional; queda en la corrida
   del flow (trazabilidad: todo paso externo deja evidencia escrita).
3. **Archivo de salida** — el archivo que resultó del procesamiento del paso;
   el flow lo registra como artefacto del paso para que los bloques siguientes
   de la cadena puedan referenciarlo. El campo PREFIERE rutas absolutas: el
   usuario introduce un path absoluto al archivo que produjo fuera de la app.
   Al confirmar, el flow COPIA el archivo a la carpeta de artefactos de la
   sesión (el workarea de la corrida, junto a los demás artefactos del flow) y
   los bloques siguientes referencian ESA copia gestionada — nunca el path
   externo suelto. La pantalla del bloque debe mostrar SIEMPRE cuál es ese
   directorio de sesión (el operador notó que no se veía ningún directorio de
   trabajo).

Semántica: el bloque es un punto de sincronización humano en la cadena — la
ejecución se pausa, el humano actúa fuera de la app, y solo continúa cuando
aportó log + archivo.

**DISEÑO APROBADO (operador, 2026-10-18)**: prototipo TUI en
`prototypes/external-step-block/` (3 variantes A/B/C con renders a color en
`external-step-block.html`). Decisión del operador: **variante A (tarjeta de
configuración con chips) para configurar + variante C (lane de ejecución) para
ejecutar** — o A sola si solo cabe una. Doctrina del prototipo que la
implementación debe respetar: el ámbar significa únicamente "esperando humano";
log y archivo pendientes se muestran en rojo con su razón; la pausa se dibuja en
el cable de la cadena; sin motion (espera de minutos/horas); footer siempre
visible con `log + archivo: OBLIGATORIOS`. Además, las variantes A y C muestran
siempre el directorio de artefactos de sesión y un ejemplo de path absoluto
(p.ej. `C:\work\flash\app_v2.s19`) en el campo ARCHIVO DE SALIDA.

**Zona de implementación**: flow builder + flow execution (FlowBuilderPanel /
FlowExecutionPanel / chain-set runner / flow_persistence loaders) — terreno del
batch-94 (rama `kimi/batch-94-flows-and-editors`). Canalizar allí o a un
batch-96-b post-merge. El "funnel de variables" (declarar de antemano las
variables a reemplazar en los JSON de los flows, un funnel por chain/flow) va
en el mismo paquete; ambos hacen evidente la necesidad de copiar/pegar bloques
en el builder.

## 2. R5 — walker completo de RECORD_LAYOUT (a2l.py)

- Parser por-componente del body (position index / datatype / dirección ROW_DIR/
  COL_DIR) en lugar de "solo primera línea" (`_resolve_record_layout`).
- `_record_layout_full_span` aceptar `DIRECT` standalone (hoy fuerza `None`) —
  NOTA: si el A2L del operador lleva `DIRECT` como 4º token de FNC_VALUES (la
  forma ASAP2 estándar), el walker actual YA lo soporta; verificar con su
  archivo real.
- Resolución de ejes externos: COM_AXIS / RES_AXIS / CURVE_AXIS / AXIS_PTS_REF
  hoy dejan `length=None` a propósito.
- Extender el encode a arrays (hoy `element_count>1` y `char_type != VALUE` se
  rechazan, a2l.py:1616-1653) para poder parchar curvas por símbolo.

## 3. E9 — descripción de parámetros A2L (curvas)

Descripción/visualización de parámetros tipo tabla/función combinando A2L
(COMPU_METHOD con descripción, unidades, límites, axis_meta) + S19/HEX (valores
actuales: axis points + FNC_VALUES decodificados). Hoy `axis_meta`/`compu_tabs`
se parsean pero ninguna vista los consume; no hay decode de puntos de eje ni
rendering de curvas. Depende del walker de R5.

## 4. Misc del PDF

- B7 raíz residual: singleton de Tk para el portapapeles (`_read_via_tk` crea/
  destruye tk.Tk en executor thread y muere a mitad de sesión). El guard
  TC-1801 mitiga el síntoma; esto ataca la causa.
- El "funnel de variables" también pide función de copiar/pegar bloques en el
  flow builder.
