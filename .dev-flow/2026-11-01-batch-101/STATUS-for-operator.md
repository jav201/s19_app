# batch-101 — estado para el operador (2026-11-06)

Sesión orquestadora nueva, sin supervisión, tras el handoff `HANDOFF-2026-11-06.md`. Todo en inglés en los registros; este resumen va en español.

## Lo fusionado y empujado a `main`

| Inc | Qué | Commit de cierre | Verificación |
|---|---|---|---|
| 4 | Documentos resuelven símbolos con el A2L cargado | `990db24` | Suite completa en el host LAN 2: solo los 4 fallos conocidos (tras arreglar 3 fallos del árbol fusionado en `c2cba35`). CI `42182116749`: solo los 4 conocidos. |
| 15 | Fallos solo-Windows (`tc331`, `tc_b94_27` y dos hermanos): eran esperas de una sola pausa en las pruebas; ahora esperan por el helper compartido. Solo pruebas, 0 archivos de producto. | `9bb0e3a` | Windows tras el arreglo 20/20 por nodo (antes 5/16 fallaban). |
| 16 | Higiene de documentación: CLAUDE.md, reglas, índice, overview y arquitectura describen la app real; se retiran `.fast-dev-flow/`, el diagrama obsoleto, `REQ-crc.md` y dos ficheros sueltos; notas terminadas archivadas con la ruta de unidad redactada. | `9bb0e3a` | Suite completa junto con Inc 15: los 4 conocidos + `tc_b97_55` (flake bajo carga ya en backlog; pasa 3/3 aislado). |
| 5 | CRC Designer y Check Editor al día tras escribir en sitio | `98d94d7` | Suite completa: los 4 conocidos + `tc_b97_55`; un fallo real de redacción (carpeta temporal de pytest con el nombre de cuenta) corregido. CI `42220640180`: solo los 4 conocidos. |
| 6 | Ciclo de vida de documentos del Patch Editor (listas `patches/` `checks/` `library/` en proyecto, ocultar prompt/control al reemplazar, Checks al día, enlaces rechazados) | se empuja con este punto de control | Mutantes 39/41 (3 equivalentes); Windows: 10 brazos de junction pasaron, pero el transcript no nombra los nodos → se repiten al cierre del batch. |

## Decisiones que tomé (cada una con su razón en el `*-rulings.md` del incremento)

- **Inc 4:** el guardia D-2 de Inc 13 fallaba sobre una base ya fusionada; ahora quita sus propias adiciones también de la base (sin debilitarlo). El handoff tenía rutas locales e IPs: redactado.
- **Inc 5 (CRC Designer tras escrituras en sitio + Check Editor):** el defecto D-4 se reprodujo (el Designer mostraba `0x9C5BCBBD` cuando el CRC real era `0x08DAAFB7`). Los bytes de una spec se indexan por (nombre, dirección, tamaño): si un A2L nuevo mueve un parámetro, pasa a fila de memoria en la dirección de la spec (nunca se juzga en otra dirección). Añadí R-CHKED-057: tras una escritura en sitio se limpian los resultados de Validate (había un `pass` viejo visible). F-26 ya estaba arreglado por el picker de batch-102 (queda guardia). Las etiquetas de filas de memoria (`SERIAL`) no vuelven tras recargar: requeriría cambiar la gramática de `.chk.json` — **decisión suya**, queda en backlog.
- **Inc 15:** sin parche de reloj global en conftest; esperas explícitas en los 9 sitios y guardia estática solo para ellos; el censo de las 146 pausas únicas en 28 archivos queda en backlog.
- **Inc 16:** la CLI se documenta como módulo (`python -m s19_app.cli <comando> <archivo>`); el orden de los ejemplos de CLAUDE.md estaba mal y no corría. `CENSUS-BASELINE` se queda en `docs/`.
- **Inc 6 (en curso):** con un proyecto abierto, las tres listas (Patch Editor, Check Editor, A2B Diff) muestran `patches/<n>`, `checks/<n>` y luego la biblioteca común como `library/<n>`; todo Write cae en el proyecto. Es el único cambio visible que admite, y es el defecto F-06 corregido. F-47 no se reprodujo: backlog sin cambio de producto.

## Necesita al operador

1. **Registros antiguos con datos locales (repo público):** 48 archivos de lotes anteriores en `.dev-flow/` tienen una ruta de unidad y 14 el nombre de la cuenta local; `BACKLOG-CODE.md` tiene dos líneas con una ruta de nube. Quedó como fila de backlog; la limpieza y si reescribir historia es decisión suya.
2. **Gramática `.chk.json`** para que vuelvan las etiquetas de filas de memoria (Inc 5, D-3): puerta de un solo sentido para archivos guardados.
3. Pendiente de reenviar a la sesión de requisitos: ids nuevos o cambiados de Incs 5, 6, 15, 16 (en cada `01-requirements.md`) y la corrección de R-DOC-DEV.2; además lo que ya estaba pendiente de Inc 13 (`S17-ears-strict.md` / D17-27).


## Punto de control (2026-11-06, fin de esta sesión)

- **Listos para E4** (E1–E3 cerrados, en sus ramas): Inc 9 (informe del re-run, nombre del flujo = nombre del archivo, guardados a través de enlaces rechazados con creación exclusiva y comprobación posterior); Inc 10a (navegación hex, estado tras descargar, foco nunca en una ventana oculta, Save project tras descargar ya no escribe la imagen descargada); Inc 10b (paneles hex, columna de valores A2L y Split/Join al día tras escribir en sitio).
- **Inc 10 se partió en 10a y 10b** en E3: con los 3 HIGH de seguridad (bytes viejos en los paneles hex tras aplicar; Save project tras descargar escribía la imagen descargada; teclas que actuaban sobre ventanas ocultas, incluida una exportación de Split/Join) excedía una pasada.
- **Falta:** E4–E5 y fusión de 9, 10a, 10b; Inc 12 completo; cierre del batch (batería completa, fold del canon, página de revisión, tag v1.0.0).
- Detalle técnico para la siguiente sesión: `HANDOFF-2026-11-06b.md`.
