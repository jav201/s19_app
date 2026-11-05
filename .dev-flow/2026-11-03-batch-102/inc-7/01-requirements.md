# E1 — Inc 7 — Flow Builder: orígenes y selección de archivos por bloque

## User story

- **US-102-07:** Como operador, quiero ver de dónde toma cada archivo un bloque y elegirlo desde el proyecto, temporales o una ruta externa válida, sin adivinar nombres ni escribir paths a ciegas.

## Alcance

- Mostrar origen/resolución de cada referencia file-bearing en tarjetas y formularios.
- Botón Browse en refs de Add/Edit que abre un selector con candidatos.
- Fuentes iniciales: archivos del proyecto activo, temporales/workarea y artefactos cargados; entrada de ruta externa.
- Importación segura de externals al workarea activo antes de que el flow los consuma.
- Depende de Inc 6 (el formulario Edit es una de las superficies de Browse).

## Requisitos EARS

1. **R-B102-FILE-001** — Ubiquitous. Each file-bearing block card shall show the reference plus its resolution source as one of `project`, `temp`, `loaded`, `external` or `missing`.
   - Umbral: 5/5 estados.
   - Mutante negativo: solo se muestra el nombre sin origen o `missing` se pinta como proyecto.

2. **R-B102-FILE-002** — Event. When the operator activates Browse beside a ref field, the system shall open a chooser listing project files, temp/workarea files and loaded artifacts, plus an external-path input.
   - Umbral: 3/3 fuentes visibles.
   - Mutante negativo: no hay Browse o sólo acepta texto manual.

3. **R-B102-FILE-003** — Event. When the operator picks a candidate, the system shall write the corresponding ref field and close the chooser without adding/editing the block.
   - Umbral: 3/3 fuentes.
   - Mutante negativo: elegir un candidato agrega el bloque inmediatamente.

4. **R-B102-FILE-004** — Event. When the operator submits an external path, the system shall verify the file exists and is readable, copy it into the active workarea `external/` folder and write the workarea-relative ref into the field.
   - Umbral: 2/2 (éxito y destino existente con nombre distinto).
   - Mutante negativo: se guarda una ruta absoluta insegura o se sobrescribe un archivo existente.

5. **R-B102-FILE-005** — Unwanted. If there is no active project/workarea, then the system shall refuse external import with `Load or create a project before importing an external file.` and shall not copy anything.
   - Umbral: 1/1.
   - Mutante negativo: se copia fuera del workarea o se permite path escape.

6. **R-B102-FILE-006** — Unwanted. If an external file cannot be read, then the system shall paint `External file not readable: <name>` and leave the ref field unchanged.
   - Umbral: 1/1.
   - Mutante negativo: se borra el campo o se escribe el path inválido.

7. **R-B102-FILE-007** — Ubiquitous. The chooser and card annotations shall render file-derived names/paths as literal text with zero markup spans.
   - Umbral: 1/1 payload hostil.
   - Mutante negativo: se pinta markup o se loguea el path completo.

## Diseño TUI (`tui-design`)

- La resolución aparece como anotación pequeña en la tarjeta (`↳ project: calib.json` / `missing: x.json`), no como otra columna pesada.
- Browse abre un selector modal con tres secciones apiladas y una fila externa; cada sección es una línea de encabezado dim con ítems seleccionables.
- El estado `missing` usa el color semántico reservado; los demás origen permanecen en dim para no competir con el dato principal.

## Decisiones

- Los externals se importan al workarea para preservar el contrato de seguridad actual (sin path escape en ejecución) y hacer el flow portable.
- Si el nombre ya existe, se genera sufijo `-1`, `-2`, etc.; nunca se sobrescribe.
- Browse no muta bloques; solo rellena el campo activo.
