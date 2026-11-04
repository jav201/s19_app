# E1 — Inc 2 — A2L load/reload siempre refresca el viewer

## User story

- **US-102-02:** Como operador, quiero que Load/Reload deje el A2L Viewer actualizado automáticamente, sin refrescar manualmente, para confiar en que las etiquetas mostradas corresponden al archivo e imagen cargados.

## Alcance

- A2L attach directo (`load_a2l_from_path` → install), install de proyecto y carga/reload de imagen con A2L ya adjunto.
- Invalidación del enriquecimiento, clave del worker precalculado y aplicación/render del filtro existente.
- Archivos fuente: `s19_app/tui/app.py`.

## Requisitos EARS

1. **R-B102-A2L-001** — Event. When an A2L attach succeeds, the system shall compute or invalidate the enriched tag cache, refresh validation state, and render the A2L tag rows before painting the successful load outcome.
   - Umbral: 3/3 rutas (attach inicial, attach distinto, re-attach del mismo archivo tras clear/reload).
   - Mutante negativo: la clave de caché vuelve a usar `id(self.current_a2l_data)`.

2. **R-B102-A2L-002** — Event. When a primary image load or reload completes while an A2L is attached, the system shall refresh memory validation and rerender the A2L tag rows automatically.
   - Umbral: 2/2 imágenes del mismo tamaño y distinto contenido (S19 inicial, reload HEX sobre el mismo A2L).
   - Mutante negativo: `_apply_prepared_load` omite `_step_a2l` o la clave no incluye la generación de imagen.

3. **R-B102-A2L-003** — State. While the A2L filter input contains non-empty text and a new A2L is attached, the system shall apply that filter to the new tags and shall render either the matching rows or `No A2L tags match '<filter>'.`
   - Umbral: 2/2 (match y no match).
   - Mutante negativo: se ignora el filtro o el mensaje genérico reemplaza al mensaje con filtro.

4. **R-B102-A2L-004** — Unwanted. If a newly attached A2L payload reuses the previous payload's object address and the memory-map size is unchanged, then the system shall still compute fresh enriched tags for the new attach generation.
   - Umbral: 1/1 con `id()` forzado idéntico y contenidos distintos.
   - Mutante negativo: la clave de caché conserva `id()` y devuelve la lista anterior.

5. **R-B102-A2L-005** — State. While no A2L is attached, the A2L Viewer shall render `No A2L loaded.` and zero tag rows.
   - Umbral: 1/1.
   - Mutante negativo: se conservan filas del A2L anterior tras clear/unload.

6. **R-B102-A2L-006** — Event. When the file-load worker precomputes A2L enrichment, the system shall carry the A2L and image generation snapshot in `PreparedLoad` and shall discard that precomputed cache if the apply-time generations differ.
   - Umbral: 2/2 (snapshot válido se instala; snapshot obsoleto se ignora y se recompute en UI).
   - Mutante negativo: el worker guarda una clave `(id(payload), mem_size)` o el apply instala el precálculo sin verificar generaciones.

## Defectos de requisitos existentes

- El requisito LLR-037.3 ya exige frescura del mapa de severidad en el sync-fallback; este incremento cierra el agujero de identidad/caché y la ventana worker→apply que podían mostrar datos obsoletos aunque el flujo llame a `update_a2l_view()`.

## Slice de funciones

- Nuevas: `_replace_current_a2l` (o equivalente) como único escritor que bumps generación A2L, `_invalidate_a2l_view_cache`; campos de generación en `PreparedLoad`.
- Cambiadas: `S19TuiApp.__init__`, `_prepare_load_payload`, `_apply_prepared_load`, `_compute_a2l_enriched_tags`, `_refresh_a2l_filtered_tags`, `update_a2l_tags_view`, `update_a2l_view`, `_install_attached_a2l`, `_install_prepared_project` y clear/unload según el censo de escritores de `current_a2l_data`.
- No se modifica `s19_app/tui/a2l.py`.
- Estimación Code-Wire: 8-10 nodos.

## Decisiones corregidas tras E3

- La clave de enriquecimiento es `(a2l_view_generation, image_generation, mem_size)`; nunca `id()`.
- Todo reemplazo de `current_a2l_data` pasa por el mismo seam y bump de generación. Eso cubre attach directo, project install, file load install y clear/unload.
- `update_a2l_tags_view` es el único writer del texto de tabla vacío; `_refresh_a2l_filtered_tags` le pasa el mensaje explícito cuando un filtro no coincide.
- El worker precalcula con un snapshot de generaciones y `PreparedLoad` los conserva; el apply los verifica después de bump de imagen/A2L. Si difieren, descarta el precálculo y `_compute_a2l_enriched_tags` recomputa en el hilo UI.
