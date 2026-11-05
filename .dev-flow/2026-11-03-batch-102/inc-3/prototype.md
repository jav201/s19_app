# Prototipo TUI — Inc 3 — A2LParameterPicker en Check Editor

## Postura y flujo

Pantalla **operada**: el operador filtra, recorre páginas e incluye filas sin soltar el teclado. El flujo dominante es `escribir filtro → ver conteo → space/enter → siguiente`.

## Marco propuesto (118 columnas)

```text
┌ A2L PARAMETERS ─────────────────────────────────────────────┐
│ Filter [engine_speed        ]                               │
│ ┌────┬──────────────────────────────┬──────────┬──────────┐ │
│ │    │ Parameter                    │ Address  │ Fmt · Un │ │
│ │  ✓ │ EngineSpeed_Raw              │ 0x800100 │ u16 rpm  │ │
│ │    │ EngineSpeed_Filtered         │ 0x800102 │ u16 rpm  │ │
│ │    │ … 198 filas montadas, no 10 000                         │
│ └────┴──────────────────────────────┴──────────┴──────────┘ │
│ 0x800100  u16 rpm  EngineSpeed_Raw                          │
│ [‹ Prev]  Page 1/50  [Next ›]  [Include parameter] space…   │
└─────────────────────────────────────────────────────────────┘
```

La paginación consume una sola fila horizontal. No se añade borde nuevo ni lenguaje visual distinto.

## Tokens

- Componentes: `patch-chip` para Prev/Next/Include; `OsClipboardInput` para filtro; ledger `DataTable` de cuatro columnas.
- Brillo: tabla y fila seleccionada normales; filtro/controles secundarios dim; acción primaria del documento (`Write .chk.json`) conserva `fill-accent`.
- Estados vacíos: una línea dim con la acción de recuperación (^L o filtrar).

## Presupuesto de contenido

- Montaje por reconstrucción: máximo 200 filas × 4 columnas ≈ 800 celdas lógicas; el render visible solo paga la ventana.
- Un toggle dirty únicamente la celda `✓`, el full-name line y el preview; no invalida el `DataTable`.
- El filtro espera 150 ms para que una ráfaga de tecleo produzca una sola reconstrucción.
- Comparación base: 10 000 filas × 4 celdas = 40 000 celdas lógicas montadas por entrada/filtro; el diseño reduce el conjunto montado en 98 % y conserva navegación completa por páginas.

## Decisión de prototipo

Se elige **continuidad coherente** en lugar de una variante radical: la pantalla ya tiene una gramática de ledger + chips, y el problema es coste y estado, no descubrimiento. La firma visual queda para Patch Editor en Inc 5.
