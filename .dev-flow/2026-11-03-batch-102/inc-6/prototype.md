# Prototipo TUI — Inc 6 — Edit/Remove por bloque

## Fila Copy/Paste extendida

```text
copy block # [2      ] [Copy] [Paste] [Edit] [Remove]  clipboard: source
```

## Modal de edición

```text
┌ EDIT BLOCK #2 — patch ──────────────────────────────────────┐
│ ref [calib_hotfix.json                    ]                 │
│                                                             │
│ [Save]                                           [Cancel]   │
└─────────────────────────────────────────────────────────────┘
```

Para A2B se muestran `image A` / `image B`; para External step, modo/instrucción/log/output. La disposición de campos replica el add-row para no introducir un segundo vocabulario.

## Remove

```text
Remove block #2 (patch)? This cannot be undone.
[Remove (y)] [Cancel (n)]
```

## Presupuesto

- Solo se añaden dos chips a una fila horizontal existente.
- El modal es una pantalla modal; no aumenta el coste permanente del rail.
- Edit/Remove actúan sobre un índice; no re-renderizan más allá del refresh normal del pipeline.
