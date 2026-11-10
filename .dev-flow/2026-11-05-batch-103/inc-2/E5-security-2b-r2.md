# Inc 2b E5 — revisión final de seguridad R2

**Veredicto: PASS-WITH-NOTES.** No hay hallazgos HIGH/MAJOR abiertos; nada bloquea la integración.
La colisión homónima BLOB/INSTANCE está corregida antes de cualquier consulta de máscara, la escritura
queda limitada al span declarado, los solapes cross-kind conservan orden global de archivo y fallan
cerrado cuando falta la longitud, y el encode mantiene parse gate, acotación de mensajes, inmutabilidad
y ausencia de I/O. Persisten una nota LOW de renderizado ya conocida y dos notas INFO, ninguna con
impacto bloqueante.

Base revisada: HEAD `e0f4553e`; según el brief, mismo producto que `57b69214` y solo un docstring
posterior. La revisión de código final (`E5-code-review-2b-r4.md`) da **PASS** y la auditoría de
cobertura R3 da **PASS-WITH-NOTES**, sin cobertura funcional pendiente.

## Método y evidencia

**Ejecutado por este revisor: nada.** Revisión estática de solo lectura en Windows; no se ejecutó
pytest ni probes y no se hicieron mutaciones git. Se leyeron `E5-security-2b.md`,
`E5-code-review-2b-r4.md`, `01-requirements.md:192-219`, las rutas actuales de
`describe_definitions`, `_pair_exempt`, `_shared_with` y `encode_definition`, y sus helpers de
selección/mezcla de máscara y codificación.

Evidencia del orquestador, solo leída:

- `evidence-e4/int2b-run14-main.txt:1-6`: **322 passed in 15.50s**.
- `evidence-e4/int2b-red-stub-final9-main.txt:2427-2446`: **125 failed, 197 passed in 29.24s**;
  incluye los brazos encode, inmutabilidad y solapes del alcance.
- `evidence-e4/int2b-red-homonym-guard.txt:1-31`: RED específico de `.138/23`, **1 failed, 309
  deselected**; sin la guarda, `MW.shared_with` es `None` en lugar de `"B"`.

## Comprobaciones de seguridad

- **Escritura fuera de span: no encontrada.** El resultado siempre usa `definition.address`
  (`s19_app/tui/a2l_definition.py:3725`, `:3808`). ASCII exige longitud máxima y devuelve exactamente
  `byte_length` bytes, con padding (`:3440-3458`). El encode numérico construye una vista de tag con la
  longitud y byte order de la definición (`:3366-3385`); la mezcla enmascarada conserva los demás bits
  y serializa exactamente `byte_length` bytes (`:3388-3419`). Arrays/curves/maps se rechazan antes de
  codificar (`:3705-3710`). No hay escritura parcial ni direcciones adicionales en `Encoded`.
- **Solapes cross-kind y orden global: correctos.** El walk asigna una posición única en preorden e
  indexa MEASUREMENT/CHARACTERISTIC y BLOB/INSTANCE (`:601-670`), con consumo alineado de
  `declared_spans` para BLOB/INSTANCE (`:643-658`). El índice por páginas conserva entradas de longitud
  desconocida como puntos fail-closed (`:674-684`); `_entry_overlaps` trata igual una longitud ausente
  o no positiva (`:3526-3542`). `_shared_with` deduplica y ordena candidatos multipágina por posición
  global (`:3563-3575`), excluye una sola vez la entrada propia por identidad estructural (`:3576-3586`)
  y devuelve el primer solape real (`:3587-3590`). La dirección `0x0` se distingue de ausencia mediante
  `is None` (`:3554-3556`).
- **Colisión homónima BLOB/INSTANCE: RESUELTA.** `_pair_exempt` devuelve `False` para todo vecino
  BLOB/INSTANCE (`:3511-3512`) antes de `mask_of(entry[1])` (`:3513`). Por tanto, un tag limpio y
  enmascarado con el mismo nombre ya no puede prestar su máscara a un BLOB o INSTANCE solapado. El caso
  `.138/23` ejerce ambos shapes y exige `shared_with == "B"` y `A2L-DEF-OVERLAP`
  (`tests/test_b103_a2l_definition.py:3394-3413`); el RED específico demuestra que la guarda es causal.
- **CLEAN masks: correctas.** `mask_of` solo devuelve una máscara si el vecino no tiene refusal y tiene
  longitud legible (`s19_app/tui/a2l_definition.py:697-715`); la precarga de la definición propia aplica
  la misma condición (`:729-732`). `_pair_exempt` exige además definición propia limpia, longitud válida
  y ambas máscaras (`:3504-3515`). La comparación se hace sobre bits seleccionados por dirección y byte
  order, no sobre enteros de máscara (`:3475-3495`, `:3516-3523`). Vecinos duplicados, con refusal de
  longitud/byte order o sin máscara no obtienen exención.
- **Contenido hostil y acotación: correctos dentro del contrato.** Las palabras de archivo pasan por
  `_echo`, con 256 caracteres y sustitución fuera de ASCII imprimible (`:310-324`); texto de operador
  pasa por `_operator_echo`, con 256 caracteres y C0/C1 sustituidos (`:3241-3248`). `_number_text` evita
  conversiones decimales ilimitadas y acota enteros enormes (`:346-354`). El texto persistido es ASCII
  imprimible o numérico; no se escriben mensajes ni texto hostil en la imagen. El hueco F-1 de la E5
  previa está cerrado por `.138/21`: BLOB con dirección hexadecimal de 5.000 dígitos queda fuera de
  alcance e INSTANCE con longitud ilegible conserva su punto de dirección y provoca OVERLAP, sin
  excepciones (`tests/test_b103_a2l_definition.py:3358-3378`).
- **Parse gate y orden de rechazo: correctos.** El refusal propio tiene prioridad
  (`s19_app/tui/a2l_definition.py:3693-3694`); cualquier error de parseo produce `A2L-DEF-PARSE` antes
  de validar el valor del operador (`:3697-3703`). Después se mantienen kind/valor, límites, encode,
  bytes de imagen, máscara, precisión y finalmente solape (`:3705-3808`). Los cinco casos `.152` y
  `.57/5` están dentro del GREEN completo.
- **Inmutabilidad y no I/O: confirmados.** `Definition`, `Refusal` y `Encoded` son dataclasses congeladas
  (`:46-47`, `:114-115`, `:168-169`); describe crea otra definición con `replace` en lugar de mutar la
  original (`:734-737`). Encode solo lee `a2l_data` e `image`, crea `method_table`, `tag`,
  `written_image` y nuevos `bytes` (`:3356-3385`, `:3764-3766`), y no escribe en el mapping recibido.
  No hay llamadas de filesystem, red o proceso en `a2l_definition.py`; esta capa devuelve datos para que
  otro componente los persista. `.58.1/1`-`/2` cubren la no mutación y pasan en `run14`.

## Hallazgos abiertos

### E5SEC-R2-1 — LOW · superficie de renderizado · controles Unicode bidi/formato

Ref: `s19_app/tui/a2l_definition.py:294-307`, `:3241-3248`; R-A2L-DEF.137 y .151/7.

`_operator_echo` cumple el contrato: acota y sustituye C0/C1, pero preserva deliberadamente el resto de
Unicode. Por ello, U+202A–U+202E, U+2066–U+2069, marcas de dirección y caracteres de ancho cero pueden
reordenar u ocultar visualmente texto de operador cuando Inc 8/9 renderice un refusal/notice. No es un
defecto de esta implementación ni permite escritura fuera de span; es una nota de hardening para el
renderer. Corrección acotada: aislar el texto reflejado con FSI/PDI o filtrar controles bidi al mostrarlo,
sin cambiar el contrato congelado de este incremento.

### E5SEC-R2-2 — INFO · redundancia · doble comprobación del span enmascarado

Ref: `s19_app/tui/a2l_definition.py:3750-3756`, `:3395-3408`.

Para escrituras enmascaradas, `_image_span_refusal` comprueba la presencia de todos los bytes y
`_merge_bit_mask` vuelve a comprobarla. La segunda rama de bytes ausentes es inalcanzable tras la primera;
no altera el orden de refusal ni la seguridad. No se requiere corrección.

### E5SEC-R2-3 — INFO · granularidad de evidencia RED

Ref: `evidence-e4/int2b-red-homonym-guard.txt:7-28`;
`tests/test_b103_a2l_definition.py:3394-3413`.

El bucle RED se detiene en BLOB y no ejecuta el shape INSTANCE. `run14` sí ejecuta ambos en GREEN y la
misma guarda explícita cubre los dos tipos, por lo que no queda una rama de producto sin revisar. No debe
describirse el RED como independiente por shape; esta limitación forma parte de las notas no bloqueantes
de cobertura R3.

## Cierre

El F-1 de `E5-security-2b.md` (cobertura hostil BLOB/INSTANCE) está cerrado por `.138/21`; la regresión
homónima tratada en la revisión de código R4 está cerrada por la guarda y `.138/23`. F-2 permanece como
E5SEC-R2-1 (LOW, renderer) y F-3 como E5SEC-R2-2 (INFO). **Veredicto final: PASS-WITH-NOTES; ningún
HIGH/MAJOR abierto.**
