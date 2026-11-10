# E3 architect — Inc 3b

## Veredicto: FAIL

Hay **3 hallazgos MAJOR**, todos `impl/design-gap`, que bloquean E4. El diseño cubre la estructura general de escritura, pero su integración con los helpers reales de 3a y con las guardas corregidas de 2b no preserva nombres, solapes ni la regla CLEAN en todos los caminos. Alcance revisado: las 12 filas de S2.7h, los 42 casos 3b y los 5 casos mixtos; base de producto `8cb8f479`.

## Hallazgos

### E3B3-A-01 — MAJOR — impl/design-gap — los mensajes de encode pierden el nombre del elemento o punto

**Ubicación:** `codewire/graph-inc3.md:824`, `:831-836`; `s19_app/tui/a2l_definition.py:2865-2884`, `:3290-3297`, `:3693-3695`, `:3727-3734`, `:3790-3793`; contrato en `01-requirements.md:226`, `:233` y casos en `02-test-cases.md:287-288`, `:293-297`.

`_element_definition` cambia `name` a `V[1,2]` o `C.X[1]`, pero conserva `_name_echo` del objeto (`V`) o del eje (`C.X`). `encode_definition` y todos sus helpers de límites, precisión, enum y solape usan `_name_echo_of`, que prefiere ese campo privado. Por tanto, el camino prescrito por `encode_values` produce `V: 'abc' is not a number`, no `V[1,2]: …`; el mismo defecto alcanza límites, precision, extended limits y notices.

La nota de `graph-inc3.md:85` ya exige `_name_echo + suffix`, pero el nodo `encode_values` vuelve a decir `element_name` para `<position>` y no prescribe actualizar el eco al delegar en `encode_definition`. Además, `element_name` usa el nombre público sin sanitizar, por lo que no satisface por sí solo R-A2L-DEF.151.

**Sonda ejecutada [P1]:** sobre una definición real del helper, `element.name == "V[1,2]"`, `element._name_echo == "V"`; `encode_definition(element, {}, "abc", {})` devolvió `A2L-DEF-NUMBER` con mensaje `V: 'abc' is not a number`.

**Corrección requerida:** al construir cada definición elemental, fijar también `_name_echo` al eco del objeto/eje más el sufijo `[i,j]` / `[k]`. Usar esa misma composición en `A2L-DEF-INDEX` y notices, no `element_name`; alinear el nodo `encode_values` con la nota de la ronda 7. Quedan cubiertos por una sola corrección los casos `.121/1`, `.121/2`, `.122/3`, `.122/5`, `.122/6`, `.122/7` y los mensajes de precisión/overlap heredados.

### E3B3-A-02 — MAJOR — impl/design-gap — un punto STD pierde el `shared_with` del objeto

**Ubicación:** `codewire/graph-inc3.md:281`, `:824`; `s19_app/tui/a2l_definition.py:1882-1908`, `:2852-2866`; contrato en `01-requirements.md:244` y R-A2L-DEF.138 de Inc 2b.

El camino de valores hace `replace(definition, …)` y hereda el `shared_with` calculado por 2b. El camino de puntos hace `replace(points, …)`; `points` se construye con `shared_with=None`, de modo que un punto STD no hereda el solape de la CURVE/MAP cuyo registro se va a devolver completo. COM y FIX se rechazan antes, pero STD llega a `encode_definition` sin la guarda de overlap.

Esto contradice la cláusula del grafo según la cual cada definición elemental conserva el `shared_with` del objeto y permitiría escribir un punto dentro de un registro compartido. Los 42 casos no incluyen un punto STD de una curva solapada, por lo que `.140/1-3` no detectan esta variante.

**Sonda ejecutada [P2]:** una CURVE con `shared_with="AXS"` y un eje STD produjo `_element_definition(curve, ("X", 1)).shared_with is None`.

**Corrección requerida:** propagar `shared_with=definition.shared_with` también en el `replace` de puntos. Añadir a la cobertura 3b un punto STD de una CURVE que comparte bytes, esperando `A2L-DEF-OVERLAP` y ninguna escritura.

### E3B3-A-03 — MAJOR — impl/design-gap — AXIS_PTS puede heredar la máscara CLEAN de un tag homónimo

**Ubicación:** `codewire/graph-inc3.md:279`, `:336-337`; `s19_app/tui/a2l_definition.py:697-715`, `:3498-3523`; corrección análoga de 2b en `../inc-2/E5-code-review-2b-r4.md:29-39`.

El grafo añade entradas `AXIS_PTS` al índice de 2b, pero `_pair_exempt` excluye de la consulta de máscara únicamente `BLOB` e `INSTANCE`. Para una entrada `AXIS_PTS`, `mask_of(entry[1])` describe por nombre un MEASUREMENT/CHARACTERISTIC: si existe un tag homónimo limpio y enmascarado, su máscara se presta al AXIS_PTS y puede hacer la pareja aparentemente disjunta. Se reabre así, al añadir el nuevo tipo de entrada, el defecto que la revisión final de 2b cerró para BLOB/INSTANCE. Un AXIS_PTS no tiene una máscara CLEAN obtenida de su propia definición y no debe habilitar la exención.

**Sonda ejecutada [P3]:** con el mismo objeto enmascarado, la misma dirección y `mask_of` homónimo `0xF0`, `_pair_exempt` devolvió `True` para una entrada `AXIS_PTS` y `False` para una `BLOB`.

**Corrección requerida:** no consultar `mask_of` para `AXIS_PTS`; preferiblemente permitir la exención solo cuando `entry[2]` sea `MEASUREMENT` o `CHARACTERISTIC`. Añadir el caso homónimo de `.140`, con máscaras aparentemente disjuntas, que debe conservar `shared_with` y `A2L-DEF-OVERLAP`.

### E3B3-A-04 — MINOR — design-gap — el contrato scalar de `encode_values` no tiene camino en el algoritmo

**Ubicación:** `codewire/graph-inc3.md:150`, frente a `:822-824`; split en `01-requirements.md:300`.

I-2 promete `encode_values` también para `number`, `enum` y `text`, aceptando únicamente `(0,)` y delegando en `encode_definition`. El nodo operativo no contiene esa rama: tras `decode_values`, valida contra `definition.shape`; en una definición scalar `shape == ()`, por lo que `(0,)` cae en `A2L-DEF-INDEX`. El propio grafo reconoce que todavía no hay fila para esta mitad de E2-5.

**Corrección requerida:** escribir la rama scalar explícita y su caso, o retirar scalar de I-2. No dejar que la validación de arrays determine implícitamente el contrato scalar.

### E3B3-A-05 — MINOR — design-gap — el orden PARSE/ELEMENTS difiere entre grafo e implementación integrada

**Ubicación:** `codewire/graph-inc3.md:383`; `s19_app/tui/a2l_definition.py:3693-3710`; R-A2L-DEF.152 en `../inc-2/01-requirements.md:215`.

El grafo ordena `definition.refusal` → `A2L-DEF-ELEMENTS` para array/curve/map → pasos 2…10 de 2b. El código integrado comprueba `a2l_data["errors"]` antes del rechazo `ELEMENTS`; por tanto, con errores de parseo devuelve `A2L-DEF-PARSE`, no `A2L-DEF-ELEMENTS`. La implementación es compatible con la regla 2b de adelantar PARSE a las comprobaciones del texto del operador, pero el diseño aprobado dice lo contrario y no fija el caso combinado.

**Corrección requerida:** alinear el nodo con R-A2L-DEF.152 y el código integrado (`refusal` → `PARSE` → `ELEMENTS`), manteniendo overlap en su paso tardío, después de bytes/precisión; fijar el orden combinado en cobertura.

## Cobertura comprobada sin otro hallazgo bloqueante

- **Edit order y posiciones:** `graph-inc3.md:147`, `:824` ordena decode, validación de posiciones, ejes X/Y antes de valores y monotonía al final; los índices malformados quedan detrás y los valores usan el orden de `_element_indexes` (`a2l_definition.py:2775-2786`).
- **FIX / COM / sin puntos:** los tres rechazos aparecen antes de delegar el punto (`graph-inc3.md:824`), con decode previo incluso para COM; las posiciones se validan antes de esas reglas.
- **Offsets y preservación:** los helpers ya implementan ROW/COLUMN (`a2l_definition.py:2789-2805`) e INDEX_INCR/DECR (`:2808-2813`); el diseño parte de una copia del registro de imagen y sustituye solo los bytes editados, conservando contadores y demás componentes (`.123`, `.132`).
- **Monotonía:** `_breaking_point` compara números almacenados y devuelve el primer punto que rompe el prefijo, incluido uno no editado; cubre las siete reglas y el default (`graph-inc3.md:869-879`).
- **Round trip y precisión:** cada elemento reutiliza `encode_definition`, incluidos exact integers, cláusulas de 15/6 dígitos, written-value limits y notices (`a2l_definition.py:3742-3800`); el registro se reconstruye solo con edits, no desde display texts.
- **Inmutabilidad:** `encode_values` declara lectura sin escritura de `image`/`a2l_data`; la copia local del registro satisface el diseño de `.58.1`, sujeto a sus dos brazos edit aún pendientes.
- **Guards 2b conservadas:** el índice pagina y desduplica por orden global (`a2l_definition.py:3557-3575`), mantiene BLOB/INSTANCE (`:643-658`) y CLEAN para tags (`:697-715`); PARSE precede al texto y overlap sigue a bytes/precisión. Las longitudes actuales del reader ya usan el producto MATRIX_DIM y NUMBER (`a2l.py:3778-3811`), aunque la descripción histórica de `graph-inc3.md:279` debe leerse rebasada a ese reader.

## Checks

### Leídos

- `01-requirements.md:229-244`, split `:291-312` y notas de `.58.1` / AXIS_PTS; `02-test-cases.md:285-329`, `:348-349`, `:410-412`, split `:417-442`.
- `codewire/graph-inc3.md:132-150`, `:262-293`, `:379-387`, `:818-879`; nodos `describe_definitions`, `_element_definition`, `decode_values`, `encode_definition`, `encode_values` y `_breaking_point`.
- Implementación actual de descripción/índice, offsets, decode y encode de `s19_app/tui/a2l_definition.py`; guards R-A2L-DEF.138/.152 y evidencia final de Inc 2b.
- Estado documental: **42 casos 3b `gap/not_run`** y **5 casos mixtos `partial`**, con sus brazos edit `not_run`.

### Ejecutados

- Solo lectura Git: `git status --short`, `git show --stat 8cb8f479`, `git log --oneline -12`; HEAD confirmado en `8cb8f479`. Sin mutaciones Git.
- Sonda `python -B` por stdin, sin pytest ni archivos: **[P1]** nombre `V` en lugar de `V[1,2]`; **[P2]** `shared_with=None` en punto STD; **[P3]** exención `True` para AXIS_PTS frente a `False` para BLOB.
- **No ejecutado:** pytest ni los 42 casos/5 brazos edit, por la restricción explícita de no ejecutar pytest en Windows y porque `encode_values` todavía no existe en producto.
