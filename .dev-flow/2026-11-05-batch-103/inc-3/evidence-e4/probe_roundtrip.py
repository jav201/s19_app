from itertools import product
import sys

sys.path.insert(0, ".")

import tests.test_b103_a2l_definition_arrays_write as w

v171 = w.v171.__wrapped__()
d = w.a2ldef.describe_definition(w.ROW_ARRAY, v171)
image = w._array_image(0x810100)
positions = list(product(*(range(n) for n in d.shape)))
for index, position in enumerate(positions):
    other = w._value_at(w._decoded(d, v171, image), d.shape, positions[(index + 1) % len(positions)])
    text = format(float(other.value), ".17g")
    try:
        w._round_trip_edit(d, v171, image, {position: text})
    except AssertionError as exc:
        print("FAIL", d.name, position, text, exc)
        break
else:
    print("ALL", len(positions))
