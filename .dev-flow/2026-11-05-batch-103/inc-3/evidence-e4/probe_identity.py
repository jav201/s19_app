import sys

sys.path.insert(0, ".")

import tests.test_b103_a2l_definition_arrays_decode as w

name = "ASAM.M.SCALAR.UBYTE.IDENTICAL"
v171 = w.v171.__wrapped__()
original = w.a2ldef._shared_with

def traced(definition, span_index, mask_of, materialize=None):
    if definition.name != name:
        return original(definition, span_index, mask_of, materialize)
    candidates = span_index.get(None, ())
    print("CANDIDATES", candidates)
    for entry in candidates:
        if "STATUS_STRING" in entry[1] or entry[1] == name:
            print("ENTRY", entry, materialize(entry))
    result = original(definition, span_index, mask_of, materialize)
    print("RESULT", result)
    return result

w.a2ldef._shared_with = traced
print("BATCH")
w.a2ldef.describe_definitions([t["name"] for t in v171["tags"]], v171)
print("SINGLE")
w.a2ldef.describe_definition(name, v171)
