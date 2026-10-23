"""P11: change-doc reader edge cases — which defects drop or alter an entry
WITHOUT an ERROR issue (i.e. invisible even to the refusal list)?"""
from common import *
from s19_app.tui.changes.io import parse_change_document
H = '{"format":"s19app-changeset","version":"2.0","kind":"change","encoding":"utf-8","value_mode":"text","entries":[%s]}'
cases = {
    "dup_json_key_bytes": '{"type":"bytes","address":"0xEB10","bytes":"AA","bytes":"BB"}',
    "dup_json_key_address": '{"type":"bytes","address":"0xEB10","address":"0xEB20","bytes":"AA"}',
    "bytes_with_value_too": '{"type":"bytes","address":"0xEB10","bytes":"AA","value":"zz"}',
    "unknown_field": '{"type":"bytes","address":"0xEB10","bytes":"AA","lenght":4}',
    "address_over_32bit": '{"type":"bytes","address":"0x100000000","bytes":"AA"}',
    "address_int_float": '{"type":"bytes","address":60176.0,"bytes":"AA"}',
    "overlapping_entries": '{"type":"bytes","address":"0xEB10","bytes":"AA BB"},{"type":"bytes","address":"0xEB11","bytes":"CC"}',
    "bytes_3hex_token": '{"type":"bytes","address":"0xEB10","bytes":"AAA"}',
    "string_nonascii": '{"type":"string","address":"0xEB10","value":"Grüß"}',
}
for name, body in cases.items():
    d = parse_change_document(H % body)
    print(f"{name:24s} has_errors={d.has_errors!s:5s} entries={[(hex(e.address), bytes(e.encoded_bytes).hex()) for e in d.entries]} issues={[(i.code, i.severity.name) for i in d.issues]}")
bom = parse_change_document("﻿" + H % '{"type":"bytes","address":"0xEB10","bytes":"AA"}')
print(f"{'utf8_bom':24s} has_errors={bom.has_errors} entries={len(bom.entries)} issues={[i.code for i in bom.issues]}")
