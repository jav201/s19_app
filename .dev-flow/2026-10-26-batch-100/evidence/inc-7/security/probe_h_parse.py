"""H: what the core parsers raise on hostile base-image bytes (the derived_from
base is re-read at save time by _image_map; _derived_record catches only
OSError / ValueError / RuntimeError)."""
from common import *
from s19_app.tui.app import _image_map
samples = {
 "garbage.s19": b"S3FFgarbage\n",
 "binary.s19": bytes(range(256)) * 4,
 "short.s19": b"S1\n",
 "badlen.s19": b"S1FF0000\n",
 "nonhex.s19": b"S113ZZZZ000000000000000000000000000000000000\n",
 "utf16.s19": "S1130000".encode("utf-16"),
 "empty.s19": b"",
 "garbage.hex": b":ZZ\n",
 "badlen.hex": b":FF000000\n",
 "binary.hex": bytes(range(256)) * 4,
 "dir.s19": None,
}
d = fresh("H")
for name, data in samples.items():
    p = d / name
    if data is None: p.mkdir()
    else: p.write_bytes(data)
    try:
        m = _image_map(p)
        print(f"{name:12s} -> ok, {len(m)} bytes")
    except (OSError, ValueError, RuntimeError) as e:
        print(f"{name:12s} -> caught class {type(e).__name__}")
    except Exception as e:
        print(f"{name:12s} -> UNCAUGHT {type(e).__name__}: {str(e)[:60]}")
