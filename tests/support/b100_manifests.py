"""Batch-100 hostile and over-cap manifests (enabler E8, Inc 7).

Each builder returns ``project.json`` content for the reader's untrusted-input
arms (LLR-169.4, LLR-169.8, SEC6-5): arrays one over the 1 000-entry cap,
75 x 1 000 ``assignments`` (the security probe that read in 14.80 s
uncapped), a file one byte over 1 MiB, the hostile ``files`` keys and
malformed records, and a manifest with every array at the cap and every
entry bad. Stdlib only: nothing here imports ``s19_app``.
"""
from __future__ import annotations

import json
from typing import Optional

#: The reader's caps (LLR-169.4), restated here as the oracle.
ENTRY_CAP = 1000
SIZE_CAP = 1 << 20

#: A valid ``files`` record value (the digest of the empty byte string).
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
VALID_RECORD = {"size": 0, "sha256": EMPTY_SHA256}

#: LLR-169.4's eight hostile ``files`` keys -> 8 x MANIFEST-PATH-ESCAPE.
HOSTILE_FILES_KEYS = (
    "../x.s19",
    "C:/abs/x.s19",
    "C:x.s19",
    "\\\\host\\share\\x.s19",
    "x.s19:ads",
    "CON",
    "x.s19.",
    "patches/NUL.json",
)

#: LLR-169.4's six malformed records -> 6 x MANIFEST-BAD-STRUCTURE.
MALFORMED_RECORDS = (
    {"size": True, "sha256": EMPTY_SHA256},
    {"size": -1, "sha256": EMPTY_SHA256},
    {"size": "1", "sha256": EMPTY_SHA256},
    {"size": 0, "sha256": "XYZ"},
    {"size": 0, "sha256": "a" * 63},
    {"size": 0, "sha256": "a" * 65},
)

#: LLR-169.8's fourteen hostile entries (manifest-keys mode) and the two
#: plain ones it accepts.
MANIFEST_MODE_REFUSED = (
    "C:x.s19",
    "c:sub/x.s19",
    "x.s19:ads",
    "x.s19.",
    "x.s19 ",
    "CON",
    "patches/NUL.json",
    "nul.s19",
    "sub./x.s19",
    "patches/x.json ",
    "../x.s19",
    "C:/x.s19",
    "\\\\host\\share\\x.s19",
    "\\\\?\\C:\\x.s19",
)
MANIFEST_MODE_ACCEPTED = ("x.s19", "patches/a.json")


def manifest(**keys) -> dict:
    """A schema-1 manifest with ``keys`` added."""
    payload = {"schema_version": 1, "active_variant": None}
    payload.update(keys)
    return payload


def over_cap(key: str, count: int = ENTRY_CAP + 1) -> dict:
    """A manifest whose ``key`` array holds ``count`` valid-looking entries."""
    if key == "batch":
        return manifest(batch=[f"patches/d{i:05d}.json" for i in range(count)])
    if key == "files":
        return manifest(files={f"f{i:05d}.s19": VALID_RECORD for i in range(count)})
    if key == "declared_regions":
        return manifest(
            declared_regions=[
                {"name": f"r{i}", "start": i * 16, "end": i * 16 + 15}
                for i in range(count)
            ]
        )
    if key == "gathered":
        return manifest(gathered={"patches": [f"patches/g{i:05d}.json" for i in range(count)]})
    if key == "derived_from":
        return manifest(
            derived_from={
                f"v{i:05d}.s19": {"base": "firmware.s19", "sha256": EMPTY_SHA256, "differ": 1}
                for i in range(count)
            }
        )
    raise ValueError(key)


def assignments_75_by_1000() -> dict:
    """75 ``assignments`` keys of 1 000 short entries each (SEC PDR-C2),
    under the 1 MiB read cap so the entry cap is what refuses it."""
    return manifest(
        assignments={
            f"v{k:02d}": [f"c{i}" for i in range(1000)]
            for k in range(75)
        }
    )


def text_of_size(size: int) -> str:
    """A valid manifest padded with spaces to exactly ``size`` bytes."""
    body = json.dumps(manifest())
    return body[:-1] + " " * (size - len(body)) + "}"


def every_array_at_cap_all_bad(distinct: bool = True) -> dict:
    """SEC6-5: every capped array at exactly the cap, every entry refused
    (an escaping path), each entry distinct across arrays when
    ``distinct``."""

    def bad(tag: str, i: int) -> str:
        return f"../{tag if distinct else 'x'}{i:04d}.s19"

    return manifest(
        batch=[bad("b", i) for i in range(ENTRY_CAP)],
        assignments={"firmware": [bad("a", i) for i in range(ENTRY_CAP)]},
        gathered={"patches": [bad("g", i) for i in range(ENTRY_CAP)]},
        files={bad("f", i): VALID_RECORD for i in range(ENTRY_CAP)},
        derived_from={
            bad("d", i): {"base": "firmware.s19", "sha256": EMPTY_SHA256, "differ": 1}
            for i in range(ENTRY_CAP)
        },
        declared_regions=[{"name": i} for i in range(ENTRY_CAP)],
    )


def dumps(payload: dict, compact: Optional[bool] = True) -> str:
    """``payload`` as compact JSON text."""
    return json.dumps(payload, separators=(",", ":")) if compact else json.dumps(payload)


#: SEC6-5 / SEC7-1 (Inc 7 corrective): a depth under the reader's
#: component cap (32), so the entries reach the filesystem walk.
WALK_DEPTH = 30


def _arrays_at_cap(prefix: str, *, keyed: bool = True) -> dict:
    """Every capped array at exactly the cap, every entry under
    ``prefix`` and none escaping on the text (no ``..``). ``files`` and
    ``derived_from`` keys sit under ``prefix`` too when ``keyed`` (they
    are refused on the text: one component only)."""
    payload = manifest(
        batch=[f"{prefix}b{i}.json" for i in range(ENTRY_CAP)],
        assignments={"firmware": [f"{prefix}a{i}.json" for i in range(ENTRY_CAP)]},
        gathered={"patches": [f"{prefix}g{i}.json" for i in range(ENTRY_CAP)]},
    )
    if keyed:
        payload["files"] = {f"{prefix}f{i}.s19": VALID_RECORD for i in range(ENTRY_CAP)}
        payload["derived_from"] = {
            f"{prefix}d{i}.s19": {"base": "firmware.s19", "sha256": EMPTY_SHA256, "differ": 1}
            for i in range(ENTRY_CAP)
        }
    return payload


def deep_missing_at_cap() -> dict:
    """The security probe A1's shape (5 x 1 000 nested entries, none on
    disk) at a depth the reader walks (:data:`WALK_DEPTH`)."""
    return _arrays_at_cap("sub/" * (WALK_DEPTH - 1))


def existing_parent_at_cap(parent: str) -> dict:
    """3 x 1 000 entries under ``parent``, a real folder chain the caller
    creates, so each entry's own name needs a filesystem check."""
    return _arrays_at_cap(parent.rstrip("/") + "/", keyed=False)


def junction_loop_at_cap(loop: str = "loop") -> dict:
    """The security probe A3's shape: 5 x 1 000 entries through ``loop``,
    a junction to itself the caller creates."""
    return _arrays_at_cap(loop + "/")


def distinct_folders_at_cap() -> dict:
    """The folder ceiling's worst case (Inc 7 corrective pass 2, R2-2):
    3 x 1 000 entries, each under its own folder (``b<i>/``, ``a<i>/``,
    ``g<i>/``, see :func:`distinct_folder_names`), plus 1 000 ``files``
    records and 1 000 ``derived_from`` records with distinct bases: the
    most folder and file checks the caps allow."""
    payload = manifest(
        batch=[f"b{i}/x.json" for i in range(ENTRY_CAP)],
        assignments={"firmware": [f"a{i}/x.json" for i in range(ENTRY_CAP)]},
        gathered={"patches": [f"g{i}/x.json" for i in range(ENTRY_CAP)]},
    )
    payload["files"] = {f"f{i}.s19": VALID_RECORD for i in range(ENTRY_CAP)}
    payload["derived_from"] = {
        f"d{i}.s19": {"base": f"base{i}.s19", "sha256": EMPTY_SHA256, "differ": 1}
        for i in range(ENTRY_CAP)
    }
    return payload


def distinct_folder_names() -> list:
    """The 3 000 folders :func:`distinct_folders_at_cap` names."""
    return [f"{prefix}{i}" for prefix in "bag" for i in range(ENTRY_CAP)]


def files_at_cap_missing(records: dict) -> dict:
    """F2's probe PB: ``records`` plus well-formed ``files`` records for
    files not on disk, up to exactly the cap (the manifest is not
    damaged), so each record is one ``missing`` problem."""
    files = dict(records)
    for i in range(ENTRY_CAP - len(files)):
        files[f"gone{i:04d}.s19"] = {"size": 1, "sha256": "0" * 64}
    return manifest(active_variant="firmware", files=files)
