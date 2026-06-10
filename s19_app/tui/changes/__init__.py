"""
v2 hex-first change system (`s19app-changeset`) — re-export facade.

Public surface of the ``changes`` package (batch-07, HLR-001): the object
model (``model.py``), the JSON reader/writer and rule-code constants
(``io.py``), and the intra-document collision rule (``validate.py``).
Import from here; the modules stay the implementation detail.
"""

from .model import (
    CHANGES_ARTIFACT,
    ChangeDocument,
    ChangeEntry,
    MemoryStatus,
)
from .validate import CHG_COLLISION, collision_issues
from .io import (
    CHG_ADDRESS_SYNTAX,
    CHG_BYTES_SYNTAX,
    CHG_ENCODE_FAIL,
    CHG_ENCODING_UNKNOWN,
    CHG_FORMAT,
    CHG_KIND_UNKNOWN,
    CHG_V1_FORMAT,
    CHG_VALUE_EMPTY,
    CHG_VALUE_MODE_UNKNOWN,
    DEFAULT_CHANGE_FILE_NAME,
    DOCUMENT_KINDS,
    FORMAT_ID,
    FORMAT_VERSION,
    MF_BAD_STRUCTURE,
    MF_ENTRY_COUNT_CEILING,
    MF_ENTRY_LIMIT,
    MF_JSON_PARSE,
    MF_PATH_UNRESOLVED,
    MF_RUN_LENGTH_CEILING,
    MF_SIZE_CAP,
    MF_WRITE_CONTAINMENT,
    READ_SIZE_CAP_BYTES,
    V1_FORMAT_ID,
    VALUE_MODES,
    read_change_document,
    serialize_change_document,
    write_change_document,
)

__all__ = [
    "CHANGES_ARTIFACT",
    "ChangeDocument",
    "ChangeEntry",
    "MemoryStatus",
    "CHG_COLLISION",
    "collision_issues",
    "CHG_ADDRESS_SYNTAX",
    "CHG_BYTES_SYNTAX",
    "CHG_ENCODE_FAIL",
    "CHG_ENCODING_UNKNOWN",
    "CHG_FORMAT",
    "CHG_KIND_UNKNOWN",
    "CHG_V1_FORMAT",
    "CHG_VALUE_EMPTY",
    "CHG_VALUE_MODE_UNKNOWN",
    "DEFAULT_CHANGE_FILE_NAME",
    "DOCUMENT_KINDS",
    "FORMAT_ID",
    "FORMAT_VERSION",
    "MF_BAD_STRUCTURE",
    "MF_ENTRY_COUNT_CEILING",
    "MF_ENTRY_LIMIT",
    "MF_JSON_PARSE",
    "MF_PATH_UNRESOLVED",
    "MF_RUN_LENGTH_CEILING",
    "MF_SIZE_CAP",
    "MF_WRITE_CONTAINMENT",
    "READ_SIZE_CAP_BYTES",
    "V1_FORMAT_ID",
    "VALUE_MODES",
    "read_change_document",
    "serialize_change_document",
    "write_change_document",
]
