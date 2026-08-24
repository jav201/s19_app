<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026.08.24-rev45 | flow_hash: 09bea075fc183f8b | corpus: 64 requirement files | corpus digest: 525c7a6d8e24682e -->

# ATLAS-ORPHANS — where are the holes?

- US/HLR/LLR in the batch record, never in the canon: **1005**
- US/HLR/LLR in the canon, in no batch record: **5** — `HLR-053..HLR-056`, `LLR-045A`, `LLR-045D`, `LLR-051.1-.8`, `US-77`
- corpus heading ids never in the canon: **282**
- registry ids never mentioned by tests/: **554**

## UNPARSED census — what this Atlas failed to read (§5.3)

An Atlas that cannot state what it failed to read is not accepted; V20 BLOCKs when this count rises against the committed copy.

UNPARSED census: 2 item(s)
- [BATCHES] .dev-flow/2026-07-23-batch-n8 — dated dir does not match the batch pattern — census, not silence
- [IFC] .dev-flow/2026-08-21-batch-85/01-requirements.md:372 — field `owner` absorbed 801 chars of trailing prose (the IFC parser has no block terminator)
