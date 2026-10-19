<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026-10-12-rev102 | flow_hash: 6f99c414f39c84d9 | corpus: 73 requirement files | corpus digest: 08b55e2304e23731 -->

# ATLAS-ORPHANS — where are the holes?

- US/HLR/LLR in the batch record, never in the canon: **1104**
- US/HLR/LLR in the canon, in no batch record: **4** — `LLR-045A`, `LLR-045D`, `LLR-051.1-.8`, `US-77`
- corpus heading ids never in the canon: **328**
- registry ids never mentioned by tests/: **542**

## UNPARSED census — what this Atlas failed to read (§5.3)

An Atlas that cannot state what it failed to read is not accepted; V20 BLOCKs when this count rises against the committed copy.

UNPARSED census: 5 item(s)
- [BATCHES] .dev-flow/2026-07-23-batch-n8 — dated dir does not match the batch pattern — census, not silence
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:382 — field `fn` absorbed 149 chars of trailing prose (the IFC parser has no block terminator)
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:452 — field `address` absorbed 99 chars of trailing prose (the IFC parser has no block terminator)
- [IFC] .dev-flow/2026-10-12-batch-94/01-requirements.md:1221 — field `owner` absorbed 1416 chars of trailing prose (the IFC parser has no block terminator)
- [IFC] .dev-flow/2026-10-13-batch-95/01-requirements.md:864 — field `inputs` absorbed 127 chars of trailing prose (the IFC parser has no block terminator)
