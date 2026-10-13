<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026-10-12-rev102 | flow_hash: ef4561d60ce65e0f | corpus: 72 requirement files | corpus digest: 3a5912b207cbeb64 -->

# ATLAS-ORPHANS — where are the holes?

- US/HLR/LLR in the batch record, never in the canon: **1074**
- US/HLR/LLR in the canon, in no batch record: **4** — `LLR-045A`, `LLR-045D`, `LLR-051.1-.8`, `US-77`
- corpus heading ids never in the canon: **326**
- registry ids never mentioned by tests/: **521**

## UNPARSED census — what this Atlas failed to read (§5.3)

An Atlas that cannot state what it failed to read is not accepted; V20 BLOCKs when this count rises against the committed copy.

UNPARSED census: 3 item(s)
- [BATCHES] .dev-flow/2026-07-23-batch-n8 — dated dir does not match the batch pattern — census, not silence
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:382 — field `fn` absorbed 149 chars of trailing prose (the IFC parser has no block terminator)
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:452 — field `address` absorbed 99 chars of trailing prose (the IFC parser has no block terminator)
