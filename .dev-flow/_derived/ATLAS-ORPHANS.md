<!-- DERIVED — DO NOT EDIT. Regenerate: devflow-validate.py --atlas --write -->
<!-- flow_version: 2026-10-12-rev102 | flow_hash: ef4561d60ce65e0f | corpus: 71 requirement files | corpus digest: 0d8e4bb7a39f8421 -->

# ATLAS-ORPHANS — where are the holes?

- US/HLR/LLR in the batch record, never in the canon: **1075**
- US/HLR/LLR in the canon, in no batch record: **39** — `HLR-136`, `HLR-141`, `HLR-142`, `LLR-045A`, `LLR-045D`, `LLR-051.1-.8`, `LLR-135.1`, `LLR-135.2`, `LLR-135.3`, `LLR-135.4`, `LLR-135.5`, `LLR-135.6`, `LLR-135.7`, `LLR-136.1`, `LLR-136.2`, `LLR-136.3`, `LLR-136.4`, `LLR-136.5`, `LLR-136.6`, `LLR-137.1`, `LLR-137.2`, `LLR-137.3`, `LLR-137.4`, `LLR-138.1`, `LLR-138.2`, `LLR-138.3`, `LLR-138.4`, `LLR-139.1`, `LLR-139.2`, `LLR-139.3`, `LLR-140.1`, `LLR-140.2`, `LLR-141.1`, `LLR-141.2`, `LLR-142.1`, `LLR-142.2`, `LLR-143.1`, `LLR-143.2`, `US-77`
- corpus heading ids never in the canon: **326**
- registry ids never mentioned by tests/: **543**

## UNPARSED census — what this Atlas failed to read (§5.3)

An Atlas that cannot state what it failed to read is not accepted; V20 BLOCKs when this count rises against the committed copy.

UNPARSED census: 3 item(s)
- [BATCHES] .dev-flow/2026-07-23-batch-n8 — dated dir does not match the batch pattern — census, not silence
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:382 — field `fn` absorbed 149 chars of trailing prose (the IFC parser has no block terminator)
- [IFC] .dev-flow/2026-10-11-batch-92/01-requirements.md:452 — field `address` absorbed 99 chars of trailing prose (the IFC parser has no block terminator)
