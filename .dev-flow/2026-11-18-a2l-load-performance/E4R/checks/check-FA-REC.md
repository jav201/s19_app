# CHECK — FA-REC (orchestrator check; transcription unit, no tests)

- Unit: FA-REC [deepseek-flash · low], worker on the Linux reference host, HEAD ec8e7bd4.
- Scope: one new file, `E4R/CORRECTIONS.md` (diff: 1 file, 0 CR, needle scan TOTAL=0). No product, test or law file touched; no git writes.
- Row 1: header, paragraph, table A (A1–A16) and table B (B1–B9) present; every row of the brief is in the file, none dropped (scripted row-by-row comparison against the brief).
- Row 2: the worker re-ran one evidence command per row (grep / `sed -n` / `git show` / `sha256sum`, read-only) and logged 25 checks in its REPORT; 23 reproduced from the tree.
  - A2: the "77–78 of 102" seam-guard figure re-measured at HEAD as 83 of 102; verdict kept (MISLEADING), re-measurement added to the evidence. Accepted.
  - A13, A14: the worker marked them UNCONFIRMED because their evidence is not in the tree. The orchestrator verified both against the out-of-repo records: the operator decision P-167(a) (the batch-end suite was stopped by PID on the operator's choice) and the archived partial chunk-1 transcript (last progress mark 61 %, 21 `F`, counted by the orchestrator). Verdicts restored to the brief's (CONTRADICTED, INCOMPLETE), each row now says the evidence lives outside the repository and what the tree alone shows (P-167b/P-167c only; the conductor's committed copy stops at 5 % with 3 `F`).
- Row 3: status note present, verbatim.
- Worker deviation disclosed and accepted: no negative control (no guard to mutate in a transcription unit).

CHECK_DONE FA-REC GO (orchestrator)
