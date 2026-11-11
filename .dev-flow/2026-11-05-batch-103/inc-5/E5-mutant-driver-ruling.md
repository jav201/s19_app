# Inc 5 — mutant-driver review ruling

DeepSeek's read-only report (`evidence-e5/deepseek-mutant-driver-final.txt`) raised one MAJOR: the expected count 2 for M-007/M-008/M-009 appeared inconsistent with its whole-line indentation analysis.

**Ruling: rejected; no driver change.** The driver uses `str.count` and `str.split`, which operate on substrings, not whole lines. The eight-space anchor occurs once at the common fan-out and is also a substring of the twelve-space event-handler line. The actual count is therefore 2, and occurrence 1 replaces only the common reset. A local AST/static check against the final product found 28 patterns with zero count mismatches. Earlier executable transcripts also reached and killed M-007, M-008 and M-009 rather than aborting at M-007.

The verified PASS findings are retained: cwd-first import isolation, discriminating M-002 and M-022 with busy preserved for M-025, and conservative ERROR/TIMEOUT classification. Duplicate mutations M-003/M-004 and M-014/M-027 exercise different requirement scenarios and are non-blocking redundancy.

Final execution: baseline **103 passed**. The initial table killed 27; M-024 survived because the earlier mutation removed only the redundant method-level guard after `^L` had already been refused by `action_load_file`. The corrected M-024 disables that actual action guard and fails all four `.024` cases. Reconciled result: **28 killed, 0 survived, 0 ERROR, 0 TIMEOUT** (`mutant-summary-final.json`).
