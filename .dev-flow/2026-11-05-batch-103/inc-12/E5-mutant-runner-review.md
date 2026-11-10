# Inc 12 — mutation runner review

Independent read-only review of `dd1f1be1` found instrument defects, not product defects:

- HIGH: every pytest rc=1 was KILLED, including fixture/setup/teardown errors.
- HIGH: inherited pytest options/plugins could make baseline and arms vacuous.
- MEDIUM: no invocation timeout; signal exits were BAD rather than CRASH; source/clone commit and test identities were not recorded; transcript paths did not resolve; absolute account paths leaked into summaries; CONTROL-KILL contaminated product-arm counts.

DeepSeek corrected the runner in `3da3b388`: JUnit call-phase verdicts, setup/teardown/collection BAD, sanitized environment and selected-node accounting, process-group timeout and signal CRASH, source/clone commit equality and dirty-tree refusal, test hashes, resolving transcript paths, tokenized publication paths and public redacted transcripts, and control separation.

Executed Linux self-test (`evidence-e5-mutant-selftest.txt`): **PASSED**. It confirms pass→SURVIVED, call assertion→KILLED, fixture error→BAD and collect-only→BAD. Product-arm results are recorded separately in the final mutant table; no count is claimed here.
