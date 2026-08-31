# Branch prune — 2026-08-30

42 local branches deleted after a triage of all 45 unmerged refs. 41 were found
patch-equivalent to `main`; 4 held unique content, of which 3 were rescued in PR #205
and 1 archived as the tag `archive/web-flask-viewer`.

**Every tip is recorded below. To restore any branch: `git branch <name> <sha>`.**
Git's reflog also holds these for 90 days. Deletion used `-D` rather than `-d` because
this repo squash-merges, so `git branch -d` refuses branches whose patches are already
in `main` — `-d`'s safety net does not apply here, and this table replaces it.

Three branches were SKIPPED because a worktree still holds them:
`claude/batch-82-lane-a-scoping`, `claude/flow-version-sync-fix-8d7086`,
`claude/blind-spot-assembled-selector-c2c117`. Removing those worktrees is a separate
decision and was not taken.

| Branch | Tip | Newest commit |
|---|---|---|
| `backup/batch-64-addendum-uncommitted` | `9f94e06` | 2026-07-27 |
| `backup/batch-65-conflicted-62c7141` | `62c7141` | 2026-07-28 |
| `chore/backlog-refresh-batch45` | `82c599f` | 2026-07-15 |
| `chore/batch-48-snapshot-regen` | `88393e5` | 2026-07-17 |
| `chore/json-height-snapshot-regen` | `76a320e` | 2026-07-17 |
| `claude/a2l-alignment-aware-b56` | `741e86e` | 2026-07-20 |
| `claude/at-tc-registry-design-f61bcd` | `aefd3ab` | 2026-07-31 |
| `claude/at-tc-registry-guard-3a1043` | `2ccf09f` | 2026-07-31 |
| `claude/backlog-at-tc-registry-carries` | `34a84f0` | 2026-07-31 |
| `claude/backlog-ci-paths-ignore` | `b74f43a` | 2026-07-30 |
| `claude/batch-62-report-escaping` | `ce349a6` | 2026-07-26 |
| `claude/batch-64-addendum-producer-bound` | `98b5b7a` | 2026-07-27 |
| `claude/batch-65-addendum-producer-bound` | `374ad90` | 2026-07-27 |
| `claude/batch-72-sync` | `e7a2372` | 2026-07-30 |
| `claude/batch-73-linkage-fix-0372a0` | `39cb970` | 2026-07-31 |
| `claude/batch-73-sync-record` | `e25cff7` | 2026-07-31 |
| `claude/batch-74-artifacts` | `2b9988e` | 2026-07-31 |
| `claude/batch-74-s19-app-a693ff` | `6e21dbb` | 2026-07-31 |
| `claude/batch-74-sync` | `c3ab5c1` | 2026-07-31 |
| `claude/batch-75-closeout` | `14f57d3` | 2026-07-31 |
| `claude/batch-75-s19-app-a6fd1e` | `14f57d3` | 2026-07-31 |
| `claude/batch-76-closeout` | `b878298` | 2026-08-01 |
| `claude/batch-76-r-tui-102-impl` | `62f80c3` | 2026-08-01 |
| `claude/batch-77-closeout` | `66250d9` | 2026-08-03 |
| `claude/batch-77-memmap-variant-a` | `bfddcc9` | 2026-08-03 |
| `claude/batch-78-cmdbar-a2bdiff` | `ce75a39` | 2026-08-06 |
| `claude/batch-79-cmdbar-deletion` | `26f7b51` | 2026-08-13 |
| `claude/batch-87-ifc-reauthor-surface-3` | `65be751` | 2026-08-24 |
| `claude/blind-spot-assembled-selector` | `0173efb` | 2026-08-16 |
| `claude/branch-audit-extract` | `6b51ff4` | 2026-07-30 |
| `claude/c3-d2-triage` | `9b08afe` | 2026-07-31 |
| `claude/crc-algorithm-designer-8f82ae` | `dfbe704` | 2026-07-20 |
| `claude/handoff-batch84-flow-rev-85aa25` | `2dc68d5` | 2026-08-21 |
| `claude/lane-a-pending-move` | `bc11c55` | 2026-07-31 |
| `claude/skills-private-repo-changes-318db8` | `0697a59` | 2026-08-15 |
| `docs/backlog-header-refresh` | `445ac79` | 2026-07-23 |
| `docs/batch-62-closeout` | `b2ada6d` | 2026-07-26 |
| `docs/batch-62-sync-record` | `d5a331e` | 2026-07-26 |
| `docs/n8-closeout-controls-backlog` | `beb1e93` | 2026-07-23 |
| `feat/batch-51-flow-builder` | `5162c6c` | 2026-07-20 |
| `feat/batch-52-crc-block` | `7d3bc4f` | 2026-07-23 |
| `web/flask-viewer` | `73edc8c` | 2026-04-13 |
