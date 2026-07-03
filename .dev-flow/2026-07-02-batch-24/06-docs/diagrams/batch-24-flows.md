# Diagrams — Batch 2026-07-02-batch-24 (A2L↔Issues reconcile + before/after report)

> Three views of the shipped behavior: (a) the reconcile data flow with both directions annotated, (b) the before/after report chain with its refusal branches, (c) the no-MAC wipe fix before/after. All symbols cited in `functionality.md` §3 with re-verified file:line.

---

## (a) Reconcile data flow — tags → enrichment → supplemental rule → merged report → row-severity map → rendered rows

Direction 1 (red ⇒ issue) is the supplemental-rule branch feeding the Issues surface; direction 2 (issue ⇒ red) is the severity-map branch feeding row colour. Both read the SAME merged report, which is why the two surfaces can no longer disagree.

```mermaid
flowchart TB
    L[Load S19 + A2L<br/>shipped load chain] --> E["A2L enrichment (frozen tui/a2l.py)<br/>sets schema_ok per tag<br/>(virtual + no address → schema_ok=True, exempt)"]
    E --> BR["build_validation_report<br/>validation_service.py:111 (open seam)"]

    subgraph report["Merged report — BOTH branches (MAC-only + primary-backed)"]
        ENG["Frozen engine rules (validation/rules.py)<br/>A2L_INVALID_ADDRESS · A2L_DUPLICATE_SYMBOL · …"] --> MERGE
        SUP["DIRECTION 1 — supplemental_a2l_row_issues (:20)<br/>schema_ok is False → A2L_TAG_SCHEMA_INCOMPLETE (ERROR)<br/>dedup: casefolded symbol × a2l × ERROR<br/>(no double-report vs engine ERRORs)"] --> MERGE
        MERGE["merge before dedupe_issues"]
    end

    BR --> report
    MERGE --> INST["_validation_issues installed<br/>worker path: precomputed pre-render<br/>sync path: via the FIXED no-MAC branch (diagram c)<br/>order pin: after enrichment, before rows render (update_a2l_view :7668)"]

    INST --> ISSUES["Issues view rows<br/>#validation_issues_list + issues report<br/>(red row now has its named ERROR here)"]
    INST --> MAP["DIRECTION 2 — _a2l_issue_severity_map (:234)<br/>casefolded symbol → max severity<br/>(a2l + non-empty symbol only; built once per render :7730)"]
    MAP --> SEV["_a2l_tag_row_severity (:295)<br/>symbol maps to ERROR → red<br/>WARNING / unmapped → existing ladder unchanged (D-2)"]
    E -->|schema_ok red · green/white/grey ladder| SEV
    SEV --> ROWS["Rendered A2L rows (#a2l_tags_list)<br/>duplicate-symbol rows now red"]

    ISSUES -.->|"AT-036a: every red row named here (was: Rendered issue rows: [])"| GATE1[["GATE AT-036a"]]
    ROWS -.->|"AT-037a: ERROR issue reds both rows (was: non-red)"| GATE2[["GATE AT-037a"]]
```

---

## (b) Before/after report chain — apply → save-back → offer → `b` → preconditions → compare → report pair

```mermaid
flowchart TB
    A["Apply change document<br/>ChangeService.apply → last_summary<br/>(entries carry before_bytes/after_bytes)"] --> S["Save-back (save_patched)<br/>stamps saved_path (post-dedup, never clobber)<br/>+ source_image_path = loaded.path (B-2 stamp, change_service.py:933)"]
    S --> O["Offer notify (information)<br/>after _surface_verify_result — a verify MISMATCH<br/>does not suppress it (report is disk-to-disk honest)"]
    O --> B["Operator presses b<br/>action_before_after_report (app.py:1710)"]
    B --> C{"compose_before_after_report<br/>before_after_service.py:182<br/>preconditions 1–5, in order"}

    C -->|"1 no summary"| R1["REFUSE: 'no saved patched image'"]
    C -->|"2 saved_path None (declined save)"| R1
    C -->|"3 either path missing on disk"| R2["REFUSE: names the missing file"]
    C -->|"4 loaded.path != source_image_path (STALE, B-2)"| R3["REFUSE: stale-summary diagnostic"]
    C -->|"5 saved_path outside current project/workarea"| R3
    C -->|"no active project (D-3)"| R4["REFUSE: names the manual A↔B path"]
    C -->|"reports/ is a symlink (S-F4)"| R5["REFUSE: destination refused"]

    R1 & R2 & R3 & R4 & R5 --> Z["Surfaced diagnostic on status line<br/>ZERO files written · app keeps running<br/>(AT-038b/c/d GUARD: positive-diagnostic + empty-listing asserts)"]

    C -->|all pass| CMP["compare_images — two SOURCE_EXTERNAL sources<br/>BOTH re-parsed FRESH from disk<br/>(original = loaded.path · after = saved_path)"]
    CMP --> GEN["generate_diff_report + _html<br/>with provenance + linkage kwargs + own stem<br/>(default-off: default output byte-identical, golden-pinned)"]
    GEN --> RP["Report pair in &lt;project&gt;/reports/<br/>timestamp-before-after-report.md + .html<br/>provenance header · linkage table · diff fences (-/+ bytes)"]
    RP --> SURF["Status line: 'Before/after report written: md | html'"]
    SURF -.->|"C-12 gate: surfaced path → dir-diff → re-read THAT file<br/>C-10: header 'after' == img-patched_1.s19 (dedup literal, not an echo)"| GATE[["GATE AT-038a"]]
```

---

## (c) The no-MAC wipe fix (B-1 / LLR-037.4) — before vs after

Old behavior: every session without MAC records lost its validation report — the reconcile's Issues-side observable was unobservable, and the shipped product was broken in all no-MAC sessions.

```mermaid
flowchart LR
    subgraph OLD["BEFORE (shipped bug)"]
        direction TB
        O1["update_mac_view<br/>no MAC records?"] -->|yes| O2["WIPE _validation_report<br/>WIPE _validation_issues<br/>+ early return"]
        O2 --> O3["Issues view EMPTY in every<br/>S19+A2L (no-MAC) session<br/>— regardless of engine output"]
    end

    subgraph NEW["AFTER (LLR-037.4, ships in I1)"]
        direction TB
        N1["update_mac_view<br/>no MAC records?"] -->|yes| N2["_refresh_no_mac_validation (app.py:6053)"]
        N2 -->|"no primary file"| N3["keep the historical clear<br/>(verbatim — TC-037.4 no-primary)"]
        N2 -->|"primary loaded"| N4["compute/RETAIN report for the<br/>primary+A2L pair via the cache<br/>_mac_view_cache_key_for (:6000)<br/>stable key: id(loaded) when records empty"]
        N4 --> N5["worker-precomputed report = cache HIT<br/>(0 rebuilds, counter-proven)<br/>sync path = compute exactly once"]
        N5 --> N6["Issues view populated in no-MAC sessions<br/>(AT-036a observable made real)"]
    end

    OLD ==>|"B-1 BLOCKER, Phase-2 architect catch<br/>operator chose fix-the-wipe (AM-1)"| NEW
```

Fixture-discipline note: the US-032/033 acceptance tests are deliberately **MAC-less** — adding a MAC record would sidestep the old wipe and green the ATs while the shipped bug persisted (the C-12-family masking class). The constraint travels inside the tests themselves.
