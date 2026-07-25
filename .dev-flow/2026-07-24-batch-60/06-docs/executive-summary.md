# Executive summary · batch-60 (FB-P1b flow-run report generation)

A Flow Builder pipeline that contains a **REPORT block** now produces a real markdown report:
a pipeline ledger of every block that ran, its findings, the image footprint (including the
before/after growth when a CRC ran), and the files it wrote. The report lands in the project's
`reports/` folder under the same naming convention as project reports, so it appears in the
existing reports list and viewer with no new UI. This completes the carry batch-53 left open,
where the REPORT block was modelled and persisted but did nothing.

Two semantics were set by the operator: a report is generated **only** when a REPORT block is
present (never implicitly), and the block is **positional** — it reports the run up to its own
position, so a REPORT at the end captures the whole pipeline while a mid-flow REPORT captures a
prefix. A run that *broke* still writes its report, labelled FAILED, because that is the run
most worth a durable record.

The batch's defining event was its **Phase-2 review, which failed the gate**. Two independent
reviewers found that the approved prototype escaped report text for the wrong markdown grammar:
the real renderer enables link auto-detection and strikethrough, so a hostile filename could
have injected a live link or struck a ledger row through — forgery in a document meant to be an
audit record. Two further contract defects were caught in the same pass. All three were fixed
**before any code was written**, and the acceptance test was rebuilt to verify output against
the real parser rather than against a list of characters. Report text is now defended twice:
sanitised when composed, and rendered by a hardened parser that cannot produce links or raw HTML
at all — which also protects the pre-existing project reports.
