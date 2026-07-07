# Executive summary — s19tool — Batch 26

> Phase 6 artifact. Audience: non-technical stakeholder. 1-2 pages.

## Bottom line (read first)

- **What we delivered:** A way for engineers to see, at a glance, *what kind of data* lives in each region of a firmware image. The tool now measures the "randomness" of the data across the image and sorts each region into four easy-to-read bands — **empty/padding, ordinary low-randomness, medium, and high (looks compressed or encrypted)**. This is delivered three ways: a behind-the-scenes engine, a section in the generated project report, and an interactive on-screen viewer opened with a single key (the `e` key) that shows a colour-coded strip plus a jump-to-address list.
- **Why it matters:** Raw firmware, viewed as hexadecimal bytes, tells you *what* the bytes are but not their *character* — which regions are unused padding, which are ordinary code and data, and which look compressed or encrypted. Judging that by eye is slow and error-prone. This feature answers that question directly and consistently, both on screen and in the project report handed to reviewers.
- **This completes the feature.** It is the final piece of Feature #12; the two earlier pieces shipped in an earlier batch (Batch 24). Feature #12 is now closed.
- **Quality of the evidence:** Built and validated in a single clean pass — every planned check passed on the first attempt, roughly **35 new automated tests** were added, the protected core of the tool was left untouched, and independent review ran at every step.
- **Next step:** Merge is pending operator approval, together with one routine housekeeping step (a refresh of some visual reference images — known, non-blocking, and already planned).

---

## Context (reference)

### Context

s19tool is the desktop tool our engineers use to inspect and edit firmware files. Firmware images are large and, viewed as raw hexadecimal, are just long runs of bytes. Engineers frequently need to understand the *nature* of the data in each part of the image — is this region empty filler, normal program code, stored data, or something that looks compressed or encrypted? — before they can reason about the firmware.

### Problem

The existing hex view shows the exact bytes but not their character. To tell padding from code from encrypted-looking data, an engineer had to scan the bytes and infer the pattern by eye. That is slow, easy to get wrong, and does not scale to a large image. There was no consistent, at-a-glance signal for "what kind of data is this?" — and nothing that reviewers could rely on in the project report.

### Solution

The tool now computes a standard measure of **randomness** (technically, Shannon entropy — a single number per region indicating how unpredictable its bytes are) across the whole image and sorts each region into four bands:

- **Padding** — empty or constant filler.
- **Low** — ordinary, structured data or code.
- **Medium** — mixed content.
- **High / random** — looks compressed or encrypted (very unpredictable).

This is delivered in three complementary ways:

- **A behind-the-scenes engine** that does the measurement. It is deliberately self-contained and deterministic, so the same image always produces the same result.
- **A section in the generated project report**, per firmware variant, so the classification travels with the written record that reviewers and auditors read. The report deliberately shows only the summary bands — never raw firmware bytes.
- **An interactive on-screen viewer**, opened with the `e` key: a colour-coded strip across the image plus a jump-to-address list, so an engineer can spot a high-randomness region and jump straight to it.

### Outcomes / results

- **Built right the first time.** The batch moved through every stage in a single clean pass — requirements, review, implementation, and validation each passed on the first attempt, with no blocking problems and no reworked stages.
- **Verified end-to-end.** Roughly **35 new automated tests** were added and passed. The tests observe the feature the way an engineer would use it: they check the engine's exact numbers, re-read the *actual written report file* from disk to confirm the section is really there, and drive the real on-screen viewer through the `e` key.
- **The feature was proven, not assumed.** For the report section, the test was run first with the report wiring deliberately disconnected — and it **failed exactly as it should**, confirming the test is checking the real feature and not a lucky coincidence — then passed once the wiring was connected.
- **No change to the protected core.** The locked-down, sensitive parsing core of the tool was left completely untouched — confirmed automatically.
- **Independent review at every step.** Each increment was reviewed independently for correctness and safety before approval; the report was confirmed to expose only summary bands, never raw bytes.
- **One honest caveat, already planned for.** Adding the new `e` shortcut changed a small on-screen footer that appears on every screen. That makes a set of stored *visual reference images* (used to catch accidental layout changes) no longer match. This is a **known, non-blocking housekeeping item** — a routine refresh of those reference images after merge, following the same procedure used in a prior batch. It is not a defect in the feature.

### Next steps

- **Merge (pending approval):** the pull request and merge await operator sign-off — a routine closing step, no open risks.
- **Routine reference-image refresh:** after merge, regenerate the affected visual reference images in the standard controlled environment, then a small follow-up confirms all of them pass. Planned and expected.
- **Minor items:** a few small code-hygiene cleanups are logged in the backlog; none affect users.
- **Feature #12 is complete.** With this piece shipped, the whole of Feature #12 is closed; the next batch will pull the next item from the backlog.
