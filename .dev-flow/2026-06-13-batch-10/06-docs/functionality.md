# Functionality — s19_app — 2026-06-13-batch-10

> **Audience:** technical stakeholders (firmware/calibration engineers, the tool maintainer).
> **Purpose:** understand what batch-10 changes for you, the operator, when you use the TUI.
> **Voice:** operator-facing. What the tool now does, why it matters, and how to try it.

This batch delivers two things that work together: the tool can finally **write** Intel HEX (not just read it), and **every save is now verified** by re-reading the file and checking it really matches what you meant to save.

---

## 1. The tool can now write Intel HEX

Until this batch the tool could **read** an Intel HEX file but had no way to **write** one — the only firmware format it could emit was Motorola S19. If you loaded a HEX image, patched it, and tried to save, you hit a refusal. That asymmetry is now closed.

There is a new emitter that turns a memory image back into valid Intel HEX text. In plain terms, an Intel HEX file is a list of ASCII lines, each one a small "record". The emitter produces three kinds:

- **Data records** — the actual bytes, written at most 16 bytes per line, each tagged with its address.
- **Extended Linear Address (ELA) records** — Intel HEX addresses in a data line are only 16 bits wide, so for any image that reaches above `0xFFFF` the format needs a separate record to carry the upper 16 bits of the address. The emitter inserts one of these automatically whenever the high part of the address changes, so an image spanning, say, `0x0804_0000` lands at exactly the right place when re-read.
- **An EOF record** — the single terminating line (`:00000001FF`) every Intel HEX file ends with.

Every line carries the Intel HEX **checksum** — a one-byte value computed so the whole line sums to zero. (Worth noting for anyone porting code between formats: Intel HEX uses a *two's-complement* checksum, whereas S19 uses a *one's-complement* one. They are not interchangeable.)

The acceptance bar is a **semantic round-trip**: take an image, emit it as HEX text, write it, re-read it with the tool's own HEX parser, and the reconstructed image must equal the original byte-for-byte, with zero load errors. This is the same contract the existing S19 emitter holds itself to. Note this is *semantic* equality, not byte-for-byte text equality — the same image can be laid out in slightly different (equally valid) HEX text, so what is guaranteed is that the **meaning** survives, not the exact characters.

---

## 2. Saving a HEX image now works

With the emitter in place, the save-back flow accepts HEX images as first-class. When you save an image you loaded as HEX, the tool now:

- **Writes a real `.hex` file** — the old "HEX save not supported" refusal is retired for HEX sources.
- **Puts it in the work area** — saves go into the project's `.s19tool/workarea/` tree, the same place S19 saves already went.
- **Never silently clobbers** — if a file with that name already exists, the name is automatically suffixed so you don't overwrite anything by accident. Targets outside the work-area tree are refused rather than written.
- **Picks the right extension for you** — a HEX image suggests a `.hex` filename, an S19 image suggests `.s19`. The format you loaded drives the default.

If you try to save something that genuinely can't be persisted (for example a `.mac` symbol file), you still get a clear refusal — that guard is intact, only the HEX case was opened up.

---

## 3. Every save is now verified

This is the certainty feature. Saving a file and *assuming* it's correct is exactly where a silent emitter bug, a truncated write, or a bad checksum would slip through unnoticed. So after **every** save — HEX or S19 — the tool now does a verify-on-save:

1. It **re-reads the file it just wrote** using the parser for that format.
2. It **diffs** the re-read image against the image you actually meant to save, reusing the batch-09 compare engine (the same diff machinery behind the A↔B comparison feature). This is the first time that engine is used outside the comparison screen.
3. It reports the outcome.

The reporting is deliberately **quiet when things are fine, loud when they are not**:

- **Faithful save → one quiet line:** a single "Saved + verified" status. No modal, no interruption. Nothing is wrong, so nothing demands your attention.
- **Mismatch → a prominent notice:** a clear notice that names the file and gives a per-kind difference summary — how many runs changed, how many bytes differ, and in which direction. A byte the file *failed to persist* shows up differently from a byte that came back *wrong*, so the summary tells you the shape of the problem, not just that there is one.

Crucially, a mismatch does **not** delete or hide the file (collect-don't-abort). You asked for the save; the file is written; the notice simply tells you not to trust it so you can inspect it yourself. The summary reports **counts and addresses only** — never raw byte values — so nothing sensitive leaks into a notification.

The result of this checking effort is the same in both cases: you get certainty that the file on disk is what you intended, instead of hoping.

---

## 4. Small TUI cleanups folded in

Two hygiene fixes rode along with the TUI work:

- The modal screens used to share one widget id (`load_buttons`) across six different screens, which risked ambiguous lookups. Each modal's button row now has its own screen-unique id.
- The Operations screen's error handling was too broad: a `KeyError` raised *inside* an operation's own logic could be mislabeled as "unknown operation". The catch is now narrowed so it only covers the registry lookup, and a real failure inside an operation surfaces honestly instead of being swallowed.

---

## 5. How to try it (TUI save flow)

1. Launch the TUI: `s19tui` (optionally `s19tui --load <a HEX or S19 file>`).
2. Load a HEX image, then apply a patch / edit as usual.
3. Trigger the save-back. The suggested filename now ends in `.hex` for a HEX image.
4. Confirm the save. Watch the status line:
   - A faithful save shows a single **"Saved + verified"** line and no notice.
   - To see the loud path, this is exercised in the test suite by injecting an emitter that drops a byte: the file is still written, and a **mismatch notice** appears naming the file and the difference summary.
5. The file lands in `.s19tool/workarea/` (collision-suffixed if needed).

The same verify-on-save applies to S19 saves — it is not HEX-only.

---

## 6. What this batch does NOT do yet

Honest boundaries, so expectations are right:

- **No on-disk mismatch report.** A mismatch surfaces as an **inline summary** in the notice only. Writing a full Markdown/HTML mismatch report to disk (reusing the batch-09 diff-report service) was evaluated and **deferred** — it needs more assembly than the inline summary warrants for this batch.
- **CLI is still out.** All of this is **TUI-only**. The command-line interface was deliberately left out of scope (it is currently unmaintained).
- **Variant-batch HEX persist stays refused.** The interactive save-back path persists HEX now; the separate variant-execution batch-persist path still refuses HEX this batch.

---

## 7. Extension point — a reusable write→verify substrate

The emitter and the verify helper together form a small, reusable **write → re-read → diff** substrate. The emitter is a pure `(memory image, ranges) -> text` function with no side effects; the verify helper is a pure `(written file, intended image, format) -> result` check. Any future writer — a `project.json` manifest writer is the obvious next candidate — can plug into the same verify-on-save guarantee without reinventing the certainty check. The compare engine doing the diff is already format-agnostic, so the substrate is not tied to HEX or S19.

---

## 8. Key learning worth recording

The emitter was originally placed in the HEX **parser** module (`hexfile.py`) for format cohesion — write code next to read code. That broke a test guard: `hexfile.py` (along with the other parsing-layer modules) is **git-frozen** — a deliberate cross-batch invariant that forbids *any* change to the parsing engine versus `main`. Adding the writer there tripped that guard.

The resolution was to co-locate the emitter with the **existing S19 emitter** in `s19_app/tui/changes/io.py` instead — "all firmware emission lives in one module." This is not frozen, trips no guards, and keeps the read/write split clean: `hexfile.py` stays the pristine reader and round-trip oracle, while `io.py` owns emission for both formats. The takeaway for future placement decisions: check the engine-frozen guard family *before* deciding where new format code lives, not after.
