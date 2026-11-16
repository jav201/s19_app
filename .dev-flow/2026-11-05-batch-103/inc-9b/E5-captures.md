# Inc 9b E5 — real Windows Terminal captures (CAP9b)

**Verdict: PASS for the 22 required sequences / 54 PNG + 54 exact-state sidecars; cleanup has the three disclosed orphan-window notes below.** Product proof is a `git archive` of `d05b5180e5f48d4a167d13e7fb45b24586293eb6`, the final E5 product SHA. The archive, generated fixtures and app work areas lived only in capture-owned scratch and were removed after evidence commit `05314689`.

## Method and protocol

- Four adapted scripts are in `evidence/e5/captures/scripts/`: `build_fixtures_9b.py`, `capture_9b_driver.py`, `capture_9b.ps1`, `run_all_9b.ps1`. Real product, real Windows Terminal, one new GUID-titled window per scene/size; no prototype or Pilot image is used as product proof.
- Requested and actual grids agree: 118x54, 220x60, and 80x24 only for long/short names. PNG dimensions are **1111x1091**, **2029x1205**, and **769x521** respectively. Every accepted image used `PrintWindow(...,2)`, was non-black and in truecolor; no fallback image was needed.
- The driver uses the app's real key path and result-preserving I-2 gates. `stage-refresh` holds the second refresh timer without blocking the UI, then invokes its callback once after `.f2` ACK. This is visual interposition, not a timing run.
- Each frame is an atomic painted-state report. The launcher writes the named PNG, copies those exact report bytes to `.png.txt`, appends PNG geometry/method/bytes/timestamp, then writes a unique ACK. `.f2` requires the next spinner in `◐→◓→◑→◒→◐`, same job/name and nondecreasing seconds. Final close is a separate flag.
- A frame-hold pauses only the cue timer between report and ACK and verifies the painted row remains stable; it then resumes. This fixed the observed WT-presentation contradiction E5-9b-8. Before close, the driver waits for all remaining bench jobs to quiesce.
- HOME/XDG_*/LOCALAPPDATA were isolated inside the launched command; `NO_COLOR` was removed and `COLORTERM=truecolor`. Both clipboard paths were stubs; all 54 sidecars report `stub_os_writes=0`. No real recent-files state was read or written.
- The shared lock was created with `FileMode.CreateNew` before each capture run, with `X9b E5 / CAP9b`, host PID and actual start. It was released in `finally` after each run and reacquired for each serial retry/resume. There was no competing owner and no WT launch without it. Final lock state: **absent**.
- Mechanical oracle: `evidence/e5/runs/validate_cap9b.py`; result `evidence/e5/runs/capture-validation.txt`: **22 sequences, 54 PNG/sidecars, PASS**, including spinner order, elapsed time, exact sidecars, ten idle frames, hostile names, cuts and post-write stage facts. Every valid and diagnostic PNG was opened and checked against its sidecar.

## Sequence index

Every listed PNG has a matching `.png.txt`. `f1/f2/idle` in the files column denotes the three complete filenames, not a missing-artifact shorthand.

| scene / size | files | verdict | painted reason |
|---|---|---|---|
| decode 118x54 | `decode.118x54.{f1,f2,idle}.png` | PASS | Amber round border, `decode LARGE`, distinct spinner; idle exact `STAGING SHEET`, accent border and LARGE values visible. |
| decode 220x60 | `decode.220x60.{f1,f2,idle}.png` | PASS | Same pair/idle contract at the wide grid; values visible after release. |
| preview 118x54 | `preview.118x54.{f1,f2,idle}.png` | PASS | `preview VAL_BLK_DEF_0001`, pair; after release the result/`✓` and idle look are visible. |
| preview 220x60 | `preview.220x60.{f1,f2,idle}.png` | PASS | Same preview result and idle restoration at 220. |
| stage-encode 118x54 | `stage-encode.118x54.{f1,f2,idle}.png` | PASS | `stage VAL_BLK_DEF_0001`; no document entry during encode hold; one 12-byte ledger entry after completion. |
| stage-encode 220x60 | `stage-encode.220x60.{f1,f2,idle}.png` | PASS | Same write/idle proof at 220; staged mark visible. |
| stage-refused 118x54 | `stage-refused.118x54.{f1,f2,idle}.png` | PASS | Held stage pair; after release the `60 outside -50..50` refusal remains, no entry and no busy cue. |
| stage-refused 220x60 | `stage-refused.220x60.{f1,f2,idle}.png` | PASS | Same refusal/no-entry/idle proof at 220. |
| stage-refresh 118x54 | `stage-refresh.118x54.{f1,f2,idle}.png` | PASS | Both busy frames are after the write: document count 1 while ledger is still 0; held callback count 1. Idle follows one resumed callback, with staged mark and the 1,048,576-byte entry. |
| stage-refresh 220x60 | `stage-refresh.220x60.{f1,f2,idle}.png` | PASS | Same post-write stepped-stage proof at 220. |
| name-markup 118x54 | `name-markup.118x54.{f1,f2}.png` | PASS | Literal `decode [@click=app.quit]X[/] ·`, no action/link; app running and two spinner frames. |
| name-markup 220x60 | `name-markup.220x60.{f1,f2}.png` | PASS | Same literal/running proof at 220. |
| name-brackets 118x54 | `name-brackets.118x54.{f1,f2}.png` | PASS | Literal `decode A[b]B ·`, not `AB`; pair valid. |
| name-brackets 220x60 | `name-brackets.220x60.{f1,f2}.png` | PASS | Same literal brackets at 220. |
| name-esc 118x54 | `name-esc.118x54.{f1,f2}.png` | PASS | Painted `decode A` + one U+FFFD + `[2J ·`; no raw ESC in sidecar. |
| name-esc 220x60 | `name-esc.220x60.{f1,f2}.png` | PASS | Same replacement/literal proof at 220. |
| name-c1 118x54 | `name-c1.118x54.{f1,f2}.png` | PASS | Painted `decode B` + one U+FFFD + `C ·`; no raw U+0085 in sidecar. |
| name-c1 220x60 | `name-c1.220x60.{f1,f2}.png` | PASS | Same C1 replacement at 220. |
| name-long 80x24 | `name-long.80x24.f1.png`, `.f2.png` | PASS | B=66: six `N` + one terminal `…`; seconds and complete ` keys still work ` survive. |
| name-long 118x54 | `name-long.118x54.f1.png`, `.f2.png` | PASS | B=106: 46 `N` + one `…`; complete pill tail. |
| name-long 220x60 | `name-long.220x60.f1.png`, `.f2.png` | PASS | B=190: 130 `N` + one `…`; complete pill tail. |
| name-short 80x24 | `name-short.80x24.f1.png`, `.f2.png` | PASS | Whole `decode N ·`, complete suffix and no ellipsis. |

## Diagnostics, supersession and cleanup

- Ten diagnostic PNG/sidecar pairs are not counted: `decode.118x54.pre-hold.*` (3), `name-brackets.118x54.pre-hold.*` (2), `stage-refresh.118x54.pre-quiesce.*` (3), and the `name-brackets` / `name-esc` `.error.seq1` frames (2). Error/diagnostic frames never substitute for required evidence.
- The pre-hold decode idle PNG still painted BUSY while its compositor report was idle; this contradiction caused E5-9b-8 and complete re-capture. Final PNG and sidecar agree.
- Every successful final window closed gracefully by its recorded launcher PID. PID-only fallback was used on failed sequences; never `pkill`, `killall`, image/name kill, title kill or shared-WT-host kill. Per-capture scratch folders were removed. The capture-owned archive/fixture tree was explicitly deleted after commit `05314689`; lock absent.
- **Cleanup note:** three failed-attempt windows remained as orphan WT windows: `b103-9b-name-brackets-118-a3871830`, `b103-9b-decode-118-da578b1e`, and `b103-9b-stage-refresh-118-d94769ff`. Their recorded launcher PIDs (`62740`, `29828`, `62352`) and enumerated descendants were already gone after PID-only fallback. No permitted PID-scoped action remained, and I did not touch the shared WT host or close by title. This is disclosed rather than hidden; all accepted capture sequences subsequently closed cleanly.
- The sanitized run log is `evidence/e5/captures/capture-run.log`; 96 C0/C1 bytes from PowerShell diagnostic output were removed from the log. No raw ESC/U+0085 occurs in records or sidecars. No Q9b measurement was rerun.
