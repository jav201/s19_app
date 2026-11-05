# Changelog

Changes that alter what s19_app computes or writes, newest release first.

## 1.0.0

### CRC: init is taken as written when reverse is true

#### What changed

The CRC operation (Operations dialog: CRC check and Write CRC) and the Flow CRC block now compute every CRC by the parametric CRC model: the register starts at `init` exactly as written in the CRC config. Earlier versions bit-reversed `init` first when `reverse` was `true`. The CRC Designer always used the model; the two now agree for the same parameters.

#### Am I affected?

Only if a CRC config has **both**:
- `"reverse": true`, and
- an `init` that is **not bit-symmetric** — its 32 bits do not read the same from both ends.

`0x00000000` and `0xFFFFFFFF` are bit-symmetric, so the example config, the CRC-32 (zlib / PKZIP) defaults and every config with one of these two inits are **not affected**. Configs with `"reverse": false` are not affected.

To check an init: write it as 32 binary digits; if the string reversed is the same string, the init is bit-symmetric (for example `0x0FF00FF0`). Otherwise the config is affected.

#### What an affected config does now

- Its CRC values change. Example over the 9 bytes `123456789`, polynomial `0x04C11DB7`, init `0x12345678`, reverse `true`, final_xor `0xFFFFFFFF`: earlier versions `0x18026B2A`, v1.0.0 `0x0F8B7431` (the model's value, the same as the CRC Designer).
- An image written with that config by an earlier version now shows **MISMATCH** in a CRC check, and the Flow CRC block writes the new value.

#### How to keep the earlier value

Replace `init` by its **bit-reversed value** (the 32 bits in reverse order). The CRC is then identical to the earlier version's for every input. Example: init `0x12345678` becomes `0x1E6A2C48`.

If the target device expects the earlier value, make this change before running a check or a write with v1.0.0. If the target expects the catalogue algorithm for these parameters, keep the config as it is: v1.0.0 now gives the catalogue value.

### Reports

The before/after report (Patch Editor → Write before/after report, `b`) is titled `Before/after report` in both files; earlier versions titled it `Diff report`. Its header computes the artifact lines against the loaded A2L and MAC (`a2l=used (<covered>/<total>)` where it read `a2l=absent`), and its Runs table fills the Symbols column from the loaded A2L and MAC.

Diff and before/after report files hold every hex window whole; earlier versions cut each Markdown window, and the HTML window of a run present in one image only, at 512 rows.

In the Markdown file of a diff or before/after report, names (image labels, variant ids, symbol, document and filter names) carry a backslash before each Markdown character (`CAL\_A`, `img\.s19`); paths stay as written inside their code spans (a backtick in a path shows as `�`). A Markdown reader shows both exactly. A plain-text search of the `.md` file for `CAL_A` no longer matches; search the HTML file instead.

If writing a diff or before/after report fails, the reports folder keeps no partial report file and no Markdown file without its HTML file.

A control or direction-override character in a name is written as `�` in both report files (a tab or a line break as one space).

An interrupted report write can leave a `<file name>.<hex>.part` file beside the report; it is safe to delete.

### Flows

When a confirmed external step copies an output that differs from the file already under its name, the copy gets a numbered name (`<name>_1.<ext>`) as before, and a later block of the same run that names the output now reads this run's copy; its summary ends ` · read <copy file name> in place of <ref>`. Earlier versions read the first copy.

A confirmed external step's relative output path is read under the project folder; earlier versions read it against the working directory.

A confirmed external step whose relative log or output path climbs above the project folder now stops the flow with `external step refused`; give an absolute path for a file outside the project.

When a PATCH block reads an external step's copy in place of its change document or A2L ref, the flow report and the chain-set report give the copy's file name in place of the ref.

### CRC config: refusal reasons

A CRC config the app cannot read now names its cause after `CRC config is structurally invalid: `: `field '<name>' is missing`, `field '<name>' is not a number: <value>`, or `a CRC Designer template is not a CRC config - it has no regions or groups`. Earlier versions named only the key (`'reverse'`) or passed the parser's own message through.

### Projects

Loading an S19, Intel HEX, MAC or A2L file into a project whose folder was deleted outside the app no longer re-creates the folder; for an S19, Intel HEX or MAC file the status reads `Project sync NOT done: project '<name>' could not be read — check that the folder can be opened, then load again.`
