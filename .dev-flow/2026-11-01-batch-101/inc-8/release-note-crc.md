# Release note — CRC init with `reverse` (v1.0.0)

Batch-101 Inc 8 (D13-20). A tracked batch-end deliverable (E3 ruling S-8): the operator's release page carries this text.

## What changed

The CRC operation (Operations dialog: CRC check and Write CRC) and the Flow CRC block now compute every CRC by the parametric CRC model: the register starts at `init` exactly as written in the CRC config. Earlier versions bit-reversed `init` first when `reverse` was `true`. The CRC Designer always used the model; the two now agree for the same parameters.

## Am I affected?

Only if a CRC config has **both**:
- `"reverse": true`, and
- an `init` that is **not bit-symmetric** — its 32 bits do not read the same from both ends.

`0x00000000` and `0xFFFFFFFF` are bit-symmetric, so the example config, the CRC-32 (zlib / PKZIP) defaults and every config with one of these two inits are **not affected**. Configs with `"reverse": false` are not affected.

To check an init: write it as 32 binary digits; if the string reversed is the same string, the init is bit-symmetric (for example `0x0FF00FF0`). Otherwise the config is affected.

## What an affected config does now

- Its CRC values change. Example over the 9 bytes `123456789`, polynomial `0x04C11DB7`, init `0x12345678`, reverse `true`, final_xor `0xFFFFFFFF`: earlier versions `0x18026B2A`, v1.0.0 `0x0F8B7431` (the model's value, the same as the CRC Designer).
- An image written with that config by an earlier version now shows **MISMATCH** in a CRC check, and the Flow CRC block writes the new value.

## How to keep the earlier value

Replace `init` by its **bit-reversed value** (the 32 bits in reverse order). The CRC is then identical to the earlier version's for every input. Example: init `0x12345678` becomes `0x1E6A2C48`.

If the target device expects the earlier value, make this change before running a check or a write with v1.0.0. If the target expects the catalogue algorithm for these parameters, keep the config as it is: v1.0.0 now gives the catalogue value.
