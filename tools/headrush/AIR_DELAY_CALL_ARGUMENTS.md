# HeadRush Core 5.2.0 — AIR Delay call argument investigation

Date: 2026-11-19. The original user's extracted `/usr/Evil/Evil` was read
**offline and without modification**. It is a stripped ARM32 ELF, size
50,711,456 bytes; SHA-256:
`1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

## Two shared function entry points

LLVM 17 ARM deassembly confirms that the previously mapped addresses
`0x014CDA18` and `0x014CD12C` are actual ARM function entry sequences,
starting with callee-saved register and stack setup. Both functions then
handle C++ string-like objects and call shared helpers, consistent with
a registration or initialization mechanism. **Exact semantics and
parameter-bounds metadata are not established.**

At `0x00A11E64..0x00A11F84`, the AIR Delay setup block calls those
functions with a fifth argument written to stack location `[sp]`.
A statically verified, constant-propagation audit yielded:

| Parameter | Raw `[sp]` bits | If interpreted as IEEE754 float32 |
| --- | --- | --- |
| `HPFdbk` | unresolved | unresolved |
| `FdbkClip` | unresolved | unresolved |
| `FdbkComp` | `0x3F400000` | 0.75 |
| `LFODepth` | `0x00000000` | 0.0 |
| `LFORate` | `0x3E99999A` | 0.3000000119 |
| `FdbkIn` | `0x00000000` | 0.0 |
| `FdbkOut` | `0x3F800000` | 1.0 |

**Important caution:** these are constants passed as one argument,
not verified minimum, maximum, normalized limits, or runtime algorithm
settings. Their location and numeric bit pattern are evidence; any
semantic interpretation must be corroborated by analysis of the callee.
The analysis labels `HPFdbk` and `FdbkClip` unknown instead of
inventing values.

The script decodes ARM `MOV` immediate, `MOVW`, `MOVT`,
`STR [sp]` and resets volatile register knowledge at other direct
calls. It deliberately does not claim complete data-flow reconstruction.

## Reproduction

```bash
python3 tools/headrush/trace_spatial_parameter_sites.py \
  --evil /private/Evil --output /private/spatial-sites.json

python3 tools/headrush/trace_airdelay_call_constants.py \
  --evil /private/Evil --references /private/spatial-sites.json \
  --output /private/airdelay-constants.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

This procedure does not modify the device, its factory rigs, or firmware.
No proprietary files are committed.

## Next evidence

1. Examine C++ helper data structures and disassemble branches in both
   callees to establish the fifth argument's **meaning and type**.
2. Look for the specific callee paths used by `HPFdbk` and `FdbkClip`;
   they may have different argument layouts than the float-like paths.
3. Relate controller strings to the SESP `AIRDelay` algorithm only after
   tracing their use, not on the basis of nearby RTTI names.
4. Repeat with `Shimmer` and `MultiChorus`, whose full parameter
   paths were not present in the earlier exact-string scanner.
