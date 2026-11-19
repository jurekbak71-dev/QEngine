# Core 5.2.0 — parameter value encoding in ARM32 ELF

2026-11-19. Read-only analysis of the owner's extracted
`/usr/Evil/Evil` ARM32 binary, SHA-256
`1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

## Findings verified by exact ARM instructions

Two previously identified shared parameter calls use different
representation paths:

**Byte path**, callee VA `0x014CDA18`:
- `0x014CDA34: mov r8,r3` preserves the caller-provided input pointer
- `0x014CDB60: ldrb r3,[r8]` obtains a single byte
- `0x014CDB8C: mov r2,#4`
- `0x014CDB90: strb r2,[r3]` writes an observed representation tag 4

**Float path**, callee VA `0x014CD12C`:
- `0x014CD148: mov r8,r3`
- `0x014CD264: vldr s15,[r8]` reads 32-bit floating-point input
- `0x014CD278: vcvt.f64.f32 d16,s15` converts float32 to float64
- `0x014CD298: mov r2,#7`
- `0x014CD29C: strb r2,[r3]` writes an observed representation tag 7
- `0x014CD2A0: strd r8,r9,[r3,#8]` stores a doubleword from registers

**Result of scanning real ELF:** 10/10 exact instruction opcodes matched.

This strongly supports distinct typed data paths used when configuring
AIR Delay parameter objects. Although the byte path is consistent with
a boolean-like value, the exact tag meaning and field owner are not
independently established. The float path explicitly includes a
`float32` to `float64` conversion before storage.

These findings are **not evidence that an arbitrary value can be
entered through the user interface, that tags 4 and 7 correspond to a
public API, that the call-site constants are min/max/default, or that
the HeadRush supports native external DSP `.so` plugins.**

## Reproduction

```bash
python3 tools/headrush/verify_spatial_value_encoding.py \
    --evil /private/Evil --output /private/value-encoding.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

No firmware content is committed, no patching or hardware interaction.

## Recommended next technical steps

- Trace the objects returned by the shared helper at `0x0069C0E0`
  and determine where their tagged values are persisted.
- Trace the caller of each path to identify the receiving controller.
- Determine whether Shimmer and MultiChorus use the same tagged
  representation even though no exact `/Engine/Patch/<name>/<parameter>`
  strings were found by the earlier scanner.
- Test a supported native Core `.rig` export/import **only after**
  obtaining a genuine exported file and independent recovery plan.
