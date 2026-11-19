# HeadRush Core 5.2.0 — AIR Delay: verified call-site stack layout

Date: 2026-11-19. Source: original user-supplied
`/usr/Evil/Evil` (ARM32), SHA-256
`1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
Analysis **read-only**, no hardware I/O, no proprietary code published.

## What was newly verified

The seven consecutive ARM calls to the two shared functions
`0x014CDA18` and `0x014CD12C` use **three distinct outgoing stack
slots** in the code starting at `0x00A11E64`:

- `[sp]` — a constant bit pattern on five paths, unknown on two paths;
- `[sp,#4]` — an integer bit pattern of 30, 31 or 32;
- `[sp,#8]` — a PC-relative pointer to the *full corresponding
  parameter path string* (checked by decoding that string in ELF).

A read-only tracker recovers the following directly from ARM instructions:

| Parameter | Function VA | `[sp]` (float32 interpretation if known) | `[sp,#4]` | `[sp,#8]` |
|---|---|---:|---:|---|
| HPFdbk | 0x014CDA18 | unresolved | 30 | path pointer |
| FdbkClip | 0x014CDA18 | unresolved | 32 | path pointer |
| FdbkComp | 0x014CD12C | 0.75 | 32 | path pointer |
| LFODepth | 0x014CD12C | 0 | 32 | path pointer |
| LFORate | 0x014CD12C | approximately 0.3 | 31 | path pointer |
| FdbkIn | 0x014CD12C | 0 | 30 | path pointer |
| FdbkOut | 0x014CD12C | 1 | 31 | path pointer |

The preceding analysis already identified some of the `[sp]` bit
patterns. **This phase additionally ties all seven calls to an exact
string pointer and an independent 30/31/32-valued argument.**

### Important limitations

- There is **no evidence yet** that 30/31/32 are parameter identifiers,
  types, valid range limits or DSP controls. All four interpretations
  are hypotheses; the values may be another field entirely.
- An IEEE-754 float32 interpretation of a bit pattern is not proof
  that the callee interprets it as float32 (or as a default).
- Two `[sp]` values intentionally remain unresolved because the
  minimal constant-propagation pass cannot prove their origins.
- This is a **straight-line partial static reconstruction**; it
  does not prove arbitrary control flow, a stable ABI or native plugin
  support.
- No `.so` loader was shown. No proprietary firmware modified.

## Reproduce

```bash
python3 tools/headrush/trace_airdelay_argument_layout.py \
   --evil /private/Evil --output /private/airdelay-argument-layout.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Local checks: seven paths and exact arguments verified on the original
ELF, plus 23 selected local unit tests passed. Three new synthetic tests
cover the name pointer, three outgoing slots, wrong BL target and unmapped
instruction handling. See GitHub Actions for the full suite.

## Next questions

1. Trace which `[sp,#4]` values are *read* by both callees and how
   they affect the object being constructed.
2. Locate the owner of the created parameter objects, then trace its
   connection to `SESP::Effect::Delay::AIRDelay`.
3. Repeat on `Shimmer` and `MultiChorus` via their RTTI/controller
   paths; do not infer that their parameters must be stored as the same
   full strings.
4. Any experiment writing to an actual Core requires an independently
   validated backup, exact `.rig` envelope, and explicit approval.
