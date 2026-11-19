# Core 5.2.0 — full executable call-site census for shared parameter helpers

Date: 2026-11-19. Source: user-provided original HeadRush Core
5.2.0 updater, restored and independently checked again.

- `Update.img`: 225,162,168 bytes, extracted from 7z SFX embedded in EXE.
- Compressed rootfs: 218,307,232 bytes; SHA-256 matches AZ0x
  partition descriptor `8f908883bbdc71d2324fd84bd43d3883518c359d38f9d163667fa5ed47907536`.
- `rootfs.img`: 514,142,208 bytes. Opened **read-only** using libext2fs.
- `/usr/Evil/Evil` ELF: 50,711,456 bytes; SHA-256
  `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
- `evil.db`: 2,508,800 bytes; SHA-256
  `11d26f52c5f1747cb9bfa1d86bf2b6ce9de4c339d57c2932f2907150a6e4882f`.

## Findings from scanning the **entire** ELF .text section

Scanning 22,862,440 bytes of ARM32 .text for direct unconditional
A32 `BL` instructions (not BLX, virtual dispatch, other ARM
conditions, Thumb or indirect calls) returned:

| Callee VA | Direct ARM32 BL callers | Role hypothesis |
|---|---:|---|
| `0x0069C0E0` | **53** | shared tagged-value helper |
| `0x009F43F8` | **36** | shared string-key helper |
| `0x009F4DE4` | **16** | shared structure combiner |
| `0x014CDA18` | **2** | byte-oriented path used by AIR Delay |
| `0x014CD12C` | **6** | float-oriented path used by AIR Delay |

Every previously identified call site (10 total for the three common
helpers) was recovered automatically by the new full-section scanner,
rather than by checking only hard-coded known locations.

**Interpretation:** the first three routines are called from multiple
regions of the executable, not just the AIR Delay setup block.
Consequently they should be treated as **general-purpose infrastructure**
until an explicit path connecting their outputs to an SESP algorithm
is demonstrated. Their broad reuse is stronger evidence against treating
them as an AIR Delay-specific DSP injection point.

No claim is made that the call-site totals cover dynamic, indirect,
virtual or Thumb calls, or that they prove the helper owns the
final serialized parameter structure.

## Repeatable, offline inspection

```bash
python3 tools/headrush/trace_common_parameter_callers.py \
  --evil /private/extracted/Evil \
  --out /private/common-helper-callers.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The JSON lists **every matching direct call-site VA**, target, and
per-target regression checks. It also records the source ELF SHA-256.

Seven new synthetic tests check ELF section bounds, little-endian
ARM branch decoding, multiple callers, wrong destinations, a backward
branch, and exclusion of conditional branches.

## Remaining unknowns

- **Unverified:** object allocation and ownership, whether the generic
  helpers write to controller objects or only serializer data;
  runtime link to `SESP::Effect::Delay::AIRDelay`.
- **Unverified:** Shimmer and MultiChorus control mechanisms.
- **Not implemented:** new native Core DSP, device-side tests,
  firmware modifications, device-compatible rig export or a custom
  `.so` loader.
- **Safety:** source binaries and factory presets remain private.
  This study is read-only.
