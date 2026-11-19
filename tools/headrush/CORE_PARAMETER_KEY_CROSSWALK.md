# Core 5.2.0 — ARM parameter keys match factory rig JSON structure

Date: 2026-11-19. This report uses the **actual owner-supplied firmware**
`Evil` ELF and `evil.db`, both extracted read-only again from the
original `HeadRush Core 5.2.0 Firmware Updater - Win.exe.zip`.

Re-extracted `Evil` SHA256:
`1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
The rootfs partition SHA256 was verified against the AZ0x descriptor
before extraction.

## New evidence: literal keys and their consumer

The two previously identified byte/float32 parameter-construction
functions explicitly load the UTF-8 strings `type`, `state` and
`value` as PC-relative string references, then pass them into the
**same key-construction routine** `0x009F43F8`. Exact source-level
ARM instructions, string target bytes and BL destinations were checked
on the original ARM ELF.

| Input function | Literal key | LDR VA | ADD VA | Constructor BL VA |
|---|---|---|---|---|
| Byte `0x014CDA18` | `type` | `0x014CDA8C` | `0x014CDAA0` | `0x014CDABC` |
| Byte `0x014CDA18` | `state` | `0x014CDAC8` | `0x014CDAD0` | `0x014CDAE8` |
| Float `0x014CD12C` | `type` | `0x014CD1A0` | `0x014CD1B4` | `0x014CD1D0` |
| Float `0x014CD12C` | `value` | `0x014CD1DC` | `0x014CD1E4` | `0x014CD1FC` |

All four BL calls target `0x009F43F8`, verified from the signed
ARM branch displacement. This routine operates on string-like data;
it is **not yet proven to be the final owner of DSP parameter objects**.

The original factory `evil.db` independently provides corresponding
JSON objects for AIR Delay:
- **83** parameter entries with both `type` and `value`,
  e.g. `Delay: {"type":0,"value":600}`.
- **30** entries with both `type` and `state`,
  e.g. `On: {"type":1,"state":false}`.
- **0** AIR Delay entries with simultaneous `state` and `value`.

These numbers count **parameter occurrences in the 50 factory rigs**,
not unique controls, or supported device parameter ranges.

## Scope limits and corrections

- This is strong static evidence that the executable contains code for
  constructing the same field names used in factory preset serialization.
- The binary's internal tags `4,5,7` **must not be equated** with the
  factory JSON `type` codes `0,1`. They are different observed data
  in different representation contexts.
- Similar field names do not alone establish the runtime path from
  controller to `SESP::Effect::Delay::AIRDelay`.
- No native DSP `.so` loader or parameter-extension mechanism has been
  verified. No hardware interactions or firmware patches were performed.

## Reproduce

```bash
python3 tools/headrush/verify_spatial_serialization_keys.py \
  --evil /private/Evil --db /private/evil.db \
  --output /private/spatial-serialization-keys.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Five synthetic tests verify string dereferences, matching constructor
targets, and detection of altered key text, modified BL destinations,
invalid LDR/ADD patterns and independent SQLite parameter statistics.

The pending work is identifying the ultimate owner/consumer of the
produced type-tagged values, and tracing Shimmer/MultiChorus controls
without assuming the same literal `/Engine/Patch/...` paths.
