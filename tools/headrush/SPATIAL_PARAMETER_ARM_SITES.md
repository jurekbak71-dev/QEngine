# Core 5.2.0 — ARM references to spatial-effect parameter paths

**Date:** 2026-11-19. **Input:** user-provided proprietary
`/usr/Evil/Evil`, ARM32 ELF. The extracted binary is kept private and was
scanned locally, read-only. No proprietary files are committed here.

This adds a stronger level of evidence than searching for parameter strings:
for every recognized full path, the tool locates ARM code assembling that
specific string's virtual address with a PC-relative `LDR` + `ADD` pair.
It also records the first subsequent nearby `BL` instruction (maximum 64
bytes), without assigning undocumented semantics to its arguments.

### Observed results on original Core 5.2.0

- **11/11** full target parameter paths have matching ARM code references
  (one match per path).
- **AIR Delay: 8/8** matched, including `Mix` and seven additional controls.
- `AIR Reverb`, `BBD Delay`, `Tape Echo`: one `Tails` path each.
- `Shimmer`, `Multi Chorus`, `AIR Flanger`: no full
  `/Engine/Patch/<model>/<parameter>\0` path matched the scanner pattern;
  this **does not** mean they lack parameters.

| AIR Delay path | ARM reference VA | Next `BL` destination VA |
|---|---|---|
| `Mix` | `0xA11D78` | `0x009F089C` |
| `HPFdbk` | `0xA11E84` | `0x014CDA18` |
| `FdbkClip` | `0xA11EB0` | `0x014CDA18` |
| `FdbkComp` | `0xA11ED0` | `0x014CD12C` |
| `LFODepth` | `0xA11EFC` | `0x014CD12C` |
| `LFORate` | `0xA11F28` | `0x014CD12C` |
| `FdbkIn` | `0xA11F50` | `0x014CD12C` |
| `FdbkOut` | `0xA11F70` | `0x014CD12C` |

Values are virtual addresses within the PIE image, **not device memory
addresses**. The functions at `0x014CDA18` and `0x014CD12C` are
shared call destinations. The instruction sequence is compatible with
registration/initialization logic, but we have **not** proven that the
function arguments represent allowed parameter ranges or initial defaults.

### Reproduction

```bash
python3 tools/headrush/trace_spatial_parameter_sites.py \
  --evil /private/Evil --output /private/spatial-parameter-sites.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

No running device was contacted and no firmware code was modified.

### Next evidence necessary

1. Disassemble common call destinations and inspect their callers to identify
   the registration data structure and whether it contains bounds/defaults.
2. Match registered parameter objects against existing preset values without
   assuming that observed preset minima and maxima are valid DSP limits.
3. For `Shimmer` and `Multi Chorus`, seek parameter keys encoded by
   different mechanisms (string object tables, serializer methods) rather
   than concluding that they have no controls.
4. Check native Core `.rig` export format using a genuine exported file
   before creating device-ready presets.
