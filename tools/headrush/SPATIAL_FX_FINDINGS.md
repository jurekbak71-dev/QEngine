# HeadRush Core 5.2.0 — reverb / delay / modulation investigation (2026-11-19)

## Scope, origin, reproducibility
User-supplied Windows firmware ZIP -> archive `Update.img` -> verified AZ0x rootfs
descriptor SHA-256 -> read-only ext4 extraction -> `/usr/Evil/Evil`.
Binary SHA-256: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
ARM32 little-endian PIE, 50,711,456 bytes. No vendor binary or raw
firmware has been committed to this public repository.

Run:

```bash
python3 tools/headrush/probe_spatial_fx.py --evil /private/Evil --out /private/spatial.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

### Observed compiled DSP types and UI strings

All 90 C++ `EvilDSPs::DSPModule<T,Controller,DSPSerializer>` RTTI
types were extracted and demangled via `c++filt`.
The following are independent textual evidence counts from the same ELF:

| Family | Sampled labels | Matched DSP RTTI types | UI-style labels |
|---|---:|---:|---:|
| Reverb | 8 | 6 | 7 |
| Delay / echo | 10 | 7 | 10 |
| Modulation | 14 | 12 | 14 |

Sample **RTTI names**: `AIRReverb`, `ElevenReverb`, `SpringReverb`,
`SpringPro`, `Shimmer`, `PartyVerb`; `AIRDelay`, `BBDDelay`,
`DynDelay`, `WarpDelay`, `PitchDelay`, `Reverse`, `TapeEcho`;
`Chorus`, `MultiChorus`, `DimChorus`, `Flanger`, `AIRFlanger`,
`OrangePhaser`, `TronPhaser`, `StonePhaser`, `VibePhaser`,
`Rotary`, `GreenTremolo`, `Vibrato`.

**Important**: the UI/model-name list also contains `Multi Delay`,
`Grain Delay`, `Reso Delay`, `Analog Flanger`, `Digital Flanger`,
`Ambi Verb`, and `C-Verb`, even where a matching `DSPModule<T>` name
was **not** observed. This does NOT show that these effects are missing or
unavailable; their implementation could use another code path.

### Directly observed state/parameter paths in Core 5.2.0 binary

- `/Engine/Patch/AIR Delay/Mix`
- `/Engine/Patch/AIR Delay/HPFdbk`
- `/Engine/Patch/AIR Delay/FdbkClip`
- `/Engine/Patch/AIR Delay/FdbkComp`
- `/Engine/Patch/AIR Delay/LFODepth`
- `/Engine/Patch/AIR Delay/LFORate`
- `/Engine/Patch/AIR Delay/FdbkIn`
- `/Engine/Patch/AIR Delay/FdbkOut`
- `/Engine/Patch/C-Verb/IRSelector`
- `/Engine/Patch/C-Verb/IRInfoString`
- `/Engine/Patch/C-Verb/ReverbType`
- `/Engine/Patch/Rotary/Cabinet`
- `/Engine/Patch/AIR Reverb/Mode`, `.../Tails`
- `/Engine/Patch/Eleven Reverb/Mode`, `.../Tails`
- `/Engine/Patch/Tape Echo/Tails`, `.../BBD Delay/Tails` and other delay tail routes.

These are string references: parameter setting semantics, valid ranges and
read/write authorization must be established independently on a controlled
test instance. **Do not send guessed API requests to the user's device**.

### Practical extension paths

**1. New spatial reverb via C-Verb (confirmed officially)**

HeadRush documents loading third-party convolution reverb impulse responses
for C-Verb, max 10 seconds, WAV/AIF/OPUS, one C-Verb per rig;
processing cost depends on IR length. This is the only directly
documented route here for adding an original reverb without patching
firmware. The effect is convolution-based, not a native new DSP algorithm.

Official vendor support:
https://support.headrushfx.com/en/support/solutions/articles/69000878423-prime-core-and-flex-prime-c-verb-reverb-file-missing-or-corrupt

Core guide transcript:
https://manualzz.com/doc/90021228/headrush-core-user-guide

**2. Modification of existing delay/modulation effects (control-level only)**

Model presets and visible parameters can be changed. Their executable
algorithms cannot be presumed modifiable just because names or API routes
are present. For `AIR Delay`, inspect controller parameter metadata
and state serialization before considering any range expansion or
alternative modulation curves.

**3. New arbitrary C++ DSP `.so` (NOT DEMONSTRATED)**

Prior analysis found an internal case-switch strongly consistent with
compiled DSP-module construction. No native plugin loader/registration
ABI has been demonstrated for external reverb, delay or modulation code.
Firmware binary patching would require a separate safety/recovery plan,
device-specific validation and explicit approval.

## Next technical tasks

- Recover and compare controller/serializer paths for `AIRDelay`,
  `AIRReverb`, `Shimmer`, `MultiChorus` and `AIRFlanger` (read-only).
- Determine which parameters are changeable in factory model presets
  versus hardcoded in DSP functions.
- Investigate whether multi-tap and granular delay aliases use a separate
  implementation path from `DSPModule<T>` in the executable.
- Prefer prototype **standalone original DSP** on a development host before
  proposing device modifications; never claim the HeadRush runs it
  without firmware/device testing.

## Validation and limits
New spatial inventory ran successfully on actual extracted firmware;
three synthetic unit tests passed locally. This does **not** test
audio processing, realtime performance, runtime API or physical hardware.
