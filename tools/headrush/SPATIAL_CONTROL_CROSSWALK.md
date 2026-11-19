# Core spatial DSP: binary control paths versus factory-rig keys

Static input: firmware 5.2.0 `/usr/Evil/Evil` and `evil.db`.
Verified 2026-11-19. Both inputs are read-only. No API calls.

The binary embeds some `/Engine/Patch/<model>/<parameter>` paths,
which are **not the same thing** as editable controls exposed through
the preset JSON. Example real results:

| Model | ELF control-path suffixes | Observed preset JSON keys (selected) |
|---|---|---|
| AIR Delay | Mix, HPFdbk, FdbkClip, FdbkComp, LFODepth, LFORate, FdbkIn, FdbkOut | Mix, Feedback, Delay, FdbkHighCut, FdbkReso, Ratio, Width |
| AIR Reverb | Mode, Tails | Mode, Time, Size, Color, Mix |
| Eleven Reverb | Mode, Tails | Mode, Decay, Tone, Pre-Delay, Mix |
| Shimmer | none found with this narrow path search | ReverbTime, HighCut, Tone, Width, Mix |
| Multi Chorus | none found with this narrow path search | Voices, LFOShape, Rate, Depth, PreDelay, Width |
| Tape Echo | Tails | Delay, Feedback, HeadTilt, RecordLevel, Wow, Mix |
| BBD Delay | Tails | Delay, Feedback, LFODepth, LFOSpeed, Mix |
| Rotary | Cabinet | Cabinet, Balance, Move, Speed, Mix |

**Crucial:** the absence of string paths is **not** evidence that
a controller is missing. A path appearing in the binary but not in
factory rigs is **not** evidence that it can be changed via API or
saved in a rig. `AIR Delay/LFODepth` should be investigated as a
possible internal control, not exposed as a confirmed feature.

Reproduce:
```bash
python3 tools/headrush/probe_spatial_control_paths.py \
  --evil /private/Evil --db /private/evil.db \
  --output /private/spatial-control-crosswalk.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Next: trace C++ parameter descriptor creation or Remote Editor UI
metadata and determine the writable range/type of each control
before any update requests. Do not treat preset min/max as hard limits.
