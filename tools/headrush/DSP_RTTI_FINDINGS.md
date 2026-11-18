# HeadRush Core 5.2.0 — DSP RTTI inventory (2026-11-18)

Source: user-supplied official HeadRush Core 5.2.0 updater; extracted `/usr/Evil/Evil` (ARM 32-bit ELF, SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`).

**Evidence:** 90 distinct Itanium ABI mangled C++ type-name strings matching `EvilDSPs::DSPModule<EvilDSPs::<effect>, EvilDSPs::<controller>, Evil::Serialization::DSPSerializer>`, found in the binary around file offsets 27,228,012–27,237,000. These are actual compiled C++ type names, **not** separately installed `.so` plugins.

Examples extracted and demangled by `c++filt -t`:
- `EvilDSPs::DSPModule<EvilDSPs::OctFuzz, EvilDSPs::OctFuzzController, Evil::Serialization::DSPSerializer>`
- `EvilDSPs::DSPModule<EvilDSPs::Octaves, EvilDSPs::OctavesController, Evil::Serialization::DSPSerializer>`
- `EvilDSPs::DSPModule<EvilDSPs::OctavesUp, EvilDSPs::OctavesUpController, Evil::Serialization::DSPSerializer>`
- `EvilDSPs::DSPModule<EvilDSPs::TriKnobFuzz, EvilDSPs::TriKnobFuzzController, Evil::Serialization::DSPSerializer>`
- `EvilDSPs::DSPModule<EvilDSPs::AIRDelay, EvilDSPs::AIRDelayController, Evil::Serialization::DSPSerializer>`

Some other names: `AnxietyOD`, `PitchDelay`, `BBDDelay`, `FacefuzzDistortion`, `DeEsser`, `Shimmer`, `Gate`, `Tuner`.

The ELF's dynamic dependencies (`DT_NEEDED`) include Qt, ALSA, FFmpeg, crypto and supporting libraries. No separately named generic DSP plugin library was found in that list. The only directly observed generic plugin-loading message (`Failed loading plugin %s at %s`) occurs with `QtQuick.2`, `qtquick2plugin`, and `lib%1%2.so`. This **does not prove** that all audio effects are exclusively statically registered, but it strongly supports investigating the internal C++ factory/registry and RTTI virtual tables before assuming a simple drop-in `.so` loader.

## Repeat analysis

```bash
python3 tools/headrush/probe_dsp_modules.py --evil /secure/path/Evil --output /secure/path/dsp-modules.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The Python source is freely distributable. **Do not commit the firmware, `Evil` binary, or vendor content to this public fork.**

## Next investigation

1. Locate the `typeinfo` references and vtable structures for `EvilDSPs::DSPModule<...>` in ELF sections `.rodata` and `.data.rel.ro`.
2. Trace constructor sites and model-ID selection (from `ModuleTypes`) to the DSP module creation path.
3. Determine which C++ ABI and allocation/context contracts a plugin would need.
4. Evaluate whether a loader would require firmware modification; do not claim `.so` support before demonstrating it.

### Validation
- Local tool run on original extracted binary: **90 unique DSP module type names**.
- Three unit tests on synthetic ELF fixtures: **passed**.
- No DSP audio/runtime test, no QEngine Core emulation, and no custom `.so` execution.
