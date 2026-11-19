# HeadRush Core 5.2.0 — spatial C++ controller and SESP algorithm linkage

Analysis date: 2026-11-19. Source: owner-supplied proprietary Core 5.2.0
firmware, extracted `/usr/Evil/Evil` ARM32 ELF. Analysis conducted
read-only; no vendor binary is committed here.

The `trace_spatial_controllers.py` utility requires four **adjacent**
Itanium ABI RTTI names, in order: `SespAdapterTypes<float, SESP::Effect::...>`,
`SespAdapterStereo<float, same algorithm>`, `EvilDSPs::<wrapper>`,
`EvilDSPs::<wrapper>Controller`. NUL padding is allowed; unrelated strings
break a match. Demangled types are compared before accepting each quartet.

A scan of the original Core 5.2.0 `Evil` found **34 matched quartets**,
including these independently checked spatial mappings:

| HeadRush wrapper | SESP algorithm type |
|---|---|
| `AIRDelay` | `SESP::Effect::Delay::AIRDelay` |
| `BBDDelay` | `SESP::Effect::Delay::MemoryMan` |
| `TapeEcho` | `SESP::Effect::Delay::TapeEchoplex` |
| `AIRReverb` | `SESP::Effect::Reverb::AlgorithmicWizooSimplified` |
| `ElevenReverb` | `SESP::Effect::Reverb::AlgorithmicOneSimplified` |
| `Shimmer` | `SESP::Effect::Reverb::Shimmer` |
| `MultiChorus` | `SESP::Effect::Modulation::ChorusMulti` |
| `Chorus` | `SESP::Effect::Modulation::ChorusEnsemble` |
| `AIRFlanger` | `SESP::Effect::Modulation::FlangerVintage` |

This confirms that the **linked type names** contain specific audio
algorithm adapters alongside the HeadRush controller types. It does not
prove any particular runtime call graph or that those classes can be
replaced in a running device.

Run on an owner's private extracted ELF (binutils required):

```bash
python3 tools/headrush/trace_spatial_controllers.py --evil /private/Evil --out /private/spatial-controller-trace.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

### Important distinction

- Confirmed: source-visible ABI RTTI strings and adjacent adapter/wrapper
  names from the original Core 5.2.0 ELF.
- Not confirmed: metadata defining controller min/max/default values,
  how controller values are translated to SESP algorithm parameters,
  exposed access to hidden internal parameters, or an external `.so` loader.
- Proposed next step: inspect controller call sites and serializer functions
  for `AIRDelay`, `AIRReverb` and `MultiChorus` and compare against
  the factory `evil.db` fields. No write or injection on physical hardware.
