# HeadRush Core 5.2.0 — RTTI / vtable mapping (2026-11-18)

Input: extracted vendor binary `/usr/Evil/Evil` from the user-supplied official 5.2.0 updater. Kept outside the public repository.

## Reproduced observations

- ARM32 little-endian ELF, compiled C++ RTTI names.
- 90 distinct `EvilDSPs::DSPModule<effect,controller,DSPSerializer>` type names.
- **90/90** have a candidate typeinfo object containing a pointer to the mangled name in the read-only data.
- **90/90** have at least one candidate Itanium C++ ABI vtable prefix `[offset-to-top=0, typeinfo-pointer, first-virtual-function]` in the ELF's relocation-ready data. The first virtual function points into `.text`.
- Examples (addresses relative to PIE image base, **not** physical device addresses):

| DSP class | RTTI typeinfo VA | vtable VA | First virtual function VA |
|---|---|---|---|
| OctFuzz | 0x02f28dac | 0x02ea8f78 | 0x0084750c |
| Octaves | 0x02f28de8 | 0x02ea920c | 0x00847b24 |
| OctavesUp | 0x02f28ddc | 0x02ea9188 | 0x008479ec |
| AIRDelay | 0x02f28d1c | 0x02ea8948 | 0x0098462c |
| TriKnobFuzz | 0x02f28f50 | 0x02eaa184 | 0x0086a3e8 |

The table is an address-level **static candidate map**, not an executed call trace. It supports the presence of compiled C++ DSP classes with virtual dispatch but does not yet locate the model-to-constructor registry/factory. An actual external `.so` plugin interface remains unverified.

## Reproduction

```bash
python3 tools/headrush/probe_dsp_vtables.py --evil /private/Evil --output /private/vtables.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The tool does not distribute vendor content or modify any input. The output containing firmware-derived offsets remains local/private.

## Follow-up
Trace instructions referencing each vtable address point (`vtable + 8` in the ABI), find constructor bodies and registry mapping from `ModuleType` IDs; distinguish Qt plugin loading from DSP registration. Do not infer a supported `.so` loader from RTTI/vtables alone.
