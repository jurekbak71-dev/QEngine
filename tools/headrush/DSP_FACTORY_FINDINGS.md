# HeadRush Core 5.2.0: candidate DSP factory and dispatch (2026-11-18)

Scope: **static, read-only** analysis of the user's extracted original `/usr/Evil/Evil`
ARM32 ELF. Firmware and proprietary executables are kept **outside** the public
repository. No runtime code was executed inside Core or QEngine.

## Evidence in ARM disassembly

Within ELF `.text` at **0x00812570** (ELF virtual address), a routine contains:

```asm
0x008125a8: cmp   r0, #138
0x008125ac: addls pc, pc, r0, lsl #2
0x008125b0: b     0x008127e0
```

The computed branch addresses **139 entries (0..138)**. Each entry branches
to a handler, or to a common default. Static branch decoding found:

- 139 case entries
- 73 entries leading directly to the common/default handler
- 66 entries leading to non-default handlers
- 48 non-default cases matched uniquely by a nearby PC-relative vtable
  reference to a known `EvilDSPs::DSPModule<...>` class, within 48 bytes
- The other 18 non-default entries **remain unresolved**. Some may invoke
  other implementations; they must not be assigned to the nearest unrelated
  class.

Representative **candidate switch-case mappings**:

| Case index (register r0) | Candidate module |
| --- | --- |
| 8 | `EvilDSPs::TriKnobFuzz` |
| 76 | `EvilDSPs::Octaves` |
| 77 | `EvilDSPs::OctavesUp` |
| 95 | `EvilDSPs::OctFuzz` |

For example, the OctFuzz branch allocates an 80-byte object, calls a
function, and initializes its vtable. This demonstrates a constructor-like
path. The original 271 vtable cross-references include 90/90 classes.
Disassembly of similar sequences elsewhere shows object destruction too.

**Interpretation:** the code is a **strong candidate for a DSP module factory**
selected by an integer passed in `r0`. It is not yet established that the
value equals Remote Editor `ModuleType`, and it does not demonstrate dynamic
loading of arbitrary `.so` files. An indexed switch over compiled C++
constructors is less compatible with simple drop-in plugins than a loadable
module registry.

## Reproduce offline

```bash
python3 tools/headrush/probe_dsp_factory_xrefs.py \
  --evil /private/Evil --output /private/dsp-factory-xrefs.json
python3 tools/headrush/probe_dsp_dispatch.py \
  --evil /private/Evil --output /private/dsp-dispatch.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

These tools require Python 3 and standard-library dependencies except for the
previous `probe_dsp_modules.py` tool's `c++filt` binary.

## Remaining questions

1. Trace the caller of the dispatch routine and the origin of the `r0` selector.
2. Compare the dispatch indices with Remote Editor model IDs from a *read-only*
   local API capture, not by assuming a shared enumeration.
3. Inspect unresolved branches and possible special implementations.
4. Identify the interface and ABI used by the constructed objects.
5. Revisit `.so` viability only after determining whether a secure registration
   path exists; **do not modify the user's physical Core**.

## Validation

- On user-supplied Core 5.2.0 ELF: 271 static references across 90 classes;
  139 dispatch indices, 73 default cases, 48 uniquely mapped DSP cases.
- Locally: 15/15 unit tests passed (synthetic fixtures). This is an offline
  syntax/parser validation and is **not** a runtime audio test.
- QEMU Core boot, plugin loader, runtime DSP: NOT VERIFIED.
