# Core 5.2.0 — ARM EHABI bounds of spatial controller methods

**Date:** 2026-11-19. **Source:** user-supplied HeadRush Core 5.2.0
firmware, original ARM32 executable `/usr/Evil/Evil`.
SHA-256: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
No proprietary firmware or presets are committed to this public repository.

## Why this analysis was needed

The earlier spatial vtable study found specialized virtual method pointers
in primary vtable slots 25 and 26 for AIR Delay, Shimmer and Multi Chorus.
Previous literal-string scanning used a fixed 0x400-byte window, which can
truncate long functions and risk capturing adjacent code. A much stronger
source for an analysis boundary is the original executable's
`.ARM.exidx` (ARM EHABI unwind index).

The binary contains **17,627 ordered unwind start entries**. All six
specialized vtable method pointers match entries **exactly**; the next
entry supplies a bounded unwind region. This supports a static method
scope but should not be treated as a dynamic execution trace or proof
that every exidx region equals exactly one original C++ source function.

## Verified method ranges

| Controller | Virtual method slot | VA range [start,next exidx) | Bytes | Direct unconditional A32 BL |
|---|---:|---|---:|---:|
| AIRDelayController | 25 | `0x00911A2C..0x00911BE4` | 440 | 5 |
| AIRDelayController | 26 | `0x00910368..0x00910768` | 1024 | 10 |
| ShimmerController | 25 | `0x009192A4..0x009194A0` | 508 | 7 |
| ShimmerController | 26 | `0x0092B8BC..0x0092BE60` | 1444 | 24 |
| MultiChorusController | 25 | `0x00917B0C..0x00917CFC` | 496 | 7 |
| MultiChorusController | 26 | `0x00926694..0x00926EF8` | 2148 | 37 |

These counts cover direct unconditional A32 `BL` words in each
EHABI-bounded region. They **exclude** virtual dispatch, `BLX`,
conditional A32 branches, Thumb and potentially indirect calls.
Embedded ARM literal pools can affect a raw instruction-word scan.

Each vtable slot was independently checked against the four-byte pointer
stored at `vtable_va + 8 + 4*slot`. A report built from a different
ELF SHA-256 is rejected.

## Confirmed literal parameter names within slot 26

The scanner looks for PC-relative `LDR` plus `ADD PC` patterns that
resolve to printable strings in the ELF `.rodata`, then compares those
strings against **actual** keys stored in the original read-only
`evil.db` factory rigs.

| Controller | Names found in slot-26 code and factory rigs |
|---|---|
| AIR Delay | `Delay`, `Feedback`, `Ratio`, `FdbkHighCut`, `FdbkResoFreq`, `FdbkReso`, `Width`, `LoCut`, `Mix` |
| Shimmer | `Delay`, `Interval`, `ReverbTime`, `Mix`, `Tone`, `Width` |
| Multi Chorus | `Rate`, `Depth`, `Mix`, `Width`, `LoCut`, `PreDelay`, `Voices` |

**22 model-parameter name matches** total (9 + 6 + 7).
No matching literal-name references were found in the slot-25
ranges under this scanning pattern.

Additional format strings in slot 26, e.g. `%.0f %%` and
`%.0f Hz`, are compatible with **parameter display/formatting**
code. This is a plausible interpretation, **not a verified method
signature or DSP audio callback classification**.

The factory rig keys `Shimmer/HighCut` and
`Multi Chorus/LFOShape` are **not literal-referenced in the exact
slot-26 regions**. The strings do occur elsewhere in the original
ELF, including code related to other effects. A string's presence
elsewhere does not attribute it to Shimmer or Multi Chorus, and its
absence in slot 26 does not prove absence of an adjustable parameter.

## Reproducibility and tests

```bash
python3 tools/headrush/probe_spatial_controller_vtables.py \
  --evil /private/Evil --db /private/evil.db \
  --out /private/controller-vtables.json

python3 tools/headrush/trace_spatial_exidx_methods.py \
  --evil /private/Evil --vtables /private/controller-vtables.json \
  --db /private/evil.db --out /private/exidx-methods.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

- [Analyzer](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_exidx_methods.py)
- [Synthetic tests](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_exidx_methods.py)
- GitHub Actions run [44549151663](https://github.com/jurekbak71-dev/QEngine/actions/runs/44549151663): **102/102 PASS**.
- Independent local validation of the same extraction rules on actual
  original `Evil` and `evil.db`: 17,627 unwind entries, all six
  bounded methods, their BL counts and literal key matches.
- Separate local test harness for boundary and corruption cases:
  **11/11 PASS**. GitHub's nine new synthetic tests were included in CI.

## Unverified and next work

**UNVERIFIED:** Whether vtable slot 26 serves the user interface, preset
serializers, parameter setters or DSP runtime. No direct path to
`SESP::Effect::Reverb::Shimmer` or
`SESP::Effect::Modulation::ChorusMulti` was proven.

**NOT DONE:** Firmware modifications, audio playback or device testing,
custom DSP loading, reliable device-compatible rig export.

Next priority: inspect direct call targets and indirect `BLX` dispatches
from the specialized controller methods; correlate any candidate
consumer with the separately discovered SESP adapter vtables.
Do not publish or install a firmware modification without a tested
backup and recovery procedure and explicit approval.
