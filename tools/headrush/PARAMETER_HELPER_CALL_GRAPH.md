# HeadRush Core 5.2.0 — shared parameter helper calls

Date: 2026-11-19. Original input: the owner's extracted `/usr/Evil/Evil`,
SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.
All firmware analysis is **offline read-only**, with no proprietary binaries
or original rigs committed to this public repository.

## Ten verified direct ARM BL calls

| Stage | Byte/state function 0x014CDA18 | Float/value function 0x014CD12C | Common callee |
|---|---|---|---|
| Create `type` key | `0x014CDABC` | `0x014CD1D0` | `0x009F43F8` |
| Create `state` / `value` key | `0x014CDAE8` | `0x014CD1FC` | `0x009F43F8` |
| Combine constructed keys/data | `0x014CDAFC` | `0x014CD210` | `0x009F4DE4` |
| Generic variant stage 1 | `0x014CDB28` | `0x014CD230` | `0x0069C0E0` |
| Generic variant stage 2 | `0x014CDB74` | `0x014CD280` | `0x0069C0E0` |

The analyzer independently verifies **all 10/10** direct branch targets
from their 32-bit ARM opcodes in the original binary. The functions at
`0x0069C0E0` and `0x009F4DE4` operate on complex C++ data structures,
including string-like fields and 24-byte elements. These observations support
a generic data-construction/serialization mechanism, rather than prove
the final runtime DSP consumer.

This is a **control-flow edge map**, not a full trace to
`SESP::Effect::Delay::AIRDelay`. The target of the constructed objects
inside the controller and the final DSP algorithm remains **UNVERIFIED**.

## Repeat

```bash
python3 tools/headrush/trace_parameter_helper_calls.py \
  --evil /private/Evil --out /private/parameter-helper-calls.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The five new synthetic tests verify ARM BL decoding, a valid edge,
a wrong target, a backward branch and a malformed image.

**No patch or program was run on the physical Core.** No plugin loading
is implied by the matched calls. Future work should trace the result of
`0x009F4DE4` to its actual owner before claiming direct control of
the SESP algorithm. Shimmer and MultiChorus require separate controller
xref evidence.
