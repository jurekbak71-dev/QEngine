# Core 5.2.0: AIR Delay string-length and typed argument verification

Date: 2026-11-19. Source: local, user-supplied `/usr/Evil/Evil` from
HeadRush Core 5.2.0 updater. The proprietary executable stays private.

## Correction to the previous AIR Delay argument report

The integers `30`, `31`, `32` passed through `[sp,#4]` are
**not unknown parameter IDs/ranges**: for all seven observed calls they
are **exactly the byte lengths of their corresponding full parameter
path strings** passed by pointer through `[sp,#8]`.

| Full parameter path suffix | Path length | Passed word `[sp,#4]` |
| --- | ---: | ---: |
| `HPFdbk` | 30 | 30 |
| `FdbkClip` | 32 | 32 |
| `FdbkComp` | 32 | 32 |
| `LFODepth` | 32 | 32 |
| `LFORate` | 31 | 31 |
| `FdbkIn` | 30 | 30 |
| `FdbkOut` | 31 | 31 |

Code-level evidence links both callees to their distinct data types:

- At `0x014CDA34`: `mov r8,r3`, then at `0x014CDB60`:
  `ldrb r3,[r8]` (one-byte input; matches `HPFdbk`, `FdbkClip`).
- At `0x014CD148`: `mov r8,r3`, then at `0x014CD264`:
  `vldr s15,[r8]` (IEEE754 `float32` input; matches the other five).
- The seven caller sites pass `r3` via `mov r3,r6`, and the
  setup block at `0x00A11E68` initializes `r6 = sp`.
  Consequently the callee receives a pointer to the caller's data
  buffer, not merely an integer or float passed by value in `r3`.
- Both functions also receive an 8-byte stack pair, interpreted in
  the caller as the buffer's text pointer and length. The exact
  callee-internal object metadata semantics remain to be determined.

The `[sp]` bit patterns previously observed can be distinguished from
the length and string-pointer fields. No evidence yet that they are
user-visible defaults or permitted min/max bounds. In particular the
integer `30..32` must **not** be modified in an attempt to extend
DSP modulation/depth limits.

## Reproduction

```bash
python3 tools/headrush/trace_airdelay_argument_layout.py \
  --evil /private/Evil --output /private/air-delay-layout.json
python3 tools/headrush/verify_airdelay_parameter_abi.py \
  --evil /private/Evil --layout /private/air-delay-layout.json \
  --output /private/air-delay-abi-check.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The verifier checks exact instruction words and compares actual UTF-8
string byte lengths, not approximate UI labels.

Actual ELF: **7/7 path lengths matched, 7/7 caller and callee
instruction patterns matched**. Five synthetic unit tests were added
to detect false positive lengths and data-type opcodes.

## Next steps

1. Trace additional C++ data structure writes inside each callee to
   establish what metadata is persisted and which owner receives it.
2. Inspect the `SESP::Effect::Delay::AIRDelay` adapter's method
   that reads these parameter objects.
3. Apply the same method to `Shimmer` and `MultiChorus` where full
   parameter path strings are absent from the simple scanner.
4. No firmware/device patch or `.so` installation should be claimed
   without a tested native loader or safe independent recovery path.
