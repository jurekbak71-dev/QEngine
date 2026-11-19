# HeadRush Core 5.2.0 — typed parameter construction sequence

Date: 2026-11-19. Input: original user-provided `/usr/Evil/Evil`
ARM32 ELF, inspected locally in **read-only** mode.

## New observation

Disassembly of both AIR Delay parameter-value helper functions reveals a
**two-stage construction sequence**. Both share the same helper function
at VA `0x0069C0E0`:

| Path | Entry VA | Shared preliminary tag | Value tag | Shared helper calls |
|---|---|---:|---:|---:|
| Byte input | `0x014CDA18` | `5` | `4` | two |
| Float32 input | `0x014CD12C` | `5` | `7` | two |

Evidence in executable instructions:
- Byte function: `mov r2,#5` at `0x014CDB3C`,
  `strb r2,[r3]` at `0x014CDB48`,
  `ldrb r3,[r8]` at `0x014CDB60`,
  `mov r2,#4` at `0x014CDB8C`,
  `strb r2,[r3]` at `0x014CDB90`.
- Float function: `mov r2,#5` at `0x014CD244`,
  `strb r2,[r3]` at `0x014CD250`,
  `vldr s15,[r8]` at `0x014CD264`,
  `vcvt.f64.f32 d16,s15` at `0x014CD278`,
  `mov r2,#7` at `0x014CD298`,
  `strb r2,[r3]` at `0x014CD29C`.

The shared helper is an actual ARM function whose body starts by
preparing stack/registers and then branches on byte fields. It contains
string comparisons and numeric-character handling. **This is not
proof that it is the owner/final storage of DSP parameters.**
Do not infer a public plugin API from the presence of this function.

## Results and confidence

- Real owner-supplied ELF: **11/11** static opcode checks matched;
  both pairs of helper call destinations resolved to `0x0069C0E0`.
- Four new synthetic unit tests passed locally, including mutation and
  unmapped-instruction checks. GitHub Actions should be consulted for
  the complete current test suite.
- No original binary, preset database or firmware uploaded to this
  public repository.
- No Core hardware commands, DSP injection, firmware changes, or audio
  playback performed.

## Shimmer and MultiChorus

The earlier RTTI evidence identifies
`SESP::Effect::Reverb::Shimmer` and
`SESP::Effect::Modulation::ChorusMulti` as compiled algorithm
types associated with HeadRush wrappers/controllers. However, the
exact `/Engine/Patch/Shimmer/Interval` and
`/Engine/Patch/Multi Chorus/Voices` full paths were **not observed** as
literal strings in the original ELF. The firmware's factory rigs
contain those parameters, which is a distinct and weaker source of
evidence for code-level parameter registration.

**NOT VERIFIED**: how Shimmer/MultiChorus keys are constructed,
how their controller parameters reach the SESP algorithm, parameter
bounds, dynamic `.so` loading, and the safety of changes on Core.

## Reproduce

```bash
python3 tools/headrush/verify_parameter_variant_sequence.py \
  --evil /private/Evil --output /private/variant-sequence.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

### Next technical objective

Locate the consumer of these constructed type-tagged objects and
determine the owner/controller; investigate Shimmer and MultiChorus
using their code references and factory preset schema rather than
inventing complete literal paths.
