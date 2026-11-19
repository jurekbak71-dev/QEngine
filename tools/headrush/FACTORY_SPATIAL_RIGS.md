# HeadRush Core 5.2.0 — factory rig spatial effect inventory

Date: 2026-11-19. Input: `/usr/Evil/Content/evil.db` extracted from the
user-supplied Core 5.2.0 updater and inspected locally in SQLite **read-only**
mode. **Do not commit the proprietary database or factory rig exports to this
public repository.**

The database contains exactly **50 factory rigs**, **0 standalone block rows**
and **6 settings rows**. The `rigs.content` field stores JSON:
`data.Patch.children.Chain.children.ModuleType1..14` identifies block
models and `data.Patch.children["Model"].children` contains parameters.

### Observed occurrences in these 50 rigs

These are **counts of model instances**, not available catalog sizes;
some rigs have a second numbered instance of the same model.

| Model | Instances | In chain | Enabled |
|---|---:|---:|---:|
| Eleven Reverb | 38 | 38 | 26 |
| AIR Reverb | 11 | 11 | 11 |
| Spring Reverb | 3 | 3 | 2 |
| Shimmer | 1 | 1 | 0 |
| Ambi Verb | 4 | 4 | 3 |
| AIR Delay | 10 | 10 | 9 |
| BBD Delay | 13 | 12 | 4 |
| Dyn Delay | 20 | 20 | 3 |
| Tape Echo | 8 | 8 | 3 |
| Multi Chorus | 4 | 4 | 0 |
| Chorus | 15 | 14 | 3 |
| Rotary | 1 | 1 | 0 |

### Real parameter keys from stored factory rigs

- `AIR Reverb`: `Mode`, `Time`, `Size`, `Color`, `Mix`, `On`.
- `Eleven Reverb`: `Mode`, `Decay`, `Tone`, `Pre-Delay`, `Mix`, `Tails`.
- `Shimmer`: `Interval`, `ReverbTime`, `Delay`, `HighCut`,
  `Tone`, `Width`, `Mix`.
- `Tape Echo`: `Delay`, `Feedback`, `HeadTilt`, `RecordLevel`,
  `Wow`, `Mix`.
- `AIR Delay`: `Delay`, `Feedback`, `FdbkHighCut`,
  `FdbkReso`, `FdbkResoFreq`, `LoCut`, `Width`, `Ratio`, `Mix`.
- `Multi Chorus`: `Voices`, `LFOShape`, `Rate`,
  `Depth`, `PreDelay`, `Width`, `LoCut`, `Mix`.

The field names here are **JSON preset keys**. They must not be
confused with the binary's internal parameter paths, which may be different.
Values observed in rig examples **do not establish valid edit ranges**.

## Reproducible inspection and experimental JSON copy

```bash
python3 tools/headrush/rig_spatial_lab.py \
    --db /secure/extracted/evil.db --out /secure/spatial-inventory.json

python3 tools/headrush/rig_spatial_lab.py \
    --db /secure/extracted/evil.db \
    --rig-name '01-GTR-6505 Fat Drive' \
    --model 'Eleven Reverb' --parameter Mix --value 20 \
    --out /secure/experimental-rig.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

The tool opens SQLite with `mode=ro&immutable=1`, validates that the
model is present in the selected rig chain, edits a deep **copy** of
existing JSON only, and writes a separate local JSON file. It rejects
unknown parameter names, malformed numeric values and unsupported types.

**NOT YET VERIFIED:** the generated JSON is accepted by a device importer,
that all represented values are safe, or that changing model parameters
alters the DSP algorithm beyond normal controls. Never write these experimental
files into a live device or `evil.db` without a validated backup-and-recovery
procedure and explicit approval.

## Objective

Prioritize reverb, echo/delay, and modulation over overdrive. Next pursue
the existing C++ controllers' parameter metadata and full DSP factory
call sites, while keeping native `.so` loading explicitly **unproven**.

## Validation

- Local scan: 50 actual factory rigs parsed successfully.
- A separate experimental JSON copy changed `Eleven Reverb/Mix` in a
  rig, with the original SQLite file left untouched.
- Seven synthetic unit tests locally: PASS.
- GitHub Actions result for the commit should be checked independently.
