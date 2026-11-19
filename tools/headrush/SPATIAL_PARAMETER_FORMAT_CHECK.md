# HeadRush Core 5.2.0 — spatial parameter observations and rig-format caution

Verified on 2026-11-19 against the extracted original firmware
`/usr/Evil/Content/evil.db` and the 50 factory rigs it contains. No vendor
binary or preset exports are committed to this public repository.

## Real factory data

- 50/50 rigs contain a 14-slot `Patch/Chain/ModuleType1..14`.
- 50/50 include `FootSwitch`, `Pedal3`, `Pedal4`, `RigEncoder`, `data`, `info`.
- The `info.version` field is `5.0.0` in all 50 factory rig contents despite
  being bundled in the Core 5.2.0 firmware.
- Observed on selected active model instances:

| Model / key | Evidence across the factory rig corpus |
|---|---|
| AIR Delay / Feedback | 10 samples, values 9..45, 6 distinct |
| AIR Delay / Mix | 10 samples, values 4..30, 5 distinct |
| Multi Chorus / Voices | 4 samples, two values: `4`, `6` |
| Multi Chorus / LFOShape | 4 samples, only `Tri` |
| Shimmer / ReverbTime | 1 sample, value 50 |

**These are observed preset values, not allowed min/max or permitted enum
sets.** Modifying arbitrary values is not a proof of safe support.

Run the read-only inventory:
```bash
python3 tools/headrush/analyze_spatial_parameters.py \
  --db /secure/evil.db --out /secure/observed-spatial-values.json
```

## Native `.rig` hypothesis — not yet proven for Core

An independent public open-source **Gigboard** rig writer uses an outer JSON
envelope with `content` containing an inner JSON document, which uses an
11-slot `ModuleType1..11` chain, `Pedal1/2`, `FootSwitch` and
`info.version=2.0.3` in its golden fixture. The 5.2.0 Core inner
documents are structurally related but differ in slot budget, pedal sections
and embedded version. This external Gigboard code cannot prove a compatible
Core 5.2.0 file exporter/importer:

https://github.com/d-led/guitar-modeler-mcp/blob/main/internal/headrush/rig/rig.go
https://github.com/d-led/guitar-modeler-mcp/blob/main/internal/headrush/rig/testdata/rig.golden

The vendor explicitly documents importing/exporting native rigs, but does
not in these sources specify the on-disk JSON schema:

https://support.headrushfx.com/en/support/solutions/articles/69000835659-headrush-prime-and-core-new-ways-to-back-up-your-unit

**No experimental JSON from our toolkit is claimed to be importable into
Core.** Obtain an actual Core 5.2.0 `.rig` exported by the device and
compare its structure byte-for-byte before generating native exports.

## Bug found and fixed in experimental rig editor

Earlier `rig_spatial_lab.py` inserted `lab_edit_metadata` at the root of
the output rig JSON. This is not present in the original Core factory JSON.
Now the edited copy preserves the root keys and places the change audit in
`<output>.audit.json`. The original SQLite database remains read-only.

The two records must not be manually merged. An unchanged schema alone
does not establish Core import compatibility or safe parameter ranges.

Validation: two new parameter-statistic tests and an additional CLI audit
test, plus the existing seven rig laboratory tests. The GitHub CI result
should be checked independently.
