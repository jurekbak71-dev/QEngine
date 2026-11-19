# Offline Core rig format comparison

`probe_core_rig_format.py` compares a real exported HeadRush Core
`.rig` file **when one is available** against the extracted factory rig
documents stored in the original `evil.db`. It does not create .rig
files, communicate with hardware, or modify firmware.

```bash
python3 tools/headrush/probe_core_rig_format.py --db /private/evil.db
python3 tools/headrush/probe_core_rig_format.py --db /private/evil.db \
  --candidate /private/core-export.rig --output /private/format-report.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

If the export is based on an existing factory rig, optionally provide
`--compare-to 'Exact Factory Rig Name'`. JSON-pointer differences identify
which values changed and which fields were removed.

The scanner accepts: standalone inner JSON; an envelope with string
`content`; or an envelope with object `content`. **Accepting these
three formats is a diagnostic convenience, not evidence that Core accepts
all three**.

Observed from 50 factory rig entries bundled with Core 5.2.0:
14 `ModuleType` slots, `Pedal1..4`, `RigEncoder`, `FootSwitch`,
`info.version=5.0.0`. The independent Gigboard project has 11 slots,
two pedals, and a string-content outer `.rig` envelope in its fixture.
That evidence is insufficient to establish the Core 5.2.0 export envelope.

**No native Core export was available for the comparison at the time
of writing; import compatibility is unverified.**
