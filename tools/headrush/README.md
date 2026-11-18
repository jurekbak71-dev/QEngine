# HeadRush Core 5.2.0 — offline registration inspection

This tool is a **read-only** inventory for an extracted HeadRush Core
`/usr/Evil/Evil` binary and `/usr/Evil/Web/static/js/main.*.js` bundle.

It checks known API identifiers, strings and their offsets, and identifies
the context of the message `Failed loading plugin %s at %s`.
It does **not** boot the device, inject code, demonstrate DSP plugin loading
or prove a custom `.so` can be installed.

```bash
python3 tools/headrush/inspect_core_registration.py \
  --evil /secure/path/Evil \
  --remote-js /secure/path/main.d6006a0b.js \
  --out /secure/path/core-registration.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Do not commit the manufacturer's firmware, executables or resulting
inspection reports to this public repository without separately evaluating
redistribution rights. The tool only uses Python's standard library.

Observed from Core 5.2.0 (the supplied updater):
- Remote Editor calls `/Evil/API/Blocks` for model categories and available
  models.
- It writes `ModuleType1..14` and calls `setModuleTypeInternal` on
  `/Evil/Engine/Patch/Chain`.
- The specific `Failed loading plugin` message is located adjacent to
  `QtQuick.2`, `qtquick2plugin` and MIDI assignment strings. It is
  **not evidence** of DSP plugin loading.
- Additional binary reverse engineering is required before claiming
  `dlopen` is used for audio effect modules.
