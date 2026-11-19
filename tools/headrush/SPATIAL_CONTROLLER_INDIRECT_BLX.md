# Core 5.2.0 — pośrednie wywołania BLX kontrolerów przestrzennych

Data analizy: **2026-11-19**. Źródło: wyłącznie odczyt oryginalnego ARM32 ELF `/usr/Evil/Evil`, wyodrębnionego z dostarczonego instalatora HeadRush Core 5.2.0.

SHA-256 `Evil`: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

## Rozszerzenie dotychczasowego skanowania

Wcześniejsze narzędzie [trace_spatial_exidx_methods.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_exidx_methods.py) liczyło wyłącznie bezpośrednie, bezwarunkowe wywołania ARM32 `BL`. Nie wykrywało pośrednich wywołań `BLX Rm`. Nowe narzędzie [trace_spatial_indirect_calls.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_indirect_calls.py) sprawdza pełne, wyznaczone przez `.ARM.exidx`, zakresy metod z indeksów **25 i 26** głównych tablic wirtualnych `AIRDelayController`, `ShimmerController` i `MultiChorusController`.

Kontrola wejścia jest potrójna: SHA-256 pliku musi być zgodny z dwoma wcześniejszymi raportami, adresy metod muszą być faktycznie zapisane w tablicach wirtualnych, a zakresy muszą wynikać z prawdziwych wpisów `.ARM.exidx` tego samego ELF.

## Wynik na oryginalnym kodzie ARM

W sześciu metodach odnaleziono **17 rejestrowych wywołań `BLX`**. W tych zakresach nie odnaleziono bezpośrednich instrukcji `BLX immediate`.

| Kontroler | Indeks 25 | Indeks 26 | Razem |
|---|---:|---:|---:|
| AIR Delay | 2 | 0 | 2 |
| Shimmer | 3 | 3 | 6 |
| Multi Chorus | 3 | 6 | 9 |
| **Razem** | **8** | **9** | **17** |

### Trzy rozpoznane mechanizmy

1. **11 wywołań przez wskaźnik tablicy wirtualnej**: instrukcja `ldr r3,[r3,#8]` (indeks 2, **3 miejsca**) albo `ldr r3,[r3,#32]` (indeks 8, **8 miejsc**), po wcześniejszym pobraniu wskaźnika tablicy z obiektu i przed `blx r3`. **Nie udowodniono**, że wskazane obiekty są samymi adapterami SESP; mogą być innymi obiektami C++.
2. **3 wywołania przez indeksowaną tablicę wskaźników**: `ldrne r1,[r3,r1]` (`0x17931001`) bezpośrednio przed `blx r1`. Są obecne w metodach indeksu 26 Shimmer (**1**) i Multi Chorus (**2**). Dynamiczna zawartość wskaźnika nie została odtworzona.
3. **3 warunkowe ścieżki zastępcze**: skok `bne` do bloku kończącego się `blx r3`, z wcześniejszym pobraniem adresu poprzez `ldr r3,[r3]`. Shimmer ma **1**, Multi Chorus **2**. Brak dowodu, że wskazany adres prowadzi do DSP audio.

### Dokładne adresy BLX

| Kontroler, metoda | Adres BLX | Identyfikowany wzorzec |
|---|---|---|
| AIR Delay 25 | `0x00911AF8` | vtable indeks 2 |
| AIR Delay 25 | `0x00911B7C` | vtable indeks 8 |
| Shimmer 25 | `0x00919370` | vtable indeks 2 |
| Shimmer 25 | `0x009193F4`, `0x00919458` | vtable indeks 8 |
| Shimmer 26 | `0x0092BAA8` | vtable indeks 8 |
| Shimmer 26 | `0x0092BAD0` | indeksowany wskaźnik |
| Shimmer 26 | `0x0092BDF8` | warunkowy wskaźnik zastępczy |
| Multi Chorus 25 | `0x00917BD8` | vtable indeks 2 |
| Multi Chorus 25 | `0x00917C58`, `0x00917CC8` | vtable indeks 8 |
| Multi Chorus 26 | `0x00926A6C`, `0x00926CBC` | vtable indeks 8 |
| Multi Chorus 26 | `0x00926B0C`, `0x00926CE4` | indeksowany wskaźnik |
| Multi Chorus 26 | `0x00926E3C`, `0x00926E4C` | warunkowy wskaźnik zastępczy |

Niezależna deasemblacja `llvm-objdump` na rzeczywistym ELF rozpoznała **dokładnie te same 17 adresów**, bez dodatkowych wywołań rejestrowych. Sprawdzono zgodność we wszystkich sześciu regionach metod.

## Wykonany kod i testy

- [Analizator BLX](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_indirect_calls.py)
- [11 nowych testów regresji](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_indirect_calls.py)
- [GitHub Actions — 113/113 PASS](https://github.com/jurekbak71-dev/QEngine/actions/runs/44565725949)

Uruchomienie z prywatnymi plikami:

```bash
python3 tools/headrush/trace_spatial_indirect_calls.py \
  --evil /private/Evil \
  --vtables /private/HeadRush_Core_520_controller_vtables.json \
  --bounds /private/HeadRush_Core_520_controller_method_bounds.json \
  --out /private/HeadRush_Core_520_indirect_BLX_controller_calls.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

**Testy:** 11/11 nowych testów lokalnych PASS; kompletna seria CI 113/113 PASS. Testy obejmują m.in. rozpoznawanie A32 `BLX` (rejestr i immediate), `BNE`, wzorce pobierania wskaźników, zgodność SHA-256, tablicy metod i granic EHABI.

## Granice dowodu

**POTWIERDZONE:** pośrednie wywołania występują w kodzie specjalizowanych metod trzech kontrolerów. Obecność odwołania przez tablicę metod lub indeksowaną tablicę adresów została potwierdzona konkretnymi instrukcjami ARM.

**PRAWDOPODOBNE:** kod wykonuje dynamiczną obsługę obiektów parametrów, formatowania lub konfiguracji kontrolera, ponieważ sąsiednia analiza metod indeksu 26 pokazała nazwy kontrolek i formaty `%.0f Hz` / `%.0f %%`. Nie jest to dowód semantyki każdego wywołania `BLX`.

**NIEZWERYFIKOWANE:** tożsamość obiektów docelowych, ich rzeczywista tablica vtable w trakcie pracy oraz powiązanie z `SESP::Effect::Reverb::Shimmer`, `SESP::Effect::Modulation::ChorusMulti` lub `SESP::Effect::Delay::AIRDelay`.

**NIEWYKONANE:** podmiana natywnego DSP, loader własnych `.so`, zapisywanie firmware, import zmodyfikowanego `.rig` i odsłuch efektu na fizycznym Core.

Następny etap: prześledzić wstecz pochodzenie obiektów wskazywanych przez `r0`, `r3` i `r1` w krytycznych miejscach `BLX`, a następnie dopasować konkretne vtable/typeinfo, dopiero wtedy analizować rzeczywistą ścieżkę sterowania SESP.