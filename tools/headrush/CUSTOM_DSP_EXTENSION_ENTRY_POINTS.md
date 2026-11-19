# HeadRush Core 5.2.0 — jak dodać własny efekt: fabryka DSP i punkty integracji

**Data weryfikacji:** 2026-11-19. **Źródło:** oryginalny, prywatny ARM32 ELF `/usr/Evil/Evil` z instalatora HeadRush Core 5.2.0. SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Badanie statyczne, read-only; **nie dodawać** oryginalnego ELF, rootfs, bazy presetów ani kodu producenta do publicznego repozytorium.

## Dlaczego to jest istotne

Główne dotychczasowe badanie SESP śledziło parametry, serializację i bufory kontrolerów. To nie rozwiązywało kluczowego problemu **jak zarejestrować nowy algorytm DSP**. W tym etapie skoncentrowano się na fabryce `0x00812570`, wcześniej wskazanej przez [DSP_FACTORY_FINDINGS.md](DSP_FACTORY_FINDINGS.md).

Ważne: napis `Failed loading plugin %s at %s` znajduje się w otoczeniu QtQuick i nie jest dowodem modułowego loadera DSP. Metody `dlopen/dlsym` same w sobie nie dostarczają weryfikowalnego ABI własnych efektów.

## Potwierdzone wywołania fabryki na oryginalnym ELF

Przeskanowano całą sekcję `.text` (22 862 440 bajtów) pod kątem **bezpośrednich bezwarunkowych instrukcji ARM32 BL** prowadzących do `0x00812570`. Znaleziono **dokładnie trzy**:

| Adres wywołania | Źródło selektora r0 | Co dalej dzieje się z wynikiem |
|---|---|---|
| `0x01633488` | `0x01633484: ldr r0,[r8,#0x44]` — dynamiczny identyfikator z tabeli | `0x01633494: ldr r2,[r0]`; `0x016334B0: ldr r9,[r2,#0x50]`, następnie `0x016334B8: blx r9` |
| `0x016565B4` | `0x016565AC: mov r0,#75` | `0x016565BC: str r0,[r4,#0x23C]`; `0x016565C4: ldr r6,[r3,#0x50]`, `0x016565F0: blx r6` |
| `0x016565F8` | `0x016565F4: mov r0,#75` | `0x01656600: str r0,[r4,#0x240]`; `0x01656608: ldr r6,[r3,#0x50]`, `0x01656630: blx r6` |

Adres `+0x50` w tablicy funkcji wirtualnych oznacza slot **20**, ale **nie identyfikuje jeszcze funkcji DSP przetwarzającej próbki**; może to być metoda konfiguracji obiektu. Odkrycie nie obejmuje wywołań przez rejestr, wskaźnik ani Thumb.

Funkcja fabryki ma zakres wyboru `cmp r0,#138`, `addls pc,pc,r0,lsl #2`, po czym tablicę **139 wpisów 0..138**. Wcześniejszy raport zanotował 66 niedomyślnych gałęzi i **48 jednoznacznie dopasowanych klas**; nie wolno utożsamiać indeksu fabryki z identyfikatorem `ModuleType` z Remote Editor bez dodatkowych dowodów.

## Ważna identyfikacja: przypadek 75 to GlobalEQ, NIE wolne miejsce

Tablica `0x008125B4` dla indeksu **75**:

- `0x008126E0: b 0x00812A40` — wejście w istniejącą gałąź.
- `0x00812A40: mov r0,#80` — alokacja obiektu **80 bajtów**.
- `0x00812A54: ldr r3,[pc,#0x508]`, `0x00812A64: add r3,pc,r3`, `0x00812A68: add r3,r3,#8`, `0x00812A6C: str r3,[r2],#60` — wpisanie wskaźnika `vptr`.
- Dekodowanie puli pod `0x00812F64` daje **vtable VA `0x02EAA39C`**, typeinfo VA `0x02F28F80`, pierwsza metoda `0x0086AB48`.
- RTTI (z `typeinfo+4`) i demangling C++:
  `EvilDSPs::DSPModule<EvilDSPs::GlobalEQ, EvilDSPs::GlobalEQController, Evil::Serialization::DSPSerializer>`.

**Wniosek:** bezpośrednia podmiana gałęzi nr 75 nie oznacza dodania nowego reverbu/delayu — naruszałaby istniejącą implementację `GlobalEQ`. Nie należy zmieniać firmware urządzenia w oparciu o ten indeks.

## Realne opcje tworzenia własnych efektów

| Podejście | Co rzeczywiście daje | Stan / ograniczenie |
|---|---|---|
| **A. Rozszerzenie fabryki o własny typ** | Nowy moduł w łańcuchu Core | **NIEZWERYFIKOWANE**: wymagane zrozumienie selektora, vtable, budowy grafu, rejestracji w UI/API, parametryzacji, zapisu presetów i mechanizmu podpisywania firmware. Sama zmiana tablicy 139 przypadków nie wystarczy. |
| **B. Zastąpienie istniejącej implementacji efektu** | Potencjalna podmiana algorytmu zachowująca dotychczasowy slot/UI | **HIPOTEZA**: trzeba zachować zgodność ABI, liczbę kanałów, stan, pamięć, format próbek i parametry; bezpieczniej badać najpierw w odizolowanym QEMU. Nie zmieniać `GlobalEQ` przypadkiem. |
| **C. Odrębny silnik efektów na Windows/Linux/Pi** | Natywne nowe reverby, delaye i modulacje, możliwość ładowania plików bez przebudowy hosta | **Technicznie wykonalne**, ale nie jest natywnym efektem w firmware HeadRush Core. Dobre środowisko do algorytmów i porównań, nie rozwiązanie sprzętowego slotu. |
| **D. Plik IR dla C-Verb** | Własna charakterystyka pogłosu w obsługiwanym efekcie | **Ograniczenie:** IR nie jest kodem własnego algorytmu DSP; nie rozwiązuje tworzenia delayów, chorusów i shimmerów. |

**Preferencja projektu:** efekty przestrzenne, delay i modulacja; nie skupiać się na przesterach.

## Strategia dalszej analizy — kod zamiast zgadywania

1. **Fabryka:** odczytać wywołania `0x01633488`, `0x016565B4`, `0x016565F8` oraz źródło selektora i prześledzić obiekt po wywołaniu wirtualnym `vtable+0x50`.
2. **Przypadki Shimmer, AIR Delay, Multi Chorus:** wskazać dokładne indeksy tablicy 0..138, ich konstruktory, klasy RTTI i layout. **Nie utożsamiać automatycznie indeksu fabryki z numerem modelu UI.**
3. **Granica ABI DSP:** odnaleźć funkcję na gorącej ścieżce bufora audio oraz jej wywołania do obiektu z fabryki. Zidentyfikować podpis/argumenty, sample format, stereo/mono i wymagania pamięci.
4. **Dopiero po dowodach:** utworzyć eksperymentalny moduł działający poza sprzętem / w sandboxie QEMU oraz sprawdzić możliwość podmiany wyłącznie w prywatnej kopii. Nie pisać zmodyfikowanego firmware na fizyczny Core bez sprawdzonego przywracania.

## Narzędzia i testy

- [trace_dsp_factory_callers.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_dsp_factory_callers.py) — inspekcja `BL` i selektora, **tylko do odczytu**.
- [test_trace_dsp_factory_callers.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_dsp_factory_callers.py) — 12 przypadków syntetycznych, w tym wadliwy cel, zły selektor i zmieniony adres metody.
- [GitHub Actions 44610764916](https://github.com/jurekbak71-dev/QEngine/actions/runs/44610764916): **178/178 PASS** po skrypcie i testach.
- Weryfikacja niezależna na oryginalnym ELF: trzy miejsca `BL`, źródła selektora, gałąź fabryki 75 i RTTI `GlobalEQ`. Testy CI nie uruchamiają prawdziwego firmware ani DSP audio.

```bash
python3 tools/headrush/trace_dsp_factory_callers.py --evil /private/Evil --out /private/factory-callers.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

**NIEZWERYFIKOWANE:** działające natywne wtyczki DSP `.so`, bezpieczna podmiana gałęzi fabryki, implementacja własnego algorytmu na Core i test na fizycznym urządzeniu.
