# HeadRush Core 5.2.0 — konstrukcja obiektów efektu i kontrolera DSP

**Data:** 20.11.2026. **Źródło:** oryginalny plik ARM32 `/usr/Evil/Evil` wyodrębniony z prywatnego instalatora Core 5.2.0. SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Tylko odczyt. W publicznym repozytorium nie zapisano własnościowego firmware.

## Potwierdzone: co naprawdę zawierają pola wrappera

Metoda o indeksie **20** głównej tablicy `DSPModule<Effect,Controller,DSPSerializer>` tworzy **dwa różne obiekty C++** dla każdego z trzech badanych efektów. Poniższe powiązania zostały sprawdzone jako pełne ciągi instrukcji ARM i metadanych RTTI, nie tylko jako podobieństwa nazw.

| Moduł | Pole wrappera | Klasa C++ wskazywanego obiektu | Alokacja | vptr po zakończeniu inicjalizacji |
|---|---|---|---:|---|
| AIR Delay | `+0x40` | `EvilDSPs::AIRDelay` | **4376 B** | `0x02EB3880` |
| AIR Delay | `+0x4C` | `EvilDSPs::AIRDelayController` | **392 B** | `0x02EB397C` |
| Shimmer | `+0x40` | `EvilDSPs::Shimmer` | **8272 B** | `0x02EB5F7C` |
| Shimmer | `+0x4C` | `EvilDSPs::ShimmerController` | **392 B** | `0x02EB6078` |
| Multi Chorus | `+0x40` | `EvilDSPs::MultiChorus` | **3776 B** | `0x02EB45BC` |
| Multi Chorus | `+0x4C` | `EvilDSPs::MultiChorusController` | **392 B** | `0x02EB46B8` |

**Uwaga:** vptr (pierwszy wpis metody widziany przez obiekt) jest o 8 bajtów dalej od początku nagłówka typowego vtable Itanium/ARM C++ ABI. Wartość `0x02EB6078` nie przeczy wcześniejszemu adresowi nagłówka `0x02EB6070` dla `ShimmerController` — to dwa miejsca tej samej tablicy.

## Dowód tworzenia i zapisu do wrappera

Każda z sześciu ścieżek zawiera:

1. **Argument alokacji**: stała bezpośrednio w instrukcji `MOV/MOVW r0,#N`.
2. **Wywołanie alokatora**: bezwarunkowe ARM `BL 0x0015BAF4`.
3. **Utrwalenie wskaźnika alokacji**: `MOV r4,r0` dla obiektu efektu; `MOV r6,r0` lub `MOV r7,r0` dla kontrolera.
4. **Zapis do wrappera**: `STR r4,[wrapper,#0x40]` albo `STR r6/r7,[wrapper,#0x4C]`.
5. **Instalacja vptr** w alokowanym obiekcie: kod oblicza adres z `LDR` PC-relative, `ADD PC` i przesunięcia +8/+12, następnie zapisuje go do początku obiektu.
6. **Potwierdzenie typu**: `vptr[-2]=0` (`offset_to_top`), `vptr[-1]` prowadzi do `typeinfo`, a z `typeinfo+4` odzyskuje się pełną nazwę C++ dokładnie odpowiadającą efektowi lub kontrolerowi.

**Szczegółowe adresy instrukcji:**

| Moduł | Zapis `efekt → +0x40` | Zapis `vptr efektu` | Zapis `kontroler → +0x4C` | Zapis `vptr kontrolera` |
|---|---|---|---|---|
| AIR Delay | `0x0097F080` | `0x0097F088` | `0x0097F1C4` | `0x0097F164` |
| Shimmer | `0x00956E10` | `0x00956E14` | `0x00956EF8` | `0x00956E98` |
| Multi Chorus | `0x0097D034` | `0x0097D0AC` | `0x0097D19C` | `0x0097D13C` |

Należy odróżnić **potwierdzenie obecności instrukcji i ich adresów** od obserwacji rzeczywistego wykonania w urządzeniu. Nie wykonano śladu dynamicznego `this` ani odsłuchu.

## Co oznacza to dla własnych efektów

POTWIERDZONE: istnieje architektura co najmniej trzech warstw: `DSPModule<Effect,Controller,DSPSerializer>` → **obiekt efektu** pod `+0x40` → **kontroler parametrów** pod `+0x4C`. Wcześniejsza analiza odnalazła 51 łańcuchów odczytu wskaźników do tych obiektów przez ich metody wirtualne.

To wskazuje, że sama podmiana wpisu fabryki nie wystarczy. Przy eksperymentalnej podmianie w kopii firmware konieczne byłoby zachowanie:

- zgodnej tablicy metod i cyklu życia obiektu efektu;
- zgodnego sposobu konstrukcji, mapowania i zwalniania kontrolera;
- integracji z serializatorem i presetami;
- rzeczywistego wejścia/wyjścia audio oraz bezpiecznego przekazywania parametrów;
- architektury ARMv7 EABI zgodnej z urządzeniem i testu rollback.

**NIEZWERYFIKOWANE:** sygnatura funkcji `processAudio`, rola konkretnych metod obiektu efektu podczas obróbki próbek, istnienie publicznego loadera własnych `.so`, stabilność ABI między wersjami firmware.

**NIEWYKONANE:** modyfikacja ELF ani firmware, wdrożenie własnego DSP w QEMU/na sprzęcie, test dźwięku, instalacja wtyczek.

## Kod i testy

- [trace_spatial_module_object_construction.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_module_object_construction.py)
- [test_trace_spatial_module_object_construction.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_module_object_construction.py)
- [GitHub Actions 44695505768](https://github.com/jurekbak71-dev/QEngine/actions/runs/44695505768) — **217/217 PASS** (15 nowych testów).

```bash
python3 tools/headrush/trace_spatial_module_object_construction.py \
    --evil /private/Evil --out /private/verified-object-construction.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Przy tworzeniu sztucznego ELF testowego poprawiono trzy błędne mutacje — dwa początkowo nachodzące na siebie obiekty vtable i zmianę bajtu, który już był zerem. Po poprawieniu **próbki testowej**, bez osłabiania walidatora, lokalne **15/15 PASS**. Skróty plików Git blob w repozytorium i lokalnej testowanej wersji są identyczne.

**Następny etap:** odnaleźć rzeczywiste wejście do SESP z obiektu `EvilDSPs::AIRDelay/Shimmer/MultiChorus` spod `+0x40`. W praktyce oznacza to śledzenie ich wirtualnych metod, wskaźników na adapter `SespAdapterStereoIf`, callbacków audio od strony ALSA i zakresu buforów próbek. Dopiero po tym etapie projektować zgodny host własnego efektu, początkowo w izolowanej kopii QEMU.
