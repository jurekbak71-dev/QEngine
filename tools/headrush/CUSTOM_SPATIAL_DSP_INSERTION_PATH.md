# HeadRush Core 5.2.0 — dwa przełączniki fabryki DSP i droga do własnych efektów

**Stan: 19.11.2026.** Badanie wyłącznie do odczytu, na prywatnym oryginalnym ELF ARM32 `/usr/Evil/Evil` wyodrębnionym z instalatora użytkownika. SHA-256: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Nie publikować firmware, plików urządzenia ani fabrycznych presetów w QEngine.

## 1. POTWIERDZONE — rzeczywista fabryka to układ DWÓCH tablic

Funkcja tworząca moduły `EvilDSPs::DSPModule<Effect,Controller,DSPSerializer>` zaczyna się pod VA `0x00812570`:

- `0x008125A8: cmp r0,#138`; `0x008125AC: addls pc,pc,r0,lsl #2`: **pierwsza tablica 139 wpisów** pod `0x008125B4`. Spośród nich 73 prowadzą do `0x008127E0`, czyli przełącznika drugiego stopnia; 66 mają inne cele.
- `0x008127E0: sub r3,r0,#27`; `0x008127E4: cmp r3,#79`; `0x008127E8: addls pc,pc,r3,lsl #2`: **druga tablica 80 wpisów** pod `0x008127F0`, indeksowana `r0-27`. 39 pozycji prowadzi do jej domyślnego adresu `0x008146C0`, a 41 do innych miejsc.
- Dla wybranych efektów przestrzennych wpis z pierwszej tablicy prowadzi **dokładnie do drugiego przełącznika**. Wcześniejsza analiza obejmująca tylko pierwszy przełącznik nie mogła odnaleźć tych konstruktorów; nie stanowi to braku efektów w firmware.

W rzeczywistym ELF potwierdzono dla każdego z poniższych indeksów: skok w pierwszym przełączniku → skok w drugim → początek konstruktora → PC-relative `LDR` i `ADD` obliczające tablicę metod → zapis `vptr` do obiektu → `typeinfo` → pełny mangled RTTI `DSPModule` z właściwą nazwą efektu.

| Indeks DSP | Efekt | Konstruktor VA | Vtable VA | Slot 20 (offset 0x50) | Slot 21 (offset 0x54) |
|---:|---|---|---|---|---|
| **32** | Tape Echo | `0x00814834` | `0x02EA8D70` | `0x00983098` | `0x009604F8` |
| **35** | BBD Delay | `0x00814A50` | `0x02EA89D4` | `0x0097F298` | `0x0095F0D8` |
| **37** | AIR Reverb | `0x008149D8` | `0x02EA8CEC` | `0x00982448` | `0x00960218` |
| **38** | Eleven Reverb | `0x0081499C` | `0x02EA8C68` | `0x00981780` | `0x0095FF38` |
| **42** | Chorus | `0x008148E8` | `0x02EA87C4` | `0x0097D2B8` | `0x0095E558` |
| **43** | Multi Chorus | `0x008148AC` | `0x02EA8740` | `0x0097CD58` | `0x0095E278` |
| **84** | AIR Delay | `0x00814B04` | `0x02EA8950` | `0x0097EAB8` | `0x0095EDF8` |
| **85** | Shimmer | `0x00814AC8` | `0x02EA8008` | `0x00955FF0` | `0x00935C68` |

**Wszystkie osiem modułów ma po 31 kolejnych wskaźników do kodu** w głównej tablicy wirtualnej. Każdy konstruktor rozpoczyna się od `mov r0,#80`, poprzedzającego wywołanie alokatora, co jest dowodem żądania **80 bajtów na obiekt wrappera** w tej ścieżce (nie całkowitego zapotrzebowania DSP na pamięć). Nie wolno utożsamiać indeksów fabryki z publicznym `ModuleType` edytora zewnętrznego bez osobnego śladu protokołu.

## 2. POTWIERDZONE — sposób wykorzystania obiektu `DSPModule`

Skan całej sekcji `.text` znalazł **trzy bezpośrednie wywołania** `BL 0x00812570`:

- `0x01633488`: argument selektora pobrany przez `ldr r0,[r8,#0x44]` z wewnętrznej struktury. Zwrócony obiekt jest używany do wywołań przez vtable **`+0x50` (slot 20)** oraz **`+0x54` (slot 21)**.
- `0x016565B4` i `0x016565F8`: poprzedzone `mov r0,#75`; selektor 75 został zweryfikowany przez RTTI jako `DSPModule<GlobalEQ,GlobalEQController,DSPSerializer>`. W tych miejscach również występuje wywołanie przez slot 20.
- Selekcja 76 została niezależnie zweryfikowana jako `DSPModule<Octaves,OctavesController,DSPSerializer>`.

Sama tablica 31 metod **nie podaje ich sygnatur, porządku argumentów ani tego, która metoda przetwarza próbki audio**. Nie zakładać, że slot 20/21 oznacza `process()`, ani że `GlobalEQ` jest bezpiecznym zamiennikiem do testów.

## 3. Co to mówi o instalowaniu własnych efektów

**POTWIERDZONE:** przestrzenne efekty korzystają z wbudowanych konstruktorów C++, kontrolerów i serializatora, wybieranych przez indeksowane tablice kodu ARM. Dotychczas nie zidentyfikowano udokumentowanego interfejsu `dlopen` umożliwiającego automatyczne dodanie własnego modułu `.so`. Nazwy `dlopen`, `dlsym`, `dlclose` występują w `.dynsym` badanego `Evil`, ale **nie występują jako symbole w relokacjach `.rel.dyn` ani `.rel.plt` tego konkretnego ELF**; to nie wyklucza ładowania innych bibliotek przez inne procesy lub pośrednie ścieżki.

**Droga A — najpierw eksperyment w kopii QEMU (hipoteza):** podmienić tworzenie lub konkretną metodę jednego istniejącego typu przestrzennego, zachowując zgodny wrapper `DSPModule`, jego kontroler, serializator i 31-slotową tabelę. Własny DSP należałoby skompilować dla **ARMv7 EABI hard-float**, nie jako Windows DLL czy zwykły VST3. Wymaga to zbadania sygnatur metod, cyklu życia, układu wejść/wyjść audio, alokacji i powrotu do oryginalnej ścieżki. To **nie jest jeszcze wykonane**. Sam `LD_PRELOAD` nie przechwytuje automatycznie wewnętrznych, statycznych wywołań `BL` do funkcji bez eksportowanego symbolu.

**Droga B — całkowicie nowy typ i nowa pozycja na liście (bardziej inwazyjna):** modyfikacja tablic wyboru i limitu indeksów, a także rejestru modeli UI, mapowania parametrów, serializacji i zdolności przywrócenia firmware. **Nie znaleziono publicznego punktu rejestracji**, który pozwalałby dopisać taki typ jednym plikiem.

**Droga C — niezależny host audio/IR:** pozwala pisać i odsłuchiwać własne algorytmy lub odpowiedzi impulsowe, ale bez potwierdzonego połączenia z silnikiem Core nie należy nazywać go efektem działającym na urządzeniu. Istniejące IR do C-Verb nie są podmianą kodu DSP.

**Bramki akceptacji przed jakimkolwiek instalowaniem:** (1) potwierdzony tor audio w QEMU/na sprzęcie testowym, (2) zidentyfikowany ABI metody procesora sygnału, (3) poprawne tworzenie/zwalnianie stanu, (4) zgodność parametrów i presetów, (5) pomiary obciążenia, opóźnienia i stabilności, (6) kopia zapasowa i sprawdzony rollback. Brak zgody na patchowanie fizycznego Core — tego nie robić.

## 4. Powtarzalny, tylko odczytowy test

Nowy kod: [verify_spatial_factory_paths.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/verify_spatial_factory_paths.py), [test_verify_spatial_factory_paths.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_verify_spatial_factory_paths.py).

```bash
python3 tools/headrush/verify_spatial_factory_paths.py \
  --evil /private/Evil --output /private/two-stage-spatial-factory.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Analizator weryfikuje SHA-256 źródła, obie tablice ARM, skoki, adresy konstruktorów, wyliczenie `vptr` z puli literalnej, RTTI/typeinfo oraz wszystkie **31 metod** i adresy slotów 20/21. Pracuje bez zapisu do firmware. Po zmianie opkodów, RTTI, selektorów albo wskaźników metod zgłasza błąd.

**Testy:** 13/13 nowych testów syntetycznych lokalnie PASS; na oryginalnym ELF 8/8 modeli zweryfikowanych; [GitHub Actions 44609671691](https://github.com/jurekbak71-dev/QEngine/actions/runs/44609671691): **166/166 PASS**.

## 5. Najważniejszy następny krok kodowy

**Nie dodawać na ślepo kolejnego indeksu switcha.** Najpierw przeanalizować i udokumentować rzeczywistą sygnaturę oraz efekty uboczne metod wrappera dla AIRDelay (slot 20: `0x0097EAB8`, slot 21: `0x0095EDF8`), Shimmer (`0x00955FF0` / `0x00935C68`), MultiChorus (`0x0097CD58` / `0x0095E278`) i ich powiązanie z adapterami SESP. Dopiero przy zweryfikowanym interfejsie można zaprojektować host **rzeczywistego efektu** załadowanego z oddzielnego pliku, zamiast atrapy imitującej firmware.

**NIEZWERYFIKOWANE:** możliwość podmiany metody przez loader w działającym QEMU lub Core, natywne rozszerzenia `.so`, żywe audio i pełny cykl życia.
