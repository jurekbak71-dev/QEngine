# HeadRush Core 5.2.0 — trzy metody łączników SESP mają wspólny szablon ARM

**Data:** 2026-11-19. Analiza offline, tylko odczyt. Źródło: oryginalny plik `/usr/Evil/Evil` z firmware HeadRush Core 5.2.0, SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

Nie przesyłać własnościowego firmware ani bazy presetów do publicznego repozytorium.

## Potwierdzone obiekty i metody

Analiza kontynuuje raport [SPATIAL_PROPERTY_CONNECTOR_OBJECTS.md](SPATIAL_PROPERTY_CONNECTOR_OBJECTS.md). Pierwsze metody wirtualne następujących instancji szablonu `DspPropertyConnectorImpl`:

| Typ SESP parametru | Wirtualna metoda VA | Następny wpis EHABI |
|---|---|---|
| `SESP::Effect::Reverb::ShimmerIntervalKind` | `0x00946668` | `0x00946A10` |
| `SESP::Effect::Modulation::ChorusMultiVoiceKind` | `0x00948AF8` | `0x00948EA0` |
| `SESP::Effect::Modulation::ChorusMultiWaveformKind` | `0x009484E0` | `0x00948888` |

Dla każdej metody potwierdzono adres w pierwszym slocie właściwej tablicy wirtualnej oraz dokładny początek regionu z `.ARM.exidx`. Przegląd adresów `.ARM.exidx` musi być ostrożny: są to granice regionów indeksu rozwijania stosu, nie gwarancja, że każde słowo aż do następnego wpisu jest instrukcją.

W tym konkretnym ELF każda metoda zawiera obszar instrukcji A32 do offsetu **`+0x338`** (824 bajty), po którym znajdują się znane wartości `0x00000002`, `0x00000000`, a następnie pula stałych. W ten sposób odróżniono **206 słów kandydującego kodu** od **28 słów puli danych** w całym regionie EHABI o rozmiarze `0x3A8` (936 bajtów).

## Wynik porównania instrukcji, weryfikowany na oryginalnym ELF

| Element | Wynik |
|---|---:|
| Słowa instrukcji analizowane na metodę | 206 |
| Instrukcje identyczne bitowo we wszystkich trzech | **182** |
| Różne kody instrukcji `BL`, ale te same adresy wywoływanych funkcji | **24** |
| Różne cele bezpośrednich wywołań `BL` | **0** |
| Różne cele `BL` łącznie (liczba unikatowych adresów) | **11** |
| Rejestrowe `BLX` w każdej metodzie | **4** |
| Słowa puli stałych identyczne | **5/28** |
| Słowa puli stałych różne | **23/28** |

Wszystkie 24 różniące się instrukcje `BL` odzyskują **identyczny cel po uwzględnieniu przesunięcia PC + 8 i znaku offsetu**. Pozostałe 182 instrukcje mają identyczne 32-bitowe kodowanie.

Wszystkie trzy metody mają wywołania `BLX` w tych samych offsetach względnych: `+0x4C (r3)`, `+0x74 (r1)`, `+0xB8 (r3)` i `+0x17C (r3)`.

Wybrane, identyczne instrukcje obsługujące obiekty:

- `+0x10: ldr r0,[r0,#4]` — odczyt wskaźnika z pola obiektu łącznika `this+4`.
- `+0x48: ldr r3,[r3,#32]`, `+0x4C: blx r3` — wywołanie metody o indeksie 8 w **jakiejś** tablicy wirtualnej obiektu pośredniego; typ pośredni nadal NIEZWERYFIKOWANY.
- `+0x58: ldr r2,[r4,#12]`, `+0x5C: ldr r1,[r4,#8]`, `+0x60: ldr r8,[r4,#24]` — odczyty pól łącznika.
- `+0x78: ldrb r3,[r5,#0xB64]`; `+0x7C: ldr r2,[r5,#0xB8C]` — odczyty pól obiektu przekazanego w drugim argumencie (zgodne z `mov r5,r1` na początku).
- `+0x88: ldr r3,[r2,r8,lsl #3]` — dostęp do struktury indeksowanej w odstępach ośmiobajtowych. To **nie identyfikuje** jeszcze semantyki tej struktury.

**Wniosek statyczny:** funkcje stanowią specjalizacje **wspólnego szablonu operacji na właściwościach**; różnice w logice kontrolnej nie występują w analizowanym obszarze instrukcji. Własne dane typu, offsety i wskaźniki w puli stałych są różne. Rozpoznanie podobieństwa nie dowodzi, że następuje bezpośrednia aktualizacja algorytmu DSP.

## Kod, uruchomienie i testy

- [compare_spatial_connector_methods.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/compare_spatial_connector_methods.py)
- [test_compare_spatial_connector_methods.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_compare_spatial_connector_methods.py)
- [GitHub Actions 44572562865](https://github.com/jurekbak71-dev/QEngine/actions/runs/44572562865) — **137/137 PASS**.

```bash
python3 tools/headrush/compare_spatial_connector_methods.py \
    --evil /private/Evil --out /private/shared-connector-methods.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Wyniki oryginalnego ELF: 206 słów kandydującego kodu, 182 identyczne, 24 z relokowanymi celami `BL`, 4 wspólne pozycje `BLX`, 23 różniące się słowa stałych. 13 nowych testów syntetycznych potwierdziło też wykrywanie zmiany opkodu, zmiany celu `BL`, błędnego SHA-256, braku zgodności vtable i `.ARM.exidx`, błędnego `BLX` oraz odróżnienie literalnej puli danych od instrukcji.

Podczas rozwoju testu wyłapano błędną wartość oczekiwaną dla przypadku zmiany puli stałych (nowy test mutował słowo pierwotnie wspólne, więc liczba różnic rosła). Poprawiono **dane testowe** i powtórzono testy z wynikiem PASS; nie pomijano niezgodności.

**Specyfikacja uzupełniająca:** [Arm Exception Handling ABI, ehabi32 — .ARM.exidx, prel31](https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst).

## Co nadal nie jest zweryfikowane

- Która z funkcji wywoływanych przez wspólny szablon, jeśli którakolwiek, aktualizuje stan aktywnego `SESP::Effect::Reverb::Shimmer` lub `SESP::Effect::Modulation::ChorusMulti`.
- Tożsamość obiektu spod `this+4` i obiektu drugiego argumentu; semantyka pól `+0xB64` i `+0xB8C`.
- Gotowy system ładowania własnych natywnych wtyczek, bezpieczeństwo patchowania firmware i poprawność importu rigów.

**NIEWYKONANE:** modyfikacja własnościowego ELF, implementacja nowego algorytmu na Core, uruchomienie DSP i testy audio na fizycznym urządzeniu.

**Następny kierunek:** prześledzić strukturę i klasę obiektu `this+4`, jego metodę wirtualną indeks 8 oraz zapis/odczyt pola kontrolera `+0xB8C` aż do właściwego odbiorcy parametrów. Dopiero wtedy można rozstrzygnąć, czy jest to most do algorytmu DSP, czy infrastruktura UI/presetów.
