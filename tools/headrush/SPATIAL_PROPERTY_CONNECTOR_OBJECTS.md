# HeadRush Core 5.2.0 — pochodzenie obiektów DspPropertyConnectorImpl

**Data:** 2026-11-19. **Źródło:** oryginalny, prywatny plik `/usr/Evil/Evil` z firmware Core 5.2.0; SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

Ta analiza dotyczy **rzeczywistych instrukcji ARM32, wskaźników C++ i tablic RTTI**. Nie modyfikuje firmware ani plików fabrycznych. Oryginalny ELF nie jest publikowany w QEngine.

## Zweryfikowane obiekty

W metodach o indeksie 26 kontrolerów zidentyfikowano **trzy odrębne instancje szablonu** `EvilDSPs::Controllers::DSPController::DspPropertyConnectorImpl<...>` używającego `StringListTranslator` i `std::mem_fn`. Nazwy RTTI z końcowymi typami SESP to:

- `SESP::Effect::Reverb::ShimmerIntervalKind`.
- `SESP::Effect::Modulation::ChorusMultiVoiceKind`.
- `SESP::Effect::Modulation::ChorusMultiWaveformKind`.

Dla każdej z trzech instancji zweryfikowano łańcuch:

1. Odczyt relatywnej stałej z puli literalnej `LDR` i obliczenie adresu `ADD PC`, a następnie `ADD #8`. Otrzymana wartość jest **dokładnie** adresem tablicy metod konkretnej instancji szablonu.
2. Zapis tego wskaźnika tablicy metod do początku budowanego obiektu instrukcją `STM`.
3. Wywołanie funkcji `0x007ED7E4` i zapis wskaźnika nowego łącznika do miejsca wskazanego przez zwrócone `r0`.
4. Odczyt `vptr[0]` z łącznika i porównanie instrukcją `CMP` z obliczoną w kodzie stałą PC-relative; stała jest równa **pierwszemu adresowi funkcji wpisanemu w tej samej oryginalnej vtable**.
5. Weryfikacja `vtable[-2]` jako `offset_to_top = 0`, `vtable[-1]` jako wskaźnika `typeinfo` i odczyt z `typeinfo+4` pełnej nazwy C++ odpowiadającej typowi SESP.

| Łącznik | Vtable VA | Pierwsza metoda vtable VA | Zapis `vptr` VA | BL helper `0x007ED7E4` VA | Zapis do zwróconego slotu VA | CMP metody VA |
|---|---|---|---|---|---|---|
| ShimmerIntervalKind | `0x02EB29F0` | `0x00946668` | `0x0092BA38` | `0x0092BA78` | `0x0092BA80` | `0x0092BA94` |
| ChorusMultiVoiceKind | `0x02EB2A7C` | `0x00948AF8` | `0x009269F8` | `0x00926A3C` | `0x00926A44` | `0x00926A58` |
| ChorusMultiWaveformKind | `0x02EB2A98` | `0x009484E0` | `0x00926C4C` | `0x00926C8C` | `0x00926C94` | `0x00926CA8` |

**POTWIERDZONE:** konstrukcja trzech **typowanych obiektów łączników parametrów** i przekazywanie ich wskaźników do struktury wyszukiwanej przez wspólną funkcję. Powiązania zostały sprawdzone na oryginalnym ARM32 ELF, a nie wywnioskowane wyłącznie z podobieństwa nazw.

**PRAWDOPODOBNE:** `0x007ED7E4` działa jako wyszukiwanie/wstawianie w indeksowanej strukturze kontrolera; w deasemblacji widać porównania kluczy, wyszukiwanie binarne i ośmiobajtowe wpisy. Szczegółowy typ kontenera, jego własność i pełne zasady życia obiektów nadal nie są potwierdzone.

**NIEZWERYFIKOWANE:** czy konstrukcja, rejestracja lub wywołanie metod łącznika bezpośrednio aktualizuje aktywny algorytm `SESP::Effect::Reverb::Shimmer` albo `SESP::Effect::Modulation::ChorusMulti`. Łącznik może uczestniczyć w synchronizacji konfiguracji bez bezpośredniego wywołania funkcji audio. Wskazane adresy **nie są wykazanym interfejsem własnych wtyczek DSP**.

## Kod, odtworzenie, testy

- [trace_spatial_connector_objects.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_connector_objects.py)
- [test_trace_spatial_connector_objects.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_connector_objects.py)

```bash
python3 tools/headrush/trace_spatial_connector_objects.py \
  --evil /private/Evil --out /private/connector-objects.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Nowy skrypt wymaga **konkretnego SHA-256 oryginalnego ELF** oraz sprawdza oryginalne instrukcje `LDR` (z dodatnim i ujemnym offsetem PC), `ADD PC`, `STM`, `BL`, `LDR` i `CMP`. Odmawia analizy przy rozbieżnościach. Jedenaście nowych testów lokalnych i w CI obejmuje m.in. błędny adres vptr, zmieniony wskaźnik pierwszej metody, inny typ RTTI, podmianę celu rejestracji, brak wymaganego zapisu, niepoprawny ELF i negatywne adresowanie PC.

[GitHub Actions 44569657222](https://github.com/jurekbak71-dev/QEngine/actions/runs/44569657222): **124/124 PASS**. To testy analizatorów na syntetycznych strukturach ELF, nie odsłuch ani wykonanie na fizycznym Core.

## Kolejny krok

Prześledzić wykonanie pierwszych metod wirtualnych `0x00946668`, `0x00948AF8` i `0x009484E0`, w szczególności ich argumentów `this` i wskaźników właściwości. Sprawdzić, czy końcowy zapis dociera do obiektu adaptera SESP. Na obecnym etapie nie modyfikować firmware ani nie zakładać istnienia bezpiecznego modułowego loadera `.so`.
