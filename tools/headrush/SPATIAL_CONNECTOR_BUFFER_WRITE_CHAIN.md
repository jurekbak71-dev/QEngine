# HeadRush Core 5.2.0 — zweryfikowany zapis do indeksowanego bufora właściwości

**Data badania:** 2026-11-19. **Materiał:** oryginalny ARM32 ELF `/usr/Evil/Evil` z prywatnego instalatora HeadRush Core 5.2.0. SHA-256: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Badanie tylko do odczytu. Oryginalny kod binarny i fabryczne presety nie zostały dodane do publicznego repozytorium.

## Najważniejsze: znane indeksy bufora z konstruktorów łączników

Wcześniej udokumentowano trzy obiekty `DspPropertyConnectorImpl` i pierwsze metody ich vtable. Na oryginalnym ARM ELF udało się teraz sprawdzić **powiązanie konstruktora, indeksu właściwości i metody zapisującej**.

| Łącznik SESP | Zapis pary `vptr` i obiektu | Zapis `łącznik+0x18` | Ustalony indeks | Offset wpisu przy kroku 8 B |
|---|---|---|---:|---:|
| `ShimmerIntervalKind` | `0x0092BA38` | `0x0092BA58` | **0** | **0** |
| `ChorusMultiVoiceKind` | `0x009269F8` | `0x00926A18` | **4** | **32** |
| `ChorusMultiWaveformKind` | `0x00926C4C` | `0x00926C6C` | **7** | **56** |

W konstruktorach odpowiednio instrukcje `mov r3,#0`, `mov r3,#4`, `mov r3,#7` poprzedzają `str r3,[this,#0x18]`. Instrukcje `stm` wpisują również do obiektu łącznika vtable i wskaźnik obiektu pobrany wcześniej ze stosu (odpowiednio rejestry `r8`, `r9`, `r7`). Przed wpisaniem wywołana jest wspólna funkcja `0x00CD2BD4`, w której występują atomowe operacje `LDREX`/`STREX`; **typ i semantyka własności obiektu nadal są do zbadania**.

**To indeksy w zaobserwowanej wewnętrznej tablicy, NIE publiczne numery parametrów, zakresy wartości lub wartości presetu.**

## Sprawdzona ścieżka we wspólnej metodzie wirtualnej

Te same opkody znajdują się w trzech pierwszych metodach vtable (`0x00946668`, `0x00948AF8`, `0x009484E0`):

| Relatywny offset | Instrukcja ARM | Ściśle potwierdzona operacja |
|---|---|---|
| `+0x10` | `ldr r0,[r0,#4]` | odczyt wskazanego obiektu z pola łącznika |
| `+0x48` i `+0x4C` | `ldr r3,[r3,#32]; blx r3` | pośrednie wywołanie wpisu vtable o indeksie 8 tego obiektu |
| `+0x60` | `ldr r8,[r4,#24]` | odczyt indeksu wpisanego przez konstruktor |
| `+0x78` | `ldrb r3,[r5,#0xB64]` | odczyt pola bajtowego drugiego argumentu |
| `+0x7C` | `ldr r2,[r5,#0xB8C]` | odczyt wskaźnika tablicy |
| `+0x88` i `+0x8C` | `ldr r3,[r2,r8,lsl #3]; add r8,r2,r8,lsl #3` | pobranie wpisu i obliczenie adresu: baza + indeks × 8 |
| `+0xE8` | `ldr r3,[r8,#4]` | pobranie adresu rekordu wartości z drugiego słowa wpisu |
| `+0x10C` i `+0x110` | `strhne r2,[r3]; strbne r1,[r3,#2]` | warunkowy zapis 16 bitów i bajtu znacznika |
| `+0x1B4` i `+0x1B8` | `strb r7,[r3]; strb r2,[r3,#2]` | alternatywny zapis wartości bajtowej i znacznika |
| `+0x114` i `+0x118` | `mov r3,#1; strb r3,[r5,#0xB6C]` | zapis bajtu `1` w polu `+0xB6C` |

Semantyka flag `+0xB64` i `+0xB6C` jest **hipotezą**: nazwa „dirty/update flag” odpowiada obserwowanemu wzorcowi, ale jej odbiorca nie został zidentyfikowany. Zapisy do rekordu są warunkowe, więc nie należy twierdzić, że każda ścieżka wykonania zawsze zmienia wartość.

## Zewnętrzny kod modyfikujący pole +0xB8C

- `0x007A68A4`: odczyt obiektu z pola `[r5,#0x534]`.
- `0x007A68B0`: wywołanie wirtualne przez `vtable+0x20` na obiekcie wejściowym.
- `0x007A68B4`: wywołanie `0x00CB2E48`; `0x007A68BC`: `str r0,[r5,#0xB8C]` — zapis zwróconej wartości do pola tego obiektu.
- Wewnątrz `0x00CB2E48`: `0x00CB2E94` pobiera `vtable+0xBC` (indeks 47), `0x00CB2E98` je wywołuje, `0x00CB2EBC` odczytuje kolejne pole `+0x18` w jednej z gałęzi wyniku, a `0x00CB2EEC` zwraca wybraną wartość w `r0`. Są też inne ścieżki i wyjątki.
- `0x007D208C` i `0x007D2098`: wyzerowanie pola `[r0,#0xB8C]` w innym fragmencie kodu.

**Istotne ograniczenie:** jednakowy offset `+0xB8C` w różnych funkcjach nie dowodzi automatycznie, że każdy `r0`/`r5` wskazuje instancję tego samego typu. Powiązanie to jest **NIEZWERYFIKOWANE**. Nie stwierdzono jeszcze, kto odczytuje zawartość rekordu i czy przekazuje ją do aktywnego algorytmu SESP.

## Nowy kod i weryfikacja

- [trace_spatial_parameter_buffer_writes.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_parameter_buffer_writes.py)
- [test_trace_spatial_parameter_buffer_writes.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_parameter_buffer_writes.py)
- [GitHub Actions 44575703411](https://github.com/jurekbak71-dev/QEngine/actions/runs/44575703411): **150/150 PASS** po dodaniu analizatora i 13 testów.

Lokalnie na oryginalnym ELF zweryfikowano 75 opkodów metod, 15 opkodów konstruktorów/odwołań i 15 punktów ścieżki ustawienia/wyzerowania pola. SHA-256 źródła jest sprawdzany przed analizą. 13 lokalnych testów syntetycznych zakończyło się sukcesem, łącznie z celowymi zmianami instrukcji i indeksów.

```bash
python3 tools/headrush/trace_spatial_parameter_buffer_writes.py \
  --evil /private/Evil \
  --output /private/property-buffer-write-chain.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

### Status

**POTWIERDZONE:** trzy indeksy bufora 0/4/7, zapis do rekordu 1–3 bajtów, marker `+0xB6C=1`, użycie pola `+0xB8C` i wskazany kod jego zapisu/zerowania.

**PRAWDOPODOBNE:** zmiany właściwości są kolejkowane/oznaczane w pośrednim buforze stanu. To nie jest jeszcze ślad rzeczywistego przetwarzania audio.

**NIEZWERYFIKOWANE:** tożsamość właścicieli struktur, ostateczny konsument rekordów, połączenie do `SESP::Effect::Reverb::Shimmer` i `SESP::Effect::Modulation::ChorusMulti`.

**NIEWYKONANE:** podmiana natywnego algorytmu, import własnej biblioteki `.so` i testy na fizycznym HeadRush Core.

**Następny etap:** odszukać odczyty pól wpisu `+4` i flagi `+0xB6C` w kodzie odbiorcy, identyfikować jego vtable i powiązanie z obiektami silnika DSP.
