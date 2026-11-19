# HeadRush Core 5.2.0 — inicjalizacja wrapperów DSP i granice aktualnej integracji własnych efektów

**Data:** 19.11.2026. Badanie wyłącznie offline i tylko do odczytu oryginalnego ARM32 ELF `/usr/Evil/Evil`, SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Nie publikowano własnościowego ELF, rootfs, firmware ani presetów.

## Nowy etap po ustaleniu dwóch tablic fabryki

Poprzedni raport [CUSTOM_SPATIAL_DSP_INSERTION_PATH.md](CUSTOM_SPATIAL_DSP_INSERTION_PATH.md) potwierdził dwustopniowy wybór wbudowanych efektów, ich konstruktory oraz 31 pozycji głównych tablic wirtualnych `DSPModule<Effect,Controller,DSPSerializer>`.

Teraz prześledzono **konkretne funkcje wirtualne z indeksami 20 i 21** dla trzech wybranych przestrzennych modułów. Dla każdej pary kod jest weryfikowany na rzeczywistym ELF razem z odpowiednią pozycją vtable (20 = `+0x50`, 21 = `+0x54`).

| Efekt | Indeks fabryki | Slot 20 VA | Rozmiar przekazany do alokatora | Slot 21 VA |
|---|---:|---|---:|---|
| AIR Delay | 84 | `0x0097EAB8` | **4376 bajtów** | `0x0095EDF8` |
| Shimmer | 85 | `0x00955FF0` | **8272 bajty** | `0x00935C68` |
| Multi Chorus | 43 | `0x0097CD58` | **3776 bajtów** | `0x0095E278` |

### Dowód instrukcjami ARM

- AIR Delay: `0x0097EB00` ustawia `r0=0x1118`, `0x0097EB14` wykonuje `BL 0x0015BAF4`.
- Shimmer: `0x0095604C` ustawia `r0=0x2050`, `0x00956050` wykonuje `BL 0x0015BAF4`.
- Multi Chorus: `0x0097CDA0` ustawia `r0=0xEC0`, `0x0097CDB4` wykonuje `BL 0x0015BAF4`.

Adres `0x0015BAF4` jest ten sam we wszystkich trzech przypadkach. Te liczby określają **obserwowaną wielkość żądania alokacji w konkretnej gałęzi funkcji**, nie całkowitą pamięć efektu, zapotrzebowanie CPU czy rozmiar formatu presetu.

W metodach o indeksie 21 pierwsze **13 instrukcji A32 jest identycznych bitowo**. Sekwencja zachowuje wskaźnik `this`, pobiera pole `[this,#0x40]`, a następnie z tego obiektu wywołuje funkcję wirtualną spod offsetu `+0x54`. Dalej sprawdza wynik i warunkowo odczytuje bajt pod `[r3,#0x125]`. Funkcja przypomina kontrolę stanu, ale jej semantyka i argumenty **NIE ZOSTAŁY POTWIERDZONE**. W szczególności indeks 21 wrappera i indeks 21 obiektu pośredniego nie muszą mieć tej samej roli.

**Nie wolno nazywać slotów 20 i 21 funkcją `processAudio`.** Sama alokacja i pośrednie wywołanie nie identyfikują toru próbek.

## Wniosek dla wprowadzania własnych efektów

Na obecnym etapie największą szansę ma **ABI-kompatybilna podmiana istniejącego efektu przestrzennego w izolowanej kopii QEMU**, bez dodawania nowego indeksu lub ingerencji w fizyczne urządzenie. Kandydatami są istniejące wpisy `AIRDelay=84`, `Shimmer=85` i `MultiChorus=43`, już zweryfikowane z obu tablic fabryki i ich `DSPModule` RTTI.

Zgodność musi objąć nie tylko algorytm, ale również: alokację i niszczenie obiektów, tablice wirtualne, ABI ARM32, kontroler parametrów, serializator, miejsce przetwarzania audio oraz ścieżkę przywrócenia. Dla dodania całkowicie nowego modelu konieczne byłyby dodatkowe zmiany selektora, rejestru efektów UI i serializacji.

**NIEZWERYFIKOWANE**: możliwość ładowania własnych `.so` bez przebudowy firmware; realna sygnatura metod przetwarzających próbki; działający tor DSP w QEMU dla Core; zachowanie sprzętowe. Nie ma podstaw, aby wydać natywną wtyczkę efektu do Core ani twierdzić, że można ją teraz załadować plikiem.

## Kod i testy

- [trace_spatial_dsp_module_abi.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/trace_spatial_dsp_module_abi.py) — tylko odczyt, sprawdza SHA-256 oryginalnego ELF, sloty 20 i 21, instrukcje MOV/MOVW oraz BL alokatora, a także 13 wspólnych instrukcji metody 21.
- [test_trace_spatial_dsp_module_abi.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_trace_spatial_dsp_module_abi.py) — **14 nowych testów syntetycznych**, w tym celowe uszkadzanie vtable, rozmiarów alokacji, celu BL i treści metody 21.
- [CI po poprawce: 44611231802](https://github.com/jurekbak71-dev/QEngine/actions/runs/44611231802) — **192/192 testy PASS**.

Przejściowy błąd CI przy pierwszym commicie testów ([44611093503](https://github.com/jurekbak71-dev/QEngine/actions/runs/44611093503)) wynikał z błędnego oczekiwania pięciu wartości zwracanych przez istniejący generator syntetycznego ELF, który w repozytorium zwracał trzy. Zmieniono destrukturyzację na `blob, at, names, *_ = synthetic_elf()`; nie wyłączono żadnego testu. Ponowna seria przeszła **192/192 PASS**.

Powtórzenie na prywatnym ELF:

```bash
python3 tools/headrush/trace_spatial_dsp_module_abi.py \
  --evil /private/Evil --output /private/spatial-dsp-module-abi.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

**Zadanie następcze:** analiza prawdziwego obiektu pod `[this,#0x40]` i jego `vtable+0x54` oraz znalezienie aktualnego wywołania algorytmu SESP przetwarzającego próbki. Nie wykonywać patcha firmware ani testu fizycznego Core przed dowodem ABI i planem przywrócenia.
