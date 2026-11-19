# HeadRush Core 5.2.0 — rzeczywiste tablice kontrolerów przestrzennych

Data analizy: **19.11.2026**. Źródło: prywatny, oryginalny ARM32 ELF `/usr/Evil/Evil` wyodrębniony z firmware 5.2.0 (tylko odczyt).

SHA-256 ELF: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

Nie publikować w tym publicznym repozytorium oryginalnego firmware, binarium ani fabrycznych presetów.

## Co ustalono

Nowy skaner odzyskuje nazwę RTTI kontrolera w `.rodata`, odpowiedni obiekt typeinfo w `.data.rel.ro` oraz wskazania trzech tablic w `.data.rel.ro.local`. Potwierdza wpisy `offset_to_top` i odczytuje **wyłącznie ciągłe wskaźniki do prawidłowych adresów wykonywalnej sekcji `.text`**.

| Kontroler | Główna vtable (VA) | Pierwsza wtórna | Druga wtórna |
|---|---|---|---|
| AIRDelayController | `0x02EB3974` | `0x02EB3A14` | `0x02EB3A5C` |
| ShimmerController | `0x02EB6070` | `0x02EB6110` | `0x02EB6158` |
| MultiChorusController | `0x02EB46B0` | `0x02EB4750` | `0x02EB4798` |

W każdym z trzech przypadków wartości `offset_to_top`: **0, -44, -124**. Długości ciągłych tablic funkcji: **31, 9, 7**.

**Korekta wcześniejszej liczby:** odstęp między tablicami obejmuje także wartości, które nie są wskaźnikami kodu (np. zero, pola przesunięć). Wstępne „38 adresów” nie było liczbą metod. Rzeczywista główna tablica zawiera **31 kolejnych wskaźników do kodu**: 27 z nich jest identycznych między wszystkimi trzema kontrolerami; cztery różne pozycje (indeksy 0, 1, 25, 26) wskazują osobne implementacje.

Druga tablica: 6/9 wspólnych, różne indeksy 0,1,8. Trzecia: 5/7 wspólnych, różne indeksy 0,1. Współdzielone adresy pokazują wspólną bazę implementacyjną; różne adresy pokazują specjalizację metod. **Nie dowodzą, że któraś metoda jest callbackiem toru audio.**

## Wartościowe wejście do kodu specyficznego dla efektu

Indeks **26** głównej tablicy prowadzi do kodu zawierającego bezpośrednie odwołania ARM `LDR`+ `ADD PC` do napisów `.rodata`. Metoda przeszukiwana jest w ograniczonym oknie 0x400 bajtów od adresu początkowego.

| Efekt | Metoda VA, slot 26 | Nazwy znalezione w metodzie i w `evil.db` |
|---|---|---|
| AIR Delay | `0x00910368` | Delay, Feedback, Ratio, FdbkHighCut, FdbkResoFreq, FdbkReso, Width, LoCut, Mix |
| Shimmer | `0x0092B8BC` | Delay, Interval, ReverbTime, Mix, Tone, Width |
| Multi Chorus | `0x00926694` | Rate, Depth, Mix, Width, LoCut, PreDelay, Voices |

**Razem 22 nazwy** powiązane z metodami (9+6+7) zostały niezależnie potwierdzone jako klucze w fabrycznych rigach.

W tym oknie nie znaleziono np. `HighCut` (Shimmer) ani `LFOShape` (Multi Chorus). **Nie oznacza to, że takich parametrów w DSP nie ma** — te nazwy występują w fabrycznych presetach; mogą być obsługiwane przez inne metody albo generowane inaczej. Nie uznajemy braków prostego skanera za nieistnienie funkcji.

Dodatkowo istnieją różne metody przy indeksie **25**: Shimmer `0x009192A4`, Multi Chorus `0x00917B0C`, AIR Delay `0x00911A2C`. Ich dokładna semantyka jest NIEZWERYFIKOWANA; sam adres nie dowodzi DSP audio.

## Kod i powtarzalność

- [Skaner RTTI, tablic i ciągów znaków](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/probe_spatial_controller_vtables.py)
- [Dziewięć testów syntetycznych](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_probe_spatial_controller_vtables.py)

Przykład lokalnego uruchomienia z prywatnymi plikami:

```bash
python3 tools/headrush/probe_spatial_controller_vtables.py \
  --evil /private/Evil --db /private/evil.db \
  --out /private/controller-vtables.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Skaner nie zapisuje niczego do firmware i otwiera SQLite w trybie `mode=ro&immutable=1`.

**Testy:** 9/9 nowych testów lokalnych PASS; GitHub Actions [44537064140](https://github.com/jurekbak71-dev/QEngine/actions/runs/44537064140): **93/93 PASS** (testy kodu na syntetycznych danych, nie testy urządzenia).

## Wnioski i prace pozostające

POTWIERDZONE: konkretne tablice kontrolerów, wspólne i unikatowe wskaźniki metod, 22 bezpośrednie odwołania do kluczy występujących w fabrycznych rigach.

NIEZWERYFIKOWANE: dokładny charakter metody na indeksie 26, czy służy UI/opisowi kontrolek, serializacji czy ustawianiu parametrów algorytmu; brak dowodu rzeczywistej ścieżki parametr → DSP SESP. Nie ma potwierdzonego systemu natywnych wtyczek `.so`.

NIEWYKONANE: modyfikacja firmware, wdrożenie własnego DSP, audio-testy Core.

Dalszy najważniejszy krok: prześledzić, do jakich obiektów kierowane są wywołania metod indeksów 25 i 26; zweryfikować, czy kod ten kiedykolwiek wywołuje adapter SESP, zamiast tylko budować UI i serializować dane.