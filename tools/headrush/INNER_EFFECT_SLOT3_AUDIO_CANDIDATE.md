# HeadRush Core 5.2.0 — ślad wrapper → kandydat toru audio (slot 3)

**Data analizy: 20.11.2026.** Źródło: wyłącznie oryginalny `/usr/Evil/Evil`, ARM32 ELF (HeadRush Core 5.2.0), wyodrębniony z instalatora użytkownika. SHA-256 `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`. Analiza wyłącznie do odczytu, bez modyfikowania firmware lub urządzenia.

## Cel

Po wcześniejszym ustaleniu, że `DSPModule<Effect,Controller,DSPSerializer>` przechowuje właściwy efekt pod `this+0x40` i kontroler pod `this+0x4C`, należało odnaleźć bardziej prawdopodobny punkt przetwarzania próbek. Zamiast zgadywać znaczenie metody 20 (alokacja) i 21 (pobranie stanu), przeanalizowano **rzeczywiste tablice metod klas `EvilDSPs::AIRDelay`, `EvilDSPs::Shimmer` i `EvilDSPs::MultiChorus`**.

## 1. Potwierdzone tablice metod wewnętrznych efektów

| Efekt | Adres `vptr` efektu | Liczba kolejnych wskaźników do kodu | Pierwszy niekodowy wpis |
|---|---|---:|---|
| AIR Delay | `0x02EB3880` | **36** | `0x02EB397C` |
| Shimmer | `0x02EB5F7C` | **36** | `0x02EB6078` |
| Multi Chorus | `0x02EB45BC` | **36** | `0x02EB46B8` |

Sprawdzono `vptr[-2]=0`, wskaźnik `typeinfo` pod `vptr[-1]` i pełną nazwę RTTI właściwej klasy. Porównanie **wszystkich 36 pozycji** wykazało **30 takich samych wskaźników funkcji** w trzech efektach. Jedynie **sześć indeksów: `0, 1, 3, 7, 32, 33`** ma osobne funkcje dla trzech efektów.

To silna przesłanka, że mechanizm cyklu życia, stanu i części obsługi parametrów jest współdzielony, natomiast funkcje specyficzne dla algorytmu występują pod sześcioma indeksami. **Nie wszystkie te sześć funkcji musi przetwarzać audio** (np. metody 0/1 mogą dotyczyć destrukcji, ale nie jest to w tym raporcie dowiedzione).

## 2. Potwierdzony skok z metody wrappera nr 3 do metody efektu nr 3

Każdy wrapper ma pod indeksem 3 następujący, **bitowo identyczny ciąg 7 instrukcji ARM A32**:

```asm
ldr r0, [r0, #0x40]  ; DSPModule → wewnętrzny obiekt efektu
str lr, [sp, #-4]!
ldr r12, [r0]        ; vptr obiektu efektu
ldr lr, [r12, #0x0C] ; wewnętrzna metoda indeks 3
mov r12, lr
ldr lr, [sp], #4
bx r12               ; skok do właściwej, specyficznej metody
```

| Efekt | Wejście w wrapperze (slot 3) | Docelowy wskaźnik metody efektu (slot 3) |
|---|---|---|
| AIR Delay | `0x0095EC40` | `0x0099CA50` |
| Shimmer | `0x00935AB0` | `0x00977CA8` |
| Multi Chorus | `0x0095E0C0` | `0x00991CE8` |

**POTWIERDZONE:** kod wrappera nie tworzy kolejnego efektu, lecz wykonuje **skok `BX r12` do adresu z `vptr+0x0C`** wewnętrznego obiektu. Zachowuje rejestry argumentów poza zastąpieniem `r0` adresem obiektu efektu. Nie udowodniono jeszcze, gdzie i kiedy silnik audio wywołuje metodę numer 3 wrappera.

## 3. Co w rzeczywistości zawierają metody efektu nr 3

| Efekt | Wejście | Następny wpis `.ARM.exidx` | Rozpiętość regionu EHABI |
|---|---|---|---:|
| AIR Delay | `0x0099CA50` | `0x0099E638` | **7144 B** |
| Shimmer | `0x00977CA8` | `0x00978A98` | **3568 B** |
| Multi Chorus | `0x00991CE8` | `0x00992C30` | **3912 B** |

Wszystkie trzy początki **dokładnie odpowiadają wpisowi `.ARM.exidx`**; nie zakłada się jednak, że każdy czterobajtowy element tego regionu jest instrukcją (wewnątrz mogą występować pule stałych).

Na każdym z trzech regionów kodu sprawdzono oryginalne instrukcje:

| Dowód | AIR Delay | Shimmer | Multi Chorus |
|---|---|---|---|
| `ldrb r3,[r0,#0xB6C]` | `0x0099CA9C` | `0x00977CF4` | `0x00991D34` |
| `vld1.32 {d20,d21},[r0]` | `0x0099D350` | `0x009785B8` | `0x00992684` |
| `vst1.32 {d16,d17},[r0]!` | `0x0099D35C` | `0x009785C4` | `0x00992690` |
| `vmul.f32 s14,s15,s14` | `0x0099CC30` | `0x00977E88` | `0x00991EBC` |

Wszystkie trzy metody odwołują się również bezpośrednimi instrukcjami ARM `BL` do tych samych adresów:

- `0x01538A80`
- `0x00C2A6E4`
- `0x00C198CC`

Adresy obliczono ze znakiem 24-bitowego offsetu i `PC+8`, niezależnie dla każdego z trzech kodów.

**Interpretacja — PRAWDOPODOBNE:** metoda efektu nr 3 wykonuje rzeczywiste operacje na buforach sygnałowych i jest **najsilniejszym dotąd kandydatem na część toru audio**. Przemawiają za tym dedykowane wersje metody, arytmetyka `VMUL.F32`, wektorowe odczyty/zapisy `VLD1/VST1` oraz odczyt flagi stanu `+0xB6C`. Sam zestaw instrukcji nie wystarcza jednak do potwierdzenia deklaracji `processAudio()`, argumentów funkcji, liczby kanałów czy rodzaju próbek.

**NIEZWERYFIKOWANE:** czy metoda nr 3 jest wywoływana z aktywnej pętli ALSA w konkretnym trybie urządzenia; który z wywoływanych podprogramów stanowi adapter SESP; czy do metody trafia interleaved/non-interleaved float audio, jakie są rozmiary bloków; ABI wstawienia własnego kodu; możliwość ładowania nowego `.so`.

## 4. Kod i testy

- [probe_inner_audio_candidate.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/probe_inner_audio_candidate.py)
- [test_probe_inner_audio_candidate.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_probe_inner_audio_candidate.py)
- [GitHub Actions 44707405145](https://github.com/jurekbak71-dev/QEngine/actions/runs/44707405145): **234/234 PASS** po commitach kodu i 17 nowych testów.

```bash
python3 tools/headrush/probe_inner_audio_candidate.py \
  --evil /private/Evil --out /private/inner-audio-candidate.json

python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Weryfikator kontroluje SHA-256 oryginalnego ELF, pełne RTTI i liczbę metod, siedmioinstrukcyjny skok wrappera, dokładne granice `.ARM.exidx`, cztery zakotwiczone opkody metody nr 3 i trzy cele bezpośrednich `BL`. Odmawia potwierdzenia, gdy adres, kod instrukcji lub ich wspólny układ zostaną zmienione. **17 nowych testów syntetycznych** sprawdza również błędy sekcji ELF, niepoprawny target, zły rozmiar tablicy i zmiany instrukcji NEON.

Przy przygotowywaniu sztucznego ELF początkowo wystąpiły błędy nakładających się nazw sekcji (`.data.rel.ro` / `.data.rel.ro.local`) oraz niezależnych celów wywołań `BL`. Naprawiono próbkę i podano cele testów jawnie, **bez obniżenia rygoru walidacji oryginalnego ELF**. Po poprawkach lokalne **17/17 PASS**, a analiza oryginalnego `Evil` zakończyła się sukcesem. Pełny zestaw GitHub Actions **234/234 PASS**.

## 5. Następny krok w kierunku własnych efektów

**Nie zastępować jeszcze metody nr 3 własnym kodem na fizycznym Core.** Najpierw trzeba znaleźć:

1. Rzeczywiste wywołanie metody `DSPModule::slot3` z pętli audio, z prześledzeniem parametrów przekazywanych do `r1/r2/r3` i na stosie.
2. Bezpośrednią relację metody wewnętrznej do adaptera `SESP::Effect::Delay::AIRDelay`, `Reverb::Shimmer` i `Modulation::ChorusMulti`.
3. Zgodny model zarządzania pamięcią i bezpieczny mechanizm podstawiania własnego kodu w odizolowanym QEMU, zanim rozważy się modyfikację firmware na urządzeniu.

**NIEWYKONANE:** host własnych efektów, ładowanie `.so`, działający nowy DSP w QEMU/HeadRush Core, odsłuch, pomiary opóźnienia, bezpieczny rollback.
