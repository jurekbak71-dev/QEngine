# HeadRush Core 5.2.0 — potwierdzone łańcuchy wywołań wrapper → obiekt wewnętrzny

**Data badania: 20.11.2026.** Kontynuacja prac nad uruchamianiem **własnych efektów** (AIR Delay, Shimmer, Multi Chorus) w oryginalnym kodzie DSP. Analiza *tylko do odczytu* na oryginalnym `/usr/Evil/Evil` ARM32; ELF SHA-256: `1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631`.

## Wynik: 51 potwierdzonych łańcuchów LDR

Na rzeczywistym ELF potwierdzono **17 indeksów metod** głównej vtable na każdy z **3** wrapperów `DSPModule`. Każdy kod zawiera w krótkim regionie A32 sekwencję:

1. `LDR rA,[r0,#0x40]` albo `LDR rA,[r0,#0x4C]`, odczyt wskaźnika obiektu przez wrapper;
2. `LDR rB,[rA]`, odczyt vptr obiektu;
3. `LDR rC,[rB,#offset]`, odczyt funkcji ze wskazanej vtable.

Skrypt odczytuje wszystkie trzy adresy rzeczywistych instrukcji i stosowane rejestry, weryfikuje zgodność SHA-256 oraz to, że adresy metod wrapperów pochodzą z wykonywalnej sekcji oryginalnego ELF.

| Slot wrappera | Pole wrappera | Offset vtable obiektu | Indeks metody obiektu |
|---:|---|---|---:|
| 3 | `+0x40` | `+0x0C` | 3 |
| 5 | `+0x40` | `+0x14` | 5 |
| 7 | `+0x40` | `+0x1C` | 7 |
| 10 | `+0x40` | `+0x28` | 10 |
| 11 | `+0x40` | `+0x2C` | 11 |
| 12 | `+0x40` | `+0x30` | 12 |
| 13 | `+0x40` | `+0x34` | 13 |
| 14 | `+0x40` | `+0x38` | 14 |
| 15 | `+0x40` | `+0x3C` | 15 |
| 16 | `+0x40` | `+0x40` | 16 |
| 17 | `+0x40` | `+0x44` | 17 |
| 18 | `+0x40` | `+0x48` | 18 |
| 21 | `+0x40` | `+0x54` | 21 |
| 25 | `+0x4C` | `+0x60` | 24 |
| 27 | `+0x40` | `+0x6C` | 27 |
| 28 | `+0x40` | `+0x70` | 28 |
| 30 | `+0x4C` | `+0x70` | 28 |

**Interpretacja:** 15 z 17 sprawdzonych pozycji odczytuje metodę obiektu spod wrapper+`0x40`; dwie — spod wrapper+`0x4C`. To daje **dwa odrębne pola obiektów**, na których skupia się potencjalna kompatybilna integracja.

**Granice dowodu:** odkryte instrukcje **ładują** wskaźnik metody. Nie każda droga musi wywołać tę metodę przy każdym wykonaniu (slot 18 zawiera m.in. porównanie z metodą znaną w kodzie i szybką ścieżkę). Nazwy klas i typy obiektów spod `+0x40`/`+0x4C` oraz sygnatury metod nadal pozostają NIEZWERYFIKOWANE. Osiągnięcie obiektu wewnętrznego nie dowodzi, że jest to callback przetwarzania próbek.

## Równoległe, potwierdzone punkty wejścia do host audio

W rzeczywistym ELF, na podstawie `.rel.plt` i bezpośrednich instrukcji ARM `BL`, odzyskano między innymi:

- `0x0129BD04` → wpis PLT `snd_pcm_writei` (`0x00161830`);
- `0x0129BE64` → wpis PLT `snd_pcm_readi` (`0x00161848`);
- `0x0129BFA8` → wpis PLT `snd_pcm_readn` (`0x00161854`);
- `0x0129C16C` → wpis PLT `snd_pcm_writen` (`0x00161860`).

**NIEZWERYFIKOWANE:** czy te konkretne funkcje ALSA odpowiadają aktywnemu w danym trybie torowi gitarowemu HeadRush Core, i czy prowadzą do któregoś z trzech badanych efektów. Aby ustalić sygnaturę procesora sygnału, trzeba prześledzić wywołania *od strony I/O audio* oraz identyfikację rzeczywistego obiektu spod wrapper+`0x40`.

## Powtarzalny kod i testy

- [probe_module_inner_dispatch.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/probe_module_inner_dispatch.py)
- [test_probe_module_inner_dispatch.py](https://github.com/jurekbak71-dev/QEngine/blob/headrush-core-520-lab/tools/headrush/test_probe_module_inner_dispatch.py)
- [GitHub Actions 44687058058](https://github.com/jurekbak71-dev/QEngine/actions/runs/44687058058) — **202/202 PASS**, w tym 10 nowych testów syntetycznych.

```bash
python3 tools/headrush/probe_module_inner_dispatch.py \
  --evil /private/Evil --output /private/inner-vtable-dispatch.json
python3 -m unittest discover -s tools/headrush -p 'test_*.py' -v
```

Lokalnie uruchomiono skan na oryginalnym ELF o zweryfikowanej sumie SHA-256: **51/51 oczekiwanych łańcuchów sprawdzonych**. 10/10 testów sztucznego ELF PASS; GitHub Actions potwierdził 202/202 PASS.

## Wniosek dla własnych efektów

Na obecnym etapie **nie należy dopisywać nowego indeksu do fabryki** ani zakładać, że wystarczy plik `.so`. Konstruktor wrappera wybiera konkretny wbudowany typ, a wrapper następnie używa wskaźników do obiektów wewnętrznych i ich vtable. Ewentualna eksperymentalna podmiana w **odizolowanej kopii QEMU** wymaga poznania rzeczywistego typu obiektu pod `+0x40`, struktury metod, punktu wykonywania DSP i destruktora oraz zachowania interfejsu kontrolera/presetów.

**Nie wykonano:** modyfikacji oryginalnego ELF ani fizycznego Core, implementacji własnego efektu, odsłuchu, ładowania własnej biblioteki czy testu odzyskiwania firmware. To analiza, nie działający loader.

**Następny etap:** skorelować wywołanie właściwej wirtualnej metody obiektu pod `+0x40` z działającym audio callbackiem; rozpatrzyć pozostałe metody wrappera niebędące prostymi łańcuchami LDR, żeby nie pomylić kontrolek/serializacji z przetwarzaniem DSP.
