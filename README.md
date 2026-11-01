# elfscope

Edukacyjny skaner i analizator plików ELF napisany w Rust.

Projekt służy do poznawania budowy plików binarnych, relacji między
ich strukturami oraz informacji wykorzystywanych podczas ładowania
i linkowania programów.

Narzędzie analizuje pliki tylko do odczytu. Nie uruchamia analizowanych
programów, nie ładuje ich bibliotek i nie stosuje relokacji.

## Wymagania

- Rust i Cargo.
- Linux dla obecnego zestawu testów integracyjnych.
- Opcjonalnie narzędzie `readelf` do porównywania wyników.
- Komponenty `rustfmt` i `clippy` do sprawdzania kodu.

Instalacja komponentów:

```bash
rustup component add rustfmt clippy
```

## Budowanie

Wersja deweloperska:

```bash
cargo build
```

Wersja zoptymalizowana:

```bash
cargo build --locked --release
```

## Użycie

Pełny raport pojedynczego pliku:

```bash
cargo run -- target/debug/elfscope
```

Skanowanie katalogu:

```bash
cargo run -- ./katalog
```

Skrócony raport — jedna linia dla każdego przeanalizowanego ELF-a:

```bash
cargo run -- --summary ./katalog
```

Pomoc:

```bash
cargo run -- --help
```

Ścieżka zaczynająca się od znaku `-`:

```bash
cargo run -- --summary -- ./-przyklad
```

Separator `--` kończy rozpoznawanie opcji programu. Przykład z nazwą,
która sama wygląda jak opcja:

```bash
cargo run -- --summary -- --przyklad
```

Uruchomienie zbudowanej wersji release:

```bash
./target/release/elfscope --summary ./katalog
```

## Wyjście programu

- Raporty analizowanych plików trafiają do `stdout`.
- Błędy i końcowe liczniki trafiają do `stderr`.
- Pliki nierozpoznane jako ELF nie otrzymują raportu.
- Napotkane dowiązania symboliczne i pliki specjalne są pomijane.

Zapis raportów do pliku:

```bash
./target/release/elfscope --summary ./katalog > /tmp/elfscope-report.txt
```

Zapis raportów i diagnostyki oddzielnie:

```bash
./target/release/elfscope --summary ./katalog \
  > /tmp/elfscope-report.txt \
  2> /tmp/elfscope-diagnostics.txt
```

Tryb `--summary` skraca prezentację, ale nadal wykonuje całą
zaimplementowaną analizę pliku.

## Kody zakończenia

| Kod | Znaczenie |
|---|---|
| 0 | Skanowanie bez zgłoszonych błędów albo wyświetlenie pomocy |
| 1 | Co najmniej jeden błąd dostępu, odczytu lub analizy |
| 2 | Nieprawidłowe argumenty |

Kod 0 nie oznacza pełnego potwierdzenia poprawności ani bezpieczeństwa
analizowanych plików.

## Obsługiwane elementy ELF

### Identyfikator i nagłówek

- Sygnatura ELF.
- ELF32 i ELF64.
- Little-endian i big-endian.
- Typ pliku i numer architektury.
- Punkt wejścia.
- Położenie, rozmiary i surowe liczniki tabel.
- Wybrane nazwy architektur i typów plików.

### Nagłówki programu

- Odczyt wpisów tabeli programu.
- Typy, flagi, adresy, offsety, rozmiary i wyrównanie.
- Kontrola zakresów danych.
- Wybrane kontrole segmentów `PT_LOAD`.
- Rozszerzona liczba wpisów przez `PN_XNUM`.

### Sekcje

- Odczyt nagłówków sekcji.
- Nazwy przez powiązaną tabelę napisów.
- Rozróżnianie sekcji mających dane w pliku i `SHT_NOBITS`.
- Rozszerzona liczba sekcji.
- Rozszerzony indeks tabeli nazw sekcji.

### Relacje sekcji i segmentów

- Mapowanie niepustych sekcji `SHF_ALLOC` do `PT_LOAD` i `PT_TLS`.
- Specjalne traktowanie zerowanych danych TLS.
- Ustalenie segmentów zawierających punkt wejścia.
- Przeliczenie punktu wejścia na offset pliku, jeżeli ma obraz na dysku.

### Interpreter i informacje dynamiczne

- Ścieżka interpretera przez `PT_INTERP`.
- Tablica informacji dynamicznych przez `PT_DYNAMIC`.
- Bezpośrednie zależności `DT_NEEDED`.
- `DT_SONAME`, `DT_RPATH` i `DT_RUNPATH`.
- Przeliczenie adresu `DT_STRTAB` na offset przez `PT_LOAD`.

### Symbole

- Tablice `SHT_SYMTAB` i `SHT_DYNSYM`.
- Statystyki typów i wiązań symboli.
- Nazwy przez `sh_link` i `st_name`.
- Wartości, rozmiary i widoczność w podglądzie.
- Rozszerzone indeksy sekcji przez `SHT_SYMTAB_SHNDX`.

Podgląd obejmuje pierwsze 20 nazwanych symboli każdej tablicy.
Nazwa w podglądzie jest ograniczona do 256 bajtów.

### Relokacje

- Rekordy `REL` i `RELA`.
- Surowe `r_offset` i `r_info`.
- Podpisany jawny addend w `RELA`.
- Powiązanie sekcji relokacji z tablicą symboli.
- Powiązanie z sekcją docelową, jeśli wskazuje ją `sh_info`.
- Dekodowanie i kontrola indeksów symboli dla i386 i x86-64.
- Nazwy symboli w podglądzie relokacji.
- Wybrane nazwy typów relokacji i386 i x86-64.

Podgląd obejmuje pierwsze 10 rekordów każdej tablicy.

## Ograniczenia

Projekt jest analizatorem edukacyjnym, nie pełnym walidatorem ELF
ani narzędziem potwierdzającym bezpieczeństwo programu.

W szczególności:

- Nie modyfikuje plików.
- Nie uruchamia analizowanych plików ani wskazanego interpretera.
- Nie stosuje relokacji i nie sprawdza wszystkich ich warunków.
- Nie wyszukuje definicji symboli w bibliotekach.
- Nie odtwarza pełnego działania dynamicznego linkera.
- Nie rozwija `$ORIGIN` ani innych tokenów ścieżek.
- Nie demangluje nazw Rusta ani C++.
- Nie interpretuje wersjonowania symboli.
- Nie obsługuje spakowanych relokacji `RELR`.
- Analiza symboli i relokacji opiera się na tabeli sekcji.
- Mapowanie sekcji obejmuje tylko wybrane przypadki `LOAD` i `TLS`.
- Nie wszystkie flagi i typy mają opisy tekstowe.
- Nieznana nazwa typu nie oznacza automatycznie uszkodzenia pliku.
- Część surowych pól nagłówka może zawierać znaczniki rozszerzonej
  numeracji, mimo że parser odczytał już rzeczywiste wartości.
- Zawartość pliku może zmienić się podczas analizy.
- Pomijanie dowiązań symbolicznych nie stanowi ochrony przed
  wyścigami podczas operacji na systemie plików.

Ścieżki wejściowe nie muszą być poprawnym UTF-8.
Nazwy odczytane z ELF-a są przechowywane jako bajty, ale ich prezentacja
może stosować konwersję stratną do UTF-8.

## Limity zasobów

Program stosuje jawne limity chroniące przed nieograniczonym
przetwarzaniem danych z nagłówków.

Przykładowe limity:

- 262 144 nagłówki programu.
- 262 144 nagłówki sekcji.
- 1 000 000 symboli łącznie w pliku.
- 128 tablic symboli.
- 1 000 000 relokacji łącznie w pliku.
- 128 tablic relokacji.
- 16 MiB dla obsługiwanych tabel napisów.
- 16 MiB danych `PT_DYNAMIC`.
- 4096 wpisów `DT_NEEDED`.
- 4096 bajtów danych `PT_INTERP`.

Nie jest to kompletny budżet pamięci ani czasu wykonania.
Dokładne kontrole i dodatkowe limity znajdują się w kodzie parserów.

Plik przekraczający limit narzędzia może być poprawnym ELF-em.

## Struktura kodu

```text
src/
├── main.rs
├── cli.rs
├── inspection.rs
├── report.rs
├── report/
│   └── relocation_types.rs
├── elf.rs
├── sections.rs
├── mapping.rs
├── interpreter.rs
├── dynamic.rs
├── symbols.rs
└── relocations.rs
```

- `main.rs` — uruchomienie, przechodzenie po katalogach i liczniki.
- `cli.rs` — argumenty i pomoc.
- `inspection.rs` — zebranie wyników analizy pojedynczego pliku.
- `report.rs` — raport szczegółowy i skrócony.
- Pozostałe moduły — odczyt i interpretacja struktur ELF.

## Sprawdzanie projektu

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features
cargo test --locked --all-targets --all-features
cargo build --locked --release
```

Testy obejmują parsery oraz uruchamianie gotowego programu
na syntetycznych plikach ELF.

Przykładowe uruchomienia wybranych testów integracyjnych:

```bash
cargo test --test cli
cargo test --test extended_numbering
cargo test --test header_report
cargo test --test symbol_report
cargo test --test relocation_report
```

Testy nie uruchamiają wygenerowanych plików ELF jako programów.

## Porównywanie z readelf

```bash
readelf -h ./plik
readelf -lW ./plik
readelf -SW ./plik
readelf -dW ./plik
readelf -sW ./plik
readelf -rW ./plik
```

Porównuj struktury tego samego pliku z tej samej kompilacji.
Adresy, rozmiary, indeksy i liczby wpisów mogą zmieniać się
po przebudowaniu programu.

## CI

Konfiguracja GitHub Actions znajduje się w:

```text
.github/workflows/ci.yml
```

Workflow sprawdza formatowanie, kompilację, Clippy, testy
oraz możliwość zbudowania wersji release.

Zielony wynik CI potwierdza przejście tych kontroli.
Nie dowodzi poprawności parsera dla wszystkich możliwych danych.
