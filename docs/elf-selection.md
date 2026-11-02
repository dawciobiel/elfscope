# Wczesna selekcja ELF i limit rozmiaru

Nowe opcje:

    --elf-type none|rel|exec|dyn|core
    --class 32|64
    --machine i386|x86_64|arm|aarch64|riscv|NUMER
    --max-size BYTES

Typy i architektury można podawać wielokrotnie. W obrębie jednego wymiaru
obowiązuje OR. Pomiędzy wymiarami jest AND. Brak filtra wymiaru oznacza
akceptowanie wszystkich wartości. Numer architektury jest dziesiętnym u16.
Nazwy są rozpoznawane dokładnie, małymi literami.
--class może mieć jedną wartość; sprzeczne deklaracje są błędem argumentów.
--max-size wymaga dodatniej liczby bajtów bez sufiksów K/M/G.
Rozmiar równy limitowi jest dozwolony.

Przykład EXEC i DYN x86-64, z diagnostyką JSONL:

    cargo run -- --json --json-errors --json-stats --quiet --elf-type exec --elf-type dyn --class 64 --machine x86_64 . > /tmp/elfscope-selected.jsonl

DYN nie oznacza wyłącznie programu PIE. Obejmuje również biblioteki
współdzielone. Nie dodano rozpoznawania 'czy ten DYN jest na pewno programem'.
Sam EXEC nie obejmuje typowych programów PIE. Nie filtrujemy po rozszerzeniu.

Kolejność operacji:

1. Wykluczenia nazw i rozpoznanie rodzaju wpisu.
2. Kontrola limitu liczby zwykłych plików.
3. Zwiększenie licznika regular_files_attempted.
4. Kontrola rozmiaru według metadanych.
5. Otwarcie pliku i odczyt/walidacja obsługiwanego głównego nagłówka.
6. Filtry typu, klasy i architektury.
7. Dalsza analiza tabel i zawartości tylko dla pasujących nagłówków.

Niepasujący ELF nie jest błędem i nie emituje rekordu elf/error.
Pominięcie przez rozmiar również nie jest błędem.
Obie sytuacje zużywają --max-files: liczymy rozpatrzone zwykłe pliki,
nie tylko wyemitowane ELF-y. Podsumowanie zawiera oddzielne liczniki:
filtered_elf_files i size_limited_files.
size_limited_files nie oznacza liczby ELF-ów: tych plików nie otwieramy,
więc ich formatu nie ustalamy.

Niepasujący ELF nie jest w pełni zwalidowany. Ewentualne uszkodzenia jego
tabel nie są wtedy wykrywane. Wadliwy główny nagłówek nadal może dać błąd,
zanim będziemy mogli zastosować filtry. Selekcja nie oznacza pełnego audytu
wszystkich napotkanych plików.

Filtry działają we wszystkich formatach: szczegółowym, --summary,
--json i --paths. Zwykły rekord ELF zachowuje poprzedni format.
Końcowy scan_summary ma dodatkowe pola konfiguracji oraz liczniki;
scope_limited uwzględnia filtry i max-size.

Metadane nie są snapshotem. Rozmiar może zmienić się po ich odczycie.
Główny nagłówek jest odczytywany do selekcji i ponownie przez istniejący
pełny parser na tym samym otwartym pliku. Nie otwieramy ponownie ścieżki,
ale nie blokujemy równoległego zapisu i nie gwarantujemy niezmienności danych.
--max-size nie jest budżetem pamięci ani czasu parsera.

Nie dodano modyfikowania ELF-ów ani uruchamiania ich kodu.
