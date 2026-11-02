# Limity relokacji po naprawie obsługi plików .o

Poprzedni limit 128 tablic był ograniczeniem programu, nie ELF-a.
Nowa wartość domyślna to 4096 tablic na jeden analizowany plik.

| Zmienna środowiskowa | Domyślnie | Znaczenie |
|---|---:|---|
| ELFSCOPE_MAX_RELOCATION_TABLES | 4096 | Liczba sekcji REL/RELA w jednym pliku |
| ELFSCOPE_MAX_RELOCATIONS | 1000000 | Łączna liczba rekordów REL/RELA w jednym pliku |
| ELFSCOPE_MAX_RELOCATION_PREVIEWS | 1000 | Łączna liczba rekordów zachowanych w podglądach jednego pliku |

Pierwsze dwa limity muszą być dodatnie. Limit podglądów może wynosić 0.
Nadal zachowujemy najwyżej 10 rekordów z jednej tablicy.
Budżet globalny jest zużywany w kolejności sekcji i rekordów.
Po jego wyczerpaniu dalsze tablice mają statystyki, ale pusty podgląd.
Nie oznacza to pominięcia odczytu lub walidacji pozostałych rekordów.
Raport tekstowy nadal używa etykiety 'maksymalnie 10' dla pojedynczej tablicy;
nie dodano nowego pola informującego osobno o wyczerpaniu budżetu.
JSON Lines zachowuje poprzedni schemat i komplet statystyk tablic.

Przykład większych budżetów, w składni działającej również przez fish:

    env ELFSCOPE_MAX_RELOCATION_TABLES=16384 ELFSCOPE_MAX_RELOCATIONS=2000000 ELFSCOPE_MAX_RELOCATION_PREVIEWS=200 cargo run -- --json --quiet . > /tmp/elfscope.jsonl

Zmienne są odczytywane raz przy uruchomieniu skanowania.
Nieprawidłowa konfiguracja powoduje kod 2 przed analizą plików.
Przekroczenie poprawnie skonfigurowanego limitu w konkretnym pliku powoduje
błąd analizy tego pliku i końcowy kod 1; skaner kontynuuje pozostałe pliki.
Pomoc i --version nie wymagają poprawnej konfiguracji limitów.

Pamięć podręczna tabel nazw symboli relokacji:

- klucz: indeks sekcji STRTAB, nie nazwa sekcji;
- osobna pamięć dla każdego analizowanego pliku;
- budżet 32 MiB danych w zachowanych wpisach;
- maksymalnie 16 MiB dla pojedynczej tabeli;
- usuwanie najstarszych załadowanych wpisów (FIFO), nie LRU;
- ponowny odczyt po usunięciu wpisu z pamięci jest dozwolony.

Budżet 32 MiB dotyczy danych zachowanych w cache, nie całego RSS procesu.
Podczas ładowania nowego wpisu może jednocześnie istnieć bufor nowej tabeli,
a więc całkowita pamięć procesu i chwilowy koszt tej operacji są większe.
Cache nie jest wspólny z parserem symboli w symbols.rs.
Może więc pozostać jeden odczyt w parserze symboli i jeden w parserze relokacji.
Nie są wykonywane wielokrotne pełne odczyty tej samej tabeli dla każdej
sekcji relokacji, o ile wpis pozostaje w cache.

Nie zmieniono pozostałych limitów parserów ani obsługiwanych ABI.
Walidacja indeksów r_info nadal dotyczy i386/ELF32 i x86-64/ELF64.
Nie stosujemy relokacji, nie zapisujemy ELF-ów, nie uruchamiamy ich.
Plik może być poprawnym ELF-em, mimo że przekracza skonfigurowany budżet.
