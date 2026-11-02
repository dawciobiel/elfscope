# Strukturalne błędy i podsumowanie JSONL

Nowe opcje są opcjonalne i wymagają --json:

    cargo run -- --json --json-errors --json-stats --quiet . > /tmp/elfscope-events.jsonl

Bez nich domyślny eksport nadal emituje wyłącznie rekordy kind=elf.
Z --json-errors pojawiają się też rekordy kind=error.
Z --json-stats na końcu pojawia się jeden rekord kind=scan_summary.
Każda linia jest niezależnym obiektem JSON, schema_version=1.
To rozszerzenie strumienia przez jawnie włączane rodzaje rekordów, nie zmiana
znaczenia pól dotychczasowego rekordu ELF.

## Błędy

Rekord zawiera path, path_bytes_hex, error.category i error.message.
Kategorie bazują na io::ErrorKind, nie analizie tekstu komunikatu:
not_found, permission_denied, invalid_data, unexpected_eof,
unsupported_or_limit, invalid_input, io_error.
Unsupported nie rozróżnia jeszcze niezrealizowanej funkcji i limitu zasobów.
Nie należy z kategorii unsupported_or_limit wnioskować, że plik jest uszkodzony.
Błędy nadal są wypisywane także na stderr, nawet z --quiet.
Wiele błędów w jednym katalogu może dać kilka rekordów z tą samą ścieżką.

## Podsumowanie

Zawiera program_version, root, root_bytes_hex, elapsed_ms, counts,
configuration (w tym efektywne limity relokacji), had_errors, status i scope_limited.
status=finished oznacza zakończenie przejścia według zadanej konfiguracji,
a nie dowód pełnego przeskanowania całego dysku ani poprawności wszystkich plików.
status=stopped_at_file_limit oznacza kontrolowane przerwanie po napotkaniu
kolejnego zwykłego pliku ponad --max-files.
had_errors jest osobne, więc zakończenie przejścia i błędy nie są mylone.
scope_limited wskazuje skonfigurowany limit głębokości, wykluczenia lub
rzeczywiste przerwanie po limicie plików. Samo podanie --max-files, gdy limit
nie został osiągnięty, nie ustawia tego pola.
elapsed_ms mierzy czas skanowania i emisji jego rekordów, bez wypisywania
końcowego podsumowania i końcowych liczników stderr.
Wykluczone poddrzewo jest liczone jako jeden wykluczony wpis, a nie wszystkie
znajdujące się w nim pliki. Program nie enumeruje pominiętego poddrzewa.

Podsumowanie jest emitowane także po błędach plików i dla pustego katalogu.
Nie jest gwarantowane po awarii procesu, przerwaniu, błędzie konfiguracji lub
błędzie zapisu na stdout. Brak podsumowania nie dowodzi więc jednego konkretnego
powodu niepowodzenia. Zamknięty potok pozostaje obsługiwany jak wcześniej.
Kod zakończenia nie jest zastępowany rekordem podsumowania: sprawdzaj oba.

## Przykłady jq (jeżeli zainstalowany)

    jq 'select(.kind == "error")' /tmp/elfscope-events.jsonl
    jq 'select(.kind == "scan_summary")' /tmp/elfscope-events.jsonl
    jq -r 'select(.kind == "elf") | .path' /tmp/elfscope-events.jsonl
    jq -r 'select(.kind == "error") | [.error.category, .path, .error.message] | @tsv' /tmp/elfscope-events.jsonl

Włączając dodatkowe rekordy, filtruj po kind zamiast zakładać, że każda linia
zawiera header, dynamic lub build_ids.

Nie dodano modyfikowania plików, uruchamiania programów ani ładowania bibliotek.
Nie zmieniono budżetów parserów ani zakresu ich walidacji.
