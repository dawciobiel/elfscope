# Statyczna analiza ścieżek dynamicznych

Model jest jawnie oznaczony jako linux_glibc_static. To nie jest uniwersalny
emulator loaderów wszystkich systemów ELF. Nie otwieramy bibliotek,
nie czytamy cache ani LD_LIBRARY_PATH i nie wykonujemy analizowanych plików.

Przy obecnym DT_RUNPATH własny DT_RPATH jest oznaczany jako pomijany.
Dotyczy to także obecnego, ale pustego RUNPATH. selected_tag oznacza
pierwszeństwo tagu z tego obiektu, nie pełną ścieżkę wyszukiwania loadera.
RUNPATH służy bezpośrednim zależnościom obiektu; nie symulujemy dziedziczenia
RPATH, grafu zależności ani secure-execution.

Listy RPATH/RUNPATH dzielimy dwukropkiem, nie średnikiem. Nie kopiujemy tu
reguły separatorów LD_LIBRARY_PATH, która w glibc jest inna.
Cały pusty napis jest ignorowany jako lista (zero elementów).
Puste elementy niepustej listy, np. :/lib:, zachowujemy oddzielnie; w zwykłym
przetwarzaniu glibc wskazują katalog bieżący. Katalog bieżący nie oznacza
katalogu analizowanego ELF-a.

Formy elementów: empty_component, absolute_literal, relative_literal, tokenized.
Tokeny rozpoznajemy leksykalnie: $ORIGIN, $LIB, $PLATFORM oraz warianty ${...}.
Nie rozwijamy ich do wartości. $ORIGINAL nie jest $ORIGIN.
Nierozpoznane '$' jest osobnym sygnałem, nie błędem parsera ELF.
Element z rozpoznanym tokenem jest tokenized nawet przy początkowym '/'.
Komponent '..' wykrywamy jako cały komponent, bez normalizacji ścieżki.

DT_NEEDED dzielimy na search_name, absolute_path, relative_path, tokenized.
Nie dzielimy DT_NEEDED dwukropkiem. Dla tokenized nie przewidujemy postaci
nazwy po rozwinięciu. Nie ustalamy, czy wskazana biblioteka istnieje.
Nie oceniamy praw zapisu katalogów ani nie nadajemy werdyktu 'bezpieczny'.

Nowe dane JSON są pod dynamic.search_paths. Stare surowe rpath/runpath/needed
pozostają bez zmian. Brak tagu to null, jawnie pusty tag to obecny obiekt
z explicitly_empty=true i zerową liczbą elementów.
Liczniki obejmują wszystkie elementy; podgląd najwyżej 32 elementy po 256 bajtów.
value_preview zawiera byte_length, truncated, text i bytes_hex podglądu.
Nie należy mylić bytes_hex podglądu z pełną wartością, jeżeli truncated=true.
Brakujące fragmenty pełnych napisów są nadal w dotychczasowych surowych polach.

    cargo run -- target/debug/elfscope
    cargo run -- --json --quiet target/debug/elfscope
    readelf -dW target/debug/elfscope

Przykład jq:

    jq 'select(.kind == "elf") | {path, search_paths: .dynamic.search_paths}' /tmp/elfscope-events.jsonl

Analiza nie dodaje nowych błędów skanowania dla nietypowej składni ścieżek.
Pozostaje interpretacją metadanych, nie rozwiązywaniem zależności.
