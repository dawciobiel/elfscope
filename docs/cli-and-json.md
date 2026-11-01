# Większa aktualizacja CLI i eksportu

## Instalacja

1. Rozpakuj archiwum w katalogu projektu. Podmień src/main.rs i src/cli.rs.
2. Dodaj src/scanner.rs, src/json_report.rs, tests/batch_cli.rs i ten dokument.
3. Zachowaj wszystkie inne źródła i testy.
4. Dodaj zależność, bez ręcznego przepisywania Cargo.toml:

    cargo add serde_json

Polecenie wymaga dostępu do rejestru pakietów; zmienia Cargo.toml i Cargo.lock.
Nie zastępuj manifestu wersją z innego projektu.

Następnie:

    cargo fmt --all
    cargo check --locked --all-targets
    cargo test --test batch_cli
    cargo test --locked --all-targets --all-features
    cargo build --locked --release

Nie uruchomiono kompilatora Rust ani testów podczas przygotowania archiwum.

## Nowe możliwości

    cargo run -- --version
    cargo run -- --json --quiet ./katalog
    cargo run -- --paths --null --quiet ./katalog
    cargo run -- --summary --max-depth 2 --max-files 100 ./katalog
    cargo run -- --json --exclude target --exclude .git ./projekt
    cargo run -- --summary --no-recursive ./katalog

--summary, --json i --paths są wzajemnie wykluczające się.
--null jest dozwolone tylko z --paths.
--quiet ukrywa końcowe liczniki, nie błędy.
Każdy tryb nadal wykonuje pełną zaimplementowaną analizę.

## Głębokość

Ścieżka startowa ma głębokość 0. Jej bezpośrednie dzieci mają 1.
--max-depth 0 nie otwiera zawartości katalogu startowego, ale analizuje
plik startowy, jeżeli wskazano plik.
--no-recursive to --max-depth 1: pliki bezpośrednie są analizowane,
ale podkatalogi nie są rozwijane.

## Wykluczenia

--exclude porównuje dokładną nazwę ostatniego komponentu potomnej ścieżki.
Nie obsługuje globów, wyrażeń regularnych ani wzorców ścieżek.
Opcję można powtarzać. Jawnie wskazany katalog/plik startowy nie jest
wykluczany. Wykluczenie katalogu pomija całe jego poddrzewo.
Domyślnie żadne nazwy nie są wykluczane, również target i .git.

## Kolejność i limit plików

Wpisy każdego katalogu są sortowane, a przejście jest wgłąb drzewa (DFS).
To deterministyczna kolejność przy niezmieniającej się zawartości katalogów,
nie globalne sortowanie wszystkich znalezionych plików po zakończeniu.
Sortowanie wymaga zebrania wpisów pojedynczego katalogu w pamięci.

--max-files ogranicza próby analizy zwykłych plików, nie tylko ELF-ów.
Plik nierozpoznany jako ELF lub kończący się błędem także zużywa limit.
Symlinki, pliki specjalne, katalogi i wykluczenia nie zużywają limitu.
Limit nie jest budżetem czasu ani wszystkich operacji systemu plików.
Zakończenie z powodu limitu nie jest błędem.
Znacznik przerwania pojawia się, gdy skaner napotka następny zwykły plik,
którego nie wolno już sprawdzić. Dokładnie N plików w całym drzewie przy
limicie N nie oznacza przerwania i pozostawia znacznik 'nie'.

## JSON Lines, schemat 1

--json emituje jeden kompletny obiekt JSON na linię dla każdego pomyślnie
przeanalizowanego ELF-a. To nie jest jedna tablica JSON.
Nie-ELF-y nie emitują rekordów. Błędy i liczniki trafiają na stderr.
--quiet nie ukrywa błędów. Częściowy raport JSONL może zawierać poprawne
rekordy mimo kodu zakończenia 1.

Pola:

- schema_version, kind, path, path_bytes_hex;
- header: klasa, endianowość, typ, architektura, wersje, rzeczywiste i surowe liczniki;
- interpreter: obiekt text/bytes_hex albo null;
- dynamic: needed, soname, rpath, runpath albo null;
- build_ids: identyfikatory, offsety i źródła;
- symbol_tables: statystyki tablic symboli;
- relocation_tables: statystyki i powiązania tablic relokacji.

Adresy i offsety w eksporcie są napisami hex, aby nie tracić precyzji
przy przetwarzaniu liczb 64-bitowych przez inne środowiska.
path może zawierać stratną reprezentację UTF-8; path_bytes_hex zachowuje
oryginalne bajty ścieżki na Unix. Napisy z ELF-a mają text i bytes_hex.
Wersja 1 nie eksportuje wszystkich segmentów, sekcji ani podglądów rekordów.
Nie jest formatem pozwalającym odtworzyć plik ELF.

Przykład z zapisem do pliku:

    cargo run -- --json --quiet ./katalog > /tmp/elfscope.jsonl

Opcjonalny podgląd przez jq, jeżeli jest zainstalowany:

    jq -r '.path' /tmp/elfscope.jsonl
    jq 'select(.header.class == "ELF64")' /tmp/elfscope.jsonl

## Lista ścieżek

--paths wypisuje surowe bajty ścieżki i newline. Nazwy zawierające newline
nie są wtedy jednoznacznym formatem rekordów. Dla automatyzacji użyj
--paths --null, które zachowuje granice rekordów i bajty nazw na Linux.

## Zapis wyniku i potoki

Tryby JSON i paths obsługują błędy Write. Zamknięty potok w tych trybach
kończy program bez komunikatu błędu. Dotychczasowe raporty tekstowe nadal
używają println! i nie zostały w tej aktualizacji objęte jednolitą obsługą
BrokenPipe. Nie traktuj tego jako ogólnej obsługi potoków we wszystkich trybach.

## Bezpieczeństwo i zakres

Nie dodano zapisu do analizowanych plików, uruchamiania ELF-ów ani ładowania
bibliotek. Nie dodano podążania za dowiązaniami. Poprzednie ograniczenia
parserów, limity zasobów i ryzyko TOCTOU pozostają aktualne.
