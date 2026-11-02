# Deklaracje dynamiczne NOW, PIE i TEXTREL

Nowe odczytywane tagi: DT_FLAGS (30), DT_FLAGS_1 (0x6ffffffb), DT_BIND_NOW (24), DT_TEXTREL (22).
NOW jest deklarowane, gdy występuje co najmniej jeden z sygnałów:
DT_BIND_NOW, DT_FLAGS z DF_BIND_NOW (0x8), DT_FLAGS_1 z DF_1_NOW (0x1).
Marker PIE jest odczytywany z DT_FLAGS_1 / DF_1_PIE (0x08000000).
TEXTREL jest deklarowane przez DT_TEXTREL lub DT_FLAGS / DF_TEXTREL (0x4).

Brak flagi nie jest dowodem przeciwnej własności środowiska wykonawczego.
Brak DF_1_PIE nie dowodzi, że DYN nie jest programem PIE.
Nie zmieniono --elf-type: nadal filtruje surowy e_type, nie marker PIE.
TEXTREL dotyczy relokacji do segmentów niezapisywalnych, nie wyłącznie nazwy .text.
Nie stosujemy relokacji ani nie mierzymy mapowań procesu.

Raport tekstowy pokazuje surowe DT_FLAGS i DT_FLAGS_1 oraz deklaracje pochodne.
Wcześniejsze zdanie 'nie oceniono BIND_NOW' zostało zastąpione informacją,
że nie potwierdzono pełnego RELRO ani rzeczywistych uprawnień procesu.
PT_GNU_RELRO + NOW to zestaw dwóch deklaracji, nie runtime'owy audyt.
Sam wpis PT_GNU_RELRO może mieć nietypowy zakres; nie dowodzi ochrony GOT.

W dynamic obiektu JSON dodano:
flags_hex, flags_1_hex, bind_now_tag, textrel_tag,
bind_now_requested, pie_flag_set, textrel_requested.
Surowe flagi są null przy braku wpisu i '0x0' przy jawnym zerze.
Jeżeli nie ma PT_DYNAMIC, całe dynamic pozostaje null.
Nazwy pól dotyczą odczytanej deklaracji, a nie potwierdzonego zachowania procesu.
Schemat 1 zachowuje dotychczasowe pola, dodając nowe.

Przykłady:

    cargo run -- target/debug/elfscope
    readelf -dW target/debug/elfscope
    cargo run -- --json --quiet target/debug/elfscope

Jeśli jq jest zainstalowany:

    jq 'select(.kind == "elf") | {path, dynamic: .dynamic}' /tmp/elfscope-events.jsonl
    jq 'select(.kind == "elf" and .dynamic.pie_flag_set == true) | .path' /tmp/elfscope-events.jsonl

Powtórzone singletony DT_FLAGS / DT_FLAGS_1 są odrzucane jako InvalidData,
podobnie jak dotychczasowe powtórzone DT_STRTAB i DT_SONAME.
Tagi obecności NOW i TEXTREL są traktowane jako logiczne sygnały obecności.
Nie interpretujemy pozostałych bitów flag. Ich surowa wartość pozostaje dostępna.
Flagi są zachowywane także wtedy, gdy tablica nie zawiera żadnych napisów.
