mod header_numbers;
mod permissions;
mod relocation_types;
use crate::cli::OutputMode;
use crate::dynamic::DynamicInfo;
use crate::elf::{self, ElfClass, ElfFile, Endianness};
use crate::inspection::Inspection;
use crate::mapping;
use crate::sections::{self, SectionTable};
use std::path::Path;
fn class_name(class: ElfClass) -> &'static str {
    match class {
        ElfClass::Elf32 => "ELF32",
        ElfClass::Elf64 => "ELF64",
    }
}
fn section_name(table: &SectionTable, index: usize) -> String {
    match table.name(index) {
        Some(bytes) => format!("{:?}", String::from_utf8_lossy(bytes)),
        None => "<brak nazwy>".into(),
    }
}
fn relocation_type_label(inspection: &Inspection, kind: u32) -> String {
    let header = &inspection.elf.header;
    relocation_types::label(header.ident.class, header.machine, kind)
}
fn print_elf(path: &Path, parsed: &ElfFile, sections: &SectionTable) {
    let h = &parsed.header;
    let endian = match h.ident.endianness {
        Endianness::Little => "little-endian",
        Endianness::Big => "big-endian",
    };
    println!("{:?}", path);
    println!("  Klasa:          {}", class_name(h.ident.class));
    println!("  Kolejność:      {}", endian);
    println!("  OS/ABI:         {}", h.ident.os_abi);
    println!("  Wersja ABI:     {}", h.ident.abi_version);
    println!("  Wersja ident.:  {}", h.ident.version);
    println!("  Wersja ELF:     {}", h.version);
    println!(
        "  Typ:            {} ({})",
        elf::file_type_name(h.file_type),
        h.file_type
    );
    println!(
        "  Architektura:   {} ({})",
        elf::machine_name(h.machine),
        h.machine
    );
    println!("  Punkt wejścia:  {:#x}", h.entry);
    println!("  Flagi:          {:#x}", h.flags);
    println!("  Rozmiar nagł.:  {} B", h.header_size);
    println!(
        "  Tabela programu: offset={:#x}, wpis={} B, licznik={}",
        h.program_header_offset,
        h.program_header_entry_size,
        header_numbers::program_count(h.program_header_count, parsed.program_headers.len())
    );
    println!(
        "  Tabela sekcji:   offset={:#x}, wpis={} B, licznik={}",
        h.section_header_offset,
        h.section_header_entry_size,
        header_numbers::section_count(h.section_header_count, sections.headers.len())
    );
    println!(
        "  Indeks nazw sekcji: {}",
        header_numbers::section_names_index(
            h.section_names_index,
            sections.headers.first().map(|s| s.link)
        )
    );
    println!("  Nagłówki programu:");
    if parsed.program_headers.is_empty() {
        println!("    Brak");
    }
    for (index, s) in parsed.program_headers.iter().enumerate() {
        println!(
            "    #{:<2} {:<14} type={:#x} {} flags={:#x}",
            index,
            elf::segment_type_name(s.segment_type),
            s.segment_type,
            elf::segment_permissions(s.flags),
            s.flags
        );
        println!(
            "        offset={:#x} vaddr={:#x} paddr={:#x}",
            s.offset, s.virtual_address, s.physical_address
        );
        println!(
            "        filesz={:#x} memsz={:#x} align={:#x}",
            s.file_size, s.memory_size, s.alignment
        );
    }
}
fn print_entry_analysis(parsed: &ElfFile) {
    let h = &parsed.header;
    println!("  Analiza punktu wejścia:");
    if !matches!(h.file_type, 2 | 3) {
        println!("    Pominięta dla tego typu pliku");
        return;
    }
    if h.entry == 0 {
        println!("    Nagłówek nie określa punktu wejścia (e_entry=0)");
        return;
    }
    let locations = mapping::entry_locations(h.entry, &parsed.program_headers);
    if locations.is_empty() {
        println!("    Adres nie pasuje do żadnego poprawnego zakresu LOAD");
        return;
    }
    if locations.len() > 1 {
        println!(
            "    Uwaga: adres pasuje do {} segmentów LOAD",
            locations.len()
        );
    }
    for location in locations {
        let s = &parsed.program_headers[location.segment_index];
        println!(
            "    Segment #{} LOAD {}",
            location.segment_index,
            elf::segment_permissions(s.flags)
        );
        match location.file_offset {
            Some(offset) => println!("    Offset w pliku: {:#x}", offset),
            None => println!("    Część zerowana segmentu — brak odpowiadających bajtów w pliku"),
        }
        if !location.executable {
            println!("    Uwaga: segment nie ma flagi wykonywania PF_X");
        }
    }
}
fn print_interpreter(path: Option<&[u8]>) {
    match path {
        Some(bytes) => println!("  Interpreter ELF: {:?}", String::from_utf8_lossy(bytes)),
        None => println!("  Interpreter ELF: brak wpisu PT_INTERP"),
    }
}
fn print_optional_dynamic_string(label: &str, value: Option<&[u8]>) {
    match value {
        Some(bytes) => println!("    {}: {:?}", label, String::from_utf8_lossy(bytes)),
        None => println!("    {}: brak wpisu", label),
    }
}
fn print_dynamic(info: Option<&DynamicInfo>) {
    println!("  Informacje dynamiczne:");
    let Some(info) = info else {
        println!("    Brak wpisu PT_DYNAMIC");
        return;
    };
    print_optional_dynamic_string("SONAME", info.soname.as_deref());
    print_optional_dynamic_string("RPATH", info.rpath.as_deref());
    print_optional_dynamic_string("RUNPATH", info.runpath.as_deref());
    println!("  Biblioteki DT_NEEDED:");
    if info.needed.is_empty() {
        println!("    Brak wpisów DT_NEEDED");
    }
    for name in &info.needed {
        println!("    {:?}", String::from_utf8_lossy(name));
    }
}
fn print_build_ids(inspection: &Inspection) {
    if inspection.build_ids.is_empty() {
        println!(
            "  GNU Build ID: nie znaleziono w sekcji .note.gnu.build-id ani w segmentach PT_NOTE"
        );
        return;
    }
    for id in &inspection.build_ids {
        let sources: Vec<String> = id.sources.iter().map(ToString::to_string).collect();
        println!("  GNU Build ID: {} ({})", id, sources.join(", "));
    }
}
fn print_sections(table: &SectionTable) {
    println!("  Sekcje:");
    if table.headers.is_empty() {
        println!("    Brak");
        return;
    }
    for (index, s) in table.headers.iter().enumerate() {
        println!(
            "    #{:<2} {} {} ({:#x}) {} flags={:#x}",
            index,
            section_name(table, index),
            sections::section_type_name(s.section_type),
            s.section_type,
            sections::section_flags(s.flags),
            s.flags
        );
        println!(
            "        offset={:#x} addr={:#x} size={:#x}",
            s.offset, s.address, s.size
        );
        println!(
            "        link={} info={} align={:#x} entsize={:#x}",
            s.link, s.info, s.alignment, s.entry_size
        );
    }
}
fn print_mapping(parsed: &ElfFile, table: &SectionTable) {
    println!("  Sekcje w LOAD i TLS (tylko niepuste, z flagą ALLOC):");
    if table.headers.is_empty() {
        println!("    Brak tabeli sekcji — nie można wyznaczyć mapowania");
        return;
    }
    let mut count = 0;
    for (index, s) in parsed.program_headers.iter().enumerate() {
        if !mapping::is_supported_segment(s) {
            continue;
        }
        count += 1;
        let matches: Vec<String> = table
            .headers
            .iter()
            .enumerate()
            .filter(|(_, section)| mapping::section_belongs_to_segment(section, s))
            .map(|(index, _)| format!("#{} {}", index, section_name(table, index)))
            .collect();
        println!(
            "    Segment #{} {} {}:",
            index,
            elf::segment_type_name(s.segment_type),
            elf::segment_permissions(s.flags)
        );
        if matches.is_empty() {
            println!("        Brak pasujących sekcji");
        } else {
            println!("        {}", matches.join(", "));
        }
    }
    if count == 0 {
        println!("    Brak wpisów LOAD i TLS");
    }
}
fn print_symbols(inspection: &Inspection) {
    println!("  Tablice symboli:");
    if inspection.symbols.is_empty() {
        println!("    Brak sekcji SYMTAB i DYNSYM");
        return;
    }
    for table in &inspection.symbols {
        println!(
            "    Sekcja #{} {}: wpisy={}",
            table.section_index,
            section_name(&inspection.sections, table.section_index),
            table.total
        );
        println!("        FUNC={}, OBJECT={}", table.functions, table.objects);
        println!(
            "        LOCAL={}, GLOBAL={}, WEAK={}",
            table.locals, table.globals, table.weaks
        );
        println!(
            "        SHN_UNDEF={}, SHN_XINDEX={}",
            table.undefined, table.extended_indices
        );
        println!("        Podgląd nazwanych wpisów, maksymalnie 20:");
        if table.preview.is_empty() {
            println!("            Brak nazwanych wpisów");
        }
        for symbol in &table.preview {
            println!(
                "            #{} {:?}{}",
                symbol.index,
                String::from_utf8_lossy(&symbol.name),
                if symbol.name_truncated {
                    " [nazwa skrócona]"
                } else {
                    ""
                }
            );
            println!(
                "                value={:#x} size={} bind={} type={} visibility={} shndx={}",
                symbol.value,
                symbol.size,
                symbol.binding,
                symbol.symbol_type,
                symbol.visibility,
                symbol.section_index
            );
        }
    }
}
fn print_relocations(inspection: &Inspection) {
    println!("  Tablice relokacji:");
    if inspection.relocations.is_empty() {
        println!("    Brak sekcji REL i RELA");
        return;
    }
    for table in &inspection.relocations {
        println!(
            "    Sekcja #{} {}: {} wpisy={}",
            table.section_index,
            section_name(&inspection.sections, table.section_index),
            if table.with_addend { "RELA" } else { "REL" },
            table.total
        );
        println!(
            "        Tablica symboli: #{} {}",
            table.symbol_table_index,
            section_name(&inspection.sections, table.symbol_table_index)
        );
        match table.target_section_index {
            Some(index) => println!(
                "        Sekcja docelowa: #{} {}",
                index,
                section_name(&inspection.sections, index)
            ),
            None => println!("        Sekcja docelowa: brak wskazania w sh_info"),
        }
        println!("        Podgląd rekordów, maksymalnie 10:");
        for record in &table.preview {
            match record.addend {
                Some(addend) => println!(
                    "            #{} r_offset={:#x} r_info={:#x} r_addend={}",
                    record.index, record.offset, record.info, addend
                ),
                None => println!(
                    "            #{} r_offset={:#x} r_info={:#x} r_addend=<niejawny>",
                    record.index, record.offset, record.info
                ),
            }
            match &record.symbol {
                Some(symbol) if symbol.index == 0 => println!(
                    "                symbol=#0 <STN_UNDEF> typ_relokacji={}",
                    relocation_type_label(inspection, symbol.relocation_type)
                ),
                Some(symbol) => {
                    let name = if symbol.name.is_empty() {
                        "<bez nazwy>".to_string()
                    } else {
                        format!("{:?}", String::from_utf8_lossy(&symbol.name))
                    };
                    println!(
                        "                symbol=#{} {}{} typ_relokacji={}",
                        symbol.index,
                        name,
                        if symbol.name_truncated {
                            " [nazwa skrócona]"
                        } else {
                            ""
                        },
                        relocation_type_label(inspection, symbol.relocation_type)
                    );
                }
                None => println!("                symbol i typ: niezdekodowane dla tego ABI"),
            }
        }
    }
}
pub(crate) fn print_inspection(path: &Path, inspection: &Inspection, mode: OutputMode) {
    match mode {
        OutputMode::Summary => {
            let h = &inspection.elf.header;
            let needed = inspection
                .dynamic
                .as_ref()
                .map_or(0, |info| info.needed.len());
            println!(
                "{:?} | {} | {} | typ={} | sekcje={} | DT_NEEDED={}",
                path,
                class_name(h.ident.class),
                elf::machine_name(h.machine),
                h.file_type,
                inspection.sections.headers.len(),
                needed
            );
        }
        OutputMode::Detailed => {
            print_elf(path, &inspection.elf, &inspection.sections);
            permissions::print(&inspection.elf.program_headers, inspection.dynamic.as_ref());
            print_entry_analysis(&inspection.elf);
            print_interpreter(inspection.interpreter.as_deref());
            print_dynamic(inspection.dynamic.as_ref());
            print_build_ids(inspection);
            print_sections(&inspection.sections);
            print_mapping(&inspection.elf, &inspection.sections);
            print_symbols(inspection);
            print_relocations(inspection);
            println!();
        }
    }
}
