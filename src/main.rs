mod dynamic;
mod elf;
mod interpreter;
mod mapping;
mod sections;

use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dynamic::DynamicInfo;
use elf::{ElfClass, ElfFile, Endianness};
use sections::SectionTable;

#[derive(Default)]
struct ScanStats {
    files: u64,
    elf_files: u64,
    skipped: u64,
    errors: u64,
}

struct Inspection {
    elf: ElfFile,
    sections: SectionTable,
    interpreter: Option<Vec<u8>>,
    dynamic: Option<DynamicInfo>,
}

fn report_error(path: &Path, error: &io::Error, stats: &mut ScanStats) {
    stats.errors += 1;
    eprintln!("Błąd dla {:?}: {}", path, error);
}

fn section_name(table: &SectionTable, index: usize) -> String {
    match table.name(index) {
        Some(bytes) => format!("{:?}", String::from_utf8_lossy(bytes)),
        None => "<brak nazwy>".to_string(),
    }
}

fn print_elf(path: &Path, parsed: &ElfFile) {
    let header = &parsed.header;

    let class = match header.ident.class {
        ElfClass::Elf32 => "ELF32",
        ElfClass::Elf64 => "ELF64",
    };

    let endianness = match header.ident.endianness {
        Endianness::Little => "little-endian",
        Endianness::Big => "big-endian",
    };

    println!("{:?}", path);
    println!("  Klasa:          {}", class);
    println!("  Kolejność:      {}", endianness);
    println!("  OS/ABI:         {}", header.ident.os_abi);
    println!("  Wersja ABI:     {}", header.ident.abi_version);
    println!("  Wersja ident.:  {}", header.ident.version);
    println!("  Wersja ELF:     {}", header.version);

    println!(
        "  Typ:            {} ({})",
        elf::file_type_name(header.file_type),
        header.file_type
    );

    println!(
        "  Architektura:   {} ({})",
        elf::machine_name(header.machine),
        header.machine
    );

    println!("  Punkt wejścia:  {:#x}", header.entry);
    println!("  Flagi:          {:#x}", header.flags);
    println!("  Rozmiar nagł.:  {} B", header.header_size);

    println!(
        "  Tabela programu: offset={:#x}, wpis={} B, licznik={}",
        header.program_header_offset, header.program_header_entry_size, header.program_header_count
    );

    println!(
        "  Tabela sekcji:   offset={:#x}, wpis={} B, licznik={}",
        header.section_header_offset, header.section_header_entry_size, header.section_header_count
    );

    println!("  Indeks nazw sekcji: {}", header.section_names_index);
    println!("  Nagłówki programu:");

    if parsed.program_headers.is_empty() {
        println!("    Brak");
    }

    for (index, segment) in parsed.program_headers.iter().enumerate() {
        println!(
            "    #{:<2} {:<14} type={:#x} {} flags={:#x}",
            index,
            elf::segment_type_name(segment.segment_type),
            segment.segment_type,
            elf::segment_permissions(segment.flags),
            segment.flags
        );

        println!(
            "        offset={:#x} vaddr={:#x} paddr={:#x}",
            segment.offset, segment.virtual_address, segment.physical_address
        );

        println!(
            "        filesz={:#x} memsz={:#x} align={:#x}",
            segment.file_size, segment.memory_size, segment.alignment
        );
    }
}

fn print_interpreter(path: Option<&[u8]>) {
    match path {
        Some(bytes) => {
            println!("  Interpreter ELF: {:?}", String::from_utf8_lossy(bytes));
        }
        None => {
            println!("  Interpreter ELF: brak wpisu PT_INTERP");
        }
    }
}

fn print_dynamic(info: Option<&DynamicInfo>) {
    println!("  Biblioteki DT_NEEDED:");

    match info {
        None => {
            println!("    Brak wpisu PT_DYNAMIC");
        }
        Some(info) if info.needed.is_empty() => {
            println!("    Brak wpisów DT_NEEDED");
        }
        Some(info) => {
            for name in &info.needed {
                println!("    {:?}", String::from_utf8_lossy(name));
            }
        }
    }
}

fn print_sections(table: &SectionTable) {
    println!("  Sekcje:");

    if table.headers.is_empty() {
        println!("    Brak");
        return;
    }

    for (index, section) in table.headers.iter().enumerate() {
        println!(
            "    #{:<2} {} {} ({:#x}) {} flags={:#x}",
            index,
            section_name(table, index),
            sections::section_type_name(section.section_type),
            section.section_type,
            sections::section_flags(section.flags),
            section.flags
        );

        println!(
            "        offset={:#x} addr={:#x} size={:#x}",
            section.offset, section.address, section.size
        );

        println!(
            "        link={} info={} align={:#x} entsize={:#x}",
            section.link, section.info, section.alignment, section.entry_size
        );
    }
}

fn print_mapping(parsed: &ElfFile, table: &SectionTable) {
    println!("  Sekcje w LOAD i TLS (tylko niepuste, z flagą ALLOC):");

    if table.headers.is_empty() {
        println!("    Brak tabeli sekcji — nie można wyznaczyć mapowania");
        return;
    }

    let mut supported_count = 0;

    for (segment_index, segment) in parsed.program_headers.iter().enumerate() {
        if !mapping::is_supported_segment(segment) {
            continue;
        }

        supported_count += 1;

        let matching_sections: Vec<String> = table
            .headers
            .iter()
            .enumerate()
            .filter(|(_, section)| mapping::section_belongs_to_segment(section, segment))
            .map(|(section_index, _)| {
                format!("#{} {}", section_index, section_name(table, section_index))
            })
            .collect();

        println!(
            "    Segment #{} {} {}:",
            segment_index,
            elf::segment_type_name(segment.segment_type),
            elf::segment_permissions(segment.flags)
        );

        if matching_sections.is_empty() {
            println!("        Brak pasujących sekcji");
        } else {
            println!("        {}", matching_sections.join(", "));
        }
    }

    if supported_count == 0 {
        println!("    Brak wpisów LOAD i TLS");
    }
}

fn inspect_file(path: &Path) -> io::Result<Option<Inspection>> {
    let mut file = File::open(path)?;

    let parsed = match elf::read_elf(&mut file)? {
        Some(parsed) => parsed,
        None => return Ok(None),
    };

    let interpreter = interpreter::read_interpreter(&mut file, &parsed.program_headers)?;

    let dynamic = dynamic::read_dynamic(&mut file, &parsed)?;

    let sections = sections::read_sections(&mut file, &parsed.header)?;

    Ok(Some(Inspection {
        elf: parsed,
        sections,
        interpreter,
        dynamic,
    }))
}

fn scan(root: &Path) -> ScanStats {
    let mut stats = ScanStats::default();
    let mut pending = vec![root.to_path_buf()];

    while let Some(path) = pending.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                report_error(&path, &error, &mut stats);
                continue;
            }
        };

        if metadata.is_symlink() {
            stats.skipped += 1;
            continue;
        }

        if metadata.is_dir() {
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(error) => {
                    report_error(&path, &error, &mut stats);
                    continue;
                }
            };

            for entry in entries {
                match entry {
                    Ok(entry) => pending.push(entry.path()),
                    Err(error) => report_error(&path, &error, &mut stats),
                }
            }

            continue;
        }

        if !metadata.is_file() {
            stats.skipped += 1;
            continue;
        }

        stats.files += 1;

        match inspect_file(&path) {
            Ok(Some(inspection)) => {
                stats.elf_files += 1;

                print_elf(&path, &inspection.elf);
                print_interpreter(inspection.interpreter.as_deref());
                print_dynamic(inspection.dynamic.as_ref());
                print_sections(&inspection.sections);
                print_mapping(&inspection.elf, &inspection.sections);

                println!();
            }
            Ok(None) => {}
            Err(error) => report_error(&path, &error, &mut stats),
        }
    }

    stats
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| "elfscope".into());

    let root = match (args.next(), args.next()) {
        (Some(path), None) => PathBuf::from(path),
        _ => {
            eprintln!("Użycie: {:?} <katalog-lub-plik>", program);
            return ExitCode::from(2);
        }
    };

    let stats = scan(&root);

    eprintln!();
    eprintln!("Sprawdzone zwykłe pliki: {}", stats.files);
    eprintln!("Przeanalizowane ELF:     {}", stats.elf_files);
    eprintln!("Pominięte wpisy:         {}", stats.skipped);
    eprintln!("Błędy:                   {}", stats.errors);

    if stats.errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
