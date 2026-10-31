mod elf;

use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use elf::{ElfClass, Endianness};

#[derive(Default)]
struct ScanStats {
    files: u64,
    elf_files: u64,
    skipped: u64,
    errors: u64,
}

fn report_error(path: &Path, error: &io::Error, stats: &mut ScanStats) {
    stats.errors += 1;
    eprintln!("Błąd dla {:?}: {}", path, error);
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

        let result = File::open(&path).and_then(|mut file| elf::read_ident(&mut file));

        match result {
            Ok(Some(ident)) => {
                stats.elf_files += 1;

                let class = match ident.class {
                    ElfClass::Elf32 => "ELF32",
                    ElfClass::Elf64 => "ELF64",
                };

                let endianness = match ident.endianness {
                    Endianness::Little => "little-endian",
                    Endianness::Big => "big-endian",
                };

                println!("{:?}", path);
                println!("  Klasa:         {}", class);
                println!("  Kolejność:     {}", endianness);
                println!("  Wersja ELF:    {}", ident.version);
                println!("  OS/ABI:        {}", ident.os_abi);
                println!("  Wersja ABI:    {}", ident.abi_version);
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
    eprintln!("Odczytane ident. ELF:    {}", stats.elf_files);
    eprintln!("Pominięte wpisy:         {}", stats.skipped);
    eprintln!("Błędy:                   {}", stats.errors);

    if stats.errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
