mod cli;
mod dynamic;
mod elf;
mod inspection;
mod interpreter;
mod mapping;
mod report;
mod sections;

use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use cli::{Action, OutputMode};

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

fn scan(root: &Path, mode: OutputMode) -> ScanStats {
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

        match inspection::inspect_file(&path) {
            Ok(Some(inspection)) => {
                stats.elf_files += 1;
                report::print_inspection(&path, &inspection, mode);
            }
            Ok(None) => {}
            Err(error) => report_error(&path, &error, &mut stats),
        }
    }

    stats
}

fn main() -> ExitCode {
    let action = match cli::parse(env::args_os().skip(1)) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("Błąd argumentów: {}", error);
            eprintln!();
            eprintln!("{}", cli::HELP);
            return ExitCode::from(2);
        }
    };

    let (path, mode) = match action {
        Action::Help => {
            print!("{}", cli::HELP);
            return ExitCode::SUCCESS;
        }
        Action::Scan { path, mode } => (path, mode),
    };

    let stats = scan(&path, mode);

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
