use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Default)]
struct ScanStats {
    files: u64,
    elf_files: u64,
    skipped: u64,
    errors: u64,
}

fn has_elf_magic(reader: &mut impl Read) -> io::Result<bool> {
    let mut magic = [0_u8; 4];

    match reader.read_exact(&mut magic) {
        Ok(()) => Ok(magic == ELF_MAGIC),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
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

        let result = File::open(&path).and_then(|mut file| has_elf_magic(&mut file));

        match result {
            Ok(true) => {
                stats.elf_files += 1;
                println!("{:?}", path);
            }
            Ok(false) => {}
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
    eprintln!("Pliki z sygnaturą ELF:   {}", stats.elf_files);
    eprintln!("Pominięte wpisy:         {}", stats.skipped);
    eprintln!("Błędy:                   {}", stats.errors);

    if stats.errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn detects_elf_magic() {
        let mut input = Cursor::new(b"\x7fELFadditional bytes");
        assert!(has_elf_magic(&mut input).unwrap());
    }

    #[test]
    fn rejects_other_magic() {
        let mut input = Cursor::new(b"not an ELF");
        assert!(!has_elf_magic(&mut input).unwrap());
    }

    #[test]
    fn rejects_short_input() {
        let mut input = Cursor::new(b"\x7fEL");
        assert!(!has_elf_magic(&mut input).unwrap());
    }

    #[test]
    fn rejects_empty_input() {
        let mut input = Cursor::new(b"");
        assert!(!has_elf_magic(&mut input).unwrap());
    }
}
