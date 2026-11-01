#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const SHN_LORESERVE: usize = 0xff00;
const SHN_XINDEX: u64 = 0xffff;
const PN_XNUM: usize = 0xffff;

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base)?;

        for _ in 0..1000 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);

            let path = base.join(format!("elfscope-extended-{}-{}", std::process::id(), id));

            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Nie udało się utworzyć katalogu testowego",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy)]
enum Class {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy)]
enum Case {
    Sections,
    Programs,
    Combined,
}

struct Fixture {
    bytes: Vec<u8>,
    section_count: usize,
    section_offset: usize,
}

fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64, endian: Endian) {
    match endian {
        Endian::Little => {
            bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        Endian::Big => {
            bytes[offset..offset + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
        }
    }
}

fn fixture(class: Class, endian: Endian, case: Case) -> Fixture {
    let (header_size, section_size, program_size, word_size): (usize, usize, usize, usize) =
        match class {
            Class::Elf32 => (52, 40, 32, 4),
            Class::Elf64 => (64, 64, 56, 8),
        };

    let extended_sections = matches!(case, Case::Sections | Case::Combined);
    let extended_programs = matches!(case, Case::Programs | Case::Combined);

    let section_count = match case {
        Case::Sections => SHN_LORESERVE,
        Case::Programs => 2,
        Case::Combined => SHN_LORESERVE + 1,
    };

    let program_count = if extended_programs { PN_XNUM } else { 0 };

    let names_index = section_count - 1;
    let names = b"\0.shstrtab\0";

    let section_offset = header_size;
    let section_end = section_offset + section_count * section_size;

    let program_offset = if program_count == 0 { 0 } else { section_end };

    let names_offset = section_end + program_count * program_size;

    let mut bytes = vec![0_u8; names_offset + names.len()];

    bytes[..4].copy_from_slice(b"\x7fELF");

    bytes[4] = match class {
        Class::Elf32 => 1,
        Class::Elf64 => 2,
    };

    bytes[5] = match endian {
        Endian::Little => 1,
        Endian::Big => 2,
    };

    bytes[6] = 1;

    // Strukturalny plik testowy, nie obraz przeznaczony do uruchomienia.
    put(&mut bytes, 16, 2, 3, endian);

    let machine = match class {
        Class::Elf32 => 3,
        Class::Elf64 => 62,
    };

    put(&mut bytes, 18, 2, machine, endian);
    put(&mut bytes, 20, 4, 1, endian);

    let (phoff_field, shoff_field, sizes_field) = match class {
        Class::Elf32 => (28, 32, 40),
        Class::Elf64 => (32, 40, 52),
    };

    put(
        &mut bytes,
        phoff_field,
        word_size,
        program_offset as u64,
        endian,
    );

    put(
        &mut bytes,
        shoff_field,
        word_size,
        section_offset as u64,
        endian,
    );

    put(&mut bytes, sizes_field, 2, header_size as u64, endian);

    let raw_program_size = if program_count == 0 {
        0
    } else {
        program_size as u64
    };

    put(&mut bytes, sizes_field + 2, 2, raw_program_size, endian);

    let raw_program_count = if extended_programs { PN_XNUM as u64 } else { 0 };

    put(&mut bytes, sizes_field + 4, 2, raw_program_count, endian);

    put(&mut bytes, sizes_field + 6, 2, section_size as u64, endian);

    let raw_section_count = if extended_sections {
        0
    } else {
        section_count as u64
    };

    put(&mut bytes, sizes_field + 8, 2, raw_section_count, endian);

    let raw_names_index = if names_index >= SHN_LORESERVE {
        SHN_XINDEX
    } else {
        names_index as u64
    };

    put(&mut bytes, sizes_field + 10, 2, raw_names_index, endian);

    let (
        section_data_offset_field,
        section_size_field,
        section_link_field,
        section_info_field,
        section_alignment_field,
    ) = match class {
        Class::Elf32 => (16, 20, 24, 28, 32),
        Class::Elf64 => (24, 32, 40, 44, 48),
    };

    // Nagłówek zerowy pozostaje typu SHT_NULL.
    if extended_sections {
        put(
            &mut bytes,
            section_offset + section_size_field,
            word_size,
            section_count as u64,
            endian,
        );
    }

    if names_index >= SHN_LORESERVE {
        put(
            &mut bytes,
            section_offset + section_link_field,
            4,
            names_index as u64,
            endian,
        );
    }

    if extended_programs {
        put(
            &mut bytes,
            section_offset + section_info_field,
            4,
            program_count as u64,
            endian,
        );
    }

    // Ostatnia sekcja przechowuje tabelę nazw.
    let names_header = section_offset + names_index * section_size;

    put(&mut bytes, names_header, 4, 1, endian);
    put(&mut bytes, names_header + 4, 4, 3, endian);

    put(
        &mut bytes,
        names_header + section_data_offset_field,
        word_size,
        names_offset as u64,
        endian,
    );

    put(
        &mut bytes,
        names_header + section_size_field,
        word_size,
        names.len() as u64,
        endian,
    );

    put(
        &mut bytes,
        names_header + section_alignment_field,
        word_size,
        1,
        endian,
    );

    bytes[names_offset..].copy_from_slice(names);

    // Pozostałe nagłówki sekcji mają typ SHT_NULL.
    // Wszystkie nagłówki programu mają typ PT_NULL.
    Fixture {
        bytes,
        section_count,
        section_offset,
    }
}

fn run_summary(path: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg("--summary")
        .arg(path)
        .output()
}

fn verify_case(case: Case) -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("fixture.elf");

    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            let fixture = fixture(class, endian, case);
            fs::write(&path, &fixture.bytes)?;

            let output = run_summary(&path)?;

            assert!(
                output.status.success(),
                "Analiza nie powiodła się.\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );

            let stdout = String::from_utf8_lossy(&output.stdout);

            let expected_class = match class {
                Class::Elf32 => " | ELF32 | ",
                Class::Elf64 => " | ELF64 | ",
            };

            assert_eq!(stdout.lines().count(), 1);
            assert!(stdout.contains(expected_class));

            assert!(stdout.contains(&format!(" | sekcje={} | ", fixture.section_count)));

            assert!(stdout.contains(" | DT_NEEDED=0"));
        }
    }

    Ok(())
}

#[test]
fn scans_extended_section_counts_in_all_layouts() -> io::Result<()> {
    verify_case(Case::Sections)
}

#[test]
fn scans_extended_program_counts_in_all_layouts() -> io::Result<()> {
    verify_case(Case::Programs)
}

#[test]
fn scans_combined_extended_numbering_in_all_layouts() -> io::Result<()> {
    verify_case(Case::Combined)
}

#[test]
fn rejects_invalid_section_zero_type() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("broken.elf");

    let mut fixture = fixture(Class::Elf64, Endian::Little, Case::Combined);

    // Zamiast SHT_NULL wpisujemy SHT_PROGBITS.
    put(
        &mut fixture.bytes,
        fixture.section_offset + 4,
        4,
        1,
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run_summary(&path)?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("SHT_NULL"));

    Ok(())
}
