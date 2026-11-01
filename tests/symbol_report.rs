#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

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

            let path = base.join(format!(
                "elfscope-symbol-report-{}-{}",
                std::process::id(),
                id
            ));

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

#[derive(Default)]
struct SectionDefinition {
    name: u32,
    kind: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    entry_size: usize,
}

struct Fixture {
    bytes: Vec<u8>,
    symbol_header_offset: usize,
    symbol_offset: usize,
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

fn write_section(
    bytes: &mut [u8],
    base: usize,
    class: Class,
    endian: Endian,
    section: SectionDefinition,
) {
    let (
        width,
        flags_field,
        offset_field,
        size_field,
        link_field,
        info_field,
        alignment_field,
        entry_size_field,
    ) = match class {
        Class::Elf32 => (4, 8, 16, 20, 24, 28, 32, 36),
        Class::Elf64 => (8, 8, 24, 32, 40, 44, 48, 56),
    };

    put(bytes, base, 4, u64::from(section.name), endian);
    put(bytes, base + 4, 4, u64::from(section.kind), endian);
    put(bytes, base + flags_field, width, section.flags, endian);

    put(
        bytes,
        base + offset_field,
        width,
        section.offset as u64,
        endian,
    );

    put(bytes, base + size_field, width, section.size as u64, endian);

    put(bytes, base + link_field, 4, u64::from(section.link), endian);
    put(bytes, base + info_field, 4, u64::from(section.info), endian);
    put(bytes, base + alignment_field, width, 1, endian);

    put(
        bytes,
        base + entry_size_field,
        width,
        section.entry_size as u64,
        endian,
    );
}

fn fixture(class: Class, endian: Endian) -> Fixture {
    let (header_size, section_size, symbol_size, width) = match class {
        Class::Elf32 => (52, 40, 16, 4),
        Class::Elf64 => (64, 64, 24, 8),
    };

    let section_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let symbol_names = b"\0example_function\0";

    let section_offset = header_size;
    let text_offset = section_offset + 5 * section_size;
    let symbols_offset = text_offset + 1;
    let strings_offset = symbols_offset + 2 * symbol_size;
    let section_names_offset = strings_offset + symbol_names.len();

    let mut bytes = vec![0_u8; section_names_offset + section_names.len()];

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

    put(&mut bytes, 16, 2, 1, endian);

    let machine = match class {
        Class::Elf32 => 3,
        Class::Elf64 => 62,
    };

    put(&mut bytes, 18, 2, machine, endian);
    put(&mut bytes, 20, 4, 1, endian);

    let (section_offset_field, sizes_field) = match class {
        Class::Elf32 => (32, 40),
        Class::Elf64 => (40, 52),
    };

    put(
        &mut bytes,
        section_offset_field,
        width,
        section_offset as u64,
        endian,
    );

    put(&mut bytes, sizes_field, 2, header_size as u64, endian);
    put(&mut bytes, sizes_field + 6, 2, section_size as u64, endian);
    put(&mut bytes, sizes_field + 8, 2, 5, endian);
    put(&mut bytes, sizes_field + 10, 2, 4, endian);

    write_section(
        &mut bytes,
        section_offset + section_size,
        class,
        endian,
        SectionDefinition {
            name: 1,
            kind: 1,
            flags: 6,
            offset: text_offset,
            size: 1,
            ..SectionDefinition::default()
        },
    );

    let symbol_header_offset = section_offset + 2 * section_size;

    write_section(
        &mut bytes,
        symbol_header_offset,
        class,
        endian,
        SectionDefinition {
            name: 7,
            kind: 2,
            offset: symbols_offset,
            size: 2 * symbol_size,
            link: 3,
            info: 1,
            entry_size: symbol_size,
            ..SectionDefinition::default()
        },
    );

    write_section(
        &mut bytes,
        section_offset + 3 * section_size,
        class,
        endian,
        SectionDefinition {
            name: 15,
            kind: 3,
            offset: strings_offset,
            size: symbol_names.len(),
            ..SectionDefinition::default()
        },
    );

    write_section(
        &mut bytes,
        section_offset + 4 * section_size,
        class,
        endian,
        SectionDefinition {
            name: 23,
            kind: 3,
            offset: section_names_offset,
            size: section_names.len(),
            ..SectionDefinition::default()
        },
    );

    // Pierwszy symbol pozostaje wpisem zerowym.
    let symbol_offset = symbols_offset + symbol_size;

    put(&mut bytes, symbol_offset, 4, 1, endian);

    let (info_field, index_field, size_field) = match class {
        Class::Elf32 => (12, 14, 8),
        Class::Elf64 => (4, 6, 16),
    };

    bytes[symbol_offset + info_field] = 0x12;

    put(&mut bytes, symbol_offset + index_field, 2, 1, endian);
    put(&mut bytes, symbol_offset + size_field, width, 1, endian);

    bytes[strings_offset..strings_offset + symbol_names.len()].copy_from_slice(symbol_names);

    bytes[section_names_offset..].copy_from_slice(section_names);

    Fixture {
        bytes,
        symbol_header_offset,
        symbol_offset,
    }
}

fn run(path: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(path)
        .output()
}

fn assert_failure(output: &Output, expected_message: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains(expected_message),
        "Brak oczekiwanego komunikatu {:?}.\nstderr:\n{}",
        expected_message,
        stderr
    );
}

#[test]
fn reports_named_symbol_in_all_layouts() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("example.o");

    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            let fixture = fixture(class, endian);
            fs::write(&path, &fixture.bytes)?;

            let output = run(&path)?;

            assert!(
                output.status.success(),
                "Analiza nie powiodła się.\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );

            let stdout = String::from_utf8_lossy(&output.stdout);

            assert!(stdout.contains("Sekcja #2 \".symtab\": wpisy=2"));
            assert!(stdout.contains("FUNC=1, OBJECT=0"));
            assert!(stdout.contains("LOCAL=1, GLOBAL=1, WEAK=0"));
            assert!(stdout.contains("SHN_UNDEF=1, SHN_XINDEX=0"));
            assert!(stdout.contains("#1 \"example_function\""));

            assert!(stdout.contains("value=0x0 size=1 bind=1 type=2 visibility=0 shndx=1"));
        }
    }

    Ok(())
}

#[test]
fn rejects_symbol_link_to_non_string_section() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("bad-link.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little);

    // sh_link tablicy symboli wskazuje teraz .text zamiast .strtab.
    put(
        &mut fixture.bytes,
        fixture.symbol_header_offset + 40,
        4,
        1,
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_failure(&output, "nie wskazuje sekcji STRTAB");

    Ok(())
}

#[test]
fn rejects_symbol_name_outside_string_table() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("bad-name.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little);

    put(
        &mut fixture.bytes,
        fixture.symbol_offset,
        4,
        999,
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_failure(&output, "st_name poza tabelą napisów");

    Ok(())
}

#[test]
fn rejects_xindex_without_auxiliary_table() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("missing-indices.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little);

    put(
        &mut fixture.bytes,
        fixture.symbol_offset + 6,
        2,
        0xffff,
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_failure(&output, "nie ma powiązanej tablicy SYMTAB_SHNDX");

    Ok(())
}
