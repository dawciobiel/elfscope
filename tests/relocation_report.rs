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
                "elfscope-relocation-report-{}-{}",
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

struct Layout {
    header_size: usize,
    section_size: usize,
    symbol_size: usize,
    word_size: usize,
}

impl Class {
    fn layout(self) -> Layout {
        match self {
            Self::Elf32 => Layout {
                header_size: 52,
                section_size: 40,
                symbol_size: 16,
                word_size: 4,
            },
            Self::Elf64 => Layout {
                header_size: 64,
                section_size: 64,
                symbol_size: 24,
                word_size: 8,
            },
        }
    }
}

struct Fixture {
    bytes: Vec<u8>,
    relocation_header_offset: usize,
    relocation_offset: usize,
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

fn write_section(bytes: &mut [u8], base: usize, class: Class, endian: Endian, fields: [u64; 10]) {
    // Kolejność:
    // name, type, flags, addr, offset, size, link, info, align, entsize.
    let widths = match class {
        Class::Elf32 => [4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
        Class::Elf64 => [4, 4, 8, 8, 8, 8, 4, 4, 8, 8],
    };

    let mut offset = base;

    for (value, width) in fields.into_iter().zip(widths) {
        put(bytes, offset, width, value, endian);
        offset += width;
    }
}

fn string_offset(table: &[u8], name: &[u8]) -> u64 {
    table
        .windows(name.len())
        .position(|window| window == name)
        .unwrap() as u64
}

fn encoded_info(class: Class, symbol_index: u64) -> u64 {
    match class {
        Class::Elf32 => (symbol_index << 8) | 2,
        Class::Elf64 => (symbol_index << 32) | 2,
    }
}

fn fixture(class: Class, endian: Endian, with_addend: bool, referenced_symbol: u32) -> Fixture {
    assert!(referenced_symbol > 0);

    let layout = class.layout();
    let symbol_count = referenced_symbol as usize + 1;

    let section_names = b"\0.text\0.symtab\0.strtab\0.rel.text\0.rela.text\0.shstrtab\0";

    let symbol_names = b"\0earlier_symbol\0external_function\0";

    let relocation_size = layout.word_size * if with_addend { 3 } else { 2 };

    let section_offset = layout.header_size;
    let text_offset = section_offset + 6 * layout.section_size;
    let symbols_offset = text_offset + 8;
    let strings_offset = symbols_offset + symbol_count * layout.symbol_size;
    let relocation_offset = strings_offset + symbol_names.len();
    let section_names_offset = relocation_offset + relocation_size;

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
        layout.word_size,
        section_offset as u64,
        endian,
    );

    put(
        &mut bytes,
        sizes_field,
        2,
        layout.header_size as u64,
        endian,
    );

    put(
        &mut bytes,
        sizes_field + 6,
        2,
        layout.section_size as u64,
        endian,
    );

    put(&mut bytes, sizes_field + 8, 2, 6, endian);
    put(&mut bytes, sizes_field + 10, 2, 5, endian);

    write_section(
        &mut bytes,
        section_offset + layout.section_size,
        class,
        endian,
        [
            string_offset(section_names, b".text\0"),
            1,
            6,
            0,
            text_offset as u64,
            8,
            0,
            0,
            1,
            0,
        ],
    );

    write_section(
        &mut bytes,
        section_offset + 2 * layout.section_size,
        class,
        endian,
        [
            string_offset(section_names, b".symtab\0"),
            2,
            0,
            0,
            symbols_offset as u64,
            (symbol_count * layout.symbol_size) as u64,
            3,
            1,
            1,
            layout.symbol_size as u64,
        ],
    );

    write_section(
        &mut bytes,
        section_offset + 3 * layout.section_size,
        class,
        endian,
        [
            string_offset(section_names, b".strtab\0"),
            3,
            0,
            0,
            strings_offset as u64,
            symbol_names.len() as u64,
            0,
            0,
            1,
            0,
        ],
    );

    let relocation_header_offset = section_offset + 4 * layout.section_size;

    let relocation_name: &[u8] = if with_addend {
        b".rela.text\0"
    } else {
        b".rel.text\0"
    };

    write_section(
        &mut bytes,
        relocation_header_offset,
        class,
        endian,
        [
            string_offset(section_names, relocation_name),
            if with_addend { 4 } else { 9 },
            0,
            0,
            relocation_offset as u64,
            relocation_size as u64,
            2,
            1,
            1,
            relocation_size as u64,
        ],
    );

    write_section(
        &mut bytes,
        section_offset + 5 * layout.section_size,
        class,
        endian,
        [
            string_offset(section_names, b".shstrtab\0"),
            3,
            0,
            0,
            section_names_offset as u64,
            section_names.len() as u64,
            0,
            0,
            1,
            0,
        ],
    );

    let info_field = match class {
        Class::Elf32 => 12,
        Class::Elf64 => 4,
    };

    for index in 1..symbol_count {
        let base = symbols_offset + index * layout.symbol_size;

        let name = if index == referenced_symbol as usize {
            string_offset(symbol_names, b"external_function\0")
        } else {
            string_offset(symbol_names, b"earlier_symbol\0")
        };

        put(&mut bytes, base, 4, name, endian);

        // GLOBAL, NOTYPE, SHN_UNDEF.
        bytes[base + info_field] = 0x10;
    }

    // r_offset = 0: początek docelowej sekcji .text.
    put(
        &mut bytes,
        relocation_offset + layout.word_size,
        layout.word_size,
        encoded_info(class, u64::from(referenced_symbol)),
        endian,
    );

    if with_addend {
        put(
            &mut bytes,
            relocation_offset + 2 * layout.word_size,
            layout.word_size,
            (-4_i64) as u64,
            endian,
        );
    }

    bytes[strings_offset..strings_offset + symbol_names.len()].copy_from_slice(symbol_names);

    bytes[section_names_offset..].copy_from_slice(section_names);

    Fixture {
        bytes,
        relocation_header_offset,
        relocation_offset,
    }
}

fn run(path: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(path)
        .output()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "Analiza nie powiodła się.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_failure(output: &Output, message: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains(message),
        "Brak komunikatu {:?}.\nstderr:\n{}",
        message,
        stderr
    );
}

#[test]
fn reports_relocations_in_all_formats() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("example.o");

    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            for with_addend in [false, true] {
                let fixture = fixture(class, endian, with_addend, 1);
                fs::write(&path, &fixture.bytes)?;

                let output = run(&path)?;
                assert_success(&output);

                let stdout = String::from_utf8_lossy(&output.stdout);

                let expected_table = if with_addend {
                    "Sekcja #4 \".rela.text\": RELA wpisy=1"
                } else {
                    "Sekcja #4 \".rel.text\": REL wpisy=1"
                };

                let expected_type = match class {
                    Class::Elf32 => "R_386_PC32 (2)",
                    Class::Elf64 => "R_X86_64_PC32 (2)",
                };

                assert!(stdout.contains(expected_table));
                assert!(stdout.contains("Tablica symboli: #2 \".symtab\""));
                assert!(stdout.contains("Sekcja docelowa: #1 \".text\""));

                assert!(stdout.contains(&format!(
                    "symbol=#1 \"external_function\" typ_relokacji={}",
                    expected_type
                )));

                if with_addend {
                    assert!(stdout.contains("r_addend=-4"));
                } else {
                    assert!(stdout.contains("r_addend=<niejawny>"));
                }
            }
        }
    }

    Ok(())
}

#[test]
fn resolves_symbol_outside_symbol_preview() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("late-symbol.o");

    let fixture = fixture(Class::Elf64, Endian::Little, true, 21);
    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("symbol=#21 \"external_function\" typ_relokacji=R_X86_64_PC32 (2)"));

    let (symbol_report, _) = stdout
        .split_once("  Tablice relokacji:")
        .expect("Brak raportu relokacji");

    assert!(
        !symbol_report.contains("\"external_function\""),
        "Symbol docelowy nie powinien mieścić się w podglądzie 20 wpisów"
    );

    Ok(())
}

#[test]
fn rejects_relocation_symbol_outside_table() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("bad-symbol.o");

    let mut fixture = fixture(Class::Elf64, Endian::Little, true, 1);

    // Tablica ma wpisy 0 i 1. Relokacja wskazuje nieistniejący wpis 2.
    put(
        &mut fixture.bytes,
        fixture.relocation_offset + 8,
        8,
        encoded_info(Class::Elf64, 2),
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_failure(&output, "indeks symbolu 2 poza tablicą");

    Ok(())
}

#[test]
fn rejects_missing_target_section_in_relocatable_file() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("missing-target.o");

    let mut fixture = fixture(Class::Elf64, Endian::Little, true, 1);

    // sh_info w nagłówku sekcji ELF64.
    put(
        &mut fixture.bytes,
        fixture.relocation_header_offset + 44,
        4,
        0,
        Endian::Little,
    );

    fs::write(&path, &fixture.bytes)?;

    let output = run(&path)?;
    assert_failure(&output, "ET_REL nie wskazuje sekcji docelowej");

    Ok(())
}
