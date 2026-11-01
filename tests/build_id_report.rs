#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);
const ID: &[u8] = &[0, 1, 2, 3, 0x0a, 0x7f, 0x80, 0xfe, 0xff];
const ID_HEX: &str = "000102030a7f80feff";

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
                "elfscope-build-id-report-{}-{}",
                std::process::id(),
                id
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
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

struct Fixture {
    bytes: Vec<u8>,
    note_offset: usize,
    note_header_offset: usize,
}

fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64, endian: Endian) {
    match endian {
        Endian::Little => {
            bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width])
        }
        Endian::Big => {
            bytes[offset..offset + width].copy_from_slice(&value.to_be_bytes()[8 - width..])
        }
    }
}

fn note(id: &[u8], endian: Endian) -> Vec<u8> {
    let mut bytes = vec![0_u8; 12];
    put(&mut bytes, 0, 4, 4, endian);
    put(&mut bytes, 4, 4, id.len() as u64, endian);
    put(&mut bytes, 8, 4, 3, endian);
    bytes.extend_from_slice(b"GNU\0");
    bytes.extend_from_slice(id);
    bytes.resize((bytes.len() + 3) & !3, 0);
    bytes
}

fn write_section(bytes: &mut [u8], base: usize, class: Class, endian: Endian, fields: [u64; 10]) {
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

fn fixture(class: Class, endian: Endian, ids: &[&[u8]]) -> Fixture {
    let (header_size, section_size, word_size) = match class {
        Class::Elf32 => (52, 40, 4),
        Class::Elf64 => (64, 64, 8),
    };
    let names = b"\0.note.gnu.build-id\0.shstrtab\0";
    let names_index = names
        .windows(b".shstrtab\0".len())
        .position(|part| part == b".shstrtab\0")
        .unwrap();
    let section_offset = header_size;
    let note_offset = section_offset + 3 * section_size;
    let mut notes = Vec::new();
    for id in ids {
        notes.extend(note(id, endian));
    }
    let names_offset = note_offset + notes.len();
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
    put(&mut bytes, 16, 2, 1, endian);
    put(
        &mut bytes,
        18,
        2,
        match class {
            Class::Elf32 => 3,
            Class::Elf64 => 62,
        },
        endian,
    );
    put(&mut bytes, 20, 4, 1, endian);

    let (section_offset_field, sizes_field) = match class {
        Class::Elf32 => (32, 40),
        Class::Elf64 => (40, 52),
    };
    put(
        &mut bytes,
        section_offset_field,
        word_size,
        section_offset as u64,
        endian,
    );
    put(&mut bytes, sizes_field, 2, header_size as u64, endian);
    put(&mut bytes, sizes_field + 6, 2, section_size as u64, endian);
    put(&mut bytes, sizes_field + 8, 2, 3, endian);
    put(&mut bytes, sizes_field + 10, 2, 2, endian);

    let note_header_offset = section_offset + section_size;
    write_section(
        &mut bytes,
        note_header_offset,
        class,
        endian,
        [
            1,
            7,
            2,
            0,
            note_offset as u64,
            notes.len() as u64,
            0,
            0,
            4,
            0,
        ],
    );
    write_section(
        &mut bytes,
        section_offset + 2 * section_size,
        class,
        endian,
        [
            names_index as u64,
            3,
            0,
            0,
            names_offset as u64,
            names.len() as u64,
            0,
            0,
            1,
            0,
        ],
    );
    bytes[note_offset..names_offset].copy_from_slice(&notes);
    bytes[names_offset..].copy_from_slice(names);
    Fixture {
        bytes,
        note_offset,
        note_header_offset,
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
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output, expected: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected),
        "Brak komunikatu {:?}.\nstderr:\n{}",
        expected,
        stderr
    );
}

#[test]
fn reports_exact_build_id_in_all_layouts() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("build-id.o");
    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            let fixture = fixture(class, endian, &[ID]);
            fs::write(&path, &fixture.bytes)?;
            let output = run(&path)?;
            assert_success(&output);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout
                .lines()
                .filter(|line| line.trim_start().starts_with("GNU Build ID:"))
                .collect();
            let expected = format!("  GNU Build ID: {} (sekcja #1)", ID_HEX);
            assert_eq!(lines, vec![expected.as_str()]);
        }
    }
    Ok(())
}

#[test]
fn reports_multiple_build_id_notes() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("multiple.o");
    let fixture = fixture(
        Class::Elf64,
        Endian::Little,
        &[&[0x01, 0x02], &[0xaa, 0xbb, 0xcc]],
    );
    fs::write(&path, &fixture.bytes)?;
    let output = run(&path)?;
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GNU Build ID: 0102 (sekcja #1)"));
    assert!(stdout.contains("GNU Build ID: aabbcc (sekcja #1)"));
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.trim_start().starts_with("GNU Build ID:"))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn absence_of_note_section_is_not_an_error() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("no-note.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little, &[ID]);
    // Zmieniamy SHT_NOTE na SHT_PROGBITS; nazwa sekcji pozostaje bez zmian.
    put(
        &mut fixture.bytes,
        fixture.note_header_offset + 4,
        4,
        1,
        Endian::Little,
    );
    fs::write(&path, &fixture.bytes)?;
    let output = run(&path)?;
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GNU Build ID: nie znaleziono w sekcji .note.gnu.build-id"));
    assert!(!stdout.contains(ID_HEX));
    Ok(())
}

#[test]
fn rejects_descriptor_outside_note_section() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("bad-size.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little, &[ID]);
    put(
        &mut fixture.bytes,
        fixture.note_offset + 4,
        4,
        4096,
        Endian::Little,
    );
    fs::write(&path, &fixture.bytes)?;
    let output = run(&path)?;
    assert_failure(&output, "wykracza poza sekcję");
    Ok(())
}

#[test]
fn rejects_unterminated_note_owner() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("bad-owner.o");
    let mut fixture = fixture(Class::Elf64, Endian::Little, &[ID]);
    fixture.bytes[fixture.note_offset + 15] = b'x';
    fs::write(&path, &fixture.bytes)?;
    let output = run(&path)?;
    assert_failure(&output, "nie jest zakończony zerem");
    Ok(())
}
